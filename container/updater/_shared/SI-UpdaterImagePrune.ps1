#Requires -Version 5.1
<#
    caj-si-updater -- IMAGE-PRUNE (SI #1215; framework IMAGE-PATCH-1 "IMAGE-PRUNE", owner 2026-11-12): THE INSTALL'S OWN
    REGISTRY KEEPS ONLY THE IMAGES OF THE CURRENT RELEASE AND OF THE ONE BEFORE IT. Why: Defender for Cloud scans every image
    STORED in a registry, not only the running ones -- the High / Critical findings customers saw were on OLD stored images.
    The only reason to keep an old image is the rollback one version down, which needs the previous release's images.

    WHEN: only after a SUCCESSFUL update AND its read-back -- the engine roll verified (setup\Invoke-SIContainerUpdate.ps1)
    and the post-roll (the web app + MCP server health-checked, the installed record, the updater itself) ended well. A
    failed, held or unread update prunes NOTHING. Called from _shared\SI-UpdaterInvardia.ps1 right after the post-roll.

    WHAT IS KEPT -- only what the install RECORDS, never guessed from tag text:
      * CURRENT  = the images the install runs AFTER the update, read back from Azure: every container and init container
                   of every Container Apps job and container app of the install's resource group (the engine jobs, the
                   updater, the web app, the MCP server, the sign-in front), the ACTIVE revisions of each app, and the
                   updater's pending self-update image (tag si-updater-pending);
      * PREVIOUS = the same read taken BEFORE the roll started (what ran until this update), plus the release record this
                   updater wrote at the last update (Key Vault secret SI-Release-Images, its 'current' = the release before);
      * the BASE-LAYER images those builds use (si-base:<hash>, si-updater-base:<hash>, <repo>-base:<hash>): a base image
        is kept when its layers are the first layers of a kept image (the build FROM it) -- read from the registry's own
        manifests;
      * every tag of a kept image (a tag shared with a kept image is kept: deletes are by manifest digest, and a digest is
        deleted only when no kept image points at it); every child of a kept multi-platform image.
    PREVIOUS NOT RECORDED (the read before the roll failed or found nothing) = NOTHING can be proven old: every image is
    kept, and the log says so. A repository the install records nothing for is never touched. A manifest that cannot be
    read is kept.

    WHERE: ONLY the install's own registry -- the one the updater builds into (SI_UPDATER_ACR), and only while it is in the
    install's own resource group (a registry elsewhere may serve someone else: nothing is deleted, said once). Only the
    registry's data plane (https://<login server>/v2/... and /acr/v1/...), through the updater's REST seam and the same token
    exchange as the tag check (setup\_shared\SI-AcrBuild.ps1 Get-SIAcrPullToken) with the delete right added. No module,
    no CLI, nothing else in Azure is changed.

    AFTER: the registry is read again and the number of images left is said per repository -- one plain line each in the
    run log, and in the update record (cfg.InstallState 'ImagePrune' for the web app and the heartbeat; the Key Vault
    release record). A failure here never fails the update: it is said, and the next update prunes again.

    A ROLLBACK to the previous release finds its images kept. A rollback further back is an ordinary update from Invardia
    (a lower version with a higher sequence): the update builds every image that is missing from the signed release
    package -- the engine image (Test-SIAcrTag in setup\Invoke-SIContainerUpdate.ps1), the web app / MCP server
    (Get-SIUpdaterAppPrebuilds), the sign-in front and the updater -- exactly as for a new release.

    THE SWITCH: SI_Updater_ImagePrune -- 'on' by default (the owner's decision); 'off' turns it off. Read from the
    configuration ($global:SI_Updater_ImagePrune), else the updater job's SI_CFG_SI_Updater_ImagePrune, else
    SI_UPDATER_IMAGE_PRUNE. PowerShell 5.1 and 7.
#>

$script:SIImagePruneManifestAccept = 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
$script:SIImagePruneRecordSecret = 'SI-Release-Images'
$script:SIImagePruneEngineBase = @{ 'si-orchestrator' = 'si-base' }

function Get-SIUpdaterImagePruneMode {
    <#
        PURE. Is the clean-up of old images on? -Value: the setting as found (configuration, else the job's variables).
        Returns @{ On; Reason }. '' / on / true / yes / 1 = on (the default); off / false / no / 0 = off; anything else = on,
        said.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return [pscustomobject]@{ On = $true; Reason = 'on (the default)' } }
    if ($v -match '^(?i)(off|false|no|0)$') { return [pscustomobject]@{ On = $false; Reason = ("off (SI_Updater_ImagePrune = {0})" -f $v) } }
    if ($v -match '^(?i)(on|true|yes|1)$') { return [pscustomobject]@{ On = $true; Reason = ("on (SI_Updater_ImagePrune = {0})" -f $v) } }
    [pscustomobject]@{ On = $true; Reason = ("on (SI_Updater_ImagePrune = '{0}' is not on or off -- the default applies)" -f $v) }
}

function Get-SIUpdaterImagePruneSetting {
    <# The setting's value: $global:SI_Updater_ImagePrune, else SI_CFG_SI_Updater_ImagePrune, else SI_UPDATER_IMAGE_PRUNE (via -Get). #>
    param([scriptblock]$Get)
    $g = $null; try { $g = Get-Variable -Name 'SI_Updater_ImagePrune' -Scope Global -ValueOnly -ErrorAction Stop } catch { $g = $null }
    if ($null -ne $g -and "$g".Trim()) { return "$g".Trim() }
    foreach ($n in 'SI_CFG_SI_Updater_ImagePrune', 'SI_UPDATER_IMAGE_PRUNE') {
        $v = if ($Get) { [string](& $Get $n) } else { [string][Environment]::GetEnvironmentVariable($n) }
        if ($v.Trim()) { return $v.Trim() }
    }
    ''
}

function ConvertTo-SIUpdaterImageRef {
    <#
        PURE. One image reference -> @{ Repo; Tag; Digest } when it is in -LoginServer's registry, else $null (another registry,
        Microsoft's, a name without a host). Forms: <login>/<repo>:<tag>, <login>/<repo>@sha256:<hex>, <login>/<repo>:<tag>@sha256:<hex>.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Image, [Parameter(Mandatory)][string]$LoginServer)
    $i = "$Image".Trim()
    if (-not $i -or -not $LoginServer) { return $null }
    $pre = $LoginServer.Trim().TrimEnd('/') + '/'
    if (-not $i.StartsWith($pre, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    $rest = $i.Substring($pre.Length)
    $digest = ''
    $at = $rest.IndexOf('@')
    if ($at -ge 0) { $digest = $rest.Substring($at + 1).ToLowerInvariant(); $rest = $rest.Substring(0, $at) }
    $tag = ''
    $colon = $rest.LastIndexOf(':')
    if ($colon -gt $rest.LastIndexOf('/')) { $tag = $rest.Substring($colon + 1); $rest = $rest.Substring(0, $colon) }
    if (-not $rest -or ($digest -and $digest -notmatch '^sha256:[0-9a-f]{64}$')) { return $null }
    if (-not $tag -and -not $digest) { $tag = 'latest' }
    [pscustomobject]@{ Repo = $rest.ToLowerInvariant(); Tag = $tag; Digest = $digest }
}

function Format-SIUpdaterImageRef {
    <# PURE. @{ Repo; Tag; Digest } -> 'repo:tag', 'repo@digest' or 'repo:tag@digest'. #>
    param([Parameter(Mandatory)]$Ref)
    $s = [string]$Ref.Repo
    if ("$($Ref.Tag)") { $s += ':' + [string]$Ref.Tag }
    if ("$($Ref.Digest)") { $s += '@' + [string]$Ref.Digest }
    $s
}

function Get-SIUpdaterResourceImages {
    <# PURE. Every image of one job / app / revision ARM object: containers and init containers of its template (or of a revision's own template). #>
    param([AllowNull()]$Resource)
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Resource) { return @() }
    $tpl = $null
    try { if ($Resource.properties -and $Resource.properties.PSObject.Properties['template']) { $tpl = $Resource.properties.template } } catch { $tpl = $null }
    if (-not $tpl) { return @() }
    foreach ($k in 'containers', 'initContainers') {
        if (-not $tpl.PSObject.Properties[$k]) { continue }
        foreach ($c in @($tpl.$k)) { if ($c -and $c.PSObject.Properties['image'] -and "$($c.image)".Trim()) { $out.Add("$($c.image)".Trim()) } }
    }
    $out.ToArray()
}

function Get-SIUpdaterImageSnapshot {
    <#
        What the install runs NOW, as it records it in Azure: every image of -LoginServer's registry named by a Container Apps
        job or container app of the install's resource group (containers and init containers), by every ACTIVE revision of
        each app, and the updater's pending self-update image (tag si-updater-pending on -UpdaterJob, repository si-updater).
        Returns @{ Ok; Refs (@{ Repo; Tag; Digest; From }); Reason }. Never throws: Ok = $false when Azure could not be read.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$LoginServer,
          [string]$UpdaterJob = 'caj-si-updater')
    $refs = New-Object System.Collections.Generic.List[object]
    $add = { param($img, $from) $r = ConvertTo-SIUpdaterImageRef -Image $img -LoginServer $LoginServer; if ($r) { $r | Add-Member -NotePropertyName From -NotePropertyValue $from -Force; $refs.Add($r) } }
    try {
        foreach ($j in @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId)) {
            if (-not $j) { continue }
            foreach ($img in @(Get-SIUpdaterResourceImages -Resource $j)) { & $add $img ([string]$j.name) }
            if ([string]$j.name -eq $UpdaterJob -and $j.PSObject.Properties['tags'] -and $j.tags) {
                foreach ($tn in 'si-updater-pending') {
                    $tv = ''; try { $tv = "$($j.tags.$tn)".Trim() } catch { $tv = '' }
                    if ($tv -and $tv -match '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$') { $refs.Add([pscustomobject]@{ Repo = 'si-updater'; Tag = $tv; Digest = ''; From = ('{0} ({1})' -f $UpdaterJob, $tn) }) }
                }
            }
        }
        $apps = @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/containerApps') -List | Where-Object { $_ })
        foreach ($a in $apps) {
            foreach ($img in @(Get-SIUpdaterResourceImages -Resource $a)) { & $add $img ([string]$a.name) }
            if (-not "$($a.id)".Trim()) { continue }
            $revs = @(Invoke-SIUpdaterArm -Path ("$($a.id)".TrimEnd('/') + '/revisions') -List | Where-Object { $_ })
            foreach ($rv in $revs) {
                $active = $false; try { $active = [bool]$rv.properties.active } catch { $active = $false }
                if ($active) { foreach ($img in @(Get-SIUpdaterResourceImages -Resource $rv)) { & $add $img ('{0} revision {1}' -f $a.name, $rv.name) } }
            }
        }
    } catch { return [pscustomobject]@{ Ok = $false; Refs = @(); Reason = ('the images the install runs could not be read: {0}' -f $_.Exception.Message) } }
    $n = $refs.Count
    [pscustomobject]@{ Ok = ($n -gt 0); Refs = $refs.ToArray(); Reason = $(if ($n) { ('{0} image reference(s) read' -f $n) } else { 'no image of this registry is named by any job or app of the install' }) }
}

function Get-SIUpdaterImageBaseRepos {
    <# PURE. The base-layer repositories of the kept repositories: si-base for the engine (si-orchestrator), <repo>-base for every other. #>
    param([string[]]$Repos)
    $set = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Repos | Where-Object { $_ })) {
        if ($r -like '*-base') { continue }
        $b = if ($script:SIImagePruneEngineBase.ContainsKey($r)) { $script:SIImagePruneEngineBase[$r] } else { $r + '-base' }
        if (-not $set.Contains($b)) { $set.Add($b) }
        $own = $r + '-base'
        if (-not $set.Contains($own)) { $set.Add($own) }
    }
    $set.ToArray()
}

function Get-SIUpdaterManifestLayers {
    <# PURE. A parsed manifest -> @{ Kind ('image' | 'index' | 'unknown'); Layers (digests, in order); Children (digests) }. #>
    param([AllowNull()]$Manifest)
    if (-not $Manifest) { return [pscustomobject]@{ Kind = 'unknown'; Layers = @(); Children = @() } }
    if ($Manifest.PSObject.Properties['manifests'] -and $null -ne $Manifest.manifests) {
        return [pscustomobject]@{ Kind = 'index'; Layers = @(); Children = @(@($Manifest.manifests) | Where-Object { $_ -and $_.digest } | ForEach-Object { ([string]$_.digest).ToLowerInvariant() }) }
    }
    if ($Manifest.PSObject.Properties['layers'] -and $null -ne $Manifest.layers) {
        return [pscustomobject]@{ Kind = 'image'; Layers = @(@($Manifest.layers) | Where-Object { $_ -and $_.digest } | ForEach-Object { ([string]$_.digest).ToLowerInvariant() }); Children = @() }
    }
    [pscustomobject]@{ Kind = 'unknown'; Layers = @(); Children = @() }
}

function Test-SIUpdaterLayerPrefix {
    <# PURE. Are -Base's layers (non-empty) the first layers of -Image, in order? (an image built FROM that base) #>
    param([string[]]$Base, [string[]]$Image)
    $b = @($Base | Where-Object { $_ }); $i = @($Image | Where-Object { $_ })
    if (-not $b.Count -or $b.Count -gt $i.Count) { return $false }
    for ($k = 0; $k -lt $b.Count; $k++) { if ($b[$k] -ne $i[$k]) { return $false } }
    $true
}

function New-SIUpdaterRegistrySeam {
    <#
        The install's registry data plane, through -Rest (the updater's REST seam): @{ LoginServer; List { param($Repo) };
        Manifest { param($Repo, $Digest) }; Delete { param($Repo, $Digest) } }. EVERY address is https://<-LoginServer>/...
        -- nothing else is ever called. A registry token per repository (the identity's ARM token exchanged at the registry,
        as the tag check does; scope pull, metadata_read and delete -- the updater is Contributor on its registry).
        List -> @{ Found; Manifests (@{ Digest; Tags; MediaType; DeleteEnabled }) } (Found $false = no such repository); THROWS
        when it cannot be read. Manifest -> the parsed manifest, $null when it cannot be read. Delete -> @{ Ok; Status; Why }.
    #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][scriptblock]$Rest, [scriptblock]$Token)
    if (-not $Token) { $Token = { param($Resource) Get-SIAzureToken -Resource $Resource } }
    $login = $LoginServer.Trim().TrimEnd('/')
    $cache = @{}
    # (the closures below run in a module of their own: they use only what they capture here and built-in commands)
    $accept = $script:SIImagePruneManifestAccept
    $bearer = {
        param([string]$Repo)
        if ($cache.ContainsKey($Repo)) { return $cache[$Repo] }
        $aad = [string](& $Token 'https://management.azure.com/')
        if (-not $aad) { throw 'no access token for the registry exchange' }
        $form = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
        $ex = & $Rest 'POST' ('https://{0}/oauth2/exchange' -f $login) ('grant_type=access_token&service={0}&access_token={1}' -f [uri]::EscapeDataString($login), [uri]::EscapeDataString($aad)) '' $form
        if ([int]$ex.Status -lt 200 -or [int]$ex.Status -ge 300) { throw ('the registry refused the token exchange: HTTP {0}' -f [int]$ex.Status) }
        $refresh = [string](("$($ex.Body)" | ConvertFrom-Json).refresh_token)
        $scope = 'repository:{0}:pull,metadata_read,delete' -f $Repo
        $tk = & $Rest 'POST' ('https://{0}/oauth2/token' -f $login) ('grant_type=refresh_token&service={0}&scope={1}&refresh_token={2}' -f [uri]::EscapeDataString($login), [uri]::EscapeDataString($scope), [uri]::EscapeDataString($refresh)) '' $form
        if ([int]$tk.Status -lt 200 -or [int]$tk.Status -ge 300) { throw ('the registry refused a token for {0}: HTTP {1}' -f $Repo, [int]$tk.Status) }
        $t = [string](("$($tk.Body)" | ConvertFrom-Json).access_token)
        $cache[$Repo] = $t
        $t
    }.GetNewClosure()
    $list = {
        param([string]$Repo)
        $b = & $bearer $Repo
        $all = New-Object System.Collections.Generic.List[object]
        $url = 'https://{0}/acr/v1/{1}/_manifests?n=1000' -f $login, $Repo
        for ($p = 0; $url -and $p -lt 50; $p++) {
            $r = & $Rest 'GET' $url $null '' @{ Authorization = ('Bearer ' + $b); Accept = 'application/json' }
            if ([int]$r.Status -eq 404) { if ($p -eq 0) { return [pscustomobject]@{ Found = $false; Manifests = @() } }; break }
            if ([int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { throw ('the images of {0} could not be listed: HTTP {1}' -f $Repo, [int]$r.Status) }
            $j = $null; if ("$($r.Body)".Trim()) { $j = "$($r.Body)" | ConvertFrom-Json }
            foreach ($m in @(if ($j -and $j.PSObject.Properties['manifests']) { $j.manifests })) {
                if (-not $m -or -not $m.digest) { continue }
                $de = $true; try { if ($m.changeableAttributes -and $m.changeableAttributes.PSObject.Properties['deleteEnabled']) { $de = [bool]$m.changeableAttributes.deleteEnabled } } catch { $de = $true }
                $all.Add([pscustomobject]@{ Digest = ([string]$m.digest).ToLowerInvariant(); Tags = @(@($m.tags) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                                            MediaType = $(if ($m.PSObject.Properties['mediaType']) { [string]$m.mediaType } else { '' }); DeleteEnabled = $de })
            }
            $url = ''
            $lk = $null; try { if ($r.Headers) { $lk = $r.Headers['Link'] } } catch { $lk = $null }
            $lt = (@($lk) | Where-Object { $_ }) -join ','
            if ($lt -match '<([^>]+)>\s*;\s*rel="?next"?') { $nx = $Matches[1]; $url = if ($nx -match '^https://') { $nx } else { 'https://{0}{1}' -f $login, $nx } }
            if ($url -and -not $url.StartsWith(('https://{0}/' -f $login), [StringComparison]::OrdinalIgnoreCase)) { $url = '' }
        }
        [pscustomobject]@{ Found = $true; Manifests = $all.ToArray() }
    }.GetNewClosure()
    $manifest = {
        param([string]$Repo, [string]$Digest)
        try {
            $b = & $bearer $Repo
            $r = & $Rest 'GET' ('https://{0}/v2/{1}/manifests/{2}' -f $login, $Repo, $Digest) $null '' @{ Authorization = ('Bearer ' + $b); Accept = $accept }
            if ([int]$r.Status -lt 200 -or [int]$r.Status -ge 300 -or -not "$($r.Body)".Trim()) { return $null }
            "$($r.Body)" | ConvertFrom-Json
        } catch { $null }
    }.GetNewClosure()
    $delete = {
        param([string]$Repo, [string]$Digest)
        try {
            $b = & $bearer $Repo
            $r = & $Rest 'DELETE' ('https://{0}/v2/{1}/manifests/{2}' -f $login, $Repo, $Digest) $null '' @{ Authorization = ('Bearer ' + $b) }
            $st = [int]$r.Status
            [pscustomobject]@{ Ok = ($st -ge 200 -and $st -lt 300) -or $st -eq 404; Status = $st; Why = $(if ($st -ge 200 -and $st -lt 300) { '' } elseif ($st -eq 404) { 'already gone' } else { 'HTTP {0}' -f $st }) }
        } catch { [pscustomobject]@{ Ok = $false; Status = 0; Why = $_.Exception.Message } }
    }.GetNewClosure()
    @{ LoginServer = $login; List = $list; Manifest = $manifest; Delete = $delete }
}

function Invoke-SIUpdaterImagePrune {
    <#
        THE CLEAN-UP ITSELF. Deletes from -Registry (New-SIUpdaterRegistrySeam, or a test's fake) every image that belongs
        neither to -Current (the read-back after the update) nor to -Previous (the read before it) nor to -Recorded (the refs
        of the release record's 'current'), nor is a base-layer image of a kept image. Nothing at all when: -On is $false;
        -Healthy is $false (the update and its read-back did not end well); -RegistryResourceGroup is not -InstallResourceGroup;
        -Current or -Previous is not Ok (not readable / nothing recorded -- nothing can be proven old).
        Returns @{ Done; Reason; Repos (@{ Repo; Before; Kept; Deleted; Failed; Left; Line }); Lines }. Never throws.
    #>
    param([bool]$On = $true, [bool]$Healthy, [Parameter(Mandatory)][hashtable]$Registry, $Current, $Previous, [object[]]$Recorded = @(),
          [AllowEmptyString()][string]$RegistryResourceGroup = '', [AllowEmptyString()][string]$InstallResourceGroup = '')
    $lines = New-Object System.Collections.Generic.List[string]
    $repos = New-Object System.Collections.Generic.List[object]
    $none = { param($why) $lines.Add($why); [pscustomobject]@{ Done = $false; Reason = $why; Repos = @(); Lines = $lines.ToArray() } }
    if (-not $On) { return (& $none 'old images: the clean-up is off (SI_Updater_ImagePrune = off) -- every image is kept') }
    if (-not $Healthy) { return (& $none 'old images: not cleaned up -- the update did not end healthy, so every image is kept') }
    if ("$RegistryResourceGroup".Trim() -and "$InstallResourceGroup".Trim() -and "$RegistryResourceGroup".Trim() -ine "$InstallResourceGroup".Trim()) {
        return (& $none 'old images: not cleaned up -- the registry is not in this install''s own resource group, so it may hold images of others; every image is kept')
    }
    if (-not $Current -or -not $Current.Ok -or -not @($Current.Refs).Count) { return (& $none ('old images: not cleaned up -- what the install runs now could not be read back ({0}); every image is kept' -f $(if ($Current) { $Current.Reason } else { 'not read' }))) }
    if (-not $Previous -or -not $Previous.Ok -or -not @($Previous.Refs).Count) {
        return (& $none ('old images: not cleaned up -- the images of the previous release are not recorded ({0}), so no image can be proven old; every image is kept' -f $(if ($Previous) { $Previous.Reason } else { 'not read before the update' })))
    }
    $keepRefs = @(@($Current.Refs) + @($Previous.Refs) + @($Recorded) | Where-Object { $_ -and $_.Repo })
    $appRepos = @($keepRefs | ForEach-Object { [string]$_.Repo } | Where-Object { $_ -notlike '*-base' } | Sort-Object -Unique)
    $baseRepos = @(Get-SIUpdaterImageBaseRepos -Repos $appRepos | Where-Object { $appRepos -notcontains $_ })
    # a base repository the install names directly is kept as an app repository too (its named images kept by name)
    $directBase = @($keepRefs | ForEach-Object { [string]$_.Repo } | Where-Object { $_ -like '*-base' } | Sort-Object -Unique)
    foreach ($d in $directBase) { if ($baseRepos -notcontains $d) { $baseRepos += $d } }

    $keptLayers = New-Object System.Collections.Generic.List[object]   # layer lists of every kept image (for the base check)
    $layersKnown = $true
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($repo in $appRepos) {
        $ls = $null
        try { $ls = & $Registry.List $repo } catch { $lines.Add(('{0}: not cleaned up -- its images could not be listed ({1}); every image is kept' -f $repo, $_.Exception.Message)); $layersKnown = $false; continue }
        if (-not $ls.Found) { continue }
        $mans = @($ls.Manifests)
        $byTag = @{}; foreach ($m in $mans) { foreach ($t in @($m.Tags)) { $byTag[[string]$t] = $m.Digest } }
        $keep = New-Object 'System.Collections.Generic.HashSet[string]'
        $missing = 0
        foreach ($r in @($keepRefs | Where-Object { [string]$_.Repo -eq $repo })) {
            if ("$($r.Digest)") { $null = $keep.Add(([string]$r.Digest).ToLowerInvariant()) }
            if ("$($r.Tag)") { if ($byTag.ContainsKey([string]$r.Tag)) { $null = $keep.Add([string]$byTag[[string]$r.Tag]) } elseif (-not "$($r.Digest)") { $missing++ } }
        }
        # every kept image read: a multi-platform one keeps its children; its layers feed the base check. Unreadable = keep the repository.
        $unreadable = $false
        foreach ($dg in @($keep)) {
            $mf = & $Registry.Manifest $repo $dg
            $info = Get-SIUpdaterManifestLayers -Manifest $mf
            if ($info.Kind -eq 'index') {
                foreach ($c in @($info.Children)) {
                    $null = $keep.Add($c)
                    $ci = Get-SIUpdaterManifestLayers -Manifest (& $Registry.Manifest $repo $c)
                    if ($ci.Kind -eq 'image') { $keptLayers.Add(@($ci.Layers)) } else { $layersKnown = $false }
                }
            } elseif ($info.Kind -eq 'image') { $keptLayers.Add(@($info.Layers)) }
            elseif (@($mans | Where-Object { $_.Digest -eq $dg }).Count) { $unreadable = $true; $layersKnown = $false }
        }
        if ($unreadable) { $lines.Add(('{0}: not cleaned up -- an image it runs could not be read; every image is kept' -f $repo)); continue }
        $del = @($mans | Where-Object { -not $keep.Contains($_.Digest) })
        $plan.Add([pscustomobject]@{ Repo = $repo; Base = $false; Before = $mans.Count; Keep = @($mans | Where-Object { $keep.Contains($_.Digest) } | ForEach-Object { $_.Digest }); Delete = $del; Missing = $missing })
    }

    foreach ($repo in $baseRepos) {
        $ls = $null
        try { $ls = & $Registry.List $repo } catch { $lines.Add(('{0}: not cleaned up -- its images could not be listed ({1}); every image is kept' -f $repo, $_.Exception.Message)); continue }
        if (-not $ls.Found -or -not @($ls.Manifests).Count) { continue }
        $mans = @($ls.Manifests)
        if (-not $layersKnown -or -not $keptLayers.Count) { $lines.Add(('{0}: not cleaned up -- the layers of the images it may serve could not all be read; every image is kept' -f $repo)); continue }
        $keep = New-Object 'System.Collections.Generic.HashSet[string]'
        $byTag = @{}; foreach ($m in $mans) { foreach ($t in @($m.Tags)) { $byTag[[string]$t] = $m.Digest } }
        foreach ($r in @($keepRefs | Where-Object { [string]$_.Repo -eq $repo })) {
            if ("$($r.Digest)") { $null = $keep.Add(([string]$r.Digest).ToLowerInvariant()) }
            if ("$($r.Tag)" -and $byTag.ContainsKey([string]$r.Tag)) { $null = $keep.Add([string]$byTag[[string]$r.Tag]) }
        }
        foreach ($m in $mans) {
            if ($keep.Contains($m.Digest)) { continue }
            $info = Get-SIUpdaterManifestLayers -Manifest (& $Registry.Manifest $repo $m.Digest)
            if ($info.Kind -ne 'image' -or -not @($info.Layers).Count) { $null = $keep.Add($m.Digest); continue }   # cannot be proven unused
            foreach ($kl in $keptLayers) { if (Test-SIUpdaterLayerPrefix -Base @($info.Layers) -Image @($kl)) { $null = $keep.Add($m.Digest); break } }
        }
        $del = @($mans | Where-Object { -not $keep.Contains($_.Digest) })
        $plan.Add([pscustomobject]@{ Repo = $repo; Base = $true; Before = $mans.Count; Keep = @($mans | Where-Object { $keep.Contains($_.Digest) } | ForEach-Object { $_.Digest }); Delete = $del; Missing = 0 })
    }

    foreach ($p in $plan) {
        $deleted = 0; $failed = 0; $locked = 0; $why = ''
        foreach ($m in @($p.Delete)) {
            if (-not $m.DeleteEnabled) { $locked++; continue }
            $d = & $Registry.Delete $p.Repo $m.Digest
            if ($d -and $d.Ok) { $deleted++ } else { $failed++; if (-not $why -and $d) { $why = [string]$d.Why } }
        }
        # the read-back: what is left, and that every kept image is still there
        $left = -1; $lost = 0
        try {
            $after = & $Registry.List $p.Repo
            $am = @(if ($after.Found) { $after.Manifests })
            $left = $am.Count
            $have = @{}; foreach ($m in $am) { $have[$m.Digest] = $true }
            foreach ($k in @($p.Keep)) { if (-not $have.ContainsKey($k)) { $lost++ } }
        } catch { $left = -1 }
        $what = if ($p.Base) { 'base images' } else { 'images' }
        $line = if ($left -lt 0) { ('{0}: {1} old {2} deleted; what is left could not be read back' -f $p.Repo, $deleted, $what) }
                else { ('{0}: {1} old {2} deleted, {3} left (this release and the one before{4})' -f $p.Repo, $deleted, $what, $left, $(if ($p.Base) { ', and the base layers they are built on' } else { '' })) }
        if ($failed) { $line += ('; {0} could not be deleted ({1}) -- kept, the next update tries again' -f $failed, $(if ($why) { $why } else { 'no answer' })) }
        if ($locked) { $line += ('; {0} locked against deletion -- kept' -f $locked) }
        if ($lost) { $line += ('; WARNING: {0} image(s) that should be kept are not there any more' -f $lost) }
        $lines.Add($line)
        $repos.Add([pscustomobject]@{ Repo = $p.Repo; Base = $p.Base; Before = $p.Before; Kept = @($p.Keep).Count; Deleted = $deleted; Failed = $failed; Left = $left; Line = $line })
    }
    $total = 0; foreach ($r in $repos) { $total += $r.Deleted }
    [pscustomobject]@{ Done = $true; Reason = ('old images: {0} deleted in {1} repositor{2}' -f $total, $repos.Count, $(if ($repos.Count -eq 1) { 'y' } else { 'ies' })); Repos = $repos.ToArray(); Lines = $lines.ToArray() }
}

function ConvertTo-SIUpdaterImagePruneValue {
    <# PURE. The clean-up result as the cfg.InstallState 'ImagePrune' value (at most 400 characters): {"at","done","deleted","left":{repo:n},"why"}. #>
    param([Parameter(Mandatory)]$Result, [datetime]$NowUtc = [datetime]::UtcNow)
    $left = [ordered]@{}; $total = 0
    foreach ($r in @($Result.Repos)) { $left[[string]$r.Repo] = [int]$r.Left; $total += [int]$r.Deleted }
    $why = if ($Result.Done) { '' } else { ([string]$Result.Reason -replace '^old images: ', '') }
    foreach ($max in 200, 80, 0) {
        $w = if ($why.Length -gt $max) { if ($max -le 3) { '' } else { $why.Substring(0, $max - 3) + '...' } } else { $why }
        $o = [ordered]@{ at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); done = [bool]$Result.Done; deleted = $total; left = $left; why = $w }
        $j = $o | ConvertTo-Json -Compress -Depth 4
        if ($j.Length -le 400) { return $j }
    }
    ([ordered]@{ at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); done = [bool]$Result.Done; deleted = $total } | ConvertTo-Json -Compress)
}

function ConvertFrom-SIUpdaterReleaseImageRecord {
    <# PURE. The Key Vault release record (JSON) -> @{ CurrentVersion; Current (refs); PreviousVersion; Previous (refs) }; an unreadable one = empty. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    $o = [pscustomobject]@{ CurrentVersion = ''; Current = @(); PreviousVersion = ''; Previous = @() }
    if (-not "$Json".Trim()) { return $o }
    try { $j = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $o }
    $conv = { param($node) @(if ($node -and $node.PSObject.Properties['images']) { foreach ($s in @($node.images)) {
                $t = "$s".Trim(); if (-not $t) { continue }
                $r = ConvertTo-SIUpdaterImageRef -Image ('x.invalid/' + $t) -LoginServer 'x.invalid'
                if ($r) { $r } } }) }
    foreach ($k in 'current', 'previous') {
        if (-not $j.PSObject.Properties[$k] -or -not $j.$k) { continue }
        $v = if ($j.$k.PSObject.Properties['version']) { [string]$j.$k.version } else { '' }
        if ($k -eq 'current') { $o.CurrentVersion = $v; $o.Current = @(& $conv $j.$k) } else { $o.PreviousVersion = $v; $o.Previous = @(& $conv $j.$k) }
    }
    $o
}

function ConvertTo-SIUpdaterReleaseImageRecord {
    <# PURE. The release record to keep: 'current' = the release now running and its images, 'previous' = the one before. #>
    param([AllowEmptyString()][string]$Version, [object[]]$Current = @(), [AllowEmptyString()][string]$PreviousVersion, [object[]]$Previous = @(), $Result, [datetime]$NowUtc = [datetime]::UtcNow)
    $fmt = { param($refs) @(@($refs) | Where-Object { $_ -and $_.Repo } | ForEach-Object { Format-SIUpdaterImageRef -Ref $_ } | Sort-Object -Unique) }
    $o = [ordered]@{ at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                     current = [ordered]@{ version = "$Version"; images = @(& $fmt $Current) }
                     previous = [ordered]@{ version = "$PreviousVersion"; images = @(& $fmt $Previous) } }
    if ($Result) {
        $left = [ordered]@{}; foreach ($r in @($Result.Repos)) { $left[[string]$r.Repo] = [int]$r.Left }
        $o['prune'] = [ordered]@{ done = [bool]$Result.Done; left = $left; lines = @($Result.Lines) }
    }
    $o | ConvertTo-Json -Compress -Depth 6
}

function Test-SIUpdaterSameRelease {
    <#
        PURE. Is this run the SAME release again -- the release record already names -Version as its current release (the
        updater's second pass after its self-roll, a re-run of that release), or the read before the roll names exactly the
        images read back after it (nothing changed)? Then the read before the roll is NOT the previous release.
    #>
    param($Record, [AllowEmptyString()][string]$Version = '', $Before, $After)
    if ($Record -and "$Version".Trim() -and "$($Record.CurrentVersion)".Trim() -and "$($Record.CurrentVersion)".Trim() -eq "$Version".Trim()) { return $true }
    if ($Before -and $Before.Ok -and $After -and $After.Ok) {
        $set = { param($refs) (@(@($refs) | Where-Object { $_ -and $_.Repo } | ForEach-Object { Format-SIUpdaterImageRef -Ref $_ } | Sort-Object -Unique) -join '|') }
        $b = & $set $Before.Refs; $a = & $set $After.Refs
        if ($b -and $b -eq $a) { return $true }
    }
    $false
}

function Invoke-SIUpdaterImagePruneStep {
    <#
        The step the update runs right after a successful post-roll (SI-UpdaterInvardia.ps1). -Before: the snapshot taken
        before the roll (Get-SIUpdaterImageSnapshot); -Healthy: the update and its read-back ended well. Reads the setting,
        the registry (Get-SIUpdaterRegistry), what runs now, and the release record (-ReadSecret / -WriteSecret: the update
        client's Key Vault seams); prunes (Invoke-SIUpdaterImagePrune); writes the release record and, with -Store, the
        cfg.InstallState 'ImagePrune' row; one log line per repository. -Registry / -After: test seams. Never throws; returns
        the clean-up result (or $null when nothing could be started).
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [bool]$Healthy, $Before, [AllowEmptyString()][string]$Version = '', [AllowEmptyString()][string]$PreviousVersion = '',
          [string]$UpdaterJob = 'caj-si-updater', [scriptblock]$Get, [scriptblock]$ReadSecret, [scriptblock]$WriteSecret, $Store,
          [hashtable]$Registry, $After)
    try {
        $mode = Get-SIUpdaterImagePruneMode -Value (Get-SIUpdaterImagePruneSetting -Get $Get)
        if (-not $mode.On) { Write-UpdLog ('old images: the clean-up is {0} -- every image is kept' -f $mode.Reason); return $null }
        if (-not $Healthy) { Write-UpdLog 'old images: not cleaned up -- the update did not end healthy, so every image is kept'; return $null }
        $acr = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $login = [string]$acr.loginServer
        if (-not $After) { $After = Get-SIUpdaterImageSnapshot -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -LoginServer $login -UpdaterJob $UpdaterJob }
        $rec = $null
        if ($ReadSecret) { try { $rec = ConvertFrom-SIUpdaterReleaseImageRecord -Json ([string](& $ReadSecret $script:SIImagePruneRecordSecret)) } catch { $rec = $null } }
        $recorded = @(if ($rec) { @($rec.Current) })
        # THE SAME RELEASE AGAIN (the updater's second pass after its self-roll, a re-run of the release already recorded):
        # what ran "before" this run is this release itself, so the PREVIOUS release is the record's 'previous' -- never the
        # read before the roll. No record of it = the previous release is not known: nothing is deleted.
        $prevSnap = $Before; $sameRelease = Test-SIUpdaterSameRelease -Record $rec -Version $Version -Before $Before -After $After
        if ($sameRelease) {
            if ($rec -and @($rec.Previous).Count) {
                $prevSnap = [pscustomobject]@{ Ok = $true; Refs = @($rec.Previous); Reason = ('the release record''s previous release {0}' -f $rec.PreviousVersion) }
                $recorded = @(@($rec.Current) + @(if ($Before -and $Before.Ok) { @($Before.Refs) }))
            } else {
                $prevSnap = [pscustomobject]@{ Ok = $false; Refs = @(); Reason = 'this release ran already before this update and the release before it is not recorded -- the previous release is not known' }
            }
        }
        if (-not $Registry) { $Registry = New-SIUpdaterRegistrySeam -LoginServer $login -Rest (Get-SIUpdaterRest) }
        $res = Invoke-SIUpdaterImagePrune -On $true -Healthy $Healthy -Registry $Registry -Current $After -Previous $prevSnap -Recorded $recorded `
                   -RegistryResourceGroup ([string]$acr.resourceGroup) -InstallResourceGroup $ResourceGroup
        foreach ($l in @($res.Lines)) { Write-UpdLog $l }
        if ($res.Done) { Write-UpdLog $res.Reason }
        # the release record: written only from what was read back after a healthy update (the next update's 'previous');
        # the same release again keeps the record's previous release as it is -- never this release as its own previous
        if ($WriteSecret -and $After -and $After.Ok) {
            if ($sameRelease) {
                $prevRefs = @(if ($rec) { @($rec.Previous) })
                $prevVer = if ($rec) { [string]$rec.PreviousVersion } else { '' }
            } else {
                $prevRefs = @(if ($Before -and $Before.Ok) { @($Before.Refs) } elseif ($rec) { @($rec.Current) })
                $prevVer = if ("$PreviousVersion".Trim()) { $PreviousVersion } elseif ($rec) { $rec.CurrentVersion } else { '' }
            }
            try { $null = & $WriteSecret $script:SIImagePruneRecordSecret (ConvertTo-SIUpdaterReleaseImageRecord -Version $Version -Current @($After.Refs) -PreviousVersion $prevVer -Previous $prevRefs -Result $res) }
            catch { Write-UpdLog ('NOTE: old images: the release record could not be written ({0}) -- the next update reads the images before it rolls, as this one did' -f $_.Exception.Message) }
        }
        if ($Store -and (Get-Command -Name Save-SIUpdaterInstallStateValue -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterInstallStateValue -Store $Store -Name 'ImagePrune' -Value (ConvertTo-SIUpdaterImagePruneValue -Result $res) }
        $res
    } catch { Write-UpdLog ('WARNING: old images: not cleaned up this time ({0}) -- every image is kept; the next update tries again' -f $_.Exception.Message); $null }
}
