#Requires -Version 5.1
<#
    caj-si-updater -- IMAGE-PRUNE (framework IMAGE-PATCH-1 "IMAGE-PRUNE"; owner 2026-11-16: "we agreed NOT to keep 1 previous,
    only the current" / "we will not keep an old image in any repo"): AFTER A PROVEN UPDATE THE INSTALL'S OWN REGISTRY KEEPS
    ONLY THE IMAGES THE INSTALL RUNS NOW. No image of a previous release is kept, in any repository. Why: Defender for Cloud
    scans every image STORED in a registry, not only the running ones; a kept old image ages into newly disclosed
    vulnerabilities and brings the attack-path finding back. ROLLBACK IS A ROLL-FORWARD: to go back, a new (higher) release
    is published, and its update builds every image it needs (below). This replaces the earlier "current + 1 previous".

    WHEN: only after a SUCCESSFUL update AND its read-back -- the engine roll verified (setup\Invoke-SIContainerUpdate.ps1)
    and the post-roll (the web app + MCP server health-checked, the installed record, the updater itself) ended well -- and
    only when what runs now was read back. A failed, held or unread update prunes NOTHING. Called from
    _shared\SI-UpdaterInvardia.ps1 right after the post-roll. An IMAGE-ONLY swap is cleaned up later, once it is PROVEN (a
    job succeeded on the new image, the apps healthy): Invoke-SIUpdaterImageOnlyPendingPrune below.

    WHAT IS KEPT -- only what the install RUNS, read back from Azure, never guessed from tag text:
      * every container and init container of every Container Apps job and container app of the install's resource group
        (the engine jobs, the updater, the web app, the MCP server, the sign-in front), the ACTIVE revisions of each app,
        and the updater's pending self-update image (tag si-updater-pending);
      * every image a RUNNING execution started with (a pipeline that started before the update keeps its image -- a
        replica it restarts must still find it). The running executions NOT READABLE = nothing is deleted;
      * the BASE-LAYER images a kept image is built FROM (si-base:<hash>, si-updater-base:<hash>, <repo>-base:<hash>): a
        base image is kept when its layers are the first layers of a kept image -- read from the registry's own manifests;
      * every tag of a kept image (deletes are by manifest digest; a digest is deleted only when nothing kept points at
        it); every child of a kept multi-platform image; every signature / attestation of a kept image (a manifest whose
        'subject' is a kept image, or a sha256-<digest>.* tag of one), transitively.
    REPOSITORIES NOTHING RUNS FROM ANY MORE (framework IMAGE-PRUNE point 3, Invardia 2026-11-16): the WHOLE registry is
    listed, and every repository SI itself created ($script:SIImagePruneOwnRepos: exact names, never a pattern) that nothing
    runs from is emptied -- e.g. signin-front at an install on the built-in sign-in; a base-layer repository among them keeps
    a base a running image is built from. A repository SI did not create is never touched; the list cannot be read =
    nothing is deleted from a repository nothing runs. A manifest that cannot be read is kept. The release
    record (Key Vault SI-Release-Images: what runs now, and the release before as history only) is written before the
    first delete; it no longer keeps anything.

    WHERE: ONLY the install's own registry -- the one the updater builds into (SI_UPDATER_ACR), and only while it is in the
    install's own resource group (a registry elsewhere may serve someone else: nothing is deleted, said once). Only the
    registry's data plane (https://<login server>/v2/... and /acr/v1/...), through the updater's REST seam and the same token
    exchange as the tag check (setup\_shared\SI-AcrBuild.ps1 Get-SIAcrPullToken) with the delete right added. No module,
    no CLI, nothing else in Azure is changed.

    THE FRAMEWORK IMAGE-PRUNE CONTRACT (Invardia framework/REQUIREMENTS.md, IMAGE-PATCH-1, 2026-11-12) is what this file
    implements: the release record is written BEFORE the first delete (not written = nothing deleted); a heartbeat on the
    update's own lock at least once a minute while it works (tried at most every 15 s, also when it fails); each
    repository's plan ("N images, K kept, D to delete") said before its deletes and its result right after, every line at
    once; kept images and child manifests counted apart.

    AFTER: the registry is read again (again a few times, with short pauses, while a deleted image is still listed: the
    registry completes its deletes after it answers them) and the number of images left is said per repository -- one plain line each in the
    run log, and in the update record (cfg.InstallState 'ImagePrune' for the web app and the heartbeat; the Key Vault
    release record). A failure here never fails the update: it is said, and the next update prunes again.

    GOING BACK is an ordinary update from Invardia (a new, higher release; or a lower version with a higher sequence): the
    update builds every image that is missing from the signed release package -- the engine image (Test-SIAcrTag in
    setup\Invoke-SIContainerUpdate.ps1), the web app / MCP server (Get-SIUpdaterAppPrebuilds), the sign-in front and the
    updater -- exactly as for a new release. A FAILED update never reaches the clean-up: its roll restores the images that
    ran before, and they are still there because nothing was deleted.

    THE SWITCH: SI_Updater_ImagePrune -- 'on' by default (the owner's decision); 'off' turns it off. Read from the
    configuration ($global:SI_Updater_ImagePrune), else the updater job's SI_CFG_SI_Updater_ImagePrune, else
    SI_UPDATER_IMAGE_PRUNE. PowerShell 5.1 and 7.
#>

$script:SIImagePruneManifestAccept = 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
$script:SIImagePruneRecordSecret = 'SI-Release-Images'
$script:SIImagePruneEngineBase = @{ 'si-orchestrator' = 'si-base' }
# SI's OWN ONE-OFF REPOSITORIES (Invardia's central image scan 2026-11-14): images built for a one-off proof and run only by a
# job that is deleted again -- pro-management/deploy/Test-SIManagementDeployment.ps1's probe. Nothing ever runs them for long, so
# the clean-up removes every image in them that no job, app revision or RUNNING execution uses. The one list.
$script:SIImagePruneOneOffRepos = @('si-management-probe')
# THE REPOSITORIES SI ITSELF CREATES (framework IMAGE-PRUNE point 3, Invardia 2026-11-16): the clean-up lists the WHOLE registry
# and empties every repository of THIS list that nothing runs from any more (e.g. signin-front at an install on Microsoft's
# built-in sign-in). An explicit list of exact names -- never a pattern: a repository SI did not create is never touched.
# The engine, the updater, the web app, the MCP server, the sign-in front, each with its base-layer repository, and the probe.
$script:SIImagePruneOwnRepos = @('si-orchestrator', 'si-base', 'si-orchestrator-base', 'si-updater', 'si-updater-base',
    'si-management', 'si-management-base', 'si-management-mcp', 'si-management-mcp-base', 'signin-front', 'signin-front-base',
    'si-management-probe')

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
    <# PURE. A parsed manifest -> @{ Kind ('image' | 'index' | 'unknown'); Layers (digests, in order); Children (digests);
       Subject (the digest of the image it signs or attests -- an OCI referrer's 'subject' -- or '') }. #>
    param([AllowNull()]$Manifest)
    if (-not $Manifest) { return [pscustomobject]@{ Kind = 'unknown'; Layers = @(); Children = @(); Subject = '' } }
    $sub = ''
    try { if ($Manifest.PSObject.Properties['subject'] -and $Manifest.subject -and $Manifest.subject.PSObject.Properties['digest']) { $sub = ([string]$Manifest.subject.digest).Trim().ToLowerInvariant() } } catch { $sub = '' }
    if ($Manifest.PSObject.Properties['manifests'] -and $null -ne $Manifest.manifests) {
        return [pscustomobject]@{ Kind = 'index'; Layers = @(); Children = @(@($Manifest.manifests) | Where-Object { $_ -and $_.digest } | ForEach-Object { ([string]$_.digest).ToLowerInvariant() }); Subject = $sub }
    }
    if ($Manifest.PSObject.Properties['layers'] -and $null -ne $Manifest.layers) {
        return [pscustomobject]@{ Kind = 'image'; Layers = @(@($Manifest.layers) | Where-Object { $_ -and $_.digest } | ForEach-Object { ([string]$_.digest).ToLowerInvariant() }); Children = @(); Subject = $sub }
    }
    [pscustomobject]@{ Kind = 'unknown'; Layers = @(); Children = @(); Subject = $sub }
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
        Catalog -> every repository name of the registry (its own token, scope registry:catalog:*); THROWS when it cannot be read.
    #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][scriptblock]$Rest, [scriptblock]$Token,
          [scriptblock]$Beat, [int]$BeatSeconds = 15)
    # framework IMAGE-PRUNE CONTRACT point 4, inside long registry work: -Beat is tried before EVERY HTTP request (token
    # calls, each page of a listing, each manifest, each delete) -- at most once per -BeatSeconds whatever its outcome, so a
    # failing beat never slows the clean-up. A single request that blocks cannot beat while it waits: its own time limit
    # (the REST seam's) is then the longest gap.
    if ($Beat) {
        $inner = $Rest; $beatAt = @{ t = [datetime]::MinValue }
        $Rest = {
            $now = [datetime]::UtcNow
            if ($BeatSeconds -le 0 -or ($now - $beatAt.t).TotalSeconds -ge $BeatSeconds) { $beatAt.t = $now; try { $null = & $Beat 'a registry call' } catch { } }
            & $inner @args
        }.GetNewClosure()
    }
    if (-not $Token) { $Token = { param($Resource) Get-SIAzureToken -Resource $Resource } }
    $login = $LoginServer.Trim().TrimEnd('/')
    $cache = @{}
    # (the closures below run in a module of their own: they use only what they capture here and built-in commands)
    $accept = $script:SIImagePruneManifestAccept
    $bearer = {
        param([string]$Repo, [string]$Scope = '')
        $key = if ($Scope) { $Scope } else { $Repo }
        if ($cache.ContainsKey($key)) { return $cache[$key] }
        $aad = [string](& $Token 'https://management.azure.com/')
        if (-not $aad) { throw 'no access token for the registry exchange' }
        $form = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
        $ex = & $Rest 'POST' ('https://{0}/oauth2/exchange' -f $login) ('grant_type=access_token&service={0}&access_token={1}' -f [uri]::EscapeDataString($login), [uri]::EscapeDataString($aad)) '' $form
        if ([int]$ex.Status -lt 200 -or [int]$ex.Status -ge 300) { throw ('the registry refused the token exchange: HTTP {0}' -f [int]$ex.Status) }
        $refresh = [string](("$($ex.Body)" | ConvertFrom-Json).refresh_token)
        $scope = if ($Scope) { $Scope } else { 'repository:{0}:pull,metadata_read,delete' -f $Repo }
        $tk = & $Rest 'POST' ('https://{0}/oauth2/token' -f $login) ('grant_type=refresh_token&service={0}&scope={1}&refresh_token={2}' -f [uri]::EscapeDataString($login), [uri]::EscapeDataString($scope), [uri]::EscapeDataString($refresh)) '' $form
        if ([int]$tk.Status -lt 200 -or [int]$tk.Status -ge 300) { throw ('the registry refused a token for {0}: HTTP {1}' -f $(if ($Scope) { 'its repository list' } else { $Repo }), [int]$tk.Status) }
        $t = [string](("$($tk.Body)" | ConvertFrom-Json).access_token)
        $cache[$key] = $t
        $t
    }.GetNewClosure()
    # every repository of the registry (/v2/_catalog, page by page); THROWS when it cannot be read
    $catalog = {
        $b = & $bearer '' 'registry:catalog:*'
        $names = New-Object System.Collections.Generic.List[string]
        $url = 'https://{0}/v2/_catalog?n=1000' -f $login
        for ($p = 0; $url -and $p -lt 50; $p++) {
            $r = & $Rest 'GET' $url $null '' @{ Authorization = ('Bearer ' + $b); Accept = 'application/json' }
            if ([int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { throw ('the registry''s repositories could not be listed: HTTP {0}' -f [int]$r.Status) }
            $j = $null; if ("$($r.Body)".Trim()) { $j = "$($r.Body)" | ConvertFrom-Json }
            foreach ($n in @(if ($j -and $j.PSObject.Properties['repositories']) { $j.repositories })) { if ("$n".Trim()) { $names.Add(("$n".Trim()).ToLowerInvariant()) } }
            $url = ''
            $lk = $null; try { if ($r.Headers) { $lk = $r.Headers['Link'] } } catch { $lk = $null }
            $lt = (@($lk) | Where-Object { $_ }) -join ','
            if ($lt -match '<([^>]+)>\s*;\s*rel="?next"?') { $nx = $Matches[1]; $url = if ($nx -match '^https://') { $nx } else { 'https://{0}{1}' -f $login, $nx } }
            if ($url -and -not $url.StartsWith(('https://{0}/' -f $login), [StringComparison]::OrdinalIgnoreCase)) { $url = '' }
            if ($url -and $p -eq 49) { throw 'the registry''s repository list did not end' }
        }
        $names.ToArray()
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
    @{ LoginServer = $login; List = $list; Manifest = $manifest; Delete = $delete; Catalog = $catalog }
}

function Invoke-SIUpdaterImagePrune {
    <#
        THE CLEAN-UP ITSELF -- ONLY WHAT RUNS STAYS (owner 2026-11-16, current only, no previous in any repository). Deletes
        from -Registry (New-SIUpdaterRegistrySeam, or a test's fake) every image of a repository the install records that is
        not run now: -Current (the read-back after a proven update: every job and app template, the active revisions, the
        pending self-update image) and -RunningRefs (every image a RUNNING execution started with), the base-layer images a
        kept image is built from, the children of a kept multi-platform image and the signatures / attestations of a kept
        image. Nothing at all when: -On is $false; -Healthy is $false (the update was not proven); -RegistryResourceGroup is
        not -InstallResourceGroup; -Current is not Ok (what runs was not read back); -RunningKnown is $false (the running
        executions were not read -- an image one of them uses could be lost). Every image kept and every image deleted is
        said in its own line, with its reason.
        Returns @{ Done; Reason; Repos (@{ Repo; Before; Kept; Deleted; Failed; Left; Pending; Line }); Lines }. Never throws.
        Left = the images listed at the last read-back; Pending = the deleted images the registry still listed then (its
        deletes complete after it answers them: the listing is read again a few times before that is said).
    #>
    param([bool]$On = $true, [bool]$Healthy, [Parameter(Mandatory)][hashtable]$Registry, $Current,
          [AllowEmptyString()][string]$RegistryResourceGroup = '', [AllowEmptyString()][string]$InstallResourceGroup = '',
          [scriptblock]$Beat, [scriptblock]$Log, [int]$BeatSeconds = 15, [scriptblock]$Sleep,
          # the images RUNNING executions started with (Get-SIUpdaterRunningExecutionRefs) and whether they were read:
          # not read = nothing is deleted (a running pipeline's image cannot be told apart from an old one)
          [object[]]$RunningRefs = @(), [bool]$RunningKnown = $false)
    # the read-back's pauses while the registry completes its deletes: three re-reads at most, 30 seconds in all per
    # repository (-Sleep { param($Seconds) } is the test seam)
    $settleWaits = @(5, 10, 15)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    # Live 2026-11-12 (internal, 3.1.12): the clean-up of a registry with hundreds of old images ran past 15 minutes without a
    # sign of life, and the pipeline's watchdog stopped the update as dead -- before one line was written. So -Beat
    # { param($What) } is called at every registry call (the update's own sign of life; the caller limits it to one a minute),
    # and -Log { param($Line) } writes every line the moment it is known (each repository's plan before its deletes, its
    # result right after), so a stopped clean-up still leaves what it did. A failure of either never stops the clean-up.
    $lines = New-Object System.Collections.Generic.List[string]
    $repos = New-Object System.Collections.Generic.List[object]
    $say = { param($l) $lines.Add($l); if ($Log) { try { $null = & $Log $l } catch { } } }
    # framework IMAGE-PRUNE CONTRACT point 4: a heartbeat at least once a minute, rate-limited -- a beat is TRIED at most once
    # per -BeatSeconds whatever its outcome (a failing beat is not retried at every registry call: with a slow or unreachable
    # database that would slow the clean-up to hours); 0 = at every registry call (tests)
    $beatAt = @{ t = [datetime]::MinValue }
    $tick = { param($w) if ($Beat) { $now = [datetime]::UtcNow; if ($BeatSeconds -le 0 -or ($now - $beatAt.t).TotalSeconds -ge $BeatSeconds) { $beatAt.t = $now; try { $null = & $Beat $w } catch { } } } }
    $none = { param($why) & $say $why; [pscustomobject]@{ Done = $false; Reason = $why; Repos = @(); Lines = $lines.ToArray() } }
    if (-not $On) { return (& $none 'old images: the clean-up is off (SI_Updater_ImagePrune = off) -- every image is kept') }
    if (-not $Healthy) { return (& $none 'old images: not cleaned up -- the update did not end healthy, so every image is kept') }
    if ("$RegistryResourceGroup".Trim() -and "$InstallResourceGroup".Trim() -and "$RegistryResourceGroup".Trim() -ine "$InstallResourceGroup".Trim()) {
        return (& $none 'old images: not cleaned up -- the registry is not in this install''s own resource group, so it may hold images of others; every image is kept')
    }
    if (-not $Current -or -not $Current.Ok -or -not @($Current.Refs).Count) { return (& $none ('old images: not cleaned up -- what the install runs now could not be read back ({0}); every image is kept' -f $(if ($Current) { $Current.Reason } else { 'not read' }))) }
    if (-not $RunningKnown) { return (& $none 'old images: not cleaned up -- the runs in progress could not be read, so an image one of them still uses could be lost; every image is kept') }
    # ONLY WHAT RUNS: every job and app template, the active revisions, the pending self-update image, and every image a
    # running execution started with -- in every repository (never an image of the release before)
    $keepRefs = @(@($Current.Refs) + @($RunningRefs) | Where-Object { $_ -and $_.Repo })
    # why each image is kept (digest -> reason) -- said with every kept and every deleted image
    $keepWhy = @{}
    $short ={ param($d) $x = "$d"; if ($x.Length -gt 19) { $x.Substring(0, 19) } else { $x } }
    $oneOff = @($script:SIImagePruneOneOffRepos)
    # a signature / attestation tag of a kept image (sha256-<hex>.sig / .att / ...): kept with it
    $sigOf = { param([string]$t) if ("$t" -match '^sha256-([0-9a-f]{64})(\..*)?$') { 'sha256:' + $Matches[1] } else { '' } }
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
        & $tick ('reading ' + $repo)
        try { $ls = & $Registry.List $repo } catch { & $say ('{0}: not cleaned up -- its images could not be listed ({1}); every image is kept' -f $repo, $_.Exception.Message); $layersKnown = $false; continue }
        if (-not $ls.Found) { continue }
        $mans = @($ls.Manifests)
        $byTag = @{}; foreach ($m in $mans) { foreach ($t in @($m.Tags)) { $byTag[[string]$t] = $m.Digest } }
        $keep = New-Object 'System.Collections.Generic.HashSet[string]'
        $missing = 0
        foreach ($r in @($keepRefs | Where-Object { [string]$_.Repo -eq $repo })) {
            $rw = 'runs: {0}' -f $(if ($r.PSObject.Properties['From'] -and "$($r.From)") { [string]$r.From } else { 'named by the install' })
            if ("$($r.Digest)") { $kd = ([string]$r.Digest).ToLowerInvariant(); $null = $keep.Add($kd); if (-not $keepWhy.ContainsKey($kd)) { $keepWhy[$kd] = $rw } }
            if ("$($r.Tag)") { if ($byTag.ContainsKey([string]$r.Tag)) { $kd = [string]$byTag[[string]$r.Tag]; $null = $keep.Add($kd); if (-not $keepWhy.ContainsKey($kd)) { $keepWhy[$kd] = $rw } } elseif (-not "$($r.Digest)") { $missing++ } }
        }
        # every kept image read: a multi-platform one keeps its children; its layers feed the base check. Unreadable = keep the repository.
        $unreadable = $false
        $children = New-Object 'System.Collections.Generic.HashSet[string]'   # contract point 5: kept images and child manifests apart
        foreach ($dg in @($keep)) {
            & $tick ('reading ' + $repo)
            $mf = & $Registry.Manifest $repo $dg
            $info = Get-SIUpdaterManifestLayers -Manifest $mf
            if ($info.Kind -eq 'index') {
                foreach ($c in @($info.Children)) {
                    if ($keep.Add($c)) { $null = $children.Add($c); $keepWhy[$c] = ('a platform image of the running {0}' -f (& $short $dg)) }
                    & $tick ('reading ' + $repo)
                    $ci = Get-SIUpdaterManifestLayers -Manifest (& $Registry.Manifest $repo $c)
                    if ($ci.Kind -eq 'image') { $keptLayers.Add(@($ci.Layers)) } else { $layersKnown = $false }
                }
            } elseif ($info.Kind -eq 'image') { $keptLayers.Add(@($info.Layers)) }
            elseif (@($mans | Where-Object { $_.Digest -eq $dg }).Count) { $unreadable = $true; $layersKnown = $false }
        }
        if ($unreadable) { & $say ('{0}: not cleaned up -- an image it runs could not be read; every image is kept' -f $repo); continue }
        # the signatures and attestations of a kept image stay with it (framework: the kept-image closure): a sha256-<digest>.*
        # tag of a kept digest, or an untagged manifest whose 'subject' is a kept image -- transitively. An untagged manifest
        # that cannot be read is kept (it cannot be proven unused). Tagged release images are not read (they name a release).
        $subjectOf = @{}
        foreach ($m in @($mans | Where-Object { -not $keep.Contains($_.Digest) })) {
            $sigTags = @(@($m.Tags) | ForEach-Object { & $sigOf ([string]$_) } | Where-Object { $_ })
            if ($sigTags.Count) { $subjectOf[[string]$m.Digest] = [string]$sigTags[0]; continue }
            if (@($m.Tags).Count) { continue }
            & $tick ('reading ' + $repo)
            $mf = & $Registry.Manifest $repo $m.Digest
            if (-not $mf) { $null = $keep.Add([string]$m.Digest); $keepWhy[[string]$m.Digest] = 'it could not be read, so it cannot be proven unused'; continue }
            $si = Get-SIUpdaterManifestLayers -Manifest $mf
            if ("$($si.Subject)") { $subjectOf[[string]$m.Digest] = [string]$si.Subject }
        }
        for ($grew = $true; $grew; ) {
            $grew = $false
            foreach ($k in @($subjectOf.Keys)) {
                if (-not $keep.Contains($k) -and $keep.Contains($subjectOf[$k])) { $null = $keep.Add($k); $keepWhy[$k] = ('a signature or attestation of the running {0}' -f (& $short $subjectOf[$k])); $grew = $true }
            }
        }
        $del = @($mans | Where-Object { -not $keep.Contains($_.Digest) })
        $plan.Add([pscustomobject]@{ Repo = $repo; Base = $false; Before = $mans.Count; Keep = @($mans | Where-Object { $keep.Contains($_.Digest) } | ForEach-Object { $_.Digest }); Delete = $del; Missing = $missing
                                     Children = @($mans | Where-Object { $children.Contains($_.Digest) }).Count; OneOff = ($oneOff -contains $repo) })
    }

    # SI's ONE-OFF REPOSITORIES that nothing runs (Invardia's central image scan 2026-11-14: si-management-probe images of a
    # vendor proof, never removed, carried critical findings): every image in them goes -- the running executions were read
    # (checked above: a proof running now keeps its image, through the repositories above), and only in this install's own
    # registry (checked above)
    foreach ($repo in @($oneOff | Where-Object { $appRepos -notcontains $_ })) {
        $ls = $null
        & $tick ('reading ' + $repo)
        try { $ls = & $Registry.List $repo } catch { & $say ('{0}: not cleaned up -- its images could not be listed ({1}); every image is kept' -f $repo, $_.Exception.Message); continue }
        if (-not $ls -or -not $ls.Found -or -not @($ls.Manifests).Count) { continue }
        $mans = @($ls.Manifests)
        $plan.Add([pscustomobject]@{ Repo = $repo; Base = $false; Before = $mans.Count; Keep = @(); Delete = $mans; Missing = 0; Children = 0; OneOff = $true })
    }

    # THE REPOSITORIES SI CREATED THAT NOTHING RUNS FROM ANY MORE (framework IMAGE-PRUNE point 3, Invardia 2026-11-16): the
    # WHOLE registry is listed, and every repository on SI's own list ($script:SIImagePruneOwnRepos, exact names) that no job,
    # app, active revision or run in progress names is emptied -- e.g. signin-front at an install on the built-in sign-in. A
    # base-layer repository goes through the base check below (a base a running image is built from stays). A repository not
    # on the list is never touched. The list cannot be read = nothing is deleted from a repository nothing runs, said once.
    # (-Registry without a Catalog -- an older seam -- = this part is left out.)
    $abandoned = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($Registry.ContainsKey('Catalog') -and $Registry.Catalog) {
        $all = $null
        & $tick 'reading the list of repositories'
        try { $all = @(& $Registry.Catalog) } catch { & $say ('old images: the registry''s repositories could not be listed ({0}) -- nothing is deleted from repositories nothing runs; the next update tries again' -f $_.Exception.Message); $all = $null }
        if ($null -ne $all) {
            $handled = @(@($appRepos) + @($baseRepos) + @($oneOff) | ForEach-Object { "$_".ToLowerInvariant() })
            $own = @($script:SIImagePruneOwnRepos | ForEach-Object { "$_".ToLowerInvariant() })
            foreach ($repo in @($all | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)) {
                if ($own -notcontains $repo -or $handled -contains $repo) { continue }
                if (@($keepRefs | Where-Object { [string]$_.Repo -eq $repo }).Count) { continue }   # (never: named = handled above)
                $null = $abandoned.Add($repo)
                if ($repo -like '*-base') { $baseRepos += $repo; continue }
                $ls = $null
                & $tick ('reading ' + $repo)
                try { $ls = & $Registry.List $repo } catch { & $say ('{0}: not cleaned up -- its images could not be listed ({1}); every image is kept' -f $repo, $_.Exception.Message); continue }
                if (-not $ls -or -not $ls.Found -or -not @($ls.Manifests).Count) { continue }
                $mans = @($ls.Manifests)
                $plan.Add([pscustomobject]@{ Repo = $repo; Base = $false; Before = $mans.Count; Keep = @(); Delete = $mans; Missing = 0; Children = 0; OneOff = $false; Abandoned = $true })
            }
        }
    }

    foreach ($repo in $baseRepos) {
        $ls = $null
        & $tick ('reading ' + $repo)
        try { $ls = & $Registry.List $repo } catch { & $say ('{0}: not cleaned up -- its images could not be listed ({1}); every image is kept' -f $repo, $_.Exception.Message); continue }
        if (-not $ls.Found -or -not @($ls.Manifests).Count) { continue }
        $mans = @($ls.Manifests)
        if (-not $layersKnown -or -not $keptLayers.Count) { & $say ('{0}: not cleaned up -- the layers of the images it may serve could not all be read; every image is kept' -f $repo); continue }
        $keep = New-Object 'System.Collections.Generic.HashSet[string]'
        $byTag = @{}; foreach ($m in $mans) { foreach ($t in @($m.Tags)) { $byTag[[string]$t] = $m.Digest } }
        foreach ($r in @($keepRefs | Where-Object { [string]$_.Repo -eq $repo })) {
            $rw = 'runs: {0}' -f $(if ($r.PSObject.Properties['From'] -and "$($r.From)") { [string]$r.From } else { 'named by the install' })
            if ("$($r.Digest)") { $kd = ([string]$r.Digest).ToLowerInvariant(); $null = $keep.Add($kd); if (-not $keepWhy.ContainsKey($kd)) { $keepWhy[$kd] = $rw } }
            if ("$($r.Tag)" -and $byTag.ContainsKey([string]$r.Tag)) { $kd = [string]$byTag[[string]$r.Tag]; $null = $keep.Add($kd); if (-not $keepWhy.ContainsKey($kd)) { $keepWhy[$kd] = $rw } }
        }
        $subjectOf = @{}
        foreach ($m in $mans) {
            if ($keep.Contains($m.Digest)) { continue }
            $sigTags = @(@($m.Tags) | ForEach-Object { & $sigOf ([string]$_) } | Where-Object { $_ })
            if ($sigTags.Count) { $subjectOf[[string]$m.Digest] = [string]$sigTags[0]; continue }
            & $tick ('reading ' + $repo)
            $info = Get-SIUpdaterManifestLayers -Manifest (& $Registry.Manifest $repo $m.Digest)
            if ("$($info.Subject)") { $subjectOf[[string]$m.Digest] = [string]$info.Subject; continue }   # a signature / attestation: kept with its image
            if ($info.Kind -ne 'image' -or -not @($info.Layers).Count) { $null = $keep.Add($m.Digest); $keepWhy[[string]$m.Digest] = 'its layers could not be read, so it cannot be proven unused'; continue }   # cannot be proven unused
            foreach ($kl in $keptLayers) { if (Test-SIUpdaterLayerPrefix -Base @($info.Layers) -Image @($kl)) { $null = $keep.Add($m.Digest); $keepWhy[[string]$m.Digest] = 'the base layers a running image is built on'; break } }
        }
        for ($grew = $true; $grew; ) {
            $grew = $false
            foreach ($k in @($subjectOf.Keys)) {
                if (-not $keep.Contains($k) -and $keep.Contains($subjectOf[$k])) { $null = $keep.Add($k); $keepWhy[$k] = ('a signature or attestation of the kept {0}' -f (& $short $subjectOf[$k])); $grew = $true }
            }
        }
        $del = @($mans | Where-Object { -not $keep.Contains($_.Digest) })
        $plan.Add([pscustomobject]@{ Repo = $repo; Base = $true; Before = $mans.Count; Keep = @($mans | Where-Object { $keep.Contains($_.Digest) } | ForEach-Object { $_.Digest }); Delete = $del; Missing = 0; Children = 0; Abandoned = $abandoned.Contains($repo) })
    }

    foreach ($p in $plan) {
        $deleted = 0; $failed = 0; $locked = 0; $why = ''
        $okDel = New-Object System.Collections.Generic.List[string]   # the digests the registry took as deleted
        # the plan, said BEFORE the deletes (written at once through -Log; not one of the result lines)
        $kids = if ($p.Children) { (' ({0} of them child manifests of multi-platform images)' -f $p.Children) } else { '' }
        if ($Log) { try { $null = & $Log ("{0}: {1} {2}, {3} kept{4}, {5} to delete" -f $p.Repo, $p.Before, $(if ($p.Base) { "base images" } else { "images" }), @($p.Keep).Count, $kids, @($p.Delete).Count) } catch { } }
        # every kept image in its own line, with its reason (written at once)
        if ($Log) { foreach ($k in @($p.Keep)) { try { $null = & $Log ('{0}@{1}: kept -- {2}' -f $p.Repo, (& $short $k), $(if ($keepWhy.ContainsKey([string]$k)) { $keepWhy[[string]$k] } else { 'named by the install' })) } catch { } } }
        $n = 0; $deletable = @($p.Delete | Where-Object { $_.DeleteEnabled }).Count
        foreach ($m in @($p.Delete)) {
            $tagText = if (@($m.Tags).Count) { ' (' + ((@($m.Tags) | Select-Object -First 3) -join ', ') + ')' } else { '' }
            if (-not $m.DeleteEnabled) {
                $locked++
                if ($Log) { try { $null = & $Log ('{0}@{1}{2}: kept -- it is locked against deletion' -f $p.Repo, (& $short $m.Digest), $tagText) } catch { } }
                continue
            }
            $n++; & $tick ("deleting {0} ({1} of {2})" -f $p.Repo, $n, $deletable)
            $d = & $Registry.Delete $p.Repo $m.Digest
            if ($d -and $d.Ok) { $deleted++; $okDel.Add([string]$m.Digest) } else { $failed++; if (-not $why -and $d) { $why = [string]$d.Why } }
            if ($Log) {
                $dl = if ($d -and $d.Ok) { $(if ($p.PSObject.Properties['Abandoned'] -and $p.Abandoned -and -not $p.Base) { '{0}@{1}{2}: deleted -- nothing runs from this repository any more' } elseif ($p.OneOff) { '{0}@{1}{2}: deleted -- a one-off proof image, nothing runs it' } elseif ($p.Base) { '{0}@{1}{2}: deleted -- no running image is built on it' } else { '{0}@{1}{2}: deleted -- no job, app, active revision or running execution uses it' }) -f $p.Repo, (& $short $m.Digest), $tagText }
                      else { '{0}@{1}{2}: kept -- the delete failed ({3}); the next update tries again' -f $p.Repo, (& $short $m.Digest), $tagText, $(if ($d) { [string]$d.Why } else { 'no answer' }) }
                try { $null = & $Log $dl } catch { }
            }
        }
        # the read-back: what is left, and that every kept image is still there. The registry completes a delete AFTER it
        # answers it (live 2026-11-13: "3 left" right after the deletes, 2 a moment later), so while an image it took as
        # deleted is still listed the listing is read again, a few times with short pauses (each a sign of life); still
        # listed after the last one = said as deletes still completing, with the count seen.
        $left = -1; $lost = 0; $pending = 0; $read = 0
        for ($try = 0; ; $try++) {
            & $tick ('reading ' + $p.Repo)
            try {
                $after = & $Registry.List $p.Repo
                $am = @(if ($after.Found) { $after.Manifests })
                $have = @{}; foreach ($m in $am) { $have[$m.Digest] = $true }
                $left = $am.Count; $read++
                $lost = 0; foreach ($k in @($p.Keep)) { if (-not $have.ContainsKey($k)) { $lost++ } }
                $pending = 0; foreach ($k in $okDel) { if ($have.ContainsKey($k)) { $pending++ } }
            } catch { break }   # a re-read that fails keeps what the read before it saw (none = could not be read back)
            if ($pending -eq 0 -or $try -ge $settleWaits.Count) { break }
            & $tick ('waiting for the deletes of {0} to complete' -f $p.Repo)
            try { & $Sleep $settleWaits[$try] } catch { }
        }
        $what = if ($p.Base) { 'base images' } else { 'images' }
        $gone = [bool]($p.PSObject.Properties['Abandoned'] -and $p.Abandoned -and -not @($p.Keep).Count)
        $line = if ($gone) {
                    ('{0}: nothing runs from it any more, {1} images deleted' -f $p.Repo, $deleted) + $(if ($read -eq 0) { '; what is left could not be read back' } elseif ($pending) { ('; {0} still listed right after -- deletes still completing' -f $left) } elseif ($left -gt 0) { ('; {0} left' -f $left) } else { '' })
                } elseif ($read -eq 0) { ('{0}: {1} old {2} deleted; what is left could not be read back' -f $p.Repo, $deleted, $what) }
                elseif ($pending) { ('{0}: {1} old {2} deleted, {3} listed right after -- deletes still completing ({4} of the deleted images still listed; the registry removes them shortly)' -f $p.Repo, $deleted, $what, $left, $pending) }
                else { ('{0}: {1} old {2} deleted, {3} left ({4})' -f $p.Repo, $deleted, $what, $left, $(if ($p.Base) { 'the base layers of what runs' } else { 'what runs' })) }
        if ($failed) { $line += ('; {0} could not be deleted ({1}) -- kept, the next update tries again' -f $failed, $(if ($why) { $why } else { 'no answer' })) }
        if ($locked) { $line += ('; {0} locked against deletion -- kept' -f $locked) }
        if ($lost) { $line += ('; WARNING: {0} image(s) that should be kept are not there any more' -f $lost) }
        & $say $line
        $repos.Add([pscustomobject]@{ Repo = $p.Repo; Base = $p.Base; Before = $p.Before; Kept = @($p.Keep).Count; Children = [int]$p.Children; Deleted = $deleted; Failed = $failed; Left = $left; Pending = $pending; Line = $line })
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
        before the roll (Get-SIUpdaterImageSnapshot; the release record's history only -- it keeps nothing); -Healthy: the
        update and its read-back ended well. Reads the setting, the registry (Get-SIUpdaterRegistry), what runs now, the
        runs in progress, and the release record (-ReadSecret / -WriteSecret: the update client's Key Vault seams); writes
        the release record BEFORE the first delete; prunes to what runs (Invoke-SIUpdaterImagePrune); writes the record
        again with what was done and, with -Store, the cfg.InstallState 'ImagePrune' row; one log line per repository and
        per image. -Registry / -After / -RunningRefs: test seams. Never throws; returns the clean-up result (or $null when
        nothing could be started).
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [bool]$Healthy, $Before, [AllowEmptyString()][string]$Version = '', [AllowEmptyString()][string]$PreviousVersion = '',
          [string]$UpdaterJob = 'caj-si-updater', [scriptblock]$Get, [scriptblock]$ReadSecret, [scriptblock]$WriteSecret, $Store,
          [hashtable]$Registry, $After, [scriptblock]$Beat,
          # the images RUNNING executions started with (test seam; default read here -- unreadable = nothing is deleted)
          $RunningRefs)
    try {
        # the update's sign of life during the clean-up (Invoke-SIUpdaterLockBeat: at most one beat a minute); every line written at once
        # (-MinSeconds 30 + the clean-up's own 15-second try limit: a beat at most ~45 s apart -- the contract's once a minute)
        if (-not $Beat -and (Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue)) { $Beat = { param($w) $null = Invoke-SIUpdaterLockBeat -What ("old images: " + $w) -MinSeconds 30 } }
        $logLine = { param($l) Write-UpdLog $l }
        $mode = Get-SIUpdaterImagePruneMode -Value (Get-SIUpdaterImagePruneSetting -Get $Get)
        if (-not $mode.On) { Write-UpdLog ('old images: the clean-up is {0} -- every image is kept' -f $mode.Reason); return $null }
        if (-not $Healthy) { Write-UpdLog 'old images: not cleaned up -- the update did not end healthy, so every image is kept'; return $null }
        $acr = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $login = [string]$acr.loginServer
        if (-not $After) { $After = Get-SIUpdaterImageSnapshot -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -LoginServer $login -UpdaterJob $UpdaterJob }
        $runKnown = $true
        if ($null -eq $RunningRefs) {
            try { $RunningRefs = @(Get-SIUpdaterRunningExecutionRefs -Jobs @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) -LoginServer $login `
                      -Executions { param($n) @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/{0}/executions' -f $n)) -List) }) }
            catch { $RunningRefs = @(); $runKnown = $false }
        }
        $rec = $null
        if ($ReadSecret) { try { $rec = ConvertFrom-SIUpdaterReleaseImageRecord -Json ([string](& $ReadSecret $script:SIImagePruneRecordSecret)) } catch { $rec = $null } }
        # THE SAME RELEASE AGAIN (the updater's second pass after its self-roll, a re-run of the release already recorded):
        # what ran "before" this run is this release itself. The release record's 'previous' is HISTORY only (owner
        # 2026-11-16: current only) -- it keeps no image; only what runs now is kept.
        $sameRelease = Test-SIUpdaterSameRelease -Record $rec -Version $Version -Before $Before -After $After
        if (-not $Registry) { $Registry = New-SIUpdaterRegistrySeam -LoginServer $login -Rest (Get-SIUpdaterRest) -Beat $Beat }
        # the release record: written only from what was read back after a healthy update; the same release again keeps the
        # record's previous release as it is -- never this release as its own previous
        $prevRefs = @(); $prevVer = ''
        if ($sameRelease) {
            $prevRefs = @(if ($rec) { @($rec.Previous) })
            $prevVer = if ($rec) { [string]$rec.PreviousVersion } else { '' }
        } else {
            $prevRefs = @(if ($Before -and $Before.Ok) { @($Before.Refs) } elseif ($rec) { @($rec.Current) })
            $prevVer = if ("$PreviousVersion".Trim()) { $PreviousVersion } elseif ($rec) { $rec.CurrentVersion } else { '' }
        }
        $canRecord = [bool]($After -and $After.Ok)
        # framework IMAGE-PRUNE CONTRACT point 5: the release record is written BEFORE the first delete. A record that cannot
        # be written (or no place to write it) = NOTHING is deleted this time, said once; the next update tries again.
        $recWritten = $false
        if ($canRecord -and $WriteSecret) {
            try { $null = & $WriteSecret $script:SIImagePruneRecordSecret (ConvertTo-SIUpdaterReleaseImageRecord -Version $Version -Current @($After.Refs) -PreviousVersion $prevVer -Previous $prevRefs -Result $null); $recWritten = $true }
            catch { Write-UpdLog ('old images: not cleaned up -- the release record could not be written before the deletes ({0}); every image is kept, the next update tries again' -f $_.Exception.Message) }
        } elseif ($canRecord) {
            Write-UpdLog 'old images: not cleaned up -- there is no place to write the release record before the deletes; every image is kept'
        }
        if ($canRecord -and -not $recWritten) {
            $res = [pscustomobject]@{ Done = $false; Reason = 'old images: not cleaned up -- the release record was not written before the deletes'; Repos = @(); Lines = @('old images: not cleaned up -- the release record was not written before the deletes') }
        } else {
            # (what runs now not read back, or the runs in progress not read: the clean-up itself refuses and says so --
            # nothing is deleted)
            $res = Invoke-SIUpdaterImagePrune -On $true -Healthy $Healthy -Registry $Registry -Current $After `
                       -RegistryResourceGroup ([string]$acr.resourceGroup) -InstallResourceGroup $ResourceGroup -Beat $Beat -Log $logLine -RunningRefs @($RunningRefs) -RunningKnown $runKnown
            if ($res.Done) { Write-UpdLog $res.Reason }
            # the record again, now with what the clean-up did (best effort: the record before the deletes is already there)
            if ($recWritten) {
                try { $null = & $WriteSecret $script:SIImagePruneRecordSecret (ConvertTo-SIUpdaterReleaseImageRecord -Version $Version -Current @($After.Refs) -PreviousVersion $prevVer -Previous $prevRefs -Result $res) }
                catch { Write-UpdLog ('NOTE: old images: what the clean-up did could not be added to the release record ({0}) -- the record written before the deletes stands' -f $_.Exception.Message) }
            }
        }
        if ($Store -and (Get-Command -Name Save-SIUpdaterInstallStateValue -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterInstallStateValue -Store $Store -Name 'ImagePrune' -Value (ConvertTo-SIUpdaterImagePruneValue -Result $res) }
        $res
    } catch { Write-UpdLog ('WARNING: old images: not cleaned up this time ({0}) -- every image is kept; the next update tries again' -f $_.Exception.Message); $null }
}

# ---- THE CLEAN-UP SWITCH CLEARS ITSELF (framework SEC-LANE-1, owner 2026-11-14: "things must work automatically"; his
# decision (4): "their image clean-up turned on once 3.1.16+ reads back"). Some installs had SI_UPDATER_IMAGE_PRUNE=off set on
# the updater job by hand while the clean-up was being proven (IMAGE-PRUNE CONTRACT point 8). Once the updater runs a release
# whose clean-up is proven (3.1.14 or later), it takes that 'off' away from its OWN job itself -- nobody does it by hand again.
$script:SIImagePruneSwitchVar = 'SI_UPDATER_IMAGE_PRUNE'
$script:SIImagePruneSwitchFrom = '3.1.14'

function Test-SIUpdaterPruneSwitchOff {
    <# PURE. Is the job (ARM shape) switched off by SI_UPDATER_IMAGE_PRUNE = off / false / no / 0 on any of its containers? #>
    param($Job)
    if (-not $Job) { return $false }
    foreach ($c in @($Job.properties.template.containers)) {
        foreach ($e in @($c.env)) { if ($e -and "$($e.name)" -eq $script:SIImagePruneSwitchVar -and "$($e.value)".Trim() -match '^(?i)(off|false|no|0)$') { return $true } }
    }
    $false
}

function New-SIUpdaterPruneSwitchClearBody {
    <# PURE. The ARM PATCH body of the job's OWN template (as read) without SI_UPDATER_IMAGE_PRUNE on any container -- nothing
       else changed; never the configuration (secrets come back without values). Read-only fields left out. JSON text. #>
    param([Parameter(Mandatory)]$Job)
    $tpl = ConvertTo-Json -InputObject $Job.properties.template -Depth 60 | ConvertFrom-Json
    foreach ($c in (@($tpl.containers) + @($tpl.initContainers))) {
        if (-not $c) { continue }
        if ($c.PSObject.Properties['env']) { $c.env = @(@($c.env) | Where-Object { $_ -and "$($_.name)" -ne $script:SIImagePruneSwitchVar }) }
        if ($c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
        if ($c.PSObject.Properties['resources'] -and $c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    ConvertTo-Json -InputObject ([ordered]@{ properties = [ordered]@{ template = $tpl } }) -Depth 60 -Compress
}

function Invoke-SIUpdaterPruneSwitchClear {
    <#
        Every update run (not an apply-settings run): the updater's OWN job (-JobName) read; SI_UPDATER_IMAGE_PRUNE = off on it
        and this updater runs -Version 3.1.14 or later = the variable is taken away from the job's template (ONE ARM PATCH,
        nothing else changed) and READ BACK, and this run's own environment drops it too (the clean-up is on from here on).
        One line when it changes, nothing when there is nothing to do. An older updater, or the setting from the
        configuration (SI_Updater_ImagePrune), is never touched. Never throws, never fails the run.
        -Arm { param($Method, $Path, $Body) }: the test seam (default the updater's ARM seam). Returns @{ Action; Line } or $null.
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$JobName, [AllowEmptyString()][string]$Version = '', [scriptblock]$Arm)
    try {
        $v = $null; $from = [version]$script:SIImagePruneSwitchFrom
        $p = @("$Version".Trim().Split('.') | Where-Object { $_ -ne '' })
        if ($p.Count -ge 3 -and -not @($p | Where-Object { $_ -notmatch '^\d{1,9}$' }).Count) { $v = [version]('{0}.{1}.{2}' -f $p[0], $p[1], $p[2]) }
        if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) Invoke-SIUpdaterArm -Method $Method -Path $Path -Body $Body -AllowNotFound:($Method -eq 'GET') } }
        $path = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/' + $JobName)
        $job = & $Arm 'GET' $path $null
        if (-not (Test-SIUpdaterPruneSwitchOff -Job $job)) { return $null }
        if ($null -eq $v -or $v -lt $from) { return $null }
        $null = & $Arm 'PATCH' $path (New-SIUpdaterPruneSwitchClearBody -Job $job)
        $back = & $Arm 'GET' $path $null
        if (Test-SIUpdaterPruneSwitchOff -Job $back) {
            $l = ('WARNING: old images: {0}=off is still on the updater job after it was taken away -- the clean-up stays off; the next update tries again' -f $script:SIImagePruneSwitchVar)
            Write-UpdLog $l; return [pscustomobject]@{ Action = 'unconfirmed'; Line = $l }
        }
        if ($Env.ContainsKey($script:SIImagePruneSwitchVar)) { $Env.Remove($script:SIImagePruneSwitchVar) }
        [Environment]::SetEnvironmentVariable($script:SIImagePruneSwitchVar, $null, 'Process')
        $l = ('old images: the clean-up switch {0}=off is taken away from the updater job by itself (this updater runs {1}, {2} or later; read back) -- the clean-up of old images is on from now on' -f $script:SIImagePruneSwitchVar, "$Version".Trim(), $script:SIImagePruneSwitchFrom)
        Write-UpdLog $l
        [pscustomobject]@{ Action = 'cleared'; Line = $l }
    } catch {
        $l = ('WARNING: old images: the clean-up switch on the updater job could not be checked ({0}) -- the next update tries again' -f $_.Exception.Message)
        try { Write-UpdLog $l } catch { }
        [pscustomobject]@{ Action = 'failed'; Line = $l }
    }
}

# ---- framework SEC-LANE-1: AFTER A PROVEN IMAGE-ONLY SWAP, ONLY WHAT RUNS STAYS (owner 2026-11-14: "i prefer we dont leave any
# old version out there as it makes noise in defender" / "when swap works we remove old"; 2026-11-16: current only). The short
# image-only path (SI-UpdaterImageOnly.ps1) records a PENDING clean-up when every part of the swap read back healthy, and a
# LATER updater run deletes only once the swap is PROVEN (framework IMAGE-PRUNE amendment, Invardia 2026-11-14: a job
# SUCCEEDED on the new image -- a healthy read-back is not enough); a swap that is not proven never gets here, so nothing is
# deleted until it is. What runs = every job's and app's template image, every ACTIVE revision, the pending self-update image,
# AND every image a RUNNING execution started with (a running pipeline keeps its image: a replica it restarts must still find
# it). Each kept and each deleted image is said in its own line with its reason.

function Get-SIUpdaterRunningExecutionRefs {
    <# The images RUNNING executions of the install's jobs started with (-Jobs: ARM shape; -Executions { param($JobName) } ->
       the job's executions, ARM shape) as refs of -LoginServer's registry (@{ Repo; Tag; Digest; From }). Running = status
       Running / Processing with no end. A job whose executions cannot be read: THROWS (nothing may be deleted then). #>
    param([object[]]$Jobs = @(), [Parameter(Mandatory)][scriptblock]$Executions, [Parameter(Mandatory)][string]$LoginServer)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($j in @($Jobs)) {
        if (-not $j -or -not "$($j.name)") { continue }
        foreach ($e in @(& $Executions ([string]$j.name))) {
            if (-not $e) { continue }
            $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
            if ("$($p.status)" -notin @('Running', 'Processing')) { continue }
            if ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim()) { continue }
            foreach ($img in @(Get-SIUpdaterResourceImages -Resource $e)) {
                $r = ConvertTo-SIUpdaterImageRef -Image $img -LoginServer $LoginServer
                if ($r) { $r | Add-Member -NotePropertyName From -NotePropertyValue ('{0} (running execution {1})' -f $j.name, $e.name) -Force; $out.Add($r) }
            }
        }
    }
    $out.ToArray()
}

function Invoke-SIUpdaterImageOnlyCleanup {
    <#
        THE CLEAN-UP AFTER A PROVEN IMAGE-ONLY SWAP (Invoke-SIUpdaterImageOnlyPendingPrune calls it). -Healthy: the swap is proven
        (Test-SIUpdaterImageOnlySwapProven); $false = nothing is deleted, said. Only what runs stays (as after a full update):
        every job and app template, the active revisions, the pending self-update image and every image a running execution
        started with; the runs in progress not readable = nothing is deleted. The switch SI_Updater_ImagePrune (off = nothing
        deleted) and the contract's other limits (only the install's own registry, in its own resource group; a read that
        fails keeps everything) hold as for the full update. The release record (Key Vault SI-Release-Images) is written
        BEFORE the first delete when -WriteSecret is given (not written = nothing deleted); without -WriteSecret there is no
        place to write it, so nothing is deleted. The cfg.InstallState 'ImagePrune' row is written. -Registry / -After /
        -RunningRefs: test seams. Never throws; returns the clean-up result or $null.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [bool]$Healthy, [string]$UpdaterJob = 'caj-si-updater', [scriptblock]$Get, $Store, [hashtable]$Registry, $After, $RunningRefs, [scriptblock]$Beat,
          [string]$RegistryResourceGroup = '', [AllowEmptyString()][string]$Version = '', [scriptblock]$ReadSecret, [scriptblock]$WriteSecret)
    try {
        if (-not $Beat -and (Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue)) { $Beat = { param($w) $null = Invoke-SIUpdaterLockBeat -What ("old images: " + $w) -MinSeconds 30 } }
        $mode = Get-SIUpdaterImagePruneMode -Value (Get-SIUpdaterImagePruneSetting -Get $Get)
        if (-not $mode.On) { Write-UpdLog ('old images: the clean-up is {0} -- every image is kept' -f $mode.Reason); return $null }
        if (-not $Healthy) { Write-UpdLog 'old images: not cleaned up -- the image-only swap is not proven yet, so nothing is deleted'; return $null }
        $login = ''; $regRg = $RegistryResourceGroup
        if (-not $Registry -or -not $After -or $null -eq $RunningRefs) {
            $acr = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
            $login = [string]$acr.loginServer; $regRg = [string]$acr.resourceGroup
        }
        if (-not $After) { $After = Get-SIUpdaterImageSnapshot -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -LoginServer $login -UpdaterJob $UpdaterJob }
        # the runs in progress: not readable = nothing is deleted (the clean-up itself refuses and says so)
        $runKnown = $true
        if ($null -eq $RunningRefs) {
            try { $RunningRefs = @(Get-SIUpdaterRunningExecutionRefs -Jobs @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) -LoginServer $login `
                      -Executions { param($n) @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/{0}/executions' -f $n)) -List) }) }
            catch { $RunningRefs = @(); $runKnown = $false }
        }
        if (-not $Registry) { $Registry = New-SIUpdaterRegistrySeam -LoginServer $login -Rest (Get-SIUpdaterRest) -Beat $Beat }
        # framework IMAGE-PRUNE CONTRACT point 5: the release record BEFORE the first delete (what runs now; the release before
        # it as history only -- it keeps nothing). Not written = nothing is deleted this time, said once.
        if ($After -and $After.Ok) {
            if (-not $WriteSecret) {
                Write-UpdLog 'old images: not cleaned up -- there is no place to write the release record before the deletes; every image is kept'
                return [pscustomobject]@{ Done = $false; Reason = 'old images: not cleaned up -- the release record was not written before the deletes'; Repos = @(); Lines = @('old images: not cleaned up -- the release record was not written before the deletes') }
            }
            $rec = $null
            if ($ReadSecret) { try { $rec = ConvertFrom-SIUpdaterReleaseImageRecord -Json ([string](& $ReadSecret $script:SIImagePruneRecordSecret)) } catch { $rec = $null } }
            $same = [bool]($rec -and "$Version".Trim() -and "$($rec.CurrentVersion)".Trim() -eq "$Version".Trim())
            $prevVer = if ($same) { [string]$rec.PreviousVersion } elseif ($rec) { [string]$rec.CurrentVersion } else { '' }
            $prevRefs = @(if ($same) { @($rec.Previous) } elseif ($rec) { @($rec.Current) })
            try { $null = & $WriteSecret $script:SIImagePruneRecordSecret (ConvertTo-SIUpdaterReleaseImageRecord -Version $Version -Current @($After.Refs) -PreviousVersion $prevVer -Previous $prevRefs -Result $null) }
            catch {
                Write-UpdLog ('old images: not cleaned up -- the release record could not be written before the deletes ({0}); every image is kept, the next update tries again' -f $_.Exception.Message)
                return [pscustomobject]@{ Done = $false; Reason = 'old images: not cleaned up -- the release record was not written before the deletes'; Repos = @(); Lines = @('old images: not cleaned up -- the release record was not written before the deletes') }
            }
        }
        if ($runKnown) { Write-UpdLog ('old images: the image-only swap is proven (a job succeeded on the new image) -- only what runs is kept ({0} image(s) of runs in progress among it)' -f @($RunningRefs).Count) }
        $res = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $Registry -Current $After -RunningRefs @($RunningRefs) -RunningKnown $runKnown `
                   -RegistryResourceGroup $regRg -InstallResourceGroup $ResourceGroup -Beat $Beat -Log { param($l) Write-UpdLog $l }
        if ($res.Done) { Write-UpdLog $res.Reason }
        if ($Store -and (Get-Command -Name Save-SIUpdaterInstallStateValue -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterInstallStateValue -Store $Store -Name 'ImagePrune' -Value (ConvertTo-SIUpdaterImagePruneValue -Result $res) }
        $res
    } catch { Write-UpdLog ('WARNING: old images: not cleaned up this time ({0}) -- every image is kept; the next update tries again' -f $_.Exception.Message); $null }
}

# ---- THE PENDING CLEAN-UP OF AN IMAGE-ONLY SWAP (framework IMAGE-PRUNE amendment, Invardia 2026-11-14): "the previous image is
# deleted only AFTER A JOB HAS SUCCEEDED ON THE NEW IMAGE". At the swap NOTHING is deleted: the swap is recorded in
# cfg.InstallState 'ImageOnlyPrunePending' { version, swappedUtc, digest (the engine jobs' new image), apps }. A LATER updater
# run (any: the nightly one, an update now) proves it first -- PER IMAGE: at least one job on that digest has an execution that SUCCEEDED,
# STARTED AFTER the swap, ON that digest, and the newest finished run on it (any job) did not fail; the web app / MCP newest revision is
# Healthy and Running -- and only then deletes as the clean-up of a proven swap (only what runs stays), and clears the record.
# Not proven = everything kept, one line naming what has no successful run yet; a failed run on the new image = kept, said (the
# swap is not proven); unreadable = not proven = kept. No job on the digest any more (a later release moved them)
# = the record is cleared, nothing deleted by it.
$script:SIImageOnlyPendingName = 'ImageOnlyPrunePending'

function ConvertTo-SIUpdaterImageOnlyPendingValue {
    <# PURE. The pending record (at most 400 characters): { version, swappedUtc, digest, apps }. #>
    param([AllowEmptyString()][string]$Version = '', [Parameter(Mandatory)][datetime]$SwappedUtc, [AllowEmptyString()][string]$Digest = '', [string[]]$Apps = @())
    $a = @(@($Apps) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
    while ($true) {
        $j = [ordered]@{ version = "$Version"; swappedUtc = $SwappedUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); digest = "$Digest"; apps = @($a) } | ConvertTo-Json -Compress
        if ($j.Length -le 400 -or -not $a.Count) { return $j }
        $a = @($a | Select-Object -First ($a.Count - 1))
    }
}

function ConvertFrom-SIUpdaterImageOnlyPendingValue {
    <# PURE. The record -> @{ Version; SwappedUtc ([datetime] UTC); Digest; Apps }, $null when it is not one. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if (-not "$Json".Trim()) { return $null }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    $at = $null
    try { $at = if ($o.swappedUtc -is [datetime]) { ([datetime]$o.swappedUtc).ToUniversalTime() } else { [datetime]::Parse([string]$o.swappedUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } } catch { return $null }
    $d = "$($o.digest)".Trim().ToLowerInvariant()
    if ($d -and $d -notmatch '^sha256:[0-9a-f]{64}$') { return $null }
    [pscustomobject]@{ Version = "$($o.version)"; SwappedUtc = $at; Digest = $d; Apps = @(@($o.apps) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) }
}

function Get-SIUpdaterImageOnlySwapDigest {
    <# PURE. The engine jobs' new image digest from what runs after the swap (Get-SIUpdaterImageSnapshot): the si-orchestrator
       digest the jobs are pinned to ('' when none or more than one -- then there is nothing to prove a run on). #>
    param($After)
    $d = @(@(if ($After) { $After.Refs }) | Where-Object { $_ -and [string]$_.Repo -eq 'si-orchestrator' -and "$($_.Digest)" } | ForEach-Object { ([string]$_.Digest).ToLowerInvariant() } | Select-Object -Unique)
    if ($d.Count -eq 1) { return $d[0] }
    ''
}

function Test-SIUpdaterImageOnlySwapProven {
    <#
        PURE (after the reads it is given). Is the recorded swap (-Pending) proven by what ran since?
          -Jobs        the install's jobs (ARM shape) -- the swapped ones are those whose template image is pinned to Pending.Digest
          -Executions  { param($JobName) } -> the job's executions (ARM shape); a throw = not readable = not proven
          -GetApp      { param($Name) } -> the container app (ARM shape) or $null (removed: nothing to prove)
          -GetRevision { param($App, $Revision) } -> the revision (ARM shape); a throw = not proven
        PER IMAGE (Invardia: "after A job has SUCCEEDED on the new image"): over every job on that digest, the executions STARTED AFTER
        the swap ON the digest and finished -- at least one Succeeded, and the newest of them all not Failed / Stopped (that one keeps
        the previous image, named by job and execution); none succeeded yet = waiting. Per app: its newest revision Healthy and Running.
        No digest recorded = not proven. Returns @{ Proven; Superseded (no job runs the digest any more); Waiting; Failed;
        Unreadable; Line }.
    #>
    param([Parameter(Mandatory)]$Pending, [object[]]$Jobs = @(), [Parameter(Mandatory)][scriptblock]$Executions,
          [scriptblock]$GetApp, [scriptblock]$GetRevision)
    $waiting = New-Object System.Collections.Generic.List[string]
    $failed = New-Object System.Collections.Generic.List[string]
    $unread = New-Object System.Collections.Generic.List[string]
    $dg = "$($Pending.Digest)".ToLowerInvariant()
    if (-not $dg) {
        return [pscustomobject]@{ Proven = $false; Superseded = $false; Waiting = @(); Failed = @(); Unreadable = @('the new engine image')
            Line = 'old images: kept -- the swap recorded no engine image to prove a run on; every image is kept' }
    }
    $onDigest = { param($res) @(Get-SIUpdaterResourceImages -Resource $res | Where-Object { ([string]$_).ToLowerInvariant().EndsWith('@' + $dg) }).Count -gt 0 }
    $swapped = @(@($Jobs) | Where-Object { $_ -and (& $onDigest $_) })
    if (-not $swapped.Count) {
        return [pscustomobject]@{ Proven = $false; Superseded = $true; Waiting = @(); Failed = @(); Unreadable = @()
            Line = ('old images: the image-only swap to {0} is no longer what the jobs run (a later update moved them) -- its pending clean-up is cleared, nothing is deleted by it' -f $Pending.Version) }
    }
    $parse = { param($t) if (-not "$t".Trim()) { return $null }; try { [datetime]::Parse("$t", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null } }
    # PER IMAGE, not per job (Invardia's words: "after A job has SUCCEEDED on the new image"; every engine job runs the ONE
    # si-orchestrator image, and an on-demand job may not run for weeks): the executions of every job on the digest, started
    # after the swap, ON the digest, finished. Proven = at least one Succeeded AND the newest of them all did not fail.
    $runs = New-Object System.Collections.Generic.List[object]
    foreach ($j in $swapped) {
        $name = [string]$j.name
        $ex = $null
        try { $ex = @(& $Executions $name) } catch { $unread.Add($name); continue }
        foreach ($e in @($ex)) {
            if (-not $e) { continue }
            $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
            $st = & $parse $p.startTime
            if (-not $st -or $st -le $Pending.SwappedUtc) { continue }
            if (-not (& $onDigest $e)) { continue }
            if ("$($p.status)" -notin @('Succeeded', 'Failed', 'Stopped', 'Degraded')) { continue }
            $runs.Add([pscustomobject]@{ Job = $name; Execution = [string]$e.name; Start = $st; Status = "$($p.status)" })
        }
    }
    $okRuns = @($runs.ToArray() | Where-Object { $_.Status -eq 'Succeeded' })
    if (-not $unread.Count) {
        if ($runs.Count) {
            $newest = @($runs.ToArray() | Sort-Object -Property Start -Descending)[0]
            if ($newest.Status -ne 'Succeeded') { $failed.Add(('{0}, execution {1}' -f $newest.Job, $newest.Execution)) }
        }
        if (-not $okRuns.Count -and -not $failed.Count) { $waiting.Add(('no job has succeeded on the new engine image ({0} job(s) on it)' -f $swapped.Count)) }
    }
    foreach ($a in @($Pending.Apps)) {
        if (-not $GetApp) { $unread.Add([string]$a); continue }
        try {
            $app = & $GetApp ([string]$a)
            if (-not $app) { continue }
            $rev = [string]$app.properties.latestRevisionName
            $r = if ($GetRevision) { & $GetRevision ([string]$a) $rev } else { $null }
            if (-not $r -or "$($r.properties.healthState)" -ne 'Healthy' -or "$($r.properties.runningState)" -notlike 'Running*') { $waiting.Add(('{0} (revision {1} not healthy and running yet)' -f $a, $rev)) }
        } catch { $unread.Add([string]$a) }
    }
    $line = if ($failed.Count) { 'old images: kept -- a run on the new image failed ({0}); nothing is deleted until a run on the new image succeeds' -f ($failed -join ', ') }
            elseif ($unread.Count) { 'old images: kept -- whether the swap is proven could not be read ({0}); not proven = every image is kept' -f ($unread -join ', ') }
            elseif ($waiting.Count) { 'old images: kept until the image-only swap to {0} is proven -- no successful run on the new image yet: {1}' -f $Pending.Version, ($waiting -join ', ') }
            else { 'old images: the image-only swap to {0} is proven -- {1} run(s) succeeded on the new engine image since {2:yyyy-MM-dd HH:mm}Z (the newest: {4}){3}' -f $Pending.Version, $okRuns.Count, $Pending.SwappedUtc, $(if (@($Pending.Apps).Count) { ', the web app revisions are healthy' } else { '' }), $(if ($okRuns.Count) { @($okRuns | Sort-Object -Property Start -Descending)[0].Job } else { '' }) }
    [pscustomobject]@{ Proven = (-not $failed.Count -and -not $unread.Count -and -not $waiting.Count); Superseded = $false
                       Waiting = @($waiting.ToArray()); Failed = @($failed.ToArray()); Unreadable = @($unread.ToArray()); Line = $line }
}

function Read-SIUpdaterImageOnlyPending {
    <# The pending record from cfg.InstallState ($null when none or unreadable). Never throws. #>
    param($Store)
    if (-not $Store -or -not $Store.Invoke) { return $null }
    try {
        $row = @(& $Store.Invoke ("IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'{0}'" -f $script:SIImageOnlyPendingName) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if (-not $row) { return $null }
        $v = if ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } else { [string]$row.Value }
        ConvertFrom-SIUpdaterImageOnlyPendingValue -Json $v
    } catch { $null }
}

function Clear-SIUpdaterImageOnlyPending {
    <# The pending record taken away. Never throws: $true done. #>
    param($Store)
    if (-not $Store -or -not $Store.Invoke) { return $false }
    try { $null = & $Store.Invoke ("IF OBJECT_ID('cfg.InstallState') IS NOT NULL DELETE FROM cfg.InstallState WHERE Name = N'{0}'" -f $script:SIImageOnlyPendingName) @{} 'nonquery'; $true } catch { $false }
}

function Invoke-SIUpdaterImageOnlyPruneStep {
    <#
        AT THE SWAP (SI-UpdaterInvardia.ps1, the short path): -Healthy (every part read back healthy) = the swap is RECORDED as a
        pending clean-up (cfg.InstallState 'ImageOnlyPrunePending': the release, the engine jobs' new digest, the apps that took
        a new revision, the time) -- NOTHING is deleted now; a later run proves it first (Invoke-SIUpdaterImageOnlyPendingPrune).
        Not healthy = nothing recorded, nothing deleted. One line either way. -After /
        -NowUtc: test seams. Never throws; returns the record written ($null = none).
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [bool]$Healthy, [string]$UpdaterJob = 'caj-si-updater', [scriptblock]$Get, $Store, $After, [AllowEmptyString()][string]$Version = '',
          [string[]]$Apps = @('ca-si-management', 'ca-si-mcp'), [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        if (-not $Healthy) { Write-UpdLog 'old images: not cleaned up -- the image-only swap did not read back healthy, so nothing is deleted'; return $null }
        if (-not $After) {
            $acr = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
            $After = Get-SIUpdaterImageSnapshot -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -LoginServer ([string]$acr.loginServer) -UpdaterJob $UpdaterJob
        }
        $dg = Get-SIUpdaterImageOnlySwapDigest -After $After
        $have = @(@(if ($After) { $After.Refs }) | ForEach-Object { [string]$_.From })
        $apps = @(@($Apps) | Where-Object { $have -contains [string]$_ })
        $v = ConvertTo-SIUpdaterImageOnlyPendingValue -Version $Version -SwappedUtc $NowUtc -Digest $dg -Apps $apps
        $ok = $false
        if ($Store -and (Get-Command -Name Save-SIUpdaterInstallStateValue -ErrorAction SilentlyContinue)) { $ok = [bool](Save-SIUpdaterInstallStateValue -Store $Store -Name $script:SIImageOnlyPendingName -Value $v) }
        if ($ok) { Write-UpdLog 'old images: nothing is deleted yet -- the previous images stay until a job has succeeded on the new image; a later update run cleans up then' }
        else { Write-UpdLog 'old images: nothing is deleted -- the swap could not be recorded for the clean-up after it is proven; every image is kept' }
        if ($ok) { $v } else { $null }
    } catch { Write-UpdLog ('old images: nothing is deleted -- the swap could not be recorded ({0}); every image is kept' -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterImageOnlyPendingPrune {
    <#
        A LATER UPDATER RUN (SI-UpdaterInvardia.ps1, every run that did not swap itself): a pending image-only clean-up is
        proven (Test-SIUpdaterImageOnlySwapProven) and, once it is, done (Invoke-SIUpdaterImageOnlyCleanup: only what runs stays,
        running executions included, one line per image) and the record cleared. Not proven = everything kept, one line.
        Superseded = the record cleared, nothing deleted. No record = nothing, nothing said.
        Seams (tests): -Pending, -Jobs, -Executions, -GetApp, -GetRevision, -Cleanup { } -> the clean-up result. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          $Store, [string]$UpdaterJob = 'caj-si-updater', [scriptblock]$Get, $Pending, $Jobs, [scriptblock]$Executions, [scriptblock]$GetApp,
          [scriptblock]$GetRevision, [scriptblock]$Cleanup,
          # the update client's Key Vault seams: the release record is written before the first delete (none = nothing deleted)
          [scriptblock]$ReadSecret, [scriptblock]$WriteSecret)
    try {
        if (-not $Pending) { $Pending = Read-SIUpdaterImageOnlyPending -Store $Store }
        if (-not $Pending) { return $null }
        if ($null -eq $Jobs) {
            try { $Jobs = @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) }
            catch { Write-UpdLog ('old images: kept -- whether the image-only swap is proven could not be read ({0}); every image is kept' -f $_.Exception.Message); return $null }
        }
        if (-not $Executions) { $Executions = { param($n) @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/{0}/executions' -f $n)) -List) } }
        if (-not $GetApp) { $GetApp = { param($n) Get-SIUpdaterContainerApp -App $n -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } }
        if (-not $GetRevision) { $GetRevision = { param($a, $r) Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/containerApps/{0}/revisions/{1}' -f $a, $r)) } }
        $t = Test-SIUpdaterImageOnlySwapProven -Pending $Pending -Jobs @($Jobs) -Executions $Executions -GetApp $GetApp -GetRevision $GetRevision
        Write-UpdLog $t.Line
        if ($t.Superseded) { $null = Clear-SIUpdaterImageOnlyPending -Store $Store; return $t }
        if (-not $t.Proven) { return $t }
        $res = if ($Cleanup) { & $Cleanup } else { Invoke-SIUpdaterImageOnlyCleanup -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Healthy $true -UpdaterJob $UpdaterJob -Get $Get -Store $Store `
                                                                                     -Version ([string]$Pending.Version) -ReadSecret $ReadSecret -WriteSecret $WriteSecret }
        if ($res -and $res.Done) { $null = Clear-SIUpdaterImageOnlyPending -Store $Store; Write-UpdLog 'old images: the pending clean-up of the image-only swap is done' }
        $t
    } catch { Write-UpdLog ('WARNING: old images: the pending clean-up was not checked ({0}) -- every image is kept; the next update tries again' -f $_.Exception.Message); $null }
}
