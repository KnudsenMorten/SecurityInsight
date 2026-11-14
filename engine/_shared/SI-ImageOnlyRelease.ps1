#Requires -Version 5.1
<#
    SecurityInsight -- THE IMAGE-ONLY RELEASE SEEN FROM AN INSTALL (framework SEC-LANE-1, owner 2026-11-14: "they pull down as
    today"; IMAGE-PATCH-1). Every edition: the updater (its short image-only update path), the pipeline runner (the 5-minute
    wake-up that starts the updater for a waiting image-only release) and the heartbeat (the images the install RUNS) load it.

    WHAT AN IMAGE-ONLY RELEASE IS, as an install can tell (no new marker is invented -- the image patch already carries them,
    setup\_shared\SI-ImagePatch.ps1 and setup\Release-SIImagePatch.ps1):
      1. its VERSION has a FOURTH part on the release the install runs: 3.1.17 -> 3.1.17.1, 3.1.17.1 -> 3.1.17.2
         (Get-SIImagePatchVersion) -- the same first three parts, a higher fourth one (Test-SIImageOnlyVersion);
      2. its own What's new entry (whats-new\<version>.json, framework WHATS-NEW-1) has type "security" -- New-SIImagePatchWhatsNewText
         writes it for every image patch, and a code release never has that type for a four-part number (Get-SIImageOnlyMarker);
      3. its engine code is the code the install runs: the engine fingerprint of the release equals the one the install
         recorded when it installed what runs now (cfg.InstallState 'EngineFingerprint', engine\_shared\SI-GuardStrict.ps1).
         Not recorded, or not readable = not proven: the full update path (never a guess).
    Any of the three missing = the release is NOT image-only, and the full update path runs exactly as before.

    THE RUNNING IMAGES (heartbeat field Update.runningImages, Invardia's contract 2e20fb60, soft): one entry per SI component --
    each job, the web app, the MCP server, the sign-in front, the updater -- { component, repo, digest, dotnet, readUtc }:
    read from ARM (a job's template image, an app's containers), the digest from the pin (repo@sha256:...) or the registry's
    manifest for the tag, and dotnet = the .NET runtime of that image as its build recorded it (the image's label
    org.securityinsight.dotnet when present, else the DOTNET_VERSION the Microsoft base image sets in the image's
    configuration). Not known = null, never a guess.

    PowerShell 5.1 and 7. No PowerShell module. PURE except New-SIRegistryImageReader (the registry over the REST seam it is
    given) and Get-SIRunningImages (the reads it is given).
#>

$script:SIImageOnly = @{
    # the heartbeat contract (Invardia 2e20fb60): at most 40 components, the keys in this order
    RunningImagesMax    = 40
    RunningImageFields  = @('component', 'repo', 'digest', 'dotnet', 'readUtc')
    ComponentRx         = '^[a-z0-9][a-z0-9._-]{0,79}$'
    RepoRx              = '^[a-z0-9][a-z0-9._/-]{0,79}$'
    DigestRx            = '^sha256:[0-9a-f]{64}$'
    DotnetRx            = '^\d+\.\d+\.\d+(\.\d+)?$'
    # the label SecurityInsight may set at build; the base image's own record otherwise
    DotnetLabel         = 'org.securityinsight.dotnet'
    DotnetEnv           = @('DOTNET_VERSION')
    ManifestAccept      = 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
}

function ConvertTo-SIImageOnlyVersionParts {
    <# PURE. '3.1.17.1' -> @(3,1,17,1) ([long]); $null when it is not 3 or 4 whole numbers. #>
    param([AllowNull()][AllowEmptyString()][string]$Version)
    $v = "$Version".Trim()
    if ($v -notmatch '^\d{1,9}(\.\d{1,9}){2,3}$') { return $null }
    , [long[]]@($v.Split('.') | ForEach-Object { [long]$_ })
}

function Compare-SIImageOnlyVersion {
    <# PURE. -1 / 0 / 1 for two versions of 3 or 4 parts (a missing fourth part is 0); $null when either is not a version. #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    $x = ConvertTo-SIImageOnlyVersionParts $A; $y = ConvertTo-SIImageOnlyVersionParts $B
    if ($null -eq $x -or $null -eq $y) { return $null }
    for ($i = 0; $i -lt 4; $i++) {
        $p = if ($i -lt $x.Count) { $x[$i] } else { 0 }; $q = if ($i -lt $y.Count) { $y[$i] } else { 0 }
        if ($p -lt $q) { return -1 }; if ($p -gt $q) { return 1 }
    }
    0
}

function Test-SIImageOnlyVersion {
    <#
        PURE. Is -Version an IMAGE PATCH of the release the install runs (-Running)? Four parts, the same first three as the
        running release and above it: 3.1.17 -> 3.1.17.1 yes, 3.1.17.1 -> 3.1.17.2 yes, 3.1.17 -> 3.1.18 no (a code
        release), 3.1.17.2 -> 3.1.17.1 no (lower), 3.1.16 -> 3.1.17.1 no (another release under it). Returns @{ Ok; Why }.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Version, [AllowNull()][AllowEmptyString()][string]$Running)
    $no = { param($w) [pscustomobject]@{ Ok = $false; Why = $w } }
    $v = ConvertTo-SIImageOnlyVersionParts $Version; $r = ConvertTo-SIImageOnlyVersionParts $Running
    if ($null -eq $v) { return (& $no ("'{0}' is not a version" -f $Version)) }
    if ($null -eq $r) { return (& $no ("the release this install runs is not known ('{0}')" -f $Running)) }
    if ($v.Count -ne 4) { return (& $no ("{0} is a code release (three parts), not an image patch" -f "$Version".Trim())) }
    # an image patch counts 1, 2, 3 ... on its release (Get-SIImagePatchVersion); a fourth part like 202610272235 is the build
    # stamp of an older ring 1 build of that release -- a code build, never an image patch
    if ($v[3] -gt 9999) { return (& $no ("{0} is a build of {1}, not an image patch" -f "$Version".Trim(), ($v[0..2] -join '.'))) }
    if ($v[0] -ne $r[0] -or $v[1] -ne $r[1] -or $v[2] -ne $r[2]) { return (& $no ("{0} is not built on the {1} this install runs" -f "$Version".Trim(), "$Running".Trim())) }
    if ((Compare-SIImageOnlyVersion $Version $Running) -le 0) { return (& $no ("{0} is not newer than the {1} this install runs" -f "$Version".Trim(), "$Running".Trim())) }
    [pscustomobject]@{ Ok = $true; Why = ("{0} is an image patch of the {1} this install runs" -f "$Version".Trim(), "$Running".Trim()) }
}

function Get-SIImageOnlyMarker {
    <# Reads ONE file. Does the release at -SIRoot carry the image patch's own What's new (whats-new\<Version>.json, type
       "security")? Returns @{ Ok; Why }. Never throws. #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Version)
    $f = [IO.Path]::Combine($SIRoot, 'whats-new', ("{0}.json" -f "$Version".Trim()))
    if (-not (Test-Path -LiteralPath $f)) { return [pscustomobject]@{ Ok = $false; Why = ("the release carries no whats-new\{0}.json" -f "$Version".Trim()) } }
    $j = $null
    try { $j = [IO.File]::ReadAllText($f) | ConvertFrom-Json -ErrorAction Stop } catch { return [pscustomobject]@{ Ok = $false; Why = ("whats-new\{0}.json cannot be read ({1})" -f "$Version".Trim(), $_.Exception.Message) } }
    $t = if ($j -and $j.PSObject.Properties['type']) { "$($j.type)".Trim().ToLowerInvariant() } else { '' }
    if ($t -ne 'security') { return [pscustomobject]@{ Ok = $false; Why = ("its What's new is of type '{0}', not the image patch's 'security'" -f $t) } }
    [pscustomobject]@{ Ok = $true; Why = 'its What''s new is the image patch''s (type security)' }
}

function Test-SIImageOnlyRelease {
    <#
        PURE (after the reads). The three rules above in one answer: -Version / -Running (Test-SIImageOnlyVersion), -Marker
        (Get-SIImageOnlyMarker), -RecordedEngineHash (what the install recorded) and -ReleaseEngineHash (the release's).
        -ScriptReady: the release's update script has the image-only mode (setup\Invoke-SIContainerUpdate.ps1 -ImageOnly).
        Returns @{ ImageOnly; Why } -- Why is one plain line either way.
    #>
    param([AllowEmptyString()][string]$Version, [AllowEmptyString()][string]$Running, $Marker,
          [AllowNull()][AllowEmptyString()][string]$RecordedEngineHash, [AllowNull()][AllowEmptyString()][string]$ReleaseEngineHash, [bool]$ScriptReady = $true)
    $no = { param($w) [pscustomobject]@{ ImageOnly = $false; Why = $w } }
    $vt = Test-SIImageOnlyVersion -Version $Version -Running $Running
    if (-not $vt.Ok) { return (& $no $vt.Why) }
    if (-not $Marker -or -not $Marker.Ok) { return (& $no $(if ($Marker) { [string]$Marker.Why } else { 'its What''s new was not read' })) }
    $rec = "$RecordedEngineHash".Trim().ToLowerInvariant(); $rel = "$ReleaseEngineHash".Trim().ToLowerInvariant()
    if (-not $rec) { return (& $no 'the engine code this install runs is not recorded, so "the same code" cannot be proven') }
    if (-not $rel) { return (& $no 'the engine code of the release could not be read') }
    if ($rec -ne $rel) { return (& $no 'its engine code differs from the code this install runs') }
    if (-not $ScriptReady) { return (& $no 'the release''s update script has no image-only mode') }
    [pscustomobject]@{ ImageOnly = $true; Why = ('{0}; same engine code; {1}' -f $vt.Why, [string]$Marker.Why) }
}

# ---- THE RUNNING IMAGES -------------------------------------------------------------------------------------------------

function ConvertFrom-SIImageReference {
    <# PURE. 'host/repo[:tag][@sha256:...]' -> @{ Registry; Repo; Tag; Digest } (lower case repo / digest); $null for an
       image without a registry host (a name Docker Hub would resolve) or one that is not an image reference. #>
    param([AllowNull()][AllowEmptyString()][string]$Image)
    $i = "$Image".Trim()
    if (-not $i -or $i -match '\s') { return $null }
    $slash = $i.IndexOf('/')
    if ($slash -le 0) { return $null }
    $reg = $i.Substring(0, $slash)
    if ($reg -notmatch '[.:]' -and $reg -ne 'localhost') { return $null }
    $rest = $i.Substring($slash + 1)
    $digest = ''
    $at = $rest.IndexOf('@')
    if ($at -ge 0) { $digest = $rest.Substring($at + 1).ToLowerInvariant(); $rest = $rest.Substring(0, $at) }
    $tag = ''
    $colon = $rest.LastIndexOf(':')
    if ($colon -gt $rest.LastIndexOf('/')) { $tag = $rest.Substring($colon + 1); $rest = $rest.Substring(0, $colon) }
    if (-not $rest) { return $null }
    if ($digest -and $digest -notmatch $script:SIImageOnly.DigestRx) { $digest = '' }
    if (-not $tag -and -not $digest) { $tag = 'latest' }
    [pscustomobject]@{ Registry = $reg.ToLowerInvariant(); Repo = $rest.ToLowerInvariant(); Tag = $tag; Digest = $digest }
}

function Get-SIRunningImageComponents {
    <#
        PURE. The SI components of the install as ARM shows them: -Jobs (Container Apps jobs, ARM shape) -> one per job (its
        first container: the job's name); -Apps (container apps, ARM shape) -> the app's first container under the app's name,
        every further container as '<app>.<container>' (the sign-in front in front of the web app). Names are lower case;
        a name the contract cannot carry is left out. At most RunningImagesMax. Returns @(@{ Component; Image }).
    #>
    param([object[]]$Jobs = @(), [object[]]$Apps = @())
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $add = { param($name, $img)
        $n = "$name".Trim().ToLowerInvariant()
        if (-not $n -or $n -notmatch $script:SIImageOnly.ComponentRx -or $seen.ContainsKey($n) -or -not "$img".Trim()) { return }
        if ($out.Count -ge $script:SIImageOnly.RunningImagesMax) { return }
        $seen[$n] = $true; $out.Add([pscustomobject]@{ Component = $n; Image = "$img".Trim() }) }
    foreach ($j in @($Jobs)) {
        if (-not $j) { continue }
        $c = $null; try { $c = @($j.properties.template.containers | Where-Object { $_ })[0] } catch { $c = $null }
        if ($c) { & $add ([string]$j.name) ([string]$c.image) }
    }
    foreach ($a in @($Apps)) {
        if (-not $a) { continue }
        $cs = @(); try { $cs = @($a.properties.template.containers | Where-Object { $_ }) } catch { $cs = @() }
        for ($k = 0; $k -lt $cs.Count; $k++) {
            $nm = if ($k -eq 0) { [string]$a.name } else { '{0}.{1}' -f [string]$a.name, [string]$cs[$k].name }
            & $add $nm ([string]$cs[$k].image)
        }
    }
    $out.ToArray()
}

function Get-SIImageDotnetVersion {
    <# PURE. The .NET runtime an image's configuration (the config blob, parsed) records: the label
       org.securityinsight.dotnet, else DOTNET_VERSION in its environment (Microsoft's .NET base images set it). '' when none. #>
    param($Config)
    if (-not $Config) { return '' }
    $cfg = if ($Config.PSObject.Properties['config'] -and $Config.config) { $Config.config } else { $Config }
    try {
        if ($cfg.PSObject.Properties['Labels'] -and $cfg.Labels -and $cfg.Labels.PSObject.Properties[$script:SIImageOnly.DotnetLabel]) {
            $l = "$($cfg.Labels.($script:SIImageOnly.DotnetLabel))".Trim()
            if ($l -match $script:SIImageOnly.DotnetRx) { return $l }
        }
    } catch { }
    try {
        foreach ($e in @($cfg.Env)) {
            foreach ($n in $script:SIImageOnly.DotnetEnv) {
                if ("$e" -like ($n + '=*')) { $v = "$e".Substring($n.Length + 1).Trim(); if ($v -match $script:SIImageOnly.DotnetRx) { return $v } }
            }
        }
    } catch { }
    ''
}

function New-SIRegistryImageReader {
    <#
        The registry's own data plane, read only, for the running images: -Http { param($Method, $Uri, $Headers, $Body) } ->
        @{ Status; Body; Headers } (the caller's REST seam), -ArmToken { } -> an ARM access token of the job's identity.
        Per registry and repository ONE pull token (the exchange at https://<registry>/oauth2/exchange, then /oauth2/token,
        scope repository:<repo>:pull), kept for the reader's life; per tag ONE digest read (HEAD of the manifest) and per
        digest ONE .NET read (the manifest, then its config blob). Read with Get-SIRegistryImageDigest /
        Get-SIRegistryImageDotnet -- plain functions over this state (a .GetNewClosure() block would not see them).
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$ArmToken)
    [pscustomobject]@{ Http = $Http; ArmToken = $ArmToken; Tokens = @{}; Digests = @{}; Dotnet = @{}; Refused = @{} }
}

function Get-SIRegistryHeader {
    <# PURE. One header of an answer's headers (any case; the first value of a list), '' when absent. #>
    param($Headers, [Parameter(Mandatory)][string]$Name)
    if (-not $Headers) { return '' }
    $keys = if ($Headers -is [System.Collections.IDictionary]) { @($Headers.Keys) } else { @($Headers.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($k in $keys) {
        if ("$k" -ieq $Name) { $v = if ($Headers -is [System.Collections.IDictionary]) { $Headers[$k] } else { $Headers.$k }; if ($v -is [array]) { $v = $v[0] }; return "$v".Trim() }
    }
    ''
}

function Get-SIRegistryPullToken {
    <# The reader's pull token for -Ref's registry and repository ('' when the registry refuses it: then never asked again
       for that registry by this reader). Never throws. #>
    param([Parameter(Mandatory)]$ImageReader, [Parameter(Mandatory)]$Ref)
    $key = '{0}|{1}' -f $Ref.Registry, $Ref.Repo
    if ($ImageReader.Tokens.ContainsKey($key)) { return [string]$ImageReader.Tokens[$key] }
    if ($ImageReader.Refused.ContainsKey([string]$Ref.Registry)) { return '' }
    $t = ''
    try {
        $aad = [string](& $ImageReader.ArmToken)
        if ($aad) {
            $form = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
            $ex = & $ImageReader.Http 'POST' ('https://{0}/oauth2/exchange' -f $Ref.Registry) $form ('grant_type=access_token&service={0}&access_token={1}' -f [uri]::EscapeDataString($Ref.Registry), [uri]::EscapeDataString($aad))
            if ([int]$ex.Status -ge 200 -and [int]$ex.Status -lt 300) {
                $refresh = [string](("$($ex.Body)" | ConvertFrom-Json).refresh_token)
                $tk = & $ImageReader.Http 'POST' ('https://{0}/oauth2/token' -f $Ref.Registry) $form ('grant_type=refresh_token&service={0}&scope={1}&refresh_token={2}' -f [uri]::EscapeDataString($Ref.Registry), [uri]::EscapeDataString(('repository:{0}:pull' -f $Ref.Repo)), [uri]::EscapeDataString($refresh))
                if ([int]$tk.Status -ge 200 -and [int]$tk.Status -lt 300) { $t = [string](("$($tk.Body)" | ConvertFrom-Json).access_token) }
            } else { $ImageReader.Refused[[string]$Ref.Registry] = $true }
        }
    } catch { $t = '' }
    $ImageReader.Tokens[$key] = $t
    $t
}

function Get-SIRegistryImageDigest {
    <# The digest -Ref runs: its pin, else the registry's manifest digest of its tag (HEAD). '' when not readable. Never throws. #>
    param([Parameter(Mandatory)]$ImageReader, $Ref)
    if (-not $Ref) { return '' }
    if ($Ref.Digest) { return [string]$Ref.Digest }
    $key = '{0}/{1}:{2}' -f $Ref.Registry, $Ref.Repo, $Ref.Tag
    if ($ImageReader.Digests.ContainsKey($key)) { return [string]$ImageReader.Digests[$key] }
    $d = ''
    try {
        $b = Get-SIRegistryPullToken -ImageReader $ImageReader -Ref $Ref
        if ($b) {
            $r = & $ImageReader.Http 'HEAD' ('https://{0}/v2/{1}/manifests/{2}' -f $Ref.Registry, $Ref.Repo, $Ref.Tag) @{ Authorization = ('Bearer ' + $b); Accept = $script:SIImageOnly.ManifestAccept } $null
            if ([int]$r.Status -ge 200 -and [int]$r.Status -lt 300) { $d = (Get-SIRegistryHeader -Headers $r.Headers -Name 'Docker-Content-Digest').ToLowerInvariant() }
        }
    } catch { $d = '' }
    if ($d -notmatch $script:SIImageOnly.DigestRx) { $d = '' }
    $ImageReader.Digests[$key] = $d
    $d
}

function Get-SIRegistryImageDotnet {
    <# The .NET runtime the image -Digest of -Ref records (Get-SIImageDotnetVersion over its config blob; a multi-platform
       index: its linux / amd64 image). '' when not known. Never throws. #>
    param([Parameter(Mandatory)]$ImageReader, $Ref, [string]$Digest)
    if (-not $Ref -or -not $Digest) { return '' }
    $key = '{0}/{1}@{2}' -f $Ref.Registry, $Ref.Repo, $Digest
    if ($ImageReader.Dotnet.ContainsKey($key)) { return [string]$ImageReader.Dotnet[$key] }
    $v = ''
    try {
        $b = Get-SIRegistryPullToken -ImageReader $ImageReader -Ref $Ref
        if ($b) {
            $auth = @{ Authorization = ('Bearer ' + $b); Accept = $script:SIImageOnly.ManifestAccept }
            $m = & $ImageReader.Http 'GET' ('https://{0}/v2/{1}/manifests/{2}' -f $Ref.Registry, $Ref.Repo, $Digest) $auth $null
            $mj = if ([int]$m.Status -ge 200 -and [int]$m.Status -lt 300) { "$($m.Body)" | ConvertFrom-Json } else { $null }
            if ($mj -and $mj.PSObject.Properties['manifests'] -and -not $mj.PSObject.Properties['config']) {
                $child = @($mj.manifests | Where-Object { $_ -and $_.platform -and "$($_.platform.os)" -eq 'linux' -and "$($_.platform.architecture)" -eq 'amd64' })[0]
                $mj = $null
                if ($child) {
                    $m2 = & $ImageReader.Http 'GET' ('https://{0}/v2/{1}/manifests/{2}' -f $Ref.Registry, $Ref.Repo, [string]$child.digest) $auth $null
                    if ([int]$m2.Status -ge 200 -and [int]$m2.Status -lt 300) { $mj = "$($m2.Body)" | ConvertFrom-Json }
                }
            }
            if ($mj -and $mj.PSObject.Properties['config'] -and $mj.config -and "$($mj.config.digest)") {
                $cb = & $ImageReader.Http 'GET' ('https://{0}/v2/{1}/blobs/{2}' -f $Ref.Registry, $Ref.Repo, [string]$mj.config.digest) @{ Authorization = ('Bearer ' + $b) } $null
                if ([int]$cb.Status -ge 200 -and [int]$cb.Status -lt 300) { $v = Get-SIImageDotnetVersion -Config ("$($cb.Body)" | ConvertFrom-Json) }
            }
        }
    } catch { $v = '' }
    $ImageReader.Dotnet[$key] = $v
    $v
}

function Get-SIRunningImages {
    <#
        The running images of the install, in the contract's shape (Invardia 2e20fb60): -Components (Get-SIRunningImageComponents),
        -ImageReader (New-SIRegistryImageReader; none = only pinned digests, no .NET), -NowUtc. Per component: repo = the
        image's repository (null when it is not one the contract can carry), digest = the pin, else the registry's manifest
        digest of the tag (null when not readable), dotnet = the image's own record (null when not known), readUtc = now.
        Never throws: a component that cannot be read is sent with what is known. Returns @(ordered entries).
    #>
    param([object[]]$Components = @(), $ImageReader, [Parameter(Mandatory)][datetime]$NowUtc)
    $now = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Components)) {
        if (-not $c) { continue }
        $ref = ConvertFrom-SIImageReference -Image ([string]$c.Image)
        $repo = $null; $dg = $null; $dn = $null
        if ($ref) {
            if ($ref.Repo -match $script:SIImageOnly.RepoRx) { $repo = [string]$ref.Repo }
            $d = ''; if ($ImageReader) { $d = [string](Get-SIRegistryImageDigest -ImageReader $ImageReader -Ref $ref) } elseif ($ref.Digest) { $d = [string]$ref.Digest }
            if ($d -match $script:SIImageOnly.DigestRx) { $dg = $d }
            if ($dg -and $ImageReader) { $n = [string](Get-SIRegistryImageDotnet -ImageReader $ImageReader -Ref $ref -Digest $dg); if ($n -match $script:SIImageOnly.DotnetRx) { $dn = $n } }
        }
        $out.Add([ordered]@{ component = [string]$c.Component; repo = $repo; digest = $dg; dotnet = $dn; readUtc = $now })
    }
    $out.ToArray()
}

function Test-SIRunningImagesValue {
    <# PURE. Is -Value what the contract takes for Update.runningImages? '' = yes, else why not (the field is then left out). #>
    param($Value)
    $c = $script:SIImageOnly
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [System.Collections.IDictionary]) { return 'runningImages is not a list' }
    $items = @($Value)
    if ($items.Count -gt $c.RunningImagesMax) { return ('runningImages has {0} entries (at most {1})' -f $items.Count, $c.RunningImagesMax) }
    $seen = @{}
    foreach ($x in $items) {
        if ($null -eq $x) { return 'runningImages has an empty entry' }
        $names = if ($x -is [System.Collections.IDictionary]) { @($x.Keys | ForEach-Object { [string]$_ }) } else { @($x.PSObject.Properties | ForEach-Object { $_.Name }) }
        if (($names -join ',') -cne ($c.RunningImageFields -join ',')) { return ('a runningImages entry has the keys {0}, not {1}' -f ($names -join ','), ($c.RunningImageFields -join ',')) }
        $get = { param($n) if ($x -is [System.Collections.IDictionary]) { $x[$n] } else { $x.$n } }
        $comp = & $get 'component'
        if (-not ($comp -is [string] -and $comp -cmatch $c.ComponentRx)) { return ("runningImages.component '{0}' is not a component name" -f $comp) }
        if ($seen.ContainsKey($comp)) { return ("component {0} appears more than once" -f $comp) }; $seen[$comp] = 1
        $repo = & $get 'repo'; if ($null -ne $repo -and -not ($repo -is [string] -and $repo -cmatch $c.RepoRx)) { return ("runningImages.repo '{0}' is not a repository" -f $repo) }
        $dg = & $get 'digest'; if ($null -ne $dg -and -not ($dg -is [string] -and $dg -cmatch $c.DigestRx)) { return ("runningImages.digest '{0}' is not a sha256 digest" -f $dg) }
        $dn = & $get 'dotnet'; if ($null -ne $dn -and -not ($dn -is [string] -and $dn -cmatch $c.DotnetRx)) { return ("runningImages.dotnet '{0}' is not a version" -f $dn) }
        $ru = & $get 'readUtc'; if (-not ($ru -is [string] -and $ru -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$')) { return 'runningImages.readUtc is not ISO-8601 UTC' }
    }
    ''
}
