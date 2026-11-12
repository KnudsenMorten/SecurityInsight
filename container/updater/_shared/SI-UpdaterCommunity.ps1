#Requires -Version 5.1
<#
    caj-si-updater -- THE COMMUNITY MANIFEST ADDRESS of the ONE update client (framework PRO-COMMUNITY-SAME, owner 2026-11-11:
    Pro and Community are built and run the same; only the licensed features and the package source differ).

    There is ONE updater flow for both editions: Invoke-SIUpdaterFromInvardia (_shared/SI-UpdaterInvardia.ps1). It runs the same
    steps for every install -- the install key slot and claim, the ring, the run gate, the database step, the roll, the web app,
    the updater itself, the state, the failure reports and the "update now" start. ONLY the manifest address and its credential
    differ (Resolve-SIUpdaterUpdateRoute decides):
      * an install with a licence           -> Invardia's install route (POST .../manifest, the install key in its header);
      * an install of the Community edition -> Invardia's anonymous Community route, read here:
           GET https://invardia.com/api/updates/securityinsight/community/<ring>   (rings 0-3)
           200 = { manifest, manifestB64, signature, keyId, downloadUrl } signed by Invardia (RS256, the SAME key list as the
           install route, kind community); 204 = nothing released to the ring yet; 404 = no such ring.
           SI_UPDATER_COMMUNITY_BASE_URL overrides the base, https only (a rehearsal against a test endpoint).
    The Community package is the public release zip (the package source): checked here by the signed size and SHA-256, its
    VERSION = the signed version, extracted safely, and it must carry the update client, so an update never strands the install.

    This file holds only those route-specific pieces, plus the compat read of the state row the Community edition's earlier
    updater kept (cfg.InstallState 'CommunityUpdateState'), so an existing Community install keeps its applied sequence.
    Every call that leaves the process goes through -Seams (tests).
#>

# Invardia's Community manifest route (the same family PIM's Community edition reads); rings 0-3.
$script:SIUpdaterCommunityBaseUrl = 'https://invardia.com'

function Get-SIUpdaterCommunityManifestUri {
    <# PURE. GET <base>/api/updates/securityinsight/community/<ring> -- anonymous; ring 0-3. #>
    param([Parameter(Mandatory)][string]$BaseUrl, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring)
    '{0}/api/updates/securityinsight/community/{1}' -f $BaseUrl.TrimEnd('/'), $Ring
}

function Get-SIUpdaterCommunityBase {
    <# The Community route's base: SI_UPDATER_COMMUNITY_BASE_URL (-Override) when it is https, else Invardia's. Returns
       @{ Base; Note } -- Note says why an override was not used. PURE. #>
    param([AllowEmptyString()][string]$Override)
    $o = "$Override".Trim()
    if ($o -and $o -notmatch '^https://') { return [pscustomobject]@{ Base = $script:SIUpdaterCommunityBaseUrl; Note = ("SI_UPDATER_COMMUNITY_BASE_URL is not https ('{0}') -- Invardia's endpoint is read" -f $o) } }
    [pscustomobject]@{ Base = $(if ($o) { $o.TrimEnd('/') } else { $script:SIUpdaterCommunityBaseUrl }); Note = '' }
}

function Invoke-SIUpdaterCommunityManifestHttp {
    <# The one anonymous GET (the default GetManifest seam). Returns @{ Status; Body } -- an HTTP error is a status, never a throw;
       no answer at all throws (the run then says the endpoint could not be read and changes nothing). #>
    param([Parameter(Mandatory)][string]$Url)
    try {
        $r = Invoke-WebRequest -Uri $Url -Method Get -UseBasicParsing -TimeoutSec 60 -Headers @{ Accept = 'application/json' } -ErrorAction Stop
        [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
    } catch {
        $resp = $null; try { $resp = $_.Exception.Response } catch { }
        if ($resp -and $resp.StatusCode) { return [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = '' } }
        throw
    }
}

function Find-SIUpdaterCommunityRoot {
    <# The SecurityInsight code the updater image carries (/si), or -- from a checkout -- this solution's root: the folder
       that holds the signed release checks (SI-CommunityUpdate.ps1). $null when none does. #>
    param([string[]]$Candidates)
    if (-not $Candidates) { $Candidates = @('/si', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..')) }
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath ([IO.Path]::Combine($c, 'engine', '_shared', 'SI-CommunityUpdate.ps1')))) { return [IO.Path]::GetFullPath($c) }
    }
    $null
}

function ConvertFrom-SIUpdaterCommunityState {
    <# PURE. COMPAT: cfg.InstallState 'CommunityUpdateState' (written by the Community edition's earlier updater) ->
       @{ appliedSequence; appliedVersion; ring; appliedUtc }. Unreadable = none (sequence 0). #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    $s = [ordered]@{ appliedSequence = [long]0; appliedVersion = ''; ring = 0; appliedUtc = '' }
    if (-not "$Json".Trim()) { return $s }
    try { $o = "$Json" | ConvertFrom-Json -ErrorAction Stop } catch { return $s }
    if ($o.PSObject.Properties['seq']) { $n = [long]0; if ([long]::TryParse("$($o.seq)", [ref]$n) -and $n -gt 0) { $s.appliedSequence = $n } }
    if ($o.PSObject.Properties['ver']) { $s.appliedVersion = "$($o.ver)".Trim() }
    if ($o.PSObject.Properties['ring']) { $r = 0; if ([int]::TryParse("$($o.ring)", [ref]$r)) { $s.ring = $r } }
    if ($o.PSObject.Properties['at']) { $s.appliedUtc = "$($o.at)" }
    $s
}

function Read-SIUpdaterCommunityStateRow {
    <# COMPAT: the 'CommunityUpdateState' row's value from the install's database, '' when none / no table / no database. Never throws. #>
    param($Store)
    if (-not $Store) { return '' }
    try {
        $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @Name" ([ordered]@{ Name = 'CommunityUpdateState' }) 'reader' | ForEach-Object { $_ })
        $row = $rows | Select-Object -First 1
        if (-not $row) { return '' }
        [string]$(if ($row -is [System.Collections.IDictionary]) { $row['Value'] } else { $row.Value })
    } catch { Write-UpdLog ("WARNING: the earlier Community update state could not be read ({0}) -- the running version is the version rule this run" -f $_.Exception.Message); '' }
}

function Merge-SIUpdaterCommunityState {
    <#
        COMPAT (PRO-COMMUNITY-SAME, 2026-11-11): an existing Community install kept what it applied in cfg.InstallState
        'CommunityUpdateState'. When the one client's state (SI-Update-State) has no applied code yet, that row is carried over
        once -- its applied sequence, version and ring -- so the install is never offered an older release again and never
        holds as a "first manifest". -State: the update state (ConvertFrom-SIInvardiaUpdateState); -Json: the old row.
        Returns $true when it was carried over. PURE.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [AllowNull()][AllowEmptyString()][string]$Json)
    if ([long]$State.code.appliedSequence -ge 0) { return $false }
    $old = ConvertFrom-SIUpdaterCommunityState -Json $Json
    if ([long]$old.appliedSequence -le 0) { return $false }
    $State.code.appliedSequence = [long]$old.appliedSequence
    $State.code.appliedVersion = [string]$old.appliedVersion
    $State.code.appliedRing = $(if ([int]$old.ring -ge 0 -and [int]$old.ring -le 3) { [int]$old.ring } else { $null })
    $State.channel = 'community'
    $true
}

function Get-SIUpdaterCommunityReleaseCommit {
    <# The commit the release was built from (BUILD.json in the payload), '' when it carries none. #>
    param([Parameter(Mandatory)][string]$PayloadRoot)
    $f = [IO.Path]::Combine($PayloadRoot, 'BUILD.json')
    if (-not (Test-Path -LiteralPath $f)) { return '' }
    try { "$(([IO.File]::ReadAllText($f).TrimStart([char]0xFEFF) | ConvertFrom-Json).commit)".Trim().ToLowerInvariant() } catch { '' }
}

# The files a release must carry for the ONE update client to keep updating the install after it (besides the release
# checks' own, $SICommunityUpdateClientFiles). SI-UpdaterCommunity.ps1 stays required: an install whose updater image is
# older still looks for it.
$script:SIUpdaterCommunityRequiredFiles = @('setup/Invoke-SIContainerUpdate.ps1', 'container/updater/Start-SIUpdater.ps1',
    'container/updater/_shared/SI-UpdaterInvardia.ps1', 'container/updater/_shared/SI-UpdaterCommunity.ps1', 'engine/_shared/SI-InvardiaUpdate.ps1')

function Test-SIUpdaterCommunityMajor {
    <#
        PURE. Owner 2026-10-28: a release whose MAJOR version differs from the installed one is refused (3.x never moves to
        4.x, and nothing moves a 2.2 install to 3: a new major version is a new installation beside the old one). Returns the
        reason in plain words, or '' when the majors match. An installed version that cannot be read is refused too (fail
        closed: nothing is applied without knowing what runs).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Installed, [AllowEmptyString()][AllowNull()][string]$Release)
    $maj = { param($v) $m = [regex]::Match("$v".Trim(), '^v?(\d+)\.'); if ($m.Success) { [int]$m.Groups[1].Value } else { -1 } }
    $i = & $maj $Installed; $r = & $maj $Release
    if ($r -lt 0) { return ("the release names no readable version ('{0}')" -f $Release) }
    if ($i -lt 0) { return ("the installed version cannot be read ('{0}'), so a release of another major version cannot be ruled out" -f $Installed) }
    if ($i -ne $r) { return ("the release is SecurityInsight {0}, another major version than the installed {1} -- a new major version is installed beside the old one, never as an update" -f $Release, $Installed) }
    ''
}

function Request-SIUpdaterCommunityCode {
    <#
        THE COMMUNITY MANIFEST of kind code for -Ring, read and checked BEFORE anything is downloaded, answered in the SAME shape
        as the install route's (New-SIInvardiaManifestResult, Kind 'code'), so the one flow decides, records and rolls it the
        same way. NEVER throws. Action: update | current | hold | none (204) | notfound (404) | refused | network.
        -Seams: GetManifest { param($Url) } -> @{ Status; Body } (default the anonymous GET); CommunityTrustedKeys { } -> the
        trust list (default: the keys embedded in engine/_shared/InvardiaUpdate.verify.ps1 -- the same keys the install route
        trusts); DownloadPrefix (default https://).
    #>
    param([Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [long]$AppliedSequence = -1, [AllowEmptyString()][string]$RunningVersion = '',
          [long]$AcceptManualStepSequence = -1, [AllowEmptyString()][string]$BaseUrl = '', [System.Collections.IDictionary]$Seams = @{})
    $res = { param($a, $why, $m = $null, $seq = -1, $dl = '', $ms = '', $code = 0)
        New-SIInvardiaManifestResult -Kind 'code' -Action $a -Reason $why -Manifest $m -Sequence $seq -DownloadUrl $dl -ManualStep $ms -StatusCode $code }
    try {
        if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) {
            $root = Find-SIUpdaterCommunityRoot
            if (-not $root) { return (& $res 'refused' 'this updater image does not carry the release checks (engine/_shared/SI-CommunityUpdate.ps1) -- re-run setup/Install-SIUpdaterJob.ps1 to rebuild it') }
            . ([IO.Path]::Combine($root, 'engine', '_shared', 'SI-CommunityUpdate.ps1'))
        }
        $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim() } else { $script:SIUpdaterCommunityBaseUrl }
        $url = Get-SIUpdaterCommunityManifestUri -BaseUrl $base -Ring $Ring
        $get = if ($Seams -and $Seams['GetManifest']) { $Seams['GetManifest'] } else { { param($u) Invoke-SIUpdaterCommunityManifestHttp -Url $u } }
        $ans = $null
        try { $ans = & $get $url } catch { return (& $res 'network' ("the Community manifest could not be read: {0}" -f $_.Exception.Message)) }
        $st = [int]$ans.Status
        if ($st -eq 204) { return (& $res 'none' ("nothing is released for ring {0} (code)" -f $Ring) $null -1 '' '' 204) }
        if ($st -eq 404) { return (& $res 'notfound' ("Invardia knows no Community ring {0} (404)" -f $Ring) $null -1 '' '' 404) }
        if ($st -ne 200) { return (& $res 'network' ("the Community manifest answered {0} -- asked again on a later run" -f $st) $null -1 '' '' $st) }
        $entry = $null; try { $entry = "$($ans.Body)".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop } catch { $entry = $null }
        if (-not $entry) { return (& $res 'refused' 'the Community manifest answer is not JSON' $null -1 '' '' 200) }
        $keys = if ($Seams -and $Seams['CommunityTrustedKeys']) { @(& $Seams.CommunityTrustedKeys) } else { @($script:SICommunityTrustedKeys) }
        $prefix = if ($Seams -and "$($Seams['DownloadPrefix'])".Trim()) { "$($Seams['DownloadPrefix'])".Trim() } else { 'https://' }
        $chk = Test-SICommunityChannelEntry -Entry $entry -Ring $Ring -TrustedKeys $keys -AppliedSequence ([Math]::Max([long]0, $AppliedSequence)) `
                   -RunningVersion "$RunningVersion" -AcceptManualStepSequence $AcceptManualStepSequence -DownloadPrefix $prefix
        if ($chk.Action -eq 'refused') { return (& $res 'refused' ([string]$chk.Reason) $null -1 '' '' 200) }
        # owner 2026-10-28: a release of ANOTHER MAJOR VERSION is never applied -- refused before anything is downloaded
        if ($chk.Action -in 'update', 'hold' -and "$RunningVersion".Trim()) {
            $mj = Test-SIUpdaterCommunityMajor -Installed "$RunningVersion" -Release ([string]$chk.Version)
            if ($mj) { return (& $res 'refused' $mj $null ([long]$chk.Sequence) '' '' 200) }
        }
        # the manifest as the one flow reads it (version, ring, sequence, size, SHA-256); minFromVersion was decided above
        $m = [pscustomobject]@{ product = 'securityinsight'; kind = 'community'; ring = $Ring; sequence = [long]$chk.Sequence; version = [string]$chk.Version
                                sha256 = [string]$chk.Sha256; size = [long]$chk.Size; minFromVersion = ''; manualStep = [string]$chk.ManualStep }
        & $res ([string]$chk.Action) ([string]$chk.Reason) $m ([long]$chk.Sequence) ([string]$chk.DownloadUrl) ([string]$chk.ManualStep) 200
    } catch { & $res 'error' ("the Community update check did not complete: {0}" -f $_.Exception.Message) }
}

function Save-SIUpdaterCommunityRelease {
    <#
        THE COMMUNITY PACKAGE of a verified code result: downloaded (no git), its size and SHA-256 = the signed ones
        (Test-InvardiaArchiveFile), extracted safely (Expand-SICommunityArchive: no rooted path, no '..') under -Work, its
        VERSION = the signed version, and it carries the update client (every file of $SICommunityUpdateClientFiles and
        $SIUpdaterCommunityRequiredFiles). A BUILD.json is stamped when the public copy carries none (the web app image needs
        one). NEVER throws. Returns @{ Ok; Reason; Root; Commit; Version }.
        -Seams: Download { param($Url, $OutFile) } (an @{ Status } answer or a throw; default Invoke-SIInvardiaUpdateDownload).
    #>
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Work, [System.Collections.IDictionary]$Seams = @{}, [int]$Ring = 0)
    $no = { param($why) [pscustomobject]@{ Ok = $false; Reason = $why; Root = ''; Commit = ''; Version = '' } }
    try {
        if (-not $Result -or -not $Result.Manifest) { return (& $no 'there is no verified manifest to download') }
        $m = $Result.Manifest
        if ("$($Result.DownloadUrl)" -notmatch '^https://[^/\s]+/') { return (& $no 'the manifest came without an https download link') }
        New-Item -ItemType Directory -Force -Path $Work | Out-Null
        $zip = Join-Path $Work ('c-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.zip')
        $dl = if ($Seams -and $Seams['Download']) { $Seams['Download'] } else { { param($u, $f) Invoke-SIInvardiaUpdateDownload -Uri $u -OutFile $f } }
        $r = $null
        try { $r = & $dl ([string]$Result.DownloadUrl) $zip } catch { return (& $no ("the release could not be downloaded: {0}" -f (Hide-SIInvardiaSecret $_.Exception.Message -Secret ([string]$Result.DownloadUrl)))) }
        if ($r -and $r.PSObject.Properties['Status'] -and [int]$r.Status -ne 200) { return (& $no ("the download answered {0}" -f [int]$r.Status)) }
        if (-not (Test-Path -LiteralPath $zip)) { return (& $no 'the download did not complete') }
        $a = Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 ([string]$m.sha256) -ExpectedSize ([long]$m.size)
        if (-not $a.ok) { return (& $no ([string]$a.reason)) }
        $payload = Expand-SICommunityArchive -ZipPath $zip -Destination (Join-Path $Work ('p-' + [guid]::NewGuid().ToString('N').Substring(0, 6)))
        $pv = Get-SICommunityRunningVersion -Root $payload
        if ($pv -ne [string]$m.version) { return (& $no ("the archive says it is {0}, the signed manifest names {1}" -f $pv, $m.version)) }
        foreach ($c in @($script:SICommunityUpdateClientFiles) + @($script:SIUpdaterCommunityRequiredFiles)) {
            if (-not "$c".Trim()) { continue }
            # one segment at a time: [IO.Path]::Combine(object[]) binds to the wrong overload in PowerShell
            $full = [string]$payload; foreach ($seg in @("$c" -split '/')) { $full = [IO.Path]::Combine($full, $seg) }
            if (-not (Test-Path -LiteralPath $full)) { return (& $no ("the release does not carry {0} -- installing it would end updates for this install" -f $c)) }
        }
        # the public copy carries no BUILD.json; the web app image needs one (pro-management/Dockerfile) -- stamped from the
        # release's own VERSION before anything is built (engine/_shared/SI-BuildInfo.ps1)
        try {
            if (-not (Get-Command -Name Initialize-SIBuildInfoFile -ErrorAction SilentlyContinue)) {
                $bi = [IO.Path]::Combine($payload, 'engine', '_shared', 'SI-BuildInfo.ps1'); if (Test-Path -LiteralPath $bi) { . $bi }
            }
            if (Get-Command -Name Initialize-SIBuildInfoFile -ErrorAction SilentlyContinue) {
                $bjs = Initialize-SIBuildInfoFile -SolutionRoot $payload -Channel 'community' -Ring $Ring
                if ($bjs -eq 'written') { Write-UpdLog ("BUILD.json written for {0} (the public copy carries none)" -f $m.version) }
            }
        } catch { Write-UpdLog ("WARNING: BUILD.json could not be written ({0}) -- the web app image build may fail" -f $_.Exception.Message) }
        [pscustomobject]@{ Ok = $true; Reason = ("SecurityInsight {0} downloaded and verified (size + SHA-256 = the signed ones)" -f $m.version); Root = [string]$payload
                           Commit = (Get-SIUpdaterCommunityReleaseCommit -PayloadRoot $payload); Version = [string]$m.version }
    } catch { & $no ("the release could not be checked: {0}" -f $_.Exception.Message) }
}

# The release checks and their verifier (Test-SICommunityChannelEntry / Expand-SICommunityArchive / Test-InvardiaArchiveFile),
# from the code this image carries (/si) or this checkout -- loaded once here.
if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) {
    $siCommunityRoot = Find-SIUpdaterCommunityRoot
    if ($siCommunityRoot) { . ([IO.Path]::Combine($siCommunityRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1')) }
}
