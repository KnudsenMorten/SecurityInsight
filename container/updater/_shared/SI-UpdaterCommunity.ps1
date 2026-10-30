#Requires -Version 5.1
<#
    caj-si-updater -- UPDATES FOR THE COMMUNITY EDITION, IN THE CLOUD, AS PRO (SI #750 (b), owner 2026-10-18: "the IN-CLOUD
    UPDATER, as Pro, on the community channel"). Loaded by Start-SIUpdater.ps1 when the image carries NO Invardia update
    client (_shared/SI-UpdaterInvardia.ps1 is SecurityInsight Pro only) and DOES carry the signed Community client
    (/si/engine/_shared/SI-CommunityUpdate.ps1 + InvardiaUpdate.verify.ps1). A Pro image never takes this path.

    One run:
      1. THE RING: Community rings only -- 2 (early release) or 3 (broad, the default). SI_UPDATER_RING on the job (2 or 3;
         recorded for the install), else the ring recorded for the install (cfg.InstallState 'Ring'), else the admin's
         SI_UpdateRing setting, else 3. Anything else (0, 1, a word) -> ring 3, said in the log.
      2. THE MANIFEST (owner + Invardia + PIM, 2026-10-28: the same Community path as PIM): GET
         https://invardia.com/api/updates/securityinsight/community/<ring>, ANONYMOUS (no install key, no code, no licence);
         200 = { manifest, manifestB64, signature, keyId, downloadUrl } SIGNED BY INVARDIA (the same RS256 family as Pro, kind
         community), 204 = nothing released to the ring yet, 404 = no such ring. SI_UPDATER_COMMUNITY_BASE_URL overrides the
         base, https only (a rehearsal against a test endpoint).
      3. THE CHECK, before anything is downloaded (Test-SICommunityChannelEntry): RS256 over the decoded manifest against the
         keys EMBEDDED in this release (engine/_shared/InvardiaUpdate.verify.ps1 -- the channel file itself is never trusted),
         product securityinsight, kind community, a ring it names = this install's ring, the sequence not lower than the one
         applied here (no replay), manualStep / minFromVersion HOLD, an https download link, the SAME MAJOR version as the
         installed one (owner 2026-10-28: a new major version is a new installation, never an update). A first manifest that
         names a version OLDER than the jobs run is held (forward-only until a release was applied from the channel).
      4. THE ARCHIVE: downloaded (no git), its size and SHA-256 = the signed ones (Test-InvardiaArchiveFile), extracted safely
         (Expand-SICommunityArchive: no rooted path, no '..'), its VERSION = the signed version, and it carries the update
         client and this updater, so an update never strands the install.
      5. THE ROLL -- the SAME steps as Pro (_shared/SI-UpdaterRollSteps.ps1 + Start-SIUpdater.ps1): the manual-deploy mark,
         the RUN GATE (never while a pipeline run is going; the wait is handed to the pipeline runner), Invoke-SIUpdaterRoll
         (the database step FIRST -- the release's own schema + grants, _shared/SI-UpdaterDatabase.ps1 -- then the release's
         setup/Invoke-SIContainerUpdate.ps1 builds in YOUR registry and rolls every job, restoring on failure), then the web
         app (_shared/SI-UpdaterWebApp.ps1), the installed record and, LAST, the updater's own job.
      6. THE STATE in the database: cfg.InstallState 'CommunityUpdateState' (applied sequence / version / ring) and the compact
         'UpdateState' the web app's Settings page reads (source 'community'). Without the database the running version is
         the guard (an entry for the version the jobs run is 'current'; an older one is held).
    NOT IN THE COMMUNITY EDITION: no install key, no claim, no licence request to Invardia, no template channel (the release
    installs its own templates through the template gate), no update tracking or failure report to Invardia (the run's
    failures are in the job's log and the Settings page). Every call that leaves the process goes through -Seams (tests).
#>

# Invardia's Community manifest route (the same family PIM's Community edition reads); rings 2 and 3 only.
$script:SIUpdaterCommunityBaseUrl = 'https://invardia.com'

function Get-SIUpdaterCommunityManifestUri {
    <# PURE. GET <base>/api/updates/securityinsight/community/<ring> -- anonymous; ring 2 or 3. #>
    param([Parameter(Mandatory)][string]$BaseUrl, [Parameter(Mandatory)][ValidateSet(2, 3)][int]$Ring)
    '{0}/api/updates/securityinsight/community/{1}' -f $BaseUrl.TrimEnd('/'), $Ring
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
       that holds the signed Community client. $null when none does. #>
    param([string[]]$Candidates)
    if (-not $Candidates) { $Candidates = @('/si', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..')) }
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath ([IO.Path]::Combine($c, 'engine', '_shared', 'SI-CommunityUpdate.ps1')))) { return [IO.Path]::GetFullPath($c) }
    }
    $null
}

function Resolve-SIUpdaterCommunityRing {
    <#
        The Community ring this install pulls for: 2 or 3, never 0 / 1 (internal rings never come from the public channel).
        Returns @{ Ring; Source; Reason }. Never throws.
          1. SI_UPDATER_RING on the job (-EnvRing): 2 or 3 -> that ring, recorded for the install; anything else -> ring 3, said;
          2. the ring recorded for the install (cfg.InstallState 'Ring'), when it is 2 or 3; a recorded 0 / 1 -> ring 3, said;
          3. the admin's SI_UpdateRing setting, when it is 2 or 3;
          4. ring 3 (broad).
    #>
    param([AllowEmptyString()][string]$EnvRing, $Store, [string]$ResourceGroup = '')
    $out = { param($r, $src, $why) [pscustomobject]@{ Ring = [int]$r; Source = $src; Reason = $why } }
    $ok = @(2, 3)
    $envText = "$EnvRing".Trim()
    if ($envText) {
        $n = 0
        if ([int]::TryParse($envText, [ref]$n) -and $ok -contains $n) {
            if ($Store -and (Get-Command -Name Invoke-SIRecordInstallRing -ErrorAction SilentlyContinue)) {
                try { $null = Invoke-SIRecordInstallRing -Store $Store -Ring $n -RingSource updater -ResourceGroupName $ResourceGroup -Channel 'community' -SetBy 'caj-si-updater' } catch { }
            }
            return (& $out $n 'SI_UPDATER_RING' ("ring {0} (SI_UPDATER_RING on the updater job)" -f $n))
        }
        return (& $out 3 'default' ("SI_UPDATER_RING '{0}' is not a Community ring (2 = early release, 3 = broad) -- ring 3 is used" -f $envText))
    }
    if ($Store) {
        if (Get-Command -Name Read-SIInstallRing -ErrorAction SilentlyContinue) {
            $row = $null; try { $row = Read-SIInstallRing -Store $Store } catch { $row = $null }
            if ($row -and $null -ne $row.Ring) {
                if ($ok -contains [int]$row.Ring) { return (& $out ([int]$row.Ring) 'install' ("ring {0} (recorded for this install)" -f $row.Ring)) }
                return (& $out 3 'default' ("the ring recorded for this install ({0}) is not a Community ring -- ring 3 is used" -f $row.Ring))
            }
        }
        if (Get-Command -Name Read-SIUpdateRingSetting -ErrorAction SilentlyContinue) {
            $set = $null; try { $set = Read-SIUpdateRingSetting -Store $Store } catch { $set = $null }
            if ($null -ne $set -and $ok -contains [int]$set) { return (& $out ([int]$set) 'setting' ("ring {0} (the Update ring setting)" -f $set)) }
        }
    }
    & $out 3 'default' 'ring 3 (broad, the Community default)'
}

function ConvertFrom-SIUpdaterManualStepAcceptCommunity {
    <# PURE. SI_UPDATER_ACCEPT_MANUAL_STEP = 'community:<sequence>' (or 'code:<sequence>', the Pro form) -> the sequence; -1 = none. #>
    param([AllowEmptyString()][string]$Text)
    foreach ($p in @("$Text" -split '[,;\s]+' | Where-Object { $_ })) {
        if ($p -match '^(community|code):(\d{1,18})$') { return [long]$Matches[2] }
    }
    [long]-1
}

function ConvertFrom-SIUpdaterCommunityState {
    <# PURE. cfg.InstallState 'CommunityUpdateState' -> @{ appliedSequence; appliedVersion; ring; appliedUtc }. Unreadable = none. #>
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

function ConvertTo-SIUpdaterCommunityStateJson {
    <# PURE. The applied release as one compact row (cfg.InstallState.Value is NVARCHAR(400)). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)
    ([ordered]@{ seq = [long]$State.appliedSequence; ver = "$($State.appliedVersion)"; ring = [int]$State.ring; at = "$($State.appliedUtc)" } | ConvertTo-Json -Compress)
}

function ConvertTo-SIUpdaterCommunityUpdateStateJson {
    <#
        PURE. The compact 'UpdateState' row the web app's Settings page and the health check read -- the same shape a Pro install
        writes (source, lastCheckUtc, code { version, sequence, ring, action, applied, hold }, error, waits), with source
        'community'. Shortened to fit 400 characters.
    #>
    param([Parameter(Mandatory)][datetime]$NowUtc, [string]$Version = '', [long]$Sequence = 0, [int]$Ring = 0, [string]$Action = '',
          [long]$Applied = 0, [string]$Hold = '', [string]$ErrorText = '', $WaitsSinceUtc = $null, [string]$WaitsReason = '')
    $iso = { param($d) ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $json = ''
    foreach ($max in 90, 50, 20, 0) {
        $short = { param($t) $t = "$t"; if ($t.Length -gt $max) { if ($max -le 3) { '' } else { $t.Substring(0, $max - 3) + '...' } } else { $t } }
        $c = [ordered]@{ source = 'community'; lastCheckUtc = (& $iso $NowUtc)
                         code = [ordered]@{ version = $Version; sequence = $Sequence; ring = $Ring; action = $Action; applied = $Applied; hold = (& $short $Hold) }
                         error = (& $short $ErrorText) }
        if ($WaitsSinceUtc) { $c['waits'] = [ordered]@{ since = (& $iso $WaitsSinceUtc); kind = 'run'; why = (& $short $WaitsReason) } }
        $json = $c | ConvertTo-Json -Compress -Depth 4
        if ($json.Length -le 400) { return $json }
    }
    $json
}

function Read-SIUpdaterCommunityStateRow {
    <# The 'CommunityUpdateState' row's value from the install's database, '' when none / no table / no database. Never throws. #>
    param($Store)
    if (-not $Store) { return '' }
    try {
        $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @Name" ([ordered]@{ Name = 'CommunityUpdateState' }) 'reader' | ForEach-Object { $_ })
        $row = $rows | Select-Object -First 1
        if (-not $row) { return '' }
        [string]$(if ($row -is [System.Collections.IDictionary]) { $row['Value'] } else { $row.Value })
    } catch { Write-UpdLog ("WARNING: the Community update state could not be read ({0}) -- the running version is the guard this run" -f $_.Exception.Message); '' }
}

function Get-SIUpdaterCommunityReleaseCommit {
    <# The commit the release was built from (BUILD.json in the payload), '' when it carries none. #>
    param([Parameter(Mandatory)][string]$PayloadRoot)
    $f = [IO.Path]::Combine($PayloadRoot, 'BUILD.json')
    if (-not (Test-Path -LiteralPath $f)) { return '' }
    try { "$(([IO.File]::ReadAllText($f).TrimStart([char]0xFEFF) | ConvertFrom-Json).commit)".Trim().ToLowerInvariant() } catch { '' }
}

# The files a release must carry for THIS updater to keep updating the install after it (besides the client's own).
$script:SIUpdaterCommunityRequiredFiles = @('setup/Invoke-SIContainerUpdate.ps1', 'container/updater/Start-SIUpdater.ps1', 'container/updater/_shared/SI-UpdaterCommunity.ps1')

function Test-SIUpdaterCommunityMajor {
    <#
        PURE. Owner 2026-10-28: the Community updater refuses a release whose MAJOR version differs from the installed one
        (3.x never moves to 4.x, and nothing moves a 2.2 install to 3: a new major version is a new installation beside the
        old one). Returns the reason in plain words, or '' when the majors match. An installed version that cannot be read
        is refused too (fail closed: nothing is applied without knowing what runs).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Installed, [AllowEmptyString()][AllowNull()][string]$Release)
    $maj = { param($v) $m = [regex]::Match("$v".Trim(), '^v?(\d+)\.'); if ($m.Success) { [int]$m.Groups[1].Value } else { -1 } }
    $i = & $maj $Installed; $r = & $maj $Release
    if ($r -lt 0) { return ("the release names no readable version ('{0}')" -f $Release) }
    if ($i -lt 0) { return ("the installed version cannot be read ('{0}'), so a release of another major version cannot be ruled out" -f $Installed) }
    if ($i -ne $r) { return ("the release is SecurityInsight {0}, another major version than the installed {1} -- a new major version is installed beside the old one, never as an update" -f $Release, $Installed) }
    ''
}

function Invoke-SIUpdaterFromCommunity {
    <#
        One update run from the signed Community channel. Returns the exit code (0 = nothing to do / applied / held / waits;
        1 = refused or a step failed). -Seams (tests and the rehearsal): GetText { param($Url) }, Download { param($Url, $OutFile) },
        Now, TrustedKeys { } -> the trust list, DownloadPrefix, RunGate { param($Holder) }, ExitGate, ReadWaits, WriteWaits,
        SecondPass, PreRoll { }, PostRoll { param($SIRoot, $Version, $Commit) }, SizingPass { param($Why) }, SelfRetry { },
        ReadState { } -> json, WriteState { param($Name, $Json) }.
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$AcrName, [string[]]$Blocked = @(), $Store, [AllowEmptyString()][string]$Deployed,
          [string]$AcceptFingerprint, [string]$SIRoot, [hashtable]$Seams = @{}, [string]$Work)
    $get = { param($k) $v = if ($Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; if ([string]::IsNullOrWhiteSpace($v)) { '' } else { "$v".Trim() } }
    $nameOf = { param($role) if (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue) { Get-SIUpdaterInstallName -Role $role -Env $Env }
                             else { @{ web = 'ca-si-management'; mcp = 'ca-si-mcp'; updater = 'caj-si-updater' }[$role] } }
    if (-not $SIRoot) { $SIRoot = Find-SIUpdaterCommunityRoot }
    if (-not $SIRoot) { Write-UpdLog 'Community updates: this updater image does not carry the signed Community client -- re-run setup/Install-SIUpdaterJob.ps1 to rebuild it'; return 1 }
    if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1')) }
    $s = New-SICommunityUpdateSeams
    $s['GetManifest'] = { param($Url) Invoke-SIUpdaterCommunityManifestHttp -Url $Url }
    foreach ($k in @($Seams.Keys)) { $s[$k] = $Seams[$k] }
    $now = ([datetime](& $s.Now)).ToUniversalTime()
    $keys = if ($s.Contains('TrustedKeys') -and $s['TrustedKeys']) { @(& $s.TrustedKeys) } else { @($script:SICommunityTrustedKeys) }
    $prefix = if ($s.Contains('DownloadPrefix') -and "$($s['DownloadPrefix'])".Trim()) { "$($s['DownloadPrefix'])".Trim() } else { 'https://' }   # the signed manifest names the archive; an https link is required
    if (-not $Work) { $Work = Join-Path ([IO.Path]::GetTempPath()) ('si-cupd-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
    New-Item -ItemType Directory -Force -Path $Work | Out-Null
    $real = -not (Get-Module -Name Pester)

    # ---- the state: what was applied from the channel (the database), else nothing ----
    $stateJson = if ($s.Contains('ReadState') -and $s['ReadState']) { [string](& $s.ReadState) } else { Read-SIUpdaterCommunityStateRow -Store $Store }
    $state = ConvertFrom-SIUpdaterCommunityState -Json $stateJson
    $Deployed = Resolve-SIUpdaterRunningRelease -Deployed $Deployed -AppliedVersion ([string]$state.appliedVersion)
    $global:SI_UpdaterEngineVersion = "$Deployed".Trim()
    $view = @{ Version = ''; Sequence = [long]0; Action = ''; Hold = ''; Error = ''; WaitsSince = $null; WaitsReason = '' }
    $ring = Resolve-SIUpdaterCommunityRing -EnvRing (& $get 'SI_UPDATER_RING') -Store $Store -ResourceGroup $ResourceGroup
    Write-UpdLog ("update ring: {0}" -f $ring.Reason)
    $global:SI_UpdaterResolvedRing = $ring.Ring
    $write = { param($name, $json)
        if ($s.Contains('WriteState') -and $s['WriteState']) { $null = & $s.WriteState $name $json }
        elseif ($Store -and (Get-Command -Name Save-SIUpdaterInstallStateValue -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterInstallStateValue -Store $Store -Name $name -Value $json } }
    $save = {
        try {
            & $write 'CommunityUpdateState' (ConvertTo-SIUpdaterCommunityStateJson -State $state)
            & $write 'UpdateState' (ConvertTo-SIUpdaterCommunityUpdateStateJson -NowUtc $now -Version $view.Version -Sequence $view.Sequence -Ring $ring.Ring -Action $view.Action `
                                       -Applied $state.appliedSequence -Hold $view.Hold -ErrorText $view.Error -WaitsSinceUtc $view.WaitsSince -WaitsReason $view.WaitsReason)
        } catch { Write-UpdLog ("WARNING: the Community update state could not be saved: {0}" -f $_.Exception.Message) }
    }
    $applied = { param($chk) $state.appliedSequence = [long]$chk.Sequence; $state.appliedVersion = [string]$chk.Version; $state.ring = $ring.Ring; $state.appliedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }

    # ---- THE RUN GATE (as Pro): nothing that changes the install while a pipeline run is going; the wait is handed to the
    # pipeline runner (tag si-update-waits). A test that brings no seam never reaches Azure or a database (Go). ----
    $gate = @{ Result = $null; Deferred = $false; TagRead = $false; Tag = $null; JobId = ''; Cleared = $false; SecondPass = $false }
    $updaterJob = & $nameOf 'updater'
    $holder = if (Get-Command -Name Get-SIUpdaterRunGateHolder -ErrorAction SilentlyContinue) { Get-SIUpdaterRunGateHolder -Env $Env } else { 'caj-si-updater' }
    $readTag = {
        if ($gate.TagRead) { return }
        $gate.TagRead = $true
        try {
            $t = if ($s['ReadWaits']) { & $s.ReadWaits } elseif ($real -and (Get-Command -Name Read-SIUpdaterWaitsTag -ErrorAction SilentlyContinue)) { Read-SIUpdaterWaitsTag -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -JobName $updaterJob } else { $null }
            if ($t) { $gate.Tag = ConvertFrom-SIUpdateWaitsTag -Value ([string]$t.Value); $gate.JobId = [string]$t.JobId }
        } catch { Write-UpdLog ("the update's wait mark could not be read: {0}" -f $_.Exception.Message) }
    }
    $writeTag = { param($value)
        if ($s['WriteWaits']) { $null = & $s.WriteWaits $value }
        elseif ($real -and $gate.JobId) { $null = Write-SIUpdaterWaitsTag -JobId $gate.JobId -Value $value } }
    $askGate = {
        if ($s['RunGate']) { & $s.RunGate $holder }
        elseif ($real -and (Get-Command -Name Invoke-SIUpdaterRunGate -ErrorAction SilentlyContinue)) {
            Invoke-SIUpdaterRunGate -Store $Store -Holder $holder -SubscriptionId $SubscriptionId `
                -BusyJobs { $en = Get-SIUpdaterEnvironment -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $updaterJob
                            @(Get-SIUpdaterBusyJobs -JobNames @($en.JobNames) -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) } `
                -DatabaseMissing { if ($Store -and "$($Store.Server)" -and "$($Store.Database)") { Test-SIUpdaterDatabaseMissing -Server ([string]$Store.Server) -Database ([string]$Store.Database) -SubscriptionId $SubscriptionId } else { $false } }
        } else { [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no run gate in this image'; RunId = ''; LockTaken = $false; Holder = '' } }
    }
    $passGate = {
        if ($gate.Result) { return $gate.Result }
        $r = & $askGate
        Write-UpdLog ("run gate: {0}" -f $r.Reason)
        # #947 (b): a bound on the wait, as Pro (SI-UpdaterInvardia.ps1): after 6 hours a run that started on an OLDER version
        # is cancelled and the update is installed. Seam (tests): CancelRun { param($RunId, $TargetVersion, $Reason) }.
        if (-not $r.Go -and ($s['CancelRun'] -or ($real -and (Get-Command -Name Invoke-SIUpdaterCancelOldRun -ErrorAction SilentlyContinue))) -and (Get-Command -Name Invoke-SIUpdaterOverdueCancel -ErrorAction SilentlyContinue)) {
            & $readTag
            $odSince = if ($gate.Tag) { $gate.Tag.SinceUtc } else { $null }
            $odTarget = if ($chk -and $chk.Version) { "$($chk.Version)".Trim() } else { '' }
            $r = Invoke-SIUpdaterOverdueCancel -Gate $r -SinceUtc $odSince -NowUtc $now -TargetVersion $odTarget -GateAgain $askGate -Log { param($m) Write-UpdLog $m } `
                     -Sleep $(if ($s['Sleep']) { $s['Sleep'] } else { { param($sec) Start-Sleep -Seconds $sec } }) `
                     -Cancel { param($id, $ver, $why) if ($s['CancelRun']) { & $s.CancelRun $id $ver $why } else { Invoke-SIUpdaterCancelOldRun -Store $Store -RunId $id -TargetVersion $ver -Reason $why -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Holder $holder } }
            if ($r.Go) { Write-UpdLog ("run gate: {0}" -f $r.Reason) }
        }
        $gate.Result = $r
        if ($r.Go) { & $readTag; if ($gate.Tag) { & $writeTag ''; $gate.Cleared = $true } }
        $r
    }
    $markWaits = { param($r)
        if ($gate.Deferred) { return }
        & $readTag
        $since = if ($gate.Tag) { $gate.Tag.SinceUtc } else { $now }
        $view.WaitsSince = $since; $view.WaitsReason = [string]$r.Reason
        if (Get-Command -Name ConvertTo-SIUpdateWaitsTag -ErrorAction SilentlyContinue) { & $writeTag (ConvertTo-SIUpdateWaitsTag -SinceUtc $since -SetUtc $now -Kind $(if ($r.Kind) { [string]$r.Kind } else { 'run' }) -Reason ([string]$r.Reason)) }
        $gate.Deferred = $true }
    $selfOff = ((& $get 'SI_UPDATER_SELF_UPDATE') -match '^(?i)(0|false|off|no)$')

    $rc = 0; $rolled = $false; $roll = $null; $chk = $null
    try {
    try {
        if ($Blocked -contains 'engine-image') {
            Write-UpdLog 'code: the customer blocks engine-image updates -- the channel is not read'
            $view.Action = 'blocked'
        } else {
            $global:SI_UpdaterStep = 'manifest'
            # THE COMMUNITY MANIFEST FROM INVARDIA (owner + Invardia + PIM, 2026-10-28 -- the same route PIM's Community edition
            # reads): GET <base>/api/updates/securityinsight/community/<ring>, ANONYMOUS (no install key, no code, no licence).
            # 200 = { manifest, manifestB64, signature, keyId, downloadUrl } (signed like Pro's, kind community); 204 = nothing
            # released to this ring yet; 404 = no such ring. SI_UPDATER_COMMUNITY_BASE_URL overrides the base, https only
            # (a rehearsal against a test endpoint).
            $base = & $get 'SI_UPDATER_COMMUNITY_BASE_URL'
            if ($base -and $base -notmatch '^https://') { Write-UpdLog ("SI_UPDATER_COMMUNITY_BASE_URL is not https ('{0}') -- Invardia's endpoint is read" -f $base); $base = '' }
            if (-not $base) { $base = $script:SIUpdaterCommunityBaseUrl }
            $url = Get-SIUpdaterCommunityManifestUri -BaseUrl $base -Ring $ring.Ring
            $ans = $null
            try { $ans = & $s.GetManifest $url }
            catch { $view.Action = 'network'; $view.Error = ("the Community manifest could not be read: {0}" -f $_.Exception.Message); Write-UpdLog ("code: {0} -- nothing changed; the next run asks again" -f $view.Error); & $save; return 0 }
            $st = [int]$ans.Status
            $entry = $null
            if ($st -eq 204) { $entry = $null }
            elseif ($st -eq 200) {
                try { $entry = "$($ans.Body)".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop } catch { $entry = $null }
                if (-not $entry) { $view.Action = 'refused'; $view.Error = 'the Community manifest answer is not JSON'; Write-UpdLog ("code REFUSED: {0} -- nothing changed" -f $view.Error); & $save; return 1 }
            }
            elseif ($st -eq 404) { $view.Action = 'refused'; $view.Error = ("Invardia knows no Community ring {0} (404)" -f $ring.Ring); Write-UpdLog ("code REFUSED: {0} -- nothing changed" -f $view.Error); & $save; return 1 }
            else { $view.Action = 'network'; $view.Error = ("the Community manifest answered {0}" -f $st); Write-UpdLog ("code: {0} -- nothing changed; the next run asks again" -f $view.Error); & $save; return 0 }
            if (-not $entry) { $view.Action = 'none'; Write-UpdLog ("code: nothing is released to ring {0} yet -- this install stays on {1}" -f $ring.Ring, $(if ($Deployed) { $Deployed } else { 'its version' })) }
            else {
                $chk = Test-SICommunityChannelEntry -Entry $entry -Ring $ring.Ring -TrustedKeys $keys -AppliedSequence ([long]$state.appliedSequence) `
                           -RunningVersion "$Deployed" -AcceptManualStepSequence (ConvertFrom-SIUpdaterManualStepAcceptCommunity (& $get 'SI_UPDATER_ACCEPT_MANUAL_STEP')) -DownloadPrefix $prefix -RingOptional
                $view.Version = [string]$chk.Version; $view.Sequence = [long]$chk.Sequence; $view.Action = [string]$chk.Action
                Write-UpdLog ("code manifest: {0} -- {1}" -f $chk.Action, $chk.Reason)
                if ($chk.Action -eq 'refused') { $view.Error = [string]$chk.Reason; & $save; return 1 }
                # owner 2026-10-28: a release of ANOTHER MAJOR VERSION is never applied (a new major version is a new
                # installation beside the old one, as 3 beside 2.2) -- refused before anything is downloaded
                if ($chk.Action -in 'update', 'hold') {
                    $installed = if ("$Deployed".Trim()) { "$Deployed" } else { Get-SICommunityRunningVersion -Root $SIRoot }
                    $mj = Test-SIUpdaterCommunityMajor -Installed $installed -Release ([string]$chk.Version)
                    if ($mj) { $view.Action = 'refused'; $view.Error = $mj; Write-UpdLog ("code REFUSED: {0} -- nothing changed" -f $mj); & $save; return 1 }
                }
                if ($chk.Action -eq 'hold') { $view.Hold = [string]$chk.Reason }
                if ($chk.Action -eq 'current' -and [long]$chk.Sequence -gt [long]$state.appliedSequence) { & $applied $chk }
                # forward-only, as Pro: a first entry that names a version older than the jobs run is held, never rolled back to
                if ($chk.Action -eq 'update' -and $chk.IsRollback -and [long]$state.appliedSequence -le 0) {
                    $view.Action = 'hold'; $view.Hold = ("HELD: ring {0} names {1}, older than the {2} the jobs run, and no release has been applied from the channel here yet -- the updater never moves the jobs backward on a first manifest" -f $ring.Ring, $chk.Version, $Deployed)
                    Write-UpdLog ("code: {0}" -f $view.Hold)
                }
                elseif ($chk.Action -eq 'update') {
                    # ---- download + prove it is the signed archive ----
                    $global:SI_UpdaterStep = 'download'
                    $zip = Join-Path $Work 'r.zip'
                    try { & $s.Download $chk.DownloadUrl $zip | Out-Null }
                    catch { $view.Action = 'network'; $view.Error = ("the release could not be downloaded: {0}" -f $_.Exception.Message); Write-UpdLog ("code: {0} -- nothing changed" -f $view.Error); & $save; return 1 }
                    $global:SI_UpdaterStep = 'verify'
                    $a = Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 $chk.Sha256 -ExpectedSize $chk.Size
                    $why = ''
                    $payload = $null
                    if (-not $a.ok) { $why = [string]$a.reason }
                    else {
                        try { $payload = Expand-SICommunityArchive -ZipPath $zip -Destination (Join-Path $Work 'p') } catch { $why = $_.Exception.Message }
                    }
                    if (-not $why) {
                        $pv = Get-SICommunityRunningVersion -Root $payload
                        if ($pv -ne $chk.Version) { $why = ("the archive says it is {0}, the signed manifest names {1}" -f $pv, $chk.Version) }
                    }
                    if (-not $why) {
                        foreach ($c in @($script:SICommunityUpdateClientFiles) + @($script:SIUpdaterCommunityRequiredFiles)) {
                            # one segment at a time: [IO.Path]::Combine(object[]) binds to the wrong overload in PowerShell
                            $full = [string]$payload; foreach ($seg in @($c -split '/')) { $full = [IO.Path]::Combine($full, $seg) }
                            if (-not (Test-Path -LiteralPath $full)) { $why = ("the release does not carry {0} -- installing it would end updates for this install" -f $c); break }
                        }
                    }
                    if ($why) { $view.Action = 'refused'; $view.Error = $why; Write-UpdLog ("code REFUSED: {0} -- nothing was rolled" -f $why); & $save; return 1 }
                    Write-UpdLog ("SecurityInsight {0} downloaded and verified (size + SHA-256 = the signed ones)" -f $chk.Version)
                    # the public copy carries no BUILD.json; the web app image needs one (pro-management/Dockerfile) -- stamped
                    # from the release's own VERSION before anything is built (engine/_shared/SI-BuildInfo.ps1)
                    try {
                        if (-not (Get-Command -Name Initialize-SIBuildInfoFile -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($payload, 'engine', '_shared', 'SI-BuildInfo.ps1')) }
                        $bjs = Initialize-SIBuildInfoFile -SolutionRoot $payload -Channel 'community' -Ring $ring.Ring
                        if ($bjs -eq 'written') { Write-UpdLog ("BUILD.json written for {0} (the public copy carries none)" -f $chk.Version) }
                    } catch { Write-UpdLog ("WARNING: BUILD.json could not be written ({0}) -- the web app image build may fail" -f $_.Exception.Message) }
                    $commit = Get-SIUpdaterCommunityReleaseCommit -PayloadRoot $payload

                    # ---- never under a manual deploy; a release that needs quiet waits ----
                    $waitMin = 60; [void][int]::TryParse((& $get 'SI_UPDATER_WAIT_MINUTES'), [ref]$waitMin); if ($waitMin -le 0) { $waitMin = 60 }
                    $pre = if ($s['PreRoll']) { & $s.PreRoll } else { Invoke-SIUpdaterInvardiaPreRoll -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $updaterJob -WaitMinutes $waitMin -SIRoot $payload }
                    $go = $true
                    if (-not $pre.Go) { $go = $false; $view.Action = 'deferred'; $view.WaitsReason = [string]$pre.Reason; Write-UpdLog ("code: deferred -- {0}" -f $pre.Reason) }
                    $recorded = if ($pre.Environment -and $pre.Environment.Record) { "$($pre.Environment.Record.Version)".Trim() } else { '' }
                    if ($go -and $recorded -and $recorded -eq "$($chk.Version)") {
                        & $applied $chk; $go = $false; $global:SI_UpdaterEngineVersion = "$($chk.Version)"
                        Write-UpdLog ("code: {0} is recorded as installed on this environment (a manual deploy of this release) -- nothing to roll" -f $chk.Version)
                    }
                    if ($go) {
                        $gr = & $passGate
                        if (-not $gr.Go) { $view.Action = 'deferred'; Write-UpdLog ("code: deferred -- {0}" -f $gr.Reason); & $markWaits $gr }
                        else {
                            $roll = Invoke-SIUpdaterRoll -SIRoot $payload -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Store $Store `
                                        -AcceptFingerprint $AcceptFingerprint -Version "$($chk.Version)" -Commit $commit `
                                        -WebApp (& $nameOf 'web') -McpApp (& $nameOf 'mcp') -UpdaterJob $updaterJob -SelfOff:$selfOff
                            if ($roll.Held) { $view.Action = 'hold'; $view.Hold = [string]$roll.Reason; Write-UpdLog ("code: held -- {0}" -f $roll.Reason) }
                            elseif ($roll.Code -eq 0) {
                                & $applied $chk; $rolled = $true; $view.Action = 'applied'
                                $global:SI_UpdaterEngineVersion = "$($chk.Version)"
                                $post = if ($s['PostRoll']) { & $s.PostRoll $payload $chk.Version $commit }
                                        else { Invoke-SIUpdaterInvardiaPostRoll -SIRoot $payload -Version $chk.Version -Commit $commit -Environment $pre.Environment -ResourceGroup $ResourceGroup `
                                                   -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $updaterJob -WebApp (& $nameOf 'web') -McpApp (& $nameOf 'mcp') -SelfOff:$selfOff }
                                Write-UpdLog ("code: {0}" -f $post.Text)
                                if ($post.Code -ne 0) { $rc = 1; $view.Error = [string]$post.Text }
                                elseif ($post.PSObject.Properties['SelfAction'] -and [string]$post.SelfAction -eq 'rolled') { $gate.SecondPass = $true }
                            } else {
                                $rc = [int]$roll.Code; $view.Action = 'failed'
                                $view.Error = $(if ($roll.Reason) { [string]$roll.Reason } else { "the roll failed (exit $($roll.Code)); the jobs were restored" })
                            }
                        }
                    }
                }
            }
        }
        # #756 (as Pro): no new code this run -- the sizes the customer's settings set still apply; never under a running run
        if ((-not $roll -or $roll.Held) -and -not $gate.Deferred) {
            $why = if ($view.Action -in 'current', 'none') { 'the code is current' } else { 'no new code is installed this run' }
            $grS = & $passGate
            if (-not $grS.Go) { Write-UpdLog ("sizes: not checked now -- {0}" -f $grS.Reason); & $markWaits $grS }
            elseif ($s['SizingPass']) { $null = & $s.SizingPass $why }
            elseif ($real) { $null = Invoke-SIUpdaterSizingPass -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Store $Store -Why $why }
        }
        # #350 (c): nothing rolled, but an earlier run could not move the updater itself -- try again (never fails the run)
        if (-not $rolled -and -not $selfOff) {
            if ($s['SelfRetry']) { $null = & $s.SelfRetry } elseif ($real) { $null = Invoke-SIUpdaterInvardiaSelfRetry -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $updaterJob }
        }
    } catch {
        $view.Error = $_.Exception.Message
        Write-UpdLog ("Community update FAILED: {0}" -f $view.Error)
        $rc = 1
    }
    & $save
    $rc
    } finally {
        if ($gate.Result -and $gate.Result.LockTaken) {
            $null = if ($s['ExitGate']) { & $s.ExitGate $holder } elseif ($real) { Exit-SIUpdaterRunGate -Store $Store -Holder $holder } else { $null }
            Write-UpdLog 'run gate: the install''s lock is released'
        }
        if (-not $gate.Deferred -and -not $gate.Cleared) { & $readTag; if ($gate.Tag) { & $writeTag '' } }
        if ($gate.SecondPass) {
            $line = if ($s['SecondPass']) { & $s.SecondPass } elseif ($real -and (Get-Command -Name Start-SIUpdaterSecondPass -ErrorAction SilentlyContinue)) { Start-SIUpdaterSecondPass -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -JobName $updaterJob } else { '' }
            if ($line) { Write-UpdLog $line }
        }
        try { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
}

# The signed Community client and its verifier, from the code this image carries (/si) or this checkout -- loaded once here,
# so the run above finds Test-SICommunityChannelEntry / Expand-SICommunityArchive / Test-InvardiaArchiveFile.
if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) {
    $siCommunityRoot = Find-SIUpdaterCommunityRoot
    if ($siCommunityRoot) { . ([IO.Path]::Combine($siCommunityRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1')) }
}
