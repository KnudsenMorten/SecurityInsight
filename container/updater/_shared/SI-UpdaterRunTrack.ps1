#Requires -Version 5.1
<#
    SecurityInsight updater -- EVERY UPDATE RUN REPORTS ITS STAGES TO INVARDIA (#506; framework DOCS/REQUIREMENTS.md §8.8
    UPDATE-TRACK, owner 2026-10-09: "it could be nice to see the stage an installation is in" -> "same with the updater
    telemetry"). Invardia live 1.0.228+ (POST /api/install/runs, migration 045).

    THE CONTRACT (Invardia apps/front/src/install.ts + packages/core/src/install.ts):
      OPEN   POST <base>/api/install/runs, header X-Invardia-Install-Key = the install key (the key of the update pull),
             body EXACTLY { productId: 'securityinsight', kind: 'update', ring: 0-3, fromVersion, toVersion }
             -> 201 { runId, token, tokenHeader: 'X-Invardia-Install-Token', eventsUrl, statusUrl }
      EVENTS POST <eventsUrl> (= <base>/api/install/events), header X-Invardia-Install-Token = the run's token, body
             { seq, step: { id, title }, state: started|ok|warning|failed|skipped|waiting|completed, at, durationMs?,
             message?, errorClass? } -- step ids: check, download, verify, build, apply, migrate, health, done, failed,
             rollback. The same (seq, state) twice is stored once.
      ENDS   done + completed | the failed stage as the last event (failed) | rollback + completed ("rolled back").
             A run that only checked (check / done only, or from = to) is closed by Invardia and not listed by default.

    SI'S STEPS -> THE STAGES (the updater's own step names, $global:SI_UpdaterStep, and the release's
    setup/Invoke-SIContainerUpdate.ps1 stage, $global:SI_UpdateStage):
      signin / settings / claim / licence / manifest -> check   download -> download   verify -> verify
      database -> migrate   templates / build -> build ('3. ROLL' -> apply, '4. VERIFY' -> health)   roll -> apply
      post-roll -> health   restore / '5. ROLLBACK' -> rollback   template-pack -> apply

    HOW THE UPDATER USES IT (the smallest change to the updater -- the other files only call this one):
      * SI-UpdaterInvardia.ps1: once the code manifest is decided, Invoke-SIUpdaterTrackHook -What open (the run is opened
        from the version the jobs run to the version the ring approved; the 'check' stage started at the run's start);
        -What waiting (deferred / held) | applied | current marks how the run ended.
      * Start-SIUpdater.ps1: every log line moves the stage when the updater's step moved (Step-SIUpdateTrack), and the end
        of the run closes it (Stop-SIUpdateTrack).

    RULES: Pro only (an install key is needed to open a run); the telemetry switch is honoured (the Settings page's
    SI_Telemetry_Enabled, then the job's SI_TELEMETRY_ENABLED, else on); an ErrorClass and ONE scrubbed line only, never data
    or secrets; BEST EFFORT -- a 10-second timeout, and the first post that fails stops the tracking for the rest of the run.
    NOTHING HERE EVER FAILS, STOPS OR SLOWS THE UPDATE. A test session never posts without its own -Transport.

    PS 5.1 and 7. No modules.
#>

$script:SIUpdateTrackConfig = @{
    Product = 'securityinsight'; TimeoutSec = 10; KeyHeader = 'X-Invardia-Install-Key'; TokenHeader = 'X-Invardia-Install-Token'
    DefaultBase = 'https://invardia.com'; MessageMax = 300
}
$script:SIUpdateTrackStages = @('check', 'download', 'verify', 'build', 'apply', 'migrate', 'health', 'done', 'failed', 'rollback')
$script:SIUpdateTrackTitles = @{
    check = 'Check for an update'; download = 'Download the release'; verify = 'Verify the signature'; build = 'Build the images'
    apply = 'Roll out the new version'; migrate = 'Update the database'; health = 'Check the new version'; done = 'Done'; failed = 'Failed'
    rollback = 'Roll back to the previous version'
}

function ConvertTo-SIUpdateTrackStage {
    <# PURE. The stage id of one updater step (-Step) and, for the engine build, the release's own stage (-Stage). #>
    param([AllowEmptyString()][AllowNull()][string]$Step, [AllowEmptyString()][AllowNull()][string]$Stage)
    $st = "$Step".Trim().ToLowerInvariant()
    $sg = "$Stage"
    switch ($st) {
        'download'      { return 'download' }
        'verify'        { return 'verify' }
        'database'      { return 'migrate' }
        'templates'     { return 'build' }
        'build' {
            if ($sg -match '(?i)ROLLBACK|RESTORE') { return 'rollback' }
            if ($sg -match '(?i)VERIFY') { return 'health' }
            if ($sg -match '(?i)\bROLL\b') { return 'apply' }
            return 'build'
        }
        'roll'          { return 'apply' }
        'post-roll'     { return 'health' }
        'restore'       { return 'rollback' }
        'template-pack' { return 'apply' }
        default         { return 'check' }   # signin, settings, claim, licence, manifest, updater, nothing yet
    }
}

function ConvertTo-SIUpdateTrackVersion {
    <# PURE. A version in Invardia's shape (^[0-9A-Za-z][0-9A-Za-z.+-]{0,49}$), else 'unknown'. #>
    param([AllowEmptyString()][AllowNull()][string]$Version)
    $v = "$Version".Trim()
    if ($v -match '^[0-9A-Za-z][0-9A-Za-z.+-]{0,49}$') { return $v }
    'unknown'
}

function ConvertTo-SIUpdateTrackMessage {
    <# PURE. ONE scrubbed line: the uplink's redaction when loaded, GUIDs and long opaque runs hidden, at most 300 chars. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $t = (("$Text" -replace '[\r\n\t]+', ' ') -replace '\s{2,}', ' ').Trim()
    if (-not $t) { return '' }
    if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { try { $t = [string](ConvertTo-AitUplinkRedacted -Text $t) } catch { } }
    $t = [regex]::Replace($t, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<id>')
    $t = [regex]::Replace($t, '(?<![A-Za-z0-9_\-+=/])(?=[A-Za-z0-9_\-+=/]*[0-9])(?=[A-Za-z0-9_\-+=/]*[A-Za-z])[A-Za-z0-9_\-+=/]{32,}', '(hidden)')
    if ($t.Length -gt $script:SIUpdateTrackConfig.MessageMax) { $t = $t.Substring(0, $script:SIUpdateTrackConfig.MessageMax - 3) + '...' }
    $t
}

function New-SIUpdateRunOpenBody {
    <# PURE. The open body, exactly the five fields Invardia takes. $null when the ring is not 0-3 (no run is opened). #>
    param([AllowNull()]$Ring, [AllowEmptyString()][AllowNull()][string]$FromVersion, [AllowEmptyString()][AllowNull()][string]$ToVersion)
    $r = 0
    if ($null -eq $Ring -or -not [int]::TryParse("$Ring", [ref]$r) -or $r -lt 0 -or $r -gt 3) { return $null }
    [ordered]@{ productId = $script:SIUpdateTrackConfig.Product; kind = 'update'; ring = $r
                fromVersion = (ConvertTo-SIUpdateTrackVersion $FromVersion); toVersion = (ConvertTo-SIUpdateTrackVersion $ToVersion) } | ConvertTo-Json -Compress
}

function New-SIUpdateRunEventBody {
    <# PURE. One stage event. -ErrorClass only when it fits Invardia's shape; the message is scrubbed here. #>
    param([Parameter(Mandatory)][int]$Seq, [Parameter(Mandatory)][string]$Stage,
          [Parameter(Mandatory)][ValidateSet('started', 'ok', 'warning', 'failed', 'skipped', 'waiting', 'completed')][string]$State,
          [Parameter(Mandatory)][datetime]$At, [AllowNull()]$DurationMs, [AllowEmptyString()][AllowNull()][string]$Message, [AllowEmptyString()][AllowNull()][string]$ErrorClass)
    if ($script:SIUpdateTrackStages -notcontains $Stage) { throw "not an update stage: $Stage" }
    $b = [ordered]@{ seq = $Seq; step = [ordered]@{ id = $Stage; title = $script:SIUpdateTrackTitles[$Stage] }; state = $State
                     at = $At.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $d = [long]0
    if ($null -ne $DurationMs -and [long]::TryParse("$DurationMs", [ref]$d) -and $d -ge 0) { $b.durationMs = [int][Math]::Min($d, [long]2147483646) }
    $m = ConvertTo-SIUpdateTrackMessage $Message
    if ($m) { $b.message = $m }
    $c = "$ErrorClass".Trim()
    if ($c -match '^[A-Za-z][A-Za-z0-9._-]{0,39}$') { $b.errorClass = $c }
    $b | ConvertTo-Json -Compress -Depth 4
}

function Send-SIUpdateTrackHttp {
    <# The default transport: one POST. Returns @{ Status (0 = no answer); Body }. Never throws. #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][hashtable]$Headers, [Parameter(Mandatory)][string]$Body, [int]$TimeoutSec = 10)
    try {
        $r = Invoke-WebRequest -Method Post -Uri $Uri -Headers $Headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($Body)) -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        $c = $r.Content; if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }
        [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$c }
    } catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        [pscustomobject]@{ Status = $code; Body = '' }
    }
}

function Get-SIUpdateTrack {
    <# The tracking state of this process ($global:SI_UpdateTrack), created empty. #>
    if ($null -eq $global:SI_UpdateTrack) {
        $global:SI_UpdateTrack = @{ Open = $false; Broken = $false; Closed = $false; RunId = ''; Token = ''; EventsUrl = ''; Seq = 0; Stage = ''; StageAt = $null
                                    Outcome = ''; OutcomeText = ''; ToVersion = ''; Transport = $null; Now = $null; Log = $null; Posted = (New-Object System.Collections.Generic.List[object]) }
    }
    $global:SI_UpdateTrack
}

function Reset-SIUpdateTrack { $global:SI_UpdateTrack = $null; $null = Get-SIUpdateTrack }

function Get-SIUpdateTrackNow {
    $t = Get-SIUpdateTrack
    if ($t.Now) { return ([datetime](& $t.Now)).ToUniversalTime() }
    [datetime]::UtcNow
}

function Send-SIUpdateTrackEvent {
    <# One event of the open run. A failed post stops the tracking for the rest of the run. Returns $true when accepted. #>
    param([Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][string]$State, [AllowNull()]$DurationMs, [string]$Message, [string]$ErrorClass, $At)
    $t = Get-SIUpdateTrack
    if (-not $t.Open -or $t.Broken -or $t.Closed) { return $false }
    try {
        $when = if ($At) { ([datetime]$At).ToUniversalTime() } else { Get-SIUpdateTrackNow }
        $t.Seq++
        $body = New-SIUpdateRunEventBody -Seq $t.Seq -Stage $Stage -State $State -At $when -DurationMs $DurationMs -Message $Message -ErrorClass $ErrorClass
        $h = @{ Accept = 'application/json' }; $h[$script:SIUpdateTrackConfig.TokenHeader] = $t.Token
        $r = & $t.Transport $t.EventsUrl $h $body
        $code = [int]$r.Status
        if ($code -ge 200 -and $code -lt 300) { $t.Posted.Add([pscustomobject]@{ Stage = $Stage; State = $State }); return $true }
        $t.Broken = $true
        if ($t.Log) { & $t.Log ("update tracking: Invardia answered {0} to a stage report -- the rest of this run is not reported (the update is not affected)" -f $code) }
    } catch {
        $t.Broken = $true
        if ($t.Log) { & $t.Log ("update tracking stopped: {0} (the update is not affected)" -f (ConvertTo-SIUpdateTrackMessage $_.Exception.Message)) }
    }
    $false
}

function Start-SIUpdateTrack {
    <#
        Opens this update run at Invardia and reports the 'check' stage as started at -CheckStartedUtc (the run's start).
        Returns @{ Opened; Reason; RunId }. NEVER throws.
          -On          the telemetry switch for this run
          -InstallKey  the install's key (inv-...); none = not opened
          -Transport   { param($Uri, $Headers, $Body) } -> @{ Status; Body }   (default Send-SIUpdateTrackHttp; the test seam)
          -Now         { } -> [datetime] UTC (tests)
          -Log         { param($Text) }
    #>
    param([bool]$On = $true, [AllowEmptyString()][AllowNull()][string]$InstallKey, [AllowEmptyString()][string]$BaseUrl, [AllowNull()]$Ring,
          [AllowEmptyString()][AllowNull()][string]$FromVersion, [AllowEmptyString()][AllowNull()][string]$ToVersion, $CheckStartedUtc,
          [scriptblock]$Transport, [scriptblock]$Now, [scriptblock]$Log)
    $out = { param($o, $why) [pscustomobject]@{ Opened = [bool]$o; Reason = $why; RunId = (Get-SIUpdateTrack).RunId } }
    try {
        $t = Get-SIUpdateTrack
        if ($t.Open) { return (& $out $true 'the run is open already') }
        if (-not $On) { return (& $out $false 'telemetry is switched off (SI_Telemetry_Enabled) -- the update run is not reported') }
        $key = "$InstallKey".Trim()
        if ($key -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return (& $out $false 'no install key -- the update run is not reported') }
        $body = New-SIUpdateRunOpenBody -Ring $Ring -FromVersion $FromVersion -ToVersion $ToVersion
        if (-not $body) { return (& $out $false 'no update ring 0-3 -- the update run is not reported') }
        if (-not $Transport) {
            if (Get-Module -Name Pester) { return (& $out $false 'a test session never posts without its own transport') }
            $to = $script:SIUpdateTrackConfig.TimeoutSec
            $Transport = { param($u, $h, $b) Send-SIUpdateTrackHttp -Uri $u -Headers $h -Body $b -TimeoutSec $to }.GetNewClosure()
        }
        $base = "$BaseUrl".Trim().TrimEnd('/')
        if (-not $base) { $base = $script:SIUpdateTrackConfig.DefaultBase }
        if ($base -notmatch '^https://[^/\s]+') { return (& $out $false ("the Invardia address must be https, not '{0}'" -f $base)) }
        $t.Transport = $Transport; $t.Now = $Now; $t.Log = $Log
        $h = @{ Accept = 'application/json' }; $h[$script:SIUpdateTrackConfig.KeyHeader] = $key
        $r = & $Transport ($base + '/api/install/runs') $h $body
        $code = [int]$r.Status
        if ($code -lt 200 -or $code -ge 300) {
            $t.Broken = $true
            if ($Log) { & $Log ("update tracking: Invardia answered {0} when the run was opened -- this run is not reported (the update is not affected)" -f $code) }
            return (& $out $false ("Invardia answered {0}" -f $code))
        }
        $j = $null; try { $j = "$($r.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
        if (-not $j -or "$($j.token)" -notmatch '^it-[A-Za-z0-9_-]{20,}$' -or -not "$($j.runId)".Trim()) {
            $t.Broken = $true
            return (& $out $false 'Invardia opened the run but sent no run id or token')
        }
        $ev = "$($j.eventsUrl)".Trim()
        if ($ev -notmatch '^https://[^/\s]+/') { $ev = $base + '/api/install/events' }
        $t.Open = $true; $t.RunId = [string]$j.runId; $t.Token = [string]$j.token; $t.EventsUrl = $ev; $t.ToVersion = (ConvertTo-SIUpdateTrackVersion $ToVersion)
        $startAt = if ($CheckStartedUtc) { ([datetime]$CheckStartedUtc).ToUniversalTime() } else { Get-SIUpdateTrackNow }
        $t.Stage = 'check'; $t.StageAt = $startAt
        $null = Send-SIUpdateTrackEvent -Stage 'check' -State 'started' -At $startAt
        if ($Log) { & $Log ("update tracking: run {0} opened at Invardia ({1} -> {2})" -f $t.RunId, (ConvertTo-SIUpdateTrackVersion $FromVersion), $t.ToVersion) }
        return (& $out $true 'opened')
    } catch {
        (Get-SIUpdateTrack).Broken = $true
        return (& $out $false ("not opened: {0}" -f (ConvertTo-SIUpdateTrackMessage $_.Exception.Message)))
    }
}

function Step-SIUpdateTrack {
    <#
        Moves the open run to the stage of the updater's current step (-Step, default $global:SI_UpdaterStep; -Stage,
        default $global:SI_UpdateStage): the stage it leaves is reported ok (with its duration), the new one started. A stage
        the engine roll passed without a log line in between (build -> apply -> health) is reported too. A roll back is left
        to Stop-SIUpdateTrack. Cheap and silent when no run is open. NEVER throws.
    #>
    param([AllowNull()][string]$Step = $global:SI_UpdaterStep, [AllowNull()][string]$Stage = $global:SI_UpdateStage)
    try {
        $t = Get-SIUpdateTrack
        if (-not $t.Open -or $t.Broken -or $t.Closed) { return }
        $new = ConvertTo-SIUpdateTrackStage -Step $Step -Stage $Stage
        if ($new -eq $t.Stage -or $new -eq 'rollback') { return }
        $chain = @($new)
        if ($t.Stage -eq 'build' -and $new -eq 'health') { $chain = @('apply', 'health') }
        foreach ($n in $chain) {
            $now = Get-SIUpdateTrackNow
            $dur = if ($t.StageAt) { [long][Math]::Max(0, ($now - [datetime]$t.StageAt).TotalMilliseconds) } else { $null }
            if ($t.Stage) { $null = Send-SIUpdateTrackEvent -Stage $t.Stage -State 'ok' -DurationMs $dur -At $now }
            $t.Stage = $n; $t.StageAt = $now
            $null = Send-SIUpdateTrackEvent -Stage $n -State 'started' -At $now
        }
    } catch { }
}

function Set-SIUpdateTrackOutcome {
    <# How the run ended, before Stop-SIUpdateTrack: applied | waiting (deferred / held) | current (nothing to apply). #>
    param([Parameter(Mandatory)][ValidateSet('applied', 'waiting', 'current')][string]$Outcome, [AllowEmptyString()][AllowNull()][string]$Text)
    try { $t = Get-SIUpdateTrack; $t.Outcome = $Outcome; $t.OutcomeText = "$Text" } catch { }
}

function Stop-SIUpdateTrack {
    <#
        Closes the open run at the end of the update run. Returns the stage events it posted (or @()). NEVER throws.
          a non-zero -ExitCode   the stage the run failed in = failed, with the ErrorClass and one scrubbed line of the last
                                 failure recorded (-Failures, default Get-SIUpdaterFailures) after the check; when the engine
                                 roll restored the previous images: rollback + completed ("rolled back")
          outcome waiting        the current stage = waiting, with the reason (held for an Admin, or deferred to the next run)
          outcome applied        the current stage ok, then done + completed
          otherwise              nothing to apply: check (or the current stage) completed / done + completed
    #>
    param([int]$ExitCode = 0, [object[]]$Failures)
    $posted = New-Object System.Collections.Generic.List[string]
    try {
        $t = Get-SIUpdateTrack
        if (-not $t.Open -or $t.Broken -or $t.Closed) { return @() }
        if ($PSBoundParameters.ContainsKey('Failures') -eq $false) {
            $Failures = if (Get-Command -Name Get-SIUpdaterFailures -ErrorAction SilentlyContinue) { @(Get-SIUpdaterFailures) } else { @() }
        }
        $now = Get-SIUpdateTrackNow
        $dur = if ($t.StageAt) { [long][Math]::Max(0, ($now - [datetime]$t.StageAt).TotalMilliseconds) } else { $null }
        $send = { param($st, $state, $d, $msg, $cls) if (Send-SIUpdateTrackEvent -Stage $st -State $state -DurationMs $d -Message $msg -ErrorClass $cls -At $now) { $posted.Add("$st/$state") } }
        if ($ExitCode -ne 0) {
            # the failure that ended it: the last one recorded outside the check (a refused licence request does not stop an update)
            $fails = @($Failures | Where-Object { $_ })
            $last = @($fails | Where-Object { "$($_.Step)" -notin @('licence', 'claim', 'signin', 'settings', 'manifest', 'updater') } | Select-Object -Last 1)
            if (-not $last.Count) { $last = @($fails | Select-Object -Last 1) }
            $text = if ($last.Count) { "$($last[0].Text)" } else { ("the update run ended with exit code {0}" -f $ExitCode) }
            $stage = if ($last.Count -and "$($last[0].Step)" -notin @('restore')) { ConvertTo-SIUpdateTrackStage -Step "$($last[0].Step)" -Stage $global:SI_UpdateStage } else { $t.Stage }
            if ($stage -eq 'rollback' -or ($stage -eq 'check' -and $t.Stage -ne 'check')) { $stage = $t.Stage }
            $cls = ''
            if (Get-Command -Name Get-SIErrorClass -ErrorAction SilentlyContinue) { try { $cls = [string](Get-SIErrorClass -Message $text) } catch { $cls = '' } }
            & $send $stage 'failed' $(if ($stage -eq $t.Stage) { $dur } else { $null }) $text $cls
            $rolledBack = ("$global:SI_UpdateStage" -match '(?i)ROLLBACK|RESTORE') -or @($fails | Where-Object { "$($_.Step)" -eq 'restore' -or "$($_.Text)" -match '(?i)\brestored\b' }).Count -gt 0
            if ($rolledBack) { & $send 'rollback' 'completed' $null 'rolled back to the previous version' '' }
        } elseif ($t.Outcome -eq 'waiting') {
            & $send $t.Stage 'waiting' $null $(if ($t.OutcomeText) { $t.OutcomeText } else { 'waiting for the next update run' }) ''
        } elseif ($t.Outcome -eq 'applied') {
            & $send $t.Stage 'ok' $dur '' ''
            & $send 'done' 'completed' $null ("updated to {0}" -f $t.ToVersion) ''
        } else {
            $why = if ($t.OutcomeText) { $t.OutcomeText } else { 'already on the version approved for this ring' }
            if ($t.Stage -eq 'check') { & $send 'check' 'completed' $dur $why '' }
            else { & $send $t.Stage 'ok' $dur '' ''; & $send 'done' 'completed' $null $why '' }
        }
        $t.Closed = $true
    } catch { }
    $posted.ToArray()
}

function Test-SIUpdateTrackOn {
    <# The telemetry switch for the tracking: the Pro Settings page first, then the job's SI_TELEMETRY_ENABLED, else on. #>
    param($Store, [hashtable]$Env = @{})
    try {
        $settings = $null
        if ($Store -and (Get-Command -Name Read-SIProSolutionSettings -ErrorAction SilentlyContinue)) { try { $settings = Read-SIProSolutionSettings -Store $Store } catch { $settings = $null } }
        $ev = if ($Env.ContainsKey('SI_TELEMETRY_ENABLED')) { [string]$Env['SI_TELEMETRY_ENABLED'] } else { [Environment]::GetEnvironmentVariable('SI_TELEMETRY_ENABLED') }
        # #918: in a Pester session the process-wide value is the test gate's (SI_TEST_GATE=1), not the test's
        if (-not $Env.ContainsKey('SI_TELEMETRY_ENABLED') -and "$env:SI_TEST_GATE" -eq '1' -and (Get-Module -Name Pester)) { $ev = $null }
        if (Get-Command -Name Test-SIUpdaterTelemetryOn -ErrorAction SilentlyContinue) { return [bool](Test-SIUpdaterTelemetryOn -Settings $settings -EnvValue $ev) }
        $s = "$ev".Trim().ToLowerInvariant()
        return -not ($s -in @('false', '0', 'off', 'no', 'disabled'))
    } catch { return $true }
}

function Invoke-SIUpdaterTrackHook {
    <#
        The ONE call SI-UpdaterInvardia.ps1 makes. NEVER throws.
          -What open      -A = the code manifest result, -B = its decision (Get-SIUpdaterInvardiaCodeDecision): opens the run
                          from -Deployed to the approved version (the target when it will be applied, else what runs now);
                          a decision that holds (a manual step to accept) ends as waiting
          -What waiting   -A = the reason (deferred / held)
          -What applied   -A = the version now running
          -What current   -A = the reason (nothing to apply)
        -Seams: the update client's (ReadSecret reads the install key, SI-Invardia-InstallKey); -Transport / -Now: tests.
    #>
    param([Parameter(Mandatory)][ValidateSet('open', 'waiting', 'applied', 'current')][string]$What, $A, $B, [System.Collections.IDictionary]$Seams, $Store,
          [hashtable]$Env = @{}, [AllowEmptyString()][AllowNull()][string]$Deployed, [AllowNull()]$Ring, [AllowEmptyString()][AllowNull()][string]$BaseUrl,
          [scriptblock]$Transport, [scriptblock]$Now, $StartedUtc)
    try {
        switch ($What) {
            'open' {
                $code = $A; $dec = $B
                $target = if ($dec -and $dec.Act -and $code) { "$($code.Version)" } elseif ("$Deployed".Trim()) { "$Deployed" } elseif ($code) { "$($code.Version)" } else { '' }
                $key = ''
                if ($Seams -and $Seams['ReadSecret']) { try { $key = "$(& $Seams.ReadSecret 'SI-Invardia-InstallKey')".Trim() } catch { $key = '' } }
                $log = { param($m) if (Get-Command -Name Write-UpdLog -ErrorAction SilentlyContinue) { Write-Host ("[{0:u}] {1}" -f [datetime]::UtcNow, $m) } else { Write-Host $m } }
                $started = if ($StartedUtc) { $StartedUtc } elseif ($global:SI_UpdaterRunStartedUtc) { $global:SI_UpdaterRunStartedUtc } else { $null }
                $a = @{ On = (Test-SIUpdateTrackOn -Store $Store -Env $Env); InstallKey = $key; BaseUrl = $BaseUrl; Ring = $Ring; FromVersion = $Deployed; ToVersion = $target
                        CheckStartedUtc = $started; Log = $log }
                if ($Transport) { $a.Transport = $Transport }
                if ($Now) { $a.Now = $Now }
                $r = Start-SIUpdateTrack @a
                if ($r.Opened -and $dec -and -not $dec.Act -and "$($dec.Hold)".Trim()) { Set-SIUpdateTrackOutcome -Outcome waiting -Text ([string]$dec.Hold) }
                return $r
            }
            'waiting' { Set-SIUpdateTrackOutcome -Outcome waiting -Text ([string]$A) }
            'applied' { Set-SIUpdateTrackOutcome -Outcome applied -Text ([string]$A) }
            'current' { Set-SIUpdateTrackOutcome -Outcome current -Text ([string]$A) }
        }
    } catch { }
}
