#Requires -Version 5.1
<#
    SecurityInsight -- the TELEMETRY RECORDS SecurityInsight would send through the framework uplink (Schema 2).

    Two kinds, as agreed with the receiving side:
      heartbeat  once a day: product, edition, version, ring, hosting, runtime identity, licence state
      run        once per engine run, at the run-health END moment: the stable Job id, Outcome (from ExitReason),
                 DurationMs, FailedStep, ErrorClass (SI-ErrorClass.ps1), Counts

    Two modes:
      anonymous   (Community, the default there) -- a random InstallId; NO tenant, NO host name, NO error text, and
                  counts only as buckets (0, 1-100, 100-1k, 1k-10k, 10k-100k, 100k+). Data that is never put in the
                  record cannot leak, so the fields are absent, not empty.
      identified  (Pro / trial) -- the install key proves who sends; the tenant and host are carried, error text is
                  shortened to 4000 characters and redacted (tokens, secrets, connection strings, SAS signatures).

    NOTHING IS SENT FROM HERE. These are pure builders: values in, one record out, no network, no file, no clock
    unless -Now is omitted. SI-TelemetrySend.ps1 calls them at the run-health END moment, shapes the record for the wire
    with the framework client's New-AitUplinkReport (engine/_shared/AitUplink.ps1, a copy of sync/_AitUplink.ps1) and
    sends it with Send-AitUplink. Every enum is checked here, so a record that would be refused by the receiver is
    refused at the source instead.

    PS 5.1 safe.
#>

if (-not (Get-Command -Name Get-SIErrorClass -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ErrorClass.ps1'))
}

function Get-SITelemetryState {
    <# The value of $script:SITelemetry, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SITelemetry) { $script:SITelemetry = @{
    Product          = 'securityinsight'
    Solution         = 'SecurityInsight'
    Schema           = 2
    Editions         = @('community', 'pro', 'trial')
    Hostings         = @('container', 'vm', 'arc')
    RuntimeIdentities = @('mi-container', 'mi-arc', 'mi-vm', 'spn-certificate', 'spn-secret')
    LicenceStates    = @('valid', 'grace', 'expired', 'none')
    Outcomes         = @('ok', 'warning', 'failed')
    # One `run` per engine run. Community engines first, then Pro.
    Jobs             = @('si-ptc', 'si-endpoint', 'si-identity', 'si-azure', 'si-publicip', 'si-ra-summary', 'si-ra-detailed', 'si-trend',
                         'si-schema-discovery', 'si-asset-tagging', 'si-correlation', 'si-asset-properties', 'si-cmdb', 'si-vuln-closeloop',
                         'si-datasync', 'si-updater', 'si-web', 'si-cmdb-sql', 'si-flow', 'si-install')
    # #641: a Risk Analysis run's reports -- how many the template has, how many are stored complete, how many are not
    CountNames       = @('assets', 'findings', 'identities', 'reportsExpected', 'reportsStored', 'reportsIncomplete')
    # Invardia's receiver DROPS a record with more than 40 Counts keys (raised from 10, Invardia 2026-10-13) (numbers only, keys ^[a-z][A-Za-z0-9]{0,30}$)
    MaxCounts        = 40
    CountKeyPattern  = '^[a-z][A-Za-z0-9]{0,30}$'
    # #641: the step and the class of a run with a report that is not complete
    ReportIncompleteStep  = 'ra-report'
    ReportIncompleteClass = 'report-incomplete'
    ErrorTextMax     = 4000   # Invardia UPLINK-FIX 2026-10-07: run ErrorText max 4000
} }
    , $script:SITelemetry
}
$script:SITelemetry = $null; $null = Get-SITelemetryState

function Get-SITelemetryContract { (Get-SITelemetryState) }

function Get-SITelemetryOutcome {
    <# PURE. ExitReason -> Outcome: success = ok, success-partial = warning, throttled = warning (#532, framework §12.18
       THROTTLE-IS-NORMAL: never failed, never a fix request), error / settings-error = failed. Anything else is refused
       (a new ExitReason must be mapped on purpose, not guessed). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$ExitReason)
    switch ($ExitReason) {
        'success'         { return 'ok' }
        'success-partial' { return 'warning' }
        'throttled'       { return 'warning' }   # #532: Microsoft throttled the run; it runs again -- information, not a problem
        'dry-run'         { return 'ok' }        # #276: a dry run that went well; a failed one keeps its own reason
        'error'           { return 'failed' }
        'settings-error'  { return 'failed' }
    }
    throw ("'{0}' is not a run-health ExitReason (success, success-partial, throttled, error, settings-error)" -f $ExitReason)
}

function Get-SITelemetryCountBucket {
    <# PURE. A count as its anonymous bucket: 0 | 1-100 | 100-1k | 1k-10k | 10k-100k | 100k+ (UPPER bound inclusive:
       100 is '1-100', 1000 is '100-1k' -- the same boundaries as the framework client, Get-AitUplinkCountBucket, and the
       receiver; the wire record is bucketed by the framework, and the two must never disagree).
       $null for an unknown count (run health uses -1 for "not counted"). #>
    param([AllowNull()]$Count)
    if ($null -eq $Count -or [string]::IsNullOrWhiteSpace([string]$Count)) { return $null }
    $n = 0L
    if (-not [long]::TryParse([string]$Count, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -or $n -lt 0) { return $null }
    if ($n -eq 0) { return '0' }
    if ($n -le 100) { return '1-100' }
    if ($n -le 1000) { return '100-1k' }
    if ($n -le 10000) { return '1k-10k' }
    if ($n -le 100000) { return '10k-100k' }
    '100k+'
}

function ConvertTo-SITelemetryErrorText {
    <# PURE. Error text an IDENTIFIED record may carry: secrets redacted, then shortened to 4000 characters (the receiver's limit). #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}', '[jwt]')
    $t = [regex]::Replace($t, '(?i)\bBearer\s+[A-Za-z0-9_\-\.=~+/]+', 'Bearer [redacted]')
    $t = [regex]::Replace($t, '(?i)\b(client_secret|password|pwd|accountkey|sharedaccesskey|apikey|api-key|x-api-key|access_token|refresh_token)\s*[=:]\s*("[^"]*"|''[^'']*''|[^;&\s,]+)', '$1=[redacted]')
    $t = [regex]::Replace($t, '(?i)\bsig=[A-Za-z0-9%+/=]+', 'sig=[redacted]')
    if ($t.Length -gt (Get-SITelemetryState).ErrorTextMax) { $t = $t.Substring(0, (Get-SITelemetryState).ErrorTextMax) }
    $t
}

function Test-SITelemetryValue {
    param([string]$Name, [AllowEmptyString()][AllowNull()][string]$Value, [string[]]$Allowed, [switch]$Optional)
    if ($Optional -and [string]::IsNullOrEmpty($Value)) { return }
    if ($Allowed -notcontains $Value) { throw ("telemetry: '{0}' is not a valid {1} ({2})" -f $Value, $Name, ($Allowed -join ', ')) }
}

function New-SITelemetryBase {
    param([string]$Kind, [string]$Edition, [string]$Version, $Ring, [string]$Hosting, [string]$RuntimeIdentity, [string]$LicenceState,
          [bool]$Anonymous, [string]$InstallId, [string]$TenantId, [string]$HostName, $Now)
    Test-SITelemetryValue -Name 'Edition' -Value $Edition -Allowed (Get-SITelemetryState).Editions
    Test-SITelemetryValue -Name 'Hosting' -Value $Hosting -Allowed (Get-SITelemetryState).Hostings
    Test-SITelemetryValue -Name 'RuntimeIdentity' -Value $RuntimeIdentity -Allowed (Get-SITelemetryState).RuntimeIdentities
    Test-SITelemetryValue -Name 'LicenceState' -Value $LicenceState -Allowed (Get-SITelemetryState).LicenceStates
    if ($Anonymous -and $InstallId -notmatch '^[A-Za-z0-9\-]{16,64}$') { throw 'telemetry: an anonymous record needs its random InstallId (16-64 letters, digits or dashes)' }
    $ts = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
    $r = [ordered]@{
        Schema          = (Get-SITelemetryState).Schema
        Kind            = $Kind
        Product         = (Get-SITelemetryState).Product
        Solution        = (Get-SITelemetryState).Solution
        Edition         = $Edition
        Version         = [string]$Version
        Ring            = $(if ($null -ne $Ring -and [string]$Ring -ne '') { [int]$Ring } else { $null })
        Hosting         = $Hosting
        RuntimeIdentity = $RuntimeIdentity
        LicenceState    = $LicenceState
        WriterSource    = $(if ($Anonymous) { 'anonymous' } else { 'install-key' })
    }
    if ($Anonymous) { $r.InstallId = $InstallId }
    else {
        $r.ClaimedTenantId = [string]$TenantId
        $r.Host = $(if ($HostName) { $HostName } else { [string][System.Environment]::MachineName })
    }
    $r.LastSeenUtc = $ts.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $r
}

function New-SITelemetryHeartbeat {
    <#
        PURE. The daily `heartbeat` record. -Anonymous drops the tenant and the host and carries -InstallId instead.
    #>
    param([Parameter(Mandatory)][string]$Edition, [Parameter(Mandatory)][string]$Version, $Ring,
          [Parameter(Mandatory)][string]$Hosting, [Parameter(Mandatory)][string]$RuntimeIdentity, [Parameter(Mandatory)][string]$LicenceState,
          [switch]$Anonymous, [string]$InstallId, [string]$TenantId, [string]$HostName, $Now)
    [pscustomobject](New-SITelemetryBase -Kind 'heartbeat' -Edition $Edition -Version $Version -Ring $Ring -Hosting $Hosting -RuntimeIdentity $RuntimeIdentity `
        -LicenceState $LicenceState -Anonymous ([bool]$Anonymous) -InstallId $InstallId -TenantId $TenantId -HostName $HostName -Now $Now)
}

function New-SITelemetryRunRecord {
    <#
        PURE. The `run` record of one engine run, built at the run-health END moment.
          -Job          the stable job id (si-ptc, si-ra-detailed, ...)
          -ExitReason   run health's ExitReason -> Outcome (ok / warning / failed)
          -DurationMs   the run's duration
          -FailedStep   the stage that failed (collect, classify, ingest, ra-query, mail, ...) -- failed / warning only
          -ErrorClass   given, or classified here from -ErrorRecord / -ErrorMessage (Get-SIErrorClass) for a run that did
                        not end ok
          -Counts       @{ assets; findings; identities } -- exact when identified, bucketed when anonymous
          -ErrorMessage the error text: carried (redacted, max 8 KB) ONLY in an identified record
        -Anonymous drops the tenant, the host and the error text and buckets the counts.
    #>
    param([Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][AllowEmptyString()][string]$ExitReason,
          [Parameter(Mandatory)][string]$Edition, [Parameter(Mandatory)][string]$Version, $Ring,
          [Parameter(Mandatory)][string]$Hosting, [Parameter(Mandatory)][string]$RuntimeIdentity, [Parameter(Mandatory)][string]$LicenceState,
          [long]$DurationMs = 0, [string]$FailedStep, [string]$ErrorClass, $ErrorRecord, [AllowEmptyString()][string]$ErrorMessage,
          [System.Collections.IDictionary]$Counts, [switch]$Anonymous, [string]$InstallId, [string]$TenantId, [string]$HostName, $Now,
          # the steps this run finished well (Get-SITelemetryStepsOk) -- ids in the FailedStep shape, at most 50; ok and
          # warning runs only: a later ok report that lists a step closes the ticket that step's failure opened
          [string[]]$StepsOk)
    Test-SITelemetryValue -Name 'Job' -Value $Job -Allowed (Get-SITelemetryState).Jobs
    $outcome = Get-SITelemetryOutcome -ExitReason $ExitReason
    if ($DurationMs -lt 0) { throw 'telemetry: DurationMs cannot be negative' }
    if ($FailedStep -and $FailedStep -notmatch '^[a-z][a-z0-9\-]{0,31}$') { throw ("telemetry: '{0}' is not a step name (lower-case letters, digits and dashes)" -f $FailedStep) }
    $cls = $null
    if ($outcome -ne 'ok') {
        $cls = if ($ErrorClass) { $ErrorClass } else { Get-SIErrorClass -ErrorRecord $ErrorRecord -Message $ErrorMessage -ExitReason $ExitReason }
        # #532 (framework §12.18): a throttled run reports ErrorClass 'throttled' -- platform-5xx / platform-timeout as the
        # only cause map the same way
        if ($ExitReason -eq 'throttled') { $cls = 'throttled' }
        Test-SITelemetryValue -Name 'ErrorClass' -Value $cls -Allowed (Get-SITelemetryErrorClassList)
    }
    $c = [ordered]@{}
    if ($Counts) {
        foreach ($k in @($Counts.Keys)) {
            if ((Get-SITelemetryState).CountNames -notcontains [string]$k) { throw ("telemetry: '{0}' is not a count ({1})" -f $k, ((Get-SITelemetryState).CountNames -join ', ')) }
            if ([string]$k -cnotmatch (Get-SITelemetryState).CountKeyPattern) { throw ("telemetry: '{0}' is not a count name the receiver accepts" -f $k) }
        }
        if (@($Counts.Keys).Count -gt (Get-SITelemetryState).MaxCounts) { throw ("telemetry: {0} counts -- the receiver drops a record with more than {1}" -f @($Counts.Keys).Count, (Get-SITelemetryState).MaxCounts) }
        foreach ($k in (Get-SITelemetryState).CountNames) {
            if (-not $Counts.Contains($k)) { continue }
            if ($Anonymous) { $c[$k] = Get-SITelemetryCountBucket $Counts[$k] }
            else { $n = 0L; $c[$k] = $(if ([long]::TryParse([string]$Counts[$k], [ref]$n) -and $n -ge 0) { $n } else { $null }) }
        }
    }
    $r = New-SITelemetryBase -Kind 'run' -Edition $Edition -Version $Version -Ring $Ring -Hosting $Hosting -RuntimeIdentity $RuntimeIdentity `
        -LicenceState $LicenceState -Anonymous ([bool]$Anonymous) -InstallId $InstallId -TenantId $TenantId -HostName $HostName -Now $Now
    $last = $r.LastSeenUtc; $r.Remove('LastSeenUtc')
    $r.Job = $Job
    $r.Outcome = $outcome
    $r.DurationMs = $DurationMs
    $r.FailedStep = $(if ($outcome -ne 'ok' -and $FailedStep) { $FailedStep } else { $null })
    if ($outcome -ne 'failed') {
        $so = New-Object System.Collections.Generic.List[string]
        foreach ($s in @($StepsOk)) {
            $id = ([string]$s).Trim().ToLowerInvariant()
            if ($id -cmatch '^[a-z][a-z0-9\-]{0,31}$' -and -not $so.Contains($id) -and $so.Count -lt 50) { $so.Add($id) }
        }
        if ($so.Count) { $r.StepsOk = [string[]]$so.ToArray() }
    }
    $r.ErrorClass = $cls
    $r.Counts = [pscustomobject]$c
    if (-not $Anonymous) {
        $txt = ''
        if ($outcome -ne 'ok') {
            $raw = if ($ErrorMessage) { $ErrorMessage } elseif ($null -ne $ErrorRecord) { Get-SIKqlErrorSummary -ErrorRecord $ErrorRecord } else { '' }
            $txt = ConvertTo-SITelemetryErrorText $raw
        }
        $r.ErrorText = $txt
    }
    $r.Ok = ($outcome -eq 'ok')
    $r.LastSeenUtc = $last
    [pscustomobject]$r
}

# the closed ErrorClass list, from the classifier (one definition)
function Get-SITelemetryErrorClassList {
    <# The value of $script:SITelemetry_ErrorClasses, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SITelemetry_ErrorClasses) { $script:SITelemetry_ErrorClasses = @(Get-SIErrorClasses) }
    , $script:SITelemetry_ErrorClasses
}
$script:SITelemetry_ErrorClasses = $null; $null = Get-SITelemetryErrorClassList
