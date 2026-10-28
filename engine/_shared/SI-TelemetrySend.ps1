#Requires -Version 5.1
<#
    SecurityInsight -- SENDING the telemetry records (#226): one `heartbeat` a day and one `run` report per engine run,
    through the framework uplink client (engine/_shared/AitUplink.ps1, a byte-identical copy of sync/_AitUplink.ps1 --
    SecurityInsight containers and Pro installs have no sync/ folder; SIv3-Telemetry.Tests.ps1 compares the two).

    WHEN: at the run-health END moment. Send-SIRunHealthRow calls Send-SITelemetryRunEnd from its `finally` for every
    Phase 'End' record, so every engine that records its run health reports its run -- success, success-partial, error
    and settings-error alike -- whether or not the Log Analytics record itself could be saved.

    WHAT (built by SI-Telemetry.ps1, which checks every value against the agreed lists, then shaped for the wire by the
    framework's New-AitUplinkReport, which drops anything the receiver would refuse):
      heartbeat  product, edition, version, hosting, runtime identity kind, licence state -- once per UTC day; an
                 IDENTIFIED (Pro / trial) heartbeat also carries Counts = users, guests, devices (#424,
                 SI-TelemetryCounts.ps1 -- the exact definitions are there); an anonymous one carries none
      run       the stable Job id, Outcome (ok / warning / failed from ExitReason), DurationMs, FailedStep, ErrorClass
                 (SI-ErrorClass.ps1) and Counts

    TWO MODES (Resolve-AitUplinkSender):
      anonymous   Community, and a Pro install that has no install key yet: the public community code, a random install
                  id kept on this machine, NO tenant, NO host name, NO error text -- the fields are never put in the
                  record -- and counts only as buckets.
      identified  Pro / trial with the install key from the install's Key Vault (SI-Invardia-InstallKey, the same key the
                  updater uses), read as the runtime identity. The tenant and host are carried; the error text is
                  redacted and shortened (here AND by the framework client AND by the receiver).

    OFF: $global:SI_Telemetry_Enabled = $false (or the environment variable SI_TELEMETRY_ENABLED = false). Then nothing is
    built, nothing is read, no file is written and no network call is made.

    RULE: TELEMETRY NEVER FAILS OR SLOWS A RUN. One attempt per record, a 5-second timeout, no retry. The first answer that is
    not 'ok' stops all telemetry for the rest of the process (no retry storm, and nothing is queued for later), and is
    said ONCE as a warning. Nothing here throws to its caller.

    PS 5.1 and 7.
#>

if (-not (Get-Command -Name New-SITelemetryRunRecord -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Telemetry.ps1')) }
if (-not (Get-Command -Name New-AitUplinkReport -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'AitUplink.ps1')) }
if (-not (Get-Command -Name Get-SITelemetryHeartbeatCounts -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-TelemetryCounts.ps1')) }
# CR4 (#654): the guard mode on the identified heartbeat (the stricter period after a release that changed engine code)
if (-not (Get-Command -Name ConvertTo-SIGuardModeWire -ErrorAction SilentlyContinue) -and [System.IO.File]::Exists([System.IO.Path]::Combine($PSScriptRoot, 'SI-GuardStrict.ps1'))) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-GuardStrict.ps1')) }
# CR3 (#657): release control -- the wave and release mode on the identified heartbeat, the 30-minute release-mode reports
if (-not (Get-Command -Name Resolve-SIReleaseControlSwitch -ErrorAction SilentlyContinue) -and [System.IO.File]::Exists([System.IO.Path]::Combine($PSScriptRoot, 'SI-ReleaseControl.ps1'))) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ReleaseControl.ps1')) }
# the ring every report carries (Resolve-SIReportedRing) -- the same order the web app's header uses
if (-not (Get-Command -Name Resolve-SIReportedRing -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ReportedRing.ps1')) }
# the setup report (Kind = setup, framework §8.7): the control list, once a day with the heartbeat (identified only)
if (-not (Get-Command -Name New-SISetupReport -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-SetupUplink.ps1')) }
# #517 / framework §12.6b: the installed licence's id on identified reports, and Invardia's "superseded by" answer
if (-not (Get-Command -Name Get-SILicenceSupersededFromAnswer -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-LicenceSuperseded.ps1')) }
# framework §8.9: the install's own links (endpoints) on the identified heartbeat -- behind SI_Telemetry_SendEndpoints (default off) -- and the deep Link on a failed run report
if (-not (Get-Command -Name Get-SITelemetryInstallEndpoints -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-TelemetryEndpoints.ps1')) }
# #709 / framework 8.16 UPLINK-CAUSES: the run record's Reports[] and the heartbeat's Capabilities / CiColumns / Licences
if (-not (Get-Command -Name ConvertTo-SIUplinkReports -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-UplinkCauses.ps1')) }
# #710 / framework 8.16: Invardia's answer names the install's environment (environmentId) -- kept for the customer mail's portal link
if (-not (Get-Command -Name Get-SIInvardiaEnvironmentIdFromAnswer -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaPortalLink.ps1')) }

function New-SITelemetrySendState {
    <# The sender's settings. Made when this file loads -- and again by the functions below when `$script:` is the scope
       of a script started from the one that loaded this file (its own scope: the functions are visible there, this
       table is not). The root comes from this function's own file, never from the caller. #>
    $file = [string]$MyInvocation.MyCommand.ScriptBlock.File
    $dir = if ($file) { [System.IO.Path]::GetDirectoryName($file) } else { $PSScriptRoot }
    @{
    SIRoot         = (Split-Path -Parent (Split-Path -Parent $dir))
    TimeoutSec     = 5
    InstallKeyName = 'SI-Invardia-InstallKey'
    # Engine name (run-health Engine / launcher folder) -> the stable Job id agreed with the receiver (#226).
    Jobs           = @{
        'privilege-tier-classifier' = 'si-ptc'
        'endpoint'                  = 'si-endpoint'
        'identity'                  = 'si-identity'
        'azure'                     = 'si-azure'
        'publicip'                  = 'si-publicip'
        'asset-trend'               = 'si-trend'
        'trend'                     = 'si-trend'
        'schema-discovery'          = 'si-schema-discovery'
        'asset-tagging'             = 'si-asset-tagging'
        'asset-correlation'         = 'si-correlation'
        'correlation'               = 'si-correlation'
        'asset-properties'          = 'si-asset-properties'
        'asset-cmdb'                = 'si-cmdb'
        'cmdb'                      = 'si-cmdb'
        'asset-cmdb-sql'            = 'si-cmdb-sql'
        'vuln-closeloop'            = 'si-vuln-closeloop'
        'datasync'                  = 'si-datasync'
        # UPLINK-FIX: the data sync records its runs as 'asset-datasync' (its job's name) -- unmapped, none of them was reported
        'asset-datasync'            = 'si-datasync'
        'updater'                   = 'si-updater'
        'web'                       = 'si-web'
        # #269: the daily job flow -- ONE run for the whole flow; FailedStep names the first step that did not succeed
        'flow'                      = 'si-flow'
        # #427: a failed step of the guided install (setup/_shared/SI-GuidedInstall.ps1) -- Send-SITelemetryFailure
        'install'                   = 'si-install'
    }
    }
}
$script:SITelemetrySend = New-SITelemetrySendState

# =====================================================================================================================
#  Pure decisions
# =====================================================================================================================
function Test-SITelemetryEnabled {
    <#
        PURE. Is telemetry on? The setting wins when it is set, then the environment variable SI_TELEMETRY_ENABLED,
        else ON (the owner's decision: on by default, one setting to turn it off). false / 0 / off / no turn it off.
    #>
    param([AllowNull()]$Value = $global:SI_Telemetry_Enabled, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_TELEMETRY_ENABLED)
    # #918: every test entry point sets SI_TELEMETRY_ENABLED=false (+ SI_TEST_GATE=1) for itself and every engine CHILD process
    # it starts -- those never send. Inside a Pester session that variable is the gate's, not the test's: such a session never
    # sends to Invardia anyway (Send-SITelemetryRunEnd needs its own -Transport there), and its suites test the sender with
    # their own stub, so the gate's process-wide value is not read in it (a value passed with -EnvValue always is).
    if (-not $PSBoundParameters.ContainsKey('EnvValue') -and "$env:SI_TEST_GATE" -eq '1' -and (Get-Module -Name Pester)) { $EnvValue = $null }
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { return $v }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        return -not ($s -in @('false', '0', 'off', 'no', 'disabled'))
    }
    return $true
}

function Resolve-SITelemetryJob {
    <# PURE. The stable Job id of an engine run, or $null (nothing is sent for an engine without one). Risk Analysis is
       two jobs: the Summary template is si-ra-summary, every other template si-ra-detailed. #>
    param([AllowEmptyString()][AllowNull()][string]$Engine, [AllowEmptyString()][AllowNull()][string]$ReportTemplate)
    $e = "$Engine".Trim().ToLowerInvariant()
    if (-not $e) { return $null }
    if ($e -eq 'risk-analysis') {
        if ("$ReportTemplate" -match '(?i)summary') { return 'si-ra-summary' }
        return 'si-ra-detailed'
    }
    if ($script:SITelemetrySend.Jobs.ContainsKey($e)) { return $script:SITelemetrySend.Jobs[$e] }
    return $null
}

function ConvertTo-SITelemetryExitReason {
    <# PURE. Run health's ExitReason as one of the four the telemetry maps. The tier classifier writes 'failure' for
       'error'; an empty or unknown value is $null (not reported rather than guessed). #>
    param([AllowEmptyString()][AllowNull()][string]$ExitReason)
    $x = "$ExitReason".Trim().ToLowerInvariant()
    if ($x -in @('success', 'success-partial', 'throttled', 'error', 'settings-error')) { return $x }   # throttled: #532
    if ($x -in @('failure', 'failed')) { return 'error' }
    if ($x -eq 'dry-run') { return 'success' }   # #276: a dry run that went well (a failed dry run keeps its own reason)
    return $null
}

function Get-SITelemetryHosting {
    <# PURE (reads env only). container | arc | vm: Container Apps sets CONTAINER_APP_* and IDENTITY_ENDPOINT +
       IDENTITY_HEADER; the Arc agent sets IDENTITY_ENDPOINT + IMDS_ENDPOINT; anything else is a VM. #>
    param([scriptblock]$GetEnv)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    $ep = [string](& $GetEnv 'IDENTITY_ENDPOINT'); $hd = [string](& $GetEnv 'IDENTITY_HEADER'); $imds = [string](& $GetEnv 'IMDS_ENDPOINT')
    if ([string](& $GetEnv 'CONTAINER_APP_JOB_NAME') -or [string](& $GetEnv 'CONTAINER_APP_NAME') -or ($ep -and $hd)) { return 'container' }
    if ($ep -and $imds) { return 'arc' }
    return 'vm'
}

function Get-SITelemetryRuntimeIdentity {
    <# PURE over -Vars (default: the run's globals). The KIND of identity the engines sign in as -- never which one:
       mi-<hosting> | spn-certificate | spn-secret. An SPN with a certificate thumbprint is spn-certificate; one with only
       a secret is spn-secret; nothing known is spn-certificate (the internal sign-in, certificate only). #>
    param([Parameter(Mandatory)][string]$Hosting, [System.Collections.IDictionary]$Vars)
    if (-not $Vars) {
        $Vars = @{ UseMi = $global:SI_UseManagedIdentity; PreferUami = $global:SI_PreferUami; UamiClientId = $global:SI_UAMI_ClientId
                   Thumbprint = @($global:SI_SPN_CertThumbprint, $global:SpnCertificateThumbprint) -join ''
                   Secret = @($global:SI_SPN_Secret, $global:SpnClientSecret) -join '' }
    }
    if ([bool]$Vars.UseMi -or ([bool]$Vars.PreferUami -and "$($Vars.UamiClientId)".Trim())) { return ('mi-' + $Hosting) }
    if ("$($Vars.Thumbprint)".Trim()) { return 'spn-certificate' }
    if ("$($Vars.Secret)".Trim()) { return 'spn-secret' }
    return 'spn-certificate'
}

function Get-SITelemetryLicenceInfo {
    <# PURE. A licence status (Get-SILicense) as Edition (community | pro | trial) + LicenceState (valid | grace |
       expired | none). Only a valid or grace licence makes the edition pro (trial when its sku says so). #>
    param([AllowNull()]$License)
    $st = if ($License) { "$($License.Status)" } else { '' }
    $state = switch ($st) { 'Valid' { 'valid' } 'Grace' { 'grace' } 'Expired' { 'expired' } default { 'none' } }
    $edition = 'community'
    # #510 (framework §12.6a): the sku names the edition -- a Community sku is community even while it verifies
    if ($state -in @('valid', 'grace')) {
        $sku = "$($License.Sku)".Trim()
        if ($sku -match '(?i)trial') { $edition = 'trial' }
        elseif ($sku -match '(?i)^(pro|trial)([^a-z]|$)|(^|[^a-z])msp([^a-z]|$)') { $edition = 'pro' }
    }
    [pscustomobject]@{ Edition = $edition; LicenceState = $state }
}

function Get-SITelemetryCounts {
    <# PURE. The run's count under the name the receiver knows: identities for the identity engine, findings for Risk
       Analysis, assets otherwise. A negative count means "not counted" and is not sent. #>
    param([Parameter(Mandatory)][string]$Job, [long]$Count = -1)
    if ($Count -lt 0) { return @{} }
    $name = switch -Regex ($Job) { '^si-identity$' { 'identities' } '^si-ra-' { 'findings' } default { 'assets' } }
    @{ $name = $Count }
}

function Get-SITelemetryFailedStep {
    <# PURE. Which stage a run that did not end ok stopped in: the run context's FailedStep when the engine recorded it,
       'settings' for a settings error, 'ra-query' for a partial Risk Analysis run, else nothing. #>
    param([AllowNull()]$RunContext, [AllowEmptyString()][string]$ExitReason, [string]$Job)
    if ($ExitReason -eq 'success') { return $null }
    if ($ExitReason -eq 'settings-error') { return 'settings' }
    if ($RunContext -and $RunContext.PSObject.Properties['FailedStep'] -and "$($RunContext.FailedStep)".Trim()) {
        $s = ("$($RunContext.FailedStep)".Trim().ToLowerInvariant() -replace '[^a-z0-9\-]', '-') -replace '^[^a-z]+', ''
        if ($s.Length -gt 32) { $s = $s.Substring(0, 32) }
        if ($s -match '^[a-z][a-z0-9\-]{0,31}$') { return $s }
    }
    if ($ExitReason -eq 'success-partial' -and $Job -like 'si-ra-*') { return 'ra-query' }
    return $null
}

function Get-SITelemetryIncompleteReports {
    <#
        PURE. #641: the reports of a Risk Analysis run that are not complete, from its run context (ReportsExpected,
        ReportsStored, ReportsIncomplete -- numbers; ReportsIncompleteLink -- the web app page that lists them).
        $null when the run has none (or is not a Risk Analysis run that counted them).
    #>
    param([AllowNull()]$RunContext)
    if ($null -eq $RunContext -or -not $RunContext.PSObject.Properties['ReportsIncomplete']) { return $null }
    $n = 0L; if (-not [long]::TryParse([string]$RunContext.ReportsIncomplete, [ref]$n) -or $n -le 0) { return $null }
    $num = { param($v) $x = 0L; if ([long]::TryParse([string]$v, [ref]$x) -and $x -ge 0) { $x } else { 0L } }
    $link = ''
    if ($RunContext.PSObject.Properties['ReportsIncompleteLink']) { $link = "$($RunContext.ReportsIncompleteLink)".Trim(); if ($link.Length -gt 400) { $link = '' } }
    [pscustomobject]@{ Expected = (& $num $RunContext.ReportsExpected); Stored = (& $num $RunContext.ReportsStored); Incomplete = $n; Link = $link }
}

function Test-SITelemetryHeartbeatDue {
    <# PURE. A heartbeat is due once per UTC day: when none was sent yet, or the last one was on an earlier UTC date. #>
    param([AllowEmptyString()][AllowNull()][string]$LastSentDate, [Parameter(Mandatory)][datetime]$NowUtc)
    $today = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    return ("$LastSentDate".Trim() -ne $today)
}

function ConvertTo-SITelemetryWire {
    <#
        PURE. A record from SI-Telemetry.ps1 (heartbeat or run, already checked) as the framework's Schema 2 wire record
        (New-AitUplinkReport). -Counts are the RAW counts: the framework buckets them itself in anonymous mode. In
        anonymous mode the tenant, the host and the error text are not passed at all -- the SI record does not carry
        them, and the framework would drop them anyway.
    #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][ValidateSet('anonymous', 'identified')][string]$Mode,
          [System.Collections.IDictionary]$Counts, $Now,
          # #517 / framework §12.6b: the installed licence's id -- on an IDENTIFIED report only, and only GUID-shaped (Invardia
          # refuses the whole report for anything else)
          [AllowEmptyString()][AllowNull()][string]$LicenceId,
          # framework §8.9: the install's own links as `endpoints` -- on an IDENTIFIED heartbeat only, and only while the send
          # gate is on (SI_Telemetry_SendEndpoints, default OFF; ConvertTo-SITelemetryEndpointList: kind + url (+ label),
          # at most 12, https, no query string); never on an anonymous record
          [AllowNull()][object[]]$Endpoints,
          # the deep link of an IDENTIFIED run report that did not end ok (the web app's run-health page), https only
          [AllowEmptyString()][AllowNull()][string]$Link,
          # MAIL-3 (#653, framework §12.11a item 4): the environment's name as the web app's header shows it -- optional,
          # on an IDENTIFIED heartbeat / run report only (a name says whose install it is: never anonymous)
          [AllowEmptyString()][AllowNull()][string]$EnvironmentName,
          # CR4 (#654, framework §12.11b item 5): the install's guard mode (ConvertTo-SIGuardModeWire) -- on an IDENTIFIED
          # heartbeat only; $null (no fingerprint recorded: an older install) = left out
          [AllowNull()]$GuardMode,
          # CR3 (#657, framework 12.11e item 4): wave { name, version, ring } and releaseMode { version, sinceUtc, untilUtc,
          # everyMinutes } -- on an IDENTIFIED heartbeat only, each as @{ Known; Value } (Get-SITelemetryReleaseFields):
          # Known = the field is sent (Value $null = JSON null: no wave / not in release mode); $null = left out
          [AllowNull()]$Wave, [AllowNull()]$ReleaseMode,
          # CR3 (framework 12.11e items 3 + 5(a), 2026-10-18): components (Testing / Stable per component) and evidence (the daily
          # counts and verdicts) -- identified heartbeat only, each @{ Known; Value } like wave; $null = left out
          [AllowNull()]$Components, [AllowNull()]$Evidence,
          # #709 / framework 8.16: the run record's Reports (ConvertTo-SIUplinkReports -- already shaped, at most 20, Detail only
          # when identified) and the heartbeat's probe (Get-SICapabilityProbe: Capabilities, CiColumns; Licences identified only)
          [AllowNull()][object[]]$Reports, [AllowNull()]$Probe,
          # framework 4.1b (owner 2026-10-18): the Invardia Support app's database access, READ ONLY (SI-SupportSqlAccess.ps1,
          # Get-SISupportSqlAccess .Wire: group, dbUser, checkedUtc, healedUtc -- healedUtc always null, SI never heals) -- on an
          # IDENTIFIED heartbeat only; $null (no Support app recorded, or not read) = left out
          [AllowNull()]$SupportSqlAccess,
          # CR2: the build label (Get-SITelemetryVersion; default: read here) -- the field `build` on a heartbeat / run report when it
          # differs from Version (the release); '' = no field. A test session reads no label of its own (pass -Build)
          [AllowNull()][AllowEmptyString()][string]$Build)
    $a = @{ Kind = [string]$Record.Kind; Mode = $Mode; Product = [string]$Record.Product; Version = [string]$Record.Version; Ring = $Record.Ring
            Edition = [string]$Record.Edition; Hosting = [string]$Record.Hosting; RuntimeIdentity = [string]$Record.RuntimeIdentity
            LicenceState = [string]$Record.LicenceState }
    if ($Now) { $a.Now = $Now }
    if ($Record.Kind -eq 'heartbeat' -and $Mode -eq 'identified' -and $Counts -and $Counts.Count) {
        # #424: the tenant counts ride ONLY on an identified heartbeat; an anonymous one never carries them.
        $h = @{}; foreach ($k in @($Counts.Keys)) { if ((Get-SITelemetryHeartbeatCountNames) -contains [string]$k) { $h[[string]$k] = $Counts[$k] } }
        if ($h.Count) { $a.Counts = $h }
    }
    if ($Record.Kind -eq 'run') {
        $a.Job = [string]$Record.Job; $a.Outcome = [string]$Record.Outcome; $a.DurationMs = $Record.DurationMs
        $a.FailedStep = [string]$Record.FailedStep; $a.ErrorClass = [string]$Record.ErrorClass
        if ($Counts -and $Counts.Count) { $h = @{}; foreach ($k in @($Counts.Keys)) { $h[[string]$k] = $Counts[$k] }; $a.Counts = $h }
    }
    if ($Mode -eq 'anonymous') {
        $a.InstallId = [string]$Record.InstallId
    } else {
        $a.TenantId = [string]$Record.ClaimedTenantId
        $a.HostName = [string]$Record.Host
        if ($Record.PSObject.Properties['ErrorText']) { $a.ErrorText = [string]$Record.ErrorText }
    }
    $w = New-AitUplinkReport @a
    # #719: the framework client keeps the first 40 Counts keys by name (10 before main's 2026-10-13 copy); Invardia takes up
    # to 40 per record -- SI still shapes the identified
    # heartbeat's Counts itself (SI-TelemetryCounts.ps1: the agreed names, whole numbers >= 0, at most 38)
    if ($w -and $a.ContainsKey('Counts') -and $Record.Kind -eq 'heartbeat' -and (Get-Command -Name ConvertTo-SITelemetryCountsWire -ErrorAction SilentlyContinue)) {
        $cw = ConvertTo-SITelemetryCountsWire -Counts $a.Counts
        if ($cw) { $w | Add-Member -NotePropertyName 'Counts' -NotePropertyValue $cw -Force }
    }
    # framework §8.5 CLOSE-LOOP: a run report that did not end ok names WHO fixes it -- customer-config (the customer's
    # permission, consent, licence or setting; Invardia shows "needs customer action" and opens no fix request) or
    # product-defect. Decided from the error class only (Get-SIErrorFixKind); no class = no FixKind. Added here, beside the
    # framework client, so AitUplink.ps1 stays as it is. Anonymous reports carry it too (an enum identifies nobody).
    if ($w -and $Record.Kind -eq 'run' -and "$($w.ErrorClass)".Trim() -and "$($w.Outcome)" -ne 'ok' -and (Get-Command -Name Get-SIErrorFixKind -ErrorAction SilentlyContinue)) {
        $fk = Get-SIErrorFixKind -ErrorClass ([string]$w.ErrorClass)
        if ($fk) { $w | Add-Member -NotePropertyName 'FixKind' -NotePropertyValue $fk -Force }
    }
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -in @('heartbeat', 'run') -and (Get-Command -Name ConvertTo-SILicenceIdOrEmpty -ErrorAction SilentlyContinue)) {
        $lid = ConvertTo-SILicenceIdOrEmpty $LicenceId
        if ($lid) { $w | Add-Member -NotePropertyName 'LicenceId' -NotePropertyValue $lid -Force }
    }
    # REMOVE-ME gate: Invardia refuses the WHOLE report (422) for a list its validator does not accept, and that validator is
    # not live yet -- the list rides only while SI_Telemetry_SendEndpoints is on (default off)
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -eq 'heartbeat' -and $Endpoints -and (Get-Command -Name ConvertTo-SITelemetryEndpointList -ErrorAction SilentlyContinue) -and (Test-SITelemetrySendEndpoints)) {
        $eps = @(ConvertTo-SITelemetryEndpointList -Items $Endpoints)
        if ($eps.Count) { $w | Add-Member -NotePropertyName 'endpoints' -NotePropertyValue $eps -Force }
    }
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -eq 'run' -and "$($w.Outcome)" -ne 'ok' -and "$Link".Trim() -and (Get-Command -Name ConvertTo-SITelemetryEndpointUrl -ErrorAction SilentlyContinue)) {
        $lk = ConvertTo-SITelemetryEndpointUrl $Link
        if ($lk) { $w | Add-Member -NotePropertyName 'Link' -NotePropertyValue $lk -Force }
    }
    # Invardia accepts the field since 2026-10-14 (it reads environmentName and EnvironmentName); no name, no field
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -in @('heartbeat', 'run')) {
        $en = ConvertTo-SITelemetryEnvironmentName $EnvironmentName
        if ($en) { $w | Add-Member -NotePropertyName 'environmentName' -NotePropertyValue $en -Force }
    }
    # Invardia 1.0.445 reads guardMode on an identified heartbeat (lenient: a value it does not understand is ignored, the
    # report is still taken); never on an anonymous one
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -eq 'heartbeat' -and $GuardMode) {
        $gmMode = if ($GuardMode -is [System.Collections.IDictionary]) { [string]$GuardMode['mode'] } elseif ($GuardMode.PSObject.Properties['mode']) { [string]$GuardMode.mode } else { '' }
        if ($gmMode -in @('strict', 'normal')) { $w | Add-Member -NotePropertyName 'guardMode' -NotePropertyValue ([pscustomobject]$GuardMode) -Force }
    }
    # CR3 (#657): the release fields -- behind SI_Telemetry_ReleaseControl (Get-SITelemetryReleaseFields decides); never anonymous
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -eq 'heartbeat') {
        foreach ($f in @(@{ N = 'wave'; V = $Wave }, @{ N = 'releaseMode'; V = $ReleaseMode }, @{ N = 'components'; V = $Components }, @{ N = 'evidence'; V = $Evidence })) {
            $fv = $f.V
            if ($null -eq $fv -or -not $fv.Known) { continue }
            $val = if ($null -ne $fv.Value) { [pscustomobject]$fv.Value } else { $null }
            $w | Add-Member -NotePropertyName $f.N -NotePropertyValue $val -Force
        }
    }
    # CR2 (Invardia 2026-10-18): Version is the release; the build label rides as `build` -- only when it says something else
    if ($w -and $Record.Kind -in @('heartbeat', 'run')) {
        $bl = if ($PSBoundParameters.ContainsKey('Build')) { [string]$Build } elseif (Get-Module -Name Pester) { '' } else { try { [string](Get-SITelemetryVersion) } catch { '' } }
        $bl = $bl.Trim()
        if ($bl -and $bl -ne [string]$w.Version -and $bl.Length -le 100) { $w | Add-Member -NotePropertyName 'build' -NotePropertyValue $bl -Force }
    }
    # framework 4.1b: supportSqlAccess { group, dbUser, checkedUtc, healedUtc } -- identified heartbeat only; group / dbUser are
    # true / false, or null when they could not be checked (never claimed); healedUtc is always null (Invardia heals, not SI)
    if ($w -and $Mode -eq 'identified' -and $Record.Kind -eq 'heartbeat' -and $SupportSqlAccess) {
        $sv = ConvertTo-SITelemetrySupportSqlAccessWire $SupportSqlAccess
        if ($sv) { $w | Add-Member -NotePropertyName 'supportSqlAccess' -NotePropertyValue $sv -Force }
    }
    # #709 / framework 8.16 UPLINK-CAUSES (Invardia 1.0.477). A problem here never costs the record: anything that fails is
    # left out, and the sender sends the record again without these fields when Invardia refuses it.
    if ($w -and $Record.Kind -eq 'run' -and $Reports -and @($Reports).Count) {
        try {
            $items = @(@($Reports) | Where-Object { $_ -and "$($_.Code)".Trim() -and "$($_.CauseClass)".Trim() } | Select-Object -First 20)
            if ($Mode -ne 'identified') { $items = @($items | ForEach-Object { $c = $_.PSObject.Copy(); if ($c.PSObject.Properties['Detail']) { $c.PSObject.Properties.Remove('Detail') }; $c }) }
            if ($items.Count) { $w | Add-Member -NotePropertyName 'Reports' -NotePropertyValue $items -Force; $w = Limit-SIUplinkRecordSize -Record $w }
        } catch { if ($w.PSObject.Properties['Reports']) { $w.PSObject.Properties.Remove('Reports') } }
    }
    if ($w -and $Record.Kind -eq 'heartbeat' -and $Probe) {
        try {
            if ($Probe.Capabilities -and @($Probe.Capabilities.Keys).Count) { $w | Add-Member -NotePropertyName 'Capabilities' -NotePropertyValue ([pscustomobject]$Probe.Capabilities) -Force }
            if (@($Probe.CiColumns).Count) { $w | Add-Member -NotePropertyName 'CiColumns' -NotePropertyValue @(@($Probe.CiColumns) | Select-Object -First 40) -Force }
            # the tenant's licences say whose tenant it is: an identified heartbeat only
            if ($Mode -eq 'identified' -and @($Probe.Licences).Count) { $w | Add-Member -NotePropertyName 'Licences' -NotePropertyValue @(@($Probe.Licences) | Select-Object -First 40) -Force }
        } catch { foreach ($n in 'Capabilities', 'CiColumns', 'Licences') { if ($w.PSObject.Properties[$n]) { $w.PSObject.Properties.Remove($n) } } }
    }
    $w
}

# the fields a record carries that Invardia may refuse; a refused record goes again ONCE without them (#657 release fields,
# #709 report causes and the capability probe; #718 the hourly heartbeat's collection state and pipeline progress; #719 the
# hourly heartbeat's eight further fields, SI-HeartbeatFields.ps1)
function Get-SITelemetryOptionalFields { @('wave', 'releaseMode', 'components', 'evidence', 'Reports', 'Capabilities', 'CiColumns', 'Licences', 'Collections', 'runProgress',
                                          'Pipeline', 'Jobs', 'Sources', 'Database', 'Update', 'Mail', 'Warnings', 'Security', 'Published', 'supportSqlAccess', 'build') }

function ConvertTo-SITelemetrySupportSqlAccessWire {
    <# PURE. The heartbeat's supportSqlAccess, exactly { group, dbUser, checkedUtc, healedUtc }: group / dbUser true, false or
       null; checkedUtc an ISO UTC time (required -- none = $null, the field is left out); healedUtc always null (SecurityInsight
       never heals: Invardia does). Anything else in the input is dropped. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $get = { param($k) if ($Value -is [System.Collections.IDictionary]) { if ($Value.Contains($k)) { $Value[$k] } else { $null } } elseif ($Value.PSObject.Properties[$k]) { $Value.$k } else { $null } }
    $tri = { param($v) if ($null -eq $v) { $null } elseif ($v -is [bool]) { $v } else { $null } }
    $c = & $get 'checkedUtc'
    if ($null -eq $c -or -not "$c".Trim()) { return $null }
    try { $iso = ([datetime]$c).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
    [pscustomobject][ordered]@{ group = (& $tri (& $get 'group')); dbUser = (& $tri (& $get 'dbUser')); checkedUtc = $iso; healedUtc = $null }
}

function Get-SITelemetryReleaseFields {
    <#
        CR3 (#657): the release fields of an IDENTIFIED heartbeat -- @{ On; Wave; ReleaseMode; Invoke; Rows; Reason }; Wave /
        ReleaseMode are @{ Known; Value } for ConvertTo-SITelemetryWire, or $null (left out). Nothing at all when:
        anonymous; SI_Telemetry_ReleaseControl does not allow it for this ring (Resolve-SIReleaseControlSwitch); held for 24
        hours after Invardia refused a heartbeat with them; no Pro database; a test session without -Rows. NEVER throws.
          -Rows    the cfg.InstallState rows (Read-SIReleaseControlRows) -- or the context's ReleaseRows (tests)
          -Invoke  the Pro database seam (default: the one the job has open, Get-SIReleaseControlInvoke)
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][datetime]$NowUtc, [scriptblock]$Invoke, $Rows)
    $out = [pscustomobject]@{ On = $false; Wave = $null; ReleaseMode = $null; Components = $null; Evidence = $null; Invoke = $Invoke; Rows = $null; Reason = '' }
    try {
        if (-not (Get-Command -Name Resolve-SIReleaseControlSwitch -ErrorAction SilentlyContinue)) { $out.Reason = 'this release does not carry release control'; return $out }
        if ($Context.Mode -eq 'anonymous') { $out.Reason = 'anonymous: never'; return $out }
        $sw = Resolve-SIReleaseControlSwitch -Ring $(if ($Context.PSObject.Properties['Ring']) { $Context.Ring } else { $null })
        if (-not $sw.On) { $out.Reason = $sw.Reason; return $out }
        if (-not $Rows -and $Context.PSObject.Properties['ReleaseRows']) { $Rows = $Context.ReleaseRows }
        if (-not $Rows) {
            if (-not $Invoke) {
                if (Get-Module -Name Pester) { $out.Reason = 'a test session never reads a database'; return $out }
                $Invoke = Get-SIReleaseControlInvoke
            }
            if (-not $Invoke) { $out.Reason = 'no Pro database is open in this run'; return $out }
            $Rows = Read-SIReleaseControlRows -Invoke $Invoke
        }
        $out.Invoke = $Invoke; $out.Rows = $Rows
        if (Test-SIReleaseControlHold -Hold ([string]$Rows.ReleaseControlHold) -NowUtc $NowUtc) { $out.Reason = 'held for 24 hours: Invardia refused a heartbeat that carried them'; return $out }
        $m = Get-SIReleaseModeFromFingerprint -Fingerprint ([string]$Rows.EngineFingerprint) -NowUtc $NowUtc
        if ($m.Known) { $out.ReleaseMode = [pscustomobject]@{ Known = $true; Value = $m.Wire } }
        $wv = Get-SIReleaseWaveFromUpdateState -Json ([string]$Rows.UpdateState)
        if ($wv.Known) { $out.Wave = [pscustomobject]@{ Known = $true; Value = $wv.Wave } }
        # framework 12.11e items 3 + 5(a): Testing / Stable per component and the daily evidence -- a failed read leaves
        # only these two out (the context's ReleaseEvidence in tests: @{ Components; Evidence })
        try {
            $ef = if ($Context.PSObject.Properties['ReleaseEvidence']) { $Context.ReleaseEvidence } elseif ($Invoke -and (Get-Command -Name Read-SIReleaseEvidenceFields -ErrorAction SilentlyContinue)) { Read-SIReleaseEvidenceFields -Invoke $Invoke -Rows $Rows -NowUtc $NowUtc } else { $null }
            if ($ef -and $ef.Components) { $out.Components = [pscustomobject]@{ Known = $true; Value = $ef.Components } }
            if ($ef -and $ef.Evidence) { $out.Evidence = [pscustomobject]@{ Known = $true; Value = $ef.Evidence } }
        } catch { $out.Components = $null; $out.Evidence = $null }
        $out.On = [bool]($out.ReleaseMode -or $out.Wave -or $out.Components -or $out.Evidence)
        $out.Reason = $sw.Reason
    } catch { $out.On = $false; $out.Wave = $null; $out.ReleaseMode = $null; $out.Reason = ("not read: {0}" -f $_.Exception.Message) }
    $out
}

function Get-SITelemetryGuardModeWire {
    <#
        CR4 (#654): the identified heartbeat's guardMode (ConvertTo-SIGuardModeWire), from the FIRST of:
          -Context.GuardMode       (tests, or a caller that has it)
          -Rows                    the cfg.InstallState rows already read (Read-SIReleaseControlRows: EngineFingerprint, GuardStrictEnd)
          -Invoke                  the Pro database the sender has open (Read-SIGuardModeState)
          Get-SIGuardModeNow       the guard code's own database (an engine run; never in a test session)
        LIVE 2026-10-18: the half-hourly heartbeat job has the Pro database open but not the guard code that finds it by
        itself, so it read "nothing recorded" and sent NO guardMode while the install was strict. $null = no fingerprint is
        recorded (an older install) or nothing could be read -- the field is left out. NEVER throws.
    #>
    param($Context, [scriptblock]$Invoke, $Rows, [Parameter(Mandatory)][datetime]$NowUtc)
    try {
        if ($Context -and $Context.PSObject.Properties['GuardMode']) { return $Context.GuardMode }
        if (-not (Get-Command -Name ConvertTo-SIGuardModeWire -ErrorAction SilentlyContinue)) { return $null }
        if ($Rows -and $Rows.PSObject.Properties['EngineFingerprint'] -and "$($Rows.EngineFingerprint)".Trim()) {
            return (ConvertTo-SIGuardModeWire -Mode (Get-SIGuardModeFromState -Fingerprint ([string]$Rows.EngineFingerprint) -StrictEnd ([string]$Rows.GuardStrictEnd) -NowUtc $NowUtc))
        }
        if ($Invoke) { return (ConvertTo-SIGuardModeWire -Mode (Read-SIGuardModeState -Invoke $Invoke -NowUtc $NowUtc)) }
        if (Get-Module -Name Pester) { return $null }
        ConvertTo-SIGuardModeWire -Mode (Get-SIGuardModeNow -NowUtc $NowUtc)
    } catch { $null }
}

function Test-SITelemetryHasReleaseFields {
    <# PURE. Does a wire record carry a release field (wave / releaseMode)? #>
    param($Record)
    [bool]($Record -and ($Record.PSObject.Properties['wave'] -or $Record.PSObject.Properties['releaseMode'] -or $Record.PSObject.Properties['components'] -or $Record.PSObject.Properties['evidence']))
}

function Send-SITelemetryRecordWithFallback {
    <#
        CR3 (#657, framework 12.22 3(b)): one record through -Transport; a heartbeat with the release fields that is NOT taken
        is sent again ONCE without them -- when that one is taken, the fields are held back for 24 hours (-Invoke:
        cfg.InstallState 'ReleaseControlHold') and said once. Returns @{ Result; Record; Held }. Never throws past the transport.
    #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][scriptblock]$Transport, [Parameter(Mandatory)]$Context, [int]$TimeoutSec = 5,
          [scriptblock]$Invoke, [datetime]$NowUtc = [datetime]::UtcNow)
    $r = & $Transport $Record $Context.Endpoint $Context.AccessCode $TimeoutSec
    # #902: a record with HOLD items (class held-last-good / held-too-long, or the hold fields) that is NOT taken goes again
    # first WITHOUT those items only -- a validator that does not know the hold contract yet never costs the real failures
    if ("$($r.Status)" -ne 'ok' -and $Record -and $Record.PSObject.Properties['Reports'] -and (Get-Command -Name Get-SIUplinkCausesContract -ErrorAction SilentlyContinue)) {
        $hc = Get-SIUplinkCausesContract
        $isHold = { param($i) $i -and (([string]$i.CauseClass -in @([string]$hc.HoldClassInfo, [string]$hc.HoldClassEscalated)) -or $i.PSObject.Properties[[string]$hc.HoldFieldHeld]) }
        $all = @($Record.Reports)
        $keep = @($all | Where-Object { -not (& $isHold $_) })
        if ($keep.Count -lt $all.Count) {
            if ($keep.Count) { $Record.Reports = $keep } else { $Record.PSObject.Properties.Remove('Reports') }
            if (-not $global:SI_UplinkHoldsWarned) { $global:SI_UplinkHoldsWarned = $true; Write-SIUplinkDiag ("Invardia did not take the run report with the held reports ({0}) -- it goes again without them" -f "$($r.Reason)") }
            $r = & $Transport $Record $Context.Endpoint $Context.AccessCode $TimeoutSec
        }
    }
    $opt = @(Get-SITelemetryOptionalFields | Where-Object { $Record -and $Record.PSObject.Properties[$_] })
    if ("$($r.Status)" -eq 'ok' -or -not $opt.Count) { return [pscustomobject]@{ Result = $r; Record = $Record; Held = $false } }
    $first = "$($r.Reason)"
    $hadRelease = [bool](Test-SITelemetryHasReleaseFields $Record)
    # #709: a record with Reports[] / the capability probe that is NOT taken goes again without them -- the run record matters
    # more than its causes (framework 8.16: send without Reports rather than fail)
    foreach ($n in $opt) { $Record.PSObject.Properties.Remove($n) }
    $r2 = & $Transport $Record $Context.Endpoint $Context.AccessCode $TimeoutSec
    if ("$($r2.Status)" -ne 'ok') { return [pscustomobject]@{ Result = $r2; Record = $Record; Held = $false } }
    if (@($opt | Where-Object { $_ -notin @('wave', 'releaseMode', 'components', 'evidence', 'Collections', 'runProgress', 'Pipeline', 'Jobs', 'Sources', 'Database', 'Update', 'Mail', 'Warnings', 'Security', 'Published', 'supportSqlAccess', 'build') }).Count) {
        if (-not $global:SI_UplinkCausesWarned) { $global:SI_UplinkCausesWarned = $true; Write-SIUplinkDiag ("Invardia did not take the status report with the report causes / capability fields ({0}) -- it was sent without them" -f (ConvertTo-AitUplinkRedacted -Text $first)) }
    }
    if (-not $hadRelease) { return [pscustomobject]@{ Result = $r2; Record = $Record; Held = $false } }
    $held = $false
    if (Get-Command -Name Save-SIReleaseControlHold -ErrorAction SilentlyContinue) { $held = Save-SIReleaseControlHold -Invoke $Invoke -NowUtc $NowUtc -Why (ConvertTo-AitUplinkRedacted -Text $first) }
    if (-not $global:SI_ReleaseControlWarned) {
        $global:SI_ReleaseControlWarned = $true
        try { Write-Warning ("Invardia did not take the status report with the release fields (wave, release mode) -- it was sent without them{0}. To turn them off: SI_Telemetry_ReleaseControl = off." -f $(if ($held) { ', and they are held back for 24 hours' } else { '' })) } catch { }
    }
    [pscustomobject]@{ Result = $r2; Record = $Record; Held = $held }
}

function ConvertTo-SITelemetryEnvironmentName {
    <# PURE. The environment's name for the uplink: trimmed, one line, without a ring / edition it carries itself
       ('Internal (ring 1, PRO)' -> 'Internal', the same name the mail subjects use), at most 100 characters; '' = left out. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = ("$Value" -replace '[\r\n\t]+', ' ').Trim()
    $v = ($v -replace '(?i)\s*\([^()]*\b(ring\s*\d|pro|community)\b[^()]*\)\s*$', '').Trim()
    if ($v.Length -gt 100) { $v = $v.Substring(0, 100).TrimEnd() }
    $v
}

function Get-SITelemetryEnvironmentName {
    <#
        The environment's name as the web app's header shows it (MAIL-3 / #653: the same name the mail subjects carry):
        SIWeb_EnvironmentName, else SI_EnvironmentName. Not set = '' (left out -- the install id is not a name). -Globals
        is the test seam.
    #>
    param([System.Collections.IDictionary]$Globals)
    foreach ($n in @('SIWeb_EnvironmentName', 'SI_EnvironmentName')) {
        $v = if ($Globals) { if ($Globals.Contains($n)) { $Globals[$n] } else { $null } } else { Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
        $v = ConvertTo-SITelemetryEnvironmentName ([string]$v)
        if ($v) { return $v }
    }
    ''
}

# =====================================================================================================================
#  This install: where state is kept, the install id, the install key, the endpoint
# =====================================================================================================================
function Get-SITelemetryStateDirectory {
    <# Where the install id and the last heartbeat date are kept: SI_TELEMETRY_STATE_DIR, else
       %ProgramData%\SecurityInsight\telemetry on Windows, else ~/.securityinsight/telemetry. #>
    param([scriptblock]$GetEnv)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    $d = [string](& $GetEnv 'SI_TELEMETRY_STATE_DIR')
    if ($d.Trim()) { return $d.Trim() }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        return [System.IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'SecurityInsight', 'telemetry')
    }
    $h = [Environment]::GetFolderPath('UserProfile'); if (-not $h) { $h = [System.IO.Path]::GetTempPath() }
    [System.IO.Path]::Combine($h, '.securityinsight', 'telemetry')
}

function Test-SITelemetryProInstall {
    <# PURE (with -GetEnv). Does this install have a Pro database (the setting, or the container's SI_CFG_ variable)? #>
    param([scriptblock]$GetEnv)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    if ("$($global:SI_ProSqlServer)".Trim() -and "$($global:SI_ProSqlDatabase)".Trim()) { return $true }
    return [bool]("$(& $GetEnv 'SI_CFG_SI_ProSqlServer')".Trim() -and "$(& $GetEnv 'SI_CFG_SI_ProSqlDatabase')".Trim())
}

function Get-SITelemetryInstallId {
    <#
        The anonymous install id: a random GUID created ONCE and kept in <state>\install-id. It identifies nothing but
        "the same install as last time". When the file cannot be written (a read-only disk) a fresh id is used for this
        process. Never throws.
    #>
    param([Parameter(Mandatory)][string]$StateDirectory, [scriptblock]$GetEnv)
    # A CONTAINER keeps no file between runs: every run was a "new install" (6 installs reported for 3 -- fix request
    # 85bd728f). There the id is derived from the install's own storage account name (one per install, the same every
    # run); it still identifies nothing but "the same install as last time".
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    $stg = "$(& $GetEnv 'SI_STORAGE_ACCOUNT')".Trim().ToLowerInvariant()
    if ($stg -and "$(& $GetEnv 'SI_ENGINE')".Trim()) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('securityinsight-install:' + $stg)) } finally { $sha.Dispose() }
        $b = New-Object byte[] 16; [Array]::Copy($h, $b, 16)
        $b[7] = [byte](($b[7] -band 0x0F) -bor 0x50); $b[8] = [byte](($b[8] -band 0x3F) -bor 0x80)   # a version-5 shaped GUID
        return ([guid]$b).ToString()
    }
    $guidRe = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $f = [System.IO.Path]::Combine($StateDirectory, 'install-id')
    $damaged = $false
    try {
        if ([System.IO.File]::Exists($f)) {
            $v = ([System.IO.File]::ReadAllText($f)).Trim().ToLowerInvariant()
            if ($v -match $guidRe) { return $v }
            $damaged = $true
        }
    } catch { }
    $new = [guid]::NewGuid().ToString()
    if ($damaged) {
        # A damaged file is replaced once, so the install keeps ONE id from here on.
        try { [System.IO.File]::WriteAllText($f, $new) } catch { }
        return $new
    }
    try {
        $null = [System.IO.Directory]::CreateDirectory($StateDirectory)
        # CreateNew: two engines starting together must not overwrite each other's id. The loser reads the winner's.
        $fs = New-Object System.IO.FileStream($f, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        try { $b = [System.Text.Encoding]::ASCII.GetBytes($new); $fs.Write($b, 0, $b.Length) } finally { $fs.Dispose() }
    } catch {
        try {
            $v = ([System.IO.File]::ReadAllText($f)).Trim().ToLowerInvariant()
            if ($v -match $guidRe) { return $v }
        } catch { }
    }
    return $new
}

function Get-SITelemetryLastHeartbeat {
    param([Parameter(Mandatory)][string]$StateDirectory)
    try {
        $f = [System.IO.Path]::Combine($StateDirectory, 'last-heartbeat')
        if ([System.IO.File]::Exists($f)) { return ([System.IO.File]::ReadAllText($f)).Trim() }
    } catch { }
    return ''
}

function Set-SITelemetryLastHeartbeat {
    param([Parameter(Mandatory)][string]$StateDirectory, [Parameter(Mandatory)][datetime]$NowUtc)
    try {
        $null = [System.IO.Directory]::CreateDirectory($StateDirectory)
        [System.IO.File]::WriteAllText([System.IO.Path]::Combine($StateDirectory, 'last-heartbeat'),
            $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture))
    } catch { }
}

function Get-SITelemetryEndpoint {
    <# The report address: SI_Telemetry_Endpoint, else SI_TELEMETRY_ENDPOINT, else '' (= the framework default, Invardia's). #>
    $e = @([string]$global:SI_Telemetry_Endpoint, [string]$env:SI_TELEMETRY_ENDPOINT) | Where-Object { "$_".Trim() } | Select-Object -First 1
    return "$e".Trim()
}

function Get-SITelemetryInstallKey {
    <# Pro / trial only: the install key from the install's Key Vault (SI-Invardia-InstallKey), read as the runtime
       identity. '' when there is none or it cannot be read -- the install then reports anonymously. Never throws, never
       prints the value.
       -WithReason: @{ Key; Reason } -- Reason says in plain words why there is no key ('' when there is one); it names
       the secret and the vault, never a value. #>
    param([switch]$WithReason)
    if ($null -eq $script:SITelemetrySend) { $script:SITelemetrySend = New-SITelemetrySendState }
    $name = $script:SITelemetrySend.InstallKeyName
    $why = ''
    $key = ''
    try {
        # an internal install: the platform Key Vault (signed in by SecurityInsight itself -- auth/SI-PlatformConnect.ps1)
        if ($global:Context -and $global:KV_HighPriv_KeyVaultName) {
            try {
                if (-not (Get-Command -Name Get-SIPlatformSecret -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'auth', 'SI-PlatformConnect.ps1')) }
                $v = [string](Get-SIPlatformSecret -Context $global:Context -Name $name -AsPlainText -ErrorAction Stop 3>$null); if ($v.Trim()) { $key = $v.Trim() }
                else { $why = ('{0} is empty or missing in the platform Key Vault {1}' -f $name, [string]$global:KV_HighPriv_KeyVaultName) }
            } catch { $why = ('{0} could not be read from the platform Key Vault {1}: {2}' -f $name, [string]$global:KV_HighPriv_KeyVaultName, $_.Exception.Message) }
        }
        if (-not $key) {
            if (-not (Get-Command -Name Get-SIVaultName -ErrorAction SilentlyContinue)) {
                $h = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'auth', 'Get-SIVaultName.ps1'); if (Test-Path -LiteralPath $h) { . $h }
            }
            $vault = $null
            if (Get-Command -Name Get-SIVaultName -ErrorAction SilentlyContinue) { try { $vault = Get-SIVaultName -AllowMissing } catch { } }
            elseif ($global:SI_KeyVaultName) { $vault = [string]$global:SI_KeyVaultName }
            if (-not $vault) {
                if (-not $why) { $why = 'the install''s Key Vault is not known to this job (SI_KeyVaultName is not set)' }
            } else {
                if (-not (Get-Command -Name Get-SIKvSecret -ErrorAction SilentlyContinue)) {
                    $h = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'auth', 'Get-SIKvSecret.ps1'); if (Test-Path -LiteralPath $h) { . $h }
                }
                if (Get-Command -Name Get-SIKvSecret -ErrorAction SilentlyContinue) {
                    $kvWarn = $null
                    $v = [string](Get-SIKvSecret -VaultName $vault -SecretName $name -WarningVariable kvWarn -WarningAction SilentlyContinue)
                    $key = $v.Trim()
                    if (-not $key) {
                        $w = (@($kvWarn) | ForEach-Object { [string]$_ } | Select-Object -First 1)
                        $why = $(if ($w) { ('{0} could not be read from the Key Vault {1}: {2}' -f $name, $vault, ($w -replace '^Get-SIKvSecret:\s*', '')) }
                                 else { ('{0} is not in the Key Vault {1}, or this job''s identity may not read secrets there' -f $name, $vault) })
                    }
                } elseif (-not $why) { $why = 'the Key Vault reader (auth\Get-SIKvSecret.ps1) is not available in this job' }
            }
        }
    } catch { $key = ''; if (-not $why) { $why = ('{0} could not be read: {1}' -f $name, $_.Exception.Message) } }
    if ($key) { $why = '' }
    if ($WithReason) { return [pscustomobject]@{ Key = $key; Reason = $why } }
    return $key
}

function Get-SITelemetryVersion {
    <#
        The BUILD LABEL of this install: the stamped build (BUILD.json) as "<display>+<shortCommit>" -- e.g.
        "3.0.0-rc.12+0dc9062" -- so a fleet view tells the builds of one release apart. No BUILD.json: the VERSION file.
        CR2 (Invardia 2026-10-18): this is NOT what Version says on the uplink -- Version is the RELEASE the install runs
        (Get-SITelemetryReleaseVersion; Invardia matches installs to releases by it: the health hold, "who runs V"); the
        label rides as its own field `build` (heartbeat and run report; an optional field, resent without when refused).
    #>
    if ($null -eq $script:SITelemetrySend) { $script:SITelemetrySend = New-SITelemetrySendState }
    try {
        $bj = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'BUILD.json')
        if ([System.IO.File]::Exists($bj)) {
            $j = [System.IO.File]::ReadAllText($bj) | ConvertFrom-Json
            $d = ([string]$j.display).Trim(); $sc = ([string]$j.shortCommit).Trim()
            if ($d) { return $(if ($sc) { '{0}+{1}' -f $d, $sc } else { $d }) }
        }
    } catch { }
    try {
        $f = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'VERSION')
        if ([System.IO.File]::Exists($f)) { return ([System.IO.File]::ReadAllText($f)).Trim() }
    } catch { }
    return ''
}

function Get-SITelemetryReleaseVersion {
    <# The RELEASE this install runs (BUILD.json 'release', stamped by Publish-SIRelease: 3.0.0.<build number>) -- what the
       error catalogue's fixedIn is compared with (#709). Not stamped (an older or a local package): the reported version,
       which never reads as newer than a fix. #>
    if ($null -eq $script:SITelemetrySend) { $script:SITelemetrySend = New-SITelemetrySendState }
    try {
        $bj = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'BUILD.json')
        if ([System.IO.File]::Exists($bj)) {
            $j = [System.IO.File]::ReadAllText($bj) | ConvertFrom-Json
            if ($j.PSObject.Properties['release'] -and "$($j.release)".Trim()) { return ([string]$j.release).Trim() }
        }
    } catch { }
    Get-SITelemetryVersion
}

function Test-SITelemetryReleasedLabel {
    <# PURE. #918 / #919: is -Release (BUILD.json 'release') the label of a RELEASED build? Digits and dots only, 3 or 4 parts --
       3.0.1 (#919, from the next release on) and 3.0.0.202610272235 (before). Empty, a dev / rc / local label, or any letter
       is not. Decided by BUILD.json's release field, never by the number of parts of VERSION. @{ Released; Reason }. #>
    param([AllowNull()][AllowEmptyString()][string]$Release)
    $r = "$Release".Trim()
    if (-not $r) { return [pscustomobject]@{ Released = $false; Reason = 'BUILD.json carries no release (a dev tree, a test VM or a gate''s work folder)' } }
    if ($r -match '^\d+\.\d+\.\d+(\.\d+)?$') { return [pscustomobject]@{ Released = $true; Reason = ('release {0}' -f $r) } }
    [pscustomobject]@{ Released = $false; Reason = ("'{0}' is a dev or pre-release label" -f $r) }
}

function Test-SITelemetryReleasedBuild {
    <# #918: does this install run a RELEASED build? Reads ONLY BUILD.json's 'release' under the solution root (-Root; default
       the root of this file's tree) -- a dev tree has none, whatever its VERSION file says. @{ Released; Reason }. Never throws. #>
    param([string]$Root)
    try {
        if (-not "$Root".Trim()) { if ($null -eq $script:SITelemetrySend) { $script:SITelemetrySend = New-SITelemetrySendState }; $Root = $script:SITelemetrySend.SIRoot }
        $bj = [System.IO.Path]::Combine($Root, 'BUILD.json')
        if (-not [System.IO.File]::Exists($bj)) { return [pscustomobject]@{ Released = $false; Reason = 'no BUILD.json (a dev tree, a test VM or a gate''s work folder)' } }
        $j = [System.IO.File]::ReadAllText($bj).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
        Test-SITelemetryReleasedLabel -Release $(if ($j.PSObject.Properties['release']) { [string]$j.release } else { '' })
    } catch { [pscustomobject]@{ Released = $false; Reason = ('BUILD.json could not be read ({0})' -f $_.Exception.Message) } }
}

function Test-SITelemetryCommunitySendAllowed {
    <# #918 (2026-10-27: 210 "installs" on version 3.0.0 were test runs and dev runs): may a record go out with -AccessCode? Only
       the PUBLIC community code is gated -- an identified install's own key is never refused here. The community code needs a
       RELEASED build (Test-SITelemetryReleasedBuild; -Released overrides it, tests). @{ Allowed; Reason }. #>
    param([AllowNull()][AllowEmptyString()][string]$AccessCode, $Released)
    $community = if (Get-Variable -Name AitUplinkCommunityCode -Scope Script -ErrorAction SilentlyContinue) { [string]$script:AitUplinkCommunityCode } else { 'invardia-community-telemetry-v1' }
    if ("$AccessCode" -ne $community) { return [pscustomobject]@{ Allowed = $true; Reason = 'not the community code' } }
    $rel = if ($null -ne $Released) { [pscustomobject]@{ Released = [bool]$Released; Reason = $(if ($Released) { 'released' } else { 'not a released build' }) } } else { Test-SITelemetryReleasedBuild }
    if ($rel.Released) { return [pscustomobject]@{ Allowed = $true; Reason = $rel.Reason } }
    [pscustomobject]@{ Allowed = $false; Reason = ('not a released build ({0}) -- nothing is sent to the public community uplink' -f $rel.Reason) }
}

function Get-SITelemetryContext {
    <#
        Who and what this install reports as, once per process (cached in $global:SI_TelemetryContext). Every input can be
        injected (tests): -License (a Get-SILicense status), -InstallKey, -GetEnv, -StateDirectory, -Vars (runtime
        identity), -TenantId, -Version. Returns Mode (anonymous | identified), Endpoint, AccessCode, Edition, LicenceState,
        Version, Hosting, RuntimeIdentity, InstallId (anonymous only), TenantId (identified only), StateDirectory.
        The install key is looked up ONLY for a Pro / trial licence: a Community install never touches a Key Vault here.
    #>
    param([AllowNull()]$License, [AllowNull()][AllowEmptyString()][string]$InstallKey, [scriptblock]$GetEnv, [string]$StateDirectory,
          [System.Collections.IDictionary]$Vars, [AllowEmptyString()][string]$TenantId, [string]$Version, [switch]$Refresh,
          # #427: the edition when the caller knows it better than a licence status (the guided install, the updater)
          [ValidateSet('', 'community', 'pro', 'trial')][string]$Edition = '',
          # the ring (Resolve-SIReportedRing): -UpdaterRing = what the updater resolved in this process; -RingFacts = the
          # cfg.InstallState rows (default $global:SI_InstallRingFacts, read by the Pro settings layer at run start);
          # -RingSetting = SI_UpdateRing (default the global); -CommunityRing = config\update.custom.json's ring
          [AllowNull()]$UpdaterRing, [AllowNull()]$RingFacts, [AllowNull()]$RingSetting, [AllowNull()]$CommunityRing,
          # framework §8.4: the install's own links (default: Get-SITelemetryInstallEndpoints) -- identified installs only
          [AllowNull()][object[]]$Endpoints,
          # MAIL-3 (#653): the environment's name (default: Get-SITelemetryEnvironmentName) -- identified installs only
          [AllowNull()][AllowEmptyString()][string]$EnvironmentName)
    $injected = @($PSBoundParameters.Keys | Where-Object { $_ -ne 'Refresh' }).Count -gt 0
    if (-not $injected -and -not $Refresh -and $global:SI_TelemetryContext) { return $global:SI_TelemetryContext }
    if ($null -eq $script:SITelemetrySend) { $script:SITelemetrySend = New-SITelemetrySendState }

    if (-not $PSBoundParameters.ContainsKey('License')) {
        $License = $null
        if (-not (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue)) {
            $cat = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'engine', 'SI-FeatureCatalog.ps1')
            # Loaded here for this call only (functions dot-sourced in a function vanish when it returns) -- enough: the
            # result is cached.
            if (Test-Path -LiteralPath $cat) { try { . $cat } catch { } }
        }
        if (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue) { try { $License = Get-SILicense 3>$null } catch { $License = $null } }
    }
    $li = Get-SITelemetryLicenceInfo -License $License
    if ($Edition) { $li = [pscustomobject]@{ Edition = $Edition; LicenceState = $li.LicenceState } }
    elseif ($li.Edition -eq 'community' -and (Test-SITelemetryProInstall -GetEnv $GetEnv)) {
        # An install WITH a Pro database is Pro even when this run could not read its licence (it failed before, or its
        # identity cannot read the vault): reported as Pro with the licence state as found -- never as an anonymous
        # Community install (fix request 85bd728f: three Pro installs reported as six Community ones).
        $li = [pscustomobject]@{ Edition = 'pro'; LicenceState = $li.LicenceState }
    }
    $hosting = Get-SITelemetryHosting -GetEnv $GetEnv
    $rt = Get-SITelemetryRuntimeIdentity -Hosting $hosting -Vars $Vars
    $key = ''
    # why this install reports anonymously (plain words; never a secret value) -- '' when it is identified
    $anonWhy = ''
    if ($li.Edition -ne 'community') {
        if ($PSBoundParameters.ContainsKey('InstallKey')) { $key = "$InstallKey".Trim(); if (-not $key) { $anonWhy = 'no install key was given' } }
        else {
            $kr = Get-SITelemetryInstallKey -WithReason
            if ($kr -is [string]) { $key = $kr.Trim() } else { $key = "$($kr.Key)".Trim(); $anonWhy = [string]$kr.Reason }
            if (-not $key -and -not $anonWhy) { $anonWhy = 'the install key (SI-Invardia-InstallKey) could not be read' }
        }
        if ($key -and $key -notmatch '^inv-[^\s]{8,}$') { $anonWhy = 'the value stored as the install key (SI-Invardia-InstallKey) is not an Invardia install key' }
        if ($key -notmatch '^inv-[^\s]{8,}$') { $key = '' }   # not an Invardia install key: report anonymously, never with it
    } else {
        $anonWhy = $(if ($null -eq $License) { 'no SecurityInsight Pro licence could be read in this run, and this install has no Pro database set' }
                     else { ('no SecurityInsight Pro licence is in force (licence: {0}{1})' -f $(if ("$($License.Status)".Trim()) { [string]$License.Status } else { 'unknown' }), $(if ("$($License.Reason)".Trim()) { ' -- ' + [string]$License.Reason } else { '' })) })
    }
    $sender = Resolve-AitUplinkSender -Enabled $true -InstallKey $key -Endpoint (Get-SITelemetryEndpoint)
    if ($sender.Mode -ne 'anonymous') { $anonWhy = '' }
    $dir = if ("$StateDirectory".Trim()) { $StateDirectory } else { Get-SITelemetryStateDirectory -GetEnv $GetEnv }
    $iid = ''; $tid = ''
    if ($sender.Mode -eq 'anonymous') { $iid = Get-SITelemetryInstallId -StateDirectory $dir -GetEnv $GetEnv }
    else {
        $tid = if ($PSBoundParameters.ContainsKey('TenantId')) { $TenantId }
               elseif (Get-Command -Name Get-SIRunTenantId -ErrorAction SilentlyContinue) { try { [string](Get-SIRunTenantId) } catch { '' } } else { '' }
    }
    # CR2: Version = the RELEASE this install runs (BUILD.json 'release', 3.0.0.<build number>); not known (a dev run) = the build
    # label, as before. The label itself rides as Build (the wire field `build`).
    $build = Get-SITelemetryVersion
    $ver = if ($PSBoundParameters.ContainsKey('Version')) { $Version } else { Get-SITelemetryReleaseVersion }
    $ring = Get-SITelemetryRing -Edition $li.Edition -BoundParameters $PSBoundParameters -UpdaterRing $UpdaterRing -RingFacts $RingFacts -RingSetting $RingSetting -CommunityRing $CommunityRing
    $ctx = [pscustomobject]@{
        Mode = $sender.Mode; Endpoint = $sender.Endpoint; AccessCode = $sender.AccessCode
        Edition = $li.Edition; LicenceState = $li.LicenceState; Version = $ver; Build = $build; Hosting = $hosting; RuntimeIdentity = $rt
        InstallId = $iid; TenantId = $tid; StateDirectory = $dir; Ring = $ring.Ring; RingSource = $ring.Source
        # why the install reports anonymously ('' when identified) -- said in the run's log by a caller that needs identified
        # (the data health record); never sent
        AnonymousReason = $anonWhy
        # #517: the installed licence's id (identified only; '' when it has no GUID-shaped id)
        LicenceId = $(if ($sender.Mode -ne 'anonymous' -and $License -and (Get-Command -Name ConvertTo-SILicenceIdOrEmpty -ErrorAction SilentlyContinue)) { ConvertTo-SILicenceIdOrEmpty ([string]$License.LicenseId) } else { '' })
        # framework §8.4: the install's own links -- identified only (an anonymous install never names its addresses)
        Endpoints = $(if ($sender.Mode -eq 'anonymous') { , @() }
                      elseif ($PSBoundParameters.ContainsKey('Endpoints')) { , @(ConvertTo-SITelemetryEndpointList -Items $Endpoints) }
                      else { , @(Get-SITelemetryInstallEndpoints) })
        # MAIL-3 (#653): the web app header's name -- identified only (a name says whose install it is)
        EnvironmentName = $(if ($sender.Mode -eq 'anonymous') { '' }
                            elseif ($PSBoundParameters.ContainsKey('EnvironmentName')) { ConvertTo-SITelemetryEnvironmentName $EnvironmentName }
                            else { Get-SITelemetryEnvironmentName })
    }
    if (-not $injected) { $global:SI_TelemetryContext = $ctx }
    $ctx
}

function Get-SITelemetryRing {
    <#
        The ring this install reports (Resolve-SIReportedRing, the order the web app's header uses): the updater's ring in
        this process > the updater's recorded state > the ring recorded for the install > SI_UpdateRing > (Community) the
        ring in config\update.custom.json. Each input the caller did not pass is read from where the product keeps it.
        NEVER throws; returns @{ Ring; Source } (Ring $null = not known, left out of the report).
    #>
    param([string]$Edition, [System.Collections.IDictionary]$BoundParameters = @{}, [AllowNull()]$UpdaterRing, [AllowNull()]$RingFacts,
          [AllowNull()]$RingSetting, [AllowNull()]$CommunityRing)
    try {
        $bound = @($BoundParameters.Keys); $has = { param($n) $bound -contains $n }
        if (-not (& $has 'RingFacts')) { $RingFacts = $global:SI_InstallRingFacts }
        if (-not (& $has 'RingSetting')) { $RingSetting = $global:SI_UpdateRing }
        if (-not (& $has 'CommunityRing')) {
            $CommunityRing = $null
            if ($Edition -eq 'community') {
                $file = [System.IO.Path]::Combine($script:SITelemetrySend.SIRoot, 'config', 'update.custom.json')
                if (Test-Path -LiteralPath $file) { try { $CommunityRing = ([IO.File]::ReadAllText($file).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop).ring } catch { $CommunityRing = $null } }
            }
        }
        $us = ''; $ir = ''
        if ($RingFacts) {
            $p = { param($n) if ($RingFacts -is [System.Collections.IDictionary]) { if ($RingFacts.Contains($n)) { [string]$RingFacts[$n] } else { '' } } elseif ($RingFacts.PSObject.Properties[$n]) { [string]$RingFacts.$n } else { '' } }
            $us = & $p 'UpdateState'; $ir = & $p 'Ring'
        }
        Resolve-SIReportedRing -UpdaterRing $UpdaterRing -UpdateStateJson $us -InstallRingJson $ir -Setting $RingSetting -CommunityRing $CommunityRing
    } catch { [pscustomobject]@{ Ring = $null; Source = '' } }
}

# =====================================================================================================================
#  The one call: at the run-health END moment
# =====================================================================================================================
function Send-SITelemetryUplink {
    <#
        #517: the default transport. EXACTLY the framework client's post (Send-AitUplink: https only, a credential, the
        X-Ait-Uplink-Code header, one attempt, never throws) -- and it keeps Invardia's answer: a 202 {"supersededBy": "<id>"}
        (framework §12.6b) comes back as SupersededBy, and (#710, Invardia 1.0.488) a 202 {"environmentId": "<id>"} as
        EnvironmentId. Refusals without a network call are Send-AitUplink's own.
        Returns @{ Status; Reason; Sent; SupersededBy; EnvironmentId }.
    #>
    param([Parameter(Mandatory)][object]$Record, [AllowNull()][string]$Endpoint, [AllowNull()][string]$AccessCode, [int]$TimeoutSec = 5)
    # #918: a build that is not a RELEASE never sends to the PUBLIC community uplink (identified installs are unchanged)
    $gate = Test-SITelemetryCommunitySendAllowed -AccessCode $AccessCode
    if (-not $gate.Allowed) { return [pscustomobject]@{ Status = 'skipped'; Reason = $gate.Reason; Sent = $false; SupersededBy = ''; EnvironmentId = '' } }
    if ("$Endpoint" -notmatch '^https://' -or -not "$AccessCode".Trim()) { return (Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec) }
    try {
        $body = $Record | ConvertTo-Json -Depth 6 -Compress
        $answer = Invoke-RestMethod -Uri $Endpoint -Method Post -Headers @{ 'X-Ait-Uplink-Code' = $AccessCode; 'Content-Type' = 'application/json' } -Body $body -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        [pscustomobject]@{ Status = 'ok'; Reason = 'uplink accepted'; Sent = $true; SupersededBy = (Get-SILicenceSupersededFromAnswer $answer); EnvironmentId = (Get-SIInvardiaEnvironmentIdFromAnswer $answer) }
    } catch {
        [pscustomobject]@{ Status = 'failed'; Reason = "uplink POST failed: $($_.Exception.Message)"; Sent = $false; SupersededBy = ''; EnvironmentId = '' }
    }
}

function Invoke-SILicenceSupersededNotice {
    <#
        #517: Invardia says the installed licence was re-issued (-LicenceId = the newest one). Recorded for the updater's
        licence step, which knocks with currentLicenceId on its next run: -OnSuperseded (tests), else the Pro database this
        run opened ($global:SI_ProSettingsStore, set by the Pro settings layer) -- no second sign-in. One plain line in the
        run's log. NEVER throws; $true when recorded.
    #>
    param([Parameter(Mandatory)][string]$LicenceId, [scriptblock]$OnSuperseded, $NowUtc)
    $done = $false
    try {
        if ($OnSuperseded) { $null = & $OnSuperseded $LicenceId; $done = $true }
        elseif ($global:SI_ProSettingsStore -and (Get-Command -Name Save-SILicenceSupersededMark -ErrorAction SilentlyContinue)) {
            Save-SILicenceSupersededMark -Store $global:SI_ProSettingsStore -LicenceId $LicenceId -NowUtc $NowUtc; $done = $true
        }
    } catch { $done = $false }
    try {
        if ($done) { Write-Host (" [INFO] Invardia has issued a newer licence for this install ({0}); the updater fetches and installs it on its next run." -f $LicenceId) }
        else { Write-Host (" [INFO] Invardia has issued a newer licence for this install ({0}), but this run could not record it for the updater. The installed licence keeps working; the next run tries again." -f $LicenceId) }
    } catch { }
    $done
}

function Get-SITelemetryLogTail {
    <# The lines of this run's own transcript ($global:SI_TranscriptPath, or -Path), read while it is still open (shared
       read) -- the last -Tail lines. Never throws: @() when there is none. #>
    param([string]$Path = [string]$global:SI_TranscriptPath, [int]$Tail = 400)
    try {
        if (-not "$Path".Trim() -or -not [System.IO.File]::Exists($Path)) { return @() }
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try { $sr = New-Object System.IO.StreamReader($fs, $true); $text = $sr.ReadToEnd() } finally { $fs.Dispose() }
        $all = @($text -split "`r?`n")
        if ($all.Count -gt $Tail) { $all = @($all[($all.Count - $Tail)..($all.Count - 1)]) }
        return $all
    } catch { return @() }
}

function Resolve-SITelemetryFailureDetail {
    <#
        The words and the class a run report that did not end ok carries (owner 2026-10-10: most failed reports reached
        Invardia as 'unknown' with the pipeline's summary only, some with no text at all):
          1. the failing STEP's own words + class when the run context carries them (FailedStepError / FailedStepErrorClass
             -- the pipeline runner sets them from the failed step's run log), the summary kept after them;
          2. else the run's own message;
          3. no message -> the run's last log lines (-LogLines, else this run's transcript: Get-SITelemetryLogTail), the
             first error lines of it (Get-SIErrorLines).
        Returns @{ Text; ErrorClass ('' = classify the text); Source = step | message | log | '' }. Never throws.
    #>
    param([AllowNull()]$RunContext, [AllowEmptyString()][string]$ErrorMessage, [AllowEmptyString()][string]$ExitReason, [AllowNull()][string[]]$LogLines)
    $out = [pscustomobject]@{ Text = ''; ErrorClass = ''; Source = '' }
    try {
        $has = { param($n) $RunContext -and $RunContext.PSObject.Properties[$n] -and "$($RunContext.$n)".Trim() }
        $msg = "$ErrorMessage".Trim()
        if (& $has 'FailedStepError') {
            $out.Text = "$($RunContext.FailedStepError)".Trim()
            if ($msg -and $msg -ne $out.Text) { $out.Text = "{0}`n({1})" -f $out.Text, $msg }
            $out.Source = 'step'
            if (& $has 'FailedStepErrorClass') {
                $c = "$($RunContext.FailedStepErrorClass)".Trim().ToLowerInvariant()
                if ((Get-SIErrorClasses) -contains $c -and $c -ne 'unknown') { $out.ErrorClass = $c }
            }
            if (-not $out.ErrorClass) { $out.ErrorClass = Get-SIErrorClass -Message "$($RunContext.FailedStepError)" -ExitReason $ExitReason }
            if ($out.ErrorClass -eq 'unknown' -and $msg) { $c2 = Get-SIErrorClass -Message $msg -ExitReason $ExitReason; if ($c2 -ne 'unknown') { $out.ErrorClass = $c2 } }
            return $out
        }
        if ($msg) { $out.Text = $msg; $out.Source = 'message'; return $out }
        $lines = if ($null -ne $LogLines) { @($LogLines) } else { @(Get-SITelemetryLogTail) }
        $t = Get-SIErrorLines -Lines $lines
        if ($t) { $out.Text = $t; $out.Source = 'log' }
    } catch { }
    $out
}

function Send-SITelemetryRunEnd {
    <#
        Report one engine run (and, once per UTC day, the heartbeat before it). NEVER throws; returns
        @{ Status; Sent; Reason } -- Status: disabled | skipped | halted | ok | failed | error.
          -RunContext    the run-health context (Engine, StartedAt, ShardIndex, FailedStep when the engine recorded it)
          -ExitReason / -ErrorMessage / -AssetCount   what Send-SIRunHealthRow was given
          -Context       a Get-SITelemetryContext result (default: this install's, cached)
          -Transport     { param($Record, $Endpoint, $AccessCode, $TimeoutSec) } -> @{ Status } (default: the framework's
                         Send-AitUplink). The test seam.
          -Now           the clock (tests)
          -HeartbeatCounts { } -> @{ users; guests; devices } for an IDENTIFIED heartbeat (default:
                         Get-SITelemetryHeartbeatCounts, #424). Never called for an anonymous one. The test seam.
        A shard other than the first reports only a run that did not end ok, so a sharded run is one report, not N.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$RunContext, [AllowEmptyString()][string]$ExitReason, [AllowEmptyString()][string]$ErrorMessage,
          [long]$AssetCount = -1, $Context, [scriptblock]$Transport, $Now, [scriptblock]$HeartbeatCounts,
          # #427: a failure report from outside an engine run (the install, the updater) carries no heartbeat
          [switch]$NoHeartbeat,
          # #491: the setup report's closed list (default config\setup-catalog.locked.json) -- the test seam
          $SetupCatalog,
          # #517: { param($LicenceId) } when Invardia answers that the installed licence was re-issued (default: recorded for
          # the updater's licence step, Save-SILicenceSupersededMark on the Pro database the run has open) -- the test seam
          [scriptblock]$OnSuperseded,
          # #709: { } -> the capability probe (Get-SICapabilityProbe's shape) for the heartbeat (default: Get-SICapabilityProbe,
          # never in a test session) -- the test seam
          [scriptblock]$CapabilityProbe,
          # #710: { param($EnvironmentId) } when Invardia's answer names an environment id this install has not recorded yet
          # (default: Save-SIInvardiaEnvironmentMark on the Pro database the run has open) -- the test seam
          [scriptblock]$OnEnvironment)
    $supSeen = ''
    $envSeen = $false
    $out = { param($s, $sent, $why) [pscustomobject]@{ Status = $s; Sent = @($sent); Reason = $why; SupersededBy = $supSeen } }
    try {
        if (-not (Test-SITelemetryEnabled)) { return (& $out 'disabled' @() 'telemetry is switched off (SI_Telemetry_Enabled)') }
        if ($global:SI_TelemetryHalted) { return (& $out 'halted' @() 'an earlier report in this process was not accepted -- nothing more is sent from it') }
        # A TEST SESSION NEVER SENDS. ~60 suites run engine code that reaches the run-health END record; none of them
        # may report to Invardia or write an install id on the test machine. Pester is never loaded by an engine run.
        # Only a test that hands in its own -Transport (a stub) gets past this line.
        if (-not $Transport -and (Get-Module -Name Pester)) { return (& $out 'skipped' @() 'a test session (Pester is loaded) never sends; pass -Transport to test the sender') }
        if ($null -eq $RunContext) { return (& $out 'skipped' @() 'no run context') }
        $job = Resolve-SITelemetryJob -Engine ([string]$RunContext.Engine) -ReportTemplate ([string]$global:ReportTemplate)
        if (-not $job) { return (& $out 'skipped' @() ("no telemetry job id for engine '{0}'" -f $RunContext.Engine)) }
        $exit = ConvertTo-SITelemetryExitReason $ExitReason
        if (-not $exit) { return (& $out 'skipped' @() ("run-health ExitReason '{0}' is not reported" -f $ExitReason)) }
        $shard = 0; if ($RunContext.PSObject.Properties['ShardIndex']) { $shard = [int]$RunContext.ShardIndex }
        if ($shard -gt 0 -and $exit -eq 'success') { return (& $out 'skipped' @() 'a successful shard other than the first is not reported separately') }

        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        if (-not $Context) { $Context = Get-SITelemetryContext }
        if (-not $Transport) {
            # #918: a build that is not a RELEASE (no BUILD.json release, a dev or rc label) never sends to the PUBLIC community
            # uplink -- test runs, gate suites, the test VM and dev runs were counted as Community installs. Identified installs
            # (their own key) are unchanged. Said here, before anything is built, so it is never a "not sent" warning.
            $cg = Test-SITelemetryCommunitySendAllowed -AccessCode ([string]$Context.AccessCode)
            if (-not $cg.Allowed) { return (& $out 'skipped' @() $cg.Reason) }
            # #517: SI's sender (Send-SITelemetryUplink) -- the framework client's post, plus Invardia's answer (supersededBy)
            $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-SITelemetryUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec }
        }
        $anon = ($Context.Mode -eq 'anonymous')
        $lid = if (-not $anon -and $Context.PSObject.Properties['LicenceId']) { [string]$Context.LicenceId } else { '' }
        # framework §8.4: the install's own links (identified heartbeat) and the run-health deep link (identified failed run)
        $eps = @()
        if (-not $anon) { $eps = @(if ($Context.PSObject.Properties['Endpoints']) { @($Context.Endpoints) } else { @(Get-SITelemetryInstallEndpoints) }) }
        $runLink = if ($eps.Count) { Get-SITelemetryRunLink -Endpoints $eps } else { '' }
        # MAIL-3 (#653): the environment's name (identified only; a context built without it carries none)
        $envName = if (-not $anon -and $Context.PSObject.Properties['EnvironmentName']) { [string]$Context.EnvironmentName } else { '' }
        $base = @{ Edition = $Context.Edition; Version = $Context.Version; Hosting = $Context.Hosting; RuntimeIdentity = $Context.RuntimeIdentity
                   LicenceState = $Context.LicenceState; Now = $nowUtc
                   # framework §8.4 / §8.7: EVERY heartbeat and run report carries the install's ring (Invardia judges the update
                   # level against the version approved for it). Not known = left out, never guessed.
                   Ring = $(if ($Context.PSObject.Properties['Ring']) { $Context.Ring } else { $null }) }
        if ($anon) { $base.Anonymous = $true; $base.InstallId = $Context.InstallId } else { $base.TenantId = $Context.TenantId }

        $durMs = 0L
        if ($RunContext.PSObject.Properties['StartedAt'] -and $RunContext.StartedAt) {
            try { $durMs = [long][Math]::Max(0, ($nowUtc - ([datetime]$RunContext.StartedAt).ToUniversalTime()).TotalMilliseconds) } catch { $durMs = 0L }
        }
        $counts = Get-SITelemetryCounts -Job $job -Count $AssetCount
        $runArgs = @{} + $base
        $runArgs.Job = $job; $runArgs.ExitReason = $exit; $runArgs.DurationMs = $durMs; $runArgs.Counts = $counts
        $step = Get-SITelemetryFailedStep -RunContext $RunContext -ExitReason $exit -Job $job
        if ($exit -ne 'success') {
            # UPLINK-FIX (Invardia, 2026-10-07): a report that did not end ok ALWAYS carries FailedStep + ErrorClass (+ the
            # ErrorText when identified) -- Invardia's signature is built from the three, and an empty one cannot be acted on
            # (customer G 2026-10-07: two fix requests with none of them). No recorded step = 'run' (the run as a whole); no
            # message = a sentence that says so, never an empty text.
            if (-not $step) { $step = 'run' }
            # Telemetry quality (owner 2026-10-10, "use telemetry from si"): the report carries the FAILING STEP's own words
            # and class -- for the pipeline the step's (RunContext.FailedStepError / FailedStepErrorClass, set by the flow
            # runner from the step's own run log), never the pipeline's summary line. No text = the run's last log lines.
            $d = Resolve-SITelemetryFailureDetail -RunContext $RunContext -ErrorMessage $ErrorMessage -ExitReason $exit
            $msg = [string]$d.Text
            if (-not $msg) { $msg = ('{0} ended {1} without an error message (step {2})' -f $job, $exit, $step) }
            # The class is computed from the text here; in anonymous mode the TEXT itself never leaves this function.
            $runArgs.ErrorClass = if ($d.ErrorClass) { [string]$d.ErrorClass } else { Get-SIErrorClass -Message $msg -ExitReason $exit }
            # #532 (framework §12.18): a throttled run is ErrorClass 'throttled', Outcome 'warning' -- never a fix request
            if ($exit -eq 'throttled') { $runArgs.ErrorClass = 'throttled' }
            if (-not $anon) { $runArgs.ErrorMessage = $msg }
        }
        if ($step) { $runArgs.FailedStep = $step }
        # #641: a Risk Analysis run with a report that is NOT COMPLETE (Risk Analysis sets the numbers on its run context):
        # FailedStep ra-report, ErrorClass report-incomplete, the three report counts (numbers only -- the report NAMES stay
        # in the run's log and the database, never in the record) and, identified, the link to the web app's page of the run
        $incN = Get-SITelemetryIncompleteReports -RunContext $RunContext
        if ($null -ne $incN -and $exit -ne 'success') {
            $c2 = @{}; foreach ($k in @($counts.Keys)) { $c2[$k] = $counts[$k] }
            $c2['reportsExpected'] = $incN.Expected; $c2['reportsStored'] = $incN.Stored; $c2['reportsIncomplete'] = $incN.Incomplete
            $counts = $c2; $runArgs.Counts = $counts
            $runArgs.FailedStep = $script:SITelemetry.ReportIncompleteStep
            $runArgs.ErrorClass = $script:SITelemetry.ReportIncompleteClass
            if ($incN.Link) { $runLink = $incN.Link }
            # the text says how many, the names are on the page and in the run's log; #709 (identified only): the most severe
            # one's cause in plain words follows -- the report's id already travels in Reports[] (framework 8.16)
            if (-not $anon) {
                $runArgs.ErrorMessage = ('{0} of {1} Risk Analysis report(s) are not complete in this run -- the run''s page lists them' -f $incN.Incomplete, $incN.Expected)
                $head = ''
                try { if ($RunContext.PSObject.Properties['ReportCauses'] -and $RunContext.ReportCauses -and (Get-Command -Name Get-SIReportCauseHeadline -ErrorAction SilentlyContinue)) { $head = Get-SIReportCauseHeadline -Facts @($RunContext.ReportCauses) } } catch { $head = '' }
                if ($head) { $runArgs.ErrorMessage += ('. First cause: {0}' -f $head) }
            }
        }
        $runRec = New-SITelemetryRunRecord @runArgs
        # #709 / framework 8.16: every report that failed, did not apply or deviated, with its code and cause (Risk Analysis
        # puts the facts on its run context as ReportCauses). Built here, never fatal: nothing = no Reports.
        $causeItems = @()
        try {
            if ($RunContext.PSObject.Properties['ReportCauses'] -and $RunContext.ReportCauses) {
                # #902: a report held on purpose goes with the hold contract only once Invardia takes it for this ring (REMOVE-ME switch)
                $holdOn = $false
                try { $holdOn = [bool](Resolve-SIUplinkHoldFieldsSwitch -Ring $(if ($Context.PSObject.Properties['Ring']) { $Context.Ring } else { $null })).On } catch { $holdOn = $false }
                $causeItems = @(ConvertTo-SIUplinkReports -Facts @($RunContext.ReportCauses) -Identified:(-not $anon) -Version (Get-SITelemetryReleaseVersion) -Region (Get-SIUplinkRegion) -HoldFields:$holdOn)
                # #902: the reports held on purpose (information only) -- a number on the run record, the names stay in the log
                $nHeld = @(@($RunContext.ReportCauses) | Where-Object { (Test-SIUplinkFactHeld -Fact $_) -eq 'info' }).Count
                if ($nHeld -gt 0) { $c3 = @{}; foreach ($k in @($counts.Keys)) { $c3[$k] = $counts[$k] }; $c3['reportsHeld'] = [long]$nHeld; $counts = $c3 }
            }
        } catch { $causeItems = @() }
        # SUP-2026-00198: a failure outside a report whose catalogue code is known (Send-SITelemetryFailure -Code: the
        # updater's roll / restore) is its own item, so the record names the code
        try {
            if ($RunContext.PSObject.Properties['FailureCode'] -and "$($RunContext.FailureCode)".Trim()) {
                $causeItems = @($causeItems) + @(ConvertTo-SIUplinkFailureItem -Code ([string]$RunContext.FailureCode) -Job ([string]$RunContext.Engine) -Step ([string]$RunContext.FailedStep) `
                                                   -Text $ErrorMessage -Identified:(-not $anon) -Version (Get-SITelemetryReleaseVersion) -Region (Get-SIUplinkRegion))
            }
        } catch { }
        # a COMPLETE report with more rows than the source counted is a note, not a failure: never in Reports, kept on the
        # run's own record (RunContext.ReportNotes) and said once in the run log
        try {
            if ($RunContext.PSObject.Properties['ReportCauses'] -and $RunContext.ReportCauses) {
                $notes = @(Get-SIUplinkReportNotes -Facts @($RunContext.ReportCauses))
                if ($notes.Count) {
                    $RunContext | Add-Member -NotePropertyName 'ReportNotes' -NotePropertyValue $notes -Force
                    Write-Host ('  Note: {0} complete report(s) returned more rows than the source counted -- nothing is missing, no action ({1}).' -f $notes.Count, ((@($notes | Select-Object -First 5) | ForEach-Object { $_.Report }) -join ', '))
                }
            }
        } catch { }

        $queue = New-Object System.Collections.Generic.List[object]
        $relF = $null
        $hbDue =Test-SITelemetryHeartbeatDue -LastSentDate (Get-SITelemetryLastHeartbeat -StateDirectory $Context.StateDirectory) -NowUtc $nowUtc
        if ($hbDue -and -not $NoHeartbeat) {
            # #424: users / guests / devices, Pro (identified) only. A count that cannot be computed is left out.
            $hbCounts = $null
            if (-not $anon) {
                # a test session never queries a workspace for them: only a handed-in -HeartbeatCounts stub runs there
                try { $hbCounts = if ($HeartbeatCounts) { & $HeartbeatCounts } elseif (-not (Get-Module -Name Pester)) { Get-SITelemetryHeartbeatCounts -NowUtc $nowUtc } }
                catch { $hbCounts = $null }
            }
            # CR3 (#657): the wave and release mode (identified only, behind SI_Telemetry_ReleaseControl) -- never fails the heartbeat
            $relF = $null
            if (-not $anon) { try { $relF = Get-SITelemetryReleaseFields -Context $Context -NowUtc $nowUtc } catch { $relF = $null } }
            # CR4 (#654): the guard mode (identified only): the context's when it carries one (tests), else the rows release
            # control read, else the database it has open, else the guard code's own read (Get-SITelemetryGuardModeWire) --
            # never fails the heartbeat (nothing recorded / not readable = left out)
            $gmWire = $null
            if (-not $anon) { $gmWire = Get-SITelemetryGuardModeWire -Context $Context -Invoke $(if ($relF) { $relF.Invoke } else { $null }) -Rows $(if ($relF) { $relF.Rows } else { $null }) -NowUtc $nowUtc }
            # #709: the capability probe (Capabilities, CiColumns; Licences identified only) -- once per process, never in a
            # test session without -CapabilityProbe, never fails the heartbeat
            $probe = $null
            try { $probe = if ($CapabilityProbe) { & $CapabilityProbe } elseif (-not (Get-Module -Name Pester)) { Get-SICapabilityProbe } } catch { $probe = $null }
            $queue.Add((ConvertTo-SITelemetryWire -Record (New-SITelemetryHeartbeat @base) -Mode $Context.Mode -Counts $hbCounts -Now $nowUtc -Endpoints $eps -LicenceId $lid -EnvironmentName $envName -GuardMode $gmWire `
                            -Wave $(if ($relF) { $relF.Wave } else { $null }) -ReleaseMode $(if ($relF) { $relF.ReleaseMode } else { $null }) -Components $(if ($relF) { $relF.Components } else { $null }) -Evidence $(if ($relF) { $relF.Evidence } else { $null }) -Probe $probe -Build $(if ($Context.PSObject.Properties['Build']) { [string]$Context.Build } else { '' })))
        }
        $queue.Add((ConvertTo-SITelemetryWire -Record $runRec -Mode $Context.Mode -Counts $counts -Now $nowUtc -Link $runLink -LicenceId $lid -EnvironmentName $envName -Reports $causeItems -Build $(if ($Context.PSObject.Properties['Build']) { [string]$Context.Build } else { '' })))
        # #491 / framework §8.7: the setup report (the control list) once a day with the heartbeat -- identified installs only,
        # LAST in the queue so a refused setup report never costs the heartbeat or the run report. SI_Telemetry_SetupControls:
        # all (default, owner 2026-10-18: "telemetry must be on") = every control in the catalog, and when Invardia refuses
        # that report it goes again once with only the minimum list; minimum = only the framework's minimum controls; off = none. Anything that fails here leaves the setup report out, nothing else.
        $setupMinimum = $null
        if ($hbDue -and -not $NoHeartbeat -and -not $anon) {
            try {
                $scope = Resolve-SISetupControlScope -Value $global:SI_Telemetry_SetupControls
                if ($scope -ne 'off') {
                    $cat = if ($SetupCatalog) { $SetupCatalog } else { Get-SISetupCatalog }
                    $us = ''; if ($global:SI_InstallRingFacts -and $global:SI_InstallRingFacts.PSObject.Properties['UpdateState']) { $us = [string]$global:SI_InstallRingFacts.UpdateState }
                    $ps = ''; if ($global:SI_InstallRingFacts -and $global:SI_InstallRingFacts.PSObject.Properties['PipelineSchedule']) { $ps = [string]$global:SI_InstallRingFacts.PipelineSchedule }
                    $states = Get-SISetupControlStates -Context $Context -ExitReason $exit -UpdateStateJson $us -NowUtc $nowUtc -PipelineScheduleJson $ps -SecretHandoverJson $(if ($global:SI_InstallRingFacts -and $global:SI_InstallRingFacts.PSObject.Properties['SecretHandover']) { [string]$global:SI_InstallRingFacts.SecretHandover } else { '' })
                    $setup = New-SISetupReport -Context $Context -Catalog $cat -States $states -Scope $scope -Now $nowUtc
                    if ($setup) { $queue.Add($setup) }
                    # 'all' (the default) refused by Invardia goes again ONCE with only the minimum list (below)
                    if ($setup -and $scope -eq 'all') { $setupMinimum = New-SISetupReport -Context $Context -Catalog $cat -States $states -Scope 'minimum' -Now $nowUtc }
                }
            } catch { }
        }

        $sent = New-Object System.Collections.Generic.List[string]
        foreach ($w in $queue) {
            if ($null -eq $w) { throw 'the report could not be built (an anonymous report needs its install id)' }
            # CR3: a heartbeat refused WITH the release fields goes again once without them (Send-SITelemetryRecordWithFallback)
            $r = (Send-SITelemetryRecordWithFallback -Record $w -Transport $Transport -Context $Context -TimeoutSec $script:SITelemetrySend.TimeoutSec `
                    -Invoke $(if ($relF) { $relF.Invoke } else { $null }) -NowUtc $nowUtc).Result
            # the setup report with every control (SI_Telemetry_SetupControls = all, the default) that Invardia does not take
            # goes again ONCE with only the framework's minimum list -- said once per process; the minimum one decides
            if ("$($r.Status)" -ne 'ok' -and [string]$w.Kind -eq 'setup' -and $setupMinimum) {
                $firstWhy = ConvertTo-AitUplinkRedacted -Text ("$($r.Reason)")
                $r = & $Transport $setupMinimum $Context.Endpoint $Context.AccessCode $script:SITelemetrySend.TimeoutSec
                if ("$($r.Status)" -eq 'ok' -and -not $global:SI_SetupControlsFallbackSaid) {
                    $global:SI_SetupControlsFallbackSaid = $true
                    Write-Host ("  Invardia did not take the setup report with every SecurityInsight control ({0}) -- it was sent with the minimum control list instead." -f $firstWhy)
                }
                $setupMinimum = $null
            }
            if ("$($r.Status)" -ne 'ok') {
                # STOP at the first answer that is not ok -- for the rest of this process. No retry, nothing queued.
                $global:SI_TelemetryHalted = $true
                $why = ConvertTo-AitUplinkRedacted -Text ("$($r.Reason)")
                if (-not $global:SI_TelemetryWarned) {
                    $global:SI_TelemetryWarned = $true
                    Write-Warning ("The status report to Invardia was not sent ({0}). The run is not affected; nothing more is sent from this run. To turn these reports off, set `$global:SI_Telemetry_Enabled = `$false." -f $why)
                }
                return (& $out 'failed' $sent $why)
            }
            $sent.Add([string]$w.Kind)
            # #517: Invardia re-issued the installed licence -> recorded ONCE per process for the updater's licence step
            if (-not $supSeen -and $r.PSObject.Properties['SupersededBy']) {
                $sup = ConvertTo-SILicenceIdOrEmpty ([string]$r.SupersededBy)
                if ($sup -and $sup -ne $lid) { $supSeen = $sup; $null = Invoke-SILicenceSupersededNotice -LicenceId $sup -OnSuperseded $OnSuperseded -NowUtc $nowUtc }
            }
            # #710: Invardia names the install's environment (identified only) -> recorded once per process, and only when it
            # is not the id already recorded, for the customer mail's portal link (Send-SIMail)
            if (-not $anon -and -not $envSeen -and $r.PSObject.Properties['EnvironmentId']) {
                try {
                    $eid = ConvertTo-SIInvardiaEnvironmentIdOrEmpty ([string]$r.EnvironmentId)
                    if ($eid) {
                        $envSeen = $true
                        if ($eid -ne (Get-SIInvardiaEnvironmentIdKnown)) { $null = Invoke-SIInvardiaEnvironmentNotice -EnvironmentId $eid -OnEnvironment $OnEnvironment -NowUtc $nowUtc }
                    }
                } catch { }
            }
            if ($w.Kind -eq 'heartbeat') {
                Set-SITelemetryLastHeartbeat -StateDirectory $Context.StateDirectory -NowUtc $nowUtc
                try {
                    $how = if ($anon) { 'anonymous: no tenant, host name or error text' } else { 'identified by this install''s key' }
                    Write-Host (" [INFO] Sent today's status report to Invardia ({0}). To turn these reports off, set `$global:SI_Telemetry_Enabled = `$false." -f $how)
                } catch { }
            }
        }
        return (& $out 'ok' $sent ("sent {0} report(s) ({1})" -f $sent.Count, $Context.Mode))
    } catch {
        # #702 (customer B 2026-10-15): a run that ran out of memory could not even build its report, so Invardia never
        # heard of the failure. Out of memory while preparing: let go of what can be let go and try ONCE more with the run
        # report alone (no heartbeat counts, no setup report -- the smallest report there is). Once per process.
        $prepErr = $_
        $isOom = $false; try { $isOom = [bool]((Get-Command -Name Test-SIOutOfMemoryText -ErrorAction SilentlyContinue) -and (Test-SIOutOfMemoryText $prepErr)) } catch { $isOom = $true }
        if ($isOom -and -not $script:SITelemetryOomRetried) {
            $script:SITelemetryOomRetried = $true
            try { [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect() } catch { }
            $again = @{}; foreach ($k in @($PSBoundParameters.Keys)) { $again[$k] = $PSBoundParameters[$k] }
            $again['NoHeartbeat'] = $true
            try { return (Send-SITelemetryRunEnd @again) } catch { $prepErr = $_ }
        }
        $global:SI_TelemetryHalted = $true
        if (-not $global:SI_TelemetryWarned) {
            $global:SI_TelemetryWarned = $true
            # si-upl-0601: the run record could not be built (data-model/errors.locked.json)
            try { Write-Warning ("The status report to Invardia could not be prepared (si-upl-0601: {0}). The run is not affected." -f (ConvertTo-AitUplinkRedacted -Text $prepErr.Exception.Message)) } catch { }
        }
        return (& $out 'error' @() ("si-upl-0601: $($prepErr.Exception.Message)"))
    }
}

# =====================================================================================================================
#  #427: failures OUTSIDE an engine run -- the guided install's failed steps and the updater's failures
# =====================================================================================================================
function Send-SITelemetryFailure {
    <#
        Report ONE failure that happened outside an engine run (framework UPLINK-FIX, owner 2026-10-07: every failure a
        product can observe reaches the uplink): -Job install (a guided install step, Job si-install), updater (Job
        si-updater) or datasync (#904: a PART of the data sync that failed while the job completed, Job si-datasync), -Step the step id (FailedStep: the install step id, or download / verify / database / build / roll /
        restore / claim / licence / ...), -ErrorMessage the error. It is a `run` report with Outcome failed, ErrorClass from
        the text, the version, no heartbeat. The SAME rules as an engine run: the telemetry switch is honoured, identified
        with the install key where one is known (the text redacted), anonymous otherwise (no tenant, no host, no text). A
        test session never sends without -Transport. NEVER throws; returns the Send-SITelemetryRunEnd result.
          -Context   a Get-SITelemetryContext result (default: this process's)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('install', 'updater', 'datasync')][string]$Job, [Parameter(Mandatory)][AllowEmptyString()][string]$Step,
          [AllowEmptyString()][string]$ErrorMessage, $StartedAt, $Context, [scriptblock]$Transport, $Now,
          # the class when the caller KNOWS it (a value of the closed list; anything else is classified from the text)
          [AllowEmptyString()][string]$ErrorClass,
          # ring 1 2026-10-10: something the CUSTOMER must do (a role grant to re-run) -- Outcome warning, never 'failed':
          # the update did not fail. With a customer-config class Invardia shows "needs customer action", no fix request.
          [switch]$CustomerAction,
          # #904: a PART of a job that failed while the job completed (-Job datasync: a part of the data sync) -- Outcome
          # warning, the class and FailedStep of that part; with a product-defect class Invardia opens a fix request
          [switch]$Partial,
          # SUP-2026-00198: the failure's error-catalogue code when the caller KNOWS it (si-upd-0803 a refused roll,
          # si-upd-0804 a failed restore, si-upd-0805 a roll that did not verify) -- sent as the record's Reports[] item
          # (ConvertTo-SIUplinkFailureItem), so Invardia files it under that code and never as 'unknown'
          [AllowEmptyString()][string]$Code)
    try {
        $st = ("$Step".Trim().ToLowerInvariant() -replace '[^a-z0-9\-]', '-') -replace '^[^a-z]+', ''
        if (-not $st) { $st = 'unknown' }
        $rc = [pscustomobject]@{ Engine = $Job; ShardIndex = 0; StartedAt = $StartedAt; FailedStep = $st }
        if ("$Code".Trim()) {
            $rc | Add-Member -NotePropertyName FailureCode -NotePropertyValue "$Code".Trim().ToLowerInvariant()
            # a registry / platform that did not answer Azure is the platform's, not 'unknown' (the 400 of 2026-10-19)
            if (-not "$ErrorClass".Trim() -and "$ErrorMessage" -match '(?i)connection refused|connection reset|i/o timeout|TLS handshake timeout|no such host|context deadline exceeded|Service Unavailable|Bad Gateway') { $ErrorClass = 'platform-5xx' }
        }
        if ("$ErrorClass".Trim()) { $rc | Add-Member -NotePropertyName FailedStepError -NotePropertyValue "$ErrorMessage"; $rc | Add-Member -NotePropertyName FailedStepErrorClass -NotePropertyValue "$ErrorClass".Trim() }
        $a = @{ RunContext = $rc; ExitReason = $(if ($CustomerAction -or $Partial) { 'success-partial' } else { 'error' }); ErrorMessage = "$ErrorMessage"; NoHeartbeat = $true }
        if ($Context) { $a.Context = $Context }
        if ($Transport) { $a.Transport = $Transport }
        if ($Now) { $a.Now = $Now }
        Send-SITelemetryRunEnd @a
    } catch { [pscustomobject]@{ Status = 'error'; Sent = @(); Reason = "$($_.Exception.Message)" } }
}


# =====================================================================================================================
#  CR3 (#657): RELEASE MODE -- the identified heartbeat every 30 minutes for 12 hours after a release that changed engine code
# =====================================================================================================================
function Send-SIReleaseModeReport {
    <#
        One release-mode report, when one is due: an IDENTIFIED heartbeat (users, guests, devices, the guard mode, the wave)
        with releaseMode { version, sinceUtc, untilUtc, everyMinutes } -- counts only, never a name. Due = this install is in
        release mode (the engine fingerprint changed less than 12 hours ago, Get-SIReleaseModeFromFingerprint) AND no report
        of this half hour was sent: the half hour is CLAIMED in the Pro database first (cfg.InstallState 'ReleaseModeReport',
        one statement), so two processes never both send it. The same rules as every report: the telemetry switch, a test
        session never sends without -Transport, the first answer that is not ok stops telemetry for the process. Behind
        SI_Telemetry_ReleaseControl (auto = the confirmed rings only). NEVER throws; returns @{ Status; Reason }:
        sent | disabled | halted | skipped | not-due | failed | error.
          -Invoke          the Pro database seam (required: no database = nothing to read, nothing sent)
          -Context         a Get-SITelemetryContext result (default: this install's)
          -Transport       the test seam (default Send-SITelemetryUplink)
          -HeartbeatCounts { } -> @{ users; guests; devices } (default Get-SITelemetryHeartbeatCounts; never in a test session)
          -Rows            the cfg.InstallState rows (tests; default read through -Invoke)
    #>
    [CmdletBinding()]
    param([scriptblock]$Invoke, $Context, [scriptblock]$Transport, $Now, [scriptblock]$HeartbeatCounts, $Rows)
    $out = { param($s, $why) [pscustomobject]@{ Status = $s; Reason = $why } }
    try {
        if (-not (Test-SITelemetryEnabled)) { return (& $out 'disabled' 'telemetry is switched off (SI_Telemetry_Enabled)') }
        if ($global:SI_TelemetryHalted) { return (& $out 'halted' 'an earlier report in this process was not accepted') }
        if (-not $Transport -and (Get-Module -Name Pester)) { return (& $out 'skipped' 'a test session (Pester is loaded) never sends; pass -Transport to test the sender') }
        if (-not $Invoke -and -not $Rows) { return (& $out 'skipped' 'no Pro database') }
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        if (-not $Context) { $Context = Get-SITelemetryContext }
        if ($Context.Mode -eq 'anonymous') { return (& $out 'skipped' 'an anonymous install sends no release-mode reports') }
        $rel = Get-SITelemetryReleaseFields -Context $Context -NowUtc $nowUtc -Invoke $Invoke -Rows $Rows
        if (-not $rel.Rows) { return (& $out 'skipped' $rel.Reason) }
        if (-not $rel.ReleaseMode -or $null -eq $rel.ReleaseMode.Value) {
            return (& $out 'not-due' $(if ($rel.ReleaseMode) { 'not in release mode' } elseif ($rel.Reason) { $rel.Reason } else { 'no engine fingerprint is recorded' }))
        }
        $mode = Get-SIReleaseModeFromFingerprint -Fingerprint ([string]$rel.Rows.EngineFingerprint) -NowUtc $nowUtc
        $slot = Get-SIReleaseModeSlot -Mode $mode -NowUtc $nowUtc
        if ($slot -lt 0) { return (& $out 'not-due' 'not in release mode') }
        $claimInvoke = if ($Invoke) { $Invoke } else { $rel.Invoke }
        if (-not $claimInvoke) { return (& $out 'skipped' 'no Pro database to claim the half hour in') }
        if (-not (Invoke-SIReleaseModeClaim -Invoke $claimInvoke -Mode $mode -Slot $slot -NowUtc $nowUtc)) { return (& $out 'not-due' ("the report of this half hour (slot {0}) was sent already" -f $slot)) }
        if (-not $Transport) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-SITelemetryUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }

        $base = @{ Edition = $Context.Edition; Version = $Context.Version; Hosting = $Context.Hosting; RuntimeIdentity = $Context.RuntimeIdentity
                   LicenceState = $Context.LicenceState; Now = $nowUtc; Ring = $(if ($Context.PSObject.Properties['Ring']) { $Context.Ring } else { $null }); TenantId = $Context.TenantId }
        $hbCounts = $null
        try { $hbCounts = if ($HeartbeatCounts) { & $HeartbeatCounts } elseif (-not (Get-Module -Name Pester)) { Get-SITelemetryHeartbeatCounts -NowUtc $nowUtc } } catch { $hbCounts = $null }
        $gmWire = $null
        try { if (Get-Command -Name ConvertTo-SIGuardModeWire -ErrorAction SilentlyContinue) { $gmWire = ConvertTo-SIGuardModeWire -Mode (Get-SIGuardModeFromState -Fingerprint ([string]$rel.Rows.EngineFingerprint) -StrictEnd ([string]$rel.Rows.GuardStrictEnd) -NowUtc $nowUtc) } } catch { $gmWire = $null }
        $eps = @(if ($Context.PSObject.Properties['Endpoints']) { @($Context.Endpoints) })
        $lid = if ($Context.PSObject.Properties['LicenceId']) { [string]$Context.LicenceId } else { '' }
        $envName = if ($Context.PSObject.Properties['EnvironmentName']) { [string]$Context.EnvironmentName } else { '' }
        $w = ConvertTo-SITelemetryWire -Record (New-SITelemetryHeartbeat @base) -Mode $Context.Mode -Counts $hbCounts -Now $nowUtc -Endpoints $eps -LicenceId $lid -EnvironmentName $envName `
                -GuardMode $gmWire -Wave $rel.Wave -ReleaseMode $rel.ReleaseMode -Components $rel.Components -Evidence $rel.Evidence -Build $(if ($Context.PSObject.Properties['Build']) { [string]$Context.Build } else { '' })
        if ($null -eq $w) { return (& $out 'error' 'the report could not be built') }
        $s = Send-SITelemetryRecordWithFallback -Record $w -Transport $Transport -Context $Context -TimeoutSec $script:SITelemetrySend.TimeoutSec -Invoke $claimInvoke -NowUtc $nowUtc
        if ("$($s.Result.Status)" -ne 'ok') {
            $global:SI_TelemetryHalted = $true
            $why = ConvertTo-AitUplinkRedacted -Text ("$($s.Result.Reason)")
            if (-not $global:SI_TelemetryWarned) {
                $global:SI_TelemetryWarned = $true
                Write-Warning ("The release-mode status report to Invardia was not sent ({0}). The run is not affected; nothing more is sent from this run." -f $why)
            }
            return (& $out 'failed' $why)
        }
        try { Write-Host (" [INFO] Sent a release-mode status report to Invardia (release {0}: every {1} minutes until {2}; counts only)." -f $(if ($mode.Version) { $mode.Version } else { 'with engine changes' }), $script:SIReleaseControl.EveryMinutes, (Format-SIGuardStrictUntil $mode.Until)) } catch { }
        & $out 'sent' ("slot {0} of release {1}" -f $slot, $mode.Version)
    } catch {
        & $out 'error' ("$($_.Exception.Message)")
    }
}

function Invoke-SIReleaseModeReportTick {
    <#
        The pipeline runner's call (engine\flow\Invoke-SIJobFlowRun.ps1): at every wake-up (every 5 minutes) and from its
        lock heartbeat during a long run. Asks Send-SIReleaseModeReport at most once every 4 minutes per process. NEVER
        throws; returns its result, or $null when it did not ask.
    #>
    param([scriptblock]$Invoke, [scriptblock]$Transport, $Now, [switch]$Force)
    try {
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        $last = $global:SI_ReleaseModeTickAt
        if (-not $Force -and $last -and ($nowUtc - [datetime]$last).TotalMinutes -lt $script:SIReleaseControl.CheckMinutes -and $nowUtc -ge [datetime]$last) { return $null }
        $global:SI_ReleaseModeTickAt = $nowUtc
        # #882 -- A RUN OF MANY HOURS: the pipeline runner is ONE process that may live a whole day (it drains the queue and
        # follows each long run). A report that was not accepted halts telemetry for the process (built for a short engine
        # run), so one refused or lost half hour silenced every later release-mode report until the runner ended. In the
        # runner the halt lasts until the NEXT half hour: then the report of that half hour is asked again (the warning is
        # not said again). Still at most one report per half hour (the slot is claimed in the database first).
        $every = [Math]::Max(1, [int]$script:SIReleaseControl.EveryMinutes)
        $slotNow = [long][Math]::Floor(($nowUtc - [datetime]::new(2000, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalMinutes / $every)
        if ($global:SI_TelemetryHalted) {
            if ($null -eq $global:SI_ReleaseModeHaltSlot) { $global:SI_ReleaseModeHaltSlot = $slotNow }
            elseif ($slotNow -gt [long]$global:SI_ReleaseModeHaltSlot) { $global:SI_TelemetryHalted = $false; $global:SI_ReleaseModeHaltSlot = $null }
        } else { $global:SI_ReleaseModeHaltSlot = $null }
        $a = @{ Invoke = $Invoke; Now = $nowUtc }
        if ($Transport) { $a.Transport = $Transport }
        $res = Send-SIReleaseModeReport @a
        if ($global:SI_TelemetryHalted -and $null -eq $global:SI_ReleaseModeHaltSlot) { $global:SI_ReleaseModeHaltSlot = $slotNow }
        $res
    } catch { $null }
}