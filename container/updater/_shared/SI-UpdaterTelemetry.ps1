#Requires -Version 5.1
<#
    SecurityInsight updater -- #427: EVERY FAILURE OF AN UPDATE RUN REACHES INVARDIA'S UPLINK (framework UPLINK-FIX, owner
    2026-10-07: "every failure a product can observe reaches the uplink: scheduled runs AND guided-install step failures
    AND updater failures (download/verify, database, build, roll, restore, claim/licence refusals)"). Live 2026-10-06/07:
    the 16 PATCH 400 "imageType" roll and the byte[] SID database step were seen only in the job's console.

    During the run each failure is RECORDED with the step it happened in (Add-SIUpdaterFailure); at the end of the run
    (Send-SIUpdaterFailureReports, from Start-SIUpdater.ps1) each recorded failure is one `run` report (Job si-updater,
    Outcome failed, FailedStep = the step, ErrorClass + the error text) through the release's SI-TelemetrySend.ps1
    (Send-SITelemetryFailure). The same rules as every SI report: the telemetry switch is honoured (the Pro Settings page's
    SI_Telemetry_Enabled first, then the job's SI_TELEMETRY_ENABLED); identified with the install key when the Key Vault has
    one, anonymous otherwise (no tenant, no host, no text); no heartbeat. NOTHING HERE EVER FAILS OR SLOWS THE UPDATE.

    Steps (FailedStep): signin, settings, claim, licence, manifest, download, verify, database, templates, build, roll,
    restore, post-roll, template-pack, updater (anything else).

    PS 5.1 and 7.
#>

$script:SIUpdaterTelemetry = @{ Max = 5 }
if ($null -eq $global:SI_UpdaterFailures) { $global:SI_UpdaterFailures = New-Object System.Collections.Generic.List[object] }

function Add-SIUpdaterFailure {
    <# Records one failure of this run (-Step, -Text; -Code its error-catalogue code when the caller knows it, e.g.
       si-upd-0803 -- SUP-2026-00198). The same step and text twice is one failure. Never throws. #>
    param([Parameter(Mandatory)][string]$Step, [AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Code = '')
    try {
        if ($null -eq $global:SI_UpdaterFailures) { $global:SI_UpdaterFailures = New-Object System.Collections.Generic.List[object] }
        $t = "$Text".Trim()
        foreach ($f in $global:SI_UpdaterFailures) { if ($f.Step -eq $Step -and $f.Text -eq $t) { return } }
        $c = "$Code".Trim().ToLowerInvariant(); if ($c -notmatch '^si-[a-z]{2,8}-\d{4}$') { $c = '' }
        $global:SI_UpdaterFailures.Add([pscustomobject]@{ Step = $Step; Text = $t; Code = $c })
    } catch { }
}

function Add-SIUpdaterCustomerAction {
    <#
        Records one thing the CUSTOMER must do (ring 1 2026-10-10, Invardia fix request: the updater may not use its secret
        hand-over key until the updater setup is re-run with its role grants). Reported like a failure, but as what it is:
        Outcome warning (the update did NOT fail), its own error class from the closed list -- one whose FixKind is
        customer-config, so Invardia shows "needs customer action" and opens no fix request -- and the exact command in the
        text. -Class: kv-403 / arm-403 / storage-403 / config-missing / licence-invalid (default kv-403). Never throws.
    #>
    param([Parameter(Mandatory)][string]$Step, [AllowEmptyString()][string]$Text, [string]$Class = 'kv-403')
    try {
        if ($null -eq $global:SI_UpdaterFailures) { $global:SI_UpdaterFailures = New-Object System.Collections.Generic.List[object] }
        $t = "$Text".Trim()
        foreach ($f in $global:SI_UpdaterFailures) { if ($f.Step -eq $Step -and $f.Text -eq $t) { return } }
        $global:SI_UpdaterFailures.Add([pscustomobject]@{ Step = $Step; Text = $t; Kind = 'customer-action'; Class = $Class })
    } catch { }
}

function Get-SIUpdaterFailures {
    if ($null -eq $global:SI_UpdaterFailures) { return @() }
    @($global:SI_UpdaterFailures.ToArray())
}

function ConvertTo-SIUpdaterRollStep {
    <#
        PURE. The step a failed engine roll stopped in, from the stage the release's setup/Invoke-SIContainerUpdate.ps1 last
        announced ($global:SI_UpdateStage: '2. BUILD', '3. ROLL ...', '4. VERIFY', '5. ROLLBACK'): build | roll | restore.
        Nothing announced (an older release) = roll.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Stage)
    $s = "$Stage"
    if ($s -match '(?i)ROLLBACK|RESTORE') { return 'restore' }
    if ($s -match '(?i)BUILD') { return 'build' }
    'roll'
}

function Get-SIUpdaterClaimFailure {
    <# PURE. The install key claim's result as a failure text, or '' when it is not one (bundle / present / claimed /
       held / off / waiting / network are not refusals; forbidden / conflict / invalid / error are). #>
    param($Claim)
    if (-not $Claim) { return '' }
    $a = "$($Claim.Action)"
    if ($a -in @('forbidden', 'conflict', 'invalid', 'error')) { return ("install key claim {0}: {1}" -f $a, "$($Claim.Reason)") }
    ''
}

function Get-SIUpdaterLicenceFailure {
    <# PURE. The licence request's result as a failure text, or '' (refused / rejected / invalid / error are failures). #>
    param($Result)
    if (-not $Result) { return '' }
    $a = "$($Result.Action)"
    if ($a -in @('refused', 'rejected', 'invalid', 'error')) { return ("licence request {0}: {1}" -f $a, "$($Result.Message)") }
    ''
}

function Test-SIUpdaterTelemetryOn {
    <#
        PURE. The telemetry switch for the updater's reports: the Pro Settings page's SI_Telemetry_Enabled (-Settings, a
        Read-SIProSolutionSettings result) wins when it is set, then the job's SI_TELEMETRY_ENABLED (-EnvValue), else ON.
    #>
    param($Settings, [AllowEmptyString()][AllowNull()][string]$EnvValue)
    $v = $null
    if ($Settings -and $Settings.PSObject.Properties['Values'] -and $Settings.Values -and $Settings.Values.ContainsKey('SI_Telemetry_Enabled')) { $v = $Settings.Values['SI_Telemetry_Enabled'] }
    foreach ($x in @($v, $EnvValue)) {
        if ($null -eq $x) { continue }
        if ($x -is [bool]) { return $x }
        $s = ([string]$x).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        return -not ($s -in @('false', '0', 'off', 'no', 'disabled'))
    }
    $true
}

function Get-SIUpdaterReportedVersion {
    <# The version this updater run reports to Invardia: the ENGINE release the install runs at the end of the run
       ($global:SI_UpdaterEngineVersion -- set when the run read what runs, and moved to the new release the moment a roll
       succeeded), '' when not known (the reports then carry the updater image's own release, as before). #>
    $v = "$global:SI_UpdaterEngineVersion".Trim()
    if ($v -match '^[0-9][0-9A-Za-z.+-]{0,49}$') { return $v }
    ''
}

function Send-SIUpdaterFailureReports {
    <#
        Sends each recorded failure of this run (at most 5) as one `run` report. -ExitCode not 0 with nothing recorded is
        reported as step 'updater'. Returns the results. NEVER throws.
          -On           the telemetry switch (Test-SIUpdaterTelemetryOn)
          -InstallKey / -TenantId   identified mode (the key from the Key Vault); '' = anonymous
          -Send          { param($Step, $Text) } -- the test seam (no context, no network)
    #>
    param([int]$ExitCode = 0, [bool]$On = $true, [AllowEmptyString()][string]$InstallKey = '', [AllowEmptyString()][string]$TenantId = '',
          $StartedAt, [scriptblock]$Send, [scriptblock]$Log)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        if (-not $Log) { $Log = { param($m) } }
        $fails = @(Get-SIUpdaterFailures)
        if (-not $fails.Count -and $ExitCode -ne 0) {
            $step = if ("$global:SI_UpdaterStep".Trim()) { "$global:SI_UpdaterStep".Trim() } else { 'updater' }
            $fails = @([pscustomobject]@{ Step = $step; Text = ("the update run ended with exit code {0}" -f $ExitCode) })
        }
        if (-not $fails.Count) { return @() }
        if (-not $On) { & $Log ("{0} failure(s) of this run are not reported to Invardia: telemetry is switched off (SI_Telemetry_Enabled)" -f $fails.Count); return @() }
        $fails = @($fails | Select-Object -First $script:SIUpdaterTelemetry.Max)
        $ctx = $null
        if (-not $Send) {
            if (Get-Module -Name Pester) { return @() }   # a test session never sends without its seam
            # loaded by Start-SIUpdater.ps1 from the code the image carries (/si/engine/_shared/SI-TelemetrySend.ps1)
            if (-not (Get-Command -Name Send-SITelemetryFailure -ErrorAction SilentlyContinue)) { & $Log 'failures are not reported to Invardia: this image carries no telemetry client'; return @() }
            $global:SI_Telemetry_Enabled = $true   # the switch was decided above (Settings page, then the job)
            $edition = if ("$InstallKey".Trim()) { 'pro' } else { '' }
            # the ring: what this updater run resolved (its own state), else the setting -- framework §8.4 / §8.7
            $ctxArgs = @{ License = $null; InstallKey = "$InstallKey"; TenantId = "$TenantId"; Edition = $edition; UpdaterRing = $global:SI_UpdaterResolvedRing }
            # Version = the ENGINE release this install runs (the one this run just applied, or found running) -- never the
            # updater's own image release, which moves only on its next run; its own build label rides as `build`
            $engineVer = Get-SIUpdaterReportedVersion
            if ($engineVer) { $ctxArgs.Version = $engineVer }
            $ctx = Get-SITelemetryContext @ctxArgs
        }
        foreach ($f in $fails) {
            $r = $null
            try {
                # a customer action: Outcome warning (the update did not fail), its own class (FixKind customer-config)
                $ca = ($f.PSObject.Properties['Kind'] -and "$($f.Kind)" -eq 'customer-action')
                # SUP-2026-00198: a failure with its catalogue code is sent with it (Reports[] Code) -- only when the
                # release's telemetry client takes -Code (an older one would refuse the call and lose the report)
                $fc = if ($f.PSObject.Properties['Code']) { "$($f.Code)".Trim() } else { '' }
                $codeArgs = @{}
                if ($fc -and -not $Send) { $sc = Get-Command -Name Send-SITelemetryFailure -ErrorAction SilentlyContinue; if ($sc -and $sc.Parameters.ContainsKey('Code')) { $codeArgs.Code = $fc } }
                $r = if ($Send) { & $Send $f.Step $f.Text $f }
                     elseif ($ca) { Send-SITelemetryFailure -Job updater -Step $f.Step -ErrorMessage $f.Text -Context $ctx -StartedAt $StartedAt -ErrorClass ([string]$f.Class) -CustomerAction }
                     else { Send-SITelemetryFailure -Job updater -Step $f.Step -ErrorMessage $f.Text -Context $ctx -StartedAt $StartedAt @codeArgs }
            } catch { $r = [pscustomobject]@{ Status = 'error'; Reason = $_.Exception.Message } }
            $out.Add([pscustomobject]@{ Step = $f.Step; Status = $(if ($r) { "$($r.Status)" } else { '' }) })
        }
        & $Log ("failures reported to Invardia: {0}" -f ((@($out | ForEach-Object { '{0} ({1})' -f $_.Step, $_.Status })) -join ', '))
    } catch { }
    $out.ToArray()
}
