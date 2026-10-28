#Requires -Version 5.1
<#
    SecurityInsight -- the SETUP status report (uplink Kind = setup, framework §8.7 UPLINK-SETUP, #491): the control list of
    critical parameters, so Invardia's customer health dashboard can show what is set and what is not.

    THE CLOSED LIST is config\setup-catalog.locked.json ({ product, steps[], findings[], controls[] }; every item { id, title,
    why, fix, docUrl? } + required (steps), productDefect (findings), enum + critical (controls), retired). Ids are stable
    and lower-case and never removed. The release hands it over to Invardia as
    <handover>\docs\securityinsight\<version>\setup-catalog.json (setup\Release-SI.ps1) with the released version added.

    WHICH CONTROLS ARE SENT -- the setting SI_Telemetry_SetupControls:
      all (default)      every control in the catalog (the framework minimum + SecurityInsight's extras). Invardia refuses the
                         WHOLE report when it carries an id it does not know, so a refused 'all' report is sent again ONCE
                         with only the minimum list, and said once (SI-TelemetrySend.ps1).
      minimum            only the framework's minimum control set (Get-SISetupMinimumControlIds).
      off                no setup report (the heartbeat and run reports are not affected).
    The telemetry switch SI_Telemetry_Enabled = $false turns this off too.

    WHAT IS SENT: identified installs only (an install key); an anonymous install never sends a setup report. Every control
    in scope is in every report -- a control that could not be checked is 'unknown', never left out. `value` only for a
    control declared with an enum, and only one of its values (the ring 1|2|3, the updater schedule, ...). Never a secret,
    a user or group name, or error text.

    PURE builders + one state reader; SI-TelemetrySend.ps1 queues the report with the daily heartbeat. PS 5.1 and 7.
#>

if (-not (Get-Command -Name ConvertTo-SIReportedRing -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ReportedRing.ps1')) }

$script:SISetupUplink = @{
    SIRoot      = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    CatalogFile = 'setup-catalog.locked.json'
    Product     = 'securityinsight'
    # The framework's minimum control set as Invardia's closed list holds it today (data/setup/securityinsight.json, seed).
    # Every catalog control is sent by default (SI_Telemetry_SetupControls = all); this minimum list is the fallback when Invardia refuses that report.
    Minimum     = @('updater-deployed', 'updater-schedule', 'update-ring', 'uplink-key', 'licence-valid', 'mail-sender',
                    'alert-recipients', 'identity-permissions', 'last-run-24h', 'backup-configured', 'update-pinned')
    States      = @('ok', 'missing', 'wrong', 'unknown')
    Scopes      = @('minimum', 'all', 'off')
    IdPattern   = '^[a-z0-9][a-z0-9.-]{0,59}$'
}

function Get-SISetupMinimumControlIds { @($script:SISetupUplink.Minimum) }

function Get-SISetupCatalog {
    <# The closed list (config\setup-catalog.locked.json) as an object. Throws when it cannot be read -- a release must not hand over a broken list. #>
    param([string]$SIRoot = $script:SISetupUplink.SIRoot)
    $f = [System.IO.Path]::Combine($SIRoot, 'config', $script:SISetupUplink.CatalogFile)
    [IO.File]::ReadAllText($f).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
}

function ConvertTo-SISetupCatalogHandover {
    <#
        PURE. The hand-over file for Invardia: { product, version, steps, findings, controls } -- exactly the fields Invardia's
        import accepts (no note, no other field), the version the release published. Returns the JSON text.
    #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][string]$Version)
    $o = [ordered]@{ product = [string]$Catalog.product; version = $Version.Trim()
                     steps = @($Catalog.steps); findings = @($Catalog.findings); controls = @($Catalog.controls) }
    ConvertTo-Json -InputObject $o -Depth 6
}

function Resolve-SISetupControlScope {
    <# PURE. SI_Telemetry_SetupControls -> minimum | all | off. Not set or not one of them = all (the default, owner
       2026-10-18: "telemetry must be on"); a report Invardia refuses with 'all' goes again once with the minimum list
       (Send-SITelemetryRunEnd). #>
    param([AllowNull()]$Value)
    $v = "$Value".Trim().Trim('$').ToLowerInvariant()
    if ($v -in @('false', 'none', 'disabled')) { $v = 'off' }
    if ($script:SISetupUplink.Scopes -contains $v) { return $v }
    'all'
}

function Get-SISetupControlIds {
    <# PURE. The control ids a report carries for -Scope: minimum = the framework minimum; all = every catalog control not retired. #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][ValidateSet('minimum', 'all', 'off')][string]$Scope)
    if ($Scope -eq 'off') { return @() }
    $live = @(@($Catalog.controls) | Where-Object { $_ -and -not ($_.PSObject.Properties['retired'] -and $_.retired) } | ForEach-Object { [string]$_.id })
    if ($Scope -eq 'all') { return $live }
    @($script:SISetupUplink.Minimum | Where-Object { $live -contains $_ })
}

function Get-SISetupControlStates {
    <#
        PURE. What this process can tell about the controls, from the telemetry context and the run that is ending:
          update-ring       the reported ring (value 1|2|3; ring 0 = development: ok without a value); none = missing
          uplink-key        identified (an install key) = ok, else missing
          licence-valid     valid = ok, grace / expired = wrong, none = missing
          licence-edition   the edition (value)
          last-run-24h      this run ended ok = ok (another outcome says nothing about the last 24 hours: unknown)
          updater-deployed / updater-schedule   the updater checked within 3 days (its recorded state) = ok / enabled
        Everything else stays unknown (the report says 'unknown', never leaves it out). Returns id -> @{ State; Value }.
    #>
    param([Parameter(Mandatory)]$Context, [AllowEmptyString()][string]$ExitReason = '', [AllowNull()][AllowEmptyString()][string]$UpdateStateJson,
          [datetime]$NowUtc = [datetime]::UtcNow,
          # job-layout: the update's pipeline-schedule check (cfg.InstallState 'PipelineSchedule', within 3 days): ok / repaired
          # = ok; would-repair / failed = wrong ("neither mode": the pipeline not scheduled and no job of it on its own timer)
          [AllowNull()][AllowEmptyString()][string]$PipelineScheduleJson,
          # secret-handover: the updater's hand-over key check (cfg.InstallState 'SecretHandover', within 3 days): ok, or missing =
          # the updater may not use its Key Vault key until the updater setup is re-run with its role grants
          [AllowNull()][AllowEmptyString()][string]$SecretHandoverJson)
    $s = @{}
    $prop = { param($n) if ($Context.PSObject.Properties[$n]) { $Context.$n } else { $null } }
    $ring = ConvertTo-SIReportedRing (& $prop 'Ring')
    $s['update-ring'] = if ($null -eq $ring) { @{ State = 'missing' } } elseif ($ring -ge 1) { @{ State = 'ok'; Value = [string]$ring } } else { @{ State = 'ok' } }
    $s['uplink-key'] = @{ State = $(if ("$(& $prop 'Mode')" -eq 'identified') { 'ok' } else { 'missing' }) }
    switch ("$(& $prop 'LicenceState')") { 'valid' { $s['licence-valid'] = @{ State = 'ok' } } 'grace' { $s['licence-valid'] = @{ State = 'wrong' } }
                                         'expired' { $s['licence-valid'] = @{ State = 'wrong' } } 'none' { $s['licence-valid'] = @{ State = 'missing' } } }
    $ed = "$(& $prop 'Edition')"; if ($ed) { $s['licence-edition'] = @{ State = 'ok'; Value = $ed } }
    if ("$ExitReason" -eq 'success') { $s['last-run-24h'] = @{ State = 'ok' } }
    if (-not [string]::IsNullOrWhiteSpace($UpdateStateJson)) {
        try {
            $o = $UpdateStateJson | ConvertFrom-Json -ErrorAction Stop
            $last = $null
            if ($o -and $o.PSObject.Properties['lastCheckUtc'] -and $o.lastCheckUtc) {
                $d = [datetime]::MinValue
                if ($o.lastCheckUtc -is [datetime]) { $last = $o.lastCheckUtc.ToUniversalTime() }
                elseif ([datetime]::TryParse("$($o.lastCheckUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { $last = $d }
            }
            if ($last -and ($NowUtc.ToUniversalTime() - $last).TotalDays -le 3) {
                $s['updater-deployed'] = @{ State = 'ok' }; $s['updater-schedule'] = @{ State = 'ok'; Value = 'enabled' }
            }
        } catch { }
    }
    if (-not [string]::IsNullOrWhiteSpace($PipelineScheduleJson)) {
        try {
            $p = $PipelineScheduleJson | ConvertFrom-Json -ErrorAction Stop
            $at = [datetime]::MinValue
            $fresh = $p.PSObject.Properties['checkedUtc'] -and [datetime]::TryParse("$($p.checkedUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$at) -and ($NowUtc.ToUniversalTime() - $at).TotalDays -le 3
            if ($fresh) {
                switch ("$($p.state)") { 'ok' { $s['job-layout'] = @{ State = 'ok' } } 'repaired' { $s['job-layout'] = @{ State = 'ok' } }
                                         'would-repair' { $s['job-layout'] = @{ State = 'wrong' } } 'failed' { $s['job-layout'] = @{ State = 'wrong' } } }
            }
        } catch { }
    }
    if (-not [string]::IsNullOrWhiteSpace($SecretHandoverJson)) {
        try {
            $h = $SecretHandoverJson | ConvertFrom-Json -ErrorAction Stop
            $at2 = [datetime]::MinValue
            $fresh2 = $h.PSObject.Properties['checkedUtc'] -and [datetime]::TryParse("$($h.checkedUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$at2) -and ($NowUtc.ToUniversalTime() - $at2).TotalDays -le 3
            if ($fresh2 -and "$($h.state)" -in @('ok', 'missing')) { $s['secret-handover'] = @{ State = "$($h.state)" } }
        } catch { }
    }
    $s
}

function New-SISetupReport {
    <#
        PURE. The Kind=setup record for the uplink, or $null when nothing is to be sent (not identified, or -Scope off).
        Every control of -Scope is in it (Get-SISetupControlIds); a control without a state in -States is 'unknown'. A state
        outside the closed list becomes 'unknown'; a value is kept only for a control declared with an enum and only when
        it is one of the enum's values. Ids in -States outside the scope are NOT sent (an unknown id rejects the report).
        Fields: Schema, Kind, Product, Version, Ring, Edition, LastSeenUtc, Controls -- nothing else (Invardia refuses any
        other field on a setup report).
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Catalog, [System.Collections.IDictionary]$States = @{},
          [ValidateSet('minimum', 'all', 'off')][string]$Scope = 'minimum', $Now)
    if ($Scope -eq 'off') { return $null }
    if ("$($Context.Mode)" -ne 'identified') { return $null }
    $ts = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
    $defs = @{}; foreach ($c in @($Catalog.controls)) { if ($c) { $defs[[string]$c.id] = $c } }
    $controls = New-Object System.Collections.Generic.List[object]
    foreach ($id in @(Get-SISetupControlIds -Catalog $Catalog -Scope $Scope)) {
        if ($id -notmatch $script:SISetupUplink.IdPattern) { continue }
        $st = $States[$id]
        $state = if ($st -and $script:SISetupUplink.States -contains "$($st.State)") { "$($st.State)" } else { 'unknown' }
        $item = [ordered]@{ id = $id; state = $state }
        $def = $defs[$id]
        if ($st -and $null -ne $st.Value -and "$($st.Value)" -ne '' -and $def -and $def.PSObject.Properties['enum'] -and (@($def.enum) -contains "$($st.Value)")) { $item['value'] = "$($st.Value)" }
        $controls.Add([pscustomobject]$item)
    }
    $o = [ordered]@{ Schema = 2; Kind = 'setup'; Product = $script:SISetupUplink.Product }
    $ver = "$($Context.Version)".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $ring = $null; if ($Context.PSObject.Properties['Ring']) { $ring = ConvertTo-SIReportedRing $Context.Ring }
    if ($null -ne $ring) { $o['Ring'] = [int]$ring }
    $ed = "$($Context.Edition)".Trim().ToLowerInvariant(); if (@('community', 'pro', 'trial') -contains $ed) { $o['Edition'] = $ed }
    $o['LastSeenUtc'] = $ts.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $o['Controls'] = $controls.ToArray()
    [pscustomobject]$o
}
