#Requires -Version 5.1
<#
    SecurityInsight -- the FIRST RUN AFTER AN UPGRADE, and the dry-run lines every run carries.

    Many 2.2 installs receive 3.0 with nobody reading the upgrade notes: 2.2's Update-SecurityInsight.ps1 pulls at once,
    the 2.2 README scheduled a daily `git pull`, and internal installs are synced from main. So 3.0 must arrive safely by
    itself. This file is that safety layer, shared by the VM loader (launcher\_lib\Initialize-LauncherConfig.ps1) and the
    container entry points (container\Start-SIInContainer.ps1, container\Start-RiskAnalysisInContainer.ps1):

      1. DETECTION, once per install: "this install ran an earlier version, and this is its first 3.0 run". A small
         state file is written on the first 3.0 run (VM: <solution>\logs\state\install-state.json; container: blob
         'install/install-state.json' in the install's 'sistate' container). With no state yet, the install is
         UPGRADED when there is evidence of earlier runs -- run logs older than this run, a 2.2 config snapshot (2.2
         loaded the engine defaults AFTER the customer file), or a setting only 2.2 knew -- and FRESH otherwise. A fresh
         install gets no upgrade notice. The state then says which one-time notices were shown, so none repeats.
      2. ONE-TIME NOTICES: what 3.0 changed by itself (upgraded installs), what the status reports to Invardia carry and
         how to turn them off (every install, once, while they are on), on a Pro install what it now does with Invardia
         by itself (the automatic licence request and the Pro updates, both on by default) with the off switch for each,
         and -- per engine, VM only -- the settings from
         the customer's own configuration that now take effect (2.2 overwrote them with its engine defaults; the list
         is computed against the 2.2.460 defaults kept in launcher\_lib\v2.2-engine-defaults.locked.json and saved to
         logs\settings-now-in-effect-<engine>.txt for support).
      3. DRY RUN is asked for PER RUN only (operator decision: "upgrade must work, no dryrun"). A WhatIfMode that comes
         from the configuration (custom.ps1, a launcher config, the Pro settings, a container job's settings) is IGNORED
         for every engine except asset tagging -- where it has always meant "do not change any tag" and is kept -- and
         every run says so in one line. A dry run is started with the launcher's -WhatIfMode switch, or with SI_WHATIF=1
         on one container job execution. A dry run says so loudly at its start and at its end (Send-SIRunHealthRow).

    RULE: nothing here may fail or stop a run. Every reader and writer swallows its own errors.
    Customer-facing text: plain words, no tracking numbers, no internal terms.
    PS 5.1 and 7.
#>

# the install-state blob (a container) goes through SI's Azure wrappers: load them where this file is
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AzRest.ps1') }
# Pro: what the install now does with Invardia by itself, and its two switches (the one-time 'pro-auto' notice)
if (-not (Get-Command -Name Get-SIProAutoNoticeLines -ErrorAction SilentlyContinue)) {
    $siFrProAuto = Join-Path $PSScriptRoot 'SI-ProAutomation.ps1'
    if (Test-Path -LiteralPath $siFrProAuto) { . $siFrProAuto }
}

$script:SIFirstRun = @{
    SolutionRoot   = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    StateFileName  = 'install-state.json'
    StateBlob      = 'install/install-state.json'
    StateContainer = 'sistate'
    RunLogContainer = 'sistaging'
    RunLogPrefix   = 'run-logs/'
    # Settings that only 2.2 read. 3.0 ships none of them, so a configuration that sets one was written for 2.2.
    Legacy22Settings = @('SendToPowerBI', 'SI_SendToPowerBI', 'TroubleshootingMode', 'SI_UseNewRuleEngine',
                         'SI_DiscoveryMode_azure', 'SI_SystemPrompt_publicip', 'SI_EnableAI_publicip')
    Legacy22Prefixes = @('PowerBI_')
    # The engines where WhatIfMode in the configuration is KEPT: asset tagging changes the customer's own resources,
    # and "report only" is what 2.2 did with it too.
    DryRunConfigEngines = @('assettagging', 'asset-tagging')
    SecretNameRe   = '(?i)Secret|Password|Pwd|ApiKey|Api_Key|AccessKey|Token(?!Lifetime)|ConnectionString|StorageKey|Cert(?:ificate)?Thumbprint'
}

# =====================================================================================================================
#  Pure decisions
# =====================================================================================================================
function Test-SIFirstRunTruthy {
    <# PURE. $true / 'true' / '1' / 'yes' / 'on' / '$true' -> $true; anything else (null, empty, false, 0 ...) -> $false. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [System.Management.Automation.SwitchParameter]) { return $Value.IsPresent }
    return ("$Value".Trim().Trim('$').ToLowerInvariant() -in @('true', '1', 'yes', 'on'))
}

function Get-SIFirstRunDecision {
    <#
        PURE. -State: the install's state ($null = none yet). -Evidence: the signs of earlier runs found ('' entries ignored).
        Returns Kind = seen (a 3.0 run already recorded this install) | upgraded (first 3.0 run of an install that ran
        before) | fresh (first run of a new install), and Origin = upgraded | fresh.
    #>
    param([AllowNull()]$State, [AllowNull()][AllowEmptyCollection()][string[]]$Evidence)
    if ($State -and $State.PSObject.Properties['Origin'] -and "$($State.Origin)" -in @('upgraded', 'fresh')) {
        return [pscustomobject]@{ Kind = 'seen'; Origin = [string]$State.Origin }
    }
    $ev = @($Evidence | Where-Object { "$_".Trim() })
    if ($ev.Count) { return [pscustomobject]@{ Kind = 'upgraded'; Origin = 'upgraded' } }
    [pscustomobject]@{ Kind = 'fresh'; Origin = 'fresh' }
}

function New-SIInstallState {
    <# PURE. A new install state. #>
    param([Parameter(Mandatory)][ValidateSet('upgraded', 'fresh')][string]$Origin, [AllowNull()][string[]]$Evidence,
          [AllowEmptyString()][string]$Version, [datetime]$NowUtc = [datetime]::UtcNow)
    [pscustomobject]@{
        Schema = 1; Origin = $Origin; FirstRunUtc = $NowUtc.ToUniversalTime().ToString('o'); FirstVersion = "$Version"
        Evidence = @($Evidence | Where-Object { "$_".Trim() }); Shown = @()
    }
}

function Test-SINoticeDue {
    <# PURE. Has the one-time notice -Id not been shown on this install yet? #>
    param([AllowNull()]$State, [Parameter(Mandatory)][string]$Id)
    if (-not $State -or -not $State.PSObject.Properties['Shown']) { return $true }
    return -not (@($State.Shown) -contains $Id)
}

function Add-SINoticeShown {
    <# Records the notice -Id as shown in -State (in place). #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Id)
    $shown = @($State.Shown | Where-Object { "$_" })
    if ($shown -notcontains $Id) { $shown += $Id }
    if ($State.PSObject.Properties['Shown']) { $State.Shown = $shown } else { $State | Add-Member -NotePropertyName Shown -NotePropertyValue $shown }
}

function Resolve-SIConfigDryRun {
    <#
        PURE. Does a WhatIfMode from the CONFIGURATION make this engine's run a dry run? Only for asset tagging (it keeps
        what it always meant there: report only, change no tag). For every other engine a dry run is asked for per run
        (-WhatIfMode on the launcher, SI_WHATIF on one container job execution), and a configuration value is ignored.
        -SetByConfig: the value came from a configuration layer (not from the caller's own session).
        Returns Ignored (a true configuration value was set aside) and WhatIfMode (the value to use before any per-run
        request is applied).
    #>
    param([AllowEmptyString()][string]$Engine, [AllowNull()]$ConfigValue, [bool]$SetByConfig = $true)
    $on = Test-SIFirstRunTruthy $ConfigValue
    $e = ("$Engine".Trim().ToLowerInvariant() -replace '[\s_]', '')
    if (-not $on) { return [pscustomobject]@{ Ignored = $false; WhatIfMode = $false } }
    if (-not $SetByConfig -or $e -in $script:SIFirstRun.DryRunConfigEngines) { return [pscustomobject]@{ Ignored = $false; WhatIfMode = $true } }
    [pscustomobject]@{ Ignored = $true; WhatIfMode = $false }
}

function ConvertTo-SISettingDisplay {
    <# PURE. A setting value as one short, readable line. Secret-looking names are never shown. #>
    param([string]$Name, [AllowNull()]$Value)
    if ($Name -match $script:SIFirstRun.SecretNameRe) { return '(hidden)' }
    if ($null -eq $Value) { return '(not set)' }
    if ($Value -is [bool]) { return ('$' + $Value.ToString().ToLowerInvariant()) }
    if ($Value -is [System.Collections.IDictionary]) { return ('@{' + ((@($Value.Keys) | ForEach-Object { "$_" }) -join ', ') + '}') }
    if ($Value -is [array] -or $Value -is [System.Collections.IList]) {
        return ('@(' + ((@($Value) | ForEach-Object { "'$_'" }) -join ', ') + ')')
    }
    $s = ("$Value" -replace '\r?\n', ' ')
    if ($Value -is [string] -and -not $s.Trim()) { return '(empty)' }
    if ($s.Length -gt 120) { $s = $s.Substring(0, 120) + '...' }
    if ($Value -is [string]) { return "'$s'" }
    return $s
}

function ConvertTo-SISettingComparable {
    <# PURE. The value as text for comparing a 2.2 default with today's value (bool / number / list / text alike). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [System.Collections.IDictionary]) { return '' }
    if ($Value -is [array] -or $Value -is [System.Collections.IList]) { return ((@($Value) | ForEach-Object { "$_".Trim() }) -join ',') }
    $s = "$Value".Trim()
    if ($s -match '^(?i)\$?(true|false)$') { return $Matches[1].ToLowerInvariant() }
    return $s
}

function Get-SISettingsNowInEffect {
    <#
        PURE. The settings of ONE engine that the customer's solution-wide configuration (config\SecurityInsight.custom.ps1)
        now makes take effect. In 2.2 the engine's shipped defaults loaded AFTER that file, so every default set without a
        guard replaced the customer's value; 3.0 loads the defaults first. A setting is listed when:
          the customer's file sets it, 2.2's defaults for this engine set it too, the engine's own customer file
          (LauncherConfig.custom.ps1, loaded last in both versions) does not, and today's value differs from the 2.2 one.
        -V22Defaults: name -> the value 2.2.460's defaults set (unguarded) for this engine.
        -CustomNames / -EngineCustomNames: the names each customer file assigns.  -Current: name -> today's value.
        Returns @{ Name; Was; Now } sorted by name.
    #>
    param([AllowNull()][System.Collections.IDictionary]$V22Defaults, [AllowNull()][string[]]$CustomNames,
          [AllowNull()][string[]]$EngineCustomNames, [AllowNull()][System.Collections.IDictionary]$Current)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $V22Defaults -or -not $Current) { return @() }
    $engineOwn = @($EngineCustomNames | Where-Object { $_ })
    foreach ($n in @($CustomNames | Where-Object { $_ } | Sort-Object -Unique)) {
        $key = @($V22Defaults.Keys | Where-Object { "$_" -ieq $n }) | Select-Object -First 1
        if (-not $key) { continue }
        if (@($engineOwn | Where-Object { $_ -ieq $n }).Count) { continue }
        $was = $V22Defaults[$key]
        $nowKey = @($Current.Keys | Where-Object { "$_" -ieq $n }) | Select-Object -First 1
        $now = if ($nowKey) { $Current[$nowKey] } else { $null }
        if ((ConvertTo-SISettingComparable $was) -ceq (ConvertTo-SISettingComparable $now)) { continue }
        $out.Add([pscustomobject]@{ Name = [string]$key; Was = $was; Now = $now })
    }
    return @($out.ToArray())
}

# =====================================================================================================================
#  The customer-facing texts (plain words; no tracking numbers, no internal terms)
# =====================================================================================================================
function Get-SIConfigDryRunIgnoredText {
    param([ValidateSet('vm', 'container')][string]$Hosting = 'vm')
    $how = if ($Hosting -eq 'container') { 'set SI_WHATIF=1 on a single job execution' } else { 'start the run with -WhatIfMode' }
    "WhatIfMode in your configuration is ignored for scheduled runs -- runs publish as normal; for a dry run, $how."
}

function Get-SIDryRunNoticeText {
    param([Parameter(Mandatory)][ValidateSet('Start', 'End')][string]$Moment)
    if ($Moment -eq 'Start') {
        return 'DRY RUN -- this run publishes nothing and sends nothing (it was started as a dry run). Run it without -WhatIfMode (or without SI_WHATIF on a container job) to publish.'
    }
    'DRY RUN finished -- nothing was published or sent. Run it without -WhatIfMode (or without SI_WHATIF on a container job) to publish.'
}

function Get-SIUpgradeNoticeLines {
    <# PURE. The one-time notice on the first 3.0 run of an upgraded install. #>
    param([ValidateSet('vm', 'container')][string]$Hosting = 'vm', [bool]$WhatIfConfigIgnored = $false)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('SecurityInsight was updated to 3.0 on this installation. These changes apply by themselves -- nothing needs to be done now:')
    if ($Hosting -eq 'vm') {
        $l.Add(' - Your own settings in config\SecurityInsight.custom.ps1 now win over the built-in engine defaults. Each engine lists once, on its first run, which of your settings now take effect (also saved in the logs folder).')
    }
    $l.Add(' - SecurityInsight no longer refreshes a Power BI dataset. Results are still written to Log Analytics; read them with the Azure Monitor workbook, your own queries or reports, or the SecurityInsight Pro web app.')
    if ($WhatIfConfigIgnored) {
        $how = if ($Hosting -eq 'container') { 'set SI_WHATIF=1 on a single job execution' } else { 'start a run with -WhatIfMode' }
        $l.Add((' - Your configuration sets WhatIfMode. It no longer stops or limits scheduled runs: they publish as normal. For a dry run, {0}.' -f $how))
    } else {
        $l.Add(' - A dry run is now asked for per run (the -WhatIfMode switch); WhatIfMode in a configuration file no longer changes scheduled runs.')
    }
    $l.Add(' - The full list is in RELEASENOTES.md, section "Upgrading from 2.2.x". This notice is shown once.')
    return @($l.ToArray())
}

function Get-SITelemetryNoticeLines {
    <# PURE. The one-time notice about the status reports to Invardia (shown while they are on). #>
    param([ValidateSet('vm', 'container')][string]$Hosting = 'vm')
    $off = if ($Hosting -eq 'container') { 'set SI_Telemetry_Enabled = $false in config\SecurityInsight.custom.ps1 and run setup again, or set SI_TELEMETRY_ENABLED=false on the jobs' }
           else { 'set $global:SI_Telemetry_Enabled = $false in config\SecurityInsight.custom.ps1' }
    @(
        'SecurityInsight sends short status reports to Invardia, the maker of SecurityInsight: one a day (version, edition, how it is hosted, licence state) and one per engine run (whether it succeeded, how long it took, the kind of error, and counts).',
        ' - A Community installation reports anonymously, with a random installation id: no tenant, no host name, no error text, and counts only as ranges.',
        ' - A Pro installation reports with its installation key; error messages are shortened and secrets are removed before they are sent.',
        (' - To turn the reports off, {0}. This notice is shown once.' -f $off)
    )
}

function Get-SISettingsNowInEffectLines {
    <# PURE. The one-time per-engine list, for the console and the file in logs\. #>
    param([Parameter(Mandatory)][string]$Engine, [AllowNull()][AllowEmptyCollection()][object[]]$Changes, [string]$FileName)
    $c = @($Changes | Where-Object { $_ })
    if (-not $c.Count) { return @(('No setting in your configuration changes the {0} engine''s behaviour with SecurityInsight 3.0.' -f $Engine)) }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add(('These settings from your configuration now take effect for the {0} engine. SecurityInsight 2.2 replaced them with its built-in defaults; 3.0 uses your values:' -f $Engine))
    foreach ($x in $c) {
        $l.Add(('   {0}: was {1}, now {2}' -f $x.Name, (ConvertTo-SISettingDisplay -Name $x.Name -Value $x.Was), (ConvertTo-SISettingDisplay -Name $x.Name -Value $x.Now)))
    }
    if ($FileName) { $l.Add((' This list is saved in logs\{0} and is shown once. To keep 2.2''s behaviour for a setting, remove it from your configuration.' -f $FileName)) }
    return @($l.ToArray())
}

function Write-SINoticeLines {
    <# Prints notice lines: the first as [NOTICE], the rest indented. Into the console and the run log (transcript). #>
    param([AllowEmptyCollection()][string[]]$Lines)
    $first = $true
    foreach ($line in @($Lines)) {
        try {
            if ($first) { Write-Host ('[NOTICE] {0}' -f $line) -ForegroundColor Yellow; $first = $false }
            else { Write-Host ('         {0}' -f $line) -ForegroundColor Yellow }
        } catch { }
    }
}

# =====================================================================================================================
#  The retired Power BI refresh -- one line per run while it is still configured (VM loader and containers alike)
# =====================================================================================================================
function Write-SIPowerBIRetiredNotice {
    <#
        The Power BI dataset refresh (SendToPowerBI, PowerBI_*) was removed in 3.0.0. When a configuration still turns it
        on -- SendToPowerBI / SI_SendToPowerBI true, or any PowerBI_* setting with a value -- print ONE line saying so and
        where the results are read now. Nothing set = nothing printed. Returns $true when it printed.
    #>
    [CmdletBinding()]
    param()
    $on = $false
    foreach ($n in @('SendToPowerBI', 'SI_SendToPowerBI')) {
        $v = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($v -is [bool]) { if ($v) { $on = $true } }
        elseif ($null -ne $v -and ([string]$v).Trim() -match '^(?i:true|1|yes|on|\$true)$') { $on = $true }
    }
    if (-not $on) {
        foreach ($var in @(Get-Variable -Name 'PowerBI_*' -Scope Global -ErrorAction SilentlyContinue)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$var.Value)) { $on = $true; break }
        }
    }
    if (-not $on) { return $false }
    Write-Warning ('The Power BI refresh was retired in SecurityInsight 3.0: SendToPowerBI and the PowerBI_* settings ' +
        'are no longer used, and no Power BI dataset is refreshed. Your results are still written to Log Analytics -- ' +
        'read them with the Azure Monitor workbook (preview\AzureWorkbook), with your own queries or a Power BI report ' +
        'connected to the workspace, or in the SecurityInsight Pro web app. Remove these settings from your ' +
        'configuration to stop this message.')
    return $true
}

# =====================================================================================================================
#  This install: the state, the evidence, the telemetry switch
# =====================================================================================================================
function Get-SIFirstRunVersion {
    param([string]$SolutionRoot = $script:SIFirstRun.SolutionRoot)
    try {
        $f = [System.IO.Path]::Combine($SolutionRoot, 'VERSION')
        if ([System.IO.File]::Exists($f)) { return ([System.IO.File]::ReadAllText($f)).Trim() }
    } catch { }
    ''
}

function Test-SIFirstRunTelemetryOn {
    <# Are the status reports on? The telemetry sender's own decision when it is loaded, else the same rule: the setting,
       then SI_TELEMETRY_ENABLED, else on. #>
    if (Get-Command -Name Test-SITelemetryEnabled -ErrorAction SilentlyContinue) { try { return [bool](Test-SITelemetryEnabled) } catch { } }
    foreach ($v in @($global:SI_Telemetry_Enabled, $env:SI_TELEMETRY_ENABLED)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { return $v }
        $s = "$v".Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        return -not ($s -in @('false', '0', 'off', 'no', 'disabled'))
    }
    $true
}

function Get-SIFirstRunProAuto {
    <#
        Pro only: is this a SecurityInsight Pro run (its settings database is configured), and are the automatic licence
        request and the Pro updates from Invardia on? The run's settings ($global:, the Pro settings layer sets them), then
        the job's environment, else on. Returns @{ Pro; LicenceOn; UpdatesOn }.
    #>
    $pro = [bool]("$($global:SI_ProSqlServer)".Trim() -and "$($global:SI_ProSqlDatabase)".Trim())
    $lic = $true; $upd = $true
    if (Get-Command -Name Resolve-SIProAutoSwitch -ErrorAction SilentlyContinue) {
        try { $lic = (Resolve-SIProAutoSwitch -Name SI_LicenseRequest_Auto -SettingValue $global:SI_LicenseRequest_Auto -EnvValue $env:SI_LICENSE_REQUEST_AUTO).On } catch { }
        try { $upd = (Resolve-SIProAutoSwitch -Name SI_InvardiaUpdate_Enabled -SettingValue $global:SI_InvardiaUpdate_Enabled -EnvValue $env:SI_INVARDIA_UPDATE_ENABLED).On } catch { }
    }
    [pscustomobject]@{ Pro = $pro; LicenceOn = [bool]$lic; UpdatesOn = [bool]$upd }
}

function ConvertFrom-SIInstallStateJson {
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    $o = $Json | ConvertFrom-Json -ErrorAction Stop
    if (-not $o.PSObject.Properties['Shown']) { $o | Add-Member -NotePropertyName Shown -NotePropertyValue @() }
    $o.Shown = @($o.Shown | Where-Object { "$_" })
    $o
}

function Read-SIInstallState {
    <#
        -Store: @{ Kind = 'file'; Path } | @{ Kind = 'blob'; Account } | @{ Kind = 'memory'; Box = @{} } (tests).
        Returns @{ Ok; State } -- Ok $false when the store could not be read (the caller then shows nothing and writes
        nothing, so an unreadable store never repeats a notice on every run). An absent state is Ok with State $null.
    #>
    param([Parameter(Mandatory)][hashtable]$Store)
    try {
        switch ($Store.Kind) {
            'file' {
                if (-not [System.IO.File]::Exists($Store.Path)) { return [pscustomobject]@{ Ok = $true; State = $null } }
                return [pscustomobject]@{ Ok = $true; State = (ConvertFrom-SIInstallStateJson ([System.IO.File]::ReadAllText($Store.Path))) }
            }
            'memory' { return [pscustomobject]@{ Ok = $true; State = (ConvertFrom-SIInstallStateJson ([string]$Store.Box['json'])) } }
            'blob' {
                $ctx = Get-SIRunStateContext -AccountName $Store.Account
                $blob = $null
                try { $blob = Get-SIAzStorageBlob -Container $script:SIFirstRun.StateContainer -Blob $script:SIFirstRun.StateBlob -Context $ctx -ErrorAction Stop }
                catch {
                    if ("$($_.Exception.Message)" -match '(?i)BlobNotFound|ContainerNotFound|does not exist|404|Can not find') { return [pscustomobject]@{ Ok = $true; State = $null } }
                    throw
                }
                if (-not $blob) { return [pscustomobject]@{ Ok = $true; State = $null } }
                $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('si-state-{0}.json' -f [guid]::NewGuid().ToString('N')))
                try {
                    Get-SIAzStorageBlobContent -Container $script:SIFirstRun.StateContainer -Blob $script:SIFirstRun.StateBlob -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
                    return [pscustomobject]@{ Ok = $true; State = (ConvertFrom-SIInstallStateJson ([System.IO.File]::ReadAllText($tmp))) }
                } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            }
            default { return [pscustomobject]@{ Ok = $false; State = $null } }
        }
    } catch {
        Write-Verbose ('install state not read: {0}' -f $_.Exception.Message)
        return [pscustomobject]@{ Ok = $false; State = $null }
    }
}

function Save-SIInstallState {
    <# Writes the state to -Store. Never throws; $true when written. #>
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)]$State)
    try {
        $json = $State | ConvertTo-Json -Depth 5
        switch ($Store.Kind) {
            'file' {
                $dir = [System.IO.Path]::GetDirectoryName($Store.Path)
                $null = [System.IO.Directory]::CreateDirectory($dir)
                $tmp = $Store.Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
                [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
                if ([System.IO.File]::Exists($Store.Path)) { [System.IO.File]::Delete($Store.Path) }
                [System.IO.File]::Move($tmp, $Store.Path)
                return $true
            }
            'memory' { $Store.Box['json'] = $json; $Store.Box['writes'] = 1 + [int]$Store.Box['writes']; return $true }
            'blob' {
                $ctx = Get-SIRunStateContext -AccountName $Store.Account
                if (-not (Get-SIAzStorageContainer -Name $script:SIFirstRun.StateContainer -Context $ctx -ErrorAction SilentlyContinue)) {
                    New-SIAzStorageContainer -Name $script:SIFirstRun.StateContainer -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
                }
                $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('si-state-{0}.json' -f [guid]::NewGuid().ToString('N')))
                try {
                    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
                    Set-SIAzStorageBlobContent -File $tmp -Container $script:SIFirstRun.StateContainer -Blob $script:SIFirstRun.StateBlob -Context $ctx -Force -ErrorAction Stop | Out-Null
                } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
                return $true
            }
        }
    } catch { Write-Verbose ('install state not saved: {0}' -f $_.Exception.Message) }
    $false
}

function Get-SILegacySettingsEvidence {
    <# PURE. 'v2.2-settings' when any of -Names is a setting only 2.2 read. #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$Names)
    foreach ($n in @($Names | Where-Object { $_ })) {
        if (@($script:SIFirstRun.Legacy22Settings | Where-Object { $_ -ieq $n }).Count) { return 'v2.2-settings' }
        foreach ($p in $script:SIFirstRun.Legacy22Prefixes) { if ($n -like "$p*") { return 'v2.2-settings' } }
    }
    ''
}

function Get-SIUpgradeEvidenceVm {
    <#
        The signs, on a VM, that this install ran before its first 3.0 run. -LogDir: the install's logs folder.
        -Before: when this run started (its own transcript is newer). -SettingNames: the names the customer files assign.
        Returns a list of: earlier-run-logs | v2.2-config-snapshot | v2.2-settings. Never throws.
    #>
    param([string]$LogDir, [datetime]$Before = [datetime]::Now, [AllowNull()][AllowEmptyCollection()][string[]]$SettingNames)
    $ev = New-Object System.Collections.Generic.List[string]
    try {
        if ($LogDir -and (Test-Path -LiteralPath $LogDir)) {
            $old = @(Get-ChildItem -LiteralPath $LogDir -Filter '*.log' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $Before })
            if ($old.Count) { $ev.Add('earlier-run-logs') }
            # 2.2 loaded the engine defaults AFTER the customer file, and its config snapshot says so in its layer trail.
            foreach ($f in @($old | Where-Object { $_.Name -like 'config-*.log' } | Sort-Object LastWriteTime -Descending | Select-Object -First 5)) {
                try {
                    $head = [System.IO.File]::ReadAllText($f.FullName)
                    if ($head -match 'Layer 4 - LauncherConfig\.defaults') { $ev.Add('v2.2-config-snapshot'); break }
                } catch { }
            }
        }
    } catch { }
    $s = Get-SILegacySettingsEvidence -Names $SettingNames
    if ($s) { $ev.Add($s) }
    @($ev.ToArray())
}

function Get-SIUpgradeEvidenceContainer {
    <#
        The signs, for a container install, that it ran before its first 3.0 run: run logs published to the install's
        storage account before this run started, or a setting only 2.2 read among the job's settings. Never throws.
    #>
    param([string]$Account, [datetime]$Before = [datetime]::UtcNow, [AllowNull()][AllowEmptyCollection()][string[]]$SettingNames)
    $ev = New-Object System.Collections.Generic.List[string]
    if ($Account) {
        try {
            $ctx = Get-SIRunStateContext -AccountName $Account
            $logs = @(Get-SIAzStorageBlob -Container $script:SIFirstRun.RunLogContainer -Prefix $script:SIFirstRun.RunLogPrefix -Context $ctx -ErrorAction Stop | Where-Object { $_ })
            $old = @($logs | Where-Object {
                $lm = $null
                if ($_.PSObject.Properties['LastModified'] -and $_.LastModified) { try { $lm = ([DateTimeOffset]$_.LastModified).UtcDateTime } catch { try { $lm = ([datetime]$_.LastModified).ToUniversalTime() } catch { } } }
                (-not $lm) -or ($lm -lt $Before.ToUniversalTime())
            })
            if ($old.Count) { $ev.Add('earlier-run-logs') }
        } catch { Write-Verbose ('earlier run logs not checked: {0}' -f $_.Exception.Message) }
    }
    $s = Get-SILegacySettingsEvidence -Names $SettingNames
    if ($s) { $ev.Add($s) }
    @($ev.ToArray())
}

# =====================================================================================================================
#  The one call per run
# =====================================================================================================================
function Invoke-SIFirstRunNotices {
    <#
        Decides and shows this run's one-time notices, and records them. Never throws. Returns @{ Kind; Origin; Shown
        (the ids shown now); Saved; SettingsFile }.
          -Hosting vm | container          -Engine   the engine (the launcher folder name on a VM)
          -Store    where the install state lives (see Read-SIInstallState)
          -Evidence { } -> string[]        evaluated ONLY when there is no state yet
          -SettingsChanges { } -> @{Name;Was;Now}[]   VM, upgraded installs: this engine's settings now in effect
          -LogDir   where the settings list file is written (VM)
          -WhatIfConfigIgnored             this run set aside a WhatIfMode from the configuration
          -TelemetryOn                     the status reports are on (default: the run's setting)
          -ProAuto                         @{ Pro; LicenceOn; UpdatesOn } (default: Get-SIFirstRunProAuto) -- a Pro install
                                           is told once what it now does with Invardia by itself and how to switch it off
    #>
    [CmdletBinding()]
    param([ValidateSet('vm', 'container')][string]$Hosting = 'vm', [string]$Engine = '', [Parameter(Mandatory)][hashtable]$Store,
          [scriptblock]$Evidence, [scriptblock]$SettingsChanges, [string]$LogDir, [bool]$WhatIfConfigIgnored = $false,
          $TelemetryOn = $null, $ProAuto = $null, [string]$Version, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [pscustomobject]@{ Kind = 'unknown'; Origin = ''; Shown = @(); Saved = $false; SettingsFile = '' }
    try {
        $read = Read-SIInstallState -Store $Store
        if (-not $read.Ok) { return $res }
        $state = $read.State
        $dirty = $false
        $ev = @()
        if (-not $state) { if ($Evidence) { try { $ev = @(& $Evidence) } catch { $ev = @() } } }
        $d = Get-SIFirstRunDecision -State $state -Evidence $ev
        $res.Kind = $d.Kind; $res.Origin = $d.Origin
        if (-not $state) {
            if (-not $PSBoundParameters.ContainsKey('Version')) { $Version = Get-SIFirstRunVersion }
            $state = New-SIInstallState -Origin $d.Origin -Evidence $ev -Version $Version -NowUtc $NowUtc
            $dirty = $true
        }
        $global:SI_InstallOrigin = [string]$state.Origin
        $shown = New-Object System.Collections.Generic.List[string]

        if ($state.Origin -eq 'upgraded' -and (Test-SINoticeDue -State $state -Id 'upgrade')) {
            Write-SINoticeLines -Lines (Get-SIUpgradeNoticeLines -Hosting $Hosting -WhatIfConfigIgnored $WhatIfConfigIgnored)
            Add-SINoticeShown -State $state -Id 'upgrade'; $shown.Add('upgrade'); $dirty = $true
        }
        $tOn = if ($null -eq $TelemetryOn) { Test-SIFirstRunTelemetryOn } else { [bool]$TelemetryOn }
        if ($tOn -and (Test-SINoticeDue -State $state -Id 'telemetry')) {
            Write-SINoticeLines -Lines (Get-SITelemetryNoticeLines -Hosting $Hosting)
            Add-SINoticeShown -State $state -Id 'telemetry'; $shown.Add('telemetry'); $dirty = $true
        }
        # Pro: the automatic licence request and the Pro updates from Invardia are ON by default -- upgraded installs
        # included, with no opt-in -- so every Pro install is told once, with the off switch for each.
        $pa = if ($null -eq $ProAuto) { if (Get-Command -Name Get-SIFirstRunProAuto -ErrorAction SilentlyContinue) { Get-SIFirstRunProAuto } else { $null } } else { $ProAuto }
        if ($pa -and $pa.Pro -and ($pa.LicenceOn -or $pa.UpdatesOn) -and (Get-Command -Name Get-SIProAutoNoticeLines -ErrorAction SilentlyContinue) -and (Test-SINoticeDue -State $state -Id 'pro-auto')) {
            Write-SINoticeLines -Lines (Get-SIProAutoNoticeLines -LicenceOn ([bool]$pa.LicenceOn) -UpdatesOn ([bool]$pa.UpdatesOn))
            Add-SINoticeShown -State $state -Id 'pro-auto'; $shown.Add('pro-auto'); $dirty = $true
        }
        $sid = 'settings:' + ("$Engine".Trim().ToLowerInvariant())
        if ($Hosting -eq 'vm' -and $state.Origin -eq 'upgraded' -and $SettingsChanges -and "$Engine".Trim() -and (Test-SINoticeDue -State $state -Id $sid)) {
            $changes = @()
            try { $changes = @(& $SettingsChanges | Where-Object { $_ }) } catch { $changes = @() }
            $file = ('settings-now-in-effect-{0}.txt' -f ("$Engine".Trim().ToLowerInvariant() -replace '[^a-z0-9_.-]', '-'))
            $lines = Get-SISettingsNowInEffectLines -Engine $Engine -Changes $changes -FileName $file
            if ($changes.Count) { Write-SINoticeLines -Lines $lines }
            if ($LogDir) {
                try {
                    $null = [System.IO.Directory]::CreateDirectory($LogDir)
                    $p = [System.IO.Path]::Combine($LogDir, $file)
                    $body = @(('SecurityInsight {0} -- first run of the {1} engine after the update, {2:yyyy-MM-dd HH:mm} UTC' -f (Get-SIFirstRunVersion), $Engine, $NowUtc)) + @('') + @($lines)
                    [System.IO.File]::WriteAllLines($p, [string[]]$body, (New-Object System.Text.UTF8Encoding($false)))
                    $res.SettingsFile = $p
                } catch { }
            }
            Add-SINoticeShown -State $state -Id $sid; $shown.Add($sid); $dirty = $true
        }
        if ($dirty) { $res.Saved = Save-SIInstallState -Store $Store -State $state }
        $res.Shown = @($shown.ToArray())
    } catch { Write-Verbose ('first-run notices skipped: {0}' -f $_.Exception.Message) }
    $res
}

function Invoke-SIContainerRunSafety {
    <#
        The container entry points' ONE call, after the settings and the Pro / customisation layer are in place and the
        job is signed in: the dry-run decision (a WhatIfMode from the job's settings is set aside unless the engine is
        asset tagging; SI_WHATIF on this execution asks for a dry run), the retired Power BI line, and the one-time
        notices (state in the install's storage account). Never throws.
    #>
    param([Parameter(Mandatory)][string]$Engine, [string]$StorageAccount, [scriptblock]$GetEnv)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    $ignored = $false
    try {
        $dr = Resolve-SIConfigDryRun -Engine $Engine -ConfigValue $global:WhatIfMode
        if ($dr.Ignored) {
            $ignored = $true
            $global:SI_WhatIfModeConfigIgnored = $true
            Write-Warning (Get-SIConfigDryRunIgnoredText -Hosting container)
        }
        $global:WhatIfMode = [bool]$dr.WhatIfMode
        if (Test-SIFirstRunTruthy (& $GetEnv 'SI_WHATIF')) { $global:WhatIfMode = $true }
    } catch { }
    try { $null = Write-SIPowerBIRetiredNotice } catch { }
    $names = @(Get-Variable -Scope Global -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $before = try { [System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime() } catch { [datetime]::UtcNow }
    $acct = $StorageAccount
    if (-not $acct) { return $null }
    Invoke-SIFirstRunNotices -Hosting container -Engine $Engine -Store @{ Kind = 'blob'; Account = $acct } -WhatIfConfigIgnored $ignored `
        -Evidence { Get-SIUpgradeEvidenceContainer -Account $acct -Before $before -SettingNames $names }
}
