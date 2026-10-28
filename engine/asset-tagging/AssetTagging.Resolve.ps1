#Requires -Version 5.1
<#
    SECURITYINSIGHT -- WHERE THE ASSET-TAGGING ENGINE FINDS ITS RULES AND ITS CONFIG (one resolution, three readers).

    The launchers (launcher\asset-tagging\launcher.*.ps1), the engine (engine\asset-tagging\AssetTagging.ps1) and the Pro
    importer (setup\Import-SIProSettings.ps1, #275 R3) all call THESE functions, so the importer looks exactly where a run
    looks -- a customisation kept anywhere the engine reads is found, and nothing the engine would not read is imported.
    The rules are the ones 2.2 shipped, moved here unchanged (2.2.460: launcher.internal-vm.ps1 "SettingsPath resolution",
    AssetTagging.ps1 "LockedYamlFile / CustomYamlFile / LegacyYamlFile" and "asset-tagging.config.json").

    PURE apart from Test-Path. PowerShell 5.1: no ?. / ??.
#>

function Resolve-SIAssetTaggingSettingsPath {
    <#
        The rules folder (SettingsPath): the -SettingsPath switch (-Cli), else the configured $global:SettingsPath, else the
        launcher's default --
          internal launcher:  <SI>\asset-tagging-rules\ when it exists, then <SI>\asset-profiling-enrichment\endpoint\, else
                              asset-tagging-rules\ (the engine then stops with the clear "No YAML found" error);
          community launcher: <SI>\asset-profiling-enrichment\endpoint\.
    #>
    param([string]$Cli, [string]$Configured, [Parameter(Mandatory)][string]$SIRoot, [ValidateSet('internal', 'community')][string]$Flavour = 'internal')
    if ($Cli) { return $Cli }
    if (-not [string]::IsNullOrWhiteSpace($Configured)) { return $Configured }
    $defaultRules = Join-Path $SIRoot 'asset-tagging-rules'
    $defaultEnrich = Join-Path $SIRoot 'asset-profiling-enrichment\endpoint'
    if ($Flavour -eq 'community') { return $defaultEnrich }
    if (Test-Path -LiteralPath $defaultRules) { return $defaultRules }
    if (Test-Path -LiteralPath $defaultEnrich) { return $defaultEnrich }
    $defaultRules
}

function Resolve-SIAssetTaggingFiles {
    <#
        The files a run reads from -SettingsPath. The YAML names: the configured ones, else the engine's own defaults
        (a launcher always sets AssetTagging.locked.yaml / AssetTagging.custom.yaml). Pro: when the settings layer
        materialised the rules (-ProAssetTaggingPath holds AssetTagging.locked.yaml) they are the WHOLE rule set.
        Returns: RulesDir, LockedYamlFile, CustomYamlFile, LegacyYamlFile, LockedPath / CustomPath / LegacyPath and
        whether each exists, FromPro, PreRenamed (the pre-2.2.392 locked name was used), Mode ('locked+custom' |
        'legacy' | 'none'), ConfigCandidates (in the order they are tried) and ConfigPath (the one read, or $null).
    #>
    param([Parameter(Mandatory)][string]$SettingsPath, [Parameter(Mandatory)][string]$SIRoot,
          [string]$LockedYamlFile, [string]$CustomYamlFile, [string]$LegacyYamlFile,
          [string]$ProAssetTaggingPath, [string]$ProConfigRoot)
    if ([string]::IsNullOrWhiteSpace($LockedYamlFile)) { $LockedYamlFile = 'SecurityInsight_CriticalAssetTagging_Locked.yaml' }
    if ([string]::IsNullOrWhiteSpace($CustomYamlFile)) { $CustomYamlFile = 'SecurityInsight_CriticalAssetTagging_Custom.yaml' }
    if ([string]::IsNullOrWhiteSpace($LegacyYamlFile)) { $LegacyYamlFile = 'CriticalAssetTagging.yaml' }
    $configuredLocked = $LockedYamlFile
    $fromPro = $false
    $taggingRulesDir = $SettingsPath
    if (-not [string]::IsNullOrWhiteSpace($ProAssetTaggingPath) -and (Test-Path -LiteralPath (Join-Path $ProAssetTaggingPath 'AssetTagging.locked.yaml'))) {
        $taggingRulesDir = $ProAssetTaggingPath
        $LockedYamlFile  = 'AssetTagging.locked.yaml'
        $CustomYamlFile  = 'AssetTagging.custom.yaml'
        $fromPro = $true
    }
    $lockedPath = Join-Path $taggingRulesDir $LockedYamlFile
    $customPath = Join-Path $taggingRulesDir $CustomYamlFile
    $legacyPath = Join-Path $taggingRulesDir $LegacyYamlFile
    $lockedExists = Test-Path -LiteralPath $lockedPath
    $customExists = Test-Path -LiteralPath $customPath
    $legacyExists = Test-Path -LiteralPath $legacyPath
    # v2.2.393 back-compat: 'AssetTagging.AutoExclude.locked.yaml' (the name before the v2.2.392 rename), in SettingsPath.
    $preRenamed = $false
    if (-not $lockedExists) {
        $preRenamedLocked = Join-Path $SettingsPath 'AssetTagging.AutoExclude.locked.yaml'
        if (Test-Path -LiteralPath $preRenamedLocked) {
            $lockedPath = $preRenamedLocked
            $LockedYamlFile = 'AssetTagging.AutoExclude.locked.yaml'
            $lockedExists = $true
            $preRenamed = $true
        }
    }
    $mode = if ($lockedExists -or $customExists) { 'locked+custom' } elseif ($legacyExists) { 'legacy' } else { 'none' }
    # asset-tagging.config.json: Pro's materialised copy first, then config\ under the solution root, then SettingsPath.
    $candidateConfigPaths = @(
        $(if (-not [string]::IsNullOrWhiteSpace($ProConfigRoot)) { Join-Path $ProConfigRoot 'asset-tagging.config.json' }),
        (Join-Path $SIRoot 'config\asset-tagging.config.json'),
        (Join-Path $SettingsPath 'asset-tagging.config.json')
    ) | Where-Object { $_ }
    $taggingConfigPath = $null
    foreach ($cand in @($candidateConfigPaths)) {
        if (Test-Path -LiteralPath $cand) { $taggingConfigPath = $cand; break }
    }
    [pscustomobject]@{
        RulesDir = $taggingRulesDir; FromPro = $fromPro; PreRenamed = $preRenamed; ConfiguredLockedYamlFile = $configuredLocked
        LockedYamlFile = $LockedYamlFile; CustomYamlFile = $CustomYamlFile; LegacyYamlFile = $LegacyYamlFile
        LockedPath = $lockedPath; CustomPath = $customPath; LegacyPath = $legacyPath
        LockedExists = $lockedExists; CustomExists = $customExists; LegacyExists = $legacyExists
        Mode = $mode; ConfigCandidates = @($candidateConfigPaths); ConfigPath = $taggingConfigPath
    }
}

# =====================================================================================================================
#  THE RUN MODE of the Community server launcher (launcher\asset-tagging\launcher.community-vm.ps1)
#  Operator decision 2026-10-07: asset tagging is REPORT ONLY by default -- as the Pro container job already is. Writing
#  is asked for explicitly: -Apply on the run, or $global:SI_AssetTagging_Apply = $true in the configuration.
# =====================================================================================================================
function ConvertTo-SIAssetTaggingBool {
    <# PURE. $true / 'true' / '1' / 'yes' / 'on' / '$true' -> $true; anything else (null, empty, false, 0 ...) -> $false. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [System.Management.Automation.SwitchParameter]) { return $Value.IsPresent }
    return ("$Value".Trim().Trim('$').ToLowerInvariant() -in @('true', '1', 'yes', 'on'))
}

function Resolve-SIAssetTaggingRunMode {
    <#
        PURE. Does this Community asset-tagging run WRITE tags? First match wins:
          1. -WhatIfMode given on this run             -> report only   (Source 'switch-whatif'; it also wins over -Apply)
          2. -Apply given on this run                  -> write         (Source 'switch-apply')
          3. WhatIfMode true in the configuration      -> report only   (Source 'config-whatif'; what it always meant here)
          4. SI_AssetTagging_Apply true in the config  -> write         (Source 'setting')
          5. nothing asked for                         -> report only   (Source 'default')
        A WhatIfMode = $false in the configuration is NOT a request to write (it was the old default, copied into many
        configurations); only -Apply or SI_AssetTagging_Apply writes.
        ABOVE ALL (#643, owner 2026-10-13: "tagging must be disabled by default. customer must enable it in settings"): a run
        WRITES only when the customer setting "Asset tagging" (SI_AssetTagging_Enabled, -EnabledSetting) is on. Off (the
        shipped default) = report only whatever -Apply / SI_AssetTagging_Apply say (Source 'tagging-off').
        Returns @{ Apply; WhatIfMode; Source }.
    #>
    param([bool]$ApplySwitch = $false, [bool]$WhatIfSwitch = $false, [AllowNull()]$ApplySetting, [AllowNull()]$ConfigWhatIf, [AllowNull()]$EnabledSetting)
    $r = { param($apply, $src) [pscustomobject]@{ Apply = [bool]$apply; WhatIfMode = -not [bool]$apply; Source = $src } }
    if ($WhatIfSwitch) { return (& $r $false 'switch-whatif') }
    $on = ConvertTo-SIAssetTaggingBool $EnabledSetting
    if ($ApplySwitch)  { if (-not $on) { return (& $r $false 'tagging-off') }; return (& $r $true 'switch-apply') }
    if (ConvertTo-SIAssetTaggingBool $ConfigWhatIf) { return (& $r $false 'config-whatif') }
    if (ConvertTo-SIAssetTaggingBool $ApplySetting) { if (-not $on) { return (& $r $false 'tagging-off') }; return (& $r $true 'setting') }
    & $r $false 'default'
}

function Get-SIAssetTaggingRunModeLine {
    <# PURE. The one line every run prints about its mode. #>
    param([Parameter(Mandatory)]$Mode)
    if ($Mode.Apply) {
        $why = if ($Mode.Source -eq 'switch-apply') { 'the -Apply switch' } else { '$global:SI_AssetTagging_Apply = $true' }
        return ('WRITES ON -- this run sets tags in Defender, Azure and Entra ({0}).' -f $why)
    }
    switch ($Mode.Source) {
        'switch-whatif' { return 'REPORT ONLY -- nothing is changed (-WhatIfMode). Every tag the rules would set is logged.' }
        'config-whatif' { return 'REPORT ONLY -- nothing is changed (WhatIfMode = $true in your configuration). Every tag the rules would set is logged.' }
        'tagging-off'   { return 'REPORT ONLY -- asset tagging is OFF (the setting "Asset tagging", SI_AssetTagging_Enabled, is not on): nothing is changed. To use it: set $global:SI_AssetTagging_Enabled = $true, then -Apply or $global:SI_AssetTagging_Apply = $true to write.' }
        default         { return 'REPORT ONLY -- nothing is changed; every tag the rules would set is logged. To write the tags: run with -Apply, or set $global:SI_AssetTagging_Apply = $true in config\SecurityInsight.custom.ps1.' }
    }
}

function Get-SIAssetTaggingReportOnlyNoticeLines {
    <# PURE. The one-time notice when the DEFAULT made a run report only. -RanBefore: this install ran asset tagging
       before (it wrote tags then, unless it was started with -WhatIfMode). #>
    param([bool]$RanBefore = $false)
    if ($RanBefore) {
        return @(
            'Asset tagging is now REPORT ONLY by default. Earlier versions wrote tags whenever the script ran without -WhatIfMode; from this version a run writes only when you ask for it.',
            ' - This run changed nothing. It logged every tag the rules would set (console, run log and SI_AssetTagActivity_CL).',
            ' - To write tags again on every run: set $global:SI_AssetTagging_Apply = $true in config\SecurityInsight.custom.ps1. For one run: add -Apply.',
            ' - This notice is shown once.'
        )
    }
    @(
        'Asset tagging is REPORT ONLY by default: it logs every tag the rules would set and changes nothing.',
        ' - To write tags: set $global:SI_AssetTagging_Apply = $true in config\SecurityInsight.custom.ps1, or add -Apply to one run. Its identity also needs the write grants (setup\Grant-SIIdentity.ps1 -Tagging).',
        ' - This notice is shown once.'
    )
}

function Test-SIAssetTaggingRanBefore {
    <# Did this install run asset tagging before this run? Its run logs (asset-tagging_*.log in -LogDir) older than
       -Before, other than -ExcludePath (this run's own log). Never throws. #>
    param([string]$LogDir, [datetime]$Before = [datetime]::Now, [string]$ExcludePath)
    try {
        if (-not $LogDir -or -not (Test-Path -LiteralPath $LogDir)) { return $false }
        $old = @(Get-ChildItem -LiteralPath $LogDir -Filter 'asset-tagging_*.log' -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -lt $Before -and (-not $ExcludePath -or $_.FullName -ne $ExcludePath) })
        return ($old.Count -gt 0)
    } catch { return $false }
}

function Invoke-SIAssetTaggingReportOnlyNotice {
    <#
        Shows the report-only notice ONCE per install (notice id 'asset-tagging-report-only' in the install state the
        first-run layer keeps, engine\_shared\SI-FirstRun.ps1: logs\state\install-state.json). Only when the DEFAULT made
        this run report only -- a run that asked for report only, or for writing, is not told. -Store: as
        Read-SIInstallState (file | memory). -RanBefore: { } -> bool, evaluated only when the notice is due.
        Returns @{ Shown; RanBefore; Lines }. Never throws; an unreadable state shows nothing (never on every run).
    #>
    param([Parameter(Mandatory)]$Mode, [Parameter(Mandatory)][hashtable]$Store, [scriptblock]$RanBefore)
    $res = [pscustomobject]@{ Shown = $false; RanBefore = $false; Lines = @() }
    try {
        if ($Mode.Apply -or $Mode.Source -ne 'default') { return $res }
        if (-not (Get-Command -Name Read-SIInstallState -ErrorAction SilentlyContinue)) { return $res }
        $id = 'asset-tagging-report-only'
        $read = Read-SIInstallState -Store $Store
        if (-not $read.Ok) { return $res }
        $state = $read.State
        if ($state -and -not (Test-SINoticeDue -State $state -Id $id)) { return $res }
        $before = $false
        if ($RanBefore) { try { $before = [bool](& $RanBefore) } catch { $before = $false } }
        if (-not $state) {
            $ev = if ($before) { @('earlier-asset-tagging-runs') } else { @() }
            $state = New-SIInstallState -Origin $(if ($before) { 'upgraded' } else { 'fresh' }) -Evidence $ev -Version ''
        }
        $lines = @(Get-SIAssetTaggingReportOnlyNoticeLines -RanBefore $before)
        Write-SINoticeLines -Lines $lines
        Add-SINoticeShown -State $state -Id $id
        $null = Save-SIInstallState -Store $Store -State $state
        $res.Shown = $true; $res.RanBefore = $before; $res.Lines = $lines
    } catch { Write-Verbose ('asset-tagging notice skipped: {0}' -f $_.Exception.Message) }
    $res
}
