#Requires -Version 5.1
<#
.SYNOPSIS
    Layered config loader for AutomateIT launchers.

.DESCRIPTION
    Dot-sources the customer-tunable config layers in the right order so
    the launcher template makes one call:

        . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
        Initialize-LauncherConfig `
            -Solution 'SecurityInsight' `
            -Engine   'SecurityInsight_RiskAnalysis' `
            -LauncherDir $PSScriptRoot `
            -RepoRoot $InstallPath `
            -Mode 'community'

    Layer order (each layer's $global:* override the previous):

      0. <RepoRoot>/SOLUTIONS/<Solution>/LAUNCHERS/_lib/<Solution>.shared-defaults.ps1  (us, ships, solution-wide)
      1. <LauncherDir>/LauncherConfig.defaults.ps1                                  (us, ships, per-engine)
      2. <RepoRoot>/SOLUTIONS/PlatformConfiguration/CUSTOMDATA/platform-defaults.ps1 (customer, internal only)
      3. <RepoRoot>/SOLUTIONS/<Solution>/CUSTOMDATA/<Solution>.custom.ps1            (customer, solution-wide)
      4. <LauncherDir>/LauncherConfig.custom.ps1  OR  LauncherConfig.ps1 (legacy)    (customer, per-engine)
      5. CLI args                                                                    (applied later in the launcher)

    Layer 0 (new): ships solution-wide shared defaults that apply to every
    engine in the solution (e.g. canonical DCE / Workspace / DCR names).
    Optional -- launcher still works if the file is absent.

    Layer 1 must always exist (shipped). Layers 2-4 are optional unless
    -RequireCustom is passed -- which community-vm launchers do, because the
    customer's SPN/MI auth lives in layer 4 there. community-azure /
    internal-vm / internal-azure all source auth from elsewhere (App Settings
    + KV / Initialize-PlatformAutomationFramework), so layer 4 is optional.

.NOTES
    Function     : Initialize-LauncherConfig
    Solution     : All
    Developed by : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

function Initialize-LauncherConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$LauncherDir,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][ValidateSet('community','internal')][string]$Mode,
        [string]$CustomConfigPath,
        [switch]$RequireCustom
    )

    function _CfgStep ([string]$m) { Write-Host "[STEP]  $m" -ForegroundColor Cyan }
    function _CfgOk   ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green }
    function _CfgInfo ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Gray }

    # Customer-owned config files (layers 3 + 4) are commonly created by
    # downloading from the Setup Configurator -> Windows stamps them with
    # Mark-of-the-Web. Dot-sourcing a MOTW-flagged script pops a blocking
    # "Security warning" dialog. Unblock-File strips the Zone.Identifier
    # ADS silently and is a no-op on files that were never flagged, so it's
    # safe to call unconditionally on files WE would otherwise dot-source.
    function _CfgUnblock ([string]$p) {
        if (-not $p) { return }
        if (-not (Test-Path -LiteralPath $p)) { return }
        try { Unblock-File -LiteralPath $p -ErrorAction SilentlyContinue } catch { }
    }

    # ---- Config-snapshot helpers (written as DATA\LOGS\config-*.log at the end) ----
    # Snapshots all SI-related $global:* variables so we can diff them between
    # layers and attribute each variable's final value to the layer that set
    # it. Names matching secret-bearing patterns are redacted in the log.
    $script:_CfgSnapBefore   = @{}
    $script:_CfgProvenance   = [ordered]@{}    # name -> @{ Value; Source; Path }  (last-touching layer; displayed in per-layer section)
    $script:_CfgHistory      = [ordered]@{}    # name -> List[{Layer;Value;Path}] (all touches; displayed in change history + aggregated summary)
    $script:_CfgLayerTrail   = [System.Collections.Generic.List[string]]::new()

    # Denylist of PS built-in / session globals we DON'T want in the snapshot.
    # Everything else is captured so the snapshot answers "where is $global:Foo
    # actually set?" -- including values that leaked in from $PROFILE, a prior
    # launcher invocation in the same session, launcher.override.ps1, or a
    # parent script.
    $script:_CfgBuiltinNames = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'Host','PSCulture','PSUICulture','PSCommandPath','PSScriptRoot',
            'PSBoundParameters','PSCmdlet','PSItem','PSHome','PSVersionTable',
            'PSDefaultParameterValues','PSEmailServer','PSSessionApplicationName',
            'PSSessionConfigurationName','PSSessionOption','PSSenderInfo','PSStyle',
            'PWD','HOME','true','false','null','Args','MyInvocation',
            'ErrorActionPreference','DebugPreference','VerbosePreference',
            'WarningPreference','InformationPreference','ConfirmPreference',
            'WhatIfPreference','ProgressPreference','ErrorView',
            'Error','LASTEXITCODE','Matches','foreach','switch','input','_',
            'StackTrace','NestedPromptLevel','PID','Profile','ShellId',
            'OutputEncoding','ExecutionContext','ConsoleFileName','OFS',
            'EnabledExperimentalFeatures','FormatEnumerationLimit',
            'MaximumAliasCount','MaximumDriveCount','MaximumErrorCount',
            'MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount',
            'IsCoreCLR','IsLinux','IsMacOS','IsWindows','true','false','null'
        ),
        [System.StringComparer]::OrdinalIgnoreCase
    )

    function _CfgGatherGlobals {
        $out = @{}
        foreach ($v in (Get-Variable -Scope Global -ErrorAction SilentlyContinue)) {
            if ($script:_CfgBuiltinNames.Contains($v.Name)) { continue }
            # Also skip the initializer's own private script-scope state.
            if ($v.Name -like '_Cfg*')       { continue }
            # Function items and scriptblocks leak into Get-Variable on older PS.
            if ($v.Value -is [System.Management.Automation.ScriptBlock]) { continue }
            $out[$v.Name] = $v.Value
        }
        return $out
    }

    function _CfgValuesDiffer($a, $b) {
        if ($null -eq $a -and $null -eq $b) { return $false }
        if ($null -eq $a -or  $null -eq $b) { return $true  }
        try { return (([string]$a) -ne ([string]$b)) } catch { return $true }
    }

    # AST-extract every '$global:Foo = ...' assignment in a layer file.
    # Complements value-diff: catches literal assignments even when the value
    # matches what an earlier layer already set (no effective change, but the
    # layer did "touch" the variable -- relevant for troubleshooting
    # "why did my Layer 5 override not take effect?" scenarios).
    function _CfgExtractAssignedGlobalNames {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path))      { return @() }
        if (-not (Test-Path -LiteralPath $Path))      { return @() }
        try {
            $errs = $null; $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
            if (-not $ast) { return @() }
            $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($node in $ast.FindAll({
                param($n)
                if ($n -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { return $false }
                if ($n.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $false }
                return ($n.Left.VariablePath.UserPath -like 'global:*')
            }, $true)) {
                $u = $node.Left.VariablePath.UserPath
                if ($u -match '^global:(.+)$') { [void]$names.Add($Matches[1]) }
            }
            return @($names)
        } catch {
            return @()
        }
    }

    function _CfgRecordLayer ([string]$LayerLabel, [string]$Path, [bool]$Loaded) {
        $status = if ($Loaded) { 'loaded' } else { 'absent' }
        $trailLine = ("{0,-40}  {1,-7}  {2}" -f $LayerLabel, $status, $Path)
        $script:_CfgLayerTrail.Add($trailLine) | Out-Null
        if (-not $Loaded) { return }
        $after = _CfgGatherGlobals

        # Union: AST-assigned names (from the layer's .ps1 file) + value-diff
        # names (from comparing snapshots before/after the layer's load).
        # AST catches literal `$global:Foo = x` even if x equals the prior value;
        # diff catches dynamic sets (Set-Variable, function side-effects).
        $astAssigned = _CfgExtractAssignedGlobalNames -Path $Path
        $touched = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $astAssigned) { [void]$touched.Add($n) }
        foreach ($n in $after.Keys) {
            $hadBefore = $script:_CfgSnapBefore.ContainsKey($n)
            $oldVal = if ($hadBefore) { $script:_CfgSnapBefore[$n] } else { $null }
            if (-not $hadBefore -or (_CfgValuesDiffer $oldVal $after[$n])) {
                [void]$touched.Add($n)
            }
        }

        foreach ($n in $touched) {
            # Store the value the layer left this variable at (post-load
            # snapshot). If the name was only in AST but never actually
            # resolved (unlikely), fall back to $null.
            $val = if ($after.ContainsKey($n)) { $after[$n] } else { $null }
            $script:_CfgProvenance[$n] = [ordered]@{ Value = $val; Source = $LayerLabel; Path = $Path }
            if (-not $script:_CfgHistory.Contains($n)) {
                $script:_CfgHistory[$n] = [System.Collections.Generic.List[object]]::new()
            }
            [void]$script:_CfgHistory[$n].Add([pscustomobject]@{
                Layer = $LayerLabel
                Value = $val
                Path  = $Path
            })
        }
        $script:_CfgSnapBefore = $after
    }

    function _CfgFormatValue ([string]$Name, $Value) {
        # Redact anything whose NAME matches a secret-bearing pattern.
        if ($Name -match '(?i)Secret|Password|Pwd|ApiKey|Api_Key|AccessKey|AccessSecret|Token(?!Lifetime)|ClientSecret|Cert(?:ificate)?Thumbprint') {
            $len = if ($Value -is [string]) { $Value.Length } elseif ($null -eq $Value) { 0 } else { ("$Value").Length }
            return "[REDACTED (len=$len)]"
        }
        if ($Value -is [System.Management.Automation.PSCredential]) {
            return "[REDACTED PSCredential; UserName=$($Value.UserName)]"
        }
        if ($Value -is [System.Security.SecureString]) {
            return '[REDACTED SecureString]'
        }
        if ($null -eq $Value) { return '$null' }
        if ($Value -is [bool])  { return ('${0}' -f $Value.ToString().ToLower()) }
        if ($Value -is [array] -or $Value -is [System.Collections.IList]) {
            $parts = @()
            foreach ($item in $Value) { $parts += "'$item'" }
            return "@(" + ($parts -join ", ") + ")"
        }
        if ($Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
            return "@{ " + (($Value.Keys | ForEach-Object { "$_ = ..." }) -join "; ") + " }"
        }
        return [string]$Value
    }

    function _CfgWriteSnapshotAndPrune {
        param(
            [Parameter(Mandatory)][string]$RepoRoot,
            [Parameter(Mandatory)][string]$Solution,
            [Parameter(Mandatory)][string]$Engine,
            [int]$RetentionDays = 7
        )
        # Resolve the right DATA\LOGS folder:
        #   Monorepo layout (internal deploys): $RepoRoot is C:\SCRIPTS\AutomateIT
        #     and the solution DATA lives under SOLUTIONS\<Solution>\DATA.
        #   Community layout: $RepoRoot IS the solution folder, so DATA lives
        #     directly under $RepoRoot.
        # Try solution-qualified path first; fall back to repo-root DATA.
        $solutionData = Join-Path $RepoRoot (Join-Path 'SOLUTIONS' (Join-Path $Solution 'DATA'))
        if (Test-Path -LiteralPath (Split-Path -Parent $solutionData)) {
            $logDir = Join-Path $solutionData 'LOGS'
        } else {
            $logDir = Join-Path $RepoRoot 'DATA\LOGS'
        }
        try {
            if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
        } catch {
            _CfgInfo ("config snapshot: cannot create {0} ({1}) -- skipping" -f $logDir, $_.Exception.Message)
            return
        }

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $device = $env:COMPUTERNAME
        $logFile = Join-Path $logDir ("config-{0}-{1}-{2}.log" -f $Engine, $stamp, $device)

        $out = New-Object System.Text.StringBuilder
        [void]$out.AppendLine('SecurityInsight -- Launcher Config Snapshot')
        [void]$out.AppendLine(('=' * 100))
        [void]$out.AppendLine(('Engine       : {0}' -f $Engine))
        [void]$out.AppendLine(('Device       : {0}' -f $device))
        [void]$out.AppendLine(('User         : {0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
        [void]$out.AppendLine(('Timestamp    : {0}' -f (Get-Date -Format 's')))
        [void]$out.AppendLine(('Install root : {0}' -f $RepoRoot))
        [void]$out.AppendLine(('PS version   : {0}' -f $PSVersionTable.PSVersion))
        [void]$out.AppendLine('')
        [void]$out.AppendLine('Layer load trail:')
        [void]$out.AppendLine(('-' * 100))
        foreach ($line in $script:_CfgLayerTrail) { [void]$out.AppendLine($line) }
        [void]$out.AppendLine('')
        [void]$out.AppendLine(('Effective configuration ({0} variables, grouped by source layer):' -f $script:_CfgProvenance.Count))
        [void]$out.AppendLine(('-' * 100))

        # SECTION 1 -- per-layer grouping: every variable the layer TOUCHED
        # (assigned explicitly OR changed value), grouped under the last-
        # touching layer. Shows what each layer contributed to the final
        # effective config.
        $layerOrder = @(
            'Layer 0 - pre-existing (session / profile / prior run)',
            'Layer 1 - platform-defaults (internal)',
            'Layer 2 - shared-defaults',
            'Layer 3 - SecurityInsight.custom',
            'Layer 4 - LauncherConfig.defaults',
            'Layer 5 - LauncherConfig.custom',
            'Layer 6 - derived'
        )
        foreach ($layer in $layerOrder) {
            $keys = @($script:_CfgProvenance.Keys | Where-Object { $script:_CfgProvenance[$_].Source -eq $layer } | Sort-Object)
            if ($keys.Count -eq 0) { continue }
            [void]$out.AppendLine('')
            [void]$out.AppendLine(('[{0}]   {1} variable(s)' -f $layer, $keys.Count))
            $src = $script:_CfgProvenance[$keys[0]].Path
            if (-not [string]::IsNullOrWhiteSpace($src)) {
                [void]$out.AppendLine(('  (source: {0})' -f $src))
            }
            foreach ($n in $keys) {
                $formatted = _CfgFormatValue $n $script:_CfgProvenance[$n].Value
                [void]$out.AppendLine(('  $global:{0,-45} = {1}' -f $n, $formatted))
            }
        }

        # SECTION 2 -- value-change history: every variable touched by MORE
        # than one layer, showing the full chain so the reader can see
        # exactly which file changed the value (and when a later-layer
        # override was a no-op because the value matched an earlier layer).
        $changed = @($script:_CfgHistory.Keys | Where-Object { $script:_CfgHistory[$_].Count -gt 1 } | Sort-Object)
        if ($changed.Count -gt 0) {
            [void]$out.AppendLine('')
            [void]$out.AppendLine(('=' * 100))
            [void]$out.AppendLine(('Value change history ({0} variable(s) touched by more than one layer):' -f $changed.Count))
            [void]$out.AppendLine(('-' * 100))
            foreach ($n in $changed) {
                $hist = $script:_CfgHistory[$n]
                [void]$out.AppendLine('')
                [void]$out.AppendLine(('  $global:{0}' -f $n))
                for ($i = 0; $i -lt $hist.Count; $i++) {
                    $step = $hist[$i]
                    $prev = if ($i -gt 0) { $hist[$i-1].Value } else { $null }
                    $changedMark = if ($i -gt 0 -and -not (_CfgValuesDiffer $prev $step.Value)) { '  [no-op: value unchanged by this layer]' } else { '' }
                    $formatted = _CfgFormatValue $n $step.Value
                    [void]$out.AppendLine(('    [{0}]  = {1}{2}' -f $step.Layer, $formatted, $changedMark))
                    if (-not [string]::IsNullOrWhiteSpace($step.Path)) {
                        [void]$out.AppendLine(('        file: {0}' -f $step.Path))
                    }
                }
            }
        }

        # SECTION 3 -- aggregated effective configuration (alphabetical).
        # Flat "what the engine actually sees" view: every variable, sorted
        # by name, with final value + winning layer + source file path.
        [void]$out.AppendLine('')
        [void]$out.AppendLine(('=' * 100))
        [void]$out.AppendLine(('Aggregated effective configuration ({0} variable(s), alphabetical):' -f $script:_CfgProvenance.Count))
        [void]$out.AppendLine(('-' * 100))
        foreach ($n in @($script:_CfgProvenance.Keys | Sort-Object)) {
            $entry = $script:_CfgProvenance[$n]
            $formatted = _CfgFormatValue $n $entry.Value
            [void]$out.AppendLine(('  $global:{0,-45} = {1}' -f $n, $formatted))
            [void]$out.AppendLine(('      from: {0}' -f $entry.Source))
            if (-not [string]::IsNullOrWhiteSpace($entry.Path)) {
                [void]$out.AppendLine(('      file: {0}' -f $entry.Path))
            }
        }

        [void]$out.AppendLine('')
        [void]$out.AppendLine(('=' * 100))
        [void]$out.AppendLine('(Values for variables whose names match secret-bearing patterns are redacted as [REDACTED (len=N)] so presence can still be verified.)')

        try {
            Set-Content -LiteralPath $logFile -Value $out.ToString() -Encoding UTF8 -NoNewline
            _CfgInfo ("config snapshot: {0}" -f $logFile)
        } catch {
            _CfgInfo ("config snapshot: failed to write {0} ({1})" -f $logFile, $_.Exception.Message)
        }

        # Prune old config-*.log files > RetentionDays.
        try {
            $cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
            $toDelete = Get-ChildItem -LiteralPath $logDir -Filter 'config-*.log' -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt $cutoff }
            foreach ($f in $toDelete) {
                try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { }
            }
            if ($toDelete -and $toDelete.Count -gt 0) {
                _CfgInfo ("config snapshot: pruned {0} log(s) older than {1} days" -f $toDelete.Count, $RetentionDays)
            }
        } catch { }
    }

    # ---- Layer 0: <Solution>.shared-defaults.ps1 (solution-wide shared baseline, ours) ----
    # Optional. The file sits in _lib/, which is always a SIBLING of the launcher
    # folder in both layouts:
    #   monorepo:  SOLUTIONS/<Solution>/LAUNCHERS/_lib/<Solution>.shared-defaults.ps1
    #   community: launchers/_lib/<Solution>.shared-defaults.ps1
    # Resolve it relative to $LauncherDir so both layouts work.
    # Layered precedence (later loads override earlier; closest = highest):
    #   Layer 1  platform-defaults        (tenant scope, internal mode only)
    #   Layer 2  shared-defaults          (solution scope, ours)
    #   Layer 3  <Solution>.custom        (solution scope, customer)
    #   Layer 4  LauncherConfig.defaults  (engine scope, ours)
    #   Layer 5  LauncherConfig.custom    (engine scope, customer, closest -- WINS)
    # "Start from top, then closer wins" -- broadest tenant baseline first,
    # closest per-engine customer override last.

    # ---- Layer 0: pre-existing globals (inherited from session, $PROFILE,
    #              prior launcher run, launcher.override.ps1, parent script) -
    # Captured BEFORE any layer loads so the snapshot answers "where is $X set?"
    # even when the answer is "before the initializer ever ran".
    $script:_CfgSnapBefore = @{}
    $__preExisting = _CfgGatherGlobals
    _CfgStep "Layer 0/5: pre-existing globals (inherited from session)"
    $__preSrc = 'Layer 0 - pre-existing (session / profile / prior run)'
    $__prePath = '(set before initializer ran -- check $PROFILE, prior launcher run, launcher.override.ps1, parent script)'
    if ($__preExisting.Count -gt 0) {
        foreach ($n in $__preExisting.Keys) {
            $script:_CfgProvenance[$n] = [ordered]@{ Value = $__preExisting[$n]; Source = $__preSrc; Path = $__prePath }
            if (-not $script:_CfgHistory.Contains($n)) {
                $script:_CfgHistory[$n] = [System.Collections.Generic.List[object]]::new()
            }
            [void]$script:_CfgHistory[$n].Add([pscustomobject]@{
                Layer = $__preSrc
                Value = $__preExisting[$n]
                Path  = $__prePath
            })
        }
        $trailLine = ("{0,-40}  {1,-7}  {2}" -f 'Layer 0 - pre-existing', 'loaded', ("{0} globals inherited from session" -f $__preExisting.Count))
        $script:_CfgLayerTrail.Add($trailLine) | Out-Null
        _CfgInfo ("{0} globals were already set before Layer 1 (captured in snapshot under 'Layer 0 - pre-existing')" -f $__preExisting.Count)
    } else {
        $trailLine = ("{0,-40}  {1,-7}  {2}" -f 'Layer 0 - pre-existing', 'empty', '(none)')
        $script:_CfgLayerTrail.Add($trailLine) | Out-Null
        _CfgInfo "no pre-existing globals at initializer entry -- session is clean"
    }
    $script:_CfgSnapBefore = $__preExisting

    # ---- Layer 1: platform-defaults.ps1 (tenant, internal mode only) ---------
    $platformPath = Join-Path $RepoRoot 'SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.ps1'
    _CfgStep "Layer 1/5: platform-defaults.ps1 (tenant -- internal mode only)"
    if ($Mode -eq 'internal') {
        if (Test-Path -LiteralPath $platformPath) {
            . $platformPath
            _CfgOk "loaded"
            _CfgRecordLayer 'Layer 1 - platform-defaults (internal)' $platformPath $true
        } else {
            _CfgInfo "absent ($platformPath) -- skipping"
            _CfgRecordLayer 'Layer 1 - platform-defaults (internal)' $platformPath $false
        }
    } else {
        _CfgInfo "skipped (community mode; platform-defaults only applies in internal / AF deployments)"
        _CfgRecordLayer 'Layer 1 - platform-defaults (internal)' $platformPath $false
    }

    # ---- Layer 2: <Solution>.shared-defaults.ps1 (solution baseline, ours) ---
    $sharedPath = Join-Path (Split-Path -Parent $LauncherDir) ("_lib\{0}.shared-defaults.ps1" -f $Solution)
    _CfgStep "Layer 2/5: $Solution.shared-defaults.ps1 (solution baseline, ours)"
    if (Test-Path -LiteralPath $sharedPath) {
        . $sharedPath
        _CfgOk "loaded ($sharedPath)"
        _CfgRecordLayer 'Layer 2 - shared-defaults' $sharedPath $true
    } else {
        _CfgInfo "absent ($sharedPath) -- skipping"
        _CfgRecordLayer 'Layer 2 - shared-defaults' $sharedPath $false
    }

    # ---- Layer 3: <Solution>.custom.ps1 (solution-wide customer overrides) ---
    $solutionCustomPath = Join-Path $RepoRoot ("SOLUTIONS\{0}\CUSTOMDATA\{0}.custom.ps1" -f $Solution)
    _CfgStep "Layer 3/5: $Solution.custom.ps1 (solution-wide customer overrides)"
    if (Test-Path -LiteralPath $solutionCustomPath) {
        _CfgUnblock $solutionCustomPath
        . $solutionCustomPath
        _CfgOk "loaded"
        _CfgRecordLayer 'Layer 3 - SecurityInsight.custom' $solutionCustomPath $true
    } else {
        _CfgInfo "absent ($solutionCustomPath) -- skipping"
        _CfgRecordLayer 'Layer 3 - SecurityInsight.custom' $solutionCustomPath $false
    }

    # ---- Layer 4: LauncherConfig.defaults.ps1 (engine baseline, ours) --------
    # Optional. Some engines (CriticalAssetTagging family, Setup-CSA, Step2/3)
    # don't ship a per-engine defaults file because Layers 1-3 + Layer 5
    # customer overrides cover everything. Absent = info, not error.
    $defaultsPath = Join-Path $LauncherDir 'LauncherConfig.defaults.ps1'
    _CfgStep "Layer 4/5: LauncherConfig.defaults.ps1 (engine baseline, ours)"
    if (Test-Path -LiteralPath $defaultsPath) {
        . $defaultsPath
        _CfgOk "loaded"
        _CfgRecordLayer 'Layer 4 - LauncherConfig.defaults' $defaultsPath $true
    } else {
        _CfgInfo "absent ($defaultsPath) -- skipping (engine has no shipped baseline)"
        _CfgRecordLayer 'Layer 4 - LauncherConfig.defaults' $defaultsPath $false
    }

    # ---- Layer 5: LauncherConfig.custom.ps1 (per-engine customer, CLOSEST) ---
    $explicit = -not [string]::IsNullOrWhiteSpace($CustomConfigPath)
    if ($explicit) {
        $customPath = $CustomConfigPath
    } else {
        $customPath = Join-Path $LauncherDir 'LauncherConfig.custom.ps1'
        if (-not (Test-Path -LiteralPath $customPath)) {
            $legacy = Join-Path $LauncherDir 'LauncherConfig.ps1'
            if (Test-Path -LiteralPath $legacy) {
                $customPath = $legacy
                _CfgInfo "legacy filename 'LauncherConfig.ps1' detected -- consider renaming to 'LauncherConfig.custom.ps1' to match the layered model"
            }
        }
    }

    _CfgStep "Layer 5/5: LauncherConfig.custom.ps1 (per-engine customer, closest -- wins)"
    if (Test-Path -LiteralPath $customPath) {
        _CfgUnblock $customPath
        . $customPath
        _CfgOk "loaded ($customPath)"
        _CfgRecordLayer 'Layer 5 - LauncherConfig.custom' $customPath $true
    } elseif ($RequireCustom) {
        $expected = Join-Path $LauncherDir 'LauncherConfig.custom.ps1'
        throw @"
Per-engine customer config not found. Looked for:
  $expected
  $(Join-Path $LauncherDir 'LauncherConfig.ps1')   (legacy)

Copy $(Join-Path $LauncherDir 'LauncherConfig.sample.ps1') to LauncherConfig.custom.ps1 in the same folder and fill in your auth values.
"@
    } else {
        _CfgInfo "absent ($customPath) -- skipping (auth comes from elsewhere on this flavour)"
        _CfgRecordLayer 'Layer 5 - LauncherConfig.custom' $customPath $false
    }

    # ---- Derived defaults: run AFTER all 5 layers so late-bound vars resolve ----
    # Platform-defaults (Layer 1, internal only) sets $global:MainLogAnalyticsWorkspaceSubId
    # but doesn't set $global:SubscriptionId. Derive it here so engines that read
    # $global:SubscriptionId don't have to duplicate the fallback logic.
    $__beforeDerived = _CfgGatherGlobals
    if ([string]::IsNullOrWhiteSpace([string]$global:SubscriptionId) -and
        -not [string]::IsNullOrWhiteSpace([string]$global:MainLogAnalyticsWorkspaceSubId)) {
        $global:SubscriptionId = [string]$global:MainLogAnalyticsWorkspaceSubId
        _CfgInfo "derived `$global:SubscriptionId from `$global:MainLogAnalyticsWorkspaceSubId"
    }
    $script:_CfgSnapBefore = $__beforeDerived
    _CfgRecordLayer 'Layer 6 - derived' '(initializer derivation step)' $true

    # ---- Write config snapshot log + prune old logs (7-day retention) --------
    _CfgWriteSnapshotAndPrune -RepoRoot $RepoRoot -Solution $Solution -Engine $Engine -RetentionDays 7
}
