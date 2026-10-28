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
            -Engine   'RiskAnalysis' `
            -LauncherDir $PSScriptRoot `
            -RepoRoot $InstallPath `
            -Mode 'community'

    Layer order (each layer's $global:* override the previous):

      0. <RepoRoot>/SOLUTIONS/<Solution>/LAUNCHERS/_lib/<Solution>.shared-defaults.ps1  (us, ships, solution-wide)
      1. <LauncherDir>/LauncherConfig.defaults.ps1                                  (us, ships, per-engine)
      2. <RepoRoot>/SOLUTIONS/PlatformConfiguration/config/platform-defaults.ps1 (customer, internal only)
      3. <RepoRoot>/SOLUTIONS/<Solution>/config/<Solution>.custom.ps1            (customer, solution-wide)
      4. <LauncherDir>/LauncherConfig.custom.ps1  OR  LauncherConfig.ps1 (legacy)    (customer, per-engine)
      5. CLI args                                                                    (applied later in the launcher)

    Layer 0 (new): ships solution-wide shared defaults that apply to every
    engine in the solution (e.g. canonical DCE / Workspace / DCR names).
    Optional -- launcher still works if the file is absent.

    Layer 1 must always exist (shipped). Layers 2-4 are optional unless
    -RequireCustom is passed -- which community-vm launchers do, because the
    customer's SPN/MI auth lives in layer 4 there. community-azure /
    internal-vm / internal-azure all source auth from elsewhere (App Settings
    + KV / the native platform sign-in), so layer 4 is optional.

.NOTES
    Function     : Initialize-LauncherConfig
    Solution     : All
    Developed by : Morten Knudsen, Microsoft MVP
#>

# #276 -- the first-run-after-upgrade safety layer, shared with the container entry points: the dry-run decision, the
# one-time notices, and Write-SIPowerBIRetiredNotice (#275 G5; it moved there so containers say it too). Loaded at
# file level so the launcher and everything it starts can reach it.
$__siFirstRunLib = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\SI-FirstRun.ps1'
if (Test-Path -LiteralPath $__siFirstRunLib) { . $__siFirstRunLib }
Remove-Variable -Name '__siFirstRunLib' -ErrorAction SilentlyContinue

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

    # Snapshot the four parameters into uniquely-named locals BEFORE any layer
    # files get dot-sourced. The layered config files (shared-defaults, Layer 4
    # solution custom, Layer 5 per-engine custom) all dot-source into THIS scope
    # via `. $path`, so any bare `$Solution = ...` / `$Engine = ...` /
    # `$RepoRoot = ...` / `$LauncherDir = ...` / `$Mode = ...` assignment in
    # those files (i.e. anywhere a customer accidentally drops the `$global:`
    # prefix) silently overwrites OUR function parameters. v2.1.203 fix.
    $__siRepoRoot    = [string]$RepoRoot
    $__siSolution    = [string]$Solution
    $__siEngine      = [string]$Engine
    $__siLauncherDir = [string]$LauncherDir
    $__siMode        = [string]$Mode

    function _CfgStep ([string]$m) { Write-Host "[STEP]  $m" -ForegroundColor Cyan }
    function _CfgOk   ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green }
    function _CfgInfo ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor White }

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
    # launcher invocation in the same session, or a parent script that
    # dot-sourced the launcher.
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

    # Truncate a string to $Max chars, collapsing newlines so the log stays
    # one-line-per-variable. Multi-line values (KQL, hashtable dumps) were the
    # root cause of "impossible to read this" logs before v2.1.154.
    function _CfgTruncate {
        param([string]$S, [int]$Max = 120)
        if ([string]::IsNullOrEmpty($S)) { return $S }
        $orig = $S.Length
        $flat = $S -replace '\r?\n', ' ' -replace '\s+', ' '
        if ($flat.Length -le $Max) { return $flat }
        return ($flat.Substring(0, $Max) + ("... [truncated, {0} total chars]" -f $orig))
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

        # Arrays / lists: show up to 3 items (each item truncated to 80 chars);
        # summarize the remainder as "... [N elements total]". Prevents giant
        # variables like $Exposure_Reports (9 elements × ~25KB of KQL each)
        # from blowing the log out to ~400KB.
        if ($Value -is [array] -or $Value -is [System.Collections.IList]) {
            $items = @($Value)
            $count = $items.Count
            if ($count -eq 0) { return '@()' }
            $maxItems = 3
            $parts = @()
            $shown = [Math]::Min($count, $maxItems)
            for ($i = 0; $i -lt $shown; $i++) {
                $item = $items[$i]
                if ($null -eq $item) { $parts += '$null'; continue }
                if ($item -is [hashtable] -or $item -is [System.Collections.IDictionary]) {
                    $keys = @($item.Keys)
                    $keyPreview = ($keys | Select-Object -First 6) -join ', '
                    if ($keys.Count -gt 6) { $keyPreview += ', ...' }
                    $parts += ("@{{{0} keys: {1}}}" -f $keys.Count, $keyPreview)
                } elseif ($item -is [string]) {
                    $parts += "'" + (_CfgTruncate -S $item -Max 80) + "'"
                } else {
                    $parts += "'" + (_CfgTruncate -S ([string]$item) -Max 80) + "'"
                }
            }
            if ($count -gt $maxItems) {
                return ("@( {0}, ... [{1} elements total] )" -f ($parts -join ', '), $count)
            }
            return ("@( {0} )" -f ($parts -join ', '))
        }

        # Hashtables: up to 5 keys shown with 60-char-truncated values; beyond
        # that, just list the key names so the reader knows what's in there.
        if ($Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
            $keys = @($Value.Keys)
            if ($keys.Count -le 5) {
                $parts = @()
                foreach ($k in $keys) {
                    $v = $Value[$k]
                    if ($null -eq $v) { $parts += ("{0} = `$null" -f $k); continue }
                    if ($v -is [string]) {
                        $parts += ("{0} = '{1}'" -f $k, (_CfgTruncate -S $v -Max 60))
                    } else {
                        $parts += ("{0} = {1}" -f $k, (_CfgTruncate -S ([string]$v) -Max 60))
                    }
                }
                return "@{ " + ($parts -join "; ") + " }"
            }
            $keyPreview = ($keys | Select-Object -First 8) -join ', '
            if ($keys.Count -gt 8) { $keyPreview += ', ...' }
            return ("@{{ {0} keys: {1} }}" -f $keys.Count, $keyPreview)
        }

        # Scalars: flatten + truncate long strings so KQL / JSON blobs don't
        # wrap across 100 lines in the log.
        if ($Value -is [string]) { return _CfgTruncate -S $Value -Max 200 }
        return _CfgTruncate -S ([string]$Value) -Max 200
    }

    function _CfgWriteSnapshotAndPrune {
        param(
            [Parameter(Mandatory)][string]$RepoRoot,
            [Parameter(Mandatory)][string]$Solution,
            [Parameter(Mandatory)][string]$Engine,
            [int]$RetentionDays = 7
        )
        # v2.2.312: write config snapshots into the same `logs\` folder as the
        # run transcripts (Start-LauncherTranscript.ps1). Pre-v2.2.312 dropped
        # them under `data\LOGS\` which (a) was a separate folder operators had
        # to discover and (b) made internal vs community parity awkward
        # (operator: "we don't use \data anymore").
        # Mirror Start-LauncherTranscript's resolution algorithm so both file
        # types always land together.
        $solutionLogs = Join-Path $RepoRoot (Join-Path 'SOLUTIONS' (Join-Path $Solution 'logs'))
        if (Test-Path -LiteralPath (Split-Path -Parent $solutionLogs)) {
            $logDir = $solutionLogs
        } else {
            # Community (flat) layout: $RepoRoot IS the solution folder.
            $logDir = Join-Path $RepoRoot 'logs'
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

        # SECTION 1 -- per-layer grouping.
        # The grouped section iterates this list to bucket variables by source
        # layer. Labels here must match the strings passed to _CfgRecordLayer
        # below -- mismatches silently drop a layer from the grouped output
        # (variables still appear in the alphabetical aggregated section at
        # the bottom).
        $layerOrder = @(
            'Layer 1 - platform sign-in',
            'Layer 1 - platform-defaults (fallback)',
            'Layer 1b - platform-defaults (cross-cutting)',
            'Layer 2 - shared-defaults',
            'Layer 3 - LauncherConfig.defaults',
            'Layer 4 - SecurityInsight.custom',
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

        # SECTION 2 -- aggregated effective configuration (alphabetical).
        # One line per variable: name + winning layer + value.
        [void]$out.AppendLine('')
        [void]$out.AppendLine(('=' * 100))
        [void]$out.AppendLine(('Aggregated effective configuration ({0} variable(s), alphabetical):' -f $script:_CfgProvenance.Count))
        [void]$out.AppendLine(('-' * 100))
        foreach ($n in @($script:_CfgProvenance.Keys | Sort-Object)) {
            $entry = $script:_CfgProvenance[$n]
            $formatted = _CfgFormatValue $n $entry.Value
            $layerShort = ($entry.Source -replace '^Layer (\d+) - ', 'L$1 ')
            [void]$out.AppendLine(('  $global:{0,-45} [{1,-30}]  = {2}' -f $n, $layerShort, $formatted))
        }

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
    #   Layer 3  LauncherConfig.defaults  (engine scope, ours)
    #   Layer 4  <Solution>.custom        (solution scope, customer -- beats the engine baseline, #183)
    #   Layer 5  LauncherConfig.custom    (engine scope, customer, closest -- WINS)
    # "Start from top, then closer wins" -- broadest tenant baseline first,
    # closest per-engine customer override last.

    # Capture the pre-existing global state as the diff baseline for Layer 1
    # onward. We do NOT record pre-existing values in the snapshot -- the user
    # only wants globals that came from one of the 5-6 layered config files,
    # not noise from $PROFILE / prior runs / parent scripts.
    $script:_CfgSnapBefore = _CfgGatherGlobals

    # ---- Layer 1: the platform sign-in (tenant scope, internal mode only) ----
    # An internal install signs in to the platform natively (auth\SI-PlatformConnect.ps1, plain REST, no PowerShell
    # module): it reads bootstrap\platform-config.json, the bootstrap identity (managed identity or certificate) reads
    # the platform Key Vault, and the run signs in as the platform's Modern identity (certificate, else secret). It sets
    # the framework's public globals ($global:Context, $global:HighPriv_Modern_*, $global:KV_HighPriv_* and friends)
    # exactly as the framework's own sign-in did. SOLUTIONS\PlatformConfiguration\config\platform-defaults.ps1 is still
    # supported as the fallback for installs not yet migrated to platform-config.json.
    $platformConfigPath = Join-Path $RepoRoot 'bootstrap\platform-config.json'
    $platformDefaultsPath = Join-Path $RepoRoot 'SOLUTIONS\PlatformConfiguration\config\platform-defaults.ps1'   # v2.2 legacy fallback
    _CfgStep "Layer 1/5: platform sign-in or platform-defaults.ps1 (fallback)"

    # SI_PLATFORM_CONFIG=off: this run must not use the machine's platform configuration (the guided install sets it)
    $platformOff = [string]([Environment]::GetEnvironmentVariable('SI_PLATFORM_CONFIG')) -match '^(?i)(off|0|false|no|disabled)$'
    if ($Mode -eq 'internal' -and $platformOff) {
        _CfgStep 'Layer 1/5: skipped -- SI_PLATFORM_CONFIG=off (this run does not use the machine''s platform configuration)'
    } elseif ($Mode -eq 'internal') {
        if (Test-Path -LiteralPath $platformConfigPath) {
            # the SecurityInsight root is the parent of launcher\ (monorepo: <repo>\SOLUTIONS\SecurityInsight; community: the install)
            $siPlatformConnect = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'auth', 'SI-PlatformConnect.ps1')
            try {
                if (-not (Get-Command -Name Connect-SIPlatform -ErrorAction SilentlyContinue)) {
                    if (-not (Test-Path -LiteralPath $siPlatformConnect)) { throw ("the platform sign-in helper is missing at {0}" -f $siPlatformConnect) }
                    . $siPlatformConnect
                }
                $null = Connect-SIPlatform -ConfigPath $platformConfigPath -ErrorAction Stop
                _CfgOk ("platform sign-in succeeded (Modern AppId {0}, KV {1}, {2})" -f $global:HighPriv_Modern_ApplicationID_Azure, $global:KV_HighPriv_KeyVaultName, $global:HighPriv_Modern_AuthMethod)
                _CfgRecordLayer 'Layer 1 - platform sign-in' $platformConfigPath $true
                # ALSO dot-source platform-defaults.ps1 if it exists -- it holds cross-cutting $global:* (SMTP / Mail /
                # AD / LA) which the platform sign-in does NOT set. v2.2.183: both must load.
                if (Test-Path -LiteralPath $platformDefaultsPath) {
                    . $platformDefaultsPath
                    _CfgOk "also loaded platform-defaults.ps1 ($platformDefaultsPath) for cross-cutting `$global:* (SMTP / Mail / AD / LA)"
                    _CfgRecordLayer 'Layer 1b - platform-defaults (cross-cutting)' $platformDefaultsPath $true
                }
            } catch {
                _CfgInfo ("platform sign-in failed: {0}. Falling back to platform-defaults.ps1 if present." -f $_.Exception.Message)
                if (Test-Path -LiteralPath $platformDefaultsPath) {
                    . $platformDefaultsPath
                    _CfgOk "loaded fallback ($platformDefaultsPath)"
                    _CfgRecordLayer 'Layer 1 - platform-defaults (fallback)' $platformDefaultsPath $true
                } else {
                    _CfgRecordLayer 'Layer 1 - platform sign-in' $platformConfigPath $false
                }
            }
        } elseif (Test-Path -LiteralPath $platformDefaultsPath) {
            # No v2.3 config -- fall back to v2.2 chain (operator hasn't migrated yet).
            . $platformDefaultsPath
            _CfgOk "loaded platform-defaults.ps1 ($platformDefaultsPath)"
            _CfgInfo "legacy platform-defaults active. Migrate via SOLUTIONS\PlatformConfiguration\INTERNAL\Migrate\Convert-V1ToPlatform.ps1 to use the platform sign-in (bootstrap\platform-config.json)."
            _CfgRecordLayer 'Layer 1 - platform-defaults (fallback)' $platformDefaultsPath $true
        } else {
            _CfgInfo "absent (no $platformConfigPath, no $platformDefaultsPath) -- skipping"
            _CfgRecordLayer 'Layer 1 - platform sign-in' $platformConfigPath $false
        }
    } else {
        _CfgInfo "skipped (community mode; Layer 1 only applies in internal / AF deployments)"
        _CfgRecordLayer 'Layer 1 - platform sign-in' $platformConfigPath $false
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

    # ---- Layer 3: LauncherConfig.defaults.ps1 (engine baseline, ours) --------
    # #183 (2026-09-30): the engine baseline loads BEFORE the customer file. It used to load after it, so
    # every value it set unguarded silently overwrote the customer's own setting in <Solution>.custom.ps1
    # (ExportDestination, AutoBucketMax, SI_Sinks_*, SI_ForceFullRun_*, SI_DefenderWorkspaceResourceId ...)
    # -- the opposite of what this file's header, the sample and the defaults headers all promise.
    # Optional. Some engines don't ship a per-engine defaults file because the other layers cover
    # everything. Absent = info, not error.
    $defaultsPath = Join-Path $LauncherDir 'LauncherConfig.defaults.ps1'
    _CfgStep "Layer 3/5: LauncherConfig.defaults.ps1 (engine baseline, ours)"
    if (Test-Path -LiteralPath $defaultsPath) {
        . $defaultsPath
        _CfgOk "loaded"
        _CfgRecordLayer 'Layer 3 - LauncherConfig.defaults' $defaultsPath $true
    } else {
        _CfgInfo "absent ($defaultsPath) -- skipping (engine has no shipped baseline)"
        _CfgRecordLayer 'Layer 3 - LauncherConfig.defaults' $defaultsPath $false
    }

    # ---- Layer 4: <Solution>.custom.ps1 (solution-wide customer overrides -- beats the engine baseline) ---
    # Path depends on layout:
    #   Monorepo (internal):   <RepoRoot>\SOLUTIONS\<Solution>\config\<Solution>.custom.ps1
    #   Community:             <RepoRoot>\config\<Solution>.custom.ps1
    # For community installs $RepoRoot IS the solution folder; the monorepo path
    # resolves to a non-existent nested folder (<RepoRoot>\SOLUTIONS\<Solution>\...)
    # which caused silent Layer-3 misses on community-vm deploys (v2.1.164 fix).
    $solutionCustomMonorepo  = Join-Path $RepoRoot ("SOLUTIONS\{0}\config\{0}.custom.ps1" -f $Solution)
    $solutionCustomCommunity = Join-Path $RepoRoot ("config\{0}.custom.ps1" -f $Solution)
    if (Test-Path -LiteralPath $solutionCustomMonorepo) {
        $solutionCustomPath = $solutionCustomMonorepo
    } elseif (Test-Path -LiteralPath $solutionCustomCommunity) {
        $solutionCustomPath = $solutionCustomCommunity
    } else {
        # Neither exists -- pick the layout-appropriate path for the "absent" log
        # message so the reader knows where to put the file.
        $solutionCustomPath = if (Test-Path -LiteralPath (Join-Path $RepoRoot "SOLUTIONS\$Solution")) {
            $solutionCustomMonorepo
        } else {
            $solutionCustomCommunity
        }
    }
    _CfgStep "Layer 4/5: $Solution.custom.ps1 (solution-wide customer overrides)"
    if (Test-Path -LiteralPath $solutionCustomPath) {
        _CfgUnblock $solutionCustomPath
        # Layer 4 is the CUSTOMER's file and is often a legacy copy carried across
        # upgrades. A common legacy pattern is an UNGUARDED optional KV pull of a
        # value SI no longer uses, and Get-PlatformSecret was changed back to THROW when
        # the secret isn't seeded (platform commit 2026-06-14). A missing *optional*
        # secret must not take down the whole engine (operator rule: "no missing
        # value should halt"). Catch only that specific case -- a missing-secret
        # error from a Get-PlatformSecret* pull -- warn, and continue with whatever
        # loaded; rethrow anything else so genuine custom.ps1 errors still surface as
        # a hard "Failed to load layered config".
        try {
            . $solutionCustomPath
        } catch {
            $msg = "$($_.Exception.Message)"
            $isOptionalSecretMiss = ($msg -match 'Get-PlatformSecret') -and ($msg -match 'not found')
            if ($isOptionalSecretMiss) {
                Write-Warning ("Layer 4 ($solutionCustomPath): an optional secret pull threw and was skipped -- $msg " +
                    "Wrap optional Key Vault pulls in the customer custom.ps1 in try/catch, or remove the ones no longer used, to silence this.")
            } else {
                throw
            }
        }
        # Track the loaded path so the engine prestage can write back
        # auto-resolved values to persist across runs.
        $global:SI_LoadedCustomConfigPath = $solutionCustomPath
        _CfgOk "loaded"
        _CfgRecordLayer 'Layer 4 - SecurityInsight.custom' $solutionCustomPath $true
    } else {
        # Even when absent, record the would-be path so prestage can CREATE
        # the file on first run with the auto-resolved values.
        $global:SI_LoadedCustomConfigPath = $solutionCustomPath
        _CfgInfo "absent ($solutionCustomPath) -- skipping"
        _CfgRecordLayer 'Layer 4 - SecurityInsight.custom' $solutionCustomPath $false
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

    # ---- Layer 5b: SecurityInsight Pro settings (SQL) -- the CLOSEST layer, Pro only ----
    # In Pro every setting lives in the Pro database (REQUIREMENTS §9.2). Two conditions, both required: the Pro module
    # is installed (it is not in the Community payload) AND a Pro database is configured. Then a failure to read it, or
    # an invalid row or document, FAILS the run (operator, 2026-10-02) -- the throw is deliberately not caught here.
    # Before it leaves, Invoke-SIProSettingsLayer itself posts ONE run-health END record (ExitReason 'settings-error')
    # with the reason, and rethrows the original failure unchanged (§9.2 C.4).
    # On success the run's settings version is $global:SI_ProSettingsVersion (§9.2 C.5) -- printed below and kept in the
    # config snapshot; documents are materialised to a run-local folder under the temp folder (§9.2 C.3).
    $__proModule = Join-Path (Split-Path -Parent (Split-Path -Parent $__siLauncherDir)) 'engine\pro-settings\SI-ProSettings.ps1'
    if ((Test-Path -LiteralPath $__proModule) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlServer) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlDatabase)) {
        _CfgStep 'Layer 5b: SecurityInsight Pro settings (SQL, closest -- wins)'
        $script:_CfgSnapBefore = _CfgGatherGlobals
        . $__proModule
        $__pro = Invoke-SIProSettingsLayer -Engine (Split-Path -Leaf $__siLauncherDir)
        _CfgOk ("loaded {0} setting(s), {1} Key Vault secret(s) and {2} document(s) from {3} -- settings version {4}" -f $__pro.Values, $__pro.Secrets, $__pro.Documents, $__pro.Store, $__pro.Version)
        if ($__pro.RulesRoot) { _CfgInfo ("tier rules from the settings database: SI_EnrichmentDataRoot = {0} (run-local)" -f $__pro.RulesRoot) }
        if ($__pro.RaSettingsPath) { _CfgInfo ("Risk Analysis exclusions / weights from the settings database: SI_ProRaSettingsPath = {0} (run-local)" -f $__pro.RaSettingsPath) }
        _CfgRecordLayer 'Layer 5b - Pro settings (SQL)' $__pro.Store $true
    }

    # #275 G5 -- the Power BI refresh was retired in 3.0. An upgraded config that still turns it on would otherwise be
    # ignored in silence and the dataset would simply stop refreshing. Said ONCE per run, after every layer.
    if (Get-Command -Name Write-SIPowerBIRetiredNotice -ErrorAction SilentlyContinue) { $null = Write-SIPowerBIRetiredNotice }

    # #276 -- v3 must arrive safely with nobody reading the upgrade notes (engine\_shared\SI-FirstRun.ps1).
    # (1) NO DRY RUN FROM THE CONFIGURATION (operator 2026-10-04: "upgrade must work, no dryrun"). In 2.2 a WhatIfMode in
    #     the config made these engines refuse to start; since #257 it would make every scheduled run publish nothing.
    #     A value a config layer set is set aside here (asset tagging keeps it: there it means "change no tag") and the
    #     run says so; the launcher's own -WhatIfMode switch, applied after this call, still asks for a dry run.
    # (2) The one-time notices: what 3.0 changed by itself, the status reports, and -- per engine -- the settings from
    #     the customer's config that now take effect (#183), against the 2.2.460 engine defaults.
    if (Get-Command -Name Invoke-SIFirstRunNotices -ErrorAction SilentlyContinue) {
        try {
            $__wifIgnored = $false
            $__dr = Resolve-SIConfigDryRun -Engine $__siEngine -ConfigValue $global:WhatIfMode -SetByConfig ($script:_CfgProvenance.Contains('WhatIfMode'))
            if ($__dr.Ignored) {
                $global:WhatIfMode = $false
                $global:SI_WhatIfModeConfigIgnored = $true
                $__wifIgnored = $true
                Write-Warning (Get-SIConfigDryRunIgnoredText -Hosting vm)
            }
            $__solLogs = Join-Path $__siRepoRoot (Join-Path 'SOLUTIONS' (Join-Path $__siSolution 'logs'))
            $__logDir = if (Test-Path -LiteralPath (Split-Path -Parent $__solLogs)) { $__solLogs } else { Join-Path $__siRepoRoot 'logs' }
            $__customFiles = @(@($solutionCustomPath, $customPath) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
            $__setNames = @(foreach ($__f in $__customFiles) { _CfgExtractAssignedGlobalNames -Path $__f })
            $__before = try { [System.Diagnostics.Process]::GetCurrentProcess().StartTime } catch { Get-Date }
            $__engineKey = Split-Path -Leaf $__siLauncherDir
            $__v22File = Join-Path $PSScriptRoot 'v2.2-engine-defaults.locked.json'
            if (-not (Test-Path -LiteralPath $__v22File)) { $__v22File = Join-Path (Split-Path -Parent $__siLauncherDir) '_lib\v2.2-engine-defaults.locked.json' }
            $null = Invoke-SIFirstRunNotices -Hosting vm -Engine $__engineKey -LogDir $__logDir -WhatIfConfigIgnored $__wifIgnored `
                -Store @{ Kind = 'file'; Path = (Join-Path $__logDir 'state\install-state.json') } `
                -Evidence { Get-SIUpgradeEvidenceVm -LogDir $__logDir -Before $__before -SettingNames $__setNames } `
                -SettingsChanges {
                    $v22 = @{}
                    $all = (Get-Content -Raw -LiteralPath $__v22File -Encoding UTF8 | ConvertFrom-Json).engines
                    $mine = $all.PSObject.Properties[$__engineKey]
                    if ($mine) { foreach ($p in $mine.Value.PSObject.Properties) { $v22[$p.Name] = $p.Value } }
                    $layer4 = if (Test-Path -LiteralPath $solutionCustomPath) { @(_CfgExtractAssignedGlobalNames -Path $solutionCustomPath) } else { @() }
                    $layer5 = if ($customPath -and (Test-Path -LiteralPath $customPath)) { @(_CfgExtractAssignedGlobalNames -Path $customPath) } else { @() }
                    $now = @{}; foreach ($n in $layer4) { $now[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
                    Get-SISettingsNowInEffect -V22Defaults $v22 -CustomNames $layer4 -EngineCustomNames $layer5 -Current $now
                }
        } catch { Write-Verbose ('first-run checks skipped: {0}' -f $_.Exception.Message) }
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

    # SPN contract bridge: the unified $global:SI_SPN_* names
    # are the canonical source on v2.2. Mirror them onto the launcher/engine
    # contract names ($global:Spn{TenantId,ClientId,ClientSecret,ObjectId})
    # so the SPN-secret auth path in launcher.community-vm.ps1 +
    # Invoke-RiskAnalysis.ps1 just works without the customer having to
    # duplicate the values.
    if ($global:SI_SPN_TenantId        -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:SI_SPN_TenantId }
    if ($global:SI_SPN_AppId           -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:SI_SPN_AppId }
    if ($global:SI_SPN_Secret          -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:SI_SPN_Secret }
    if ($global:SI_SPN_ObjectId        -and -not $global:SpnObjectId)              { $global:SpnObjectId              = [string]$global:SI_SPN_ObjectId }
    # v2.2.229 -- bridge was missing the cert-thumbprint mapping. Community-vm
    # launcher's SPN+cert auth branch reads $global:SpnCertificateThumbprint;
    # without this mirror, GUI-generated configs that only set
    # SI_SPN_CertThumbprint silently fell through every auth branch and threw
    # "No authentication method configured". This unblocks SPN+cert community login.
    if ($global:SI_SPN_CertThumbprint  -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint }

    # #222 -- ONE sign-in decision, managed identity first (operator 2026-10-03). Runs after every layer so the
    # customer's SI_AuthMethod / SPN settings are final. Without SI_AuthMethod an existing install keeps what it has
    # (platform identity / SPN); a new one without an SPN gets the host's managed identity (Azure VM, Azure Arc server).
    # The identity helper is loaded here so every token site on a VM can reach the host's identity endpoint.
    # The helpers are loaded at the bottom of this file (outside the function), so they live in the launcher's scope.
    if (Get-Command -Name 'Set-SIAuthMethodGlobals' -ErrorAction SilentlyContinue) {
        $__auth = Set-SIAuthMethodGlobals
        _CfgInfo ("sign-in: {0} ({1})" -f $__auth.Mode, $__auth.Reason)
    }

    $script:_CfgSnapBefore = $__beforeDerived
    _CfgRecordLayer 'Layer 6 - derived' '(initializer derivation step)' $true

    # ---- Write config snapshot log + prune old logs (7-day retention) --------
    # Use the v2.1.203 SNAPSHOTTED locals (taken before any dot-sourcing) so a
    # bare `$Solution = ...` / `$RepoRoot = ...` in a customer-owned layer file
    # can't blank out the params and break parameter binding here.
    _CfgWriteSnapshotAndPrune -RepoRoot $__siRepoRoot -Solution $__siSolution -Engine $__siEngine -RetentionDays 7
}

# #222 -- the sign-in helpers, loaded HERE (file level) rather than inside the function: launchers dot-source this
# file, so the helpers land in the launcher's scope and every engine the launcher starts can reach the host's
# managed identity endpoint. Initialize-LauncherConfig applies the decision after the last layer.
$__siAuthDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth'
if (Test-Path -LiteralPath (Join-Path $__siAuthDir 'SI-AuthMethod.ps1')) {
    . (Join-Path $__siAuthDir 'SI-ManagedIdentity.ps1')
    . (Join-Path $__siAuthDir 'SI-AuthMethod.ps1')
}
Remove-Variable -Name '__siAuthDir' -ErrorAction SilentlyContinue
