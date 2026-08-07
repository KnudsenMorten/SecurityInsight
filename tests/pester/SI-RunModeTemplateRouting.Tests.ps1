#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #39: the run mode must agree with the resolved report template.

.DESCRIPTION
    $global:Summary / $global:Detailed do not merely label a run. `Invoke-RiskAnalysis.ps1`
    reads them to choose the mail lane AND -- the expensive part -- the Log Analytics table
    and the DCR:

        if ([bool]$global:Detailed) { $laTable = $tblDetailed; $laDcrName = ...detailed }
        else                        { $laTable = $tblSummary;  $laDcrName = ...summary  }

    Both VM launchers resolved that mode via Resolve-RunMode BEFORE the template was known,
    and Resolve-RunMode never looked at -ReportTemplate. So the documented launch line

        launcher.internal-vm.ps1 -ReportTemplate RiskAnalysis_Detailed

    ran the Detailed catalog with Detailed=$false and ingested Detailed rows into
    SI_RiskAnalysis_Summary_CL. Measured in the live workspace on 2026-08-07: 64 mis-routed
    snapshots / 133,213 rows since 2026-06-06 (91% of that table), while
    SI_RiskAnalysis_Detailed_CL held exactly ONE snapshot -- the single run ever launched
    with -Detailed. Because most nights the Detailed run finished last, the documented
    contract `where CollectionTime == max(CollectionTime)` on the Summary table returned
    Detailed rows.

    These tests execute the reconciliation block pulled straight out of each launcher
    (AST for the helper, marked span for the block) -- the same technique as
    SI-PreIngestGuard -- so they assert the code that actually runs, not a copy. If the
    block is deleted or renamed, extraction throws and the suite goes red.
#>

BeforeAll {
    $script:si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    $script:launchers = @{
        'internal-vm'  = Join-Path $script:si 'launcher\risk-analysis\launcher.internal-vm.ps1'
        'community-vm' = Join-Path $script:si 'launcher\risk-analysis\launcher.community-vm.ps1'
    }

    # Start of the reconciliation span, and the first line after it. Both are load-bearing:
    # the block must sit AFTER the template is resolved and BEFORE the banner prints the mode.
    $script:markerStart = '# --- Reconcile the run mode with the resolved template (finding #39)'
    $script:markerEnd   = 'Write-Info ("[LAUNCHER] AutomationFramework='

    $script:fnText    = @{}
    $script:blockText = @{}

    foreach ($name in $script:launchers.Keys) {
        $path = $script:launchers[$name]
        if (-not (Test-Path $path)) { throw "launcher not found: $path" }

        $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errs)
        if ($errs -and $errs.Count) { throw "$name has parse errors: $($errs.Count)" }

        # The launcher body executes on load (it connects and invokes the engine), so take
        # only the helper out of the AST rather than dot-sourcing the file.
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Get-SIRunModeForTemplate'
        }, $true)
        if (-not $fn -or $fn.Count -ne 1) {
            throw "$name : expected exactly one Get-SIRunModeForTemplate definition, found $(@($fn).Count)"
        }
        $script:fnText[$name] = $fn[0].Extent.Text

        $lines = Get-Content -LiteralPath $path
        $iStart = ($lines | Select-String -SimpleMatch $script:markerStart | Select-Object -First 1).LineNumber
        if (-not $iStart) { throw "$name : reconciliation block marker not found -- finding #39 guard is gone" }
        $after = $lines | Select-Object -Skip $iStart
        $rel   = ($after | Select-String -SimpleMatch $script:markerEnd | Select-Object -First 1).LineNumber
        if (-not $rel) { throw "$name : banner line not found after the reconciliation block" }
        # Span = marker line .. line before the banner (LineNumber values are 1-based).
        $script:blockText[$name] = ($lines[($iStart - 1)..($iStart + $rel - 3)]) -join [Environment]::NewLine
    }

    # Executes the REAL extracted block against a synthetic starting state.
    function Invoke-ModeReconcile {
        param(
            [string]$Launcher,
            [hashtable]$Bound,
            [bool]$StartSummary,
            [bool]$StartDetailed,
            [string]$Template
        )
        $global:Summary        = $StartSummary
        $global:Detailed       = $StartDetailed
        $global:ReportTemplate = $Template

        $prefix = 'param($cliBound)' + [Environment]::NewLine +
                  'function Write-Info { param($m) }' + [Environment]::NewLine
        $sb = [scriptblock]::Create(
            $prefix + $script:fnText[$Launcher] + [Environment]::NewLine + $script:blockText[$Launcher])
        & $sb $Bound

        [pscustomobject]@{
            Summary  = [bool]$global:Summary
            Detailed = [bool]$global:Detailed
        }
    }
}

# ============================================================================
Describe 'audit #39 -- template -> run mode classification' -ForEach @('internal-vm','community-vm') {
# ============================================================================
    BeforeAll { $script:L = $_ }

    It 'classifies the shipped Detailed templates as Detailed' -ForEach @(
        'RiskAnalysis_Detailed', 'AssetSimulationComplexDetailed'
    ) {
        $sb = [scriptblock]::Create($script:fnText[$script:L] + [Environment]::NewLine +
                                    "Get-SIRunModeForTemplate -Template '$_'")
        & $sb | Should -Be 'Detailed'
    }

    It 'classifies the shipped Summary templates as Summary' -ForEach @(
        'RiskAnalysis_Summary', 'RiskAnalysis_Summary_Bucket', 'AssetSimulationComplexSummary'
    ) {
        $sb = [scriptblock]::Create($script:fnText[$script:L] + [Environment]::NewLine +
                                    "Get-SIRunModeForTemplate -Template '$_'")
        & $sb | Should -Be 'Summary'
    }

    It 'leaves an unrecognised template unclassified rather than guessing' -ForEach @(
        'MyCustomCatalog', '', '   '
    ) {
        $sb = [scriptblock]::Create($script:fnText[$script:L] + [Environment]::NewLine +
                                    "Get-SIRunModeForTemplate -Template '$_'")
        & $sb | Should -BeNullOrEmpty
    }
}

# ============================================================================
Describe 'audit #39 -- the live defect and its fix' -ForEach @('internal-vm','community-vm') {
# ============================================================================
    BeforeAll { $script:L = $_ }

    It 'THE DEFECT: -ReportTemplate RiskAnalysis_Detailed now yields Detailed=$true' {
        # Exactly the sanctioned launch line. Before the fix this ended Summary=$true /
        # Detailed=$false and ingested into SI_RiskAnalysis_Summary_CL.
        $r = Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ ReportTemplate = 'RiskAnalysis_Detailed' } `
            -StartSummary $true -StartDetailed $false -Template 'RiskAnalysis_Detailed'
        $r.Detailed | Should -BeTrue
        $r.Summary  | Should -BeFalse
    }

    It 'the sanctioned Summary launch line is unchanged' {
        $r = Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ ReportTemplate = 'RiskAnalysis_Summary' } `
            -StartSummary $true -StartDetailed $false -Template 'RiskAnalysis_Summary'
        $r.Summary  | Should -BeTrue
        $r.Detailed | Should -BeFalse
    }

    It '-Detailed alone still resolves Detailed (the one path that was already correct)' {
        $r = Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ Detailed = $true } `
            -StartSummary $false -StartDetailed $true -Template 'RiskAnalysis_Detailed'
        $r.Detailed | Should -BeTrue
        $r.Summary  | Should -BeFalse
    }

    It 'a Detailed simulation routes to Detailed, not to the Summary table' {
        $r = Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ RunAssetSimulation = 'ComplexDetailed' } `
            -StartSummary $true -StartDetailed $false -Template 'AssetSimulationComplexDetailed'
        $r.Detailed | Should -BeTrue
        $r.Summary  | Should -BeFalse
    }

    It 'a custom template leaves the configured mode alone' {
        $r = Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ ReportTemplate = 'MyCustomCatalog' } `
            -StartSummary $true -StartDetailed $false -Template 'MyCustomCatalog'
        $r.Summary  | Should -BeTrue
        $r.Detailed | Should -BeFalse
    }
}

# ============================================================================
Describe 'audit #39 -- contradictions fail loudly instead of picking a table' -ForEach @('internal-vm','community-vm') {
# ============================================================================
    BeforeAll { $script:L = $_ }

    It '-Summary with an explicit Detailed template throws' {
        { Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ Summary = $true; ReportTemplate = 'RiskAnalysis_Detailed' } `
            -StartSummary $true -StartDetailed $false -Template 'RiskAnalysis_Detailed'
        } | Should -Throw -ExpectedMessage '*Contradictory parameters*'
    }

    It '-Detailed with an explicit Summary template throws' {
        { Invoke-ModeReconcile -Launcher $script:L `
            -Bound @{ Detailed = $true; ReportTemplate = 'RiskAnalysis_Summary' } `
            -StartSummary $false -StartDetailed $true -Template 'RiskAnalysis_Summary'
        } | Should -Throw -ExpectedMessage '*Contradictory parameters*'
    }

    It 'the throw names the tables at stake, so the operator can act on it' {
        $msg = $null
        try {
            Invoke-ModeReconcile -Launcher $script:L `
                -Bound @{ Summary = $true; ReportTemplate = 'RiskAnalysis_Detailed' } `
                -StartSummary $true -StartDetailed $false -Template 'RiskAnalysis_Detailed'
        } catch { $msg = $_.Exception.Message }
        $msg | Should -Match 'Log Analytics table'
    }
}

# ============================================================================
Describe 'audit #39 -- the guard cannot be silently removed' {
# ============================================================================

    It 'both VM launchers carry the reconciliation block' -ForEach @('internal-vm','community-vm') {
        $script:blockText[$_] | Should -Not -BeNullOrEmpty
        $script:blockText[$_] | Should -Match 'Get-SIRunModeForTemplate'
    }

    It 'the block sits AFTER template resolution and BEFORE the mode banner' -ForEach @('internal-vm','community-vm') {
        # Order is the whole point: reconciling before the template is known would be a
        # no-op, and reconciling after the banner would print a mode the run does not use.
        $lines  = Get-Content -LiteralPath $script:launchers[$_]
        $iTpl   = ($lines | Select-String -SimpleMatch 'ReportTemplate_Default_Summary' | Select-Object -Last 1).LineNumber
        $iBlock = ($lines | Select-String -SimpleMatch $script:markerStart | Select-Object -First 1).LineNumber
        $iBan   = ($lines | Select-String -SimpleMatch $script:markerEnd   | Select-Object -First 1).LineNumber
        $iBlock | Should -BeGreaterThan $iTpl
        $iBlock | Should -BeLessThan    $iBan
    }

    It 'the engine still selects the LA table from $global:Detailed (the reason this matters)' {
        # If this ever stops being true, the reconciliation is guarding the wrong thing.
        $engine = Join-Path $script:si 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $body   = Get-Content -LiteralPath $engine -Raw
        $body | Should -Match '(?s)if \(\[bool\]\$global:Detailed\) \{\s*\r?\n\s*\$laTable\s*=\s*\$tblDetailed'
    }
}
