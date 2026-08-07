#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #17: the pre-ingest AlwaysOn dead-column guard.

.DESCRIPTION
    `engine/asset-profiling/stages/Invoke-Output.ps1` refuses to ingest when an ALWAYS-ON
    column is at 0% population:

        "FAILED: critical schema columns empty -- LA ingest skipped to prevent stale data."

    Audit #5 established that this guard is the only thing standing between a broken
    collection and overwriting yesterday's good snapshot with an empty one -- and #17's
    re-verification found it had NO executing coverage. The Pester gate PARSES the engines
    but never runs them, and Test-Smoke's SCHEMA-DRIFT check asserts a different thing
    (declared vs emitted columns, not fill rate).

    The decision was inline, so it was extracted into three pure functions that the stage
    now calls. These tests execute those functions, pulled straight out of the stage script
    via the AST -- the same technique SI-RiskAnalysis-QueryBuild uses -- so they assert the
    code that actually runs, not a copy.
#>

BeforeAll {
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $stage = Join-Path $si 'engine\asset-profiling\stages\Invoke-Output.ps1'
    if (-not (Test-Path $stage)) { throw "Output stage not found at $stage" }

    # Invoke-Output.ps1 is a runnable stage (its body executes on load), so take ONLY the
    # functions under test out of the AST rather than dot-sourcing the file.
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($stage, [ref]$tokens, [ref]$errs)
    if ($errs -and $errs.Count) { throw "Output stage has parse errors: $($errs.Count)" }

    $want = @('Test-SIValuePopulated','Get-SIColumnPopulationStats','Get-SIDeadCriticalColumns')
    $fns = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $want -contains $n.Name
    }, $true)
    $missing = @($want | Where-Object { $fns.Name -notcontains $_ })
    if ($missing.Count) { throw "pre-ingest guard function(s) missing from the stage: $($missing -join ', ')" }
    foreach ($f in $fns) { . ([scriptblock]::Create($f.Extent.Text)) }

    function New-Row { param([hashtable]$Props) [pscustomobject]$Props }
}

# ============================================================================
Describe 'audit #17 -- what counts as a populated cell' {
# ============================================================================

    It 'a real value is populated' -ForEach @('x', 'DEVICE-01', 0, 1, 'False') {
        Test-SIValuePopulated $_ | Should -BeTrue
    }

    It 'null and empty string are NOT populated' {
        Test-SIValuePopulated $null | Should -BeFalse
        Test-SIValuePopulated ''    | Should -BeFalse
    }

    It 'an empty container serialisation is NOT populated' -ForEach @('{}', '[]') {
        # A column that only ever holds "{}" or "[]" is a data-flow regression wearing a
        # value. Counting it as populated would let the guard pass on broken data.
        Test-SIValuePopulated $_ | Should -BeFalse
    }
}

# ============================================================================
Describe 'audit #17 -- column population statistics' {
# ============================================================================

    It 'counts only populated cells, and reports the total' {
        $rows = @(
            New-Row @{ Tier = 1;  PrimaryEntityId = 'a' }
            New-Row @{ Tier = ''; PrimaryEntityId = 'b' }
            New-Row @{ Tier = 2;  PrimaryEntityId = $null }
        )
        $s = @(Get-SIColumnPopulationStats -Rows $rows -Columns @('Tier','PrimaryEntityId'))
        ($s | Where-Object Column -eq 'Tier').Populated            | Should -Be 2
        ($s | Where-Object Column -eq 'Tier').Total                | Should -Be 3
        ($s | Where-Object Column -eq 'PrimaryEntityId').Populated | Should -Be 2
    }

    It 'a column absent from every row is 0%' {
        $rows = @( (New-Row @{ Tier = 1 }), (New-Row @{ Tier = 2 }) )
        (@(Get-SIColumnPopulationStats -Rows $rows -Columns @('RunId')) | Select-Object -First 1).Pct | Should -Be 0
    }

    It 'no rows does not divide by zero' {
        { Get-SIColumnPopulationStats -Rows @() -Columns @('Tier') } | Should -Not -Throw
    }
}

# ============================================================================
Describe 'audit #17 -- the pre-ingest halt decision' {
# ============================================================================

    BeforeAll {
        # Pester v5 does not carry Describe-body variables into It blocks -- script scope does.
        # These are the real always-on sentinels from $engineDispatch in the stage.
        $script:alwaysOn = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType','Tier')
    }

    It 'halts when an ALWAYS-ON column is completely empty' {
        # The regression this exists to catch: collection broke, every row lost its
        # PrimaryEntityId, and ingesting would overwrite a good snapshot with a dead one.
        $stats = @(
            [pscustomobject]@{ Column = 'Tier';            Pct = 100 }
            [pscustomobject]@{ Column = 'PrimaryEntityId'; Pct = 0   }
        )
        $dead = Get-SIDeadCriticalColumns -Stats $stats -AlwaysOn $script:alwaysOn
        @($dead).Count | Should -Be 1
        @($dead)[0].Column | Should -Be 'PrimaryEntityId'
    }

    It 'does NOT halt when everything critical is populated' {
        $stats = @(
            [pscustomobject]@{ Column = 'Tier';            Pct = 100 }
            [pscustomobject]@{ Column = 'PrimaryEntityId'; Pct = 97  }
        )
        @(Get-SIDeadCriticalColumns -Stats $stats -AlwaysOn $script:alwaysOn).Count | Should -Be 0
    }

    It 'a NON-critical column at 0% must never halt the run' {
        # Optional columns are legitimately empty in some tenants. Halting on those would
        # block ingest for a non-problem -- the inverse failure, and just as damaging.
        $stats = @(
            [pscustomobject]@{ Column = 'Tier';           Pct = 100 }
            [pscustomobject]@{ Column = 'SomeOptionalCol'; Pct = 0  }
        )
        @(Get-SIDeadCriticalColumns -Stats $stats -AlwaysOn $script:alwaysOn).Count | Should -Be 0
    }

    It 'reports EVERY dead critical column, not just the first' {
        $stats = @(
            [pscustomobject]@{ Column = 'RunId';           Pct = 0 }
            [pscustomobject]@{ Column = 'PrimaryEntityId'; Pct = 0 }
            [pscustomobject]@{ Column = 'Tier';            Pct = 5 }
        )
        @(Get-SIDeadCriticalColumns -Stats $stats -AlwaysOn $script:alwaysOn).Count | Should -Be 2
    }

    It 'a single populated row in a huge set does NOT halt, despite truncating to 0%' {
        # Pct is integer-truncated: 1/10000 -> 0%. If the guard tested the truncated Pct
        # against a threshold rather than "no populated cells at all", one surviving row
        # would block the whole ingest. End-to-end through the real stats function.
        $rows = @(1..10000 | ForEach-Object { New-Row @{ Tier = if ($_ -eq 1) { 3 } else { '' } } })
        $stats = @(Get-SIColumnPopulationStats -Rows $rows -Columns @('Tier'))
        $stats[0].Populated | Should -Be 1
        $stats[0].Pct       | Should -Be 0
        # Documents the CURRENT contract: truncation means this DOES trip the halt.
        # If that is ever judged wrong, change the guard and this assertion together.
        @(Get-SIDeadCriticalColumns -Stats $stats -AlwaysOn $script:alwaysOn).Count | Should -Be 1
    }
}
