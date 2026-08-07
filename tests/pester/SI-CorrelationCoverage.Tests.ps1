#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #27: cross-source correlation coverage must be visible every run.

.DESCRIPTION
    Operator: "correlation of data among endpoint/entra/azure ... isn't working as intended".

    The merge itself is sound, and that is worth stating: `Invoke-Discover.ps1` merges
    MDE / EG / Entra records by AadDeviceId, lower-cases the key, skips the zero GUID, and
    REFUSES to merge when a record carries conflicting ids across sources rather than
    asserting "same device" on contradictory evidence.

    The defect was that every OUTCOME of that logic went through `Write-SIDiag`, which
    prints only under `-Verbose`. Correlation could fail across most of the estate and the
    run still looked clean -- which is exactly the shape of the complaint: it may be partly
    working, silently.

    Re-verification also found the finding understated it: `$zeroSkipCount` was declared and
    NEVER incremented (the comment said so outright), so the "records with no usable key"
    number -- the one that bounds everything else -- did not exist at all.

    The decision was inline, so it is now the pure `Get-SICorrelationCoverage` in the stage,
    pulled out here via the AST the same way SI-PreIngestGuard does -- so these assert the
    code that actually runs, not a copy.
#>

BeforeAll {
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:StagePath = Join-Path $si 'engine\asset-profiling\stages\Invoke-Discover.ps1'
    if (-not (Test-Path $script:StagePath)) { throw "Discover stage not found at $script:StagePath" }

    # Invoke-Discover.ps1 is a runnable stage (its body executes on load), so take ONLY the
    # function under test out of the AST rather than dot-sourcing the file.
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:StagePath, [ref]$tokens, [ref]$errs)
    if ($errs -and $errs.Count) { throw "Discover stage has parse errors: $($errs.Count)" }

    $fn = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SICorrelationCoverage'
    }, $true)
    if (-not $fn -or @($fn).Count -eq 0) { throw 'Get-SICorrelationCoverage missing from the Discover stage' }
    . ([scriptblock]::Create(@($fn)[0].Extent.Text))

    $script:StageText = Get-Content -LiteralPath $script:StagePath -Raw
}

# ============================================================================
Describe 'audit #27 -- coverage arithmetic' {
# ============================================================================

    It 'reports the share of records that carry a usable id' {
        $c = Get-SICorrelationCoverage -Considered 100 -Merged 10 -NoKey 25 `
                                       -ConflictWithinRecord 0 -ConflictSharedId 0 -FinalCount 90
        $c.WithKey     | Should -Be 75
        $c.CoveragePct | Should -Be 75
    }

    It 'counts the two refusal causes separately AND together' {
        # They are different upstream data problems with different fixes, so a single
        # lumped number would not tell the operator what to go and fix.
        $c = Get-SICorrelationCoverage -Considered 50 -Merged 5 -NoKey 0 `
                                       -ConflictWithinRecord 3 -ConflictSharedId 4 -FinalCount 45
        $c.ConflictWithinRecord | Should -Be 3
        $c.ConflictSharedId     | Should -Be 4
        $c.Conflicts            | Should -Be 7
        $c.HasConflicts         | Should -BeTrue
    }

    It 'does not divide by zero when there is nothing to correlate' {
        $c = Get-SICorrelationCoverage -Considered 0 -Merged 0 -NoKey 0 `
                                       -ConflictWithinRecord 0 -ConflictSharedId 0 -FinalCount 0
        $c.CoveragePct | Should -Be 0
    }

    It 'never reports a negative population if the counters disagree' {
        $c = Get-SICorrelationCoverage -Considered 10 -Merged 0 -NoKey 99 `
                                       -ConflictWithinRecord 0 -ConflictSharedId 0 -FinalCount 10
        $c.WithKey | Should -Be 0
    }

    It 'does NOT pass judgement on a low percentage' {
        # A first version warned below 50%. The operator corrected it: a large share of records
        # CANNOT have an AadDeviceId by nature -- an Azure resource such as a Key Vault exists in
        # Azure with no object in Entra ID at all. Low coverage is the normal shape of a mixed
        # estate, and a warning on it would fire every run and be learned into background noise,
        # which is the exact failure #27 set out to fix. Report the number; do not editorialise.
        $c = Get-SICorrelationCoverage -Considered 100 -Merged 0 -NoKey 90 `
                                       -ConflictWithinRecord 0 -ConflictSharedId 0 -FinalCount 100
        $c.CoveragePct | Should -Be 10
        $c.PSObject.Properties.Name | Should -Not -Contain 'CoverageIsPoor'
    }

    It 'separates "clean estate" from "nothing could correlate" -- the whole point' {
        # Both merge 0 records. Only the coverage ratio distinguishes them, which is why
        # "merged N" alone was never evidence that correlation works.
        $clean  = Get-SICorrelationCoverage -Considered 100 -Merged 0 -NoKey 0 `
                                            -ConflictWithinRecord 0 -ConflictSharedId 0 -FinalCount 100
        $noKeys = Get-SICorrelationCoverage -Considered 100 -Merged 0 -NoKey 100 `
                                            -ConflictWithinRecord 0 -ConflictSharedId 0 -FinalCount 100
        $clean.Merged      | Should -Be $noKeys.Merged
        $clean.CoveragePct  | Should -Be 100
        $noKeys.CoveragePct | Should -Be 0
    }
}

# ============================================================================
Describe 'audit #27 -- the counts are actually visible, and actually counted' {
# ============================================================================

    It 'the summary is INFO, not DIAG' {
        # The whole defect: Write-SIDiag prints only when $global:SI_Verbose or -Verbose is
        # set, so on a normal run the operator saw nothing.
        $script:StageText | Should -Match 'Write-SIInfo \(''correlation \(AadDeviceId\)'
    }

    It 'no longer hides the merge total behind -Verbose' {
        $script:StageText | Should -Not -Match "Write-SIDiag \('second-pass merge by AadDeviceId"
        $script:StageText | Should -Not -Match "Write-SIDiag \('second-pass merge: \{0\} record"
    }

    It 'refusals are warned about, not merely counted' {
        $script:StageText | Should -Match 'Write-SIWarn \(''correlation: \{0\} merge\(s\) refused'
    }

    It 'the dead $zeroSkipCount counter is gone' {
        # It was declared and never incremented, so the "no usable key" figure -- the one
        # that bounds every other number here -- did not exist.
        $script:StageText | Should -Not -Match '\$zeroSkipCount'
    }

    It 'records with no usable AadDeviceId are now counted' {
        $script:StageText | Should -Match '\$noKeyCount\+\+'
    }

    It 'both refusal branches increment their own counter' {
        $script:StageText | Should -Match '\$conflictWithinRecordCount\+\+'
        $script:StageText | Should -Match '\$conflictSharedIdCount\+\+'
    }

    It 'the per-record detail stays at DIAG so the summary stays readable' {
        # Surfacing the summary must not turn every conflicting record into console noise.
        $script:StageText | Should -Match "Write-SIDiag \('discover: skipping AadDeviceId merge"
        $script:StageText | Should -Match "Write-SIDiag \('discover: REFUSING AadDeviceId merge"
    }
}
