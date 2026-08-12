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

    foreach ($fnName in @('Get-SICorrelationCoverage','Format-SIConflictList','Get-SIRecordAadAttribution')) {
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fnName
        }, $true)
        if (-not $fn -or @($fn).Count -eq 0) { throw "$fnName missing from the Discover stage" }
        . ([scriptblock]::Create(@($fn)[0].Extent.Text))
    }

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

# ============================================================================
Describe 'audit #27 follow-up -- a refused merge must NAME the assets' {
# ============================================================================
    # 2026-08-12: a customer run warned "3 merge(s) refused on conflicting AadDeviceIds". Nobody
    # ever found out WHICH 3, because the identities were DIAG-only and the sole route to them was
    # re-running the whole profiler with -Verbose against a live tenant mid-incident. The count was
    # visible and still not actionable, so the finding was carried across sessions un-chased.

    It 'the summary no longer tells the operator to re-run the profiler to find out which assets' {
        # The old summary ended "Re-run with -Verbose to list them." -- a full profiler run to learn
        # three names. That instruction is what made this un-chased.
        $script:StageText | Should -Not -Match 'stay split across sources\. Re-run with -Verbose to list them'
    }

    It 'both refusal causes emit a WARN naming the affected assets' {
        $script:StageText | Should -Match "Write-SIWarn \('correlation: MDE/EG/Entra disagree about the AadDeviceId of"
        $script:StageText | Should -Match "Write-SIWarn \('correlation: one AadDeviceId is claimed by two differently-named assets"
    }

    It 'names are collected in BOTH refusal branches, not just one' {
        $script:StageText | Should -Match '\$conflictWithinRecordNames\.Add'
        $script:StageText | Should -Match '\$conflictSharedIdNames\.Add'
    }

    It 'lists every asset when the list is small -- the normal case' {
        # Refusals need genuinely contradictory upstream data, so this is the shape that ships.
        Format-SIConflictList -Items @('"A"','"B"','"C"') | Should -Be '"A", "B", "C"'
    }

    It 'is not itself a source of noise when one upstream sync breaks' {
        $r = Format-SIConflictList -Items (1..25 | ForEach-Object { "host$_" }) -Max 20
        $r | Should -Match 'and 5 more'
        $r | Should -Match 're-run with -Verbose to list every one'
    }

    It 'never hides HOW MANY -- only how many are printed on one line' {
        # The bound is a line-length bound, not a data bound. The true total comes from the count
        # line above it, which is unbounded, and every name is still available at DIAG. A display
        # limit that suppressed the real number would recreate the defect it is here to fix.
        $c = Get-SICorrelationCoverage -Considered 500 -Merged 0 -NoKey 0 `
                                       -ConflictWithinRecord 400 -ConflictSharedId 0 -FinalCount 500
        $c.Conflicts | Should -Be 400
        $script:StageText | Should -Match '\$cov\.Conflicts, \$cov\.ConflictWithinRecord, \$cov\.ConflictSharedId'
    }

    It 'handles an empty list without emitting a bare fragment' {
        Format-SIConflictList -Items @() | Should -Be ''
    }
}

# ============================================================================
Describe 'audit #27 follow-up -- WHICH source disagrees is the remediation' {
# ============================================================================
    # "This asset has two AadDeviceIds" is not actionable. "EG and Entra agree, MDE does not" names
    # the record to go and fix -- and the stage comment already said the fix is usually MDE's.

    $zero = '00000000-0000-0000-0000-000000000000'

    It 'attributes each id to the source that claimed it' {
        $rec = [pscustomobject]@{ Raw = @(
            @{ MDE_AadDeviceId = 'AAAA-1'; EG_AadDeviceId = 'bbbb-2' }
            @{ ENTRA_AadDeviceId = 'BBBB-2' }
        )}
        $r = Get-SIRecordAadAttribution -r $rec -ZeroGuid $zero
        # Lower-cased so the two spellings of the same id are visibly ONE id, not a third conflict.
        $r | Should -Be 'MDE=aaaa-1 | EG=bbbb-2 | ENTRA=bbbb-2'
    }

    It 'excludes the zero GUID, which is "not Entra-joined" and not a disagreement' {
        $rec = [pscustomobject]@{ Raw = @(
            @{ MDE_AadDeviceId = $zero; EG_AadDeviceId = 'real-1' }
        )}
        Get-SIRecordAadAttribution -r $rec -ZeroGuid $zero | Should -Be 'EG=real-1'
    }

    It 'says (none) rather than an empty string when there is nothing to attribute' {
        $rec = [pscustomobject]@{ Raw = @(@{ MDE_AadDeviceId = '' }) }
        Get-SIRecordAadAttribution -r $rec -ZeroGuid $zero | Should -Be '(none)'
    }

    It 'the within-record DIAG line carries the attribution, not a bare id join' {
        $script:StageText | Should -Match 'Get-SIRecordAadAttribution -r \$rec -ZeroGuid \$zeroGuid'
        $script:StageText | Should -Not -Match "\`$allIds\.Count, \(\(\`$allIds\) -join ', '\)"
    }
}
