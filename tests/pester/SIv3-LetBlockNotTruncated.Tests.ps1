#Requires -Version 5.1
<#
    A `let` BLOCK THE ENGINE PRE-FETCHES MUST NOT BE TRUNCATED BY A SEMICOLON IN A COMMENT.

    🔴 THE REGRESSION THIS EXISTS FOR (2026-08-28). A comment added to the `EpJoinKey` block read:

        // SI_AssetId is unique per asset by construction; that is what a dedup key must be.

    The hybrid path finds the end of a `let` binding by scanning for `;`. That semicolon terminated the
    block **mid-`case(`**, Log Analytics answered `SYN0002 -- Query could not be parsed`, the CL
    pre-fetch failed, and the engine fell back to sending the raw query to XDR Advanced Hunting where
    `SI_Endpoint_Profile_CL` does not exist. **74 cascading failures from one punctuation mark**, on a
    run whose previous three had zero.

    🪤 AND THE SUITE DID NOT NOTICE. 3026 tests passed over the broken catalog, because nothing renders
    a `let` block the way the engine does and runs it. That is the gap this file closes -- it is a
    STRUCTURAL check, deliberately requiring no network.

    🔑 THE RULE IS NARROWER THAN IT LOOKS, and three wrong theories died proving it:
      * *"inline `//` comments in an operator arg list break the parser"* -- **false**, measured live.
      * *"an emoji in a comment breaks it"*  -- **false**, measured live.
      * *"a semicolon in a comment breaks it"* -- **false in general**: 86 pre-existing comments in this
        catalog contain semicolons and always have.
    What is actually fatal is a `;` inside a `let` block **that gets pre-fetched**, because only there
    does the engine's scan-for-`;` decide where the query ends.

    ⚠️ THE TWO EXTRACTION RULES MUST AGREE, and that disagreement is what hid the bug. A hand-rolled
    check that terminates on a line *ending* with `;` finds the block intact and passes; the engine
    terminates on a line *containing* `;` and truncates. This test uses the ENGINE's rule on purpose.
#>

BeforeAll {
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Catalog   = Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    # The let-bindings the hybrid CL path pre-fetches from Log Analytics. #505 -- the profile bindings (_ep, _ap,
    # _TargetCmdb, _SourceCmdb, _cl) are gone; the reports now pre-fetch the CI blocks (_ciLink / _ciAsset, RA-CiKql.ps1)
    # and the Defender recommendation lookups (_dfcPairs, _dfcRecByKey, _recAll over SI_AzureRecommendation_CL).
    # _deviceTierOwn (0600fe8c9, identity tier rules): the admin-logon reports read a device's OWN tier from SI_CI_CL
    # (claims without LogonByT0User); its body carries no ';' before its closing `project _dtKey, _dtCiId, _dtTier;` (#741 (2):
    # one row per link key, cut per query slice under LookupNeededKeys).
    $script:PreFetched = '_ciLink', '_ciAsset', '_subTierG', '_ciPeer', '_dfcPairs', '_dfcRecByKey', '_recAll', '_deviceTierOwn'

    function script:Get-TruncatedLetBlocks {
        $y   = Get-Content $script:Catalog
        $rx  = '^\s*let (' + ($script:PreFetched -join '|') + ') ='
        $bad = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $y.Count; $i++) {
            if ($y[$i] -notmatch $rx) { continue }
            $name = ($y[$i] -replace '^\s*let (\S+) =.*$', '$1')
            # ENGINE RULE: the block ends at the first line CONTAINING ';' -- not the first line
            # ending with one. Using the looser rule here is the whole point.
            for ($j = $i; $j -lt [Math]::Min($y.Count, $i + 120); $j++) {
                if (-not $y[$j].Contains(';')) { continue }
                if ($y[$j] -match '^\s*//') {
                    [void]$bad.Add([pscustomobject]@{
                        Let  = $name
                        Line = $j + 1
                        Text = $y[$j].Trim()
                    })
                }
                break
            }
        }
        $bad
    }
}

Describe 'no pre-fetched let block is cut short by a comment' {

    It 'every pre-fetched let terminates on real KQL, never on a comment semicolon' {
        $bad = script:Get-TruncatedLetBlocks
        $detail = ($bad | ForEach-Object { '{0} @ line {1}: {2}' -f $_.Let, $_.Line, $_.Text }) -join "`n"
        $bad.Count | Should -Be 0 -Because "the engine ends a let at the first ';' it sees, so these truncate the query mid-expression and Log Analytics returns SYN0002:`n$detail"
    }

    It 'the guard actually inspects something -- it must be able to fail' {
        # 🪤 Without this, a regex that silently matches no `let` at all would make the assertion above
        # pass over a catalog full of truncated blocks. A guard that cannot fail is worse than none.
        $y = Get-Content $script:Catalog
        $rx = '^\s*let (' + ($script:PreFetched -join '|') + ') ='
        @($y | Where-Object { $_ -match $rx }).Count | Should -BeGreaterThan 100 -Because 'every report carries a CI block'
    }

    It 'the list names every binding the engine pre-fetches from the catalog (no new pre-fetched let escapes the guard)' {
        # The engine's own pattern (Resolve-ProfileCLLetBlocks): a let whose body reads an SI_*_CL table, up to its first ';'.
        $y = [IO.File]::ReadAllText($script:Catalog)
        $names = @([regex]::Matches($y, '(?ms)\blet\s+(\w+)\s*=\s*[^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $names.Count | Should -BeGreaterThan 0
        @($names | Where-Object { $script:PreFetched -notcontains $_ }) | Should -BeNullOrEmpty
    }

    It 'the canonical CI blocks carry exactly one ";" -- their end (RA-CiKql.ps1)' {
        . (Join-Path $script:SIRootDir 'engine\risk-analysis\_shared\RA-CiKql.ps1')
        foreach ($k in 'link', 'asset') {
            ([regex]::Matches((Get-RACiKqlBlock -Kind $k), ';')).Count | Should -Be 1 -Because "the $k block is cut at its first ';'"
            # #541: with the report's scope and factor set the block still ends at its only ';'
            $scoped = Get-RACiKqlBlock -Kind $k -FactorSet @('no_mfa', 'stale_sign_in') -ScopePredicate 'coalesce(tobool(column_ifexists("si_account_enabled", bool(null))), true) and not(si_stale_)'
            ([regex]::Matches($scoped, ';')).Count | Should -Be 1 -Because "the scoped $k block is cut at its first ';'"
        }
        { Get-RACiKqlBlock -Kind asset -ScopePredicate 'true; drop' } | Should -Throw -Because 'a predicate with a semicolon would cut the block'
    }
}

Describe 'no aggregation list ends with a comma immediately before its `by` clause' {

    It 'KQL forbids a trailing comma before `by` -- and LA reports it as a parse error at that keyword' {
        # 🔴 THE REGRESSION (2026-08-28). A bulk rewrite appended ',' to every
        # `AssetId = any(...)` line, including the ones that were the LAST aggregation in their
        # summarize. `summarize a, b, c, by k` is invalid: the parser expects another aggregation and
        # finds `by`, so Log Analytics answers
        #     SYN0002 -- Query could not be parsed at 'by' on line [85,181]
        # -- column 181 on a 180-character line, i.e. one past the end. Both buckets of
        # Endpoint_ExcludedAssets_Summary failed and the engine reported it as a QUERY DEFECT:
        # "RE-RUNNING WILL FAIL IDENTICALLY -- the query has to be fixed."
        #
        # 🪤 Nothing offline saw it: the YAML parsed, the report count was unchanged, and 3029 tests
        # passed. Only a live render surfaces it, which is exactly why this structural check exists.
        $y = Get-Content $script:Catalog
        $bad = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $y.Count; $i++) {
            if ($y[$i] -notmatch ',\s*$') { continue }
            # skip blank lines and comments to find the next real token line
            $j = $i + 1
            while ($j -lt $y.Count -and ($y[$j].Trim() -eq '' -or $y[$j].Trim() -match '^//')) { $j++ }
            if ($j -ge $y.Count) { continue }
            if ($y[$j].Trim() -match '^by\b') {
                [void]$bad.Add(('line {0}: {1}' -f ($i + 1), $y[$i].Trim()))
            }
        }
        $bad.Count | Should -Be 0 -Because "a comma before `by` makes the summarize unparseable:`n$($bad -join "`n")"
    }
}