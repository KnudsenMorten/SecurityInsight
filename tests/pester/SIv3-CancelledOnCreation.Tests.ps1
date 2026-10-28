#Requires -Version 5.1
<#
    AUDIT #99 -- "Query cancelled on creation" was read as a query defect, and it is a cancellation.

    🔴 WHAT ACTUALLY HAPPENED, on the 2026-09-01 Summary run. The full service message is:

        ScalarEvaluator.Evaluate failed: Query cancelled on creation:. Fix semantic errors in your query.

    That trailing sentence is generic boilerplate the service appends; the signal is the PREFIX. The
    v2.2.455 query-defect test matches on `Fix semantic errors in your query`, so the failure was
    classified PERMANENT -- the bucket was never retried, never sub-bucketed, and the operator was
    told "RE-RUNNING WILL FAIL IDENTICALLY -- the query has to be fixed".

    🔬 THE SAME RUN DISPROVES THAT DIAGNOSIS, which is why this is a classifier defect and not a KQL
    one. `Attack_Paths_Summary_Github_to_Azure_Resources` split into 2 buckets over 480 rows:

      * bucket 1 (249 rows inlined) -> this message -> declared a permanent query defect, lost;
      * bucket 2 (231 rows inlined) -> 900s ceiling  -> correctly queued for sub-bucketing, split 4
        then 16 ways, and EVERY sub-bucket ran the SAME QUERY TEXT successfully -- 312s, 59s, 56s,
        49s, 46s, 32s, 31s.

    Submitting that query text to advanced hunting directly returns cleanly (0 rows). A semantically
    invalid query can neither run for 900 seconds nor return successfully seven times.

    🔑 So the bucket was RESIZABLE, and its twin proved it on the same report in the same run. The
    cost of the misreading is not only the lost bucket: a previous session recorded "🔴 Fix the
    QUERY" as an open defect and went looking for a fault in a query that has none.

    🔒 THE FIX IS DELIBERATELY NARROW. The v2.2.455 separation of query defects from platform
    failures is correct and stays: a real semantic error must still fail on attempt 1 and say the
    query needs fixing. Only this one cancellation prefix moves into the resizable family.

    📌 These tests EXECUTE the shipped predicates rather than restating their regexes, so a future
    edit to the classification is tested rather than merely described.
#>

BeforeAll {
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Hunting = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'
    $script:Engine  = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'

    # The exact text the service produced, taken from the 2026-09-01 transcript. Not paraphrased --
    # the whole defect is in how the two halves of this string interact.
    $script:RealMsg  = '[BadRequest] : ScalarEvaluator.Evaluate failed: Query cancelled on creation:. Fix semantic errors in your query.'
    # A genuine semantic defect, for the control. Mixed-type case() is the one v2.2.455 was built for.
    $script:RealDefect = "[BadRequest] : Fix semantic errors in your query. 'case' operator: the return types are not compatible"

    # The second measured platform failure, audit #106 (2026-09-03). Verbatim from the run log.
    # `TvmSCASnapshotCooked` is Microsoft's INTERNAL entity behind the documented
    # DeviceTvmSecureConfigurationAssessment tables the report queries -- it appears nowhere in this
    # repo. Same query: 449 rows, then 0, then 448 on re-run. Transient, and a retry recovers it.
    $script:RealMsg106 = "[BadRequest] : Errors occurred while resolving remote entities. Failed to resolve name or pattern 'TvmSCASnapshotCooked' in one or more scopes: (`$Cluster='', Database=''). Fix semantic errors in your query."

    # 🔑 DOT-SOURCE THE SHIPPED FILE. The predicate now calls Get-RAPlatformFailurePrefixPattern, which
    # is defined at file scope alongside the prefix list, so the extracted expression cannot be run in
    # isolation any more. Loading the real file is STRICTLY BETTER than stubbing the helper: the test
    # then exercises the actual shipped list, and adding a prefix there is covered here automatically.
    . $script:Hunting

    # Pull the SHIPPED assignments out of the source and run them. Assert against behaviour, not text.
    $src = Get-Content -LiteralPath $script:Hunting -Raw
    $script:CancelExpr = ([regex]::Match($src, '(?m)^\s*\$isCancelledOnCreation\s*=.*$')).Value
    $script:DefectExpr = ([regex]::Match($src, '(?ms)^\s*\$looksQueryDefect\s*=.*?\)\s*$')).Value

    function script:Classify {
        param([string]$Message)
        $msg = $Message
        $isCancelledOnCreation = $null
        $looksQueryDefect = $null
        . ([scriptblock]::Create($script:CancelExpr))
        . ([scriptblock]::Create($script:DefectExpr))
        [pscustomobject]@{ Cancelled = [bool]$isCancelledOnCreation; Defect = [bool]$looksQueryDefect }
    }
}

Describe 'the cancelled-on-creation classification -- audit #99' {

    It 'extracted both shipped predicates, or the tests below prove nothing' {
        # 🪤 A source-scraping test that silently matches nothing passes vacuously. Fail loudly here
        # instead, so a rename cannot turn this whole file into a no-op.
        $script:CancelExpr | Should -Not -BeNullOrEmpty
        $script:DefectExpr | Should -Not -BeNullOrEmpty
        $script:DefectExpr | Should -Match 'isCancelledOnCreation'
    }

    Context 'the real message from the 2026-09-01 run' {

        It 'is recognised as a cancellation' {
            (script:Classify -Message $script:RealMsg).Cancelled | Should -BeTrue
        }

        It 'is NOT called a query defect -- this is the assertion that fails against the old code' {
            # Before the fix this was $true, purely because of the appended boilerplate sentence.
            (script:Classify -Message $script:RealMsg).Defect | Should -BeFalse
        }

        It 'joins the resizable family, so the sub-bucket pass takes it like its twin did' {
            $src = Get-Content -LiteralPath $script:Hunting -Raw
            $src | Should -Match '\$isDeterministicTooLarge\s*=\s*\$isTaskCanceled\s*-or\s*\$is502BadGateway\s*-or\s*\$isCancelledOnCreation'
        }
    }

    Context 'the separation that must NOT be widened (v2.2.455)' {

        It 'still calls a genuine mixed-type case() a query defect' {
            $r = script:Classify -Message $script:RealDefect
            $r.Cancelled | Should -BeFalse
            $r.Defect    | Should -BeTrue
        }

        It 'still calls a plain syntax error a query defect' {
            $r = script:Classify -Message '[BadRequest] : Fix syntax errors in your query.'
            $r.Defect | Should -BeTrue
        }

        It 'does not treat an unrelated failure as a cancellation' {
            (script:Classify -Message '[TooManyRequests] : 429 throttled').Cancelled | Should -BeFalse
        }
    }

    Context 'the SECOND site, which reads the recorded message and would still have mislabelled it' {

        It 'excludes the cancellation from the report-level QUERY DEFECT verdict' {
            # 🔴 Fixing only the hunting layer is not enough: the bucket would be resized correctly
            # and STILL reported to the operator as a defect that fails identically every run,
            # because this filter matches on `semantic` and `BadRequest` in the recorded text.
            $src = Get-Content -LiteralPath $script:Engine -Raw
            $filter = ([regex]::Match($src, '(?ms)\$__permanent\s*=\s*@\(.*?\n\s*\}\)')).Value
            $filter | Should -Not -BeNullOrEmpty
            # 🔴 ASSERT THE SHARED SOURCE, NOT A LITERAL (audit #106). This used to require the string
            # 'Query cancelled on creation' here, which pinned a LOCAL COPY of the exclusion into this
            # site -- and that is exactly how the second prefix got fixed in one place and missed here.
            # The contract is now: this site excludes via the SHARED pattern.
            $filter | Should -Match '\$__platformPfx'
            $src    | Should -Match 'Get-RAPlatformFailurePrefixPattern'

            # ...and run it, rather than trusting that the text implies the behaviour.
            # 🪤 The filter reads `$__platformPfx`, which the shipped code resolves on the lines just
            # above it. Extract and run THAT too -- hard-coding the pattern here would test my copy of
            # the rule instead of the one that ships, which is the failure this whole file guards.
            $pfxExpr = ([regex]::Match($src, '(?ms)\$__platformPfx\s*=\s*if\s*\(.*?\n\s*\}')).Value
            $pfxExpr | Should -Not -BeNullOrEmpty

            $script:_RABucketLoss = @(
                ("bucket 1/2: query failed -- {0}" -f $script:RealMsg),
                ("bucket 2/2: query failed -- {0}" -f $script:RealDefect)
            )
            $__platformPfx = $null
            $__permanent = $null
            . ([scriptblock]::Create($pfxExpr))
            . ([scriptblock]::Create($filter))
            @($__permanent).Count | Should -Be 1
            @($__permanent)[0]    | Should -Match 'case'
        }

        It '🔴 and excludes the #106 resolution failure too -- the prefix this site did NOT know about' {
            # Before the shared list, this site named the two #99 forms inline. A report that lost 449
            # findings to a transient service-side failure was therefore still reported as a permanent
            # query defect, telling the operator to fix a query that has nothing wrong with it.
            $src = Get-Content -LiteralPath $script:Engine -Raw
            $filter  = ([regex]::Match($src, '(?ms)\$__permanent\s*=\s*@\(.*?\n\s*\}\)')).Value
            $pfxExpr = ([regex]::Match($src, '(?ms)\$__platformPfx\s*=\s*if\s*\(.*?\n\s*\}')).Value

            $script:_RABucketLoss = @(
                ("bucket 1/2: query failed -- {0}" -f $script:RealMsg106),
                ("bucket 2/2: query failed -- {0}" -f $script:RealDefect)
            )
            $__platformPfx = $null
            $__permanent = $null
            . ([scriptblock]::Create($pfxExpr))
            . ([scriptblock]::Create($filter))
            # Only the genuine defect survives as permanent; the resolution failure is platform.
            @($__permanent).Count | Should -Be 1
            @($__permanent)[0]    | Should -Match 'case'
        }
    }

    Context '🔴 the SECOND platform prefix -- audit #106, and why this is now a LIST' {

        It 'the shared prefix list is reachable and names all three forms' {
            # Reachability, not just existence: #99 and #106 were both fixed in one place and missed
            # in another, so the helper being CALLABLE is the property worth asserting.
            (Get-Command Get-RAPlatformFailurePrefixPattern -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
            $p = Get-RAPlatformFailurePrefixPattern
            $p | Should -Match 'Query cancelled on creation'
            $p | Should -Match 'ScalarEvaluator'
            $p | Should -Match 'Errors occurred while resolving remote entities'
        }

        It 'the resolution failure is recognised as PLATFORM, not a query defect' {
            $r = script:Classify -Message $script:RealMsg106
            $r.Cancelled | Should -BeTrue     # i.e. joins the resizable/retryable family
            $r.Defect    | Should -BeFalse    # the assertion that fails against the pre-#106 code
        }

        It 'so it joins the resizable family and gets retried rather than declared permanent' {
            $src = Get-Content -LiteralPath $script:Hunting -Raw
            $src | Should -Match '\$isDeterministicTooLarge\s*=\s*\$isTaskCanceled\s*-or\s*\$is502BadGateway\s*-or\s*\$isCancelledOnCreation'
        }

        It '🔒 and a REAL defect is still a defect -- the v2.2.455 separation is not widened' {
            (script:Classify -Message $script:RealDefect).Defect | Should -BeTrue
            (script:Classify -Message '[BadRequest] : Fix syntax errors in your query.').Defect | Should -BeTrue
            # An unrelated platform failure must not be swept in by the new list either.
            (script:Classify -Message '[TooManyRequests] : 429 throttled').Cancelled | Should -BeFalse
        }
    }
}
