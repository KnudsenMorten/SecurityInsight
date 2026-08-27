#Requires -Version 5.1
<#
    AN EXPECTED FAILURE MUST NOT SURFACE AS A TERMINATING ERROR.

    Operator, 2026-08-26: *"i dont want to see things like that in logs, as customers are calling me
    asking what it means"*.

    PowerShell transcripts record EVERY terminating error -- including ones that are caught and
    handled -- as a `PS>TerminatingError(...)` block, complete with HTTP status, request ids and
    response bodies. So a run that is behaving exactly as designed can print several alarming stack
    dumps, and the customer reading their own transcript reasonably concludes something broke.

    THREE PLACES DID THIS. In the first two the failure is the EXPECTED answer, not a fault; in the
    third it is a real failure that was being reported in an unusable FORM:

    1. `Test-AdvancedHuntingHasTable` (v2.2.445) -- asks whether a customer's SI_*_CL table is
       mirrored into advanced hunting. For most tenants the answer is legitimately NO, and the engine
       immediately routes to Log Analytics instead. It asked with `-ErrorAction Stop`, which PROMOTES
       the cmdlet's non-terminating error into a terminating one. Four dumps per healthy run.

    2. `Invoke-SISentinelLakeQuery` (v2.2.451) -- queries the Sentinel data lake. The lake is NOT
       onboarded on most tenants, so `400 InvalidDatabaseInQuery` is the expected reply and the
       caller already falls back silently. It produced TWO terminating errors per attempt: one from
       `Invoke-RestMethod -ErrorAction Stop`, and one from our own `throw` of the formatted message.

    3. `Invoke-GraphHuntingQuery` (v2.2.452) -- the REAL advanced-hunting query, not the probe. A
       query that exceeds AH limits or hits the 900s ceiling IS a genuine failure worth logging, and
       it drives bucket escalation -- but it printed ~20 lines of HTTP headers TWICE per failure.
       The failure is still reported; it is now ONE SHORT LINE.

    🔑 THE TRAP THAT CATCHES YOU TWICE: re-throwing inside the fix. A caught-and-rethrown error is
    still a terminating error, so `catch { throw $msg }` writes the very block you are removing.
    Sites 1 and 2 therefore RETURN the failure rather than throwing it. I made exactly this mistake in
    the first cut of fix 1 and caught it before shipping; these tests exist so the next person does
    not have to.

    🔴 AND THE TRAP THAT IS WORSE, because it breaks BEHAVIOUR rather than logs. Site 3 must still
    raise something -- callers depend on it for retry and bucket escalation -- so it raises a SHORT
    message instead of the SDK's exception object. But the 900s ceiling arrives as
        "The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing."
    which matches NEITHER message fallback in Test-IsDeterministicTooLargeError. Today it is caught
    ONLY by the `-is [TaskCanceledException]` TYPE check -- so raising a PLAIN string would erase the
    type and SILENTLY DISABLE the AutoBucket ramp on exactly the reports that need sub-bucketing.
    The type is therefore preserved as TEXT, and a behavioural test proves the difference:
        plain 900s text  -> Test-IsDeterministicTooLargeError = False
        prefixed text    -> Test-IsDeterministicTooLargeError = True
    That case exists because tidying the log must never quietly change what the engine does.
#>

BeforeAll {
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Engine  = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $script:Hunting = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'
    $script:LAQuery = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1'

    function script:BodyOf {
        # The source text of one function, by AST -- so these assertions read the SHIPPING code and
        # cannot drift from a copy.
        param([string]$File, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$null, [ref]$null)
        $fn  = $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name
        }, $true) | Select-Object -First 1
        if (-not $fn) { return '' }
        # strip full-line comments: the block comments QUOTE the calls they describe
        (($fn.Extent.Text -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
}

Describe 'the advanced-hunting table probe (v2.2.445)' {

    BeforeAll { $script:Probe = script:BodyOf -File $script:LAQuery -Name 'Test-AdvancedHuntingHasTable' }

    It 'the function exists and was found by AST' {
        $script:Probe | Should -Not -BeNullOrEmpty
    }

    It '🔴 does not ask with -ErrorAction Stop' {
        # -ErrorAction Stop PROMOTES the cmdlet's non-terminating error to a terminating one, which
        # is the only reason the transcript ever saw it.
        $script:Probe | Should -Not -Match '-ErrorAction Stop'
    }

    It 'asks with SilentlyContinue + an ErrorVariable instead' {
        $script:Probe | Should -Match '-ErrorAction SilentlyContinue'
        $script:Probe | Should -Match '-ErrorVariable'
    }

    It '🔴 never re-throws -- a re-thrown error is still a terminating error' {
        # The trap that catches you twice. The first cut of this fix did `throw $probeErr[0]` to reuse
        # the classification below it, which would have restored the exact block being removed.
        $script:Probe | Should -Not -Match '(?m)^\s*throw\b'
    }

    It 'still classifies the three outcomes -- available, not-mirrored, inconclusive' {
        # Removing the noise must not remove the ROUTING DECISION the probe exists to make.
        $script:Probe | Should -Match 'IS queryable from advanced hunting'
        $script:Probe | Should -Match 'is NOT queryable from advanced hunting'
        $script:Probe | Should -Match 'inconclusive'
    }
}

Describe 'the Sentinel data-lake query (v2.2.451)' {

    BeforeAll {
        $script:Lake   = script:BodyOf -File $script:Engine  -Name 'Invoke-SISentinelLakeQuery'
        $script:Caller = Get-Content $script:Hunting -Raw
    }

    It 'the function exists and was found by AST' {
        $script:Lake | Should -Not -BeNullOrEmpty
    }

    It '🔴 RETURNS its failure instead of THROWING it' {
        $script:Lake | Should -Match '_SILakeError'
        # The old code ended the catch with `throw $msg`.
        $script:Lake | Should -Not -Match '(?m)^\s*throw \$msg\b'
    }

    It 'asks PS7 for the response rather than an exception' {
        # -SkipHttpErrorCheck returns the body on a non-2xx instead of throwing, so nothing
        # terminates and the transcript stays clean.
        $script:Lake | Should -Match 'SkipHttpErrorCheck'
        $script:Lake | Should -Match 'StatusCodeVariable'
    }

    It 'still detects a non-2xx and reports it in the SAME message shape' {
        # The caller pattern-matches on this text to decide "permanently unavailable" vs "retry", so
        # the shape must not drift.
        $script:Lake | Should -Match "lake-\{0\}"
        $script:Lake | Should -Match 'api-body'
    }

    It '🪤 PS 5.1 still has a working path (it has no -SkipHttpErrorCheck)' {
        $script:Lake | Should -Match 'PSVersion\.Major -ge 6'
        $script:Lake | Should -Match "ErrorAction'\] = 'Stop'"
    }

    It 'the CALLER reads the returned failure and keeps its fallback policy' {
        $script:Caller | Should -Match '_SILakeError'
        # The deferred-warning policy must survive: a superseded attempt is stashed, not warned.
        $script:Caller | Should -Match "Add-SupersededAttempt -Path 'lake'"
        $script:Caller | Should -Match 'InvalidDatabaseInQuery'
        $script:Caller | Should -Match '_SentinelLakeUnavailable = \$true'
    }

    It 'the caller no longer passes -ErrorAction Stop to the lake helper' {
        $script:Caller | Should -Not -Match 'Invoke-SISentinelLakeQuery[^\r\n]*-ErrorAction Stop'
    }

    It 'a genuine fault still has a backstop catch' {
        # Returning the expected failure must not mean a REAL fault (auth, transport) escapes.
        $script:Caller | Should -Match '\$lakeMsg = \$_\.Exception\.Message'
    }
}

Describe 'the advanced-hunting QUERY call (v2.2.452)' {
    # The third and largest noise site: the real query, not the probe. It printed ~20 lines of HTTP
    # status, request ids and x-ms-ags-diagnostic headers, TWICE per failure -- once for the cmdlet's
    # promoted error and once for this function's re-throw. Operator: "it looks very amateur".

    BeforeAll {
        $script:Hunt = script:BodyOf -File $script:Hunting -Name 'Invoke-GraphHuntingQuery'
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
        # The exact text the 900s ceiling produces, taken from a customer transcript.
        $script:Real900s = 'The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing.'
    }

    It 'the query is no longer asked with -ErrorAction Stop' {
        $script:Hunt | Should -Not -Match 'Start-MgBetaSecurityHuntingQuery -Query \$Query -ErrorAction Stop'
    }

    It 'it asks with SilentlyContinue + an ErrorVariable' {
        $script:Hunt | Should -Match 'Start-MgBetaSecurityHuntingQuery[^\r\n]*-ErrorAction SilentlyContinue'
        $script:Hunt | Should -Match '-ErrorVariable ahErr'
    }

    It 'the raised error is a SHORT message, not the SDK exception object' {
        # `throw` on an ErrorRecord reproduces the full HTTP dump. Throwing our own string keeps the
        # transcript entry to one line -- the failure is still reported, just not as a stack dump.
        $script:Hunt | Should -Match 'throw \(\$__typ \+ \[string\]\$__e\.Exception\.Message\)'
    }

    It '🔴 THE TYPE SIGNAL IS PRESERVED AS TEXT -- without it, escalation silently stops' {
        # The 900s ceiling message matches NEITHER message fallback; today only the
        # -is [TaskCanceledException] TYPE check catches it. Raising a plain string would erase the
        # type and quietly disable the AutoBucket ramp on exactly the reports that need it.
        $script:Hunt | Should -Match 'TaskCanceledException: '
    }

    It '🔴 PROOF the prefix is load-bearing: plain text does NOT classify, prefixed text DOES' {
        # This is the assertion that would have caught the near-miss. It exercises the REAL
        # classifier that drives bucket escalation.
        Test-IsDeterministicTooLargeError -Err $script:Real900s                              | Should -BeFalse
        Test-IsDeterministicTooLargeError -Err ('TaskCanceledException: ' + $script:Real900s) | Should -BeTrue
    }

    It 'the catch also matches the type as TEXT, so either path classifies' {
        $script:Hunt | Should -Match "\`$msg -match 'TaskCanceledException'"
    }

    It 'a genuine AH limits failure still classifies as bucket overflow' {
        # The other real message from the customer log -- must be unaffected.
        Test-IsBucketOverflowError -Err 'Query execution has exceeded the allowed limits. The query execution was preempted.' |
            Should -BeTrue
    }
}

Describe 'an inconclusive probe must not route to advanced hunting (v2.2.460)' {

    BeforeAll {
        $script:Probe  = script:BodyOf -File $script:LAQuery -Name 'Test-AdvancedHuntingHasTable'
        $script:Router = Get-Content -Raw -LiteralPath $script:Hunting
    }

    It 'the inconclusive branch answers FALSE, not TRUE' {
        # The two routes are not symmetric. LA-direct works for an SI-owned SI_*_CL table because
        # SI writes it to the workspace; advanced hunting only works if the customer ALSO mirrored
        # it. So an uncertain answer must resolve to the route that works, never the one that can
        # fail -- when it fails the bucket returns nothing, the report ships PARTIAL, and the
        # findings are absent from the workbook AND the CL table while the run reports success.
        $inconclusive = ($script:Probe -split 'inconclusive')[1]
        $inconclusive | Should -Not -BeNullOrEmpty
        $inconclusive | Should -Match 'return \$false'
    }

    It 'the inconclusive branch does NOT cache its guess' {
        # It cached $true for the WHOLE RUN, so one transient blip -- a throttle, a timeout, a
        # reworded service error -- mis-routed every later query touching that table. The comment
        # in the source already said "Don't cache"; the code did anyway.
        $inconclusive = ($script:Probe -split 'inconclusive')[1]
        $inconclusive | Should -Not -Match '_TableInAdvHunting\[\$TableName\]\s*=\s*\$true'
    }

    It 'a table genuinely present in advanced hunting is still cached as available' {
        # The fix must not disable the optimisation for customers who HAVE mirrored their tables.
        $script:Probe | Should -Match 'IS queryable from advanced hunting'
        $script:Probe | Should -Match '_TableInAdvHunting\[\$TableName\]\s*=\s*\$true'
    }

    It 'a definitive not-mirrored answer is still cached, so it is probed once per run' {
        $notMirrored = ($script:Probe -split 'Failed to resolve table or column expression')[1]
        $notMirrored | Should -Match '_TableInAdvHunting\[\$TableName\]\s*=\s*\$false'
    }
}

Describe 'the routing decision is visible in a normal run (v2.2.460)' {

    BeforeAll { $script:Router = Get-Content -Raw -LiteralPath $script:Hunting }

    It 'the route taken is announced with Write-Info, not Write-Diag' {
        # This bug has been seen twice -- v2.2.272 on one report and 2026-08-26 on another -- where
        # the probe said "not in advanced hunting" and the query went there anyway. Both times the
        # breadcrumb that would have named the branch was verbose-only, so neither run could be
        # explained afterwards. A diagnostic that only fires once you already suspect a problem is
        # not a diagnostic.
        $script:Router | Should -Match 'Write-Info \("routing to \{0\}'
    }

    It 'the announcement names the route AND the tables that drove it' {
        # Route alone is not enough to diagnose: the tables are what the probe was asked about.
        $script:Router | Should -Match "advanced hunting.*Log Analytics direct|Log Analytics direct.*advanced hunting"
        $script:Router | Should -Match '\$clTableHits'
    }

    It 'the verbose-only breadcrumb is not how the route is reported any more' {
        # Guards the regression directly: if someone demotes this back to Write-Diag, the next
        # occurrence is unexplainable again.
        $script:Router | Should -Not -Match 'Write-Diag \("\[route\] CL probe done'
    }
}
