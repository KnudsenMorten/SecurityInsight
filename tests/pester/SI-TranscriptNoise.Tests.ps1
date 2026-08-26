#Requires -Version 5.1
<#
    AN EXPECTED FAILURE MUST NOT SURFACE AS A TERMINATING ERROR.

    Operator, 2026-08-26: *"i dont want to see things like that in logs, as customers are calling me
    asking what it means"*.

    PowerShell transcripts record EVERY terminating error -- including ones that are caught and
    handled -- as a `PS>TerminatingError(...)` block, complete with HTTP status, request ids and
    response bodies. So a run that is behaving exactly as designed can print several alarming stack
    dumps, and the customer reading their own transcript reasonably concludes something broke.

    TWO PLACES DID THIS, and in both the failure is the EXPECTED answer, not a fault:

    1. `Test-AdvancedHuntingHasTable` (v2.2.445) -- asks whether a customer's SI_*_CL table is
       mirrored into advanced hunting. For most tenants the answer is legitimately NO, and the engine
       immediately routes to Log Analytics instead. It asked with `-ErrorAction Stop`, which PROMOTES
       the cmdlet's non-terminating error into a terminating one. Four dumps per healthy run.

    2. `Invoke-SISentinelLakeQuery` (v2.2.451) -- queries the Sentinel data lake. The lake is NOT
       onboarded on most tenants, so `400 InvalidDatabaseInQuery` is the expected reply and the
       caller already falls back silently. It produced TWO terminating errors per attempt: one from
       `Invoke-RestMethod -ErrorAction Stop`, and one from our own `throw` of the formatted message.

    🔑 THE TRAP THAT CATCHES YOU TWICE: re-throwing inside the fix. A caught-and-rethrown error is
    still a terminating error, so `catch { throw $msg }` writes the very block you are removing. Both
    fixes therefore RETURN the failure rather than throwing it. I made exactly this mistake in the
    first cut of fix 1 and caught it before shipping; these tests exist so the next person does not
    have to.
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
