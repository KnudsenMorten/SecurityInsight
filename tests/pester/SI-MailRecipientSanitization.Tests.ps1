#Requires -Version 5.1
<#
    v2.2.444 -- ONE EMPTY STRING IN THE RECIPIENT ARRAY KILLED THE ENTIRE RISK ANALYSIS RUN.

    Reported from a production run. The operator's config carried a trailing empty element:
        $global:RiskAnalysis_Detailed_To = @("a@x.dk","b@y.dk","c@y.dk","")
    which is what a trailing comma, or deleting an address and leaving its quotes behind, produces.
    Nothing between the config and the cmdlet ever looked at the values, so it reached
    Send-MailMessage's -To -- which validates PER ELEMENT -- and threw:
        "Cannot bind argument to parameter 'To' because it is an empty string"

    🪤 AND IT LANDED AT THE WORST POSSIBLE MOMENT. The report was built, the workbook written, every
    query already run, and the run died on the FINAL dispatch. Same shape as v2.2.439, where a finished
    Risk Analysis run could be thrown away at the last write. The engine's own diagnostic dump even
    printed the trailing ", " in its To line and nothing said why that mattered.

    These tests pin the FILTER (the logic that fixes it) and the WIRING (that the engine actually uses
    it) separately, because green filter logic proves nothing if the engine never calls it -- the
    "declared but never wired" shape this codebase has produced eleven times.
#>

BeforeAll {
    # tests\pester\<file> -> two parents lands in tests\, so the solution root needs the '..' the other
    # suites in this folder also use. Getting this wrong made every WIRING test fail on a missing file
    # rather than on the thing it guards -- a test that fails for an unrelated reason is worse than none.
    $script:Engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..\engine\risk-analysis\Invoke-RiskAnalysis.ps1'

    # The filter exactly as the engine applies it. Kept as a function here so the SHAPES can be
    # enumerated cheaply; the wiring block below asserts the engine contains this same expression.
    function script:SanitizeTo {
        param([AllowNull()]$Raw)
        $r = @($Raw)
        ,@($r | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
}

Describe 'the recipient filter -- every shape an operator config can produce' {

    It '🔴 THE REPORTED BUG: a trailing empty string is dropped, the real recipients survive' {
        $to = script:SanitizeTo @("a@x.net","b@y.dk","c@y.dk","d@y.dk","e@y.dk","")
        $to.Count | Should -Be 5
        $to       | Should -Not -Contain ''
        $to[0]    | Should -BeExactly 'a@x.net'
    }

    It 'drops a whitespace-only element' {
        (script:SanitizeTo @("a@x.dk","   ","b@y.dk")).Count | Should -Be 2
    }

    It 'drops a $null element -- @() over a config array can contain one' {
        (script:SanitizeTo @("a@x.dk",$null,"b@y.dk")).Count | Should -Be 2
    }

    It 'TRIMS surrounding whitespace rather than dropping the address' {
        # "  a@x.dk  " is a usable address with a typo around it, not a blank. Dropping it would lose a
        # real recipient silently -- the opposite failure, and a worse one.
        $to = script:SanitizeTo @("  a@x.dk  ","b@y.dk")
        $to.Count | Should -Be 2
        $to[0]    | Should -BeExactly 'a@x.dk'
    }

    It '🔑 a CLEAN list is returned completely unchanged' {
        # The regression that would matter most: a fix that quietly drops good recipients.
        $in = @("a@x.dk","b@y.dk","c@z.dk")
        $to = script:SanitizeTo $in
        $to.Count | Should -Be 3
        ($to -join '|') | Should -BeExactly ($in -join '|')
    }

    It 'an ALL-BLANK list yields zero, not one empty string' {
        (script:SanitizeTo @("","   ",$null)).Count | Should -Be 0
    }

    It 'an empty or null config yields zero and does not throw' {
        { script:SanitizeTo @() }  | Should -Not -Throw
        { script:SanitizeTo $null } | Should -Not -Throw
        (script:SanitizeTo @()).Count | Should -Be 0
    }

    It 'a single bare string (not an array) still works' {
        # $global:MailTo = "a@x.dk" is legal config and must not be split into characters.
        $to = script:SanitizeTo 'a@x.dk'
        $to.Count | Should -Be 1
        $to[0]    | Should -BeExactly 'a@x.dk'
    }
}

Describe '🔑 IS THE FILTER ACTUALLY WIRED? -- green filter logic proves nothing on its own' {

    BeforeAll { $script:Code = Get-Content $script:Engine -Raw }

    It 'the engine sanitises rather than assigning $global:Report_To straight through' {
        # The defect line was:  $to = @($global:Report_To)
        $script:Code | Should -Not -Match '\$to\s*=\s*@\(\$global:Report_To\)\s*$'
        $script:Code | Should -Match 'IsNullOrWhiteSpace'
    }

    It 'the filter sits ABOVE the send decision, so BOTH send branches are covered' {
        # Anonymous and secure are two separate calls. Filtering inside one would leave the other
        # exposed, and the two would drift.
        $iFilter = $script:Code.IndexOf('$__toDropped')
        $iSend   = $script:Code.IndexOf('sending mail anonymously to')
        $iFilter | Should -BeGreaterThan 0
        $iSend   | Should -BeGreaterThan 0
        $iFilter | Should -BeLessThan $iSend
    }

    It '🔴 an all-blank list SKIPS the send instead of throwing -- mail is non-fatal here' {
        # The report and workbook are already complete on disk by this point. Discarding a finished run
        # over an email is the v2.2.439 failure, and this must not reintroduce it.
        $script:Code | Should -Match 'mail dispatch SKIPPED'
        $script:Code | Should -Match '\$global:Report_SendMail\s*=\s*\$false'
    }

    It 'the dropped count is REPORTED, not silently swallowed' {
        # House rule: every silent cap says what it dropped. A config that quietly loses a recipient
        # looks exactly like one that works.
        $script:Code | Should -Match 'mail recipients: dropped'
    }

    It 'the skip message tells the operator their report is SAFE' {
        # Without this, "mail dispatch SKIPPED" reads as "the run failed" and someone re-runs a
        # 30-minute Risk Analysis for nothing.
        $script:Code | Should -Match 'COMPLETE and on disk'
    }
}
