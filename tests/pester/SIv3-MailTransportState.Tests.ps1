#Requires -Version 7.0
<#
    THE CLOSE-LOOP MAIL STEP FAILED ON INTERNAL (2026-11-01, 3.0.13): the technical owners' monthly review threw "Exception
    calling Substring with 2 argument(s): length ('-3') must be a non-negative value" while it was sent. The mail transport
    keeps its limits in file-level values ($script:SIMailSubjectEnvMax = 48, ...); where they were EMPTY in the scope the send
    ran in, Get-SIMailSubjectEnvironment cut the environment name to length 48 - 3 with 48 missing -> -3. Every function that
    reads those values now fills them with the transport's own defaults first (Initialize-SIMailTransportState).

      * with every file-level value removed, a subject still builds (environment name, product, length limit);
      * the restriction verdict, the forward sentinels and the settings' inline size still read their defaults;
      * a value already set is kept (a test's or an install's own);
      * CONTROL: the old line, with the limit empty, throws exactly the live error.
#>

BeforeAll {
    $script:SIRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $script:SIRoot 'engine\_shared\SI-MailTransport.ps1')
    $script:Names = 'SIMailTransportRoot', 'SIMailGraphInlineMaxMb', 'SIMailRestrictionCache', 'SIMailAllowedStates', 'SIMailProduct', 'SIMailSubjectMax', 'SIMailSubjectEnvMax', 'SIMailForwardSentinels'
    function script:Clear-TransportState { foreach ($n in $script:Names) { Set-Variable -Name $n -Scope Script -Value $null } }
}

Describe 'the mail transport works with its file-level values empty' {
    BeforeEach { Clear-TransportState }

    It 'builds the environment part of a subject (the live failure)' {
        $long = [pscustomobject]@{ Name = ('A very long internal environment name that is longer than the subject limit allows') }
        { Get-SIMailSubjectEnvironment -Environment $long } | Should -Not -Throw
        $n = Get-SIMailSubjectEnvironment -Environment $long
        $n.Length | Should -BeLessOrEqual 48
        $n | Should -Match '\.\.\.$'
    }

    It 'builds a whole subject with the product and the default length limit' {
        $s = Get-SIMailSubject -Subject 'Technical review' -Environment ([pscustomobject]@{ Name = 'Internal' })
        $s | Should -Match '\[SecurityInsight\]'
        $s.Length | Should -BeLessOrEqual 120
    }

    It 'every value the functions read gets its default' {
        Initialize-SIMailTransportState
        $script:SIMailAllowedStates | Should -Contain 'verified'
        $script:SIMailGraphInlineMaxMb | Should -Be 3
        $script:SIMailRestrictionCache.GetType().Name | Should -Be 'Hashtable'
        $script:SIMailForwardSentinels | Should -Contain 'none'
        $script:SIMailProduct | Should -Be 'SecurityInsight'
        $script:SIMailTransportRoot | Should -Not -BeNullOrEmpty
    }

    It 'a value already set is kept' {
        $script:SIMailSubjectEnvMax = 20
        Initialize-SIMailTransportState
        $script:SIMailSubjectEnvMax | Should -Be 20
    }

    It 'CONTROL: the old line throws exactly the live error when the limit is empty' {
        $max = $null; $n = 'A name longer than nothing'
        { if ($n.Length -gt $max) { $n.Substring(0, $max - 3) } } | Should -Throw '*must be a non-negative value*'
    }
}
