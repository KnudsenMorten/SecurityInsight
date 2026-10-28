#Requires -Version 7.0
<#
    #882 A REPORT THAT FAILS FAILS ALONE (owner 2026-10-22: "we cannot loose data (prio 1) but if a report fails, then let it
    fail so job completes so we can fix issue"). The Risk Analysis step ends FAILED only when nothing of the run can be trusted
    as stored (RA-Delivery.ps1 Get-RARunEndVerdict + the engine's end):
      1. rows of a report could not be removed AND could not be recorded as held back (#877);
      2. the collection could not be marked complete;
      3. a run WITHOUT a database whose Log Analytics post was refused or not delivered in full;
      4. a run WITH a database whose result could not go there and reached no copy ("nothing could be stored").
    Every other report failure is a warning: the report keeps its last complete result, the run is partial, the job completes.
    Live evidence (2026-10-22, old build): a large install's Device_Missing_CVEs_Detailed lost slices to 504 Gateway Timeout and
    then could not remove its rows in time -- the step ended failed; a 504 is now asked again at the same size (busy, #880).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Delivery.ps1')
    $script:Engine = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
}

Describe 'when the run ends failed -- one case each' {
    It '1. rows that cannot be recorded as held back fail the run' {
        $v = Get-RARunEndVerdict -StreamWanted $true -StreamOn $true -Broken 'the rows of report X could not be removed, and not recorded as held'
        $v.Fail | Should -BeTrue
        $v.Why | Should -Match 'not complete'
    }
    It '2. a collection that cannot be marked complete fails the run' {
        (Get-RARunEndVerdict -StreamWanted $true -StreamOn $true -CompleteError 'timeout').Fail | Should -BeTrue
    }
    It '3. a run without a database: Log Analytics refused or did not receive the post' {
        (Get-RARunEndVerdict -StreamOn $false -LaRefused @('SI_RiskAnalysis_Detailed_CL was NOT written')).Fail | Should -BeTrue
        (Get-RARunEndVerdict -StreamOn $false -LaNotDelivered @('did not receive this run''s result in full')).Fail | Should -BeTrue
    }
    It '4. a run with a database whose result could not go there and reached no copy: nothing could be stored' {
        $v = Get-RARunEndVerdict -StreamWanted $true -StreamOn $false -LaSent $false -StreamWhy 'login failed'
        $v.Fail | Should -BeTrue
        $v.Why | Should -Match 'nothing of this run could be stored.*login failed'
        (Get-RARunEndVerdict -StreamWanted $true -StreamOn $false -LaSent $true).Fail | Should -BeFalse -Because 'the copy in Log Analytics holds it'
        (Get-RARunEndVerdict -StreamWanted $true -StreamOn $false -WhatIf $true).Fail | Should -BeFalse -Because 'a dry run stores nothing on purpose'
    }
}

Describe 'when the run does NOT end failed' {
    It 'a run with a database whose reports failed, were held or lost slices -- and whose Log Analytics COPY failed -- completes' {
        $v = Get-RARunEndVerdict -StreamWanted $true -StreamOn $true -LaRefused @('copy refused') -LaNotDelivered @('copy cut')
        $v.Fail | Should -BeFalse -Because 'with a database the copy never fails the run (#743); the reports keep their last complete result (#877)'
    }
    It 'a Community run without a database that stored its result in Log Analytics completes' {
        (Get-RARunEndVerdict -StreamWanted $false -StreamOn $false -LaSent $true).Fail | Should -BeFalse
    }
}

Describe 'the engine' {
    It 'judges the end with Get-RARunEndVerdict, knows whether the run has a database, and throws only through _RAEndFailure' {
        $script:Engine | Should -Match 'Get-RARunEndVerdict -StreamWanted \(\[bool\]\$script:RAStreamWanted\)'
        $script:Engine | Should -Match '(?s)if \(Test-RAStreamWanted\) \{.{0,400}\$script:RAStreamWanted = \$true'
        $script:Engine | Should -Match 'throw \(\[string\]\$script:_RAEndFailure\.Throw\)'
    }
    It 'a report that throws is caught per report and recorded NOT COMPLETE (the loop goes on)' {
        $script:Engine | Should -Match '(?s)foreach \(\$includeItem in \$script:RALoopList\) \{\s+try \{'
        $script:Engine | Should -Match "completeness: report '\{0\}' is NOT COMPLETE in this run"
    }
    It 'the held-back rule (#877) and the per-report scope are still what makes such a run partial, not failed' {
        $script:Engine | Should -Match 'Set-RAStreamHeldReports -Stream \$script:RAStream'
        $script:Engine | Should -Match "Get-RAPartialScope -Reports"
    }
}
