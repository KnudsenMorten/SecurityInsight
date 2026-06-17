#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 tests for the SI Analyzer POC -- the pure, offline cores.
.DESCRIPTION
    Covers: the read-only KQL guardrail (allow-list + destructive-operator
    rejection), the prestaged-KQL builders, the snapshot diff (new/closed/
    score-delta), the score-timeline aggregation, and the AI-prompt assembly
    (grounding + AI-optional degradation). No network; demo data only.
#>

BeforeAll {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> SecurityInsight (3 ups)
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:LibDir = Join-Path $si 'analyzer\lib'
    . (Join-Path $script:LibDir 'SiAnalyzer-Kql.ps1')
    . (Join-Path $script:LibDir 'SiAnalyzer-Diff.ps1')
    . (Join-Path $script:LibDir 'SiAnalyzer-Ai.ps1')
    . (Join-Path $script:LibDir 'SiAnalyzer-Data.ps1')
    $script:DemoRows = @(Get-SiDemoRows)
}

Describe 'Read-only guardrail (Test-SiKqlReadOnly)' {

    It 'allows a clean snapshot-correct query over an allowed table' {
        $q = "SI_Endpoint_Profile_CL | where CollectionTime == toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime)) | take 10"
        (Test-SiKqlReadOnly -Query $q).Allowed | Should -BeTrue
    }

    It 'rejects a .drop control command' {
        (Test-SiKqlReadOnly -Query '.drop table SI_Endpoint_Profile_CL').Allowed | Should -BeFalse
    }

    It 'rejects .set / .append / .create / .ingest / .purge' {
        foreach ($cmd in @('.set X','.append X','.create table X','.ingest inline into table X','.purge table X')) {
            (Test-SiKqlReadOnly -Query "$cmd <[ SI_Endpoint_Profile_CL ]>").Allowed | Should -BeFalse
        }
    }

    It 'rejects externaldata / cluster() / database()' {
        (Test-SiKqlReadOnly -Query 'externaldata (x:string) [@"http://evil"]').Allowed | Should -BeFalse
        (Test-SiKqlReadOnly -Query 'cluster("other").database("d").SI_Endpoint_Profile_CL').Allowed | Should -BeFalse
        (Test-SiKqlReadOnly -Query 'database("d").SI_Endpoint_Profile_CL').Allowed | Should -BeFalse
    }

    It 'rejects a table not on the allow-list' {
        $r = Test-SiKqlReadOnly -Query 'SecretCustomerStuff_CL | take 5'
        $r.Allowed | Should -BeFalse
        ($r.Reasons -join ' ') | Should -Match 'allow-list'
    }

    It 'rejects an ungrounded query (no recognised table)' {
        (Test-SiKqlReadOnly -Query 'print 1').Allowed | Should -BeFalse
    }

    It 'rejects an empty query' {
        (Test-SiKqlReadOnly -Query '').Allowed | Should -BeFalse
    }

    It 'reports the referenced tables it found' {
        $r = Test-SiKqlReadOnly -Query 'SI_Endpoint_Profile_CL | join ExposureGraphNodes on $left.x == $right.y'
        $r.Tables | Should -Contain 'SI_Endpoint_Profile_CL'
        $r.Tables | Should -Contain 'ExposureGraphNodes'
    }
}

Describe 'Prestaged + builder KQL' {

    It 'top worklist query is snapshot-correct and read-only' {
        $q = Build-SiTopWorklistKql -Top 100 -Domain 'all'
        $q | Should -Match 'max\(CollectionTime\)'
        (Test-SiKqlReadOnly -Query $q).Allowed | Should -BeTrue
    }

    It 'score timeline query references all four profile tables' {
        $q = Build-SiScoreTimelineKql
        foreach ($t in @('SI_Endpoint_Profile_CL','SI_Identity_Profile_CL','SI_Azure_Profile_CL','SI_PublicIP_Profile_CL')) {
            $q | Should -Match $t
        }
    }

    It 'every prestaged analysis passes the read-only guardrail' {
        (Test-SiPrestagedLibrary).Count | Should -Be 0
    }

    It 'ships at least 3 prestaged analyses' {
        (Get-SiPrestagedAnalyses).Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'Snapshot diff (Get-SiSnapshotDiff)' {

    It 'detects new findings between the two demo snapshots' {
        $d = Get-SiSnapshotDiff -Rows $script:DemoRows
        $d.NewCount | Should -BeGreaterThan 0
    }

    It 'detects a closed finding (score fell to/below threshold)' {
        # Demo: az-0201 fell from 63 -> 28; with a closed threshold of 40 it counts as closed.
        $d = Get-SiSnapshotDiff -Rows $script:DemoRows -ClosedThreshold 40
        ($d.Closed | ForEach-Object { $_.ConfigurationId }) | Should -Contain 'az-0201'
    }

    It 'computes a score delta consistent with totals' {
        $d = Get-SiSnapshotDiff -Rows $script:DemoRows
        [math]::Round($d.CurrentTotal - $d.PreviousTotal, 2) | Should -Be $d.ScoreDelta
    }

    It 'flags a regression and an improvement' {
        $d = Get-SiSnapshotDiff -Rows $script:DemoRows
        # DEMO-WEB-07 went 78 -> 82 (regressed); demo-storage-prod 63 -> 28 (improved).
        ($d.Regressed | ForEach-Object { $_.Row.ConfigurationId }) | Should -Contain 'ep-0002'
        ($d.Improved  | ForEach-Object { $_.Row.ConfigurationId }) | Should -Contain 'az-0201'
    }

    It 'handles a single snapshot without throwing' {
        $one = @($script:DemoRows | Where-Object { $_.CollectionTime -eq '2026-06-17T06:00:00Z' })
        { Get-SiSnapshotDiff -Rows $one } | Should -Not -Throw
    }
}

Describe 'Score timeline (Get-SiScoreTimeline)' {

    It 'produces one point per CollectionTime' {
        $tl = Get-SiScoreTimeline -Rows $script:DemoRows
        $tl.Count | Should -Be 2
    }

    It 'computes a percent-from-previous on the latest point' {
        $tl = Get-SiScoreTimeline -Rows $script:DemoRows
        $tl[-1].PercentFromPrev | Should -Not -BeNullOrEmpty
    }

    It 'each point carries a per-tier breakdown' {
        $tl = Get-SiScoreTimeline -Rows $script:DemoRows
        $tl[0].PerTier.Keys.Count | Should -BeGreaterThan 0
    }
}

Describe 'AI prompt assembly + AI-optional degradation' {

    It 'grounds the prompt in the actual rows' {
        $p = Build-SiGroundedPrompt -Instruction 'Explain.' -Rows $script:DemoRows -Audience 'analyst'
        $p | Should -Match 'DATA ROWS'
        $p | Should -Match 'DEMO-DC-01'
        $p | Should -Match 'do not invent'
    }

    It 'NL->KQL prompt carries the allow-list and read-only contract' {
        $p = Build-SiNlToKqlPrompt -Question 'show risky servers' -AllowedTables (Get-SiAnalyzerAllowedTables)
        $p | Should -Match 'READ-ONLY ONLY'
        $p | Should -Match 'SI_Endpoint_Profile_CL'
    }

    It 'AI is reported unavailable when no OpenAI config is present' {
        # No $global:OpenAI_* set in this offline test process.
        Test-SiAiAvailable | Should -BeFalse
    }

    It 'templated fallback produces a plain-language summary without AI' {
        $latest = Get-SiLatestSnapshot -Rows $script:DemoRows
        $s = Get-SiTemplatedSummary -Rows $latest -Audience 'management'
        $s | Should -Match 'risk'
        $s | Should -Match 'AI summary unavailable'
    }

    It 'Invoke-SiAiChat returns null (fail-soft) when AI is unavailable' {
        Invoke-SiAiChat -SystemPrompt 's' -UserPrompt 'u' | Should -BeNullOrEmpty
    }
}
