#Requires -Version 5.1
<#
    AI summary modes -- Consistent vs PerReport, and the leader that decides whose
    figures both reports show.

    THE DEFECT THESE PIN. A customer reported the Detailed report's (much larger)
    figures appearing as the AI summary in BOTH mails, even though Detailed runs
    later. Reuse was gated only on the snapshot being younger than
    $SI_AISummary_MaxAgeHours, so the owner was not "whoever ran first" but "whoever
    first crossed the 24h line" -- which with a daily cadence and a gap between the
    two jobs drifts and then parks on Detailed.

    🪤 THE SECOND DEFECT, AND IT IS THE ONE WORTH REMEMBERING. Fixing the read path
    alone changed nothing: FOUR separate sites in the engine decide "may I adopt this
    snapshot", and three of them carried their own copy of the age test. The read path
    would correctly decline yesterday's snapshot and the pre-POST race guard, a few
    hundred lines later, would adopt the very same one. The last Describe block below
    asserts against the source that no site has grown its own copy again -- a
    structural assertion, because behaviour tests on the pure core cannot see it.
#>

BeforeAll {
    $script:Shared = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\_shared'
    . (Join-Path $script:Shared 'RA-AISummaryMode.ps1')
    $script:EnginePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'

    # A leader snapshot written the PREVIOUS UTC evening, read by the follower the NEXT
    # morning. This is the operator's own scheduling example and the case that killed
    # the UTC-day design -- so it is the fixture everything else is built around.
    $script:PrevEvening = [datetime]::new(2026, 9, 7, 23, 30, 0, [DateTimeKind]::Utc)
    $script:NextMorning = [datetime]::new(2026, 9, 8,  6,  0, 0, [DateTimeKind]::Utc)
}

Describe 'AI summary mode -- resolving the customer setting' {

    It 'defaults to Consistent when unset, because that is what every install already does' {
        # Changing this default would silently move the headline score on ~30 customers
        # and ~6,000 community installs on their next sync, with no announcement.
        (Resolve-RAAISummaryMode -Value $null).Mode   | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value '').Mode      | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value '   ').Mode   | Should -Be 'Consistent'
    }

    It 'accepts both modes case-insensitively' {
        (Resolve-RAAISummaryMode -Value 'consistent').Mode | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value 'PERREPORT').Mode  | Should -Be 'PerReport'
        (Resolve-RAAISummaryMode -Value 'per-report').Mode | Should -Be 'PerReport'
    }

    It 'accepts the words the behaviours were first described in' {
        # A config written from the design discussion rather than the reference file
        # still has to resolve, or a customer silently gets the wrong mode.
        (Resolve-RAAISummaryMode -Value 'FirstCome').Mode | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value 'Actual').Mode    | Should -Be 'PerReport'
    }

    It 'falls back to Consistent on an unrecognised value AND reports it unrecognised' {
        # Both halves matter: falling back keeps an unattended nightly report alive
        # through a typo, and the flag is what lets the engine warn instead of failing
        # silently into a mode the customer did not choose.
        $r = Resolve-RAAISummaryMode -Value 'Consistnet'
        $r.Mode       | Should -Be 'Consistent'
        $r.Recognised | Should -BeFalse
    }

    It 'distinguishes "not supplied" from "supplied and unrecognised"' {
        (Resolve-RAAISummaryMode -Value $null).Supplied   | Should -BeFalse
        (Resolve-RAAISummaryMode -Value 'rubbish').Supplied | Should -BeTrue
    }
}

Describe 'AI summary mode -- the default depends on the edition' {

    It 'Pro defaults to PerReport when the setting is unset' {
        # Operator 2026-10-05: in the Pro web app Summary and Detailed are one click
        # apart, so each report shows its own figures unless told otherwise.
        foreach ($v in @($null, '', '   ')) {
            $r = Resolve-RAAISummaryMode -Value $v -Edition 'Pro'
            $r.Mode     | Should -Be 'PerReport'
            $r.Supplied | Should -BeFalse
            $r.Edition  | Should -Be 'Pro'
        }
        (Resolve-RAAISummaryMode -Value $null -Edition 'pro').Mode | Should -Be 'PerReport'
    }

    It 'Community keeps Consistent, and an unknown or missing edition is Community' {
        # Not knowing the edition must never move ~6,000 community installs off their default.
        (Resolve-RAAISummaryMode -Value $null -Edition 'Community').Mode | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value $null -Edition $null).Mode       | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value $null -Edition 'Enterprise').Mode | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value $null).Edition                   | Should -Be 'Community'
    }

    It 'an explicitly set value wins in both editions' {
        (Resolve-RAAISummaryMode -Value 'Consistent' -Edition 'Pro').Mode       | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value 'PerReport'  -Edition 'Community').Mode | Should -Be 'PerReport'
        (Resolve-RAAISummaryMode -Value 'FirstCome'  -Edition 'Pro').Mode       | Should -Be 'Consistent'
        (Resolve-RAAISummaryMode -Value 'Consistent' -Edition 'Pro').Supplied   | Should -BeTrue
    }

    It 'an unrecognised value falls back to the EDITION default and says so' {
        $p = Resolve-RAAISummaryMode -Value 'Consistnet' -Edition 'Pro'
        $p.Mode | Should -Be 'PerReport'; $p.Recognised | Should -BeFalse
        $c = Resolve-RAAISummaryMode -Value 'Consistnet' -Edition 'Community'
        $c.Mode | Should -Be 'Consistent'; $c.Recognised | Should -BeFalse
    }

    It 'the edition is Pro exactly when the run took its settings from the Pro settings database' {
        Get-RAAISummaryEdition -ProSettingsVersion '20261005.1234-abc' | Should -Be 'Pro'
        Get-RAAISummaryEdition -ProSettingsVersion $null               | Should -Be 'Community'
        Get-RAAISummaryEdition -ProSettingsVersion ''                  | Should -Be 'Community'
        Get-RAAISummaryEdition -ProSettingsVersion '  '                | Should -Be 'Community'
    }

    It 'the default mode per edition' {
        Get-RAAISummaryDefaultMode -Edition 'Pro'       | Should -Be 'PerReport'
        Get-RAAISummaryDefaultMode -Edition 'Community' | Should -Be 'Consistent'
        Get-RAAISummaryDefaultMode -Edition $null       | Should -Be 'Consistent'
    }

    It 'the engine resolves the mode WITH the edition from the Pro settings version' {
        $src = Get-Content -LiteralPath $script:EnginePath -Raw
        $src | Should -Match 'Get-RAAISummaryEdition -ProSettingsVersion \(\[string\]\$global:SI_ProSettingsVersion\)'
        # every call to the resolver in the engine passes the edition
        $all  = ([regex]::Matches($src, 'Resolve-RAAISummaryMode -Value')).Count
        $with = ([regex]::Matches($src, 'Resolve-RAAISummaryMode -Value \(\[string\]\$global:SI_AISummary_Mode\) -Edition')).Count
        $all  | Should -BeGreaterOrEqual 2
        $with | Should -Be $all
    }

    It 'the settings catalog says the default depends on the edition' {
        # The settings catalog is SecurityInsight Pro: a Community copy does not carry it (Test-Path, then skip).
        $catPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config\settings.catalog.locked.json'
        if (-not (Test-Path -LiteralPath $catPath)) { Set-ItResult -Skipped -Because 'the settings catalog is SecurityInsight Pro'; return }
        $cat = Get-Content -LiteralPath $catPath -Raw | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_AISummary_Mode' })[0]
        $s.default      | Should -BeNullOrEmpty
        $s.defaultText  | Should -Match 'Pro: PerReport'
        $s.defaultText  | Should -Match 'Community: Consistent'
    }
}

Describe 'the cached KPI follows the mode' {

    BeforeAll { $script:Kpi = [pscustomobject]@{ GlobalScore = 71; SourceTemplate = 'RiskAnalysis_Summary_Bucket' } }

    It 'PerReport never takes a cached score, even when one is in memory' {
        # In PerReport each report computes its own KPI -- the leader's score must not
        # reach the other report's mail or executive view.
        Test-RAAISummaryUseCachedKpi -Mode 'PerReport' -CachedKpi $script:Kpi | Should -BeFalse
    }

    It 'Consistent takes the cached score when it carries one' {
        Test-RAAISummaryUseCachedKpi -Mode 'Consistent' -CachedKpi $script:Kpi | Should -BeTrue
    }

    It 'nothing to take when there is no snapshot or it has no score' {
        Test-RAAISummaryUseCachedKpi -Mode 'Consistent' -CachedKpi $null | Should -BeFalse
        Test-RAAISummaryUseCachedKpi -Mode 'Consistent' -CachedKpi ([pscustomobject]@{ GlobalScore = $null }) | Should -BeFalse
        Test-RAAISummaryUseCachedKpi -Mode 'Consistent' -CachedKpi ([pscustomobject]@{ AISummaryText = 'x' }) | Should -BeFalse
    }

    It 'a Pro run with the setting unset therefore never takes the leader''s score' {
        $mode = (Resolve-RAAISummaryMode -Value $null -Edition (Get-RAAISummaryEdition -ProSettingsVersion 'v1')).Mode
        Test-RAAISummaryUseCachedKpi -Mode $mode -CachedKpi $script:Kpi | Should -BeFalse
        Test-RAAISummaryShouldAdopt -Mode $mode -LeaderGrain 'Summary' -MyGrain 'Detailed' -SnapshotGrain 'Summary' `
            -GeneratedAtUtc $script:NextMorning.AddMinutes(-5) -NowUtc $script:NextMorning -MaxAgeHours 24 -HasSnapshot |
            ForEach-Object { $_.Adopt | Should -BeFalse }
    }

    It 'every engine site that would override the score with the cached one asks the shared gate' {
        $src = Get-Content -LiteralPath $script:EnginePath -Raw
        $src | Should -Not -Match 'if \(\$script:_CachedRAKPI -and \$null -ne \$script:_CachedRAKPI\.GlobalScore'
        ([regex]::Matches($src, 'Test-RAAISummaryUseCachedKpi -Mode')).Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'AI summary leader -- who is the source of truth' {

    It 'defaults to Detailed (#636: the Summary step is optional and off by default)' {
        (Resolve-RAAISummaryLeader -Value $null).Leader | Should -Be 'Detailed'
    }

    It 'can be inverted to Detailed for customers whose management reads that report' {
        (Resolve-RAAISummaryLeader -Value 'Detailed').Leader | Should -Be 'Detailed'
        (Resolve-RAAISummaryLeader -Value 'detail').Leader   | Should -Be 'Detailed'
    }

    It 'falls back to Detailed on nonsense, and says it did not recognise it' {
        $r = Resolve-RAAISummaryLeader -Value 'whatever'
        $r.Leader     | Should -Be 'Detailed'
        $r.Recognised | Should -BeFalse
    }
}

Describe 'report grain -- reducing a template name to Summary or Detailed' {

    It 'classifies the template names that actually ship' {
        # These differ per install: the engine default carries the auto-bucketing
        # suffix, the community launcher does not.
        Get-RAReportGrainLabel -ReportTemplate 'RiskAnalysis_Summary_Bucket'  | Should -Be 'Summary'
        Get-RAReportGrainLabel -ReportTemplate 'RiskAnalysis_Detailed_Bucket' | Should -Be 'Detailed'
        Get-RAReportGrainLabel -ReportTemplate 'RiskAnalysis_Summary'         | Should -Be 'Summary'
        Get-RAReportGrainLabel -ReportTemplate 'RiskAnalysis_Detailed'        | Should -Be 'Detailed'
    }

    It 'tests Detailed FIRST, so a name carrying both words is not mislabelled' {
        # 'RiskAnalysis_Detailed_Summary_Bucket' is a Detailed report. Matching Summary
        # first would call it a Summary and let it adopt figures of the wrong grain.
        Get-RAReportGrainLabel -ReportTemplate 'RiskAnalysis_Detailed_Summary_Bucket' | Should -Be 'Detailed'
    }

    It 'returns null for a template it cannot classify, rather than guessing' {
        # Customers may set $global:ReportTemplate to anything. Guessing here would put
        # an unclassifiable report into the leader/follower relationship.
        Get-RAReportGrainLabel -ReportTemplate 'CustomerBespokeReport' | Should -BeNullOrEmpty
        Get-RAReportGrainLabel -ReportTemplate ''                     | Should -BeNullOrEmpty
        Get-RAReportGrainLabel -ReportTemplate $null                  | Should -BeNullOrEmpty
    }
}

Describe 'the adoption decision -- Consistent mode' {

    It 'THE OPERATOR SCHEDULE: follower adopts a leader snapshot from the previous UTC day' {
        # The case that killed the UTC-day design. Summary 23:30, Detailed 06:00 next
        # morning -- different dates, same intent, and they MUST still agree.
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                -MyGrain 'Detailed' -SnapshotGrain 'Summary' `
                -GeneratedAtUtc $script:PrevEvening -NowUtc $script:NextMorning `
                -MaxAgeHours 24 -HasSnapshot
        $r.Adopt | Should -BeTrue
    }

    It 'THE REPORTED BUG: the leader never adopts the follower figures' {
        # This is the whole complaint. Detailed's larger numbers must never appear in
        # the Summary mail, whatever ran first and whenever it ran.
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                -MyGrain 'Summary' -SnapshotGrain 'Detailed' `
                -GeneratedAtUtc $script:PrevEvening -NowUtc $script:NextMorning `
                -MaxAgeHours 24 -HasSnapshot
        $r.Adopt | Should -BeFalse
    }

    It 'the leader does not even adopt its OWN previous snapshot -- it always rebuilds' {
        # Otherwise the leader would replay stale figures instead of reporting today.
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                -MyGrain 'Summary' -SnapshotGrain 'Summary' `
                -GeneratedAtUtc $script:PrevEvening -NowUtc $script:NextMorning `
                -MaxAgeHours 24 -HasSnapshot
        $r.Adopt | Should -BeFalse
    }

    It 'the follower does not adopt a snapshot left by another follower run' {
        # A snapshot written by the follower (in a cycle where the leader did not run)
        # must not be promoted into the leader's role on the next cycle.
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                -MyGrain 'Detailed' -SnapshotGrain 'Detailed' `
                -GeneratedAtUtc $script:PrevEvening -NowUtc $script:NextMorning `
                -MaxAgeHours 24 -HasSnapshot
        $r.Adopt | Should -BeFalse
    }

    It 'inverting the leader inverts the relationship and nothing else' {
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Detailed' `
                -MyGrain 'Summary' -SnapshotGrain 'Detailed' `
                -GeneratedAtUtc $script:PrevEvening -NowUtc $script:NextMorning `
                -MaxAgeHours 24 -HasSnapshot
        $r.Adopt | Should -BeTrue
    }

    It 'refuses a snapshot past the backstop, so an offline host cannot poison today' {
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                -MyGrain 'Detailed' -SnapshotGrain 'Summary' `
                -GeneratedAtUtc $script:PrevEvening.AddDays(-9) -NowUtc $script:NextMorning `
                -MaxAgeHours 24 -HasSnapshot
        $r.Adopt  | Should -BeFalse
        $r.Reason | Should -Match 'backstop'
    }

    It 'is time-of-day agnostic: adoption does not change across a midnight boundary' {
        # The property the leader design exists to provide. Same relationship, four very
        # different clock positions, one answer.
        foreach ($pair in @(
            @{ Gen = [datetime]::new(2026,9,7,13,0,0,[DateTimeKind]::Utc); Now = [datetime]::new(2026,9,7,23,0,0,[DateTimeKind]::Utc) }
            @{ Gen = [datetime]::new(2026,9,7,23,59,0,[DateTimeKind]::Utc); Now = [datetime]::new(2026,9,8,0,1,0,[DateTimeKind]::Utc) }
            @{ Gen = [datetime]::new(2026,9,7,18,0,0,[DateTimeKind]::Utc); Now = [datetime]::new(2026,9,8,5,0,0,[DateTimeKind]::Utc) }
            @{ Gen = [datetime]::new(2026,9,8,1,0,0,[DateTimeKind]::Utc);  Now = [datetime]::new(2026,9,8,7,0,0,[DateTimeKind]::Utc) }
        )) {
            $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                    -MyGrain 'Detailed' -SnapshotGrain 'Summary' `
                    -GeneratedAtUtc $pair.Gen -NowUtc $pair.Now -MaxAgeHours 24 -HasSnapshot
            $r.Adopt | Should -BeTrue -Because "generated $($pair.Gen) read at $($pair.Now) is the same relationship"
        }
    }

    It 'builds its own when there is no snapshot at all' {
        $r = Test-RAAISummaryShouldAdopt -Mode Consistent -LeaderGrain 'Summary' `
                -MyGrain 'Detailed' -SnapshotGrain $null -GeneratedAtUtc $null `
                -NowUtc $script:NextMorning -MaxAgeHours 24
        $r.Adopt | Should -BeFalse
    }
}

Describe 'the adoption decision -- PerReport mode' {

    It 'never adopts, whatever the leader, grain or age say' {
        # PerReport is the mode where each report shows its own numbers. If ANY
        # combination adopted, the mode would not deliver what it promises.
        foreach ($leader in @('Summary','Detailed')) {
            foreach ($mine in @('Summary','Detailed')) {
                foreach ($snap in @('Summary','Detailed')) {
                    $r = Test-RAAISummaryShouldAdopt -Mode PerReport -LeaderGrain $leader `
                            -MyGrain $mine -SnapshotGrain $snap `
                            -GeneratedAtUtc $script:NextMorning.AddMinutes(-5) `
                            -NowUtc $script:NextMorning -MaxAgeHours 24 -HasSnapshot
                    $r.Adopt | Should -BeFalse -Because "PerReport must never adopt (leader=$leader mine=$mine snapshot=$snap)"
                }
            }
        }
    }
}

Describe 'the engine wiring -- structural, because behaviour tests cannot see this' {

    BeforeAll { $script:EngineSrc = Get-Content -LiteralPath $script:EnginePath -Raw }

    It 'dot-sources the decision helper' {
        $script:EngineSrc | Should -Match '_shared/RA-AISummaryMode\.ps1'
    }

    It 'routes EVERY freshness decision through the one shared function' {
        # 🪤 THE REGRESSION THIS EXISTS FOR. Four sites ask "may I adopt this snapshot":
        # the initial read, the pre-POST race re-check, the post-build race check and the
        # final pre-email re-read. Three of them used to carry their own age test, so a
        # fix to the read path was silently undone a few hundred lines later.
        $calls = ([regex]::Matches($script:EngineSrc, 'Test-RAAISummaryShouldAdopt')).Count
        $calls | Should -BeGreaterOrEqual 4
    }

    It 'has NO site left comparing snapshot age on its own' {
        # The exact shape of the defect: `if ($someAge.TotalHours -le $aiSummaryMaxAgeHours)`
        # as a standalone adoption gate. Any reappearance is a site that has grown its
        # own opinion again.
        $script:EngineSrc | Should -Not -Match 'TotalHours\s+-le\s+\$aiSummaryMaxAgeHours'
    }

    It 'gates the cache read AND the cache write on the mode, in the functions themselves' {
        # PerReport is enforced inside Get-/Save-RATop50CachedFile rather than at the
        # seven call sites, so it cannot be partially applied.
        $script:EngineSrc | Should -Match "function Get-RATop50CachedFile[\s\S]{0,2000}?_AISummaryMode -eq 'PerReport'"
        $script:EngineSrc | Should -Match "function Save-RATop50CachedFile[\s\S]{0,2000}?_AISummaryMode -eq 'PerReport'"
    }

    It 'narrates the cache write from what the writer REPORTS, not from having called it' {
        # 🪤 FOUND BY THE FIRST LIVE PerReport RUN, not by any test. The mode gate lives
        # inside Save-RATop50CachedFile (correctly), but the Write-Info sat unconditionally
        # after the call -- so a run that wrote nothing logged "persisted fresh AI summary
        # ... (next run within 24h will reuse it)". A log line claiming work that never
        # happened is the same defect as one hiding work that did.
        $script:EngineSrc | Should -Match '\$_wrote\s*=\s*Save-RATop50CachedFile'
        $script:EngineSrc | Should -Match 'if\s*\(Save-RATop50CachedFile[^)]*\)\s*\{'
        # and the writer has to actually report it
        $script:EngineSrc | Should -Match 'return \$wroteLocal'
    }

    It 'does not warn about a missing cache file in the mode that deliberately has none' {
        # Same live run also produced "[WARN] cache file disappeared between AI-write and
        # KPI-update" -- describing PerReport working exactly as designed. A warning that
        # fires on correct behaviour teaches operators to ignore warnings.
        # (Bug B, 2026-10-22: the gate is "the cache is readable" -- the Consistent mode with its readers defined; PerReport and a
        # run with the AI summary off, which has no mode at all, never touch it)
        $script:EngineSrc | Should -Match "_RACacheNeedsKPIUpdate -and \`$global:RA_KPI -and \`$script:RACacheReadable"
        $script:EngineSrc | Should -Match "\`$script:RACacheReadable = \(\`$script:_AISummaryMode -eq 'Consistent'\) -and \[bool\]\(Get-Command -Name Get-RATop50CachedFile -ErrorAction SilentlyContinue\)"
    }

    It 'Bug B (2026-10-22): no late reader of the cache runs where the readers are not defined (the AI summary off)' {
        foreach ($site in '$finalCheck = Get-RATop50CachedFile', '$cachedNow = Get-RATop50CachedFile', '$__cachedP = Get-RATop50CachedFile') {
            $i = $script:EngineSrc.IndexOf($site)
            $i | Should -BeGreaterThan 0 -Because $site
            $gate = $script:EngineSrc.LastIndexOf('$script:RACacheReadable', $i)
            $gate | Should -BeGreaterThan 0 -Because "$site is behind the gate"
            ($i - $gate) | Should -BeLessThan 1200 -Because "$site sits right under its gate"
        }
    }

    It 'ships the grain explanation in the mail body in BOTH modes' {
        # (B) -- the sentence that answers management's question instead of hiding it.
        # It must not sit inside a mode branch.
        $script:EngineSrc | Should -Match '\$grainNote\s*='
        $script:EngineSrc | Should -Match 'counts distinct <strong>assets</strong>'
    }
}
