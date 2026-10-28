#Requires -Version 5.1
<#
    #636 (owner 2026-10-19): THE PROTECTION SCORE -- ONE engine function for both editions (engine\_shared\SI-ProtectionScore.ps1),
    computed by Risk Analysis from the Detailed findings and the CIs, shown in the Risk Analysis mail in its two views; and the
    source's own first-seen on the finding rows (engine\risk-analysis\_shared\RA-SourceFirstSeen.ps1). Offline, Community-safe
    (no Pro file). The engine function and the Pro SQL agree on one fixture: SIv3-Remediations.Tests.ps1 (local SQL Server).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $script:Root 'engine\_shared\SI-ProtectionScore.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-PatchCycle.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SourceFirstSeen.ps1')
    $script:T = [datetime]'2026-10-19T15:00:00'
    # #860: the fixture tests the grace MECHANICS on findings of every kind, so -- unless -Shipped -- a non-patch finding gets the
    # same 30 days (SI_ProtectionScore_OtherGraceDays_*); the shipped default (0) has its own tests below
    function script:NewFixture($Settings = @{}, [switch]$Shipped) {
        $s = @{}
        if (-not $Shipped) { foreach ($k in 'Device', 'Identity', 'CloudResource', 'PublicIp') { $s['SI_ProtectionScore_OtherGraceDays_' + $k] = '30' } }
        foreach ($k in $Settings.Keys) { $s[$k] = $Settings[$k] }
        $t = New-SIProtectionTally -CollectionTime $script:T -Settings $s
        Add-SIProtectionAsset $t 'srv-oct' 'device' 'Server' 0       # October update, released 2026-10-13 (6 days)
        Add-SIProtectionAsset $t 'srv-aug' 'device' 'Server' 1       # August update (69 days)
        Add-SIProtectionAsset $t 'pc-ok' 'device' 'Workstation' 2    # only a Medium finding
        Add-SIProtectionAsset $t 'user-nodate' 'identity' 'User' 0   # a High finding without any date
        Add-SIProtectionAsset $t 'user-14d' 'identity' 'User' 2      # the source saw it 14 days ago
        Add-SIProtectionAsset $t 'sa-edge' 'cloud_resource' 'Storage' 1   # the fix released exactly 30 days ago
        Add-SIProtectionAsset $t 'grp' 'identity' 'Group' 0          # a group: never in scope
        Add-SIProtectionAsset $t 'pc-gone' 'device' 'Workstation' 2 -Active $false
        Add-SIProtectionFinding $t 'srv-oct' 'High' -UpdateName 'October 2026 Security Updates'
        Add-SIProtectionFinding $t 'srv-aug' 'Very High' -UpdateName 'August 2026 Security Updates'
        Add-SIProtectionFinding $t 'pc-ok' 'Medium'
        Add-SIProtectionFinding $t 'user-nodate' 'High'
        Add-SIProtectionFinding $t 'user-14d' 'High' -SourceFirstSeen '2026-10-05T15:00:00Z'
        Add-SIProtectionFinding $t 'sa-edge' 'High' -FixRelease '2026-09-19T15:00:00Z'
        Add-SIProtectionFinding $t 'grp' 'Very High'
        Add-SIProtectionFinding $t 'pc-gone' 'Very High'
        Add-SIProtectionFinding $t 'pc-ok' 'High' -Exempted $true
        $t
    }
}

Describe 'the protection score (the one engine function)' {
    It 'is the tier-weighted share of active assets in good standing, in two views; groups and inactive assets left out' {
        $s = Complete-SIProtectionTally -Tally (NewFixture)
        $s.Assets | Should -Be 6
        # weights 8 + 4 + 2 + 8 + 2 + 4 = 28; technical: only pc-ok (2) is good; lifecycle: srv-oct (8), pc-ok (2), user-14d (2)
        $s.Technical | Should -Be 7.1
        $s.Lifecycle | Should -Be 42.9
        $s.NoDate | Should -Be 1; $s.Findings | Should -Be 5
        (@($s.Rows | Where-Object { $_.Figure -eq 'lifecycle' -and $_.Dim1 -eq 'Devices' -and $_.Dim2 -eq '(all)' })[0]).Value | Should -Be 71.4
        (@($s.Rows | Where-Object { $_.Figure -eq 'agebasis' -and $_.Dim1 -eq 'fix release' })[0]).Value | Should -Be 3
    }
    It 'a finding exactly at the grace counts; the grace is per asset type; 0 = the technical view' {
        $s = Complete-SIProtectionTally -Tally (NewFixture @{ SI_ProtectionScore_GraceDays_Identity = '7'; SI_ProtectionScore_OtherGraceDays_Identity = '7' })
        $s.Lifecycle | Should -Be 35.7 -Because 'the 14-day identity finding now counts too'
        $z = Complete-SIProtectionTally -Tally (NewFixture @{ SI_ProtectionScore_GraceDays_Device = '0'; SI_ProtectionScore_GraceDays_Identity = '0'; SI_ProtectionScore_GraceDays_CloudResource = '0'
                                                             SI_ProtectionScore_OtherGraceDays_Device = '0'; SI_ProtectionScore_OtherGraceDays_Identity = '0'; SI_ProtectionScore_OtherGraceDays_CloudResource = '0' })
        $z.Lifecycle | Should -Be $z.Technical
    }
    It '#860 the accepted lifecycle is for PATCH findings only: every other finding counts from day one by default' {
        # owner 2026-10-21: "go with your recommendation, grace 0 for non-patch" -- the shipped settings: user-14d (a finding with
        # only the source's first-seen: not a patch) now counts; srv-oct (the October update, 6 days) stays within its grace
        $s = Complete-SIProtectionTally -Tally (NewFixture -Shipped)
        $s.Lifecycle | Should -Be 35.7 -Because 'srv-oct (8) and pc-ok (2) of 28 -- user-14d is no longer in good standing'
        $s.Technical | Should -Be 7.1
        (Get-SIProtectionScoreSettings -Settings @{}).OtherGrace.identity | Should -Be 0
        (Get-SIProtectionScoreSettings -Settings @{ SI_ProtectionScore_OtherGraceDays_Identity = '14' }).OtherGrace.identity | Should -Be 14
        (Get-SIProtectionScoreSettings -Settings @{ SI_ProtectionScore_OtherGraceDays_Identity = 'soon' }).OtherGrace.identity | Should -Be 0 -Because 'invalid = the default'
        # a customer raises the other findings' grace for identities: user-14d is within 14 days again
        (Complete-SIProtectionTally -Tally (NewFixture -Shipped @{ SI_ProtectionScore_OtherGraceDays_Identity = '15' })).Lifecycle | Should -Be 42.9
    }
    It '#860 what a patch finding is: a fix release, a recommended update (name or id), or a patch cycle that is a cycle' {
        Test-SIProtectionPatchFinding -FixRelease '2026-10-01T00:00:00Z' | Should -BeTrue
        Test-SIProtectionPatchFinding -UpdateName 'October 2026 Security Updates' | Should -BeTrue
        Test-SIProtectionPatchFinding -UpdateId '5127648' | Should -BeTrue
        Test-SIProtectionPatchFinding -PatchCycle 'In monthly cycle' | Should -BeTrue
        Test-SIProtectionPatchFinding -PatchCycle 'Catch-up' | Should -BeTrue
        Test-SIProtectionPatchFinding -PatchCycle 'No fix available' | Should -BeFalse
        Test-SIProtectionPatchFinding -PatchCycle 'Unknown' | Should -BeFalse
        Test-SIProtectionPatchFinding -FixRelease 'not a date' | Should -BeFalse
        Test-SIProtectionPatchFinding | Should -BeFalse
    }
    It 'the tier weights and the severities are settings, not code' {
        (Complete-SIProtectionTally -Tally (NewFixture @{ SI_ProtectionScore_TierWeights = '1,1,1,1' })).Technical | Should -Be 16.7
        (Complete-SIProtectionTally -Tally (NewFixture @{ SI_ProtectionScore_Severities = 'Very High' })).Technical | Should -Be 85.7
    }
    It 'reads a Risk Analysis row: its CI, severity, exemption, update name and the source''s first-seen' {
        $t = New-SIProtectionTally -CollectionTime $script:T -Settings @{}
        Add-SIProtectionAsset $t 'ci-1' 'device' 'Server' 0
        Add-SIProtectionRow -Tally $t -Row ([pscustomobject]@{ si_ci_id = 'CI-1'; SecuritySeverity = 'High'; si_source_first_seen = '2026-10-18T00:00:00Z'; si_fix_recommended_update_id = '5127648' })
        $s = Complete-SIProtectionTally -Tally $t
        $s.Technical | Should -Be 0; $s.Lifecycle | Should -Be 100 -Because 'a patch (its update id) seen 1 day before is within the grace'
        (@($s.Rows | Where-Object { $_.Figure -eq 'agebasis' -and $_.Dim1 -eq 'source first seen' })[0]).Value | Should -Be 1
        # #860: the same row without a fix is not a patch -- it counts from day one; a source's patch cycle makes it one
        $u = New-SIProtectionTally -CollectionTime $script:T -Settings @{}
        Add-SIProtectionAsset $u 'ci-1' 'device' 'Server' 0
        Add-SIProtectionRow -Tally $u -Row ([pscustomobject]@{ si_ci_id = 'CI-1'; SecuritySeverity = 'High'; si_source_first_seen = '2026-10-18T00:00:00Z' })
        (Complete-SIProtectionTally -Tally $u).Lifecycle | Should -Be 0
        $c = New-SIProtectionTally -CollectionTime $script:T -Settings @{}
        Add-SIProtectionAsset $c 'ci-1' 'device' 'Server' 0
        Add-SIProtectionRow -Tally $c -Row ([pscustomobject]@{ si_ci_id = 'CI-1'; SecuritySeverity = 'High'; si_source_first_seen = '2026-10-18T00:00:00Z'; si_patch_cycle = 'In monthly cycle' })
        (Complete-SIProtectionTally -Tally $c).Lifecycle | Should -Be 100
    }
}

Describe 'the Risk Analysis mail shows the protection score, never the old 0-100 KPI' {
    It 'both views, the accepted lifecycle first, per asset type, and how many findings had no date' {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        $p = Complete-SIProtectionTally -Tally (NewFixture)
        $kpi = [pscustomobject]@{ Protection = $p; TotalRows = 5; SevCount = @{ Critical = 1; High = 4 }; SevByDomain = @{} }
        $html = ConvertTo-RAReportMailHtml -Kpi $kpi -ReportLabel 'RiskAnalysis_Detailed'
        # #827 (owner 2026-10-20): the two names, each value in its band's words and colour
        $html | Should -Match 'Protection Score, within Accepted Lifecycle:</strong> <strong data-band="at-risk" style="color:#c62828;">42\.9 % · At Risk</strong>'
        $html | Should -Match 'Protection Score, Actual Risks:</strong> <strong data-band="at-risk" style="color:#c62828;">7\.1 % · At Risk</strong>'
        $html | Should -Not -Match '% technical'
        $html | Should -Match 'Protection Score by asset type'
        $html | Should -Match '(?s)Devices.{0,400}71\.4 %</strong> within Accepted Lifecycle .{0,20}Actual Risks'
        $html | Should -Match '1 of 5 counted findings had no usable date'
        $html | Should -Not -Match '/100'
        $html | Should -Not -Match 'Risk Analysis KPI'
    }
    It 'a run without the score says WHY in one plain line -- never that the score comes later (owner 2026-10-22)' {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        $html = ConvertTo-RAReportMailHtml -Kpi ([pscustomobject]@{ TotalRows = 0; SevCount = @{}; SevByDomain = @{} }) -ProtectionReason (Get-SIProtectionReason 'summary')
        $html | Should -Match 'Protection Score:</strong> <span data-mail-protection="none">not shown for this run -- it is in the Detailed report, which counts the findings of every asset\.</span>'
        $html | Should -Not -Match 'Protection Score by asset type'
        # a tally with no asset in scope says so (the live bug: "0 assets in scope" printed as an empty %)
        $empty = Complete-SIProtectionTally -Tally (New-SIProtectionTally -CollectionTime $script:T -Settings @{})
        $empty.Lifecycle | Should -BeNullOrEmpty
        (ConvertTo-RAReportMailHtml -Kpi ([pscustomobject]@{ Protection = $empty; TotalRows = 0; SevCount = @{}; SevByDomain = @{} })) | Should -Match 'not shown for this run -- no active asset is in scope'
        (ConvertTo-SIProtectionMailHtml -Score $null -Reason (Get-SIProtectionReason 'no-cis')) | Should -Match 'not shown for this run -- no CIs are stored yet'
        # the old wording is gone from every mail and page source
        foreach ($p in 'engine\risk-analysis\_shared\RA-ReportMail.ps1', 'engine\_shared\SI-ProtectionScore.ps1', 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') {
            [IO.File]::ReadAllText((Join-Path $script:Root $p)) | Should -Not -Match 'computed by the Detailed run' -Because $p
        }
    }
    It 'the stale flag of a CI from the database is TEXT: ''false'' is an active CI (live 2026-10-22: every CI was counted inactive)' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Not -Match '\[bool\]\$__c\.si_stale_'
        $ra | Should -Match "\(\[string\]\`$__c\.si_stale_\)\.Trim\(\) -in 'true', '1'"
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-CiContext.ps1')) | Should -Match "'si_stale_' -NotePropertyValue \`$\(if .*\{ 'true' \} else \{ 'false' \}\)"
        # the same read on the shapes both sources give
        foreach ($c in @(@('false', $false), @('true', $true), @($false, $false), @($true, $true), @('1', $true), @('0', $false))) {
            (([string]$c[0]).Trim() -in 'true', '1') | Should -Be $c[1] -Because "si_stale_ = '$($c[0])'"
        }
    }
    It 'the tally COUNTS its findings (memory grows with the assets, never with the findings) and gives the same answer' {
        $t = NewFixture
        $t.PSObject.Properties['Findings'] | Should -BeNullOrEmpty -Because 'no list of every finding is kept'
        $t.BasisCount[1] | Should -Be 3; $t.BasisCis[1].Count | Should -Be 3
        (Get-Command Add-SIProtectionFinding).Definition | Should -Not -Match '\.Add\(@\{'
        $s = Complete-SIProtectionTally -Tally $t
        $s.Findings | Should -Be 5; $s.NoDate | Should -Be 1
        @($s.Rows | Where-Object { $_.Figure -eq 'technical' }).Count | Should -Be @($s.Rows | Where-Object { $_.Figure -eq 'lifecycle' }).Count
        (@($s.Rows | Where-Object { $_.Figure -eq 'technical' -and $_.Dim1 -eq '(all)' -and $_.Dim2 -eq '(all)' })[0]).Value | Should -Be 7.1
        (@($s.Rows | Where-Object { $_.Figure -eq 'lifecycle' -and $_.Dim1 -eq 'Identities' -and $_.Dim2 -eq 'Tier 0' })[0]).Value | Should -Be 0
    }
    It 'the stored figures (Pro) read into the same shape and render with the same code -- the values exactly as stored' {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        $kf = @(
            @{ Block = 'headline'; Figure = 'protection_lifecycle'; Dim1 = ''; Dim2 = ''; Value = 96.5; Assets = 40; Total = 42; Available = $true; Note = $null }
            @{ Block = 'headline'; Figure = 'protection_technical'; Dim1 = ''; Dim2 = ''; Value = 54.3; Assets = 20; Total = 42; Available = $true; Note = $null }
            @{ Block = 'protection'; Figure = 'lifecycle'; Dim1 = 'Devices'; Dim2 = '(all)'; Value = 90; Assets = 9; Total = 10; Available = $true }
            @{ Block = 'protection'; Figure = 'technical'; Dim1 = 'Devices'; Dim2 = '(all)'; Value = 50.05; Assets = 5; Total = 10; Available = $true }
            @{ Block = 'protection'; Figure = 'agebasis'; Dim1 = 'no date (counted)'; Dim2 = ''; Value = 3; Assets = 2; Total = 17; Available = $true })
        $p = ConvertFrom-SIProtectionKeyFigures -Rows $kf -Settings @{}
        $p.Source | Should -Be 'stored'; $p.Lifecycle | Should -Be 96.5; $p.Technical | Should -Be 54.3; $p.Assets | Should -Be 42; $p.NoDate | Should -Be 3; $p.Findings | Should -Be 17
        $h = ConvertTo-RAReportMailHtml -Kpi ([pscustomobject]@{ Protection = $p; TotalRows = 1; SevCount = @{}; SevByDomain = @{} })
        $h | Should -Match 'within Accepted Lifecycle:</strong> <strong data-band="very-good" style="color:#1b5e20;">96\.5 % · Very Good</strong>'
        $h | Should -Match 'Actual Risks:</strong> <strong data-band="moderate" style="color:#a14a00;">54\.3 % · Moderate</strong>'
        $h | Should -Match '90\.0 %</strong> within Accepted Lifecycle'
        # a stored score that is not available: its stored reason, one line
        $na = @($kf[0].Clone(), $kf[1].Clone()); $na[0].Available = $false; $na[0].Value = $null; $na[0].Note = 'no active asset is in scope yet'
        $q = ConvertFrom-SIProtectionKeyFigures -Rows $na -Settings @{}
        (ConvertTo-RAReportMailHtml -Kpi ([pscustomobject]@{ Protection = $q; TotalRows = 1; SevCount = @{}; SevByDomain = @{} })) | Should -Match 'not shown for this run -- no active asset is in scope yet\.'
        ConvertFrom-SIProtectionKeyFigures -Rows @() | Should -BeNullOrEmpty -Because 'no stored score yet'
        # the marks of a mail that waits for its score, and the fill
        $w = ConvertTo-RAReportMailHtml -Kpi ([pscustomobject]@{ TotalRows = 1; SevCount = @{}; SevByDomain = @{} }) -ProtectionPending
        $w | Should -Match '<!--SI:PROTECTION-SUMMARY-->'; $w | Should -Match '<!--SI:PROTECTION-TYPES-->'
        $filled = Set-RAReportMailProtection -BodyHtml $w -Protection $p
        $filled | Should -Not -Match '<!--SI:PROTECTION'
        $filled | Should -Match '96\.5 % · Very Good'
        $filled | Should -Match 'Protection Score by asset type'
    }
    It 'the engine computes it in the Detailed run, after the cache override, and keeps it for the Summary run' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match '(?s)New-SIProtectionTally.*Add-SIProtectionRow -Tally \$__prot -Row \$r.*Complete-SIProtectionTally -Tally \$__prot.*NotePropertyName Protection'
        $ra.IndexOf('Complete-SIProtectionTally -Tally $__prot') | Should -BeGreaterThan $ra.IndexOf('OVERRIDE with cached values')
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ExecView.ps1')) | Should -Match "kpiOut\['Protection'\]"
    }
}

Describe 'Pro: the Detailed mail waits for the STORED score (owner 2026-10-22: one computation)' {
    BeforeAll { . (Join-Path $script:Root 'engine\_shared\data-sql\SI-RaMailOutbox.ps1') }
    It 'decides each waiting mail: the stored score always goes; otherwise only a wake-up that can decide sends it, with why' {
        $start = [datetime]'2026-10-22T20:30:00'
        $mail = { param($fig, $status, $created, $cid = 7) [pscustomobject]@{ MailId = 1; CollectionId = $cid; Figured = $fig; CollectionStatus = $status; CreatedAt = [datetime]$created } }
        (Get-SIRaMailOutboxDecision -Mail (& $mail 1 'Complete' '2026-10-22T20:26:00') -Role datasync -RunStartedUtc $start).Action | Should -Be 'score'
        (Get-SIRaMailOutboxDecision -Mail (& $mail 1 'Complete' '2026-10-22T20:26:00') -Role producer -OwnCollectionId 8).Action | Should -Be 'score'
        # kept after this data sync started: the next data sync decides
        (Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Complete' '2026-10-22T20:31:00') -Role datasync -RunStartedUtc $start).Action | Should -Be 'wait'
        # complete, figures not reached yet this run (its budget): waits
        (Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Complete' '2026-10-22T20:26:00') -Role datasync -RunStartedUtc $start -KeyFigures @{ Status = 'ok'; Pending = 2 }).Action | Should -Be 'wait'
        $f = Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Complete' '2026-10-22T20:26:00') -Role datasync -RunStartedUtc $start -KeyFigures @{ Status = 'failed'; Error = 'timeout' }
        $f.Action | Should -Be 'reason'; $f.Reason | Should -Match 'could not compute this run''s figures.*\(timeout\)'
        $h = Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Loading' '2026-10-22T20:26:00') -Role datasync -RunStartedUtc $start
        $h.Action | Should -Be 'reason'; $h.Reason | Should -Match "did not take this run's results in.*'Loading'"
        # the next Detailed run: an earlier run's mail still waiting is sent (with why), unless a data sync is running now; never its own
        (Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Complete' '2026-10-22T20:26:00') -Role producer -OwnCollectionId 8).Reason | Should -Match 'has not computed this run''s figures'
        (Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Complete' '2026-10-22T20:26:00') -Role producer -OwnCollectionId 8 -SyncRunning $true).Action | Should -Be 'wait'
        (Get-SIRaMailOutboxDecision -Mail (& $mail 0 'Complete' '2026-10-22T20:26:00' 8) -Role producer -OwnCollectionId 8).Action | Should -Be 'wait'
    }
    It 'the kept view''s Kpi.Protection has the shape the Risk Analysis page parses, from the same score' {
        $p = Complete-SIProtectionTally -Tally (NewFixture)
        $j = ConvertTo-SIRaExecViewProtectionJson -Protection $p | ConvertFrom-Json
        $j.Lifecycle | Should -Be 42.9; $j.Technical | Should -Be 7.1; $j.Assets | Should -Be 6; $j.NoDate | Should -Be 1; $j.Findings | Should -Be 5
        $j.ByType.Devices.Lifecycle | Should -Be 71.4; $j.ByType.Devices.Assets | Should -Be 3
        ConvertTo-SIRaExecViewProtectionJson -Protection $null | Should -BeNullOrEmpty
    }
    It 'a Pro Detailed run keeps its mail for the stored score instead of counting one; a mail that cannot be kept is sent at once, saying why' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match '\$script:RAProtectionFromStore = \(Get-RAReportGrainLabel'
        $ra | Should -Match "-not \[string\]::IsNullOrWhiteSpace\(\[string\]\`$global:SI_ProSettingsVersion\) -and \[bool\]\`$script:RAStreamOn"
        $ra | Should -Match '(?s)if \(\$script:RAProtectionFromStore\) \{.{0,1600}Invoke-SIRaMailOutbox -Invoke \$__oInv -Role producer.{0,1500}-ProtectionPending.{0,400}Add-SIRaMailOutbox -Invoke \$__oInv.{0,900}\$__sendNow = \$false'
        $ra | Should -Match "(?s)\} catch \{.{0,300}ConvertTo-RAReportMailHtml -Kpi \`$kpi @__mailArgs -GroupingsHtml \`$__sgHtml -ProtectionReason \(Get-SIProtectionReason 'no-wait'"
        $ra | Should -Match '(?s)if \(\$__sendNow\) \{\s+Write-Step'
    }
}

Describe 'review 2 (2026-10-22): the outbox never holds a mail that cannot go, never waits for nothing, never sends twice' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-RaMailOutbox.ps1')
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        # a fake database seam: the outbox's statements by what they are, every call recorded
        function script:New-FakeOutbox([switch]$FailMark, [switch]$FailNote) {
            $w = [pscustomobject]@{ Calls = (New-Object System.Collections.Generic.List[string]); FailMark = [bool]$FailMark; FailNote = [bool]$FailNote }
            $w | Add-Member -NotePropertyName Invoke -NotePropertyValue ({
                param($Sql, $P, $Mode)
                $kind = if ($Sql -match 'FROM sidata\.RaMailOutbox o LEFT JOIN') { 'open' } elseif ($Sql -match "SET State = N'sending'") { 'claim' }
                        elseif ($Sql -match "SET State = N'sent'") { 'sent' } elseif ($Sql -match "sent, not marked: ") { 'note' } elseif ($Sql -match "SET State = N'waiting'") { 'release' }
                        elseif ($Sql -match 'FROM sidata\.KeyFigure') { 'kf' } else { 'other' }
                $w.Calls.Add($kind)
                switch ($kind) {
                    'open'  { return , @([pscustomobject]@{ MailId = 5; CollectionId = 7; CollectionTime = [datetime]'2026-10-22T20:00:00'; CreatedAt = [datetime]'2026-10-22T20:26:00'; State = 'waiting'; CollectionStatus = 'Complete'; Figured = 0 }) }
                    'claim' { return , @([pscustomobject]@{ MailId = 5; CollectionId = 7; CollectionTime = [datetime]'2026-10-22T20:00:00'; Subject = 's'; BodyHtml = '<p><!--SI:PROTECTION-SUMMARY--></p><!--SI:PROTECTION-TYPES-->'; ToJson = '["a@example.com"]'; FromAddress = ''; Priority = 'High'; AttachmentName = $null; AttachmentBase64 = $null; Attempts = 1 }) }
                    'sent'  { if ($w.FailMark) { throw 'SQL 40613: the database is not available' }; return 1 }
                    'note'  { if ($w.FailNote) { throw 'still down' }; return 1 }
                    default { return 1 }
                }
            }.GetNewClosure()) -Force
            $w
        }
    }
    It 'S1: the key figures did not run, or ran and left nothing for later -- the mail goes now: "not computed for this run -- <reason>"' {
        $start = [datetime]'2026-10-22T20:30:00'
        $m = [pscustomobject]@{ MailId = 1; CollectionId = 7; Figured = 0; CollectionStatus = 'Complete'; CreatedAt = [datetime]'2026-10-22T20:26:00' }
        $d = Get-SIRaMailOutboxDecision -Mail $m -Role datasync -RunStartedUtc $start -KeyFigures $null
        $d.Action | Should -Be 'reason'; $d.Reason | Should -Be 'not computed for this run -- the key figures step did not run this time'
        $d = Get-SIRaMailOutboxDecision -Mail $m -Role datasync -RunStartedUtc $start -KeyFigures @{ Status = 'ok'; Pending = 0 }
        $d.Action | Should -Be 'reason'; $d.Reason | Should -Match '^not computed for this run -- the key figures did not include this run$'
        (Get-SIRaMailOutboxDecision -Mail $m -Role datasync -RunStartedUtc $start -KeyFigures @{ Status = 'ok' }).Action | Should -Be 'reason' -Because 'no Pending = nothing left for later'
        (Get-SIRaMailOutboxDecision -Mail $m -Role datasync -RunStartedUtc $start -KeyFigures @{ Status = 'ok'; Pending = 1 }).Action | Should -Be 'wait' -Because 'their time budget left it for the next data sync'
        (Get-SIRaMailOutboxDecision -Mail $m -Role datasync -RunStartedUtc $start -KeyFigures @{ Status = 'dry-run' }).Action | Should -Be 'wait'
        Get-SIProtectionNoScoreText -Reason $d.Reason | Should -Be 'not computed for this run -- the key figures did not include this run.'
        $fake = New-FakeOutbox
        $got = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIRaMailOutbox -Invoke $fake.Invoke -Role datasync -Send ({ param($x) $got.Add($x.BodyHtml); @{ Sent = $true } }.GetNewClosure()) -RunStartedUtc $start -KeyFigures $null -Settings @{} -Log { param($l, $m) }
        $r.Sent | Should -Be 1
        $got[0] | Should -Match 'Protection Score:</strong> <span data-mail-protection="none">not computed for this run -- the key figures step did not run this time\.</span>'
    }
    It 'S2: once the server ACCEPTED the mail it is never put back to waiting -- "mark sent" is tried again, then the row is noted "sent, not marked"' {
        $fake = New-FakeOutbox -FailMark
        $r = Invoke-SIRaMailOutbox -Invoke $fake.Invoke -Role datasync -Send { param($x) @{ Sent = $true } } -RunStartedUtc ([datetime]'2026-10-22T20:30:00') -Settings @{} -Log { param($l, $m) } -MarkRetrySeconds 0
        $r.Sent | Should -Be 1; $r.Failed | Should -Be 0
        @($fake.Calls | Where-Object { $_ -eq 'sent' }).Count | Should -Be 3 -Because 'marking sent is idempotent: tried again'
        @($fake.Calls | Where-Object { $_ -eq 'note' }).Count | Should -Be 1
        @($fake.Calls | Where-Object { $_ -eq 'release' }).Count | Should -Be 0 -Because 'an accepted mail never waits again (it would be sent twice)'
        # even when the note cannot be written: never released
        $fake2 = New-FakeOutbox -FailMark -FailNote
        $null = Invoke-SIRaMailOutbox -Invoke $fake2.Invoke -Role datasync -Send { param($x) @{ Sent = $true } } -RunStartedUtc ([datetime]'2026-10-22T20:30:00') -Settings @{} -Log { param($l, $m) } -MarkRetrySeconds 0
        @($fake2.Calls | Where-Object { $_ -eq 'release' }).Count | Should -Be 0
        # a mail noted "sent, not marked" is never claimed or listed again -- the lease cannot resend it
        (Get-SIRaMailOutboxClaimSql) | Should -Match "AND ISNULL\(o\.LastError, N''\) NOT LIKE N'sent, not marked%'"
        (Get-SIRaMailOutboxOpenSql) | Should -Match "NOT LIKE N''sent, not marked%''"
        # a send that FAILED is still put back (it was not accepted)
        $fake3 = New-FakeOutbox
        $null = Invoke-SIRaMailOutbox -Invoke $fake3.Invoke -Role datasync -Send { param($x) @{ Sent = $false; Error = '451' } } -RunStartedUtc ([datetime]'2026-10-22T20:30:00') -Settings @{} -Log { param($l, $m) }
        @($fake3.Calls | Where-Object { $_ -eq 'release' }).Count | Should -Be 1
    }
    It 'B1: the data sync records whether it can send; a Detailed run keeps its mail only when it said ok -- else sends at once, saying where the score is' {
        (Get-SIRaMailSenderState -MailSettings ([pscustomobject]@{ Off = $false; Problems = @() })).Value | Should -Be 'ok'
        $no = Get-SIRaMailSenderState -MailSettings ([pscustomobject]@{ Off = $false; Problems = @('authenticated SMTP is configured but SMTPPassword is empty -- store it') })
        $no.Ready | Should -BeFalse; $no.Value.Length | Should -BeLessOrEqual 64; $no.Value | Should -Match '^not set up: authenticated SMTP'
        (Get-SIRaMailSenderState -MailSettings ([pscustomobject]@{ Off = $true; Problems = @() })).Ready | Should -BeFalse
        (Test-SIRaMailSender -Invoke { param($s, $p, $m) 'ok' }).Ready | Should -BeTrue
        $t = Test-SIRaMailSender -Invoke { param($s, $p, $m) [DBNull]::Value }
        $t.Ready | Should -BeFalse; $t.Why | Should -Match 'has not recorded'
        (Test-SIRaMailSender -Invoke { param($s, $p, $m) 'not set up: x' }).Why | Should -Match 'cannot send mail \(not set up: x\)'
        (Test-SIRaMailSender -Invoke { param($s, $p, $m) throw 'down' }).Ready | Should -BeFalse
        Get-SIProtectionNoScoreText -Reason (Get-SIProtectionReason 'mail-not-ready') | Should -Be 'not shown for this run -- the protection score is shown in SecurityInsight.'
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match "(?s)\`$__sender = Test-SIRaMailSender -Invoke \`$__oInv\s+if \(-not \`$__sender\.Ready\) \{.{0,500}-ProtectionReason \(Get-SIProtectionReason 'mail-not-ready'\).{0,120}throw"
        $ra.IndexOf('$__sender = Test-SIRaMailSender') | Should -BeLessThan $ra.IndexOf('$__mid = Add-SIRaMailOutbox')
    }
}
Describe 'the Protection Score''s bands: ONE file the engine and the web app read (#827)' {
    It 'reads data-model\protection-score-bands.locked.json: a band is the first, from the top, whose minimum the score reaches' {
        $script:SIProtectionBandsCache = $null
        @(Get-SIProtectionBands | ForEach-Object Name) | Should -Be @('Very Good', 'Good', 'Moderate', 'At Risk')
        foreach ($c in @(@(100, 'Very Good'), @(90, 'Very Good'), @(89.99, 'Good'), @(75, 'Good'), @(74.9, 'Moderate'), @(50, 'Moderate'), @(49.9, 'At Risk'), @(0, 'At Risk'))) {
            (Get-SIProtectionBand -Score $c[0]).Name | Should -Be $c[1] -Because ('a score of {0}' -f $c[0])
        }
        (Get-SIProtectionBand -Score $null).Tone | Should -Be 'unknown'
        (Get-SIProtectionBand -Score 96.5).Ink | Should -Be '#1b5e20'
        (Get-SIProtectionBand -Score 60).Ink | Should -Be '#a14a00'
    }
    # (the web app's embedded copy equals it: SecurityPostureTests, Pro -- this suite is Community-safe)
    It 'the mails write the value in its band''s words: the Risk Analysis mail line' {
        $h = ConvertTo-SIProtectionMailHtml -Score (Complete-SIProtectionTally -Tally (NewFixture))
        $h | Should -Match 'Protection Score, within Accepted Lifecycle:</strong> <span data-band="at-risk" style="color:#c62828;font-weight:700;">42\.9 % &middot; At Risk</span>'
        $h | Should -Match 'Protection Score, Actual Risks:</strong> <span data-band="at-risk"'
    }
}

Describe 'the source''s own first-seen on the finding rows (RA-SourceFirstSeen.ps1)' {
    It 'reads a line of Defender''s software vulnerabilities export in either case of the property names' {
        $a = ConvertFrom-RASourceFirstSeenLine '{"id":"x","deviceId":"ABC123","cveId":"cve-2026-1","firstSeenTimestamp":"2026-09-01 10:13:34.8476880","lastSeenTimestamp":"2026-10-18 10:00:00"}'
        $a.Key | Should -Be 'abc123|CVE-2026-1'; $a.FirstSeen | Should -Be ([datetime]'2026-09-01T10:13:34.8476880')
        (ConvertFrom-RASourceFirstSeenLine '{"DeviceId":"d","CveId":"CVE-2026-2","FirstSeenTimestamp":"2026-08-01T00:00:00Z"}').Key | Should -Be 'd|CVE-2026-2'
        ConvertFrom-RASourceFirstSeenLine '{"deviceId":"d","cveId":null,"firstSeenTimestamp":"2026-08-01"}' | Should -BeNullOrEmpty -Because 'software without a CVE'
    }
    It 'keeps the earliest sighting per device + CVE, and puts it on the CVE rows; Defender for Cloud and Shodan dates are carried over' {
        $lines = @('{"deviceId":"dev1","cveId":"CVE-2026-1","firstSeenTimestamp":"2026-09-10 00:00:00"}', '{"deviceId":"dev1","cveId":"CVE-2026-1","firstSeenTimestamp":"2026-09-02 00:00:00"}')
        $rows = @(
            [pscustomobject]@{ MdeDeviceId = 'DEV1'; ConfigurationId = 'CVE-2026-1' },
            [pscustomobject]@{ MdeDeviceId = 'dev2'; ConfigurationId = 'CVE-2026-1' },
            [pscustomobject]@{ ConfigurationId = 'mdc-1'; si_source_first_detected = '2026-07-01T00:00:00Z' },
            [pscustomobject]@{ ConfigurationId = 'port-443'; si_banner_first_seen = '2025-01-01T00:00:00Z' },
            [pscustomobject]@{ MdeDeviceId = 'dev1'; ConfigurationId = 'scid-10' })
        $global:RA_SourceFirstSeenIndex = $null; $global:RA_SourceFirstSeenSaid = $false
        $out = Add-RASourceFirstSeen -Rows $rows -Fetch { param($u) @{ Files = @('f1') } } -Download { param($u) $lines }
        $out[0].si_source_first_seen | Should -Be '2026-09-02T00:00:00Z'
        $out[1].PSObject.Properties['si_source_first_seen'] | Should -BeNullOrEmpty -Because 'Defender has no sighting of it'
        $out[2].si_source_first_seen | Should -Be '2026-07-01T00:00:00Z'
        $out[3].si_source_first_seen | Should -Be '2025-01-01T00:00:00Z'
        $out[4].PSObject.Properties['si_source_first_seen'] | Should -BeNullOrEmpty -Because 'secure configurations have no first-seen'
        $global:RA_SourceFirstSeenIndex = $null
    }
    It 'a refused read is said once and changes nothing; the setting switches the read off' {
        $global:RA_SourceFirstSeenIndex = $null; $global:RA_SourceFirstSeenSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        $rows = @([pscustomobject]@{ MdeDeviceId = 'dev1'; ConfigurationId = 'CVE-2026-1' })
        $null = Add-RASourceFirstSeen -Rows $rows -Fetch { param($u) @{ Error = '403 Forbidden' } } -Log { param($m) $said.Add($m) }
        $null = Add-RASourceFirstSeen -Rows $rows -Log { param($m) $said.Add($m) }
        $said.Count | Should -Be 1; $said[0] | Should -Match 'Vulnerability.Read.All'
        $rows[0].PSObject.Properties['si_source_first_seen'] | Should -BeNullOrEmpty
        Test-RASourceFirstSeenOn -Setting 'off' | Should -BeFalse; Test-RASourceFirstSeenOn -Setting $null | Should -BeTrue
        $global:RA_SourceFirstSeenIndex = $null
    }
    It 'the field is in the catalog, the finding texts carry it and the Pro column stores it before the older field' {
        (Get-Content (Join-Path $script:Root 'data-model\field-catalog.locked.json') -Raw) | Should -Match '"name": "si_source_first_seen"'
        (Get-Content (Join-Path $script:Root 'data-model\finding-texts.locked.json') -Raw) | Should -Match '"si_source_first_seen": \[\s*"si_source_first_seen",\s*"si_source_first_detected"'
        (Get-Content (Join-Path $script:Root 'data-model\mappings\mde.locked.json') -Raw) | Should -Match '"export.firstSeenTimestamp"'
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match 'Add-RASourceFirstSeen -Rows @\(\$ResultFiltered\)'
    }
}
