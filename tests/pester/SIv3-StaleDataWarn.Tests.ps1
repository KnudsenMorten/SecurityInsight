#Requires -Version 5.1
<#
    SecurityInsight -- #1396 DATA GETTING OLD (owner 2026-11-26: "why have nobody found out" / "fix it"): one install had no
    complete pipeline run for eight days, others were 1.5 to 2.5 days behind, and nobody was told.

    What must hold (OFFLINE: every database read, transport and store is a stub; nothing is mailed or sent):
      - SI_Pro_StaleDataWarnHours: default 36, 0 = off, a value that is not a whole number >= 0 = the default;
      - THE AGE counts from when the shown collection became Complete (LoadedAt), not its collection time (set near the run's
        start): a collection 40 hours old that completed 20 hours ago does not warn; LoadedAt unknown = the collection time;
      - the decision: 37 hours warns, 35 does not, exactly the limit does not, 0 never, nothing shown yet never; the detail
        names the date, "No new data has been published since then", the age, the limit, Operations > Jobs, the newest run
        in plain words ("failed on ... at step x", "was stopped on ...", "completed ..., but its data was not published",
        "in progress") and si-flow-1206;
      - the reads: the pages' own view sidata.vPublishedCollection (its fallback before the first publish), and the newest
        WHOLE-PIPELINE run with its first failed step (never a cancelled step);
      - THE GUARD WARNING ONCE PER DAY when the check is switched on: the first tick of a day records it, later ticks that day
        record nothing and say nothing, the next day records it again -- through the real Send-SIGuardEvent; never a mail;
        OFF BY DEFAULT (nothing set = no event); a run-record read that fails still warns; a data read that fails never throws;
      - the catalog entries (the guard: warning only, never mails, off by default; the code in both copies of the error
        catalogue; the setting with its default and bounds); the heartbeat runs the check.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-StaleData.ps1')
    $script:Quiet = { param($l, $m) }
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-26 10:00:00', 'Utc')
    function script:U([string]$t) { [datetime]::SpecifyKind([datetime]$t, 'Utc') }
    # the shown collection: collected -Hours ago, Complete -DoneHours ago (default: when it was collected)
    function script:New-Shown([double]$Hours, [AllowNull()]$DoneHours) {
        , @([pscustomobject]@{ CollectionTime = $script:Now.AddHours(-$Hours); LoadedAt = $(if ($null -ne $DoneHours) { $script:Now.AddHours(-[double]$DoneHours) } else { $script:Now.AddHours(-$Hours) }) })
    }
    function script:New-FailedRunRows {
        , @([pscustomobject]@{ FlowRunId = 'run-77'; State = 'Failed'; StartedUtc = (U '2026-11-25 02:00'); EndedUtc = (U '2026-11-25 04:10'); HeartbeatUtc = [System.DBNull]::Value
                               StopReason = [System.DBNull]::Value; FailedJob = 'si-asset-datasync'; FailedState = 'Failed'; FailedError = 'the execution ended Failed: out of memory' })
    }
}

Describe 'the setting SI_Pro_StaleDataWarnHours' {
    It 'default 36, 0 = off, any whole number >= 0 kept, anything else the default' {
        Get-SIStaleDataWarnHours $null | Should -Be 36
        Get-SIStaleDataWarnHours '' | Should -Be 36
        Get-SIStaleDataWarnHours 0 | Should -Be 0
        Get-SIStaleDataWarnHours '0' | Should -Be 0
        Get-SIStaleDataWarnHours 48 | Should -Be 48
        Get-SIStaleDataWarnHours '72' | Should -Be 72
        Get-SIStaleDataWarnHours -1 | Should -Be 36 -Because 'NEGATIVE: a negative limit is not a limit'
        Get-SIStaleDataWarnHours 'soon' | Should -Be 36
        Get-SIStaleDataWarnHours '1.5' | Should -Be 36
    }
}

Describe 'the decision' {
    It 'warns at 37 hours, not at 35, not exactly at the limit' {
        $d = Get-SIStaleDataDecision -ShownUtc $script:Now.AddHours(-37) -SinceUtc $null -WarnHours 36 -NowUtc $script:Now -LastRun $null
        $d | Should -Not -BeNullOrEmpty
        ($d.AgeHours, $d.LimitHours, $d.Day, $d.CauseKey) | Should -Be @(37, 36, '2026-11-26', 'stale|2026-11-26')
        $d.Detail | Should -Match '^The newest complete data is from 2026-11-24 21:00 UTC\. No new data has been published since then \(37 hours; the limit is 36 hours\) -- see Operations > Jobs\.'
        $d.Detail | Should -Match '\(si-flow-1206\)$'
        Get-SIStaleDataDecision -ShownUtc $script:Now.AddHours(-35) -SinceUtc $null -WarnHours 36 -NowUtc $script:Now -LastRun $null | Should -BeNullOrEmpty
        Get-SIStaleDataDecision -ShownUtc $script:Now.AddHours(-36) -SinceUtc $null -WarnHours 36 -NowUtc $script:Now -LastRun $null | Should -BeNullOrEmpty
    }
    It 'THE AGE counts from when the collection became Complete: collected 40 h ago, complete 20 h ago = no warning' {
        Get-SIStaleDataDecision -ShownUtc $script:Now.AddHours(-40) -SinceUtc $script:Now.AddHours(-20) -WarnHours 36 -NowUtc $script:Now -LastRun $null | Should -BeNullOrEmpty -Because 'a large install''s healthy run takes > 12 h from start to publish'
        $d = Get-SIStaleDataDecision -ShownUtc $script:Now.AddHours(-60) -SinceUtc $script:Now.AddHours(-40) -WarnHours 36 -NowUtc $script:Now -LastRun $null
        $d.AgeHours | Should -Be 40
        $d.Detail | Should -Match 'from 2026-11-23 22:00 UTC\.' -Because 'the date named is the data''s own date'
        $s = Get-SIStaleDataShown -Rows (New-Shown 40 20)
        ($s.CollectionUtc, $s.SinceUtc) | Should -Be @($script:Now.AddHours(-40), $script:Now.AddHours(-20))
        (Get-SIStaleDataShown -Rows @([pscustomobject]@{ CollectionTime = $script:Now.AddHours(-40); LoadedAt = [System.DBNull]::Value })).SinceUtc | Should -Be $script:Now.AddHours(-40) -Because 'not recorded = the collection time'
        Get-SIStaleDataShown -Rows @() | Should -BeNullOrEmpty
    }
    It 'never warns when off (0) or when nothing is shown yet' {
        Get-SIStaleDataDecision -ShownUtc $script:Now.AddDays(-30) -SinceUtc $null -WarnHours 0 -NowUtc $script:Now -LastRun $null | Should -BeNullOrEmpty
        Get-SIStaleDataDecision -ShownUtc $null -SinceUtc $null -WarnHours 36 -NowUtc $script:Now -LastRun $null | Should -BeNullOrEmpty
    }
    It 'says days after two days, and the newest run in plain words' {
        $d = Get-SIStaleDataDecision -ShownUtc (U '2026-11-18 03:00') -SinceUtc $null -WarnHours 36 -NowUtc $script:Now -LastRun (ConvertTo-SIStaleDataLastRun -Rows (New-FailedRunRows))
        $d.Detail | Should -Match '\(8 days; the limit is 36 hours\)'
        $d.RunText | Should -Be 'The last run failed on 2026-11-25 04:10 UTC at step si-asset-datasync: the execution ended Failed: out of memory.'
        $d.Detail | Should -Match ([regex]::Escape($d.RunText))
        Get-SIStaleDataRunText -LastRun ([pscustomobject]@{ State = 'Running'; StartedUtc = (U '2026-11-26 02:00'); EndedUtc = $null; Steps = @() }) | Should -Be 'A run is in progress (started 2026-11-26 02:00 UTC).'
        Get-SIStaleDataRunText -LastRun ([pscustomobject]@{ State = 'Cancelled'; StartedUtc = (U '2026-11-26 01:00'); EndedUtc = (U '2026-11-26 06:00'); StopReason = 'cancelled by ops: update'; Steps = @() }) |
            Should -Be 'The last run was stopped on 2026-11-26 06:00 UTC: cancelled by ops: update.'
        Get-SIStaleDataRunText -LastRun ([pscustomobject]@{ State = 'Success'; StartedUtc = (U '2026-11-26 01:00'); EndedUtc = (U '2026-11-26 07:00'); StopReason = ''; Steps = @() }) |
            Should -Be 'The last run completed on 2026-11-26 07:00 UTC, but its data was not published.'
        Get-SIStaleDataRunText -LastRun ([pscustomobject]@{ State = 'Failed'; StartedUtc = (U '2026-11-26 01:00'); EndedUtc = (U '2026-11-26 03:00'); StopReason = ''; Steps = @() }) |
            Should -Be 'The last run failed on 2026-11-26 03:00 UTC.'
        Get-SIStaleDataRunText -LastRun $null | Should -Be ''
        ConvertTo-SIStaleDataLastRun -Rows @() | Should -BeNullOrEmpty
    }
}

Describe 'the reads' {
    It 'the shown collection is the pages'' own view; the run is the newest WHOLE-PIPELINE run, never a cancelled step' {
        $s = Get-SIStaleDataShownSql
        $s | Should -Match 'FROM sidata\.vPublishedCollection AS pc WHERE pc\.Kind = N''Detailed'''
        $s | Should -Match 'pc\.LoadedAt'
        $s | Should -Not -Match 'sidata\.Collection\b' -Because 'the fallback before the first publish is the view''s (retired / views-ready filters), never its own'
        $r = Get-SIStaleDataLastRunSql
        $r | Should -Match ([regex]::Escape("r.Scope IS NULL OR r.Scope IN (N''pipeline'', N''from-step'')")) -Because '"Re-run from here" (Scope from-step) is a whole-pipeline run'
        $r | Should -Match ([regex]::Escape("x.ErrorClass <> N''cancelled''"))
        $r | Should -Match 'ORDER BY r\.StartedUtc DESC'
    }
}

Describe 'the guard warning, once per day' {
    BeforeEach {
        $global:SI_GuardSeenThisRun = @{}
        $script:Store = New-SIGuardMemoryStateStore
        $script:Mails = New-Object System.Collections.Generic.List[object]
        $script:Health = New-Object System.Collections.Generic.List[object]
        $script:Lines = New-Object System.Collections.Generic.List[object]
        $script:GuardArgs = @{
            StateStore = $script:Store; Version = '3.1.52'; NoTelemetry = $true
            Log = { param($l, $m) $script:Lines.Add([pscustomobject]@{ L = $l; M = $m }) }
            MailTransport = { param($to, $subject, $html, $priority) $script:Mails.Add($subject); $true }
            RunHealth = { param($c, $x, $m, $h) $script:Health.Add([pscustomobject]@{ Exit = $x; Msg = $m }) }
        }
        # the Guards-page event is off by default (the owner's guard rule): these tests switch it on
        $script:Globals = @{ SI_Pro_StaleDataWarnHours = 36; MailTo = 'secops@contoso.test'; SI_Guard_DataPublishedStale_Enabled = $true }
    }
    It 'the first tick of the day records it; every later tick that day records and says nothing; the next day again' {
        $a = Invoke-SIStaleDataCheck -ShownRows (New-Shown 37) -RunRows (New-FailedRunRows) -Globals $script:Globals -NowUtc $script:Now -GuardArgs $script:GuardArgs
        $a.Status | Should -Be 'raised'
        ($a.Event.Event.GuardId, $a.Event.Event.Outcome) | Should -Be @('data.published.stale', 'warning')
        $a.Line | Should -Match '^data getting old: The newest complete data is from '
        $a.Line | Should -Match 'at step si-asset-datasync'
        $script:Health.Count | Should -Be 1
        $script:Health[0].Exit | Should -Be 'guard-warning'
        @($script:Lines | Where-Object L -eq 'WARN').Count | Should -Be 1
        foreach ($m in 30, 120, 600) {
            $global:SI_GuardSeenThisRun = @{}   # every tick is its own execution
            $b = Invoke-SIStaleDataCheck -ShownRows (New-Shown 37) -Globals $script:Globals -NowUtc $script:Now.AddMinutes($m) -GuardArgs $script:GuardArgs
            $b.Status | Should -Be 'reported' -Because "+$m min is the same day"
            $b.Line | Should -Be ''
        }
        $script:Health.Count | Should -Be 1 -Because 'ONE warning per day'
        @($script:Lines | Where-Object L -eq 'WARN').Count | Should -Be 1 -Because 'the guard says its WARN line only when it records (two-agent check: no WARN every tick)'
        $global:SI_GuardSeenThisRun = @{}
        $c = Invoke-SIStaleDataCheck -ShownRows (New-Shown 37) -Globals $script:Globals -NowUtc $script:Now.AddDays(1).Date.AddMinutes(7) -GuardArgs $script:GuardArgs
        $c.Status | Should -Be 'raised'
        $c.Decision.Day | Should -Be '2026-11-27'
        $script:Health.Count | Should -Be 2
        $script:Mails.Count | Should -Be 0 -Because 'a warning only: this check never mails'
    }
    It 'fresh data (35 hours), completed recently, the limit 0 and no data record nothing and never call the guard' {
        $sent = New-Object System.Collections.Generic.List[object]
        $send = { param([hashtable]$Arguments) $sent.Add($Arguments); [pscustomobject]@{ Status = 'recorded' } }.GetNewClosure()
        (Invoke-SIStaleDataCheck -ShownRows (New-Shown 35) -Globals $script:Globals -NowUtc $script:Now -Send $send).Status | Should -Be 'fresh'
        (Invoke-SIStaleDataCheck -ShownRows (New-Shown 50 10) -Globals $script:Globals -NowUtc $script:Now -Send $send).Status | Should -Be 'fresh'
        (Invoke-SIStaleDataCheck -ShownRows (New-Shown (24 * 9)) -Globals @{ SI_Pro_StaleDataWarnHours = 0 } -NowUtc $script:Now -Send $send).Status | Should -Be 'off'
        (Invoke-SIStaleDataCheck -ShownRows @() -Globals $script:Globals -NowUtc $script:Now -Send $send).Status | Should -Be 'no-data'
        $sent.Count | Should -Be 0
    }
    It 'hands the guard the day as its cause, the age against the limit, and never a mail' {
        $sent = New-Object System.Collections.Generic.List[object]
        $send = { param([hashtable]$Arguments) $sent.Add($Arguments); [pscustomobject]@{ Status = 'recorded' } }.GetNewClosure()
        $null = Invoke-SIStaleDataCheck -ShownRows (New-Shown 50) -Globals @{ SI_Pro_StaleDataWarnHours = '48' } -NowUtc $script:Now -Send $send
        $sent.Count | Should -Be 1
        ($sent[0].GuardId, $sent[0].Outcome, $sent[0].RunId) | Should -Be @('data.published.stale', 'warning', 'stale-data-2026-11-26')
        @($sent[0].CauseKeys) | Should -Be @('stale|2026-11-26')
        $sent[0].NoMail | Should -BeTrue
        ($sent[0].Values[0].Measured, $sent[0].Values[0].Limit) | Should -Be @(50, 48)
    }
    It 'OFF BY DEFAULT: nothing set = no event; switched off = no event (the pages still warn)' {
        foreach ($g in @(@{ SI_Pro_StaleDataWarnHours = 36 }, @{ SI_Pro_StaleDataWarnHours = 36; SI_Guard_DataPublishedStale_Enabled = $false })) {
            $r = Invoke-SIStaleDataCheck -ShownRows (New-Shown 37) -Globals $g -NowUtc $script:Now -GuardArgs $script:GuardArgs
            $r.Status | Should -Be 'guard-off'
            $r.Line | Should -Be ''
        }
        $script:Health.Count | Should -Be 0
    }
    It 'NEGATIVE: a data read that fails is a status, never an exception; a run read that fails still warns' {
        $boom = { param($sql, $p, $mode) throw 'the database did not answer' }
        $r = Invoke-SIStaleDataCheck -DataInvoke $boom -Globals $script:Globals -NowUtc $script:Now -GuardArgs $script:GuardArgs
        $r.Status | Should -Be 'error'
        $r.Line | Should -Match 'not checked this time'
        $w = Invoke-SIStaleDataCheck -ShownRows (New-Shown 37) -RunInvoke $boom -Globals $script:Globals -NowUtc $script:Now -GuardArgs $script:GuardArgs
        $w.Status | Should -Be 'raised'
        $w.Decision.RunText | Should -Be ''
    }
}

Describe 'the guard WARN line (round 2): a check that holds or refuses says it every time; a warn-only check once per cause' {
    It 'refused with a cause reported before: WARN again (held data is never quiet); warning with a cause reported before: no WARN' {
        $lines = New-Object System.Collections.Generic.List[object]
        $common = @{ StateStore = (New-SIGuardMemoryStateStore); Version = '3.1.52'; NoTelemetry = $true; NoMail = $true
                     Log = { param($l, $m) $lines.Add([pscustomobject]@{ L = $l; M = $m }) }.GetNewClosure(); RunHealth = { param($c, $x, $m, $h) }
                     Globals = @{ SI_Guard_DatasyncCollectionRefused_Enabled = $true; SI_Guard_DataPublishedStale_Enabled = $true } }
        foreach ($run in 'r1', 'r2') {
            $global:SI_GuardSeenThisRun = @{}
            $null = Send-SIGuardEvent -GuardId 'datasync.collection.refused' -Outcome 'refused' -RunId $run -CauseKeys @('same-cause') -Detail 'refused (test)' @common
        }
        @($lines | Where-Object { $_.L -eq 'WARN' -and $_.M -like 'REFUSED:*' }).Count | Should -Be 2 -Because 'a refusal is said on every occurrence, also for a cause reported before'
        $lines.Clear()
        foreach ($run in 'w1', 'w2') {
            $global:SI_GuardSeenThisRun = @{}
            $null = Send-SIGuardEvent -GuardId 'data.published.stale' -Outcome 'warning' -RunId $run -CauseKeys @('stale|2026-11-26') -Detail 'old (test)' @common
        }
        @($lines | Where-Object L -eq 'WARN').Count | Should -Be 1 -Because 'a warn-only check is said once per cause'
    }
}
Describe 'the catalogs and the wiring' {
    It 'the guard: a warning only, never mails, OFF by default (the page warning is on by itself), its limit is the setting' {
        $g = @((Get-SIGuardCatalog -Refresh).guards | Where-Object id -eq 'data.published.stale')
        $g.Count | Should -Be 1
        $g[0].mail | Should -Be 'never'
        [bool]($g[0].PSObject.Properties['defaultOff'] -and $g[0].defaultOff) | Should -BeTrue
        Test-SIGuardOn -GuardId 'data.published.stale' -Globals @{} -Log $script:Quiet | Should -BeFalse
        Test-SIGuardOn -GuardId 'data.published.stale' -Globals @{ SI_Guard_DataPublishedStale_Enabled = $true } -Log $script:Quiet | Should -BeTrue
        Test-SIGuardOutcomeMails -Event (New-SIGuardEvent -GuardId 'data.published.stale' -Outcome warning) | Should -BeFalse
        @($g[0].limits) | Should -Be @('SI_Pro_StaleDataWarnHours')
    }
    It 'the code si-flow-1206 is in both copies of the error catalogue (the same file)' {
        $a = Join-Path $script:SIRoot 'data-model\errors.locked.json'
        $b = Join-Path $script:SIRoot 'pro-management\src\SI.Management.Core\ProData\DataModel\errors.locked.json'
        $e = @(Get-Content -LiteralPath $a -Raw | ConvertFrom-Json | Where-Object code -eq 'si-flow-1206')
        $e.Count | Should -Be 1
        ($e[0].causeClass, $e[0].whoActs, $e[0].opensTicket) | Should -Be @('held-too-long', 'support', $false)
        $e[0].customerText | Should -Not -Match '#\d|si-|SI_'
        (Get-FileHash $a).Hash | Should -Be (Get-FileHash $b).Hash
    }
    It 'the setting: 36 hours by default, 0 to a year, on the Guards card' {
        $s = @((Get-Content -LiteralPath (Join-Path $script:SIRoot 'config\settings.catalog.locked.json') -Raw | ConvertFrom-Json).settings | Where-Object name -eq 'SI_Pro_StaleDataWarnHours')
        $s.Count | Should -Be 1
        ($s[0].type, $s[0].defaultText, $s[0].min, $s[0].max, $s[0].group) | Should -Be @('int', '36', 0, 8760, 'Guards (safety checks)')
        $s[0].description | Should -Not -Match '#\d'
    }
    It 'the heartbeat runs the check on every tick and never fails for it' {
        $hb = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\heartbeat\Invoke-SIHeartbeat.ps1'))
        $hb | Should -Match ([regex]::Escape("engine/_shared/SI-StaleData.ps1"))
        $hb | Should -Match ([regex]::Escape('Invoke-SIStaleDataCheck -DataInvoke $dataInvoke -RunInvoke $proInvoke -Invoke $proInvoke'))
        $i = $hb.IndexOf('Invoke-SIStaleDataCheck -DataInvoke')
        $hb.LastIndexOf('try {', $i) | Should -BeGreaterThan $hb.LastIndexOf('if ($extra) { exit 0 }', $i) -Because 'after the extra heartbeat exit, inside its own try'
    }
}
