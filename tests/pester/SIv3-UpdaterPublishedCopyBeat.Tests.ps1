#Requires -Version 5.1
<#
    SecurityInsight -- #1357 THE UPDATER'S PUBLISHED-COPIES STEP SAYS IT IS WORKING WHILE IT WORKS (setup\Invoke-SIContainerUpdate.ps1,
    Invoke-SIUpdatePublishedCopy, step 9j).

    Live 2026-11-25 at the largest install: 9j refreshed 2,292,675 rows in 4,520 ranges over 6,746 s, but its header came only
    when it ended and the engine driver's progress lines were dropped (no -Log), so the log read "still working: 9q ..." for two
    hours. What must hold:
      * the header '9j. PUBLISHED COPIES' is said when the refresh STARTS (its first beat or its first line), once;
      * the driver's lines (progress, one per copy, a transient retry) are said as they come; the catch-up's own closing line is
        said once, after the call, at its level (as before);
      * copies that are current: nothing is said (as before);
      * every range beats the update's own row (throttled to a minute by Invoke-SIUpdaterLockBeat), so a refresh longer than
        the liveness window (15 min) and longer than the 121 minutes of the live stop is never judged dead by the UNCHANGED
        rule (engine\_shared\SI-ExecutionLiveness.ps1); without the beat it is.
    Offline; the clock of the long refresh is virtual (no real 15 minutes).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ExecutionLiveness.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataModel.ps1')        # Get-SIDataNextSize, as the engine loads it
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataPublishedRun.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-UpdateSqlBeat.ps1')
    $script:Update = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
    $script:Fn = [regex]::Match($script:Update, '(?s)function Invoke-SIUpdatePublishedCopy \{.*?\n\}').Value
}
AfterAll { $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null }

Describe 'the updater says 9j while it works (Invoke-SIUpdatePublishedCopy, run with the catch-up as a seam)' {
    BeforeAll {
        # the update's step function, defined here as the script defines it; the catch-up, the lines and the beat recorded
        # (the catch-up and the lock beat renamed to the seams below, so the engine's and the run gate's own -- loaded above --
        # never answer in their place)
        $fnText = ($script:Fn -replace '^function Invoke-SIUpdatePublishedCopy \{', 'function script:Invoke-SIUpdatePublishedCopyUnderTest {')
        $fnText = $fnText.Replace('Invoke-SIPublishedCopyCatchUp', 'Invoke-SIPublishedCopyCatchUpSeam').Replace('Invoke-SIUpdaterLockBeat', 'Invoke-SIUpdaterLockBeatSeam')
        . ([scriptblock]::Create($fnText))
        $script:solRoot = $script:SIRoot
        $script:globals = @{}
        $script:Apply = $true; $script:DetectOnly = $false
        function script:Step([string]$m) { $script:Out.Add("STEP $m") }
        function script:Info([string]$m) { $script:Out.Add("INFO $m") }
        function script:Warn([string]$m) { $script:Out.Add("WARN $m") }
        function script:Invoke-SIUpdaterLockBeatSeam { param([string]$What, [int]$MinSeconds = 60, [switch]$Force, $NowUtc) $script:Out.Add("BEAT $What"); $true }
        function script:Get-SIAzureToken { param($Resource) 'tok' }
        function script:Invoke-SIPublishedCopyCatchUpSeam {
            param([scriptblock]$Invoke, [switch]$WhatIf, [switch]$AfterPublish, [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Beat, [scriptblock]$Wave)
            & $script:Scenario $Log $Beat
        }
        $script:Final = "the merged assets' pages (CIs and assets) showed a copy older than the run the web app shows (run published 2026-11-24 22:49 UTC, copy 2026-11-23 20:00 UTC) -- refreshed now (2,292,675 row(s) written in 4,520 range(s), 6,746 s); every page shows the same run again"
    }
    BeforeEach {
        $script:Out = New-Object System.Collections.Generic.List[string]
        $env:SI_UPDATER_PRO_SQL_SERVER = 'sql-x'; $env:SI_UPDATER_PRO_SQL_DATABASE = 'sqldb-pro'
    }
    AfterEach { $env:SI_UPDATER_PRO_SQL_SERVER = $null; $env:SI_UPDATER_PRO_SQL_DATABASE = $null }

    It 'a long refresh: the header first (at its first beat), every range beats, the driver''s lines as they come, the closing line once' {
        $script:Scenario = {
            param($Log, $Beat)
            & $Beat                                                                    # the driver beats when the refresh starts
            & $Log 'INFO' 'published copies: CiPub -- 1,200 range(s), 812,000 row(s) written so far'
            & $Beat
            & $Log 'WARN' 'published copies: 3 range(s) of CiFindingPub met a transient SQL error (a deadlock, a timeout or Azure SQL busy) -- run again in 2 s (retry 1 of 5)'
            & $Log 'INFO' 'published copies: CiFindingPub -- 2,292,675 row(s) written in 4,520 range(s), 6,746 s'
            & $Log 'WARN' $script:Final                                                # the catch-up's own line (also in Lines)
            [pscustomobject]@{ Action = 'refreshed'; Lines = @($script:Final) }
        }
        Invoke-SIUpdatePublishedCopyUnderTest
        @($script:Out) | Should -Be @(
            'STEP 9j. PUBLISHED COPIES'
            'BEAT 9j. PUBLISHED COPIES'
            'INFO published copies: CiPub -- 1,200 range(s), 812,000 row(s) written so far'
            'BEAT 9j. PUBLISHED COPIES'
            'WARN published copies: 3 range(s) of CiFindingPub met a transient SQL error (a deadlock, a timeout or Azure SQL busy) -- run again in 2 s (retry 1 of 5)'
            'INFO published copies: CiFindingPub -- 2,292,675 row(s) written in 4,520 range(s), 6,746 s'
            "INFO $($script:Final)")
    }
    It 'the header comes with the first line when no beat came before it, and is said once' {
        $script:Scenario = {
            param($Log, $Beat)
            & $Log 'INFO' "published copies: the merged assets' copies are refreshed 4 range(s) at a time (the database's cores)"
            & $Beat
            [pscustomobject]@{ Action = 'refreshed'; Lines = @($script:Final) }
        }
        Invoke-SIUpdatePublishedCopyUnderTest
        @($script:Out | Where-Object { $_ -like 'STEP *' }).Count | Should -Be 1
        $script:Out[0] | Should -Be 'STEP 9j. PUBLISHED COPIES'
        $script:Out[1] | Should -Match '^INFO published copies: the merged assets'' copies are refreshed 4 range'
    }
    It 'copies that are current: nothing said, nothing beaten (as before)' {
        $script:Scenario = { param($Log, $Beat) [pscustomobject]@{ Action = 'current'; Lines = @() } }
        Invoke-SIUpdatePublishedCopyUnderTest
        $script:Out.Count | Should -Be 0
    }
    It 'an older database (the procedure refreshes, no beat, no line): the header and the closing line, as before' {
        $script:Scenario = { param($Log, $Beat) [pscustomobject]@{ Action = 'refreshed'; Lines = @($script:Final) } }
        Invoke-SIUpdatePublishedCopyUnderTest
        @($script:Out) | Should -Be @('STEP 9j. PUBLISHED COPIES', "INFO $($script:Final)")
    }
    It 'a failed catch-up: its line once, as a warning' {
        $script:F = 'the copies of the merged assets could not be checked or refreshed (no answer) -- the next wake-up tries again'
        $script:Scenario = { param($Log, $Beat) & $Log 'WARN' $script:F; [pscustomobject]@{ Action = 'failed'; Lines = @($script:F) } }
        Invoke-SIUpdatePublishedCopyUnderTest
        @($script:Out) | Should -Be @('STEP 9j. PUBLISHED COPIES', "WARN $($script:F)")
    }
    It 'the wiring: the catch-up gets -Log and -Beat, the beat names the step, the header is no longer only at the end' {
        $script:Fn | Should -Match ([regex]::Escape('$r = Invoke-SIPublishedCopyCatchUp -Invoke $dataSql -WhatIf:(-not $Apply -or $DetectOnly) -Log $copyLog -Beat $copyBeat @copyWave'))
        $script:Fn | Should -Match ([regex]::Escape("Invoke-SIUpdaterLockBeat -What '9j. PUBLISHED COPIES'"))
        $script:Fn | Should -Not -Match ([regex]::Escape("if (@(`$r.Lines).Count) { Step '9j. PUBLISHED COPIES' }"))
    }
}

Describe 'a 9j refresh longer than the liveness window keeps a fresh beat and is not stopped (engine driver + the update''s beat + the unchanged rule)' {
    BeforeAll {
        $script:Holder = 'caj-si-updater:caj-si-updater-nd0t0o9'
        # one long refresh on a virtual clock: CiPub takes 100 ranges of 90 s (150 min, longer than the 121 min of the live
        # stop); every other copy is one short range. After every range the pipeline's rule judges the update.
        $script:RunRefresh = {
            param([bool]$WithBeat)
            $t0 = [datetime]::UtcNow
            $st = @{ Now = $t0; Ranges = 0; Judged = (New-Object System.Collections.Generic.List[object]); Row = [pscustomobject]@{ LockName = 'updater'; Holder = $script:Holder; HeartbeatUtc = $null } }
            $script:St = $st
            $script:Exec = [pscustomobject]@{ name = 'caj-si-updater-nd0t0o9'; properties = [pscustomobject]@{ status = 'Running'; startTime = $t0.AddMinutes(-5).ToString('o') } }
            # the update's own row registered as the updater does it, its beat (the seam) writes the row on the virtual clock
            $null = Register-SIUpdaterExecutionBeat -Holder $script:Holder -Beat { param($h, $w) $script:St.Row.HeartbeatUtc = $script:St.Now; $true }
            $global:SI_UpdaterExecBeat.LastUtc = $t0
            $script:RangeSql = Get-SIPublishedCopyRangeSql
            # (plain scriptblocks, no closure: they see this file's functions and $script: values)
            $invoke = {
                param([string]$Sql, $P, [string]$Mode)
                if ($Sql -ne $script:RangeSql) { return }
                $script:St.Ranges++
                $long = ([string]$P.Table -eq 'Ci')
                $script:St.Now = $script:St.Now.AddSeconds($(if ($long) { 90 } else { 1 }))
                $lv = Get-SIExecutionLiveness -Execution $script:Exec -Kind updater -Locks @($script:St.Row) -NowUtc $script:St.Now
                $script:St.Judged.Add($lv)
                $done = (-not $long) -or ($script:St.Ranges -ge 100)
                [pscustomobject]@{ Rows = 500; Next = $(if ($done) { $null } else { 'k' + $script:St.Ranges }); Done = $(if ($done) { 1 } else { 0 }) }
            }
            # the update's beat per range (as $copyBeat: Invoke-SIUpdaterLockBeat, at most once a minute) -- on the virtual clock
            $beat = { $null = Invoke-SIUpdaterLockBeat -What '9j. PUBLISHED COPIES' -NowUtc $script:St.Now }
            $a = @{ Invoke = $invoke; BeatSeconds = 0 }
            if ($WithBeat) { $a.Beat = $beat }
            $r = Invoke-SIPublishedCopyRefresh @a
            $global:SI_UpdaterExecBeat = $null
            [pscustomobject]@{ Result = $r; Judged = $st.Judged.ToArray(); Minutes = ($st.Now - $t0).TotalMinutes }
        }
    }
    It 'with the beat: alive at every range across 150 minutes; the row''s beat is never older than a range and a minute' {
        $o = & $script:RunRefresh $true
        $o.Result.Ok | Should -BeTrue
        $o.Minutes | Should -BeGreaterThan 121
        @($o.Judged | Where-Object { -not $_.Alive }).Count | Should -Be 0
        ($o.Judged | Measure-Object -Property MinutesSinceBeat -Maximum).Maximum | Should -BeLessOrEqual 3
        $o.Judged[-1].LastBeatUtc | Should -Not -BeNullOrEmpty
    }
    It 'without it (the negative): the unchanged rule judges the same refresh dead within the window (its sign-in row only: #1406 quiet needs the install lock or the run beat)' {
        $o = & $script:RunRefresh $false
        @($o.Judged | Where-Object { -not $_.Alive }).Count | Should -BeGreaterThan 0
    }
}
