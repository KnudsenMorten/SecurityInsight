#Requires -Version 5.1
<#
    SecurityInsight -- A DATABASE STATEMENT OF THE UPDATE KEEPS ITS SIGN OF LIFE (setup\_shared\SI-UpdateSqlBeat.ps1, wired into
    setup\Invoke-SIContainerUpdate.ps1). Live 2026-11-12: the pipeline runner's rule "no beat for 15 minutes = dead"
    (engine\_shared\SI-ExecutionLiveness.ps1, UNCHANGED) stopped updates at two installs while one long database statement ran
    after '9q. COLLECT PRODUCERS' -- the statement wrote no log line, so nothing beat the updater's own lock row.

    What must hold:
      * while a statement BLOCKS (a .NET call that holds the update's thread), a beat on a thread and runspace of its own keeps
        the updater's row beaten every interval and writes one line "<step>: SQL statement running <N> min";
      * the beat STOPS when the statement ends AND when it throws (the exception reaches the caller unchanged; the output too);
      * a statement that hangs past the cap (the liveness rule's own 6 h) stops being beaten, and the UNCHANGED rule judges the
        update dead 15 minutes after its last beat;
      * a beat that fails never reaches the statement; outside the updater (no row registered) nothing is beaten;
      * every Execute* of Invoke-SIContainerUpdate.ps1 runs inside the beat; the summary views' statements (9f) carry a 2-hour
        limit, and a statement stopped by it is a warning -- the update goes on; one wave of the published copies (9j) runs
        under the beat too.
    The beat's interval is a seam (-IntervalSeconds), never 5 real minutes. Offline, plus ONE run on the test runner's SQL
    Server (SI_TEST_LOCALSQL): the production beat on its own connection while another connection is busy in WAITFOR.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ExecutionLiveness.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-UpdateSqlBeat.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SummaryGroupsRebuild.ps1')
    $script:Update = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))

    # a fake beat (TEXT: compiled in the beat's own runspace) -- every beat recorded in $Target.Calls; $Target.Fail = it throws
    $script:FakeBeat = @'
param($Target, $State, [string]$What)
[void]$Target.Calls.Add([pscustomobject]@{ What = $What; Utc = [datetime]::UtcNow; Rows = @($Target.Rows).Count })
if ($Target.Fail) { throw 'the database did not answer' }
$true
'@
    function script:New-FakeTarget([switch]$Fail) {
        [pscustomobject]@{ Calls = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)); Fail = [bool]$Fail
                           Rows = @([pscustomobject]@{ LockId = 'updater'; Holder = 'caj-si-updater:exec-1' }) }
    }
    # a blocking statement: the update's thread held by a .NET call (as ExecuteReader holds it), never a PowerShell wait
    function script:Invoke-Blocked([int]$Ms) { [System.Threading.Thread]::Sleep($Ms) }
}
AfterAll { $global:SI_UpdateSqlBeatSettings = $null; $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null }

Describe 'a blocking statement keeps the update alive' {
    It 'while the statement blocks the update''s thread, the row is beaten every interval and every beat writes one line' {
        $t = New-FakeTarget; $sw = New-Object IO.StringWriter; $log = [IO.TextWriter]::Synchronized($sw)
        Invoke-SIUpdateSqlBeat -What '9f. SUMMARY VIEWS' -Target $t -IntervalSeconds 0.3 -Log $log -BeatScript $script:FakeBeat -Action { Invoke-Blocked 2000 }
        $log = $sw   # the text the synchronized writer wrote
        $rec = $script:SIUpdateSqlBeatLast
        $rec.Beats | Should -BeGreaterOrEqual 3 -Because '2 s at a 0.3 s interval'
        $t.Calls.Count | Should -Be $rec.Beats
        @($t.Calls)[0].What | Should -Be 'an update of SecurityInsight: 9f. SUMMARY VIEWS: SQL statement running 0 min'
        @($t.Calls)[0].Rows | Should -Be 1
        $lines = @($log.ToString() -split "`r?`n" | Where-Object { $_.Trim() })
        $lines.Count | Should -Be $rec.Beats
        foreach ($l in $lines) { $l.Trim() | Should -Be '9f. SUMMARY VIEWS: SQL statement running 0 min' }
        $rec.Ended | Should -BeTrue
    }
    It 'the line counts the minutes the statement has run (the beat''s own clock)' {
        # the minute is the floor of the elapsed time: a 0.3 s interval never reaches minute 1; the format is the contract
        $t = New-FakeTarget; $log = New-Object IO.StringWriter
        Invoke-SIUpdateSqlBeat -What '9j. PUBLISHED COPIES' -Target $t -IntervalSeconds 0.2 -Log $log -BeatScript $script:FakeBeat -Action { Invoke-Blocked 700 }
        $log.ToString() | Should -Match '(?m)^    9j\. PUBLISHED COPIES: SQL statement running \d+ min\r?$'
    }
    It 'the default interval is 5 minutes; the step falls back to the step the update is in' {
        $script:SIUpdateSqlBeatLoop | Should -Match 'WaitOne\(\$IntervalMs\)'
        ((Get-Command Start-SIUpdateSqlBeat).ScriptBlock.Ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'IntervalSeconds' }).DefaultValue.Value | Should -Be 300
        $global:SI_UpdateStage = '9q. COLLECT PRODUCERS (started only by the pipeline)'
        try {
            $t = New-FakeTarget
            Invoke-SIUpdateSqlBeat -Target $t -IntervalSeconds 0.2 -Log (New-Object IO.StringWriter) -BeatScript $script:FakeBeat -Action { Invoke-Blocked 500 }
            @($t.Calls)[0].What | Should -Match '9q\. COLLECT PRODUCERS \(started only by the pipeline\): SQL statement running 0 min$'
        } finally { $global:SI_UpdateStage = $null }
    }
}

Describe 'the beat stops when the statement ends or throws' {
    It 'ended: no beat after the statement returned; the runspace has ended; the output is passed on unchanged' {
        $t = New-FakeTarget
        $out = Invoke-SIUpdateSqlBeat -What 'x' -Target $t -IntervalSeconds 0.2 -Log (New-Object IO.StringWriter) -BeatScript $script:FakeBeat -Action { Invoke-Blocked 600; , @(1, 2, 3) }
        $n = $t.Calls.Count
        $n | Should -BeGreaterThan 0
        [System.Threading.Thread]::Sleep(800)
        $t.Calls.Count | Should -Be $n -Because 'the beat is stopped in the finally'
        $script:SIUpdateSqlBeatLast.Ended | Should -BeTrue
        @($out).Count | Should -Be 3
        # streamed rows, a scalar and $null pass as before
        @(Invoke-SIUpdateSqlBeat -Target (New-FakeTarget) -BeatScript $script:FakeBeat -IntervalSeconds 5 -Action { [pscustomobject]@{ A = 1 }; [pscustomobject]@{ A = 2 } }).Count | Should -Be 2
        Invoke-SIUpdateSqlBeat -Target (New-FakeTarget) -BeatScript $script:FakeBeat -IntervalSeconds 5 -Action { return 42 } | Should -Be 42
        $null -eq (Invoke-SIUpdateSqlBeat -Target (New-FakeTarget) -BeatScript $script:FakeBeat -IntervalSeconds 5 -Action { return $null }) | Should -BeTrue
    }
    It 'threw: the statement''s exception reaches the caller unchanged, and the beat is stopped' {
        $t = New-FakeTarget
        $err = $null
        try { Invoke-SIUpdateSqlBeat -What 'x' -Target $t -IntervalSeconds 0.2 -Log (New-Object IO.StringWriter) -BeatScript $script:FakeBeat -Action { Invoke-Blocked 600; throw 'Execution Timeout Expired.' } }
        catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Be 'Execution Timeout Expired.'
        $n = $t.Calls.Count
        [System.Threading.Thread]::Sleep(800)
        $t.Calls.Count | Should -Be $n
        $script:SIUpdateSqlBeatLast.Ended | Should -BeTrue
        $script:SIUpdateSqlBeatActive | Should -BeFalse
    }
    It 'a beat that fails never reaches the statement: the statement runs on, the line says the sign of life was not written' {
        $t = New-FakeTarget -Fail; $log = New-Object IO.StringWriter
        $r = Invoke-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target $t -IntervalSeconds 0.2 -Log $log -BeatScript $script:FakeBeat -Action { Invoke-Blocked 600; 'done' }
        $r | Should -Be 'done'
        $script:SIUpdateSqlBeatLast.Beats | Should -Be 0
        $script:SIUpdateSqlBeatLast.Failed | Should -BeGreaterThan 0
        $script:SIUpdateSqlBeatLast.LastError | Should -Be 'the database did not answer'
        $log.ToString() | Should -Match '9i\. KEY FIGURES: SQL statement running 0 min \(its sign of life could not be written this time'
    }
    It 'a statement inside a beaten statement is beaten once, by the outer one' {
        $t = New-FakeTarget
        Invoke-SIUpdateSqlBeat -What 'outer' -Target $t -IntervalSeconds 0.2 -Log (New-Object IO.StringWriter) -BeatScript $script:FakeBeat -Action {
            Invoke-SIUpdateSqlBeat -What 'inner' -Target $t -IntervalSeconds 0.2 -BeatScript $script:FakeBeat -Action { Invoke-Blocked 700 }
        }
        @($t.Calls | Where-Object { $_.What -match 'inner' }).Count | Should -Be 0
        @($t.Calls | Where-Object { $_.What -match 'outer' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'past the cap the update is judged by the unchanged rule' {
    It 'the cap is the liveness rule''s own outer fallback (6 h), and the rule itself is unchanged (15 / 30 minutes, 6 h)' {
        $c = Get-SIExecutionLivenessContract
        $c.BeatStaleMinutes | Should -Be 15; $c.NeverBeatGraceMinutes | Should -Be 30; $c.FallbackHours | Should -Be 6
        Get-SIUpdateSqlBeatCapMinutes | Should -Be 360
    }
    It 'a statement that hangs past the cap stops being beaten -- 15 minutes after its last beat the rule says dead' {
        $t = New-FakeTarget; $log = New-Object IO.StringWriter
        Invoke-SIUpdateSqlBeat -What '9f. SUMMARY VIEWS' -Target $t -IntervalSeconds 0.2 -CapMinutes 0.015 -Log $log -BeatScript $script:FakeBeat -Action { Invoke-Blocked 2500 }
        $rec = $script:SIUpdateSqlBeatLast
        $rec.Capped | Should -BeTrue
        $rec.Beats | Should -BeLessOrEqual 5 -Because 'the cap (0.9 s) ended the beat long before the statement (2.5 s)'
        $log.ToString() | Should -Match 'no longer says it is alive'
        $last = [datetime]$rec.LastBeatUtc
        $exec = [pscustomobject]@{ name = 'exec-1'; properties = [pscustomobject]@{ status = 'Running'; startTime = $last.AddMinutes(-60).ToString('o') } }
        $locks = @([pscustomobject]@{ LockName = 'updater'; Holder = 'caj-si-updater:exec-1'; HeartbeatUtc = $last })
        (Get-SIExecutionLiveness -Execution $exec -Kind updater -Locks $locks -NowUtc $last.AddMinutes(14)).Alive | Should -BeTrue
        (Get-SIExecutionLiveness -Execution $exec -Kind updater -Locks $locks -NowUtc $last.AddMinutes(16)).Alive | Should -BeFalse
    }
    It 'a hang OUTSIDE a statement is never beaten: the beat lives only inside Invoke-SIUpdateSqlBeat' {
        $script:SIUpdateSqlBeatActive | Should -BeFalse
        $script:Update | Should -Not -Match 'Start-SIUpdateSqlBeat' -Because 'the update starts a beat only through the wrapper (started before, stopped in its finally)'
        $def = (Get-Command Invoke-SIUpdateSqlBeat).Definition
        $def | Should -Match '(?s)try \{ & \$Action \}\s+finally \{.*Stop-SIUpdateSqlBeat -Beat \$sbBeat'
    }
}

Describe 'where the beat writes, and when nothing is beaten' {
    BeforeEach { $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null; $global:SI_UpdateSqlBeatSettings = $null }
    It 'outside the updater (no row registered): no target, the statement just runs, no beat starts' {
        Get-SIUpdateSqlBeatTarget -Token { 'tok' } | Should -BeNullOrEmpty
        $script:SIUpdateSqlBeatLast = 'untouched'
        Invoke-SIUpdateSqlBeat -What 'x' -Action { 7 } | Should -Be 7
        $script:SIUpdateSqlBeatLast | Should -Be 'untouched'
    }
    It 'the updater''s own row and the install lock it holds, on the Pro database it registered; test seams are never called from the beat' {
        $global:SI_UpdaterExecBeat = [pscustomobject]@{ Holder = 'caj-si-updater:exec-1'; Beat = $null; Server = 'sql-x'; Database = 'sqldb-pro' }
        $global:SI_UpdaterLockBeat = [pscustomobject]@{ Holder = 'caj-si-updater:exec-1'; Real = $true; Beat = $null }
        $t = Get-SIUpdateSqlBeatTarget -Token { 'tok-1' }
        $t.Server | Should -Be ('sql-x' + '.' + 'database.windows.net'); $t.Database | Should -Be 'sqldb-pro'; $t.AccessToken | Should -Be 'tok-1'
        @($t.Rows | ForEach-Object { $_.LockId }) | Should -Be @('updater', 'install')
        @($t.Libs)[0] | Should -Match 'SI-SqlRetry\.ps1$'
        Test-Path -LiteralPath @($t.Libs)[0] | Should -BeTrue
        $t.Statement | Should -Match 'UPDATE cfg\.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME\(\), What = @What WHERE LockId = @LockId AND Holder = @Holder'
        # a registration that is a test seam: nothing to beat from another thread
        $global:SI_UpdaterExecBeat = [pscustomobject]@{ Holder = 'h'; Beat = { $true } }
        $global:SI_UpdaterLockBeat = [pscustomobject]@{ Holder = 'h'; Real = $false; Beat = $null }
        Get-SIUpdateSqlBeatTarget -Token { 'tok' } | Should -BeNullOrEmpty
        # no token: nothing (never a beat that cannot sign in)
        $global:SI_UpdaterExecBeat = [pscustomobject]@{ Holder = 'h'; Beat = $null; Server = 's'; Database = 'd' }
        Get-SIUpdateSqlBeatTarget -Token { '' } | Should -BeNullOrEmpty
    }
    It 'the updater registers where its row lives (Register-SIUpdaterExecutionBeat: the store''s server and database)' {
        $rg = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1'))
        $rg | Should -Match "Server = \`$\(if \(\`$Store -and \`$Store\.PSObject\.Properties\['Server'\]\)"
    }
    It 'the beat never runs the update''s own code: its loop and beat are text, compiled in its own runspace' {
        $def = (Get-Command Start-SIUpdateSqlBeat).Definition
        $def | Should -Match '\[runspacefactory\]::CreateRunspace\(\)'
        $def | Should -Match 'AddScript\(\$script:SIUpdateSqlBeatLoop\)'
        $script:SIUpdateSqlBeatLoop | Should -Match '\[scriptblock\]::Create\(\$BeatText\)'
        $script:SIUpdateSqlBeatScript | Should -Match 'Open-SISqlConnectionRetry @open' -Because 'its own connection, through the shared open'
        $script:SIUpdateSqlBeatScript | Should -Not -Match 'Invoke-SIUpdaterLockBeat|\$global:'
    }
}

Describe 'a beat connection that drops after its token ran out opens again with a FRESH token' {
    BeforeEach {
        $script:Opened = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $script:Fetched = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        [System.AppDomain]::CurrentDomain.SetData('SIUpdateSqlBeatTestOpened', $script:Opened)
        [System.AppDomain]::CurrentDomain.SetData('SIUpdateSqlBeatTestFetched', $script:Fetched)
    }
    AfterEach { [System.AppDomain]::CurrentDomain.SetData('SIUpdateSqlBeatTestOpened', $null); [System.AppDomain]::CurrentDomain.SetData('SIUpdateSqlBeatTestFetched', $null) }
    It 'the production beat: the first open uses the main thread''s token; the connection drops; the next open uses a token fetched in the beat''s runspace' {
        # the open's -Connect seam (TEXT, compiled in the beat's runspace): records every token it is given; the main thread's
        # token has EXPIRED after the first open (a sign-in with it fails); every connection DROPS after one beat
        $connect = @'
param($Server, $Database, $Token)
$rec = [System.AppDomain]::CurrentDomain.GetData('SIUpdateSqlBeatTestOpened')
if ($Token -eq 'expired-main-thread-token' -and $rec.Count -gt 0) { throw "Login failed for user '<token-identified principal>'. The token is expired." }
[void]$rec.Add($Token)
$cn = [pscustomobject]@{ State = [System.Data.ConnectionState]::Open }
$cn | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
$cn | Add-Member -MemberType ScriptMethod -Name CreateCommand -Value {
    $p = [pscustomobject]@{}; $p | Add-Member -MemberType ScriptMethod -Name AddWithValue -Value { param($n, $v) $null }
    $cmd = [pscustomobject]@{ CommandTimeout = 0; CommandText = ''; Conn = $this; Parameters = $p }
    $cmd | Add-Member -MemberType ScriptMethod -Name ExecuteScalar -Value { $this.Conn.State = [System.Data.ConnectionState]::Closed; 1 }
    $cmd }
$cn
'@
        $fresh = @'
param($Target)
$n = [System.AppDomain]::CurrentDomain.GetData('SIUpdateSqlBeatTestFetched'); [void]$n.Add([datetime]::UtcNow)
'fresh-token-' + $n.Count
'@
        $target = [pscustomobject]@{ Server = 'server.database.windows.net'; Database = 'sqldb-pro'; AccessToken = 'expired-main-thread-token'; ConnectText = $connect
                                     Libs = @($script:SIUpdateSqlBeatRetryLib); Statement = $script:SIUpdateSqlBeatStatement
                                     Rows = @([pscustomobject]@{ LockId = 'updater'; Holder = 'caj-si-updater:exec-1' })
                                     TokenText = $fresh; TokenLibs = @(); Auth = @{ Mode = 'ManagedIdentity'; ClientId = '' } }
        Invoke-SIUpdateSqlBeat -What '9f. SUMMARY VIEWS' -Target $target -IntervalSeconds 0.3 -Log (New-Object IO.StringWriter) -Action { Invoke-Blocked 1800 }
        $rec = $script:SIUpdateSqlBeatLast
        $rec.LastError | Should -BeNullOrEmpty
        $script:Opened.Count | Should -BeGreaterOrEqual 2 -Because 'every beat dropped its connection, so the next one opened it again'
        $script:Opened[0] | Should -Be 'expired-main-thread-token' -Because 'the main thread''s token stays the first one'
        $script:Opened[1] | Should -Be 'fresh-token-1' -Because 'the second open uses a freshly fetched token, never the expired one'
        @($script:Opened | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^fresh-token-\d+$' }).Count | Should -Be 0
        $rec.Beats | Should -BeGreaterOrEqual 2 -Because 'the beats go on after the drop'
        $rec.FreshTokens | Should -BeGreaterOrEqual 1
        $rec.Opens | Should -Be $script:Opened.Count
    }
    It 'the target carries the means to fetch one (a copy of the recorded sign-in, the fetch as text, the REST token path as libs)' {
        $script:SIUpdateSqlBeatTokenScript | Should -Match ([regex]::Escape("Get-SIAzureToken -Resource 'https://database.windows.net/' -Auth `$Target.Auth -ForceRefresh"))
        $script:SIUpdateSqlBeatTokenScript | Should -Not -Match '\$global:|Invoke-SIUpdaterLockBeat'
        foreach ($l in $script:SIUpdateSqlBeatTokenLibs) { Test-Path -LiteralPath $l | Should -BeTrue }
        @($script:SIUpdateSqlBeatTokenLibs | ForEach-Object { Split-Path -Leaf $_ }) | Should -Be @('SI-LogIngest.ps1', 'SI-AzRest.ps1', 'SI-ManagedIdentity.ps1')
        $global:SI_UpdaterExecBeat = [pscustomobject]@{ Holder = 'caj-si-updater:exec-1'; Beat = $null; Server = 'sql-x'; Database = 'sqldb-pro' }
        try {
            $t = Get-SIUpdateSqlBeatTarget -Token { 'tok-1' }
            $t.AccessToken | Should -Be 'tok-1'
            $t.TokenText | Should -Be $script:SIUpdateSqlBeatTokenScript
            @($t.TokenLibs).Count | Should -Be 3
        } finally { $global:SI_UpdaterExecBeat = $null }
    }
}

Describe 'a beat always loses a deadlock against the update''s own statement' {
    It 'the beat''s statement sets DEADLOCK_PRIORITY LOW before it touches the lock row' {
        $script:SIUpdateSqlBeatStatement | Should -Match ([regex]::Escape('SET DEADLOCK_PRIORITY LOW;'))
        $script:SIUpdateSqlBeatStatement.IndexOf('SET DEADLOCK_PRIORITY LOW;') | Should -BeLessThan $script:SIUpdateSqlBeatStatement.IndexOf('UPDATE cfg.PipelineLock')
    }
}

Describe 'the update runs every database statement under the beat (setup\Invoke-SIContainerUpdate.ps1)' {
    It 'loads the beat and EVERY ExecuteReader / ExecuteNonQuery / ExecuteScalar sits inside the beat''s -Action' {
        $script:Update | Should -Match "\. \(Join-Path \`$PSScriptRoot '_shared/SI-UpdateSqlBeat\.ps1'\)"
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Update, [ref]$null, [ref]$null)
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and "$($n.Member)" -match '^Execute(Reader|NonQuery|Scalar)$' }, $true))
        $calls.Count | Should -BeGreaterOrEqual 20
        $outside = foreach ($c in $calls) {
            $p = $c.Parent; $inside = $false
            while ($p) {
                if ($p -is [System.Management.Automation.Language.CommandAst]) {
                    $first = $p.CommandElements[0]
                    $name = if ($first -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $first.Value } else { $first.Extent.Text }
                    if ($name -in @('Invoke-SIUpdateSqlBeat', '$sqlBeat')) { $inside = $true; break }
                }
                $p = $p.Parent
            }
            if (-not $inside) { 'line {0}: {1}' -f $c.Extent.StartLineNumber, $c.Extent.Text }
        }
        ($outside -join "`n") | Should -BeNullOrEmpty
    }
    It 'each block names its step for the log line; the shared Pro statement takes the calling step''s name' {
        foreach ($s in '8. JOB SIZE', '9a. MISSING JOBS', '9b. PIPELINE SCHEDULE', '9c. NIGHTLY SCHEDULE', '9d. PIPELINE LAYOUT', '9e. REPORT ROW COPY', '9f. SUMMARY VIEWS', '9g. SIGN-IN FRONT STORE', '9i. KEY FIGURES', '9j. PUBLISHED COPIES', '12. DISPLAY NAMES') {
            $script:Update | Should -Match ("Invoke-SIUpdateSqlBeat -What '{0}'" -f [regex]::Escape($s))
        }
        $script:Update | Should -Match 'Invoke-SIUpdateSqlBeat -What "\$sqlStep"'
        foreach ($s in '9k. OWN SQL TARGET', '9m. SERVICENOW DATA OUT', '9n. SERVICENOW STAGING STATUS', '9o. SERVICENOW ONE ROUTE', '9p. SUPPORT ACCESS') {
            $script:Update | Should -Match ("\`$sqlStep = '{0}'; \`$sql = \`$script:SIUpdateProSql" -f [regex]::Escape($s))
        }
    }
    It 'the key figures'' stepped session (a closure) reaches the beat through a local copy of it' {
        $script:Update | Should -Match ([regex]::Escape('$sqlBeat = ${function:Invoke-SIUpdateSqlBeat}'))
        $script:Update | Should -Match ([regex]::Escape('$sqlBeat = $sqlBeat   # a local copy'))
        $script:Update | Should -Match "& \`$sqlBeat -What '9i\. KEY FIGURES' -Action"
    }
    It 'one wave of the published copies runs under the beat; the engine driver hands -Wave on (and an older driver gets the call as before)' {
        $script:Update | Should -Match ([regex]::Escape("`$copyWave['Wave'] = { param(`$info, `$ranges) Invoke-SIUpdateSqlBeat -What '9j. PUBLISHED COPIES' -Action { Invoke-SIPublishedCopyRangeWave -Info `$info -Ranges `$ranges } }"))
        $script:Update | Should -Match ([regex]::Escape("if ((Get-Command -Name Invoke-SIPublishedCopyCatchUp).Parameters.ContainsKey('Wave'))"))
        $script:Update | Should -Match ([regex]::Escape('$r = Invoke-SIPublishedCopyCatchUp -Invoke $dataSql -WhatIf:(-not $Apply -or $DetectOnly) -Beat $copyBeat @copyWave'))
        $pr = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataPublishedRun.ps1'))
        # (the driver names it -RangeWave: its own $wave is the list of ranges -- PowerShell names are not case-sensitive)
        $pr | Should -Match ([regex]::Escape("`$rfWave = @{}; if (`$Wave) { `$rfWave['RangeWave'] = `$Wave }"))
        $pr | Should -Match ([regex]::Escape('$res.Refresh = Invoke-SIPublishedCopyRefresh -Invoke $Invoke -Log $Log -Beat $Beat @rfWave'))
        $pr | Should -Match ([regex]::Escape("`$rpWave = @{}; if (`$RangeWave) { `$rpWave['Wave'] = `$RangeWave }"))
        $pr | Should -Match ([regex]::Escape('foreach ($r in (Invoke-SIPublishedCopyRangesParallel -ConnectionInfo $ci -Ranges $wave.ToArray() -Log $Log @rpWave))'))
    }
}

Describe 'the summary views (9f) carry a 2-hour limit; reaching it is a warning and the update goes on' {
    It 'its statements stop after 7200 s (never 0 = for ever); the limit is said in plain words' {
        $script:Update | Should -Match '\$script:SIUpdateSummaryTimeoutSeconds = 7200'
        $fn = [regex]::Match($script:Update, '(?s)function Invoke-SIUpdateSummaryRebuild \{.*?\n\}').Value
        $fn | Should -Match '\$cmd\.CommandTimeout = \$script:SIUpdateSummaryTimeoutSeconds'
        $fn | Should -Not -Match 'CommandTimeout = 0'
        $fn | Should -Match 'ran past its limit of \{0\} minutes and was stopped'
        $fn | Should -Match '\$e -is \[System\.Data\.SqlClient\.SqlException\] -and \$e\.Number -eq -2'
    }
    It 'a statement stopped by the limit: the step answers failed with one line (a warning), it never throws' {
        $boom = { param($q, $p, $m) throw 'a database statement of the summary views ran past its limit of 120 minutes and was stopped' }
        $r = Invoke-SISummaryGroupsRebuild -DataSql $boom -Sql $boom -Hash 'h' -DataSyncInstalled $true
        $r.Action | Should -Be 'failed'
        @($r.Lines)[0] | Should -Match 'ran past its limit of 120 minutes'
        $fn = [regex]::Match($script:Update, '(?s)function Invoke-SIUpdateSummaryRebuild \{.*?\n\}').Value
        $fn | Should -Match "foreach \(\`$l in @\(\`$r\.Lines\)\) \{ if \(\`$r\.Action -eq 'failed'\) \{ Warn \`$l \}"
    }
}

Describe 'on a real SQL Server: the production beat on its own connection while another one is busy' {
    It 'the updater''s row is beaten (and only its own) during a 4-second WAITFOR on another connection' -Skip:(-not $script:LocalSql) {
        $db = 'sibeat_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $cs = { param($d) "Server=$($env:SI_TEST_LOCALSQL);Database=$d;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True" }
        $run = { param($d, $q) $cn = New-Object System.Data.SqlClient.SqlConnection((& $cs $d)); $cn.Open(); try { $c = $cn.CreateCommand(); $c.CommandTimeout = 120; $c.CommandText = $q; [void]$c.ExecuteNonQuery() } finally { $cn.Dispose() } }
        & $run 'master' "CREATE DATABASE [$db]"
        try {
            & $run $db "CREATE SCHEMA cfg;"
            & $run $db "CREATE TABLE cfg.PipelineLock (LockId nvarchar(32) NOT NULL PRIMARY KEY, Holder nvarchar(128) NULL, What nvarchar(200) NULL, HeartbeatUtc datetime2 NULL);"
            & $run $db "INSERT cfg.PipelineLock VALUES (N'updater', N'caj-si-updater:exec-1', N'start', '2026-01-01'), (N'install', N'caj-si-flow-other', N'a run', '2026-01-01');"
            # the open's own -Connect seam, as text (a SQL login on the runner; the product opens with its Entra token)
            $connect = 'param($Server, $Database, $Token) $cn = New-Object System.Data.SqlClient.SqlConnection(''{0}''); $cn.Open(); $cn' -f ((& $cs $db) -replace "'", "''")
            $target = [pscustomobject]@{ Server = [string]$env:SI_TEST_LOCALSQL; Database = $db; AccessToken = 'unused-with-a-login'; ConnectText = $connect
                                         Libs = @($script:SIUpdateSqlBeatRetryLib); Statement = $script:SIUpdateSqlBeatStatement
                                         Rows = @([pscustomobject]@{ LockId = 'updater'; Holder = 'caj-si-updater:exec-1' }, [pscustomobject]@{ LockId = 'install'; Holder = 'caj-si-updater:exec-1' }) }
            $start = [datetime]::UtcNow.AddSeconds(-1)
            $log = New-Object IO.StringWriter
            # the default (production) beat: no -BeatScript
            Invoke-SIUpdateSqlBeat -What '9f. SUMMARY VIEWS' -Target $target -IntervalSeconds 1 -Log $log -Action { & $run $db "WAITFOR DELAY '00:00:04';" }
            $rec = $script:SIUpdateSqlBeatLast
            $rec.LastError | Should -BeNullOrEmpty
            $rec.Beats | Should -BeGreaterOrEqual 2
            $cn = New-Object System.Data.SqlClient.SqlConnection((& $cs $db)); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandText = "SELECT LockId, Holder, What, HeartbeatUtc FROM cfg.PipelineLock ORDER BY LockId"
                $rd = $c.ExecuteReader(); $rows = @{}
                while ($rd.Read()) { $rows[[string]$rd.GetValue(0)] = [pscustomobject]@{ Holder = [string]$rd.GetValue(1); What = [string]$rd.GetValue(2); At = [datetime]$rd.GetValue(3) } }
                $rd.Close()
            } finally { $cn.Dispose() }
            $rows['updater'].What | Should -Be 'an update of SecurityInsight: 9f. SUMMARY VIEWS: SQL statement running 0 min'
            $rows['updater'].At | Should -BeGreaterThan $start
            $rows['install'].What | Should -Be 'a run' -Because 'a row another holder holds is never touched'
            $log.ToString() | Should -Match '9f\. SUMMARY VIEWS: SQL statement running 0 min'
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            & $run 'master' "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]"
        }
    }
}
