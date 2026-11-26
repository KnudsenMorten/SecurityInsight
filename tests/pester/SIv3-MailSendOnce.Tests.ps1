#Requires -Version 5.1
<#
    A MAIL GOES ONCE -- the send record and the queue claim (engine\_shared\data-sql\SI-MailSendRecord.ps1).

    What these tests keep true:
      * the RISK ANALYSIS mail: at most one per pipeline run (or per collection outside the pipeline) -- a second run of the
        step does not send it again, nor keep a second copy for the data sync, and leaves the first run's kept mail to the
        data sync (-HoldMailIds); FAIL OPEN: a record that cannot be read or written (its database not opened, the
        pipeline run unreadable, the claim failed) = SENT as before with one line that a duplicate is possible -- only a
        definite "already sent / kept / being sent" keeps it back; no database at all = as before;
      * the CLOSE-LOOP daily mail: at most one per schedule slot day (the key is the slot's day, not the wall clock: a
        23:50 slot run that starts at 00:05 keeps its day) -- a second run for that slot sends nothing; a failed send is sent
        by the next run; a hold (the send right could not be checked) gives its try back; mail off is not recorded as sent;
        FAIL OPEN like Risk Analysis; a database without the table = as before;
      * the MAIL QUEUES: each row is claimed before it is sent; a row another sender holds is left to it; a claim that
        cannot be made = not sent (never twice); a row not sent is released for the next run; a hold keeps its tries; a row
        the server accepted but that could not be marked sent is noted 'sent, not marked' and never claimed again (not
        after the lease either), and a later run marks it sent;
      * the schema: the table and the claim columns are additive and guarded, in the shipped schema files, and the engine
        holds the same statement;
      * REAL SQL (when the tests' SQL Server is there): two claims -> one; eight claims at once -> one claimant; a failed
        send -> claimed again; a hold gives the try back; an accepted-but-unmarked mail is never taken again, not even after
        the lease; an install without the table / the columns behaves as before and reaches the new state from the
        shipped files.
    Offline parts use fakes; NO mail is sent anywhere.
#>

BeforeDiscovery {
    $script:SqlUp = $false
    if ($env:SI_TEST_LOCALSQL) {
        for ($try = 0; $try -lt 6 -and -not $script:SqlUp; $try++) {
            try { $p = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"; $p.Open(); $p.Dispose(); $script:SqlUp = $true } catch { Start-Sleep -Seconds 5 }
        }
    }
    $script:HasSql = $script:SqlUp -and $PSVersionTable.PSVersion.Major -ge 7
    # the close-loop and exemption mails are Pro files: a Community copy has neither -- their parts are skipped there
    $r = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ProMail = (Test-Path -LiteralPath (Join-Path $r 'engine\asset-cmdb\_shared\SI-CloseLoopMail.ps1')) -and (Test-Path -LiteralPath (Join-Path $r 'engine\asset-cmdb\_shared\SI-ExemptionMail.ps1'))
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-MailSendRecord.ps1')
    foreach ($pro in 'engine\asset-cmdb\_shared\SI-CloseLoopMail.ps1', 'engine\asset-cmdb\_shared\SI-ExemptionMail.ps1') { $pp = Join-Path $script:Root $pro; if (Test-Path -LiteralPath $pp) { . $pp } }
    . (Join-Path $script:Root 'engine\_shared\SI-RunOutcome.ps1')   # the pipeline run of a step (Get-SIFlowStepOutcomeSql)
    $script:Quiet = { param($l, $m) }
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-13T10:45:00', 'Utc')

    # A FAKE SEND RECORD: the claim and its outcomes, by statement, in memory (the same rules as the SQL; the real SQL is
    # proven below). -NoTable: a database the updater has not reached; -Broken: a database that cannot be read.
    function script:New-FakeRecord([switch]$NoTable, [switch]$Broken) {
        $w = [pscustomobject]@{ Rows = @{}; Calls = (New-Object System.Collections.Generic.List[string]); NoTable = [bool]$NoTable; Broken = [bool]$Broken }
        $w | Add-Member -NotePropertyName Invoke -NotePropertyValue ({
            param($Sql, $P, $Mode)
            if ($w.Broken) { throw 'SQL 40613: the database is not available' }
            $rows = $w.Rows
            $ans = { param($o, $k) $r = $rows[$k]; , @([pscustomobject]@{ Outcome = $o; State = $(if ($r) { $r.State } else { $null }); OutboxMailId = $(if ($r) { $r.OutboxMailId } else { $null }); SentAt = $(if ($r) { $r.SentAt } else { $null }); LastError = $(if ($r) { $r.LastError } else { $null }) }) }
            if ($Sql -match 'WITH \(UPDLOCK, HOLDLOCK\)') {
                $w.Calls.Add('claim')
                if ($w.NoTable) { return (& $ans 'no-table' '') }
                $k = [string]$P.MailKey; $r = $rows[$k]
                if (-not $r) { $rows[$k] = @{ State = 'sending'; ClaimedBy = [string]$P.By; Attempts = 1; OutboxMailId = $null; SentAt = $null; LastError = $null }; return (& $ans 'claimed' $k) }
                if ($r.State -eq 'sending' -and $r.ClaimedBy -eq [string]$P.By) { return (& $ans 'claimed' $k) }
                if ($r.State -eq 'waiting') { $r.State = 'sending'; $r.ClaimedBy = [string]$P.By; $r.Attempts++; return (& $ans 'claimed' $k) }
                return (& $ans 'taken' $k)
            }
            if ($Sql -match '^SET NOCOUNT ON; IF OBJECT_ID\(''sidata\.MailSendRecord''\) IS NULL SELECT 0; ELSE BEGIN UPDATE') {
                if ($w.NoTable) { return 0 }
                $k = [string]$P.MailKey; $r = $rows[$k]
                if (-not $r -or $r.State -ne 'sending' -or $r.ClaimedBy -ne [string]$P.By) { return 0 }
                if ($Sql -match "State = N'sent'") { $w.Calls.Add('sent'); $r.State = 'sent'; $r.SentAt = [datetime]'2026-11-13T10:46:00' }
                elseif ($Sql -match "State = N'queued'") { $w.Calls.Add('queued'); $r.State = 'queued'; $r.OutboxMailId = [long]$P.OutboxMailId }
                elseif ($Sql -match "State = N'waiting'") { $w.Calls.Add('waiting'); $r.State = 'waiting'; $r.ClaimedBy = $null; $r.LastError = [string]$P.Error; if ($Sql -match 'Attempts - 1') { $r.Attempts-- } }
                elseif ($Sql -match 'sent, not marked') { $w.Calls.Add('unmarked'); $r.LastError = 'sent, not marked: ' + [string]$P.Error }
                return 1
            }
            throw "unexpected SQL: $Sql"
        }.GetNewClosure()) -Force
        $w
    }

    # the close-loop's own reads (a quiet day is enough: the mail is what is counted)
    function script:New-CloseLoopSql {
        {
            param([string]$sql, $p, [string]$mode)
            if ($sql -match 'AS HasVuln') { return , @(@{ HasVuln = 1; HasTier = 0; HasLifecycle = 0; HasSettings = 0 }) }
            if ($sql -match 'e\.Action IN') { return , @() }
            if ($sql -match "WHERE i\.State = N'Open'") { return , @(@{ Severity = 'High'; Tier = [System.DBNull]::Value; Items = [long]3 }) }
            throw "unexpected SQL: $sql"
        }
    }
    $script:ClGlobals = @{ Mail_CloseLoop_Daily_SendMail = $true; Mail_CloseLoop_Daily_To = @('secops@example.invalid'); SI_VulnSync_SqlServer = 'sql.example.invalid'; SI_VulnSync_SqlDatabase = 'si'; TenantShort = 'contoso' }
    function script:Invoke-CloseLoop($Record, $Send, [string]$Problem = '', [datetime]$At = $script:Now, $Log = $script:Quiet) {
        $cl = New-CloseLoopSql
        Invoke-SICloseLoopMailCore -Globals $script:ClGlobals -NewInvoke { param($s, $d) $cl }.GetNewClosure() -Send $Send -Now $At -Log $Log `
            -SendRecord @{ Invoke = $(if ($Record) { $Record.Invoke } else { $null }); Problem = $Problem }
    }
    function script:New-CountingSend([switch]$Fail, [switch]$Held, [switch]$Off) {
        $w = [pscustomobject]@{ Count = 0; Tried = 0; Fail = [bool]$Fail; Held = [bool]$Held; Off = [bool]$Off }
        $w | Add-Member -NotePropertyName Send -NotePropertyValue ({
            param($to, $subject, $html)
            $w.Tried++
            if ($w.Held) { $ex = [System.InvalidOperationException]::new('the close-loop mail was not sent: the send right on the shared mailbox could not be checked, so SecurityInsight does not send this time'); $ex.Data['SIMailHeld'] = 'check-unreadable'; throw $ex }
            if ($w.Fail) { throw 'the close-loop mail was not sent: 451 try again later' }
            if ($w.Off) { return $false }
            $w.Count++
            $true
        }.GetNewClosure()) -Force
        $w
    }
}

Describe 'THE SCHEMA: additive, guarded, in the shipped files the code already uses' {
    It 'sidata.MailSendRecord: the SAME guarded statement in sql\si-data-schema.sql and in the engine' {
        $schema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql')).Replace("`r`n", "`n")
        $sql = (Get-SIMailSendRecordTableSql).Trim().Replace("`r`n", "`n")
        $schema | Should -Match ([regex]::Escape($sql))
        $sql | Should -Match "^IF OBJECT_ID\('sidata\.MailSendRecord'\) IS NULL\s+CREATE TABLE sidata\.MailSendRecord"
        $sql | Should -Match "CHECK \(State IN \('sending', 'sent', 'queued', 'waiting'\)\)"
        # the engine never creates it (its identity has no DDL right): a database without it answers 'no-table'
        (Get-SIMailSendRecordClaimSql) | Should -Match "^SET NOCOUNT ON;\s+IF OBJECT_ID\('sidata\.MailSendRecord'\) IS NULL\s+SELECT N'no-table'"
        (Get-SIMailSendRecordClaimSql) | Should -Not -Match 'CREATE TABLE'
    }
    It 'the queues'' claim columns: nullable, each behind IF COL_LENGTH ... IS NULL, in sql\si-pro-settings.sql' {
        $cfg = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        foreach ($t in 'ExemptionMail', 'SignInMail', 'ReportMail', 'GovernanceMail') {
            $cfg | Should -Match ("IF COL_LENGTH\('cfg\.{0}', 'ClaimedAt'\) IS NULL\s+ALTER TABLE cfg\.{0} ADD ClaimedAt DATETIME2\(3\) NULL;" -f $t)
            $cfg | Should -Match ("IF COL_LENGTH\('cfg\.{0}', 'ClaimedBy'\) IS NULL\s+ALTER TABLE cfg\.{0} ADD ClaimedBy NVARCHAR\(200\) NULL;" -f $t)
            # without the columns the claim answers -1 and the job sends as before
            (Get-SIMailQueueClaimSql -Table "cfg.$t") | Should -Match ("^SET NOCOUNT ON; IF COL_LENGTH\(N'cfg\.{0}', N'ClaimedBy'\) IS NULL SELECT -1;" -f $t)
        }
        { Get-SIMailQueueClaimSql -Table 'cfg.Setting' } | Should -Throw
    }
}

Describe 'THE KEY: one per pipeline run, else per collection; one per day for a daily mail' {
    It 'names the run, the collection or the day' {
        Get-SIMailSendRecordKey -Kind 'ra-detailed' -FlowRunId 'fr-1' -CollectionId 9 | Should -Be 'ra-detailed|run:fr-1'
        Get-SIMailSendRecordKey -Kind 'ra-detailed' -CollectionId 9 | Should -Be 'ra-detailed|collection:9'
        Get-SIMailSendRecordKey -Kind 'close-loop-daily' -Day '2026-11-13' | Should -Be 'close-loop-daily|2026-11-13'
        Get-SIMailSendRecordKey -Kind 'ra-detailed' | Should -Be ''
    }
    It 'the record lives in the data backend (the same rule as the data sync); none configured = $null' {
        (Get-SIMailSendRecordDatabase -Globals @{ SI_ProSqlServer = 'a'; SI_ProSqlDatabase = 'b' }).Database | Should -Be 'b'
        (Get-SIMailSendRecordDatabase -Globals @{ SI_ProSqlServer = 'a'; SI_ProSqlDatabase = 'b'; SI_Pro_DataSqlServer = 'c'; SI_Pro_DataSqlDatabase = 'd' }).Server | Should -Be 'c'
        Get-SIMailSendRecordDatabase -Globals @{} | Should -BeNullOrEmpty
    }
}

Describe 'THE CLOSE-LOOP DAILY MAIL: at most one per UTC day' -Skip:(-not $script:ProMail) {
    It 'two runs the same day -> ONE mail; the next day -> its own mail' {
        $rec = New-FakeRecord; $s = New-CountingSend
        $lines = New-Object System.Collections.Generic.List[string]
        $log = { param($l, $m) $lines.Add($m) }.GetNewClosure()
        (Invoke-CloseLoop -Record $rec -Send $s.Send).Sent | Should -BeTrue
        $r2 = Invoke-CloseLoop -Record $rec -Send $s.Send -At $script:Now.AddHours(3) -Log $log
        $r2.Sent | Should -BeFalse
        $s.Count | Should -Be 1
        $r2.Reason | Should -Match 'close-loop: the daily mail of 2026-11-13 was already sent at 2026-11-13 10:46 UTC -- it is not sent again'
        @($lines | Where-Object { $_ -match 'already sent' }).Count | Should -Be 1
        (Invoke-CloseLoop -Record $rec -Send $s.Send -At $script:Now.AddDays(1)).Sent | Should -BeTrue
        $s.Count | Should -Be 2
    }
    It 'a failed send FAILS the run and is sent by the next run of the day' {
        $rec = New-FakeRecord; $bad = New-CountingSend -Fail; $good = New-CountingSend
        { Invoke-CloseLoop -Record $rec -Send $bad.Send } | Should -Throw '*451*'
        $rec.Rows['close-loop-daily|2026-11-13'].State | Should -Be 'waiting'
        (Invoke-CloseLoop -Record $rec -Send $good.Send).Sent | Should -BeTrue
        $good.Count | Should -Be 1
        $rec.Rows['close-loop-daily|2026-11-13'].Attempts | Should -Be 2
    }
    It 'a HOLD (the send right could not be checked) gives its try back and still throws the hold, unchanged' {
        $rec = New-FakeRecord; $held = New-CountingSend -Held
        $err = $null; try { $null = Invoke-CloseLoop -Record $rec -Send $held.Send } catch { $err = $_ }
        Test-SIMailHeldUnreadable -Failure $err | Should -BeTrue
        $rec.Rows['close-loop-daily|2026-11-13'].State | Should -Be 'waiting'
        $rec.Rows['close-loop-daily|2026-11-13'].Attempts | Should -Be 0 -Because 'a hold uses no try'
    }
    It 'mail switched off (the sender answers $false) is not recorded as sent' {
        $rec = New-FakeRecord; $off = New-CountingSend -Off; $on = New-CountingSend
        $null = Invoke-CloseLoop -Record $rec -Send $off.Send
        $rec.Rows['close-loop-daily|2026-11-13'].State | Should -Be 'waiting'
        (Invoke-CloseLoop -Record $rec -Send $on.Send).Sent | Should -BeTrue
        $on.Count | Should -Be 1
    }
    It 'FAIL OPEN: a record that cannot be read, or a database that cannot be opened -> SENT as before, one line that a duplicate is possible' {
        $s = New-CountingSend
        $lines = New-Object System.Collections.Generic.List[string]
        $log = { param($l, $m) $lines.Add("[$l] $m") }.GetNewClosure()
        $r = Invoke-CloseLoop -Record (New-FakeRecord -Broken) -Send $s.Send -Log $log
        $r.Sent | Should -BeTrue
        @($lines | Where-Object { $_ -match '^\[WARN\] close-loop: the daily mail of 2026-11-13: its send record could not be checked \(SQL 40613.*\) -- it is sent as before, so a duplicate is possible$' }).Count | Should -Be 1 -Because ($lines -join ' | ')
        $lines.Clear()
        $r = Invoke-CloseLoop -Record $null -Send $s.Send -Problem 'its database could not be opened: login failed' -Log $log
        $r.Sent | Should -BeTrue
        @($lines | Where-Object { $_ -match '^\[WARN\].*could not be checked \(its database could not be opened: login failed\) -- it is sent as before, so a duplicate is possible$' }).Count | Should -Be 1
        $s.Count | Should -Be 2
        # only a definite "already sent" keeps it back
        $rec = New-FakeRecord
        (Invoke-CloseLoop -Record $rec -Send $s.Send).Sent | Should -BeTrue
        (Invoke-CloseLoop -Record $rec -Send $s.Send).Sent | Should -BeFalse
        $s.Count | Should -Be 3
    }
    It 'THE KEY IS THE SLOT''S DAY, not the wall clock: a 23:50 slot run that starts at 00:05 keys to the slot''s day; the next day''s 23:50 run still sends' {
        Get-SICloseLoopMailSlotDay -Now ([datetime]::SpecifyKind([datetime]'2026-11-14T00:05:00', 'Utc')) -SendTimeUtc '23:50' | Should -Be '2026-11-13'
        Get-SICloseLoopMailSlotDay -Now ([datetime]::SpecifyKind([datetime]'2026-11-14T23:50:00', 'Utc')) -SendTimeUtc '23:50' | Should -Be '2026-11-14'
        Get-SICloseLoopMailSlotDay -Now ([datetime]::SpecifyKind([datetime]'2026-11-14T23:49:30', 'Utc')) -SendTimeUtc '23:50' | Should -Be '2026-11-14' -Because 'a start a little early still belongs to its slot'
        Get-SICloseLoopMailSlotDay -Now $script:Now -SendTimeUtc '' | Should -Be '2026-11-13' -Because 'no setting = the 10:45 default slot'
        Get-SICloseLoopMailSlotDay -Now $script:Now -SendTimeUtc 'soon' | Should -Be '2026-11-13'
        # end to end: the late 00:05 run is the 13th's mail; the 14th's 23:50 run sends its own
        $g = @{}; foreach ($k in $script:ClGlobals.Keys) { $g[$k] = $script:ClGlobals[$k] }; $g['Mail_CloseLoop_Daily_SendTimeUtc'] = '23:50'
        $rec = New-FakeRecord; $s = New-CountingSend; $cl = New-CloseLoopSql
        $newInv = { param($a, $b) $cl }.GetNewClosure()
        (Invoke-SICloseLoopMailCore -Globals $g -NewInvoke $newInv -Send $s.Send -Now ([datetime]::SpecifyKind([datetime]'2026-11-14T00:05:00', 'Utc')) -Log $script:Quiet -SendRecord @{ Invoke = $rec.Invoke; Problem = '' }).Sent | Should -BeTrue
        $rec.Rows.ContainsKey('close-loop-daily|2026-11-13') | Should -BeTrue
        (Invoke-SICloseLoopMailCore -Globals $g -NewInvoke $newInv -Send $s.Send -Now ([datetime]::SpecifyKind([datetime]'2026-11-14T23:50:00', 'Utc')) -Log $script:Quiet -SendRecord @{ Invoke = $rec.Invoke; Problem = '' }).Sent | Should -BeTrue
        $rec.Rows.ContainsKey('close-loop-daily|2026-11-14') | Should -BeTrue
        $s.Count | Should -Be 2
        $job = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\asset-cmdb\_shared\SI-CloseLoopMail.ps1'))
        $job | Should -Match ([regex]::Escape("`$day = Get-SICloseLoopMailSlotDay -Now `$until -SendTimeUtc ([string]`$Globals['Mail_CloseLoop_Daily_SendTimeUtc'])"))
    }
    It 'a database WITHOUT the table (before the update) sends as before, saying so; no record given = as before, silent' {
        $s = New-CountingSend
        $lines = New-Object System.Collections.Generic.List[string]
        $log = { param($l, $m) $lines.Add($m) }.GetNewClosure()
        (Invoke-CloseLoop -Record (New-FakeRecord -NoTable) -Send $s.Send -Log $log).Sent | Should -BeTrue
        (Invoke-CloseLoop -Record (New-FakeRecord -NoTable) -Send $s.Send).Sent | Should -BeTrue
        $s.Count | Should -Be 2
        @($lines | Where-Object { $_ -match 'does not keep a send record yet .* sent as before' }).Count | Should -Be 1
        $cl = New-CloseLoopSql
        (Invoke-SICloseLoopMailCore -Globals $script:ClGlobals -NewInvoke { param($a, $b) $cl }.GetNewClosure() -Send $s.Send -Now $script:Now -Log $script:Quiet).Sent | Should -BeTrue
    }
    It 'the job passes the record of the data backend; a database that cannot be opened is a Problem, not a skip' {
        $job = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\asset-cmdb\Invoke-SICloseLoopMail.ps1'))
        $job | Should -Match '-SendRecord \$clRecord'
        $job | Should -Match '\$rdb = Get-SIMailSendRecordDatabase -Globals \$globalsNow'
        $job | Should -Match "\`$clRecord\.Problem = \('its database could not be opened: '"
    }
}

Describe 'THE RISK ANALYSIS MAIL: at most one per pipeline run (or collection)' {
    BeforeAll {
        function script:New-Settings([string]$FlowRunId, [switch]$Broken) {
            $o = [pscustomobject]@{ FlowRunId = $FlowRunId; Broken = [bool]$Broken }
            $o | Add-Member -NotePropertyName Invoke -NotePropertyValue ({
                param($Sql, $P, $Mode)
                if ($o.Broken) { throw 'Lock request time out period exceeded' }
                if (-not $o.FlowRunId) { return , @() }
                , @([pscustomobject]@{ FlowRunId = $o.FlowRunId; StepOrder = 9; Mine = 1 }, [pscustomobject]@{ FlowRunId = $o.FlowRunId; StepOrder = 2; Mine = 0 })
            }.GetNewClosure()) -Force
            $o
        }
        function script:Open-Ra($Rec, $Settings, [int]$CollectionId = 41, [string]$Grain = 'Detailed', [bool]$Wanted = $true, [switch]$NoStream, $Log = $script:Quiet) {
            $stream = $(if ($NoStream) { $null } else { [pscustomobject]@{ Invoke = $Rec.Invoke; Grain = $Grain; CollectionId = $CollectionId } })
            Open-SIRaMailSendRecord -Stream $stream -StreamWanted $Wanted -SettingsStore $Settings -Log $Log
        }
    }
    It 'a second run of the step in the SAME pipeline run sends nothing -- even with a new collection of its own' {
        $rec = New-FakeRecord; $set = New-Settings 'fr-20261113'
        $a = Open-Ra $rec $set -CollectionId 41
        $a.Send | Should -BeTrue; $a.Claimed | Should -BeTrue; $a.Key | Should -Be 'ra-detailed|run:fr-20261113'
        Exit-SIMailSendRecord -Invoke $a.Invoke -Key $a.Key -By $a.By -As sent -Log $script:Quiet | Should -BeTrue
        $lines = New-Object System.Collections.Generic.List[string]
        $b = Open-Ra $rec $set -CollectionId 42 -Log ({ param($l, $m) $lines.Add($m) }.GetNewClosure())
        $b.Send | Should -BeFalse
        $lines[0] | Should -Match '^mail: the Risk Analysis mail of this run was already sent at .* -- it is not sent again$'
        # the Summary step of the same pipeline run mails on its own record; the next pipeline run mails again
        (Open-Ra $rec $set -Grain 'Summary').Send | Should -BeTrue
        (Open-Ra $rec (New-Settings 'fr-20261114')).Send | Should -BeTrue
    }
    It 'a run while the first one is still sending sends nothing; a failed send is sent by the next run of the step' {
        $rec = New-FakeRecord; $set = New-Settings 'fr-1'
        $a = Open-Ra $rec $set
        (Open-Ra $rec $set).Send | Should -BeFalse -Because 'the first run holds the claim'
        $null = Exit-SIMailSendRecord -Invoke $a.Invoke -Key $a.Key -By $a.By -As waiting -Reason '451' -Log $script:Quiet
        (Open-Ra $rec $set).Send | Should -BeTrue
    }
    It 'a mail KEPT for the data sync: a second run neither keeps nor sends one, and leaves the first one to the data sync' {
        $rec = New-FakeRecord; $set = New-Settings 'fr-2'
        $a = Open-Ra $rec $set
        $null = Exit-SIMailSendRecord -Invoke $a.Invoke -Key $a.Key -By $a.By -As queued -OutboxMailId 5 -Log $script:Quiet
        $b = Open-Ra $rec $set -CollectionId 42
        $b.Send | Should -BeFalse
        [long]$b.OutboxMailId | Should -Be 5
        $b.Line | Should -Match 'already kept for the data sync'
        # the producer's sweep holds that mail (it would otherwise be sent now, early, without its score)
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-RaMailOutbox.ps1')
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        . (Join-Path $script:Root 'engine\_shared\SI-ProtectionScore.ps1')
        $claims = New-Object System.Collections.Generic.List[string]
        $ob = { param($Sql, $P, $Mode)
            if ($Sql -match 'FROM sidata\.RaMailOutbox o LEFT JOIN') { return , @([pscustomobject]@{ MailId = 5; CollectionId = 41; CollectionTime = [datetime]'2026-11-13T05:00:00'; CreatedAt = [datetime]'2026-11-13T05:30:00'; State = 'waiting'; CollectionStatus = 'Complete'; Figured = 0 }) }
            $claims.Add($Sql); , @() }.GetNewClosure()
        $r = Invoke-SIRaMailOutbox -Invoke $ob -Role producer -Send { param($x) throw 'must not send' } -OwnCollectionId 42 -Log $script:Quiet -HoldMailIds @($b.OutboxMailId)
        $r.Waiting | Should -Be 1; $r.Sent | Should -Be 0
        $claims.Count | Should -Be 0
    }
    It 'outside the pipeline the collection is the key; no database at all = as before; FAIL OPEN when the record cannot be checked' {
        $rec = New-FakeRecord
        (Open-Ra $rec $null -CollectionId 77).Key | Should -Be 'ra-detailed|collection:77'
        (Open-Ra $rec (New-Settings '') -CollectionId 77).Send | Should -BeFalse -Because 'the same collection was already claimed (a definite answer)'
        # no database for this run at all: nothing to record in -- sent as before
        $n = Open-Ra $rec $null -NoStream -Wanted $false
        $n.Send | Should -BeTrue; $n.Claimed | Should -BeFalse
        # owner rule: a lost mail is worse than a rare duplicate. A database that could not be reached, a pipeline run that
        # could not be read (its lock timeout too), a record that cannot be read: SENT as before, with ONE line each
        $cases = @(
            @{ Name = 'stream not opened'; Open = { Open-Ra $rec $null -NoStream -Wanted $true -Log $args[0] }; Why = "this run's database could not be reached" }
            @{ Name = 'pipeline run unreadable'; Open = { Open-Ra $rec (New-Settings 'x' -Broken) -Log $args[0] }; Why = "this run's pipeline run could not be read: Lock request time out period exceeded" }
            @{ Name = 'claim unreadable'; Open = { Open-Ra (New-FakeRecord -Broken) (New-Settings 'fr-3') -Log $args[0] }; Why = 'SQL 40613: the database is not available' }
        )
        foreach ($c in $cases) {
            $lines = New-Object System.Collections.Generic.List[string]
            $log = { param($l, $m) $lines.Add("[$l] $m") }.GetNewClosure()
            $o = & $c.Open $log
            $o.Send | Should -BeTrue -Because $c.Name
            $o.Claimed | Should -BeFalse -Because $c.Name
            @($lines).Count | Should -Be 1 -Because $c.Name
            $lines[0] | Should -Be ('[WARN] mail: the Risk Analysis mail of this run: its send record could not be checked ({0}) -- it is sent as before, so a duplicate is possible' -f $c.Why) -Because $c.Name
        }
        # the run's own guard: an unexpected failure opening the record also sends, saying so
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape('$__mailRec = [pscustomobject]@{ Send = $true; Claimed = $false; OutboxMailId = $null }'))
        # before the update (no table): sent as before
        $t = Open-Ra (New-FakeRecord -NoTable) (New-Settings 'fr-3')
        $t.Send | Should -BeTrue; $t.Claimed | Should -BeFalse
    }
    It 'a sent mail whose record cannot be written is noted "sent, not marked" -- never sent again' {
        $rec = New-FakeRecord; $set = New-Settings 'fr-4'
        $a = Open-Ra $rec $set
        $flaky = { param($Sql, $P, $Mode) if ($Sql -match "State = N'sent'") { throw 'transport-level error' }; & $rec.Invoke $Sql $P $Mode }.GetNewClosure()
        Exit-SIMailSendRecord -Invoke $flaky -Key $a.Key -By $a.By -As sent -Log $script:Quiet -RetrySeconds 0 | Should -BeFalse
        $rec.Rows[$a.Key].LastError | Should -Match '^sent, not marked: transport-level error'
        (Get-SIMailSendRecordClaimSql) | Should -Match "NOT LIKE N''sent, not marked%''"
    }
    It 'WIRING: the run opens its record before the mail, holds the kept mail, records kept / sent / not sent' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra.IndexOf('$__mailRec = Open-SIRaMailSendRecord') | Should -BeGreaterThan 0
        $ra.IndexOf('$__mailRec = Open-SIRaMailSendRecord') | Should -BeLessThan $ra.IndexOf('if (-not $__mailRec.Send) { $__sendNow = $false }')
        $ra | Should -Match '-HoldMailIds @\(\$__mailRec\.OutboxMailId\)'
        $ra | Should -Match "if \(-not \`$__sendNow\) \{ throw \[System\.OperationCanceledException\]::new\('send-record'\) \}"
        $ra.IndexOf('-As queued -OutboxMailId $__mid') | Should -BeGreaterThan $ra.IndexOf('$__mid = Add-SIRaMailOutbox')
        $ra.IndexOf("-As `$(if (`$__mailRes.Sent) { 'sent' } else { 'waiting' })") | Should -BeGreaterThan $ra.IndexOf('$__mailRes = Send-SIMail')
    }
}

Describe 'THE MAIL QUEUES: a claim before every send' -Skip:(-not $script:ProMail) {
    BeforeAll {
        # a fake queue (cfg.SignInMail and cfg.ReportMail empty): the claim answers per row from -Claim (1 | 0 | -1 | 'throw')
        function script:New-Queue([object[]]$Rows, [hashtable]$Claim = @{}) {
            $w = [pscustomobject]@{ Rows = $Rows; Claim = $Claim; Claims = (New-Object System.Collections.Generic.List[string]); Released = (New-Object System.Collections.Generic.List[string]) }
            $w | Add-Member -NotePropertyName Invoke -NotePropertyValue ({
                param([string]$sql, $p, [string]$mode)
                if ($sql -match 'AS Ready') { return , @(@{ Ready = 1 }) }
                if ($sql -match 'SET ClaimedAt = SYSUTCDATETIME\(\)') {
                    $w.Claims.Add([string]$p.ClaimMailId); $a = $w.Claim[[string]$p.ClaimMailId]
                    if ($a -eq 'throw') { throw 'deadlock victim' }
                    if ($null -eq $a) { return 1 }; return $a
                }
                if ($sql -match 'SET ClaimedAt = NULL, ClaimedBy = NULL') { $w.Released.Add([string]$p.ClaimMailId); return }
                if ($sql -match 'FROM cfg\.Setting') { return , @() }
                if ($sql -match 'FROM cfg\.ExemptionMail WHERE SentAt IS NULL AND Attempts') { return , @($w.Rows | Where-Object { -not $_.Sent }) }
                if ($sql -match 'FROM cfg\.(SignInMail|ReportMail)') { return , @() }
                if ($sql -match '^UPDATE cfg\.ExemptionMail SET SentAt') { foreach ($r in $w.Rows) { if ([string]$r.MailId -eq [string]$p.MailId) { $r.Sent = $true; $r.Attempts++ } }; return }
                if ($sql -match '^UPDATE cfg\.ExemptionMail SET Attempts') { foreach ($r in $w.Rows) { if ([string]$r.MailId -eq [string]$p.MailId) { $r.Attempts++; $r.LastError = $p.Error } }; return }
                if ($sql -match '^UPDATE cfg\.ExemptionMail SET LastError') { foreach ($r in $w.Rows) { if ([string]$r.MailId -eq [string]$p.MailId) { $r.LastError = $p.Error } }; return }
                throw "unexpected SQL: $sql"
            }.GetNewClosure()) -Force
            $w
        }
        function script:Row([int]$Id) { @{ MailId = $Id; Kind = 'decision'; ToList = 'req@example.invalid'; Subject = "mail $Id"; BodyHtml = '<p>x</p>'; Sent = $false; Attempts = 0; LastError = $null } }
        $script:G = @{ SI_ProSqlServer = 'sql.example.invalid'; SI_ProSqlDatabase = 'sipro' }
        function script:Run-Queue($q, $Send) { Invoke-SIExemptionMailCore -Globals $script:G -NewInvoke { param($s, $d) $q.Invoke }.GetNewClosure() -Send $Send -Now $script:Now -OutboxOnly -Log $script:Quiet }
    }
    It 'every row is claimed before it is sent; a row another sender holds is left to it' {
        $q = New-Queue -Rows @((Row 1), (Row 2)) -Claim @{ '2' = 0 }
        $sent = New-Object System.Collections.Generic.List[string]
        $r = Run-Queue $q ({ param($to, $s, $h) $sent.Add($s) }.GetNewClosure())
        $r.Sent | Should -Be 1; $r.Failed | Should -Be 0
        @($sent) | Should -Be @('mail 1')
        @($q.Claims) | Should -Be @('1', '2')
    }
    It 'a claim that cannot be made -> the row is not sent this time (never twice), uses no try, and is counted as waiting' {
        $q = New-Queue -Rows @((Row 3)) -Claim @{ '3' = 'throw' }
        $r = Run-Queue $q { param($to, $s, $h) throw 'must not send' }
        $r.Sent | Should -Be 0; $r.Failed | Should -Be 0; $r.Waiting | Should -Be 1
        $q.Rows[0].Attempts | Should -Be 0
    }
    It 'a failed send counts a try and RELEASES the row for the next run; a HOLD keeps its tries and is released too' {
        $q = New-Queue -Rows @((Row 4))
        $r = Run-Queue $q { param($to, $s, $h) throw '451 try again later' }
        $r.Failed | Should -Be 1
        $q.Rows[0].Attempts | Should -Be 1
        @($q.Released) | Should -Be @('4')
        $q2 = New-Queue -Rows @((Row 5))
        $hold = { param($to, $s, $h) throw 'the close-loop mail was not sent: the send right on the shared mailbox could not be checked, so SecurityInsight does not send this time' }
        $null = Run-Queue $q2 $hold
        $q2.Rows[0].Attempts | Should -Be 0 -Because '3.1.16: a hold keeps its tries'
        $q2.Rows[0].LastError | Should -Match 'could not be checked'
        @($q2.Released) | Should -Be @('5')
        # the next run sends it
        $sent = New-Object System.Collections.Generic.List[string]
        (Run-Queue $q2 ({ param($to, $s, $h) $sent.Add($s) }.GetNewClosure())).Sent | Should -Be 1
    }
    It 'a queue without the claim columns (before the update) sends as before' {
        $q = New-Queue -Rows @((Row 6)) -Claim @{ '6' = -1 }
        $sent = New-Object System.Collections.Generic.List[string]
        (Run-Queue $q ({ param($to, $s, $h) $sent.Add($s) }.GetNewClosure())).Sent | Should -Be 1
        $sent.Count | Should -Be 1
    }
    It 'a mail the server accepted but that could not be marked sent is not released (it would go twice)' {
        $q = New-Queue -Rows @((Row 8))
        $inner = $q.Invoke
        $q | Add-Member -NotePropertyName Invoke -NotePropertyValue ({ param($sql, $p, $mode) if ($sql -match '^UPDATE cfg\.ExemptionMail SET SentAt') { throw 'transport-level error' }; & $inner $sql $p $mode }.GetNewClosure()) -Force
        $r = Run-Queue $q { param($to, $s, $h) }
        $r.Sent | Should -Be 1; $r.Failed | Should -Be 0
        $q.Released.Count | Should -Be 0
        # ... and it is NOTED, so that no later claim (the lease neither) takes it again
        $q.Rows[0].LastError | Should -Be 'transport-level error' -Because 'the note statement carries the reason (the fake stores the parameter)'
        (Get-SIMailQueueSentNotMarkedSql -Table 'cfg.ExemptionMail') | Should -Match "^UPDATE cfg\.ExemptionMail SET LastError = LEFT\(N'sent, not marked: '"
        (Get-SIMailQueueSentNotMarkedSql -Table 'cfg.SignInMail') | Should -Match "BodyHtml = N'\(removed once sent: it carried a one-time sign-in secret\)'" -Because 'a noted sign-in mail never goes again: its secret is not kept'
        foreach ($t in 'ExemptionMail', 'SignInMail', 'ReportMail', 'GovernanceMail') { (Get-SIMailQueueClaimSql -Table "cfg.$t") | Should -Match "NOT LIKE N''sent, not marked%''" }
    }
    It 'a row noted "sent, not marked" is never claimed again: it is not sent, it is marked sent now, one line' {
        $q = New-Queue -Rows @((Row 9)) -Claim @{ '9' = -2 }
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIExemptionMailCore -Globals $script:G -NewInvoke { param($s, $d) $q.Invoke }.GetNewClosure() -Send { param($to, $s, $h) throw 'must not send' } -Now $script:Now -OutboxOnly -Log ({ param($l, $m) $lines.Add($m) }.GetNewClosure())
        $r.Sent | Should -Be 0; $r.Failed | Should -Be 0
        $q.Rows[0].Sent | Should -BeTrue -Because 'the row is marked sent now'
        @($lines | Where-Object { $_ -eq 'exemption mail 9 was already sent (the server accepted it) but could not be marked sent then -- it is not sent again; it is marked sent now' }).Count | Should -Be 1 -Because ($lines -join ' | ')
        (Request-SIMailQueueClaim -Invoke { param($a, $b, $c) -2 } -Table 'cfg.SignInMail' -MailId 1 -By 'x').Outcome | Should -Be 'sent-unmarked'
    }
    It 'WIRING: the governance outbox claims and releases the same way' {
        $gov = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-GovernanceMail.ps1'))
        $gov | Should -Match "Request-SIMailQueueClaim -Invoke \`$invoke -Table 'cfg\.GovernanceMail' -MailId \`$id -By \`$claimBy"
        $gov | Should -Match "Undo-SIMailQueueClaim -Invoke \`$invoke -Table 'cfg\.GovernanceMail' -MailId \`$id -By \`$claimBy"
        # #1338 (e13824d86): the sender's answer is kept ($false = mail off, NOT sent), so the send line reads 'try { $answer = & $Send';
        # the claim comes before it, mail off leaves the row before any claim, and a "not sent" answer gives the claim back
        $iClaim = $gov.IndexOf("Request-SIMailQueueClaim -Invoke `$invoke -Table 'cfg.GovernanceMail'")
        $iSend = $gov.IndexOf('try { $answer = & $Send $to $subject')
        $iOff = $gov.IndexOf('if ($MailOff) { $res.OutboxWaiting++; continue }')
        $iSend | Should -BeGreaterThan 0
        $iOff | Should -BeGreaterThan 0
        $iClaim | Should -BeLessThan $iSend
        $iOff | Should -BeLessThan $iClaim -Because 'mail off: nothing is claimed, sent or marked -- the row stays queued'
        $gov | Should -Match ([regex]::Escape("if (& `$notSent `$answer) { `$null = Undo-SIMailQueueClaim -Invoke `$invoke -Table 'cfg.GovernanceMail' -MailId `$id -By `$claimBy; `$res.OutboxWaiting++; continue }"))
    }
}

Describe 'REAL SQL: the send record and the queue claim on the tests'' SQL Server' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_mailonce_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:Cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$($script:Db);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "CREATE DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        function script:Exec([string]$Sql) {
            $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
            try { $c = $cn.CreateCommand(); $c.CommandTimeout = 120; $c.CommandText = $Sql; [void]$c.ExecuteNonQuery() } finally { $cn.Dispose() }
        }
        # the engine's seam: (sql, params, mode); every parameter as text, as the engine passes them
        $cs = $script:Cs
        $script:Seam = {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection $cs; $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 120; $c.CommandText = $sql
                if ($p) { foreach ($k in @($p.Keys)) { $v = $p[$k]; if ($null -eq $v) { $v = [DBNull]::Value }; [void]$c.Parameters.AddWithValue('@' + $k, $v) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { [void]$c.ExecuteNonQuery(); return }
                $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
                , $out.ToArray()
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        $script:DataSchema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))
        $script:ProSchema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        Exec 'CREATE SCHEMA sidata;'
        Exec 'CREATE SCHEMA cfg;'
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { }
    }
    It 'before the update: no table -> "no-table" (sent as before); the shipped statement makes it, a second time changes nothing' {
        (Request-SIMailSendRecord -Invoke $script:Seam -Key 'ra-detailed|run:a' -Kind 'ra-detailed' -By 'x').Outcome | Should -Be 'no-table'
        $block = [regex]::Match($script:DataSchema, "(?s)IF OBJECT_ID\('sidata\.MailSendRecord'\) IS NULL\s+CREATE TABLE sidata\.MailSendRecord \(.*?\n\);").Value
        $block | Should -Not -BeNullOrEmpty
        Exec $block; Exec $block
        (Request-SIMailSendRecord -Invoke $script:Seam -Key 'ra-detailed|run:a' -Kind 'ra-detailed' -By 'x').Outcome | Should -Be 'claimed'
    }
    It 'two runs -> one claimant; the claimant''s own retried statement stays its own; sent -> never again' {
        $k = 'close-loop-daily|2026-11-13'
        (Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'close-loop-daily' -By 'run-1').Outcome | Should -Be 'claimed'
        (Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'close-loop-daily' -By 'run-1').Outcome | Should -Be 'claimed'
        (Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'close-loop-daily' -By 'run-2').Outcome | Should -Be 'taken'
        Exit-SIMailSendRecord -Invoke $script:Seam -Key $k -By 'run-1' -As sent -Log $script:Quiet | Should -BeTrue
        $c = Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'close-loop-daily' -By 'run-3'
        $c.Outcome | Should -Be 'taken'; $c.State | Should -Be 'sent'; $c.SentAt | Should -BeOfType [datetime]
    }
    It 'EIGHT claims at once -> exactly one claimant' {
        $sql = Get-SIMailSendRecordClaimSql; $cs = $script:Cs
        $outs = 1..8 | ForEach-Object -ThrottleLimit 8 -Parallel {
            $cn = New-Object System.Data.SqlClient.SqlConnection $using:cs; $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandText = $using:sql; $c.CommandTimeout = 120
                foreach ($kv in @(@('MailKey', 'ra-detailed|run:parallel'), @('Kind', 'ra-detailed'), @('By', "run-$_"), @('LeaseMinutes', '60'))) { [void]$c.Parameters.AddWithValue('@' + $kv[0], $kv[1]) }
                $rd = $c.ExecuteReader(); try { if ($rd.Read()) { [string]$rd['Outcome'] } } finally { $rd.Close() }
            } catch { 'error: ' + $_.Exception.Message } finally { $cn.Dispose() }
        }
        @($outs | Where-Object { $_ -eq 'claimed' }).Count | Should -Be 1
        @($outs | Where-Object { $_ -eq 'taken' }).Count | Should -Be 7 -Because ('every other claimant is told it is taken: ' + (@($outs) -join '; '))
    }
    It 'a failed send -> back to waiting -> the next run claims it; a HOLD gives the try back; kept for the data sync -> never again' {
        $k = 'ra-detailed|run:fail'
        $null = Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'ra-detailed' -By 'r1'
        $null = Exit-SIMailSendRecord -Invoke $script:Seam -Key $k -By 'r1' -As waiting -Reason '451' -Log $script:Quiet
        $c = Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'ra-detailed' -By 'r2'
        $c.Outcome | Should -Be 'claimed'
        $null = Exit-SIMailSendRecord -Invoke $script:Seam -Key $k -By 'r2' -As waiting -Reason 'held' -Held -Log $script:Quiet
        [int](& $script:Seam "SELECT Attempts FROM sidata.MailSendRecord WHERE MailKey = N'$k'" @{} 'scalar') | Should -Be 1 -Because 'two claims, one of them a hold'
        $null = Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'ra-detailed' -By 'r3'
        $null = Exit-SIMailSendRecord -Invoke $script:Seam -Key $k -By 'r3' -As queued -OutboxMailId 77 -Log $script:Quiet
        $t = Request-SIMailSendRecord -Invoke $script:Seam -Key $k -Kind 'ra-detailed' -By 'r4'
        $t.Outcome | Should -Be 'taken'; $t.State | Should -Be 'queued'; [long]$t.OutboxMailId | Should -Be 77
    }
    It 'a claim whose claimant died is taken after the lease -- but never one the server accepted ("sent, not marked")' {
        $null = Request-SIMailSendRecord -Invoke $script:Seam -Key 'k|died' -Kind 'ra-detailed' -By 'dead'
        $null = Request-SIMailSendRecord -Invoke $script:Seam -Key 'k|unmarked' -Kind 'ra-detailed' -By 'dead'
        & $script:Seam (Get-SIMailSendRecordDoneSql -As unmarked) @{ MailKey = 'k|unmarked'; By = 'dead'; Error = 'x'; OutboxMailId = '0' } 'scalar' | Out-Null
        Exec "UPDATE sidata.MailSendRecord SET ClaimedAt = DATEADD(hour, -3, SYSUTCDATETIME()) WHERE MailKey IN (N'k|died', N'k|unmarked');"
        (Request-SIMailSendRecord -Invoke $script:Seam -Key 'k|died' -Kind 'ra-detailed' -By 'alive' -LeaseMinutes 60).Outcome | Should -Be 'claimed'
        (Request-SIMailSendRecord -Invoke $script:Seam -Key 'k|unmarked' -Kind 'ra-detailed' -By 'alive' -LeaseMinutes 60).Outcome | Should -Be 'taken'
    }
    It 'THE QUEUE: before the update (no columns) as before; the shipped ALTERs add them; eight claims at once -> one sender; a release frees it' {
        $create = [regex]::Match($script:ProSchema, "(?s)IF OBJECT_ID\('cfg\.ExemptionMail'\) IS NULL\s+CREATE TABLE cfg\.ExemptionMail \(.*?\r?\n\);").Value
        $create | Should -Not -BeNullOrEmpty
        Exec $create
        Exec "INSERT cfg.ExemptionMail (Kind, ToList, Subject, BodyHtml, QueuedBy) VALUES (N'decision', N'req@example.invalid', N's', N'<p/>', N'test');"
        $id = [string](& $script:Seam 'SELECT MAX(MailId) FROM cfg.ExemptionMail' @{} 'scalar')
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By 'old').Outcome | Should -Be 'as-before'
        foreach ($col in 'ClaimedAt', 'ClaimedBy') {
            $alter = [regex]::Match($script:ProSchema, ("IF COL_LENGTH\('cfg\.ExemptionMail', '{0}'\) IS NULL\s+ALTER TABLE cfg\.ExemptionMail ADD {0} [^;]+;" -f $col)).Value
            $alter | Should -Not -BeNullOrEmpty
            Exec $alter; Exec $alter
        }
        $sql = Get-SIMailQueueClaimSql -Table 'cfg.ExemptionMail'; $cs = $script:Cs
        $outs = 1..8 | ForEach-Object -ThrottleLimit 8 -Parallel {
            $cn = New-Object System.Data.SqlClient.SqlConnection $using:cs; $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandText = $using:sql; $c.CommandTimeout = 120
                [void]$c.Parameters.AddWithValue('@ClaimMailId', [string]$using:id); [void]$c.Parameters.AddWithValue('@ClaimBy', "sender-$_"); [void]$c.Parameters.AddWithValue('@ClaimLease', '60')
                [string]$c.ExecuteScalar()
            } catch { 'error: ' + $_.Exception.Message } finally { $cn.Dispose() }
        }
        @($outs | Where-Object { $_ -eq '1' }).Count | Should -Be 1 -Because (@($outs) -join '; ')
        @($outs | Where-Object { $_ -eq '0' }).Count | Should -Be 7
        $holder = [string](& $script:Seam "SELECT ClaimedBy FROM cfg.ExemptionMail WHERE MailId = $id" @{} 'scalar')
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By 'late').Outcome | Should -Be 'taken'
        Undo-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By 'not-the-holder' | Should -BeTrue
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By 'late').Outcome | Should -Be 'taken' -Because 'only the holder releases'
        $null = Undo-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By $holder
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By 'next-run').Outcome | Should -Be 'claimed'
        Exec "UPDATE cfg.ExemptionMail SET SentAt = SYSUTCDATETIME() WHERE MailId = $id;"
        Exec "UPDATE cfg.ExemptionMail SET ClaimedAt = DATEADD(hour, -3, SYSUTCDATETIME()) WHERE MailId = $id;"
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $id -By 'after-lease').Outcome | Should -Be 'taken' -Because 'a sent row is never claimed again'
    }
    It 'THE QUEUE: accepted but not marked -> noted; after the lease it is NOT claimed again (a dead claim without the note still is)' {
        # (the table and its claim columns come from the test above)
        Exec "INSERT cfg.ExemptionMail (Kind, ToList, Subject, BodyHtml, QueuedBy) VALUES (N'decision', N'req@example.invalid', N'noted', N'<p/>', N'test'), (N'decision', N'req@example.invalid', N'died', N'<p/>', N'test');"
        $noted = [string](& $script:Seam "SELECT MailId FROM cfg.ExemptionMail WHERE Subject = N'noted'" @{} 'scalar')
        $died = [string](& $script:Seam "SELECT MailId FROM cfg.ExemptionMail WHERE Subject = N'died'" @{} 'scalar')
        foreach ($m in $noted, $died) { (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $m -By 'dead').Outcome | Should -Be 'claimed' }
        # the server accepted 'noted', then the database went away for the mark -- the note goes in
        Set-SIMailQueueSentNotMarked -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $noted -Why 'transport-level error' -Label 'exemption mail' -Log $script:Quiet | Should -BeTrue
        [string](& $script:Seam "SELECT LastError FROM cfg.ExemptionMail WHERE MailId = $noted" @{} 'scalar') | Should -Be 'sent, not marked: transport-level error'
        Exec "UPDATE cfg.ExemptionMail SET ClaimedAt = DATEADD(hour, -3, SYSUTCDATETIME()) WHERE MailId IN ($noted, $died);"
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $noted -By 'after-lease').Outcome | Should -Be 'sent-unmarked' -Because 'its one copy went: the lease never resends it'
        (Request-SIMailQueueClaim -Invoke $script:Seam -Table 'cfg.ExemptionMail' -MailId $died -By 'after-lease').Outcome | Should -Be 'claimed' -Because 'a claimant that died before the server accepted anything is taken over (a lost mail is worse)'
        [string](& $script:Seam "SELECT ClaimedBy FROM cfg.ExemptionMail WHERE MailId = $noted" @{} 'scalar') | Should -Be 'dead' -Because 'the noted row was not touched'
    }
}
