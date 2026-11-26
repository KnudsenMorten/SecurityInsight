#Requires -Version 5.1
<#
    #1021 -- THE SUPPORT GRANT JOB caj-si-support-grant, offline (engine\support-grant\SI-SupportGrant.ps1):
      * the request is a REQUEST: only the six agreed keys, raw JSON, every value checked (action, level, maxUntil within
        8 h and in the future, reason 1-200, ticket / name lengths, no control characters); refused = bad-request (exit 4);
      * the newest message not older than 15 minutes is the request; every message read is deleted;
      * the ONE log line Invardia reads, exactly; exit 0 ok / 2 could not / 3 no consent / 4 bad request;
      * the job (fake databases): the sweep FIRST; open on the Pro database first, then the others; one that fails ROLLS
        BACK the ones already opened; the granted level comes from the read-back, not the request; close on every database;
      * a value of the request only ever travels as a SQL PARAMETER (never in the statement text);
      * the procedure's error numbers map to the result words.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\support-grant\SI-SupportGrant.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-01T10:00:00', 'Utc')
    $script:Iso = { param([int]$Minutes) $script:Now.AddMinutes($Minutes).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $script:Msg = {
        param([hashtable]$Over = @{}, [string[]]$Drop = @())
        $m = [ordered]@{ SI_SUPPORT_ACTION = 'open'; SI_SUPPORT_LEVEL = 'setup'; SI_SUPPORT_MAXUNTIL = (& $script:Iso 120); SI_SUPPORT_REASON = 'ticket 42: the pipeline stops'; SI_SUPPORT_TICKET = 'SUP-2026-00042'; SI_AUDIT_STARTED_BY = 'agent@invardia' }
        foreach ($k in $Over.Keys) { $m[$k] = $Over[$k] }
        foreach ($k in $Drop) { $m.Remove($k) }
        $m | ConvertTo-Json -Compress
    }
    # a fake product database: answers the four procedures from a script, records every call (sql + parameters)
    $script:NewDb = {
        param([string]$Name, [hashtable]$Answers)
        $state = @{ Calls = [System.Collections.Generic.List[object]]::new(); Answers = $Answers; Name = $Name }
        $seam = {
            param($Sql, $Params, $Mode)
            $p = @{}; if ($Params) { foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] } }
            $state.Calls.Add([pscustomobject]@{ Sql = [string]$Sql; Params = $p })
            $kind = if ($Sql -match 'SupportGrantOpen') { 'Open' } elseif ($Sql -match 'SupportGrantClose') { 'Close' } elseif ($Sql -match 'SupportGrantSweep') { 'Sweep' } elseif ($Sql -match 'SupportJitMarker WHERE ClosedUtc IS NULL') { 'OpenGrants' } else { 'Status' }
            $a = $state.Answers[$kind]
            if ($a -is [scriptblock]) { $a = & $a $p }
            if ($a -is [string] -and $a -like 'THROW*') { throw ($a.Substring(6)) }
            , @($a)
        }.GetNewClosure()
        [pscustomobject]@{ Seam = $seam; State = $state }
    }
    $script:OkOpen = { param($p) @{ Database = 'x'; LevelGranted = $(if ($p.Level -eq 'setup') { 'setup' } else { 'troubleshoot' }); RoleName = 'db_owner'; UntilUtc = $p.MaxUntilUtc; RoleHeld = 1; ReadOnlyHeld = 1 } }
    $script:OkClose = @{ Database = 'x'; Closed = 1; RolesRemoved = 1; SessionsEnded = 0; StillOpen = 0; RolesStillHeld = 0; UserPresent = 1; ReadOnlyHeld = 1 }
    $script:OkSweep = @{ Database = 'x'; Closed = 0; RolesRemoved = 0; UserPresent = 1; ReadOnlyHeld = 1 }
    $script:Run = {
        param($Dbs, [object[]]$Messages)
        $removed = New-Object System.Collections.Generic.List[string]; $said = New-Object System.Collections.Generic.List[string]; $events = [System.Collections.Generic.List[object]]::new()
        $map = [ordered]@{}; foreach ($d in $Dbs) { $map[$d.State.Name] = $d.Seam }
        $r = Invoke-SISupportGrantJob -Databases $map -Receive { foreach ($m in @($Messages)) { $m } }.GetNewClosure() -Remove { param($m) $removed.Add([string]$m.Id) }.GetNewClosure() -NowUtc $script:Now `
                -Say { param($l, $t) $said.Add("[$l] $t") }.GetNewClosure() -Report { param($e) $events.Add($e) }.GetNewClosure()
        [pscustomobject]@{ R = $r; Removed = $removed.ToArray(); Said = $said.ToArray(); Events = $events.ToArray() }
    }
    $script:M = { param([string]$Text, [int]$AgeMinutes = 1, [string]$Id = ([guid]::NewGuid().ToString())) [pscustomobject]@{ Id = $Id; PopReceipt = 'pr'; Inserted = $script:Now.AddMinutes(-$AgeMinutes); Text = $Text } }
}

Describe 'the request is a REQUEST: every value checked, nothing in it ever run' {
    It 'a full, valid open request is read' {
        $r = ConvertFrom-SISupportGrantMessage -Text (& $script:Msg) -NowUtc $script:Now
        $r.Ok | Should -BeTrue; $r.Action | Should -Be 'open'; $r.Level | Should -Be 'setup'; $r.Ticket | Should -Be 'SUP-2026-00042'
        $r.MaxUntilUtc | Should -Be $script:Now.AddMinutes(120)
    }
    It 'a close carries a valid level and maxUntil too (agreed with Invardia)' {
        (ConvertFrom-SISupportGrantMessage -Text (& $script:Msg @{ SI_SUPPORT_ACTION = 'close' }) -NowUtc $script:Now).Ok | Should -BeTrue
        (ConvertFrom-SISupportGrantMessage -Text (& $script:Msg @{ SI_SUPPORT_ACTION = 'close' } -Drop 'SI_SUPPORT_LEVEL') -NowUtc $script:Now).Ok | Should -BeFalse
    }
    It 'refused: <Case>' -ForEach @(
        @{ Case = 'an unknown key';            Over = @{ SI_SUPPORT_PRINCIPAL = 'x' }; Drop = @() }
        @{ Case = 'an action not in the list'; Over = @{ SI_SUPPORT_ACTION = 'grant' }; Drop = @() }
        @{ Case = 'a level not in the list';   Over = @{ SI_SUPPORT_LEVEL = 'admin' }; Drop = @() }
        @{ Case = 'maxUntil in the past';      Over = @{ SI_SUPPORT_MAXUNTIL = '2026-11-01T09:59:00Z' }; Drop = @() }
        @{ Case = 'maxUntil over 24 hours';    Over = @{ SI_SUPPORT_MAXUNTIL = '2026-11-02T10:01:00Z' }; Drop = @() }
        @{ Case = 'maxUntil over 8 hours (a support session is at most 8 hours)'; Over = @{ SI_SUPPORT_MAXUNTIL = '2026-11-01T18:03:00Z' }; Drop = @() }
        @{ Case = 'a close with maxUntil over 8 hours'; Over = @{ SI_SUPPORT_ACTION = 'close'; SI_SUPPORT_MAXUNTIL = '2026-11-01T20:00:00Z' }; Drop = @() }
        @{ Case = 'maxUntil without UTC';      Over = @{ SI_SUPPORT_MAXUNTIL = '2026-11-01T12:00:00' }; Drop = @() }
        @{ Case = 'maxUntil not a time';       Over = @{ SI_SUPPORT_MAXUNTIL = 'tomorrow' }; Drop = @() }
        @{ Case = 'no reason';                 Over = @{}; Drop = @('SI_SUPPORT_REASON') }
        @{ Case = 'a reason of 201 characters'; Over = @{ SI_SUPPORT_REASON = ('x' * 201) }; Drop = @() }
        @{ Case = 'a reason with a line break'; Over = @{ SI_SUPPORT_REASON = "a`nb" }; Drop = @() }
        @{ Case = 'a ticket of 65 characters'; Over = @{ SI_SUPPORT_TICKET = ('t' * 65) }; Drop = @() }
        @{ Case = 'a value that is not text';  Over = @{ SI_SUPPORT_LEVEL = 3 }; Drop = @() }
    ) {
        $r = ConvertFrom-SISupportGrantMessage -Text (& $script:Msg $Over $Drop) -NowUtc $script:Now
        $r.Ok | Should -BeFalse; $r.Why | Should -Not -BeNullOrEmpty
    }
    It 'a session of at most 8 hours: exactly 8 h ahead is read (with two minutes for the clocks), 8 h 3 min is refused and says 8 hours' {
        (ConvertFrom-SISupportGrantMessage -Text (& $script:Msg @{ SI_SUPPORT_MAXUNTIL = '2026-11-01T18:00:00Z' }) -NowUtc $script:Now).Ok | Should -BeTrue
        (ConvertFrom-SISupportGrantMessage -Text (& $script:Msg @{ SI_SUPPORT_MAXUNTIL = '2026-11-01T18:02:00Z' }) -NowUtc $script:Now).Ok | Should -BeTrue
        $r = ConvertFrom-SISupportGrantMessage -Text (& $script:Msg @{ SI_SUPPORT_MAXUNTIL = '2026-11-01T18:03:00Z' }) -NowUtc $script:Now
        $r.Ok | Should -BeFalse
        $r.Why | Should -Be 'SI_SUPPORT_MAXUNTIL is more than 8 hours ahead'
        # the job and the open procedure keep the same limit
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-SupportGrantSql.ps1')
        (Get-SISupportGrantContract).MaxHours | Should -Be 8
    }
    It 'refused: base64, not JSON, an array, empty, larger than 4 KB' {
        foreach ($t in @([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((& $script:Msg))), 'not json', '[1,2]', '', ('{"SI_SUPPORT_REASON":"' + ('x' * 5000) + '"}'))) {
            (ConvertFrom-SISupportGrantMessage -Text $t -NowUtc $script:Now).Ok | Should -BeFalse
        }
    }
    It 'the keys are exact (case counts): si_support_action is not SI_SUPPORT_ACTION' {
        (ConvertFrom-SISupportGrantMessage -Text ((& $script:Msg) -replace 'SI_SUPPORT_ACTION', 'si_support_action') -NowUtc $script:Now).Ok | Should -BeFalse
    }
}

Describe 'the newest fresh message is the request; the queue answer is read' {
    It 'the newest one not older than 15 minutes; the others are dropped with why' {
        $a = & $script:M 'a' 1 'A'; $b = & $script:M 'b' 5 'B'; $c = & $script:M 'c' 16 'C'
        $s = Select-SISupportGrantMessage -Messages @($b, $c, $a) -NowUtc $script:Now
        $s.Message.Id | Should -Be 'A'
        @($s.Dropped).Count | Should -Be 2
        (@($s.Dropped) | Where-Object Id -eq 'C').Why | Should -Match 'older than 15 minutes'
    }
    It 'only stale messages = no request' { (Select-SISupportGrantMessage -Messages @((& $script:M 'x' 20)) -NowUtc $script:Now).Message | Should -BeNullOrEmpty }
    It 'the Get Messages XML (raw JSON text, XML-escaped) is read back as it was put' {
        $json = & $script:Msg
        $xml = '<?xml version="1.0" encoding="utf-8"?><QueueMessagesList><QueueMessage><MessageId>11111111-2222-3333-4444-555555555555</MessageId><InsertionTime>Sun, 01 Nov 2026 09:58:00 GMT</InsertionTime><PopReceipt>AgAAAA==</PopReceipt><MessageText>' + [Security.SecurityElement]::Escape($json) + '</MessageText></QueueMessage></QueueMessagesList>'
        $m = @(ConvertFrom-SISupportGrantQueueXml -Xml $xml)
        $m.Count | Should -Be 1; $m[0].Text | Should -Be $json; $m[0].Inserted | Should -Be $script:Now.AddMinutes(-2)
    }
}

Describe 'THE line Invardia reads and the exit codes' {
    It 'exactly: SUPPORT-GRANT action= level= until= result= (the agreed shape)' {
        Get-SISupportGrantLogLine -Action open -Level setup -Until $script:Now.AddHours(2) -Result ok | Should -BeExactly 'SUPPORT-GRANT action=open level=setup until=2026-11-01T12:00:00Z result=ok'
        Get-SISupportGrantLogLine -Action '' -Level '' -Until $null -Result 'bad-request' | Should -BeExactly 'SUPPORT-GRANT action=none level=none until=none result=bad-request'
        Get-SISupportGrantLogLine -Action close -Level troubleshoot -Until '2026-11-01T10:00:00Z' -Result 'no consent!' | Should -BeExactly 'SUPPORT-GRANT action=close level=troubleshoot until=2026-11-01T10:00:00Z result=noconsent'
    }
    It 'exit 0 ok, 2 could not, 3 no consent, 4 bad request' {
        Get-SISupportGrantExitCode 'ok' | Should -Be 0
        foreach ($w in 'not-prepared', 'failed', 'refused', 'anything') { Get-SISupportGrantExitCode $w | Should -Be 2 }
        Get-SISupportGrantExitCode 'no-consent' | Should -Be 3
        foreach ($w in 'bad-request', 'no-request') { Get-SISupportGrantExitCode $w | Should -Be 4 }
    }
    It 'the procedures'' error numbers map to the result words (from an inner SqlException-like Number, or the text)' {
        $inner = New-Object System.Exception 'x'; $inner | Add-Member -NotePropertyName Number -NotePropertyValue 51803
        Get-SISupportGrantErrorResult (New-Object System.Exception('outer', $inner)) | Should -Be 'no-consent'
        Get-SISupportGrantErrorResult (New-Object System.Exception 'Msg 51802: maxUntil must be ...') | Should -Be 'bad-request'
        Get-SISupportGrantErrorResult (New-Object System.Exception 'the support grant procedure is not signed') | Should -Be 'not-prepared'
        Get-SISupportGrantErrorResult (New-Object System.Exception "Could not find stored procedure 'cfg.SupportGrantOpen'") | Should -Be 'not-prepared'
        Get-SISupportGrantErrorResult (New-Object System.Exception 'timeout') | Should -Be 'failed'
    }
}

Describe 'THE JOB (fake databases)' {
    It 'OPEN: the sweep first, then the Pro database first; parameters only; the granted level from the READ-BACK; exit 0; every message deleted' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Open = $script:OkOpen; Close = $script:OkClose }
        $led = & $script:NewDb 'ledger' @{ Sweep = $script:OkSweep; Open = $script:OkOpen; Close = $script:OkClose }
        $x = & $script:Run @($pro, $led) @((& $script:M (& $script:Msg) 1 'A'), (& $script:M 'old' 20 'B'))
        $x.R.ExitCode | Should -Be 0; $x.R.Result | Should -Be 'ok'
        $x.R.Line | Should -BeExactly ('SUPPORT-GRANT action=open level=setup until={0} result=ok' -f (& $script:Iso 120))
        $x.Removed | Should -Be @('A', 'B')
        @($pro.State.Calls)[0].Sql | Should -Match 'SupportGrantSweep'; @($pro.State.Calls)[1].Sql | Should -Match 'SupportGrantOpen'
        @($led.State.Calls | Where-Object { $_.Sql -match 'SupportGrantOpen' }).Count | Should -Be 1
        # nothing of the request is in the statement text -- it travels as parameters
        foreach ($c in @($pro.State.Calls.ToArray()) + @($led.State.Calls.ToArray())) { $c.Sql | Should -Not -Match 'ticket 42|SUP-2026|agent@invardia' }
        @($pro.State.Calls)[1].Params.Reason | Should -Be 'ticket 42: the pipeline stops'
        $x.Events[0].event | Should -Be 'support.granted'
    }
    It 'the customer consented to less: the read-back''s level is what the line says' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Open = @{ LevelGranted = 'troubleshoot'; RoleName = 'db_datareader'; UntilUtc = (& $script:Iso 120); RoleHeld = 1; ReadOnlyHeld = 1 } }
        $x = & $script:Run @($pro) @((& $script:M (& $script:Msg) 1))
        $x.R.Line | Should -Match 'level=troubleshoot'
        ($x.Said -join "`n") | Should -Match 'consented to troubleshoot'
    }
    It 'NO CONSENT: exit 3, nothing open' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Open = 'THROW Msg 51803, no consent: the customer has not granted' }
        $x = & $script:Run @($pro) @((& $script:M (& $script:Msg) 1))
        $x.R.ExitCode | Should -Be 3; $x.R.Line | Should -Match 'result=no-consent$'
        $x.Events[0].event | Should -Be 'support.grant-failed'
    }
    It 'a second database fails: the ones opened are CLOSED again (never a half grant), exit 2' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Open = $script:OkOpen; Close = $script:OkClose }
        $led = & $script:NewDb 'ledger' @{ Sweep = $script:OkSweep; Open = 'THROW Msg 51801, the support grant procedure is not signed' }
        $x = & $script:Run @($pro, $led) @((& $script:M (& $script:Msg) 1))
        $x.R.ExitCode | Should -Be 2; $x.R.Result | Should -Be 'not-prepared'
        @($pro.State.Calls | Where-Object { $_.Sql -match 'SupportGrantClose' }).Count | Should -Be 1
    }
    It 'a grant that does not read back (the role not held) is a failure and rolled back' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Open = @{ LevelGranted = 'setup'; RoleName = 'db_owner'; UntilUtc = (& $script:Iso 60); RoleHeld = 0; ReadOnlyHeld = 1 }; Close = $script:OkClose }
        $x = & $script:Run @($pro) @((& $script:M (& $script:Msg) 1))
        $x.R.ExitCode | Should -Be 2
        @($pro.State.Calls | Where-Object { $_.Sql -match 'SupportGrantClose' }).Count | Should -Be 1
    }
    It 'CLOSE: every database, read back; a role still held is a failure; the read-only role missing is a WARNING' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Close = $script:OkClose }
        $led = & $script:NewDb 'ledger' @{ Sweep = $script:OkSweep; Close = @{ Closed = 1; RolesRemoved = 1; StillOpen = 0; RolesStillHeld = 0; UserPresent = 1; ReadOnlyHeld = 0 } }
        $x = & $script:Run @($pro, $led) @((& $script:M (& $script:Msg @{ SI_SUPPORT_ACTION = 'close' }) 1))
        $x.R.ExitCode | Should -Be 0; $x.R.Line | Should -Match '^SUPPORT-GRANT action=close '
        ($x.Said -join "`n") | Should -Match 'WARNING the Support app is not in its read-only role'
        $x.Events[0].event | Should -Be 'support.revoked'
        $bad = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Close = @{ Closed = 1; RolesRemoved = 0; RolesStillHeld = 1; UserPresent = 1; ReadOnlyHeld = 1 } }
        (& $script:Run @($bad) @((& $script:M (& $script:Msg @{ SI_SUPPORT_ACTION = 'close' }) 1))).R.ExitCode | Should -Be 2
    }
    It 'a stale message or a bad one: exit 4; an EMPTY queue (#1154: the queue starts the job, another execution took it): exit 0, no line -- and the sweep still ran' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep }
        $e = (& $script:Run @($pro) @()).R; $e.ExitCode | Should -Be 0; $e.Line | Should -BeNullOrEmpty
        $s = (& $script:Run @($pro) @((& $script:M (& $script:Msg) 16))).R
        $s.ExitCode | Should -Be 4; $s.Line | Should -BeExactly 'SUPPORT-GRANT action=none level=none until=none result=no-request'
        (& $script:Run @($pro) @((& $script:M '{"SI_SUPPORT_ACTION":"open","EVIL":"x"}' 1))).R.Line | Should -Match 'result=bad-request$'
        @($pro.State.Calls | Where-Object { $_.Sql -match 'SupportGrantSweep' }).Count | Should -Be 3
        @($pro.State.Calls | Where-Object { $_.Sql -match 'SupportGrantOpen' }).Count | Should -Be 0
    }
    It 'the sweep: closed markers are said; a database without the procedures is NOT READY, never a failure' {
        $pro = & $script:NewDb 'pro' @{ Sweep = @{ Closed = 2; RolesRemoved = 1; UserPresent = 1; ReadOnlyHeld = 1 } }
        $led = & $script:NewDb 'ledger' @{ Sweep = "THROW Could not find stored procedure 'cfg.SupportGrantSweep'" }
        $s = Invoke-SISupportGrantSweep -Databases ([ordered]@{ pro = $pro.Seam; ledger = $led.Seam })
        $s.Closed | Should -Be 2; @($s.NotReady) | Should -Be @('ledger'); @($s.Failed).Count | Should -Be 0
        ($s.Lines -join "`n") | Should -Match 'pro: 2 expired support grant marker'
    }
    It 'the status (heartbeat): readOnly / jitOpen / jitUntil over every database; overdue and standing db_owner said' {
        $pro = & $script:NewDb 'pro' @{ Status = @{ Database = 'pro'; Signed = 1; ReadOnlyHeld = 1; JitOpen = 1; JitUntilUtc = '2026-11-01T12:00:00Z'; JitLevel = 'setup'; JitOverdue = 0; StandingOwner = 0 } }
        $led = & $script:NewDb 'ledger' @{ Status = @{ Database = 'ledger'; Signed = 1; ReadOnlyHeld = 1; JitOpen = 0; JitUntilUtc = $null; JitLevel = $null; JitOverdue = 1; StandingOwner = 1 } }
        $s = Get-SISupportGrantStatus -Databases ([ordered]@{ pro = $pro.Seam; ledger = $led.Seam }) -NowUtc $script:Now
        $s.Wire.readOnly | Should -BeTrue; $s.Wire.jitOpen | Should -BeTrue; $s.Wire.jitUntil | Should -Be '2026-11-01T12:00:00Z'
        $s.Text | Should -Match 'OVERDUE'; $s.Text | Should -Match 'holds db_owner outside a support grant'
    }
    It 'the status: a database WITHOUT the procedures beside one with them reads missing (readOnly false), not unknown' {
        $pro = & $script:NewDb 'pro' @{ Status = @{ Database = 'pro'; Signed = 1; ReadOnlyHeld = 1; JitOpen = 0; JitUntilUtc = $null; JitLevel = $null; JitOverdue = 0; StandingOwner = 0 } }
        $led = & $script:NewDb 'ledger' @{}
        $s = Get-SISupportGrantStatus -Databases ([ordered]@{ pro = $pro.Seam; ledger = $led.Seam }) -NowUtc $script:Now
        $s.Wire.readOnly | Should -BeFalse
        $s.Text | Should -Match 'ledger: no support grant procedures yet'
    }
    It 'the status: readOnly is true only when the read role is held AND the procedures are signed (Invardia: the just-in-time model is in place)' {
        $ok = @{ Database = 'pro'; Signed = 1; ReadOnlyHeld = 1; JitOpen = 0; JitUntilUtc = $null; JitLevel = $null; JitOverdue = 0; StandingOwner = 0 }
        $unsigned = @{ Database = 'ledger'; Signed = 0; ReadOnlyHeld = 1; JitOpen = 0; JitUntilUtc = $null; JitLevel = $null; JitOverdue = 0; StandingOwner = 0 }
        (Get-SISupportGrantStatus -Databases ([ordered]@{ pro = (& $script:NewDb 'pro' @{ Status = $ok }).Seam; ledger = (& $script:NewDb 'ledger' @{ Status = $unsigned }).Seam }) -NowUtc $script:Now).Wire.readOnly | Should -BeFalse -Because 'a role without signed procedures cannot open a session'
        (Get-SISupportGrantStatus -Databases ([ordered]@{ pro = (& $script:NewDb 'pro' @{ Status = $ok }).Seam }) -NowUtc $script:Now).Wire.readOnly | Should -BeTrue
    }
    It 'no switch holds the change back any more (Invardia 2026-11-20): the SupportAccess heartbeat replaces the support.* events' {
        Get-Command -Name Resolve-SIUplinkSupportGrantSwitch -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command -Name Start-SISupportAccessHeartbeat -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe '#1356 / #1368 -- several pending requests: each read on its own, a close wins over its OWN session, a bad one fails alone' {
    BeforeAll {
        # a request of a Support session (-Session) as Invardia's tools write it: "Invardia Support: <operator> (session <id>)"
        $script:By = { param([string]$Session) if ($Session) { "Invardia Support: agent@invardia (session $Session)" } else { 'agent@invardia' } }
        $script:Close = { param([int]$Age, [string]$Id, [string]$Session = '') & $script:M (& $script:Msg @{ SI_SUPPORT_ACTION = 'close'; SI_SUPPORT_LEVEL = 'troubleshoot'; SI_AUDIT_STARTED_BY = (& $script:By $Session) }) $Age $Id }
        $script:Open = { param([int]$Age, [string]$Id, [string]$Session = '') & $script:M (& $script:Msg @{ SI_AUDIT_STARTED_BY = (& $script:By $Session) }) $Age $Id }
        $script:Bad = { param([int]$Age, [string]$Id) & $script:M '{"SI_SUPPORT_ACTION":"close","EVIL":"x"}' $Age $Id }
        $script:Dbs = { @((& $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Open = $script:OkOpen; Close = $script:OkClose }), (& $script:NewDb 'ledger' @{ Sweep = $script:OkSweep; Open = $script:OkOpen; Close = $script:OkClose })) }
        $script:XmlOf = {
            param([object[]]$Messages)
            $body = foreach ($m in $Messages) {
                '<QueueMessage><MessageId>{0}</MessageId><InsertionTime>{1}</InsertionTime><PopReceipt>pr-{0}</PopReceipt><MessageText>{2}</MessageText></QueueMessage>' -f $m.Id, $m.Inserted.ToString('r', [Globalization.CultureInfo]::InvariantCulture), [Security.SecurityElement]::Escape([string]$m.Text)
            }
            '<?xml version="1.0" encoding="utf-8"?><QueueMessagesList>' + (@($body) -join '') + '</QueueMessagesList>'
        }
        # the queue read EXACTLY as the job script did before the #1356 fix: one read's batch collected with @( ) = ONE item
        $script:RunNested = {
            param($Dbs, [object[]]$Messages)
            $batch = @(ConvertFrom-SISupportGrantQueueXml -Xml (& $script:XmlOf $Messages))
            $removed = New-Object System.Collections.Generic.List[string]; $said = New-Object System.Collections.Generic.List[string]
            $map = [ordered]@{}; foreach ($d in $Dbs) { $map[$d.State.Name] = $d.Seam }
            $recv = { $all = [System.Collections.Generic.List[object]]::new(); foreach ($m in $batch) { $all.Add($m) }; $all.ToArray() }.GetNewClosure()
            $r = Invoke-SISupportGrantJob -Databases $map -Receive $recv -Remove { param($m) $removed.Add([string]$m.Id) }.GetNewClosure() -NowUtc $script:Now -Say { param($l, $t) $said.Add("[$l] $t") }.GetNewClosure()
            [pscustomobject]@{ R = $r; Removed = $removed.ToArray(); Said = $said.ToArray(); BatchItems = $batch.Count }
        }
        # a QUEUE across executions: each execution reads what is still on it and deletes what it deleted; until it is empty
        $script:RunQueue = {
            param($Dbs, [object[]]$Messages, [int]$Max = 6)
            $q = [System.Collections.Generic.List[object]]::new(); foreach ($m in $Messages) { $q.Add($m) }
            $map = [ordered]@{}; foreach ($d in $Dbs) { $map[$d.State.Name] = $d.Seam }
            $runs = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $Max -and $q.Count; $i++) {
                $said = New-Object System.Collections.Generic.List[string]
                $recv = { , $q.ToArray() }.GetNewClosure()
                $rm = { param($m) $hit = @($q | Where-Object { $_.Id -eq $m.Id }); foreach ($h in $hit) { [void]$q.Remove($h) } }.GetNewClosure()
                $r = Invoke-SISupportGrantJob -Databases $map -Receive $recv -Remove $rm -NowUtc $script:Now -Say { param($l, $t) $said.Add("[$l] $t") }.GetNewClosure()
                $runs.Add([pscustomobject]@{ Line = $r.Line; Said = $said.ToArray() })
            }
            [pscustomobject]@{ Runs = $runs.ToArray(); Left = $q.Count }
        }
        # the order of the grant calls a database saw (Open / Close), the sweep and the reads left out
        $script:Seq = { param($Db) @($Db.State.Calls | ForEach-Object { if ($_.Sql -match 'SupportGrantOpen') { 'Open' } elseif ($_.Sql -match 'SupportGrantClose') { 'Close' } } | Where-Object { $_ }) }
        $script:Calls = { param($Db, [string]$Kind) @($Db.State.Calls | Where-Object { $_.Sql -match ('SupportGrant' + $Kind) }).Count }
    }

    It 'the live shape (one read''s batch as ONE item): open + close of ONE session -> the CLOSE is answered, ok, never the DateTime failure' {
        $dbs = & $script:Dbs
        $x = & $script:RunNested $dbs @((& $script:Open 3 'A' 's1'), (& $script:Close 1 'B' 's1'))
        $x.BatchItems | Should -Be 1 -Because 'this is the shape that failed live: two messages, one item'
        $x.R.Result | Should -Be 'ok'; $x.R.ExitCode | Should -Be 0
        $x.R.Line | Should -Match '^SUPPORT-GRANT action=close level=troubleshoot until=\S+ result=ok$'
        ($x.Said -join "`n") | Should -Not -Match 'System.Object\[\]'
        foreach ($d in $dbs) { & $script:Calls $d 'Close' | Should -Be 1; & $script:Calls $d 'Open' | Should -Be 0 }
        @($x.Removed | Sort-Object) | Should -Be @('A', 'B')
        ($x.Said -join "`n") | Should -Match 'a close wins over its own session''s open'
    }
    It 'the batch flattened: two and three messages in one read are two and three messages; empty stays empty' {
        $two = @(ConvertTo-SISupportGrantMessageList -Messages @(, @((& $script:Open 2 'A'), (& $script:Close 1 'B'))) | ForEach-Object { $_ })
        $two.Count | Should -Be 2; @($two | ForEach-Object { $_.Id }) | Should -Be @('A', 'B')
        $three = @(ConvertTo-SISupportGrantMessageList -Messages @(, @(, @((& $script:Open 3 'A'), (& $script:Close 2 'B'), $null, (& $script:Close 1 'C')))) | ForEach-Object { $_ })
        $three.Count | Should -Be 3
        @(ConvertTo-SISupportGrantMessageList -Messages @() | ForEach-Object { $_ }).Count | Should -Be 0
    }
    It 'the session key: the session id in SI_AUDIT_STARTED_BY (case ignored); none = the request is its own session' {
        Get-SISupportGrantSessionKey -StartedBy 'Invardia Support: operator on host1 (session 3F2A-77)' -MessageId 'm1' | Should -Be 'session:3f2a-77'
        Get-SISupportGrantSessionKey -StartedBy 'Invardia Support: x (SESSION 3f2a-77)' -MessageId 'm2' | Should -Be 'session:3f2a-77'
        Get-SISupportGrantSessionKey -StartedBy 'agent@invardia' -MessageId 'm1' | Should -Be 'message:m1'
        Get-SISupportGrantSessionKey -StartedBy '' -MessageId 'm2' | Should -Be 'message:m2'
    }
    It 'TWO SESSIONS in one queue read (A open, B open, A close): A''s close is answered first, A''s open dropped, B''s open STAYS on the queue -- then B is opened and kept' {
        $dbs = & $script:Dbs
        $x = & $script:RunQueue $dbs @((& $script:Open 4 'A1' 'sA'), (& $script:Open 3 'B1' 'sB'), (& $script:Close 2 'A2' 'sA'))
        @($x.Runs).Count | Should -Be 2; $x.Left | Should -Be 0
        $x.Runs[0].Line | Should -Match '^SUPPORT-GRANT action=close .* result=ok$'
        ($x.Runs[0].Said -join "`n") | Should -Match 'a close wins over its own session''s open'
        ($x.Runs[0].Said -join "`n") | Should -Match '1 more support request\(s\) stay on the queue'
        $x.Runs[1].Line | Should -Match '^SUPPORT-GRANT action=open .* result=ok$'
        # per database: A's close, then B's open -- and nothing closes B afterwards (kept)
        foreach ($d in $dbs) { @(& $script:Seq $d) | Should -Be @('Close', 'Open') }
        @($dbs[0].State.Calls | Where-Object { $_.Sql -match 'SupportGrantOpen' })[0].Params.StartedBy | Should -Match '\(session sB\)'
        # then B closes: both sessions are closed, read back from the close's answer
        $y = & $script:RunQueue $dbs @((& $script:Close 1 'B2' 'sB'))
        $y.Runs[0].Line | Should -Match '^SUPPORT-GRANT action=close .* result=ok$'
        foreach ($d in $dbs) { @(& $script:Seq $d) | Should -Be @('Close', 'Open', 'Close') }
    }
    It 'TWO SESSIONS, then both close: A open, B open, A close, B close -> every request answered in turn; both closed at the end' {
        $dbs = & $script:Dbs
        $x = & $script:RunQueue $dbs @((& $script:Open 5 'A1' 'sA'), (& $script:Open 4 'B1' 'sB'), (& $script:Close 3 'A2' 'sA'), (& $script:Close 1 'B2' 'sB'))
        $x.Left | Should -Be 0
        @($x.Runs | ForEach-Object { ($_.Line -split ' ')[1] }) | Should -Be @('action=close', 'action=close')
        # B's own close won over B's waiting open: B never opened, nothing is left open
        foreach ($d in $dbs) { @(& $script:Seq $d) | Should -Be @('Close', 'Close') }
        $x = & $script:RunQueue (& $script:Dbs) @((& $script:Open 5 'A1' 'sA'), (& $script:Open 4 'B1' 'sB'))
        @($x.Runs | ForEach-Object { ($_.Line -split ' ')[1] }) | Should -Be @('action=open', 'action=open') -Because 'two opens = each answered, oldest first'
    }
    It 'NO session id: every request is its own session -- a close never drops another request''s open (it stays and is answered next)' {
        $dbs = & $script:Dbs
        $x = & $script:RunQueue $dbs @((& $script:Close 3 'A'), (& $script:Open 1 'B'))
        @($x.Runs | ForEach-Object { ($_.Line -split ' ')[1] }) | Should -Be @('action=close', 'action=open')
        foreach ($d in $dbs) { @(& $script:Seq $d) | Should -Be @('Close', 'Open') }
        $s = Select-SISupportGrantRequest -Messages @((& $script:Open 3 'O'), (& $script:Close 1 'C')) -NowUtc $script:Now
        $s.Message.Id | Should -Be 'C'; @($s.Later | ForEach-Object { $_.Id }) | Should -Be @('O'); @($s.Dropped).Count | Should -Be 0
    }
    It 'close + close of ONE session: one close is answered, the other said as the same close; each database closed once' {
        $dbs = & $script:Dbs
        $x = & $script:RunNested $dbs @((& $script:Close 2 'A' 's1'), (& $script:Close 1 'B' 's1'))
        $x.R.Result | Should -Be 'ok'; $x.R.Line | Should -Match '^SUPPORT-GRANT action=close '
        foreach ($d in $dbs) { & $script:Calls $d 'Close' | Should -Be 1 }
        ($x.Said -join "`n") | Should -Match 'the same close of this session was asked again'
        @($x.Removed | Sort-Object) | Should -Be @('A', 'B')
    }
    It 'three pending of ONE session (open, close, open): the close wins; nothing is opened; all three deleted' {
        $dbs = & $script:Dbs
        $x = & $script:RunNested $dbs @((& $script:Open 4 'A' 's1'), (& $script:Close 3 'B' 's1'), (& $script:Open 1 'C' 's1'))
        $x.R.Line | Should -Match '^SUPPORT-GRANT action=close .* result=ok$'
        foreach ($d in $dbs) { & $script:Calls $d 'Open' | Should -Be 0; & $script:Calls $d 'Close' | Should -Be 1 }
        @($x.Removed).Count | Should -Be 3
    }
    It 'a bad request fails ALONE: close + bad (the bad one newer) -> the close is answered ok, the bad one refused, said and deleted' {
        $dbs = & $script:Dbs
        $x = & $script:RunNested $dbs @((& $script:Close 3 'A'), (& $script:Bad 1 'B'))
        $x.R.Result | Should -Be 'ok'; $x.R.Line | Should -Match '^SUPPORT-GRANT action=close '
        ($x.Said -join "`n") | Should -Match '\[WARN\] the support request was refused: the key EVIL is not part of a support request'
        foreach ($d in $dbs) { & $script:Calls $d 'Close' | Should -Be 1 }
        @($x.Removed | Sort-Object) | Should -Be @('A', 'B')
    }
    It 'only bad requests: bad-request (exit 4), nothing granted or closed; only stale ones: no-request' {
        $dbs = & $script:Dbs
        $x = & $script:RunNested $dbs @((& $script:Bad 2 'A'), (& $script:Bad 1 'B'))
        $x.R.Line | Should -BeExactly 'SUPPORT-GRANT action=none level=none until=none result=bad-request'; $x.R.ExitCode | Should -Be 4
        @($x.Said | Where-Object { $_ -match 'was refused' }).Count | Should -Be 2
        foreach ($d in $dbs) { & $script:Calls $d 'Open' | Should -Be 0; & $script:Calls $d 'Close' | Should -Be 0 }
        (& $script:RunNested (& $script:Dbs) @((& $script:Close 30 'A'), (& $script:Open 20 'B'))).R.Result | Should -Be 'no-request'
    }
    It 'open + open (no close): the OLDEST open is answered, the newer one stays on the queue for the next execution' {
        $s = Select-SISupportGrantRequest -Messages @((& $script:Open 1 'NEW'), (& $script:Open 5 'OLD')) -NowUtc $script:Now
        $s.Message.Id | Should -Be 'OLD'; $s.Request.Action | Should -Be 'open'
        @($s.Later | ForEach-Object { $_.Id }) | Should -Be @('NEW'); @($s.Dropped).Count | Should -Be 0
    }
    It 'LOG ONLY: before a close, the job says which OTHER sessions'' open grants it ends (read first, never its own; no procedure change)' {
        $rows = @(@{ GrantId = '11111111-1111-1111-1111-111111111111'; StartedBy = 'Invardia Support: operator (session sB)'; Reason = 'SecurityInsight fold-why: read'; LevelGranted = 'troubleshoot'; AtUtc = '2026-11-01T09:50:00Z' },
                  @{ GrantId = '22222222-2222-2222-2222-222222222222'; StartedBy = 'Invardia Support: operator (session sA)'; Reason = 'SecurityInsight duplicate check'; LevelGranted = 'troubleshoot'; AtUtc = '2026-11-01T09:55:00Z' })
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Close = $script:OkClose; OpenGrants = $rows }
        $x = & $script:RunNested @($pro) @((& $script:Close 1 'A2' 'sA'))
        $x.R.Line | Should -Match '^SUPPORT-GRANT action=close .* result=ok$'
        $said = ($x.Said -join "`n")
        $said | Should -Match '\[WARN\] pro: this close also ends the open grant of ANOTHER support session -- Invardia Support: operator \(session sB\), troubleshoot since 2026-11-01T09:50:00Z: SecurityInsight fold-why: read'
        $said | Should -Not -Match 'session sA\), troubleshoot since'
        # the read came BEFORE the close, and it is a read only (no procedure, no write)
        $kinds = @($pro.State.Calls | ForEach-Object { if ($_.Sql -match 'SupportJitMarker WHERE ClosedUtc IS NULL') { 'Read' } elseif ($_.Sql -match 'SupportGrantClose') { 'Close' } } | Where-Object { $_ })
        $kinds | Should -Be @('Read', 'Close')
        (Get-SISupportGrantOpenGrantsSql) | Should -Not -Match '(?i)\b(INSERT|UPDATE|DELETE|MERGE|EXEC|ALTER|DROP)\b'
    }
    It 'the READ IS REFUSED (si_engine is not granted it, SEC-CHANGE-1 point 1): "could not read the other open grants" is said, the close goes on and reads back, the line is ok' {
        $dbs = @((& $script:NewDb 'pro' @{ Sweep = $script:OkSweep; Close = $script:OkClose; OpenGrants = 'THROW The SELECT permission was denied on the object ''SupportJitMarker'', database ''sqldb-si-pro'', schema ''cfg''.' }),
                 (& $script:NewDb 'ledger' @{ Sweep = $script:OkSweep; Close = $script:OkClose; OpenGrants = 'THROW The SELECT permission was denied on the object ''SupportGrant''' }))
        $y = & $script:RunNested $dbs @((& $script:Close 1 'A2' 'sA'))
        $y.R.Result | Should -Be 'ok'; $y.R.ExitCode | Should -Be 0
        $y.R.Line | Should -Match '^SUPPORT-GRANT action=close .* result=ok$'
        $said = ($y.Said -join "`n")
        $said | Should -Match '\[INFO\] pro: could not read the other open grants -- .*the close goes on'
        $said | Should -Match '\[INFO\] ledger: could not read the other open grants'
        $said | Should -Not -Match '\[WARN\].*could not read the other open grants'
        foreach ($d in $dbs) { & $script:Calls $d 'Close' | Should -Be 1 }
        ($said) | Should -Match 'pro: closed \(1 marker'
    }
    It 'NO new right: si_engine has no grant on cfg.SupportJitMarker / cfg.SupportGrant (writes stay DENIED); the read is listed as not granted on purpose' {
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
        @($script:SIEngineObjectGrants | Where-Object { $_.Object -in 'cfg.SupportJitMarker', 'cfg.SupportGrant' }).Count | Should -Be 0
        $d = @($script:SIEngineDenies | Where-Object { $_.Object -in 'cfg.SupportJitMarker', 'cfg.SupportGrant' })
        @($d | ForEach-Object { $_.Verbs }) | Should -Be @('INSERT, UPDATE, DELETE', 'INSERT, UPDATE, DELETE')
        @($script:SIEngineNotEngine | Where-Object { $_.Function -eq 'Get-SISupportGrantOpenGrantsSql' }).Count | Should -Be 1
    }
    It 'the job script opens the read''s batch up into one item per message' {
        $e = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\support-grant\Invoke-SISupportGrant.ps1')
        $e | Should -Match 'ConvertFrom-SISupportGrantQueueXml -Xml \(\[string\]\$r\.Content\) \| ForEach-Object \{ \$_ \}'
    }
}
