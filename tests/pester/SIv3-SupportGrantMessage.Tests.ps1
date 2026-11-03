#Requires -Version 5.1
<#
    #1021 -- THE SUPPORT GRANT JOB caj-si-support-grant, offline (engine\support-grant\SI-SupportGrant.ps1):
      * the request is a REQUEST: only the six agreed keys, raw JSON, every value checked (action, level, maxUntil within
        24 h and in the future, reason 1-200, ticket / name lengths, no control characters); refused = bad-request (exit 4);
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
            $kind = if ($Sql -match 'SupportGrantOpen') { 'Open' } elseif ($Sql -match 'SupportGrantClose') { 'Close' } elseif ($Sql -match 'SupportGrantSweep') { 'Sweep' } else { 'Status' }
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
    It 'no message, a stale one or a bad one: exit 4 -- and the sweep still ran' {
        $pro = & $script:NewDb 'pro' @{ Sweep = $script:OkSweep }
        (& $script:Run @($pro) @()).R.Line | Should -BeExactly 'SUPPORT-GRANT action=none level=none until=none result=no-request'
        (& $script:Run @($pro) @((& $script:M (& $script:Msg) 16))).R.ExitCode | Should -Be 4
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
    It 'the uplink events are OFF until Invardia agrees them (auto = no ring; on / a ring list turns them on)' {
        (Resolve-SIUplinkSupportGrantSwitch -Value $null -EnvValue '' -Ring 0).On | Should -BeFalse
        (Resolve-SIUplinkSupportGrantSwitch -Value 'auto' -EnvValue '' -Ring 0).On | Should -BeFalse
        (Resolve-SIUplinkSupportGrantSwitch -Value 'on' -EnvValue '' -Ring 2).On | Should -BeTrue
        (Resolve-SIUplinkSupportGrantSwitch -Value '0' -EnvValue '' -Ring 0).On | Should -BeTrue
        (Resolve-SIUplinkSupportGrantSwitch -Value '0' -EnvValue '' -Ring 1).On | Should -BeFalse
    }
}
