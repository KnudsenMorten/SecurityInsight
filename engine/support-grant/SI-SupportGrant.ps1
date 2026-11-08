#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE SUPPORT GRANT JOB caj-si-support-grant (#1021; framework DOCS/REQUIREMENTS.md SECAUDIT-1a, 4a,
    4b). The Invardia Support session puts ONE message on the queue si-support-requests of the install's own storage account,
    and THE QUEUE STARTS THE JOB (#1154, framework 5.5: an event trigger, the azure-queue scaler signed in as the engine
    identity). The Support app holds ONLY Storage Queue Data Message Sender on that queue and NO right on any job: a start
    right alone (Microsoft.App/jobs/start/action) accepts a container override, so it could have run a command of its own as
    the engine identity. Nothing below depends on how the job was started: it reads the queue either way.

    THE MESSAGE IS A REQUEST, NEVER AN INSTRUCTION (agreed with Invardia and PIM, SEC-92). Raw JSON, only these keys:
        SI_SUPPORT_ACTION    open | close                                         required
        SI_SUPPORT_LEVEL     troubleshoot | setup                                 required (a close carries one too)
        SI_SUPPORT_MAXUNTIL  ISO-8601 UTC, in the future, at most 8 h ahead       required (a close carries one too)
        SI_SUPPORT_REASON    the ticket / session reason, 1-200 characters        required
        SI_SUPPORT_TICKET    the ticket number, at most 64 characters             optional
        SI_AUDIT_STARTED_BY  who started it, at most 256 characters               optional
    No field is ever run or used as a name, path, principal or SQL text: they travel as SQL PARAMETERS to the signed
    procedures (engine\pro-settings\SI-SupportGrantSql.ps1), which take the principal from the customer's consent record
    and grant the LOWER of the asked and the consented level.

    THE JOB, in order (Invoke-SISupportGrantJob):
      1. the SWEEP on every product database: a grant past its maxUntil is revoked first, whatever the message says;
      2. every message on the queue is read and DELETED; the newest one not older than 15 minutes is the request, the
         others are dropped and said;
      3. open: the Pro database first (it holds the consent the customer recorded), then the identity ledger and the data
         database; one that fails rolls back the ones already opened (they are closed again) -- never a half grant;
         close: every database, each on its own;
      4. THE READ-BACK each procedure returns (from the catalog, not from the request) decides the result;
      5. ONE log line Invardia reads -- exactly
            SUPPORT-GRANT action=<open|close|none> level=<granted level|none> until=<ISO UTC|none> result=<ok|reason>
         and the exit code: 0 ok, 2 could not (not prepared, a database failed), 3 no consent, 4 bad request (only stale
         messages, an unknown key, a bad value). An EMPTY queue (#1154: another execution the scaler started took the
         request) is no request: exit 0 and no SUPPORT-GRANT line.
    The uplink events support.granted / support.revoked / support.grant-failed go out only where SI_Uplink_SendSupportGrant
    says so -- OFF until Invardia has agreed the wire (owner rule: an unknown key drops the section).

    PURE except the seams. Strict-mode safe; PS 5.1 and 7.
#>

if (-not (Get-Command -Name Get-SISupportGrantCallSql -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'pro-settings', 'SI-SupportGrantSql.ps1'))
}

$script:SISupportGrantJob = [ordered]@{
    Job            = 'caj-si-support-grant'
    Queue          = 'si-support-requests'
    MaxMessageBytes = 4096
    StaleMinutes   = 15
    # a support session is at most 8 hours (framework rule, owner 2026-11-04) -- the open procedure refuses more as well;
    # two minutes for the clock difference between the Support session that wrote maxUntil and this job
    MaxHours       = 8
    ClockSlackMinutes = 2
    Keys           = @('SI_SUPPORT_ACTION', 'SI_SUPPORT_LEVEL', 'SI_SUPPORT_MAXUNTIL', 'SI_SUPPORT_REASON', 'SI_SUPPORT_TICKET', 'SI_AUDIT_STARTED_BY')
    Required       = @('SI_SUPPORT_ACTION', 'SI_SUPPORT_LEVEL', 'SI_SUPPORT_MAXUNTIL', 'SI_SUPPORT_REASON')
    # the result word -> the exit code
    Exit           = [ordered]@{ 'ok' = 0; 'not-prepared' = 2; 'failed' = 2; 'refused' = 2; 'no-consent' = 3; 'bad-request' = 4; 'no-request' = 4 }
}

function Get-SISupportGrantJobContract { $script:SISupportGrantJob }

function Get-SISupportGrantExitCode {
    <# PURE. The exit code of a result word (anything unknown = 2, "could not"). #>
    param([AllowEmptyString()][string]$Result)
    if ($script:SISupportGrantJob.Exit.Contains($Result)) { return [int]$script:SISupportGrantJob.Exit[$Result] }
    2
}

function Format-SISupportGrantUtc {
    <# PURE. A time as the log line and the procedures carry it: yyyy-MM-ddTHH:mm:ssZ (UTC). '' for $null. #>
    param($Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return '' }
    $d = if ($Value -is [datetime]) { $Value } else { [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') }
    $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SISupportGrantLogLine {
    <# PURE. THE line Invardia reads (agreed 2026-11-01 -- never change its shape):
       SUPPORT-GRANT action=<open|close|none> level=<granted level|none> until=<ISO UTC|none> result=<ok|reason> #>
    param([AllowEmptyString()][string]$Action, [AllowEmptyString()][string]$Level, $Until, [Parameter(Mandatory)][string]$Result)
    $a = if ($Action -in 'open', 'close') { $Action } else { 'none' }
    $l = if ($Level -in 'troubleshoot', 'setup') { $Level } else { 'none' }
    $u = Format-SISupportGrantUtc $Until; if (-not $u) { $u = 'none' }
    $r = ($Result -replace '[^a-z0-9-]', '').ToLowerInvariant(); if (-not $r) { $r = 'failed' }
    'SUPPORT-GRANT action={0} level={1} until={2} result={3}' -f $a, $l, $u, $r
}

function ConvertFrom-SISupportGrantMessage {
    <#
        PURE. One queue message's text -> @{ Ok; Why; Action; Level; MaxUntilUtc; Reason; Ticket; StartedBy }. Refused (Ok
        false, Why in plain words) when: larger than 4 KB, not ONE JSON object, a key that is not in the list, a value that
        is not text, a required key missing, an action / level not in the list, maxUntil not an ISO-8601 UTC time, in the
        past or more than 8 hours ahead, a reason empty or longer than 200 characters, a ticket or a name with control
        characters or too long. Nothing in it is ever run.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][datetime]$NowUtc)
    $c = $script:SISupportGrantJob
    $no = { param($w) [pscustomobject]@{ Ok = $false; Why = $w; Action = ''; Level = ''; MaxUntilUtc = $null; Reason = ''; Ticket = ''; StartedBy = '' } }
    if ($null -eq $Text -or -not $Text.Trim()) { return (& $no 'the message is empty') }
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt $c.MaxMessageBytes) { return (& $no ('the message is larger than {0} bytes' -f $c.MaxMessageBytes)) }
    $t = $Text.Trim()
    if (-not $t.StartsWith('{') -or -not $t.EndsWith('}')) { return (& $no 'the message is not one JSON object (raw JSON, not base64)') }
    # the values EXACTLY as sent: PowerShell 7's ConvertFrom-Json turns a time text into a date (and loses how it was
    # written), so the JSON is read with System.Text.Json where it is there (PowerShell 7), else ConvertFrom-Json (5.1)
    $vals = @{}
    $pairs = [System.Collections.Generic.List[object]]::new()
    if ('System.Text.Json.JsonDocument' -as [type]) {
        $doc = $null
        try { $doc = [System.Text.Json.JsonDocument]::Parse($t) } catch { return (& $no 'the message is not valid JSON') }
        try {
            if ($doc.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return (& $no 'the message is not one JSON object') }
            foreach ($p in $doc.RootElement.EnumerateObject()) {
                $isText = ($p.Value.ValueKind -eq [System.Text.Json.JsonValueKind]::String)
                $isNull = ($p.Value.ValueKind -eq [System.Text.Json.JsonValueKind]::Null)
                $pairs.Add([pscustomobject]@{ Name = [string]$p.Name; Text = $(if ($isText) { $p.Value.GetString() } else { '' }); Ok = ($isText -or $isNull) })
            }
        } finally { $doc.Dispose() }
    } else {
        $o = $null
        try { $o = $t | ConvertFrom-Json -ErrorAction Stop } catch { return (& $no 'the message is not valid JSON') }
        if ($null -eq $o -or $o -isnot [pscustomobject]) { return (& $no 'the message is not one JSON object') }
        foreach ($p in $o.PSObject.Properties) { $pairs.Add([pscustomobject]@{ Name = [string]$p.Name; Text = [string]$p.Value; Ok = ($null -eq $p.Value -or $p.Value -is [string]) }) }
    }
    foreach ($p in $pairs) {
        if ($c.Keys -cnotcontains $p.Name) { return (& $no ('the key {0} is not part of a support request' -f ($p.Name -replace '[^\w.-]', '?'))) }
        if ($vals.ContainsKey($p.Name)) { return (& $no ('{0} is given twice' -f $p.Name)) }
        if (-not $p.Ok) { return (& $no ('{0} must be text' -f $p.Name)) }
        $vals[$p.Name] = $p.Text
    }
    foreach ($k in $c.Required) { if (-not $vals.ContainsKey($k) -or -not $vals[$k].Trim()) { return (& $no ('{0} is missing' -f $k)) } }
    $ctl = '[\x00-\x1F\x7F]'
    $action = $vals['SI_SUPPORT_ACTION'].Trim().ToLowerInvariant()
    if ($action -notin 'open', 'close') { return (& $no 'SI_SUPPORT_ACTION must be open or close') }
    $level = $vals['SI_SUPPORT_LEVEL'].Trim().ToLowerInvariant()
    if ($level -notin 'troubleshoot', 'setup') { return (& $no 'SI_SUPPORT_LEVEL must be troubleshoot or setup') }
    $mu = $vals['SI_SUPPORT_MAXUNTIL'].Trim()
    if ($mu -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|\+00:00)$') { return (& $no 'SI_SUPPORT_MAXUNTIL must be an ISO-8601 UTC time (ending in Z)') }
    $until = [datetime]::MinValue
    if (-not [datetime]::TryParse($mu, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$until)) { return (& $no 'SI_SUPPORT_MAXUNTIL is not a valid time') }
    $until = [datetime]::SpecifyKind($until.AddTicks(-($until.Ticks % [TimeSpan]::TicksPerSecond)), 'Utc')
    $now = $NowUtc.ToUniversalTime()
    if ($until -le $now) { return (& $no 'SI_SUPPORT_MAXUNTIL is in the past') }
    if ($until -gt $now.AddHours($c.MaxHours).AddMinutes($c.ClockSlackMinutes)) { return (& $no ('SI_SUPPORT_MAXUNTIL is more than {0} hours ahead' -f $c.MaxHours)) }
    $reason = $vals['SI_SUPPORT_REASON'].Trim()
    if ($reason.Length -gt 200 -or $reason -match $ctl) { return (& $no 'SI_SUPPORT_REASON must be 1-200 characters of text') }
    $ticket = if ($vals.ContainsKey('SI_SUPPORT_TICKET')) { $vals['SI_SUPPORT_TICKET'].Trim() } else { '' }
    if ($ticket.Length -gt 64 -or $ticket -match $ctl) { return (& $no 'SI_SUPPORT_TICKET must be at most 64 characters of text') }
    $by = if ($vals.ContainsKey('SI_AUDIT_STARTED_BY')) { $vals['SI_AUDIT_STARTED_BY'].Trim() } else { '' }
    if ($by.Length -gt 256 -or $by -match $ctl) { return (& $no 'SI_AUDIT_STARTED_BY must be at most 256 characters of text') }
    [pscustomobject]@{ Ok = $true; Why = ''; Action = $action; Level = $level; MaxUntilUtc = $until; Reason = $reason; Ticket = $ticket; StartedBy = $by }
}

function Select-SISupportGrantMessage {
    <#
        PURE. The request among the messages read (@{ Id; Inserted (UTC); Text }): the NEWEST one that is not older than 15
        minutes. Returns @{ Message (or $null); Dropped = @(@{ Id; Why }) } -- every other message, with why it was not used.
    #>
    param([AllowEmptyCollection()][object[]]$Messages = @(), [Parameter(Mandatory)][datetime]$NowUtc)
    $limit = $NowUtc.ToUniversalTime().AddMinutes(-$script:SISupportGrantJob.StaleMinutes)
    $all = @($Messages | Where-Object { $null -ne $_ } | Sort-Object { [datetime]$_.Inserted } -Descending)
    $pick = $null; $dropped = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $all) {
        $at = ([datetime]$m.Inserted).ToUniversalTime()
        if ($at -lt $limit) { $dropped.Add([pscustomobject]@{ Id = [string]$m.Id; Why = ('older than {0} minutes (put on the queue {1})' -f $script:SISupportGrantJob.StaleMinutes, (Format-SISupportGrantUtc $at)) }); continue }
        if ($null -eq $pick) { $pick = $m; continue }
        $dropped.Add([pscustomobject]@{ Id = [string]$m.Id; Why = 'a newer request came after it' })
    }
    [pscustomobject]@{ Message = $pick; Dropped = $dropped.ToArray() }
}

function ConvertFrom-SISupportGrantQueueXml {
    <# PURE. The Get Messages answer of Azure Queue storage -> @(@{ Id; PopReceipt; Inserted; Text }). #>
    param([AllowNull()][AllowEmptyString()][string]$Xml)
    if (-not "$Xml".Trim()) { return @() }
    $x = [xml]($Xml -replace '^﻿', '')
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @($x.QueueMessagesList.QueueMessage)) {
        if ($null -eq $m) { continue }
        $ins = [datetime]::UtcNow
        try { $ins = [datetime]::Parse([string]$m.InsertionTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') } catch { }
        $out.Add([pscustomobject]@{ Id = [string]$m.MessageId; PopReceipt = [string]$m.PopReceipt; Inserted = $ins; Text = [string]$m.MessageText })
    }
    , $out.ToArray()
}

function Read-SISupportGrantRow {
    <# The first row a procedure answered through a { param($Sql, $Params, $Mode) } seam (mode 'rows'). Throws on a failure. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    @(& $Invoke $Sql $Params 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
}

function Get-SISupportGrantRowValue {
    <# PURE. One column of a row (hashtable / PSObject / DataRow), '' when not there or NULL. #>
    param($Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return '' }
    $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$Name] } elseif ($Row -is [System.Data.DataRow]) { $Row[$Name] } elseif ($Row.PSObject.Properties[$Name]) { $Row.$Name } else { $null }
    if ($null -eq $v -or $v -is [System.DBNull]) { '' } else { [string]$v }
}

function Invoke-SISupportGrantSweep {
    <#
        THE SWEEP on every product database (-Databases: ordered @{ <database> = { param($Sql, $Params, $Mode) } }): a grant
        past its maxUntil is revoked. Used by the grant job on every start and by the heartbeat on every tick. NEVER throws.
        Returns @{ Closed; RolesRemoved; Failed = @(<database: why>); NotReady = @(<database>); Lines = @() } -- a database
        without the procedures (an install the admin step has not reached) is NotReady, never a failure.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Databases, [string]$By = 'sweep')
    $closed = 0; $removed = 0; $failed = New-Object System.Collections.Generic.List[string]; $notReady = New-Object System.Collections.Generic.List[string]
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($db in @($Databases.Keys)) {
        try {
            $row = Read-SISupportGrantRow -Invoke $Databases[$db] -Sql (Get-SISupportGrantCallSql -Name Sweep) -Params @{ By = $By }
            $c = 0; [void][int]::TryParse((Get-SISupportGrantRowValue $row 'Closed'), [ref]$c)
            $r = 0; [void][int]::TryParse((Get-SISupportGrantRowValue $row 'RolesRemoved'), [ref]$r)
            $closed += $c; $removed += $r
            if ($c) { $lines.Add(('{0}: {1} expired support grant marker(s) closed, {2} role membership(s) removed' -f $db, $c, $r)) }
            if ((Get-SISupportGrantRowValue $row 'ReadOnlyHeld') -eq '0' -and (Get-SISupportGrantRowValue $row 'UserPresent') -eq '1') { $lines.Add(('{0}: WARNING the Support app is not in its read-only role -- support may have lost its standing access' -f $db)) }
        } catch {
            $w = Get-SISupportGrantErrorResult $_
            if ($w -eq 'not-prepared') { $notReady.Add([string]$db) } else { $failed.Add(('{0}: {1}' -f $db, $_.Exception.Message)) }
        }
    }
    foreach ($f in $failed) { $lines.Add(('the support grant sweep failed -- {0} (tried again on the next tick)' -f $f)) }
    [pscustomobject]@{ Closed = $closed; RolesRemoved = $removed; Failed = $failed.ToArray(); NotReady = $notReady.ToArray(); Lines = $lines.ToArray() }
}

function Get-SISupportGrantStatus {
    <#
        READ ONLY. cfg.SupportGrantStatus on every product database -> @{ Wire; Text; Rows }. Wire = the heartbeat's JIT shape
        of supportSqlAccess { readOnly, jitOpen, jitUntil, jitLevel, checkedUtc } (sent only where its switch says so);
        $null when no database answered. NEVER throws.
          readOnly  true = in EVERY database the Support app's user is in the read-only role AND the grant procedures are
                    there and signed (the path that opens a session works); false = not so in one (no role, no procedures,
                    or not signed); null = at least one could not be read and none was read as missing
          jitOpen   a grant is open in any database;  jitUntil its latest maxUntil;  jitLevel setup | troubleshoot | null
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Databases, [Parameter(Mandatory)][datetime]$NowUtc)
    $rows = [System.Collections.Generic.List[object]]::new(); $said = New-Object System.Collections.Generic.List[string]
    $unknown = 0; $missing = 0; $open = $false; $until = $null; $level = $null
    foreach ($db in @($Databases.Keys)) {
        try {
            $r = Read-SISupportGrantRow -Invoke $Databases[$db] -Sql (Get-SISupportGrantCallSql -Name Status)
            # no procedures in this database is MISSING, not unknown: it was read, and the grant is not there (seen live
            # 2026-11-05: the Pro database had them, the identity database not -- the heartbeat said unknown)
            if ($null -eq $r) { $missing++; $said.Add(('{0}: no support grant procedures yet' -f $db)); continue }
            $rows.Add($r)
            # readOnly true = the just-in-time model is in place: the read role held AND the grant procedures present and SIGNED
            # (the path that opens a session works) -- Invardia's rule for every product (framework, PIM the same)
            if ((Get-SISupportGrantRowValue $r 'ReadOnlyHeld') -ne '1' -or (Get-SISupportGrantRowValue $r 'Signed') -ne '1') { $missing++ }
            $n = 0; [void][int]::TryParse((Get-SISupportGrantRowValue $r 'JitOpen'), [ref]$n)
            if ($n -gt 0) {
                $open = $true
                $u = Get-SISupportGrantRowValue $r 'JitUntilUtc'; if ($u -and (-not $until -or $u -gt $until)) { $until = $u }
                $lv = Get-SISupportGrantRowValue $r 'JitLevel'; if ($lv -eq 'setup' -or -not $level) { $level = $lv }
            }
            $over = Get-SISupportGrantRowValue $r 'JitOverdue'; $stand = Get-SISupportGrantRowValue $r 'StandingOwner'
            $said.Add(('{0}: read-only {1}, {2}{3}{4}' -f $db, $(if ((Get-SISupportGrantRowValue $r 'ReadOnlyHeld') -eq '1') { 'yes' } else { 'NO' }),
                $(if ($n -gt 0) { 'a support grant is open until ' + (Get-SISupportGrantRowValue $r 'JitUntilUtc') } else { 'no support grant open' }),
                $(if ($over -and $over -ne '0') { ' -- OVERDUE (past maxUntil, not revoked yet)' } else { '' }),
                $(if ($stand -eq '1') { ' -- the Support app holds db_owner outside a support grant' } else { '' })))
        } catch { $unknown++; $said.Add(('{0}: could not be read ({1})' -f $db, $_.Exception.Message)) }
    }
    if (-not $rows.Count) { return [pscustomobject]@{ Wire = $null; Text = ('support grant: not known -- {0}' -f ($said.ToArray() -join '; ')); Rows = @() } }
    $ro = $(if ($missing) { $false } elseif ($unknown) { $null } else { $true })
    $wire = [ordered]@{ readOnly = $ro; jitOpen = $open; jitUntil = $(if ($until) { $until } else { $null }); jitLevel = $(if ($level) { $level } else { $null })
                        checkedUtc = (Format-SISupportGrantUtc $NowUtc) }
    [pscustomobject]@{ Wire = $wire; Text = ('support grant: {0}' -f ($said.ToArray() -join '; ')); Rows = $rows.ToArray() }
}

function Invoke-SISupportGrantJob {
    <#
        THE JOB (see the header). Seams (tests pass fakes; Invoke-SISupportGrant.ps1 the real ones):
          -Databases  ordered @{ <database> = { param($Sql, $Params, $Mode) } } -- the Pro database FIRST
          -Receive    { } -> @(@{ Id; PopReceipt; Inserted; Text }) -- every message on the queue (read, not yet deleted)
          -Remove     { param($Message) } -- deletes one message; a failure is said, never a failed job
          -Say        { param([string]$Level, [string]$Text) }
          -Report     { param($Event) } -- the uplink event (only called where the switch is on; never throws upward)
        Returns @{ ExitCode; Result; Action; Level; Until; Line; Databases = @(rows) }. NEVER throws.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Databases, [Parameter(Mandatory)][scriptblock]$Receive, [scriptblock]$Remove,
          [Parameter(Mandatory)][datetime]$NowUtc, [scriptblock]$Say, [scriptblock]$Report)
    if (-not $Say) { $Say = { param($l, $t) } }
    $res = [ordered]@{ ExitCode = 2; Result = 'failed'; Action = ''; Level = ''; Until = $null; Line = ''; Databases = @() }
    $finish = {
        param($result)
        $res.Result = $result; $res.ExitCode = Get-SISupportGrantExitCode $result
        $res.Line = Get-SISupportGrantLogLine -Action $res.Action -Level $res.Level -Until $res.Until -Result $result
        if ($Report -and $res.Action) {
            $ev = if ($result -eq 'ok' -and $res.Action -eq 'open') { 'support.granted' } elseif ($result -eq 'ok') { 'support.revoked' } else { 'support.grant-failed' }
            try { & $Report ([pscustomobject][ordered]@{ event = $ev; action = $res.Action; level = $(if ($res.Level) { $res.Level } else { $null }); untilUtc = $(if ($res.Until) { Format-SISupportGrantUtc $res.Until } else { $null }); result = $result; atUtc = (Format-SISupportGrantUtc $NowUtc) }) } catch { }
        }
        [pscustomobject]$res
    }
    try {
        # 1. the sweep first: an expired grant is revoked whatever the message says
        $sw = Invoke-SISupportGrantSweep -Databases $Databases -By $script:SISupportGrantJob.Job
        foreach ($l in $sw.Lines) { & $Say $(if ($l -match 'failed|WARNING') { 'WARN' } else { 'INFO' }) $l }

        # 2. every message is read and deleted; the newest fresh one is the request
        $msgs = @()
        try { $msgs = @(& $Receive) } catch { & $Say 'WARN' ('the support request queue could not be read ({0})' -f $_.Exception.Message); return (& $finish 'no-request') }
        # #1154: the QUEUE starts this job, so an empty queue is no request at all -- the execution that started for the same
        # message took it first (the scaler may start one more while the first reads). Nothing was asked of this execution:
        # it ends ok and writes NO SUPPORT-GRANT line (the line answers a request; this one has none to answer).
        if (-not $msgs.Count) {
            & $Say 'INFO' 'no support request on the queue -- another execution has answered it; nothing to do'
            $res.Result = 'empty'; $res.ExitCode = 0; $res.Line = ''
            return [pscustomobject]$res
        }
        foreach ($m in $msgs) { if ($Remove) { try { & $Remove $m } catch { & $Say 'WARN' ('a support request could not be deleted from the queue ({0}) -- it is ignored after {1} minutes' -f $_.Exception.Message, $script:SISupportGrantJob.StaleMinutes) } } }
        $pick = Select-SISupportGrantMessage -Messages $msgs -NowUtc $NowUtc
        foreach ($d in $pick.Dropped) { & $Say 'INFO' ('a support request was not used: {0}' -f $d.Why) }
        if (-not $pick.Message) { & $Say 'WARN' 'no support request on the queue (a start without a fresh request does nothing)'; return (& $finish 'no-request') }
        $req = ConvertFrom-SISupportGrantMessage -Text ([string]$pick.Message.Text) -NowUtc $NowUtc
        if (-not $req.Ok) {
            # what the request asked is told only when it could be read -- never a value of a refused one
            & $Say 'WARN' ('the support request was refused: {0}' -f $req.Why); return (& $finish 'bad-request')
        }
        $res.Action = $req.Action
        $rid = [guid]::Empty
        if (-not [guid]::TryParse([string]$pick.Message.Id, [ref]$rid)) { $rid = [guid]::NewGuid() }
        $p = @{ RequestId = $rid.ToString(); Reason = $req.Reason; StartedBy = $req.StartedBy }
        & $Say 'INFO' ('support request: {0} at level {1} until {2} -- {3}{4}' -f $req.Action, $req.Level, (Format-SISupportGrantUtc $req.MaxUntilUtc), $req.Reason, $(if ($req.Ticket) { ' (ticket ' + $req.Ticket + ')' } else { '' }))

        $rows = [System.Collections.Generic.List[object]]::new()
        if ($req.Action -eq 'open') {
            $p['Level'] = $req.Level; $p['MaxUntilUtc'] = (Format-SISupportGrantUtc $req.MaxUntilUtc); $p['Ticket'] = $req.Ticket
            $opened = New-Object System.Collections.Generic.List[string]
            $fail = ''
            foreach ($db in @($Databases.Keys)) {
                try {
                    $row = Read-SISupportGrantRow -Invoke $Databases[$db] -Sql (Get-SISupportGrantCallSql -Name Open) -Params $p
                    $rows.Add($row); $opened.Add([string]$db)
                    if ((Get-SISupportGrantRowValue $row 'RoleHeld') -ne '1') { $fail = 'failed'; & $Say 'WARN' ('{0}: the grant does not read back (the role is not held)' -f $db); break }
                    & $Say 'INFO' ('{0}: {1} ({2}) until {3}, read back' -f $db, (Get-SISupportGrantRowValue $row 'LevelGranted'), (Get-SISupportGrantRowValue $row 'RoleName'), (Get-SISupportGrantRowValue $row 'UntilUtc'))
                } catch {
                    $fail = Get-SISupportGrantErrorResult $_
                    & $Say 'WARN' ('{0}: the support grant could not be opened -- {1}' -f $db, $_.Exception.Message)
                    break
                }
            }
            if ($fail) {
                # never a half grant: what was opened is closed again
                $cp = @{ RequestId = [guid]::NewGuid().ToString(); Reason = ('rolled back: the grant failed ({0})' -f $fail); StartedBy = $script:SISupportGrantJob.Job }
                foreach ($db in $opened) {
                    try { $null = Read-SISupportGrantRow -Invoke $Databases[$db] -Sql (Get-SISupportGrantCallSql -Name Close) -Params $cp; & $Say 'INFO' ('{0}: rolled back' -f $db) }
                    catch { & $Say 'WARN' ('{0}: the roll-back failed ({1}) -- the grant there ends at its maxUntil' -f $db, $_.Exception.Message) }
                }
                $res.Databases = $rows.ToArray()
                return (& $finish $fail)
            }
            $first = $rows[0]
            $res.Level = Get-SISupportGrantRowValue $first 'LevelGranted'
            $res.Until = Get-SISupportGrantRowValue $first 'UntilUtc'
            if ($res.Level -ne $req.Level) { & $Say 'INFO' ('the request asked for {0}; the customer consented to {1} -- {1} was granted' -f $req.Level, $res.Level) }
            $res.Databases = $rows.ToArray()
            return (& $finish 'ok')
        }

        # close: every database, each on its own
        $bad = ''
        foreach ($db in @($Databases.Keys)) {
            try {
                $row = Read-SISupportGrantRow -Invoke $Databases[$db] -Sql (Get-SISupportGrantCallSql -Name Close) -Params $p
                $rows.Add($row)
                if ((Get-SISupportGrantRowValue $row 'RolesStillHeld') -notin '', '0') { $bad = 'failed'; & $Say 'WARN' ('{0}: a role is still held after the close' -f $db) }
                else { & $Say 'INFO' ('{0}: closed ({1} marker(s), {2} role membership(s) removed, {3} session(s) ended), read back' -f $db, (Get-SISupportGrantRowValue $row 'Closed'), (Get-SISupportGrantRowValue $row 'RolesRemoved'), (Get-SISupportGrantRowValue $row 'SessionsEnded')) }
                if ((Get-SISupportGrantRowValue $row 'UserPresent') -eq '1' -and (Get-SISupportGrantRowValue $row 'ReadOnlyHeld') -ne '1') { & $Say 'WARN' ('{0}: WARNING the Support app is not in its read-only role' -f $db) }
            } catch {
                $w = Get-SISupportGrantErrorResult $_
                if (-not $bad) { $bad = $w }
                & $Say 'WARN' ('{0}: the support grant could not be closed -- {1} (it ends at its maxUntil; the sweep retries)' -f $db, $_.Exception.Message)
            }
        }
        $res.Level = $req.Level
        $res.Until = (Format-SISupportGrantUtc $NowUtc)
        $res.Databases = $rows.ToArray()
        if ($bad) { return (& $finish $bad) }
        & $finish 'ok'
    } catch {
        & $Say 'WARN' ('the support grant job failed: {0}' -f $_.Exception.Message)
        & $finish 'failed'
    }
}

function Get-SISupportGrantDatabases {
    <#
        The install's product databases, the Pro database FIRST (it holds the consent): ordered @{ <database> = seam }, each
        signed in as the job (New-SIRecordSqlInvoke). The identity ledger and the data database where the install has them
        (each on its own server setting); the same database twice is once. Empty when no Pro database is configured.
    #>
    $out = [ordered]@{}
    $proSrv = [string]$global:SI_ProSqlServer; $proDb = [string]$global:SI_ProSqlDatabase
    if (-not $proSrv.Trim() -or -not $proDb.Trim()) { return $out }
    $out[$proDb] = New-SIRecordSqlInvoke -Server $proSrv -Database $proDb
    $ledSrv = $(if ([string]$global:SI_LedgerSqlServer) { [string]$global:SI_LedgerSqlServer } else { $proSrv })
    if ([string]$global:SI_LedgerDatabase -and -not $out.Contains([string]$global:SI_LedgerDatabase)) { $out[[string]$global:SI_LedgerDatabase] = New-SIRecordSqlInvoke -Server $ledSrv -Database ([string]$global:SI_LedgerDatabase) }
    $datSrv = $(if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { $proSrv })
    if ([string]$global:SI_Pro_DataSqlDatabase -and -not $out.Contains([string]$global:SI_Pro_DataSqlDatabase)) { $out[[string]$global:SI_Pro_DataSqlDatabase] = New-SIRecordSqlInvoke -Server $datSrv -Database ([string]$global:SI_Pro_DataSqlDatabase) }
    $out
}

function Resolve-SIUplinkSupportGrantSwitch {
    <# PURE. Do the support grant's uplink events go out (SI_Uplink_SendSupportGrant / SI_UPLINK_SENDSUPPORTGRANT)? OFF until
       Invardia has agreed the wire: 'auto' confirms no ring. on / off / a ring list as every uplink switch. #>
    param([AllowNull()]$Value = $global:SI_Uplink_SendSupportGrant, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_UPLINK_SENDSUPPORTGRANT, [AllowNull()]$Ring)
    $rn = -1; if ($null -ne $Ring -and "$Ring".Trim() -ne '') { if (-not [int]::TryParse("$Ring", [ref]$rn)) { $rn = -1 } }
    $set = ''
    foreach ($v in @($Value, $EnvValue)) { if ($null -eq $v) { continue }; if ($v -is [bool]) { $set = $(if ($v) { 'on' } else { 'off' }); break }; $s = ([string]$v).Trim().ToLowerInvariant(); if ($s) { $set = $s; break } }
    if ($set -in 'on', 'true', 'yes', 'enabled') { return [pscustomobject]@{ On = $true; Reason = 'SI_Uplink_SendSupportGrant is on' } }
    if ($set -match '^(ring\s*)?[0-3](\s*[,;]\s*(ring\s*)?[0-3])*$') { $rings = @([regex]::Matches($set, '[0-3]') | ForEach-Object { [int]$_.Value }); return [pscustomobject]@{ On = ($rn -ge 0 -and $rings -contains $rn); Reason = 'SI_Uplink_SendSupportGrant: rings ' + ($rings -join ', ') } }
    [pscustomobject]@{ On = $false; Reason = 'SI_Uplink_SendSupportGrant waits until Invardia has agreed the support grant events' }
}
