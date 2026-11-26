#Requires -Version 5.1
<#
    SECURITYINSIGHT -- THE JOB REQUEST JOB caj-si-job-requests (#1252, SECURE-WEB-1 part 2; owner 2026-11-25 "Build queue fix
    now"). Since 3.1.18 the internet-facing web app holds no right on any job (a start right alone accepts a container
    override, so it would let the web run its own command as the engine identity). Its buttons -- Run now (the pipeline, a
    stage, a step, a single job), Stop (cancel the running run), the schedule / enable edits (cfg.JobTriggerRequest rows the
    pipeline runner applies, woken here), a template release, a mail "send now" -- now put ONE message on the queue
    si-job-requests of the install's own storage account (the web identity's ONE new right: Storage Queue Data Message Sender
    on that queue only). THE QUEUE STARTS THIS JOB (an event trigger, the azure-queue scaler signed in as the engine identity
    -- the same trigger as caj-si-support-grant), and this job starts the asked job AS THE ENGINE IDENTITY with its EXISTING
    rights (Container Apps Jobs Contributor on the install's resource group, Storage Queue Data Contributor on the account).

    THE MESSAGE IS A REQUEST, NEVER AN INSTRUCTION. Raw JSON (not base64), at most 8 KB, only these keys:
        SI_JOBREQ_ACTION     start                                                 required
        SI_JOBREQ_JOB        the job's name: one of THIS install's caj-si-* jobs   required
        SI_JOBREQ_ENV        a JSON object name -> text: the values for this ONE execution; only the names allowed for that
                             job (Get-SIJobRequestAllowed: engine\_shared\SI-JobStartRequest.ps1's list + the few below)
        SI_JOBREQ_ID         the web app's request id (said in the log line), at most 64 characters   optional
        SI_AUDIT_STARTED_BY  the signed-in person who asked, at most 256 characters                   optional
    Refused (said, with why, one line per message): older than 15 minutes on the queue (the queue's own insertion time),
    not one JSON object, an unknown key, a job that is not one of this install's jobs (or this job itself), a name not
    allowed for that job, a value longer than 1000 characters or with control characters. No value is ever run: a start
    with values carries the job's OWN container (image, command, arguments, every variable kept) plus the allowed values.

    THE JOB, in order (Invoke-SIJobRequestsJob): every message on the queue is read and DELETED; then each is answered ON
    ITS OWN, oldest first (#1356: never a batch as one item; one bad message never blocks the others). ONE log line per
    message -- exactly
        JOB-REQUEST id=<request id|message id> job=<job|none> by=<who|unknown> result=<started|refused|failed> detail=<words>
    An empty queue (another execution the scaler started took the messages) ends ok with no line. Exit 0; 2 = the queue could
    not be read. PURE except the seams. Strict-mode safe; PS 5.1 and 7.
#>

if (-not (Get-Command -Name Get-SIJobStartRequestAllowed -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-JobStartRequest.ps1'))
}

$script:SIJobRequestsJob = [ordered]@{
    Job             = 'caj-si-job-requests'
    Queue           = 'si-job-requests'
    MaxMessageBytes = 8192
    StaleMinutes    = 15
    MaxValueLength  = 1000
    Keys            = @('SI_JOBREQ_ACTION', 'SI_JOBREQ_JOB', 'SI_JOBREQ_ENV', 'SI_JOBREQ_ID', 'SI_AUDIT_STARTED_BY')
    Actions         = @('start')
}

# The names the web app's buttons send that SI-JobStartRequest.ps1's list does not carry (that list is what a job's OWN
# entrypoint takes from a database row; these reach the execution as real variables): Stop = the pipeline runner started
# with the cancel of the running run (#700); the mail check's verify run; the updater's short "apply settings" run.
$script:SIJobRequestsExtraAllowed = @{
    'flow'            = @('SI_FLOW_CANCEL', 'SI_FLOW_CANCEL_RUN', 'SI_FLOW_CANCEL_REASON', 'SI_FLOW_CANCEL_RUNNER')
    'close-loop-mail' = @('SI_MAIL_VERIFY')
    'updater'         = @('SI_UPDATER_MODE')
    # #1391: the Resend page (Pages/Admin/Resend.cshtml.cs -- "Send this collection again" / "Undo the last run") starts the
    # connector's own job (SendConnector.Job) with EXACTLY these four names, read by engine\asset-cmdb\_shared\SI-CollectionSend.ps1
    'asset-vulnerabilities'      = @('SI_VulnSync_SendId', 'SI_VulnSync_Connector', 'SI_VulnSync_CollectionTime', 'SI_VulnSync_UndoRunId')
    'asset-vulns-servicenow'     = @('SI_VulnSync_SendId', 'SI_VulnSync_Connector', 'SI_VulnSync_CollectionTime', 'SI_VulnSync_UndoRunId')
}
# #1391: the ONLY names outside the upper-case shape a request may carry -- exactly the Resend page's four, by name (never a
# pattern); every other mixed-case name is still refused as "not an environment variable name"
$script:SIJobRequestsExactNames = @('SI_VulnSync_SendId', 'SI_VulnSync_Connector', 'SI_VulnSync_CollectionTime', 'SI_VulnSync_UndoRunId')
# a value that must be one of a few words
$script:SIJobRequestsValueRules = @{ 'SI_UPDATER_MODE' = '^apply-settings$' }

function Get-SIJobRequestsContract { $script:SIJobRequestsJob }

function Get-SIJobRequestAllowed {
    <# PURE. The names a request may set on job -Job (caj-si-<x> or <x>): the start-request list + the extras above. #>
    param([string]$Job)
    $key = ([string]$Job) -replace '^caj-si-', ''
    $names = @(Get-SIJobStartRequestAllowed -Job $Job)
    if ($script:SIJobRequestsExtraAllowed.ContainsKey($key)) { $names += @($script:SIJobRequestsExtraAllowed[$key]) }
    @($names | Select-Object -Unique)
}

function Get-SIJobRequestLogLine {
    <# PURE. THE line per message (never change its shape): JOB-REQUEST id=.. job=.. by=.. result=.. detail=.. #>
    param([string]$Id, [string]$Job, [string]$By, [Parameter(Mandatory)][string]$Result, [string]$Detail)
    $clean = { param($v, $d) $x = (([string]$v) -replace '[\x00-\x1F\x7F]', ' ').Trim(); if (-not $x) { $d } else { $x -replace '\s', '_' } }
    'JOB-REQUEST id={0} job={1} by={2} result={3} detail={4}' -f (& $clean $Id 'none'), (& $clean $Job 'none'), (& $clean $By 'unknown'), $Result,
        ((([string]$Detail) -replace '[\x00-\x1F\x7F]', ' ').Trim())
}

function ConvertFrom-SIJobRequestJson {
    <# PURE. One JSON object -> ordered pairs @(@{ Name; Kind (text | object | null | other); Text; Pairs }); throws on bad JSON
       or when it is not an object. System.Text.Json where it is there (values exactly as sent), else ConvertFrom-Json. #>
    param([Parameter(Mandatory)][string]$Text)
    $out = [System.Collections.Generic.List[object]]::new()
    if ('System.Text.Json.JsonDocument' -as [type]) {
        $doc = [System.Text.Json.JsonDocument]::Parse($Text)
        try {
            if ($doc.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'not one JSON object' }
            foreach ($p in $doc.RootElement.EnumerateObject()) {
                $k = $p.Value.ValueKind
                if ($k -eq [System.Text.Json.JsonValueKind]::String) { $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'text'; Text = $p.Value.GetString(); Pairs = @() }) }
                elseif ($k -eq [System.Text.Json.JsonValueKind]::Null) { $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'null'; Text = ''; Pairs = @() }) }
                elseif ($k -eq [System.Text.Json.JsonValueKind]::Object) {
                    $inner = [System.Collections.Generic.List[object]]::new()
                    foreach ($q in $p.Value.EnumerateObject()) {
                        $isText = ($q.Value.ValueKind -eq [System.Text.Json.JsonValueKind]::String)
                        $inner.Add([pscustomobject]@{ Name = [string]$q.Name; Kind = $(if ($isText) { 'text' } else { 'other' }); Text = $(if ($isText) { $q.Value.GetString() } else { '' }); Pairs = @() })
                    }
                    $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'object'; Text = ''; Pairs = $inner.ToArray() })
                } else { $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'other'; Text = ''; Pairs = @() }) }
            }
        } finally { $doc.Dispose() }
    } else {
        $o = $Text | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $o -or $o -isnot [pscustomobject]) { throw 'not one JSON object' }
        foreach ($p in $o.PSObject.Properties) {
            $v = $p.Value
            if ($null -eq $v) { $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'null'; Text = ''; Pairs = @() }) }
            elseif ($v -is [string]) { $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'text'; Text = $v; Pairs = @() }) }
            elseif ($v -is [pscustomobject]) {
                $inner = @(foreach ($q in $v.PSObject.Properties) { [pscustomobject]@{ Name = [string]$q.Name; Kind = $(if ($q.Value -is [string]) { 'text' } else { 'other' }); Text = $(if ($q.Value -is [string]) { [string]$q.Value } else { '' }); Pairs = @() } })
                $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'object'; Text = ''; Pairs = $inner })
            } else { $out.Add([pscustomobject]@{ Name = [string]$p.Name; Kind = 'other'; Text = ''; Pairs = @() }) }
        }
    }
    , $out.ToArray()
}

function ConvertFrom-SIJobRequestMessage {
    <#
        PURE. One queue message's text -> @{ Ok; Why; Action; Job; Env (ordered); Id; StartedBy }. Ok false with why in plain
        words for anything that is not a well-formed request. Whether the JOB and its NAMES are allowed is decided by
        Get-SIJobRequestDecision (it needs the install's job list). Id / StartedBy are filled whenever they could be read.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $c = $script:SIJobRequestsJob
    $r = [pscustomobject]@{ Ok = $false; Why = ''; Action = ''; Job = ''; Env = [ordered]@{}; Id = ''; StartedBy = '' }
    $no = { param($w) $r.Why = $w; $r.Ok = $false; $r }
    if ($null -eq $Text -or -not $Text.Trim()) { return (& $no 'the message is empty') }
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt $c.MaxMessageBytes) { return (& $no ('the message is larger than {0} bytes' -f $c.MaxMessageBytes)) }
    $t = $Text.Trim()
    if (-not $t.StartsWith('{') -or -not $t.EndsWith('}')) { return (& $no 'the message is not one JSON object (raw JSON, not base64)') }
    $pairs = @()
    try { $pairs = @(ConvertFrom-SIJobRequestJson -Text $t | ForEach-Object { $_ }) } catch { return (& $no 'the message is not one valid JSON object') }
    $ctl = '[\x00-\x1F\x7F]'
    $seen = @{}
    $envPairs = $null
    foreach ($p in $pairs) {
        if ($c.Keys -cnotcontains $p.Name) { return (& $no ('the key {0} is not part of a job request' -f ($p.Name -replace '[^\w.-]', '?'))) }
        if ($seen.ContainsKey($p.Name)) { return (& $no ('{0} is given twice' -f $p.Name)) }
        $seen[$p.Name] = $true
        if ($p.Name -eq 'SI_JOBREQ_ENV') {
            if ($p.Kind -eq 'null') { continue }
            if ($p.Kind -ne 'object') { return (& $no 'SI_JOBREQ_ENV must be a JSON object of name -> text') }
            $envPairs = @($p.Pairs); continue
        }
        if ($p.Kind -notin 'text', 'null') { return (& $no ('{0} must be text' -f $p.Name)) }
        $v = ([string]$p.Text).Trim()
        switch ($p.Name) {
            'SI_JOBREQ_ID' { if ($v.Length -le 64 -and $v -notmatch $ctl) { $r.Id = $v } else { return (& $no 'SI_JOBREQ_ID must be at most 64 characters of text') } }
            'SI_AUDIT_STARTED_BY' { if ($v.Length -le 256 -and $v -notmatch $ctl) { $r.StartedBy = $v } else { return (& $no 'SI_AUDIT_STARTED_BY must be at most 256 characters of text') } }
            'SI_JOBREQ_ACTION' { $r.Action = $v.ToLowerInvariant() }
            'SI_JOBREQ_JOB' { $r.Job = $v }
        }
    }
    if (-not $r.Action) { return (& $no 'SI_JOBREQ_ACTION is missing') }
    if ($c.Actions -cnotcontains $r.Action) { return (& $no ('SI_JOBREQ_ACTION must be {0}' -f ($c.Actions -join ' or '))) }
    if (-not $r.Job) { return (& $no 'SI_JOBREQ_JOB is missing') }
    if ($r.Job -cnotmatch '^caj-si-[a-z0-9][a-z0-9-]{0,24}$') { $r.Job = ($r.Job -replace '[^\w.-]', '?'); return (& $no 'SI_JOBREQ_JOB is not a SecurityInsight job name') }
    foreach ($e in @($envPairs | Where-Object { $_ })) {
        if ($e.Kind -ne 'text') { return (& $no ('the value of {0} must be text' -f ($e.Name -replace '[^\w.-]', '?'))) }
        if ($e.Name -cnotmatch '^[A-Z][A-Z0-9_]{0,63}$' -and $script:SIJobRequestsExactNames -cnotcontains [string]$e.Name) { return (& $no ('{0} is not an environment variable name' -f ($e.Name -replace '[^\w.-]', '?'))) }
        if ($r.Env.Contains($e.Name)) { return (& $no ('{0} is given twice' -f $e.Name)) }
        $r.Env[$e.Name] = [string]$e.Text
    }
    $r.Ok = $true
    $r
}

function Get-SIJobRequestDecision {
    <#
        PURE. May this install start the request (ConvertFrom-SIJobRequestMessage's answer)? -Installed: the install's job
        names. Only a caj-si-* job of this install that is not this job itself; every value's name allowed for that job;
        every value at most 1000 characters, no control characters, and a value with a rule ($script:SIJobRequestsValueRules)
        matching it. @{ Ok; Why }.
    #>
    param([Parameter(Mandatory)]$Request, [AllowEmptyCollection()][string[]]$Installed = @())
    $c = $script:SIJobRequestsJob
    $job = [string]$Request.Job
    if ($job -ceq $c.Job) { return @{ Ok = $false; Why = 'this job does not start itself' } }
    if (@($Installed) -cnotcontains $job) { return @{ Ok = $false; Why = ('{0} is not one of this install''s jobs' -f $job) } }
    $allowed = @(Get-SIJobRequestAllowed -Job $job)
    foreach ($k in @($Request.Env.Keys)) {
        if ($allowed -cnotcontains [string]$k) { return @{ Ok = $false; Why = ('{0} may not be set on {1}' -f $k, $job) } }
        $v = [string]$Request.Env[$k]
        if ($v.Length -gt $c.MaxValueLength -or $v -match '[\x00-\x1F\x7F]') { return @{ Ok = $false; Why = ('the value of {0} must be at most {1} characters of text' -f $k, $c.MaxValueLength) } }
        if ($script:SIJobRequestsValueRules.ContainsKey([string]$k) -and $v -cnotmatch $script:SIJobRequestsValueRules[[string]$k]) { return @{ Ok = $false; Why = ('{0} has a value that is not allowed' -f $k) } }
    }
    @{ Ok = $true; Why = '' }
}

function ConvertTo-SIJobRequestMessageList {
    <# PURE. #1356: the messages read as ONE flat list (a read's batch is never one item), oldest first. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Messages = @())
    $out = [System.Collections.Generic.List[object]]::new()
    $add = $null
    $add = {
        param($Item)
        if ($null -eq $Item) { return }
        if ($Item -is [System.Collections.IEnumerable] -and $Item -isnot [string] -and $Item -isnot [System.Collections.IDictionary]) { foreach ($i in $Item) { & $add $i }; return }
        $out.Add($Item)
    }
    foreach ($m in @($Messages)) { & $add $m }
    $at = { param($m) try { ([datetime]$m.Inserted).ToUniversalTime() } catch { [datetime]::MinValue } }
    , @($out.ToArray() | Sort-Object -Property @{ Expression = { & $at $_ } }, @{ Expression = { [string]$_.Id } })
}

function Invoke-SIJobRequestsJob {
    <#
        THE JOB (see the header). Seams (tests pass fakes; Invoke-SIJobRequests.ps1 the real ones):
          -Receive   { } -> @(@{ Id; PopReceipt; Inserted (UTC); Text }) -- every message on the queue (read, not yet deleted)
          -Remove    { param($Message) } -- deletes one message; a failure is said, never a failed job
          -Installed { } -> the install's job names (read once, only when a message needs it)
          -Start     { param([string]$Job, [System.Collections.IDictionary]$Env) } -> the execution name (the engine identity)
          -Say       { param([string]$Level, [string]$Text) }
        Returns @{ ExitCode; Results = @(@{ Id; Job; By; Result; Detail }); Lines = @(the JOB-REQUEST lines) }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Receive, [scriptblock]$Remove, [Parameter(Mandatory)][scriptblock]$Installed,
          [Parameter(Mandatory)][scriptblock]$Start, [Parameter(Mandatory)][datetime]$NowUtc, [scriptblock]$Say)
    if (-not $Say) { $Say = { param($l, $t) } }
    $c = $script:SIJobRequestsJob
    $results = [System.Collections.Generic.List[object]]::new(); $lines = [System.Collections.Generic.List[string]]::new()
    $done = { param($code) [pscustomobject]@{ ExitCode = $code; Results = $results.ToArray(); Lines = $lines.ToArray() } }
    $answer = {
        param($id, $job, $by, $result, $detail)
        $results.Add([pscustomobject]@{ Id = $id; Job = $job; By = $by; Result = $result; Detail = $detail })
        $line = Get-SIJobRequestLogLine -Id $id -Job $job -By $by -Result $result -Detail $detail
        $lines.Add($line)
        & $Say $(if ($result -eq 'started') { 'INFO' } else { 'WARN' }) $line
    }
    $msgs = @()
    try { $msgs = @(ConvertTo-SIJobRequestMessageList -Messages @(& $Receive) | ForEach-Object { $_ }) }
    catch { & $Say 'WARN' ('the job request queue could not be read ({0})' -f $_.Exception.Message); return (& $done 2) }
    if (-not $msgs.Count) { & $Say 'INFO' 'no job request on the queue -- another execution has answered it; nothing to do'; return (& $done 0) }
    # every message is deleted FIRST: a request is answered once (a start that failed is the person's to ask again)
    foreach ($m in $msgs) { if ($Remove) { try { & $Remove $m } catch { & $Say 'WARN' ('a job request could not be deleted from the queue ({0}) -- it is refused as too old after {1} minutes' -f $_.Exception.Message, $c.StaleMinutes) } } }
    $limit = $NowUtc.ToUniversalTime().AddMinutes(-$c.StaleMinutes)
    $names = $null
    foreach ($m in $msgs) {
        $mid = [string]$m.Id
        # #1391: what is known of the request when something unforeseen breaks -- its id, kind, job and who asked are said
        # with the step it broke in, never only the bare error ("Cannot index into a null array" said nothing on 3.1.50)
        $req = $null; $at = 'reading the message'
        try {
            $req = ConvertFrom-SIJobRequestMessage -Text ([string]$m.Text)
            $at = 'checking the request'
            $id = if ($req.Id) { $req.Id } else { $mid }
            $when = [datetime]::MinValue; try { $when = ([datetime]$m.Inserted).ToUniversalTime() } catch { }
            if ($when -lt $limit) { & $answer $id $req.Job $req.StartedBy 'refused' ('older than {0} minutes (put on the queue {1})' -f $c.StaleMinutes, $(if ($when -eq [datetime]::MinValue) { 'at an unknown time' } else { $when.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) })); continue }
            if (-not $req.Ok) { & $answer $id $req.Job $req.StartedBy 'refused' $req.Why; continue }
            if ($null -eq $names) {
                try { $names = @(& $Installed | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
                catch { $names = $null; & $answer $id $req.Job $req.StartedBy 'failed' ('the install''s jobs could not be read: {0}' -f (([string]$_.Exception.Message) -split "`n")[0]); continue }
            }
            $at = 'deciding whether this install may start it'
            $d = Get-SIJobRequestDecision -Request $req -Installed $names
            if (-not $d.Ok) { & $answer $id $req.Job $req.StartedBy 'refused' $d.Why; continue }
            $exec = ''
            $at = 'starting the job'
            try { $exec = [string](& $Start $req.Job $req.Env) }
            catch { & $answer $id $req.Job $req.StartedBy 'failed' ('{0} could not be started: {1}' -f $req.Job, (([string]$_.Exception.Message) -split "`n")[0]); continue }
            $what = if ($req.Env.Count) { 'with ' + (@($req.Env.Keys) -join ', ') } else { 'as configured' }
            & $answer $id $req.Job $req.StartedBy 'started' ('execution {0} ({1})' -f $(if ($exec) { $exec } else { 'started' }), $what)
        } catch {
            $err = (([string]$_.Exception.Message) -split "`n")[0]
            $kid = $mid; $kjob = ''; $kby = ''; $kind = 'unknown'
            if ($null -ne $req) {
                if ($req.Id) { $kid = [string]$req.Id }
                $kjob = [string]$req.Job; $kby = [string]$req.StartedBy
                if ($req.Action) { $kind = [string]$req.Action }
            }
            $vals = if ($null -ne $req -and $req.Env -and $req.Env.Count) { 'with ' + (@($req.Env.Keys) -join ', ') } else { 'with no values' }
            & $answer $kid $kjob $kby 'failed' ('the request (kind {0}, {1}, queue message {2}) could not be answered -- SecurityInsight broke while {3}: {4}. Nothing was started; ask again, and if it repeats this is a SecurityInsight fault' -f $kind, $vals, $mid, $at, $err)
        }
    }
    & $done 0
}

function ConvertFrom-SIJobRequestQueueXml {
    <# PURE. The Get Messages answer of Azure Queue storage -> @(@{ Id; PopReceipt; Inserted; Text }) (the support grant's reader). #>
    param([AllowNull()][AllowEmptyString()][string]$Xml)
    if (-not "$Xml".Trim()) { return , @() }
    $x = [xml]($Xml -replace ('^' + [char]0xFEFF), '')
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @($x.QueueMessagesList.QueueMessage)) {
        if ($null -eq $m) { continue }
        # an insertion time that cannot be read is NOT "now": the request is refused as too old (never started on a guess)
        $ins = [datetime]::MinValue
        try { $ins = [datetime]::Parse([string]$m.InsertionTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') } catch { }
        $out.Add([pscustomobject]@{ Id = [string]$m.MessageId; PopReceipt = [string]$m.PopReceipt; Inserted = $ins; Text = [string]$m.MessageText })
    }
    , $out.ToArray()
}

function New-SIJobRequestStartBody {
    <# PURE. The body of POST .../jobs/<job>/start: {} for a start as configured, else the job's OWN container with the
       allowed values added (New-SIJobStartTemplate: image, command, arguments and every other variable kept). #>
    param($Job, [System.Collections.IDictionary]$Env = @{}, [string]$What = 'the job')
    if (-not $Env -or $Env.Count -eq 0) { return [ordered]@{} }
    New-SIJobStartTemplate -Job $Job -Env $Env -What $What
}
