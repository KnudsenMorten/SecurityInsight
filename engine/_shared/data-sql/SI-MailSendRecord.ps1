#Requires -Version 5.1
<#
    A MAIL GOES ONCE -- the send record and the queue claim (both editions).

    A step can run twice for the same work: the platform retries a job execution, a start is retried, a run is restarted
    or started by hand while the first is still going. Before this, two mails were not protected against that:
      * the Risk Analysis mail (one per run of the Summary / Detailed step) -- a second run of the step mailed again;
      * the vulnerability close-loop's daily mail -- a second run of the mail job on the same day mailed again.
    And the mail queues (cfg.ExemptionMail, cfg.SignInMail, cfg.ReportMail, cfg.GovernanceMail) were read and marked sent
    without a claim -- safe only because two mail jobs never ran at once.

    1. THE SEND RECORD (sidata.MailSendRecord, one row per mail that must go at most once, keyed by MailKey):
         Risk Analysis   'ra-<grain>|run:<pipeline run>'    (the pipeline run this step belongs to), or
                         'ra-<grain>|collection:<id>'       (a run outside the pipeline: its own collection)
         close-loop      'close-loop-daily|<yyyy-MM-dd>'    (the UTC day of the mail's schedule slot -- not the wall
                                                             clock: a slot run that starts late after midnight keeps its day)
       CLAIMED in one transaction (the row is read under an update lock and inserted or taken in the same statement), so
       two runs can never both send. The claimant marks it 'sent' right after the transport accepted the mail, or
       'queued' (the Risk Analysis mail kept in the Pro outbox -- the outbox sends it, once); a send that failed puts the
       record back to 'waiting'; a hold for an unreadable send right does the same and gives the try back. Who sends a
       'waiting' mail: for the close-loop, the next run of the job the same slot day; for Risk Analysis, only a second run
       of the step in the SAME pipeline run (a platform retry, a restart) -- the key is per pipeline run, so the next
       pipeline run does not resend it: it sends its own, newer mail (a waiting record holds no mail to send, and an older
       run's mail next to the newer one would only be a stale copy). The failed send is said in the run's log.
       A claim whose claimant died is taken again after the lease -- except one whose mail the server ACCEPTED but could
       not be marked ('sent, not marked'): that one is never sent again.
       FAIL OPEN (owner rule: a lost mail is worse than a rare duplicate): a record that cannot be read or written -- its
       database cannot be opened, the pipeline run cannot be read, the claim fails -- means the mail is SENT AS BEFORE, with
       one line that the send record could not be checked so a duplicate is possible. Only a definite "already sent / kept
       / being sent by another run" keeps a mail back. A database without the table yet (the updater adds it with the data
       schema) also sends as before, saying so: the engine identity has no right to create tables.
    2. THE QUEUE CLAIM: every queued row is claimed before it is sent (one UPDATE that sets ClaimedAt / ClaimedBy only when
       nobody holds it), so two senders never take the same row; a row that is not sent (a failure, a hold) is released for
       the next run. A queue table without the claim columns yet sends as before.
    PS 5.1 and 7; no module.
#>

$script:SIMailQueueTables = @('cfg.ExemptionMail', 'cfg.SignInMail', 'cfg.ReportMail', 'cfg.GovernanceMail')

# The same guarded, additive statement as the data schema (sql\si-data-schema.sql; a test holds the two equal).
function Get-SIMailSendRecordTableSql {
    @'
IF OBJECT_ID('sidata.MailSendRecord') IS NULL
CREATE TABLE sidata.MailSendRecord (
    MailKey      NVARCHAR(200)  NOT NULL CONSTRAINT PK_MailSendRecord PRIMARY KEY,
    Kind         NVARCHAR(32)   NOT NULL,
    State        NVARCHAR(16)   NOT NULL,
    ClaimedBy    NVARCHAR(200)  NULL,
    ClaimedAt    DATETIME2(3)   NULL,
    Attempts     INT            NOT NULL CONSTRAINT DF_MailSendRecord_Attempts DEFAULT 0,
    SentAt       DATETIME2(3)   NULL,
    OutboxMailId BIGINT         NULL,
    LastError    NVARCHAR(2000) NULL,
    CreatedAt    DATETIME2(3)   NOT NULL CONSTRAINT DF_MailSendRecord_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_MailSendRecord_State CHECK (State IN ('sending', 'sent', 'queued', 'waiting'))
);
'@
}

function Get-SIMailSendRecordClaimSql {
    <#
        THE CLAIM, one transaction: no row -> inserted 'sending' by @By; a 'waiting' row (a send that failed), or a 'sending'
        row whose claim is older than @LeaseMinutes (its claimant died, and it was not accepted by the server), -> taken by
        @By; this claimant's own row (a retried statement) -> still this claimant's. Anything else -> 'taken'. Answers
        Outcome (claimed | taken | no-table), State, OutboxMailId, SentAt, LastError.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.MailSendRecord') IS NULL
    SELECT N'no-table' AS Outcome, CAST(NULL AS nvarchar(16)) AS State, CAST(NULL AS bigint) AS OutboxMailId, CAST(NULL AS datetime2(3)) AS SentAt, CAST(NULL AS nvarchar(2000)) AS LastError;
ELSE
    EXEC sp_executesql N'SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @s nvarchar(16), @b0 nvarchar(200), @at datetime2(3), @e nvarchar(2000), @o nvarchar(16) = N''claimed'';
SELECT @s = State, @b0 = ClaimedBy, @at = ClaimedAt, @e = LastError FROM sidata.MailSendRecord WITH (UPDLOCK, HOLDLOCK) WHERE MailKey = @k;
IF @s IS NULL
    INSERT sidata.MailSendRecord (MailKey, Kind, State, ClaimedBy, ClaimedAt, Attempts) VALUES (@k, @kind, N''sending'', @by, SYSUTCDATETIME(), 1);
ELSE IF @s = N''sending'' AND @b0 = @by
    SET @o = N''claimed'';
ELSE IF @s = N''waiting'' OR (@s = N''sending'' AND @at < DATEADD(minute, -CONVERT(int, @lease), SYSUTCDATETIME()) AND ISNULL(@e, N'''') NOT LIKE N''sent, not marked%'')
    UPDATE sidata.MailSendRecord SET State = N''sending'', ClaimedBy = @by, ClaimedAt = SYSUTCDATETIME(), Attempts = Attempts + 1 WHERE MailKey = @k;
ELSE
    SET @o = N''taken'';
COMMIT;
SELECT @o AS Outcome, State, OutboxMailId, SentAt, LastError FROM sidata.MailSendRecord WHERE MailKey = @k;', N'@k nvarchar(200), @kind nvarchar(32), @by nvarchar(200), @lease nvarchar(10)', @k = @MailKey, @kind = @Kind, @by = @By, @lease = @LeaseMinutes;
'@
}

function Get-SIMailSendRecordDoneSql {
    <#
        What became of this claimant's mail (only its own 'sending' row; answers the rows changed):
          sent      the transport accepted it
          queued    kept in the Pro outbox (@OutboxMailId) -- the outbox sends it, once
          waiting   not sent (a failure): a later claim of the same key sends it (see the header: who that is); -Held also
                    gives the try back (a hold uses no try)
          unmarked  ACCEPTED, but 'sent' could not be written: the note keeps every later claim -- the lease too -- away
    #>
    param([Parameter(Mandatory)][ValidateSet('sent', 'queued', 'waiting', 'unmarked')][string]$As, [switch]$Held)
    $set = switch ($As) {
        'sent'     { "State = N'sent', SentAt = SYSUTCDATETIME(), LastError = NULL" }
        'queued'   { "State = N'queued', OutboxMailId = CONVERT(bigint, @OutboxMailId), LastError = NULL" }
        'waiting'  { "State = N'waiting', ClaimedBy = NULL, ClaimedAt = NULL, LastError = LEFT(@Error, 2000)" + $(if ($Held) { ', Attempts = CASE WHEN Attempts > 0 THEN Attempts - 1 ELSE 0 END' } else { '' }) }
        'unmarked' { "LastError = LEFT(N'sent, not marked: ' + @Error, 2000)" }
    }
    "SET NOCOUNT ON; IF OBJECT_ID('sidata.MailSendRecord') IS NULL SELECT 0; ELSE BEGIN UPDATE sidata.MailSendRecord SET $set WHERE MailKey = @MailKey AND State = N'sending' AND ClaimedBy = @By; SELECT @@ROWCOUNT; END"
}

function Get-SIMailSendRecordKey {
    <# PURE. The record's key: -Day (yyyy-MM-dd) for a daily mail, else the pipeline run, else the collection; '' when none. #>
    param([Parameter(Mandatory)][string]$Kind, [string]$FlowRunId, [int]$CollectionId = 0, [string]$Day)
    $k = $Kind.Trim().ToLowerInvariant()
    if ("$Day".Trim()) { return ('{0}|{1}' -f $k, "$Day".Trim()) }
    if ("$FlowRunId".Trim()) { return ('{0}|run:{1}' -f $k, "$FlowRunId".Trim()) }
    if ($CollectionId -gt 0) { return ('{0}|collection:{1}' -f $k, $CollectionId) }
    ''
}

function Get-SIMailSendRecordValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Get-SIMailSendRecordRows {
    <# The rows of a 'reader' answer, one level unrolled (the reader answers its list as ONE object). #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Answer = @())
    foreach ($x in @($Answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IDictionary] -or $x -is [System.Management.Automation.PSCustomObject] -or $x -isnot [System.Collections.IEnumerable] -or $x -is [string]) { $x; continue }
        foreach ($h in $x) { if ($null -ne $h) { $h } }
    }
}

function Get-SIMailSendRecordDatabase {
    <# PURE. Where the send record lives: the data backend (SI_Pro_DataSqlServer / _SqlDatabase, else SI_ProSqlServer /
       SI_ProSqlDatabase -- the same rule as Resolve-SIDataSettings). $null when no database is configured. #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n) -and $null -ne $Globals[$n]) { "$($Globals[$n])".Trim() } else { '' } }
    $s = & $g 'SI_Pro_DataSqlServer'; if (-not $s) { $s = & $g 'SI_ProSqlServer' }
    $d = & $g 'SI_Pro_DataSqlDatabase'; if (-not $d) { $d = & $g 'SI_ProSqlDatabase' }
    if ($s -and $d) { return [pscustomobject]@{ Server = $s; Database = $d } }
    $null
}

function Request-SIMailSendRecord {
    <# The claim (Get-SIMailSendRecordClaimSql). @{ Outcome = claimed | taken | no-table | unreadable; State; OutboxMailId;
       SentAt; LastError; Error }. Never throws: a failure is 'unreadable' (the caller does not send). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Kind,
          [Parameter(Mandatory)][string]$By, [int]$LeaseMinutes = 60)
    $out = [ordered]@{ Outcome = 'unreadable'; State = $null; OutboxMailId = $null; SentAt = $null; LastError = $null; Error = '' }
    try {
        $raw = & $Invoke (Get-SIMailSendRecordClaimSql) @{ MailKey = $Key; Kind = $Kind; By = $By; LeaseMinutes = [string]$LeaseMinutes } 'reader'
        $row = @(Get-SIMailSendRecordRows -Answer @($raw)) | Select-Object -First 1
        $o = [string](Get-SIMailSendRecordValue $row 'Outcome')
        if ($o -notin 'claimed', 'taken', 'no-table') { $out.Error = 'the send record answered nothing usable'; return [pscustomobject]$out }
        $out.Outcome = $o
        $out.State = [string](Get-SIMailSendRecordValue $row 'State')
        $out.OutboxMailId = Get-SIMailSendRecordValue $row 'OutboxMailId'
        $out.SentAt = Get-SIMailSendRecordValue $row 'SentAt'
        $out.LastError = [string](Get-SIMailSendRecordValue $row 'LastError')
    } catch { $out.Outcome = 'unreadable'; $out.Error = $_.Exception.Message }
    [pscustomobject]$out
}

function Format-SIMailSendRecordTaken {
    <# PURE. The one line for a mail that is not sent because its record says it went (or goes) already. #>
    param([Parameter(Mandatory)]$Claim, [Parameter(Mandatory)][string]$What)
    $st = [string]$Claim.State
    if ($st -eq 'queued') { return ('{0} is already kept for the data sync, which sends it -- it is not kept or sent again' -f $What) }
    if ($st -eq 'sent') {
        $at = ''
        if ($Claim.SentAt -is [datetime]) { $at = ' at ' + ([datetime]$Claim.SentAt).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' }
        return ('{0} was already sent{1} -- it is not sent again' -f $What, $at)
    }
    if ("$($Claim.LastError)" -like 'sent, not marked*') { return ('{0} was already sent -- it is not sent again' -f $What) }
    ('{0} is being sent by another run right now -- it is not sent again' -f $What)
}

function Enter-SIMailSendRecord {
    <#
        Before a mail that must go at most once: may it be sent now? @{ Send; Claimed; OutboxMailId; Line }.
          -Problem   the record's database could not be opened -> SENT AS BEFORE (fail open), said once: a duplicate is possible
          -Invoke    $null (no database is configured for this run at all) -> sent as before, nothing recorded
          claimed    -> Send, Claimed (the caller then calls Exit-SIMailSendRecord)
          no-table   -> sent as before (the updater adds the table), said once
          taken      -> not sent, said once (Format-SIMailSendRecordTaken) -- the ONLY answer that keeps a mail back
          unreadable -> SENT AS BEFORE (fail open), said once: a duplicate is possible
        Owner rule: a lost mail is worse than a rare duplicate -- only a definite "already sent / kept / being sent by another
        run" suppresses a mail; a record that cannot be read or written never does.
    #>
    param([scriptblock]$Invoke, [string]$Problem, [string]$Key, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$By,
          [Parameter(Mandatory)][string]$What, [int]$LeaseMinutes = 60, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $out = [ordered]@{ Send = $false; Claimed = $false; OutboxMailId = $null; Line = '' }
    $failOpen = { param($why) $out.Send = $true; $out.Line = ('{0}: its send record could not be checked ({1}) -- it is sent as before, so a duplicate is possible' -f $What, $why); & $Log 'WARN' $out.Line }
    if ("$Problem".Trim()) { & $failOpen "$Problem".Trim(); return [pscustomobject]$out }
    if ($null -eq $Invoke) { $out.Send = $true; return [pscustomobject]$out }
    if (-not "$Key".Trim()) { & $failOpen 'neither the pipeline run nor the collection of this run is known'; return [pscustomobject]$out }
    $c = Request-SIMailSendRecord -Invoke $Invoke -Key $Key -Kind $Kind -By $By -LeaseMinutes $LeaseMinutes
    switch ($c.Outcome) {
        'claimed'  { $out.Send = $true; $out.Claimed = $true }
        'no-table' { $out.Send = $true; $out.Line = ('{0}: the database does not keep a send record yet (the update adds it) -- sent as before' -f $What); & $Log 'INFO' $out.Line }
        'taken'    { $out.OutboxMailId = $c.OutboxMailId; $out.Line = (Format-SIMailSendRecordTaken -Claim $c -What $What); & $Log 'INFO' $out.Line }
        default    { & $failOpen $c.Error }
    }
    [pscustomobject]$out
}

function Exit-SIMailSendRecord {
    <#
        After the send (only for a claimed record): -As sent | queued | waiting (not sent; -Held = a hold, the try given
        back) -- written with up to 3 tries. A 'sent' that cannot be written becomes 'unmarked' (never sent again). Never
        throws; answers $true when written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$By,
          [Parameter(Mandatory)][ValidateSet('sent', 'queued', 'waiting')][string]$As, $OutboxMailId, [string]$Reason, [switch]$Held,
          [string]$What = 'the mail', [scriptblock]$Log, [int]$RetrySeconds = 2)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $p = @{ MailKey = $Key; By = $By; Error = $(if ($Reason) { $Reason } else { 'the mail was not sent' }); OutboxMailId = $(if ($null -ne $OutboxMailId) { [string]$OutboxMailId } else { '0' }) }
    $err = $null
    foreach ($try in 1..3) {
        try { [void](& $Invoke (Get-SIMailSendRecordDoneSql -As $As -Held:$Held) $p 'scalar'); $err = $null; break }
        catch { $err = $_.Exception.Message; if ($try -lt 3 -and $RetrySeconds -gt 0) { Start-Sleep -Seconds ($RetrySeconds * $try) } }
    }
    if (-not $err) { return $true }
    if ($As -eq 'waiting') {
        & $Log 'WARN' ('{0}: its send record could not be put back ({1}) -- a later run takes it again once its claim is old' -f $What, $err)
    } else {
        $p.Error = $err
        try { [void](& $Invoke (Get-SIMailSendRecordDoneSql -As unmarked) $p 'scalar') } catch { }
        & $Log 'WARN' ('{0}: it was {1}, but its send record could not be written ({2}) -- it is not sent again' -f $What, $(if ($As -eq 'queued') { 'kept for the data sync' } else { 'sent' }), $err)
    }
    $false
}

function Get-SIMailFlowRunId {
    <#
        The pipeline run that is running -Job now (cfg.FlowStepRun: the step Starting / Running in a Running run --
        SI-RunOutcome.ps1 Get-SIFlowStepOutcomeSql). @{ FlowRunId (''= not a pipeline run, or no settings database); Error }.
        Never throws: a read that failed is Error (the caller sends as before, saying a duplicate is possible).
    #>
    param($SettingsStore, [Parameter(Mandatory)][string]$Job)
    $none = [pscustomobject]@{ FlowRunId = ''; Error = '' }
    if ($null -eq $SettingsStore -or $null -eq $SettingsStore.Invoke) { return $none }
    if (-not (Get-Command -Name Get-SIFlowStepOutcomeSql -ErrorAction SilentlyContinue)) {
        $ro = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'SI-RunOutcome.ps1')
        if (Test-Path -LiteralPath $ro) { try { . $ro } catch { } }
        if (-not (Get-Command -Name Get-SIFlowStepOutcomeSql -ErrorAction SilentlyContinue)) { return $none }
    }
    try {
        $raw = & $SettingsStore.Invoke (Get-SIFlowStepOutcomeSql) @{ Job = $Job } 'reader'
        foreach ($r in @(Get-SIMailSendRecordRows -Answer @($raw))) {
            if ([int](Get-SIMailSendRecordValue $r 'Mine') -eq 1) {
                return [pscustomobject]@{ FlowRunId = [string](Get-SIMailSendRecordValue $r 'FlowRunId'); Error = '' }
            }
        }
        $none
    } catch { [pscustomobject]@{ FlowRunId = ''; Error = $_.Exception.Message } }
}

function Open-SIRaMailSendRecord {
    <#
        The Risk Analysis run, before its mail: its send record (Enter-SIMailSendRecord), keyed by the pipeline run of this
        step, else by this run's collection. -Stream: the run's database stream (RA-Stream: Invoke, Grain, CollectionId);
        -StreamWanted: this run has a database (a stream that could not be opened = the record cannot be read -> sent as
        before, fail open, with the line). A pipeline run that cannot be read (incl. its lock timeout) -> sent as before,
        with the line. No database at all -> sent as before. Answers @{ Send; Claimed; Key; By; Invoke; OutboxMailId; Line }.
    #>
    param($Stream, [bool]$StreamWanted, $SettingsStore, [scriptblock]$Log, [int]$LeaseMinutes = 60)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $by = 'ra:' + [guid]::NewGuid().ToString('N')
    $what = 'mail: the Risk Analysis mail of this run'
    $res = { param($e, $key, $inv) [pscustomobject]@{ Send = [bool]$e.Send; Claimed = [bool]$e.Claimed; Key = $key; By = $by; Invoke = $inv; OutboxMailId = $e.OutboxMailId; Line = [string]$e.Line } }
    if ($null -eq $Stream -or $null -eq $Stream.Invoke) {
        $prob = $(if ($StreamWanted) { 'this run''s database could not be reached' } else { '' })
        return (& $res (Enter-SIMailSendRecord -Invoke $null -Problem $prob -Kind 'ra' -By $by -What $what -Log $Log) '' $null)
    }
    $grain = [string]$Stream.Grain
    $job = $(if ($grain -eq 'Summary') { 'risk-analysis' } else { 'risk-analysis-detailed' })
    $fr = Get-SIMailFlowRunId -SettingsStore $SettingsStore -Job $job
    if ($fr.Error) {
        return (& $res (Enter-SIMailSendRecord -Invoke $Stream.Invoke -Problem ('this run''s pipeline run could not be read: ' + $fr.Error) -Kind 'ra' -By $by -What $what -Log $Log) '' $null)
    }
    $kind = 'ra-' + $(if ($grain) { $grain.ToLowerInvariant() } else { 'detailed' })
    $key = Get-SIMailSendRecordKey -Kind $kind -FlowRunId $fr.FlowRunId -CollectionId ([int]$Stream.CollectionId)
    & $res (Enter-SIMailSendRecord -Invoke $Stream.Invoke -Key $key -Kind $kind -By $by -What $what -LeaseMinutes $LeaseMinutes -Log $Log) $key $Stream.Invoke
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE QUEUE CLAIM (cfg.ExemptionMail, cfg.SignInMail, cfg.ReportMail, cfg.GovernanceMail)
# ---------------------------------------------------------------------------------------------------------------------
function Get-SIMailQueueClaimSql {
    <# One UPDATE: the row becomes this sender's only when it is not sent, not noted 'sent, not marked' (the server accepted
       it: it is never sent again -- not after the lease either) and nobody holds it (or the claim is older than the lease).
       Answers 1 (claimed), 0 (another sender has it, or it was sent), -2 (accepted, not marked: never again), -1 (no claim
       columns yet: as before). #>
    param([Parameter(Mandatory)][ValidateSet('cfg.ExemptionMail', 'cfg.SignInMail', 'cfg.ReportMail', 'cfg.GovernanceMail')][string]$Table)
    "SET NOCOUNT ON; IF COL_LENGTH(N'$Table', N'ClaimedBy') IS NULL SELECT -1; ELSE EXEC sp_executesql N'UPDATE $Table SET ClaimedAt = SYSUTCDATETIME(), ClaimedBy = @b WHERE MailId = CONVERT(bigint, @m) AND SentAt IS NULL AND ISNULL(LastError, N'''') NOT LIKE N''sent, not marked%'' AND (ClaimedBy IS NULL OR ClaimedAt IS NULL OR ClaimedAt < DATEADD(minute, -CONVERT(int, @l), SYSUTCDATETIME())); IF @@ROWCOUNT > 0 SELECT 1; ELSE IF EXISTS (SELECT 1 FROM $Table WHERE MailId = CONVERT(bigint, @m) AND SentAt IS NULL AND LastError LIKE N''sent, not marked%'') SELECT -2; ELSE SELECT 0;', N'@m nvarchar(40), @b nvarchar(200), @l nvarchar(10)', @m = @ClaimMailId, @b = @ClaimBy, @l = @ClaimLease;"
}

function Get-SIMailQueueSentNotMarkedSql {
    <# The note on a row the server ACCEPTED but that could not be marked sent: it keeps every later claim -- the lease too --
       away from it (Get-SIMailQueueClaimSql). A sign-in mail's body is blanked as a sent one's is (it carried a one-time
       secret). Only while not sent. #>
    param([Parameter(Mandatory)][ValidateSet('cfg.ExemptionMail', 'cfg.SignInMail', 'cfg.ReportMail', 'cfg.GovernanceMail')][string]$Table)
    $body = $(if ($Table -eq 'cfg.SignInMail') { ", BodyHtml = N'(removed once sent: it carried a one-time sign-in secret)'" } else { '' })
    "UPDATE $Table SET LastError = LEFT(N'sent, not marked: ' + ISNULL(@Error, N''), 1000)$body WHERE MailId = CONVERT(bigint, @MailId) AND SentAt IS NULL;"
}

function Set-SIMailQueueSentNotMarked {
    <# A queued row the server accepted, whose 'sent' could not be written: noted 'sent, not marked' (never sent again). One
       line for the admin either way; answers $true when the note was written. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)]$MailId,
          [string]$Why, [string]$Label = 'the mail', [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        [void](& $Invoke (Get-SIMailQueueSentNotMarkedSql -Table $Table) @{ MailId = [string]$MailId; Error = [string]$Why } 'nonquery')
        & $Log 'WARN' ("{0} {1} was SENT (the server accepted it), but could not be marked sent ({2}) -- it is noted 'sent, not marked' and is never sent again" -f $Label, $MailId, $Why)
        $true
    } catch {
        & $Log 'WARN' ("{0} {1} was SENT (the server accepted it), but could not be marked sent ({2}) nor noted ({3}) -- a later run may send it once more after its claim is old" -f $Label, $MailId, $Why, $_.Exception.Message)
        $false
    }
}

function Get-SIMailQueueReleaseSql {
    <# A claimed row that was not sent goes back to the queue (only this sender's claim, only while not sent). #>
    param([Parameter(Mandatory)][ValidateSet('cfg.ExemptionMail', 'cfg.SignInMail', 'cfg.ReportMail', 'cfg.GovernanceMail')][string]$Table)
    "SET NOCOUNT ON; IF COL_LENGTH(N'$Table', N'ClaimedBy') IS NOT NULL EXEC sp_executesql N'UPDATE $Table SET ClaimedAt = NULL, ClaimedBy = NULL WHERE MailId = CONVERT(bigint, @m) AND ClaimedBy = @b AND SentAt IS NULL;', N'@m nvarchar(40), @b nvarchar(200)', @m = @ClaimMailId, @b = @ClaimBy;"
}

function Request-SIMailQueueClaim {
    <# Claims one queued row: 'claimed' | 'as-before' (no claim columns yet) | 'taken' | 'sent-unmarked' (the server accepted
       it but it could not be marked sent: never sent again) | 'unreadable' (+ Error). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)]$MailId,
          [Parameter(Mandatory)][string]$By, [int]$LeaseMinutes = 60)
    try {
        $v = @(& $Invoke (Get-SIMailQueueClaimSql -Table $Table) @{ ClaimMailId = [string]$MailId; ClaimBy = $By; ClaimLease = [string]$LeaseMinutes } 'scalar') | Select-Object -Last 1
        if ($v -is [System.DBNull]) { $v = $null }
        $n = 0
        if ($null -eq $v -or -not [int]::TryParse("$v", [ref]$n)) { return [pscustomobject]@{ Outcome = 'unreadable'; Error = 'the claim answered nothing usable' } }
        if ($n -eq -2) { return [pscustomobject]@{ Outcome = 'sent-unmarked'; Error = '' } }
        if ($n -lt 0) { return [pscustomobject]@{ Outcome = 'as-before'; Error = '' } }
        if ($n -ge 1) { return [pscustomobject]@{ Outcome = 'claimed'; Error = '' } }
        [pscustomobject]@{ Outcome = 'taken'; Error = '' }
    } catch { [pscustomobject]@{ Outcome = 'unreadable'; Error = $_.Exception.Message } }
}

function Undo-SIMailQueueClaim {
    <# Releases this sender's claim on a row that was not sent. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)]$MailId, [Parameter(Mandatory)][string]$By)
    try { [void](& $Invoke (Get-SIMailQueueReleaseSql -Table $Table) @{ ClaimMailId = [string]$MailId; ClaimBy = $By } 'nonquery'); $true } catch { $false }
}
