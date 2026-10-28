#Requires -Version 5.1
<#
    THE RISK ANALYSIS DETAILED MAIL WAITS FOR ITS PROTECTION SCORE (Pro; owner 2026-10-22: "protection score must be a %" / "the
    mail's percentages must be EXACTLY the same numbers the web app shows for that collection: one computation, never two that
    can differ").

    The Protection Score of a collection is computed ONCE, by the data sync's key figures (sidata.KeyFigure), after the data sync
    has taken the collection in (its asset keys, the reports carried, the lifecycle stamp) -- that is the number the web app
    shows. A Detailed run therefore does not send its mail itself in Pro: it builds the whole mail with the score's two places
    marked (ConvertTo-RAReportMailHtml -ProtectionPending) and keeps it here, in sidata.RaMailOutbox. The data sync, right after
    its key figures, fills the two places from the STORED rows (ConvertFrom-SIProtectionKeyFigures -> the same renderer) and
    sends it. The mail never computes a score of its own.

    NEVER LOST, NEVER SENT TWICE:
      * a mail is CLAIMED atomically (one UPDATE: waiting -> sending, by one claimant) before it is sent -- two data syncs, or a
        data sync and a Detailed run, can never both send it;
      * it is marked 'sent' with the time right after the transport accepted it; a send that failed puts it back to 'waiting'
        with the error, and the next wake-up (the next data sync, or the next Detailed run) sends it again;
      * a claim whose claimant died before it could mark the mail (a killed job) is taken again after -LeaseMinutes -- the
        only case in which a second copy can arrive (the transport accepted it and the job died in the same moment); a mail is
        never dropped for it.
    WHEN THE SCORE CANNOT BE SHOWN the mail still goes, with ONE plain line why (Get-SIProtectionReason): the data sync could
    not compute the figures, did not take the run in, or -- the next Detailed run sends a mail that is still waiting -- has not
    processed the run. A mail is never held back for the score beyond the next wake-up that can decide.
    The table comes from the data schema (the updater applies it); Add-SIRaMailOutbox runs the SAME guarded statement first, so
    a database the updater has not reached yet still keeps the mail. PS 5.1 and 7; no module.
#>

# The same guarded, additive statement as the data schema (a test holds the two equal).
function Get-SIRaMailOutboxTableSql {
    @'
IF OBJECT_ID('sidata.RaMailOutbox') IS NULL
CREATE TABLE sidata.RaMailOutbox (
    MailId           BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_RaMailOutbox PRIMARY KEY,
    CollectionId     INT            NOT NULL,
    CollectionTime   DATETIME2(3)   NOT NULL,
    CreatedAt        DATETIME2(3)   NOT NULL CONSTRAINT DF_RaMailOutbox_CreatedAt DEFAULT SYSUTCDATETIME(),
    Subject          NVARCHAR(1000) NOT NULL,
    BodyHtml         NVARCHAR(MAX)  NOT NULL,
    ToJson           NVARCHAR(MAX)  NOT NULL,
    FromAddress      NVARCHAR(400)  NULL,
    Priority         NVARCHAR(16)   NULL,
    AttachmentName   NVARCHAR(400)  NULL,
    AttachmentBase64 VARCHAR(MAX)   NULL,
    State            NVARCHAR(16)   NOT NULL CONSTRAINT DF_RaMailOutbox_State DEFAULT N'waiting',
    ClaimedAt        DATETIME2(3)   NULL,
    ClaimedBy        NVARCHAR(200)  NULL,
    Attempts         INT            NOT NULL CONSTRAINT DF_RaMailOutbox_Attempts DEFAULT 0,
    SentAt           DATETIME2(3)   NULL,
    SentBy           NVARCHAR(32)   NULL,
    Shown            NVARCHAR(1000) NULL,
    LastError        NVARCHAR(2000) NULL,
    CONSTRAINT CK_RaMailOutbox_State CHECK (State IN ('waiting', 'sending', 'sent'))
);
'@
}

function Get-SIRaMailOutboxAddSql {
    <# The table (guarded), then one waiting mail; answers its MailId. #>
    (Get-SIRaMailOutboxTableSql) + @'
INSERT sidata.RaMailOutbox (CollectionId, CollectionTime, Subject, BodyHtml, ToJson, FromAddress, Priority, AttachmentName, AttachmentBase64)
OUTPUT inserted.MailId
VALUES (CONVERT(int, @CollectionId), CONVERT(datetime2(3), @CollectionTime, 126), @Subject, @BodyHtml, @ToJson, NULLIF(@FromAddress, N''), NULLIF(@Priority, N''),
        NULLIF(@AttachmentName, N''), NULLIF(CONVERT(varchar(max), @AttachmentBase64), ''));
'@
}

function Get-SIRaMailOutboxOpenSql {
    <#
        The mails not sent yet, oldest first, each with what decides it: its collection's state and whether the collection has
        its stored score (the headline protection rows). None on a database without the table.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RaMailOutbox') IS NULL
    SELECT TOP (0) CAST(0 AS bigint) AS MailId, CAST(0 AS int) AS CollectionId, CAST(NULL AS datetime2(3)) AS CollectionTime, CAST(NULL AS datetime2(3)) AS CreatedAt,
           CAST(N'' AS nvarchar(16)) AS State, CAST(NULL AS datetime2(3)) AS ClaimedAt, CAST(NULL AS nvarchar(32)) AS CollectionStatus, CAST(0 AS int) AS Figured;
ELSE
    EXEC sp_executesql N'SELECT o.MailId, o.CollectionId, o.CollectionTime, o.CreatedAt, o.State, o.ClaimedAt, c.Status AS CollectionStatus,
        CASE WHEN OBJECT_ID(''sidata.KeyFigure'') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.KeyFigure k WHERE k.CollectionId = o.CollectionId AND k.Block = N''headline'' AND k.Figure = N''protection_lifecycle'') THEN 1 ELSE 0 END AS Figured
        FROM sidata.RaMailOutbox o LEFT JOIN sidata.Collection c ON c.CollectionId = o.CollectionId
        WHERE o.State IN (N''waiting'', N''sending'') AND ISNULL(o.LastError, N'''') NOT LIKE N''sent, not marked%'' ORDER BY o.MailId';
'@
}

function Get-SIRaMailOutboxClaimSql {
    <#
        THE CLAIM: one statement, so two claimants can never both win -- a waiting mail, or one whose claim is older than
        @LeaseMinutes (its claimant died), becomes 'sending' by @By. Answers the mail when this claimant got it, else nothing.
    #>
    @'
SET NOCOUNT ON;
UPDATE o SET State = N'sending', ClaimedAt = SYSUTCDATETIME(), ClaimedBy = @By, Attempts = o.Attempts + 1
OUTPUT inserted.MailId, inserted.CollectionId, inserted.CollectionTime, inserted.Subject, inserted.BodyHtml, inserted.ToJson, inserted.FromAddress,
       inserted.Priority, inserted.AttachmentName, inserted.AttachmentBase64, inserted.Attempts
FROM sidata.RaMailOutbox AS o WITH (ROWLOCK, UPDLOCK)
WHERE o.MailId = CONVERT(bigint, @MailId)
  AND (o.State = N'waiting' OR (o.State = N'sending' AND o.ClaimedAt < DATEADD(minute, -CONVERT(int, @LeaseMinutes), SYSUTCDATETIME())))
  -- review S2: a mail the server ACCEPTED but that could not be marked is never taken again (it would be sent twice)
  AND ISNULL(o.LastError, N'') NOT LIKE N'sent, not marked%';
'@
}

function Get-SIRaMailOutboxSentSql {
    <# Marks the claimed mail sent (the time, who, what the score line said) and lets its attachment go. Answers the rows marked. #>
    @'
SET NOCOUNT ON;
UPDATE sidata.RaMailOutbox SET State = N'sent', SentAt = SYSUTCDATETIME(), SentBy = @Role, Shown = LEFT(@Shown, 1000), LastError = NULL, AttachmentBase64 = NULL
WHERE MailId = CONVERT(bigint, @MailId) AND State = N'sending' AND ClaimedBy = @By;
SELECT @@ROWCOUNT;
'@
}

function Get-SIRaMailOutboxSentNotMarkedSql {
    <# Review S2: the server ACCEPTED the mail but marking it sent failed -- the row stays claimed, with a note that keeps every
       later claim (the lease too) away from it: it is never sent again. #>
    @'
SET NOCOUNT ON;
UPDATE sidata.RaMailOutbox SET LastError = LEFT(N'sent, not marked: ' + @Error, 2000)
WHERE MailId = CONVERT(bigint, @MailId) AND State = N'sending' AND ClaimedBy = @By;
SELECT @@ROWCOUNT;
'@
}

function Get-SIRaMailOutboxReleaseSql {
    <# A send that failed: the claimed mail waits again, with the error -- the next wake-up sends it. #>
    @'
SET NOCOUNT ON;
UPDATE sidata.RaMailOutbox SET State = N'waiting', ClaimedAt = NULL, ClaimedBy = NULL, LastError = LEFT(@Error, 2000)
WHERE MailId = CONVERT(bigint, @MailId) AND State = N'sending' AND ClaimedBy = @By;
SELECT @@ROWCOUNT;
'@
}

function Get-SIRaProtectionKeyFiguresSql {
    <# The stored Protection Score of one collection: the rows ConvertFrom-SIProtectionKeyFigures reads. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.KeyFigure') IS NULL
    SELECT TOP (0) CAST(N'' AS nvarchar(16)) AS Block, CAST(N'' AS nvarchar(48)) AS Figure, CAST(N'' AS nvarchar(200)) AS Dim1, CAST(N'' AS nvarchar(120)) AS Dim2,
           CAST(NULL AS float) AS Value, CAST(NULL AS int) AS Assets, CAST(NULL AS int) AS Total, CAST(0 AS bit) AS Available, CAST(NULL AS nvarchar(400)) AS Note;
ELSE
    EXEC sp_executesql N'SELECT Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note FROM sidata.KeyFigure
        WHERE CollectionId = CONVERT(int, @c) AND ((Block = N''protection'' AND Figure IN (N''technical'', N''lifecycle'', N''agebasis''))
           OR (Block = N''headline'' AND Figure IN (N''protection_technical'', N''protection_lifecycle'')))', N'@c nvarchar(20)', @c = @CollectionId;
'@
}

function Get-SIRaExecViewProtectionSql {
    <#
        The kept executive view of the Detailed run of one collection time takes the STORED score (the Risk Analysis page and the
        management mail read it) -- the same rows as the mail. Answers the rows changed (0 when there is no such view).
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RiskExecView') IS NULL SELECT 0;
ELSE
BEGIN
    UPDATE sidata.RiskExecView SET PayloadJson = JSON_MODIFY(PayloadJson, '$.Kpi.Protection', JSON_QUERY(@Protection))
    WHERE Grain = N'Detailed' AND CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND ISJSON(PayloadJson) = 1
      AND JSON_QUERY(PayloadJson, '$.Kpi') IS NOT NULL
      AND ISNULL(JSON_QUERY(PayloadJson, '$.Kpi.Protection'), N'') <> @Protection;
    SELECT @@ROWCOUNT;
END
'@
}

function Get-SIRaMailOutboxValue {
    <# A column of a database row (a dictionary from 'reader', or an object); DBNull is $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Get-SIRaMailOutboxRows {
    <# The rows of a 'reader' answer, one level unrolled (the reader answers its list as ONE object). #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Answer = @())
    foreach ($x in @($Answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IDictionary] -or $x -is [System.Management.Automation.PSCustomObject] -or $x -isnot [System.Collections.IEnumerable] -or $x -is [string]) { $x; continue }
        foreach ($h in $x) { if ($null -ne $h) { $h } }
    }
}

function Format-SIRaMailOutboxTime {
    <# PURE. A time as the statements take it (ISO, UTC, milliseconds). #>
    param($Time)
    if ($null -eq $Time) { return $null }
    $d = if ($Time -is [datetime]) { [datetime]$Time } else { [datetime]::Parse([string]$Time, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
    if ($d.Kind -eq [DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
    $d.ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
}

function Add-SIRaMailOutbox {
    <#
        Keeps one Detailed mail until its score is stored (see above). -AttachmentPath: the workbook the mail attaches (kept with
        the mail -- the data sync attaches the same file). Answers the MailId; THROWS when the mail could not be kept, so the
        caller sends it at once instead (a mail is never lost).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [Parameter(Mandatory)][datetime]$CollectionTime,
          [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$BodyHtml, [Parameter(Mandatory)][string[]]$To,
          [string]$From, [string]$Priority = 'High', [string]$AttachmentPath)
    $name = ''; $b64 = ''
    if ("$AttachmentPath".Trim() -and (Test-Path -LiteralPath $AttachmentPath)) {
        $name = Split-Path -Leaf $AttachmentPath
        $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($AttachmentPath))
    }
    $p = @{ CollectionId = [string]$CollectionId; CollectionTime = (Format-SIRaMailOutboxTime $CollectionTime); Subject = $Subject; BodyHtml = $BodyHtml
            ToJson = (ConvertTo-Json -InputObject @($To) -Compress); FromAddress = [string]$From; Priority = [string]$Priority; AttachmentName = $name; AttachmentBase64 = $b64 }
    $id = @(& $Invoke (Get-SIRaMailOutboxAddSql) $p 'scalar') | Select-Object -Last 1
    if ($null -eq $id -or "$id" -notmatch '^\d+$' -or [long]"$id" -le 0) { throw 'the mail was not kept (no id came back)' }
    [long]"$id"
}

function Get-SIRaMailOutboxDecision {
    <#
        PURE. What to do with ONE open mail now: @{ Action = score | reason | wait; Reason }.
          score   the collection has its stored score -- always sent, with it;
          reason  sent now, with one plain line why there is no score;
          wait    left for the next wake-up that can decide.
        -Role datasync: a mail kept BEFORE this data sync started (-RunStartedUtc) and still without a score is decided -- the
        figures failed (-KeyFigures.Status failed / no-schema), or the collection was not taken in (not Complete); a complete
        collection whose figures this run did not reach yet (its budget) waits. A mail kept after this data sync started waits
        for the next one. -Role producer (the next Detailed run): a mail of an EARLIER collection still waiting is sent, unless a
        data sync is running right now (-SyncRunning) -- that one decides it.
    #>
    param([Parameter(Mandatory)]$Mail, [Parameter(Mandatory)][ValidateSet('datasync', 'producer')][string]$Role, $RunStartedUtc, $KeyFigures,
          [int]$OwnCollectionId = 0, [bool]$SyncRunning = $false)
    $g = { param($n) Get-SIRaMailOutboxValue $Mail $n }
    if ([int](& $g 'Figured') -eq 1) { return @{ Action = 'score'; Reason = '' } }
    if ($Role -eq 'producer') {
        if ([int](& $g 'CollectionId') -eq $OwnCollectionId) { return @{ Action = 'wait'; Reason = '' } }
        if ($SyncRunning) { return @{ Action = 'wait'; Reason = '' } }
        return @{ Action = 'reason'; Reason = (Get-SIProtectionReason 'not-figured') }
    }
    $created = & $g 'CreatedAt'
    if ($null -ne $RunStartedUtc -and $null -ne $created -and ([datetime]$created) -ge ([datetime]$RunStartedUtc)) { return @{ Action = 'wait'; Reason = '' } }
    $kfStatus = ''; $kfError = ''
    if ($null -ne $KeyFigures) { $kfStatus = [string](Get-SIRaMailOutboxValue $KeyFigures 'Status'); $kfError = [string](Get-SIRaMailOutboxValue $KeyFigures 'Error') }
    $status = [string](& $g 'CollectionStatus')
    if ($status -ne 'Complete') {
        $what = $(if ($status) { "its collection is '$status'" } else { 'its collection is not in the database any more' })
        return @{ Action = 'reason'; Reason = (Get-SIProtectionReason 'not-taken-in' $what) }
    }
    if ($kfStatus -eq 'failed') { return @{ Action = 'reason'; Reason = (Get-SIProtectionReason 'figures-failed' $kfError) } }
    if ($kfStatus -eq 'no-schema') { return @{ Action = 'reason'; Reason = (Get-SIProtectionReason 'figures-failed' 'the database does not have the key figures table yet -- the updater adds it') } }
    # review S1: the key figures did not run this time, or ran and left nothing for later, and this collection has no figures:
    # waiting would only hold the mail until the next Detailed run -- it goes now, saying so. Only a collection the key figures
    # left for their next run (Pending > 0: their time budget) waits for it.
    if ($null -eq $KeyFigures) { return @{ Action = 'reason'; Reason = (Get-SIProtectionReason 'not-computed' 'the key figures step did not run this time') } }
    $pending = 0; $pv = Get-SIRaMailOutboxValue $KeyFigures 'Pending'; if ($null -ne $pv -and "$pv" -match '^\d+$') { $pending = [int]"$pv" }
    if ($kfStatus -eq 'dry-run') { return @{ Action = 'wait'; Reason = '' } }
    if ($kfStatus -ne 'ok' -or $pending -le 0) { return @{ Action = 'reason'; Reason = (Get-SIProtectionReason 'not-computed' $(if ($kfStatus -ne 'ok') { "the key figures ended '$kfStatus'" } else { 'the key figures did not include this run' })) } }
    @{ Action = 'wait'; Reason = '' }
}

function ConvertTo-SIRaExecViewProtectionJson {
    <# PURE. The kept executive view's Kpi.Protection (RA-ExecView.ps1's shape, which the web app parses) of a score; $null without one. #>
    param($Protection)
    if ($null -eq $Protection -or $null -eq $Protection.Lifecycle) { return $null }
    $types = [ordered]@{}
    foreach ($row in @($Protection.Rows)) {
        if ($null -ne $row -and $row.Dim2 -eq '(all)' -and $row.Dim1 -ne '(all)' -and $row.Figure -in 'technical', 'lifecycle') {
            if (-not $types.Contains([string]$row.Dim1)) { $types[[string]$row.Dim1] = [ordered]@{ Assets = [int]$row.Total } }
            $types[[string]$row.Dim1][$(if ($row.Figure -eq 'technical') { 'Technical' } else { 'Lifecycle' })] = $row.Value
        }
    }
    ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ Lifecycle = [double]$Protection.Lifecycle; Technical = [double]$Protection.Technical; LifecycleGood = [int]$Protection.LifecycleGood
        TechnicalGood = [int]$Protection.TechnicalGood; Assets = [int]$Protection.Assets; NoDate = [int]$Protection.NoDate; Findings = [int]$Protection.Findings; ByType = $types; Source = 'stored' })
}

function Read-SIRaStoredProtection {
    <# The stored Protection Score of one collection (ConvertFrom-SIProtectionKeyFigures), $null when there is none yet. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, $Settings)
    $rows = @(Get-SIRaMailOutboxRows -Answer @(& $Invoke (Get-SIRaProtectionKeyFiguresSql) @{ CollectionId = [string]$CollectionId } 'reader'))
    ConvertFrom-SIProtectionKeyFigures -Rows $rows -Settings $Settings
}

function Invoke-SIRaMailOutbox {
    <#
        Sends every open Detailed mail that can be decided now (Get-SIRaMailOutboxDecision): claim, fill the score from the
        STORED rows (or the one line why), send through -Send, mark sent -- or, when the send failed, put it back with the error.
        -Send { param($Mail) } -> @{ Sent; Error }: $Mail = @{ Subject; BodyHtml; To; From; Priority; Attachments (paths) }.
        Answers @{ Sent; Waiting; Failed; Lines }. Never throws (a mail that could not be decided stays waiting; said once).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('datasync', 'producer')][string]$Role,
          [Parameter(Mandatory)][scriptblock]$Send, $RunStartedUtc, $KeyFigures, [int]$OwnCollectionId = 0, [bool]$SyncRunning = $false,
          [int]$LeaseMinutes = 60, [string]$By, $Settings, [switch]$DryRun, [scriptblock]$Log, [int]$MarkRetrySeconds = 2)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    if (-not $By) { $By = '{0}:{1}' -f $Role, [guid]::NewGuid().ToString('N') }
    $out = [ordered]@{ Sent = 0; Waiting = 0; Failed = 0; Lines = New-Object System.Collections.Generic.List[string] }
    $open = @()
    try { $open = @(Get-SIRaMailOutboxRows -Answer @(& $Invoke (Get-SIRaMailOutboxOpenSql) @{} 'reader')) }
    catch { & $Log 'WARN' ("risk analysis mail: the waiting mails could not be read ({0}) -- they stay waiting; the next run sends them" -f $_.Exception.Message); return [pscustomobject]$out }
    foreach ($m in $open) {
        $mid = [long](Get-SIRaMailOutboxValue $m 'MailId'); $cid = [int](Get-SIRaMailOutboxValue $m 'CollectionId')
        $ct = Get-SIRaMailOutboxValue $m 'CollectionTime'
        $d = Get-SIRaMailOutboxDecision -Mail $m -Role $Role -RunStartedUtc $RunStartedUtc -KeyFigures $KeyFigures -OwnCollectionId $OwnCollectionId -SyncRunning $SyncRunning
        if ($d.Action -eq 'wait') { $out.Waiting++; continue }
        if ($DryRun) { $out.Lines.Add(("the mail of the run of {0:yyyy-MM-dd HH:mm} UTC would be sent ({1})" -f $ct, $d.Action)); continue }
        $tmpDir = $null; $accepted = $false
        try {
            $claimed = @(Get-SIRaMailOutboxRows -Answer @(& $Invoke (Get-SIRaMailOutboxClaimSql) @{ MailId = [string]$mid; By = $By; LeaseMinutes = [string]$LeaseMinutes } 'reader')) | Select-Object -First 1
            if ($null -eq $claimed) { $out.Waiting++; continue }    # another claimant has it
            $prot = $null; $why = [string]$d.Reason
            if ($d.Action -eq 'score') {
                $prot = Read-SIRaStoredProtection -Invoke $Invoke -CollectionId $cid -Settings $Settings
                if ($null -eq $prot) { $why = Get-SIProtectionReason 'not-figured' }
            }
            $body = Set-RAReportMailProtection -BodyHtml ([string](Get-SIRaMailOutboxValue $claimed 'BodyHtml')) -Protection $prot -Reason $why
            $shown = $(if ($null -ne $prot -and $null -ne $prot.Lifecycle) { [string]::Format([Globalization.CultureInfo]::InvariantCulture, 'within Accepted Lifecycle {0:0.0} %, Actual Risks {1:0.0} % (stored figures of collection {2})', [double]$prot.Lifecycle, [double]$prot.Technical, $cid) }
                       else { Get-SIProtectionNoScoreText -Score $prot -Reason $why })
            $att = @()
            $b64 = [string](Get-SIRaMailOutboxValue $claimed 'AttachmentBase64')
            if ($b64) {
                $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('si-ramail-' + [guid]::NewGuid().ToString('N'))
                $null = New-Item -ItemType Directory -Path $tmpDir -Force
                $file = Join-Path $tmpDir ([string](Get-SIRaMailOutboxValue $claimed 'AttachmentName'))
                [System.IO.File]::WriteAllBytes($file, [Convert]::FromBase64String($b64)); $att = @($file)
            }
            $to = @(); try { $to = @(ConvertFrom-Json -InputObject ([string](Get-SIRaMailOutboxValue $claimed 'ToJson'))) } catch { $to = @() }
            $mail = @{ Subject = [string](Get-SIRaMailOutboxValue $claimed 'Subject'); BodyHtml = $body; To = @($to | ForEach-Object { [string]$_ })
                       From = [string](Get-SIRaMailOutboxValue $claimed 'FromAddress'); Priority = $(if ([string](Get-SIRaMailOutboxValue $claimed 'Priority')) { [string](Get-SIRaMailOutboxValue $claimed 'Priority') } else { 'High' }); Attachments = $att }
            $r = $null; try { $r = & $Send $mail } catch { $r = @{ Sent = $false; Error = $_.Exception.Message } }
            if ($r -and [bool](Get-SIRaMailOutboxValue $r 'Sent')) {
                # review S2: the server ACCEPTED it -- from here it is never put back to waiting (that would send it twice).
                # Marking it sent is idempotent (only this claimant's 'sending' row): tried again; when it still fails, the row
                # stays claimed with the note 'sent, not marked' that keeps every later claim -- the lease too -- away from it.
                $accepted = $true
                $markErr = $null
                foreach ($try in 1..3) {
                    try { [void](& $Invoke (Get-SIRaMailOutboxSentSql) @{ MailId = [string]$mid; By = $By; Role = $Role; Shown = $shown } 'scalar'); $markErr = $null; break }
                    catch { $markErr = $_.Exception.Message; if ($try -lt 3 -and $MarkRetrySeconds -gt 0) { Start-Sleep -Seconds ($MarkRetrySeconds * $try) } }
                }
                if ($markErr) {
                    try { [void](& $Invoke (Get-SIRaMailOutboxSentNotMarkedSql) @{ MailId = [string]$mid; By = $By; Error = $markErr } 'scalar') } catch { }
                    & $Log 'WARN' ("risk analysis mail: the Detailed mail of the run of {0} UTC was SENT, but could not be marked sent ({1}) -- it is not sent again" -f (Format-SIRaMailOutboxTime $ct), $markErr)
                }
                $out.Sent++
                $line = "risk analysis mail: the Detailed mail of the run of {0} UTC is sent -- Protection Score: {1}" -f (Format-SIRaMailOutboxTime $ct), $shown
                $out.Lines.Add($line); & $Log 'OK' $line
            } else {
                $err = [string](Get-SIRaMailOutboxValue $r 'Error'); if (-not $err) { $err = 'the mail was not sent' }
                [void](& $Invoke (Get-SIRaMailOutboxReleaseSql) @{ MailId = [string]$mid; By = $By; Error = $err } 'scalar')
                $out.Failed++
                $line = "risk analysis mail: the Detailed mail of the run of {0} UTC was NOT sent ({1}) -- it waits; the next run sends it" -f (Format-SIRaMailOutboxTime $ct), $err
                $out.Lines.Add($line); & $Log 'WARN' $line
            }
        } catch {
            if ($accepted) { & $Log 'WARN' ("risk analysis mail: the Detailed mail of collection {0} was sent; what came after failed ({1}) -- it is not sent again" -f $cid, $_.Exception.Message); continue }
            $out.Failed++
            # a claim that was taken stays claimed until its lease ends, then the next wake-up takes it again -- never lost
            try { [void](& $Invoke (Get-SIRaMailOutboxReleaseSql) @{ MailId = [string]$mid; By = $By; Error = $_.Exception.Message } 'scalar') } catch { }
            & $Log 'WARN' ("risk analysis mail: the Detailed mail of collection {0} could not be sent ({1}) -- it waits; the next run sends it" -f $cid, $_.Exception.Message)
        } finally {
            if ($tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    [pscustomobject]$out
}

function Update-SIRaExecViewProtection {
    <#
        The kept Detailed executive view takes its collection's STORED score -- the Risk Analysis page and the management mail
        then show the numbers the Executive overview and the mail show. Every data sync, for the view's own collection time (a
        view without stored figures yet is left as it is). Answers @{ Updated; Problem }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Settings, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        $q = "SET NOCOUNT ON; IF OBJECT_ID('sidata.RiskExecView') IS NULL SELECT TOP (0) CAST(0 AS int) AS CollectionId, CAST(NULL AS datetime2(3)) AS CollectionTime; ELSE SELECT c.CollectionId, v.CollectionTime FROM sidata.RiskExecView v JOIN sidata.Collection c ON c.CollectionTime = v.CollectionTime AND c.Kind = N'Detailed' WHERE v.Grain = N'Detailed';"
        $views = @(Get-SIRaMailOutboxRows -Answer @(& $Invoke $q @{} 'reader'))
        $n = 0
        foreach ($v in $views) {
            $prot = Read-SIRaStoredProtection -Invoke $Invoke -CollectionId ([int](Get-SIRaMailOutboxValue $v 'CollectionId')) -Settings $Settings
            $json = ConvertTo-SIRaExecViewProtectionJson -Protection $prot
            if (-not $json) { continue }
            $n += [int](@(& $Invoke (Get-SIRaExecViewProtectionSql) @{ CollectionTime = (Format-SIRaMailOutboxTime (Get-SIRaMailOutboxValue $v 'CollectionTime')); Protection = $json } 'scalar') | Select-Object -Last 1)
        }
        if ($n -gt 0) { & $Log 'INFO' 'exec view : the Detailed view carries its collection''s stored Protection Score (the numbers the Executive overview shows)' }
        [pscustomobject]@{ Updated = $n; Problem = $null }
    } catch {
        & $Log 'WARN' ("exec view : the stored Protection Score was not put on the Detailed view ({0}) -- the Risk Analysis page shows it on the next run" -f $_.Exception.Message)
        [pscustomobject]@{ Updated = 0; Problem = $_.Exception.Message }
    }
}

# =====================================================================================================================
# REVIEW B1 (2026-10-22): A MAIL IS KEPT ONLY WHEN THE DATA SYNC CAN SEND IT. The data sync records, every run, whether its own
# mail settings can send (sidata.ViewState 'ramail-sender': 'ok', else why not); a Detailed run keeps its mail for the stored
# score only when the last data sync said 'ok'. Otherwise -- not recorded yet (the first run after the update), or the data
# sync has no relay password / mail settings -- the Detailed run sends its mail at once, with the line "the protection score is
# shown in SecurityInsight". A mail is never held where it cannot go out.
# =====================================================================================================================
function Get-SIRaMailSenderSetSql {
    <# Records whether the data sync can send (@Value: 'ok' or a short why); 1, or 0 on a database without the table. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.ViewState') IS NULL SELECT 0;
ELSE
BEGIN
    UPDATE sidata.ViewState SET Value = LEFT(@Value, 64), UpdatedAt = SYSUTCDATETIME() WHERE Name = N'ramail-sender';
    IF @@ROWCOUNT = 0 INSERT sidata.ViewState (Name, Value) VALUES (N'ramail-sender', LEFT(@Value, 64));
    SELECT 1;
END
'@
}

function Get-SIRaMailSenderReadSql {
    "SET NOCOUNT ON; IF OBJECT_ID('sidata.ViewState') IS NULL SELECT CAST(NULL AS nvarchar(64)); ELSE SELECT (SELECT Value FROM sidata.ViewState WHERE Name = N'ramail-sender');"
}

function Get-SIRaMailSenderState {
    <# PURE. Whether these mail settings (Get-SIMailSettings) can send: @{ Ready; Value ('ok' or a short why) }. #>
    param($MailSettings)
    if ($null -eq $MailSettings) { return @{ Ready = $false; Value = 'no mail settings' } }
    if ([bool]$MailSettings.Off) { return @{ Ready = $false; Value = 'mail is off' } }
    $p = @($MailSettings.Problems | Where-Object { "$_".Trim() })
    if ($p.Count) { $v = 'not set up: ' + [string]$p[0]; if ($v.Length -gt 64) { $v = $v.Substring(0, 64) }; return @{ Ready = $false; Value = $v } }
    @{ Ready = $true; Value = 'ok' }
}

function Set-SIRaMailSender {
    <# The data sync, every run: records whether it can send (Get-SIRaMailSenderState). Never throws; answers the state. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $MailSettings, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $st = Get-SIRaMailSenderState -MailSettings $MailSettings
    try { [void](& $Invoke (Get-SIRaMailSenderSetSql) @{ Value = [string]$st.Value } 'scalar') }
    catch { & $Log 'WARN' ("risk analysis mail: whether this job can send could not be recorded ({0}) -- the Detailed runs send their mail at once" -f $_.Exception.Message) }
    if (-not $st.Ready) { & $Log 'WARN' ("risk analysis mail: this job cannot send mail ({0}) -- the Detailed runs send their mail at once, without waiting for the stored Protection Score" -f $st.Value) }
    $st
}

function Test-SIRaMailSender {
    <# The Detailed run: did the last data sync record that it can send? @{ Ready; Why }. Not recorded / not readable = not ready. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $v = $null
    try { $v = @(& $Invoke (Get-SIRaMailSenderReadSql) @{} 'scalar') | Select-Object -Last 1 } catch { return @{ Ready = $false; Why = ('the data sync''s mail state could not be read: ' + $_.Exception.Message) } }
    if ($v -is [System.DBNull]) { $v = $null }
    if ([string]$v -eq 'ok') { return @{ Ready = $true; Why = '' } }
    @{ Ready = $false; Why = $(if ($v) { "the data sync cannot send mail ($v)" } else { 'the data sync has not recorded that it can send mail yet' }) }
}