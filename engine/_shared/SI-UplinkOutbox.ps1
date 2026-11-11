#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE UPLINK OUTBOX (framework 8.4, agreed with Invardia 2026-11-05).

    WHY. A run report is sent ONCE, at the end of its job (Send-SITelemetryRunEnd, SI-TelemetrySend.ps1). Until now a report
    Invardia did not take -- no answer, a timeout, a 429, any answer that is not ok -- was lost: Invardia never heard of that
    run. Now such a report is kept in the install's own Pro database (cfg.UplinkOutbox, sql\si-pro-settings.sql) and sent
    again later by the heartbeat job. The send at job end is unchanged.

    THE THREE MOMENTS
      1. JOB END (Add-SIUplinkOutboxRecord, called by Send-SITelemetryRunEnd): a run record that was NOT taken -- or not sent
         at all because an earlier report of the same process was refused -- is ONE cheap insert (a 5-second lock timeout).
         Identified installs only, and only where the run has the Pro database open; an install without SQL (Community)
         does nothing new. A failed insert is said ONCE and dropped -- telemetry never fails or slows a run.
      2. THE HEARTBEAT TICK (Invoke-SIUplinkOutboxTick, engine\heartbeat\Invoke-SIHeartbeat.ps1, LAST in the tick -- the
         heartbeat itself goes FIRST): the rows are sent again OLDEST FIRST (by the time they were kept; so each job's runs
         reach Invardia in the order they ran), in ROUNDS: at most 20 POSTs per round, at least 65 seconds between rounds, at
         most 5 rounds per tick. A record taken is DELETED (it reached its target). The first answer that is not ok (a 429
         or anything else) STOPS the drain for this tick -- the record stays, with its attempt counted. A tick whose own
         heartbeat was not taken sends nothing from the outbox. Never in an engine job.
      3. THE BOUND (Get-SIUplinkOutboxBoundSql, applied with every insert and at the start of every tick): at most 7 days
         and at most 5,000 rows; beyond that the OLDEST rows go and are COUNTED in cfg.InstallState 'UplinkOutbox'
         ({ dropped, said, drainUntilUtc }) -- the tick says the drops it has not said yet, once.
    ONE DRAIN AT A TIME: the tick takes a 15-minute lease in the same state row (drainUntilUtc) -- a second execution of
    the heartbeat job (a manual start) sends nothing from the outbox while the first drains.
    THE HEARTBEAT FIELD UplinkBacklog { pending, oldestUtc, checkedUtc } (SI-HeartbeatFields.ps1) is read from this table
    (Get-SIUplinkOutboxBacklogSql) -- on every ring (Invardia deployed it 2026-11-05), its own switch turns it off.

    NOTHING HERE THROWS TO ITS CALLER. PS 5.1 and 7. No PowerShell modules. A test session never opens a database (every
    reader is a seam).
#>

$script:SIUplinkOutbox = @{
    Table          = 'cfg.UplinkOutbox'
    StateName      = 'UplinkOutbox'
    MaxDays        = 7
    MaxRows        = 5000
    RoundSize      = 20
    RoundWaitSec   = 65
    MaxRounds      = 5
    LeaseMinutes   = 15
    InsertLockMs   = 5000
    AnswerMax      = 400
    JsonDepth      = 6
    Kinds          = @('run')
    By             = 'si-engine (uplink outbox)'
}

function Get-SIUplinkOutboxContract { $script:SIUplinkOutbox }

function Get-SIUplinkOutboxInvoke {
    <# The Pro database seam the run has open (the Pro settings layer's store), or $null: none open, or a test session. #>
    try {
        if (Get-Module -Name Pester) { return $null }
        if ($global:SI_ProSettingsStore -and $global:SI_ProSettingsStore.PSObject.Properties['Invoke'] -and $global:SI_ProSettingsStore.Invoke -is [scriptblock]) { return $global:SI_ProSettingsStore.Invoke }
    } catch { }
    $null
}

function ConvertTo-SIUplinkOutboxJson {
    <# PURE. A wire record as the JSON the uplink client sends (the same depth, compressed). #>
    param([Parameter(Mandatory)]$Record)
    $Record | ConvertTo-Json -Depth ([int]$script:SIUplinkOutbox.JsonDepth) -Compress
}

function ConvertFrom-SIUplinkOutboxJsonElement {
    param($Element)
    switch ([string]$Element.ValueKind) {
        'Object' {
            $o = [ordered]@{}
            foreach ($p in $Element.EnumerateObject()) { $o[$p.Name] = ConvertFrom-SIUplinkOutboxJsonElement $p.Value }
            return [pscustomobject]$o
        }
        'Array' {
            $a = New-Object System.Collections.Generic.List[object]
            foreach ($e in $Element.EnumerateArray()) { $a.Add((ConvertFrom-SIUplinkOutboxJsonElement $e)) }
            return , $a.ToArray()
        }
        'String' { return $Element.GetString() }
        'Number' { $l = 0L; if ($Element.TryGetInt64([ref]$l)) { return $l }; return $Element.GetDouble() }
        'True' { return $true }
        'False' { return $false }
        default { return $null }
    }
}

function ConvertFrom-SIUplinkOutboxJson {
    <#
        PURE. A kept record back as an object that the uplink client serialises to the SAME JSON: on PowerShell 7 through
        System.Text.Json (ConvertFrom-Json there turns ISO time strings into dates, and the record would leave in another
        form); on 5.1 ConvertFrom-Json (it keeps strings as they are).
    #>
    param([Parameter(Mandatory)][string]$Json)
    $t = 'System.Text.Json.JsonDocument' -as [type]
    if ($t) {
        $doc = [System.Text.Json.JsonDocument]::Parse($Json)
        try { return (ConvertFrom-SIUplinkOutboxJsonElement $doc.RootElement) } finally { $doc.Dispose() }
    }
    $Json | ConvertFrom-Json
}

function ConvertTo-SIUplinkOutboxAnswer {
    <# PURE. The uplink's answer as one short line (at most 400 characters), redacted when the framework client is loaded. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = ("$Text" -replace '[\r\n\t]+', ' ').Trim()
    if (-not $t) { $t = 'no answer' }
    try { if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { $t = ConvertTo-AitUplinkRedacted -Text $t } } catch { }
    $max = [int]$script:SIUplinkOutbox.AnswerMax
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3) + '...' }
    $t
}

# =====================================================================================================================
#  The statements (fixed text, every value a parameter)
# =====================================================================================================================
function Get-SIUplinkOutboxBoundSql {
    <#
        The BOUND (a fragment of a batch; needs @NowUtc, @MaxDays, @MaxRows, @StateName, @By): rows older than @MaxDays, then
        the oldest rows beyond @MaxRows, are deleted; their number is added to cfg.InstallState @StateName 'dropped'. Leaves
        @dropNow (int) set.
    #>
    @'
    DECLARE @dropNow int = 0, @cut DATETIME2(3) = DATEADD(DAY, -@MaxDays, @NowUtc), @rowsNow bigint;
    DELETE FROM cfg.UplinkOutbox WHERE CreatedUtc < @cut;
    SET @dropNow = @@ROWCOUNT;
    SELECT @rowsNow = COUNT_BIG(*) FROM cfg.UplinkOutbox;
    IF @rowsNow > @MaxRows
    BEGIN
        DELETE FROM cfg.UplinkOutbox WHERE OutboxId IN (SELECT TOP (CAST(@rowsNow - @MaxRows AS int)) OutboxId FROM cfg.UplinkOutbox ORDER BY CreatedUtc, OutboxId);
        SET @dropNow = @dropNow + @@ROWCOUNT;
    END
    IF @dropNow > 0 AND OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    BEGIN
        IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @StateName)
            UPDATE cfg.InstallState
               SET Value = JSON_MODIFY(CASE WHEN ISJSON(Value) = 1 THEN Value ELSE N'{}' END, '$.dropped',
                                       CAST(CASE WHEN ISJSON(Value) = 1 THEN ISNULL(TRY_CONVERT(bigint, JSON_VALUE(Value, '$.dropped')), 0) ELSE 0 END + @dropNow AS bigint)),
                   UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
             WHERE Name = @StateName;
        ELSE
            INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@StateName, CONCAT(N'{"dropped":', @dropNow, N',"said":0}'), NULL, @By);
    END
'@
}

function Get-SIUplinkOutboxInsertSql {
    <# ONE record kept (@Job, @Kind, @Json, @Answer, @NowUtc), then the bound. Answers ONE row: Kept (1 / 0 = no table yet). #>
    $bound = Get-SIUplinkOutboxBoundSql
    @"
SET NOCOUNT ON;
SET LOCK_TIMEOUT $([int]$script:SIUplinkOutbox.InsertLockMs);
IF OBJECT_ID(N'cfg.UplinkOutbox') IS NULL
    SELECT CAST(0 AS int) AS Kept;
ELSE
BEGIN
    INSERT cfg.UplinkOutbox (Job, Kind, RecordJson, CreatedUtc, Attempts, LastAttemptUtc, LastAnswer)
    VALUES (@Job, @Kind, @Json, @NowUtc, 1, @NowUtc, @Answer);
$bound
    SELECT CAST(1 AS int) AS Kept;
END
"@
}

function Get-SIUplinkOutboxBeginSql {
    <#
        The tick's start: the bound, then the drain lease (cfg.InstallState @StateName 'drainUntilUtc': taken when none is
        set or it has run out). Answers ONE row: HasTable, Taken, Dropped, Said.
    #>
    $bound = Get-SIUplinkOutboxBoundSql
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.UplinkOutbox') IS NULL OR OBJECT_ID(N'cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS HasTable, CAST(0 AS int) AS Taken, CAST(0 AS bigint) AS Dropped, CAST(0 AS bigint) AS Said;
ELSE
BEGIN
$bound
    BEGIN TRAN;
    DECLARE @v NVARCHAR(400) = NULL, @has int = 0;
    SELECT @v = Value, @has = 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @StateName;
    IF ISNULL(ISJSON(@v), 0) <> 1 SET @v = N'{"dropped":0,"said":0}';
    DECLARE @until DATETIME2(0) = TRY_CONVERT(DATETIME2(0), JSON_VALUE(@v, '$.drainUntilUtc'), 127);
    DECLARE @taken int = CASE WHEN @until IS NULL OR @until <= @NowUtc THEN 1 ELSE 0 END;
    IF @taken = 1
    BEGIN
        SET @v = JSON_MODIFY(@v, '$.drainUntilUtc', CONVERT(NVARCHAR(19), DATEADD(MINUTE, @LeaseMinutes, @NowUtc), 126) + N'Z');
        IF @has = 1 UPDATE cfg.InstallState SET Value = @v, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @StateName;
        ELSE INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@StateName, @v, NULL, @By);
    END
    COMMIT;
    SELECT CAST(1 AS int) AS HasTable, @taken AS Taken,
           ISNULL(TRY_CONVERT(bigint, JSON_VALUE(@v, '$.dropped')), 0) AS Dropped, ISNULL(TRY_CONVERT(bigint, JSON_VALUE(@v, '$.said')), 0) AS Said;
END
"@
}

function Get-SIUplinkOutboxEndSql {
    <# The tick's end: the drops said so far recorded (@Said); the lease released only by the execution that holds it (@Release = 1). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    UPDATE cfg.InstallState
       SET Value = CASE WHEN @Release = 1
                        THEN JSON_MODIFY(JSON_MODIFY(CASE WHEN ISJSON(Value) = 1 THEN Value ELSE N'{}' END, '$.drainUntilUtc', NULL), '$.said', CAST(@Said AS bigint))
                        ELSE JSON_MODIFY(CASE WHEN ISJSON(Value) = 1 THEN Value ELSE N'{}' END, '$.said', CAST(@Said AS bigint)) END,
           UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
     WHERE Name = @StateName;
'@
}

function Get-SIUplinkOutboxReadSql {
    <# The next @Take rows, OLDEST first (by the time kept, then the row id). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.UplinkOutbox') IS NOT NULL
    SELECT TOP (@Take) OutboxId, Job, Kind, RecordJson, CONVERT(NVARCHAR(23), CreatedUtc, 126) AS CreatedUtc, Attempts
    FROM cfg.UplinkOutbox ORDER BY CreatedUtc, OutboxId;
'@
}

function Get-SIUplinkOutboxTakenSql { 'DELETE FROM cfg.UplinkOutbox WHERE OutboxId = @Id;' }

function Get-SIUplinkOutboxNotTakenSql {
    'UPDATE cfg.UplinkOutbox SET Attempts = Attempts + 1, LastAttemptUtc = @NowUtc, LastAnswer = @Answer WHERE OutboxId = @Id;'
}

function Get-SIUplinkOutboxBacklogSql {
    <# What is still to send: Pending (rows) and OldestUtc -- both NULL when the table is not there yet (not known). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.UplinkOutbox') IS NULL
    SELECT CAST(NULL AS bigint) AS Pending, CAST(NULL AS DATETIME2(3)) AS OldestUtc;
ELSE
    SELECT COUNT_BIG(*) AS Pending, MIN(CreatedUtc) AS OldestUtc FROM cfg.UplinkOutbox;
'@
}

function ConvertTo-SIUplinkOutboxRows {
    <# PURE. Whatever a database seam answers (ONE array of rows, rows one by one, a single row) as rows. #>
    param($Answer)
    foreach ($x in @($Answer)) {
        if ($null -eq $x -or $x -is [DBNull]) { continue }
        if ($x -is [array]) { foreach ($y in $x) { if ($null -ne $y -and -not ($y -is [DBNull])) { $y } } } else { $x }
    }
}

function Get-SIUplinkOutboxValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [DBNull]) { return $null }
    $v
}

function Get-SIUplinkOutboxParams {
    <# The parameters every statement here shares. #>
    param([Parameter(Mandatory)][datetime]$NowUtc)
    $c = $script:SIUplinkOutbox
    [ordered]@{ NowUtc = $NowUtc.ToUniversalTime(); MaxDays = [int]$c.MaxDays; MaxRows = [int]$c.MaxRows; StateName = [string]$c.StateName; By = [string]$c.By }
}

# =====================================================================================================================
#  1. JOB END -- one cheap insert
# =====================================================================================================================
function Add-SIUplinkOutboxRecord {
    <#
        Keep ONE record that Invardia did not take (-Json: the record as it would have been sent; -Answer: what the uplink
        said). $true = kept. NEVER throws: no database, no table yet (an install one update behind) or a failed insert is
        $false -- a failure is said ONCE per process and the record is dropped.
    #>
    param([scriptblock]$Invoke, [AllowEmptyString()][string]$Job, [AllowEmptyString()][string]$Json, [AllowNull()][AllowEmptyString()][string]$Answer,
          [string]$Kind = 'run', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        if (-not $Invoke -or -not "$Job".Trim() -or -not "$Json".Trim()) { return $false }
        if ($script:SIUplinkOutbox.Kinds -notcontains $Kind) { return $false }
        $p = Get-SIUplinkOutboxParams -NowUtc $NowUtc
        $p.Job = ("$Job".Trim()); if ($p.Job.Length -gt 64) { $p.Job = $p.Job.Substring(0, 64) }
        $p.Kind = $Kind; $p.Json = $Json; $p.Answer = (ConvertTo-SIUplinkOutboxAnswer $Answer)
        $rows = @(ConvertTo-SIUplinkOutboxRows (& $Invoke (Get-SIUplinkOutboxInsertSql) $p 'reader'))
        if (-not $rows.Count) { return $true }
        return ([int](Get-SIUplinkOutboxValue $rows[0] 'Kept') -eq 1)
    } catch {
        if (-not $global:SI_UplinkOutboxWarned) {
            $global:SI_UplinkOutboxWarned = $true
            try { Write-Warning ("The status report could not be kept for a later send either ({0}). The run is not affected." -f (ConvertTo-SIUplinkOutboxAnswer $_.Exception.Message)) } catch { }
        }
        return $false
    }
}

# =====================================================================================================================
#  The backlog -- what the heartbeat field UplinkBacklog says
# =====================================================================================================================
function ConvertTo-SIUplinkBacklog {
    <#
        PURE. UplinkBacklog { pending, oldestUtc, checkedUtc } from the backlog row (Pending, OldestUtc): EXACTLY these
        three keys; pending a whole number >= 0, oldestUtc ISO-8601 UTC or null, checkedUtc ISO-8601 UTC (always). Caught up
        = pending 0, oldestUtc null -- a value, never "empty". $null = not known (no table yet / not read): the field is left out.
    #>
    param($Row, [Parameter(Mandatory)][datetime]$NowUtc)
    $n = Get-SIUplinkOutboxValue $Row 'Pending'
    if ($null -eq $n -or "$n".Trim() -eq '') { return $null }
    $cnt = 0L
    if (-not [long]::TryParse("$n".Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$cnt) -or $cnt -lt 0) { return $null }
    $iso = { param($v)
        if ($null -eq $v -or "$v".Trim() -eq '') { return $null }
        $d = $null
        if ($v -is [datetime]) { $d = $(if ($v.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($v, 'Utc') } else { $v.ToUniversalTime() }) }
        else { try { $d = [datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { return $null } }
        $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $old = if ($cnt -gt 0) { & $iso (Get-SIUplinkOutboxValue $Row 'OldestUtc') } else { $null }
    [pscustomobject][ordered]@{ pending = [int][Math]::Min($cnt, [long][int]::MaxValue); oldestUtc = $old; checkedUtc = (& $iso $NowUtc) }
}

function Get-SIUplinkOutboxBacklog {
    <# The backlog read through -Invoke (the Pro database). $null = no database, no table yet, or not readable. Never throws. #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$NowUtc)
    try {
        if (-not $Invoke) { return $null }
        $rows = @(ConvertTo-SIUplinkOutboxRows (& $Invoke (Get-SIUplinkOutboxBacklogSql) @{} 'reader'))
        if (-not $rows.Count) { return $null }
        ConvertTo-SIUplinkBacklog -Row $rows[0] -NowUtc $NowUtc
    } catch { $null }
}

# =====================================================================================================================
#  2. THE HEARTBEAT TICK -- the drain, in rounds
# =====================================================================================================================
function Invoke-SIUplinkOutboxDrain {
    <#
        Send the kept records again: OLDEST first, at most -RoundSize POSTs per round, -RoundWaitSec (at least 65) between
        rounds (-Sleep { param($Seconds) }, the test seam), at most -MaxRounds rounds. A record taken is deleted; the first
        record NOT taken stops the drain (its attempt counted, the record kept). -Send { param($Record) } -> @{ Status; Reason }
        (default: Send-SITelemetryRecordWithFallback through -Transport with -Context). Returns @{ Sent; Rounds; Stopped;
        Why; Order }. Throws only when the database cannot be read (the tick says it).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Send, [Parameter(Mandatory)][datetime]$NowUtc,
          [scriptblock]$Sleep, [int]$RoundSize = $script:SIUplinkOutbox.RoundSize, [int]$RoundWaitSec = $script:SIUplinkOutbox.RoundWaitSec,
          [int]$MaxRounds = $script:SIUplinkOutbox.MaxRounds, [scriptblock]$Clock)
    if ($RoundWaitSec -lt 65) { $RoundWaitSec = 65 }
    if (-not $Sleep) { $Sleep = { param($Seconds) Start-Sleep -Seconds $Seconds } }
    if (-not $Clock) { $Clock = { [datetime]::UtcNow } }
    $out = [pscustomobject]@{ Sent = 0; Rounds = 0; Stopped = $false; Why = ''; Order = (New-Object System.Collections.Generic.List[long]) }
    while ($out.Rounds -lt $MaxRounds) {
        $rows = @(ConvertTo-SIUplinkOutboxRows (& $Invoke (Get-SIUplinkOutboxReadSql) ([ordered]@{ Take = [int]$RoundSize }) 'reader'))
        if (-not $rows.Count) { break }
        # the rounds keep Invardia's rate limit: a wait BEFORE every round but the first, and only when there is more to send
        if ($out.Rounds -gt 0) { & $Sleep $RoundWaitSec }
        $out.Rounds++
        foreach ($row in $rows) {
            $id = [long](Get-SIUplinkOutboxValue $row 'OutboxId')
            $r = $null
            try {
                $rec = ConvertFrom-SIUplinkOutboxJson -Json ([string](Get-SIUplinkOutboxValue $row 'RecordJson'))
                $r = & $Send $rec
            } catch { $r = [pscustomobject]@{ Status = 'failed'; Reason = ('the kept record could not be sent: {0}' -f $_.Exception.Message) } }
            $out.Order.Add($id)
            $now = ([datetime](& $Clock)).ToUniversalTime()
            if ($r -and "$($r.Status)" -eq 'ok') {
                $null = & $Invoke (Get-SIUplinkOutboxTakenSql) ([ordered]@{ Id = $id }) 'nonquery'
                $out.Sent++
                continue
            }
            $why = ConvertTo-SIUplinkOutboxAnswer $(if ($r) { [string]$r.Reason } else { 'no answer' })
            try { $null = & $Invoke (Get-SIUplinkOutboxNotTakenSql) ([ordered]@{ Id = $id; NowUtc = $now; Answer = $why }) 'nonquery' } catch { }
            $out.Stopped = $true; $out.Why = $why
            break
        }
        if ($out.Stopped) { break }
        if ($rows.Count -lt $RoundSize) { break }
    }
    $out
}

function Invoke-SIUplinkOutboxTick {
    <#
        The outbox's part of ONE heartbeat tick -- called LAST in the tick, after the heartbeat itself. NEVER throws; returns
        @{ Status; Sent; Left; Dropped; Lines } -- Status: disabled | skipped | no-table | busy | held | caught-up | drained |
        stopped | error. Every input is a seam (tests):
          -Invoke            the Pro database (required: no database = skipped)
          -HeartbeatStatus   this tick's heartbeat (Send-SIHeartbeatTick's Status): failed / error = Invardia did not take
                             it, nothing is sent from the outbox this tick (the bound and the drop count still run)
          -Context / -Transport / -Send   the sender (default: this install's context, Send-SITelemetryUplink through
                             Send-SITelemetryRecordWithFallback); a test session sends nothing without -Transport or -Send
          -Sleep / -Now      the wait between rounds and the clock
    #>
    [CmdletBinding()]
    param([scriptblock]$Invoke, [AllowEmptyString()][string]$HeartbeatStatus = '', $Context, [scriptblock]$Transport, [scriptblock]$Send,
          [scriptblock]$Sleep, $Now, [hashtable]$Rounds = @{})
    $lines = New-Object System.Collections.Generic.List[string]
    $out = { param($s, $sent, $left, $dropped) [pscustomobject]@{ Status = $s; Sent = [int]$sent; Left = $left; Dropped = [long]$dropped; Lines = $lines.ToArray() } }
    $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
    $leased = $false; $said = $null; $c = $script:SIUplinkOutbox
    try {
        if ((Get-Command -Name Test-SITelemetryEnabled -ErrorAction SilentlyContinue) -and -not (Test-SITelemetryEnabled)) { return (& $out 'disabled' 0 $null 0) }
        if (-not $Invoke) { return (& $out 'skipped' 0 $null 0) }
        $p = Get-SIUplinkOutboxParams -NowUtc $nowUtc
        $p.LeaseMinutes = [int]$c.LeaseMinutes
        $b = @(ConvertTo-SIUplinkOutboxRows (& $Invoke (Get-SIUplinkOutboxBeginSql) $p 'reader'))
        $b0 = if ($b.Count) { $b[0] } else { $null }
        if (-not $b0 -or [int](Get-SIUplinkOutboxValue $b0 'HasTable') -ne 1) { return (& $out 'no-table' 0 $null 0) }
        $dropped = [long](Get-SIUplinkOutboxValue $b0 'Dropped'); $saidBefore = [long](Get-SIUplinkOutboxValue $b0 'Said')
        $leased = ([int](Get-SIUplinkOutboxValue $b0 'Taken') -eq 1)
        # the drops not said yet -- ONCE, in this tick's line (the count keeps growing; "said" remembers how far it was said)
        $newDrops = $dropped - $saidBefore
        if ($newDrops -gt 0) {
            $lines.Add(('Invardia support link, run results: {0} unsent run report(s) were dropped -- older than {1} days or beyond {2:N0} kept (the oldest go first); {3} dropped in all' -f $newDrops, $c.MaxDays, $c.MaxRows, $dropped))
            $said = $dropped
        }
        if (-not $leased) { $lines.Add('Invardia support link, run results: another execution is sending the kept run reports -- nothing sent from here'); return (& $out 'busy' 0 $null $newDrops) }
        if ($HeartbeatStatus -in @('failed', 'error')) {
            $left = Get-SIUplinkOutboxBacklog -Invoke $Invoke -NowUtc $nowUtc
            if ($left -and $left.pending -gt 0) { $lines.Add(('Invardia support link, run results: {0} run report(s) kept; not sent this tick -- Invardia did not take the heartbeat' -f $left.pending)) }
            return (& $out 'held' 0 $(if ($left) { $left.pending } else { $null }) $newDrops)
        }
        if (-not $Send) {
            if (-not $Transport -and (Get-Module -Name Pester)) { return (& $out 'skipped' 0 $null $newDrops) }
            if (-not $Context -and (Get-Command -Name Get-SITelemetryContext -ErrorAction SilentlyContinue)) { $Context = Get-SITelemetryContext }
            if (-not $Context -or [string]$Context.Mode -ne 'identified') { return (& $out 'skipped' 0 $null $newDrops) }
            if (-not $Transport) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-SITelemetryUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
            $obCtx = $Context; $obTr = $Transport; $obTo = 5
            try { $obTo = [int](Get-SITelemetrySendState).TimeoutSec } catch { $obTo = 5 }
            # PLAIN, not a closure: the drain calls it in this function's scope chain, so $obCtx / $obTr / $obTo are the ones
            # here -- and the sender's functions are found where the caller loaded them (a closure sees only global ones)
            $Send = { param($Record) (Send-SITelemetryRecordWithFallback -Record $Record -Transport $obTr -Context $obCtx -TimeoutSec $obTo -NowUtc ([datetime]::UtcNow)).Result }
        }
        $da = @{ Invoke = $Invoke; Send = $Send; NowUtc = $nowUtc; Sleep = $Sleep }
        foreach ($k in 'RoundSize', 'RoundWaitSec', 'MaxRounds') { if ($Rounds.ContainsKey($k)) { $da[$k] = [int]$Rounds[$k] } }
        $d = Invoke-SIUplinkOutboxDrain @da
        $left = Get-SIUplinkOutboxBacklog -Invoke $Invoke -NowUtc $nowUtc
        $leftN = if ($left) { $left.pending } else { $null }
        if ($d.Stopped) {
            $lines.Add(('Invardia support link, run results: {0} kept run report(s) sent, then Invardia did not take the next ({1}) -- the rest stay for the next tick ({2} kept)' -f $d.Sent, $d.Why, $(if ($null -ne $leftN) { $leftN } else { 'unknown' })))
            return (& $out 'stopped' $d.Sent $leftN $newDrops)
        }
        if ($d.Sent -gt 0) {
            $lines.Add(('Invardia support link, run results: {0} kept run report(s) sent in {1} round(s){2}' -f $d.Sent, $d.Rounds, $(if ($leftN) { ('; {0} left for the next tick' -f $leftN) } else { '; caught up' })))
            return (& $out 'drained' $d.Sent $leftN $newDrops)
        }
        & $out 'caught-up' 0 $leftN $newDrops
    } catch {
        $lines.Add(('Invardia support link, run results: not sent this tick ({0})' -f (ConvertTo-SIUplinkOutboxAnswer $_.Exception.Message)))
        & $out 'error' 0 $null 0
    } finally {
        if ($leased -or $null -ne $said) {
            $sv = if ($null -ne $said) { [long]$said } else { [long]$saidBefore }
            try { $null = & $Invoke (Get-SIUplinkOutboxEndSql) ([ordered]@{ StateName = [string]$c.StateName; By = [string]$c.By; Said = $sv; Release = $(if ($leased) { 1 } else { 0 }) }) 'nonquery' } catch { }
        }
    }
}
