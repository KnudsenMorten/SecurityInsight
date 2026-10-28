#Requires -Version 5.1
<#
    SecurityInsight -- THE STATE OF EACH SOURCE (owner 2026-10-12: "a source dropout should not block ci calculation, then
    use latest avail collection from the source" / "last known state is sufficient to send if a source is not working").

    A SOURCE is one collection step of the pipeline (identity / azure / endpoint / publicip). The pipeline runner tells
    this store how each collection ended (engine\_shared\SI-JobFlow.ps1, -SourceState):

      Good     the collection ended well: the source's last good collection is this one.
      Dropped  the collection did not end well. Two things happen, in ONE statement:
                 1. nothing it wrote counts as a complete collection. A feed (provider + record type) the failed step had
                    already closed since it started (a collection in several processes: one of them died) is HELD: its
                    row in sidata.RecordCollection says so, and ONE of its records is marked "not complete" -- the CI
                    build reads a feed's completeness from its newest collection's records (Get-SICiFeedLatestSql), so
                    every record the collection did not reach stays FROZEN (it keeps its CI active) instead of turning
                    'not seen'. A collection that never closed is not complete already (SI-RecordSql.ps1: the feed close).
                 2. the source is recorded as on its last good collection (sidata.SourceState: LastGoodAt stays, the
                    attempt and the first moment it dropped are kept) -- what the run's sentence, the data sync and the
                    finding lifecycle read.

    The two tables come from sql\si-data-schema.sql (the updater applies it); on a database that does not have them yet
    every statement here answers "nothing" and changes nothing. SQL over the (sql, params, mode) seam the record writer
    uses (New-SIRecordSqlInvoke: every parameter is text; mode 'rows' answers objects). Free code, both editions.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

function Get-SISourceStateSql {
    <# The T-SQL of the source state (one place; the real-SQL test runs it against sql\si-data-schema.sql). Times are ISO
       text (@sinceText, @nowText); a feed the step wrote counts from 5 minutes before the step started (clocks differ). #>
    param([Parameter(Mandatory)][ValidateSet('Good', 'Dropped', 'Read')][string]$Name)
    switch ($Name) {
        'Good' { @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.SourceState') IS NULL BEGIN SELECT CAST(NULL AS DATETIME2(3)) AS LastGoodAt, 0 AS Held; RETURN; END
DECLARE @since DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@sinceText, N''), 127);
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
DECLARE @good DATETIME2(3) = NULL;
IF OBJECT_ID('sidata.RecordCollection') IS NOT NULL
    SELECT @good = MAX(CollectionTime) FROM sidata.RecordCollection
    WHERE Engine = @source AND State = N'good' AND CollectionTime >= DATEADD(minute, -5, ISNULL(@since, @now));
SET @good = COALESCE(@good, @since, @now);
MERGE sidata.SourceState AS t
USING (SELECT @source AS Source) AS s ON t.Source = s.Source
WHEN MATCHED THEN UPDATE SET LastGoodAt = @good, LastAttemptAt = @now, LastAttemptOk = 1, DroppedSince = NULL, Detail = NULL, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Source, LastGoodAt, LastAttemptAt, LastAttemptOk) VALUES (@source, @good, @now, 1);
SELECT @good AS LastGoodAt, 0 AS Held;
'@ }
        'Dropped' { @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.SourceState') IS NULL BEGIN SELECT CAST(NULL AS DATETIME2(3)) AS LastGoodAt, 0 AS Held; RETURN; END
DECLARE @since DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@sinceText, N''), 127);
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
DECLARE @from DATETIME2(3) = DATEADD(minute, -5, ISNULL(@since, @now));
DECLARE @held INT = 0, @before DATETIME2(3) = NULL;
BEGIN TRANSACTION;
IF OBJECT_ID('sidata.RecordCollection') IS NOT NULL
BEGIN
    -- 1. every feed this collection had closed since the step started is held: it did not end well
    DECLARE @h TABLE (Provider NVARCHAR(32) NOT NULL, RecordType NVARCHAR(32) NOT NULL, CollectionTime DATETIME2(3) NOT NULL);
    UPDATE sidata.RecordCollection SET State = N'held', Reason = LEFT(N'the collection did not complete: ' + ISNULL(@why, N''), 400), UpdatedAt = SYSUTCDATETIME()
    OUTPUT inserted.Provider, inserted.RecordType, inserted.CollectionTime INTO @h (Provider, RecordType, CollectionTime)
    WHERE Engine = @source AND State = N'good' AND CollectionTime >= @from;
    SET @held = @@ROWCOUNT;
    IF @held > 0
    BEGIN
        -- one record of each held feed's collection says "not complete": the CI build then freezes what that collection missed
        ;WITH x AS (SELECT r.RecordKey, ROW_NUMBER() OVER (PARTITION BY r.Provider, ISNULL(r.RecordType, N'') ORDER BY r.RecordKey) AS n
                   FROM sidata.CiRecord r JOIN @h h ON h.Provider = r.Provider AND h.RecordType = ISNULL(r.RecordType, N'') AND h.CollectionTime = r.CollectionTime)
        UPDATE r SET Complete = 0 FROM sidata.CiRecord r JOIN x ON x.RecordKey = r.RecordKey WHERE x.n = 1;
    END
    -- a source that dropped before its state was ever recorded: its last good collection is the newest one it closed before
    SELECT @before = MAX(CollectionTime) FROM sidata.RecordCollection WHERE Engine = @source AND State = N'good' AND CollectionTime < @from;
END
-- 2. the source is on its last good collection
MERGE sidata.SourceState AS t
USING (SELECT @source AS Source) AS s ON t.Source = s.Source
WHEN MATCHED THEN UPDATE SET LastGoodAt = ISNULL(t.LastGoodAt, @before), LastAttemptAt = @now, LastAttemptOk = 0, DroppedSince = ISNULL(t.DroppedSince, @now),
     Detail = LEFT(ISNULL(@why, N''), 400), UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Source, LastGoodAt, LastAttemptAt, LastAttemptOk, DroppedSince, Detail) VALUES (@source, @before, @now, 0, @now, LEFT(ISNULL(@why, N''), 400));
COMMIT TRANSACTION;
SELECT LastGoodAt, @held AS Held FROM sidata.SourceState WHERE Source = @source;
'@ }
        'Read' { @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.SourceState') IS NULL
    SELECT CAST(NULL AS NVARCHAR(32)) AS Source, CAST(NULL AS DATETIME2(3)) AS LastGoodAt, CAST(NULL AS DATETIME2(3)) AS LastAttemptAt, CAST(NULL AS BIT) AS LastAttemptOk,
           CAST(NULL AS DATETIME2(3)) AS DroppedSince, CAST(NULL AS NVARCHAR(400)) AS Detail WHERE 1 = 0
ELSE
    SELECT Source, LastGoodAt, LastAttemptAt, LastAttemptOk, DroppedSince, Detail FROM sidata.SourceState ORDER BY Source;
'@ }
    }
}

function ConvertTo-SISourceStateTime {
    <# PURE. A time as the ISO text the statements take ('' for none); a database time back as UTC [datetime] or $null. #>
    param($Value, [switch]$FromDb)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value" -eq '') { if ($FromDb) { return $null } else { return '' } }
    if ($FromDb) {
        if ($Value -is [datetime]) { return [datetime]::SpecifyKind([datetime]$Value, 'Utc') }
        try { return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { return $null }
    }
    ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-SISourceStateRow {
    <# PURE. A sidata.SourceState row (object or hashtable) as @{ Source; LastGoodUtc; LastAttemptUtc; Ok; DroppedSinceUtc; Detail }. #>
    param($Row)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { $Row = [pscustomobject]$Row }
    $g = { param($n) if ($Row.PSObject.Properties[$n]) { $Row.$n } else { $null } }
    $ok = & $g 'LastAttemptOk'
    [pscustomobject]@{ Source = [string](& $g 'Source'); LastGoodUtc = (ConvertTo-SISourceStateTime (& $g 'LastGoodAt') -FromDb); LastAttemptUtc = (ConvertTo-SISourceStateTime (& $g 'LastAttemptAt') -FromDb)
                       Ok = ($null -eq $ok -or $ok -is [DBNull] -or "$ok" -in @('True', '1')); DroppedSinceUtc = (ConvertTo-SISourceStateTime (& $g 'DroppedSince') -FromDb)
                       Detail = $(if ($null -eq (& $g 'Detail') -or (& $g 'Detail') -is [DBNull]) { '' } else { [string](& $g 'Detail') }) }
}

function New-SISourceStateStore {
    <#
        The source state over the database seam -Invoke { param($Sql, $Params, $Mode) } (New-SIRecordSqlInvoke, or a test's).
        Good($Source, $SinceUtc, $NowUtc) and Dropped($Source, $SinceUtc, $NowUtc, $Why) answer when that source last
        collected completely (UTC, or $null: never recorded); Read() answers every source's row. The methods throw on a
        database error -- the pipeline runner catches it, says it and goes on.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $o = [pscustomobject]@{ Invoke = $Invoke }
    $o | Add-Member -MemberType ScriptMethod -Name Good -Value {
        param($Source, $SinceUtc, $NowUtc)
        $r = @(& $this.Invoke (Get-SISourceStateSql 'Good') @{ source = ([string]$Source).ToLowerInvariant(); sinceText = (ConvertTo-SISourceStateTime $SinceUtc); nowText = (ConvertTo-SISourceStateTime $NowUtc) } 'rows' | ForEach-Object { $_ }) | Select-Object -First 1
        if ($r -is [System.Collections.IDictionary]) { $r = [pscustomobject]$r }
        if ($r) { ConvertTo-SISourceStateTime $r.LastGoodAt -FromDb } else { $null }
    }
    $o | Add-Member -MemberType ScriptMethod -Name Dropped -Value {
        param($Source, $SinceUtc, $NowUtc, $Why)
        $r = @(& $this.Invoke (Get-SISourceStateSql 'Dropped') @{ source = ([string]$Source).ToLowerInvariant(); sinceText = (ConvertTo-SISourceStateTime $SinceUtc); nowText = (ConvertTo-SISourceStateTime $NowUtc); why = [string]$Why } 'rows' | ForEach-Object { $_ }) | Select-Object -First 1
        if ($r -is [System.Collections.IDictionary]) { $r = [pscustomobject]$r }
        if ($r) { ConvertTo-SISourceStateTime $r.LastGoodAt -FromDb } else { $null }
    }
    $o | Add-Member -MemberType ScriptMethod -Name Read -Value {
        # flattened first: the data sync's seam hands the rows back as ONE array object, which would be read as a single row
        @(& $this.Invoke (Get-SISourceStateSql 'Read') @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { ConvertFrom-SISourceStateRow $_ } | Where-Object { $_ -and $_.Source })
    }
    $o
}

function Get-SISourceDropouts {
    <#
        The sources that are on their LAST GOOD collection right now (their newest collection did not end well):
        @(@{ Source; LastGoodUtc; DroppedSinceUtc; Detail }). Never throws: a database that cannot be read answers none
        (and says so through -Log) -- callers that must be careful treat "cannot tell" themselves.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    try {
        @((New-SISourceStateStore -Invoke $Invoke).Read() | Where-Object { -not $_.Ok })
    } catch {
        if ($Log) { & $Log 'WARN' ('the state of the sources could not be read ({0})' -f $_.Exception.Message) }
        @()
    }
}

# =====================================================================================================================
#  WHAT RESTS ON A DROPPED SOURCE -- only that is frozen (owner 2026-10-12: "Freeze only if ALL its sources are down")
# =====================================================================================================================
# While a source is on its last good collection, a finding or ticket that goes missing is FROZEN (never counted absent,
# never closed) only when EVERY source that describes its CI is down; a CI that at least one healthy source still
# describes closes its findings as usual. What can be told with certainty is which CIs a source describes: the feeds
# (provider + record type) each collection step writes are registered when a collection closes
# (sidata.RecordCollection.Engine), and sidata.CiRecord says which CI every record belongs to -- the unit is the CI:
#   FROZEN   every CI that has a record in a feed of a dropped source and NO record in a feed of a healthy source,
#            every owner that is not a CI, and every CI no record points to;
#   AS USUAL every CI that a healthy source describes (also when a dropped source describes it too), and every CI no
#            dropped source describes.
#   (A feed that both a dropped and a healthy collection step write counts as dropped; a record of a feed no collection
#   step registered -- a CMDB record -- is no evidence either way.)
# THE KNOWN CONSEQUENCE, accepted by the owner: a finding that ONLY the dropped source could see, on a CI another source
# still describes, can be counted absent and closed after the usual complete runs although nothing shows a fix. It opens
# again, as reopened, when that source is back.
# A dropped source whose feeds are not known (nothing registered in the last 30 days) cannot be attributed at all: then
# nothing is closed in that run (Known = $false).

function Get-SISourceDropoutOwnersSql {
    <# The T-SQL of the per-source freeze. 'Sources': each dropped source and how many feeds are known for it.
       'Lifecycle': the finding-lifecycle OWNER keys to freeze (the CIs ONLY dropped sources describe, and the open owners
       that cannot be attributed). 'Cis': every CI that has records, N = 1 when only dropped sources describe it. #>
    param([Parameter(Mandatory)][ValidateSet('Sources', 'Lifecycle', 'Cis')][string]$Name)
    $head = @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.SourceState') IS NULL OR OBJECT_ID('sidata.RecordCollection') IS NULL OR OBJECT_ID('sidata.CiRecord') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(450)) AS K, 0 AS N WHERE 1 = 0;
    RETURN;
END
'@
    $feeds = @'
WITH f AS (SELECT DISTINCT c.Provider, c.RecordType
           FROM sidata.RecordCollection c JOIN sidata.SourceState d ON d.Source = c.Engine
           WHERE d.LastAttemptOk = 0 AND c.CollectionTime >= DATEADD(day, -30, SYSUTCDATETIME())),
     g AS (SELECT DISTINCT c.Provider, c.RecordType
           FROM sidata.RecordCollection c
           WHERE c.CollectionTime >= DATEADD(day, -30, SYSUTCDATETIME()) AND c.Engine <> N''
             AND NOT EXISTS (SELECT 1 FROM sidata.SourceState d WHERE d.Source = c.Engine AND d.LastAttemptOk = 0)
             AND NOT EXISTS (SELECT 1 FROM f WHERE f.Provider = c.Provider AND f.RecordType = c.RecordType)),
     x AS (SELECT r.CiId, MAX(CASE WHEN f.Provider IS NULL THEN 0 ELSE 1 END) AS Down, MAX(CASE WHEN g.Provider IS NULL THEN 0 ELSE 1 END) AS Healthy
           FROM sidata.CiRecord r
           LEFT JOIN f ON f.Provider = r.Provider AND f.RecordType = ISNULL(r.RecordType, N'')
           LEFT JOIN g ON g.Provider = r.Provider AND g.RecordType = ISNULL(r.RecordType, N'')
           WHERE r.CiId IS NOT NULL GROUP BY r.CiId)
'@
    switch ($Name) {
        'Sources' { $head + @'

SELECT d.Source AS K,
       (SELECT COUNT(*) FROM (SELECT DISTINCT c.Provider, c.RecordType FROM sidata.RecordCollection c
                              WHERE c.Engine = d.Source AND c.CollectionTime >= DATEADD(day, -30, SYSUTCDATETIME())) x) AS N
FROM sidata.SourceState d WHERE d.LastAttemptOk = 0;
'@ }
        # ONE result set (a seam may read only the first): the CIs a dropped source describes, and the open owners that are
        # not a CI or whose CI no record points to. No lifecycle table = no lifecycle rows = nothing to freeze.
        'Lifecycle' { $head + @'

IF OBJECT_ID('sidata.CiFindingState') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(450)) AS K, 0 AS N WHERE 1 = 0;
    RETURN;
END
;
'@ + $feeds + @'
,
-- an open owner under an asset key (no CI id; an empty one is none): the CIs its asset is PROVEN to belong to -- a stored
-- finding of a CI that names the asset id, or the CI link of the asset's own id
oa AS (SELECT DISTINCT s.OwnerKey FROM sidata.CiFindingState s
       WHERE s.State <> N'closed' AND NULLIF(s.CiId, N'') IS NULL AND s.OwnerKey LIKE N'asset:%'),
lk AS (SELECT oa.OwnerKey, cf.CiId FROM oa JOIN sidata.CiFinding cf ON N'asset:' + LOWER(cf.AssetId) = oa.OwnerKey
       WHERE NULLIF(cf.CiId, N'') IS NOT NULL AND NULLIF(cf.AssetId, N'') IS NOT NULL
       UNION
       SELECT oa.OwnerKey, l.CiId FROM oa JOIN sidata.CiLink l ON l.NativeId = SUBSTRING(oa.OwnerKey, 7, 450)),
-- unfrozen ONLY when the link is proven (exactly one CI) AND every source of that CI is on a current collection (its
-- records rest on no dropped source, and on at least one healthy one); anything unproven stays frozen
pv AS (SELECT k.OwnerKey FROM lk k GROUP BY k.OwnerKey
       HAVING COUNT(DISTINCT k.CiId) = 1 AND EXISTS (SELECT 1 FROM x WHERE x.CiId = MIN(k.CiId) AND x.Down = 0 AND x.Healthy = 1))
SELECT CAST(x.CiId AS NVARCHAR(450)) AS K, 1 AS N
FROM x WHERE x.Down = 1 AND x.Healthy = 0
UNION
SELECT s.OwnerKey AS K, 0 AS N FROM sidata.CiFindingState s
WHERE s.State <> N'closed' AND (NULLIF(s.CiId, N'') IS NULL OR NOT EXISTS (SELECT 1 FROM sidata.CiRecord r WHERE r.CiId = s.CiId))
  AND NOT EXISTS (SELECT 1 FROM pv WHERE pv.OwnerKey = s.OwnerKey);
'@ }
        'Cis' { $head + @'

;
'@ + $feeds + @'

SELECT x.CiId AS K, CASE WHEN x.Down = 1 AND x.Healthy = 0 THEN 1 ELSE 0 END AS N FROM x;
'@ }
    }
}

function Get-SISourceDropoutOwners {
    <#
        What must be frozen while a source is on its last good collection. -For Lifecycle (default): .Owners = the finding
        lifecycle's owner keys to freeze. -For Cis: .Healthy = the CI keys (lower case) whose records are all from healthy
        sources -- every other asset is frozen (Test-SISourceAssetFrozen).
        Returns @{ Dropouts; Known; Owners; Unlinked; Healthy; Why } (Unlinked: the open owners frozen because no CI with current sources is proven for them). No source dropped: Dropouts empty, Known $true, nothing frozen.
        Known = $false when it cannot be told what rests on a dropped source (its feeds are not registered, or the database
        could not be read) -- the caller then closes NOTHING in that run. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [ValidateSet('Lifecycle', 'Cis')][string]$For = 'Lifecycle', [scriptblock]$Log)
    $out = [ordered]@{ Dropouts = @(); Known = $true; Owners = @(); Unlinked = 0; Healthy = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)); Why = '' }
    $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r -and $r.PSObject.Properties[$n]) { $r.$n } else { $null } }
    try {
        $out.Dropouts = @((New-SISourceStateStore -Invoke $Invoke).Read() | Where-Object { -not $_.Ok })
        if (-not $out.Dropouts.Count) { return [pscustomobject]$out }
        $known = @{}
        foreach ($r in @(& $Invoke (Get-SISourceDropoutOwnersSql 'Sources') @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })) { $known[[string](& $val $r 'K')] = [int](& $val $r 'N') }
        $blind = @($out.Dropouts | Where-Object { -not $known.ContainsKey([string]$_.Source) -or $known[[string]$_.Source] -lt 1 } | ForEach-Object { [string]$_.Source })
        if ($blind.Count) {
            $out.Known = $false
            $out.Why = ('which assets {0} describes is not known yet (no complete collection of it is registered)' -f ($blind -join ', '))
            return [pscustomobject]$out
        }
        $rows = @(& $Invoke (Get-SISourceDropoutOwnersSql $For) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if ($For -eq 'Cis') {
            foreach ($r in $rows) { $k = [string](& $val $r 'K'); if ($k -and [int](& $val $r 'N') -eq 0) { [void]$out.Healthy.Add($k.Trim()) } }
        } else {
            $out.Owners = @($rows | ForEach-Object { [string](& $val $_ 'K') } | Where-Object { $_ } | Sort-Object -Unique)
            # the open owners frozen because no CI is proven for them (or their CI's sources are not shown current): counted, said
            $out.Unlinked = @($rows | Where-Object { [int](& $val $_ 'N') -eq 0 -and [string](& $val $_ 'K') }).Count
        }
    } catch {
        $out.Known = $false
        $out.Why = ('what rests on the dropped source could not be read ({0})' -f $_.Exception.Message)
        if ($Log) { & $Log 'WARN' $out.Why }
    }
    [pscustomobject]$out
}

function Test-SISourceAssetFrozen {
    <# PURE. Is this asset (its CI key) frozen while a source is on its last good collection? Yes unless it is a CI whose
       records are all from healthy sources (-Freeze: Get-SISourceDropoutOwners -For Cis). No source dropped: never. #>
    param([AllowEmptyString()][AllowNull()][string]$Key, $Freeze)
    if ($null -eq $Freeze -or -not @($Freeze.Dropouts).Count) { return $false }
    $k = ([string]$Key).Trim()
    if (-not $k) { return $true }
    -not $Freeze.Healthy.Contains($k)
}

# =====================================================================================================================
#  THE AGE OF A SOURCE -- known, said, and after 7 days it holds delivery (owner 2026-10-12: "last known state is
#  sufficient to send if a source is not working" -- for a while: SI_Pro_SourceDropout_HoldDeliveryDays, default 7)
# =====================================================================================================================
function Get-SISourceAgeDays {
    <# PURE. How many days a source has been without a good collection: 0 while its newest collection completed; else the
       days since its last good collection (a source that never had one: since it first dropped). #>
    param($Source, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Source -or $Source.Ok) { return 0.0 }
    $from = $null
    if ($Source.LastGoodUtc) { $from = ([datetime]$Source.LastGoodUtc).ToUniversalTime() } elseif ($Source.DroppedSinceUtc) { $from = ([datetime]$Source.DroppedSinceUtc).ToUniversalTime() }
    if ($null -eq $from) { return 0.0 }
    [math]::Round([math]::Max(0.0, ($NowUtc.ToUniversalTime() - $from).TotalDays), 2)
}

function Get-SISourceHoldDays {
    <# PURE. After how many days without a good collection of a source delivery waits: SI_Pro_SourceDropout_HoldDeliveryDays,
       default 7; 0 = delivery never waits for a source; anything that is not a whole number from 0 to 365 = the default. #>
    param($Value = $global:SI_Pro_SourceDropout_HoldDeliveryDays)
    $n = 0
    if ($null -ne $Value -and [int]::TryParse(([string]$Value).Trim(), [ref]$n) -and $n -ge 0 -and $n -le 365) { return $n }
    7
}

function Get-SISourceAgeText {
    <# PURE. One plain line per source that is on its last good collection, with how old that collection is:
       "endpoint has had no good collection for 3 days -- its data is from 2026-10-09 14:05 UTC". #>
    param([AllowEmptyCollection()][object[]]$Sources = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    foreach ($s in @($Sources | Where-Object { $_ -and -not $_.Ok })) {
        $d = Get-SISourceAgeDays -Source $s -NowUtc $NowUtc
        $age = if ($d -lt 1) { '{0} hour(s)' -f [int][math]::Floor($d * 24) } else { '{0} day(s)' -f [int][math]::Floor($d) }
        if ($s.LastGoodUtc) { '{0} has had no good collection for {1} -- its data is from {2} UTC' -f $s.Source, $age, ([datetime]$s.LastGoodUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', $inv) }
        else { '{0} has had no good collection for {1}' -f $s.Source, $age }
    }
}

function Get-SISourceDeliveryHold {
    <#
        PURE. Why delivery must wait, or '' when it need not: a source has had no good collection for -HoldDays days or
        more. The calculation (the CI build, Risk Analysis) goes on; mails, tickets and the other delivery steps wait until
        that source collects again -- what they would send rests on data that old. -HoldDays 0 = never.
    #>
    param([AllowEmptyCollection()][object[]]$Sources = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$HoldDays = 7)
    if ($HoldDays -le 0) { return '' }
    $old = @($Sources | Where-Object { $_ -and -not $_.Ok -and (Get-SISourceAgeDays -Source $_ -NowUtc $NowUtc) -ge $HoldDays })
    if (-not $old.Count) { return '' }
    'delivery waits: {0} had no good collection for {1} days or more ({2}) -- nothing is mailed and no ticket is changed until that source collects again; the calculation goes on' -f `
        ((@($old | ForEach-Object { [string]$_.Source })) -join ', '), $HoldDays,
        ((@($old | ForEach-Object { '{0}: {1} days' -f $_.Source, [int][math]::Floor((Get-SISourceAgeDays -Source $_ -NowUtc $NowUtc)) })) -join ', ')
}

# =====================================================================================================================
#  LABELLED EVERYWHERE -- the same sentence on the pages, on an export's info sheet and in the mails
# =====================================================================================================================
function Get-SISourceLabel {
    <# PURE. A source as a person reads it: Endpoint / Identity / Azure / Public IP scan (the web app says the same). #>
    param([AllowEmptyString()][AllowNull()][string]$Source)
    switch (([string]$Source).Trim().ToLowerInvariant()) {
        'endpoint' { 'Endpoint' } 'identity' { 'Identity' } 'azure' { 'Azure' } 'publicip' { 'Public IP scan' } default { [string]$Source }
    }
}

function Get-SISourceNoteText {
    <# PURE. "Endpoint data is from 2026-10-10 14:05 UTC -- the last collection from that source did not complete." #>
    param([AllowEmptyString()][AllowNull()][string]$Source, $LastGoodUtc)
    $when = 'its last good collection'
    if ($LastGoodUtc) { $when = ([datetime]$LastGoodUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' }
    '{0} data is from {1} -- the last collection from that source did not complete.' -f (Get-SISourceLabel $Source), $when
}

function Get-SISourceCollectionMarkSql {
    <#
        ONE statement, at the end of every data sync: each loaded collection that was produced while a source was on its
        last good collection gets a row saying which source and from when (sidata.CollectionSource) -- what the web app
        shows when that collection is opened later. A collection is marked once; marks of collections that are gone are
        cleared. Answers the rows added. Guarded: without the tables it does nothing.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CollectionSource') IS NULL OR OBJECT_ID('sidata.SourceState') IS NULL OR OBJECT_ID('sidata.Collection') IS NULL
BEGIN
    SELECT 0 AS Marked;
    RETURN;
END
DELETE FROM sidata.CollectionSource WHERE NOT EXISTS (SELECT 1 FROM sidata.Collection AS c WHERE c.CollectionId = sidata.CollectionSource.CollectionId);
INSERT sidata.CollectionSource (CollectionId, Source, LastGoodAt)
SELECT c.CollectionId, s.Source, s.LastGoodAt
FROM sidata.Collection AS c CROSS JOIN sidata.SourceState AS s
WHERE s.LastAttemptOk = 0 AND c.Status = N'Complete'
  AND c.CollectionTime >= ISNULL(s.DroppedSince, c.CollectionTime)
  AND NOT EXISTS (SELECT 1 FROM sidata.CollectionSource AS x WHERE x.CollectionId = c.CollectionId AND x.Source = s.Source);
SELECT @@ROWCOUNT AS Marked;
'@
}

function Invoke-SISourceCollectionMark {
    <# The data sync's call: marks the loaded collections (Get-SISourceCollectionMarkSql). Never throws; returns the rows added. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    try {
        $n = & $Invoke (Get-SISourceCollectionMarkSql) @{} 'scalar'
        if ($null -eq $n -or $n -is [DBNull]) { return 0 }
        if ([int]$n -gt 0 -and $Log) { & $Log 'INFO' ("sources     : {0} collection(s) marked as calculated while a source was on its last good collection" -f [int]$n) }
        [int]$n
    } catch {
        if ($Log) { & $Log 'WARN' ("sources     : the collections could not be marked ({0}) -- the web app shows the current state of the sources only" -f $_.Exception.Message) }
        0
    }
}

# the mails: read once per process (a job sends its mails within minutes), from the install's database
$script:SISourceMailNotes = $null

function Get-SISourceMailNotes {
    <#
        The sentence(s) a mail carries while a source is on its last good collection -- none when every source collected.
        -Invoke: the database seam (default: the install's database, when one is configured). Never throws; read once per
        process (-Fresh reads again).
    #>
    param([scriptblock]$Invoke, [switch]$Fresh)
    if (-not $Fresh -and -not $Invoke -and $null -ne $script:SISourceMailNotes) { return @($script:SISourceMailNotes) }
    $notes = @()
    try {
        if (-not $Invoke) {
            if (-not ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase)) { return @() }
            if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-RecordSql.ps1')) }
            $Invoke = New-SIRecordSqlInvoke
            if (-not $Invoke) { return @() }
            $notes = @(Get-SISourceDropouts -Invoke $Invoke | ForEach-Object { Get-SISourceNoteText -Source $_.Source -LastGoodUtc $_.LastGoodUtc })
            $script:SISourceMailNotes = $notes
        } else {
            $notes = @(Get-SISourceDropouts -Invoke $Invoke | ForEach-Object { Get-SISourceNoteText -Source $_.Source -LastGoodUtc $_.LastGoodUtc })
        }
    } catch { $notes = @() }
    @($notes)
}

function Get-SISourceDropoutText {
    <# PURE. "endpoint (data from 2026-10-10 14:05 UTC)" for each source on its last good collection, joined; '' for none. #>
    param([AllowEmptyCollection()][object[]]$Dropouts = @())
    $inv = [Globalization.CultureInfo]::InvariantCulture
    (@($Dropouts | Where-Object { $_ } | ForEach-Object {
        if ($_.LastGoodUtc) { '{0} (data from {1} UTC)' -f $_.Source, ([datetime]$_.LastGoodUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', $inv) } else { '{0} (its last good collection)' -f $_.Source }
    })) -join ', '
}
