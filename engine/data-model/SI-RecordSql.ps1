#Requires -Version 5.1
<#
    PROVIDER RECORDS IN SQL (#477, V3-DATA-MODEL 2.20 -- operator 2026-10-08/09: correlation in SQL ONLY, SQL in every v3
    install; "la is only for kusto risk analysis"). Every batch of records a profiler captures is written to the install's
    database -- and ONLY there (a copy to Log Analytics is the optional export SI_LaExport, never read back):

      sidata.CiRecord          one row per record key (provider, type, class, name, collection time, complete, the record
                               as JSON, its CONTENT HASH) -- MERGE by key; the CI a record belongs to (CiId) is kept
      sidata.RecordIdentifier  the record's strong identifiers (the identity ledger's types -- the SAME extraction the CI
                               build groups on, Get-SIRecordIdentifiers) -- narrow and indexed

    COST (#501, operator: "performance and cost must be optimed"): a record whose CONTENT did not change (the hash leaves out
    what changes every run: collection time, run id, complete) keeps its JSON and its identifiers -- only its collection
    time and completeness are set (one set-based statement for the batch; the link state reads them). A changed record
    gets its JSON, hash and identifiers rewritten.
    A failed write is said and counted; it never fails the profiler (the profile rows are unaffected), but the CIs of a
    run with missing records are built from what the database holds.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIRecordIdentifiers -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-CiBuild.ps1') }
if (-not (Get-Command -Name Get-SIObjectLedgerConnection -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'identity\SI-ObjectLedgerStore.ps1') }

# the fields that change on every run without the record changing -- left out of the content hash; the first three are
# kept as COLUMNS (CollectionTime, Complete, SourceLastSeen) and the CI build reads them from the columns, not the JSON
$script:SIRecordVolatileFields = @('si_collection_time', 'si_collection_complete', 'si_source_last_seen', 'si_run_id')

function Get-SIContentHash {
    <#
        PURE. SHA-256 (hex) of an object's content WITHOUT the -Exclude fields: the keys in ordinal order, compact JSON --
        the same content always gives the same hash on every host (no culture, no key order).
    #>
    param([Parameter(Mandatory)]$Item, [string[]]$Exclude = @())
    $o = [ordered]@{}
    $names = New-Object System.Collections.Generic.List[string]
    if ($Item -is [System.Collections.IDictionary]) { foreach ($k in $Item.Keys) { $names.Add([string]$k) } }
    else { foreach ($p in $Item.PSObject.Properties) { $names.Add([string]$p.Name) } }
    $arr = $names.ToArray(); [Array]::Sort($arr, [StringComparer]::Ordinal)
    foreach ($n in $arr) {
        if ($Exclude -contains $n) { continue }
        if ($Item -is [System.Collections.IDictionary]) { $o[$n] = $Item[$n] } else { $o[$n] = $Item.PSObject.Properties[$n].Value }
    }
    $json = ConvertTo-Json -InputObject $o -Compress -Depth 14
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($json))) -replace '-', '') }
    finally { $sha.Dispose() }
}

# 🔴 THE IDENTIFIER KEY MUST FIT SQL SERVER'S 900-BYTE CLUSTERED KEY. sidata.RecordIdentifier's key is RecordKey + IdType +
# IdValue, and an Azure resource's record key ("azure:<resource id>") plus its resource id identifier is longer: one such
# record made the whole batch's write fail ("The index entry of length 906 bytes for the index 'PK_RecordIdentifier'
# exceeds the maximum length of 900 bytes"), on every run, so no Azure record reached the database, their CIs were no
# longer built, and Risk Analysis lost the CI -- tier, risk factors, classification (the SQL tag) -- of every cloud resource.
# The schema is additive-only (no key change), so a LONG identifier value is stored as its SHA-256 instead. The decision
# depends on the value alone, so the same identifier is the same stored value on every record (the grouping compares
# equality only), and the readers that match a plain value against the table hash it the same way
# (Get-SIRecordIdValueSqlExpr). A record whose key is still too long is written without that identifier, with a warning,
# instead of failing the batch.
$script:SIRecordIdValueMaxChars = 128
$script:SIRecordIdKeyMaxBytes = 900

function ConvertTo-SIRecordIdValue {
    <# PURE. The stored form of an identifier value: the value (lower-cased), or 'sha256:' + the lower-case hex SHA-256 of its
       UTF-16LE bytes when it is longer than 128 characters -- what T-SQL HASHBYTES('SHA2_256', <nvarchar>) answers. #>
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return $null }
    $v = $Value.Trim().ToLowerInvariant()
    if ($v.Length -le $script:SIRecordIdValueMaxChars) { return $v }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ('sha256:' + (([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($v))) -replace '-', '').ToLowerInvariant())) }
    finally { $sha.Dispose() }
}

function Get-SIRecordIdValueSqlExpr {
    <# PURE. The T-SQL expression that turns a plain identifier value <Expr> into its stored form (ConvertTo-SIRecordIdValue). #>
    param([Parameter(Mandatory)][string]$Expr)
    "(CASE WHEN LEN($Expr) > $($script:SIRecordIdValueMaxChars) THEN N'sha256:' + LOWER(CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CAST(LOWER(LTRIM(RTRIM($Expr))) AS NVARCHAR(4000))), 2)) ELSE LOWER(LTRIM(RTRIM($Expr))) END)"
}

function ConvertTo-SIRecordSqlItems {
    <#
        PURE. Record rows (the record rows of one batch) -> @{ Records = [CiRecord items]; Identifiers = [items] }.
        A row without a record key is left out. Every record carries its content hash (Hash, hex).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [datetime]$Now = [datetime]::UtcNow, [hashtable]$TypeMap = (Get-SICiLedgerTypeMap),
          # #882 -DeferDoc: no DocJson yet (Write-SIRecordsToSql builds it only for the records that changed); the rows each
          # record came from are answered as Sources (same order as Records)
          [switch]$DeferDoc)
    $srcs = New-Object System.Collections.Generic.List[object]
    $recs = New-Object System.Collections.Generic.List[object]
    $ids = New-Object System.Collections.Generic.List[object]
    $iso = { param($v) if ($null -eq $v -or "$v" -eq '') { $null } elseif ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { [string]$v } }
    # one record per key (the database compares keys without case): the LAST row of a key wins, whole -- never a mix of
    # two rows' columns, and only that row's identifiers
    $last = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::OrdinalIgnoreCase)
    $all = @($Rows)
    for ($n = 0; $n -lt $all.Count; $n++) {
        if ($null -eq $all[$n]) { continue }
        $k = [string](Get-SIItemValue $all[$n] 'si_record_key'); if ($k) { $last[$k] = $n }
    }
    for ($n = 0; $n -lt $all.Count; $n++) {
        $r = $all[$n]
        if ($null -eq $r) { continue }
        $key = [string](Get-SIItemValue $r 'si_record_key')
        if (-not $key -or $last[$key] -ne $n) { continue }
        $complete = Get-SIItemValue $r 'si_collection_complete'
        $recs.Add([ordered]@{
            RecordKey = $key; Provider = [string](Get-SIItemValue $r 'si_provider'); RecordType = [string](Get-SIItemValue $r 'si_record_type')
            Class = [string](Get-SIItemValue $r 'si_class'); Name = [string](Get-SIItemValue $r 'si_asset_name')
            SourceLastSeen = (& $iso (Get-SIItemValue $r 'si_source_last_seen')); CollectionTime = (& $iso (Get-SIItemValue $r 'si_collection_time'))
            Complete = $(if ($null -eq $complete) { $null } else { [bool]($complete -eq $true -or "$complete" -match '^(?i)true|1$') })
            Hash = (Get-SIContentHash -Item $r -Exclude $script:SIRecordVolatileFields)
            DocJson = $(if ($DeferDoc) { $null } else { ConvertTo-Json -InputObject $r -Compress -Depth 12 })
        })
        $srcs.Add($r)
        foreach ($i in (Get-SIRecordIdentifiers -Record $r -TypeMap $TypeMap)) {
            $iv = ConvertTo-SIRecordIdValue ([string]$i.Value)
            if (2 * ($key.Length + ([string]$i.Type).Length + $iv.Length) -gt $script:SIRecordIdKeyMaxBytes) {
                $script:SIRecordIdTooLong++
                continue
            }
            $ids.Add([ordered]@{ RecordKey = $key; IdType = [string]$i.Type; IdValue = $iv; SeenAt = $Now.ToUniversalTime().ToString('o') })
        }
    }
    $o = [pscustomobject]@{ Records = $recs.ToArray(); Identifiers = $ids.ToArray() }
    if ($DeferDoc) { $o | Add-Member -NotePropertyName Sources -NotePropertyValue $srcs.ToArray() }
    $o
}

function Get-SIRecordSqlChangedKeysSql {
    <#
        #882 -- ONLY WHAT CHANGED IS SENT. One read before a batch is written: of the batch's records (@deltaKeys = [{ RecordKey; Hash }]),
        which are new or carry another content hash than the stored one (@deltaKeys: a parameter name no other statement uses -- the seams and tests tell the statements apart by it). Answers ONE row: DeltaAsked (how many keys were
        asked -- the caller trusts the answer only when it matches) and ChangedKeys (JSON [{ RecordKey }]). Read-only.
        Measured at a large install (2026-10-21): 2.5 million records a run, 1.43 million of them on-premises AD identities
        93 % unchanged -- each sent whole (its document) and parsed by the database on every run.
    #>
    @'
SET NOCOUNT ON;
DECLARE @k TABLE (RecordKey NVARCHAR(450) PRIMARY KEY, Hash VARBINARY(32));
INSERT @k SELECT RecordKey, MAX(CONVERT(VARBINARY(32), Hash, 2))
FROM OPENJSON(@deltaKeys) WITH (RecordKey NVARCHAR(450), Hash VARCHAR(64)) WHERE RecordKey IS NOT NULL GROUP BY RecordKey;
SELECT (SELECT COUNT(*) FROM @k) AS DeltaAsked,
       (SELECT k.RecordKey FROM @k k LEFT JOIN sidata.CiRecord t ON t.RecordKey = k.RecordKey
        WHERE t.RecordKey IS NULL OR t.ContentHash IS NULL OR t.ContentHash <> k.Hash FOR JSON PATH) AS ChangedKeys;
'@
}

function Get-SIRecordSqlChangedKeys {
    <#
        #882: the keys of -Records (ConvertTo-SIRecordSqlItems items) that are new or changed in the database, as a
        case-insensitive set -- or $null when that cannot be shown (no answer, an answer that does not count every key asked,
        an error): then every record is sent whole, as before. Never throws.
    #>
    param([AllowEmptyCollection()][object[]]$Records = @(), [Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $hk = @(foreach ($x in @($Records)) { if ($null -ne $x) { [ordered]@{ RecordKey = [string]$x.RecordKey; Hash = [string]$x.Hash } } })
        if (-not $hk.Count) { return $null }
        $res = @(& $Invoke (Get-SIRecordSqlChangedKeysSql) @{ deltaKeys = (ConvertTo-SIJsonArray $hk) } 'rows')
        $row = $null; if ($res.Count -gt 0) { $row = $res[0] }
        if ($null -eq $row) { return $null }
        $asked = Get-SIItemValue $row 'DeltaAsked'
        if ($null -eq $asked -or $asked -is [System.DBNull]) { return $null }
        $distinct = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in $hk) { [void]$distinct.Add([string]$x.RecordKey) }
        if ([int]$asked -ne $distinct.Count) { return $null }
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $json = Get-SIItemValue $row 'ChangedKeys'
        if ($null -ne $json -and $json -isnot [System.DBNull] -and "$json".Trim()) {
            foreach ($c in @(ConvertFrom-Json -InputObject ([string]$json))) { if ($null -ne $c -and [string]$c.RecordKey) { [void]$set.Add([string]$c.RecordKey) } }
        }
        , $set
    } catch { $null }
}

function Get-SIRecordSqlWriteSql {
    <#
        The ONE statement a batch is written with. New or CHANGED records (hash differs): the whole row and their
        identifiers. Unchanged records: only the collection time, completeness and source last-seen. Answers one row:
        Seen (the batch), Changed (new + changed), and the identifier rows written.
        ONE WRITER AT A TIME (record-deadlock, 2026-10-26): several processes publish one run's buckets at once, and two of
        them deadlocked on sidata.CiRecord (SQL error 1205 -- their keys are disjoint, but the UPDATE moves the collection
        time in three indexes and the joins can scan). So the transaction first takes the database's application lock
        'si-record-write', owned by the TRANSACTION (freed by its commit or rollback, never left behind), waiting up to
        -LockMs. Not free in time: error 51222, retried like a lock timeout (Write-SIRecordsToSql). Only this write waits --
        the merging, the conversion and the changed-keys read stay parallel. Which records changed is read INSIDE the
        lock, so it is what the write sees. -LockMs 0 = no lock (only the tests' measurement uses it).
        SAFE TO RERUN: SET XACT_ABORT ON rolls the whole transaction back on any error (a deadlock victim too) and ends
        the batch; a rerun is a new batch that declares its table variables again from @r / @i and reads @changed again
        from what is committed -- the same input gives the same rows (proven on a real SQL Server: SIv3-RecordDeadlock).
    #>
    param([int]$LockMs = 120000)
    $lock = ''
    if ($LockMs -gt 0) {
        $lock = ("DECLARE @lk INT;`n" +
            "EXEC @lk = sp_getapplock @Resource = N'si-record-write', @LockMode = N'Exclusive', @LockOwner = N'Transaction', @LockTimeout = {0};`n" +
            "IF @lk < 0 BEGIN DECLARE @lkm NVARCHAR(300) = CONCAT(N'the record write lock (si-record-write) was not free in {1} s (sp_getapplock answered ', @lk, N')'); THROW 51222, @lkm, 1; END;`n") -f [int]$LockMs, [int][Math]::Ceiling($LockMs / 1000.0)
    }
    (@'
SET XACT_ABORT ON;
SET NOCOUNT ON;
DECLARE @s TABLE (RecordKey NVARCHAR(450) PRIMARY KEY, Provider NVARCHAR(32), RecordType NVARCHAR(32), Class NVARCHAR(16), Name NVARCHAR(400),
    SourceLastSeen DATETIME2(3), CollectionTime DATETIME2(3), Complete BIT, Hash VARBINARY(32), DocJson NVARCHAR(MAX));
INSERT @s SELECT RecordKey, MAX(Provider), MAX(RecordType), MAX(Class), MAX(Name), MAX(SourceLastSeen), MAX(CollectionTime), CAST(MAX(CAST(Complete AS INT)) AS BIT),
    MAX(CONVERT(VARBINARY(32), Hash, 2)), MAX(DocJson)
FROM OPENJSON(@r) WITH (RecordKey NVARCHAR(450), Provider NVARCHAR(32), RecordType NVARCHAR(32), Class NVARCHAR(16), Name NVARCHAR(400),
    SourceLastSeen DATETIME2(3), CollectionTime DATETIME2(3), Complete BIT, Hash VARCHAR(64), DocJson NVARCHAR(MAX))
WHERE RecordKey IS NOT NULL GROUP BY RecordKey;
DECLARE @changed TABLE (RecordKey NVARCHAR(450) PRIMARY KEY);
BEGIN TRANSACTION;
{WRITELOCK}INSERT @changed SELECT s.RecordKey FROM @s s LEFT JOIN sidata.CiRecord t ON t.RecordKey = s.RecordKey
WHERE (t.RecordKey IS NULL OR t.ContentHash IS NULL OR t.ContentHash <> s.Hash) AND s.DocJson IS NOT NULL;
UPDATE t SET CollectionTime = s.CollectionTime, Complete = s.Complete, SourceLastSeen = s.SourceLastSeen
FROM sidata.CiRecord t JOIN @s s ON s.RecordKey = t.RecordKey
WHERE s.RecordKey NOT IN (SELECT RecordKey FROM @changed)
  AND (t.CollectionTime <> s.CollectionTime OR ISNULL(t.Complete, 1) <> ISNULL(s.Complete, 1) OR ISNULL(t.SourceLastSeen, '19000101') <> ISNULL(s.SourceLastSeen, '19000101'));
MERGE sidata.CiRecord AS t
USING (SELECT s.* FROM @s s JOIN @changed c ON c.RecordKey = s.RecordKey) AS s
ON t.RecordKey = s.RecordKey
WHEN MATCHED THEN UPDATE SET Provider = s.Provider, RecordType = s.RecordType, Class = s.Class, Name = s.Name, SourceLastSeen = s.SourceLastSeen,
    CollectionTime = s.CollectionTime, Complete = s.Complete, ContentHash = s.Hash, DocJson = s.DocJson
WHEN NOT MATCHED THEN INSERT (RecordKey, Provider, RecordType, Class, Name, SourceLastSeen, CollectionTime, Complete, ContentHash, DocJson)
    VALUES (s.RecordKey, s.Provider, s.RecordType, s.Class, s.Name, s.SourceLastSeen, s.CollectionTime, s.Complete, s.Hash, s.DocJson);
DELETE ri FROM sidata.RecordIdentifier ri WHERE ri.RecordKey IN (SELECT RecordKey FROM @changed);
INSERT sidata.RecordIdentifier (RecordKey, IdType, IdValue, SeenAt)
SELECT DISTINCT x.RecordKey, x.IdType, x.IdValue, x.SeenAt FROM OPENJSON(@i) WITH (RecordKey NVARCHAR(450), IdType NVARCHAR(40), IdValue NVARCHAR(400), SeenAt DATETIME2(3)) x
WHERE x.RecordKey IN (SELECT RecordKey FROM @changed) AND x.IdValue IS NOT NULL;
DECLARE @ids INT = @@ROWCOUNT;
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM @s) AS Seen, (SELECT COUNT(*) FROM @changed) AS Changed, @ids AS Identifiers;
'@).Replace('{WRITELOCK}', $lock)
}

# a batch write that lost a DEADLOCK (1205) or waited too long for a lock (1222; 51222 = the record write lock above) is
# written again -- the statement is safe to rerun (Get-SIRecordSqlWriteSql). Attempts in all, and the first wait (doubled
# each time, plus 0-100 % at random so two losers do not meet again). Tests set the wait to almost nothing.
$script:SIRecordWriteAttempts = 4
$script:SIRecordWriteRetryMs = 500

function Get-SIRecordWriteRetryReason {
    <#
        PURE. Why a failed batch write may be tried again: 'deadlock' (SQL error 1205), 'lock timeout' (1222, or 51222 = the
        record write lock was not free in time) -- or $null (any other failure: not retried). Reads the SqlException's
        numbers through the inner exceptions, else the text Format-SISqlError makes ("SQL error 1205 (line ...").
    #>
    param($Exception)
    $nums = New-Object System.Collections.Generic.List[int]
    $texts = New-Object System.Collections.Generic.List[string]
    $e = $Exception
    while ($e) {
        $texts.Add([string]$e.Message)
        if ($e -is [System.Data.SqlClient.SqlException]) { foreach ($x in $e.Errors) { $nums.Add([int]$x.Number) } }
        $e = $e.InnerException
    }
    foreach ($t in $texts) { foreach ($m in [regex]::Matches($t, 'SQL error (\d+)\b')) { $nums.Add([int]$m.Groups[1].Value) } }
    if ($nums.Contains(1205)) { return 'deadlock' }
    if ($nums.Contains(1222) -or $nums.Contains(51222)) { return 'lock timeout' }
    $null
}

function Write-SIRecordsToSql {
    <#
        One batch of record rows -> the database. -Invoke { param($Sql, $Params, $Mode) } is the SQL seam (tests; a caller's
        store; Mode 'rows' answers objects). Returns @{ Seen; Changed; Identifiers; Failed }; never throws (a failure is a
        warning and Failed = the batch's records).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$Now = [datetime]::UtcNow,
          # THE FEED CLOSE (New-SIRecordFeedClose): with it, the first record of each feed in this batch is written "not
          # complete" until the whole collection is in (Complete-SIRecordFeeds), and a failed batch is counted on it
          $Close,
          # what this batch is, for the log lines ("bucket 7"); empty = "a batch of N record(s)"
          [string]$What = '',
          # how long the write waits for the record write lock (Get-SIRecordSqlWriteSql); 0 = no lock (tests' measurement)
          [int]$LockMs = 120000)
    $items = $null
    $attempt = 0; $why = $null
    $pinned = @()
    try {
        $script:SIRecordIdTooLong = 0
        if ($Close) { $pinned = @(Set-SIRecordFeedPins -Rows $Rows -Close $Close | Where-Object { $null -ne $_ }) }
        $changedKeys = $null
        try {
            $items = ConvertTo-SIRecordSqlItems -Rows $Rows -Now $Now -DeferDoc
            # #882: ONLY WHAT CHANGED IS SENT WHOLE -- the database says which records are new or changed (their content hash);
            # an unchanged record goes with its key and hash only (its collection time, completeness and last-seen are
            # updated as before). When that cannot be shown, every record is sent whole, as before.
            $changedKeys = Get-SIRecordSqlChangedKeys -Records @($items.Records) -Invoke $Invoke
            for ($ri = 0; $ri -lt @($items.Records).Count; $ri++) {
                $rec = $items.Records[$ri]
                if ($null -eq $changedKeys -or $changedKeys.Contains([string]$rec.RecordKey)) { $rec.DocJson = ConvertTo-Json -InputObject $items.Sources[$ri] -Compress -Depth 12 }
            }
            if ($null -ne $changedKeys) { $items.Identifiers = @($items.Identifiers | Where-Object { $changedKeys.Contains([string]$_.RecordKey) }) }
        }
        finally { foreach ($pr in $pinned) { $pr.si_collection_complete = $true } }   # the rows themselves are handed on unchanged
        if ($script:SIRecordIdTooLong -gt 0) {
            Write-Warning ('records: {0} identifier(s) left out -- their record key is too long for the identifier index (900 bytes); those records are kept and grouped by their other identifiers.' -f $script:SIRecordIdTooLong)
        }
        if ($items.Records.Count -eq 0) { return [pscustomobject]@{ Seen = 0; Changed = 0; Identifiers = 0; Failed = 0 } }
        $p = @{ r = (ConvertTo-SIJsonArray $items.Records); i = (ConvertTo-SIJsonArray $items.Identifiers) }
        # A DEADLOCK OR A LOCK TIMEOUT IS WRITTEN AGAIN (record-deadlock, 2026-10-26: 3,632 of 36,011 records of a run were
        # lost to two 1205s). The statement is safe to rerun: it rolled back in full. Any other failure, or the last attempt,
        # fails the batch exactly as before -- said and counted, never a silent loss.
        $writeSql = Get-SIRecordSqlWriteSql -LockMs $LockMs
        $max = [Math]::Max(1, [int]$script:SIRecordWriteAttempts)
        $res = $null
        $label = $What; if (-not $label) { $label = 'a batch of {0} record(s)' -f @($items.Records).Count }
        for ($attempt = 1; $attempt -le $max; $attempt++) {
            try { $res = @(& $Invoke $writeSql $p 'rows'); break }
            catch {
                $why = Get-SIRecordWriteRetryReason -Exception $_.Exception
                if (-not $why -or $attempt -ge $max) { throw }
                $waitMs = [int]([double]$script:SIRecordWriteRetryMs * [Math]::Pow(2, $attempt - 1) * (1.0 + (Get-Random -Minimum 0.0 -Maximum 1.0)))
                Write-Warning ('records: {0} on {1}, attempt {2} of {3} -- retried in {4:0.0} s' -f $why, $label, $attempt, $max, ($waitMs / 1000.0))
                Start-Sleep -Milliseconds $waitMs
            }
        }
        if ($attempt -gt 1) { Write-Host ('[INFO] records: {0} written on attempt {1} of {2} (after a {3})' -f $label, $attempt, $max, $why) }
        $row = $null; if ($res.Count -gt 0) { $row = $res[0] }
        [pscustomobject]@{ Seen = [int](Get-SIItemValue $row 'Seen'); Changed = [int](Get-SIItemValue $row 'Changed'); Identifiers = [int](Get-SIItemValue $row 'Identifiers'); Failed = 0 }
    } catch {
        $n = 0; if ($items) { $n = @($items.Records).Count }
        $tries = ''; if ($why -and $attempt -gt 1) { $tries = (' -- FAILED after {0} attempts, the last a {1}' -f $attempt, $why) }
        $where = ''; if ($What) { $where = ' of ' + $What }
        Write-Warning ('records: {0} record(s){1} could not be written to the database{2} -- {3}. The next run writes them again.' -f $n, $where, $tries, $_.Exception.Message)
        if ($Close) { $Close.Failed = [int]$Close.Failed + [Math]::Max(1, $n) }
        [pscustomobject]@{ Seen = 0; Changed = 0; Identifiers = 0; Failed = $n }
    }
}

# =====================================================================================================================
#  THE FEED CLOSE -- a half-written collection never counts as a complete one
# =====================================================================================================================
# The CI build reads, per feed (provider + record type), the NEWEST collection time and whether every record of it says
# "complete" (Get-SICiFeedLatestSql); a record missing from a complete newer collection turns 'not seen'. The records of
# one collection are written in batches, by one process or by several. A collection that stopped half-way -- the process
# ended, a batch could not be written -- must not look like a complete one that simply has fewer records: every record it
# did not reach would turn 'not seen', and CIs would be retired by a failure.
# So the FIRST record of each feed in every batch is written "not complete" (a PIN), and the pins are set to complete in
# ONE statement when every batch of the collection is in (Complete-SIRecordFeeds) -- which also registers the collection
# (sidata.RecordCollection: who wrote it, how many records). A collection that never closed keeps its pins: its feed's
# newest collection is not complete, so what it missed is FROZEN (it keeps its CI active). Cost: one extra statement per
# collection and a handful of rows. Absence is never read from a collection that did not close.

function New-SIRecordFeedClose {
    <# The close of ONE collection (one engine run): the pins written so far, the feeds seen, the batches that failed. #>
    param([string]$Engine = '')
    [pscustomobject]@{ Engine = ([string]$Engine).Trim().ToLowerInvariant(); Pins = (New-Object System.Collections.Generic.List[string])
                       Feeds = @{}; Incomplete = @{}; Failed = 0; PinFeed = @{} }
}

function Set-SIRecordFeedPins {
    <#
        PURE (changes -Rows in place; the caller sets them back). The first record of each feed in this batch whose pull
        was complete is marked "not complete" and remembered on -Close. A feed whose own pull was NOT complete is only
        noted (its records already say so, and it is not registered as a good collection). Returns the rows it pinned.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)]$Close)
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $key = [string](Get-SIItemValue $r 'si_record_key')
        if (-not $key) { continue }
        $feed = Get-SIRecordFeed $r
        $c = Get-SIItemValue $r 'si_collection_complete'
        if ($null -ne $c -and -not ($c -eq $true -or "$c" -match '^(?i)(true|1)$')) { $Close.Incomplete[$feed] = $true; continue }
        $Close.Feeds[$feed] = $true
        if ($seen.ContainsKey($feed)) { continue }
        if (-not ($r -is [psobject]) -or -not $r.PSObject.Properties['si_collection_complete']) { continue }
        $seen[$feed] = $true
        $r.si_collection_complete = $false
        $Close.Pins.Add($key)
        if ($Close.PSObject.Properties['PinFeed']) { $Close.PinFeed[$key] = $feed }
        $out.Add($r)
    }
    # each pinned row by itself (never the list as ONE object: the caller sets every row back, one by one)
    $out.ToArray()
}

function Get-SIRecordFeedCloseSql {
    <#
        The ONE statement that closes a collection: @k = the pinned record keys (JSON array of text), @f = its feeds
        ([{ Provider; RecordType }]), @ctText = the collection time (ISO), @engine = the collection step that wrote it.
        The pins become complete; each feed's collection is registered with its record count (a collection a failed step
        already had HELD stays held). Answers Closed (pins set) and Feeds (registered).
        A feed may carry State 'drop' and a Reason (the asset-drop guard keeps the last good collection: one of its pins is
        then left out of @k by the caller, so that feed's collection stays "not complete").
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @ct DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@ctText, N''), 127);
DECLARE @n INT = 0, @feeds INT = 0;
BEGIN TRANSACTION;
UPDATE r SET Complete = 1
FROM sidata.CiRecord r JOIN OPENJSON(@k) WITH (RecordKey NVARCHAR(450) '$') k ON k.RecordKey = r.RecordKey
WHERE r.CollectionTime = @ct AND r.Complete = 0;
SET @n = @@ROWCOUNT;
IF OBJECT_ID('sidata.RecordCollection') IS NOT NULL
BEGIN
    MERGE sidata.RecordCollection AS t
    USING (SELECT f.Provider, ISNULL(f.RecordType, N'') AS RecordType, f.State, f.Reason,
                  (SELECT COUNT(*) FROM sidata.CiRecord r WHERE r.Provider = f.Provider AND ISNULL(r.RecordType, N'') = ISNULL(f.RecordType, N'') AND r.CollectionTime = @ct) AS Records
           FROM OPENJSON(@f) WITH (Provider NVARCHAR(32), RecordType NVARCHAR(32), State NVARCHAR(16), Reason NVARCHAR(400)) f WHERE f.Provider IS NOT NULL) AS s
    ON t.Provider = s.Provider AND t.RecordType = s.RecordType AND t.CollectionTime = @ct
    WHEN MATCHED THEN UPDATE SET Records = s.Records, UpdatedAt = SYSUTCDATETIME(),
         State = CASE WHEN t.State = N'held' OR s.State IS NULL THEN t.State ELSE s.State END, Reason = ISNULL(s.Reason, t.Reason)
    WHEN NOT MATCHED THEN INSERT (Provider, RecordType, CollectionTime, Engine, Records, State, Reason) VALUES (s.Provider, s.RecordType, @ct, @engine, s.Records, ISNULL(s.State, N'good'), s.Reason);
    SET @feeds = @@ROWCOUNT;
END
COMMIT TRANSACTION;
SELECT @n AS Closed, @feeds AS Feeds;
'@
}

# =====================================================================================================================
#  THE ASSET-DROP GUARD (collection.source.asset-drop) -- the customer decides (owner 2026-10-12: "what happens with
#  assets, make guard, let customer decide. it can be deletion of many azure ress")
# =====================================================================================================================
# A collection can COMPLETE and still carry far fewer assets than before: a real clean-up (many Azure resources removed),
# or a source that answered only in part. Findings and vulnerabilities go up and down and are never judged by count; the
# RECORDS of a feed (provider + record type: devices, users, Azure resources ...) are assets, and they are judged here,
# when the collection closes -- BEFORE the CI build reads the feed:
#   the feed's record count against its LAST GOOD collection, down by SI_Pro_DataQuality_AssetDropPercent (30 %) or more,
#   and only when that last good collection had at least 20 records (a small feed moves by whole assets: 3 of 8 gone is
#   38 % and no sign of a broken source -- 20 keeps the limit above "a handful of assets changed").
# What then happens is the customer's choice, SI_Pro_SourceDropout_AssetDropAction:
#   confirm (default)  the new collection is NOT taken as the truth: it is registered as a 'drop', and one of its records
#                      stays "not complete", so everything it no longer lists is frozen (as when a collection fails). The
#                      run goes on. When the NEXT complete collection of that feed shows the same level (within the
#                      limit of the dropped level) the drop is accepted by itself -- a real mass deletion needs no person
#                      and costs one run. Back to normal instead = the drop never took effect.
#   accept             the records are taken as they came; the guard only reports.
# One event per drop: the first collection that drops raises it; the collections that follow while it is unconfirmed do not.
# A collection published by several processes at once (scheduled shards) is not judged: each sees only its own part.
$script:SIRecordDropMinRecords = 20
$script:SIRecordDropGuardId = 'collection.source.asset-drop'
# A FEED SEVERAL STEPS WRITE IS JUDGED ONLY BY THE STEP THAT WRITES IT WHOLE. Every collection step reads the Exposure
# Graph, so an eg feed is written by more than one step under the same collection time (the time is the minute the run
# started): the endpoint step records the eg nodes of its Azure VMs and Arc machines (a handful), the Azure step every
# Azure node. The step that closed first counted only what was written so far and held a feed that was not yet whole --
# 3 against 36, then 36 against 36 one minute later (three installs, 2026-10-19/20). The other steps' part of such a feed
# is a subset of the owner's (same record keys), so the owner's close always sees the whole feed; the others do not judge it.
$script:SIRecordFeedOwner = @{ 'eg|azure_resource' = 'azure'; 'eg|public_ip' = 'azure'; 'eg|device' = 'endpoint'
                               'eg|user' = 'identity'; 'eg|service_principal' = 'identity' }

function Test-SIRecordFeedJudgedBy {
    <# PURE. Whether the collection step -Engine judges the feed (provider|record type): its owner does, a step that writes
       only a part of it does not ("not judged yet" -- never held, never a drop). An unknown step judges every feed. #>
    param([string]$Feed, [string]$Engine = '')
    $e = ([string]$Engine).Trim().ToLowerInvariant()
    $f = ([string]$Feed).Trim().ToLowerInvariant()
    if (-not $e -or -not $script:SIRecordFeedOwner.ContainsKey($f)) { return $true }
    $script:SIRecordFeedOwner[$f] -eq $e
}

function Get-SIRecordDropSettings {
    <# PURE. The limit and the choice: @{ Percent (1-100, default 30); Action ('confirm' | 'accept'); MinRecords }. #>
    param($Percent = $global:SI_Pro_DataQuality_AssetDropPercent, $Action = $global:SI_Pro_SourceDropout_AssetDropAction)
    $pc = 0
    if (-not ($null -ne $Percent -and [int]::TryParse(([string]$Percent).Trim(), [ref]$pc) -and $pc -ge 1 -and $pc -le 100)) { $pc = 30 }
    $act = if (([string]$Action).Trim().ToLowerInvariant() -eq 'accept') { 'accept' } else { 'confirm' }
    [pscustomobject]@{ Percent = $pc; Action = $act; MinRecords = $script:SIRecordDropMinRecords }
}

function Get-SIRecordFeedDropVerdict {
    <#
        PURE. One feed's collection against its history. -Now: its record count; -History: its earlier collections, NEWEST
        FIRST (@{ Records; State }: good | drop | held). Returns @{ Action; Drop; Baseline; ChangePercent; Event; Confirmed }:
          take    not a drop (or nothing to compare with, or a feed too small to judge) -- taken as it came;
          hold    a drop under 'confirm': the last good collection is kept (Event = $true only for the FIRST such collection);
          accept  a drop that is taken: under 'accept' at once (Event = $true, it only reports), or under 'confirm' because
                  the collection before it was a drop at the same level (Confirmed = $true, no event).
    #>
    param([int]$Now, [AllowEmptyCollection()][object[]]$History = @(), [int]$Percent = 30, [int]$MinRecords = 20, [string]$Action = 'confirm')
    $res = [ordered]@{ Action = 'take'; Drop = $false; Baseline = $null; ChangePercent = $null; Event = $false; Confirmed = $false }
    $hist = @($History | Where-Object { $_ })
    $good = @($hist | Where-Object { [string]$_.State -eq 'good' }) | Select-Object -First 1
    if (-not $good -or [int]$good.Records -lt $MinRecords) { return [pscustomobject]$res }
    $base = [int]$good.Records
    $res.Baseline = $base
    $res.ChangePercent = [math]::Round(100.0 * ($Now - $base) / $base, 1)
    if ($res.ChangePercent -gt (0 - $Percent)) { return [pscustomobject]$res }
    $res.Drop = $true
    if ($Action -eq 'accept') { $res.Action = 'accept'; $res.Event = $true; return [pscustomobject]$res }
    $prev = $hist[0]
    if ([string]$prev.State -eq 'drop') {
        $pr = [int]$prev.Records
        if ($pr -gt 0 -and [math]::Abs(100.0 * ($Now - $pr) / $pr) -lt $Percent) { $res.Action = 'accept'; $res.Confirmed = $true }
        else { $res.Action = 'hold' }
        return [pscustomobject]$res
    }
    $res.Action = 'hold'; $res.Event = $true
    [pscustomobject]$res
}

function Get-SIRecordFeedDropSql {
    <# ONE read at the close: per feed of @f, how many records the collection @ctText holds now, and the feed's 8 newest
       earlier collections OF THE SAME COLLECTION STEP @engine (newest first). Without sidata.RecordCollection: no rows.
       Why the step: one feed can be written by two steps -- the endpoint collection records the Exposure Graph nodes of
       Azure VMs and Arc machines (eg azure_resource, a handful), the Azure collection records every Azure node (eg
       azure_resource, all of them). Measured at the internal install 2026-10-13: the endpoint's 8 were judged against the
       Azure collection's 101 (-92 %) and held, every night, though nothing was missing. A step is judged against itself. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RecordCollection') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(32)) AS Provider, CAST(NULL AS NVARCHAR(32)) AS RecordType, 0 AS NowRecords, CAST(NULL AS DATETIME2(3)) AS CollectionTime, 0 AS Records, CAST(NULL AS NVARCHAR(16)) AS State WHERE 1 = 0;
    RETURN;
END
DECLARE @ct DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@ctText, N''), 127);
SELECT f.Provider, ISNULL(f.RecordType, N'') AS RecordType,
       (SELECT COUNT(*) FROM sidata.CiRecord r WHERE r.Provider = f.Provider AND ISNULL(r.RecordType, N'') = ISNULL(f.RecordType, N'') AND r.CollectionTime = @ct) AS NowRecords,
       h.CollectionTime, h.Records, h.State
FROM OPENJSON(@h) WITH (Provider NVARCHAR(32), RecordType NVARCHAR(32)) f
OUTER APPLY (SELECT TOP (8) c.CollectionTime, c.Records, c.State FROM sidata.RecordCollection c
             WHERE c.Provider = f.Provider AND c.RecordType = ISNULL(f.RecordType, N'') AND c.CollectionTime < @ct
               AND (ISNULL(@engine, N'') = N'' OR ISNULL(c.Engine, N'') = @engine)
             ORDER BY c.CollectionTime DESC) h
WHERE f.Provider IS NOT NULL
ORDER BY f.Provider, f.RecordType, h.CollectionTime DESC;
'@
}

function Get-SIRecordFeedDrops {
    <#
        The asset-drop guard's verdicts for the feeds of one collection, at its close: @(@{ Feed; Provider; RecordType; Now;
        Baseline; ChangePercent; Action; Event; Confirmed; Text }) -- only the feeds that DROPPED. Nothing is judged when
        the guard is off (Settings > Guards), when the collection is published by several processes at once (scheduled
        shards), or when the history cannot be read. Never throws -- a guard never blocks a run.
    #>
    param([AllowEmptyCollection()][object[]]$Feeds = @(), [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CollectionTimeText, [string]$Engine = '',
          $Settings, [int]$ShardCount = -1,
          # owner 2026-10-17 (guards heal themselves): every feed judged and NOT held is added here as a guard check
          # (@{ GuardId; Subject; Values; Detail }) -- the close hands them to the guard, which clears an earlier drop's episode
          [System.Collections.Generic.List[object]]$Checks)
    try {
        if (-not @($Feeds).Count) { return }
        if ($ShardCount -lt 0) { $sc = 0; if (-not [int]::TryParse([string][Environment]::GetEnvironmentVariable('SI_SHARD_COUNT'), [ref]$sc)) { $sc = 1 }; $ShardCount = $sc }
        if ($ShardCount -gt 1) { return }
        # a feed this step writes only a part of is judged by the step that writes it whole (Test-SIRecordFeedJudgedBy)
        $Feeds = @(@($Feeds) | Where-Object { $_ -and (Test-SIRecordFeedJudgedBy -Feed ('{0}|{1}' -f (Get-SIItemValue $_ 'Provider'), (Get-SIItemValue $_ 'RecordType')) -Engine $Engine) })
        if (-not $Feeds.Count) { return }
        if ((Get-Command -Name Test-SIGuardOn -ErrorAction SilentlyContinue) -and -not (Test-SIGuardOn -GuardId $script:SIRecordDropGuardId)) { return }
        if (-not $Settings) {
            $Settings = Get-SIRecordDropSettings
            # CR4 (#654): halved for 24 hours after a release that changed engine code (the configured share x 0.5, at least 1)
            if (-not (Get-Command -Name Resolve-SIGuardLimit -ErrorAction SilentlyContinue)) {
                $sgs = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-GuardStrict.ps1')
                if ([IO.File]::Exists($sgs)) { . $sgs }
            }
            if (Get-Command -Name Resolve-SIGuardLimit -ErrorAction SilentlyContinue) {
                $Settings.Percent = [int](Resolve-SIGuardLimit -GuardId $script:SIRecordDropGuardId -Name 'changePercent' -Label 'Asset drop at most (% of a source''s records)' -Configured $Settings.Percent -Unit '%').Effective
            }
        }
        $rows = @(& $Invoke (Get-SIRecordFeedDropSql) @{ h = (ConvertTo-SIJsonArray @($Feeds)); ctText = $CollectionTimeText; engine = ([string]$Engine).Trim().ToLowerInvariant() } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        $by = [ordered]@{}
        foreach ($r in $rows) {
            $p = [string](Get-SIItemValue $r 'Provider'); if (-not $p) { continue }
            $k = '{0}|{1}' -f $p, [string](Get-SIItemValue $r 'RecordType')
            if (-not $by.Contains($k)) { $by[$k] = [pscustomobject]@{ Provider = $p; RecordType = [string](Get-SIItemValue $r 'RecordType'); Now = [int](Get-SIItemValue $r 'NowRecords'); History = (New-Object System.Collections.Generic.List[object]) } }
            $st = Get-SIItemValue $r 'State'
            if ($null -ne $st -and -not ($st -is [DBNull]) -and "$st") { $rc = Get-SIItemValue $r 'Records'; if ($null -eq $rc -or $rc -is [DBNull]) { $rc = 0 }; $by[$k].History.Add([pscustomobject]@{ Records = [int]$rc; State = [string]$st }) }
        }
        foreach ($k in $by.Keys) {
            $f = $by[$k]
            $v = Get-SIRecordFeedDropVerdict -Now $f.Now -History $f.History.ToArray() -Percent $Settings.Percent -MinRecords $Settings.MinRecords -Action $Settings.Action
            if ($null -ne $Checks) { $ck = Get-SIRecordFeedDropCheck -Feed $f -Verdict $v -Percent $Settings.Percent; if ($ck) { $Checks.Add($ck) } }
            if (-not $v.Drop) { continue }
            $what = '{0} {1} records: {2} in this collection against {3} in the last good one ({4} %)' -f $f.Provider, $f.RecordType, $f.Now, $v.Baseline, $v.ChangePercent
            $text = switch ($v.Action) {
                'hold' { $what + ' -- the last good collection is kept until the next complete collection shows the same level' }
                default { if ($v.Confirmed) { $what + ' -- the same level as the collection before it: the drop is accepted' } else { $what + ' -- taken as it came (SI_Pro_SourceDropout_AssetDropAction = accept)' } }
            }
            Write-Host ('[{0}] records: {1}' -f $(if ($v.Action -eq 'hold') { 'WARN' } else { 'INFO' }), $text)
            [pscustomobject]@{ Feed = $k; Provider = $f.Provider; RecordType = $f.RecordType; Now = $f.Now; Baseline = $v.Baseline; ChangePercent = $v.ChangePercent
                               Action = $v.Action; Event = [bool]$v.Event; Confirmed = [bool]$v.Confirmed; Text = $text; Percent = $Settings.Percent }
        }
    } catch { Write-Warning ('records: the asset-drop check could not be made -- {0}. The collection is taken as it came.' -f $_.Exception.Message) }
}

function Get-SIRecordFeedDropCheck {
    <#
        PURE. One judged feed as a guard CHECK (owner 2026-10-17, guards heal themselves) -- @{ GuardId; Subject; Values;
        Detail }, or $null when the feed is held or raised its own event this run:
          take               back within the limit of its last good collection (or nothing to judge): clears an earlier drop
                             "back at the normal level" -- the drop never took effect;
          accept, confirmed  the same level twice: the drop is TAKEN AS THE NEW LEVEL -- never a heal: the episode closes
                             with its own words (How 'taken': "taken as the new level after 2 runs at the same level -- not
                             back to normal"), Invardia is NOT told it cleared (its ticket stays), and a later collection at
                             that level is not read as "back to normal";
          hold / accept now  still low, or reported this run: nothing is cleared.
    #>
    param([Parameter(Mandatory)]$Feed, [Parameter(Mandatory)]$Verdict, [int]$Percent = 30)
    $sub = '{0} {1}' -f $Feed.Provider, $Feed.RecordType
    if ($Verdict.Action -eq 'take') {
        $vals = @(); $det = ''
        if ($null -ne $Verdict.Baseline) {
            $vals = @(@{ Name = 'changePercent'; Label = 'Change'; Measured = $Verdict.ChangePercent; Limit = (-1 * $Percent); Unit = '%' })
            $det = '{0} records: {1} in this collection against {2} in the last good one -- back at the normal level.' -f $sub, $Feed.Now, $Verdict.Baseline
        }
        return @{ GuardId = $script:SIRecordDropGuardId; Subject = $sub; Values = $vals; Detail = $det }
    }
    if ($Verdict.Action -eq 'accept' -and $Verdict.Confirmed) {
        return @{ GuardId = $script:SIRecordDropGuardId; Subject = $sub; Values = @(); How = 'taken'
                  Detail = ('{0} records: {1} in this collection against {2} in the last good one, the same level as the collection before it.' -f $sub, $Feed.Now, $Verdict.Baseline) }
    }
    $null
}

function Get-SIGuardCallsForRecordDrop {
    <# PURE. The guard events of the drops that raise one (Send-SIGuardEvent arguments): 'held' when the last good collection
       is kept, 'warning' when the drop was taken at once. One per feed and drop -- a drop that is still unconfirmed, or
       confirmed, raises none. #>
    param([AllowEmptyCollection()][object[]]$Drops = @(), [string]$Engine = '')
    foreach ($d in @($Drops | Where-Object { $_ -and $_.Event })) {
        $c = @{ GuardId = $script:SIRecordDropGuardId; Outcome = $(if ($d.Action -eq 'hold') { 'held' } else { 'warning' }); Subject = ('{0} {1}' -f $d.Provider, $d.RecordType)
                HeldCount = [long]([math]::Max(0, [int]$d.Baseline - [int]$d.Now)); Detail = ([string]$d.Text + '.')
                Values = @(@{ Name = 'previousAssets'; Label = 'Assets in the last good collection'; Measured = [long]$d.Baseline },
                           @{ Name = 'currentAssets'; Label = 'Assets in this collection'; Measured = [long]$d.Now },
                           @{ Name = 'changePercent'; Label = 'Change'; Measured = $d.ChangePercent; Limit = (-1 * [int]$d.Percent); Unit = '%' }) }
        if ($Engine) { $c['Job'] = 'si-' + $Engine.Trim().ToLowerInvariant() }
        $c
    }
}

function Send-SIRecordFeedDropEvents {
    <# Raises the drops' guard events (the Guards page, run health, the guard's mail). Never throws; without the guard
       code loaded the drop is in the run log only. #>
    param([AllowEmptyCollection()][object[]]$Drops = @(), [string]$Engine = '',
          # the feeds judged and not held (Get-SIRecordFeedDropCheck): a complete collection back at the normal level clears an
          # earlier drop's episode -- recorded, and reported to Invardia as cleared (owner 2026-10-17)
          [AllowEmptyCollection()][object[]]$Checks = @())
    try {
        $calls = @(Get-SIGuardCallsForRecordDrop -Drops $Drops -Engine $Engine)
        $checked = @($Checks | Where-Object { $_ })
        if (-not $calls.Count -and -not $checked.Count) { return }
        if (-not (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue)) {
            $g = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-Guard.ps1')
            if ([IO.File]::Exists($g)) { . $g }
        }
        if (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) {
            $common = @{ Engine = $Engine }
            if ($Engine) { $common['Job'] = 'si-' + $Engine.Trim().ToLowerInvariant() }
            if ($checked.Count) { $null = Invoke-SIGuardCalls -Calls $calls -Common $common -Checked $checked -Complete $true }
            else { $null = Invoke-SIGuardCalls -Calls $calls -Common @{ Engine = $Engine } }
        }
    } catch { Write-Warning ('records: the asset-drop event could not be raised -- {0}' -f $_.Exception.Message) }
}

function Complete-SIRecordFeeds {
    <#
        The end of a collection's records: when every batch was written (-Close.Failed = 0) the pins become complete and
        the collection is registered; when a batch failed NOTHING is closed -- the collection stays "not complete" and the
        records it did not write stay as the last good collection left them (said plainly). Never throws.
        Returns @{ Closed; Feeds; Held } (Held = $true when it was left open).
    #>
    param([Parameter(Mandatory)]$Close, [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$CollectionTime)
    try {
        if ([int]$Close.Failed -gt 0) {
            Write-Warning ('records: this collection is NOT complete -- {0} record(s) could not be written. The records it did not reach keep their last good state (nothing is shown as gone); the next collection that completes sets it right.' -f [int]$Close.Failed)
            return [pscustomobject]@{ Closed = 0; Feeds = 0; Held = $true }
        }
        if ($Close.Pins.Count -eq 0) { return [pscustomobject]@{ Closed = 0; Feeds = 0; Held = $false } }
        $feeds = @(@($Close.Feeds.Keys) | Where-Object { -not $Close.Incomplete.ContainsKey($_) } | Sort-Object | ForEach-Object {
                $i = ([string]$_).IndexOf('|'); [ordered]@{ Provider = ([string]$_).Substring(0, $i); RecordType = ([string]$_).Substring($i + 1) } })
        # (a feed whose own pull was not complete has no pins: all of its records say "not complete", and it is not registered)
        $ctText = $CollectionTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        # THE ASSET-DROP GUARD, before the close: a feed that completed with far fewer assets than its last good collection
        # keeps the last good collection (one of its pins stays "not complete") until the next collection confirms the level
        $dropChecks = New-Object System.Collections.Generic.List[object]
        # (a close that is only one of several processes publishing the same collection -- Judge = $false -- counts a feed
        # before it is whole: not judged, as a sharded collection is not)
        $drops = @()
        if (-not ($Close.PSObject.Properties['Judge'] -and -not $Close.Judge)) {
            $drops = @(Get-SIRecordFeedDrops -Feeds $feeds -Invoke $Invoke -CollectionTimeText $ctText -Engine ([string]$Close.Engine) -Checks $dropChecks)
        }
        $pins = New-Object System.Collections.Generic.List[string]
        $kept = @{}
        foreach ($d in @($drops | Where-Object { $_.Action -eq 'hold' })) { $kept[[string]$d.Feed] = $d }
        $left = @{}
        foreach ($k in $Close.Pins) {
            $pf = if ($Close.PSObject.Properties['PinFeed'] -and $Close.PinFeed.ContainsKey($k)) { [string]$Close.PinFeed[$k] } else { '' }
            if ($pf -and $kept.ContainsKey($pf) -and -not $left.ContainsKey($pf)) { $left[$pf] = $k; continue }   # ONE pin of a held feed stays
            $pins.Add($k)
        }
        foreach ($f in $feeds) {
            $fk = '{0}|{1}' -f $f.Provider, $f.RecordType
            if ($kept.ContainsKey($fk) -and $left.ContainsKey($fk)) { $f['State'] = 'drop'; $f['Reason'] = [string]$kept[$fk].Text }
        }
        $p = @{ k = (ConvertTo-SIJsonArray $pins.ToArray()); f = (ConvertTo-SIJsonArray $feeds); ctText = $ctText; engine = [string]$Close.Engine }
        $row = @(& $Invoke (Get-SIRecordFeedCloseSql) $p 'rows') | Select-Object -First 1
        # the collection CLOSED complete (every batch written): the feeds back at the normal level clear an earlier drop
        Send-SIRecordFeedDropEvents -Drops $drops -Engine ([string]$Close.Engine) -Checks $dropChecks.ToArray()
        [pscustomobject]@{ Closed = [int](Get-SIItemValue $row 'Closed'); Feeds = [int](Get-SIItemValue $row 'Feeds'); Held = $false; Drops = $drops }
    } catch {
        Write-Warning ('records: the collection could not be closed -- {0}. It counts as not complete: nothing it did not reach is shown as gone.' -f $_.Exception.Message)
        [pscustomobject]@{ Closed = 0; Feeds = 0; Held = $true }
    }
}

function ConvertTo-SIJsonArray {
    <# PURE. Always a JSON ARRAY for OPENJSON (PowerShell 5.1 writes a one-item list as the bare object). #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Items, [int]$Depth = 6)
    if ($null -eq $Items -or @($Items).Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject @($Items) -Compress -Depth $Depth
    if ($j.TrimStart().StartsWith('[')) { $j } else { '[' + $j + ']' }
}

function New-SIRecordSqlInvoke {
    <#
        The SQL seam over the install's database (SI_ProSqlServer / SI_ProSqlDatabase), signed in as the job (managed
        identity in a container, else the engine certificate) -- the identity ledger's connection. $null = no database
        configured: records and CIs live in SQL only, so the caller says plainly that nothing is kept.
    #>
    param([string]$Server = [string]$global:SI_ProSqlServer, [string]$Database = [string]$global:SI_ProSqlDatabase)
    if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) { return $null }
    # Not a GetNewClosure(): a closure runs in its own module scope and does not see the connection helpers the caller
    # loaded. The server and database go in as literals; the functions are found where the seam is called.
    $q = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
    [scriptblock]::Create(('param($Sql, $Params, $Mode) Invoke-SIRecordSqlDb -Server {0} -Database {1} -Sql $Sql -Params $Params -Mode $Mode' -f (& $q $Server), (& $q $Database)))
}

function Read-SISqlRows {
    <#
        Runs a command and answers the rows of EVERY result set, reading them to the end. A batch whose first statements
        return nothing (temp tables, a loop, then the one SELECT) and whose later statement fails must be an ERROR here,
        never an empty answer: closing a reader early discards the rest of the batch and its error (customer H 2026-10-09:
        the CI grouping ran 294 s, answered no row and no error, and the build said "no records").
    #>
    param([Parameter(Mandatory)]$Command)
    # 'Stop': a .NET exception in a loop condition is only STATEMENT-terminating -- under a container's error preference
    # the loop just ended and the function answered nothing (customer H 2026-10-09: "answered no result", no error shown)
    $ErrorActionPreference = 'Stop'
    $rows = New-Object System.Collections.Generic.List[object]
    $rd = $null
    # what the database answered, for the "answered no result" messages (ring 1 2026-10-09, #513: a one-row SELECT came back
    # with no row and no error inside the container, and nothing said whether the database or the reader lost it)
    $global:SISqlLastRead = [ordered]@{ Sets = 0; Fields = ''; Rows = 0; HasRows = '' }
    try {
        $rd = $Command.ExecuteReader()
        do {
            $global:SISqlLastRead.Sets++
            $global:SISqlLastRead.Fields = ('{0}{1}{2}' -f $global:SISqlLastRead.Fields, $(if ($global:SISqlLastRead.Fields) { '/' } else { '' }), $rd.FieldCount)
            $global:SISqlLastRead.HasRows = ('{0}{1}' -f $global:SISqlLastRead.HasRows, $(if ($rd.HasRows) { 'y' } else { 'n' }))
            # 🔒 the rows are read HERE, never by handing the reader to a function: a data reader is enumerable, and binding it to
            # a function's parameter let PowerShell 7.4 (the container image) enumerate it -- every row consumed before the
            # function's own Read(). Ring 1 2026-10-09 (#513): "1 result set(s), columns 1, rows reported y, 0 row(s) read";
            # pwsh 7.6 (mgmt1, the test VM) does not, so no offline run ever showed it. Guarded by SIv3-CiBuildSql.
            if ($rd.FieldCount -gt 0) {
                $names = @(for ($i = 0; $i -lt $rd.FieldCount; $i++) { $rd.GetName($i) })
                while ($rd.Read()) {
                    $o = [ordered]@{}
                    for ($i = 0; $i -lt $names.Count; $i++) { $v = $rd.GetValue($i); if ($v -is [System.DBNull]) { $v = $null }; $o[$names[$i]] = $v }
                    $rows.Add([pscustomobject]$o)
                }
            }
            $global:SISqlLastRead.Rows = $rows.Count
        } while ($rd.NextResult())
    } catch {
        throw (New-Object System.Exception((Format-SISqlError -Exception $_.Exception -InfoMessages @($script:SISqlInfoMessages)), $_.Exception))
    } finally { if ($rd) { $rd.Close() } }
    $rows.ToArray()
}

# the server's info messages of the current statement (SqlConnection.InfoMessage) -- part of an error's text
$script:SISqlInfoMessages = New-Object System.Collections.Generic.List[string]

function Get-SIRecordSchemaCheckSql {
    <#
        READ-ONLY: what the record writer and the CI build need of the database, beyond what an older release created --
        answers ONE row, Missing = the names that are not there (empty = all there). The engine never changes the schema:
        the tables, columns and indexes come from sql\si-data-schema.sql, which the updater applies (the job's identity
        has data rights only -- customer H 2026-10-09).
    #>
    @'
SET NOCOUNT ON;
SELECT CONCAT_WS(N', ',
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NULL THEN N'sidata.CiRecord' END,
    CASE WHEN OBJECT_ID('sidata.RecordIdentifier') IS NULL THEN N'sidata.RecordIdentifier' END,
    CASE WHEN OBJECT_ID('sidata.Ci') IS NULL THEN N'sidata.Ci' END,
    CASE WHEN OBJECT_ID('sidata.CiGroupMember') IS NULL THEN N'sidata.CiGroupMember' END,
    CASE WHEN OBJECT_ID('sidata.CiGroupEdge') IS NULL THEN N'sidata.CiGroupEdge' END,
    CASE WHEN OBJECT_ID('sidata.CiBuildState') IS NULL THEN N'sidata.CiBuildState' END,
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'ContentHash') IS NULL THEN N'sidata.CiRecord.ContentHash' END,
    CASE WHEN OBJECT_ID('sidata.Ci') IS NOT NULL AND COL_LENGTH('sidata.Ci', 'ContentHash') IS NULL THEN N'sidata.Ci.ContentHash' END,
    CASE WHEN OBJECT_ID('sidata.Ci') IS NOT NULL AND COL_LENGTH('sidata.Ci', 'PostedHash') IS NULL THEN N'sidata.Ci.PostedHash' END,
    CASE WHEN OBJECT_ID('sidata.Ci') IS NOT NULL AND COL_LENGTH('sidata.Ci', 'PostedAt') IS NULL THEN N'sidata.Ci.PostedAt' END,
    -- #534 the incremental CI build: what each record was at its last build, its group's dirty mark, a CI's last posted row
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'BuiltHash') IS NULL THEN N'sidata.CiRecord.BuiltHash' END,
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'BuiltGroupKey') IS NULL THEN N'sidata.CiRecord.BuiltGroupKey' END,
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'BuiltState') IS NULL THEN N'sidata.CiRecord.BuiltState' END,
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'BuiltTimeSig') IS NULL THEN N'sidata.CiRecord.BuiltTimeSig' END,
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'BuiltAt') IS NULL THEN N'sidata.CiRecord.BuiltAt' END,
    CASE WHEN OBJECT_ID('sidata.CiGroupMember') IS NOT NULL AND COL_LENGTH('sidata.CiGroupMember', 'Dirty') IS NULL THEN N'sidata.CiGroupMember.Dirty' END,
    CASE WHEN OBJECT_ID('sidata.CiGroupMember') IS NOT NULL AND COL_LENGTH('sidata.CiGroupMember', 'CurHash') IS NULL THEN N'sidata.CiGroupMember.CurHash' END,
    CASE WHEN OBJECT_ID('sidata.CiGroupMember') IS NOT NULL AND COL_LENGTH('sidata.CiGroupMember', 'CurState') IS NULL THEN N'sidata.CiGroupMember.CurState' END,
    CASE WHEN OBJECT_ID('sidata.CiGroupMember') IS NOT NULL AND COL_LENGTH('sidata.CiGroupMember', 'CurTimeSig') IS NULL THEN N'sidata.CiGroupMember.CurTimeSig' END,
    CASE WHEN OBJECT_ID('sidata.Ci') IS NOT NULL AND COL_LENGTH('sidata.Ci', 'PostRowHash') IS NULL THEN N'sidata.Ci.PostRowHash' END,
    -- identities before devices: the owner / user values a device / resource CI named
    CASE WHEN OBJECT_ID('sidata.CiIdentityRef') IS NULL THEN N'sidata.CiIdentityRef' END,
    -- #534 follow-up: when a record is next due, and the owning CMDB's items per CI
    CASE WHEN OBJECT_ID('sidata.CiRecord') IS NOT NULL AND COL_LENGTH('sidata.CiRecord', 'NextDueAt') IS NULL THEN N'sidata.CiRecord.NextDueAt' END,
    CASE WHEN OBJECT_ID('sidata.CiCmdbUse') IS NULL THEN N'sidata.CiCmdbUse' END,
    CASE WHEN OBJECT_ID('sidata.CiCmdbKey') IS NULL THEN N'sidata.CiCmdbKey' END
) AS Missing;
'@
}

function Get-SIRecordSchemaMissing {
    <# The names Get-SIRecordSchemaCheckSql reports missing (an empty list = the database is current). Throws on a SQL error. #>
    param([Parameter(Mandatory)][scriptblock]$Sql)
    $global:SISqlLastRead = $null
    $got = @(& $Sql (Get-SIRecordSchemaCheckSql) @{} 'rows')
    $row = $got | Select-Object -First 1
    if ($null -eq $row) { throw ('the schema check answered no result ({0})' -f (Get-SISqlLastReadText -Answered $got.Count)) }
    $m = [string](Get-SIItemValue $row 'Missing')
    @($m.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-SISqlLastReadText {
    <#
        What the database answered to the last read (Read-SISqlRows), as one plain phrase -- the evidence an "answered no
        result" message carries: no read at all, or N result set(s), their column counts, whether the server said it had
        rows, and how many rows were read. -Answered: how many objects reached the caller.
    #>
    param([int]$Answered = 0)
    $r = $global:SISqlLastRead
    if ($null -eq $r) { return ('the statement was not read by the database reader; {0} object(s) came back' -f $Answered) }
    'the database answered {0} result set(s), columns {1}, rows reported {2}, {3} row(s) read; {4} object(s) came back' -f $r.Sets, $r.Fields, $r.HasRows, $r.Rows, $Answered
}

function Format-SISqlError {
    <#
        A SQL failure as one line with what the database said: every error's number, line and message (a SqlException
        carries several; .Message alone hid the real cause on customer H 2026-10-09), plus the server's info messages.
    #>
    param([Parameter(Mandatory)]$Exception, [string[]]$InfoMessages = @())
    $e = $Exception
    while ($e -and -not ($e -is [System.Data.SqlClient.SqlException]) -and $e.InnerException) { $e = $e.InnerException }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($e -is [System.Data.SqlClient.SqlException]) {
        foreach ($x in $e.Errors) { $parts.Add(('SQL error {0} (line {1}): {2}' -f $x.Number, $x.LineNumber, $x.Message)) }
    }
    if ($parts.Count -eq 0) { $parts.Add([string]$Exception.Message) }
    foreach ($i in @($InfoMessages | Select-Object -Last 3)) { if ($i) { $parts.Add('server said: ' + $i) } }
    ($parts | Select-Object -Unique) -join ' | '
}

$script:SIRecordSqlConnections = @{}

function Invoke-SIRecordSqlDb {
    <#
        One statement against the database, signed in as the job. The connection is kept open for the process (one sign-in,
        not one per statement -- a CI build sends hundreds) and re-opened once when it was lost.
        -Mode: nonquery | scalar | rows (objects, the first result set).
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params, [string]$Mode = 'nonquery', [int]$TimeoutSeconds = 0)
    $ErrorActionPreference = 'Stop'
    $key = ('{0}|{1}' -f $Server, $Database).ToLowerInvariant()
    for ($try = 1; $try -le 2; $try++) {
        $cn = $script:SIRecordSqlConnections[$key]
        if ($null -eq $cn -or $cn.State -ne [System.Data.ConnectionState]::Open) {
            if ($cn) { try { $cn.Dispose() } catch { } }
            $cn = Get-SIObjectLedgerConnection -Server $Server -Database $Database
            if (-not $cn) { throw 'the database could not be opened' }
            Register-SISqlInfoMessages -Connection $cn
            $script:SIRecordSqlConnections[$key] = $cn
        }
        try {
            $script:SISqlInfoMessages.Clear()
            $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = $TimeoutSeconds
            if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
            return $c.ExecuteNonQuery()
        } catch {
            # a lost connection (closed, broken, a token past its life) is re-opened once; anything else is the answer
            if ($try -eq 1 -and $cn.State -ne [System.Data.ConnectionState]::Open) { $script:SIRecordSqlConnections.Remove($key); continue }
            throw (New-Object System.Exception((Format-SISqlError -Exception $_.Exception -InfoMessages @($script:SISqlInfoMessages)), $_.Exception))
        }
    }
}

function Register-SISqlInfoMessages {
    <# Keeps the server's info messages of a connection (PRINT, warnings) for the error text of its next failure. #>
    param([Parameter(Mandatory)]$Connection)
    # a delegate, not an event job: SqlClient raises it on this thread, while the statement runs; the closure holds the
    # one list (cleared, never replaced, before every statement)
    $list = $script:SISqlInfoMessages
    $h = { param($s, $e) foreach ($x in $e.Errors) { [void]$list.Add(('{0}: {1}' -f $x.Number, $x.Message)) } }.GetNewClosure()
    try { $Connection.add_InfoMessage([System.Data.SqlClient.SqlInfoMessageEventHandler]$h) } catch { }
}

# =====================================================================================================================
#  ONE CI BUILD AT A TIME (owner 2026-10-12: "we cannot have 2 builds running at the same time. add as guard")
# =====================================================================================================================
# Two CI builds side by side write the same CIs, links, identity ledger and SI_CI_CL rows at once. Every starter (the
# pipeline, a job run by hand, a release check, Risk Analysis building the CIs in its own run) shares ONE place: the
# database. So the build holds an exclusive APPLICATION LOCK there for as long as it writes:
#   * sp_getapplock, owned by the SESSION of a connection that is opened for the lock alone and stays open for the whole
#     build. The server frees it when that connection ends -- a build that is stopped or killed frees it by itself. No
#     flag is left behind, so nothing stale can ever block a build (LastBuildStatus 'running' is NOT the lock: after a
#     stopped build it only means "carry on", Test-SICiCarryOn).
#   * a second build that finds the lock held builds NOTHING beside the first: it WAITS (one line when it starts to wait,
#     one every few minutes; bounded only by its own job's run limit) and then runs as an ordinary build -- incremental
#     and quick when the first one just finished. It reads the build's state only AFTER it holds the lock, so a build
#     that is running now is never taken for a stopped one.
#   * WHO HOLDS IT is written to sidata.CiBuildState 'BuildLockHolder' ({ token; since; who }) by the holder, for the
#     waiting build's log line and the event -- information only, never the lock.
#   * THE CONNECTION CAN DROP while the build runs. The build checks its lock before every batch it writes
#     (Test-SICiBuildLock). Lost: it takes the lock again at once; when 'BuildLockHolder' still carries its own token no
#     other build ran in between and it goes on. In every other case (another build holds the lock, or held it
#     meanwhile, or the check cannot be made) it STOPS without writing -- the next build builds what is left.
#   * THE GUARD ci.build.concurrent is the REPORT (one event when a build has to wait); the lock is the correctness and
#     holds whether the guard is on or off.
# No database (Community without SQL): there is no CI build in SQL, so there is nothing to lock.
$script:SICiBuildLockGuardId = 'ci.build.concurrent'
# the lock THIS process holds: @{ Connection; Open; Token; Holder (its 'BuildLockHolder' value); Since; Who } -- kept
# when this file is loaded again (the job holds the lock across the scripts it loads)
if (-not (Test-Path -LiteralPath 'variable:script:SICiBuildLockState')) { $script:SICiBuildLockState = $null }

function Get-SICiBuildLockSql {
    <# The statements of the CI build's lock (one place; the real-SQL tests run them). #>
    param([Parameter(Mandatory)][ValidateSet('Take', 'Mode', 'Release', 'HolderSet', 'HolderGet', 'HolderClear')][string]$Name)
    switch ($Name) {
        # @ms: how long to wait for it (0 = ask once). Result >= 0: held; -1: another session holds it
        'Take' { "SET NOCOUNT ON; DECLARE @r INT, @t INT = CAST(@ms AS INT); EXEC @r = sp_getapplock @Resource = N'si-ci-build', @LockMode = N'Exclusive', @LockOwner = N'Session', @LockTimeout = @t; SELECT @r AS Result;" }
        'Mode' { "SET NOCOUNT ON; SELECT APPLOCK_MODE(N'public', N'si-ci-build', N'Session') AS Mode;" }
        'Release' { "SET NOCOUNT ON; IF APPLOCK_MODE(N'public', N'si-ci-build', N'Session') <> N'NoLock' EXEC sp_releaseapplock @Resource = N'si-ci-build', @LockOwner = N'Session'; SELECT 1 AS Released;" }
        'HolderSet' { @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiBuildState') IS NULL BEGIN SELECT 0 AS Written; RETURN; END
MERGE sidata.CiBuildState AS t USING (SELECT N'BuildLockHolder' AS Name, LEFT(@v, 400) AS Value) AS s ON t.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = s.Value, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (s.Name, s.Value);
SELECT 1 AS Written;
'@ }
        'HolderGet' { @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiBuildState') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(400)) AS Value; RETURN; END
SELECT (SELECT TOP 1 Value FROM sidata.CiBuildState WHERE Name = N'BuildLockHolder') AS Value;
'@ }
        # only its own value: a build that lost the lock never clears the next holder's
        'HolderClear' { "SET NOCOUNT ON; IF OBJECT_ID('sidata.CiBuildState') IS NOT NULL UPDATE sidata.CiBuildState SET Value = N'', UpdatedAt = SYSUTCDATETIME() WHERE Name = N'BuildLockHolder' AND Value = LEFT(@v, 400); SELECT 1 AS Cleared;" }
    }
}

function Invoke-SICiBuildLockSql {
    <# One statement on the lock's own connection -> its rows. Throws when the connection is gone. #>
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params, [int]$TimeoutSeconds = 0)
    $ErrorActionPreference = 'Stop'
    $c = $Connection.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = $TimeoutSeconds
    if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
    @(Read-SISqlRows -Command $c)
}

function Get-SICiBuildLockOpen {
    <# The lock's connection for this install's database (SI_ProSqlServer / SI_ProSqlDatabase), signed in as the job --
       a scriptblock that opens one; $null when no database is configured (nothing to lock). #>
    param([string]$Server = [string]$global:SI_ProSqlServer, [string]$Database = [string]$global:SI_ProSqlDatabase)
    if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) { return $null }
    $q = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
    [scriptblock]::Create(('Get-SIObjectLedgerConnection -Server {0} -Database {1}' -f (& $q $Server), (& $q $Database)))
}

function Get-SICiBuildLockWho {
    <# PURE. Who a build is, in the words the other build's log line and the event use: the job run (a container job's
       execution carries the job's name), else the run id and the machine. #>
    param([string]$RunId, [string]$Execution = [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME, [string]$Computer = [string]$env:COMPUTERNAME)
    if (-not [string]::IsNullOrWhiteSpace($Execution)) { return ('job run {0}' -f $Execution.Trim()) }
    $who = if (-not [string]::IsNullOrWhiteSpace($RunId)) { 'run {0}' -f $RunId.Trim() } else { 'a run started by hand' }
    if (-not [string]::IsNullOrWhiteSpace($Computer)) { $who = '{0} on {1}' -f $who, $Computer.Trim() }
    $who
}

function ConvertFrom-SICiBuildLockHolder {
    <# PURE. The 'BuildLockHolder' value -> @{ Token; Since ([datetime] UTC or $null); Who }; $null when there is none. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        $o = ConvertFrom-Json -InputObject $Value
        $since = $null
        if ($o.PSObject.Properties['since'] -and $o.since) {
            # (PowerShell 7 hands an ISO time in JSON back as a date already)
            $d = [datetime]::MinValue
            if ($o.since -is [datetime]) { $since = ([datetime]$o.since).ToUniversalTime() }
            elseif ([datetime]::TryParse([string]$o.since, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $since = $d }
        }
        [pscustomobject]@{ Token = [string]$o.token; Since = $since; Who = [string]$o.who }
    } catch { $null }
}

function Format-SICiBuildLockLine {
    <#
        PURE. The run log's lines about the lock, in plain words:
          Wait   a build finds another one running (-Other: its ConvertFrom-SICiBuildLockHolder, when known)
          Still  it is still waiting (-Minutes so far)
          Go     the other build finished (-Minutes waited)
          Kept   this build's lock connection was lost and taken again; nothing ran in between
    #>
    param([Parameter(Mandatory)][ValidateSet('Wait', 'Still', 'Go', 'Kept')][string]$Kind, $Other, [int]$Minutes = 0)
    $about = @()
    if ($Other -and $Other.Since) { $about += ('since {0:yyyy-MM-dd HH:mm} UTC' -f ([datetime]$Other.Since).ToUniversalTime()) }
    if ($Other -and $Other.Who) { $about += [string]$Other.Who }
    $in = if ($about.Count) { ' ({0})' -f ($about -join ', ') } else { '' }
    switch ($Kind) {
        'Wait' { 'CIs: another CI build is running{0} -- this one waits for it and then builds what is left' -f $in }
        'Still' { 'CIs: still waiting for the other CI build{0} -- {1} minute(s) so far; nothing is built beside it' -f $in, $Minutes }
        'Go' { 'CIs: the other CI build has finished (waited {0} minute(s)) -- this one builds what is left' -f $Minutes }
        'Kept' { 'CIs: the connection that holds this build''s lock was lost and opened again -- no other CI build ran in between, so the build goes on' }
    }
}

function Get-SIGuardCallsForCiBuildWait {
    <# PURE. The guard event of a CI build that was started while another one was running and waits for it
       (Send-SIGuardEvent arguments): a warning -- nothing is held, nothing fails. One per build that has to wait. #>
    param($Other, [string]$Who, [string]$RunId, [string]$Engine)
    $first = if ($Other -and $Other.Who) { [string]$Other.Who } else { 'another run' }
    $since = if ($Other -and $Other.Since) { ', running since {0:yyyy-MM-dd HH:mm} UTC' -f ([datetime]$Other.Since).ToUniversalTime() } else { '' }
    $c = @{ GuardId = $script:SICiBuildLockGuardId; Outcome = 'warning'
            Detail = ('A CI build ({0}) was started while another CI build ({1}{2}) was still running. It waits for that build to finish and then builds what is left.' -f $(if ($Who) { $Who } else { 'this run' }), $first, $since) }
    if ($RunId) { $c['RunId'] = $RunId }
    if ($Engine) { $c['Engine'] = $Engine; $c['Job'] = 'si-' + $Engine.Trim().ToLowerInvariant(); $c['Subject'] = $Engine.Trim().ToLowerInvariant() }
    $c
}

function Send-SICiBuildWaitEvent {
    <# Raises the event of a build that has to wait (the Guards page, run health). Never throws; without the guard code
       loaded the wait is in the run log only. #>
    param($Other, [string]$Who, [string]$RunId, [string]$Engine)
    try {
        if (-not (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue)) {
            $g = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-Guard.ps1')
            if ([IO.File]::Exists($g)) { . $g }
        }
        if (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) {
            $inv = $null; if (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue) { $inv = Get-SIGuardProInvoke }
            $null = Invoke-SIGuardCalls -Calls @(Get-SIGuardCallsForCiBuildWait -Other $Other -Who $Who -RunId $RunId -Engine $Engine) -Common @{ Invoke = $inv }
        }
    } catch { Write-Warning ('CIs: the event of a CI build that waits could not be raised -- {0}' -f $_.Exception.Message) }
}

function Close-SICiBuildLockConnection {
    <# Ends the lock's connection for good (never back into a pool with the lock on it). Never throws. #>
    param($Connection)
    if ($null -eq $Connection) { return }
    try { $Connection.GetType()::ClearPool($Connection) } catch { }
    try { $Connection.Dispose() } catch { }
}

function Enter-SICiBuildLock {
    <#
        Takes the CI build's lock for this process, waiting for a build that holds it. Returns
        @{ Held = $true; Owned (this call took it -- the caller that owns it releases it, Exit-SICiBuildLock);
           Waited; WaitSeconds; Other (the build it waited for, when known) }.
        A process that already holds it (the correlation job takes it before the CI build asks) gets Owned = $false, or --
        when its lock was lost and another build ran meanwhile -- Held = $false with Why.
        Throws when the lock cannot be asked for at all (the database does not answer, five times in a row).
        Seams (tests): -Open { } -> an open connection; -Guard { param($Other, $Who) } instead of the guard event;
        -Sleep { param($Seconds) }; -Now { }.
    #>
    param([scriptblock]$Open, [string]$RunId, [string]$Engine, [scriptblock]$Log, [int]$PollSeconds = 30, [int]$ProgressMinutes = 5,
          [scriptblock]$Guard, [scriptblock]$Sleep = { param($Seconds) Start-Sleep -Seconds $Seconds }, [scriptblock]$Now = { [datetime]::UtcNow })
    if (-not $Log) { $Log = { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-Host ('[' + $l + '] ' + $m) } } }
    if ($script:SICiBuildLockState) {
        $chk = Test-SICiBuildLock -Log $Log
        return [pscustomobject]@{ Held = [bool]$chk.Held; Owned = $false; Waited = $false; WaitSeconds = 0; Other = $null; Why = [string]$chk.Why }
    }
    if (-not $Open) { $Open = Get-SICiBuildLockOpen }
    if (-not $Open) { throw 'no database is configured for the lock that keeps CI builds apart' }
    if ($PollSeconds -lt 1) { $PollSeconds = 1 }
    $who = Get-SICiBuildLockWho -RunId $RunId
    $cn = $null; $t0 = ([datetime](& $Now)).ToUniversalTime(); $lastSaid = $t0; $waiting = $false; $other = $null; $fails = 0
    while ($true) {
        $code = $null
        try {
            if ($null -eq $cn -or $cn.State -ne [System.Data.ConnectionState]::Open) {
                Close-SICiBuildLockConnection $cn
                $cn = & $Open
                if (-not $cn) { throw 'the database could not be opened' }
            }
            # asked once; while waiting, in turns of -PollSeconds (the server queues the request: the lock is taken the moment it is free)
            $ms = if ($waiting) { $PollSeconds * 1000 } else { 0 }
            $r = @(Invoke-SICiBuildLockSql -Connection $cn -Sql (Get-SICiBuildLockSql 'Take') -Params @{ ms = [string]$ms } -TimeoutSeconds ($PollSeconds + 120))
            $code = [int]$r[0].Result
            if ($code -lt 0 -and $code -ne -1) { throw ('the database refused the lock (result {0})' -f $code) }
            $fails = 0
        } catch {
            $fails++
            Close-SICiBuildLockConnection $cn; $cn = $null
            if ($fails -ge 5) { throw ('the lock that keeps two CI builds apart could not be taken ({0})' -f $_.Exception.Message) }
            & $Sleep ([Math]::Min(30, 5 * $fails))
            continue
        }
        if ($code -ge 0) { break }
        $nowU = ([datetime](& $Now)).ToUniversalTime()
        if (-not $waiting) {
            $waiting = $true; $lastSaid = $nowU
            try { $other = ConvertFrom-SICiBuildLockHolder ([string]@(Invoke-SICiBuildLockSql -Connection $cn -Sql (Get-SICiBuildLockSql 'HolderGet'))[0].Value) } catch { $other = $null }
            & $Log 'INFO' (Format-SICiBuildLockLine -Kind Wait -Other $other)
            # the report (never the lock): one event for this build
            if ($Guard) { try { & $Guard $other $who } catch { } } else { Send-SICiBuildWaitEvent -Other $other -Who $who -RunId $RunId -Engine $Engine }
        } elseif (($nowU - $lastSaid).TotalMinutes -ge $ProgressMinutes) {
            $lastSaid = $nowU
            & $Log 'INFO' (Format-SICiBuildLockLine -Kind Still -Other $other -Minutes ([int]($nowU - $t0).TotalMinutes))
        }
    }
    $t1 = ([datetime](& $Now)).ToUniversalTime()
    $token = [guid]::NewGuid().ToString('n')
    $holder = ConvertTo-Json -Compress -InputObject ([ordered]@{ token = $token; since = $t1.ToString('o'); who = $(if ($who.Length -gt 200) { $who.Substring(0, 200) } else { $who }) })
    $written = $false
    try { $written = ([int]@(Invoke-SICiBuildLockSql -Connection $cn -Sql (Get-SICiBuildLockSql 'HolderSet') -Params @{ v = $holder })[0].Written -eq 1) } catch { $written = $false }
    $script:SICiBuildLockState = [pscustomobject]@{ Connection = $cn; Open = $Open; Token = $(if ($written) { $token } else { '' }); Holder = $holder; Since = $t1; Who = $who }
    if ($waiting) { & $Log 'INFO' (Format-SICiBuildLockLine -Kind Go -Minutes ([int]($t1 - $t0).TotalMinutes)) }
    [pscustomobject]@{ Held = $true; Owned = $true; Waited = $waiting; WaitSeconds = [int]($t1 - $t0).TotalSeconds; Other = $other; Why = '' }
}

function Test-SICiBuildLock {
    <#
        Does this process still hold the CI build's lock? Asked before every batch the build writes (it also keeps the
        lock's connection in use). @{ Held; Why }. No lock in this process (no database, a test seam): Held, nothing to
        check. A lost connection: the lock is taken again at once, and the build goes on only when 'BuildLockHolder' still
        carries this build's own token (no other build ran in between); else Held = $false and the lock is given up.
    #>
    param([scriptblock]$Log)
    $s = $script:SICiBuildLockState
    if (-not $s) { return [pscustomobject]@{ Held = $true; Why = '' } }
    try {
        if ($s.Connection -and $s.Connection.State -eq [System.Data.ConnectionState]::Open) {
            if ([string]@(Invoke-SICiBuildLockSql -Connection $s.Connection -Sql (Get-SICiBuildLockSql 'Mode'))[0].Mode -eq 'Exclusive') { return [pscustomobject]@{ Held = $true; Why = '' } }
        }
    } catch { }
    # the lock is gone with its connection
    Close-SICiBuildLockConnection $s.Connection
    $script:SICiBuildLockState = $null
    $cn = $null
    try {
        $cn = & $s.Open
        if (-not $cn) { throw 'the database could not be opened' }
        if ([int]@(Invoke-SICiBuildLockSql -Connection $cn -Sql (Get-SICiBuildLockSql 'Take') -Params @{ ms = '0' })[0].Result -lt 0) {
            Close-SICiBuildLockConnection $cn
            return [pscustomobject]@{ Held = $false; Why = 'this build lost its lock (its database connection ended) and another CI build is running now -- this build stops here and writes nothing more; the next build builds what is left' }
        }
        $now = ConvertFrom-SICiBuildLockHolder ([string]@(Invoke-SICiBuildLockSql -Connection $cn -Sql (Get-SICiBuildLockSql 'HolderGet'))[0].Value)
        if ($s.Token -and $now -and [string]$now.Token -eq [string]$s.Token) {
            $s.Connection = $cn
            $script:SICiBuildLockState = $s
            if ($Log) { & $Log 'INFO' (Format-SICiBuildLockLine -Kind Kept) }
            return [pscustomobject]@{ Held = $true; Why = '' }
        }
        try { $null = Invoke-SICiBuildLockSql -Connection $cn -Sql (Get-SICiBuildLockSql 'Release') } catch { }
        Close-SICiBuildLockConnection $cn
        return [pscustomobject]@{ Held = $false; Why = 'this build lost its lock (its database connection ended) and another CI build may have run meanwhile -- this build stops here and writes nothing more; the next build builds what is left' }
    } catch {
        Close-SICiBuildLockConnection $cn
        return [pscustomobject]@{ Held = $false; Why = ('this build lost its lock (its database connection ended) and could not take it again ({0}) -- this build stops here and writes nothing more; the next build builds what is left' -f $_.Exception.Message) }
    }
}

function Exit-SICiBuildLock {
    <# Releases the CI build's lock of this process and ends its connection. Never throws; nothing held = nothing done. #>
    $s = $script:SICiBuildLockState
    $script:SICiBuildLockState = $null
    if (-not $s) { return }
    try {
        if ($s.Connection -and $s.Connection.State -eq [System.Data.ConnectionState]::Open) {
            try { $null = Invoke-SICiBuildLockSql -Connection $s.Connection -Sql (Get-SICiBuildLockSql 'HolderClear') -Params @{ v = [string]$s.Holder } } catch { }
            $null = Invoke-SICiBuildLockSql -Connection $s.Connection -Sql (Get-SICiBuildLockSql 'Release')
        }
    } catch { }
    Close-SICiBuildLockConnection $s.Connection
}
