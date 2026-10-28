#Requires -Version 5.1
<#
    SecurityInsight Pro -- FULL ASSET METADATA IN THE PRO DATABASE (REQUIREMENTS #301 / #408 / #412).

    Two levels, one setting (SI_AssetProperties):
      security (the default)  what SecurityInsight needs for risk -- the typed profile columns. NOTHING is stored here.
      full                    every property every source system reports about an asset (SI_AssetProperties_CL,
                              written by the endpoint / identity / azure profilers from their own single pull, #412),
                              copied into sidata.AssetMetadata so the web app's asset page can show it -- every snapshot,
                              with its history -- kept SI_AssetProperties_RetentionDays (default 3).

    THE STORAGE IS GENERIC (operator 2026-08-31: "store lots of detailed properties under Properties, like how Azure does
    it for an Azure object"; 2026-10-06: "store data in generic fields in the asset full, so we dont have to extend schema
    to milions of columns ... many are stored in array format under properties"). One row per (CI, source system, source
    record, item) and the source object itself as JSON, verbatim -- ARRAYS STAY ARRAYS. No column per property, no
    numbered columns for array elements, no schema change when a source adds a field. Why not one row per property path
    (an EAV table): an Azure VM alone has ~200 leaf paths, so an estate of 10,000 assets x 6 sources would be ~12 million
    rows a day, its arrays would have to be flattened into numbered paths (exactly what the operator ruled out), and the
    asset page would have to re-assemble every object from its pieces. The asset page reads ONE CI's few objects, so
    walking the JSON there is cheap; a cross-asset question is still one query (OPENJSON / JSON_VALUE by path).

    THE ALGORITHM (Invoke-SIDataAssetMetadataSync, called by the data sync on every run):
      1. SI_AssetProperties is not 'full' -> nothing is read or written (said once). Retention still runs, so metadata
         stored before the level was switched back ages out.
      2. The database must carry sidata.AssetMetadata / AssetMetadataLoad with its SourceRows column (else said once: run
         setup\Initialize-SIDataSql.ps1 -- the updater applies it by itself).
      3. EVERY SI_AssetProperties_CL snapshot (CollectionTime) inside the retention window, oldest first, with its row
         count and size (#412: each profiler publishes its own sources with its own CollectionTime, and the asset page
         shows the history -- so every snapshot is kept, not only the newest). One already in sidata.AssetMetadataLoad
         with at least as many rows -> nothing to do; one that has GROWN since (a second profiler published with the same
         CollectionTime) is loaded again. A table that does not exist yet (full never ran) -> said, skipped.
      4. A snapshot is read in measured hash partitions (Get-SIDataPartitionCount; a too-large answer doubles them and
         starts again). Each row's CI = the correlation map's ledger id for its SI_AssetId, else the id the row itself
         carries when the map marked it ledger, else SI_AssetId -- the same key sidata.Asset uses (Get-SIDataAssetKey).
      5. Each chunk is written in ONE transaction and ADDED: the CI's objects of older collections stay (#412 history --
         retention removes them after SI_AssetProperties_RetentionDays). A load that died part way is cleaned (its rows
         removed) before it is loaded again; the snapshot is recorded LAST.

    Every builder is PURE (text in, text out) so the shapes are testable offline. PS 5.1 safe; no PowerShell modules.
#>

$script:SIDataMetadataTable = 'SI_AssetProperties_CL'

function Get-SIDataAssetMetadataMode {
    <# PURE. SI_AssetProperties from a name -> value map: 'full' (any case) turns the full level on; anything else = 'security'. #>
    param([hashtable]$Globals = @{})
    $raw = ''
    if ($Globals.ContainsKey('SI_AssetProperties') -and $null -ne $Globals['SI_AssetProperties']) { $raw = ([string]$Globals['SI_AssetProperties']).Trim() }
    if ($raw -eq 'full') { return 'full' }
    'security'
}

function Get-SIDataAssetMetadataSnapshotKql {
    <#
        PURE. EVERY SI_AssetProperties_CL snapshot (#412: one per profiler run -- each publishes its own sources with its own
        CollectionTime) of the last -LookbackDays: its CollectionTime, row count, estimated size, source systems and
        profilers, oldest first.
    #>
    param([int]$LookbackDays = 8)
    @"
SI_AssetProperties_CL
| where TimeGenerated > ago($($LookbackDays)d)
| summarize Rows = count(), Bytes = sum(estimate_data_size(*)), Sources = make_set(tostring(column_ifexists("SourceSystem", "")), 64),
            Engines = make_set(tostring(column_ifexists("Engine", "")), 8) by CollectionTime
| order by CollectionTime asc
"@
}

function Get-SIDataAssetMetadataKql {
    <#
        PURE. The rows of ONE snapshot, one hash partition of the asset ids (-Partition 0..Partitions-1). Properties is
        read as JSON TEXT (tostring of the dynamic column): the object exactly as collected, arrays as arrays.
    #>
    param(
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [int]$Partition = 0,
        [int]$Partitions = 1,
        [int]$LookbackDays = 8
    )
    if ($Partitions -lt 1) { throw 'Get-SIDataAssetMetadataKql: -Partitions must be 1 or more' }
    if ($Partition -lt 0 -or $Partition -ge $Partitions) { throw ('Get-SIDataAssetMetadataKql: -Partition {0} is outside 0..{1}' -f $Partition, ($Partitions - 1)) }
    $part = if ($Partitions -gt 1) { "| where hash(_aid, $Partitions) == $Partition" } else { '' }
    @"
SI_AssetProperties_CL
| where TimeGenerated > ago($($LookbackDays)d)
| where CollectionTime == $(ConvertTo-SIDataKqlTime -Time $CollectionTime)
| extend _aid = tostring(column_ifexists("SI_AssetId", ""))
$part
| project SI_AssetId = _aid,
          SI_CorrelationId = tostring(column_ifexists("SI_CorrelationId", "")),
          SI_IdSource = tostring(column_ifexists("SI_IdSource", "")),
          SourceSystem = tostring(column_ifexists("SourceSystem", "")),
          ItemName = tostring(column_ifexists("ItemName", "")),
          SerialNumber = tostring(column_ifexists("SerialNumber", "")),
          MacAddress = tostring(column_ifexists("MacAddress", "")),
          ParentResourceId = tostring(column_ifexists("ParentResourceId", "")),
          PropertyCount = tolong(column_ifexists("PropertyCount", long(null))),
          PropertiesBytes = tolong(column_ifexists("PropertiesBytes", long(null))),
          Dropped = tobool(column_ifexists("PropertiesDropped", false)),
          Held = tobool(column_ifexists("SI_HandoffHeld", false)),
          PropertiesJson = tostring(column_ifexists("Properties", dynamic(null)))
"@
}

function ConvertTo-SIDataMetadataJsonText {
    <#
        PURE. The JSON the store keeps for one row's Properties: an object or an array is kept VERBATIM (arrays stay
        arrays); empty becomes {}; anything else (a bare value) is wrapped as { "value": <text> } so it is never lost.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = ([string]$Text).Trim()
    if (-not $t -or $t -eq 'null') { return '{}' }
    if (($t.StartsWith('{') -and $t.EndsWith('}')) -or ($t.StartsWith('[') -and $t.EndsWith(']'))) { return $t }
    '{"value":' + (ConvertTo-SIDataJsonString $t) + '}'
}

function ConvertTo-SIDataAssetMetadataItems {
    <#
        PURE. Snapshot rows -> the JSON items the store's write reads (one per (CI, source system, record, item); the
        first of a duplicate wins). Returns @{ Items; Keys (the CIs); Sources; Unmatched (rows without an asset id) }.
        The CI key is sidata.Asset's: the correlation map's ledger id, else the row's own id when the map marked it
        ledger, else SI_AssetId.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [hashtable]$Index = @{},
        [int]$MaxKeyLength = 400
    )
    $items = New-Object System.Collections.Generic.List[string]
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $sources = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $unmatched = 0
    $get = { param($r, [string]$n) $p = $r.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value -and -not ($p.Value -is [System.DBNull])) { ([string]$p.Value).Trim() } else { '' } }
    $num = { param($r, [string]$n) $v = & $get $r $n; $x = [long]0; if ($v -and [long]::TryParse($v, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$x)) { [string]$x } else { 'null' } }
    $flag = { param($r, [string]$n) $v = & $get $r $n; if ($v -eq 'true' -or $v -eq 'True' -or $v -eq '1') { 'true' } else { 'false' } }
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $aid = & $get $r 'SI_AssetId'
        if (-not $aid -or $aid.Length -gt $MaxKeyLength) { $unmatched++; continue }
        $ak = Get-SIDataAssetKey -SIAssetId $aid -Index $Index
        $key = [string]$ak.Key
        if ($ak.Source -ne 'ledger') {
            $own = & $get $r 'SI_CorrelationId'
            if ($own -and (& $get $r 'SI_IdSource') -eq 'ledger' -and $own.Length -le $MaxKeyLength) { $key = $own }
        }
        $src = (& $get $r 'SourceSystem').ToLowerInvariant(); if (-not $src) { $src = 'unknown' }
        if ($src.Length -gt 32) { $src = $src.Substring(0, 32) }
        $item = & $get $r 'ItemName'; if ($item.Length -gt 256) { $item = $item.Substring(0, 256) }
        $dk = $key + '|' + $src + '|' + $aid + '|' + $item
        if (-not $seen.Add($dk)) { continue }
        [void]$keys.Add($key); [void]$sources.Add($src)
        $ser = & $get $r 'SerialNumber'; $mac = & $get $r 'MacAddress'; $par = & $get $r 'ParentResourceId'
        $items.Add('{"AssetKey":' + (ConvertTo-SIDataJsonString $key) + ',"SourceSystem":' + (ConvertTo-SIDataJsonString $src) +
            ',"ItemName":' + (ConvertTo-SIDataJsonString $item) + ',"MemberAssetId":' + (ConvertTo-SIDataJsonString $aid) +
            ',"SerialNumber":' + $(if ($ser) { ConvertTo-SIDataJsonString $ser } else { 'null' }) +
            ',"MacAddress":' + $(if ($mac) { ConvertTo-SIDataJsonString $mac } else { 'null' }) +
            ',"ParentResourceId":' + $(if ($par) { ConvertTo-SIDataJsonString $par } else { 'null' }) +
            ',"PropertyCount":' + (& $num $r 'PropertyCount') + ',"PropertiesBytes":' + (& $num $r 'PropertiesBytes') +
            ',"Dropped":' + (& $flag $r 'Dropped') + ',"Held":' + (& $flag $r 'Held') +
            ',"Props":' + (ConvertTo-SIDataJsonString (ConvertTo-SIDataMetadataJsonText (& $get $r 'PropertiesJson'))) + '}')
    }
    [pscustomobject]@{ Items = $items.ToArray(); Keys = $keys; Sources = @($sources | Sort-Object); Unmatched = $unmatched }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataAssetMetadataSchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.AssetMetadata') IS NOT NULL AND OBJECT_ID('sidata.AssetMetadataLoad') IS NOT NULL AND COL_LENGTH('sidata.AssetMetadataLoad', 'SourceRows') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataAssetMetadataLoadedSql {
    <#
        1 when THIS snapshot is already loaded with at least @SourceRows rows of Log Analytics (#412: every snapshot is kept,
        so the check is per snapshot; a load recorded before SourceRows existed counts as complete).
    #>
    "SELECT COUNT(*) FROM sidata.AssetMetadataLoad WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND (SourceRows IS NULL OR SourceRows >= @SourceRows)"
}

function Get-SIDataAssetMetadataCleanSql {
    <# One batch of the clean-up of a load that died part way: the rows of THIS snapshot (it is not recorded as loaded). #>
    @'
DELETE TOP (@Batch) FROM sidata.AssetMetadata WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126);
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataWriteAssetMetadataSql {
    <#
        One chunk, ONE transaction: the CIs' objects of this snapshot are ADDED (#412 history -- the objects of older
        collections stay until retention removes them). A Props text that is not JSON is kept as
        { "_siPayloadUnreadable": "<its first 400 characters>" } -- named, never dropped and never failing the chunk. The
        typed display columns are cut to their width; the object keeps the whole value. Returns the items read.
    #>
    @'
SET XACT_ABORT ON;
DECLARE @r TABLE (AssetKey nvarchar(400), SourceSystem nvarchar(32), ItemName nvarchar(256), MemberAssetId nvarchar(400), SerialNumber nvarchar(max),
                  MacAddress nvarchar(max), ParentResourceId nvarchar(max), PropertyCount bigint, PropertiesBytes bigint, Dropped bit, Held bit, Props nvarchar(max));
INSERT @r SELECT j.AssetKey, j.SourceSystem, ISNULL(j.ItemName, N''), j.MemberAssetId, j.SerialNumber, j.MacAddress, j.ParentResourceId, j.PropertyCount,
                 j.PropertiesBytes, ISNULL(j.Dropped, 0), ISNULL(j.Held, 0), j.Props
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), SourceSystem nvarchar(32), ItemName nvarchar(256), MemberAssetId nvarchar(400), SerialNumber nvarchar(max),
                        MacAddress nvarchar(max), ParentResourceId nvarchar(max), PropertyCount bigint, PropertiesBytes bigint, Dropped bit, Held bit, Props nvarchar(max)) j;
BEGIN TRAN;
INSERT sidata.AssetMetadata (AssetKey, SourceSystem, ItemName, MemberAssetId, CollectionTime, SerialNumber, MacAddress, ParentResourceId, PropertyCount,
                             PropertiesBytes, Dropped, HandoffHeld, PropertiesJson)
SELECT r.AssetKey, r.SourceSystem, r.ItemName, r.MemberAssetId, CONVERT(datetime2(3), @CollectionTime, 126), LEFT(r.SerialNumber, 128), LEFT(r.MacAddress, 256),
       LEFT(r.ParentResourceId, 1024),
       CASE WHEN r.PropertyCount BETWEEN 0 AND 2147483647 THEN CONVERT(int, r.PropertyCount) END,
       CASE WHEN r.PropertiesBytes BETWEEN 0 AND 2147483647 THEN CONVERT(int, r.PropertiesBytes) END,
       r.Dropped, r.Held,
       CASE WHEN ISJSON(r.Props) = 1 THEN r.Props ELSE JSON_MODIFY(N'{}', '$._siPayloadUnreadable', LEFT(r.Props, 400)) END
FROM @r AS r;
COMMIT;
SELECT COUNT(*) FROM @r;
'@
}

function Get-SIDataAssetMetadataRecordSql {
    <#
        The snapshot is recorded as loaded -- LAST, after every chunk landed -- with its Log Analytics row count
        (@SourceRows). A snapshot loaded again because it grew updates its record.
    #>
    @'
UPDATE sidata.AssetMetadataLoad SET [Rows] = @Rows, Assets = @Assets, Sources = @Sources, Unmatched = @Unmatched, SourceRows = @SourceRows, LoadedAt = SYSUTCDATETIME()
WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126);
IF @@ROWCOUNT = 0
INSERT sidata.AssetMetadataLoad (CollectionTime, [Rows], Assets, Sources, Unmatched, SourceRows)
SELECT CONVERT(datetime2(3), @CollectionTime, 126), @Rows, @Assets, @Sources, @Unmatched, @SourceRows;
SELECT 1;
'@
}

function Get-SIDataAssetMetadataPruneSql {
    <# One batch of the retention step: metadata (-What Rows) or load records (-What Loads) collected before @Cutoff. Nothing without the table. #>
    param([ValidateSet('Rows', 'Loads')][string]$What = 'Rows')
    $t = if ($What -eq 'Rows') { 'sidata.AssetMetadata' } else { 'sidata.AssetMetadataLoad' }
    @"
IF OBJECT_ID('$t') IS NULL BEGIN SELECT 0; RETURN; END;
DELETE TOP (@Batch) FROM $t WHERE CollectionTime < CONVERT(datetime2(3), @Cutoff, 126);
SELECT @@ROWCOUNT;
"@
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STEPS
# ------------------------------------------------------------------------------------------------------------------

function Invoke-SIDataAssetMetadataPrune {
    <#
        Removes the stored full metadata collected before -Cutoff, in batches (rows, then the load records). Runs at
        every level: metadata stored while 'full' was on ages out after the level is switched back. Returns the rows removed.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$Cutoff)
    $batch = [long]5000
    $p = @{ Cutoff = (Format-SIDataSqlTime -Time $Cutoff) }
    $n = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataAssetMetadataPruneSql -What Rows) -Params $p -BatchSize ([ref]$batch)
    [void](Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataAssetMetadataPruneSql -What Loads) -Params $p -BatchSize ([ref]$batch))
    [long]$n
}


function Invoke-SIDataAssetMetadataSync {
    <#
        The data sync's full-metadata step (see the header). Loads EVERY snapshot not yet stored (#412 history), oldest
        first, inside the retention window (-RetentionDays before -Now; older ones would be pruned at once). -ReadIndex is
        called only when a snapshot is loaded and no correlation index was read by this run yet. Returns @{ Mode; Status;
        CollectionTime (the newest snapshot stored, else the newest seen); Rows; Assets; Sources; Unmatched; Partitions;
        Snapshots (stored this run) }. Status: off | no-schema | no-table | empty | already | dry-run | loaded.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Query,
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [Parameter(Mandatory)][scriptblock]$ReadOrSkip,
        [string]$Mode = 'security',
        [AllowNull()]$Index,
        [scriptblock]$ReadIndex,
        [int]$LookbackDays = 8,
        [int]$RetentionDays = 0,
        [datetime]$Now = [datetime]::UtcNow,
        [switch]$DryRun,
        [scriptblock]$Log,
        [ref]$ChunkChars
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $res = [ordered]@{ Mode = $Mode; Status = 'off'; CollectionTime = $null; Rows = 0L; Assets = 0; Sources = @(); Unmatched = 0; Partitions = 0; Snapshots = 0 }
    if ($Mode -ne 'full') {
        & $Log 'INFO' 'metadata    : full asset metadata is off (SI_AssetProperties = security) -- the security profile only; nothing extra is stored.'
        return [pscustomobject]$res
    }
    if ([int](& $Invoke (Get-SIDataAssetMetadataSchemaCheckSql) @{} 'scalar') -ne 1) {
        $res.Status = 'no-schema'
        & $Log 'WARN' 'metadata    : full asset metadata is on, but the database does not have its tables yet -- run setup\Initialize-SIDataSql.ps1 again to add them (the updater does this by itself); the asset page shows no full metadata until then.'
        return [pscustomobject]$res
    }
    $snap = & $ReadOrSkip (Get-SIDataAssetMetadataSnapshotKql -LookbackDays $LookbackDays) $script:SIDataMetadataTable
    if ($null -eq $snap) { $res.Status = 'no-table'; return [pscustomobject]$res }
    $cutoff = $null
    if ($RetentionDays -ge 1) { $cutoff = $Now.ToUniversalTime().AddDays(-$RetentionDays) }
    $snaps = @(@($snap) | Where-Object { $_ -and $null -ne $_.CollectionTime -and -not [string]::IsNullOrWhiteSpace([string]$_.CollectionTime) } |
        ForEach-Object { [pscustomobject]@{ At = (ConvertTo-SIDataUtc $_.CollectionTime); Rows = [long](ConvertTo-SIDataNumber $_.Rows); Bytes = [double](ConvertTo-SIDataNumber $_.Bytes) } } |
        Where-Object { $null -eq $cutoff -or $_.At -ge $cutoff } | Sort-Object At)
    if ($snaps.Count -eq 0) {
        $res.Status = 'empty'
        & $Log 'INFO' ('metadata    : no full asset metadata in the last {0} day(s) -- no profiler has run with SI_AssetProperties = full yet.' -f $LookbackDays)
        return [pscustomobject]$res
    }
    $res.CollectionTime = $snaps[-1].At

    # which snapshots are not stored yet (or have grown since they were)
    $todo = @(foreach ($s in $snaps) {
        $p = @{ CollectionTime = (Format-SIDataSqlTime -Time $s.At); SourceRows = [int][Math]::Min([long][int]::MaxValue, $s.Rows) }
        if ([int](& $Invoke (Get-SIDataAssetMetadataLoadedSql) $p 'scalar') -eq 0) { $s }
    })
    if ($todo.Count -eq 0) {
        $res.Status = 'already'
        & $Log 'INFO' ("metadata    : every full-metadata snapshot up to {0:yyyy-MM-dd HH:mm} UTC is already stored ({1} snapshot(s) kept)." -f $res.CollectionTime, $snaps.Count)
        return [pscustomobject]$res
    }
    if ($DryRun) {
        $res.Status = 'dry-run'; $res.Rows = [long](($todo | Measure-Object -Property Rows -Sum).Sum); $res.Snapshots = $todo.Count
        & $Log 'INFO' ("metadata    : {0} full-metadata row(s) of {1} snapshot(s) would be stored; nothing is written." -f $res.Rows, $todo.Count)
        return [pscustomobject]$res
    }
    if ($null -eq $Index) { $Index = $(if ($ReadIndex) { & $ReadIndex } else { @{} }) }
    if ($null -eq $Index) { $Index = @{} }

    $chunk = [long]0; if ($ChunkChars -and $ChunkChars.Value -gt 0) { $chunk = [long]$ChunkChars.Value }
    $batch = [long]5000
    $allKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $allSrcs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $todo) {
        $at = $s.At
        $p = @{ CollectionTime = (Format-SIDataSqlTime -Time $at) }
        $partitions = Get-SIDataPartitionCount -Rows $s.Rows -Bytes $s.Bytes -Expansion 1.5
        while ($true) {
            # a load that died part way (or the previous, too-large attempt, or a snapshot that has grown) leaves rows of
            # this snapshot: removed first
            [void](Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataAssetMetadataCleanSql) -Params $p -BatchSize ([ref]$batch))
            $written = 0L; $unmatched = 0
            $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $srcs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $tooLarge = $false
            for ($i = 0; $i -lt $partitions; $i++) {
                $kql = Get-SIDataAssetMetadataKql -CollectionTime $at -Partition $i -Partitions $partitions -LookbackDays $LookbackDays
                try { $part = @(& $Query $kql) }
                catch {
                    if (Test-SIDataResponseTooLarge -Text $_.Exception.Message) { $tooLarge = $true; break }
                    throw
                }
                $conv = ConvertTo-SIDataAssetMetadataItems -Rows $part -Index $Index
                $unmatched += [int]$conv.Unmatched
                foreach ($k in $conv.Keys) { [void]$keys.Add($k) }
                foreach ($x in $conv.Sources) { [void]$srcs.Add($x) }
                if (@($conv.Items).Count -gt 0) {
                    $cc = [long]$chunk
                    $written += Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataWriteAssetMetadataSql) -Items $conv.Items -Params $p -ChunkChars ([ref]$cc) -What 'full asset metadata'
                    $chunk = $cc
                }
            }
            if (-not $tooLarge) { break }
            $partitions = $partitions * 2
            & $Log 'WARN' ("metadata    : a partition's answer was too large -- reading again in {0} partitions." -f $partitions)
            if ($partitions -gt 4096) { throw 'full asset metadata: the snapshot cannot be read in partitions small enough for Log Analytics.' }
        }
        $sources = @($srcs | Sort-Object)
        [void](& $Invoke (Get-SIDataAssetMetadataRecordSql) @{ CollectionTime = $p.CollectionTime; Rows = [int]$written; Assets = [int]$keys.Count; Sources = ($sources -join ', '); Unmatched = [int]$unmatched
                                                              SourceRows = [int][Math]::Min([long][int]::MaxValue, $s.Rows) } 'scalar')
        foreach ($k in $keys) { [void]$allKeys.Add($k) }
        foreach ($x in $sources) { [void]$allSrcs.Add($x) }
        $res.Rows += $written; $res.Unmatched += $unmatched; $res.Snapshots++
        if ($partitions -gt $res.Partitions) { $res.Partitions = $partitions }
        & $Log 'OK' ("metadata    : full asset metadata collected {0:yyyy-MM-dd HH:mm} UTC stored -- {1} object(s) of {2} CI(s) from {3}{4}" -f $at, $written, $keys.Count,
            $(if ($sources.Count) { $sources -join ', ' } else { '(no source)' }), $(if ($unmatched) { ('; {0} row(s) without an asset id were not stored' -f $unmatched) } else { '' }))
    }
    if ($ChunkChars) { $ChunkChars.Value = $chunk }
    $res.Status = 'loaded'; $res.Assets = $allKeys.Count; $res.Sources = @($allSrcs | Sort-Object)
    [pscustomobject]$res
}
