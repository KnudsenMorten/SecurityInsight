#Requires -Version 5.1
<#
    SI v3 -- THE CORRELATION MAP AT MILLIONS OF ASSETS (#639, owner 2026-10-21: "memory issues must not be a problem in any
    step. env must work in millions of assets env").

    The map used to hold the WHOLE snapshot at once: every profile row of every engine read in one Log Analytics answer
    (cut by the service above ~500,000 rows, and the cut was not looked at), grouped in memory, the WHOLE identity ledger
    read, every map row built and posted in one call -- ~30 GB at 2 M assets. Now:

      1. READ     each engine's snapshot in hash PARTS (abs(hash(SI_AssetId)) % parts), the snapshot time pinned by one
                  count query, so every part reads the same snapshot; the number of parts follows the row count
                  (SI_Correlation_PartRows rows per part, default 100,000); a part refused as a cut answer is read again
                  as two parts. Each part is turned into correlation inputs and STAGED in SQL (sidata.CorrInput +
                  CorrInputKey) before the next part is read.
      2. GROUP    in SQL: connected components over the shared joinable identifiers (and every force-merge decision's
                  anchors as one more edge) by label propagation, each round its own statement, then the components are
                  numbered into BATCHES of about SI_Correlation_BatchRows rows (default 5,000) -- a component is never
                  split, so a batch holds whole objects.
      3. PER BATCH  the batch's input rows (in read order) go through the SAME pure core (Get-SICorrelationGroups with the
                  operator's decision plan): a component is self-contained, so the batch decides exactly what the whole
                  snapshot would for its objects. The identity ledger is read for the batch only (SQL:
                  Get-SIObjectLedgerSubset, written per batch with Save-SIObjectLedgerSet -- as the CI build does; a blob
                  ledger is one document: read whole once, written once at the end, and that is said). The batch's map
                  rows are built and posted, then let go.

    Memory = one part while reading, one batch while correlating, at any tenant size. Without a database (or one the
    updater has not updated -- no sidata.CorrInput) the engine keeps the whole-snapshot path of before and says so.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

function Get-SICorrValue {
    <# PURE. A named value of a row (dictionary or object), case-insensitive; $null when absent or DBNull. #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    $v = $null
    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Name)) { $v = $Item[$Name] } else { foreach ($k in $Item.Keys) { if ([string]::Equals([string]$k, $Name, [StringComparison]::OrdinalIgnoreCase)) { $v = $Item[$k]; break } } }
    } else { $p = $Item.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function ConvertTo-SICorrJsonArray {
    <# PURE. Always a JSON ARRAY for OPENJSON (PowerShell 5.1 writes a one-item list as the bare object). #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Items, [int]$Depth = 4)
    if ($null -eq $Items -or @($Items).Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject @($Items) -Compress -Depth $Depth
    if ($j.TrimStart().StartsWith('[')) { $j } else { '[' + $j + ']' }
}

function Get-SICorrelationPartRows {
    <# Rows per snapshot part (SI_Correlation_PartRows, default 100,000): sizes each Log Analytics answer well under the
       service's answer limit. It paces the reads; it never limits how many rows are read. #>
    $n = 0
    if ($global:SI_Correlation_PartRows -and [int]::TryParse(([string]$global:SI_Correlation_PartRows).Trim(), [ref]$n) -and $n -gt 0) { return $n }
    100000
}

function Get-SICorrelationBatchRows {
    <# Input rows per correlation batch (SI_Correlation_BatchRows, default 5,000 -- about the CI build's batch of 2,000
       CIs). A component (one object and everything joined to it) is never split, so a batch can be larger. #>
    $n = 0
    if ($global:SI_Correlation_BatchRows -and [int]::TryParse(([string]$global:SI_Correlation_BatchRows).Trim(), [ref]$n) -and $n -gt 0) { return $n }
    5000
}

function Get-SICorrelationCountKql {
    <# One engine's current snapshot: its time (the v3 rows' newest CollectionTime) and its row count, in ONE small answer. #>
    param([Parameter(Mandatory)][string]$TableName)
    @(
        ('let v3 = {0} | where isnotempty(tostring(column_ifexists("SI_AssetId", "")));' -f $TableName)
        'let snap = toscalar(v3 | summarize max(CollectionTime));'
        'v3'
        '| where CollectionTime == snap'
        '| summarize Rows = count(), SnapshotTime = max(CollectionTime)'
    ) -join "`n"
}

function Test-SICorrelationCutAnswer {
    <# PURE. Is this failure an answer the service cut or refused for its size (read the part again in two)? #>
    param([AllowNull()][string]$Message)
    if (-not $Message) { return $false }
    return ($Message -match '(?i)(partial|cut|truncat|too large|too big|result set|E_QUERY_RESULT_SET_TOO_LARGE|exceed|maximum|limit|OutOfMemory|64 ?MB|500,?000)')
}

function ConvertTo-SICorrelationStageKey {
    <# PURE. An identifier key ('type|value', lower case) as the stage holds it: as it is up to 450 characters, else its SHA-256. #>
    param([Parameter(Mandatory)][string]$Key)
    if ($Key.Length -le 450) { return $Key }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { 'sha|' + (([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))) -replace '-', '').ToLowerInvariant()) } finally { $sha.Dispose() }
}

function Get-SICorrelationInputKeys {
    <#
        PURE. The grouping edges of one input: its joinable identifiers as 'type|value' (the key Get-SICorrelationGroups
        unions on), and 'force|<n>' for every force-merge decision (-Plan) whose anchors it carries -- so the inputs a
        force-merge joins land in one component, and one batch.
    #>
    param([Parameter(Mandatory)]$In, $Plan)
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $mine = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($id in (Get-SIMemberIdentifiers -Member $In)) {
        $k = '{0}|{1}' -f ([string]$id.Type).ToLowerInvariant(), ([string]$id.Value)
        [void]$keys.Add((ConvertTo-SICorrelationStageKey -Key $k))
        [void]$mine.Add(('{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()))
    }
    if ($null -ne $Plan -and -not $Plan.IsEmpty) {
        $f = 0
        foreach ($fe in @($Plan.Force)) {
            foreach ($a in @($fe.AnchorKeys)) { if ($mine.Contains([string]$a)) { [void]$keys.Add(('force|{0}' -f $f)); break } }
            $f++
        }
    }
    $out = New-Object 'string[]' $keys.Count; $keys.CopyTo($out); $out
}

function ConvertTo-SICorrelationStageDoc {
    <# PURE. One input as the stage keeps it (JSON): e = engine, a = SI_AssetId, i = [[type, value]]. #>
    param([Parameter(Mandatory)]$In)
    $ids = @(foreach ($id in (Get-SIMemberIdentifiers -Member $In)) { , @([string]$id.Type, [string]$id.Value) })
    ConvertTo-Json -InputObject ([ordered]@{ e = [string]$In.Engine; a = [string]$In.SIAssetId; i = $ids }) -Compress -Depth 4
}

function ConvertFrom-SICorrelationStageDoc {
    <# PURE. The stage's JSON back to the input ConvertTo-SICorrelationInput made (Engine, SIAssetId, Identifiers). #>
    param([Parameter(Mandatory)][string]$Json)
    $o = ConvertFrom-Json -InputObject $Json
    $ids = New-Object System.Collections.ArrayList
    foreach ($p in @($o.i)) { if ($null -ne $p -and @($p).Count -ge 2) { [void]$ids.Add([pscustomobject]@{ Type = [string]@($p)[0]; Value = [string]@($p)[1] }) } }
    [pscustomobject]@{ Engine = [string]$o.e; SIAssetId = [string]$o.a; Identifiers = @($ids) }
}

function Get-SICorrelationStageCheckSql {
    "SET NOCOUNT ON; SELECT CASE WHEN OBJECT_ID(N'sidata.CorrInput') IS NULL OR OBJECT_ID(N'sidata.CorrInputKey') IS NULL THEN 0 ELSE 1 END AS HasStage;"
}

function Get-SICorrelationStageClearSql {
    <# One step of emptying the stage (@n rows of each table per statement): answers Deleted. #>
    @'
SET NOCOUNT ON;
DELETE TOP (CONVERT(INT, @n)) FROM sidata.CorrInputKey;
DECLARE @a INT = @@ROWCOUNT;
DELETE TOP (CONVERT(INT, @n)) FROM sidata.CorrInput;
SELECT @a + @@ROWCOUNT AS Deleted;
'@
}

function Get-SICorrelationStageWriteSql {
    <# One chunk of staged inputs: @r = [{ n; e; d }] (row number, engine, the input's JSON), @k = [{ n; k }] (its keys). #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRANSACTION;
INSERT sidata.CorrInput (RowNo, Engine, Lbl, BatchNo, Doc)
SELECT x.n, x.e, x.n, NULL, x.d FROM OPENJSON(@r) WITH (n INT, e NVARCHAR(32), d NVARCHAR(MAX)) x WHERE x.n IS NOT NULL;
INSERT sidata.CorrInputKey (K, RowNo)
SELECT DISTINCT LEFT(x.k, 450), x.n FROM OPENJSON(@k) WITH (n INT, k NVARCHAR(450)) x WHERE x.n IS NOT NULL AND x.k IS NOT NULL AND x.k <> N'';
COMMIT TRANSACTION;
SELECT @@ROWCOUNT AS Written;
'@
}

function Get-SICorrelationGroupingStepSql {
    <#
        The SQL grouping's statements, each its own round trip (each commits):
          round   every input takes the smallest label among the inputs it shares a key with (only keys two or more inputs
                  carry), then every label jumps to its own label's label -- answers Changed
          batches the components (one label each) numbered into batches of about @per rows in label order (a component
                  never split) -- answers Rows, Components, Largest, Batches
    #>
    param([Parameter(Mandatory)][ValidateSet('round', 'batches')][string]$Step)
    switch ($Step) {
        'round' {
            @'
SET NOCOUNT ON;
DECLARE @c1 INT = 0, @c2 INT = 0;
UPDATE i SET Lbl = x.m FROM sidata.CorrInput i JOIN (
    SELECT k.RowNo, MIN(km.m) AS m FROM sidata.CorrInputKey k
    JOIN (SELECT k2.K, MIN(i2.Lbl) AS m FROM sidata.CorrInputKey k2 JOIN sidata.CorrInput i2 ON i2.RowNo = k2.RowNo GROUP BY k2.K HAVING COUNT(*) > 1) km ON km.K = k.K
    GROUP BY k.RowNo) x ON x.RowNo = i.RowNo
WHERE x.m < i.Lbl;
SET @c1 = @@ROWCOUNT;
UPDATE i SET Lbl = j.Lbl FROM sidata.CorrInput i JOIN sidata.CorrInput j ON j.RowNo = i.Lbl WHERE j.Lbl < i.Lbl;
SET @c2 = @@ROWCOUNT;
SELECT @c1 + @c2 AS Changed;
'@
        }
        'batches' {
            @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @p BIGINT = CONVERT(BIGINT, @per);
WITH c AS (SELECT Lbl, COUNT_BIG(*) AS n FROM sidata.CorrInput GROUP BY Lbl),
     s AS (SELECT Lbl, SUM(n) OVER (ORDER BY Lbl ROWS UNBOUNDED PRECEDING) - n AS before FROM c)
UPDATE i SET BatchNo = CONVERT(INT, 1 + s.before / @p) FROM sidata.CorrInput i JOIN s ON s.Lbl = i.Lbl;
SELECT (SELECT COUNT_BIG(*) FROM sidata.CorrInput) AS Rows,
       (SELECT COUNT_BIG(DISTINCT Lbl) FROM sidata.CorrInput) AS Components,
       ISNULL((SELECT MAX(n) FROM (SELECT COUNT_BIG(*) AS n FROM sidata.CorrInput GROUP BY Lbl) z), 0) AS Largest,
       ISNULL((SELECT MAX(BatchNo) FROM sidata.CorrInput), 0) AS Batches;
'@
        }
    }
}

function Get-SICorrelationBatchSql {
    <# One batch's inputs (@b), in read order. #>
    "SET NOCOUNT ON; SELECT RowNo, Doc FROM sidata.CorrInput WHERE BatchNo = CONVERT(INT, @b) ORDER BY RowNo;"
}

function Wait-SICorrelationFreshSnapshot {
    <#
        The freshness wait of Get-SICorrelationSnapshot (the same expectations, the same bounded wait, the same lines) over
        each engine's snapshot TIME only (Get-SICorrelationCountKql: one small answer per engine and poll) -- the paged read
        never reads a whole snapshot just to look at its age. Answers the engines still behind ('' = none).
    #>
    param([Parameter(Mandatory)][hashtable]$EngineTables, [string]$WorkspaceResourceId, [datetime]$ExpectFreshSince = [datetime]::MinValue,
          [hashtable]$LocalRunStart, [int]$MaxWaitSeconds = -1, [int]$PollSeconds = 30, [scriptblock]$Kql)
    if (-not $Kql) { $Kql = { param($Query) Invoke-SICorrelationKql -WorkspaceResourceId $WorkspaceResourceId -Query $Query } }
    if ($MaxWaitSeconds -lt 0) { $MaxWaitSeconds = if ($global:SI_CorrelationFreshnessWaitSec) { [int]$global:SI_CorrelationFreshnessWaitSec } else { 600 } }
    $toMinute = { param([datetime]$T) [datetime]::new($T.Year, $T.Month, $T.Day, $T.Hour, $T.Minute, 0, [DateTimeKind]::Utc) }
    $expected = @{}
    foreach ($engine in @($EngineTables.Keys)) {
        $want = $ExpectFreshSince
        if ($LocalRunStart -and $LocalRunStart.ContainsKey($engine)) { $local = [datetime]$LocalRunStart[$engine]; if ($local -gt $want) { $want = $local } }
        if ($want -gt [datetime]::MinValue) { $expected[$engine] = (& $toMinute $want.ToUniversalTime()) }
    }
    if ($expected.Count -eq 0) { return '' }
    $deadline = (Get-Date).ToUniversalTime().AddSeconds($MaxWaitSeconds); $announced = $false
    while ($true) {
        $behind = @()
        foreach ($engine in @($expected.Keys)) {
            $have = $null
            try {
                $c = @(& $Kql (Get-SICorrelationCountKql -TableName ([string]$EngineTables[$engine]))) | Select-Object -First 1
                if ($c) { $st = Get-SICorrValue $c 'SnapshotTime'; if ($st) { $have = & $toMinute ([datetime]$st).ToUniversalTime() } }
            } catch {
                if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName ([string]$EngineTables[$engine])) { continue }
                throw
            }
            if (-not $have -or $have -lt [datetime]$expected[$engine]) { $behind += ('{0} (snapshot {1}, expected >= {2:u})' -f $engine, $(if ($have) { '{0:u}' -f $have } else { 'none' }), $expected[$engine]) }
        }
        if ($behind.Count -eq 0) { if ($announced) { Write-Warning 'correlation: all snapshots are current; continuing.' }; return '' }
        if ((Get-Date).ToUniversalTime() -ge $deadline) {
            Write-Warning ("correlation: PROCEEDING WITH OLDER DATA after waiting {0}s for Log Analytics ingest. Still behind: {1}. The map is built from the last data that WAS queryable, which is correct but not current." -f $MaxWaitSeconds, ($behind -join '; '))
            return ($behind -join '; ')
        }
        if (-not $announced) { Write-Warning ("correlation: a profiler finished more recently than the newest queryable snapshot -- waiting up to {0}s for Log Analytics ingest. Behind: {1}" -f $MaxWaitSeconds, ($behind -join '; ')); $announced = $true }
        Start-Sleep -Seconds $PollSeconds
    }
}

function Read-SICorrelationSnapshotParts {
    <#
        READ, part by part: every engine's current snapshot (Get-SICorrelationCountKql pins its time and counts it), each
        part (abs(hash(SI_AssetId)) % parts) handed to -OnPart { param($Engine, $Inputs) } as correlation inputs before the
        next part is read. A part the service refuses or cuts for its size is read again as two (never accepted cut: an
        answer whose error the reader reports is refused here). A table that does not exist is skipped, said as before.
        -Kql { param($Query) } -> rows: the query seam (tests); default Invoke-SICorrelationKql. Answers the per-engine
        statistics (Engine, Table, Rows, NoJoinableId, SnapshotTime, AgeDays, Note, Parts) and the largest part read (MaxPartRows).
    #>
    param([Parameter(Mandatory)][hashtable]$EngineTables, [Parameter(Mandatory)][scriptblock]$OnPart, [scriptblock]$Kql, [string]$WorkspaceResourceId, [int]$RowLimit = 0, [int]$PartRows = 0)
    if (-not $Kql) { $Kql = { param($Query) Invoke-SICorrelationKql -WorkspaceResourceId $WorkspaceResourceId -Query $Query } }
    if ($PartRows -le 0) { $PartRows = Get-SICorrelationPartRows }
    $stats = New-Object System.Collections.Generic.List[object]
    $maxPart = 0
    foreach ($engine in @($EngineTables.Keys | Sort-Object)) {
        $table = [string]$EngineTables[$engine]
        $note = ''; $rowsN = 0L; $snapUtc = $null; $noKeys = 0; $read = 0L; $parts = 1
        try {
            $c = @(& $Kql (Get-SICorrelationCountKql -TableName $table)) | Select-Object -First 1
            if ($c) {
                $rowsN = [long](Get-SICorrValue $c 'Rows')
                $st = Get-SICorrValue $c 'SnapshotTime'
                if ($st) { try { $snapUtc = ([datetime]$st).ToUniversalTime() } catch { $snapUtc = $null } }
            }
        } catch {
            if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName $table) {
                $note = 'table not present -- engine has never run here'
                Write-Warning ("correlation: SKIPPING {0} ({1}) -- {2}" -f $engine, $table, $note)
            } else { throw }
        }
        if (-not $note -and $rowsN -gt 0 -and $snapUtc) {
            $parts = [int][Math]::Max(1, [Math]::Ceiling($rowsN / [double]$PartRows))
            if ($RowLimit -gt 0) { $parts = 1 }
            # the parts to read: (part, of); a refused part becomes two of twice as many
            $todo = New-Object System.Collections.Generic.Stack[object]
            for ($p = $parts - 1; $p -ge 0; $p--) { $todo.Push(@($p, $parts)) }
            while ($todo.Count -gt 0) {
                $pp = $todo.Pop(); $part = [int]$pp[0]; $of = [int]$pp[1]
                $q = Get-SICorrelationSnapshotKql -TableName $table -RowLimit $RowLimit -SnapshotTime $snapUtc -Part $part -Parts $of
                $rows = $null
                try { $rows = @(& $Kql $q) }
                catch {
                    if ((Test-SICorrelationCutAnswer -Message $_.Exception.Message) -and ($of * 2) -le [Math]::Max(2L, $rowsN)) {
                        Write-Warning ("correlation: {0} part {1} of {2} was refused for its size -- read again as two parts of {3}" -f $engine, ($part + 1), $of, ($of * 2))
                        $todo.Push(@(($part + $of), ($of * 2))); $todo.Push(@($part, ($of * 2)))
                        continue
                    }
                    throw
                }
                if ($rows.Count -gt $maxPart) { $maxPart = $rows.Count }
                $ins = New-Object System.Collections.Generic.List[object]
                foreach ($r in $rows) {
                    $in = ConvertTo-SICorrelationInput -Row $r -Engine $engine
                    if (@($in.Identifiers).Count -eq 0) { $noKeys++ }
                    $ins.Add($in)
                }
                $read += $rows.Count
                $rows = $null
                $null = & $OnPart $engine $ins.ToArray()
                $ins = $null
            }
        }
        $ageDays = if ($snapUtc) { [int]([datetime]::UtcNow - $snapUtc).TotalDays } else { -1 }
        $stats.Add([pscustomobject]@{ Engine = $engine; Table = $table; Rows = $read; NoJoinableId = $noKeys; SnapshotTime = $snapUtc; AgeDays = $ageDays; Note = $note; Parts = $parts; Counted = $rowsN })
    }
    [pscustomobject]@{ Tables = $stats.ToArray(); MaxPartRows = $maxPart }
}

function Invoke-SICorrelationPaged {
    <#
    .SYNOPSIS  The correlation map, staged and correlated a batch at a time (see the header). Returns the run's figures.
    .PARAMETER Sql        the install database seam { param($Sql, $Params, $Mode) } ('rows' | 'scalar')
    .PARAMETER ReadParts  { param($OnPart) } -> the snapshot statistics: calls $OnPart with each part's inputs (tests pass
                          their own; the engine passes Read-SICorrelationSnapshotParts)
    .PARAMETER LedgerProvider  the identity ledger (Get-SIObjectLedgerProvider); $null = none (derived-provisional ids, said)
    .PARAMETER Post       { param($Rows) } -> rows accepted; default Send-SIObjectMapRows (SI_ObjectMap_CL)
    .PARAMETER OnMapRows  { param($Rows) } every batch's map rows (the -JsonOutPath writer; tests)
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Sql,
        [Parameter(Mandatory)][scriptblock]$ReadParts,
        $Plan,
        $LedgerProvider,
        [string]$RunId = ([guid]::NewGuid().ToString()),
        [datetime]$CollectionTime = [datetime]::UtcNow,
        [switch]$DryRun,
        [scriptblock]$Post,
        [scriptblock]$OnMapRows,
        [scriptblock]$Log,
        [int]$BatchRows = 0,
        # accepted and ignored: the grouping has no clock (a round that changes rows is progress; see step 2)
        [int]$BudgetSeconds = 0
    )
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[' + $l + '] ' + $m) } }
    if ($BatchRows -le 0) { $BatchRows = Get-SICorrelationBatchRows }
    $issues = New-Object System.Collections.Generic.List[object]
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # ---- 1. READ + STAGE ----
    $step = 50000
    while ($true) {
        $r = @(& $Sql (Get-SICorrelationStageClearSql) @{ n = [string]$step } 'rows') | Select-Object -First 1
        if (-not $r -or [int](Get-SICorrValue $r 'Deleted') -lt $step) { break }
    }
    $ctr = @{ N = 0 }
    $stageState = @{ Rows = 0L; Statements = 0; MaxHeld = 0 }
    $flush = {
        param($R, $K)
        if ($R.Count -eq 0) { return }
        $null = & $Sql (Get-SICorrelationStageWriteSql) @{ r = (ConvertTo-SICorrJsonArray $R.ToArray() -Depth 3); k = (ConvertTo-SICorrJsonArray $K.ToArray() -Depth 3) } 'rows'
        $stageState.Rows += $R.Count; $stageState.Statements++
        if ($R.Count -gt $stageState.MaxHeld) { $stageState.MaxHeld = $R.Count }
        $R.Clear(); $K.Clear()
    }
    $chunkBytes = 2048 * 1024
    $onPart = {
        param($Engine, $Inputs)
        $rb = New-Object System.Collections.Generic.List[object]; $kb = New-Object System.Collections.Generic.List[object]; $bytes = 0
        foreach ($in in $Inputs) {
            $ctr.N++
            $n = $ctr.N
            $d = ConvertTo-SICorrelationStageDoc -In $in
            $rb.Add([ordered]@{ n = $n; e = [string]$Engine; d = $d }); $bytes += $d.Length + 40
            foreach ($k in (Get-SICorrelationInputKeys -In $in -Plan $Plan)) { $kb.Add([ordered]@{ n = $n; k = $k }); $bytes += $k.Length + 16 }
            if ($bytes -ge $chunkBytes) { & $flush $rb $kb; $bytes = 0 }
        }
        & $flush $rb $kb
    }
    $snap = & $ReadParts $onPart
    $times = [ordered]@{ read = [Math]::Round($sw.Elapsed.TotalSeconds, 1) }; $sw.Restart()

    # ---- 2. GROUP, in SQL ----
    $rounds = 0
    while ($true) {
        $rounds++
        $c = @(& $Sql (Get-SICorrelationGroupingStepSql -Step round) @{} 'rows') | Select-Object -First 1
        if ($null -eq $c) { throw 'correlation: the grouping statement answered no result' }
        $changedNow = [int](Get-SICorrValue $c 'Changed')
        if ($changedNow -eq 0) { break }
        # NO CLOCK (owner 2026-10-22: "remove those stupid breaks"): a round only ever lowers a label (WHERE x.m < i.Lbl), so a
        # round that changes rows is progress and the rounds always end; each one is said, so a slow tier shows where the time goes
        & $Log 'INFO' ("  grouping round {0}: {1:N0} row(s) relabelled ({2:N0} s so far)" -f $rounds, $changedNow, $sw.Elapsed.TotalSeconds)
    }
    $g = @(& $Sql (Get-SICorrelationGroupingStepSql -Step batches) @{ per = [string]$BatchRows } 'rows') | Select-Object -First 1
    if ($null -eq $g) { throw 'correlation: the batch statement answered no result' }
    $nRows = [long](Get-SICorrValue $g 'Rows'); $nBatches = [int](Get-SICorrValue $g 'Batches'); $nComp = [long](Get-SICorrValue $g 'Components')
    $times['group'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1); $sw.Restart()
    & $Log 'INFO' ("  staged {0:N0} row(s) in {1} statement(s); grouped into {2:N0} component(s) in {3} round(s) ({4} s); {5} batch(es) of about {6:N0} row(s)" -f $nRows, $stageState.Statements, $nComp, $rounds, $times['group'], $nBatches, $BatchRows)

    # ---- 3. PER BATCH: the pure core, the ledger, the map rows ----
    $rep = [ordered]@{ Rows = 0L; Objects = 0L; CrossEngine = 0L; LargestGroup = 0; Unseeded = 0; SingleSource = 0L; Deterministic = 0L; GraphInferred = 0L; Unexplained = 0L }
    $pub = [ordered]@{ Objects = 0L; Rows = 0L }
    $tot = [ordered]@{ MapRows = 0L; Posted = 0L; PostFailed = 0; Minted = 0L; Reused = 0L; Merged = 0L; Unkeyable = 0L; Split = 0L; WrongMergeSplit = 0L; Anchors = 0L; Superseded = 0L; Shrunk = 0L; WouldAnchors = 0L; MaxBatchRows = 0; Batches = 0 }
    $refused = New-Object System.Collections.Generic.List[object]; $pinned = 0L
    $unseededByEngine = @{}; $unseededRows = 0L; $unseededObjects = 0L
    $biggest = $null
    $splits = New-Object System.Collections.Generic.List[object]; $supers = New-Object System.Collections.Generic.List[object]
    $ledgerOk = ($null -ne $LedgerProvider); $ledgerWhole = $null; $ledgerETag = $null
    $blobDecisions = New-Object System.Collections.Generic.List[object]; $blobSuperseded = New-Object System.Collections.Generic.List[object]
    if ($ledgerOk -and [string]$LedgerProvider.Kind -ne 'sql') {
        try {
            $rd = Read-SIObjectLedger -Provider $LedgerProvider
            $ledgerWhole = $rd.Ledger; $ledgerETag = $rd.ETag
            & $Log 'INFO' ("  the identity ledger is a blob -- read whole for this run ({0:N0} anchor(s){1}); an identity ledger in SQL is read a batch at a time" -f @($ledgerWhole.Keys).Count, $(if (-not $rd.Existed) { ' -- FIRST RUN, every id will be minted now' } else { '' }))
        } catch {
            $ledgerOk = $false
            $issues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the identity ledger could not be read ({0}) -- the map was published with DERIVED, PROVISIONAL ids (SI_IdSource); a connector does not create CIs from them' -f $_.Exception.Message) })
        }
    }
    $ledgerFailed = $false
    for ($b = 1; $b -le $nBatches; $b++) {
        $rows = @(& $Sql (Get-SICorrelationBatchSql) @{ b = [string]$b } 'rows')
        if ($rows.Count -eq 0) { continue }
        $tot.Batches++
        if ($rows.Count -gt $tot.MaxBatchRows) { $tot.MaxBatchRows = $rows.Count }
        $inputs = New-Object 'object[]' $rows.Count
        for ($i = 0; $i -lt $rows.Count; $i++) { $inputs[$i] = ConvertFrom-SICorrelationStageDoc -Json ([string](Get-SICorrValue $rows[$i] 'Doc')) }
        $rows = $null
        $groups = @(Get-SICorrelationGroups -Inputs $inputs -Plan $Plan)
        $inputs = $null
        $br = Get-SICorrelationReport -Groups $groups
        foreach ($k in 'Rows', 'Objects', 'CrossEngine', 'Unseeded', 'SingleSource', 'Deterministic', 'GraphInferred', 'Unexplained') { $rep[$k] += [long]$br.$k }
        if ([int]$br.LargestGroup -gt $rep.LargestGroup) {
            $rep.LargestGroup = [int]$br.LargestGroup
            $bg = @($groups | Sort-Object { @($_.Members).Count } -Descending | Select-Object -First 1)[0]
            $biggest = [pscustomobject]@{ SICorrelationId = [string]$bg.SICorrelationId; JoinBasis = @($bg.JoinBasis); Engines = @($bg.Engines) }
        }
        if ($groups.Count -gt 0 -and $groups[0].PSObject.Properties['RefusedJoins']) { foreach ($rj in @($groups[0].RefusedJoins)) { $refused.Add($rj) } }
        $pinned += @($groups | Where-Object { $_.PinnedBy }).Count
        $unseeded = @($groups | Where-Object { -not $_.SICorrelationId })
        $keep = @($groups | Where-Object { $_.SICorrelationId })
        foreach ($u in $unseeded) {
            $unseededObjects++; $unseededRows += @($u.Members).Count
            $ek = (@($u.Engines) -join ','); if ($unseededByEngine.ContainsKey($ek)) { $unseededByEngine[$ek]++ } else { $unseededByEngine[$ek] = 1 }
        }
        $groups = $null
        $pr = Get-SICorrelationReport -Groups $keep
        $pub.Objects += [long]$pr.Objects; $pub.Rows += [long]$pr.Rows
        # the identity ledger, for this batch only
        $resolved = $null
        if ($ledgerOk -and -not $ledgerFailed -and $keep.Count -gt 0) {
            try {
                $ambig = $null
                if ($keep[0].PSObject.Properties['AmbiguousIdKeys']) { $ambig = $keep[0].AmbiguousIdKeys }
                if ([string]$LedgerProvider.Kind -eq 'sql') {
                    $lk = @(foreach ($gx in $keep) { foreach ($m in @($gx.Members)) { foreach ($id in (Get-SIMemberIdentifiers -Member $m)) { [pscustomobject]@{ Type = (Get-SICanonicalIdType -Type ([string]$id.Type)); Value = ([string]$id.Value).ToLowerInvariant() } } } })
                    $ledger = Get-SIObjectLedgerSubset -Connection $LedgerProvider.Connection -Keys $lk
                } else { $ledger = $ledgerWhole }
                $idy = Resolve-SIObjectIdentity -Groups $keep -Ledger $ledger -Now $CollectionTime -AmbiguousIdKeys $ambig
                $tot.Minted += [long]$idy.Minted; $tot.Reused += [long]$idy.Reused; $tot.Merged += [long]$idy.Merged; $tot.Unkeyable += [long]$idy.Unkeyable
                $tot.Split += [long]$idy.Split; $tot.WrongMergeSplit += [long]$idy.WrongMergeSplit; $tot.Shrunk += @($idy.ShrunkObjects).Count
                foreach ($s in @($idy.Splits)) { if ($splits.Count -lt 50) { $splits.Add($s) } }
                foreach ($s in @($idy.Superseded)) { if ($supers.Count -lt 50) { $supers.Add($s) } }
                $resolved = @{}
                foreach ($d in @($idy.Decisions)) { if ($null -ne $d -and $d.Group -and -not [string]::IsNullOrWhiteSpace([string]$d.CorrelationId)) { $resolved[[string]$d.Group.SICorrelationId] = [string]$d.CorrelationId } }
                if ($DryRun) {
                    foreach ($d in @($idy.Decisions)) { $tot.WouldAnchors += @($d.NewIdentifiers).Count }
                } elseif ([string]$LedgerProvider.Kind -eq 'sql') {
                    $lw = Save-SIObjectLedgerSet -Connection $LedgerProvider.Connection -Decisions @($idy.Decisions) -Superseded @($idy.Superseded) -Now $CollectionTime
                    $tot.Anchors += [long]$lw.AnchorsWritten; $tot.Superseded += [long]$lw.SupersededWritten
                } else {
                    foreach ($d in @($idy.Decisions)) { if ($d.CorrelationId) { $blobDecisions.Add([pscustomobject]@{ CorrelationId = $d.CorrelationId; Action = $d.Action; NewIdentifiers = @($d.NewIdentifiers) }) } }
                    foreach ($s in @($idy.Superseded)) { $blobSuperseded.Add($s) }
                }
                $idy = $null; $ledger = $null
            } catch {
                # DEGRADE LOUDLY, NEVER DIE -- and never end green: a WARNING of the run (the ids of this batch and every one
                # after it go out derived-provisional, which is true, and a connector does not create CIs from them)
                $ledgerFailed = $true; $resolved = $null
                $issues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the identity ledger was unavailable from batch {0} of {1} ({2}) -- those objects were published with DERIVED, PROVISIONAL ids (SI_IdSource); a connector does not create CIs from them' -f $b, $nBatches, $_.Exception.Message) })
            }
        }
        $map = @(ConvertTo-SIObjectMapRows -Groups $keep -RunId $RunId -CollectionTime $CollectionTime -ResolvedIds $resolved)
        $keep = $null
        $tot.MapRows += $map.Count
        if ($OnMapRows) { & $OnMapRows $map }
        if (-not $DryRun -and $map.Count -gt 0) {
            $sent = 0
            try {
                if ($Post) { $sent = [int](& $Post $map) } else { $sent = [int](Send-SIObjectMapRows -Rows $map) }
            } catch { & $Log 'WARN' ("  batch {0} of the map could not be posted to SI_ObjectMap_CL -- {1}" -f $b, $_.Exception.Message); $sent = 0 }
            $tot.Posted += $sent
            if ($sent -lt $map.Count) { $tot.PostFailed++ }
        }
        $map = $null
    }
    # a blob ledger: written once, with every batch's decisions (one document -- read and written whole)
    if ($ledgerOk -and -not $ledgerFailed -and -not $DryRun -and [string]$LedgerProvider.Kind -ne 'sql' -and $blobDecisions.Count -gt 0) {
        try {
            $lw = Write-SIObjectLedger -Provider $LedgerProvider -Decisions $blobDecisions.ToArray() -Superseded $blobSuperseded.ToArray() -IfMatchETag $ledgerETag -CurrentLedger $ledgerWhole
            $tot.Anchors += [long]$lw.AnchorsWritten; $tot.Superseded += [long]$lw.SupersededWritten
        } catch { $issues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the identity ledger could not be written ({0}) -- this run''s new ids are minted again on the next run' -f $_.Exception.Message) }) }
    }
    if ($tot.PostFailed -gt 0) { $issues.Add([pscustomobject]@{ Level = 'FAILED'; Text = ('{0} batch(es) of the correlation map did not reach SI_ObjectMap_CL -- the map in Log Analytics is short this run' -f $tot.PostFailed) }) }
    $times['correlate'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    [pscustomobject]@{
        Snapshot = $snap; StagedRows = $nRows; Rounds = $rounds; Components = $nComp; Batches = $nBatches; Report = [pscustomobject]$rep; Published = [pscustomobject]$pub
        Totals = [pscustomobject]$tot; Refused = $refused.ToArray(); PinnedApplied = $pinned; Biggest = $biggest
        UnseededObjects = $unseededObjects; UnseededRows = $unseededRows; UnseededByEngine = $unseededByEngine
        Splits = $splits.ToArray(); Superseded = $supers.ToArray(); LedgerUsed = ($ledgerOk -and -not $ledgerFailed); Issues = $issues.ToArray(); Times = $times
        MaxStagedChunk = $stageState.MaxHeld
    }
}
