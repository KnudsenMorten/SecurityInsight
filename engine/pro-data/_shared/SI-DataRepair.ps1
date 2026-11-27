#Requires -Version 5.1
<#
    SecurityInsight Pro -- every stored finding carries the report it came from (#296). Found 2026-10-05 on ring 1's Pro
    database: collection 1 (2026-10-03) had ReportName NULL on all 14,273 findings -- it was loaded before the data sync
    read the report from AssetDetectedInReportName. The value is in each finding's own DetailJson.
    New loads always set it (SI-DataModel.ps1, ConvertTo-SIDataFindingJson / Get-SIDataReportNameFromDetail); this repairs
    what is stored. GUARDED (only a NULL ReportName, only from the row's own data, only complete collections),
    IDEMPOTENT (a second run finds nothing), dry-run aware, and returned for the audit trail (datasync.reportname.backfill,
    written by Invoke-SIDataSync.ps1). PS 5.1 safe.
#>

# ---------------------------------------------------------------------------------------------------------------------
#  REPAIR: report names (#296)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataReportNameExpr {
    param([string]$Alias = 'f')
    "LEFT(COALESCE(NULLIF(LTRIM(RTRIM(JSON_VALUE($Alias.DetailJson, '$.AssetDetectedInReportName'))), N''), NULLIF(LTRIM(RTRIM(JSON_VALUE($Alias.DetailJson, '$.ReportName'))), N'')), 256)"
}

function Get-SIDataReportNameMissingSql {
    <# The complete collections holding findings whose ReportName is NULL but whose own DetailJson names the report. #>
    @"
SELECT f.CollectionId, CONVERT(nvarchar(10), CAST(c.CollectionTime AS date), 23) AS [Day], COUNT_BIG(*) AS Findings
FROM sidata.Finding AS f
JOIN sidata.Collection AS c ON c.CollectionId = f.CollectionId
WHERE c.Status = N'Complete' AND f.ReportName IS NULL AND ISJSON(f.DetailJson) = 1 AND $(Get-SIDataReportNameExpr) IS NOT NULL
GROUP BY f.CollectionId, CAST(c.CollectionTime AS date)
ORDER BY f.CollectionId;
"@
}

function Get-SIDataReportNameFillSql {
    <#
        One batch: only a NULL ReportName, only from the row's own DetailJson -- a stored value is never changed.
        #1435 ONE KEYED WALK over the collection: the batch is the next @Batch findings with a NULL report name after @After
        (their FindingId; 0 = from the first), each read ONCE over the whole walk -- before, every batch read the collection again
        from its first row and parsed again every row whose own data names no report (measured: 0.7 s at 150,000 findings,
        36 s at 1,000,000). Answers ONE value, '<changed>|<read>|<last FindingId>' (fewer read than @Batch = the walk is done).
    #>
    @"
SET NOCOUNT ON;
CREATE TABLE #w (FindingId BIGINT NOT NULL PRIMARY KEY);
INSERT #w (FindingId)
SELECT TOP (@Batch) f.FindingId FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId AND f.ReportName IS NULL AND f.FindingId > @After
ORDER BY f.FindingId;
-- the name is read only from a row that IS JSON (CASE), whatever order the optimizer evaluates the conditions in
UPDATE f SET ReportName = CASE WHEN ISJSON(f.DetailJson) = 1 THEN $(Get-SIDataReportNameExpr) END
-- one-statement-ok: one batch -- the keys in #w are TOP (@Batch) after @After
FROM sidata.Finding AS f
JOIN #w AS w ON w.FindingId = f.FindingId
WHERE f.CollectionId = @CollectionId AND f.ReportName IS NULL AND ISJSON(f.DetailJson) = 1 AND (CASE WHEN ISJSON(f.DetailJson) = 1 THEN $(Get-SIDataReportNameExpr) END) IS NOT NULL;
DECLARE @changed INT = @@ROWCOUNT;
SELECT CONCAT(@changed, N'|', (SELECT COUNT(*) FROM #w), N'|', (SELECT MAX(w.FindingId) FROM #w AS w));
"@
}

function Invoke-SIDataReportNameFillWalk {
    <#
        #1435 The report-name fill of ONE collection (Get-SIDataReportNameFillSql) as one keyed walk: every finding with a NULL
        report name read once, the batch sized from the last one's time (Get-SIDataNextSize; the database's own load paces it
        when SI-SqlPacing.ps1 is loaded). Exactly the rows the repeated "UPDATE TOP" filled before, with the same values: whether
        a row is filled depends only on that row. -BatchSize: the size to start with, and the size reached (for the next
        collection). Returns the rows filled.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [ref]$BatchSize, [long]$TargetMs = 5000)
    $size = [long]5000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
    $sql = Get-SIDataReportNameFillSql
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
    $after = 0L; $total = 0L
    while ($true) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace -and $pace.Shrink) { $size = [Math]::Max(100L, [long][Math]::Floor($size / 2)) } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $raw = [string](& $Invoke $sql @{ CollectionId = $CollectionId; Batch = $size; After = $after } 'scalar')
        $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
        $parts = $raw.Split([char]'|', 3)
        if ($parts.Count -lt 3) { throw ("the report-name fill answered '{0}', not '<changed>|<read>|<last FindingId>'" -f $raw) }
        $total += [long]$parts[0]
        if ([long]$parts[1] -lt $size -or $parts[2] -eq '') { break }
        $after = [long]$parts[2]
        $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 100
    }
    if ($BatchSize) { $BatchSize.Value = $size }
    $total
}

function Get-SIDataRederiveSql {
    <#
        A collection whose findings changed is derived again by the steps that follow: its views' data (DerivedAt), its
        services (ServicesDerivedAt), its departments (ResolvedVersion) -- and its counted twins become stale with them.
        Only the columns the database has.
    #>
    @'
UPDATE sidata.Collection SET DerivedAt = NULL WHERE CollectionId = @CollectionId;
IF COL_LENGTH('sidata.Collection', 'ServicesDerivedAt') IS NOT NULL EXEC sp_executesql N'UPDATE sidata.Collection SET ServicesDerivedAt = NULL WHERE CollectionId = @c', N'@c int', @c = @CollectionId;
IF COL_LENGTH('sidata.Collection', 'ResolvedVersion') IS NOT NULL EXEC sp_executesql N'UPDATE sidata.Collection SET ResolvedVersion = NULL WHERE CollectionId = @c', N'@c int', @c = @CollectionId;
SELECT 1;
'@
}

function Invoke-SIDataReportNameBackfill {
    <#
        #296: every stored finding with a NULL ReportName gets the report from its own DetailJson; its collection is derived
        again and its day re-aggregated. Guarded (NULL only, the row's own value), idempotent, -DryRun reports only.
        Returns @{ Collections = @(@{ CollectionId; Day; Findings }); Findings; Days }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [ref]$BatchSize, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $raw = & $Invoke (Get-SIDataReportNameMissingSql) @{} 'reader'
    $list = @(@($raw) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ CollectionId = [int]$_['CollectionId']; Day = [string]$_['Day']; Findings = [long]$_['Findings'] } })
    $res = [pscustomobject]@{ Collections = $list; Findings = [long](($list | Measure-Object -Property Findings -Sum).Sum); Days = @($list | ForEach-Object { $_.Day } | Select-Object -Unique) }
    if (-not $list.Count) { return $res }
    if ($DryRun) {
        & $Log 'INFO' ("reports     : {0} finding(s) in {1} collection(s) would get the report they came from (it is in their own data); nothing is written." -f $res.Findings, $list.Count)
        return $res
    }
    $written = 0L
    if (-not $BatchSize) { $size = [long]0; $BatchSize = [ref]$size }
    foreach ($c in $list) {
        $n = Invoke-SIDataReportNameFillWalk -Invoke $Invoke -CollectionId $c.CollectionId -BatchSize $BatchSize
        $written += $n
        [void](& $Invoke (Get-SIDataRederiveSql) @{ CollectionId = $c.CollectionId } 'scalar')
    }
    $res.Findings = $written
    & $Log 'OK' ("reports     : {0} finding(s) in {1} collection(s) got the report they came from" -f $written, $list.Count)
    $res
}
