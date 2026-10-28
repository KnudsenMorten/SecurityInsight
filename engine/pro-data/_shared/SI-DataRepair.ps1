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
    <# One batch: only a NULL ReportName, only from the row's own DetailJson -- a stored value is never changed. #>
    @"
UPDATE TOP (@Batch) f SET ReportName = $(Get-SIDataReportNameExpr)
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId AND f.ReportName IS NULL AND ISJSON(f.DetailJson) = 1 AND $(Get-SIDataReportNameExpr) IS NOT NULL;
SELECT @@ROWCOUNT;
"@
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
        $n = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataReportNameFillSql) -Params @{ CollectionId = $c.CollectionId } -BatchSize $BatchSize
        $written += $n
        [void](& $Invoke (Get-SIDataRederiveSql) @{ CollectionId = $c.CollectionId } 'scalar')
    }
    $res.Findings = $written
    & $Log 'OK' ("reports     : {0} finding(s) in {1} collection(s) got the report they came from" -f $written, $list.Count)
    $res
}
