#Requires -Version 5.1
<#
    THE FINDINGS BROWSER AND THE PIVOTS, PRE-COMPUTED PER COLLECTION (REQUIREMENTS #812, 2026-10-19 -- owner rule "SI views:
    SQL-cached + indexed columns"; a large customer, 1,117,524 finding rows). The findings browser counted and sorted every
    finding of the collection on each open, its tier x severity x domain pivot grouped them with a distinct count of assets,
    and the Weighted risk score's Pivot tab grouped them again per request and per filter choice list. The data sync now
    writes, ONCE per complete Detailed collection, in one statement (Invoke-SIDataFindingPivots):
      * Finding.ImportanceRank -- the browser's default order as a number (IX_Finding_Importance pages it by a seek);
      * sidata.FindingPivotCell (+ Counted twin) -- the browser's pivot cells, over every report and per report;
      * sidata.PivotCell -- the Weighted risk pivot's cube (CI x tier x domain x report x severity x department x service x
        exempted), from which every pivot over those fields is a GROUP BY of thousands of rows;
      * sidata.FindingPivotState -- when (the pages read none of it before the state row is written).
    Exactly the values the pages computed per request before (a real-SQL test holds them equal: SIv3-StoredPivots.Tests.ps1).
    EXISTING INSTALLS: the schema adds the column, the index and the tables (the updater applies sql\si-data-schema.sql); the
    next data sync fills every stored complete collection, newest first, within a time budget. Never fails the data sync.
#>

# the web app's own expressions -- the C# tests compare them with ProDataSql.TierExpr("f.Tier") and
# ProDataSql.Sorts[FindingSorts.Importance], so the stored order and cells are the browser's own
$script:SIDataPivotTierWords = "CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N'')) BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N''))) ELSE N'Unclassified' END"
$script:SIDataImportanceOrder = "CASE WHEN CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N'')) BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N''))) ELSE N'Unclassified' END = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N'')) BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N''))) ELSE N'Unclassified' END) END, f.RiskScore DESC, f.AssetName, f.Title"

function Get-SIDataFindingPivotsSchemaCheckSql {
    <# 1 when the database carries the tables, the rank column and the finding columns they read; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.FindingPivotCell') IS NOT NULL AND OBJECT_ID('sidata.FindingPivotCellCounted') IS NOT NULL AND OBJECT_ID('sidata.PivotCell') IS NOT NULL AND OBJECT_ID('sidata.FindingPivotState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ImportanceRank') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskScoreWeighted') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'DepartmentId') IS NOT NULL AND OBJECT_ID('sidata.ServiceMember') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataFindingPivotsPendingSql {
    <#
        Complete Detailed collections whose views' columns are derived (the weighted score comes from there) and whose rows
        are missing -- new loads and, once, every collection stored before the tables existed -- or older than the derive (an
        asset merge or a repair derived the collection again; the services are derived with it). Newest first. Never retired.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.FindingPivotState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND (s.CollectionId IS NULL OR s.BuiltAt < c.DerivedAt)$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataFindingPivotsSql {
    <#
        ONE collection (@CollectionId). (1) the importance rank of every finding, set in batches of finding ids (short
        statements, the clustered order: a page reads it only once the state row below exists); (2) the browser's pivot cells
        and the Weighted pivot's cube, both variants, with the state row in ONE transaction. Answers the number of cells.
        Reads the narrow finding columns only (never DetailJson); every finding counted -- no cap, no sample.
    #>
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #r (FindingId BIGINT NOT NULL PRIMARY KEY, Rn BIGINT NOT NULL);
INSERT #r (FindingId, Rn)
SELECT f.FindingId, ROW_NUMBER() OVER (ORDER BY {ORDER}, f.FindingId)
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId;
DECLARE @lo BIGINT = (SELECT ISNULL(MIN(FindingId), 0) - 1 FROM #r), @top BIGINT = (SELECT ISNULL(MAX(FindingId), 0) FROM #r);
WHILE @lo < @top
BEGIN
    UPDATE f SET ImportanceRank = r.Rn
    FROM sidata.Finding AS f JOIN #r AS r ON r.FindingId = f.FindingId
    WHERE f.CollectionId = @CollectionId AND f.FindingId > @lo AND f.FindingId <= @lo + 100000;
    SET @lo = @lo + 100000;
END;
CREATE TABLE #c (Counted BIT NOT NULL, ByReport BIT NOT NULL, ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, Tier NVARCHAR(12) COLLATE DATABASE_DEFAULT NOT NULL,
                 Severity NVARCHAR(30) COLLATE DATABASE_DEFAULT NOT NULL, SecurityDomain NVARCHAR(128) COLLATE DATABASE_DEFAULT NOT NULL, Findings BIGINT NOT NULL, Assets BIGINT NOT NULL,
                 Lc NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL);
-- #855: every cell carries its findings' CI lifecycle as a key (an asset has one lifecycle, so the distinct assets add up)
INSERT #c (Counted, ByReport, ReportName, Tier, Severity, SecurityDomain, Findings, Assets, Lc)
SELECT v.Counted, CONVERT(bit, 0), NULL, {TIER}, COALESCE(f.Severity, N''), COALESCE(f.SecurityDomain, N''), COUNT_BIG(*), COUNT_BIG(DISTINCT f.AssetKey), f.CiLifecycle
FROM sidata.Finding AS f CROSS APPLY (VALUES (CONVERT(bit, 0)), (CONVERT(bit, 1))) AS v (Counted)
WHERE f.CollectionId = @CollectionId AND (v.Counted = 0 OR f.ExemptionId IS NULL)
GROUP BY v.Counted, f.CiLifecycle, {TIER}, COALESCE(f.Severity, N''), COALESCE(f.SecurityDomain, N'');
INSERT #c (Counted, ByReport, ReportName, Tier, Severity, SecurityDomain, Findings, Assets, Lc)
SELECT v.Counted, CONVERT(bit, 1), f.ReportName, {TIER}, COALESCE(f.Severity, N''), COALESCE(f.SecurityDomain, N''), COUNT_BIG(*), COUNT_BIG(DISTINCT f.AssetKey), f.CiLifecycle
FROM sidata.Finding AS f CROSS APPLY (VALUES (CONVERT(bit, 0)), (CONVERT(bit, 1))) AS v (Counted)
WHERE f.CollectionId = @CollectionId AND f.ReportName IS NOT NULL AND (v.Counted = 0 OR f.ExemptionId IS NULL)
GROUP BY v.Counted, f.CiLifecycle, f.ReportName, {TIER}, COALESCE(f.Severity, N''), COALESCE(f.SecurityDomain, N'');
CREATE TABLE #m (Exempted BIT NOT NULL, ServicePrimary BIT NOT NULL, ServiceKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, ServiceName NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL,
                 AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, AssetName NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, AssetKind NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL, Tier TINYINT NULL,
                 SecurityDomain NVARCHAR(128) COLLATE DATABASE_DEFAULT NULL, ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, Severity NVARCHAR(30) COLLATE DATABASE_DEFAULT NULL, DepartmentId INT NULL,
                 Findings BIGINT NOT NULL, RiskSum FLOAT NULL, WeightedSum FLOAT NULL, WeightedMax FLOAT NULL, WeightedN BIGINT NOT NULL, Lc NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL);
WITH ps AS (
    SELECT sm.AssetKey, MIN(sm.ServiceKey) AS FirstService FROM sidata.ServiceMember AS sm WHERE sm.CollectionId = @CollectionId GROUP BY sm.AssetKey
)
INSERT #m (Exempted, ServicePrimary, ServiceKey, ServiceName, AssetKey, AssetName, AssetKind, Tier, SecurityDomain, ReportName, Severity, DepartmentId, Findings, RiskSum, WeightedSum, WeightedMax, WeightedN, Lc)
SELECT CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END, CASE WHEN sm.ServiceKey IS NULL OR sm.ServiceKey = ps.FirstService THEN 1 ELSE 0 END,
       sm.ServiceKey, sm.ServiceName, f.AssetKey, f.AssetName, a.AssetKind, f.Tier, f.SecurityDomain, f.ReportName, f.Severity, f.DepartmentId,
       COUNT_BIG(*), SUM(f.RiskScore), SUM(f.RiskScoreWeighted), MAX(f.RiskScoreWeighted), COUNT_BIG(f.RiskScoreWeighted), f.CiLifecycle
FROM sidata.Finding AS f
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
LEFT JOIN sidata.ServiceMember AS sm ON sm.CollectionId = f.CollectionId AND sm.AssetKey = f.AssetKey
LEFT JOIN ps ON ps.AssetKey = f.AssetKey
WHERE f.CollectionId = @CollectionId
GROUP BY CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END, CASE WHEN sm.ServiceKey IS NULL OR sm.ServiceKey = ps.FirstService THEN 1 ELSE 0 END,
         sm.ServiceKey, sm.ServiceName, f.AssetKey, f.AssetName, a.AssetKind, f.Tier, f.SecurityDomain, f.ReportName, f.Severity, f.DepartmentId, f.CiLifecycle;
DECLARE @cells INT = (SELECT COUNT(*) FROM #c WHERE Counted = 0);
DECLARE @cube INT = (SELECT COUNT(*) FROM #m);
DECLARE @findings BIGINT = (SELECT ISNULL(SUM(Findings), 0) FROM #c WHERE Counted = 0 AND ByReport = 0);
DECLARE @counted BIGINT = (SELECT ISNULL(SUM(Findings), 0) FROM #c WHERE Counted = 1 AND ByReport = 0);
BEGIN TRAN;
DELETE FROM sidata.FindingPivotCell WHERE CollectionId = @CollectionId;
INSERT sidata.FindingPivotCell (CollectionId, ByReport, ReportName, Tier, Severity, SecurityDomain, Findings, Assets, CiLifecycle)
SELECT @CollectionId, c.ByReport, c.ReportName, c.Tier, c.Severity, c.SecurityDomain, c.Findings, c.Assets, c.Lc FROM #c AS c WHERE c.Counted = 0;
DELETE FROM sidata.FindingPivotCellCounted WHERE CollectionId = @CollectionId;
INSERT sidata.FindingPivotCellCounted (CollectionId, ByReport, ReportName, Tier, Severity, SecurityDomain, Findings, Assets, CiLifecycle)
SELECT @CollectionId, c.ByReport, c.ReportName, c.Tier, c.Severity, c.SecurityDomain, c.Findings, c.Assets, c.Lc FROM #c AS c WHERE c.Counted = 1;
DELETE FROM sidata.PivotCell WHERE CollectionId = @CollectionId;
INSERT sidata.PivotCell (CollectionId, Exempted, ServicePrimary, ServiceKey, ServiceName, AssetKey, AssetName, AssetKind, Tier, SecurityDomain, ReportName, Severity, DepartmentId, Findings, RiskSum, WeightedSum, WeightedMax, WeightedN, CiLifecycle)
SELECT @CollectionId, m.Exempted, m.ServicePrimary, m.ServiceKey, m.ServiceName, m.AssetKey, m.AssetName, m.AssetKind, m.Tier, m.SecurityDomain, m.ReportName, m.Severity, m.DepartmentId, m.Findings, m.RiskSum, m.WeightedSum, m.WeightedMax, m.WeightedN, m.Lc FROM #m AS m;
DELETE FROM sidata.FindingPivotState WHERE CollectionId = @CollectionId;
INSERT sidata.FindingPivotState (CollectionId, BuiltAt, Findings, CountedFindings, Cells, CubeRows) VALUES (@CollectionId, SYSUTCDATETIME(), @findings, @counted, @cells, @cube);
COMMIT;
SELECT @cells;
'@).Replace('{ORDER}', $script:SIDataImportanceOrder).Replace('{TIER}', $script:SIDataPivotTierWords)
}

function Invoke-SIDataFindingPivots {
    <# .SYNOPSIS Writes the browser's rank and cells and the pivot cube of every complete collection that has none (or older ones). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'pivots' -Rows 'findings order and pivot cells' -Page 'Findings and the Weighted risk score pivot' `
        -SchemaSql (Get-SIDataFindingPivotsSchemaCheckSql) -PendingSql (Get-SIDataFindingPivotsPendingSql) -BuildSql (Get-SIDataFindingPivotsSql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}
