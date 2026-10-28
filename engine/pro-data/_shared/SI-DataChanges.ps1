#Requires -Version 5.1
<#
    WHAT CHANGED AND THE WALL BOARD'S TOP TIER-0 ASSETS, PRE-COMPUTED (REQUIREMENTS #812, 2026-10-19 -- a large customer,
    1,117,524 finding rows per collection; owner rule "SI views: SQL-cached + indexed columns").

    (1) /Collection/Changes grouped EVERY finding of BOTH collections per request (CollectionViewSql.FindingChanges /
        FindingChangesExcluding / AssetChanges, and ChangeSummary twice more for the counts). The data sync now writes, once
        per complete Detailed collection B, its comparison with the PREVIOUS complete Detailed collection A -- the pair the
        page opens with (CollectionPageModel.Previous: the collection listed before it) -- into sidata.FindingChange
        (new / gone / changed findings; unchanged ones are counted, not listed), sidata.AssetChange (every CI), sidata.ChangeCount
        (the headline) and their counted twins (#264: exempted findings left out on both sides, the 'exempted' reason
        included), with sidata.ChangeState (the pair, when) -- ONE pass per side, ONE transaction. Exactly the per-request
        statements the page ran before (a real-SQL test holds them equal: tests\pester\SIv3-StoredChanges.Tests.ps1).
    (2) The wall board's top Tier-0 assets (ProDataSql.Tier0TopText: distinct Very High / High CVEs per asset, the total risk
        score, the asset's own name) grouped every finding of the collection per refresh. Now sidata.Tier0Asset + counted
        twin + sidata.Tier0AssetState, once per collection.
    EXISTING INSTALLS: the schema adds the tables (the updater applies sql\si-data-schema.sql); the next data sync fills every
    stored complete collection, newest first, within a time budget (the rest follow on the next runs). A pair is written again
    when either collection was derived again after it, or when the collection before B is another one (one retired). Until
    then the pages say the comparison / the list is being prepared -- they never compare the finding rows themselves. The
    retention removes a pair when either collection goes (Get-SIDataPurgeCollectionSql). Never fails the data sync.
#>

# the page's own change rule (CollectionViewSql.ChangeCase) -- a C# test holds the two texts equal
$script:SIDataChangeCase = @'
CASE WHEN ka.IssueKey IS NULL THEN N'new'
     WHEN kb.IssueKey IS NULL THEN N'gone'
     WHEN ISNULL(ka.Severity, N'') <> ISNULL(kb.Severity, N'') OR ISNULL(ka.RiskScore, -1) <> ISNULL(kb.RiskScore, -1)
       OR ISNULL(ka.Tier, 255) <> ISNULL(kb.Tier, 255) OR ISNULL(ka.RiskRating, N'') <> ISNULL(kb.RiskRating, N'') THEN N'changed'
     ELSE N'unchanged' END
'@

# the 'exempted' reason of the counted variant (CollectionViewSql.ExemptedInB, B = @CollectionId) -- a C# test holds them alike
$script:SIDataChangeExemptedInB = @"

            WHEN EXISTS (SELECT 1 FROM sidata.Finding AS ex_xb
                         WHERE ex_xb.CollectionId = @CollectionId AND ex_xb.ExemptionId IS NOT NULL
                           AND COALESCE(ex_xb.AssetKey, N'') = ka.AssetKey AND COALESCE(ex_xb.Cve, ex_xb.ConfigurationId, ex_xb.Title, N'') = ka.IssueKey
                           AND COALESCE(ex_xb.ReportName, N'') = ka.ReportName) THEN N'exempted'
"@

function Get-SIDataChangePrevSql {
    <#
        The previous complete Detailed collection of the collection aliased <Of> -- what the page compares a collection with
        by default: the collection listed before it (a collection that never got its view data written is left out while any
        collection carries the mark, as CollectionViewSql.CollectionsReady lists them; never a retired one).
    #>
    param([Parameter(Mandatory)][string]$Of, [string]$Columns = 'p.CollectionId')
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'p' }
    "SELECT TOP (1) $Columns FROM sidata.Collection AS p WHERE p.Status = 'Complete' AND p.Kind = 'Detailed' AND p.CollectionTime < $Of.CollectionTime AND (p.ViewsReadyAt IS NOT NULL OR NOT EXISTS (SELECT 1 FROM sidata.Collection AS r WHERE r.ViewsReadyAt IS NOT NULL))$live ORDER BY p.CollectionTime DESC"
}

function Get-SIDataChangesSchemaCheckSql {
    <# 1 when the database carries the change tables and the finding columns they are built from; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.FindingChange') IS NOT NULL AND OBJECT_ID('sidata.FindingChangeCounted') IS NOT NULL AND OBJECT_ID('sidata.AssetChange') IS NOT NULL AND OBJECT_ID('sidata.AssetChangeCounted') IS NOT NULL AND OBJECT_ID('sidata.ChangeCount') IS NOT NULL AND OBJECT_ID('sidata.ChangeCountCounted') IS NOT NULL AND OBJECT_ID('sidata.ChangeState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskRating') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ViewsReadyAt') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataChangesPendingSql {
    <#
        Complete Detailed collections (with the view data mark rule of the listing) that HAVE a previous collection and whose
        stored comparison is missing, is with another collection, or is older than either collection's derive. Newest first.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    $prev = Get-SIDataChangePrevSql -Of 'c' -Columns 'p.CollectionId AS PrevId, p.DerivedAt AS PrevDerivedAt'
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c OUTER APPLY ($prev) AS pv LEFT JOIN sidata.ChangeState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND pv.PrevId IS NOT NULL AND (c.ViewsReadyAt IS NOT NULL OR NOT EXISTS (SELECT 1 FROM sidata.Collection AS r WHERE r.ViewsReadyAt IS NOT NULL)) AND (s.CollectionId IS NULL OR s.PrevCollectionId <> pv.PrevId OR s.BuiltAt < c.DerivedAt OR s.BuiltAt < pv.PrevDerivedAt)$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataChangesSql {
    <#
        ONE collection B (@CollectionId) against its previous collection A: the finding comparison (listed rows: new / gone /
        changed), the CI comparison (every CI), the headline counts, both variants, and the state row -- replacing what B held,
        in ONE transaction. Answers the number of listed finding rows (every finding); -1 when B has no previous collection.
        Reads the narrow finding columns only (never DetailJson). Exactly CollectionViewSql.FindingChanges (every finding),
        FindingChangesExcluding over the counted rows (the counted variant), AssetChanges and ChangeSummary.
    #>
    $prev = Get-SIDataChangePrevSql -Of 'b'
    $tierA = $script:SIDataAssetTierWords.Replace('f.Tier', 'ka.Tier'); $tierB = $script:SIDataAssetTierWords.Replace('f.Tier', 'kb.Tier')
    $tierAa = $script:SIDataAssetTierWords.Replace('f.Tier', 'aa.Tier'); $tierAb = $script:SIDataAssetTierWords.Replace('f.Tier', 'ab.Tier')
    # 2026-10-20 (owner: "fix the things i reported"): the build that did not finish within 40 minutes at 1.1 M findings per
    # collection joined the two sides on three wide text keys (up to 1,400 characters) over temp tables without an index, and
    # asked the 'exempted' reason with a correlated probe of sidata.Finding per row. Now: a 32-byte key K per finding key
    # (HASHBYTES over the three keys, upper-cased and right-trimmed as the database's case-insensitive '=' compares them) with
    # the full keys kept as the residual of the join (the same match as before), clustered indexes on the temp tables (merge
    # joins), the newer collection's exempted keys and its CIs read ONCE into indexed sets. Same rows (the real-SQL test).
    $fcInsert = foreach ($c in 0, 1) {
        # the 'exempted' reason of the counted variant: $script:SIDataChangeExemptedInB, answered from #xb (B's exempted keys)
        $reason = if ($c -eq 1) { "`n            WHEN EXISTS (SELECT 1 FROM #xb AS xb WHERE xb.XK = ka.XK) THEN N'exempted'" } else { '' }
@"
INSERT #fc
SELECT $c, COALESCE(kb.IdKey, ka.IdKey) + N'|' + COALESCE(kb.IssueKey, ka.IssueKey) + N'|' + COALESCE(kb.ReportName, ka.ReportName),
       $($script:SIDataChangeCase.Trim()),
       CASE WHEN kb.IssueKey IS NOT NULL OR ka.IssueKey IS NULL THEN NULL$reason
            WHEN kba.AssetKey IS NOT NULL AND ka.AssetKey <> N'' THEN N'absent' ELSE NULL END,
       COALESCE(kb.AssetKey, ka.AssetKey), COALESCE(kb.AssetName, ka.AssetName), COALESCE(kb.IssueKey, ka.IssueKey), COALESCE(kb.Title, ka.Title), COALESCE(kb.ReportName, ka.ReportName),
       ka.Severity, kb.Severity, ka.RiskScore, kb.RiskScore, COALESCE(kb.RiskScore, 0) - COALESCE(ka.RiskScore, 0),
       CASE WHEN ka.IssueKey IS NULL THEN NULL ELSE $tierA END,
       CASE WHEN kb.IssueKey IS NULL THEN NULL ELSE $tierB END
FROM (SELECT * FROM #v WHERE Counted = $c AND Side = 0) AS ka
FULL OUTER JOIN (SELECT * FROM #v WHERE Counted = $c AND Side = 1) AS kb
  ON kb.K = ka.K AND kb.IdKey = ka.IdKey AND kb.IssueKey = ka.IssueKey AND kb.ReportName = ka.ReportName
LEFT JOIN #ba AS kba ON kba.Counted = $c AND kba.AssetKey = ka.AssetKey;
"@
    }
    $acInsert = foreach ($c in 0, 1) {
@"
INSERT #ac
SELECT $c, COALESCE(ab.AssetKey, aa.AssetKey), COALESCE(ab.AssetName, aa.AssetName),
       CASE WHEN aa.AssetKey IS NULL THEN N'new' WHEN ab.AssetKey IS NULL THEN N'gone'
            WHEN aa.Findings <> ab.Findings OR ISNULL(aa.TotalRisk, -1) <> ISNULL(ab.TotalRisk, -1) OR ISNULL(aa.Tier, 255) <> ISNULL(ab.Tier, 255) THEN N'changed'
            ELSE N'unchanged' END,
       aa.Findings, ab.Findings, aa.TotalRisk, ab.TotalRisk, COALESCE(ab.TotalRisk, 0) - COALESCE(aa.TotalRisk, 0),
       CASE WHEN aa.AssetKey IS NULL THEN NULL ELSE $tierAa END,
       CASE WHEN ab.AssetKey IS NULL THEN NULL ELSE $tierAb END
FROM (SELECT * FROM #w WHERE Counted = $c AND Side = 0) AS aa
FULL OUTER JOIN (SELECT * FROM #w WHERE Counted = $c AND Side = 1) AS ab ON ab.AssetKey = aa.AssetKey;
"@
    }
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @A INT = (SELECT pv.CollectionId FROM sidata.Collection AS b CROSS APPLY ({PREV}) AS pv WHERE b.CollectionId = @CollectionId);
IF @A IS NULL BEGIN SELECT -1; RETURN; END;
-- one row per finding key and side: every finding (the plain columns) and the findings without an exemption mark (c*)
CREATE TABLE #k (Side TINYINT NOT NULL, IdKey NVARCHAR(410) COLLATE DATABASE_DEFAULT NOT NULL, IssueKey NVARCHAR(1000) COLLATE DATABASE_DEFAULT NOT NULL,
                 ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL,
                 AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, AssetName NVARCHAR(400) NULL, Title NVARCHAR(1000) NULL, Severity NVARCHAR(30) NULL, RiskScore FLOAT NULL, Tier TINYINT NULL, RiskRating NVARCHAR(16) NULL,
                 cN INT NOT NULL, cAssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, cAssetName NVARCHAR(400) NULL, cTitle NVARCHAR(1000) NULL, cSeverity NVARCHAR(30) NULL, cRiskScore FLOAT NULL, cTier TINYINT NULL, cRiskRating NVARCHAR(16) NULL);
INSERT #k
SELECT s.Side, COALESCE(f.AssetKey, N'name:' + LOWER(COALESCE(f.AssetName, N''))), COALESCE(f.Cve, f.ConfigurationId, f.Title, N''), COALESCE(f.ReportName, N''),
       MAX(COALESCE(f.AssetKey, N'')), COALESCE(MAX(an.AssetName), MAX(f.AssetName)), MAX(f.Title), MAX(f.Severity), MAX(f.RiskScore), MIN(f.Tier), MAX(f.RiskRating),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END), MAX(CASE WHEN f.ExemptionId IS NULL THEN COALESCE(f.AssetKey, N'') END),
       COALESCE(MAX(CASE WHEN f.ExemptionId IS NULL THEN an.AssetName END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.AssetName END)),
       MAX(CASE WHEN f.ExemptionId IS NULL THEN f.Title END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.Severity END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScore END),
       MIN(CASE WHEN f.ExemptionId IS NULL THEN f.Tier END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.RiskRating END)
FROM sidata.Finding AS f
JOIN (VALUES (@A, CONVERT(tinyint, 0)), (@CollectionId, CONVERT(tinyint, 1))) AS s (C, Side) ON f.CollectionId = s.C
LEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey
GROUP BY s.Side, COALESCE(f.AssetKey, N'name:' + LOWER(COALESCE(f.AssetName, N''))), COALESCE(f.Cve, f.ConfigurationId, f.Title, N''), COALESCE(f.ReportName, N'');
CREATE TABLE #v (Counted BIT NOT NULL, Side TINYINT NOT NULL, K BINARY(32) NOT NULL, XK BINARY(32) NULL,
                 IdKey NVARCHAR(410) COLLATE DATABASE_DEFAULT NOT NULL, IssueKey NVARCHAR(1000) COLLATE DATABASE_DEFAULT NOT NULL,
                 ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, AssetName NVARCHAR(400) NULL, Title NVARCHAR(1000) NULL,
                 Severity NVARCHAR(30) NULL, RiskScore FLOAT NULL, Tier TINYINT NULL, RiskRating NVARCHAR(16) NULL);
-- K: the finding key (CI, issue, report) as the join compares it; XK (the counted rows): the key the 'exempted' reason looks up
INSERT #v SELECT 0, Side, HASHBYTES('SHA2_256', CONCAT(UPPER(RTRIM(IdKey)), NCHAR(31), UPPER(RTRIM(IssueKey)), NCHAR(31), UPPER(RTRIM(ReportName)))), NULL,
                 IdKey, IssueKey, ReportName, AssetKey, AssetName, Title, Severity, RiskScore, Tier, RiskRating FROM #k;
INSERT #v SELECT 1, Side, HASHBYTES('SHA2_256', CONCAT(UPPER(RTRIM(IdKey)), NCHAR(31), UPPER(RTRIM(IssueKey)), NCHAR(31), UPPER(RTRIM(ReportName)))),
                 HASHBYTES('SHA2_256', CONCAT(UPPER(RTRIM(cAssetKey)), NCHAR(31), UPPER(RTRIM(IssueKey)), NCHAR(31), UPPER(RTRIM(ReportName)))),
                 IdKey, IssueKey, ReportName, cAssetKey, cAssetName, cTitle, cSeverity, cRiskScore, cTier, cRiskRating FROM #k WHERE cN > 0;
DROP TABLE #k;
CREATE CLUSTERED INDEX cx ON #v (Counted, Side, K);
-- the newer collection's CIs per variant (a finding no longer reported on a CI still reported = 'absent')
SELECT Counted, AssetKey INTO #ba FROM #v WHERE Side = 1 AND AssetKey IS NOT NULL GROUP BY Counted, AssetKey;
CREATE CLUSTERED INDEX cx ON #ba (Counted, AssetKey);
-- the newer collection's EXEMPTED finding keys ($script:SIDataChangeExemptedInB: an exempted finding of B with the CI, issue
-- and report of the A row), read once
SELECT DISTINCT HASHBYTES('SHA2_256', CONCAT(UPPER(RTRIM(COALESCE(f.AssetKey, N''))), NCHAR(31), UPPER(RTRIM(COALESCE(f.Cve, f.ConfigurationId, f.Title, N''))), NCHAR(31), UPPER(RTRIM(COALESCE(f.ReportName, N''))))) AS XK
INTO #xb FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.ExemptionId IS NOT NULL;
CREATE CLUSTERED INDEX cx ON #xb (XK);
CREATE TABLE #fc (Counted BIT NOT NULL, ChangeKey NVARCHAR(1800) NOT NULL, Change NVARCHAR(16) NOT NULL, ChangeReason NVARCHAR(16) NULL, AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL,
                  Issue NVARCHAR(1000) NULL, Title NVARCHAR(1000) NULL, ReportName NVARCHAR(256) NULL, SeverityBefore NVARCHAR(30) NULL, SeverityAfter NVARCHAR(30) NULL,
                  RiskBefore FLOAT NULL, RiskAfter FLOAT NULL, RiskDelta FLOAT NULL, TierBefore NVARCHAR(12) NULL, TierAfter NVARCHAR(12) NULL);
{FCINSERTS}
-- one row per CI and side, both variants
CREATE TABLE #a (Side TINYINT NOT NULL, AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, AssetName NVARCHAR(400) NULL, Findings BIGINT NOT NULL, TotalRisk FLOAT NULL, Tier TINYINT NULL,
                 cFindings BIGINT NOT NULL, cAssetName NVARCHAR(400) NULL, cTotalRisk FLOAT NULL, cTier TINYINT NULL);
INSERT #a
SELECT s.Side, f.AssetKey, COALESCE(MAX(an.AssetName), MAX(f.AssetName)), COUNT_BIG(*), SUM(f.RiskScore), MIN(f.Tier),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END),
       COALESCE(MAX(CASE WHEN f.ExemptionId IS NULL THEN an.AssetName END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.AssetName END)),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScore END), MIN(CASE WHEN f.ExemptionId IS NULL THEN f.Tier END)
FROM sidata.Finding AS f
JOIN (VALUES (@A, CONVERT(tinyint, 0)), (@CollectionId, CONVERT(tinyint, 1))) AS s (C, Side) ON f.CollectionId = s.C
LEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey
WHERE f.AssetKey IS NOT NULL
GROUP BY s.Side, f.AssetKey;
CREATE TABLE #w (Counted BIT NOT NULL, Side TINYINT NOT NULL, AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, AssetName NVARCHAR(400) NULL, Findings BIGINT NOT NULL, TotalRisk FLOAT NULL, Tier TINYINT NULL);
INSERT #w SELECT 0, Side, AssetKey, AssetName, Findings, TotalRisk, Tier FROM #a;
INSERT #w SELECT 1, Side, AssetKey, cAssetName, cFindings, cTotalRisk, cTier FROM #a WHERE cFindings > 0;
CREATE CLUSTERED INDEX cx ON #w (Counted, Side, AssetKey);
CREATE TABLE #ac (Counted BIT NOT NULL, AssetKey NVARCHAR(400) NOT NULL, AssetName NVARCHAR(400) NULL, Change NVARCHAR(16) NOT NULL, FindingsBefore BIGINT NULL, FindingsAfter BIGINT NULL,
                  RiskBefore FLOAT NULL, RiskAfter FLOAT NULL, RiskDelta FLOAT NULL, TierBefore NVARCHAR(12) NULL, TierAfter NVARCHAR(12) NULL);
{ACINSERTS}
DECLARE @rows BIGINT = (SELECT COUNT_BIG(*) FROM #fc WHERE Counted = 0 AND Change <> N'unchanged');
DECLARE @assets INT = (SELECT COUNT(*) FROM #ac WHERE Counted = 0);
BEGIN TRAN;
DELETE FROM sidata.FindingChange WHERE CollectionId = @CollectionId;
INSERT sidata.FindingChange (CollectionId, PrevCollectionId, ChangeKey, Change, ChangeReason, AssetKey, AssetName, Issue, Title, ReportName, SeverityBefore, SeverityAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter)
SELECT @CollectionId, @A, ChangeKey, Change, ChangeReason, AssetKey, AssetName, Issue, Title, ReportName, SeverityBefore, SeverityAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter
FROM #fc WHERE Counted = 0 AND Change <> N'unchanged';
DELETE FROM sidata.FindingChangeCounted WHERE CollectionId = @CollectionId;
INSERT sidata.FindingChangeCounted (CollectionId, PrevCollectionId, ChangeKey, Change, ChangeReason, AssetKey, AssetName, Issue, Title, ReportName, SeverityBefore, SeverityAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter)
SELECT @CollectionId, @A, ChangeKey, Change, ChangeReason, AssetKey, AssetName, Issue, Title, ReportName, SeverityBefore, SeverityAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter
FROM #fc WHERE Counted = 1 AND Change <> N'unchanged';
DELETE FROM sidata.AssetChange WHERE CollectionId = @CollectionId;
INSERT sidata.AssetChange (CollectionId, PrevCollectionId, AssetKey, AssetName, Change, FindingsBefore, FindingsAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter)
SELECT @CollectionId, @A, AssetKey, AssetName, Change, FindingsBefore, FindingsAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter FROM #ac WHERE Counted = 0;
DELETE FROM sidata.AssetChangeCounted WHERE CollectionId = @CollectionId;
INSERT sidata.AssetChangeCounted (CollectionId, PrevCollectionId, AssetKey, AssetName, Change, FindingsBefore, FindingsAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter)
SELECT @CollectionId, @A, AssetKey, AssetName, Change, FindingsBefore, FindingsAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter FROM #ac WHERE Counted = 1;
DELETE FROM sidata.ChangeCount WHERE CollectionId = @CollectionId;
INSERT sidata.ChangeCount (CollectionId, PrevCollectionId, What, Change, N)
SELECT @CollectionId, @A, N'findings', Change, COUNT_BIG(*) FROM #fc WHERE Counted = 0 GROUP BY Change
UNION ALL SELECT @CollectionId, @A, N'assets', Change, COUNT_BIG(*) FROM #ac WHERE Counted = 0 GROUP BY Change;
DELETE FROM sidata.ChangeCountCounted WHERE CollectionId = @CollectionId;
INSERT sidata.ChangeCountCounted (CollectionId, PrevCollectionId, What, Change, N)
SELECT @CollectionId, @A, N'findings', Change, COUNT_BIG(*) FROM #fc WHERE Counted = 1 GROUP BY Change
UNION ALL SELECT @CollectionId, @A, N'assets', Change, COUNT_BIG(*) FROM #ac WHERE Counted = 1 GROUP BY Change;
DELETE FROM sidata.ChangeState WHERE CollectionId = @CollectionId;
INSERT sidata.ChangeState (CollectionId, PrevCollectionId, BuiltAt, FindingRows, AssetRows) VALUES (@CollectionId, @A, SYSUTCDATETIME(), @rows, @assets);
COMMIT;
SELECT @rows;
'@).Replace('{PREV}', $prev).Replace('{FCINSERTS}', ($fcInsert -join "`n")).Replace('{ACINSERTS}', ($acInsert -join "`n"))
}

function Invoke-SIDataChanges {
    <# .SYNOPSIS Writes the comparison of every complete collection with the one before it (missing or stale). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'changes' -Rows 'stored comparison' -Page 'What changed' `
        -SchemaSql (Get-SIDataChangesSchemaCheckSql) -PendingSql (Get-SIDataChangesPendingSql) -BuildSql (Get-SIDataChangesSql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE WALL BOARD'S TOP TIER-0 ASSETS
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataTier0SchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.Tier0Asset') IS NOT NULL AND OBJECT_ID('sidata.Tier0AssetCounted') IS NOT NULL AND OBJECT_ID('sidata.Tier0AssetState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataTier0PendingSql {
    <# Complete Detailed collections whose views' columns are derived and whose tier-0 rows are missing or older than the derive. Newest first. #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.Tier0AssetState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND (s.CollectionId IS NULL OR s.BuiltAt < c.DerivedAt)$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataTier0Sql {
    <#
        ONE collection: per asset with tier-0 findings, the distinct Very High and High CVEs, the total risk score, the asset's
        own name and kind -- every finding and the counted variant -- and the state row, ONE transaction. Exactly
        ProDataSql.Tier0TopText's aggregate (without its TOP: every tier-0 asset is stored, the board reads the first ten).
    #>
    $rank = $script:SIDataCveSeverityRank
    $t0 = "$($script:SIDataAssetTierWords) = N'0'"
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #t (AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, AssetName NVARCHAR(400) NULL, AssetKind NVARCHAR(16) NULL, VeryHigh INT NOT NULL, High INT NOT NULL, RiskTotal FLOAT NULL,
                 cN INT NOT NULL, cAssetName NVARCHAR(400) NULL, cAssetKind NVARCHAR(16) NULL, cVeryHigh INT NOT NULL, cHigh INT NOT NULL, cRiskTotal FLOAT NULL,
                 Lc NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL);
-- #855: each asset row carries its CI's lifecycle -- the wall board's top ten are the active CIs' (a retired tier-0 CI is never on it)
INSERT #t
SELECT f.AssetKey, COALESCE(MAX(a.AssetName), MAX(f.AssetName)), MAX(a.AssetKind),
       COUNT(DISTINCT CASE WHEN COALESCE(f.Cve, N'') <> N'' AND {RANK} = 0 THEN f.Cve END),
       COUNT(DISTINCT CASE WHEN COALESCE(f.Cve, N'') <> N'' AND {RANK} = 1 THEN f.Cve END),
       SUM(COALESCE(f.RiskScore, 0)),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END),
       COALESCE(MAX(CASE WHEN f.ExemptionId IS NULL THEN a.AssetName END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.AssetName END)), MAX(CASE WHEN f.ExemptionId IS NULL THEN a.AssetKind END),
       COUNT(DISTINCT CASE WHEN f.ExemptionId IS NULL AND COALESCE(f.Cve, N'') <> N'' AND {RANK} = 0 THEN f.Cve END),
       COUNT(DISTINCT CASE WHEN f.ExemptionId IS NULL AND COALESCE(f.Cve, N'') <> N'' AND {RANK} = 1 THEN f.Cve END),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN COALESCE(f.RiskScore, 0) END),
       MAX(f.CiLifecycle)
FROM sidata.Finding AS f
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
WHERE f.CollectionId = @CollectionId AND {T0}
GROUP BY f.AssetKey;
DECLARE @assets INT = (SELECT COUNT(*) FROM #t);
DECLARE @counted INT = (SELECT COUNT(*) FROM #t WHERE cN > 0);
BEGIN TRAN;
DELETE FROM sidata.Tier0Asset WHERE CollectionId = @CollectionId;
INSERT sidata.Tier0Asset (CollectionId, AssetKey, AssetName, AssetKind, VeryHigh, High, RiskTotal, CiLifecycle)
SELECT @CollectionId, AssetKey, AssetName, AssetKind, VeryHigh, High, RiskTotal, Lc FROM #t;
DELETE FROM sidata.Tier0AssetCounted WHERE CollectionId = @CollectionId;
INSERT sidata.Tier0AssetCounted (CollectionId, AssetKey, AssetName, AssetKind, VeryHigh, High, RiskTotal, CiLifecycle)
SELECT @CollectionId, AssetKey, cAssetName, cAssetKind, cVeryHigh, cHigh, cRiskTotal, Lc FROM #t WHERE cN > 0;
DELETE FROM sidata.Tier0AssetState WHERE CollectionId = @CollectionId;
INSERT sidata.Tier0AssetState (CollectionId, BuiltAt, Assets, CountedAssets) VALUES (@CollectionId, SYSUTCDATETIME(), @assets, @counted);
COMMIT;
SELECT @assets;
'@).Replace('{RANK}', $rank).Replace('{T0}', $t0)
}

function Invoke-SIDataTier0 {
    <# .SYNOPSIS Writes the wall board's tier-0 rows of every complete collection that has none (or older ones). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'tier0' -Rows 'tier-0 rows' -Page 'the wall board' `
        -SchemaSql (Get-SIDataTier0SchemaCheckSql) -PendingSql (Get-SIDataTier0PendingSql) -BuildSql (Get-SIDataTier0Sql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}
