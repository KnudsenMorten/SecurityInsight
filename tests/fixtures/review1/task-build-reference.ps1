#Requires -Version 7.0
<#
    THE REFERENCE: the remediation task build as it worked the whole collection out at once (commit becac84ea), kept verbatim
    under another name so the scale bench can prove that the build which works a range of CIs at a time writes EXACTLY the same
    task and link rows (SIv3-RemediationTaskScale, SI_BENCH_COMPARE=1). Uses the product's Get-SIRemediationTaskSigExpr and
    Get-SIRemediationTaskKeyApplySql (unchanged). Test-only: never loaded by the engine.
#>
function Get-SIRemediationTaskBuildSqlReference {
    <#
        THE BUILD of one collection (@CollectionId) over its base (@BaseId, '' = none -- a first build), the signatures and the
        bundled splits of build @BuildId: the tasks and their links worked out, the lifecycle applied, both tables of the
        collection replaced a range of CIs at a time (each range one short transaction; @FirstTake its first size, measured
        from there) and Collection.RemediationTasksAt stamped after the last range. @HoldOwners (JSON list): the owners whose
        evidence could not be read -- held as they are. Answers one row: Tasks, Open, Closed, NewlyClosed, Kept, Reopened,
        Links, Findings, NoTask, WriteRanges, Held. -Fields: the signature's fields (Get-SIRemediationTaskSigExpr).
    #>
    param([Parameter(Mandatory)][string[]]$Fields)
    $sig = Get-SIRemediationTaskSigExpr -Fields $Fields
    $combo = { param($o, $v, $p, $r) "HASHBYTES('SHA2_256', CONCAT($o, NCHAR(31), ISNULL($v, N''), NCHAR(31), $p, NCHAR(31), $r))" }
    $hashCols = "CONCAT(o.TaskName, NCHAR(31), o.Kind, NCHAR(31), ISNULL(o.Product, N''), NCHAR(31), ISNULL(o.Vendor, N''), NCHAR(31), ISNULL(o.Version, N''), NCHAR(31), ISNULL(o.Application, N''), NCHAR(31), ISNULL(o.ApplicationPaths, N''), NCHAR(31), o.Findings, NCHAR(31), o.Cves, NCHAR(31), ISNULL(o.HighestSeverity, N''), NCHAR(31), ISNULL(CONVERT(nvarchar(40), o.MaxRiskScore, 2), N''), NCHAR(31), ISNULL(CONVERT(nvarchar(4), o.Tier), N''), NCHAR(31), ISNULL(o.CiOwner, N''), NCHAR(31), ISNULL(o.CiDepartment, N''), NCHAR(31), ISNULL(o.CmdbId, N''), NCHAR(31), o.State, NCHAR(31), ISNULL(o.ClosedWhy, N''), NCHAR(31), ISNULL(CONVERT(nvarchar(30), o.ClosedAt, 126), N''), NCHAR(31), CONVERT(nvarchar(30), o.FirstSeen, 126), NCHAR(31), o.ReopenCount)"
    $text = @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c INT = CONVERT(int, @CollectionId), @b INT = TRY_CONVERT(int, NULLIF(@BaseId, N'')), @bid UNIQUEIDENTIFIER = CONVERT(uniqueidentifier, @BuildId),
        @keep INT = CONVERT(int, @KeepClosedDays);
DECLARE @ct DATETIME2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @c);
-- THE BUILD LOCK IS PROVEN before anything is written (and again before every range below): it is held by this build's own
-- session; a lock that could be granted now means that session is gone -- the build stops, nothing more is written
IF APPLOCK_TEST(N'public', N'si-remediation-task-build', N'Exclusive', N'Session') = 1 THROW 51277, N'the build lock was lost -- nothing is written this run', 1;
DECLARE @now DATETIME2(3) = SYSUTCDATETIME();
-- where the build's time goes (ms since the start, per phase -- returned as BuildPhases)
DECLARE @ph NVARCHAR(400) = N'', @pt DATETIME2(3) = SYSUTCDATETIME();
-- the reports of this collection that are COMPLETE (a run whose incompleteness is not one named report: none)
DECLARE @runOk BIT = ISNULL((SELECT CASE WHEN NULLIF(x.RaPartialReason, N'') IS NULL OR x.RaPartialScope = N'reports' THEN 1 ELSE 0 END FROM sidata.Collection AS x WHERE x.CollectionId = @c), 0);
CREATE TABLE #rep (ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
IF @runOk = 1 AND OBJECT_ID('sidata.RaReportStatus') IS NOT NULL
    INSERT #rep (ReportName) SELECT DISTINCT s.ReportName FROM sidata.RaReportStatus AS s WHERE s.CollectionTime = @ct AND s.Grain = N'Detailed' AND s.State = N'Complete';
-- the findings of the collection: owner, key, signature; Own = this run's own row in a complete report
CREATE TABLE #f (FindingId BIGINT NOT NULL PRIMARY KEY, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL,
                 SigHash BINARY(32) NOT NULL, AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL, CmdbName NVARCHAR(400) NULL, Cve NVARCHAR(100) NULL,
                 Title NVARCHAR(1000) NULL, SevRank TINYINT NOT NULL, RiskScore FLOAT NULL, Weighted FLOAT NULL, Tier TINYINT NULL, SecurityDomain NVARCHAR(128) NULL,
                 DepartmentId INT NULL, Own BIT NOT NULL, Exempt BIT NOT NULL);
INSERT #f
SELECT f.FindingId, LEFT(o.OwnerKey, 450), k.FKey, {SIG}, f.AssetKey, f.AssetName, COALESCE(NULLIF(f.ContextCmdbName, N''), f.CmdbName),
       CASE WHEN k.Typ = N'cve' THEN LEFT(UPPER(k.FKey), 100) END, LEFT(f.Title, 1000),
       CASE LOWER(LTRIM(RTRIM(f.Severity))) WHEN N'very high' THEN 4 WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium-high' THEN 2
            WHEN N'medium' THEN 2 WHEN N'moderate' THEN 2 WHEN N'low' THEN 1 ELSE 0 END,
       f.RiskScore, ISNULL(f.RiskScoreWeighted, f.RiskScore), f.Tier, f.SecurityDomain, f.DepartmentId,
       CASE WHEN f.CarriedFrom IS NULL AND EXISTS (SELECT 1 FROM #rep AS r WHERE r.ReportName = f.ReportName) THEN 1 ELSE 0 END,
       CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END
FROM sidata.Finding AS f
{APPLY}
WHERE f.CollectionId = @c AND f.RaFindingKey IS NOT NULL AND sp.P > 1;
CREATE INDEX IX_f ON #f (OwnerKey, FindingKey) INCLUDE (Own, Exempt);
SET @ph = @ph + N'findings=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';'; SET @pt = SYSUTCDATETIME();
-- the owners whose software evidence could not be read this run (a page of the evidence read failed): UNKNOWN -- held
CREATE TABLE #hold (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
INSERT #hold (OwnerKey) SELECT DISTINCT LEFT(j.[value], 450) FROM OPENJSON(ISNULL(NULLIF(@HoldOwners, N''), N'[]')) AS j WHERE j.[value] IS NOT NULL;
-- the owners (this collection's and the base's): the CI's lifecycle -- active | retired | hold (not seen, frozen, gone, or its
-- evidence not read this run)
CREATE TABLE #o (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Lc NVARCHAR(16) NOT NULL, CiId NVARCHAR(64) NULL,
                 CiOwner NVARCHAR(400) NULL, CiDept NVARCHAR(400) NULL, CmdbId NVARCHAR(256) NULL);
INSERT #o
SELECT x.OwnerKey,
       CASE WHEN EXISTS (SELECT 1 FROM #hold AS h WHERE h.OwnerKey = x.OwnerKey) THEN N'hold'
            WHEN x.OwnerKey LIKE N'asset:%' THEN N'active' WHEN c.CiId IS NULL THEN N'hold' WHEN LOWER(LTRIM(RTRIM(c.Lifecycle))) = N'retired' THEN N'retired'
            WHEN c.Lifecycle IS NULL OR LOWER(LTRIM(RTRIM(c.Lifecycle))) = N'active' THEN N'active' ELSE N'hold' END,
       c.CiId, c.Owner, c.Department, c.CmdbId
FROM (SELECT OwnerKey FROM #f UNION SELECT OwnerKey FROM sidata.RemediationTask WHERE CollectionId = @b) AS x
LEFT JOIN sidata.Ci AS c ON x.OwnerKey NOT LIKE N'asset:%' AND c.CiId = LEFT(x.OwnerKey, 64);
-- the base's tasks
SELECT p.* INTO #p FROM sidata.RemediationTask AS p WHERE p.CollectionId = @b;
CREATE UNIQUE CLUSTERED INDEX CX_p ON #p (TaskId);
-- the base's tasks by CI: the units below ask, per finding, whether the base has that copy as an open bundled task -- a seek
-- per CI, never a scan of every base task per finding (the second build of a collection took 1,278 s instead of 9 at 150,000)
CREATE INDEX IX_p_owner ON #p (OwnerKey, Kind, State) INCLUDE (Product, Version);
-- the units of every finding of an ACTIVE CI: its signature's tasks; a software unit whose evidence was read: its bundled tasks,
-- and its own task only when a copy is not bundled. A name equal to the asset's own name is never a task. A software unit whose
-- evidence has no disk path this run (none read, or a registry row only) while the base has its copy as a BUNDLED task gets no
-- plain task: where that copy is is not known this run (the bundled task is kept as it was) -- never a guessed second task.
CREATE TABLE #l (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, TaskKey NVARCHAR(1000) COLLATE DATABASE_DEFAULT NOT NULL, TaskName NVARCHAR(1000) NOT NULL,
                 Kind NVARCHAR(32) NOT NULL, Product NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Vendor NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL,
                 Version NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Application NVARCHAR(400) NULL, Paths NVARCHAR(MAX) NULL, EvidenceAt DATETIME2(3) NULL,
                 FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, FindingId BIGINT NOT NULL);
INSERT #l
SELECT f.OwnerKey, s.TaskKey, s.TaskName, s.Kind, s.Product, s.Vendor, s.Version, NULL, NULL, NULL, f.FindingKey, f.FindingId
FROM #f AS f
JOIN #o AS o ON o.OwnerKey = f.OwnerKey AND o.Lc = N'active'
JOIN sidata.RemediationTaskSig AS s ON s.BuildId = @bid AND s.SigHash = f.SigHash
OUTER APPLY (SELECT TOP (1) x.KeepPlain FROM sidata.RemediationTaskSplit AS x
             WHERE s.Kind = N'software-upgrade' AND x.BuildId = @bid AND x.ComboHash = {COMBO_F}
             ORDER BY x.KeepPlain DESC) AS kp
OUTER APPLY (SELECT MAX(CASE WHEN x.TaskKey IS NULL AND ISNULL(x.Paths, N'') <> N'' THEN 1 ELSE 0 END) AS HasDisk FROM sidata.RemediationTaskSplit AS x
             WHERE s.Kind = N'software-upgrade' AND x.BuildId = @bid AND x.ComboHash = {COMBO_F}) AS dk
WHERE f.Exempt = 0 AND (kp.KeepPlain IS NULL OR kp.KeepPlain = 1)
  AND NOT (s.Kind = N'software-upgrade' AND ISNULL(dk.HasDisk, 0) = 0
           AND EXISTS (SELECT 1 FROM #p AS hb WHERE hb.OwnerKey = f.OwnerKey AND hb.Kind = N'bundled-upgrade' AND hb.State = N'open'
                                                AND ISNULL(hb.Product, N'') = s.Product AND ISNULL(hb.Version, N'') = s.Version))
  AND LOWER(LTRIM(RTRIM(s.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.AssetName, N''))))
  AND LOWER(LTRIM(RTRIM(s.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.CmdbName, N''))));
INSERT #l
SELECT f.OwnerKey, x.TaskKey, x.TaskName, N'bundled-upgrade', s.Product, s.Vendor, s.Version, x.Application, x.Paths, x.EvidenceAt, f.FindingKey, f.FindingId
FROM #f AS f
JOIN #o AS o ON o.OwnerKey = f.OwnerKey AND o.Lc = N'active'
JOIN sidata.RemediationTaskSig AS s ON s.BuildId = @bid AND s.SigHash = f.SigHash AND s.Kind = N'software-upgrade'
JOIN sidata.RemediationTaskSplit AS x ON x.BuildId = @bid AND x.ComboHash = {COMBO_F} AND x.TaskKey IS NOT NULL
WHERE f.Exempt = 0 AND LOWER(LTRIM(RTRIM(x.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.AssetName, N''))))
  AND LOWER(LTRIM(RTRIM(x.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.CmdbName, N''))));
CREATE INDEX IX_l ON #l (OwnerKey, FindingKey) INCLUDE (Product, Version);
SET @ph = @ph + N'owners+units=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';'; SET @pt = SYSUTCDATETIME();
-- the tasks worked out from this collection
CREATE TABLE #t (TaskId BINARY(32) NOT NULL PRIMARY KEY, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, TaskKey NVARCHAR(1000) COLLATE DATABASE_DEFAULT NOT NULL,
                 TaskName NVARCHAR(1000) NOT NULL, Kind NVARCHAR(32) NOT NULL, Product NVARCHAR(400) NULL, Vendor NVARCHAR(400) NULL, Version NVARCHAR(400) NULL,
                 Application NVARCHAR(400) NULL, Paths NVARCHAR(MAX) NULL, EvidenceAt DATETIME2(3) NULL, Findings INT NOT NULL, Cves INT NOT NULL, SevRank TINYINT NULL,
                 MaxRisk FLOAT NULL, MaxWeighted FLOAT NULL, Tier TINYINT NULL, Doms INT NOT NULL, Dom NVARCHAR(128) NULL, Depts INT NOT NULL, Dept INT NULL,
                 AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL);
INSERT #t
SELECT HASHBYTES('SHA2_256', CONCAT(g.OwnerKey, N'|', g.TaskKey)), g.OwnerKey, g.TaskKey, g.TaskName, g.Kind, NULLIF(g.Product, N''), NULLIF(g.Vendor, N''),
       NULLIF(g.Version, N''), g.Application, g.Paths, g.EvidenceAt, g.Findings, g.Cves, g.SevRank, g.MaxRisk, g.MaxWeighted, g.Tier,
       g.Doms, CASE WHEN g.Doms = 1 THEN g.Dom END, g.Depts, CASE WHEN g.Depts = 1 THEN g.Dept END, g.AssetKey, g.AssetName
FROM (SELECT l.OwnerKey, l.TaskKey, MAX(l.TaskName) AS TaskName, MAX(l.Kind) AS Kind, MAX(l.Product) AS Product, MAX(l.Vendor) AS Vendor,
             CASE WHEN MIN(l.Version) = MAX(l.Version) THEN MAX(l.Version) ELSE N'' END AS Version, MAX(l.Application) AS Application,
             MAX(l.Paths) AS Paths, MAX(l.EvidenceAt) AS EvidenceAt, COUNT(DISTINCT l.FindingKey) AS Findings, COUNT(DISTINCT f.Cve) AS Cves,
             MAX(f.SevRank) AS SevRank, MAX(f.RiskScore) AS MaxRisk, MAX(f.Weighted) AS MaxWeighted, MIN(f.Tier) AS Tier,
             COUNT(DISTINCT ISNULL(f.SecurityDomain, N'')) AS Doms, MAX(f.SecurityDomain) AS Dom,
             COUNT(DISTINCT ISNULL(f.DepartmentId, -1)) AS Depts, MAX(f.DepartmentId) AS Dept, MAX(f.AssetKey) AS AssetKey, MAX(f.AssetName) AS AssetName
      FROM #l AS l JOIN #f AS f ON f.FindingId = l.FindingId
      GROUP BY l.OwnerKey, l.TaskKey) AS g;
-- the links of those tasks (one per task and finding key)
CREATE TABLE #k (TaskId BINARY(32) NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL,
                 FindingId BIGINT NOT NULL, Cve NVARCHAR(100) NULL, Title NVARCHAR(1000) NULL, SevRank TINYINT NULL, RiskScore FLOAT NULL, Version NVARCHAR(400) NULL,
                 PRIMARY KEY (TaskId, FindingKey));
INSERT #k
SELECT t.TaskId, l.FindingKey, MAX(l.OwnerKey), MIN(l.FindingId), MAX(f.Cve), MAX(f.Title), MAX(f.SevRank), MAX(f.RiskScore), NULLIF(MAX(l.Version), N'')
FROM #l AS l JOIN #t AS t ON t.OwnerKey = l.OwnerKey AND t.TaskKey = l.TaskKey JOIN #f AS f ON f.FindingId = l.FindingId
GROUP BY t.TaskId, l.FindingKey;
-- THE BASE'S OPEN TASKS NOT WORKED OUT NOW (on an active CI): what each of their findings is now. "fixed" ONLY ON POSITIVE
-- EVIDENCE that the finding is gone -- never because a task with the same key did not come out this run:
--   fixed    the finding is gone and the finding lifecycle closed it as remediated (complete runs); or -- a BUNDLED task --
--            the finding is still there, the software evidence of that copy on this CI was READ this run WITH its paths on
--            disk, and none of the task's paths holds that library version any more (the application no longer bundles it)
--   retired / report   closed as asset retired / report changed by the lifecycle
--   changed  the finding is still there (in a complete report) but no task with this key comes out now: its version moved or
--            went blank, the grouping rule now names another task or none, the name is now the asset's own; a bundled copy
--            whose paths still hold the library under another application's name
--   unknown  anything else -- kept as it was: absent but not closed, seen only in an incomplete report or carried; a bundled
--            copy whose evidence was not read, or was read without a path on disk (a registry row only); a task written with a
SET @ph = @ph + N'tasks+links=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';'; SET @pt = SYSUTCDATETIME();
CREATE TABLE #ls (TaskId BINARY(32) NOT NULL, St NVARCHAR(16) NOT NULL);
INSERT #ls
SELECT p.TaskId,
       CASE WHEN fx.AnyRow = 1 AND fx.Live = 0 THEN N'exempted'
            WHEN fx.OwnLive = 1 THEN
                 CASE WHEN p.Kind <> N'bundled-upgrade' THEN N'changed'
                      WHEN ISNULL(p.Version, N'') = N'' OR ISNULL(p.ApplicationPaths, N'') = N'' THEN N'unknown'
                      WHEN ev.HasDisk = 1 AND pa.Held = 0 THEN N'fixed'
                      WHEN ev.HasDisk = 1 THEN N'changed'
                      WHEN ev.Found = 1 THEN N'unknown'
                      -- not read this run, and the finding still names that version: not known
                      WHEN EXISTS (SELECT 1 FROM #f AS f2 JOIN sidata.RemediationTaskSig AS s2 ON s2.BuildId = @bid AND s2.SigHash = f2.SigHash
                                   WHERE f2.OwnerKey = p.OwnerKey AND f2.FindingKey = pl.FindingKey AND s2.Kind = N'software-upgrade'
                                     AND s2.Product = ISNULL(p.Product, N'') AND s2.Version = p.Version) THEN N'unknown'
                      ELSE N'changed' END
            WHEN fx.AnyRow = 1 THEN N'unknown'
            WHEN st.State = N'closed' AND st.CloseReason = N'remediated' THEN N'fixed'
            WHEN st.State = N'closed' AND st.CloseReason = N'asset_retired' THEN N'retired'
            WHEN st.State = N'closed' AND st.CloseReason = N'report changed' THEN N'report'
            WHEN st.State = N'closed' AND st.CloseReason = N'rekeyed' THEN N'changed'
            ELSE N'unknown' END
FROM #p AS p
JOIN #o AS o ON o.OwnerKey = p.OwnerKey AND o.Lc = N'active'
JOIN sidata.RemediationTaskFinding AS pl ON pl.CollectionId = @b AND pl.TaskId = p.TaskId
LEFT JOIN sidata.CiFindingState AS st ON st.OwnerKey = p.OwnerKey AND st.FindingKey = pl.FindingKey
OUTER APPLY (SELECT MAX(1) AS AnyRow, MAX(CASE WHEN f.Exempt = 0 THEN 1 ELSE 0 END) AS Live, MAX(CASE WHEN f.Own = 1 AND f.Exempt = 0 THEN 1 ELSE 0 END) AS OwnLive
             FROM #f AS f WHERE f.OwnerKey = p.OwnerKey AND f.FindingKey = pl.FindingKey) AS fx
-- the copy's evidence this run (bundled): read at all (Found), read with its paths on disk (HasDisk)
OUTER APPLY (SELECT MAX(1) AS Found, MAX(CASE WHEN ISNULL(x.Paths, N'') <> N'' THEN 1 ELSE 0 END) AS HasDisk FROM sidata.RemediationTaskSplit AS x
             WHERE p.Kind = N'bundled-upgrade' AND x.BuildId = @bid AND x.ComboHash = {COMBO_P} AND x.TaskKey IS NULL) AS ev
-- the task's own paths against them: one still holds it (Held) -- both sides the full paths as the evidence gives them
OUTER APPLY (SELECT MAX(z.Held) AS Held
             FROM (SELECT CASE WHEN EXISTS (SELECT 1 FROM sidata.RemediationTaskSplit AS x WHERE x.BuildId = @bid AND x.ComboHash = {COMBO_P} AND x.TaskKey IS NULL
                                                  AND CHARINDEX(N';' + LTRIM(RTRIM(s.[value])) + N';', N';' + ISNULL(x.Paths, N'') + N';') > 0) THEN 1 ELSE 0 END AS Held
                   FROM STRING_SPLIT(CASE WHEN p.Kind = N'bundled-upgrade' THEN ISNULL(p.ApplicationPaths, N'') ELSE N'' END, N';') AS s
                   WHERE LTRIM(RTRIM(s.[value])) <> N'') AS z) AS pa
WHERE p.State = N'open' AND NOT EXISTS (SELECT 1 FROM #t AS t WHERE t.TaskId = p.TaskId);
CREATE TABLE #d (TaskId BINARY(32) NOT NULL PRIMARY KEY, Unknown INT NOT NULL, Fixed INT NOT NULL, Retired INT NOT NULL, Report INT NOT NULL, Exempted INT NOT NULL, N INT NOT NULL);
INSERT #d SELECT TaskId, SUM(CASE WHEN St = N'unknown' THEN 1 ELSE 0 END), SUM(CASE WHEN St = N'fixed' THEN 1 ELSE 0 END),
                 SUM(CASE WHEN St = N'retired' THEN 1 ELSE 0 END), SUM(CASE WHEN St = N'report' THEN 1 ELSE 0 END), SUM(CASE WHEN St = N'exempted' THEN 1 ELSE 0 END), COUNT(*)
FROM #ls GROUP BY TaskId;
-- THE COLLECTION'S TASKS: the ones worked out now (open; reopened when the base had them closed) + the base's tasks not worked
-- out now (closed by the rules above, or carried as they were) + the base's closed tasks within the retention
SET @ph = @ph + N'base-states=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';'; SET @pt = SYSUTCDATETIME();
SELECT TOP (0) CAST(NULL AS NVARCHAR(16)) AS Src, p.* INTO #out FROM #p AS p;
INSERT #out (Src, CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Vendor, Version, Application, ApplicationPaths, EvidenceAt,
             Findings, Cves, HighestSeverity, MaxRiskScore, MaxWeightedRisk, Tier, SecurityDomain, DepartmentId, Departments, CiOwner, CiDepartment, CmdbId,
             FirstSeen, LastSeen, State, ClosedAt, ClosedWhy, ReopenCount, InThisCollection, RowHash, ChangedAt, SentInScope)
SELECT CASE WHEN p.TaskId IS NULL THEN N'new' WHEN p.State = N'closed' THEN N'reopened' ELSE N'seen' END,
       @c, t.TaskId, t.OwnerKey, o.CiId, t.AssetKey, t.AssetName, t.TaskKey, t.TaskName, t.Kind, t.Product, t.Vendor, t.Version, t.Application, t.Paths, t.EvidenceAt,
       t.Findings, t.Cves, CASE t.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END,
       t.MaxRisk, t.MaxWeighted, t.Tier, t.Dom, ad.DepartmentId, CASE WHEN ad.DepartmentId IS NULL THEN 0 ELSE 1 END, o.CiOwner, o.CiDept, o.CmdbId,
       ISNULL(p.FirstSeen, @ct), @ct, N'open', NULL, NULL, ISNULL(p.ReopenCount, 0) + CASE WHEN p.State = N'closed' THEN 1 ELSE 0 END, 1, 0x00, @now, p.SentInScope
FROM #t AS t
JOIN #o AS o ON o.OwnerKey = t.OwnerKey
LEFT JOIN #p AS p ON p.TaskId = t.TaskId
-- a task belongs to ONE CI: the CI's own department (sidata.Asset.DepartmentId -- the department its views scope by)
LEFT JOIN sidata.Asset AS ad ON ad.AssetKey = t.AssetKey;
INSERT #out (Src, CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Vendor, Version, Application, ApplicationPaths, EvidenceAt,
             Findings, Cves, HighestSeverity, MaxRiskScore, MaxWeightedRisk, Tier, SecurityDomain, DepartmentId, Departments, CiOwner, CiDepartment, CmdbId,
             FirstSeen, LastSeen, State, ClosedAt, ClosedWhy, ReopenCount, InThisCollection, RowHash, ChangedAt, SentInScope)
SELECT z.Src, @c, p.TaskId, p.OwnerKey, p.CiId, p.AssetKey, p.AssetName, p.TaskKey, p.TaskName, p.Kind, p.Product, p.Vendor, p.Version, p.Application, p.ApplicationPaths, p.EvidenceAt,
       p.Findings, p.Cves, p.HighestSeverity, p.MaxRiskScore, p.MaxWeightedRisk, p.Tier, p.SecurityDomain, p.DepartmentId, p.Departments, p.CiOwner, p.CiDepartment, p.CmdbId,
       p.FirstSeen, p.LastSeen, CASE WHEN z.Why IS NULL THEN p.State ELSE N'closed' END, CASE WHEN z.Why IS NULL THEN p.ClosedAt ELSE @ct END,
       ISNULL(z.Why, p.ClosedWhy), p.ReopenCount, 0, p.RowHash, p.ChangedAt, p.SentInScope
FROM #p AS p
LEFT JOIN #o AS o ON o.OwnerKey = p.OwnerKey
LEFT JOIN #d AS d ON d.TaskId = p.TaskId
CROSS APPLY (SELECT CASE WHEN p.State = N'closed' THEN N'carried-closed'
                         WHEN o.Lc = N'retired' THEN N'closed'
                         WHEN o.Lc = N'active' AND d.TaskId IS NOT NULL AND d.Unknown = 0 AND d.N > 0 THEN N'closed'
                         ELSE N'kept' END AS Src,
                    CASE WHEN p.State = N'closed' THEN NULL
                         WHEN o.Lc = N'retired' THEN N'asset retired'
                         WHEN o.Lc = N'active' AND d.TaskId IS NOT NULL AND d.Unknown = 0 AND d.N > 0 THEN
                              CASE WHEN d.Fixed = d.N THEN N'fixed' WHEN d.Fixed + d.Exempted = d.N THEN N'exempted' WHEN d.Retired > 0 THEN N'asset retired' WHEN d.Report > 0 THEN N'report changed' ELSE N'task changed' END
                         END AS Why) AS z
WHERE NOT EXISTS (SELECT 1 FROM #t AS t WHERE t.TaskId = p.TaskId)
  AND (p.State = N'open' OR p.ClosedAt >= DATEADD(day, -@keep, @ct));
UPDATE o SET RowHash = HASHBYTES('SHA2_256', {HASHCOLS}) FROM #out AS o;
UPDATE o SET ChangedAt = CASE WHEN p.TaskId IS NOT NULL AND p.RowHash = o.RowHash THEN p.ChangedAt ELSE @now END
FROM #out AS o LEFT JOIN #p AS p ON p.TaskId = o.TaskId;
DECLARE @noTask INT = (SELECT COUNT(*) FROM (SELECT DISTINCT f.OwnerKey, f.FindingKey FROM #f AS f JOIN #o AS o ON o.OwnerKey = f.OwnerKey AND o.Lc = N'active'
                                               WHERE f.Exempt = 0 AND NOT EXISTS (SELECT 1 FROM #l AS l WHERE l.OwnerKey = f.OwnerKey AND l.FindingKey = f.FindingKey)) AS q);
-- THE WRITE, A RANGE OF OWNERS AT A TIME: each range (the CIs in key order) is its own short transaction -- its old task and link
-- rows deleted and its new ones inserted together -- so the locks stay at row / page level and the log is bounded, and every CI
-- shows either its old set or its new one, never half. The range is sized by measuring (about two seconds of work), never a
-- fixed limit. The collection is marked built (RemediationTasksAt -- what the outputs and the hand-off read) only after the
-- last range; a write that stops part-way leaves it unmarked and the next run writes it again, range by range.
SET @ph = @ph + N'out+hash=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';'; SET @pt = SYSUTCDATETIME();
CREATE TABLE #w (Rn INT IDENTITY(1, 1) NOT NULL PRIMARY KEY, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL UNIQUE);
INSERT #w (OwnerKey) SELECT x.OwnerKey FROM (SELECT OwnerKey FROM #out UNION SELECT OwnerKey FROM sidata.RemediationTask WHERE CollectionId = @c
                                             UNION SELECT OwnerKey FROM sidata.RemediationTaskFinding WHERE CollectionId = @c) AS x ORDER BY x.OwnerKey;
CREATE TABLE #wk (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
DECLARE @wn INT = (SELECT COUNT(*) FROM #w), @lo INT = 1, @take INT = ISNULL(TRY_CONVERT(int, NULLIF(@FirstTake, N'')), 0), @t0 DATETIME2(3), @ms INT, @ranges INT = 0;
IF @take < 1 SET @take = 256;
WHILE @lo <= @wn
BEGIN
    IF APPLOCK_TEST(N'public', N'si-remediation-task-build', N'Exclusive', N'Session') = 1 THROW 51277, N'the build lock was lost part-way -- the collection is not marked built; the next run writes it again', 1;
    TRUNCATE TABLE #wk;
    INSERT #wk (OwnerKey) SELECT OwnerKey FROM #w WHERE Rn >= @lo AND Rn < @lo + @take;
    SET @t0 = SYSUTCDATETIME();
    BEGIN TRAN;
    DELETE l FROM sidata.RemediationTaskFinding AS l JOIN #wk AS w ON w.OwnerKey = l.OwnerKey WHERE l.CollectionId = @c;
    DELETE t FROM sidata.RemediationTask AS t JOIN #wk AS w ON w.OwnerKey = t.OwnerKey WHERE t.CollectionId = @c;
    INSERT sidata.RemediationTask (CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Vendor, Version, Application, ApplicationPaths,
                                   EvidenceAt, Findings, Cves, HighestSeverity, MaxRiskScore, MaxWeightedRisk, Tier, SecurityDomain, DepartmentId, Departments, CiOwner,
                                   CiDepartment, CmdbId, FirstSeen, LastSeen, State, ClosedAt, ClosedWhy, ReopenCount, InThisCollection, RowHash, ChangedAt, SentInScope)
    SELECT o.CollectionId, o.TaskId, o.OwnerKey, o.CiId, o.AssetKey, o.AssetName, o.TaskKey, o.TaskName, o.Kind, o.Product, o.Vendor, o.Version, o.Application, o.ApplicationPaths,
           o.EvidenceAt, o.Findings, o.Cves, o.HighestSeverity, o.MaxRiskScore, o.MaxWeightedRisk, o.Tier, o.SecurityDomain, o.DepartmentId, o.Departments, o.CiOwner,
           o.CiDepartment, o.CmdbId, o.FirstSeen, o.LastSeen, o.State, o.ClosedAt, o.ClosedWhy, o.ReopenCount, o.InThisCollection, o.RowHash, o.ChangedAt, o.SentInScope
    FROM #out AS o JOIN #wk AS w ON w.OwnerKey = o.OwnerKey;
    INSERT sidata.RemediationTaskFinding (CollectionId, TaskId, FindingKey, OwnerKey, FindingId, Cve, Title, Severity, RiskScore, Version, InThisCollection, SentInScope)
    SELECT @c, k.TaskId, k.FindingKey, k.OwnerKey, k.FindingId, k.Cve, k.Title,
           CASE k.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END, k.RiskScore, k.Version, 1, bl.SentInScope
    FROM #k AS k JOIN #out AS o ON o.TaskId = k.TaskId JOIN #wk AS w ON w.OwnerKey = o.OwnerKey
    LEFT JOIN sidata.RemediationTaskFinding AS bl ON bl.CollectionId = @b AND bl.TaskId = k.TaskId AND bl.FindingKey = k.FindingKey;
    INSERT sidata.RemediationTaskFinding (CollectionId, TaskId, FindingKey, OwnerKey, FindingId, Cve, Title, Severity, RiskScore, Version, InThisCollection, SentInScope)
    SELECT @c, pl.TaskId, pl.FindingKey, pl.OwnerKey, NULL, pl.Cve, pl.Title, pl.Severity, pl.RiskScore, pl.Version, 0, pl.SentInScope
    FROM sidata.RemediationTaskFinding AS pl
    JOIN #out AS o ON o.TaskId = pl.TaskId AND o.InThisCollection = 0
    JOIN #wk AS w ON w.OwnerKey = o.OwnerKey
    WHERE pl.CollectionId = @b;
    COMMIT;
    SET @ranges = @ranges + 1;
    SET @lo = @lo + @take;
    SET @ms = DATEDIFF(millisecond, @t0, SYSUTCDATETIME());
    SET @take = CASE WHEN @ms < 1000 AND @take < @wn THEN @take * 2 WHEN @ms > 4000 AND @take > 1 THEN @take / 2 ELSE @take END;
END
IF APPLOCK_TEST(N'public', N'si-remediation-task-build', N'Exclusive', N'Session') = 1 THROW 51277, N'the build lock was lost before the collection was marked -- the next run writes it again', 1;
UPDATE sidata.Collection SET RemediationTasksAt = SYSUTCDATETIME() WHERE CollectionId = @c;
SET @ph = @ph + N'write=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';'; SET @pt = SYSUTCDATETIME();
SELECT (SELECT COUNT(*) FROM #out) AS Tasks, (SELECT COUNT(*) FROM #out WHERE State = N'open') AS [Open],
       (SELECT COUNT(*) FROM #out WHERE State = N'closed') AS Closed, (SELECT COUNT(*) FROM #out WHERE Src = N'closed') AS NewlyClosed,
       (SELECT COUNT(*) FROM #out WHERE Src = N'kept') AS Kept, (SELECT COUNT(*) FROM #out WHERE Src = N'reopened') AS Reopened,
       (SELECT COUNT(*) FROM sidata.RemediationTaskFinding WHERE CollectionId = @c) AS Links,
       (SELECT COUNT(*) FROM (SELECT DISTINCT OwnerKey, FindingKey FROM #f) AS q) AS Findings, @noTask AS NoTask,
       (SELECT COUNT(*) FROM #f WHERE Own = 1) AS OwnRows, (SELECT COUNT(*) FROM #rep) AS CompleteReports,
       (SELECT STRING_AGG(CONVERT(nvarchar(max), St), N',') FROM #ls) AS LinkStates, @ranges AS WriteRanges, (SELECT COUNT(*) FROM #hold) AS Held, @ph AS BuildPhases;
'@
    $text = $text.Replace('{SIG}', $sig).Replace('{APPLY}', (Get-SIRemediationTaskKeyApplySql)).Replace('{HASHCOLS}', $hashCols)
    $text = $text.Replace('{COMBO_F}', (& $combo 'f.OwnerKey' 's.Vendor' 's.Product' 's.Version'))
    $text.Replace('{COMBO_P}', (& $combo 'p.OwnerKey' 'p.Vendor' "ISNULL(p.Product, N'')" 'p.Version'))
}

