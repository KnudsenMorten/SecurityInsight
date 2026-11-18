-- #1283 THE TASK REPORTS' STORED ROWS of collection @c (time @ct), written by the task build (SI-DataRemediationTask.ps1,
-- Get-SIRemediationTaskReportsSql) after its last range and BEFORE the collection is marked built, from the collection's FINAL
-- task rows -- the same rows and rules the task grid reads. The web app's proof tests run THIS file over their own task rows
-- (RemediationTaskReportsLocalSqlTests), so what is stored and what is proven are one text.
--   sidata.RemediationTaskRollup  one row per distinct task across assets, OPEN tasks only: assets (distinct CIs), Tier 0/1 assets,
--                                 findings (a sum: each finding is on one asset), DISTINCT CVEs over every link, highest severity
--                                 and risk rating, highest and summed weighted risk (each asset's highest: "assets x risk"),
--                                 the oldest first seen
--   sidata.RemediationTaskTrend   one row per tool ('' = every tool): open tasks and assets, the oldest open, and what this build
--                                 opened / closed as fixed / closed for another reason (#tr: Channel, Opened, ClosedFixed,
--                                 ClosedOther -- added up per range by the build)
-- A trend row of a collection no longer stored is removed. One code path at every size; no cap.
DELETE FROM sidata.RemediationTaskRollup WHERE CollectionId = @c;
INSERT sidata.RemediationTaskRollup (CollectionId, TaskKeyHash, TaskName, Kind, Channel, Product, Version, Assets, Tier01Assets, Findings, Cves,
                                     HighestSeverity, HighestRiskRating, MaxWeightedRisk, SumWeightedRisk, OldestFirstSeen)
SELECT @c, g.TaskKeyHash, g.TaskName, g.Kind, g.Channel, g.Product, g.Version, g.Assets, g.Tier01Assets, g.Findings, ISNULL(cv.Cves, 0),
       CASE g.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END,
       CASE g.RatingRank WHEN 4 THEN N'Critical' WHEN 3 THEN N'High' WHEN 2 THEN N'Moderate' WHEN 1 THEN N'Low' END,
       g.MaxWeightedRisk, g.SumWeightedRisk, g.OldestFirstSeen
FROM (SELECT t.TaskKeyHash, MAX(t.TaskName) AS TaskName, MAX(t.Kind) AS Kind, MAX(t.Channel) AS Channel,
             CASE WHEN MIN(ISNULL(t.Product, N'')) = MAX(ISNULL(t.Product, N'')) THEN MAX(t.Product) END AS Product,
             CASE WHEN MIN(ISNULL(t.Version, N'')) = MAX(ISNULL(t.Version, N'')) THEN MAX(t.Version) END AS Version,
             COUNT(DISTINCT t.OwnerKey) AS Assets, COUNT(DISTINCT CASE WHEN t.Tier IN (0, 1) THEN t.OwnerKey END) AS Tier01Assets, SUM(t.Findings) AS Findings,
             MAX(CASE t.HighestSeverity WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium' THEN 2 WHEN N'low' THEN 1 ELSE 0 END) AS SevRank,
             MAX(CASE LOWER(LTRIM(RTRIM(ISNULL(t.HighestRiskRating, N'')))) WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'moderate' THEN 2 WHEN N'medium' THEN 2 WHEN N'low' THEN 1 ELSE 0 END) AS RatingRank,
             MAX(t.MaxWeightedRisk) AS MaxWeightedRisk, SUM(t.MaxWeightedRisk) AS SumWeightedRisk, MIN(t.FirstSeen) AS OldestFirstSeen
      FROM sidata.RemediationTask AS t
      WHERE t.CollectionId = @c AND t.State = N'open' AND t.TaskKeyHash IS NOT NULL
      GROUP BY t.TaskKeyHash) AS g
LEFT JOIN (SELECT t.TaskKeyHash, COUNT(DISTINCT l.Cve) AS Cves
           FROM sidata.RemediationTask AS t
           JOIN sidata.RemediationTaskFinding AS l ON l.CollectionId = t.CollectionId AND l.TaskId = t.TaskId
           WHERE t.CollectionId = @c AND t.State = N'open' AND t.TaskKeyHash IS NOT NULL
           GROUP BY t.TaskKeyHash) AS cv ON cv.TaskKeyHash = g.TaskKeyHash;
DELETE r FROM sidata.RemediationTaskTrend AS r
WHERE r.CollectionId = @c OR NOT EXISTS (SELECT 1 FROM sidata.Collection AS x WHERE x.CollectionId = r.CollectionId);
INSERT sidata.RemediationTaskTrend (CollectionId, Channel, CollectionTime, OpenTasks, OpenAssets, Opened, ClosedFixed, ClosedOther, OldestOpen)
SELECT @c, ch.Channel, @ct, o.OpenTasks, o.OpenAssets, ISNULL(r.Opened, 0), ISNULL(r.ClosedFixed, 0), ISNULL(r.ClosedOther, 0), o.OldestOpen
FROM (SELECT N'' AS Channel UNION SELECT t.Channel FROM sidata.RemediationTask AS t WHERE t.CollectionId = @c AND t.State = N'open' AND t.Channel IS NOT NULL
      UNION SELECT x.Channel FROM #tr AS x) AS ch
CROSS APPLY (SELECT COUNT(*) AS OpenTasks, COUNT(DISTINCT t.OwnerKey) AS OpenAssets, MIN(t.FirstSeen) AS OldestOpen
             FROM sidata.RemediationTask AS t
             WHERE t.CollectionId = @c AND t.State = N'open' AND (ch.Channel = N'' OR t.Channel = ch.Channel)) AS o
OUTER APPLY (SELECT SUM(x.Opened) AS Opened, SUM(x.ClosedFixed) AS ClosedFixed, SUM(x.ClosedOther) AS ClosedOther
             FROM #tr AS x WHERE ch.Channel = N'' OR x.Channel = ch.Channel) AS r;
