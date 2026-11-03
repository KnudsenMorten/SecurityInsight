-- #1052 READ ONLY. What the fix will do to an install's CIs, BEFORE it is released: run against the install's SI database
-- (sidata) with read rights only. Nothing here writes. Each block answers one question of the data-quality proof.

-- 1. THE WRONG DEVICE CIs: Exposure Graph DEVICE records that are AD computer accounts (AD ids, no device id at all) --
--    the records Test-SIRecordAdAccountAsDevice calls gone -- and the CIs they build.
;WITH acc AS (
    SELECT r.RecordKey, r.CiId FROM sidata.CiRecord r
    WHERE r.Provider = N'eg' AND r.RecordType = N'device'
      AND EXISTS (SELECT 1 FROM sidata.RecordIdentifier i WHERE i.RecordKey = r.RecordKey AND i.IdType IN (N'ActiveDirectoryObjectGuid', N'SecurityIdentifier'))
      AND NOT EXISTS (SELECT 1 FROM sidata.RecordIdentifier i WHERE i.RecordKey = r.RecordKey AND i.IdType IN (N'MdeDeviceId', N'AadDeviceId', N'IntuneDeviceId', N'AzureResourceId', N'AzureVmId'))),
cis AS (SELECT DISTINCT a.CiId FROM acc a WHERE a.CiId IS NOT NULL),
ci AS (
    -- the CI retires at once only when EVERY record it has is such an account; a CI with any other record stays
    -- (an OUTER APPLY flag, never an aggregate over a subquery -- Azure SQL refuses that)
    SELECT s.CiId, CASE WHEN o.Other IS NULL THEN 1 ELSE 0 END AS RetiresAtOnce
    FROM cis s
    OUTER APPLY (SELECT TOP (1) 1 AS Other FROM sidata.CiRecord r2 WHERE r2.CiId = s.CiId AND NOT EXISTS (SELECT 1 FROM acc a2 WHERE a2.RecordKey = r2.RecordKey)) o),
n AS (SELECT COUNT(*) AS AccountDeviceRecords FROM acc)
SELECT MAX(n.AccountDeviceRecords) AS AccountDeviceRecords,
       COUNT(c.CiId) AS CisWithSuchRecords,
       SUM(ci.RetiresAtOnce) AS CisThatRetireAtOnce,
       SUM(CASE WHEN ci.RetiresAtOnce = 1 AND ISNULL(c.Lifecycle, N'') <> N'retired' THEN 1 ELSE 0 END) AS ActiveNowThatRetire,
       SUM(CASE WHEN ci.RetiresAtOnce = 0 THEN 1 ELSE 0 END) AS MixedCisThatStay,
       SUM(CASE WHEN ci.RetiresAtOnce = 1 AND c.Tier = 0 THEN 1 ELSE 0 END) AS Tier0Duplicates,
       SUM(CASE WHEN ci.RetiresAtOnce = 1 THEN ISNULL(c.OpenFindings, 0) ELSE 0 END) AS OpenFindingsOnRetiring,
       SUM(CASE WHEN ci.RetiresAtOnce = 1 AND ISNULL(c.CmdbId, N'') <> N'' THEN 1 ELSE 0 END) AS RetiringWithCmdbId
FROM n LEFT JOIN ci ON 1 = 1 LEFT JOIN sidata.Ci c ON c.CiId = ci.CiId;

-- 1b. the same, one row per retiring CI (name, tier, findings) -- the list the owner reads; check that NONE carries a
--     Defender, Azure, Entra or Intune link (that would be a real machine and the fix would NOT retire it)
;WITH acc AS (
    SELECT r.RecordKey, r.CiId FROM sidata.CiRecord r
    WHERE r.Provider = N'eg' AND r.RecordType = N'device'
      AND EXISTS (SELECT 1 FROM sidata.RecordIdentifier i WHERE i.RecordKey = r.RecordKey AND i.IdType IN (N'ActiveDirectoryObjectGuid', N'SecurityIdentifier'))
      AND NOT EXISTS (SELECT 1 FROM sidata.RecordIdentifier i WHERE i.RecordKey = r.RecordKey AND i.IdType IN (N'MdeDeviceId', N'AadDeviceId', N'IntuneDeviceId', N'AzureResourceId', N'AzureVmId')))
SELECT c.CiId, c.Name, c.Class, c.AssetType, c.Tier, c.TierReason, c.Lifecycle, c.OpenFindings, c.CmdbId,
       (SELECT COUNT(*) FROM sidata.CiLink l WHERE l.CiId = c.CiId AND l.Provider IN (N'mde', N'azure', N'mdc', N'entra', N'intune')) AS HardLinks
FROM sidata.Ci c
WHERE c.CiId IN (SELECT CiId FROM acc)
  AND NOT EXISTS (SELECT 1 FROM sidata.CiRecord o WHERE o.CiId = c.CiId AND o.RecordKey NOT IN (SELECT RecordKey FROM acc))
ORDER BY c.Tier, c.Name;

-- 2. THE DOMAIN CONTROLLERS TODAY: CIs whose document says domain_controller, with their class and findings -- after the
--    fix the duplicates retire and the real machines (a Defender link) carry the role (compare with the account check, 4)
SELECT c.CiId, c.Name, c.Class, c.Tier, c.Lifecycle, c.OpenFindings,
       (SELECT COUNT(*) FROM sidata.CiLink l WHERE l.CiId = c.CiId AND l.Provider = N'mde') AS DefenderLinks
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, N'') <> N'retired' AND c.DocJson LIKE N'%domain[_]controller%'
ORDER BY DefenderLinks, c.Name;

-- 3. ONE HARD ID, ONE ACTIVE CI: the CIs Get-SICiMergedRetireSql retires (no current record; a linked record builds another
--    live CI), with the survivor -- and the hard ids two live CIs that BOTH have current records share (reported only)
;WITH cand AS (
    SELECT c.CiId, c.Name, c.Class, c.Tier, c.OpenFindings, c.CmdbId FROM sidata.Ci c
    WHERE ISNULL(c.Lifecycle, N'') <> N'retired'
      AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE r.CiId = c.CiId))
SELECT x.CiId, x.Name, x.Class, x.Tier, x.OpenFindings, x.CmdbId, r.CiId AS SurvivorCiId, l.Provider, l.NativeId
FROM cand x
JOIN sidata.CiLink l ON l.CiId = x.CiId AND l.RecordType <> N'child_resource'
JOIN sidata.CiRecord r ON r.RecordKey = l.Provider + N':' + l.NativeId
JOIN sidata.Ci d ON d.CiId = r.CiId AND ISNULL(d.Lifecycle, N'') <> N'retired'
WHERE r.CiId <> x.CiId AND EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = r.RecordKey)
ORDER BY x.CiId, l.Provider;

-- (no aggregate over a subquery -- Azure SQL refuses it: the "has current records" flag comes from an OUTER APPLY)
SELECT l.Provider, l.NativeId, COUNT(DISTINCT l.CiId) AS ActiveCis, SUM(ISNULL(cur.HasCurrent, 0)) AS WithCurrentRecords
FROM sidata.CiLink l JOIN sidata.Ci c ON c.CiId = l.CiId AND ISNULL(c.Lifecycle, N'') <> N'retired'
OUTER APPLY (SELECT TOP (1) 1 AS HasCurrent FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE r.CiId = l.CiId) cur
WHERE l.RecordType <> N'child_resource' AND l.Provider NOT IN (N'cmdb', N'servicenow')
GROUP BY l.Provider, l.NativeId HAVING COUNT(DISTINCT l.CiId) > 1
ORDER BY l.Provider, l.NativeId;

-- 3c. THE TWINS' FINDINGS: what each merged twin holds now and what moves to its survivor (a finding the survivor
--     already has stays once, on the survivor) -- the counts the owner compares after the first build with the fix
;WITH cand AS (
    SELECT c.CiId FROM sidata.Ci c
    WHERE ISNULL(c.Lifecycle, N'') <> N'retired'
      AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE r.CiId = c.CiId)),
tw AS (
    SELECT x.CiId, MIN(r.CiId) AS SurvivorCiId
    FROM cand x
    JOIN sidata.CiLink l ON l.CiId = x.CiId AND l.RecordType <> N'child_resource'
    JOIN sidata.CiRecord r ON r.RecordKey = l.Provider + N':' + l.NativeId
    JOIN sidata.CiGroupMember gm ON gm.RecordKey = r.RecordKey
    JOIN sidata.Ci d ON d.CiId = r.CiId AND ISNULL(d.Lifecycle, N'') <> N'retired'
    WHERE r.CiId <> x.CiId
    GROUP BY x.CiId)
SELECT t.CiId AS TwinCiId, t.SurvivorCiId, tf.TwinFindings, sf.SurvivorFindings, ov.Overlap,
       sf.SurvivorFindings + tf.TwinFindings - ov.Overlap AS SurvivorFindingsAfter
FROM tw t
OUTER APPLY (SELECT COUNT(*) AS TwinFindings FROM sidata.CiFinding f WHERE f.CiId = t.CiId) tf
OUTER APPLY (SELECT COUNT(*) AS SurvivorFindings FROM sidata.CiFinding f WHERE f.CiId = t.SurvivorCiId) sf
OUTER APPLY (SELECT COUNT(*) AS Overlap FROM sidata.CiFinding f WHERE f.CiId = t.CiId
             AND EXISTS (SELECT 1 FROM sidata.CiFinding s WHERE s.CiId = t.SurvivorCiId AND s.FindingKey = f.FindingKey)) ov
ORDER BY tf.TwinFindings DESC;

-- 3d. (the SETTINGS database, cfg -- another database: paste the CI ids of 1b as a JSON array into @ids) every retiring
--     account CI must have NO vulnerable item ServiceNow was sent (ItemKey = '<CI id>|<finding key>') before its close row
-- DECLARE @ids NVARCHAR(MAX) = N'["0346fbd5-...", "..."]';
-- SELECT LEFT(i.ItemKey, CHARINDEX(N'|', i.ItemKey) - 1) AS CiId, COUNT(*) AS VulnerableItems
-- FROM cfg.DataOutItem i JOIN OPENJSON(@ids) WITH (k NVARCHAR(64) '$') p ON i.ItemKey LIKE p.k + N'|%'
-- WHERE i.OutputId = N'servicenow-vulnerable-item'
-- GROUP BY LEFT(i.ItemKey, CHARINDEX(N'|', i.ItemKey) - 1);      -- expected: no row

-- 4. THE ACCOUNTS' MATCHES are decided from Advanced Hunting, not from this database: run the two queries the capture asks
--    (engine\asset-profiling\discovery\Get-SIEgAdComputers.ps1 -- Get-SIEgAdComputerDomainKql, then Get-SIEgAdComputerKql)
--    read-only, save both answers as JSON and count the states offline with diagnostics\Measure-SIComputerAccountMatch.ps1.
