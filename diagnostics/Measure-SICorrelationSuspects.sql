/*
    SecurityInsight #1053 -- THE CORRELATION GATEKEEPER: READ-ONLY PRECISION COUNTS for an install (the pilot first).
    Run against the install's Pro DATA database (sidata) through the Invardia Support app, each block on its own.
    Nothing here writes a user table: Q4 is the gatekeeper's own statement with @Write = 0 (temp tables only).
    The cases to confirm: the same short name / FQDN label on a server pair (name rule, tier conflict), one hard id on two CIs,
    Exposure Graph node churn (a leftover CI), the computer-account device CIs, devices named "dummydevicename".
    Hand back the result grids as they come (counts; Q4 and Q5 list device names -- they stay with the owner, never in a doc).
*/

-- Q1. The base: active CIs by class, asset type and OS family (the denominators of every rate below)
SELECT c.Class, c.AssetType, c.OsFamily, COUNT_BIG(*) AS ActiveCis
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, N'active') = N'active'
GROUP BY c.Class, c.AssetType, c.OsFamily
ORDER BY ActiveCis DESC;

-- Q2. RULE hardid: hard identifiers held by two or more ACTIVE device / cloud CIs, per identifier type -- values, CIs,
--     distinct CI sets (= groups), and how many of those CI sets have a CI with no link still seen (a leftover)
;WITH c AS (SELECT CiId FROM sidata.Ci WHERE ISNULL(Lifecycle, N'active') = N'active' AND Class IN (N'device', N'cloud_resource')),
i AS (
    SELECT DISTINCT r.CiId, ri.IdType, ri.IdValue
    FROM sidata.CiRecord r JOIN c ON c.CiId = r.CiId JOIN sidata.RecordIdentifier ri ON ri.RecordKey = r.RecordKey
    WHERE ri.IdType IN (N'MdeDeviceId', N'AadDeviceId', N'IntuneDeviceId', N'AzureResourceId', N'AzureVmId', N'CloudNativeResourceId', N'SecurityIdentifier', N'ActiveDirectoryObjectGuid')
      AND LTRIM(RTRIM(ri.IdValue)) NOT IN (N'', N'0', N'00000000-0000-0000-0000-000000000000')
    UNION
    SELECT y.CiId, N'Record', l.Provider + N':' + l.NativeId
    FROM sidata.CiLink l JOIN c ON c.CiId = l.CiId
    JOIN sidata.CiRecord r ON r.RecordKey = l.Provider + N':' + l.NativeId JOIN c o ON o.CiId = r.CiId
    CROSS APPLY (VALUES (l.CiId), (r.CiId)) y(CiId)
    WHERE r.CiId <> l.CiId AND l.Provider NOT IN (N'cmdb', N'servicenow') AND ISNULL(l.RecordType, N'') <> N'child_resource'
),
shared AS (SELECT IdType, IdValue FROM i GROUP BY IdType, IdValue HAVING COUNT(DISTINCT CiId) > 1),
sets AS (
    SELECT s.IdType, s.IdValue, STRING_AGG(CONVERT(NVARCHAR(MAX), i.CiId), N',') WITHIN GROUP (ORDER BY i.CiId) AS CiSet
    FROM shared s JOIN i ON i.IdType = s.IdType AND i.IdValue = s.IdValue GROUP BY s.IdType, s.IdValue
),
lo AS (
    SELECT DISTINCT st.CiSet FROM sets st CROSS APPLY STRING_SPLIT(st.CiSet, N',') v
    WHERE NOT EXISTS (SELECT 1 FROM sidata.CiLink k WHERE k.CiId = v.value AND ISNULL(k.State, N'active') IN (N'active', N'frozen') AND k.Provider NOT IN (N'cmdb', N'servicenow'))
)
SELECT st.IdType, COUNT(*) AS SharedValues, COUNT(DISTINCT st.CiSet) AS CiSets,
       SUM(CASE WHEN st.CiSet IN (SELECT CiSet FROM lo) THEN 1 ELSE 0 END) AS ValuesWithALeftover
FROM sets st GROUP BY st.IdType ORDER BY SharedValues DESC;

-- Q3. RULE name: the funnel -- how many short names survive each filter (the noise rule's measured effect)
;WITH c AS (
    SELECT x.CiId, x.AssetType, x.OsFamily,
           CASE WHEN EXISTS (SELECT 1 FROM sidata.CiLink k WHERE k.CiId = x.CiId AND k.Provider IN (N'mde', N'azure', N'mdc', N'entra', N'intune')) THEN 1 ELSE 0 END AS Anchored,
           CASE WHEN x.AssetType IN (N'Server', N'Database', N'Compute') OR EXISTS (SELECT 1 FROM sidata.CiLink k WHERE k.CiId = x.CiId AND k.Provider IN (N'azure', N'mdc')
                     AND (k.NativeId LIKE N'%/providers/microsoft.compute/virtualmachines/%' OR k.NativeId LIKE N'%/providers/microsoft.hybridcompute/machines/%')) THEN 1 ELSE 0 END AS Machine,
           CASE WHEN x.AssetType = N'Mobile' OR x.OsFamily IN (N'iOS', N'Android') THEN 1 ELSE 0 END AS Mobile
    FROM sidata.Ci x WHERE ISNULL(x.Lifecycle, N'active') = N'active' AND x.Class IN (N'device', N'cloud_resource')
),
nm AS (
    SELECT x.CiId, LOWER(LTRIM(RTRIM(x.Name))) AS Nm FROM sidata.Ci x JOIN c ON c.CiId = x.CiId
    UNION SELECT x.CiId, LOWER(LTRIM(RTRIM(x.Hostname))) FROM sidata.Ci x JOIN c ON c.CiId = x.CiId
    UNION SELECT r.CiId, LOWER(LTRIM(RTRIM(r.Name))) FROM sidata.CiRecord r JOIN c ON c.CiId = r.CiId
),
n AS (
    SELECT DISTINCT nm.CiId, LEFT(nm.Nm, CHARINDEX(N'.', nm.Nm + N'.') - 1) AS Short,
           CASE WHEN CHARINDEX(N'.', nm.Nm) > 0 THEN SUBSTRING(nm.Nm, CHARINDEX(N'.', nm.Nm) + 1, 400) ELSE N'' END AS Suffix
    FROM nm WHERE nm.Nm IS NOT NULL AND LEN(nm.Nm) >= 2 AND nm.Nm NOT LIKE N'%[/\@ ]%' AND NOT (nm.Nm NOT LIKE N'%[^0-9.]%' AND nm.Nm LIKE N'%.%') AND nm.Nm NOT LIKE N'%:%'
),
g AS (
    SELECT n.Short, COUNT(DISTINCT n.CiId) AS Cis, COUNT(DISTINCT NULLIF(n.Suffix, N'')) AS Suffixes,
           MAX(c.Machine) AS AnyMachine, MAX(c.Mobile) AS AnyMobile, MIN(c.Anchored) AS MinAnchored,
           CASE WHEN n.Short IN (N'iphone', N'ipad', N'android', N'localhost', N'unknown', N'default', N'desktop', N'laptop', N'pc', N'computer', N'dummydevicename', N'(none)', N'n/a')
                  OR n.Short LIKE N'android%' OR n.Short LIKE N'galaxy%' OR n.Short LIKE N'samsung%' OR n.Short LIKE N'pixel%' OR n.Short LIKE N'macbook%' OR n.Short LIKE N'imac%' OR n.Short LIKE N'surface%' THEN 1 ELSE 0 END AS Generic
    FROM n JOIN c ON c.CiId = n.CiId GROUP BY n.Short
)
SELECT N'1 short names on 2+ active CIs' AS Step, COUNT(*) AS ShortNames, SUM(Cis) AS CisInThem FROM g WHERE Cis >= 2
UNION ALL SELECT N'2 ... of them on 2-3 CIs', COUNT(*), SUM(Cis) FROM g WHERE Cis BETWEEN 2 AND 3
UNION ALL SELECT N'3 ... not a generic / placeholder name', COUNT(*), SUM(Cis) FROM g WHERE Cis BETWEEN 2 AND 3 AND Generic = 0
UNION ALL SELECT N'4 ... at most one DNS suffix', COUNT(*), SUM(Cis) FROM g WHERE Cis BETWEEN 2 AND 3 AND Generic = 0 AND Suffixes <= 1
UNION ALL SELECT N'5 ... a server / VM among them', COUNT(*), SUM(Cis) FROM g WHERE Cis BETWEEN 2 AND 3 AND Generic = 0 AND Suffixes <= 1 AND AnyMachine = 1
UNION ALL SELECT N'6 ... no phone among them', COUNT(*), SUM(Cis) FROM g WHERE Cis BETWEEN 2 AND 3 AND Generic = 0 AND Suffixes <= 1 AND AnyMachine = 1 AND AnyMobile = 0
UNION ALL SELECT N'7 ... one without a hard device id (= the name rule)', COUNT(*), SUM(Cis) FROM g WHERE Cis BETWEEN 2 AND 3 AND Generic = 0 AND Suffixes <= 1 AND AnyMachine = 1 AND AnyMobile = 0 AND MinAnchored = 0
UNION ALL SELECT N'x names on 4+ CIs (never a reason)', COUNT(*), SUM(Cis) FROM g WHERE Cis >= 4
UNION ALL SELECT N'x phone names on 2+ CIs (never a reason)', COUNT(*), SUM(Cis) FROM g WHERE Cis >= 2 AND AnyMobile = 1;

-- Q5. Names 4 or more active device CIs share -- the candidates for the generic list (generic_device_names); top 50
SELECT TOP (50) LOWER(LTRIM(RTRIM(x.Name))) AS Name, COUNT_BIG(*) AS ActiveCis,
       SUM(CASE WHEN x.AssetType = N'Mobile' OR x.OsFamily IN (N'iOS', N'Android') THEN 1 ELSE 0 END) AS Phones,
       SUM(CASE WHEN x.OpenFindings > 0 THEN 1 ELSE 0 END) AS WithFindings
FROM sidata.Ci x
WHERE ISNULL(x.Lifecycle, N'active') = N'active' AND x.Class = N'device'
GROUP BY LOWER(LTRIM(RTRIM(x.Name)))
HAVING COUNT_BIG(*) >= 4
ORDER BY ActiveCis DESC;

-- Q6. Does a record that vanished keep its rows? (rule hardid's leftover detection depends on it)
--     a) links of ACTIVE CIs whose record row is gone; b) records of ACTIVE CIs not collected for 7+ days, and their identifiers;
--     c) the pilot's own case: the Exposure Graph links of active CIs last seen 7+ days ago that are still 'active'
SELECT N'a links of active CIs without their record' AS Measure, COUNT_BIG(*) AS N
FROM sidata.CiLink l JOIN sidata.Ci c ON c.CiId = l.CiId AND ISNULL(c.Lifecycle, N'active') = N'active'
WHERE l.Provider NOT IN (N'cmdb', N'servicenow') AND NOT EXISTS (SELECT 1 FROM sidata.CiRecord r WHERE r.RecordKey = l.Provider + N':' + l.NativeId)
UNION ALL
SELECT N'b records of active CIs not collected for 7+ days', COUNT_BIG(*)
FROM sidata.CiRecord r JOIN sidata.Ci c ON c.CiId = r.CiId AND ISNULL(c.Lifecycle, N'active') = N'active'
WHERE r.CollectionTime < DATEADD(day, -7, SYSUTCDATETIME())
UNION ALL
SELECT N'b2 ... their identifiers still stored', COUNT_BIG(*)
FROM sidata.CiRecord r JOIN sidata.Ci c ON c.CiId = r.CiId AND ISNULL(c.Lifecycle, N'active') = N'active'
JOIN sidata.RecordIdentifier ri ON ri.RecordKey = r.RecordKey
WHERE r.CollectionTime < DATEADD(day, -7, SYSUTCDATETIME())
UNION ALL
SELECT N'c Exposure Graph links still active, last seen 7+ days ago', COUNT_BIG(*)
FROM sidata.CiLink l JOIN sidata.Ci c ON c.CiId = l.CiId AND ISNULL(c.Lifecycle, N'active') = N'active'
WHERE l.Provider = N'eg' AND ISNULL(l.State, N'active') = N'active' AND l.LastSeen < DATEADD(day, -7, SYSUTCDATETIME());

-- Q7. What an Exposure Graph DEVICE record carries (is the node label / an AD id kept on the record?) -- key counts over at most
--     2,000 records (a sample of the document keys, not of the data)
;WITH r AS (SELECT TOP (2000) r.DocJson FROM sidata.CiRecord r WHERE r.Provider = N'eg' AND r.RecordType IN (N'device', N'computer_account') AND ISJSON(r.DocJson) = 1)
SELECT j.[key] AS DocKey, COUNT_BIG(*) AS Records
FROM r CROSS APPLY OPENJSON(r.DocJson) AS j
GROUP BY j.[key]
ORDER BY Records DESC, DocKey;

-- Q4. THE GATEKEEPER ITSELF, read only (@Write = 0, temp tables only; the decision tables do not exist yet at the pilot):
--     every suspect group with its CIs. The owner marks each group TRUE (one machine / a placeholder) or FALSE -> the precision.
--     The lists are the shipped ones (data-model\lists.locked.json); the pilot has no override.
DECLARE @Generic NVARCHAR(MAX) = N'["iphone","iphone %","ipad","ipad %","android","android%","galaxy%","samsung%","pixel%","localhost","unknown","default","desktop","laptop","pc","computer","macbook%","imac%","surface%"]';
DECLARE @Placeholder NVARCHAR(MAX) = N'["dummydevicename","unknown","localhost","(none)","n/a"]';
DECLARE @Write INT = 0;
SET NOCOUNT ON;
SET XACT_ABORT ON;
-- 0. the active CIs that can be a machine: narrow columns only (never the document)
CREATE TABLE #c (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Class NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL,
                 Name NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, Hostname NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL,
                 AssetType NVARCHAR(128) COLLATE DATABASE_DEFAULT NULL, OsFamily NVARCHAR(64) COLLATE DATABASE_DEFAULT NULL,
                 Tier TINYINT NULL, TierSetBy NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL, OpenFindings INT NULL, Weighted FLOAT NULL,
                 Anchored BIT NOT NULL DEFAULT 0, ActiveLinks INT NOT NULL DEFAULT 0, Machine BIT NOT NULL DEFAULT 0, Mobile BIT NOT NULL DEFAULT 0);
INSERT #c (CiId, Class, Name, Hostname, AssetType, OsFamily, Tier, TierSetBy, OpenFindings, Weighted)
SELECT c.CiId, c.Class, c.Name, c.Hostname, c.AssetType, c.OsFamily, c.Tier, c.TierSetBy, c.OpenFindings, c.WeightedRiskScore
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, N'active') = N'active' AND c.Class IN (N'device', N'cloud_resource');
-- its links: a hard device link (Defender, Azure, Defender for Cloud, Entra, Intune), the links still seen, a machine link
UPDATE x SET Anchored = CASE WHEN ISNULL(l.Hard, 0) > 0 THEN 1 ELSE 0 END, ActiveLinks = ISNULL(l.Act, 0),
             Machine = CASE WHEN ISNULL(l.Vm, 0) > 0 OR x.AssetType IN (N'Server', N'Database', N'Compute') THEN 1 ELSE 0 END,
             Mobile = CASE WHEN x.AssetType = N'Mobile' OR x.OsFamily IN (N'iOS', N'Android') THEN 1 ELSE 0 END
FROM #c x
CROSS APPLY (SELECT SUM(CASE WHEN k.Provider IN (N'mde', N'azure', N'mdc', N'entra', N'intune') THEN 1 ELSE 0 END) AS Hard,
                    SUM(CASE WHEN ISNULL(k.State, N'active') IN (N'active', N'frozen') THEN 1 ELSE 0 END) AS Act,
                    SUM(CASE WHEN k.Provider IN (N'azure', N'mdc') AND (k.NativeId LIKE N'%/providers/microsoft.compute/virtualmachines/%'
                                  OR k.NativeId LIKE N'%/providers/microsoft.hybridcompute/machines/%') THEN 1 ELSE 0 END) AS Vm
             FROM sidata.CiLink k WHERE k.CiId = x.CiId AND k.Provider NOT IN (N'cmdb', N'servicenow')) l;

-- 1. HARD IDS: every hard identifier of the records of each CI, and each CI's links whose record builds ANOTHER active CI
CREATE TABLE #i (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, IdType NVARCHAR(48) COLLATE DATABASE_DEFAULT NOT NULL, IdValue NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL);
INSERT #i (CiId, IdType, IdValue)
SELECT DISTINCT r.CiId, ri.IdType, LEFT(ri.IdValue, 450)
FROM sidata.CiRecord r
JOIN #c x ON x.CiId = r.CiId
JOIN sidata.RecordIdentifier ri ON ri.RecordKey = r.RecordKey
WHERE ri.IdType IN (N'MdeDeviceId', N'AadDeviceId', N'IntuneDeviceId', N'AzureResourceId', N'AzureVmId', N'CloudNativeResourceId', N'SecurityIdentifier', N'ActiveDirectoryObjectGuid')
  AND LTRIM(RTRIM(ri.IdValue)) NOT IN (N'', N'0', N'00000000-0000-0000-0000-000000000000');
INSERT #i (CiId, IdType, IdValue)
SELECT DISTINCT y.CiId, N'Record', LEFT(l.Provider + N':' + l.NativeId, 450)
FROM sidata.CiLink l
JOIN #c x ON x.CiId = l.CiId
JOIN sidata.CiRecord r ON r.RecordKey = l.Provider + N':' + l.NativeId
JOIN #c o ON o.CiId = r.CiId
CROSS APPLY (VALUES (l.CiId), (r.CiId)) y(CiId)
WHERE r.CiId <> l.CiId AND l.Provider NOT IN (N'cmdb', N'servicenow') AND ISNULL(l.RecordType, N'') <> N'child_resource';
CREATE TABLE #hv (IdType NVARCHAR(48) COLLATE DATABASE_DEFAULT NOT NULL, IdValue NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, CiSet NVARCHAR(MAX) COLLATE DATABASE_DEFAULT NOT NULL,
                  CiHash VARBINARY(32) NULL);
;WITH shared AS (SELECT IdType, IdValue FROM (SELECT DISTINCT IdType, IdValue, CiId FROM #i) d GROUP BY IdType, IdValue HAVING COUNT(*) > 1)
INSERT #hv (IdType, IdValue, CiSet)
SELECT s.IdType, s.IdValue, STRING_AGG(CONVERT(NVARCHAR(MAX), d.CiId), N',') WITHIN GROUP (ORDER BY d.CiId)
FROM shared s JOIN (SELECT DISTINCT IdType, IdValue, CiId FROM #i) d ON d.IdType = s.IdType AND d.IdValue = s.IdValue
GROUP BY s.IdType, s.IdValue;
UPDATE #hv SET CiHash = HASHBYTES('SHA2_256', CiSet);

CREATE TABLE #s (GroupKey NVARCHAR(80) COLLATE DATABASE_DEFAULT NOT NULL, CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, [Rule] NVARCHAR(16) COLLATE DATABASE_DEFAULT NOT NULL,
                 Severity NVARCHAR(8) COLLATE DATABASE_DEFAULT NOT NULL DEFAULT N'medium', GroupLabel NVARCHAR(450) COLLATE DATABASE_DEFAULT NULL,
                 Evidence NVARCHAR(2000) COLLATE DATABASE_DEFAULT NULL, [Role] NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL,
                 Dismissed BIT NOT NULL DEFAULT 0, DecisionId BIGINT NULL, PRIMARY KEY (GroupKey, CiId));
-- one group per SET of CIs (the CIs that share one id usually share several: the Azure id AND the Defender id)
;WITH g AS (
    SELECT N'hardid:' + CONVERT(NVARCHAR(64), h.CiHash, 2) AS GroupKey, MAX(h.CiSet) AS CiSet,
           COUNT(*) AS Ids, MIN(h.IdType + N' ' + h.IdValue) AS FirstId,
           STRING_AGG(CONVERT(NVARCHAR(MAX), h.IdType + N' ' + h.IdValue), N'; ') WITHIN GROUP (ORDER BY h.IdType, h.IdValue) AS Ids2
    FROM #hv h GROUP BY h.CiHash
)
INSERT #s (GroupKey, CiId, [Rule], GroupLabel, Evidence)
SELECT g.GroupKey, LTRIM(RTRIM(v.value)), N'hardid', LEFT(g.FirstId, 450),
       LEFT(CONVERT(NVARCHAR(20), g.Ids) + N' shared id(s): ' + g.Ids2, 2000)
FROM g CROSS APPLY STRING_SPLIT(g.CiSet, N',') v
WHERE LTRIM(RTRIM(v.value)) <> N'';

-- 2. THE SAME NAME: every name of a CI (its name, its host name, the names of its current records), its short name and
--    its DNS suffix; IP addresses, paths and mail-like names are no host names
CREATE TABLE #n (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, Nm NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL,
                 Short NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Suffix NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL);
;WITH nm AS (
    SELECT x.CiId, v.Nm FROM #c x CROSS APPLY (VALUES (LOWER(LTRIM(RTRIM(x.Name)))), (LOWER(LTRIM(RTRIM(x.Hostname))))) v(Nm)
    UNION
    SELECT r.CiId, LOWER(LTRIM(RTRIM(r.Name))) FROM sidata.CiRecord r JOIN #c x ON x.CiId = r.CiId WHERE r.Name IS NOT NULL
)
INSERT #n (CiId, Nm, Short, Suffix)
SELECT DISTINCT n.CiId, n.Nm, LEFT(n.Nm, CHARINDEX(N'.', n.Nm + N'.') - 1),
       CASE WHEN CHARINDEX(N'.', n.Nm) > 0 THEN SUBSTRING(n.Nm, CHARINDEX(N'.', n.Nm) + 1, 400) ELSE N'' END
FROM nm n
WHERE n.Nm IS NOT NULL AND LEN(n.Nm) >= 2
  AND n.Nm NOT LIKE N'%[/\@ ]%'
  AND NOT (n.Nm NOT LIKE N'%[^0-9.]%' AND n.Nm LIKE N'%.%')
  AND n.Nm NOT LIKE N'%:%';
DELETE FROM #n WHERE LEN(Short) < 2;
-- generic names never make CIs one machine; a placeholder name is its own rule
DELETE n FROM #n n WHERE EXISTS (SELECT 1 FROM OPENJSON(@Generic) g WHERE n.Short LIKE g.[value] COLLATE DATABASE_DEFAULT OR n.Nm LIKE g.[value] COLLATE DATABASE_DEFAULT)
                      OR EXISTS (SELECT 1 FROM OPENJSON(@Placeholder) p WHERE n.Short = p.[value] COLLATE DATABASE_DEFAULT OR n.Nm = p.[value] COLLATE DATABASE_DEFAULT);
;WITH grp AS (
    SELECT n.Short, COUNT(DISTINCT n.CiId) AS Cis, COUNT(DISTINCT NULLIF(n.Suffix, N'')) AS Suffixes
    FROM #n n GROUP BY n.Short
),
ok AS (
    SELECT g.Short
    FROM grp g
    WHERE g.Cis BETWEEN 2 AND 3 AND g.Suffixes <= 1
      AND EXISTS (SELECT 1 FROM #n n JOIN #c x ON x.CiId = n.CiId WHERE n.Short = g.Short AND x.Machine = 1)
      AND NOT EXISTS (SELECT 1 FROM #n n JOIN #c x ON x.CiId = n.CiId WHERE n.Short = g.Short AND x.Mobile = 1)
      AND EXISTS (SELECT 1 FROM #n n JOIN #c x ON x.CiId = n.CiId WHERE n.Short = g.Short AND x.Anchored = 0)
)
INSERT #s (GroupKey, CiId, [Rule], GroupLabel, Evidence)
SELECT DISTINCT N'name:' + CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', o.Short), 2), n.CiId, N'name', LEFT(o.Short, 450),
       LEFT(N'the short name ' + o.Short + N' is the name, or the first label of the FQDN, of each of them', 2000)
FROM ok o JOIN #n n ON n.Short = o.Short;
-- a name group whose CIs are all in ONE hard-id group says nothing new: the hard id is the stronger evidence
DELETE s FROM #s s
WHERE s.[Rule] = N'name' AND s.GroupKey IN (
    SELECT n.GroupKey FROM #s n JOIN #s h ON h.CiId = n.CiId AND h.[Rule] = N'hardid'
    WHERE n.[Rule] = N'name'
    GROUP BY n.GroupKey, h.GroupKey
    HAVING COUNT(DISTINCT n.CiId) = (SELECT COUNT(*) FROM #s x WHERE x.GroupKey = n.GroupKey));

-- 3. PLACEHOLDER NAMES: one group per placeholder name, every active device that carries it
INSERT #s (GroupKey, CiId, [Rule], Severity, GroupLabel, Evidence)
SELECT N'placeholder:' + CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', LOWER(LTRIM(RTRIM(x.Name)))), 2), x.CiId, N'placeholder', N'low', LEFT(LOWER(LTRIM(RTRIM(x.Name))), 450),
       LEFT(N'the name ' + LOWER(LTRIM(RTRIM(x.Name))) + N' is a placeholder a source gives a device it has no name for', 2000)
FROM #c x
WHERE x.Class = N'device' AND EXISTS (SELECT 1 FROM OPENJSON(@Placeholder) p WHERE LOWER(LTRIM(RTRIM(x.Name))) = p.[value] COLLATE DATABASE_DEFAULT);

-- 4. SEVERITY AND ROLE: different tiers inside a group = high; a CI with no link still seen while another has one = leftover;
--    a CI with no hard device id while another has one = unanchored
;WITH t AS (
    SELECT s.GroupKey, MIN(x.Tier) AS TMin, MAX(x.Tier) AS TMax, COUNT(DISTINCT ISNULL(CONVERT(INT, x.Tier), -1)) AS Tiers,
           MAX(x.ActiveLinks) AS MaxAct, MAX(CONVERT(INT, x.Anchored)) AS AnyAnchored
    FROM #s s JOIN #c x ON x.CiId = s.CiId WHERE s.[Rule] <> N'placeholder' GROUP BY s.GroupKey
)
UPDATE s SET Severity = CASE WHEN t.Tiers > 1 THEN N'high' ELSE N'medium' END,
             [Role] = CASE WHEN x.ActiveLinks = 0 AND t.MaxAct > 0 THEN N'leftover' WHEN x.Anchored = 0 AND t.AnyAnchored = 1 THEN N'unanchored' ELSE N'' END
FROM #s s JOIN #c x ON x.CiId = s.CiId JOIN t ON t.GroupKey = s.GroupKey;

-- 5. no decision tables in this database yet: nothing is dismissed

-- 6. THE CURRENT SET, replaced in one transaction (a dry run answers the rows only)
IF @Write = 1
BEGIN
    BEGIN TRANSACTION;
    DELETE FROM sidata.CiSuspect;
    INSERT sidata.CiSuspect (GroupKey, CiId, [Rule], Severity, GroupLabel, Evidence, Name, Class, AssetType, Tier, TierSetBy, OpenFindings, WeightedRiskScore, Anchored, ActiveLinks, [Role], Dismissed, DecisionId)
    SELECT s.GroupKey, s.CiId, s.[Rule], s.Severity, s.GroupLabel, s.Evidence, x.Name, x.Class, x.AssetType, x.Tier, x.TierSetBy, x.OpenFindings, x.Weighted, x.Anchored, x.ActiveLinks, s.[Role], s.Dismissed, s.DecisionId
    FROM #s s JOIN #c x ON x.CiId = s.CiId;
    COMMIT TRANSACTION;
END
SELECT s.GroupKey, s.[Rule], s.Severity, s.GroupLabel, s.Evidence, s.CiId, x.Name, x.Class, x.AssetType, x.Tier, x.TierSetBy, x.OpenFindings,
       x.Weighted AS WeightedRiskScore, CONVERT(INT, x.Anchored) AS Anchored, x.ActiveLinks, s.[Role], CONVERT(INT, s.Dismissed) AS Dismissed, s.DecisionId
FROM #s s JOIN #c x ON x.CiId = s.CiId
ORDER BY CASE s.Severity WHEN N'high' THEN 0 WHEN N'medium' THEN 1 ELSE 2 END, s.[Rule], s.GroupKey, x.Tier, s.CiId;
DROP TABLE #s; DROP TABLE #n; DROP TABLE #hv; DROP TABLE #i; DROP TABLE #c;
