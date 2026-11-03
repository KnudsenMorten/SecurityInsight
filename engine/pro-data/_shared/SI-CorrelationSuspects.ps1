#Requires -Version 5.1
<#
    SecurityInsight -- THE CORRELATION GATEKEEPER (REQUIREMENTS #1053, owner 2026-11-02: "it would be great to have a
    gatekeeper that could have detected this problem, where node name is the same so it is probably the same device so
    there was a correlation issue -- data quality"; "why not fix this issue automatically, we need to define rules so
    things works automatically").

    The automatic correlation rules (the CI build: one hard id -> one active CI; an AD computer account -> its device, #1052)
    merge what they can decide. This finds what they could NOT decide -- CIs that are probably one machine, or one machine
    that is probably two -- and lists each suspect BY NAME so a person can act. A WARNING ONLY: it never blocks a run, a
    step or a hand-off, and it changes no CI. A person's decision (web app, Data quality > Correlation suspects) is stored
    in sidata.CiSuspectDecision: "not the same" stops the warning for that group; "same machine" makes the next CI build
    merge their records (the grouping's own path, Get-SICiGroupingStepSql); removing it splits them again.

    THE RULES (set-based, ONE statement batch over the Pro database; the active CIs of class device / cloud_resource):
      hardid       one hard identifier (Defender / Entra / Intune device id, Azure resource / VM id, a multicloud resource
                   id, an AD SID / object GUID) on two or more ACTIVE CIs -- or a link of an active CI whose record builds
                   ANOTHER active CI now (a merge left its old row behind; Exposure Graph node id churn). A hard id names
                   one machine, so this is never noise and no name filter applies.
      name         the same short name -- the name, or the first label of an FQDN -- on 2 or 3 active CIs (a name on 4 or
                   more is a name many machines share), where: the names have at most one DNS suffix between them; at
                   least one CI is a server / VM (asset type Server, Database or Compute, or an Azure / Arc machine link);
                   none is a phone or tablet (asset type Mobile, OS family iOS / Android); at least one has NO hard device
                   id (two Defender devices with one name are two onboardings, not a correlation error); and the name is
                   not one of the shipped generic names (data-model list generic_device_names, customer-overridable).
      placeholder  an active device whose name is a source's placeholder (data-model list placeholder_device_names, e.g.
                   Defender's "dummydevicename"): a person cannot tell those devices apart. #1054: the CI build takes the
                   name from another linked source; when none has one it names the CI 'unnamed-device-<short id>' -- such
                   a CI is listed here too, in the group of the placeholder its records carry (the data-quality flag).
    SEVERITY: high when the CIs of a group carry DIFFERENT tiers (the pilot: Tier 0 on the empty duplicate, Tier 3 on the
    machine with the findings -- the most critical asset loses its priority), else medium; placeholder = low.
    ROLE of a CI in its group: leftover (no active link while another CI of the group has one), unanchored (no hard id
    while another has one), else empty.
    DECISIONS: a group whose CIs are ALL named by one "not the same" decision in force (by CI id or by one of their records,
    as they were when it was made) is Dismissed -- still stored, never warned about; a new CI joining the group raises it
    again. A group a "same machine" decision covers waits for the next CI build (Dismissed, the decision named).

    WHEN: once per data sync, at its start -- after the CI build (the asset correlation job) and before the collection is
    loaded, so the correlation evidence of the load (the "Possible duplicate" figure of Correlation quality) and the
    data-quality warnings at the end of the sync read THE SAME result. The current set is replaced in one transaction.
    COST: one scan of the active CIs (narrow columns, no document), their links and the identifiers of their records; the
    name rule groups the names once. No sample, no cap: every active CI is read, every suspect stored.

    WHAT IT RETURNS (Invoke-SICorrelationSuspects): the groups with their CIs, the data-quality metrics (corr.*, kind corr)
    and warnings (rule correlation-suspect, one per rule, each group a field naming its CIs), and the run's one WARNING
    for the telemetry -- counts only, never a name (Get-SICorrelationSuspectIssue).

    Writes only SecurityInsight's own database. No PowerShell modules; PS 5.1 syntax (the containers run pwsh 7).
#>

$script:SICorrelationSuspects = @{
    # the shipped lists, used when the data model cannot be read (the same values as data-model\lists.locked.json)
    GenericDefault     = @('iphone', 'iphone *', 'ipad', 'ipad *', 'android', 'android*', 'galaxy*', 'samsung*', 'pixel*', 'localhost', 'unknown', 'default', 'desktop', 'laptop', 'pc', 'computer', 'macbook*', 'imac*', 'surface*')
    PlaceholderDefault = @('dummydevicename', 'unknown', 'localhost', '(none)', 'n/a')
    GenericListId      = 'generic_device_names'
    PlaceholderListId  = 'placeholder_device_names'
    Rules              = [ordered]@{
        hardid      = @{ Label = 'Correlation suspects: one hard id on two or more active CIs'; Unit = 'group(s)' }
        name        = @{ Label = 'Correlation suspects: the same name on 2-3 active server / VM CIs'; Unit = 'group(s)' }
        placeholder = @{ Label = 'Correlation suspects: active devices with a placeholder name'; Unit = 'name(s)' }
    }
    PagePath           = '/Admin/CorrelationSuspects'
    Invariant          = [System.Globalization.CultureInfo]::InvariantCulture
}

function Get-SICorrelationSuspectValue {
    <# PURE. A value of a row (hashtable, data row or object), $null when absent or DBNull. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row -is [System.Data.DataRow]) { if ($Row.Table.Columns.Contains($Name)) { $v = $Row[$Name] } }
    else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

# =====================================================================================================================
#  The lists -- generic names (never a reason to merge) and placeholder names (a warning of their own)
# =====================================================================================================================
function ConvertTo-SICorrelationLikePattern {
    <# PURE. A list entry (lower case, * = any text) -> a T-SQL LIKE pattern ([, %, _ taken literally). '' for an empty entry. #>
    param([AllowNull()][string]$Entry)
    $e = ([string]$Entry).Trim().ToLowerInvariant()
    if (-not $e) { return '' }
    $e = $e.Replace('[', '[[]').Replace('%', '[%]').Replace('_', '[_]')
    $e.Replace('*', '%')
}

function Get-SICorrelationSuspectLists {
    <#
        The generic and the placeholder names in force: the data model's lists (locked + the customer's override) when the
        data model can be read, else the shipped defaults. -Lists: the merged lists template's .lists (a test seam).
        Returns @{ Generic (LIKE patterns); Placeholder (lower-case names); Source }.
    #>
    param($Lists, [string]$Root, [string]$OverlayRoot)
    $src = 'shipped defaults'
    if ($null -eq $Lists) {
        try {
            if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) {
                $f = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'SI-DataModelTemplates.ps1')
                if (Test-Path -LiteralPath $f) { . $f }
            }
            if (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue) {
                if (-not $Root -and $global:SI_DataModelRoot) { $Root = [string]$global:SI_DataModelRoot }
                if (-not $OverlayRoot -and $global:SI_DataModelOverlayRoot) { $OverlayRoot = [string]$global:SI_DataModelOverlayRoot }
                $rootArg = $Root
                if (-not $rootArg) { $rootArg = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'data-model') }
                $t = Get-SIDataModelTemplate -Name 'lists' -Root $rootArg -OverlayRoot $OverlayRoot
                if ($t -and $t.Document) { $Lists = @($t.Document.lists); $src = 'data model' }
            }
        } catch { $Lists = $null; $src = 'shipped defaults (the data model could not be read: ' + $_.Exception.Message + ')' }
    } else { $src = 'given' }
    $generic = $null; $placeholder = $null
    foreach ($l in @($Lists)) {
        if ($null -eq $l) { continue }
        $id = [string](Get-SICorrelationSuspectValue $l 'id')
        if ($id -eq $script:SICorrelationSuspects.GenericListId) { $generic = @(Get-SICorrelationSuspectValue $l 'values') }
        elseif ($id -eq $script:SICorrelationSuspects.PlaceholderListId) { $placeholder = @(Get-SICorrelationSuspectValue $l 'values') }
    }
    if ($null -eq $generic) { $generic = $script:SICorrelationSuspects.GenericDefault }
    if ($null -eq $placeholder) { $placeholder = $script:SICorrelationSuspects.PlaceholderDefault }
    [pscustomobject]@{
        Generic     = @(@($generic) | ForEach-Object { ConvertTo-SICorrelationLikePattern ([string]$_) } | Where-Object { $_ } | Select-Object -Unique)
        Placeholder = @(@($placeholder) | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
        Source      = $src
    }
}

# =====================================================================================================================
#  The statement -- ONE batch: the rules, the decisions, the current set replaced, the rows answered
# =====================================================================================================================
function Get-SICorrelationSuspectColumnsSql {
    <# PURE. Which optional columns of sidata.Ci this database has (OsFamily, Hostname) and whether the tables exist. #>
@'
SELECT CASE WHEN OBJECT_ID(N'sidata.Ci') IS NOT NULL AND OBJECT_ID(N'sidata.CiLink') IS NOT NULL AND OBJECT_ID(N'sidata.CiRecord') IS NOT NULL
                  AND OBJECT_ID(N'sidata.RecordIdentifier') IS NOT NULL THEN 1 ELSE 0 END AS HasCi,
       CASE WHEN OBJECT_ID(N'sidata.CiSuspect') IS NOT NULL THEN 1 ELSE 0 END AS HasSuspect,
       CASE WHEN OBJECT_ID(N'sidata.CiSuspectDecision') IS NOT NULL AND OBJECT_ID(N'sidata.CiSuspectDecisionRecord') IS NOT NULL THEN 1 ELSE 0 END AS HasDecision,
       CASE WHEN COL_LENGTH(N'sidata.Ci', N'OsFamily') IS NOT NULL THEN 1 ELSE 0 END AS HasOsFamily,
       CASE WHEN COL_LENGTH(N'sidata.Ci', N'Hostname') IS NOT NULL THEN 1 ELSE 0 END AS HasHostname;
'@
}

function Get-SICorrelationSuspectSql {
    <#
        PURE. The gatekeeper's batch. Parameters: @Generic / @Placeholder (JSON arrays: LIKE patterns / lower-case names),
        @Write (1 = replace sidata.CiSuspect; 0 = a dry run answers the rows only). -HasOsFamily / -HasHostname: the optional
        columns of sidata.Ci (Get-SICorrelationSuspectColumnsSql); -HasDecision: the decision tables exist.
        Answers one row per (group, CI): GroupKey, Rule, Severity, GroupLabel, Evidence, CiId, Name, Class, AssetType, Tier,
        TierSetBy, OpenFindings, WeightedRiskScore, Anchored, ActiveLinks, Role, Dismissed, DecisionId.
    #>
    param([switch]$HasOsFamily, [switch]$HasHostname, [switch]$HasDecision)
    $os = if ($HasOsFamily) { 'c.OsFamily' } else { 'CAST(NULL AS NVARCHAR(64))' }
    $hostNames = if ($HasHostname) { ', (LOWER(LTRIM(RTRIM(x.Hostname))))' } else { '' }
    $hostCol = if ($HasHostname) { 'c.Hostname' } else { 'CAST(NULL AS NVARCHAR(400))' }
    $decisions = if ($HasDecision) {
        @'
-- 5. THE DECISIONS: a group is dismissed while EVERY CI of it is named by one decision in force (by its id, or by one of
--    its current records as they were when the decision was made). "not_same" = they are different machines; "same" = the
--    next CI build merges them (the group waits for it).
;WITH cov AS (
    SELECT g.GroupKey, x.DecisionId, g.CiId
    FROM #s g JOIN sidata.CiSuspectDecisionRecord x ON x.CiId = g.CiId AND x.RecordKey = N''
    WHERE g.[Rule] <> N'placeholder'
    UNION
    SELECT g.GroupKey, x.DecisionId, g.CiId
    FROM #s g
    JOIN sidata.CiRecord r ON r.CiId = g.CiId
    JOIN sidata.CiSuspectDecisionRecord x ON x.RecordKey = r.RecordKey AND x.RecordKey <> N''
    WHERE g.[Rule] <> N'placeholder'
),
best AS (
    SELECT c.GroupKey, c.DecisionId, COUNT(DISTINCT c.CiId) AS Covered
    FROM cov c JOIN sidata.CiSuspectDecision d ON d.DecisionId = c.DecisionId AND d.Removed = 0
    GROUP BY c.GroupKey, c.DecisionId
),
need AS (SELECT GroupKey, COUNT(*) AS Members FROM #s GROUP BY GroupKey),
hit AS (
    SELECT b.GroupKey, MAX(b.DecisionId) AS DecisionId
    FROM best b JOIN need n ON n.GroupKey = b.GroupKey
    WHERE b.Covered >= n.Members
    GROUP BY b.GroupKey
)
UPDATE s SET Dismissed = 1, DecisionId = h.DecisionId FROM #s s JOIN hit h ON h.GroupKey = s.GroupKey;
'@
    } else { '-- 5. no decision tables in this database yet: nothing is dismissed' }
@"
SET NOCOUNT ON;
SET XACT_ABORT ON;
-- 0. the active CIs that can be a machine: narrow columns only (never the document)
CREATE TABLE #c (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Class NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL,
                 Name NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, Hostname NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL,
                 AssetType NVARCHAR(128) COLLATE DATABASE_DEFAULT NULL, OsFamily NVARCHAR(64) COLLATE DATABASE_DEFAULT NULL,
                 Tier TINYINT NULL, TierSetBy NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL, OpenFindings INT NULL, Weighted FLOAT NULL,
                 Anchored BIT NOT NULL DEFAULT 0, ActiveLinks INT NOT NULL DEFAULT 0, Machine BIT NOT NULL DEFAULT 0, Mobile BIT NOT NULL DEFAULT 0);
INSERT #c (CiId, Class, Name, Hostname, AssetType, OsFamily, Tier, TierSetBy, OpenFindings, Weighted)
SELECT c.CiId, c.Class, c.Name, $hostCol, c.AssetType, $os, c.Tier, c.TierSetBy, c.OpenFindings, c.WeightedRiskScore
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
    SELECT x.CiId, v.Nm FROM #c x CROSS APPLY (VALUES (LOWER(LTRIM(RTRIM(x.Name))))$hostNames) v(Nm)
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

-- 3. PLACEHOLDER NAMES: one group per placeholder name, every active device that carries it -- and (#1054) every active machine
--    the CI build NAMED because no linked source had a name for it (unnamed-device-<short id>), in the group of the placeholder
--    its records carry
INSERT #s (GroupKey, CiId, [Rule], Severity, GroupLabel, Evidence)
SELECT N'placeholder:' + CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', LOWER(LTRIM(RTRIM(x.Name)))), 2), x.CiId, N'placeholder', N'low', LEFT(LOWER(LTRIM(RTRIM(x.Name))), 450),
       LEFT(N'the name ' + LOWER(LTRIM(RTRIM(x.Name))) + N' is a placeholder a source gives a device it has no name for', 2000)
FROM #c x
WHERE x.Class = N'device' AND EXISTS (SELECT 1 FROM OPENJSON(@Placeholder) p WHERE LOWER(LTRIM(RTRIM(x.Name))) = p.[value] COLLATE DATABASE_DEFAULT);
;WITH gen AS (
    SELECT x.CiId, LOWER(LTRIM(RTRIM(x.Name))) AS Nm,
           ISNULL((SELECT MIN(LOWER(LTRIM(RTRIM(r.Name)))) FROM sidata.CiRecord r
                   WHERE r.CiId = x.CiId AND EXISTS (SELECT 1 FROM OPENJSON(@Placeholder) p WHERE LOWER(LTRIM(RTRIM(r.Name))) = p.[value] COLLATE DATABASE_DEFAULT)),
                  N'unnamed-device') AS Ph
    FROM #c x
    WHERE x.Name LIKE N'unnamed-device-%' AND NOT EXISTS (SELECT 1 FROM #s s WHERE s.CiId = x.CiId AND s.[Rule] = N'placeholder')
)
INSERT #s (GroupKey, CiId, [Rule], Severity, GroupLabel, Evidence)
SELECT N'placeholder:' + CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', g.Ph), 2), g.CiId, N'placeholder', N'low', LEFT(g.Ph, 450),
       LEFT(N'no linked source has a name for it (a source gives the placeholder ' + g.Ph + N'): SecurityInsight named it ' + g.Nm, 2000)
FROM gen g;

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

$decisions

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
"@
}

# =====================================================================================================================
#  The rows -> groups, words, metrics, warnings -- PURE
# =====================================================================================================================
function Format-SICorrelationSuspectCount {
    <# PURE. A count for a person (grouped, invariant). #>
    param($Value)
    if ($null -eq $Value) { return '' }
    ([double]$Value).ToString('N0', $script:SICorrelationSuspects.Invariant)
}

function ConvertTo-SICorrelationSuspectGroups {
    <#
        PURE. The statement's rows -> one object per group, high severity first: @{ GroupKey; Rule; Severity; Label; Evidence;
        Dismissed; DecisionId; Members (@{ CiId; Name; Class; AssetType; Tier; TierSetBy; OpenFindings; WeightedRiskScore;
        Anchored; ActiveLinks; Role }, by tier then name); Names (the CIs' names); Impact (the tier words, '' when none) }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $groups = [ordered]@{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = [string](Get-SICorrelationSuspectValue $r 'GroupKey'); if (-not $k) { continue }
        if (-not $groups.Contains($k)) {
            $dec = Get-SICorrelationSuspectValue $r 'DecisionId'
            $groups[$k] = [pscustomobject]@{
                GroupKey = $k; Rule = [string](Get-SICorrelationSuspectValue $r 'Rule'); Severity = [string](Get-SICorrelationSuspectValue $r 'Severity')
                Label = [string](Get-SICorrelationSuspectValue $r 'GroupLabel'); Evidence = [string](Get-SICorrelationSuspectValue $r 'Evidence')
                Dismissed = ([int](Get-SICorrelationSuspectValue $r 'Dismissed') -eq 1); DecisionId = $(if ($null -ne $dec) { [long]$dec } else { $null })
                Members = (New-Object System.Collections.Generic.List[object]); Names = @(); Impact = ''
            }
        }
        $t = Get-SICorrelationSuspectValue $r 'Tier'; $of = Get-SICorrelationSuspectValue $r 'OpenFindings'; $w = Get-SICorrelationSuspectValue $r 'WeightedRiskScore'
        $groups[$k].Members.Add([pscustomobject]@{
            CiId = [string](Get-SICorrelationSuspectValue $r 'CiId'); Name = [string](Get-SICorrelationSuspectValue $r 'Name')
            Class = [string](Get-SICorrelationSuspectValue $r 'Class'); AssetType = [string](Get-SICorrelationSuspectValue $r 'AssetType')
            Tier = $(if ($null -ne $t) { [int]$t } else { $null }); TierSetBy = [string](Get-SICorrelationSuspectValue $r 'TierSetBy')
            OpenFindings = $(if ($null -ne $of) { [int]$of } else { $null }); WeightedRiskScore = $(if ($null -ne $w) { [double]$w } else { $null })
            Anchored = ([int](Get-SICorrelationSuspectValue $r 'Anchored') -eq 1); ActiveLinks = [int](Get-SICorrelationSuspectValue $r 'ActiveLinks')
            Role = [string](Get-SICorrelationSuspectValue $r 'Role')
        })
    }
    $sevRank = @{ high = 0; medium = 1; low = 2 }
    $out = foreach ($g in $groups.Values) {
        $m = @($g.Members | Sort-Object @{ Expression = { if ($null -eq $_.Tier) { 9 } else { $_.Tier } } }, Name, CiId)
        $g.Members = $m
        $g.Names = @($m | ForEach-Object { if ($_.Name) { $_.Name } else { $_.CiId } })
        $g.Impact = Get-SICorrelationSuspectImpact -Group $g
        $g
    }
    @($out | Sort-Object @{ Expression = { $r = $sevRank[[string]$_.Severity]; if ($null -eq $r) { 3 } else { $r } } }, Rule, Label, GroupKey)
}

function Get-SICorrelationSuspectImpact {
    <#
        PURE. What the suspect costs, in words, for a group whose CIs carry different tiers: the most critical tier and on
        which CI (its findings), and the CI with the most findings and its tier -- "Tier 0 is on azvm-dc01 (0 findings);
        azvm-dc01.contoso.local (2,202 findings) is Tier 3". '' when the tiers agree (or a placeholder group).
    #>
    param($Group)
    if ($null -eq $Group -or [string]$Group.Rule -eq 'placeholder') { return '' }
    $m = @($Group.Members)
    $tiers = @($m | ForEach-Object { if ($null -eq $_.Tier) { 'none' } else { [string]$_.Tier } } | Select-Object -Unique)
    if ($tiers.Count -le 1) { return '' }
    $f = { param($x) if ($null -eq $x.OpenFindings) { 'findings not counted yet' } else { '{0} finding{1}' -f (Format-SICorrelationSuspectCount $x.OpenFindings), $(if ([int]$x.OpenFindings -eq 1) { '' } else { 's' }) } }
    $nm = { param($x) if ($x.Name) { $x.Name } else { $x.CiId } }
    $tw = { param($x) if ($null -eq $x.Tier) { 'without a tier' } else { 'Tier ' + $x.Tier } }
    $top = @($m | Where-Object { $null -ne $_.Tier } | Sort-Object Tier, @{ Expression = { [int]$_.OpenFindings } })[0]
    $most = @($m | Sort-Object @{ Expression = { if ($null -eq $_.OpenFindings) { -1 } else { [int]$_.OpenFindings } }; Descending = $true }, Tier)[0]
    if ($null -eq $top) { return ('the CIs carry different tiers: ' + (@($m | ForEach-Object { '{0} {1}' -f (& $nm $_), (& $tw $_) }) -join ', ')) }
    if ($top.CiId -eq $most.CiId) {
        return ('the CIs carry different tiers: ' + (@($m | ForEach-Object { '{0} is {1} ({2})' -f (& $nm $_), (& $tw $_), (& $f $_) }) -join '; '))
    }
    ('{0} is on {1} ({2}); {3} ({4}) is {5}' -f (& $tw $top), (& $nm $top), (& $f $top), (& $nm $most), (& $f $most), (& $tw $most))
}

function Get-SICorrelationSuspectFieldLabel {
    <# PURE. One group in one line, every CI by name: "azvm-dc01 (Tier 0, 0 findings, leftover) + azvm-dc01.x (Tier 3, ...) -- <evidence>; <impact>". #>
    param($Group)
    $ci = @($Group.Members | ForEach-Object {
        $bits = @()
        if ($null -ne $_.Tier) { $bits += ('Tier ' + $_.Tier) } else { $bits += 'no tier' }
        if ($null -ne $_.OpenFindings) { $bits += ('{0} findings' -f (Format-SICorrelationSuspectCount $_.OpenFindings)) }
        if ($_.Role -eq 'leftover') { $bits += 'no source sees it any more' } elseif ($_.Role -eq 'unanchored') { $bits += 'no hard device id' }
        '{0} ({1})' -f $(if ($_.Name) { $_.Name } else { $_.CiId }), ($bits -join ', ')
    })
    if ([string]$Group.Rule -eq 'placeholder') {
        $withFindings = @($Group.Members | Where-Object { [int]$_.OpenFindings -gt 0 }).Count
        return ('{0}: {1} active device(s), {2} with findings' -f $Group.Label, (Format-SICorrelationSuspectCount @($Group.Members).Count), (Format-SICorrelationSuspectCount $withFindings))
    }
    $line = ($ci -join ' + ') + ' -- ' + [string]$Group.Evidence
    if ($Group.Impact) { $line += '; ' + [string]$Group.Impact }
    $line
}

function Get-SICorrelationSuspectMetrics {
    <# PURE. The run's key numbers (kind corr, never compared with earlier runs): groups per rule, of them with a tier conflict, dismissed. #>
    param([AllowEmptyCollection()][object[]]$Groups = @())
    $live = @($Groups | Where-Object { -not $_.Dismissed })
    $metric = { param($k, $l, $v) [pscustomobject]@{ Key = $k; Kind = 'corr'; Label = $l; Value = [double]$v; Step = 'asset-correlation' } }
    @(
        (& $metric 'corr.hardid' 'Correlation suspects: one hard id on two or more active CIs (groups)' @($live | Where-Object { $_.Rule -eq 'hardid' }).Count),
        (& $metric 'corr.name' 'Correlation suspects: the same name on 2-3 active server / VM CIs (groups)' @($live | Where-Object { $_.Rule -eq 'name' }).Count),
        (& $metric 'corr.placeholder' 'Correlation suspects: active devices with a placeholder name' (@($live | Where-Object { $_.Rule -eq 'placeholder' } | ForEach-Object { @($_.Members).Count }) | Measure-Object -Sum).Sum),
        (& $metric 'corr.tierconflict' 'Correlation suspects: groups whose CIs carry different tiers' @($live | Where-Object { $_.Severity -eq 'high' }).Count),
        (& $metric 'corr.dismissed' 'Correlation suspects: groups a person decided about' @($Groups | Where-Object { $_.Dismissed }).Count)
    )
}

function Find-SICorrelationSuspectAnomalies {
    <#
        PURE. ONE warning per rule that has a group nobody decided about yet (rule correlation-suspect, kind corr, from the
        first run on -- an absolute rule like "classification incomplete", never learning): Now = how many groups (placeholder:
        devices), Expected = 0, each group a field whose label names every CI, the evidence and the tier impact; the cause =
        the first groups in words. A rule without a group is no warning -- it clears itself.
    #>
    param([AllowEmptyCollection()][object[]]$Groups = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $script:SICorrelationSuspects.Rules.Keys) {
        $gs = @($Groups | Where-Object { $_ -and -not $_.Dismissed -and [string]$_.Rule -eq $rule })
        if (-not $gs.Count) { continue }
        $d = $script:SICorrelationSuspects.Rules[$rule]
        $now = if ($rule -eq 'placeholder') { [double](@($gs | ForEach-Object { @($_.Members).Count }) | Measure-Object -Sum).Sum } else { [double]$gs.Count }
        $fields = @(foreach ($g in $gs) {
            $n = if ($rule -eq 'placeholder') { [double]@($g.Members).Count } else { [double]@($g.Members).Count }
            [pscustomobject]@{ Key = ('corr.{0}.{1}' -f $rule, $g.GroupKey); Kind = 'corr'; Label = (Get-SICorrelationSuspectFieldLabel $g); Earlier = @(); Expected = 0.0; Now = $n; ChangePct = $n }
        })
        $high = @($gs | Where-Object { $_.Severity -eq 'high' }).Count
        $named = @($fields | Select-Object -First 3 | ForEach-Object { $_.Label })
        $more = $fields.Count - $named.Count
        $cause = ($named -join ' | ') + $(if ($more -gt 0) { (' | and {0} more' -f $more) } else { '' })
        if ($high -gt 0) { $cause = ('{0} of them carry different tiers -- the most critical tier may sit on the wrong CI. ' -f $high) + $cause }
        $out.Add([pscustomobject]@{
            Key = ('corr.' + $rule); Kind = 'corr'; Label = [string]$d.Label; Step = 'asset-correlation'; Rule = 'correlation-suspect'
            Direction = 'rise'; Earlier = @(); Expected = 0.0; Now = $now; ChangePct = $now; Cause = $cause; CauseChangeIds = @(); Fields = $fields
        })
    }
    @($out | Sort-Object @{ Expression = { if ($_.Key -eq 'corr.hardid') { 0 } elseif ($_.Key -eq 'corr.name') { 1 } else { 2 } } })
}

function Get-SICorrelationSuspectIssue {
    <#
        PURE. The run's ONE warning for the status (the run's issues -> the telemetry -> Invardia): COUNTS ONLY -- no CI, no
        name, no id ever leaves the install. '' when nothing is suspected.
    #>
    param([AllowEmptyCollection()][object[]]$Groups = @())
    $live = @($Groups | Where-Object { $_ -and -not $_.Dismissed })
    if (-not $live.Count) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    $hard = @($live | Where-Object { $_.Rule -eq 'hardid' }); $name = @($live | Where-Object { $_.Rule -eq 'name' }); $ph = @($live | Where-Object { $_.Rule -eq 'placeholder' })
    if ($hard.Count) { $parts.Add(('{0} hard id(s) on two or more active CIs' -f (Format-SICorrelationSuspectCount $hard.Count))) }
    if ($name.Count) { $parts.Add(('{0} likely duplicate machine(s) by name' -f (Format-SICorrelationSuspectCount $name.Count))) }
    if ($ph.Count) { $parts.Add(('{0} device(s) with a placeholder name' -f (Format-SICorrelationSuspectCount ((@($ph | ForEach-Object { @($_.Members).Count }) | Measure-Object -Sum).Sum)))) }
    $high = @($live | Where-Object { $_.Severity -eq 'high' }).Count
    $text = 'correlation suspects: ' + ($parts -join ', ')
    if ($high) { $text += (' ({0} with different tiers in one group)' -f (Format-SICorrelationSuspectCount $high)) }
    $text + ' -- Data quality > Correlation suspects names them; a warning only, nothing was blocked'
}

function Get-SICorrelationSuspectLines {
    <# PURE. The run log's lines: one per rule with groups, high-severity groups first, each named. #>
    param([AllowEmptyCollection()][object[]]$Groups = @())
    $live = @($Groups | Where-Object { $_ -and -not $_.Dismissed })
    @(foreach ($g in $live) { 'correlation suspect ({0}, {1}): {2}' -f $g.Rule, $g.Severity, (Get-SICorrelationSuspectFieldLabel $g) })
}

# =====================================================================================================================
#  The other CI of each suspect, for the correlation evidence ("Possible duplicate" on Correlation quality)
# =====================================================================================================================
function Get-SICorrelationSuspectMapSql {
    <# PURE. Per CI of a group nobody decided about (rules hardid / name): the first other CI of its group. No table = no row. #>
@'
IF OBJECT_ID(N'sidata.CiSuspect') IS NULL
    SELECT CAST(NULL AS NVARCHAR(64)) AS CiId, CAST(NULL AS NVARCHAR(64)) AS OtherCiId, CAST(NULL AS NVARCHAR(400)) AS OtherName WHERE 1 = 0;
ELSE
    SELECT a.CiId, o.CiId AS OtherCiId, o.Name AS OtherName
    FROM sidata.CiSuspect a
    CROSS APPLY (SELECT TOP (1) b.CiId, b.Name FROM sidata.CiSuspect b WHERE b.GroupKey = a.GroupKey AND b.CiId <> a.CiId ORDER BY b.Tier, b.CiId) o
    WHERE a.[Rule] IN (N'hardid', N'name') AND a.Dismissed = 0;
'@
}

function ConvertTo-SICorrelationSuspectMap {
    <# PURE. The map rows -> CI id (lower case) -> @{ OtherCiId; OtherName }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($r in @($Rows)) {
        $c = [string](Get-SICorrelationSuspectValue $r 'CiId'); if (-not $c) { continue }
        $k = $c.ToLowerInvariant()
        if ($map.ContainsKey($k)) { continue }
        $map[$k] = [pscustomobject]@{ OtherCiId = [string](Get-SICorrelationSuspectValue $r 'OtherCiId'); OtherName = [string](Get-SICorrelationSuspectValue $r 'OtherName') }
    }
    $map
}

# =====================================================================================================================
#  The step -- NEVER throws, never blocks
# =====================================================================================================================
function Read-SICorrelationSuspectRows {
    <# The rows of a 'reader' statement, one by one (the Pro database seam answers them as ONE array: unrolled one level). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    $out = & $Invoke $Sql $Params 'reader'
    foreach ($x in @($out)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IList] -and -not ($x -is [string])) { foreach ($y in $x) { if ($null -ne $y) { $y } } }
        else { $x }
    }
}

function Invoke-SICorrelationSuspects {
    <#
        Runs the gatekeeper once: the lists, the statement (replacing sidata.CiSuspect unless -DryRun), the groups, the
        metrics, the warnings and the run's one count-only warning. -Invoke: the data database ({ param($sql, $params, $mode) }).
        -Lists: the merged lists (a test seam). Returns @{ Status (ok | no-tables | no-schema | failed); Groups; Metrics;
        Anomalies; Issue; Lines; Seconds; Problem }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log = { param($l, $m) }, $Lists, [string]$DataModelRoot)
    $res = [ordered]@{ Status = ''; Groups = @(); Metrics = @(); Anomalies = @(); Issue = ''; Lines = @(); Seconds = 0.0; Problem = '' }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $cols = @(Read-SICorrelationSuspectRows -Invoke $Invoke -Sql (Get-SICorrelationSuspectColumnsSql)) | Select-Object -First 1
        if ($null -eq $cols -or [int](Get-SICorrelationSuspectValue $cols 'HasCi') -ne 1) {
            $res.Status = 'no-tables'; & $Log 'INFO' 'correlation suspects: no CIs in this database yet -- nothing to check'
            return [pscustomobject]$res
        }
        $write = -not $DryRun
        if ([int](Get-SICorrelationSuspectValue $cols 'HasSuspect') -ne 1) {
            $write = $false
            & $Log 'INFO' 'correlation suspects: the table for them is not in the database yet (setup and the updater apply sql\si-data-schema.sql) -- checked, not stored'
            $res.Status = 'no-schema'
        }
        $lists = Get-SICorrelationSuspectLists -Lists $Lists -Root $DataModelRoot
        $sql = Get-SICorrelationSuspectSql -HasOsFamily:([int](Get-SICorrelationSuspectValue $cols 'HasOsFamily') -eq 1) `
            -HasHostname:([int](Get-SICorrelationSuspectValue $cols 'HasHostname') -eq 1) -HasDecision:([int](Get-SICorrelationSuspectValue $cols 'HasDecision') -eq 1)
        $p = @{
            Generic     = (ConvertTo-Json -InputObject @($lists.Generic) -Compress)
            Placeholder = (ConvertTo-Json -InputObject @($lists.Placeholder) -Compress)
            Write       = $(if ($write) { 1 } else { 0 })
        }
        $rows = @(Read-SICorrelationSuspectRows -Invoke $Invoke -Sql $sql -Params $p)
        $groups = @(ConvertTo-SICorrelationSuspectGroups -Rows $rows)
        $res.Groups = $groups
        $res.Metrics = @(Get-SICorrelationSuspectMetrics -Groups $groups)
        $res.Anomalies = @(Find-SICorrelationSuspectAnomalies -Groups $groups)
        $res.Issue = Get-SICorrelationSuspectIssue -Groups $groups
        $res.Lines = @(Get-SICorrelationSuspectLines -Groups $groups)
        if (-not $res.Status) { $res.Status = 'ok' }
        $sw.Stop(); $res.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        $live = @($groups | Where-Object { -not $_.Dismissed })
        if ($live.Count) {
            & $Log 'WARN' ('correlation suspects: {0} group(s) to look at ({1} s) -- a warning only, nothing was blocked; Data quality > Correlation suspects' -f $live.Count, $res.Seconds)
            foreach ($l in $res.Lines) { & $Log 'WARN' ('  ' + $l) }
        } else {
            & $Log 'OK' ('correlation suspects: none ({0} group(s) decided by a person; {1} s)' -f @($groups | Where-Object { $_.Dismissed }).Count, $res.Seconds)
        }
    } catch {
        $res.Status = 'failed'; $res.Problem = $_.Exception.Message
        & $Log 'WARN' ('correlation suspects: not checked this run -- {0}. Nothing was blocked.' -f $_.Exception.Message)
    }
    [pscustomobject]$res
}
