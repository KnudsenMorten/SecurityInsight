#Requires -Version 5.1
<#
    SecurityInsight Pro -- the v3 DATA MODEL in the Pro database (V3-DATA-MODEL part 2, 2.3 / M5). The CI build writes the
    CIs, their links, the daily trend row and the provider records to these tables ITSELF (engine/data-model, #477:
    "we dont support la for correlation, sql only") -- the data sync reads NO records and NO CIs from Log Analytics. What
    is left here: the findings per CI (SI_Finding_CL, Risk Analysis's output) into sidata.CiFinding, then the CIs' finding
    totals (risk score, weighted score, open findings) set-based in SQL.

      sidata.Ci          the CURRENT CI (one row per CI id, upserted): the columns the grids filter and sort on + DocJson,
                         the whole CI document (resolved fields, tier claims, field sources, risk factors, criticality)
      sidata.CiLink      the CI's linked objects (provider, type, native id, primary, state, last seen) -- replaced per CI
      sidata.CiFinding   the findings of the NEWEST finding collection (one row per CI and finding key) -- replaced when a
                         newer collection arrives
      sidata.CiDaily     one narrow row per CI per day: tier, risk score, weighted score, open findings -- the trend (kept 13
                         months by default: SI_Pro_CiDailyRetentionDays)
      sidata.CiRecord    the CURRENT provider records (one row per record key) + DocJson -- the Raw view
      sidata.CiLoad      what was loaded, per kind and collection time -- a re-run loads nothing twice

    The tables are ADDITIVE (created here when missing; sql/si-data-schema.sql carries the same statements for a new install).
    Never fails the data sync: a failure is said and the findings load is not affected.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

function Get-SIDataCiTablesSql {
    <# The v3 tables, created when missing (idempotent, additive only). #>
    @'
IF SCHEMA_ID('sidata') IS NULL EXEC ('CREATE SCHEMA sidata');
IF OBJECT_ID('sidata.Ci') IS NULL
CREATE TABLE sidata.Ci (
    CiId              NVARCHAR(64)   NOT NULL CONSTRAINT PK_Ci PRIMARY KEY,
    Class             NVARCHAR(16)   NULL,
    Name              NVARCHAR(400)  NULL,
    AssetType         NVARCHAR(128)  NULL,
    Tier              TINYINT        NULL,
    TierSetBy         NVARCHAR(16)   NULL,
    TierReason        NVARCHAR(512)  NULL,
    Lifecycle         NVARCHAR(16)   NULL,
    InternetExposed   BIT            NULL,
    CmdbId            NVARCHAR(256)  NULL,
    CmdbName          NVARCHAR(400)  NULL,
    CmdbCriticality   NVARCHAR(64)   NULL,
    CriticalityFactor FLOAT          NULL,
    RiskFactors       NVARCHAR(1000) NULL,
    LinkCount         INT            NULL,
    RiskScore         FLOAT          NULL,
    WeightedRiskScore FLOAT          NULL,
    OpenFindings      INT            NULL,
    LastSeen          DATETIME2(3)   NULL,
    CollectionTime    DATETIME2(3)   NOT NULL,
    DocJson           NVARCHAR(MAX)  NULL,
    UpdatedAt         DATETIME2(0)   NOT NULL CONSTRAINT DF_Ci_UpdatedAt DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_Grid' AND object_id = OBJECT_ID('sidata.Ci'))
CREATE INDEX IX_Ci_Grid ON sidata.Ci (Class, Tier, Lifecycle) INCLUDE (Name, AssetType, WeightedRiskScore, OpenFindings, LastSeen);
IF OBJECT_ID('sidata.CiLink') IS NULL
CREATE TABLE sidata.CiLink (
    CiId        NVARCHAR(64)   NOT NULL,
    Provider    NVARCHAR(32)   NOT NULL,
    RecordType  NVARCHAR(32)   NOT NULL,
    NativeId    NVARCHAR(450)  NOT NULL,
    IsPrimary   BIT            NOT NULL,
    State       NVARCHAR(16)   NULL,
    LastSeen    DATETIME2(3)   NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_CiLink' AND object_id = OBJECT_ID('sidata.CiLink'))
CREATE CLUSTERED INDEX CX_CiLink ON sidata.CiLink (CiId, Provider);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiLink_Native' AND object_id = OBJECT_ID('sidata.CiLink'))
CREATE INDEX IX_CiLink_Native ON sidata.CiLink (NativeId) INCLUDE (CiId, Provider);
IF OBJECT_ID('sidata.CiFinding') IS NULL
CREATE TABLE sidata.CiFinding (
    CiFindingId       BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CiFinding PRIMARY KEY NONCLUSTERED,
    CiId              NVARCHAR(64)   NULL,
    AssetId           NVARCHAR(400)  NULL,
    FindingKey        NVARCHAR(256)  NOT NULL,
    FindingType       NVARCHAR(32)   NULL,
    Title             NVARCHAR(1000) NULL,
    Severity          NVARCHAR(16)   NULL,
    Tier              TINYINT        NULL,
    RiskScore         FLOAT          NULL,
    WeightedRiskScore FLOAT          NULL,
    RiskRating        NVARCHAR(16)   NULL,
    SecurityDomain    NVARCHAR(64)   NULL,
    DetectedBy        NVARCHAR(2000) NULL,
    RiskFactors       NVARCHAR(2000) NULL,
    ExemptionId       NVARCHAR(64)   NULL,
    CollectionTime    DATETIME2(3)   NOT NULL,
    DocJson           NVARCHAR(MAX)  NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_CiFinding' AND object_id = OBJECT_ID('sidata.CiFinding'))
CREATE CLUSTERED INDEX CX_CiFinding ON sidata.CiFinding (CiId, FindingKey);
IF COL_LENGTH('sidata.CiFinding', 'Component') IS NULL
BEGIN
    ALTER TABLE sidata.CiFinding ADD Component NVARCHAR(64) NULL;
    -- #881 the findings already stored get it from their own row in the data sync, a CiFindingId range at a time
    -- (Invoke-SIDataCiColumnBackfill) -- never one statement over the whole table here
    PRINT 0;
END
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_Component' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_Component ON sidata.CiFinding (Component) INCLUDE (CiId, FindingKey)');
-- #772 the finding's ServiceNow sub-CI (si_servicenow_subci: OS / SQL / Other, the customer's buckets): a column of its own
IF COL_LENGTH('sidata.CiFinding', 'SubCi') IS NULL
BEGIN
    ALTER TABLE sidata.CiFinding ADD SubCi NVARCHAR(64) NULL;
    -- #881 the findings already stored get it from their own row in the data sync, a CiFindingId range at a time
    -- (Invoke-SIDataCiColumnBackfill) -- never one statement over the whole table here
    PRINT 0;
END
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_SubCi' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_SubCi ON sidata.CiFinding (SubCi) INCLUDE (CiId, FindingKey)');
-- #772 the finding's patch cycle (si_patch_cycle): a column of its own
IF COL_LENGTH('sidata.CiFinding', 'PatchCycle') IS NULL
BEGIN
    ALTER TABLE sidata.CiFinding ADD PatchCycle NVARCHAR(64) NULL;
    -- #881 the findings already stored get it from their own row in the data sync, a CiFindingId range at a time
    -- (Invoke-SIDataCiColumnBackfill) -- never one statement over the whole table here
    PRINT 0;
END
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_PatchCycle' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_PatchCycle ON sidata.CiFinding (PatchCycle) INCLUDE (CiId, FindingKey)');
-- #772 the CVE's published date (si_cve_published: exposure age), typed
IF COL_LENGTH('sidata.CiFinding', 'CvePublished') IS NULL
    ALTER TABLE sidata.CiFinding ADD CvePublished DATETIME2(3) NULL;
-- the content hash (the schema file adds it; here only where this identity may -- without it the swap writes as before)
IF COL_LENGTH('sidata.CiFinding', 'ContentHash') IS NULL
BEGIN TRY ALTER TABLE sidata.CiFinding ADD ContentHash BINARY(32) NULL; END TRY BEGIN CATCH END CATCH
IF OBJECT_ID('sidata.CiDaily') IS NULL
CREATE TABLE sidata.CiDaily (
    [Day]             DATE           NOT NULL,
    CiId              NVARCHAR(64)   NOT NULL,
    Tier              TINYINT        NULL,
    RiskScore         FLOAT          NULL,
    WeightedRiskScore FLOAT          NULL,
    OpenFindings      INT            NULL,
    CONSTRAINT PK_CiDaily PRIMARY KEY CLUSTERED ([Day], CiId)
);
IF OBJECT_ID('sidata.CiRecord') IS NULL
CREATE TABLE sidata.CiRecord (
    RecordKey         NVARCHAR(450)  NOT NULL CONSTRAINT PK_CiRecord PRIMARY KEY,
    CiId              NVARCHAR(64)   NULL,
    Provider          NVARCHAR(32)   NOT NULL,
    RecordType        NVARCHAR(32)   NULL,
    Class             NVARCHAR(16)   NULL,
    Name              NVARCHAR(400)  NULL,
    SourceLastSeen    DATETIME2(3)   NULL,
    CollectionTime    DATETIME2(3)   NOT NULL,
    Complete          BIT            NULL,
    DocJson           NVARCHAR(MAX)  NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRecord_Provider' AND object_id = OBJECT_ID('sidata.CiRecord'))
CREATE INDEX IX_CiRecord_Provider ON sidata.CiRecord (Provider, RecordType) INCLUDE (CiId, Name, SourceLastSeen);
IF OBJECT_ID('sidata.CiLoad') IS NULL
CREATE TABLE sidata.CiLoad (
    Kind            NVARCHAR(16)   NOT NULL,
    CollectionTime  DATETIME2(3)   NOT NULL,
    [Rows]          INT            NOT NULL,
    LoadedAt        DATETIME2(0)   NOT NULL CONSTRAINT DF_CiLoad_LoadedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_CiLoad PRIMARY KEY (Kind, CollectionTime)
);
SELECT 1;
'@
}

# THE NEWEST FINDING COLLECTION IS READ IN PAGES, COUNTED AND STAGED (#639, owner 2026-10-13: "we can NOT loose data").
# It was read as ONE answer, held whole with a JSON copy of every row, and its lifecycle input went to SQL as ONE JSON
# string -- at a large install (33,000-69,000 finding rows, 8 GiB per job) the store timed out, and nothing compared the
# rows read with the rows Log Analytics holds, so a cut answer could have replaced the stored findings with a part of them
# and the lifecycle could have counted the rest absent. Now: one small count query pins the collection (its time as text,
# its row count, its measured size); its rows are read a page at a time by a hash of their own key (_pk) exactly as the
# findings load reads a collection (Read-SIDataPages: a page too large to answer or to hold is read again in two halves);
# each page is staged in SQL (the findings and the lifecycle input, in chunks) before the next is read; and only when the
# rows read equal the collection's count are the stored findings replaced (one transaction) and the lifecycle advanced.
function Get-SIDataCiFindingCountKql {
    <#
        PURE. The newest finding collection, PINNED: its time as text (CollectionTimeText -- the page queries match it as
        text, so a newer collection arriving while the pages are read cannot mix in), its row count and its measured size.
        #829 LastIngest: when its newest row reached Log Analytics -- a collection still arriving is never read
        (Test-SIDataCiFindingCopySettled). No collection: Rows 0.
    #>
    param([int]$LookbackDays = 8)
    @"
let _t = toscalar(SI_Finding_CL | where TimeGenerated > ago(${LookbackDays}d) | summarize max(si_collection_time));
SI_Finding_CL
| where TimeGenerated > ago(${LookbackDays}d) and si_collection_time == _t
| summarize Rows = count(), Bytes = sum(estimate_data_size(*)), CollectionTimeText = tostring(take_any(si_collection_time)), LastIngest = tostring(max(ingestion_time()))
"@
}

function Get-SIDataCiFindingPageKql {
    <#
        PURE. ONE PAGE of the pinned finding collection: the rows whose own key (_pk: the row's _ItemId, its CI and its
        finding key) falls in the page's hash cuts (Get-SIDataPageFilter -- the findings load's own paging). Every column of
        the row comes back as stored (the stored finding keeps the whole row as its document); the paging key is projected
        away. -CountOnly: how many rows the page holds and whether one key is all it holds (Read-SIDataPages splits a page
        that is too large, and stops on a single row that is).
    #>
    param([Parameter(Mandatory)][string]$CollectionTimeText, [int]$LookbackDays = 8, [string]$PageFilter = '', [switch]$CountOnly)
    $t = $CollectionTimeText.Replace('\', '\\').Replace('"', '\"')
    $head = @"
SI_Finding_CL
| where TimeGenerated > ago(${LookbackDays}d)
| where tostring(si_collection_time) == "$t"
| extend _pk = strcat(tostring(_ItemId), "|", tostring(column_ifexists("si_ci_id", "")), "|", tostring(column_ifexists("si_finding_key", "")))
$PageFilter
"@
    if ($CountOnly) { return ($head + "`n| summarize PageRows = count(), KeyMin = min(_pk), KeyMax = max(_pk)`n| project PageRows, OneKey = (KeyMin == KeyMax)") }
    $head + "`n| project-away _pk"
}

function ConvertTo-SIDataCiFindingItem {
    <# PURE. One SI_Finding_CL row -> the stored-finding item (sidata.CiFinding's columns + the lifecycle's fields). #>
    param([Parameter(Mandatory)]$Row)
    $f = $Row
    [ordered]@{ CiId = [string]$f.si_ci_id; AssetId = [string]$f.si_asset_id; FindingKey = [string]$f.si_finding_key; FindingType = [string]$f.si_finding_type
        Title = [string]$f.si_title; Severity = [string]$f.si_severity; Tier = $f.si_tier; RiskScore = $f.si_risk_score; WeightedRiskScore = $f.si_weighted_risk_score
        RiskRating = [string]$f.si_risk_rating; SecurityDomain = [string]$f.si_security_domain
        DetectedBy = ((@(ConvertTo-SIDataCiJsonValue $f.si_detected_by) | ForEach-Object { [string]$_ }) -join '; ')
        RiskFactors = ((@(ConvertTo-SIDataCiJsonValue $f.si_finding_risk_factors) | ForEach-Object { [string]$_ }) -join ';')
        # #464 the providers' own keys of a finding merged by the recommendation equivalence (the lifecycle carries them)
        Aliases = ((@(ConvertTo-SIDataCiJsonValue $f.si_finding_aliases) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ';')
        ExemptionId = [string]$f.si_exemption_id; CollectionTime = [string]$f.si_collection_time; Component = [string]$f.si_component
        SubCi = [string]$f.si_servicenow_subci; PatchCycle = [string]$f.si_patch_cycle; CvePublished = [string]$f.si_cve_published; DocJson = ($f | ConvertTo-Json -Compress -Depth 8) }
}

function Get-SIDataCiLifecycleStageCheckSql {
    <# 1 when the database has the lifecycle input's staging table (sidata.CiFindingLifecycleStage), else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.CiFindingLifecycleStage') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCiLifecycleStageSql {
    <#
        One chunk of the lifecycle input into sidata.CiFindingLifecycleStage (-First empties it). -Kind f: @j = findings
        (ConvertTo-SIDataFindingStateItems: OwnerKey, FindingKey, CiId, Severity, DetectedBy, ExemptionId); -Kind a: @j =
        the equivalence's key changes (ConvertTo-SIDataFindingAliasItems: o, a, c). Answers the rows staged.
    #>
    param([ValidateSet('f', 'a')][string]$Kind = 'f', [switch]$First)
    $clear = ''; if ($First) { $clear = 'DELETE FROM sidata.CiFindingLifecycleStage;' }
    if ($Kind -eq 'a') {
        return @"
SET XACT_ABORT ON;
$clear
INSERT sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey, Canonical)
SELECT N'a', LEFT(x.o, 450), LEFT(x.a, 256), LEFT(x.c, 256)
FROM OPENJSON(@j) WITH (o NVARCHAR(MAX), a NVARCHAR(MAX), c NVARCHAR(MAX)) x
WHERE x.o IS NOT NULL AND x.a IS NOT NULL AND x.c IS NOT NULL;
SELECT @@ROWCOUNT;
"@
    }
    @"
SET XACT_ABORT ON;
$clear
INSERT sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey, CiId, Severity, DetectedBy, ExemptionId)
SELECT N'f', LEFT(x.OwnerKey, 450), LEFT(x.FindingKey, 256), NULLIF(LEFT(x.CiId, 64), N''), LEFT(x.Severity, 16), LEFT(x.DetectedBy, 2000), LEFT(x.ExemptionId, 64)
FROM OPENJSON(@j) WITH (OwnerKey NVARCHAR(MAX), FindingKey NVARCHAR(MAX), CiId NVARCHAR(MAX), Severity NVARCHAR(MAX), DetectedBy NVARCHAR(MAX), ExemptionId NVARCHAR(MAX)) x
WHERE x.OwnerKey IS NOT NULL AND x.FindingKey IS NOT NULL;
SELECT @@ROWCOUNT;
"@
}

function Get-SIDataCiLifecycleStageClearSql { 'DELETE FROM sidata.CiFindingLifecycleStage; SELECT 1;' }

function Write-SIDataCiLifecycleStage {
    <#
        Stages the lifecycle input of -Items (stored-finding items) in chunks: the findings (Kind f), then the equivalence's
        key changes (Kind a). -First empties the staging table first. Returns @{ Findings; Aliases } (rows staged).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][object[]]$Items = @(), [bool]$First = $false)
    if (-not (Get-Command -Name ConvertTo-SIDataFindingStateItems -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataCiLifecycle.ps1') }
    $st = @(ConvertTo-SIDataFindingStateItems -Items @($Items))
    $al = @(ConvertTo-SIDataFindingAliasItems -Items @($Items))
    $nF = 0; $nA = 0
    if ($First) { Clear-SIDataCiStage -Invoke $Invoke -Table 'sidata.CiFindingLifecycleStage' }
    if ($st.Count) { $nF = Invoke-SIDataCiChunks -Invoke $Invoke -Sql { param($first) Get-SIDataCiLifecycleStageSql -Kind f } -Items $st }
    if ($al.Count) { $nA = Invoke-SIDataCiChunks -Invoke $Invoke -Sql { param($first) Get-SIDataCiLifecycleStageSql -Kind a } -Items $al }
    [pscustomobject]@{ Findings = $nF; Aliases = $nA }
}

function ConvertTo-SIDataCiJsonValue {
    <# PURE. A Log Analytics cell that holds JSON text (dynamic) -> its object; anything else as it is. #>
    param($Value)
    if ($Value -is [string]) { $s = $Value.Trim(); if ($s.StartsWith('[') -or $s.StartsWith('{')) { try { return ($s | ConvertFrom-Json) } catch { } } }
    return $Value
}

function Get-SIDataWriteCiFindingSql {
    <#
        The newest finding collection replaces the stored one (first chunk: -First clears). @j = findings.
        EVERY FINDING ON ITS CI (ring 1 2026-10-11: CiId was EMPTY on every stored finding -- Risk Analysis's rows carry the
        CI's id as their asset id, and an empty string is not NULL, so nothing below ever filled it): the CiId is the
        finding's own si_ci_id when it has one, else the CI whose id IS the asset id, else the CI the asset id is a linked
        object of (sidata.CiLink -- a Defender for Endpoint / Entra / Azure id, an Azure child resource's id: its parent CI).
        An empty CiId is stored as NULL, never as ''.
        The finding's component (si_component: OS, SQL, ...) is stored as a column of its own -- the Findings per CI view
        filters on it; a finding without one is stored as NULL, never as ''. -SubCi (#772): so is its ServiceNow sub-CI
        (si_servicenow_subci), when the database has the column (Get-SIDataCiFindingSubCiCheckSql).
    #>
    param(
        [switch]$First,
        [switch]$SubCi,
        # the rows go to the staging table (sidata.CiFindingStage; -First empties IT) and reach sidata.CiFinding in ONE step
        # afterwards (Get-SIDataCiFindingSwapSql) -- the stored findings stay whole while the new ones are written
        [switch]$Stage,
        # #636: the finding's category and subcategory as columns of their own (the Domain > Category > Subcategory filter),
        # from its si_category / si_subcategory, else Category / Subcategory -- only on a database that has the columns
        [switch]$Category
    )
    $table = 'sidata.CiFinding'; if ($Stage) { $table = 'sidata.CiFindingStage' }
    $clear = ''; if ($First) { $clear = "DELETE FROM $table;" }
    $sc = ''; $sv = ''; $sw = ''
    if ($SubCi) {
        # #772 the sub-CI and the patch cycle travel together (one schema update adds both)
        $sc = ', SubCi, PatchCycle, CvePublished'; $sv = ", NULLIF(LEFT(LTRIM(RTRIM(x.SubCi)), 64), N''), NULLIF(LEFT(LTRIM(RTRIM(x.PatchCycle)), 64), N''), TRY_CONVERT(datetime2(3), LEFT(x.CvePublished, 23), 127)"; $sw = ', SubCi nvarchar(max), PatchCycle nvarchar(max), CvePublished nvarchar(64)'
    }
    $catCols = ''; $catVals = ''
    if ($Category) {
        $catCols = ', Category, Subcategory'
        $catVals = ", CASE WHEN ISJSON(x.DocJson) = 1 THEN NULLIF(LEFT(LTRIM(RTRIM(COALESCE(NULLIF(JSON_VALUE(x.DocJson, '$.si_category'), N''), JSON_VALUE(x.DocJson, '$.Category')))), 256), N'') END" +
                   ", CASE WHEN ISJSON(x.DocJson) = 1 THEN NULLIF(LEFT(LTRIM(RTRIM(COALESCE(NULLIF(JSON_VALUE(x.DocJson, '$.si_subcategory'), N''), JSON_VALUE(x.DocJson, '$.Subcategory')))), 256), N'') END"
    }
    @"
SET XACT_ABORT ON;
BEGIN TRAN;
$clear
INSERT $table (CiId, AssetId, FindingKey, FindingType, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, ExemptionId, CollectionTime, DocJson, Component$sc$catCols)
SELECT COALESCE(NULLIF(LTRIM(RTRIM(x.CiId)), N''), ci.CiId, lk.CiId), LEFT(x.AssetId, 400), LEFT(x.FindingKey, 256), x.FindingType, LEFT(x.Title, 1000), x.Severity, CASE WHEN x.Tier BETWEEN 0 AND 255 THEN x.Tier END, x.RiskScore,
       x.WeightedRiskScore, x.RiskRating, x.SecurityDomain, LEFT(x.DetectedBy, 2000), LEFT(x.RiskFactors, 2000), x.ExemptionId,
       ISNULL(TRY_CONVERT(datetime2(3), x.CollectionTime, 127), SYSUTCDATETIME()), x.DocJson, NULLIF(LEFT(LTRIM(RTRIM(x.Component)), 64), N'')$sv$catVals
FROM OPENJSON(@j) WITH (CiId nvarchar(64), AssetId nvarchar(max), FindingKey nvarchar(max), FindingType nvarchar(32), Title nvarchar(max), Severity nvarchar(16), Tier int,
     RiskScore float, WeightedRiskScore float, RiskRating nvarchar(16), SecurityDomain nvarchar(64), DetectedBy nvarchar(max), RiskFactors nvarchar(max), ExemptionId nvarchar(64),
     CollectionTime nvarchar(64), DocJson nvarchar(max), Component nvarchar(max)$sw) x
OUTER APPLY (SELECT TOP (1) c.CiId FROM sidata.Ci c WHERE NULLIF(LTRIM(RTRIM(x.CiId)), N'') IS NULL AND LEN(x.AssetId) BETWEEN 1 AND 64 AND c.CiId = x.AssetId) ci
OUTER APPLY (SELECT TOP (1) l.CiId FROM sidata.CiLink l
             WHERE NULLIF(LTRIM(RTRIM(x.CiId)), N'') IS NULL AND ci.CiId IS NULL AND LEN(x.AssetId) BETWEEN 1 AND 450 AND l.NativeId = LOWER(x.AssetId)
             ORDER BY l.IsPrimary DESC, CASE WHEN l.State IN (N'active', N'frozen') THEN 0 ELSE 1 END, l.LastSeen DESC) lk
WHERE x.FindingKey IS NOT NULL;
DECLARE @n INT = @@ROWCOUNT;
COMMIT;
SELECT @n;
"@
}

# THE FINDINGS PER CI ARE REPLACED IN ONE STEP (2026-10-12): the newest finding collection used to be written straight into
# sidata.CiFinding -- emptied by the first chunk, refilled chunk by chunk -- so "Findings per CI" showed a partial list for
# a minute or two, and every chunk was another change the web app's kept pages were dropped for. Now the chunks go to a
# staging table and ONE transaction replaces the stored set from it. Why this and not a rename or a partition switch: those
# need rights to change the schema, which the data sync's identity does not have (and must not get), and a rename also
# carries the indexes' names and every cached plan with it. DELETE + INSERT ... SELECT in one transaction keeps the table,
# its five indexes and its rights as they are; a reader sees the whole old set until the commit and the whole new set
# after it (Azure SQL reads committed row versions, so a reader does not even wait), and anything that fails inside it
# rolls back to the old set. Its cost is the log of one delete and one insert of the set -- what the chunks wrote before,
# in one piece, without the JSON parsing and the CI lookups (those are done while staging).
$script:SIDataCiFindingColumns = 'CiId, AssetId, FindingKey, FindingType, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, ExemptionId, CollectionTime, DocJson, Component'

function Get-SIDataCiFindingStageCheckSql {
    <# 1 when the database has the staging table (the schema of this release) and sidata.CiFinding its component column, else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.CiFindingStage') IS NOT NULL AND COL_LENGTH('sidata.CiFindingStage', 'Component') IS NOT NULL AND COL_LENGTH('sidata.CiFinding', 'Component') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCiFindingSubCiCheckSql {
    <# #772: 1 when sidata.CiFinding and its staging table both carry the ServiceNow sub-CI and patch cycle columns, else 0 (written without them). #>
    "SELECT CASE WHEN COL_LENGTH('sidata.CiFinding', 'SubCi') IS NOT NULL AND COL_LENGTH('sidata.CiFindingStage', 'SubCi') IS NOT NULL AND COL_LENGTH('sidata.CiFinding', 'PatchCycle') IS NOT NULL AND COL_LENGTH('sidata.CiFindingStage', 'PatchCycle') IS NOT NULL AND COL_LENGTH('sidata.CiFinding', 'CvePublished') IS NOT NULL AND COL_LENGTH('sidata.CiFindingStage', 'CvePublished') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCiFindingRunFields {
    <#
        PURE. The fields of a stored finding's DOCUMENT (DocJson) that every run moves -- left out of its content hash, so a
        finding seen again with the same data is not rewritten (2026-10-25, owner: "for data only as things like
        collectiontime field will chg every run"). The database path's document carries si_collection_time; the Log Analytics
        path's (the SI_Finding_CL row as it came) also the ingest columns. A field missing here only costs speed (the row looks
        changed and is replaced, as before); a field here that is real data cannot lose anything either: the document of a
        finding that keeps its row is always written from the new one (Get-SIDataCiFindingSwapSql).
    #>
    @('si_collection_time', 'TimeGenerated', '_TimeReceived', '_ItemId', '_BilledSize')
}

function Get-SIDataCiFindingHashSql {
    <#
        PURE. The SQL of one row's hash over the moved columns (-Names) of the row alias -Alias. Answers @{ Apply; Expr }:
        Expr is the SHA-256 (every column NULL-marked and length-prefixed, as bytes); Apply is the CROSS APPLY chain it reads
        (empty for -All). -All: EVERY moved column (the one swap of before, #834: a row identical in every column). Else the
        CONTENT HASH: every moved column but CollectionTime, and the document with its run fields (Get-SIDataCiFindingRunFields)
        taken out -- top-level keys only, only when its text names them, only when it is JSON; the document comes last.
    #>
    param([Parameter(Mandatory)][string]$Alias, [Parameter(Mandatory)][string[]]$Names, [switch]$All)
    $part = { param([string]$c) 'CASE WHEN {0}.[{1}] IS NULL THEN 0x00 ELSE 0x01 + CAST(DATALENGTH({0}.[{1}]) AS binary(4)) + CAST({0}.[{1}] AS varbinary(max)) END' -f $Alias, $c }
    if ($All) { return @{ Apply = ''; Expr = 'HASHBYTES(''SHA2_256'', ' + ((@($Names | ForEach-Object { & $part $_ })) -join ' + ') + ')' } }
    $cols = @($Names | Where-Object { $_ -notin 'CollectionTime', 'DocJson' })
    # each level names the one before it twice at most (the optimizer inlines the chain: a level that named it more often made
    # the expression grow past SQL Server's limit) -- whether the document is JSON and names the field is read from the
    # document itself (taking a field out never adds one)
    $doc0 = '{0}.[DocJson]' -f $Alias
    $apply = New-Object System.Text.StringBuilder
    [void]$apply.Append((' CROSS APPLY (SELECT CASE WHEN {0} IS NULL THEN 0 ELSE ISJSON({0}) END AS J) AS {1}_rfj' -f $doc0, $Alias))
    $prev = $doc0; $i = 0
    foreach ($f in @(Get-SIDataCiFindingRunFields)) {
        $i++
        $key = '"' + $f + '"'
        [void]$apply.Append((' CROSS APPLY (SELECT CASE WHEN {2}_rfj.J = 1 AND CHARINDEX(N''{1}'', {4}) > 0 THEN JSON_MODIFY({0}, N''$.{1}'', NULL) ELSE {0} END AS D) AS {2}_rf{3}' -f $prev, $key, $Alias, $i, $doc0))
        $prev = '{0}_rf{1}.D' -f $Alias, $i
    }
    $doc = 'CASE WHEN {0} IS NULL THEN 0x00 ELSE 0x01 + CAST({0} AS varbinary(max)) END' -f $prev
    @{ Apply = $apply.ToString(); Expr = 'HASHBYTES(''SHA2_256'', ' + ((@(@($cols | ForEach-Object { & $part $_ }) + $doc)) -join ' + ') + ')' }
}

function Get-SIDataCiFindingContentHashCheckSql {
    <# 1 when sidata.CiFinding carries its content hash column (the schema of this release), else 0: the swap then writes as before. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.CiFinding', 'ContentHash') IS NOT NULL THEN 1 ELSE 0 END"
}

$script:SIDataCiFindingFullMark = 'CiFindingFullSwap'
$script:SIDataCiFindingFullDays = 7

function Get-SIDataCiFindingFullDueSql {
    <# 1 when the weekly full swap is due: never done, or its mark (sidata.CiBuildState) older than @Days days. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.CiBuildState') IS NULL THEN 1 WHEN EXISTS (SELECT 1 FROM sidata.CiBuildState WHERE Name = N'$script:SIDataCiFindingFullMark' AND TRY_CONVERT(datetime2(0), Value, 126) > DATEADD(day, -CONVERT(int, @Days), SYSUTCDATETIME())) THEN 0 ELSE 1 END"
}

function Get-SIDataCiFindingFullMarkSql {
    <# The weekly full swap is done: its mark set to now. #>
    "MERGE sidata.CiBuildState AS b USING (SELECT N'$script:SIDataCiFindingFullMark' AS Name, CONVERT(nvarchar(400), SYSUTCDATETIME(), 126) AS Value) AS v ON b.Name = v.Name WHEN MATCHED THEN UPDATE SET Value = v.Value, UpdatedAt = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (v.Name, v.Value); SELECT 1;"
}

function Get-SIDataCiFindingSwapSql {
    <#
        ONE transaction: the stored findings per CI are replaced by the staged ones. Answers the rows now stored. XACT_ABORT:
        a failure anywhere in it (a time-out, a full log, a lost connection) leaves sidata.CiFinding exactly as it was.
        @Expected = the rows staged: when the staging table holds another number (another run wrote to it meanwhile, or a
        chunk is missing) nothing is replaced and the statement fails -- a partial set never becomes the stored one.
        -SubCi (#772): the ServiceNow sub-CI column is moved too.
        -Category (#636): the category and subcategory columns travel too (a database that has them on both tables).
        #834 ONLY WHAT CHANGED IS WRITTEN: a stored row is matched to a staged one by a SHA-256 of its columns (NULL kept
        apart from empty) and by its place among rows with the same hash; every other stored row goes; the staged rows
        without a match come in, in the staged order. The stored count must come out as the staged count, else the
        transaction rolls back and the stored findings are kept as they are. (TRUNCATE or a table swap would need ALTER on
        the table, which the engine is never granted -- SI-EngineGrants.ps1.)
        -ContentHash (2026-10-25, the database has sidata.CiFinding.ContentHash): matched by the CONTENT HASH -- the data
        only, not what every run moves (Get-SIDataCiFindingHashSql; a stored row's hash is its ContentHash, worked out from
        the row when that is NULL). A matched row keeps its row; its CollectionTime and its document are written from the
        staged row, and its ContentHash -- each only where it differs. Every other column of a matched row is equal by the
        hash, so the stored set is exactly the delete-all + insert-all's. The staged rows that come in carry their hash.
        -Full (with -ContentHash: the weekly full swap): matched by EVERY column as before #834's content rule (so every
        row a run moved is replaced), and every stored row's ContentHash written anew from its data.
    #>
    param([switch]$SubCi, [switch]$Category, [switch]$ContentHash, [switch]$Full)
    $cols = $script:SIDataCiFindingColumns; if ($SubCi) { $cols += ', SubCi, PatchCycle, CvePublished' }; if ($Category) { $cols += ', Category, Subcategory' }
    $names = @($cols -split ',\s*' | Where-Object { $_ })
    $sCols = (@($names | ForEach-Object { 's.[{0}]' -f $_ })) -join ', '
    $byAll = (-not $ContentHash) -or $Full
    $mS = Get-SIDataCiFindingHashSql -Alias 's' -Names $names -All:$byAll
    $mT = Get-SIDataCiFindingHashSql -Alias 't' -Names $names -All:$byAll
    $cS = Get-SIDataCiFindingHashSql -Alias 's' -Names $names
    $tH = if ($byAll) { $mT.Expr } else { 'ISNULL(t.ContentHash, ' + $mT.Expr + ')' }
    $sC = if ($ContentHash) { ', ' + $cS.Expr } else { ', CAST(NULL AS binary(32))' }
    $sApply = $mS.Apply; if ($ContentHash -and $byAll) { $sApply = $cS.Apply }
    # the staged side: its match hash (H) and its content hash (C) -- one and the same, worked out once, unless -Full
    $sSel = $mS.Expr + ' AS H' + $sC
    if (-not $byAll) { $sApply = $mS.Apply + ' CROSS APPLY (SELECT ' + $mS.Expr + ' AS H) AS hx'; $sSel = 'hx.H AS H, hx.H' }
    $insCols = $cols; $insVals = $sCols; $keep = ''
    if ($ContentHash) {
        $insCols += ', ContentHash'; $insVals += ', k.C'
        $keep = @"
UPDATE f SET CollectionTime = s.CollectionTime, DocJson = s.DocJson, ContentHash = k.C /* one-statement-ok: only the kept rows, inside the swap's one transaction (the stored set is replaced atomically) */
FROM sidata.CiFinding AS f JOIN @tk AS t ON t.CiFindingId = f.CiFindingId JOIN @sk AS k ON k.H = t.H AND k.Rn = t.Rn JOIN sidata.CiFindingStage AS s ON s.StageId = k.StageId
WHERE f.CollectionTime <> s.CollectionTime OR ISNULL(DATALENGTH(f.DocJson), -1) <> ISNULL(DATALENGTH(s.DocJson), -1) OR CAST(f.DocJson AS varbinary(max)) <> CAST(s.DocJson AS varbinary(max))
   OR f.ContentHash IS NULL OR f.ContentHash <> k.C
OPTION (RECOMPILE);
"@
    }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @staged BIGINT = (SELECT COUNT_BIG(*) FROM sidata.CiFindingStage WITH (TABLOCKX));
IF @staged <> CONVERT(BIGINT, @Expected)
BEGIN
    ROLLBACK;
    DECLARE @msg NVARCHAR(200) = CONCAT(N'the staged findings per CI are not the set this run wrote (', @staged, N' staged, ', @Expected, N' written) -- the stored findings are kept as they are');
    THROW 51000, @msg, 1;
END
DECLARE @sk TABLE (StageId BIGINT NOT NULL PRIMARY KEY, H BINARY(32) NOT NULL, C BINARY(32) NULL, Rn BIGINT NOT NULL, INDEX IX_sk (H, Rn));
DECLARE @tk TABLE (CiFindingId BIGINT NOT NULL PRIMARY KEY, H BINARY(32) NOT NULL, Rn BIGINT NOT NULL, INDEX IX_tk (H, Rn));
INSERT @sk (StageId, H, C, Rn)
SELECT x.StageId, x.H, x.C, ROW_NUMBER() OVER (PARTITION BY x.H ORDER BY x.StageId) FROM (SELECT s.StageId, $sSel AS C FROM sidata.CiFindingStage AS s$sApply) AS x;
INSERT @tk (CiFindingId, H, Rn)
SELECT x.CiFindingId, x.H, ROW_NUMBER() OVER (PARTITION BY x.H ORDER BY x.CiFindingId) FROM (SELECT t.CiFindingId, $tH AS H FROM sidata.CiFinding AS t$($mT.Apply)) AS x;
DELETE f FROM sidata.CiFinding AS f
WHERE f.CiFindingId IN (SELECT t.CiFindingId FROM @tk AS t WHERE NOT EXISTS (SELECT 1 FROM @sk AS k WHERE k.H = t.H AND k.Rn = t.Rn))
OPTION (RECOMPILE);
$keep
INSERT sidata.CiFinding ($insCols)
SELECT $insVals FROM sidata.CiFindingStage AS s JOIN @sk AS k ON k.StageId = s.StageId
WHERE NOT EXISTS (SELECT 1 FROM @tk AS t WHERE t.H = k.H AND t.Rn = k.Rn)
ORDER BY s.StageId
OPTION (RECOMPILE);
DECLARE @n INT = (SELECT COUNT(*) FROM sidata.CiFinding);
IF @n <> @staged
BEGIN
    ROLLBACK;
    DECLARE @msg2 NVARCHAR(200) = CONCAT(N'the findings per CI did not come out as the staged set (', @n, N' stored, ', @staged, N' staged) -- the stored findings are kept as they are');
    THROW 51000, @msg2, 1;
END
COMMIT;
SELECT @n;
"@
}

$script:SIDataCiBackfillColumns = [ordered]@{ Component = 'si_component'; SubCi = 'si_servicenow_subci'; PatchCycle = 'si_patch_cycle' }

function Get-SIDataCiColumnBackfillSql {
    <# #881 One CiFindingId range (@After < CiFindingId <= @Upto) of one stored column filled from the finding's own row -- only
       a row that has no value and whose row names one (so a second pass writes nothing). Answers the rows written. #>
    # -ClearHash (the database has sidata.CiFinding.ContentHash): a row whose column is written loses its content hash -- the
    # next swap works it out from the row again (a stored hash is only ever the hash of the row as it is)
    param([Parameter(Mandatory)][ValidateSet('Component', 'SubCi', 'PatchCycle')][string]$Column, [switch]$ClearHash)
    $clear = ''; if ($ClearHash) { $clear = ', ContentHash = NULL' }
    $path = $script:SIDataCiBackfillColumns[$Column]
    $expr = "NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DocJson, '`$.$path'))), 64), N'')"
    @"
SET NOCOUNT ON;
UPDATE f SET [$Column] = $expr$clear
FROM sidata.CiFinding AS f
WHERE f.CiFindingId > CONVERT(bigint, @After) AND f.CiFindingId <= CONVERT(bigint, @Upto)
  AND f.[$Column] IS NULL AND ISJSON(f.DocJson) = 1 AND $expr IS NOT NULL;
SELECT @@ROWCOUNT;
"@
}

function Invoke-SIDataCiColumnBackfill {
    <#
        #881 THE FINDINGS ALREADY STORED GET A NEW STORED COLUMN FROM THEIR OWN ROW (Component, SubCi, PatchCycle) -- a
        CiFindingId range at a time, each its own statement, sized from the measured time of the one before, paced; never one
        statement over the whole table (the schema used to do it in its one transaction when the column was added: ~50 M rows
        in one transaction during the update). Once per column per database: the mark sidata.ViewState 'cicol:<column>'
        holds the last id done (a stopped run goes on from there) and 'done' at the end. Values: exactly the expression the
        schema used. Never throws (said; the next run goes on). Returns @{ Column = rows written }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [long]$FirstSize = 50000, [long]$TargetMs = 5000, [scriptblock]$Log = { param($l, $m) })
    $out = [ordered]@{}
    foreach ($col in $script:SIDataCiBackfillColumns.Keys) {
        try {
            $mark = 'cicol:' + $col
            $st = [string](& $Invoke ("SELECT CASE WHEN COL_LENGTH('sidata.CiFinding', '{0}') IS NULL OR OBJECT_ID('sidata.ViewState') IS NULL THEN N'none' ELSE ISNULL((SELECT Value FROM sidata.ViewState WHERE Name = @Name), N'') END;" -f $col) @{ Name = $mark } 'scalar')
            if ($st -in 'none', 'done') { continue }
            $b = @(@(& $Invoke 'SELECT ISNULL(MIN(CiFindingId), 0) AS Lo, ISNULL(MAX(CiFindingId), -1) AS Hi FROM sidata.CiFinding;' @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            $get = { param($n) if ($b -is [System.Collections.IDictionary]) { $b[$n] } else { $b.$n } }
            $after = [long](& $get 'Lo') - 1; $hi = [long](& $get 'Hi')
            $from = 0L; if ([long]::TryParse($st, [ref]$from) -and $from -gt $after) { $after = $from }
            $hasHash = ([string](& $Invoke (Get-SIDataCiFindingContentHashCheckSql) @{} 'scalar') -eq '1')
            $sql = Get-SIDataCiColumnBackfillSql -Column $col -ClearHash:$hasHash
            $size = [Math]::Max(1L, $FirstSize); $n = 0L; $lastMs = 0L
            $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
            $setMark = { param([string]$v) $null = & $Invoke "IF EXISTS (SELECT 1 FROM sidata.ViewState WHERE Name = @Name) UPDATE sidata.ViewState SET Value = @Value, UpdatedAt = SYSUTCDATETIME() WHERE Name = @Name; ELSE INSERT sidata.ViewState (Name, Value) VALUES (@Name, @Value);" @{ Name = $mark; Value = $v } 'nonquery' }
            while ($after -lt $hi) {
                if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) } }
                $upto = [long][Math]::Min([double]$hi, [double]$after + [double]$size)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $n += [long](& $Invoke $sql @{ After = [string]$after; Upto = [string]$upto } 'scalar')
                $lastMs = $sw.ElapsedMilliseconds; $after = $upto
                & $setMark ([string]$after)
                if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
            }
            & $setMark 'done'
            $out[$col] = $n
            if ($n -gt 0) { & $Log 'INFO' ("v3 model    : the findings per CI already stored got their {0} from their own row ({1:N0} row(s))" -f $col, $n) }
        } catch { & $Log 'WARN' ("v3 model    : the findings per CI already stored did not all get their {0} this run ({1}) -- the next run goes on" -f $col, $_.Exception.Message) }
    }
    $out
}

function Invoke-SIDataCiFindingSwap {
    <#
        #881 THE SAME SWAP (Get-SIDataCiFindingSwapSql: the staged set replaces the stored one, only what changed is written),
        with its heavy part out of one transaction. On ONE connection (the seam's mode 'session') the hashes are worked out a
        key range at a time into #temp tables, each range its own statement, sized from the measured time of the one before.
        2026-10-29 THE WRITES IN HASH RANGES TOO (live at the largest install: 4,064 s for 1,300,749 rows in the one write
        transaction -- every kept row's time and document are rewritten on a new collection): the rows are matched and written
        one range of hashes at a time -- every row of one hash is in one range, so the pairing of stored and staged rows is
        exactly the one statement's -- each range ONE command and its own transaction (remove, keep, add; its own counts
        checked or it rolls back), the range's size from the measured time of the one before, one log line per range. The end
        state is exactly the one statement's: the same multiset in every column (only which CiFindingId a row has may differ).
          * ONE REPLACE AT A TIME: the session lock si-cifinding-swap for the whole replace.
          * BEFORE THE FIRST WRITE neither table changed since the hashes (the staged count, its first and last StageId, the
            stored count and its last CiFindingId), and the staged count is the count this run wrote -- else nothing is written.
          * WHILE IT RUNS the mark sidata.ViewState 'cifinding-swap' is OPEN: the web app reads the published copies, and the
            copy refresh and the publish hold while the mark is open (SI-DataPublishedRun.ps1) -- a half-replaced set is never
            copied to what the pages show.
          * AT THE END the stored count must come out as the staged one; only then is the mark taken away. A run that stops
            part-way leaves the mark open; the next run stages its collection again and the same ranges finish the replace
            (a range already done matches and writes nothing).
        -ContentHash: matched by the content hash (a stored row's ContentHash is read where it has one). -Full (with
        -ContentHash: the weekly check): every stored row's content hash worked out again from its data -- the rows a run
        moved are matched by their content and their time and document written, the end state the old full swap's (every
        column of every row equal to its staged row), without removing and adding every row. Without -ContentHash (a database
        before the column): matched by every column. A seam without sessions (a test's fake) runs the one statement.
        Answers the rows now stored.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$Expected, [switch]$SubCi, [switch]$Category,
          [switch]$ContentHash, [switch]$Full,
          [long]$FirstSize = 50000, [long]$TargetMs = 5000, [scriptblock]$Log = { param($l, $m) },
          # what the mark names (the collection's time, for a person reading it)
          [string]$CollectionText = '',
          # tests only: stop after this many write ranges, as a run that ends part-way
          [int]$StopAfterRanges = 0)
    if ($Invoke.PSObject.Properties['SIRangeFirstTake'] -and [long]$Invoke.SIRangeFirstTake -gt 0) { $FirstSize = [long]$Invoke.SIRangeFirstTake }
    $session = $Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo
    if (-not $session) { return [long](& $Invoke (Get-SIDataCiFindingSwapSql -SubCi:$SubCi -Category:$Category -ContentHash:$ContentHash -Full:$Full) @{ Expected = [string]$Expected } 'scalar') }
    $cols = $script:SIDataCiFindingColumns; if ($SubCi) { $cols += ', SubCi, PatchCycle, CvePublished' }; if ($Category) { $cols += ', Category, Subcategory' }
    $names = @($cols -split ',\s*' | Where-Object { $_ })
    $sCols = (@($names | ForEach-Object { 's.[{0}]' -f $_ })) -join ', '
    # every column (no content hash column yet), or the content hash -- on the weekly check worked out again from the data
    $byAll = -not $ContentHash
    $mS = Get-SIDataCiFindingHashSql -Alias 's' -Names $names -All:$byAll
    $mT = Get-SIDataCiFindingHashSql -Alias 't' -Names $names -All:$byAll
    if ($byAll) { $sApply = $mS.Apply; $sSel = $mS.Expr + ' AS H, CAST(NULL AS binary(32))' }
    else { $sApply = $mS.Apply + ' CROSS APPLY (SELECT ' + $mS.Expr + ' AS H) AS hx'; $sSel = 'hx.H AS H, hx.H' }
    $exp = [long]$Expected
    $nextSize = { param([long]$cur, [long]$ms) if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { Get-SIDataNextSize -Current $cur -ElapsedMs $ms -TargetMs $TargetMs -Minimum 1 } else { [Math]::Max(1L, $cur) } }
    $logFn = $Log
    $insCols = $cols; $insVals = $sCols; $keep = ''
    if ($ContentHash) {
        $insCols += ', ContentHash'; $insVals += ', i.C'
        # a kept row: the run's time and document from its staged row, and its hash -- each only where it differs
        $keep = @'
UPDATE f SET CollectionTime = s.CollectionTime, DocJson = s.DocJson, ContentHash = k.C /* one-statement-ok: one hash range (#rkeep holds this range's rows only) */
FROM sidata.CiFinding AS f JOIN #rkeep AS k ON k.CiFindingId = f.CiFindingId JOIN sidata.CiFindingStage AS s ON s.StageId = k.StageId
WHERE f.CollectionTime <> s.CollectionTime OR ISNULL(DATALENGTH(f.DocJson), -1) <> ISNULL(DATALENGTH(s.DocJson), -1) OR CAST(f.DocJson AS varbinary(max)) <> CAST(s.DocJson AS varbinary(max))
   OR f.ContentHash IS NULL OR f.ContentHash <> k.C;
SET @w = @@ROWCOUNT;
'@
    }
    $hex = { param($b) if ($null -eq $b -or $b -is [System.DBNull]) { $null } else { '0x' + ([BitConverter]::ToString([byte[]]$b)).Replace('-', '') } }
    # (ViewState.Value holds 64 characters: 'open' and the collection's time; UpdatedAt says since when)
    $markText = ('open {0}' -f $(if ($CollectionText) { $CollectionText } else { 'the newest collection' }))
    if ($markText.Length -gt 64) { $markText = $markText.Substring(0, 64) }
    $markSql = "MERGE sidata.ViewState AS v USING (SELECT N'cifinding-swap' AS Name, N'{0}' AS Value) AS x ON v.Name = x.Name WHEN MATCHED THEN UPDATE SET Value = x.Value, UpdatedAt = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (x.Name, x.Value);" -f $markText.Replace("'", "''")
    $stopAt = $StopAfterRanges
    $onSession = {
        param($Run)
        $lock = [int](& $Run "DECLARE @l int; EXEC @l = sp_getapplock @Resource = N'si-cifinding-swap', @LockMode = N'Exclusive', @LockOwner = N'Session', @LockTimeout = 0; SELECT @l;" 'scalar')
        if ($lock -lt 0) { throw 'another data sync is replacing the findings per CI right now -- the stored findings are kept as they are' }
        & $Run 'CREATE TABLE #skh (StageId BIGINT NOT NULL, H BINARY(32) NOT NULL, C BINARY(32) NULL, PRIMARY KEY CLUSTERED (H, StageId)); CREATE TABLE #tkh (CiFindingId BIGINT NOT NULL, H BINARY(32) NOT NULL, PRIMARY KEY CLUSTERED (H, CiFindingId));' 'none'
        # the hashes, a key range at a time (reads; the #temp tables live in tempdb, outside the user database's log)
        foreach ($side in @(@{ Tbl = 'sidata.CiFindingStage'; Key = 'StageId'; Into = '#skh'; Sel = $sSel; Cols = 'H, C'; Apply = $sApply; A = 's' },
                            @{ Tbl = 'sidata.CiFinding'; Key = 'CiFindingId'; Into = '#tkh'; Sel = $(if ($byAll) { $mT.Expr } else { $mT.Expr }) + ' AS H'; Cols = 'H'; Apply = $mT.Apply; A = 't' })) {
            $b = @(& $Run ("SELECT ISNULL(MIN({0}), 0) AS Lo, ISNULL(MAX({0}), -1) AS Hi FROM {1};" -f $side.Key, $side.Tbl) 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
            $after = [long]$b['Lo'] - 1; $hi = [long]$b['Hi']; $size = [Math]::Max(1L, $FirstSize)
            while ($after -lt $hi) {
                $upto = [long][Math]::Min([double]$hi, [double]$after + [double]$size)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                if ($side.A -eq 't' -and -not $byAll -and -not $Full) {
                    # a stored row's content hash is read where it has one; only a row without one has it worked out
                    & $Run ("INSERT #tkh (CiFindingId, H) SELECT t.CiFindingId, t.ContentHash FROM sidata.CiFinding AS t WHERE t.ContentHash IS NOT NULL AND t.CiFindingId > {0} AND t.CiFindingId <= {1};" -f $after, $upto) 'none'
                    & $Run ("INSERT #tkh (CiFindingId, H) SELECT t.CiFindingId, {0} FROM sidata.CiFinding AS t{1} WHERE t.ContentHash IS NULL AND t.CiFindingId > {2} AND t.CiFindingId <= {3};" -f $mT.Expr, $mT.Apply, $after, $upto) 'none'
                } else {
                    # the staged side; the stored side by every column, or (the weekly check) by its content worked out from its data
                    & $Run ("INSERT {0} ({1}, {2}) SELECT {3}.{1}, {4} FROM {5} AS {3}{6} WHERE {3}.{1} > {7} AND {3}.{1} <= {8};" -f $side.Into, $side.Key, $side.Cols, $side.A, $side.Sel, $side.Tbl, $side.Apply, $after, $upto) 'none'
                }
                $after = $upto
                $size = & $nextSize $size $sw.ElapsedMilliseconds
            }
        }
        # nothing written yet: the staged set is the one this run wrote, and neither table changed while it was compared
        $chk = @(& $Run @"
SELECT (SELECT COUNT_BIG(*) FROM sidata.CiFindingStage) AS Staged, (SELECT ISNULL(MIN(StageId), 0) FROM sidata.CiFindingStage) AS SLo, (SELECT ISNULL(MAX(StageId), 0) FROM sidata.CiFindingStage) AS SHi,
       (SELECT COUNT_BIG(*) FROM #skh) AS SkCount, (SELECT ISNULL(MIN(StageId), 0) FROM #skh) AS SkLo, (SELECT ISNULL(MAX(StageId), 0) FROM #skh) AS SkHi,
       (SELECT COUNT_BIG(*) FROM sidata.CiFinding) AS Stored, (SELECT ISNULL(MAX(CiFindingId), 0) FROM sidata.CiFinding) AS THi,
       (SELECT COUNT_BIG(*) FROM #tkh) AS TkCount, (SELECT ISNULL(MAX(CiFindingId), 0) FROM #tkh) AS TkHi;
"@ 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        if ([long]$chk['Staged'] -ne $exp) { throw ('the staged findings per CI are not the set this run wrote ({0} staged, {1} written) -- the stored findings are kept as they are' -f [long]$chk['Staged'], $exp) }
        if ([long]$chk['Staged'] -ne [long]$chk['SkCount'] -or [long]$chk['SLo'] -ne [long]$chk['SkLo'] -or [long]$chk['SHi'] -ne [long]$chk['SkHi'] -or
            [long]$chk['Stored'] -ne [long]$chk['TkCount'] -or [long]$chk['THi'] -ne [long]$chk['TkHi']) {
            throw 'the findings per CI or their staging changed while they were compared -- the stored findings are kept as they are'
        }
        # the mark is OPEN from the first write until the stored count is checked at the end
        & $Run $markSql 'none'
        $tot = @{ D = 0L; I = 0L; K = 0L; W = 0L }
        $take = [Math]::Max(1L, $FirstSize); $hasLo = $false; $lo = $null; $i = 0
        while ($true) {
            $lop = ''; if ($hasLo) { $lop = ' WHERE u.H > ' + $lo }
            $bd = @(& $Run ("SELECT MAX(x.k) AS Hi, COUNT_BIG(*) AS N FROM (SELECT TOP ({0}) u.H AS k FROM (SELECT H FROM #skh UNION ALL SELECT H FROM #tkh) AS u{1} ORDER BY u.H) AS x;" -f $take, $lop) 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
            $hiHex = & $hex $bd['Hi']; $last = ($null -eq $hiHex) -or ([long]$bd['N'] -lt $take)
            $p = ''; if ($hasLo) { $p += ' AND H > ' + $lo }; if (-not $last) { $p += ' AND H <= ' + $hiHex }
            $i++
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = @(& $Run @"
SET XACT_ABORT ON;
IF OBJECT_ID('tempdb..#rs') IS NOT NULL DROP TABLE #rs; IF OBJECT_ID('tempdb..#rt') IS NOT NULL DROP TABLE #rt;
IF OBJECT_ID('tempdb..#rdel') IS NOT NULL DROP TABLE #rdel; IF OBJECT_ID('tempdb..#rins') IS NOT NULL DROP TABLE #rins; IF OBJECT_ID('tempdb..#rkeep') IS NOT NULL DROP TABLE #rkeep;
SELECT StageId, H, C, ROW_NUMBER() OVER (PARTITION BY H ORDER BY StageId) AS Rn INTO #rs FROM #skh WHERE 1 = 1$p;
SELECT CiFindingId, H, ROW_NUMBER() OVER (PARTITION BY H ORDER BY CiFindingId) AS Rn INTO #rt FROM #tkh WHERE 1 = 1$p;
SELECT t.CiFindingId INTO #rdel FROM #rt AS t WHERE NOT EXISTS (SELECT 1 FROM #rs AS k WHERE k.H = t.H AND k.Rn = t.Rn);
SELECT k.StageId, k.C INTO #rins FROM #rs AS k WHERE NOT EXISTS (SELECT 1 FROM #rt AS t WHERE t.H = k.H AND t.Rn = k.Rn);
SELECT t.CiFindingId, k.StageId, k.C INTO #rkeep FROM #rt AS t JOIN #rs AS k ON k.H = t.H AND k.Rn = t.Rn;
DECLARE @d BIGINT = (SELECT COUNT_BIG(*) FROM #rdel), @i BIGINT = (SELECT COUNT_BIG(*) FROM #rins), @k BIGINT = (SELECT COUNT_BIG(*) FROM #rkeep), @w BIGINT = 0, @x BIGINT;
BEGIN TRAN;
DELETE f FROM sidata.CiFinding AS f JOIN #rdel AS d ON d.CiFindingId = f.CiFindingId /* one-statement-ok: one hash range (#rdel holds this range's rows only) */;
SET @x = @@ROWCOUNT;
IF @x <> @d BEGIN ROLLBACK; THROW 51000, N'the findings per CI changed while they were replaced -- this part is kept as it was and the next run finishes the replace', 1; END
$keep
INSERT sidata.CiFinding ($insCols)
SELECT $insVals FROM sidata.CiFindingStage AS s JOIN #rins AS i ON i.StageId = s.StageId
ORDER BY s.StageId;
SET @x = @@ROWCOUNT;
IF @x <> @i BEGIN ROLLBACK; THROW 51000, N'the staged findings per CI changed while they were replaced -- this part is kept as it was and the next run finishes the replace', 1; END
COMMIT;
DROP TABLE #rs; DROP TABLE #rt; DROP TABLE #rdel; DROP TABLE #rins; DROP TABLE #rkeep;
SELECT @d AS D, @i AS I, @k AS K, @w AS W;
"@ 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
            $ms = $sw.ElapsedMilliseconds
            foreach ($q in 'D', 'I', 'K', 'W') { $tot[$q] += [long]$r[$q] }
            & $logFn 'INFO' ('v3 model    : findings per CI: swap -- range {0}: {1:N0} removed, {2:N0} kept ({3:N0} rewritten), {4:N0} added -- {5:N1} s' -f $i, [long]$r['D'], [long]$r['K'], [long]$r['W'], [long]$r['I'], ($ms / 1000.0))
            if ($last) { break }
            if ($stopAt -gt 0 -and $i -ge $stopAt) { throw ('stopped after {0} range(s) (a test of a run that ends part-way)' -f $i) }
            $hasLo = $true; $lo = $hiHex
            $take = & $nextSize $take $ms
        }
        # the stored set must come out as the staged one -- only then is the mark taken away
        $n = [long](& $Run 'SELECT COUNT_BIG(*) FROM sidata.CiFinding;' 'scalar')
        if ($n -ne [long]$chk['Staged']) { throw ('the findings per CI did not come out as the staged set ({0} stored, {1} staged) -- the next run finishes the replace; until then the pages keep showing the published run' -f $n, [long]$chk['Staged']) }
        & $Run "DELETE FROM sidata.ViewState WHERE Name = N'cifinding-swap';" 'none'
        $null = & $Run "EXEC sp_releaseapplock @Resource = N'si-cifinding-swap', @LockOwner = N'Session';" 'none'
        $how = if (-not $ContentHash) { 'every column (the database has no content hash yet)' } elseif ($Full) { 'their content worked out again from every row (the weekly full check)' } else { 'their content hash' }
        & $logFn 'INFO' ('v3 model    : the findings per CI replaced -- {0:N0} stored: {1:N0} kept, {2:N0} removed, {3:N0} added (matched by {4}; {5:N0} range(s))' -f $n, $tot.K, $tot.D, $tot.I, $how, $i)
        $n
    }
    # a database without the mark table (not updated yet) cannot hold the copies while the replace runs: the one statement
    $hasMark = $false
    try { $hasMark = ([string](& $Invoke "SELECT CASE WHEN OBJECT_ID('sidata.ViewState') IS NOT NULL THEN 1 ELSE 0 END;" @{} 'scalar') -eq '1') } catch { $hasMark = $false }
    if (-not $hasMark) { return [long](& $Invoke (Get-SIDataCiFindingSwapSql -SubCi:$SubCi -Category:$Category -ContentHash:$ContentHash -Full:$Full) @{ Expected = [string]$Expected } 'scalar') }
    [long](& $Invoke $null $null 'session' $onSession)
}

function Get-SIDataCiFindingSwapOpenSql {
    <# READS ONLY. The open mark of a replace of the findings per CI (Invoke-SIDataCiFindingSwap), as the one column
       CiFindingSwapOpen ('' when there is none). The same read is in SI-DataPublishedRun.ps1 (a test keeps the two equal). #>
    "SELECT CASE WHEN OBJECT_ID('sidata.ViewState') IS NULL THEN N'' ELSE ISNULL((SELECT TOP (1) Value FROM sidata.ViewState WHERE Name = N'cifinding-swap'), N'') END AS CiFindingSwapOpen;"
}

function Invoke-SIDataCiLifecycleFromStage {
    <#
        #881 Get-SIDataCiLifecycleFromStageSql a key range at a time: the lifecycle's work table emptied in batches, then
        filled from the staged findings one StageId range per statement (sized from the measured time of the one before) --
        no transaction over the whole set. The rows written are counted against the rows the staged set yields (one count);
        a different number throws -- the lifecycle never runs on a part of the set (a short input would close findings).
        A seam without the work-table helpers takes the one statement as before. Answers the rows written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [long]$FirstSize = 50000, [long]$TargetMs = 5000)
    Clear-SIDataCiDbTable -Invoke $Invoke -Table 'sidata.CiFindingLifecycleStage'
    $b = @(@(& $Invoke 'SELECT ISNULL(MIN(StageId), 0) AS Lo, ISNULL(MAX(StageId), -1) AS Hi FROM sidata.CiFindingStage;' @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $get = { param($n) if ($b -is [System.Collections.IDictionary]) { $b[$n] } else { $b.$n } }
    $after = [long](& $get 'Lo') - 1; $hi = [long](& $get 'Hi'); $size = [Math]::Max(1L, $FirstSize); $written = 0L
    $sql = Get-SIDataCiLifecycleFromStageRangeSql
    while ($after -lt $hi) {
        $upto = [long][Math]::Min([double]$hi, [double]$after + [double]$size)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $written += [long](& $Invoke $sql @{ After = [string]$after; Upto = [string]$upto } 'scalar')
        $after = $upto
        if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 1 }
    }
    $want = [long](& $Invoke "SELECT COUNT_BIG(*) FROM sidata.CiFindingStage s CROSS APPLY (SELECT NULLIF(JSON_VALUE(s.DocJson, '`$.si_ci_id'), N'') AS Ci) o WHERE s.FindingKey IS NOT NULL AND COALESCE(o.Ci, NULLIF(s.AssetId, N'')) IS NOT NULL;" @{} 'scalar')
    if ($written -ne $want) { throw ('the lifecycle input of the staged findings is not whole ({0:N0} written, {1:N0} staged) -- no finding is closed this run' -f $written, $want) }
    $written
}

function Get-SIDataCiLifecycleFromStageRangeSql {
    <# #881 One StageId range (@After < StageId <= @Upto) of Get-SIDataCiLifecycleFromStageSql's rows, its own statement. #>
    @'
SET NOCOUNT ON;
INSERT sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey, CiId, Severity, DetectedBy, ExemptionId)
SELECT N'f', LEFT(COALESCE(o.Ci, N'asset:' + LOWER(NULLIF(s.AssetId, N''))), 450), LEFT(s.FindingKey, 256), LEFT(o.Ci, 64), LEFT(s.Severity, 16), LEFT(s.DetectedBy, 2000), LEFT(s.ExemptionId, 64)
FROM sidata.CiFindingStage s
CROSS APPLY (SELECT NULLIF(JSON_VALUE(s.DocJson, '$.si_ci_id'), N'') AS Ci) o
WHERE s.StageId > CONVERT(bigint, @After) AND s.StageId <= CONVERT(bigint, @Upto)
  AND s.FindingKey IS NOT NULL AND COALESCE(o.Ci, NULLIF(s.AssetId, N'')) IS NOT NULL;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataCiFindingCategoryCheckSql {
    <# 1 when both finding-per-CI tables carry the category and subcategory columns (#636), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.CiFinding', 'Category') IS NOT NULL AND COL_LENGTH('sidata.CiFinding', 'Subcategory') IS NOT NULL AND COL_LENGTH('sidata.CiFindingStage', 'Category') IS NOT NULL AND COL_LENGTH('sidata.CiFindingStage', 'Subcategory') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCiFindingStageClearSql {
    <# Empties the staging table (after the swap; the next run's first chunk empties it too). #>
    'DELETE FROM sidata.CiFindingStage; SELECT 1;'
}

function Clear-SIDataCiStage {
    <# 2026-10-29 A staging table emptied: on a real database in batches (Clear-SIDataCiDbTable -- one DELETE over 1.3 M staged
       findings with their documents was one command and one transaction); any other seam the one statement of before. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('sidata.CiFindingStage', 'sidata.CiFindingLifecycleStage')][string]$Table)
    if (Test-SIDataRangedSeam $Invoke) { Clear-SIDataCiDbTable -Invoke $Invoke -Table $Table; return }
    if ($Table -eq 'sidata.CiFindingStage') { [void](& $Invoke (Get-SIDataCiFindingStageClearSql) @{} 'scalar') }
    else { [void](& $Invoke (Get-SIDataCiLifecycleStageClearSql) @{} 'scalar') }
}

function Get-SIDataCiTotalsSql {
    <#
        The CIs' finding totals, SET-BASED from the stored findings (the CI build writes the CIs and never touches these):
        per CI the sum of risk scores, of weighted scores and the count of open findings -- an exempted finding is not
        counted; a CI without findings has 0. Only rows whose totals moved are written; today's trend row follows.
        #855 W6 (owner 2026-10-21: "we need to be able to trust all data"): only OPEN findings count -- a finding whose
        lifecycle row is closed (sidata.CiFindingState: fixed, asset retired, no longer monitored) is not, and a RETIRED CI
        has none (its findings close as asset retired; the lifecycle step may close them after this step in the same run).
        So a retired CI never keeps its open findings and risk score -- here, on the CI list, and in what goes to ServiceNow.
        -Ranged (2026-10-29): the same statement for ONE CiId range (@RangeLo / @RangeHi, Invoke-SIDataCiTotals) -- every
        finding of a CI is in its CI's range, so each CI's totals are exactly the whole statement's.
    #>
    param([switch]$Ranged)
    $sql = @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @t TABLE (CiId NVARCHAR(64) PRIMARY KEY, Score FLOAT, Weighted FLOAT, Cnt INT);
INSERT @t SELECT f.CiId, SUM(ISNULL(f.RiskScore, 0)), SUM(ISNULL(f.WeightedRiskScore, 0)), COUNT(*) FROM sidata.CiFinding AS f
JOIN sidata.Ci AS ci ON ci.CiId = f.CiId AND ISNULL(ci.Lifecycle, N'') <> N'retired'
WHERE f.CiId IS NOT NULL AND ISNULL(f.ExemptionId, N'') = N''/*R:f.CiId*/
  AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState AS s WHERE s.OwnerKey = f.CiId AND s.FindingKey = f.FindingKey AND s.State = N'closed')
GROUP BY f.CiId;
BEGIN TRAN;
UPDATE c SET RiskScore = t.Score, WeightedRiskScore = t.Weighted, OpenFindings = ISNULL(t.Cnt, 0)
FROM sidata.Ci c LEFT JOIN @t t ON t.CiId = c.CiId
WHERE (ISNULL(c.RiskScore, -1) <> ISNULL(t.Score, -1) OR ISNULL(c.WeightedRiskScore, -1) <> ISNULL(t.Weighted, -1) OR ISNULL(c.OpenFindings, 0) <> ISNULL(t.Cnt, 0))/*R:c.CiId*/;
DECLARE @n INT = @@ROWCOUNT;
UPDATE d SET RiskScore = c.RiskScore, WeightedRiskScore = c.WeightedRiskScore, OpenFindings = c.OpenFindings
FROM sidata.CiDaily d JOIN sidata.Ci c ON c.CiId = d.CiId
WHERE d.[Day] = CONVERT(date, SYSUTCDATETIME())/*R:d.CiId*/
  AND (ISNULL(d.RiskScore, -1) <> ISNULL(c.RiskScore, -1) OR ISNULL(d.WeightedRiskScore, -1) <> ISNULL(c.WeightedRiskScore, -1) OR ISNULL(d.OpenFindings, 0) <> ISNULL(c.OpenFindings, 0));
COMMIT;
SELECT @n;
'@
    if ($Ranged) { return $sql }
    Expand-SIDataRangeMarker -Sql $sql
}

function Invoke-SIDataCiRangedStatement {
    <#
        2026-10-29 ONE statement with range markers (/*R:..*/), run per CiId range of sidata.Ci (Invoke-SIDataKeyRanges) on a
        real database's seam -- or once, without the markers, on any other seam (a test's fake). -Params: the statement's own
        parameters. Answers the sum of what the ranges answered (a scalar each).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{}, [string]$What = 'ranges',
          [string]$Table = 'sidata.Ci', [string]$Column = 'CiId', [scriptblock]$Log, [long]$FirstTake = 2000, [long]$TargetMs = 5000)
    if (-not (Test-SIDataRangedSeam $Invoke)) { return [long](& $Invoke (Expand-SIDataRangeMarker -Sql $Sql) $Params 'scalar') }
    $inv = $Invoke; $text = $Sql; $prm = $Params
    $answers = Invoke-SIDataKeyRanges -Invoke $Invoke -Table $Table -Column $Column -What $What -Log $Log -FirstTake $FirstTake -TargetMs $TargetMs -Step {
        param($r)
        $p = @{}; foreach ($k in $prm.Keys) { $p[$k] = $prm[$k] }
        $null = Add-SIDataRangeParams -Params $p -Range $r
        $v = & $inv (Expand-SIDataRangeMarker -Sql $text -Range $r) $p 'scalar'
        if ($null -eq $v -or $v -is [System.DBNull]) { 0L } else { [long]$v }
    }
    $sum = 0L; foreach ($a in @($answers)) { $sum += [long]$a }
    $sum
}

function Invoke-SIDataCiTotals {
    <# The CIs' finding totals (Get-SIDataCiTotalsSql): per CiId range on a real database, the one statement otherwise. Answers the CIs written. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    Invoke-SIDataCiRangedStatement -Invoke $Invoke -Sql (Get-SIDataCiTotalsSql -Ranged) -What "v3 model    : the CIs' finding totals" -Log $Log
}

# THE CI GRID'S FIELDS AS COLUMNS (2026-10-11, owner: "why is the performance so bad"): sidata.Ci column -> CI document field.
# The web app's twin is CiColumns.Promoted (pro-management/src/SI.Management.Core/ProData/CiColumns.cs); a test holds the two
# lists equal. The schema adds the columns (sql/si-data-schema.sql); a bool field is a BIT, the tier explanation NVARCHAR(4000), every other one NVARCHAR(400).
$script:SIDataCiDocFields = [ordered]@{
    AssetSubtype = 'si_asset_subtype'; OsName = 'si_os_name'; OsPlatform = 'si_os_platform'; OsVersion = 'si_os_version'
    OnboardingStatus = 'si_onboarding_status'; Owner = 'si_owner'; Department = 'si_department'; Hostname = 'si_hostname'
    IpAddress = 'si_ip_address'; AzureResourceType = 'si_azure_resource_type'; IdentityType = 'si_identity_type'; Purpose = 'si_purpose'
    AccountEnabled = 'si_account_enabled'; MfaRegistered = 'si_mfa_registered'
    TierExplanation = 'si_tier_explanation'
}
$script:SIDataCiDocBoolFields = @('AccountEnabled', 'MfaRegistered')
# the tier explanation is a sentence (#579), longer than a 400-character cell: NVARCHAR(4000), JSON_VALUE's own limit
$script:SIDataCiDocLongFields = @('TierExplanation')

function Get-SIDataCiDocFieldsSql {
    <#
        The CI grid's fields as columns of sidata.Ci, filled from each CI's document -- SET-BASED, only for the CIs whose
        content hash moved since their columns were filled (DocFieldsHash <> ContentHash; a CI written before content hashes
        existed counts as hash 0x00). The document is parsed ONCE per CI (OPENJSON ... WITH), in batches of -BatchSize so no
        transaction holds the table long. A database without the columns (the schema not updated yet) is skipped -- the
        statement is run from text, so it compiles there too. Answers the number of CIs filled.
    #>
    param([int]$BatchSize = 2000,
          # 2026-10-29 ONE CiId range (/*R:c.CiId*/, Invoke-SIDataCiDocFields): the same UPDATE without the loop -- the loop of
          # batches ran inside ONE command, so the client waited for every batch of the whole table at once
          [switch]$Ranged)
    $set = New-Object System.Collections.Generic.List[string]
    $with = New-Object System.Collections.Generic.List[string]
    foreach ($k in $script:SIDataCiDocFields.Keys) {
        $path = [string]$script:SIDataCiDocFields[$k]
        if ($script:SIDataCiDocBoolFields -contains $k) {
            $set.Add(("[{0}] = CASE LOWER(j.[{0}]) WHEN N''true'' THEN 1 WHEN N''false'' THEN 0 END" -f $k))
            $with.Add(("[{0}] NVARCHAR(8) ''$.{1}''" -f $k, $path))
        } elseif ($k -eq 'IpAddress') {
            # #856 a device's IP address: the public IP of a public IP CI (si_ip_address), else the BEST of the CI's own
            # addresses (si_ip_addresses: an IPv4 address first, loopback last) -- a device Defender only discovered had the
            # column empty although its record carries its addresses. The CI document is not changed (si_ip_address stays the
            # public IP field); the web app reads the same value from the document (CiDisplayName.IpFromDocumentSql).
            $set.Add(("[{0}] = COALESCE(j.[{0}], {1}, j.[IpOne])" -f $k, (Get-SIDataCiBestIpSql -ListJson 'j.[IpList]')))
            $with.Add(("[{0}] NVARCHAR(400) ''$.{1}''" -f $k, $path))
            $with.Add("[IpList] NVARCHAR(MAX) ''$.si_ip_addresses'' AS JSON")
            $with.Add("[IpOne] NVARCHAR(400) ''$.si_ip_addresses''")
        } else {
            $set.Add(("[{0}] = j.[{0}]" -f $k))
            $len = if ($script:SIDataCiDocLongFields -contains $k) { 4000 } else { 400 }
            $with.Add(("[{0}] NVARCHAR({2}) ''$.{1}''" -f $k, $path, $len))
        }
    }
    if ($Ranged) {
        return @"
SET NOCOUNT ON;
IF COL_LENGTH('sidata.Ci', 'DocFieldsHash') IS NULL BEGIN SELECT 0; RETURN; END
DECLARE @n INT;
EXEC sp_executesql N'
SET NOCOUNT ON;
UPDATE c SET $($set -join ', '), DocFieldsHash = ISNULL(c.ContentHash, 0x00)
FROM sidata.Ci AS c
OUTER APPLY OPENJSON(CASE WHEN ISJSON(c.DocJson) = 1 THEN c.DocJson END) WITH ($($with -join ', ')) AS j
WHERE (c.DocFieldsHash IS NULL OR c.DocFieldsHash <> ISNULL(c.ContentHash, 0x00))/*R:c.CiId*/;
SET @n = @@ROWCOUNT;', N'@n INT OUTPUT/*RPL*/', @n = @n OUTPUT/*RPV*/;
SELECT @n;
"@
    }
    @"
SET NOCOUNT ON;
IF COL_LENGTH('sidata.Ci', 'DocFieldsHash') IS NULL BEGIN SELECT 0; RETURN; END
DECLARE @n INT;
EXEC sp_executesql N'
SET NOCOUNT ON;
DECLARE @b INT = 1, @t INT = 0;
WHILE @b > 0
BEGIN
    UPDATE TOP ($BatchSize) c SET $($set -join ', '), DocFieldsHash = ISNULL(c.ContentHash, 0x00)
    FROM sidata.Ci AS c
    OUTER APPLY OPENJSON(CASE WHEN ISJSON(c.DocJson) = 1 THEN c.DocJson END) WITH ($($with -join ', ')) AS j
    WHERE c.DocFieldsHash IS NULL OR c.DocFieldsHash <> ISNULL(c.ContentHash, 0x00);
    SET @b = @@ROWCOUNT; SET @t += @b;
END
$(Get-SIDataCiIpCatchUpSql -BatchSize $BatchSize)
SET @n = @t;', N'@n INT OUTPUT', @n = @n OUTPUT;
SELECT @n;
"@
}

function Get-SIDataCiBestIpSql {
    <#
        PURE. #856 the best IP address of a JSON list (SQL text, quotes doubled for the sp_executesql body it is part of): an
        IPv4 address first, then any other (IPv6), a loopback address last, in list order within each; NULL for none. The
        web app's twin is CiDisplayName.BestIpSql (pro-management/src/SI.Management.Core/ProData/CiDisplayName.cs).
    #>
    param([Parameter(Mandatory)][string]$ListJson)
    "(SELECT TOP (1) CONVERT(nvarchar(400), ip.[value]) FROM OPENJSON($ListJson) AS ip WHERE ip.[type] = 1 AND LEN(ip.[value]) > 0 ORDER BY CASE WHEN ip.[value] LIKE N''127.%'' OR ip.[value] = N''::1'' THEN 2 WHEN ip.[value] LIKE N''%:%'' THEN 1 ELSE 0 END, TRY_CONVERT(int, ip.[key]))"
}

function Get-SIDataCiIpCatchUpSql {
    <#
        #856 ONCE per database: the device CIs whose IpAddress column was filled BEFORE it took the CI's own addresses (their
        content has not moved since, so the fill above does not visit them) get their best address -- set-based, in batches.
        Only rows that GET a value are written, so every batch shrinks the set and the loop ends. Marked done in
        sidata.ViewState ('ci-ip-fill'), so later runs skip it; a database without that table is left as it is (the fill
        above still gives every CI that changes its address). Part of the sp_executesql body of Get-SIDataCiDocFieldsSql.
    #>
    param([int]$BatchSize = 2000)
    @"
IF OBJECT_ID(''sidata.ViewState'') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.ViewState WHERE Name = N''ci-ip-fill'')
BEGIN
    SET @b = 1;
    WHILE @b > 0
    BEGIN
        UPDATE TOP ($BatchSize) c SET IpAddress = x.Ip
        FROM sidata.Ci AS c
        CROSS APPLY (SELECT $(Get-SIDataCiBestIpSql -ListJson "CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_QUERY(c.DocJson, N''$.si_ip_addresses'') END") AS Ip) AS x
        WHERE c.IpAddress IS NULL AND c.Class = N''device'' AND x.Ip IS NOT NULL;
        SET @b = @@ROWCOUNT; SET @t += @b;
    END
    INSERT sidata.ViewState (Name, Value) VALUES (N''ci-ip-fill'', N''1'');
END
"@
}

function Get-SIDataCiIpCatchUpRangeSql {
    <# 2026-10-29 Get-SIDataCiIpCatchUpSql for ONE CiId range (/*R:c.CiId*/), without its loop and its mark (the caller sets the
       mark once every range is done). Answers the CIs written; 0 when the mark is there or the mark table is not. #>
    @"
SET NOCOUNT ON;
IF OBJECT_ID('sidata.ViewState') IS NULL OR EXISTS (SELECT 1 FROM sidata.ViewState WHERE Name = N'ci-ip-fill') BEGIN SELECT 0; RETURN; END
DECLARE @n INT;
EXEC sp_executesql N'
UPDATE c SET IpAddress = x.Ip
FROM sidata.Ci AS c
CROSS APPLY (SELECT $(Get-SIDataCiBestIpSql -ListJson "CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_QUERY(c.DocJson, N''$.si_ip_addresses'') END") AS Ip) AS x
WHERE c.IpAddress IS NULL AND c.Class = N''device'' AND x.Ip IS NOT NULL/*R:c.CiId*/;
SET @n = @@ROWCOUNT;', N'@n INT OUTPUT/*RPL*/', @n = @n OUTPUT/*RPV*/;
SELECT @n;
"@
}

function Invoke-SIDataCiDocFields {
    <#
        2026-10-29 The CI list's columns (Get-SIDataCiDocFieldsSql) and the one-time IP catch-up: on a real database a CiId range
        at a time, each range one command (the same UPDATE, the same expressions, the same CIs picked by their hash); the
        catch-up's mark only after its last range. Any other seam: the one statement of before. Answers the CIs filled.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    if (-not (Test-SIDataRangedSeam $Invoke)) { return [int](& $Invoke (Get-SIDataCiDocFieldsSql) @{} 'scalar') }
    $n = Invoke-SIDataCiRangedStatement -Invoke $Invoke -Sql (Get-SIDataCiDocFieldsSql -Ranged) -What "v3 model    : the CI list's columns" -Log $Log
    $due = $false
    try { $due = ([string](& $Invoke "SELECT CASE WHEN OBJECT_ID('sidata.ViewState') IS NOT NULL AND COL_LENGTH('sidata.Ci', 'IpAddress') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.ViewState WHERE Name = N'ci-ip-fill') THEN 1 ELSE 0 END;" @{} 'scalar') -eq '1') } catch { $due = $false }
    if ($due) {
        $n += Invoke-SIDataCiRangedStatement -Invoke $Invoke -Sql (Get-SIDataCiIpCatchUpRangeSql) -What "v3 model    : the devices' IP address from their own addresses (once)" -Log $Log
        $null = & $Invoke "IF NOT EXISTS (SELECT 1 FROM sidata.ViewState WHERE Name = N'ci-ip-fill') INSERT sidata.ViewState (Name, Value) VALUES (N'ci-ip-fill', N'1'); SELECT 1;" @{} 'scalar'
    }
    [int]$n
}

function Get-SIDataCiStoredColumnsProbeSql {
    <# 1 when sidata.Ci carries the columns the CI views read (the schema of this release), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Ci', 'DocFieldsHash') IS NOT NULL THEN 1 ELSE 0 END"
}

function Invoke-SIDataCiStoredColumns {
    <#
    .SYNOPSIS  The CI views' stored columns are current WHEN THE CI BUILD ENDS: the CI list's columns (Get-SIDataCiDocFieldsSql)
               and the CI context columns of the views (SI-DataViewContext.ps1), for the CIs the build changed. Never throws.
    .NOTES     Called by the CI build as its last write, inside the build's lock (engine\data-model\SI-CiBuildRun.ps1). Before,
               only the data sync filled them -- so from the end of a CI build until the next data sync the web app read every
               changed CI's fields from its document, and the CI views filtered and sorted without their indexes.
               Both statements pick the CIs whose content hash moved since their columns were filled (set-based, in batches):
               a build that changed nothing writes nothing, and the data sync -- which keeps running them -- then finds nothing
               to do. A database without the columns (not updated yet, or an install without the Pro schema) is left alone
               without a word. -Invoke is the build's database seam { param($Sql, $Params, $Mode) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $has = $false
    try { $has = ([string](& $Invoke (Get-SIDataCiStoredColumnsProbeSql) @{} 'scalar') -eq '1') } catch { $has = $false }
    if (-not $has) { return [pscustomobject]@{ Status = 'no-schema'; DocFields = 0; ViewColumns = $null } }
    $nD = 0; $failed = $false
    try { $nD = [int](Invoke-SIDataCiDocFields -Invoke $Invoke) }
    # NEVER A WARNING of the build: a line of level WARN in the CI build's log is an alert, and nothing is wrong with the
    # build or its CIs when this convenience step cannot run -- the data sync fills the columns as it always did (and warns
    # itself if it cannot). What happened is said at INFO, with the reason.
    catch { $failed = $true; & $Log 'INFO' ("CIs: the CI list's columns were not filled at the end of this build ({0}) -- the data sync fills them; until then the CIs page reads those fields from the document." -f $_.Exception.Message) }
    # the CI context of the views: only on a database that has those columns too (its own check); the fill's own lines stay
    # with it -- the build says ONE line of its own below
    $ctx = $null
    try {
        if (-not (Get-Command -Name Invoke-SIDataCiViewColumns -ErrorAction SilentlyContinue)) {
            $ctxScript = Join-Path $PSScriptRoot 'SI-DataViewContext.ps1'
            if (Test-Path -LiteralPath $ctxScript) { . $ctxScript }
        }
        if (Get-Command -Name Invoke-SIDataCiViewColumns -ErrorAction SilentlyContinue) {
            $list = Get-SIViewStoredColumns
            if ($list -and ([string](& $Invoke (Get-SIDataCiContextSchemaCheckSql -List $list) @{} 'scalar') -eq '1')) {
                $ctx = Invoke-SIDataCiViewColumns -Invoke $Invoke -Log { } -List $list
                if ($ctx -and [string]$ctx.Status -ne 'ok') {
                    $failed = $true
                    $why = [string]$ctx.Status; if ($ctx.PSObject.Properties['Error'] -and [string]$ctx.Error) { $why = [string]$ctx.Error }
                    & $Log 'INFO' ("CIs: the CI context columns of the views were not filled at the end of this build ({0}) -- the data sync fills them." -f $why)
                }
            }
        }
    } catch { $failed = $true; & $Log 'INFO' ("CIs: the CI context columns of the views were not filled at the end of this build ({0}) -- the data sync fills them." -f $_.Exception.Message) }
    $nC = 0; if ($ctx -and [string]$ctx.Status -eq 'ok') { $nC = [int]$ctx.Fields }
    if (-not $failed) { & $Log 'INFO' ("CIs: the columns the CI views read are current -- filled on {0} CI(s) this build changed ({1} with their view context)" -f $nD, $nC) }
    return [pscustomobject]@{ Status = $(if ($failed) { 'partial' } else { 'ok' }); DocFields = $nD; ViewColumns = $ctx }
}

# =====================================================================================================================
#  KEY RANGES (2026-10-29): NO COMMAND OF THE DATA SYNC DOES WORK THAT GROWS WITH THE COLLECTION. Live at the largest
#  installs: the findings-per-CI replace ran 4,064 s as one transaction over 1.3 M rows, the CI view columns 8,139 s as one
#  command, the exempted twins past the SQL limit -- one statement is one wait of the client and one transaction of the
#  database, however large the collection grows. Every such step now walks its key in ranges: each range is ONE command and
#  its own transaction, sized from the measured time of the one before (Get-SIDataNextSize: -TargetMs per command, no fixed
#  ceiling), paced by the database's own load, and logged with its rows and seconds. A seam of a real database runs them
#  (marked SISqlRanged: New-SIDataSqlInvoke, New-SIRecordSqlInvoke); a test's fake runs the one statement of before.
# =====================================================================================================================

function Test-SIDataRangedSeam {
    <# PURE. Does this seam run the heavy steps in key ranges (a real database's seam, marked SISqlRanged)? #>
    param($Invoke)
    [bool]($null -ne $Invoke -and $Invoke.PSObject.Properties['SISqlRanged'] -and $Invoke.SISqlRanged)
}

function Get-SIDataKeyRangePredicate {
    <# PURE. ' AND <column> > @RangeLo AND <column> <= @RangeHi' for one range -- each side only when the range has it (the
       first range has no lower bound, the last none above); '' without a range. #>
    param([Parameter(Mandatory)][string]$Column, $Range)
    if ($null -eq $Range) { return '' }
    $p = ''
    if ($Range.HasLo) { $p += (' AND {0} > @RangeLo' -f $Column) }
    if ($Range.HasHi) { $p += (' AND {0} <= @RangeHi' -f $Column) }
    $p
}

function Expand-SIDataRangeMarker {
    <# PURE. Every /*R:<column>*/ of -Sql becomes the range's predicate on that column (Get-SIDataKeyRangePredicate); without
       -Range every marker goes (the one statement of before). /*RP*/, /*RPL*/, /*RPV*/ pass the range on into a dynamic
       statement (sp_executesql): its whole parameter part, the declarations added to a list, the values added to a list. #>
    param([Parameter(Mandatory)][string]$Sql, $Range)
    $r = $Range
    # (a plain loop: a closure handed to the regex could not see the functions the caller loaded)
    $sb = New-Object System.Text.StringBuilder
    $at = 0
    foreach ($m in [regex]::Matches($Sql, '/\*R:([A-Za-z0-9_\.\[\]]+)\*/')) {
        [void]$sb.Append($Sql.Substring($at, $m.Index - $at))
        [void]$sb.Append((Get-SIDataKeyRangePredicate -Column $m.Groups[1].Value -Range $r))
        $at = $m.Index + $m.Length
    }
    [void]$sb.Append($Sql.Substring($at))
    $out = $sb.ToString()
    if ($null -eq $r) { return $out.Replace('/*RP*/', '').Replace('/*RPL*/', '').Replace('/*RPV*/', '') }
    $out.Replace('/*RP*/', ", N'@RangeLo NVARCHAR(450), @RangeHi NVARCHAR(450)', @RangeLo = @RangeLo, @RangeHi = @RangeHi").Replace('/*RPL*/', ', @RangeLo NVARCHAR(450), @RangeHi NVARCHAR(450)').Replace('/*RPV*/', ', @RangeLo = @RangeLo, @RangeHi = @RangeHi')
}

function Add-SIDataRangeParams {
    <# The range's bounds as the statement's parameters @RangeLo / @RangeHi (both always there; NULL where the range is open). #>
    param([Parameter(Mandatory)][hashtable]$Params, $Range)
    $Params['RangeLo'] = $(if ($Range -and $Range.HasLo) { [string]$Range.Lo } else { $null })
    $Params['RangeHi'] = $(if ($Range -and $Range.HasHi) { [string]$Range.Hi } else { $null })
    $Params
}

function Get-SIDataKeyRangeBoundSql {
    <# READS ONLY. The upper bound of the next range of -Column in -Table: the value of the @Take-th row after @RangeLo (every
       row of that value goes with it), and how many rows were looked at (fewer than @Take = the last range). #>
    param([Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Column, [string]$Where = '', [switch]$HasLo)
    $lo = ''; if ($HasLo) { $lo = (' AND {0} > @RangeLo' -f $Column) }
    'SELECT MAX(x.k) AS Hi, COUNT_BIG(*) AS N FROM (SELECT TOP (CONVERT(bigint, @Take)) {1} AS k FROM {0} WHERE {1} IS NOT NULL{2}{3} ORDER BY {1}) AS x;' -f $Table, $Column, $lo, $Where
}

function Get-SIDataRangeAnswerText {
    <# PURE. One range's answer as words for its log line: a number = rows, an object = its Text (else its N). #>
    param($Answer)
    if ($null -eq $Answer) { return 'nothing written' }
    if ($Answer -is [System.ValueType] -or $Answer -is [string]) { return ('{0:N0} row(s)' -f [double]$Answer) }
    if ($Answer.PSObject.Properties['Text'] -and $Answer.Text) { return [string]$Answer.Text }
    if ($Answer.PSObject.Properties['N']) { return ('{0:N0} row(s)' -f [double]$Answer.N) }
    [string]$Answer
}

function Invoke-SIDataKeyRanges {
    <#
        Walks -Column of -Table in ranges of about -FirstTake rows to start with (every row of one key value in one range; the
        first range open below, the last open above, so a row whose key is not in -Table yet -- a staged row -- is in a range
        too) and runs -Step { param($Range) } for each: ONE command, its own transaction. The next range's size follows the
        measured time of this one (Get-SIDataNextSize, -TargetMs); the database's load paces it (Invoke-SISqlPacing). One
        log line per range: -What, its number, what it wrote, its seconds. -After: go on after that key (a stopped run's
        mark). -OnDone { param($Range, $Answer) }: after each range (a mark). Returns every range's answer, in order.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Column,
          [string]$Where = '', [Parameter(Mandatory)][scriptblock]$Step, [string]$What = 'ranges', [AllowNull()]$After = $null,
          [long]$FirstTake = 2000, [long]$TargetMs = 5000, [scriptblock]$Log, [scriptblock]$OnDone)
    # (a test's seam may start with smaller ranges: SIRangeFirstTake)
    if ($Invoke.PSObject.Properties['SIRangeFirstTake'] -and [long]$Invoke.SIRangeFirstTake -gt 0) { $FirstTake = [long]$Invoke.SIRangeFirstTake }
    $take = [Math]::Max(1L, $FirstTake)
    $hasLo = ($null -ne $After -and "$After" -ne ''); $lo = $(if ($hasLo) { [string]$After } else { $null })
    $i = 0; $lastMs = 0L
    $out = New-Object System.Collections.Generic.List[object]
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    $val = { param($row, $n) if ($null -eq $row) { $null } elseif ($row -is [System.Collections.IDictionary]) { $v = $row[$n]; if ($v -is [System.DBNull]) { $null } else { $v } } else { $v = $row.$n; if ($v -is [System.DBNull]) { $null } else { $v } } }
    while ($true) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $take = [Math]::Max(1L, [long][Math]::Floor($take / 2)) } }
        $p = @{ Take = [string]$take }; if ($hasLo) { $p['RangeLo'] = $lo }
        $b = @(@(& $Invoke (Get-SIDataKeyRangeBoundSql -Table $Table -Column $Column -Where $Where -HasLo:$hasLo) $p 'rows') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $hi = & $val $b 'Hi'; $n = & $val $b 'N'; if ($null -eq $n) { $n = 0 }
        $last = ([long]$n -lt $take) -or ($null -eq $hi)
        $i++
        $range = [pscustomobject]@{ Index = $i; HasLo = $hasLo; Lo = $lo; HasHi = (-not $last); Hi = $(if ($last) { $null } else { [string]$hi }) }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ans = & $Step $range
        $lastMs = $sw.ElapsedMilliseconds
        $out.Add($ans)
        if ($Log) { & $Log 'INFO' ('{0} -- range {1}: {2} -- {3:N1} s' -f $What, $i, (Get-SIDataRangeAnswerText $ans), ($lastMs / 1000.0)) }
        if ($OnDone) { & $OnDone $range $ans }
        if ($last) { break }
        $hasLo = $true; $lo = [string]$hi
        if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $take = Get-SIDataNextSize -Current $take -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
    }
    , $out.ToArray()
}

function Invoke-SIDataCiChunks {
    <# Sends items in JSON chunks of -Size; returns the total the SQL reported. -ClearFirst $false: the first chunk is not the
       first of the set (a later page of a paged read) -- -Sql is then never asked for its clearing first statement. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Sql, [AllowEmptyCollection()][object[]]$Items = @(), [int]$Size = 500, [bool]$ClearFirst = $true)
    $n = 0
    for ($i = 0; $i -lt $Items.Count; $i += $Size) {
        $chunk = @($Items[$i..([Math]::Min($i + $Size, $Items.Count) - 1)])
        $p = @{ j = (ConvertTo-Json -InputObject $chunk -Compress -Depth 14) }
        $n += [int](& $Invoke (& $Sql ($i -eq 0 -and $ClearFirst)) $p 'scalar')
    }
    return $n
}

function Get-SIDataCiDisabledOwners {
    <#
        #533 rule 4 -- the finding-lifecycle owner keys of assets whose account is DISABLED in its own directory (this run's
        profiles: Get-SIDisabledAssetIdsKql) and that a setting leaves out of Risk Analysis (SI_DisabledAssets_RiskAnalysis:
        their findings vanish from the collection) or of finding actions (SI_DisabledAssets_StateActions). Their absent
        findings freeze. Returns @{ Owners; Known }: Owners empty when both stages include disabled assets; Known $false when the
        state cannot be read (said) -- the caller then closes nothing this run, because unknown never closes.
    #>
    param([Parameter(Mandatory)][scriptblock]$ReadOrSkip, $Policy, [scriptblock]$Log)
    if (-not (Get-Command -Name Get-SIDisabledAssetPolicy -ErrorAction SilentlyContinue)) {
        . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-DisabledAssets.ps1'))
    }
    if (-not (Get-Command -Name Get-SIDataDisabledOwnerKeys -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataCiLifecycle.ps1') }
    if (-not $Policy) { $Policy = Get-SIDisabledAssetPolicy }
    if ($Policy.Effective.RiskAnalysis -and $Policy.Effective.StateActions) { return [pscustomobject]@{ Owners = @(); Known = $true } }
    try {
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($t in 'SI_Endpoint_Profile_CL', 'SI_Identity_Profile_CL', 'SI_Azure_Profile_CL') {
            $a = & $ReadOrSkip (Get-SIDisabledAssetIdsKql -TableName $t) $t
            foreach ($r in @($a | Where-Object { $_ })) { if ([string]$r.SI_AssetId) { $ids.Add([string]$r.SI_AssetId) } }
        }
        if ($ids.Count -eq 0) { return [pscustomobject]@{ Owners = @(); Known = $true } }
        if (-not (Get-Command -Name Get-SIDataObjectMapKql -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataKql.ps1') }
        $m = & $ReadOrSkip (Get-SIDataObjectMapKql) 'SI_ObjectMap_CL'
        $owners = @(Get-SIDataDisabledOwnerKeys -AssetIds $ids.ToArray() -MapRows @($m | Where-Object { $_ }))
        return [pscustomobject]@{ Owners = $owners; Known = $true }
    } catch {
        if ($Log) { & $Log 'WARN' ("v3 model    : which accounts are disabled could not be read ({0}) -- no finding is closed this run (unknown never closes)" -f $_.Exception.Message) }
        return [pscustomobject]@{ Owners = @(); Known = $false }
    }
}

function Get-SIDataCiOutOfScopeSql {
    <# The CIs every provider record of which is marked out of the collection scope (si_in_scope = false). Guarded. #>
    @'
IF OBJECT_ID('sidata.CiRecord') IS NULL SELECT CAST(NULL AS NVARCHAR(64)) AS CiId WHERE 1 = 0;
ELSE SELECT r.CiId FROM sidata.CiRecord AS r WHERE r.CiId IS NOT NULL
GROUP BY r.CiId
HAVING MIN(CASE WHEN LOWER(JSON_VALUE(r.DocJson, '$.si_in_scope')) = N'false' THEN 1 ELSE 0 END) = 1;
'@
}

function Get-SIDataCiOutOfScopeOwners {
    <#
        CIs follow the collection scope (owner 2026-10-10): the finding-lifecycle owner keys (CI ids) of the CIs the collection
        scope leaves out -- their findings vanish from Risk Analysis because their profile rows are left out, so their absent
        findings FREEZE, never close. Returns @{ Owners; Known }; Known $false when it cannot be read (said) -- the caller then
        closes nothing this run.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    try {
        # flattened: a seam may hand the rows back as ONE array (', @(...)'), which would otherwise be read as a single row
        $rows = @(& $Invoke (Get-SIDataCiOutOfScopeSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        $owners = @($rows | Where-Object { $_ } | ForEach-Object { $x = $_; if ($x -is [System.Collections.IDictionary]) { [string]$x['CiId'] } elseif ($x.PSObject.Properties['CiId']) { [string]$x.CiId } } | Where-Object { $_ } | Sort-Object -Unique)
        return [pscustomobject]@{ Owners = $owners; Known = $true }
    } catch {
        if ($Log) { & $Log 'WARN' ("v3 model    : which CIs the collection scope leaves out could not be read ({0}) -- no finding is closed this run (unknown never closes)" -f $_.Exception.Message) }
        return [pscustomobject]@{ Owners = @(); Known = $false }
    }
}

function Get-SIDataCiLatestCompleteSql {
    <# READS ONLY. The newest COMPLETE Risk Analysis (Detailed) collection's time as ISO text, NULL when there is none. #>
    "SELECT CONVERT(nvarchar(30), MAX(CollectionTime), 126) FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete';"
}

function Get-SIDataCiNoFindingsText {
    <# PURE. The plain sentence when Log Analytics has no finding collection to store but the database holds a complete Risk
       Analysis collection (-LatestComplete, its time); '' when there is none either (a new install: nothing to say). #>
    param($LatestComplete, [int]$LookbackDays = 8,
          # #829 the copy of the findings to Log Analytics is off (the default): the findings per CI come from the database, so
          # what is missing is a Risk Analysis result there that carries its finding keys -- not a copy in Log Analytics
          [switch]$CopyOff)
    if ($null -eq $LatestComplete -or $LatestComplete -is [System.DBNull] -or -not "$LatestComplete".Trim()) { return '' }
    $t = "$LatestComplete".Trim()
    try { $t = ([datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal')).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } catch { }
    if ($CopyOff) {
        return ('the findings per CI were not updated: the Risk Analysis result of {0} in the database carries no findings per CI to make them from, and there is no finding collection in Log Analytics from the last {1} days either. The CIs show no findings, no finding history and nothing is opened or closed until a Risk Analysis Detailed run writes its result -- check that the update has run and that the last Risk Analysis Detailed runs ended well.' -f $t, $LookbackDays)
    }
    ('the findings per CI were not updated: there is no finding collection in Log Analytics from the last {0} days, although the Risk Analysis result of {1} is complete in the database. The CIs show no findings, no finding history and nothing is opened or closed until a Risk Analysis run sends its findings to Log Analytics -- check that Risk Analysis sends to Log Analytics and that its last runs ended well.' -f $LookbackDays, $t)
}

function Test-SIDataCiFindingCopySettled {
    <#
        PURE. #829 Has the copy of the findings in Log Analytics (-CollectionTimeText, the pinned collection) stopped arriving?
        A large install posted 892,520 rows for 5 h+ and a data sync started meanwhile read 733,168 of them before it was
        refused, 4 h later. Settled only when BOTH are shown:
          * the Risk Analysis run that wrote it has ENDED -- a run-health END record (-Runs: StartedAt, DurationSec) whose
            window holds the collection time; Risk Analysis writes the copy BEFORE its END record;
          * its newest row reached Log Analytics at least -SettleMinutes ago (-LastIngestText) -- END and the last rows
            travel separately.
        Anything that cannot be shown is NOT settled (the caller makes the findings from the database at once).
        Returns @{ Settled; Why } (Why: plain words, '' when settled).
    #>
    param([AllowEmptyString()][string]$CollectionTimeText, [AllowEmptyString()][string]$LastIngestText, [AllowEmptyCollection()][object[]]$Runs = @(),
          [datetime]$Now = [datetime]::UtcNow, [int]$SettleMinutes = 10, [int]$SlackMinutes = 15)
    $parse = { param([string]$s) $d = $null; if ($s -and $s.Trim()) { try { $d = [datetime]::Parse($s.Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $d = $null } }; $d }
    $snap = & $parse $CollectionTimeText
    if ($null -eq $snap) { return [pscustomobject]@{ Settled = $false; Why = 'the collection has no time that can be read' } }
    $ended = @($Runs | Where-Object {
            $_ -and $_.StartedAt -and
            ([datetime]$_.StartedAt).ToUniversalTime() -le $snap.AddMinutes($SlackMinutes) -and
            ([datetime]$_.StartedAt).ToUniversalTime().AddSeconds([double]$_.DurationSec).AddMinutes($SlackMinutes) -ge $snap
        })
    if ($ended.Count -eq 0) { return [pscustomobject]@{ Settled = $false; Why = 'the Risk Analysis run that writes it has not ended' } }
    $last = & $parse $LastIngestText
    if ($null -eq $last) { return [pscustomobject]@{ Settled = $false; Why = 'when its last rows arrived cannot be read' } }
    $mins = ($Now.ToUniversalTime() - $last).TotalMinutes
    if ($mins -lt $SettleMinutes) { return [pscustomobject]@{ Settled = $false; Why = ('its last rows arrived {0:N0} minute(s) ago' -f [Math]::Max(0, $mins)) } }
    [pscustomobject]@{ Settled = $true; Why = '' }
}

# #774 THE FINDINGS PER CI FROM THE DATABASE WHEN LOG ANALYTICS HAS NONE (a customer install, 2026-10-19: sidata.CiFinding was EMPTY, every
# CI's risk score blank and OpenFindings 0, because Risk Analysis Detailed -- published from SQL -- never posted SI_Finding_CL).
# The Risk Analysis result Risk Analysis wrote to the database (sidata.Finding, its RaFindingKey = the SI_Finding_CL key:
# '<CI or asset:<id>>|<finding key>') is the same result SI_Finding_CL is made from: when Log Analytics has no finding
# collection, or only one older than the newest complete Risk Analysis collection in the database, the findings per CI are
# made from that collection IN SQL, set-based, with the SI_Finding_CL semantics (Publish-SIFindings / ConvertTo-SIFindingRows):
# one finding per (CI, key), the highest severity and scores, the lowest tier, every report in DetectedBy, every risk-factor
# token once, an exemption when any row had one; the CI by the finding's own CI id, else the CI whose id is the asset id or
# the asset/CI key, else the CI the asset id is a linked object of. Then the same swap, totals and lifecycle follow. Said as a
# WARNING on the run record (the findings were not published), never a blocking guard.
function Get-SIDataCiDbSourceSql {
    <# READS ONLY. The newest COMPLETE Risk Analysis (Detailed) collection that Risk Analysis wrote with its finding keys:
       CollectionId, CollectionTimeText (ISO), FindingRows. No such collection (or no RaFindingKey column yet): no row.
       #881 NO SCAN: the rule is unchanged (every complete collection that holds keyed rows, newest first; its keyed rows
       counted); the filtered index IX_Finding_RaFindingKey (sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL,
       sql\si-data-schema.sql -- on a large table built on its own, resumable) answers both the test and the count from the
       keyed rows' collection ids alone. Before it, every finding of every collection was read on every run. #>
    @'
SET NOCOUNT ON;
IF COL_LENGTH('sidata.Finding', 'RaFindingKey') IS NULL OR OBJECT_ID('sidata.Collection') IS NULL
    SELECT TOP (0) CAST(0 AS int) AS CollectionId, CAST(NULL AS nvarchar(30)) AS CollectionTimeText, CAST(0 AS bigint) AS FindingRows;
ELSE EXEC sp_executesql N'
SELECT TOP (1) c.CollectionId, CONVERT(nvarchar(30), c.CollectionTime, 126) AS CollectionTimeText,
       (SELECT COUNT_BIG(*) FROM sidata.Finding f WHERE f.CollectionId = c.CollectionId AND f.RaFindingKey IS NOT NULL) AS FindingRows
FROM sidata.Collection c
WHERE c.Kind = N''Detailed'' AND c.Status = N''Complete''
  AND EXISTS (SELECT 1 FROM sidata.Finding f WHERE f.CollectionId = c.CollectionId AND f.RaFindingKey IS NOT NULL)
ORDER BY c.CollectionTime DESC;';
'@
}

function Read-SIDataCiDbSource {
    <# The database's newest keyed Risk Analysis collection (Get-SIDataCiDbSourceSql) as @{ CollectionId; TimeText; Time; Rows },
       $null when there is none or it cannot be read (said at INFO: Log Analytics' findings are then used as before). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    try {
        $rows = @(& $Invoke (Get-SIDataCiDbSourceSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        foreach ($h in $rows) {
            $get = { param($n) if ($h -is [System.Collections.IDictionary]) { if ($h.Contains($n)) { $h[$n] } else { $null } } elseif ($h.PSObject.Properties[$n]) { $h.$n } else { $null } }
            $cid = & $get 'CollectionId'; $tt = & $get 'CollectionTimeText'; $fr = & $get 'FindingRows'
            if ($null -eq $cid -or $cid -is [System.DBNull] -or $null -eq $tt -or $tt -is [System.DBNull]) { continue }
            $t = $null
            try { $t = [datetime]::Parse([string]$tt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { continue }
            $n = 0L; if ($null -ne $fr -and $fr -isnot [System.DBNull]) { $n = [long]$fr }
            return [pscustomobject]@{ CollectionId = [int]$cid; TimeText = [string]$tt; Time = $t; Rows = $n }
        }
        return $null
    } catch {
        if ($Log) { & $Log 'INFO' ("v3 model    : the Risk Analysis result in the database could not be read for the findings per CI ({0}) -- the findings in Log Analytics are used" -f $_.Exception.Message) }
        return $null
    }
}

function Get-SIDataCiDbFallbackTime {
    <# PURE. The database collection's time as people read it ('yyyy-MM-dd HH:mm UTC'). #>
    param($Source)
    if ($null -eq $Source -or $null -eq $Source.Time) { return '' }
    ([datetime]$Source.Time).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Get-SIDataCiDbFallbackText {
    <#
        PURE. '' = the findings per CI come from Log Analytics as before. Else the plain sentence why they are made from the
        database: Log Analytics has no finding collection (-LaRows 0), or its newest one (-LaTimeText) is older than the
        database's newest complete Risk Analysis collection (-Source, Read-SIDataCiDbSource) that holds findings.
    #>
    param($Source, [long]$LaRows = 0, [string]$LaTimeText = '', [int]$LookbackDays = 8)
    if ($null -eq $Source -or [long]$Source.Rows -le 0 -or $null -eq $Source.Time) { return '' }
    $fmt = { param([datetime]$d) $d.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' }
    $tDb = Get-SIDataCiDbFallbackTime $Source
    if ($LaRows -gt 0) {
        $tLa = $null
        try { $tLa = [datetime]::Parse($LaTimeText, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $tLa = $null }
        # a time that cannot be read is not judged older: Log Analytics' collection is used as before
        if ($null -eq $tLa -or $tLa -ge ([datetime]$Source.Time).AddSeconds(-1)) { return '' }
        return ('the findings per CI were made from the Risk Analysis result of {0} in the database: the newest finding collection in Log Analytics ({1}) is older -- Risk Analysis did not publish the findings of its last Detailed run; check that run''s log' -f $tDb, (& $fmt $tLa))
    }
    return ('the findings per CI were made from the Risk Analysis result of {0} in the database: there is no finding collection in Log Analytics from the last {1} days -- Risk Analysis did not publish its findings; check that it sends to Log Analytics and that its last Detailed run ended well' -f $tDb, $LookbackDays)
}

function Get-SIDataCiFindingFromDbSql {
    <#
        ONE statement, one transaction: the findings per CI of one Risk Analysis collection (@CollectionId) into the staging
        table (emptied first), from sidata.Finding -- the SI_Finding_CL semantics (see above). @B0 / @B1 / @B2: the rating
        bands (critical / high / moderate, invariant text). Answers the findings staged; Get-SIDataCiFindingSwapSql follows.
        -SubCi / -Category (a database that has those columns on both tables, as Get-SIDataWriteCiFindingSql): the ServiceNow
        sub-CI, patch cycle and CVE published date / the category and subcategory are filled too, from the SAME fields the
        Log Analytics path reads (the Risk Analysis row: si_servicenow_subci, si_patch_cycle, si_cve_published; si_category
        else Category, si_subcategory else Subcategory) -- here out of the finding's DetailJson, the first row of each key.
    #>
    param([switch]$SubCi, [switch]$Category,
          # #639 ONE KEY RANGE of the collection (Invoke-SIDataCiFindingFromDbRanged): the rows are read from the work table
          # (sidata.CiFindingDbWork, filled from sidata.Finding a page of ids at a time) for the key hashes in (@After,
          # @Upper] -- every row of a finding key is in one range -- and ADDED to the staging table (emptied before the first
          # range), each range its own statement; the swap follows once every range is in
          [switch]$FromWork)
    $raf = ''; $ins = ''; $val = ''; $doc = ''
    if ($SubCi) {
        $raf += ",`n       NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '`$.si_servicenow_subci'))), 64), N'') AS SubCi," +
                " NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '`$.si_patch_cycle'))), 64), N'') AS PatchCycle," +
                " JSON_VALUE(f.DetailJson, '`$.si_cve_published') AS CvePublished"
        $ins += ', SubCi, PatchCycle, CvePublished'
        $val += ', f1.SubCi, f1.PatchCycle, TRY_CONVERT(datetime2(3), LEFT(f1.CvePublished, 23), 127)'
        $doc += ', f1.SubCi AS si_servicenow_subci, f1.PatchCycle AS si_patch_cycle, f1.CvePublished AS si_cve_published'
    }
    if ($Category) {
        $raf += ",`n       NULLIF(LEFT(LTRIM(RTRIM(COALESCE(NULLIF(JSON_VALUE(f.DetailJson, '`$.si_category'), N''), JSON_VALUE(f.DetailJson, '`$.Category')))), 256), N'') AS Cat," +
                " NULLIF(LEFT(LTRIM(RTRIM(COALESCE(NULLIF(JSON_VALUE(f.DetailJson, '`$.si_subcategory'), N''), JSON_VALUE(f.DetailJson, '`$.Subcategory')))), 256), N'') AS SubCat"
        $ins += ', Category, Subcategory'
        $val += ', f1.Cat, f1.SubCat'
        $doc += ', f1.Cat AS si_category, f1.SubCat AS si_subcategory'
    }
    $text = (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @cid INT = CONVERT(int, @CollectionId);
DECLARE @band0 FLOAT = CONVERT(float, @B0), @band1 FLOAT = CONVERT(float, @B1), @band2 FLOAT = CONVERT(float, @B2);
DECLARE @ct DATETIME2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @cid);
IF OBJECT_ID('tempdb..#raf') IS NOT NULL DROP TABLE #raf;
SELECT f.FindingId, f.RaSeq, f.RaFindingKey, f.AssetKey, f.RaAssetId, f.ConfigurationId, f.Title, f.AssetName, f.SecurityDomain, f.ReportName,
       f.Tier, f.RiskScore, f.ExemptionId,
       COALESCE(TRY_CONVERT(float, JSON_VALUE(f.DetailJson, '$.RiskScoreTotal_Weighted')), f.RiskScoreWeighted) AS Weighted,
       NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_component'))), N'') AS Component,
       CONCAT(JSON_VALUE(f.DetailJson, '$.RiskFactor_Probability_Detailed'), N';', JSON_VALUE(f.DetailJson, '$.RiskFactor_Consequence_Detailed')) AS Factors,
       CASE LOWER(LTRIM(RTRIM(f.Severity))) WHEN N'very high' THEN 4 WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium-high' THEN 2
            WHEN N'medium' THEN 2 WHEN N'moderate' THEN 2 WHEN N'low' THEN 1 ELSE 0 END AS SevRank,
       ROW_NUMBER() OVER (PARTITION BY f.RaFindingKey ORDER BY f.RaSeq, f.FindingId) AS Rn/*raf*/
INTO #raf
FROM sidata.Finding f
WHERE f.CollectionId = @cid AND f.RaFindingKey IS NOT NULL AND CHARINDEX(N'|', f.RaFindingKey) > 1;
CREATE CLUSTERED INDEX CX_raf ON #raf (RaFindingKey, RaSeq);
BEGIN TRAN;
DELETE FROM sidata.CiFindingStage;
INSERT sidata.CiFindingStage (CiId, AssetId, FindingKey, FindingType, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, ExemptionId, CollectionTime, DocJson, Component/*ins*/)
SELECT COALESCE(k.OwnerCi, ci.CiId, ck.CiId, lk.CiId), LEFT(ISNULL(k.AssetIdK, N''), 400), LEFT(k.FKey, 256), v.FType, LEFT(f1.Title, 1000), v.Sev, g.Tier, v.Score,
       v.Weighted, v.Rating, LEFT(f1.SecurityDomain, 64), LEFT(rep.Reports, 2000), LEFT(fac.Factors, 2000), CONVERT(nvarchar(64), g.ExemptionId),
       ISNULL(@ct, SYSUTCDATETIME()),
       (SELECT k.OwnerCi AS si_ci_id, k.AssetIdK AS si_asset_id, k.FKey AS si_finding_key, v.FType AS si_finding_type, v.Cve AS si_cve, f1.Title AS si_title,
               f1.AssetName AS si_asset_name, f1.SecurityDomain AS si_security_domain, rep.FirstReport AS si_report_name, JSON_QUERY(rep.ReportsJson) AS si_detected_by,
               v.Sev AS si_severity, v.Score AS si_risk_score, v.Weighted AS si_weighted_risk_score, v.Rating AS si_risk_rating,
               JSON_QUERY(fac.FactorsJson) AS si_finding_risk_factors, g.Cnt AS si_finding_rows, CONVERT(nvarchar(30), @ct, 127) AS si_collection_time,
               g.Tier AS si_tier, CONVERT(nvarchar(64), g.ExemptionId) AS si_exemption_id, cp.Component AS si_component/*doc*/, N'database' AS si_finding_source
        FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
       NULLIF(LEFT(cp.Component, 64), N'')/*val*/
FROM (SELECT RaFindingKey, MIN(Tier) AS Tier, MAX(RiskScore) AS Score, MAX(Weighted) AS Weighted, MAX(SevRank) AS SevRank, MAX(ExemptionId) AS ExemptionId, COUNT(*) AS Cnt
      FROM #raf GROUP BY RaFindingKey) g
JOIN #raf f1 ON f1.RaFindingKey = g.RaFindingKey AND f1.Rn = 1
CROSS APPLY (SELECT LEFT(g.RaFindingKey, CHARINDEX(N'|', g.RaFindingKey) - 1) AS Owner, SUBSTRING(g.RaFindingKey, CHARINDEX(N'|', g.RaFindingKey) + 1, 900) AS KeyPart) o
CROSS APPLY (SELECT CASE WHEN o.Owner LIKE N'asset:%' THEN NULL ELSE LEFT(o.Owner, 64) END AS OwnerCi,
                    CASE WHEN o.Owner LIKE N'asset:%' THEN SUBSTRING(o.Owner, 7, 450) END AS AssetIdK,
                    CASE WHEN LOWER(f1.ConfigurationId) = o.KeyPart THEN f1.ConfigurationId ELSE o.KeyPart END AS FKey) k
CROSS APPLY (SELECT CASE WHEN k.FKey LIKE N'CVE-[0-9][0-9][0-9][0-9]-%' THEN N'cve' ELSE N'recommendation' END AS FType,
                    CASE WHEN k.FKey LIKE N'CVE-[0-9][0-9][0-9][0-9]-%' THEN UPPER(k.FKey) END AS Cve,
                    CASE g.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END AS Sev,
                    ROUND(g.Score, 0) AS Score, ROUND(g.Weighted, 0) AS Weighted,
                    CASE WHEN g.Score IS NULL THEN N'low' WHEN g.Score >= @band0 THEN N'critical' WHEN g.Score >= @band1 THEN N'high' WHEN g.Score >= @band2 THEN N'moderate' ELSE N'low' END AS Rating) v
OUTER APPLY (SELECT TOP (1) x.Component FROM #raf x WHERE x.RaFindingKey = g.RaFindingKey AND x.Component IS NOT NULL
             ORDER BY CASE WHEN x.Component = N'Other' THEN 1 ELSE 0 END, x.RaSeq) cp
OUTER APPLY (SELECT STRING_AGG(CONVERT(nvarchar(max), d.ReportName), N'; ') WITHIN GROUP (ORDER BY d.S) AS Reports,
                    N'[' + STRING_AGG(CONVERT(nvarchar(max), N'"' + STRING_ESCAPE(d.ReportName, 'json') + N'"'), N',') WITHIN GROUP (ORDER BY d.S) + N']' AS ReportsJson,
                    MIN(CASE WHEN d.Pos = 1 THEN d.ReportName END) AS FirstReport
             FROM (SELECT x.ReportName, MIN(x.RaSeq) AS S, ROW_NUMBER() OVER (ORDER BY MIN(x.RaSeq)) AS Pos FROM #raf x
                   WHERE x.RaFindingKey = g.RaFindingKey AND x.ReportName IS NOT NULL GROUP BY x.ReportName) d) rep
OUTER APPLY (SELECT STRING_AGG(CONVERT(nvarchar(max), t.Tok), N';') WITHIN GROUP (ORDER BY t.S) AS Factors,
                    N'[' + STRING_AGG(CONVERT(nvarchar(max), N'"' + STRING_ESCAPE(t.Tok, 'json') + N'"'), N',') WITHIN GROUP (ORDER BY t.S) + N']' AS FactorsJson
             FROM (SELECT LTRIM(RTRIM(s.value)) AS Tok, MIN(x.RaSeq) AS S FROM #raf x CROSS APPLY STRING_SPLIT(x.Factors, N';') s
                   WHERE x.RaFindingKey = g.RaFindingKey AND LTRIM(RTRIM(s.value)) <> N'' GROUP BY LTRIM(RTRIM(s.value))) t) fac
OUTER APPLY (SELECT TOP (1) c.CiId FROM sidata.Ci c WHERE k.OwnerCi IS NULL AND LEN(k.AssetIdK) BETWEEN 1 AND 64 AND c.CiId = k.AssetIdK) ci
OUTER APPLY (SELECT TOP (1) c.CiId FROM sidata.Ci c WHERE k.OwnerCi IS NULL AND ci.CiId IS NULL AND LEN(f1.AssetKey) BETWEEN 1 AND 64 AND c.CiId = f1.AssetKey) ck
OUTER APPLY (SELECT TOP (1) l.CiId FROM sidata.CiLink l
             WHERE k.OwnerCi IS NULL AND ci.CiId IS NULL AND ck.CiId IS NULL AND LEN(k.AssetIdK) BETWEEN 1 AND 450 AND l.NativeId = LOWER(k.AssetIdK)
             ORDER BY l.IsPrimary DESC, CASE WHEN l.State IN (N'active', N'frozen') THEN 0 ELSE 1 END, l.LastSeen DESC) lk;
DECLARE @n INT = @@ROWCOUNT;
COMMIT;
DROP TABLE #raf;
SELECT @n;
'@)
    if ($FromWork) {
        # the same statement over ONE key range of the work table (its rows already projected), added to the staging table
        $a = $text.IndexOf('SELECT f.FindingId, f.RaSeq'); $b = $text.IndexOf("CHARINDEX(N'|', f.RaFindingKey) > 1;")
        if ($a -lt 0 -or $b -lt 0) { throw 'the findings-per-CI statement is not in the shape its key ranges are cut from' }
        $b += "CHARINDEX(N'|', f.RaFindingKey) > 1;".Length
        $wcols = 'w.FindingId, w.RaSeq, w.RaFindingKey, w.AssetKey, w.RaAssetId, w.ConfigurationId, w.Title, w.AssetName, w.SecurityDomain, w.ReportName, w.Tier, w.RiskScore, w.ExemptionId, w.Weighted, w.Component, w.Factors, w.SevRank'
        if ($SubCi) { $wcols += ', w.SubCi, w.PatchCycle, w.CvePublished' }
        if ($Category) { $wcols += ', w.Cat, w.SubCat' }
        $sel = "SELECT $wcols, ROW_NUMBER() OVER (PARTITION BY w.RaFindingKey ORDER BY w.RaSeq, w.FindingId) AS Rn`nINTO #raf`nFROM sidata.CiFindingDbWork w`nWHERE w.KeyHash > CONVERT(bigint, @After) AND w.KeyHash <= CONVERT(bigint, @Upper);"
        $text = $text.Substring(0, $a) + $sel + $text.Substring($b)
        # (the line, whatever line ending the file was checked out with)
        $text = [regex]::Replace($text, 'DELETE FROM sidata\.CiFindingStage;\r?\n', '')
    }
    $text = $text.Replace('/*raf*/', $raf).Replace('/*ins*/', $ins).Replace('/*doc*/', $doc).Replace('/*val*/', $val)
    if ($FromWork) {
        # #879 the range's findings are made into a temp table first and added to the staging table in one short insert at
        # the end: ranges that run at once never wait on each other's locks on the staging table while they compute
        $m = [regex]::Match($text, 'INSERT sidata\.CiFindingStage \(([^)]*)\)')
        if (-not $m.Success) { throw 'the findings-per-CI statement is not in the shape its key ranges are cut from' }
        $cols = $m.Groups[1].Value
        $text = [regex]::Replace($text, 'BEGIN TRAN;\r?\n', ("SELECT TOP (0) {0} INTO #st FROM sidata.CiFindingStage;`n" -f $cols))
        $text = $text.Replace('INSERT sidata.CiFindingStage (' + $cols + ')', 'INSERT #st (' + $cols + ')')
        $text = [regex]::Replace($text, 'DECLARE @n INT = @@ROWCOUNT;\r?\nCOMMIT;\r?\n',
            ("BEGIN TRAN;`nINSERT sidata.CiFindingStage ({0}) SELECT {0} FROM #st;`nDECLARE @n INT = @@ROWCOUNT;`nCOMMIT;`nDROP TABLE #st;`n" -f $cols))
    }
    $text
}

# ---- #639 the findings per CI from the database in KEY RANGES (30 M rows were one transaction past the 1,800 s limit) ----

function Get-SIDataCiDbWorkTableSql {
    <# The work table of the ranged path (the same text as sql/si-data-schema.sql; additive). Answers a marker row when it is there. #>
    @'
IF OBJECT_ID(N'sidata.CiFindingDbWork') IS NULL
CREATE TABLE sidata.CiFindingDbWork (
    WorkId          BIGINT IDENTITY(1, 1) NOT NULL,
    KeyHash         INT            NOT NULL,
    FindingId       BIGINT         NOT NULL,
    RaSeq           BIGINT         NULL,
    RaFindingKey    NVARCHAR(900)  NOT NULL,
    AssetKey        NVARCHAR(400)  NULL,
    RaAssetId       NVARCHAR(400)  NULL,
    ConfigurationId NVARCHAR(256)  NULL,
    Title           NVARCHAR(1000) NULL,
    AssetName       NVARCHAR(400)  NULL,
    SecurityDomain  NVARCHAR(128)  NULL,
    ReportName      NVARCHAR(256)  NULL,
    Tier            TINYINT        NULL,
    RiskScore       FLOAT          NULL,
    ExemptionId     BIGINT         NULL,
    Weighted        FLOAT          NULL,
    Component       NVARCHAR(4000) NULL,
    Factors         NVARCHAR(MAX)  NULL,
    SevRank         INT            NOT NULL,
    SubCi           NVARCHAR(64)   NULL,
    PatchCycle      NVARCHAR(64)   NULL,
    CvePublished    NVARCHAR(4000) NULL,
    Cat             NVARCHAR(256)  NULL,
    SubCat          NVARCHAR(256)  NULL,
    CONSTRAINT PK_CiFindingDbWork PRIMARY KEY CLUSTERED (KeyHash, WorkId)
);
IF OBJECT_ID(N'sidata.CiFindingDbWork') IS NOT NULL SELECT N'si-ci-dbwork' AS Ready;
'@
}

function Get-SIDataCiDbWorkFillSql {
    <# ONE RANGE of the collection's keyed rows (@After < FindingId <= @Upto, sidata.Finding's own key: a clustered-key seek)
       projected into the work table with the hash of their finding key. #879: the rows are made into a temp table first
       (the read of every finding's JSON -- the slow part) and added to the work table in one short insert, so ranges that
       run at once never wait on each other's locks on the work table while they read. Answers the rows added. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @cid INT = CONVERT(int, @CollectionId);
IF OBJECT_ID('tempdb..#w') IS NOT NULL DROP TABLE #w;
SELECT CHECKSUM(f.RaFindingKey) AS KeyHash, f.FindingId, f.RaSeq, f.RaFindingKey, f.AssetKey, f.RaAssetId, f.ConfigurationId, f.Title, f.AssetName, f.SecurityDomain, f.ReportName,
       f.Tier, f.RiskScore, f.ExemptionId,
       COALESCE(TRY_CONVERT(float, JSON_VALUE(f.DetailJson, '$.RiskScoreTotal_Weighted')), f.RiskScoreWeighted) AS Weighted,
       NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_component'))), N'') AS Component,
       CONCAT(JSON_VALUE(f.DetailJson, '$.RiskFactor_Probability_Detailed'), N';', JSON_VALUE(f.DetailJson, '$.RiskFactor_Consequence_Detailed')) AS Factors,
       CASE LOWER(LTRIM(RTRIM(f.Severity))) WHEN N'very high' THEN 4 WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium-high' THEN 2
            WHEN N'medium' THEN 2 WHEN N'moderate' THEN 2 WHEN N'low' THEN 1 ELSE 0 END AS SevRank,
       NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_servicenow_subci'))), 64), N'') AS SubCi,
       NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_patch_cycle'))), 64), N'') AS PatchCycle,
       JSON_VALUE(f.DetailJson, '$.si_cve_published') AS CvePublished,
       NULLIF(LEFT(LTRIM(RTRIM(COALESCE(NULLIF(JSON_VALUE(f.DetailJson, '$.si_category'), N''), JSON_VALUE(f.DetailJson, '$.Category')))), 256), N'') AS Cat,
       NULLIF(LEFT(LTRIM(RTRIM(COALESCE(NULLIF(JSON_VALUE(f.DetailJson, '$.si_subcategory'), N''), JSON_VALUE(f.DetailJson, '$.Subcategory')))), 256), N'') AS SubCat
INTO #w
FROM sidata.Finding f
WHERE f.CollectionId = @cid AND f.FindingId > CONVERT(bigint, @After) AND f.FindingId <= CONVERT(bigint, @Upto)
  AND f.RaFindingKey IS NOT NULL AND CHARINDEX(N'|', f.RaFindingKey) > 1;
INSERT sidata.CiFindingDbWork (KeyHash, FindingId, RaSeq, RaFindingKey, AssetKey, RaAssetId, ConfigurationId, Title, AssetName, SecurityDomain, ReportName, Tier, RiskScore, ExemptionId,
                               Weighted, Component, Factors, SevRank, SubCi, PatchCycle, CvePublished, Cat, SubCat)
SELECT KeyHash, FindingId, RaSeq, RaFindingKey, AssetKey, RaAssetId, ConfigurationId, Title, AssetName, SecurityDomain, ReportName, Tier, RiskScore, ExemptionId,
       Weighted, Component, Factors, SevRank, SubCi, PatchCycle, CvePublished, Cat, SubCat
FROM #w;
DECLARE @n INT = @@ROWCOUNT;
DROP TABLE #w;
SELECT @n;
'@
}

function Get-SIDataCiDbWorkBoundsSql {
    <# READS ONLY. The collection's first and last FindingId (Lo, Hi; NULL when it has no row) -- a clustered-key seek. #>
    'SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId);'
}

function Get-SIDataCiDbWorkRangeSql {
    <# The upper key hash of the next range: the hash of the @Take-th row after @After (every row of that hash goes with it). NULL at the end. #>
    'SELECT MAX(x.KeyHash) FROM (SELECT TOP (CONVERT(int, @Take)) KeyHash FROM sidata.CiFindingDbWork WHERE KeyHash > CONVERT(bigint, @After) ORDER BY KeyHash) AS x;'
}

function Clear-SIDataCiDbTable {
    <# Empties the work table or the staging table in chunks (one statement over 30 M rows is one transaction). Never a TRUNCATE (the engine has no ALTER).
       -AfterFindingId (the work table only): only its rows past that FindingId -- what a fill that stopped part-way added after its last mark. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('sidata.CiFindingDbWork', 'sidata.CiFindingStage', 'sidata.CiFindingLifecycleStage')][string]$Table, [int]$Take = 50000,
          [AllowNull()][Nullable[long]]$AfterFindingId = $null)
    if ($null -ne $AfterFindingId) {
        if ($Table -ne 'sidata.CiFindingDbWork') { throw 'only the work table is emptied past a FindingId' }
        while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (CONVERT(int, @Take)) FROM sidata.CiFindingDbWork WHERE FindingId > CONVERT(bigint, @After); SELECT @@ROWCOUNT;' @{ Take = $Take; After = [string]$AfterFindingId } 'scalar') -gt 0) { }
        return
    }
    while ([long](& $Invoke ("SET NOCOUNT ON; DELETE TOP (CONVERT(int, @Take)) FROM {0}; SELECT @@ROWCOUNT;" -f $Table) @{ Take = $Take } 'scalar') -gt 0) { }
}

function Test-SIDataCiDbWork {
    <# The ranged path's work table is there (created when missing; $false when it cannot be -- the one-statement path is used). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    # a seam that cannot ANSWER that it is there (a fake, a database the engine may not change) takes the one statement
    try { $a = & $Invoke (Get-SIDataCiDbWorkTableSql) @{} 'reader'; return (@(@($a) | Where-Object { $_ -is [System.Collections.IDictionary] -and [string]$_['Ready'] -eq 'si-ci-dbwork' }).Count -gt 0) } catch { return $false }
}

# ---- #879 the work table is KEPT for the newest collection: a data sync on the same collection does not read every finding's
# JSON again (the fill is the slow part: ~140 s per 100,000 rows read one after another at the largest Pro tenant), and a fill
# a run left half done goes on from its last whole wave. The mark (sidata.ViewState 'ciwork:<collection>') = '<FindingId up
# to which every range is in>;<the rows in the work table>'. It is used only when the work table holds exactly those rows and
# the collection was not derived again after it (an asset merge rewrites a collection's rows and derives it again).

function Get-SIDataCiWorkMarkName {
    <# PURE. The work table's mark of one collection (sidata.ViewState.Name, at most 64). #>
    param([Parameter(Mandatory)][long]$CollectionId)
    ('ciwork:{0}' -f $CollectionId)
}

function ConvertFrom-SIDataCiWorkMark {
    <# PURE. '<upto>;<rows>' -> @{ Upto; Rows }, $null when it is not that shape. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    $m = [regex]::Match([string]$Value, '^\s*(-?\d+);(\d+)\s*$')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ Upto = [long]$m.Groups[1].Value; Rows = [long]$m.Groups[2].Value }
}

function Get-SIDataCiWorkMarkReadSql {
    <# The mark of @CollectionId (@Name), or nothing: none, no mark table, or the collection was derived again after it
       (or is not derived: a collection whose rows may still change is never taken from the work table). #>
    "IF OBJECT_ID('sidata.ViewState') IS NOT NULL SELECT TOP (1) v.Value FROM sidata.ViewState AS v JOIN sidata.Collection AS c ON c.CollectionId = CONVERT(int, @CollectionId) WHERE v.Name = @Name AND c.DerivedAt IS NOT NULL AND DATEADD(second, 1, c.DerivedAt) < v.UpdatedAt;"
}

function Get-SIDataCiWorkMarkWriteSql {
    <# Keep the mark (@Name, @Value). Answers 1 when the mark table is there, 0 when it is not. #>
    "IF OBJECT_ID('sidata.ViewState') IS NULL SELECT 0; ELSE BEGIN UPDATE sidata.ViewState SET Value = @Value, UpdatedAt = SYSUTCDATETIME() WHERE Name = @Name; IF @@ROWCOUNT = 0 INSERT sidata.ViewState (Name, Value) VALUES (@Name, @Value); SELECT 1; END"
}

function Get-SIDataCiWorkMarkClearSql {
    <# Every work-table mark goes (the work table is about to hold another collection). #>
    "IF OBJECT_ID('sidata.ViewState') IS NOT NULL DELETE FROM sidata.ViewState WHERE Name LIKE N'ciwork:%';"
}

function Read-SIDataFillDatabaseKind {
    <#
        2026-10-25 What the database IS, for the number of ranges the findings per CI run at once: the engine (5 = Azure SQL
        Database), its edition and service objective, its DTU limit, and the newest log write of its own load (percent of
        what its tier allows). Each read on its own -- a read that is refused or not there (a local SQL Server has neither
        the DTU columns nor sys.dm_db_resource_stats) leaves that value $null. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $k = [ordered]@{ EngineEdition = $null; Edition = $null; ServiceObjective = $null; DtuLimit = $null; LogWritePercent = $null }
    $one = { param($sql) try { $v = & $Invoke $sql @{} 'scalar'; if ($null -eq $v -or $v -is [System.DBNull]) { $null } else { $v } } catch { $null } }
    $k.EngineEdition = & $one "SELECT CONVERT(int, SERVERPROPERTY('EngineEdition'));"
    $k.Edition = & $one "SELECT CONVERT(nvarchar(64), DATABASEPROPERTYEX(DB_NAME(), 'Edition'));"
    $k.ServiceObjective = & $one "SELECT CONVERT(nvarchar(64), DATABASEPROPERTYEX(DB_NAME(), 'ServiceObjective'));"
    if ([int]("0$($k.EngineEdition)" -replace '[^0-9]', '') -eq 5) {
        $k.DtuLimit = & $one 'SELECT MAX(dtu_limit) FROM sys.dm_user_db_resource_governance WHERE database_id = DB_ID();'
        # the newest minute of the database's own load (4 rows of 15 s)
        $k.LogWritePercent = & $one 'SELECT MAX(avg_log_write_percent) FROM (SELECT TOP (4) avg_log_write_percent FROM sys.dm_db_resource_stats ORDER BY end_time DESC) r;'
    }
    [pscustomobject]$k
}

function Get-SIDataFillRangeCount {
    <#
        PURE. 2026-10-25 (measured on two large installs, S3 / 100 DTU, under LOG_RATE_GOVERNOR): the findings per CI's two
        FindingId ranges at once blocked each other (LCK_M_X on the work table's pages) and gained nothing. So:
          a DTU database (edition Basic / Standard / Premium, a service objective Basic / S<n> / P<n>, or a DTU limit) -> 1
          a database whose log write is at its limit now (at or above -HighPercent, the pacing's HIGH mark)       -> 1
          otherwise                                                     -> -Cores (the database's cores, as before)
        Nothing known = the cores, as before. The ranges are disjoint, so the rows written are the same either way: only
        how many run at once changes. Returns @{ Count; Reason } (Reason = '' when it is the cores).
    #>
    param($Kind, [int]$Cores = 1, [double]$HighPercent = 85)
    $c = [Math]::Max(1, $Cores)
    $g = { param($n) if ($null -eq $Kind) { return $null }; $p = $Kind.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value -and -not ($p.Value -is [System.DBNull])) { $p.Value } else { $null } }
    $ed = [string](& $g 'Edition'); $slo = [string](& $g 'ServiceObjective'); $dtu = & $g 'DtuLimit'; $lw = & $g 'LogWritePercent'
    $isDtu = ($ed -match '^(?i)(Basic|Standard|Premium)$') -or ($slo -match '^(?i)(Basic|S\d+|P\d+)$') -or ($null -ne $dtu -and [double]$dtu -gt 0)
    if ($isDtu) {
        $name = if ($slo) { $slo } elseif ($ed) { $ed } else { 'DTU' }
        return [pscustomobject]@{ Count = 1; Reason = ('a DTU database ({0}): one range at a time -- ranges at once wait on each other''s pages under its log limit and gain nothing' -f $name) }
    }
    if ($null -ne $lw -and [double]$lw -ge $HighPercent) {
        return [pscustomobject]@{ Count = 1; Reason = ('the database''s log write is at {0:N0} % of its limit: one range at a time -- ranges at once would only wait on each other' -f [double]$lw) }
    }
    [pscustomobject]@{ Count = $c; Reason = '' }
}

function Invoke-SIDataCiFindingFromDbRanged {
    <#
        #639 THE FINDINGS PER CI FROM THE DATABASE IN KEY RANGES: the collection's keyed rows are projected into the work table
        a range of ids at a time, then staged a key range at a time (about -RangeTake rows each; every row of a finding key in
        one range, so the SI_Finding_CL semantics of Get-SIDataCiFindingFromDbSql hold), each range its own statement --
        never one transaction over the collection. The staging table is emptied first. Answers the findings staged; the
        one-step swap follows (#834's change-only replace). A failure throws: nothing is swapped, the stored findings stay as
        they are.
        #879 (owner 2026-10-22, "step 2 go": 7+ hours serial on an idle database at the largest Pro tenant) -- AT SCALE:
          * the fill: FindingId ranges run AT ONCE, each on its own connection, as many as the database has cores
            (Get-SIDataFillWorkers), one fewer each time the database is saturated (SI-SqlPacing.ps1) and one more again
            when it is not; the range size is measured (-FillTake is only the first size, -TargetMs what a range aims for);
          * the staging: the key ranges run at once the same way, a wave of ranges at a time;
          * the fill is not done again for the collection the work table already holds (its mark, see above), and a fill
            that stopped part-way goes on from its last whole wave. Without the mark table the work table is emptied at
            the end as before.
        A seam without a connection to hand out (a test's fake) runs the ranges one after another, as before. -Workers:
        0 = the database's cores; 1 = one after another.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][hashtable]$Params, [switch]$SubCi, [switch]$Category,
          [long]$FillTake = 100000, [int]$RangeTake = 100000, [long]$TargetMs = 5000, [int]$Workers = 0, [scriptblock]$Log,
          # how often a long fill says how far it is (seconds; a line only while rows are left)
          [double]$ProgressSeconds = 60)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $cid = [long]$Params.CollectionId
    # the parallel ranges and the database's cores (SI-DataViewContext.ps1; the data sync has it loaded)
    $ci = $null; if ($Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo) { $ci = $Invoke.SIConnectionInfo }
    if ($ci -and -not (Get-Command -Name Invoke-SIDataParallelRanges -ErrorAction SilentlyContinue)) {
        $ctxScript = Join-Path $PSScriptRoot 'SI-DataViewContext.ps1'
        if (Test-Path -LiteralPath $ctxScript) { . $ctxScript }
    }
    if (-not (Get-Command -Name Invoke-SIDataParallelRanges -ErrorAction SilentlyContinue)) { $ci = $null }
    $maxWorkers = 1
    if ($ci -and $Workers -ne 1) { $maxWorkers = $(if ($Workers -gt 1) { $Workers } else { Get-SIDataFillWorkers -Invoke $Invoke }) }
    # 2026-10-25 the database's kind decides (Get-SIDataFillRangeCount): one range at a time on a DTU database or one whose log
    # write is at its limit -- both phases, and the pacing never grows it back past this. -Workers given = that number.
    if ($maxWorkers -gt 1 -and $Workers -le 0) {
        $high = 85.0; if (Get-Command -Name Get-SISqlPacingSettings -ErrorAction SilentlyContinue) { try { $high = [double](Get-SISqlPacingSettings).High } catch { $high = 85.0 } }
        $rc = Get-SIDataFillRangeCount -Kind (Read-SIDataFillDatabaseKind -Invoke $Invoke) -Cores $maxWorkers -HighPercent $high
        if ([int]$rc.Count -lt $maxWorkers) { $maxWorkers = [int]$rc.Count; & $Log 'INFO' ("v3 model    : the findings per CI -- {0}" -f $rc.Reason) }
    }
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    if ($maxWorkers -gt 1) { & $Log 'INFO' ("v3 model    : the findings per CI are made {0} range(s) at a time (the database's cores)" -f $maxWorkers) }

    Clear-SIDataCiDbTable -Invoke $Invoke -Table 'sidata.CiFindingStage'

    # ---- 1. the work table: the collection's keyed rows, kept between runs ------------------------------------------------
    $mark = Get-SIDataCiWorkMarkName -CollectionId $cid
    $bRaw = & $Invoke (Get-SIDataCiDbWorkBoundsSql) @{ CollectionId = [string]$cid } 'reader'
    $b = @($bRaw) | Select-Object -First 1
    $lo = 1L; $hi = 0L
    if ($b -and $null -ne $b['Lo'] -and -not ($b['Lo'] -is [System.DBNull])) { $lo = [long]$b['Lo']; $hi = [long]$b['Hi'] }
    $after = $lo - 1; $rows = 0L; $kept = $false
    $wm = $null; try { $wm = ConvertFrom-SIDataCiWorkMark (& $Invoke (Get-SIDataCiWorkMarkReadSql) @{ Name = $mark; CollectionId = [string]$cid } 'scalar') } catch { $wm = $null }
    if ($wm -and $wm.Upto -ge ($lo - 1) -and $wm.Upto -le $hi) {
        # rows a wave that did not end added past the mark go first; then the work table must hold exactly the rows the mark says
        if ($wm.Upto -lt $hi) { Clear-SIDataCiDbTable -Invoke $Invoke -Table 'sidata.CiFindingDbWork' -AfterFindingId $wm.Upto }
        $have = -1L; try { $have = [long](& $Invoke 'SELECT COUNT_BIG(*) FROM sidata.CiFindingDbWork;' @{} 'scalar') } catch { $have = -1L }
        if ($have -eq $wm.Rows) {
            $kept = $true; $after = $wm.Upto; $rows = $wm.Rows
            if ($after -ge $hi) { & $Log 'INFO' ("v3 model    : the findings per CI use the rows of collection {0} already read ({1:N0}) -- the findings are not read again" -f $cid, $rows) }
            else { & $Log 'INFO' ("v3 model    : the findings per CI go on where the last run left reading collection {0}" -f $cid) }
        } else {
            & $Log 'INFO' ("v3 model    : the rows kept for the findings per CI do not match their mark ({0:N0} kept, {1:N0} marked) -- collection {2} is read again" -f $have, $wm.Rows, $cid)
        }
    }
    $canMark = $true
    if (-not $kept) {
        try { $null = & $Invoke (Get-SIDataCiWorkMarkClearSql) @{} 'nonquery' } catch { }
        Clear-SIDataCiDbTable -Invoke $Invoke -Table 'sidata.CiFindingDbWork'
        $after = $lo - 1; $rows = 0L
        try { $canMark = ([string](& $Invoke (Get-SIDataCiWorkMarkWriteSql) @{ Name = $mark; Value = ('{0};0' -f $after) } 'scalar') -eq '1') } catch { $canMark = $false }
    }
    $ok = $false
    try {
        $fill = Get-SIDataCiDbWorkFillSql
        # 2026-10-25 the collection's narrow findings (read ONCE this run, shared with the remediations) where they can be made
        if (Get-Command -Name Use-SIDataFindingNarrow -ErrorAction SilentlyContinue) {
            $nf = $null; try { $nf = ConvertTo-SIDataNarrowSql -Sql $fill } catch { $nf = $null }
            if ($nf -and (Use-SIDataFindingNarrow -Invoke $Invoke -CollectionId $cid -Log $Log)) { $fill = $nf }
        }
        $size = [Math]::Max(1L, $FillTake); $workersNow = $maxWorkers; $lastMs = 0L
        $total = [Math]::Max(0L, $hi - $after); $start = $after
        $clock = [Diagnostics.Stopwatch]::StartNew(); $said = [double]0
        while ($after -lt $hi) {
            # the database's own load paces the ranges (SI-SqlPacing.ps1): fewer and smaller ranges only while it is saturated
            if ($paced) {
                $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log
                if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)); $workersNow = [Math]::Max(1, $workersNow - 1) }
                elseif ($workersNow -lt $maxWorkers -and [string]$pace.State -eq 'normal') { $workersNow++ }
            }
            $wave = New-Object System.Collections.Generic.List[object]
            $from = $after
            for ($k = 0; $k -lt $workersNow -and $from -lt $hi; $k++) { $to = [Math]::Min($hi, $from + $size); $wave.Add(@($from, $to)); $from = $to }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $n = 0L; $ms = 0L
            if ($wave.Count -gt 1) {
                foreach ($r in (Invoke-SIDataParallelRanges -ConnectionInfo $ci -Sql $fill -CollectionId $cid -Ranges $wave.ToArray())) { $n += [long]$r.N; if ([long]$r.Ms -gt $ms) { $ms = [long]$r.Ms } }
            } else {
                $n = [long](& $Invoke $fill @{ CollectionId = [string]$cid; After = [string]$wave[0][0]; Upto = [string]$wave[0][1] } 'scalar')
                $ms = $sw.ElapsedMilliseconds
            }
            $lastMs = $ms; $rows += $n; $after = $from
            # the wave is whole: everything up to $after is in the work table -- the next run starts from there
            if ($canMark) { try { $null = & $Invoke (Get-SIDataCiWorkMarkWriteSql) @{ Name = $mark; Value = ('{0};{1}' -f $after, $rows) } 'scalar' } catch { } }
            $size = Get-SIDataNextSize -Current $size -ElapsedMs $ms -TargetMs $TargetMs -Minimum 1
            $now = $clock.Elapsed.TotalSeconds
            if ($after -lt $hi -and ($now - $said) -ge $ProgressSeconds) {
                $said = $now; $done = $after - $start
                $left = if ($done -gt 0) { ($total - $done) * ($now / $done) } else { 0 }
                & $Log 'INFO' ("v3 model    : the findings per CI -- collection {0} read up to {1:N0} of {2:N0} ids, about {3:N0} min left" -f $cid, $done, $total, [Math]::Ceiling($left / 60))
            }
        }

        # ---- 2. the staging: key ranges, a wave at a time -----------------------------------------------------------------
        $sql = Get-SIDataCiFindingFromDbSql -SubCi:$SubCi -Category:$Category -FromWork
        $staged = 0L; $hAfter = [long][int]::MinValue - 1; $end = $false
        while (-not $end) {
            $wave = New-Object System.Collections.Generic.List[object]
            $prev = $hAfter
            for ($k = 0; $k -lt $maxWorkers; $k++) {
                $u = & $Invoke (Get-SIDataCiDbWorkRangeSql) @{ After = [string]$prev; Take = $RangeTake } 'scalar'
                if ($null -eq $u -or $u -is [System.DBNull]) { $end = $true; break }
                $wave.Add(@($prev, [long]$u)); $prev = [long]$u
            }
            if ($wave.Count -eq 0) { break }
            if ($wave.Count -gt 1) {
                foreach ($r in (Invoke-SIDataParallelRanges -ConnectionInfo $ci -Sql $sql -CollectionId $cid -Ranges $wave.ToArray() -Params $Params -UpperName 'Upper')) { $staged += [long]$r.N }
            } else {
                $p = @{}; foreach ($k2 in $Params.Keys) { $p[$k2] = $Params[$k2] }
                $p['After'] = [string]$wave[0][0]; $p['Upper'] = [string]$wave[0][1]
                $staged += [long](& $Invoke $sql $p 'scalar')
            }
            $hAfter = $prev
        }
        $ok = $true
        return $staged
    } finally {
        # without the mark table the work table is not kept (as before); a failed fill keeps what its whole waves wrote
        if (-not $canMark) { try { Clear-SIDataCiDbTable -Invoke $Invoke -Table 'sidata.CiFindingDbWork' } catch { } }
        elseif (-not $ok -and $after -lt $hi) { & $Log 'INFO' ("v3 model    : the rows of collection {0} read so far for the findings per CI are kept -- the next run goes on from there" -f $cid) }
    }
}

function Get-SIDataCiLifecycleFromStageSql {
    <# The lifecycle input (Kind f) of the findings staged from the database -- what ConvertTo-SIDataFindingStateItems makes of
       the Log Analytics items: owner = the finding's own CI id, else 'asset:<asset id>'. Empties the staging table first. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRAN;
DELETE FROM sidata.CiFindingLifecycleStage;
INSERT sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey, CiId, Severity, DetectedBy, ExemptionId)
SELECT N'f', LEFT(COALESCE(o.Ci, N'asset:' + LOWER(NULLIF(s.AssetId, N''))), 450), LEFT(s.FindingKey, 256), LEFT(o.Ci, 64), LEFT(s.Severity, 16), LEFT(s.DetectedBy, 2000), LEFT(s.ExemptionId, 64)
FROM sidata.CiFindingStage s
CROSS APPLY (SELECT NULLIF(JSON_VALUE(s.DocJson, '$.si_ci_id'), N'') AS Ci) o
WHERE s.FindingKey IS NOT NULL AND COALESCE(o.Ci, NULLIF(s.AssetId, N'')) IS NOT NULL;
DECLARE @n INT = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
}

function Get-SIDataCiRatingBandParams {
    <# The rating bands as the statement's parameters (invariant text): the data-model's bands when loaded, else 50 / 30 / 15. #>
    $b = @(50.0, 30.0, 15.0)
    if (Get-Command -Name Get-RARiskRatingBands -ErrorAction SilentlyContinue) { try { $x = [double[]]@(Get-RARiskRatingBands); if ($x.Count -eq 3) { $b = $x } } catch { } }
    $ci = [Globalization.CultureInfo]::InvariantCulture
    @{ B0 = ([double]$b[0]).ToString($ci); B1 = ([double]$b[1]).ToString($ci); B2 = ([double]$b[2]).ToString($ci) }
}

function Invoke-SIDataCiSync {
    <#
    .SYNOPSIS  SI_Finding_CL -> the Pro database, then the CIs' finding totals in SQL. Returns a summary; never throws.
    .NOTES     The CIs and the provider records are NOT read here any more: the CI build writes them to the database itself.
               #639 THE NEWEST FINDING COLLECTION IS READ IN PAGES AND COUNTED (see Get-SIDataCiFindingCountKql above):
                 1. one count query pins the collection (its time, its rows, its size); none = nothing to store;
                 2. its rows are read a page at a time (Read-SIDataPages: a page too large to answer or to hold is read
                    again in two halves) and each page is STAGED before the next is read -- the findings in chunks into
                    sidata.CiFindingStage, the lifecycle input in chunks into sidata.CiFindingLifecycleStage (never one JSON
                    string in one parameter). What is held is one page, never the collection;
                 3. ONLY when the rows read equal the collection's count are the stored findings replaced (one transaction,
                    Get-SIDataCiFindingSwapSql) and the lifecycle advanced. A short read replaces nothing and closes nothing:
                    it is FAILED for that collection (working rule 4). A failure anywhere is FAILED too, said in plain words.
               Issues: every caught failure as @{ Level = WARNING | FAILED; Text } (SI-RunOutcome.ps1) -- the data sync's run
               record carries them; nothing here ends green on a failure.
               -LaQuery: the job's raw Log Analytics seam { param($kql) rows } for the page reads. Named so on purpose: the
               page reader's own parameter is -Query, and the data sync's $readOrSkip reads a variable named $Query -- called
               from inside the page reader it would find the page reader's own and call itself. Without -LaQuery (tests) the
               pages are read through -ReadOrSkip.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$ReadOrSkip, [int]$LookbackDays = 8, [switch]$DryRun, [scriptblock]$Log,
          [scriptblock]$LaQuery, [long]$TargetChars = 16MB,
          # #829 the SI_RA_Findings value (the copy of the findings to Log Analytics; not set = off) -- the job's setting by default
          [AllowNull()]$FindingsCopy = $global:SI_RA_Findings,
          # 2026-10-25 the data sync's per-phase timing { param($Name, $Rows) } (log line + cfg.StepPhaseTime); none = not timed
          [scriptblock]$Phase)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $ph = $Phase; if (-not $ph) { $ph = { param($Name, $Rows) } }
    $issues = New-Object System.Collections.Generic.List[object]
    $say = { param([string]$lvl, [string]$text) $issues.Add([pscustomobject]@{ Level = $lvl; Text = $text }) }
    try {
        if (-not $DryRun) { [void](& $Invoke (Get-SIDataCiTablesSql) @{} 'scalar') }
        # #881 a stored column the schema added is filled for the findings already stored, a range at a time (a real database)
        if (-not $DryRun -and $Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo) { $null = Invoke-SIDataCiColumnBackfill -Invoke $Invoke -Log $Log }
        # the page reader and its helpers (the data sync has them loaded; a caller of this file alone gets them here)
        if (-not (Get-Command -Name Read-SIDataPages -ErrorAction SilentlyContinue)) {
            $sharedRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            if (-not (Get-Command -Name Get-SIKqlErrorText -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($sharedRoot, '_shared', 'SI-KqlError.ps1')) }
            if (-not (Get-Command -Name ConvertTo-SIDataNumber -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\data-sql\SI-DataModel.ps1') }
            if (-not (Get-Command -Name Get-SIDataPageFilter -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataKql.ps1') }
            . (Join-Path $PSScriptRoot 'SI-DataSync.ps1')
        }
        if (-not (Get-Command -Name Invoke-SIDataCiLifecycle -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataCiLifecycle.ps1') }

        # #829 "Copy findings per CI to Log Analytics (SI_Finding_CL)" -- an optional output of Risk Analysis, OFF by default
        # (SI_RA_Findings, read by the engine's own rule: Test-SIFindingsCopyOn). Off: the findings per CI are made from the
        # Risk Analysis result in the database -- the NORMAL path, one plain line, Log Analytics is not read. On: Log
        # Analytics is read only when its collection is the newest and whole, and never while it is still being written.
        $copyOn = $false
        try {
            if (-not (Get-Command -Name Test-SIFindingsCopyOn -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'risk-analysis', '_shared', 'RA-Findings.ps1')) }
            $copyOn = [bool](Test-SIFindingsCopyOn -Value $FindingsCopy)
        } catch { $copyOn = $false }
        $expected = 0L; $timeText = ''; $bytes = 0.0; $lastIngest = ''
        $dbSrc = $null; $dbWhy = ''; $dbNote = ''
        if (-not $copyOn -and -not $DryRun) { $dbSrc = Read-SIDataCiDbSource -Invoke $Invoke -Log $Log }
        # a database without that result (not updated yet, or no Detailed run yet) reads Log Analytics as before
        $sqlNormal = (-not $copyOn -and $null -ne $dbSrc -and [long]$dbSrc.Rows -gt 0)

        # ---- 1. the collection, pinned and counted -------------------------------------------------------------------
        if (-not $sqlNormal) {
            # a reader answer is ONE array object (the data sync's $readOrSkip): ASSIGNED first, then enumerated; a table
            # that does not exist yet answers $null
            $cAns = & $ReadOrSkip (Get-SIDataCiFindingCountKql -LookbackDays $LookbackDays) 'SI_Finding_CL'
            $c0 = @(@($cAns) | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Rows'] }) | Select-Object -First 1
            if ($c0) {
                $n0 = ConvertTo-SIDataNumber $c0.Rows; if ($null -ne $n0) { $expected = [long]$n0 }
                $timeText = [string]$c0.CollectionTimeText
                $b0 = ConvertTo-SIDataNumber $c0.Bytes; if ($null -ne $b0) { $bytes = [double]$b0 }
                if ($c0.PSObject.Properties['LastIngest']) { $lastIngest = [string]$c0.LastIngest }
            }
            if ($expected -gt 0 -and -not $timeText) { throw 'the newest finding collection has rows but no collection time -- it cannot be read whole' }
        }
        if ($copyOn -and -not $DryRun) {
            # #774: no finding collection in Log Analytics, or only one older than the newest complete Risk Analysis result in
            # the database -- the findings per CI are made from that result in SQL (Get-SIDataCiFindingFromDbSql), a WARNING
            $dbSrc = Read-SIDataCiDbSource -Invoke $Invoke -Log $Log
            $dbWhy = Get-SIDataCiDbFallbackText -Source $dbSrc -LaRows $expected -LaTimeText $timeText -LookbackDays $LookbackDays
            # #829 the newest collection, but is it still being written? Checked BEFORE a page is read; not shown = the
            # database at once (one line), never a read that is refused hours later
            if (-not $dbWhy -and $expected -gt 0) {
                $runs = @()
                try {
                    if (-not (Get-Command -Name Get-SIVulnRunHealthKql -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'asset-cmdb', '_shared', 'SI-VulnDesired.ps1')) }
                    $rAns = & $ReadOrSkip (Get-SIVulnRunHealthKql) 'SI_RunHealth_CL'
                    $runs = @(@($rAns) | Where-Object { $_ } | ForEach-Object {
                            $st = $null; try { $st = [datetime]::Parse([string]$_.StartedAt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { }
                            [pscustomobject]@{ StartedAt = $st; DurationSec = $_.DurationSec } })
                } catch { $runs = @() }
                $settle = Test-SIDataCiFindingCopySettled -CollectionTimeText $timeText -LastIngestText $lastIngest -Runs $runs
                if (-not $settle.Settled) {
                    $tLa = $timeText
                    try { $tLa = ([datetime]::Parse($timeText, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal')).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } catch { }
                    if ($null -ne $dbSrc -and [long]$dbSrc.Rows -gt 0) {
                        $dbNote = ('the findings per CI were made from the Risk Analysis result of {0} in the database: the copy of the findings in Log Analytics ({1}) is still being written ({2}) and is not read' -f (Get-SIDataCiDbFallbackTime $dbSrc), $tLa, $settle.Why)
                    } else {
                        $hold = ('the findings per CI were not updated this run: the copy of the findings in Log Analytics ({0}) is still being written ({1}) and the database holds no Risk Analysis result to make them from -- the stored findings are kept as they are and no finding is closed; the next data sync stores them' -f $tLa, $settle.Why)
                        & $Log 'WARN' ('v3 model    : ' + $hold)
                        & $say 'WARNING' $hold
                        return [pscustomobject]@{ Status = 'ok'; Held = $true; Findings = 0; Totals = 0; DryRun = $false; Rows = 0L; Expected = $expected; Issues = $issues.ToArray(); FrozenReports = [string[]]@(); RunComplete = $false }
                    }
                }
            }
        }
        $useDb = $sqlNormal -or [bool]$dbWhy -or [bool]$dbNote
        # no finding collection to store while the database holds a complete Risk Analysis collection: the findings per CI,
        # their lifecycle and their history stay EMPTY (a large install showed 0 lifecycle rows next to ~20,000 CIs) --
        # never silent: one plain warning on the run record (Get-SIDataCiNoFindingsText)
        if ($expected -eq 0 -and -not $DryRun -and -not $useDb) {
            $latest = $null
            try { $latest = & $Invoke (Get-SIDataCiLatestCompleteSql) @{} 'scalar' } catch { $latest = $null }
            $noF = Get-SIDataCiNoFindingsText -LatestComplete $latest -LookbackDays $LookbackDays -CopyOff:(-not $copyOn)
            if ($noF) { & $Log 'WARN' ('v3 model    : ' + $noF); & $say 'WARNING' $noF }
        }

        # ---- 2. the pages, each staged before the next is read -------------------------------------------------------
        $state = @{ Read = 0L; Staged = 0L; LcStaged = 0L; First = $true; PreCleared = $false; Snap = $null; LcStage = $false; Pages = 0L; Cuts = 0L; SubCi = $false; Category = $false }
        if (($expected -gt 0 -or $useDb) -and -not $DryRun) {
            $hasStage = $false
            try { $hasStage = ([string](& $Invoke (Get-SIDataCiFindingStageCheckSql) @{} 'scalar') -eq '1') } catch { $hasStage = $false }
            # a database without the staging table cannot take a collection in pages without emptying the stored findings
            # first -- they are kept as they are instead (the updater adds the table)
            if (-not $hasStage) { throw 'the database does not have the staging table of the findings per CI yet (the updater adds it) -- the stored findings are kept as they are' }
            try { $state.Category = ([string](& $Invoke (Get-SIDataCiFindingCategoryCheckSql) @{} 'scalar') -eq '1') } catch { $state.Category = $false }
            try { $state.LcStage = ([string](& $Invoke (Get-SIDataCiLifecycleStageCheckSql) @{} 'scalar') -eq '1') } catch { $state.LcStage = $false }
            # #772 the ServiceNow sub-CI column, where the database has it (a database before it is written as before)
            try { $state.SubCi = ([string](& $Invoke (Get-SIDataCiFindingSubCiCheckSql) @{} 'scalar') -eq '1') } catch { $state.SubCi = $false }
        }
        if ($useDb) {
            # ONE set-based statement stages the collection's findings per CI; the swap below replaces the stored set with them
            $pDb = Get-SIDataCiRatingBandParams; $pDb['CollectionId'] = [string]$dbSrc.CollectionId
            # #639: in key ranges through the work table where the database has it (each range its own statement); a database
            # without it (the updater adds it) takes the one statement as before. #879: the ranges run at once, as many as
            # the database has cores, and the collection's rows already read are not read again
            if (Test-SIDataCiDbWork -Invoke $Invoke) { $nDb = Invoke-SIDataCiFindingFromDbRanged -Invoke $Invoke -Params $pDb -SubCi:([bool]$state.SubCi) -Category:([bool]$state.Category) -Log $Log }
            else { $nDb = [long](& $Invoke (Get-SIDataCiFindingFromDbSql -SubCi:([bool]$state.SubCi) -Category:([bool]$state.Category)) $pDb 'scalar') }
            $state.Read = $nDb; $state.Staged = $nDb; $expected = $nDb; $state.First = $false
            $state.Snap = [string]$dbSrc.TimeText; $timeText = [string]$dbSrc.TimeText
            & $ph 'findings per CI: staged from the database' ([long]$nDb)
            # #881 a real database: a StageId range at a time, counted whole (a seam without connections: the one statement)
            if ($state.LcStage -and $nDb -gt 0) {
                if ($Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo) { $state.LcStaged = Invoke-SIDataCiLifecycleFromStage -Invoke $Invoke }
                else { $state.LcStaged = [long](& $Invoke (Get-SIDataCiLifecycleFromStageSql) @{} 'scalar') }
            }
            & $ph 'findings per CI: lifecycle input' ([long]$state.LcStaged)
            if ($dbWhy) {
                & $Log 'WARN' ('v3 model    : ' + $dbWhy)
                & $say 'WARNING' $dbWhy
            } elseif ($dbNote) {
                # #829 the copy is on but still arriving: the database at once, one line -- the next data sync reads the copy
                & $Log 'INFO' ('v3 model    : ' + $dbNote)
            } else {
                # #829 the copy is off (the default): the database IS the source -- a plain line, never a warning
                & $Log 'OK' ('v3 model    : the findings per CI were made from the Risk Analysis result of {0} in the database' -f (Get-SIDataCiDbFallbackTime $dbSrc))
            }
        } elseif ($expected -gt 0) {
            $planned = Get-SIDataPartitionCount -Rows $expected -Bytes $bytes
            $pageRead = {
                param([string]$kql)
                if ($LaQuery) { @(& $LaQuery $kql) }
                else { $pa = & $ReadOrSkip $kql 'SI_Finding_CL'; foreach ($x in @($pa)) { if ($null -ne $x) { $x } } }
            }
            $kqlOf = {
                param($cuts, $countOnly)
                Get-SIDataCiFindingPageKql -CollectionTimeText $timeText -LookbackDays $LookbackDays -PageFilter (Get-SIDataPageFilter -Cuts $cuts) -CountOnly:([bool]$countOnly)
            }
            $onRows = {
                param($rows)
                # one page: each row becomes its item and is LET GO at once; the page's items are staged, then let go
                $pageItems = New-Object System.Collections.Generic.List[object]
                $chars = 0L
                for ($ri = 0; $ri -lt $rows.Count; $ri++) {
                    $f = $rows[$ri]; $rows[$ri] = $null
                    if ($null -eq $f) { continue }
                    $it = ConvertTo-SIDataCiFindingItem -Row $f
                    $f = $null
                    $chars += ([string]$it['DocJson']).Length + 64
                    $pageItems.Add($it)
                }
                $state.Read += $pageItems.Count
                if (-not $state.Snap -and $pageItems.Count) { $state.Snap = [string]$pageItems[0]['CollectionTime'] }
                if (-not $DryRun -and $pageItems.Count) {
                    $arr = $pageItems.ToArray(); $pageItems.Clear()
                    $state.Staged += Invoke-SIDataCiChunks -Invoke $Invoke -Sql { param($first) Get-SIDataWriteCiFindingSql -First:$first -Stage -SubCi:([bool]$state.SubCi) -Category:([bool]$state.Category) } -Items $arr -ClearFirst ($state.First -and -not $state.PreCleared)
                    if ($state.LcStage) { $lw = Write-SIDataCiLifecycleStage -Invoke $Invoke -Items $arr -First $state.First; $state.LcStaged += [long]$lw.Findings }
                    $state.First = $false
                    $arr = $null
                }
                $chars
            }
            # 2026-10-29 a real database: the staging table is emptied in batches before the first page (not by the first chunk's one DELETE)
            if (Test-SIDataRangedSeam $Invoke) { Clear-SIDataCiStage -Invoke $Invoke -Table 'sidata.CiFindingStage'; $state.PreCleared = $true }
            $read = Read-SIDataPages -Query $pageRead -KqlOf $kqlOf -Pages $planned -OnRows $onRows -TargetChars $TargetChars -What 'the newest finding collection' -Log $Log
            $state.Pages = [long]$read.Pages; $state.Cuts = [long]$read.Cuts
        }
        $collText = $timeText; if (-not $collText) { $collText = 'the newest collection' }

        # ---- 3. whole, or nothing replaced ---------------------------------------------------------------------------
        if ($state.Read -ne $expected) {
            $why = ("the findings per CI were NOT stored: Log Analytics holds {0} finding row(s) for the collection of {1}, {2} were read -- the stored findings are kept as they are and no finding is closed this run" -f $expected, $collText, $state.Read)
            & $Log 'WARN' ("v3 model    : " + $why)
            & $say 'FAILED' $why
            if (-not $DryRun -and $state.Staged -gt 0) { try { Clear-SIDataCiStage -Invoke $Invoke -Table 'sidata.CiFindingStage' } catch { } }
            return [pscustomobject]@{ Status = 'failed'; Short = $true; Findings = 0; Rows = $state.Read; Expected = $expected; Error = $why; Issues = $issues.ToArray() }
        }
        if ($DryRun) {
            & $Log 'INFO' ("v3 model    : {0} finding(s) would be stored -- dry run (the CIs are written by the CI build)" -f $state.Read)
            return [pscustomobject]@{ Findings = $state.Read; Totals = 0; DryRun = $true; Rows = $state.Read; Expected = $expected; Status = 'ok'; Issues = $issues.ToArray() }
        }
        $nF = 0
        if ($state.Read -gt 0) {
            # ONE STEP for the readers: the staged rows replace the stored set in one transaction (a failure of it leaves
            # the stored findings as they were); the staged count must be the count this run wrote
            $nF = [int]$state.Staged
            # #881 the hashes and the matching outside the transaction (a key range at a time); the transaction only writes
            # what changed, after checking nothing changed meanwhile (a seam without sessions: the one statement as before)
            # 2026-10-25 matched by the CONTENT HASH (the data only, not what every run moves) where the database has the column
            # -- ON by default; without it every column, as before. Once a week the full swap (every column) as the safety net.
            $hashOn = $false; $fullDue = $false
            try { $hashOn = ([string](& $Invoke (Get-SIDataCiFindingContentHashCheckSql) @{} 'scalar') -eq '1') } catch { $hashOn = $false }
            if ($hashOn) { try { $fullDue = ([string](& $Invoke (Get-SIDataCiFindingFullDueSql) @{ Days = [string]$script:SIDataCiFindingFullDays } 'scalar') -ne '0') } catch { $fullDue = $true } }
            [void](Invoke-SIDataCiFindingSwap -Invoke $Invoke -Expected ([long]$nF) -SubCi:([bool]$state.SubCi) -Category:([bool]$state.Category) -ContentHash:$hashOn -Full:$fullDue -Log $Log -CollectionText ([string]$timeText))
            if ($hashOn -and $fullDue) { try { [void](& $Invoke (Get-SIDataCiFindingFullMarkSql) @{} 'scalar') } catch { & $Log 'WARN' ("v3 model    : the weekly full swap of the findings per CI ran, its mark was not set ({0}) -- the next run does it again" -f $_.Exception.Message) } }
            & $ph 'findings per CI: swap' ([long]$nF)
            try { Clear-SIDataCiStage -Invoke $Invoke -Table 'sidata.CiFindingStage' } catch { }
            if ($state.Pages -gt 1 -or $state.Cuts -gt 0) { & $Log 'INFO' ("v3 model    : the collection of {0} was read in {1} page(s) ({2} row(s), every one counted)" -f $collText, $state.Pages, $state.Read) }
        }
        $nT = [int](Invoke-SIDataCiTotals -Invoke $Invoke -Log $Log)
        & $Log 'OK' ("v3 model    : {0} finding(s) of the newest collection stored; finding totals updated on {1} CI(s)" -f $nF, $nT)
        # #774: never a plain success when the CIs got no finding while the Risk Analysis result in the database holds findings
        if ($nF -eq 0 -and $null -ne $dbSrc -and [long]$dbSrc.Rows -gt 0) {
            $zero = ('no finding per CI was stored, although the Risk Analysis result of {0} in the database holds {1} finding row(s) -- the CIs show no risk score and no open findings until a finding collection is stored' -f (Get-SIDataCiDbFallbackTime $dbSrc), $dbSrc.Rows)
            & $Log 'WARN' ('v3 model    : ' + $zero)
            & $say 'WARNING' $zero
        }
        # the CI grid's fields as columns (owner 2026-10-11, the CIs page took ~10 s): filled from the documents that moved --
        # until it ran, the web app reads those CIs' fields from the document (a WARNING: the data is whole in the document)
        $nD = 0
        try {
            $nD = [int](Invoke-SIDataCiDocFields -Invoke $Invoke -Log $Log)
            & $Log 'OK' ("v3 model    : the CI list's columns filled from the document on {0} CI(s)" -f $nD)
        } catch {
            & $Log 'WARN' ("v3 model    : the CI list's columns were not filled this run ({0}) -- the CIs page reads those fields from the document until the next run" -f $_.Exception.Message)
            & $say 'WARNING' ("the CI list's columns were not filled this run ({0}) -- the CIs page reads them from each CI's document" -f $_.Exception.Message)
        }
        & $ph 'findings per CI: totals and CI list columns' ([long]$nT)
        # what every data view shows of a CI by default (owner, subscription, resource group, ... and the identifier values and
        # linked object ids) as columns too -- SI-DataViewContext.ps1
        $nC = $null
        if (Get-Command -Name Invoke-SIDataCiViewColumns -ErrorAction SilentlyContinue) {
            $nC = Invoke-SIDataCiViewColumns -Invoke $Invoke -Log $Log
            if ($nC -and [string]$nC.Status -eq 'failed') { & $say 'WARNING' ("the CI context columns of the views were not filled this run ({0}) -- the views read them from each CI's document" -f [string]$nC.Error) }
        }
        & $ph 'findings per CI: CI view columns'
        # #464 the finding lifecycle (first detected / last seen / open / reopened / closed + reason), today's trend detail and
        # the history retention (SI-DataCiLifecycle.ps1)
        $snap = $state.Snap
        # per report: a run partial only because named reports could not be completed is complete for every other report
        $cmp = Test-SIDataFindingCollectionComplete -SnapshotTime $snap -ReadOrSkip $ReadOrSkip -Invoke $Invoke
        $frozenReports = @(); if ($cmp.PSObject.Properties['FrozenReports']) { $frozenReports = @($cmp.FrozenReports | Where-Object { $_ }) }
        if (-not $cmp.Complete -and $snap) { & $Log 'INFO' ("v3 model    : the finding collection is not shown complete ({0}) -- no finding is closed this run" -f $cmp.Reason) }
        elseif ($frozenReports.Count) { & $Log 'INFO' ("v3 model    : {0}" -f $cmp.Reason) }
        $dis = Get-SIDataCiDisabledOwners -ReadOrSkip $ReadOrSkip -Log $Log
        if (-not $dis.Known) { & $say 'WARNING' 'which accounts are disabled could not be read -- no finding was closed this run (unknown never closes)' }
        # CIs follow the collection scope: an out-of-scope CI's absent findings freeze like a disabled asset's
        $oos = Get-SIDataCiOutOfScopeOwners -Invoke $Invoke -Log $Log
        if (-not $oos.Known) { & $say 'WARNING' 'which CIs the collection scope leaves out could not be read -- no finding was closed this run (unknown never closes)' }
        $frozenOwners = @(@($dis.Owners) + @($oos.Owners) | Where-Object { $_ } | Sort-Object -Unique)
        # a source on its last good collection (its newest collection did not complete): ONLY what rests on that source is
        # frozen -- the absent findings of the CIs it describes are not counted absent and not closed; the findings of CIs
        # that rest on healthy sources close as usual. What cannot be attributed is frozen, and when nothing can be attributed
        # no finding is closed this run (engine\_shared\SI-SourceState.ps1: Get-SISourceDropoutOwners)
        $srcFreeze = $null
        try {
            if (-not (Get-Command -Name Get-SISourceDropoutOwners -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-SourceState.ps1')) }
            $srcFreeze = Get-SISourceDropoutOwners -Invoke $Invoke -For Lifecycle -Log $Log
        } catch { $srcFreeze = [pscustomobject]@{ Dropouts = @(); Known = $false; Owners = @(); Why = $_.Exception.Message } }
        if (@($srcFreeze.Dropouts).Count -and $srcFreeze.Known) {
            & $Log 'INFO' ("v3 model    : {0} on the last good collection -- the findings of the {1} CI(s) and owner(s) that rest on it are kept as they are this run (not counted absent, not closed); everything else closes as usual" -f (Get-SISourceDropoutText -Dropouts @($srcFreeze.Dropouts)), @($srcFreeze.Owners).Count)
            $unl = 0; if ($srcFreeze.PSObject.Properties['Unlinked']) { $unl = [int]$srcFreeze.Unlinked }
            if ($unl -gt 0) { & $Log 'INFO' ("v3 model    : {0} of them are kept because no CI with current sources is proven for them (an asset key no stored finding or CI link ties to exactly one such CI) -- unknown never closes" -f $unl) }
            # ... and the loaded collections calculated meanwhile say so when they are opened (sidata.CollectionSource)
            $null = Invoke-SISourceCollectionMark -Invoke $Invoke -Log $Log
        } elseif (-not $srcFreeze.Known) {
            if (@($srcFreeze.Dropouts).Count) { $null = Invoke-SISourceCollectionMark -Invoke $Invoke -Log $Log }
            & $Log 'INFO' ("v3 model    : a source is on its last good collection and {0} -- no finding is closed or counted absent this run" -f $srcFreeze.Why)
        }
        $lc = $null
        if ($state.Read -gt 0 -and -not $state.LcStage) {
            # never one JSON string in one parameter: without its staging table the lifecycle waits for the updater
            & $Log 'WARN' 'v3 model    : the finding lifecycle was not updated this run -- the database does not have the staging table of its input yet (the updater adds it). The findings are stored; nothing was closed.'
            & $say 'WARNING' 'the finding lifecycle was not updated this run (the database is not updated yet) -- the findings are stored; nothing was closed'
        } else {
            $lc = Invoke-SIDataCiLifecycle -Invoke $Invoke -Staged:($state.LcStaged -gt 0) -SnapshotTime $snap -Complete ([bool]$cmp.Complete -and [bool]$dis.Known -and [bool]$oos.Known -and [bool]$srcFreeze.Known) -Log $Log -DisabledOwners $frozenOwners -OwnersKnown ([bool]$dis.Known -and [bool]$oos.Known) -SourceOwners @($srcFreeze.Owners) -FrozenReports $frozenReports
            if ($lc -and $lc.PSObject.Properties['Problem'] -and [string]$lc.Problem) { & $say 'WARNING' ('the finding lifecycle was not updated this run ({0}) -- the findings are stored; nothing was closed' -f [string]$lc.Problem) }
        }
        & $ph 'findings per CI: lifecycle' ([long]$(if ($lc) { [long]$lc.Seen + [long]$lc.Opened } else { -1 }))
        return [pscustomobject]@{ Findings = $nF; Totals = $nT; DocFields = $nD; ViewColumns = $nC; DryRun = $false; Lifecycle = $lc; Status = 'ok'; Rows = $state.Read; Expected = $expected; Pages = $state.Pages; Issues = $issues.ToArray()
                                  # per report: what the data out keeps as it was (the findings of reports this run could not complete)
                                  FrozenReports = [string[]]@($frozenReports); RunComplete = [bool]$cmp.Complete }
    } catch {
        & $Log 'WARN' ("v3 model    : the findings per CI were not stored this run -- {0}. It is tried again on the next run; the findings load is not affected." -f $_.Exception.Message)
        & $say 'FAILED' ("the findings per CI of the newest collection were not stored -- {0}. The stored findings are kept as they are; no finding is closed this run" -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message; Issues = $issues.ToArray() }
    }
}
