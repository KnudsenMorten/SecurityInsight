-- si-data-schema.sql -- the PRO DATA BACKEND, SecurityInsight Pro (REQUIREMENTS §9.3.3 phase B, data contract §9.3.4).
--
-- Every COMPLETE Risk Analysis Detailed collection is copied here from Log Analytics by the data sync
-- (engine/pro-data/Invoke-SIDataSync.ps1), so the Pro web app can show the latest collection, open an older one
-- by its collection time, and draw trends without grouping finding rows live. It lives in the one Pro database
-- beside `cfg` (settings), `vuln` (the vulnerability close-loop) and `si` (the identity ledger).
--
-- THE SHAPE:
--   Run                 one row per Risk Analysis run that produced a loaded collection (from SI_RunHealth_CL)
--   Collection          one row per loaded collection; Status = 'Loading' until every row landed, then 'Complete'
--   Asset               one row per CI. AssetKey = the identity ledger's SI_CorrelationId when the correlation map
--                       carries a LEDGER id for the asset, else SI_AssetId (a provisional correlation id moves when
--                       group membership changes, so it is never used as a key)
--   AssetIdentifier     every identifier the correlation map knows for a CI (SI_AssetId included)
--   Finding             NARROW finding rows + DetailJson (the full Log Analytics row) -- never the 291-column shape
--   Recommendation      Defender for Cloud recommendations in force at the collection time
--   FindingDaily        PRE-COMPUTED daily aggregate (the latest complete collection of each day) -- dashboards,
--                       trends and the big screen read this, never Finding
--   VulnLifecycleDaily  PRE-COMPUTED daily opened / closed / reopened / open-at-end-of-day from vuln.VulnerabilityEvent
--   FindingFacet        PRE-COMPUTED per collection: counts per MITRE tactic, compliance tag, risk rating, CVSS band, ...
--                       (the web app's collection views, #241)
--   ServiceMember / ServiceAsset / ServiceRisk  PRE-COMPUTED per collection: which CMDB service(s) each CI belongs to,
--                       and the weighted risk per service and per (service, CI) -- the Services view (#255)
--   SummaryLoad / SummaryRow / SummaryAsset   the Risk Analysis SUMMARY rows (the RiskAnalysis_Summary workbook's rows)
--                       with their impacted assets -- the former Summary page /Summary (#583)
--   vLatestCollection, vCurrentFinding, vCi   the read views
--
-- RETENTION is NOT here: purging old collections is a DELETE, and this file is additive only. The data sync purges
-- collections older than SI_Pro_DataRetentionDays (default 90) in batches. vuln.*, si.* and cfg.* are never purged.
--
-- ADDITIVE AND IDEMPOTENT ONLY: every statement is guarded, so re-running is a no-op, and no destructive verb appears
-- in this file (Test-SISchemaIsAdditive refuses one). A view is created once (IF OBJECT_ID ... IS NULL); a later
-- change to a view ships as a NEW view name, never as an ALTER of this one.

IF SCHEMA_ID('sidata') IS NULL EXEC ('CREATE SCHEMA sidata');

-- ---------------------------------------------------------------------------------------------
-- Run: the Risk Analysis run (its run-health END record) that produced a collection.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.Run') IS NULL
CREATE TABLE sidata.Run (
    RunId            NVARCHAR(64)   NOT NULL CONSTRAINT PK_Run PRIMARY KEY,
    Engine           NVARCHAR(64)   NOT NULL,
    CollectionTime   DATETIME2(3)   NOT NULL,   -- the collection the run produced
    Verdict          NVARCHAR(64)   NOT NULL,   -- the run-health ExitReason ('success' -- only complete runs are loaded)
    StartedAt        DATETIME2(3)   NULL,
    EndedAt          DATETIME2(3)   NULL,
    SolutionVersion  NVARCHAR(64)   NULL,
    LoadedAt         DATETIME2(0)   NOT NULL CONSTRAINT DF_Run_LoadedAt DEFAULT SYSUTCDATETIME()
);

-- ---------------------------------------------------------------------------------------------
-- Collection: one row per loaded collection. The unique key (Kind, CollectionTime) is what makes a re-run load
-- nothing twice. A collection is visible to readers only when Status = 'Complete' -- a load that died half way
-- stays 'Loading', is invisible, and is cleaned and loaded again by the next run.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.Collection') IS NULL
CREATE TABLE sidata.Collection (
    CollectionId     INT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_Collection PRIMARY KEY,
    CollectionTime   DATETIME2(3)   NOT NULL,
    Kind             NVARCHAR(16)   NOT NULL,
    RunId            NVARCHAR(64)   NULL,
    [Rows]           INT            NULL,       -- rows loaded; equals the rows Log Analytics held for the collection
    Status           NVARCHAR(16)   NOT NULL CONSTRAINT DF_Collection_Status DEFAULT 'Loading',
    StartedLoadAt    DATETIME2(0)   NOT NULL CONSTRAINT DF_Collection_StartedLoadAt DEFAULT SYSUTCDATETIME(),
    LoadedAt         DATETIME2(0)   NULL,       -- set when Status becomes 'Complete'
    SolutionVersion  NVARCHAR(64)   NULL,
    CONSTRAINT UQ_Collection_KindTime UNIQUE (Kind, CollectionTime),
    CONSTRAINT CK_Collection_Kind CHECK (Kind IN ('Detailed', 'Summary')),
    CONSTRAINT CK_Collection_Status CHECK (Status IN ('Loading', 'Complete'))
);

-- latest-collection lookup: newest complete collection per kind
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Collection_Latest' AND object_id = OBJECT_ID('sidata.Collection'))
CREATE INDEX IX_Collection_Latest ON sidata.Collection (Kind, Status, CollectionTime DESC) INCLUDE (RunId, [Rows], LoadedAt);

-- ---------------------------------------------------------------------------------------------
-- Asset: the CI. Current state, upserted on every load.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.Asset') IS NULL
CREATE TABLE sidata.Asset (
    AssetKey         NVARCHAR(400)  NOT NULL CONSTRAINT PK_Asset PRIMARY KEY,
    AssetName        NVARCHAR(400)  NULL,
    AssetKind        NVARCHAR(16)   NULL,       -- endpoint | identity | azure | publicip
    Tier             TINYINT        NULL,       -- 0 (most critical) .. 3, the most critical of the CI's members
    KeySource        NVARCHAR(16)   NOT NULL,   -- 'ledger' (SI_CorrelationId) | 'asset' (SI_AssetId)
    FirstSeen        DATETIME2(3)   NOT NULL,
    LastSeen         DATETIME2(3)   NOT NULL,
    PropertiesJson   NVARCHAR(MAX)  NULL,       -- SI_AssetProperties_CL, one property bag per source system
    UpdatedAt        DATETIME2(0)   NOT NULL CONSTRAINT DF_Asset_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_Asset_KeySource CHECK (KeySource IN ('ledger', 'asset'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Asset_Name' AND object_id = OBJECT_ID('sidata.Asset'))
CREATE INDEX IX_Asset_Name ON sidata.Asset (AssetName) INCLUDE (AssetKind, Tier, LastSeen);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Asset_LastSeen' AND object_id = OBJECT_ID('sidata.Asset'))
CREATE INDEX IX_Asset_LastSeen ON sidata.Asset (LastSeen);

-- AssetKinds (ADDED 2026-10-07, #431, operator "Match any part"): EVERY kind the CI is made of, most descriptive first,
-- ';'-separated ('endpoint;azure' for an Azure VM correlated into its MDE endpoint). AssetKind stays the ONE most
-- descriptive kind, for display; the web app's asset-kind FILTER and its per-kind counts match any kind in this set
-- (counts per kind can overlap; "All" counts each asset once). Written by the data sync's asset upsert; NULL on a row
-- loaded before the column existed -- readers fall back to AssetKind (COALESCE), and the next loaded collection fills it.
IF COL_LENGTH('sidata.Asset', 'AssetKinds') IS NULL
ALTER TABLE sidata.Asset ADD AssetKinds NVARCHAR(64) NULL;

-- ---------------------------------------------------------------------------------------------
-- AssetIdentifier: every identifier the correlation map knows for a CI (MDE device id, ARM id, Entra object id,
-- Exposure Graph node id, ... and SI_AssetId itself). Values are stored as published, lower-cased.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.AssetIdentifier') IS NULL
CREATE TABLE sidata.AssetIdentifier (
    AssetIdentifierId BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetIdentifier PRIMARY KEY,
    AssetKey          NVARCHAR(400)  NOT NULL,
    IdentifierType    NVARCHAR(64)   NOT NULL,
    IdentifierValue   NVARCHAR(256)  NOT NULL,   -- the identity ledger's width: an identifier that does not fit there does not fit here
    FirstSeen         DATETIME2(3)   NOT NULL,
    LastSeen          DATETIME2(3)   NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_AssetIdentifier_Key' AND object_id = OBJECT_ID('sidata.AssetIdentifier'))
CREATE UNIQUE INDEX UX_AssetIdentifier_Key ON sidata.AssetIdentifier (AssetKey, IdentifierType, IdentifierValue);

-- reverse lookup: which CI carries this identifier
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetIdentifier_Value' AND object_id = OBJECT_ID('sidata.AssetIdentifier'))
CREATE INDEX IX_AssetIdentifier_Value ON sidata.AssetIdentifier (IdentifierValue, IdentifierType) INCLUDE (AssetKey);

-- ---------------------------------------------------------------------------------------------
-- Finding: one row per Risk Analysis Detailed row, NARROW + the whole row as JSON. Clustered on the collection,
-- so opening one collection and purging one collection both read one contiguous range.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.Finding') IS NULL
CREATE TABLE sidata.Finding (
    FindingId        BIGINT IDENTITY(1, 1) NOT NULL,
    CollectionId     INT            NOT NULL CONSTRAINT FK_Finding_Collection REFERENCES sidata.Collection (CollectionId),
    AssetKey         NVARCHAR(400)  NULL,       -- NULL only for a row Risk Analysis published without an asset id
    AssetName        NVARCHAR(400)  NULL,
    ReportName       NVARCHAR(256)  NULL,
    SecurityDomain   NVARCHAR(128)  NULL,
    ConfigurationId  NVARCHAR(256)  NULL,
    Cve              NVARCHAR(100)  NULL,       -- set when ConfigurationId is a CVE id
    Title            NVARCHAR(1000) NULL,       -- ConfigurationName
    Severity         NVARCHAR(30)   NULL,       -- SecuritySeverity
    Tier             TINYINT        NULL,       -- CriticalityTier
    RiskScore        FLOAT          NULL,       -- RiskScoreTotal
    DetailJson       NVARCHAR(MAX)  NULL,
    CONSTRAINT PK_Finding PRIMARY KEY CLUSTERED (CollectionId, FindingId)
);

-- one-collection drill-down: "most important first" = lowest tier, then highest score
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Drilldown' AND object_id = OBJECT_ID('sidata.Finding'))
CREATE INDEX IX_Finding_Drilldown ON sidata.Finding (CollectionId, Tier, Severity, RiskScore DESC)
    INCLUDE (AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title);

-- asset lookup: every finding of one CI, newest collection first
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Asset' AND object_id = OBJECT_ID('sidata.Finding'))
CREATE INDEX IX_Finding_Asset ON sidata.Finding (AssetKey, CollectionId) INCLUDE (ConfigurationId, Cve, Severity, Tier, RiskScore);

-- vulnerability lookup: where is this CVE, in one collection
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Cve' AND object_id = OBJECT_ID('sidata.Finding'))
CREATE INDEX IX_Finding_Cve ON sidata.Finding (CollectionId, Cve) INCLUDE (AssetKey, Severity, Tier, RiskScore);

-- ---------------------------------------------------------------------------------------------
-- Recommendation: Defender for Cloud recommendations (SI_AzureRecommendation_CL) in force at the collection time.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.Recommendation') IS NULL
CREATE TABLE sidata.Recommendation (
    RecommendationRowId BIGINT IDENTITY(1, 1) NOT NULL,
    CollectionId        INT            NOT NULL CONSTRAINT FK_Recommendation_Collection REFERENCES sidata.Collection (CollectionId),
    AssetKey            NVARCHAR(400)  NULL,
    RecommendationId    NVARCHAR(400)  NULL,    -- the assessment key
    Name                NVARCHAR(1000) NULL,
    Severity            NVARCHAR(30)   NULL,
    Tier                TINYINT        NULL,
    DetailJson          NVARCHAR(MAX)  NULL,
    CONSTRAINT PK_Recommendation PRIMARY KEY CLUSTERED (CollectionId, RecommendationRowId)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Recommendation_Asset' AND object_id = OBJECT_ID('sidata.Recommendation'))
CREATE INDEX IX_Recommendation_Asset ON sidata.Recommendation (AssetKey, CollectionId) INCLUDE (RecommendationId, Severity, Tier);

-- ---------------------------------------------------------------------------------------------
-- FindingDaily: the daily aggregate, pre-computed right after each load. ONE collection per day (the latest complete
-- one), so a trend line never counts a day twice. Dashboards, trends and the big screen read only this.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.FindingDaily') IS NULL
CREATE TABLE sidata.FindingDaily (
    FindingDailyId   BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_FindingDaily PRIMARY KEY NONCLUSTERED,
    [Day]            DATE           NOT NULL,
    CollectionId     INT            NOT NULL CONSTRAINT FK_FindingDaily_Collection REFERENCES sidata.Collection (CollectionId),
    Tier             TINYINT        NULL,
    Severity         NVARCHAR(30)   NOT NULL,   -- '' when the row carried none
    SecurityDomain   NVARCHAR(128)  NOT NULL,
    ReportName       NVARCHAR(256)  NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,
    ScoreTotal       FLOAT          NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_FindingDaily_Day' AND object_id = OBJECT_ID('sidata.FindingDaily'))
CREATE CLUSTERED INDEX CX_FindingDaily_Day ON sidata.FindingDaily ([Day], Tier, Severity);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingDaily_Collection' AND object_id = OBJECT_ID('sidata.FindingDaily'))
CREATE INDEX IX_FindingDaily_Collection ON sidata.FindingDaily (CollectionId);

-- ScoreMax (ADDED 2026-10-04, #245): the HIGHEST risk score of one finding in the group. ScoreTotal stays (it is how an
-- average is formed: ScoreTotal / Findings), but a sum of every finding's score is never SHOWN -- it only grows with the
-- number of findings. Additive: NULL on rows computed before the column existed; the data sync fills it from then on.
IF COL_LENGTH('sidata.FindingDaily', 'ScoreMax') IS NULL
ALTER TABLE sidata.FindingDaily ADD ScoreMax FLOAT NULL;

-- ---------------------------------------------------------------------------------------------
-- AssetDaily (ADDED 2026-10-05, #295): the DISTINCT assets with findings of the day's collection at EVERY grain a view
-- can show -- each combination of asset tier, severity, security domain and report, with any of them "all" (a CUBE).
-- FindingDaily.Assets is distinct only within its own (tier, severity, domain, report) group, so adding it up counted an
-- asset once per group it has findings in (measured on ring 1: Tier 0 showed 159 assets where 35 had findings).
-- GroupingId = GROUPING_ID(Tier, Severity, SecurityDomain, ReportName): bit 8 = every tier, 4 = every severity,
-- 2 = every domain, 1 = every report (0 = the finest grain, 15 = the whole day). A grouped-away column holds NULL.
-- Written by the data sync with the day's FindingDaily (one collection per day, the latest complete one). Additive.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.AssetDaily') IS NULL
CREATE TABLE sidata.AssetDaily (
    AssetDailyId     BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetDaily PRIMARY KEY NONCLUSTERED,
    [Day]            DATE           NOT NULL,
    CollectionId     INT            NOT NULL CONSTRAINT FK_AssetDaily_Collection REFERENCES sidata.Collection (CollectionId),
    GroupingId       TINYINT        NOT NULL,
    Tier             TINYINT        NULL,
    Severity         NVARCHAR(30)   NULL,
    SecurityDomain   NVARCHAR(128)  NULL,
    ReportName       NVARCHAR(256)  NULL,
    Assets           INT            NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_AssetDaily_Day' AND object_id = OBJECT_ID('sidata.AssetDaily'))
CREATE CLUSTERED INDEX CX_AssetDaily_Day ON sidata.AssetDaily ([Day], GroupingId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetDaily_Collection' AND object_id = OBJECT_ID('sidata.AssetDaily'))
CREATE INDEX IX_AssetDaily_Collection ON sidata.AssetDaily (CollectionId);

-- ---------------------------------------------------------------------------------------------
-- VulnLifecycleDaily: the close-loop's daily statistics, re-derived from vuln.VulnerabilityEvent after each sync.
-- Every calendar day from the first event onward has a row (a day with no change shows 0 / 0 / 0 and the running
-- open count), so a chart never draws a quiet day as a gap.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.VulnLifecycleDaily') IS NULL
CREATE TABLE sidata.VulnLifecycleDaily (
    [Day]            DATE           NOT NULL CONSTRAINT PK_VulnLifecycleDaily PRIMARY KEY,
    Opened           INT            NOT NULL,
    Closed           INT            NOT NULL,   -- closed by SI (Close) or by an engineer (EngineerClose)
    Reopened         INT            NOT NULL,
    OpenAtEndOfDay   INT            NOT NULL,
    ComputedAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_VulnLifecycleDaily_ComputedAt DEFAULT SYSUTCDATETIME()
);

-- ---------------------------------------------------------------------------------------------
-- THE COLLECTION VIEWS (#241): the web app's fourteen views per collection read columns the narrow Finding row did not
-- carry, and per-collection aggregates that would otherwise mean scanning every finding on every page view.
-- Added IN PLACE to an existing install (each guarded by COL_LENGTH / OBJECT_ID, so re-running is a no-op). The data
-- sync fills them from DetailJson (the whole Risk Analysis row it already stores) -- for new loads AND, once, for every
-- collection loaded before these columns existed -- and records when in Collection.DerivedAt.
--   RiskScoreWeighted  RiskScoreTotal_Weighted
--   RiskRating         RiskRating (Critical | High | Moderate | Low, banded from RiskScoreTotal by Risk Analysis)
--   MitreTactics       MITRE_Tactics, ';'-separated      MitreTechniques  MITRE_Techniques, ';'-separated
--   ComplianceTags     ComplianceTags, ';'-separated
--   Cvss               MaxCvssScore, else (a CVE row) Impact -- the CVE report writes the CVSS score there
--   HasExploit         HasExploit
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'RiskScoreWeighted') IS NULL
ALTER TABLE sidata.Finding ADD RiskScoreWeighted FLOAT NULL;

IF COL_LENGTH('sidata.Finding', 'RiskRating') IS NULL
ALTER TABLE sidata.Finding ADD RiskRating NVARCHAR(16) NULL;

IF COL_LENGTH('sidata.Finding', 'MitreTactics') IS NULL
ALTER TABLE sidata.Finding ADD MitreTactics NVARCHAR(1000) NULL;

IF COL_LENGTH('sidata.Finding', 'MitreTechniques') IS NULL
ALTER TABLE sidata.Finding ADD MitreTechniques NVARCHAR(2000) NULL;

IF COL_LENGTH('sidata.Finding', 'ComplianceTags') IS NULL
ALTER TABLE sidata.Finding ADD ComplianceTags NVARCHAR(2000) NULL;

IF COL_LENGTH('sidata.Finding', 'Cvss') IS NULL
ALTER TABLE sidata.Finding ADD Cvss FLOAT NULL;

IF COL_LENGTH('sidata.Finding', 'HasExploit') IS NULL
ALTER TABLE sidata.Finding ADD HasExploit BIT NULL;

-- when the views' columns and sidata.FindingFacet were computed for the collection (NULL = not yet)
IF COL_LENGTH('sidata.Collection', 'DerivedAt') IS NULL
ALTER TABLE sidata.Collection ADD DerivedAt DATETIME2(0) NULL;

-- FindingFacet: PRE-COMPUTED per collection, right after its views' columns are filled: findings, CIs and score per
-- MITRE tactic / technique, compliance tag, risk rating, CVSS band, risk score, weighted score, severity, tier, domain
-- and report. The facet views read this, never a GROUP BY over the finding rows.
IF OBJECT_ID('sidata.FindingFacet') IS NULL
CREATE TABLE sidata.FindingFacet (
    CollectionId     INT            NOT NULL CONSTRAINT FK_FindingFacet_Collection REFERENCES sidata.Collection (CollectionId),
    Facet            NVARCHAR(16)   NOT NULL,
    Value            NVARCHAR(256)  NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,
    ScoreTotal       FLOAT          NOT NULL,
    WeightedTotal    FLOAT          NULL,
    MaxScore         FLOAT          NULL,
    CONSTRAINT PK_FindingFacet PRIMARY KEY CLUSTERED (CollectionId, Facet, Value)
);

-- The views' covering index: one collection's findings by CI (correlated view, CI view, the comparison of two
-- collections), with every column a view shows -- so a view never reads the wide clustered rows (DetailJson).
-- Created through EXEC: in one batch with the ALTER TABLE ADDs above, a plain CREATE INDEX naming the new columns is
-- compiled before they exist.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Views' AND object_id = OBJECT_ID('sidata.Finding'))
EXEC ('CREATE INDEX IX_Finding_Views ON sidata.Finding (CollectionId, AssetKey) INCLUDE (AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, Cvss, HasExploit, MitreTactics, MitreTechniques, ComplianceTags)');

-- ---------------------------------------------------------------------------------------------
-- ASSET RESPONSIBILITY (#254, phase 1): the department each finding belongs to, PRE-RESOLVED by the data sync, so a view
-- or a mail reads the answer and never resolves it per request. cfg.Department / cfg.ResponsibilityRule /
-- cfg.ResponsibilityOverride (si-pro-settings.sql) hold the policy; these hold the result.
--   DepartmentId          the resolved department (NULL = Unassigned)
--   ResponsibilitySource  recommendation-override | asset-override | tag | rule | default | unassigned
--   ResponsibilityDetail  which override, tag or rule it was (e.g. "Department = Finance (azure)", "rule 3: name SRV-FIN*")
-- On sidata.Asset the same three columns are the asset's own resolution (without recommendation overrides).
-- Collection.ResolvedVersion = the fingerprint of the policy the collection was resolved with: a policy change (settings,
-- departments, rules, overrides) re-resolves every retained collection on the next sync.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'DepartmentId') IS NULL
ALTER TABLE sidata.Finding ADD DepartmentId INT NULL;

IF COL_LENGTH('sidata.Finding', 'ResponsibilitySource') IS NULL
ALTER TABLE sidata.Finding ADD ResponsibilitySource NVARCHAR(24) NULL;

IF COL_LENGTH('sidata.Finding', 'ResponsibilityDetail') IS NULL
ALTER TABLE sidata.Finding ADD ResponsibilityDetail NVARCHAR(256) NULL;

IF COL_LENGTH('sidata.Asset', 'DepartmentId') IS NULL
ALTER TABLE sidata.Asset ADD DepartmentId INT NULL;

IF COL_LENGTH('sidata.Asset', 'ResponsibilitySource') IS NULL
ALTER TABLE sidata.Asset ADD ResponsibilitySource NVARCHAR(24) NULL;

IF COL_LENGTH('sidata.Asset', 'ResponsibilityDetail') IS NULL
ALTER TABLE sidata.Asset ADD ResponsibilityDetail NVARCHAR(256) NULL;

IF COL_LENGTH('sidata.Collection', 'ResolvedAt') IS NULL
ALTER TABLE sidata.Collection ADD ResolvedAt DATETIME2(0) NULL;

IF COL_LENGTH('sidata.Collection', 'ResolvedVersion') IS NULL
ALTER TABLE sidata.Collection ADD ResolvedVersion CHAR(64) NULL;

-- AssetTag: the platform tags and groupings the profiles carry for a CI (current state, replaced per CI on each load):
--   Source azure | azure-subscription | endpoint | identity   a tag (TagName = '' for a bare Defender tag)
--   Source service                                          the CMDB / business service (TagName 'Service')
--   Source group                                            MachineGroup | RbacGroup | ResourceGroup | Subscription
IF OBJECT_ID('sidata.AssetTag') IS NULL
CREATE TABLE sidata.AssetTag (
    AssetTagId   BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetTag PRIMARY KEY,
    AssetKey     NVARCHAR(400)  NOT NULL,
    Source       NVARCHAR(24)   NOT NULL,
    TagName      NVARCHAR(128)  NOT NULL,
    TagValue     NVARCHAR(256)  NOT NULL,
    SeenAt       DATETIME2(3)   NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_AssetTag_Key' AND object_id = OBJECT_ID('sidata.AssetTag'))
CREATE UNIQUE INDEX UX_AssetTag_Key ON sidata.AssetTag (AssetKey, Source, TagName, TagValue);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetTag_Value' AND object_id = OBJECT_ID('sidata.AssetTag'))
CREATE INDEX IX_AssetTag_Value ON sidata.AssetTag (Source, TagName, TagValue) INCLUDE (AssetKey);

-- DepartmentFacet: PRE-COMPUTED per collection per department (DepartmentId 0 = Unassigned): findings, CIs and score per
-- severity (Tier '*'), per tier (Severity '*') and the department's total (both '*'). The department pages, their
-- trend and the monthly report read this, never a GROUP BY over the finding rows.
IF OBJECT_ID('sidata.DepartmentFacet') IS NULL
CREATE TABLE sidata.DepartmentFacet (
    CollectionId     INT            NOT NULL CONSTRAINT FK_DepartmentFacet_Collection REFERENCES sidata.Collection (CollectionId),
    DepartmentId     INT            NOT NULL,
    Severity         NVARCHAR(30)   NOT NULL,
    Tier             NVARCHAR(12)   NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,
    ScoreTotal       FLOAT          NOT NULL,
    WeightedTotal    FLOAT          NULL,
    CONSTRAINT PK_DepartmentFacet PRIMARY KEY CLUSTERED (CollectionId, DepartmentId, Severity, Tier)
);

-- one department's findings of one collection (the department page's grid, the Unassigned triage view)
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Department' AND object_id = OBJECT_ID('sidata.Finding'))
EXEC ('CREATE INDEX IX_Finding_Department ON sidata.Finding (CollectionId, DepartmentId) INCLUDE (AssetKey, AssetName, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, ResponsibilitySource)');

-- THE SERVICES VIEW (#255): the collection's CIs per CMDB business service, ranked by weighted risk.
-- Which service(s) a CI belongs to is decided by ONE resolver (engine/_shared/data-sql/SI-DataSql.ps1,
-- Get-SIDataServiceSources): an ordered list of membership sources, each a read-only SELECT of (AssetKey, ServiceKey,
-- ServiceName) for one collection. Its output for each collection is ServiceMember; ServiceAsset and ServiceRisk are
-- aggregated from it by the data sync, so the web app never groups finding rows per page view. A CI may belong to
-- several services: it is then counted under EACH of them (SharedAssets says how many of a service's CIs are shared).
-- CIs with no membership are the no-service row (ServiceKey = N'').
--   Finding.CmdbId / CmdbName   the CMDB service the Risk Analysis row carried (cmdbId / cmdbName) -- the first source
--   Collection.ServicesDerivedAt when ServiceMember / ServiceAsset / ServiceRisk were computed (NULL = not yet)
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'CmdbId') IS NULL
ALTER TABLE sidata.Finding ADD CmdbId NVARCHAR(256) NULL;

IF COL_LENGTH('sidata.Finding', 'CmdbName') IS NULL
ALTER TABLE sidata.Finding ADD CmdbName NVARCHAR(400) NULL;

IF COL_LENGTH('sidata.Collection', 'ServicesDerivedAt') IS NULL
ALTER TABLE sidata.Collection ADD ServicesDerivedAt DATETIME2(0) NULL;

-- the resolver's output: one row per (service, CI) of the collection, stamped with the source that placed it
IF OBJECT_ID('sidata.ServiceMember') IS NULL
CREATE TABLE sidata.ServiceMember (
    CollectionId     INT            NOT NULL CONSTRAINT FK_ServiceMember_Collection REFERENCES sidata.Collection (CollectionId),
    ServiceKey       NVARCHAR(256)  NOT NULL,
    AssetKey         NVARCHAR(400)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Source           NVARCHAR(32)   NOT NULL
);

-- (service, CI) is unique by construction (the data sync de-duplicates); the key is not a constraint because
-- ServiceKey + AssetKey can exceed SQL Server's 900-byte clustered key
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_ServiceMember' AND object_id = OBJECT_ID('sidata.ServiceMember'))
CREATE CLUSTERED INDEX CX_ServiceMember ON sidata.ServiceMember (CollectionId, ServiceKey);

-- one row per (service, CI): the CI's findings in the collection, and how many services it belongs to
IF OBJECT_ID('sidata.ServiceAsset') IS NULL
CREATE TABLE sidata.ServiceAsset (
    CollectionId     INT            NOT NULL CONSTRAINT FK_ServiceAsset_Collection REFERENCES sidata.Collection (CollectionId),
    ServiceKey       NVARCHAR(256)  NOT NULL,   -- N'' = the CI belongs to no service
    AssetKey         NVARCHAR(400)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Source           NVARCHAR(32)   NULL,
    AssetName        NVARCHAR(400)  NULL,
    Tier             TINYINT        NULL,
    ServiceCount     INT            NOT NULL,   -- services this CI belongs to (0 on the no-service row)
    Findings         INT            NOT NULL,
    Critical         INT            NOT NULL,
    High             INT            NOT NULL,
    Medium           INT            NOT NULL,
    Low              INT            NOT NULL,
    WeightedTotal    FLOAT          NULL,
    RiskTotal        FLOAT          NULL,
    MaxWeighted      FLOAT          NULL
);

-- the drill-down service -> its CIs reads one (collection, service) range
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_ServiceAsset' AND object_id = OBJECT_ID('sidata.ServiceAsset'))
CREATE CLUSTERED INDEX CX_ServiceAsset ON sidata.ServiceAsset (CollectionId, ServiceKey);

-- one row per service of the collection (and the no-service row)
IF OBJECT_ID('sidata.ServiceRisk') IS NULL
CREATE TABLE sidata.ServiceRisk (
    CollectionId     INT            NOT NULL CONSTRAINT FK_ServiceRisk_Collection REFERENCES sidata.Collection (CollectionId),
    ServiceKey       NVARCHAR(256)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Assets           INT            NOT NULL,
    SharedAssets     INT            NOT NULL,   -- of those, CIs that also belong to another service
    Findings         INT            NOT NULL,
    WeightedTotal    FLOAT          NULL,
    WeightedPerAsset FLOAT          NULL,
    RiskTotal        FLOAT          NULL,
    MaxWeighted      FLOAT          NULL,
    Critical         INT            NOT NULL,
    High             INT            NOT NULL,
    Medium           INT            NOT NULL,
    Low              INT            NOT NULL,
    Tier0            INT            NOT NULL,   -- findings on tier 0 .. 3 / unclassified
    Tier1            INT            NOT NULL,
    Tier2            INT            NOT NULL,
    Tier3            INT            NOT NULL,
    TierUnclassified INT            NOT NULL,
    TopAssetKey      NVARCHAR(400)  NULL,       -- the CI with the highest weighted total in this service
    TopAssetName     NVARCHAR(400)  NULL,
    TopAssetWeighted FLOAT          NULL,
    Sources          NVARCHAR(200)  NULL,       -- the membership sources that placed its CIs
    CONSTRAINT PK_ServiceRisk PRIMARY KEY CLUSTERED (CollectionId, ServiceKey)
);

-- the first membership source reads the CMDB columns of one collection's findings without the wide rows
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Service' AND object_id = OBJECT_ID('sidata.Finding'))
EXEC ('CREATE INDEX IX_Finding_Service ON sidata.Finding (CollectionId, AssetKey) INCLUDE (CmdbId, CmdbName)');

-- ---------------------------------------------------------------------------------------------
-- EXEMPTED FINDINGS (#264): an exemption never removes a finding. Risk Analysis keeps every row and MARKS the ones an
-- approved exemption (cfg.Exemption) covered at run time -- SI_ExemptionId, SI_ExemptedUntil, SI_ExemptionRequestId on the
-- Log Analytics row -- and the data sync copies the mark onto the finding here. So the mark is resolved PER COLLECTION
-- (what was exempted when the collection was taken), and ALL hiding / excluding happens at READ time: every view, query,
-- report and mail asks the ONE predicate "f.ExemptionId IS NULL" (counted) / "IS NOT NULL" (exempted), governed by the
-- settings SIWeb_Exempted_ShowInViews / SI_Exempted_CountInManagement / SI_Exempted_InDepartmentReports and a per-view tick.
--   ExemptionId         the cfg.Exemption row that covered the finding (NULL = not exempted)
--   ExemptedUntil       its end date at run time (NULL with an ExemptionId = no end date)
--   ExemptionRequestId  the request (#252) it was approved from, when it came through the flow
-- THE COUNTED VARIANTS: every pre-computed aggregate exists twice -- the existing table counts EVERY finding (exempted
-- included), its "...Counted" twin counts only the findings without a mark -- so a page answers either way from a
-- pre-computed table and never groups finding rows per page view. The data sync fills the twins for each collection and
-- stamps Collection.ExemptedDerivedAt (NULL = not yet; a collection loaded before the twins existed is filled once).
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'ExemptionId') IS NULL
ALTER TABLE sidata.Finding ADD ExemptionId BIGINT NULL;

IF COL_LENGTH('sidata.Finding', 'ExemptedUntil') IS NULL
ALTER TABLE sidata.Finding ADD ExemptedUntil DATETIME2(0) NULL;

IF COL_LENGTH('sidata.Finding', 'ExemptionRequestId') IS NULL
ALTER TABLE sidata.Finding ADD ExemptionRequestId BIGINT NULL;

IF COL_LENGTH('sidata.Collection', 'ExemptedDerivedAt') IS NULL
ALTER TABLE sidata.Collection ADD ExemptedDerivedAt DATETIME2(0) NULL;

-- the exempted findings of one collection (the "N exempted not counted" notes): a filtered index, tiny by construction
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Exempted' AND object_id = OBJECT_ID('sidata.Finding'))
EXEC ('CREATE INDEX IX_Finding_Exempted ON sidata.Finding (CollectionId, ExemptionId) INCLUDE (AssetKey, ExemptedUntil, ExemptionRequestId, DepartmentId, Severity, Tier) WHERE ExemptionId IS NOT NULL');

-- #284: every view that leaves exempted findings out reads "ExemptionId IS NULL" -- the views' covering index must carry the
-- mark, or each such read falls back to the wide clustered rows (live ring 1: 12,566 reads instead of 1,953 per page). The
-- index gains ONE included column, rebuilt in place (same name, same keys); guarded, so it runs once and never again.
IF NOT EXISTS (SELECT 1 FROM sys.indexes AS i JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
               JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
               WHERE i.name = 'IX_Finding_Views' AND i.object_id = OBJECT_ID('sidata.Finding') AND c.name = 'ExemptionId')
   AND EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Views' AND object_id = OBJECT_ID('sidata.Finding'))
EXEC ('CREATE INDEX IX_Finding_Views ON sidata.Finding (CollectionId, AssetKey) INCLUDE (AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, Cvss, HasExploit, MitreTactics, MitreTechniques, ComplianceTags, ExemptionId) WITH (DROP_EXISTING = ON)');

IF OBJECT_ID('sidata.FindingDailyCounted') IS NULL
CREATE TABLE sidata.FindingDailyCounted (
    FindingDailyId   BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_FindingDailyCounted PRIMARY KEY NONCLUSTERED,
    [Day]            DATE           NOT NULL,
    CollectionId     INT            NOT NULL CONSTRAINT FK_FindingDailyCounted_Collection REFERENCES sidata.Collection (CollectionId),
    Tier             TINYINT        NULL,
    Severity         NVARCHAR(30)   NOT NULL,
    SecurityDomain   NVARCHAR(128)  NOT NULL,
    ReportName       NVARCHAR(256)  NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,
    ScoreTotal       FLOAT          NOT NULL,
    ScoreMax         FLOAT          NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_FindingDailyCounted_Day' AND object_id = OBJECT_ID('sidata.FindingDailyCounted'))
CREATE CLUSTERED INDEX CX_FindingDailyCounted_Day ON sidata.FindingDailyCounted ([Day], Tier, Severity);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingDailyCounted_Collection' AND object_id = OBJECT_ID('sidata.FindingDailyCounted'))
CREATE INDEX IX_FindingDailyCounted_Collection ON sidata.FindingDailyCounted (CollectionId);

-- #295: AssetDaily's counted twin (the distinct assets over the findings without an exemption mark)
IF OBJECT_ID('sidata.AssetDailyCounted') IS NULL
CREATE TABLE sidata.AssetDailyCounted (
    AssetDailyId     BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetDailyCounted PRIMARY KEY NONCLUSTERED,
    [Day]            DATE           NOT NULL,
    CollectionId     INT            NOT NULL CONSTRAINT FK_AssetDailyCounted_Collection REFERENCES sidata.Collection (CollectionId),
    GroupingId       TINYINT        NOT NULL,
    Tier             TINYINT        NULL,
    Severity         NVARCHAR(30)   NULL,
    SecurityDomain   NVARCHAR(128)  NULL,
    ReportName       NVARCHAR(256)  NULL,
    Assets           INT            NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_AssetDailyCounted_Day' AND object_id = OBJECT_ID('sidata.AssetDailyCounted'))
CREATE CLUSTERED INDEX CX_AssetDailyCounted_Day ON sidata.AssetDailyCounted ([Day], GroupingId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetDailyCounted_Collection' AND object_id = OBJECT_ID('sidata.AssetDailyCounted'))
CREATE INDEX IX_AssetDailyCounted_Collection ON sidata.AssetDailyCounted (CollectionId);

IF OBJECT_ID('sidata.FindingFacetCounted') IS NULL
CREATE TABLE sidata.FindingFacetCounted (
    CollectionId     INT            NOT NULL CONSTRAINT FK_FindingFacetCounted_Collection REFERENCES sidata.Collection (CollectionId),
    Facet            NVARCHAR(16)   NOT NULL,
    Value            NVARCHAR(256)  NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,
    ScoreTotal       FLOAT          NOT NULL,
    WeightedTotal    FLOAT          NULL,
    MaxScore         FLOAT          NULL,
    CONSTRAINT PK_FindingFacetCounted PRIMARY KEY CLUSTERED (CollectionId, Facet, Value)
);

IF OBJECT_ID('sidata.DepartmentFacetCounted') IS NULL
CREATE TABLE sidata.DepartmentFacetCounted (
    CollectionId     INT            NOT NULL CONSTRAINT FK_DepartmentFacetCounted_Collection REFERENCES sidata.Collection (CollectionId),
    DepartmentId     INT            NOT NULL,
    Severity         NVARCHAR(30)   NOT NULL,
    Tier             NVARCHAR(12)   NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,
    ScoreTotal       FLOAT          NOT NULL,
    WeightedTotal    FLOAT          NULL,
    CONSTRAINT PK_DepartmentFacetCounted PRIMARY KEY CLUSTERED (CollectionId, DepartmentId, Severity, Tier)
);

IF OBJECT_ID('sidata.ServiceAssetCounted') IS NULL
CREATE TABLE sidata.ServiceAssetCounted (
    CollectionId     INT            NOT NULL CONSTRAINT FK_ServiceAssetCounted_Collection REFERENCES sidata.Collection (CollectionId),
    ServiceKey       NVARCHAR(256)  NOT NULL,
    AssetKey         NVARCHAR(400)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Source           NVARCHAR(32)   NULL,
    AssetName        NVARCHAR(400)  NULL,
    Tier             TINYINT        NULL,
    ServiceCount     INT            NOT NULL,
    Findings         INT            NOT NULL,
    Critical         INT            NOT NULL,
    High             INT            NOT NULL,
    Medium           INT            NOT NULL,
    Low              INT            NOT NULL,
    WeightedTotal    FLOAT          NULL,
    RiskTotal        FLOAT          NULL,
    MaxWeighted      FLOAT          NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_ServiceAssetCounted' AND object_id = OBJECT_ID('sidata.ServiceAssetCounted'))
CREATE CLUSTERED INDEX CX_ServiceAssetCounted ON sidata.ServiceAssetCounted (CollectionId, ServiceKey);

IF OBJECT_ID('sidata.ServiceRiskCounted') IS NULL
CREATE TABLE sidata.ServiceRiskCounted (
    CollectionId     INT            NOT NULL CONSTRAINT FK_ServiceRiskCounted_Collection REFERENCES sidata.Collection (CollectionId),
    ServiceKey       NVARCHAR(256)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Assets           INT            NOT NULL,
    SharedAssets     INT            NOT NULL,
    Findings         INT            NOT NULL,
    WeightedTotal    FLOAT          NULL,
    WeightedPerAsset FLOAT          NULL,
    RiskTotal        FLOAT          NULL,
    MaxWeighted      FLOAT          NULL,
    Critical         INT            NOT NULL,
    High             INT            NOT NULL,
    Medium           INT            NOT NULL,
    Low              INT            NOT NULL,
    Tier0            INT            NOT NULL,
    Tier1            INT            NOT NULL,
    Tier2            INT            NOT NULL,
    Tier3            INT            NOT NULL,
    TierUnclassified INT            NOT NULL,
    TopAssetKey      NVARCHAR(400)  NULL,
    TopAssetName     NVARCHAR(400)  NULL,
    TopAssetWeighted FLOAT          NULL,
    Sources          NVARCHAR(200)  NULL,
    CONSTRAINT PK_ServiceRiskCounted PRIMARY KEY CLUSTERED (CollectionId, ServiceKey)
);

-- ---------------------------------------------------------------------------------------------
-- RiskExecView (#288): what the last Risk Analysis mail of each report grain showed -- the Risk Score KPI and band,
-- the domain x severity table, the per-domain scores, the AI-written analysis and the Top-50 risky assets -- exactly
-- as the engine rendered it (engine/risk-analysis/_shared/RA-ExecView.ps1). One row per grain, replaced only by a
-- NEWER view. The web app's Overview > Executive report > "Risk Analysis" page reads it; it is never recomputed.
-- FiguresFromGrain: whose figures the mail carried (the leader's, when the report adopted them in Consistent mode).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.RiskExecView') IS NULL
CREATE TABLE sidata.RiskExecView (
    Grain            NVARCHAR(16)   NOT NULL CONSTRAINT PK_RiskExecView PRIMARY KEY,
    GeneratedAt      DATETIME2(3)   NOT NULL,   -- when the run that wrote it built its mail (UTC)
    CollectionTime   DATETIME2(3)   NULL,
    ReportTemplate   NVARCHAR(128)  NULL,
    Mode             NVARCHAR(16)   NOT NULL,   -- the agreement mode in force for that run
    Leader           NVARCHAR(16)   NOT NULL,
    FiguresFromGrain NVARCHAR(16)   NOT NULL,
    PayloadJson      NVARCHAR(MAX)  NOT NULL,
    LoadedAt         DATETIME2(0)   NOT NULL CONSTRAINT DF_RiskExecView_LoadedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_RiskExecView_Grain CHECK (Grain IN ('Summary', 'Detailed')),
    CONSTRAINT CK_RiskExecView_Mode CHECK (Mode IN ('Consistent', 'PerReport')),
    CONSTRAINT CK_RiskExecView_Leader CHECK (Leader IN ('Summary', 'Detailed')),
    CONSTRAINT CK_RiskExecView_From CHECK (FiguresFromGrain IN ('Summary', 'Detailed'))
);

-- =============================================================================================
-- CORRELATION EVIDENCE (#299): WHY SecurityInsight says these source records are ONE CI, and how good the correlation
-- is per collection. Written by the data sync with every load (engine\pro-data\_shared\SI-DataEvidence.ps1); the asset
-- page's Evidence section and the Correlation quality report read it. The correlation engine stays read-only towards
-- every source: these rows are derived from what the profiles and the correlation map already published.
--   AssetEvidence     one row per (CI, source record, key): the source system that reported the key (Defender, Entra,
--                     Active Directory, Azure, Exposure Graph, Shodan, CMDB, ServiceNow, Risk Analysis), the source
--                     record it was on (its SI_AssetId) and that record's profile (RecordKind), the MATCH RULE that put
--                     the record into this CI and its CONFIDENCE (exact | strong | weak), whether the key itself joined
--                     two records (IsJoinKey), when the source last saw it (SourceLastSeen; NULL = the source gives no
--                     time) and when SecurityInsight last read the record (RecordSeenAt). FirstSeen / LastSeen = the
--                     collections the evidence was present in; FirstLoadId / LastLoadId = the loads (CollectionId) that
--                     first / last carried it -- what the id-history detection compares.
--                     MatchRule: exact-id (a durable id two records share) | graph-link (an Exposure Graph node id two
--                     records share) | same-record (the key is on a record that joined by another key, or on the CI's
--                     only record) | cmdb-pinned | cmdb-rule | cmdb-id | cmdb-name (how the CMDB matched the record) |
--                     unresolved (seen only in a Risk Analysis finding; no source record matched it)
--   AssetIdHistory    the CI's id history: alias (a source record's SI id moved while its durable id stayed -- #279),
--                     rekey (the CI's key changed), merge (a CI's durable ids now belong to another, already existing CI)
--   AssetConflict     a value the CI's source records disagree on (Name, OS, Domain, CMDB CI), one row per source record,
--                     and Field 'Possible duplicate': another CI with the same name and no shared durable id. Current
--                     when LastLoadId is the CI's newest load; an older row is a conflict that has since been resolved.
--   AssetCorrelation  PRE-COMPUTED per collection, one row per CI: records joined, source systems (count + names), the
--                     weakest confidence and how the records were joined, conflicts, id changes found in that load, a
--                     possible duplicate, and the CMDB match state -- the Correlation quality report reads this, never
--                     the evidence rows
--   Collection.CorrelatedAt  when the collection's correlation evidence was computed (NULL = not yet)
-- =============================================================================================
IF OBJECT_ID('sidata.AssetEvidence') IS NULL
CREATE TABLE sidata.AssetEvidence (
    AssetEvidenceId  BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetEvidence PRIMARY KEY,
    AssetKey         NVARCHAR(400)  NOT NULL,
    EvidenceHash     BINARY(32)     NOT NULL,   -- SHA2_256 of lower(MemberAssetId)|KeyType|KeyValue: the row's identity within the CI
    Source           NVARCHAR(32)   NOT NULL,
    RecordKind       NVARCHAR(16)   NOT NULL,   -- endpoint | identity | azure | publicip | finding
    MemberAssetId    NVARCHAR(400)  NOT NULL,
    KeyType          NVARCHAR(64)   NOT NULL,
    KeyValue         NVARCHAR(256)  NOT NULL,
    MatchRule        NVARCHAR(24)   NOT NULL,
    Confidence       NVARCHAR(8)    NOT NULL,
    IsJoinKey        BIT            NOT NULL CONSTRAINT DF_AssetEvidence_IsJoinKey DEFAULT 0,
    SourceLastSeen   DATETIME2(3)   NULL,
    RecordSeenAt     DATETIME2(3)   NULL,
    FirstSeen        DATETIME2(3)   NOT NULL,
    LastSeen         DATETIME2(3)   NOT NULL,
    FirstLoadId      INT            NOT NULL,
    LastLoadId       INT            NOT NULL,
    CONSTRAINT CK_AssetEvidence_Confidence CHECK (Confidence IN ('exact', 'strong', 'weak'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_AssetEvidence_Key' AND object_id = OBJECT_ID('sidata.AssetEvidence'))
CREATE UNIQUE INDEX UX_AssetEvidence_Key ON sidata.AssetEvidence (AssetKey, EvidenceHash);

-- the id-history detection: which CI carried this durable key before
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetEvidence_Value' AND object_id = OBJECT_ID('sidata.AssetEvidence'))
CREATE INDEX IX_AssetEvidence_Value ON sidata.AssetEvidence (KeyValue, KeyType) INCLUDE (AssetKey, MemberAssetId, FirstLoadId, LastLoadId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetEvidence_Load' AND object_id = OBJECT_ID('sidata.AssetEvidence'))
CREATE INDEX IX_AssetEvidence_Load ON sidata.AssetEvidence (LastLoadId) INCLUDE (AssetKey);

IF OBJECT_ID('sidata.AssetIdHistory') IS NULL
CREATE TABLE sidata.AssetIdHistory (
    AssetIdHistoryId BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetIdHistory PRIMARY KEY,
    AssetKey         NVARCHAR(400)  NOT NULL,   -- the CI as it is now
    EventType        NVARCHAR(8)    NOT NULL,
    PreviousId       NVARCHAR(400)  NOT NULL,   -- alias: the record's previous SI id; rekey / merge: the CI's previous key
    CurrentId        NVARCHAR(400)  NOT NULL,   -- alias: the record's SI id now; rekey / merge: the CI key now
    ViaType          NVARCHAR(64)   NULL,       -- the durable key both sides carry: the proof
    ViaValue         NVARCHAR(256)  NULL,
    DetectedAt       DATETIME2(3)   NOT NULL,   -- the collection time of the load that saw it
    LoadId           INT            NOT NULL,
    CONSTRAINT CK_AssetIdHistory_EventType CHECK (EventType IN ('alias', 'rekey', 'merge'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_AssetIdHistory_Key' AND object_id = OBJECT_ID('sidata.AssetIdHistory'))
CREATE UNIQUE INDEX UX_AssetIdHistory_Key ON sidata.AssetIdHistory (AssetKey, EventType, PreviousId);

-- "this key was merged into ...": the asset page of an old key finds its CI now
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetIdHistory_Previous' AND object_id = OBJECT_ID('sidata.AssetIdHistory'))
CREATE INDEX IX_AssetIdHistory_Previous ON sidata.AssetIdHistory (PreviousId) INCLUDE (AssetKey, EventType, DetectedAt);

IF OBJECT_ID('sidata.AssetConflict') IS NULL
CREATE TABLE sidata.AssetConflict (
    AssetConflictId  BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetConflict PRIMARY KEY,
    AssetKey         NVARCHAR(400)  NOT NULL,
    ConflictHash     BINARY(32)     NOT NULL,   -- SHA2_256 of Field|Source|lower(MemberAssetId)
    Field            NVARCHAR(32)   NOT NULL,   -- Name | OS | Domain | CMDB CI | Possible duplicate
    Source           NVARCHAR(32)   NOT NULL,
    MemberAssetId    NVARCHAR(400)  NOT NULL,   -- the record that carries the value (Possible duplicate: the other CI's key)
    Value            NVARCHAR(400)  NOT NULL,
    FirstSeen        DATETIME2(3)   NOT NULL,
    LastSeen         DATETIME2(3)   NOT NULL,
    FirstLoadId      INT            NOT NULL,
    LastLoadId       INT            NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_AssetConflict_Key' AND object_id = OBJECT_ID('sidata.AssetConflict'))
CREATE UNIQUE INDEX UX_AssetConflict_Key ON sidata.AssetConflict (AssetKey, ConflictHash);

IF OBJECT_ID('sidata.AssetCorrelation') IS NULL
CREATE TABLE sidata.AssetCorrelation (
    CollectionId        INT            NOT NULL CONSTRAINT FK_AssetCorrelation_Collection REFERENCES sidata.Collection (CollectionId),
    AssetKey            NVARCHAR(400)  NOT NULL,
    AssetName           NVARCHAR(400)  NULL,
    AssetKind           NVARCHAR(16)   NULL,
    Tier                TINYINT        NULL,
    Records             INT            NOT NULL,   -- source records joined into the CI
    SourceCount         INT            NOT NULL,   -- distinct source systems
    Sources             NVARCHAR(400)  NULL,       -- their names, "; "-separated
    Confidence          NVARCHAR(8)    NOT NULL,   -- the weakest: exact | strong | weak
    JoinRule            NVARCHAR(24)   NOT NULL,   -- exact-id | graph-link | single-record | unresolved
    Conflicts           INT            NOT NULL,
    IdChanges           INT            NOT NULL,
    PossibleDuplicateOf NVARCHAR(400)  NULL,
    CmdbState           NVARCHAR(12)   NULL,       -- matched | si-only | stale | NULL (no CMDB answered for the CI)
    CmdbSource          NVARCHAR(16)   NULL,       -- servicenow | generic-csv
    CmdbId              NVARCHAR(256)  NULL,
    CONSTRAINT PK_AssetCorrelation PRIMARY KEY CLUSTERED (CollectionId, AssetKey),
    CONSTRAINT CK_AssetCorrelation_Confidence CHECK (Confidence IN ('exact', 'strong', 'weak'))
);

IF COL_LENGTH('sidata.Collection', 'CorrelatedAt') IS NULL
ALTER TABLE sidata.Collection ADD CorrelatedAt DATETIME2(0) NULL;

-- THE SHARED PREDICATE, as a view: the exempted findings (the mark), one row each -- what a report, a mail or a note counts
-- as "exempted, not counted". Its complement (ExemptionId IS NULL) is what every surface counts by default.
IF OBJECT_ID('sidata.vExemptedFinding') IS NULL
EXEC ('CREATE VIEW sidata.vExemptedFinding AS
SELECT f.CollectionId, f.FindingId, f.AssetKey, f.AssetName, f.SecurityDomain, f.ReportName, f.Cve, f.ConfigurationId, f.Severity, f.Tier,
       f.DepartmentId, f.ExemptionId, f.ExemptedUntil, f.ExemptionRequestId
FROM sidata.Finding AS f
WHERE f.ExemptionId IS NOT NULL');

-- ---------------------------------------------------------------------------------------------
-- VIEWS. Created through EXEC because CREATE VIEW must start its own batch.
-- ---------------------------------------------------------------------------------------------

-- ---------------------------------------------------------------------------------------------
-- CollectionPartial: a collection an Admin RELEASED although the Risk Analysis run that produced it was not shown
-- complete (Operations > Guards (safety checks), "Release: load this collection anyway"; cfg.GuardRelease kind 'collection'). The data
-- sync loads it ONCE and marks it here: why it was held (which part of the run was incomplete), who released it, when.
-- The web app shows a "partial" badge wherever such a collection is used -- a partial result is never shown as whole.
-- No foreign key: the retention purge removes the mark with its collection (and the data sync clears orphans).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.CollectionPartial') IS NULL
CREATE TABLE sidata.CollectionPartial (
    CollectionId     INT            NOT NULL CONSTRAINT PK_CollectionPartial PRIMARY KEY,
    Reason           NVARCHAR(2000) NULL,
    ReleasedBy       NVARCHAR(256)  NULL,
    ReleasedUtc      DATETIME2(0)   NULL,
    MarkedUtc        DATETIME2(0)   NOT NULL CONSTRAINT DF_CollectionPartial_MarkedUtc DEFAULT SYSUTCDATETIME()
);

-- The newest COMPLETE collection of each kind.
IF OBJECT_ID('sidata.vLatestCollection') IS NULL
EXEC ('CREATE VIEW sidata.vLatestCollection AS
SELECT c.CollectionId, c.CollectionTime, c.Kind, c.RunId, c.[Rows], c.LoadedAt, c.SolutionVersion
FROM sidata.Collection c
WHERE c.Status = ''Complete''
  AND c.CollectionTime = (SELECT MAX(x.CollectionTime) FROM sidata.Collection x WHERE x.Kind = c.Kind AND x.Status = ''Complete'')');

-- The findings of the newest complete Detailed collection.
IF OBJECT_ID('sidata.vCurrentFinding') IS NULL
EXEC ('CREATE VIEW sidata.vCurrentFinding AS
SELECT f.FindingId, f.CollectionId, l.CollectionTime, f.AssetKey, f.AssetName, f.ReportName, f.SecurityDomain,
       f.ConfigurationId, f.Cve, f.Title, f.Severity, f.Tier, f.RiskScore, f.DetailJson
FROM sidata.Finding f
JOIN sidata.vLatestCollection l ON l.CollectionId = f.CollectionId AND l.Kind = ''Detailed''');

-- The CI view: one row per asset, its identifiers as "type:value" separated by "; ".
IF OBJECT_ID('sidata.vCi') IS NULL
EXEC ('CREATE VIEW sidata.vCi AS
SELECT a.AssetKey, a.AssetName, a.AssetKind, a.Tier, a.KeySource,
       (SELECT STRING_AGG(CAST(i.IdentifierType + N'':'' + i.IdentifierValue AS NVARCHAR(MAX)), N''; '')
          FROM sidata.AssetIdentifier i WHERE i.AssetKey = a.AssetKey) AS Identifiers,
       a.FirstSeen, a.LastSeen
FROM sidata.Asset a');

-- =============================================================================================
-- FULL ASSET METADATA (#301 / #408): every property each source system knows about a CI, stored GENERICALLY -- one row
-- per (CI, source system, source record, item), the source object itself as JSON. No column per property: an Azure VM's
-- `properties`, an Intune device, an Exposure Graph node and a VM extension all land in the same shape, ARRAYS STAY
-- ARRAYS (networkInterfaces, dataDisks, tags, ipAddresses ...), and a new upstream field needs no schema change.
-- Operator 2026-08-31: "store lots of detailed properties under Properties, like how Azure does it for an Azure object".
-- Written by the data sync ONLY when the install runs SI_AssetProperties = 'full' (engine\pro-data\_shared\
-- SI-DataAssetMetadata.ps1), from SI_AssetProperties_CL; the security level stores nothing here. The asset page's
-- "Full metadata" section reads it. Kept SI_AssetProperties_RetentionDays (default 3): the data sync prunes it, audited.
--   AssetMetadata      EVERY kept snapshot of each (CI, source system, record, item) -- #412 (operator 2026-10-06, "one
--                      pull per source + history"): a newer collection no longer replaces the older one; each profiler
--                      run's objects are added with that run's CollectionTime, and the asset page shows them newest
--                      first with what changed between consecutive snapshots. Retention (SI_AssetProperties_RetentionDays)
--                      removes the older ones. ItemName = '' for the object itself, a child's own name for a child
--                      row (a VM extension, ParentResourceId = its VM). PropertiesJson = the source object verbatim
--                      (or the oversize marker { "_siPayloadDropped": "oversize", ... } -- never a cut object).
--   AssetMetadataLoad  one row per Log Analytics snapshot loaded: when, how many rows and CIs, which sources -- what
--                      makes a re-run load a snapshot once, and what the asset page says when there is no data yet.
--                      SourceRows (#412): the snapshot's row count in Log Analytics when it was loaded -- a snapshot that
--                      has grown since (a second profiler published with the same CollectionTime) is loaded again.
-- =============================================================================================
IF OBJECT_ID('sidata.AssetMetadata') IS NULL
CREATE TABLE sidata.AssetMetadata (
    AssetMetadataId  BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AssetMetadata PRIMARY KEY,
    AssetKey         NVARCHAR(400)  NOT NULL,   -- the CI (sidata.Asset.AssetKey)
    SourceSystem     NVARCHAR(32)   NOT NULL,   -- mde | entra-device | entra-user | entra-serviceprincipal | arm | arm-vm-extension | ad-computer | exposure-graph | intune-device
    ItemName         NVARCHAR(256)  NOT NULL CONSTRAINT DF_AssetMetadata_ItemName DEFAULT N'',
    MemberAssetId    NVARCHAR(400)  NOT NULL,   -- the source record (its SI_AssetId)
    CollectionTime   DATETIME2(3)   NOT NULL,   -- when the asset-properties run collected it
    SerialNumber     NVARCHAR(128)  NULL,
    MacAddress       NVARCHAR(256)  NULL,
    ParentResourceId NVARCHAR(1024) NULL,
    PropertyCount    INT            NULL,       -- distinct leaf paths (an array counts once)
    PropertiesBytes  INT            NULL,
    Dropped          BIT            NOT NULL CONSTRAINT DF_AssetMetadata_Dropped DEFAULT 0,      -- over the size budget: PropertiesJson is the marker
    HandoffHeld      BIT            NOT NULL CONSTRAINT DF_AssetMetadata_HandoffHeld DEFAULT 0,  -- the collection-change guard re-published the previous object
    PropertiesJson   NVARCHAR(MAX)  NOT NULL,
    LoadedAt         DATETIME2(0)   NOT NULL CONSTRAINT DF_AssetMetadata_LoadedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_AssetMetadata_Json CHECK (ISJSON(PropertiesJson) = 1)
);

-- the asset page: one CI's objects
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetMetadata_Asset' AND object_id = OBJECT_ID('sidata.AssetMetadata'))
CREATE INDEX IX_AssetMetadata_Asset ON sidata.AssetMetadata (AssetKey, SourceSystem) INCLUDE (CollectionTime);

-- retention: everything collected before the cutoff
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetMetadata_Time' AND object_id = OBJECT_ID('sidata.AssetMetadata'))
CREATE INDEX IX_AssetMetadata_Time ON sidata.AssetMetadata (CollectionTime);

IF OBJECT_ID('sidata.AssetMetadataLoad') IS NULL
CREATE TABLE sidata.AssetMetadataLoad (
    CollectionTime   DATETIME2(3)   NOT NULL CONSTRAINT PK_AssetMetadataLoad PRIMARY KEY,
    [Rows]           INT            NOT NULL,
    Assets           INT            NOT NULL,
    Sources          NVARCHAR(400)  NULL,       -- the source systems in the snapshot, ", "-separated
    Unmatched        INT            NOT NULL CONSTRAINT DF_AssetMetadataLoad_Unmatched DEFAULT 0,  -- rows without an asset id (not stored)
    LoadedAt         DATETIME2(0)   NOT NULL CONSTRAINT DF_AssetMetadataLoad_LoadedAt DEFAULT SYSUTCDATETIME()
);

-- SourceRows (ADDED 2026-10-06, #412): the snapshot's row count in Log Analytics at load. Additive: NULL on the loads
-- recorded before it existed (those count as complete).
IF COL_LENGTH('sidata.AssetMetadataLoad', 'SourceRows') IS NULL
ALTER TABLE sidata.AssetMetadataLoad ADD SourceRows INT NULL;

-- ---------------------------------------------------------------------------------------------
-- THE v3 DATA MODEL (V3-DATA-MODEL part 2; ADDED 2026-10-08): CIs, their links, findings per CI, daily CI rows, the
-- provider records. Was created at run time by the data sync (SI-DataCi.ps1), whose identity may not hold the right to
-- create tables -- it belongs here, applied by setup and the updater (#477). The same guarded statements.
-- ---------------------------------------------------------------------------------------------
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
-- The component the finding concerns (si_component: OS, SQL, Network, Hardware, Browser, Office, Application, Other) as a
-- column of its own, so the Findings per CI view filters on it and exports it. Additive and guarded; the data sync runs
-- the same statements and fills the column with the next finding collection it stores.
IF COL_LENGTH('sidata.CiFinding', 'Component') IS NULL
BEGIN
    ALTER TABLE sidata.CiFinding ADD Component NVARCHAR(64) NULL;
    -- #881 the findings already stored get it from their own row in the data sync, a CiFindingId range at a time
    -- (Invoke-SIDataCiColumnBackfill) -- never one statement over the whole table here
    PRINT 0;
END
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_Component' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_Component ON sidata.CiFinding (Component) INCLUDE (CiId, FindingKey)');
-- #772 the ServiceNow sub-CI the finding is linked under (si_servicenow_subci: OS / SQL / Other by default, the customer's
-- buckets) as a column of its own, so the Findings per CI view shows, filters and exports it. Additive and guarded.
IF COL_LENGTH('sidata.CiFinding', 'SubCi') IS NULL
BEGIN
    ALTER TABLE sidata.CiFinding ADD SubCi NVARCHAR(64) NULL;
    -- #881 the findings already stored get it from their own row in the data sync, a CiFindingId range at a time
    -- (Invoke-SIDataCiColumnBackfill) -- never one statement over the whole table here
    PRINT 0;
END
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_SubCi' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_SubCi ON sidata.CiFinding (SubCi) INCLUDE (CiId, FindingKey)');
-- #772 the finding's patch cycle (si_patch_cycle: In monthly cycle / Catch-up / No fix available / Unknown), stored + indexed
IF COL_LENGTH('sidata.CiFinding', 'PatchCycle') IS NULL
BEGIN
    ALTER TABLE sidata.CiFinding ADD PatchCycle NVARCHAR(64) NULL;
    -- #881 the findings already stored get it from their own row in the data sync, a CiFindingId range at a time
    -- (Invoke-SIDataCiColumnBackfill) -- never one statement over the whole table here
    PRINT 0;
END
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_PatchCycle' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_PatchCycle ON sidata.CiFinding (PatchCycle) INCLUDE (CiId, FindingKey)');
-- #772 the CVE's published date (si_cve_published), typed, for the exposure age
IF COL_LENGTH('sidata.CiFinding', 'CvePublished') IS NULL
    ALTER TABLE sidata.CiFinding ADD CvePublished DATETIME2(3) NULL;
-- the CONTENT HASH of a stored finding (2026-10-25, owner: "performance must be good like the hash idea but for data only"):
-- SHA-256 of its data, the fields every run moves left out (its CollectionTime, the run fields of its document --
-- SI-DataCi.ps1 Get-SIDataCiFindingRunFields). Written by the data sync's swap only; a finding seen again with the same
-- content keeps its row and gets only the run's time and document. NULL = not known (worked out from the row). Additive.
IF COL_LENGTH('sidata.CiFinding', 'ContentHash') IS NULL
    ALTER TABLE sidata.CiFinding ADD ContentHash BINARY(32) NULL;
-- CiFindingStage: where the data sync writes a new finding collection before ONE transaction replaces sidata.CiFinding
-- from it -- so "Findings per CI" shows the whole previous set or the whole new one, never a part. The same columns as
-- sidata.CiFinding, no index besides its key (it is written, read once in order, and emptied). Empty between runs. A
-- database without it is written the old way (emptied, then refilled in steps) until the updater has applied this file.
IF OBJECT_ID('sidata.CiFindingStage') IS NULL
CREATE TABLE sidata.CiFindingStage (
    StageId           BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CiFindingStage PRIMARY KEY,
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
    DocJson           NVARCHAR(MAX)  NULL,
    Component         NVARCHAR(64)   NULL,
    SubCi             NVARCHAR(64)   NULL,
    PatchCycle        NVARCHAR(64)   NULL,
    CvePublished      DATETIME2(3)   NULL
);
-- #772 a staging table made before the ServiceNow sub-CI: the column added in place
IF COL_LENGTH('sidata.CiFindingStage', 'SubCi') IS NULL
    ALTER TABLE sidata.CiFindingStage ADD SubCi NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.CiFindingStage', 'PatchCycle') IS NULL
    ALTER TABLE sidata.CiFindingStage ADD PatchCycle NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.CiFindingStage', 'CvePublished') IS NULL
    ALTER TABLE sidata.CiFindingStage ADD CvePublished DATETIME2(3) NULL;
-- #772 the Microsoft update release dates per KB (the Security Update Guide, read once a day by Risk Analysis for the patch
-- cycle): one row per KB, its first release date; the row Kb = '$state' holds when they were read and which release
-- documents (Detail, JSON). Small (thousands of rows), written in one statement.
IF OBJECT_ID('sidata.KbReleaseDate') IS NULL
CREATE TABLE sidata.KbReleaseDate (
    Kb          NVARCHAR(16)   NOT NULL CONSTRAINT PK_KbReleaseDate PRIMARY KEY,
    ReleaseDate DATE           NULL,
    Detail      NVARCHAR(MAX)  NULL,
    UpdatedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_KbReleaseDate_UpdatedAt DEFAULT SYSUTCDATETIME()
);
-- CiFindingLifecycleStage (#639, 2026-10-13): the finding lifecycle's input of the collection being stored, staged by the
-- data sync page by page in chunks (Kind f = a finding: owner, key, CI, severity, detectors, exemption; Kind a = a key the
-- recommendation equivalence changed: owner, the provider's own key in FindingKey, the shared key in Canonical). The
-- lifecycle statement reads it from here -- the whole collection was ONE JSON string in one parameter, which timed out at
-- a large install. Emptied after the lifecycle ran (the next run's first chunk empties it too). A database without it skips
-- the lifecycle for that run (said; nothing is closed) until the updater has applied this file.
IF OBJECT_ID('sidata.CiFindingLifecycleStage') IS NULL
CREATE TABLE sidata.CiFindingLifecycleStage (
    StageId           BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CiFindingLifecycleStage PRIMARY KEY,
    Kind              NCHAR(1)       NOT NULL,
    OwnerKey          NVARCHAR(450)  NOT NULL,
    FindingKey        NVARCHAR(256)  NOT NULL,
    CiId              NVARCHAR(64)   NULL,
    Severity          NVARCHAR(16)   NULL,
    DetectedBy        NVARCHAR(2000) NULL,
    ExemptionId       NVARCHAR(64)   NULL,
    Canonical         NVARCHAR(256)  NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFindingLifecycleStage_Key' AND object_id = OBJECT_ID('sidata.CiFindingLifecycleStage'))
    EXEC (N'CREATE INDEX IX_CiFindingLifecycleStage_Key ON sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey)');
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

-- ---------------------------------------------------------------------------------------------
-- RecordIdentifier (ADDED 2026-10-08, #477 -- correlation in SQL): every strong identifier of a provider record (the
-- identity ledger's types), narrow and indexed -- the CI build groups records into CIs on it, in SQL, at any tenant size.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.RecordIdentifier') IS NULL
CREATE TABLE sidata.RecordIdentifier (
    RecordKey   NVARCHAR(450)  NOT NULL,
    IdType      NVARCHAR(40)   NOT NULL,
    IdValue     NVARCHAR(400)  NOT NULL,
    SeenAt      DATETIME2(3)   NOT NULL,
    CONSTRAINT PK_RecordIdentifier PRIMARY KEY (RecordKey, IdType, IdValue)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RecordIdentifier_Id' AND object_id = OBJECT_ID('sidata.RecordIdentifier'))
CREATE INDEX IX_RecordIdentifier_Id ON sidata.RecordIdentifier (IdType, IdValue) INCLUDE (RecordKey);

-- ---------------------------------------------------------------------------------------------
-- CORRELATION IN SQL (ADDED 2026-10-09, #477 steps 2-4 -- operator: "we dont support la for correlation, sql only";
-- #501 "performance and cost must be optimed"). The CI build groups the records into CIs IN SQL and writes only what
-- changed: a CONTENT HASH on the records and the CIs (the fields that change every run left out), the CI's hash as last
-- posted to Log Analytics (SI_CI_CL), the group of every record of this build, and the build's own state.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.CiRecord', 'ContentHash') IS NULL
    ALTER TABLE sidata.CiRecord ADD ContentHash VARBINARY(32) NULL;
IF COL_LENGTH('sidata.Ci', 'ContentHash') IS NULL
    ALTER TABLE sidata.Ci ADD ContentHash VARBINARY(32) NULL;
IF COL_LENGTH('sidata.Ci', 'PostedHash') IS NULL
    ALTER TABLE sidata.Ci ADD PostedHash VARBINARY(32) NULL;
IF COL_LENGTH('sidata.Ci', 'PostedAt') IS NULL
    ALTER TABLE sidata.Ci ADD PostedAt DATETIME2(0) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRecord_Collection' AND object_id = OBJECT_ID('sidata.CiRecord'))
CREATE INDEX IX_CiRecord_Collection ON sidata.CiRecord (CollectionTime) INCLUDE (RecordType, Provider, Complete);
IF OBJECT_ID('sidata.CiGroupMember') IS NULL
CREATE TABLE sidata.CiGroupMember (
    RecordKey   NVARCHAR(450)  NOT NULL CONSTRAINT PK_CiGroupMember PRIMARY KEY,
    GroupKey    NVARCHAR(450)  NOT NULL,
    BatchNo     INT            NOT NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiGroupMember_Batch' AND object_id = OBJECT_ID('sidata.CiGroupMember'))
CREATE INDEX IX_CiGroupMember_Batch ON sidata.CiGroupMember (BatchNo, GroupKey) INCLUDE (RecordKey);
-- the identifiers two or more current records share -- the only ones the grouping's rounds read (2026-10-09: the
-- one-statement grouping over every identifier did not finish on a small database tier at ~100,000 records)
IF OBJECT_ID('sidata.CiGroupEdge') IS NULL
CREATE TABLE sidata.CiGroupEdge (
    RecordKey   NVARCHAR(450)  NOT NULL,
    IdType      NVARCHAR(40)   NOT NULL,
    IdValue     NVARCHAR(400)  NOT NULL,
    CONSTRAINT PK_CiGroupEdge PRIMARY KEY (RecordKey, IdType, IdValue)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiGroupEdge_Id' AND object_id = OBJECT_ID('sidata.CiGroupEdge'))
CREATE INDEX IX_CiGroupEdge_Id ON sidata.CiGroupEdge (IdType, IdValue) INCLUDE (RecordKey);
IF OBJECT_ID('sidata.CiBuildState') IS NULL
CREATE TABLE sidata.CiBuildState (
    Name        NVARCHAR(64)   NOT NULL CONSTRAINT PK_CiBuildState PRIMARY KEY,
    Value       NVARCHAR(400)  NULL,
    UpdatedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_CiBuildState_UpdatedAt DEFAULT SYSUTCDATETIME()
);

-- ---------------------------------------------------------------------------------------------
-- THE INCREMENTAL CI BUILD (ADDED 2026-10-10, #534 -- owner: "can we improve the speed of ci corelation by validating on
-- hash values or similar ... and then a weekly full reconsile process"). Only the groups whose input changed since their
-- last build are read and built; every other CI keeps its row (a set-based statement moves its collection time).
--   CiRecord.Built*        what the record was when its group was last built: its content hash, its group, its link
--                          state (a = active, n = not seen, f = frozen) and its time signature (which of the build's
--                          day thresholds -- field freshness, evidence age, rule date conditions -- its dates were within,
--                          and its place in its group by last seen)
--   CiGroupMember.Cur*     the same, computed this build; Dirty = its group is built this run
--   Ci.PostRowHash         the hash of the CI's newest SI_CI_CL full row: a CI whose full row did not reach Log Analytics
--                          (PostedHash differs) is built again
-- The build's own state (sidata.CiBuildState): LastFullBuild, BuildFingerprint, LastBuildStatus, LastBuildStart.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.CiRecord', 'BuiltHash') IS NULL
    ALTER TABLE sidata.CiRecord ADD BuiltHash VARBINARY(32) NULL;
IF COL_LENGTH('sidata.CiRecord', 'BuiltGroupKey') IS NULL
    ALTER TABLE sidata.CiRecord ADD BuiltGroupKey NVARCHAR(450) NULL;
IF COL_LENGTH('sidata.CiRecord', 'BuiltState') IS NULL
    ALTER TABLE sidata.CiRecord ADD BuiltState CHAR(1) NULL;
IF COL_LENGTH('sidata.CiRecord', 'BuiltTimeSig') IS NULL
    ALTER TABLE sidata.CiRecord ADD BuiltTimeSig VARBINARY(32) NULL;
IF COL_LENGTH('sidata.CiRecord', 'BuiltAt') IS NULL
    ALTER TABLE sidata.CiRecord ADD BuiltAt DATETIME2(3) NULL;
IF COL_LENGTH('sidata.CiGroupMember', 'Dirty') IS NULL
    ALTER TABLE sidata.CiGroupMember ADD Dirty BIT NOT NULL CONSTRAINT DF_CiGroupMember_Dirty DEFAULT 1;
IF COL_LENGTH('sidata.CiGroupMember', 'CurHash') IS NULL
    ALTER TABLE sidata.CiGroupMember ADD CurHash VARBINARY(32) NULL;
IF COL_LENGTH('sidata.CiGroupMember', 'CurState') IS NULL
    ALTER TABLE sidata.CiGroupMember ADD CurState CHAR(1) NULL;
IF COL_LENGTH('sidata.CiGroupMember', 'CurTimeSig') IS NULL
    ALTER TABLE sidata.CiGroupMember ADD CurTimeSig VARBINARY(32) NULL;
IF COL_LENGTH('sidata.Ci', 'PostRowHash') IS NULL
    ALTER TABLE sidata.Ci ADD PostRowHash VARBINARY(32) NULL;
-- the indexes on the new columns are created from text: this file is one batch, and a column added above does not exist
-- yet when the batch is compiled
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRecord_Built' AND object_id = OBJECT_ID('sidata.CiRecord'))
    EXEC (N'CREATE INDEX IX_CiRecord_Built ON sidata.CiRecord (BuiltGroupKey) WHERE BuiltGroupKey IS NOT NULL');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRecord_Ci' AND object_id = OBJECT_ID('sidata.CiRecord'))
    EXEC (N'CREATE INDEX IX_CiRecord_Ci ON sidata.CiRecord (CiId) WHERE CiId IS NOT NULL');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiGroupMember_Dirty' AND object_id = OBJECT_ID('sidata.CiGroupMember'))
    EXEC (N'CREATE INDEX IX_CiGroupMember_Dirty ON sidata.CiGroupMember (Dirty, BatchNo) INCLUDE (GroupKey)');
-- IDENTITIES BEFORE DEVICES (ADDED 2026-10-10, owner): identity CIs are built and written first in a run, and a device /
-- resource CI links to its owner's and users' identity CIs (si_owner_ci_id, si_user_ci_ids). CiIdentityRef keeps, per record
-- of a built device / resource CI, the owner / user values it named (UPN, object id, SID; lower case): an identity group
-- that becomes dirty makes the device groups that name it dirty too.
IF OBJECT_ID('sidata.CiIdentityRef') IS NULL
CREATE TABLE sidata.CiIdentityRef (
    RecordKey   NVARCHAR(450)  NOT NULL,
    RefValue    NVARCHAR(400)  NOT NULL,
    CONSTRAINT PK_CiIdentityRef PRIMARY KEY (RecordKey, RefValue)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiIdentityRef_Value' AND object_id = OBJECT_ID('sidata.CiIdentityRef'))
CREATE INDEX IX_CiIdentityRef_Value ON sidata.CiIdentityRef (RefValue) INCLUDE (RecordKey);
-- THE INCREMENTAL CI BUILD, ROOT FIXES (ADDED 2026-10-10, #534 follow-up -- owner):
--   CiRecord.NextDueAt   the earliest moment after its group's last build at which one of the build's day thresholds flips
--                        for the record -- the time part of the dirty check is NextDueAt <= now (no scan of every record's
--                        JSON each run)
--   CiCmdbRef            per record of a built CI, the owning CMDB's lookup keys it used (svc|<CMDB id>, arm|<Azure id>,
--                        entra|<object id>, fqdn|<FQDN>)
--   CiCmdbKey            every lookup key of the owning CMDB's index and the hash of the item behind it, as the last build
--                        saw it: a key whose item is new, changed or gone dirties only the groups that used it -- the CMDB's
--                        items are no longer in the build fingerprint (its OWNER and the criticality mapping still are)
IF COL_LENGTH('sidata.CiRecord', 'NextDueAt') IS NULL
    ALTER TABLE sidata.CiRecord ADD NextDueAt DATETIME2(3) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRecord_NextDue' AND object_id = OBJECT_ID('sidata.CiRecord'))
    EXEC (N'CREATE INDEX IX_CiRecord_NextDue ON sidata.CiRecord (NextDueAt) WHERE NextDueAt IS NOT NULL');
IF OBJECT_ID('sidata.CiCmdbRef') IS NULL
CREATE TABLE sidata.CiCmdbRef (
    RecordKey   NVARCHAR(450)  NOT NULL,
    RefKey      NVARCHAR(450)  NOT NULL,
    CONSTRAINT PK_CiCmdbRef PRIMARY KEY (RecordKey, RefKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiCmdbRef_Key' AND object_id = OBJECT_ID('sidata.CiCmdbRef'))
CREATE INDEX IX_CiCmdbRef_Key ON sidata.CiCmdbRef (RefKey) INCLUDE (RecordKey);
-- CiCmdbUse (ADDED 2026-10-11) replaces CiCmdbRef, whose clustered key stops at 900 bytes: a long record key with a long
-- lookup key failed the build (SQL error 1946). Same rows, a NONCLUSTERED key (1,700 bytes) and lookup keys of at most 400
-- characters; CiCmdbRef stays (additive) and is no longer written. Its rows are carried over once.
IF OBJECT_ID('sidata.CiCmdbUse') IS NULL
CREATE TABLE sidata.CiCmdbUse (
    RecordKey   NVARCHAR(450)  NOT NULL,
    RefKey      NVARCHAR(400)  NOT NULL,
    CONSTRAINT PK_CiCmdbUse PRIMARY KEY NONCLUSTERED (RecordKey, RefKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiCmdbUse_Key' AND object_id = OBJECT_ID('sidata.CiCmdbUse'))
CREATE INDEX IX_CiCmdbUse_Key ON sidata.CiCmdbUse (RefKey) INCLUDE (RecordKey);
IF COL_LENGTH('sidata.CiCmdbRef', 'RefKey') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiCmdbUse)
    INSERT sidata.CiCmdbUse (RecordKey, RefKey) SELECT RecordKey, RefKey FROM sidata.CiCmdbRef WHERE LEN(RefKey) <= 400;
IF OBJECT_ID('sidata.CiCmdbKey') IS NULL
CREATE TABLE sidata.CiCmdbKey (
    RefKey      NVARCHAR(450)  NOT NULL CONSTRAINT PK_CiCmdbKey PRIMARY KEY,
    Hash        VARCHAR(64)    NULL
);
-- #639 (ADDED 2026-10-21) THE CI BUILD AND THE CORRELATION MAP AT MILLIONS OF ASSETS: scratch tables the jobs fill in chunks
-- and read back a page or a batch at a time, instead of holding a tenant-sized set in the job's memory. Additive; a database
-- without them keeps the whole-set path of before (said in the run log).
--   CiBuildStage    the CI build's keys: Kind 'ck' = the owning CMDB's and the business services' lookup keys with the hash
--                   of what is behind each (V = the CMDB item's fields a CI reads), 'seen' = the CIs of the clean groups,
--                   'idk' = the identity CIs by the values a device names. Emptied by the build that fills it.
--   CorrInput       the correlation map's input: one row per profile row of the snapshot (its engine, its SI_AssetId and
--                   its joinable identifiers as JSON), the component it belongs to (Lbl) and its batch
--   CorrInputKey    the joinable identifiers of each input row ('type|value', lower case; 'force|<n>' for a force-merge
--                   decision), compared exactly (binary collation) -- the grouping's edges
IF OBJECT_ID('sidata.CiBuildStage') IS NULL
CREATE TABLE sidata.CiBuildStage (
    Kind        NVARCHAR(16)   NOT NULL,
    K           NVARCHAR(450)  NOT NULL,
    H           VARCHAR(64)    NULL,
    V           NVARCHAR(MAX)  NULL,
    CONSTRAINT PK_CiBuildStage PRIMARY KEY (Kind, K)
);
IF OBJECT_ID('sidata.CorrInput') IS NULL
CREATE TABLE sidata.CorrInput (
    RowNo       INT            NOT NULL CONSTRAINT PK_CorrInput PRIMARY KEY,
    Engine      NVARCHAR(32)   NOT NULL,
    Lbl         INT            NOT NULL,
    BatchNo     INT            NULL,
    Doc         NVARCHAR(MAX)  NOT NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CorrInput_Batch' AND object_id = OBJECT_ID('sidata.CorrInput'))
CREATE INDEX IX_CorrInput_Batch ON sidata.CorrInput (BatchNo, RowNo);
IF OBJECT_ID('sidata.CorrInputKey') IS NULL
CREATE TABLE sidata.CorrInputKey (
    K           NVARCHAR(450)  COLLATE Latin1_General_BIN2 NOT NULL,
    RowNo       INT            NOT NULL,
    CONSTRAINT PK_CorrInputKey PRIMARY KEY (K, RowNo)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CorrInputKey_Row' AND object_id = OBJECT_ID('sidata.CorrInputKey'))
CREATE INDEX IX_CorrInputKey_Row ON sidata.CorrInputKey (RowNo) INCLUDE (K);

-- ---------------------------------------------------------------------------------------------
-- MANUAL CI OVERRIDES (ADDED 2026-10-10, #462 -- V3-DATA-MODEL 2.8 precedence 1): an Admin sets a CI field (tier, purpose,
-- category, department, a CMDB field) with a REASON and an optional EXPIRY; the CI build applies every override in force
-- over the rules (si_tier_set_by = override) and lists it on the CI (si_overrides). Removed = soft delete (who removed it
-- and when are kept). Additive: a database without the table has no overrides.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.CiOverride') IS NULL
CREATE TABLE sidata.CiOverride (
    OverrideId  BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CiOverride PRIMARY KEY,
    CiId        NVARCHAR(64)   NOT NULL,
    Field       NVARCHAR(64)   NOT NULL,
    Value       NVARCHAR(400)  NULL,
    Reason      NVARCHAR(1000) NOT NULL,
    SetBy       NVARCHAR(256)  NOT NULL,
    SetAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_CiOverride_SetAt DEFAULT SYSUTCDATETIME(),
    ExpiresAt   DATETIME2(0)   NULL,
    Removed     BIT            NOT NULL CONSTRAINT DF_CiOverride_Removed DEFAULT 0,
    RemovedBy   NVARCHAR(256)  NULL,
    RemovedAt   DATETIME2(0)   NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiOverride_Ci' AND object_id = OBJECT_ID('sidata.CiOverride'))
CREATE INDEX IX_CiOverride_Ci ON sidata.CiOverride (CiId, Field) INCLUDE (Value, ExpiresAt, Removed);

-- ---------------------------------------------------------------------------------------------
-- HISTORY PER CI (ADDED 2026-10-10, #464 -- V3-DATA-MODEL 2.8.3). sidata.CiChange: one row per change of a TRACKED field
-- of a CI (tier, tier set-by, lifecycle, internet exposure, the asset risk factors, the CMDB owner's values), a link added or
-- removed, a CI created -- with the old value, the new value, the source (provider / rule / override), the reason, the run
-- and the time. Written by the CI build in the same statement as the CI (only for CIs whose content changed). Both editions
-- (SQL in every install, #477). Retention: SI_Pro_CiChangeRetentionDays (default 730 = 2 years, Q7).
-- sidata.CiDaily gains the open findings by severity and the risk-factor count (the data sync fills them).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.CiChange') IS NULL
CREATE TABLE sidata.CiChange (
    ChangeId    BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CiChange PRIMARY KEY NONCLUSTERED,
    CiId        NVARCHAR(64)   NOT NULL,
    Field       NVARCHAR(64)   NOT NULL,
    OldValue    NVARCHAR(1000) NULL,
    NewValue    NVARCHAR(1000) NULL,
    Source      NVARCHAR(64)   NULL,
    Reason      NVARCHAR(512)  NULL,
    RunId       NVARCHAR(64)   NULL,
    ChangedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_CiChange_ChangedAt DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_CiChange' AND object_id = OBJECT_ID('sidata.CiChange'))
CREATE CLUSTERED INDEX CX_CiChange ON sidata.CiChange (CiId, ChangedAt);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiChange_When' AND object_id = OBJECT_ID('sidata.CiChange'))
CREATE INDEX IX_CiChange_When ON sidata.CiChange (ChangedAt) INCLUDE (Field);
IF COL_LENGTH('sidata.CiDaily', 'FactorCount') IS NULL ALTER TABLE sidata.CiDaily ADD FactorCount INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'OpenCritical') IS NULL ALTER TABLE sidata.CiDaily ADD OpenCritical INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'OpenHigh') IS NULL ALTER TABLE sidata.CiDaily ADD OpenHigh INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'OpenMedium') IS NULL ALTER TABLE sidata.CiDaily ADD OpenMedium INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'OpenLow') IS NULL ALTER TABLE sidata.CiDaily ADD OpenLow INT NULL;

-- ---------------------------------------------------------------------------------------------
-- FINDING LIFECYCLE IN THE CORE (ADDED 2026-10-10, #464 -- V3-DATA-MODEL 2.8.2). One row per (owner, finding key): the CI
-- (or 'asset:<id>' for a finding no CI holds) and the de-duplicated finding Risk Analysis published (SI_Finding_CL). First
-- detected, last seen, state open | reopened | closed, close reason remediated | asset_retired | no_longer_monitored |
-- report changed (#690 (34): a report that found it changed its query or was removed -- never a fix). A close
-- needs absence in SI_VulnSync_CloseAfterRuns (default 2) COMPLETE Risk Analysis runs (the vulnerability loop's rule); an
-- incomplete run changes nothing. Before this the lifecycle lived only in the connector table vuln.VulnerabilityItem.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.CiFindingState') IS NULL
CREATE TABLE sidata.CiFindingState (
    OwnerKey      NVARCHAR(450)  NOT NULL,
    FindingKey    NVARCHAR(256)  NOT NULL,
    CiId          NVARCHAR(64)   NULL,
    State         NVARCHAR(16)   NOT NULL,
    FirstDetected DATETIME2(3)   NOT NULL,
    LastSeen      DATETIME2(3)   NOT NULL,
    LastSnapshot  DATETIME2(3)   NOT NULL,
    AbsentRuns    INT            NOT NULL CONSTRAINT DF_CiFindingState_Absent DEFAULT 0,
    ClosedAt      DATETIME2(3)   NULL,
    CloseReason   NVARCHAR(32)   NULL,
    ReopenedAt    DATETIME2(3)   NULL,
    ReopenCount   INT            NOT NULL CONSTRAINT DF_CiFindingState_Reopen DEFAULT 0,
    Severity      NVARCHAR(16)   NULL,
    DetectedBy    NVARCHAR(2000) NULL,
    ExemptionId   NVARCHAR(64)   NULL,
    CONSTRAINT PK_CiFindingState PRIMARY KEY (OwnerKey, FindingKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFindingState_Ci' AND object_id = OBJECT_ID('sidata.CiFindingState'))
CREATE INDEX IX_CiFindingState_Ci ON sidata.CiFindingState (CiId, State) INCLUDE (FindingKey, FirstDetected, LastSeen, Severity);

-- ---------------------------------------------------------------------------------------------
-- THE CI GRAPH (ADDED 2026-10-10, #493 relations between CIs, #496 service ownership -- V3-DATA-MODEL 2.8.4 / 2.8.5).
--   CiService        one row per (CI, business service) -- written by the CI build from the CI's services (si_services:
--                    a link on the CMDB page, a service model binding rule, the CI's own CMDB record), with the service's
--                    owner, criticality, data sensitivity, environment and department; Strictest = the membership whose
--                    criticality the CI inherits. A CI in no service has no row (sidata.vCiUnowned lists it).
--   CiRelationClaim  what each CI's build claims (data-model relations: owner, logged-on users, public IP, subscription,
--                    resource group, groups, roles ...): replaced whenever the CI is rebuilt
--   CiRelation       the resolved relations, from -> to, one row per (from, kind, target): the target CI when a CI carries
--                    the identifier, else the identifier itself (ToType / ToValue); first seen, last seen, active | gone
--                    (a relation no claim holds any more is gone, never deleted; ChangedAt = when it was added, ended or
--                    pointed at another CI -- what SI_CIRelation_CL receives)
-- Both editions (SQL in every install, #477). Retention: gone relations are kept (they are the relation history).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.CiService') IS NULL
CREATE TABLE sidata.CiService (
    CiId             NVARCHAR(64)   NOT NULL,
    ServiceKey       NVARCHAR(256)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Source           NVARCHAR(32)   NULL,     -- cmdb_link | service_model | cmdb
    MatchedBy        NVARCHAR(400)  NULL,
    Criticality      NVARCHAR(64)   NULL,
    DataSensitivity  NVARCHAR(64)   NULL,
    Environment      NVARCHAR(64)   NULL,
    Owner            NVARCHAR(256)  NULL,
    Department       NVARCHAR(128)  NULL,
    Strictest        BIT            NOT NULL CONSTRAINT DF_CiService_Strictest DEFAULT 0,
    FirstSeen        DATETIME2(3)   NOT NULL,
    UpdatedAt        DATETIME2(3)   NOT NULL,
    CONSTRAINT PK_CiService PRIMARY KEY CLUSTERED (CiId, ServiceKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiService_Service' AND object_id = OBJECT_ID('sidata.CiService'))
CREATE INDEX IX_CiService_Service ON sidata.CiService (ServiceKey) INCLUDE (CiId, ServiceName, Source, Strictest);

IF OBJECT_ID('sidata.CiRelationClaim') IS NULL
CREATE TABLE sidata.CiRelationClaim (
    OwnerCiId   NVARCHAR(64)   NOT NULL,
    RelationId  NVARCHAR(48)   NOT NULL,
    Kind        NVARCHAR(48)   NOT NULL,
    FromCiId    NVARCHAR(64)   NOT NULL,
    ToType      NVARCHAR(48)   NOT NULL,
    ToValue     NVARCHAR(400)  NOT NULL,
    Detail      NVARCHAR(400)  NULL,
    Source      NVARCHAR(32)   NULL,
    Confidence  NVARCHAR(16)   NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_CiRelationClaim' AND object_id = OBJECT_ID('sidata.CiRelationClaim'))
CREATE CLUSTERED INDEX CX_CiRelationClaim ON sidata.CiRelationClaim (OwnerCiId);

IF OBJECT_ID('sidata.CiRelation') IS NULL
CREATE TABLE sidata.CiRelation (
    RelKey      VARBINARY(32)  NOT NULL CONSTRAINT PK_CiRelation PRIMARY KEY CLUSTERED,   -- SHA-256 of from | kind | to type | to value
    FromCiId    NVARCHAR(64)   NOT NULL,
    Kind        NVARCHAR(48)   NOT NULL,
    ToType      NVARCHAR(48)   NOT NULL,
    ToValue     NVARCHAR(400)  NOT NULL,
    ToCiId      NVARCHAR(64)   NULL,
    Detail      NVARCHAR(400)  NULL,
    Source      NVARCHAR(32)   NULL,
    Confidence  NVARCHAR(16)   NULL,
    State       NVARCHAR(8)    NOT NULL,      -- active | gone
    FirstSeen   DATETIME2(3)   NOT NULL,
    LastSeen    DATETIME2(3)   NOT NULL,
    GoneAt      DATETIME2(3)   NULL,
    ChangedAt   DATETIME2(3)   NOT NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRelation_From' AND object_id = OBJECT_ID('sidata.CiRelation'))
CREATE INDEX IX_CiRelation_From ON sidata.CiRelation (FromCiId, State) INCLUDE (Kind, ToType, ToValue, ToCiId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRelation_To' AND object_id = OBJECT_ID('sidata.CiRelation'))
CREATE INDEX IX_CiRelation_To ON sidata.CiRelation (ToCiId, State) INCLUDE (Kind, FromCiId) WHERE ToCiId IS NOT NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRelation_Changed' AND object_id = OBJECT_ID('sidata.CiRelation'))
CREATE INDEX IX_CiRelation_Changed ON sidata.CiRelation (ChangedAt);

-- ---------------------------------------------------------------------------------------------
-- FINDINGS PER CI -- ONE MODEL (ADDED 2026-10-10, #494): sidata.CiFindingState becomes the one lifecycle row of a finding on
-- its CI, joined with what the other parts know of it: the finding's type and title, its OWNER (the owner of the CI's most
-- critical business service, else the CI's CMDB owner, else the CI's own owner -- OwnerSource says which), the business
-- services it inherits (ServiceKeys), its SLA (SlaDays by severity, SI_Pro_FindingSla_<severity>Days) and due date (DueAt,
-- counted from the first detection or the last reopen), its exemption (reason, expiry -- cfg.Exemption), the ticket of the
-- vulnerability close-loop (vuln.VulnerabilityItem: state, closed at, close reason) and whether the finding is EXCLUDED
-- because its asset is disabled and left out by a setting (#533: kept as it was, never resolved or closed). The data sync
-- fills them after the lifecycle step. The read model: sidata.vCiFindingModel (status open | reopened | exempted | fixed |
-- closed, overdue) and sidata.vServiceFinding (per service).
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.CiFindingState', 'FindingType') IS NULL ALTER TABLE sidata.CiFindingState ADD FindingType NVARCHAR(32) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'Title') IS NULL ALTER TABLE sidata.CiFindingState ADD Title NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'Owner') IS NULL ALTER TABLE sidata.CiFindingState ADD Owner NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'OwnerSource') IS NULL ALTER TABLE sidata.CiFindingState ADD OwnerSource NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'ServiceKeys') IS NULL ALTER TABLE sidata.CiFindingState ADD ServiceKeys NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'ServiceCriticality') IS NULL ALTER TABLE sidata.CiFindingState ADD ServiceCriticality NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'SlaDays') IS NULL ALTER TABLE sidata.CiFindingState ADD SlaDays INT NULL;
IF COL_LENGTH('sidata.CiFindingState', 'DueAt') IS NULL ALTER TABLE sidata.CiFindingState ADD DueAt DATETIME2(3) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'ExemptionReason') IS NULL ALTER TABLE sidata.CiFindingState ADD ExemptionReason NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'ExemptedUntil') IS NULL ALTER TABLE sidata.CiFindingState ADD ExemptedUntil DATETIME2(0) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'TicketState') IS NULL ALTER TABLE sidata.CiFindingState ADD TicketState NVARCHAR(20) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'TicketClosedAt') IS NULL ALTER TABLE sidata.CiFindingState ADD TicketClosedAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'TicketCloseReason') IS NULL ALTER TABLE sidata.CiFindingState ADD TicketCloseReason NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.CiFindingState', 'Excluded') IS NULL ALTER TABLE sidata.CiFindingState ADD Excluded BIT NOT NULL CONSTRAINT DF_CiFindingState_Excluded DEFAULT 0;
IF COL_LENGTH('sidata.CiFindingState', 'ModelAt') IS NULL ALTER TABLE sidata.CiFindingState ADD ModelAt DATETIME2(3) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFindingState_Due' AND object_id = OBJECT_ID('sidata.CiFindingState'))
    EXEC (N'CREATE INDEX IX_CiFindingState_Due ON sidata.CiFindingState (State, DueAt) INCLUDE (CiId, Severity, Owner)');

-- ---------------------------------------------------------------------------------------------
-- HISTORY PER CI, the daily row extended (ADDED 2026-10-10, #495): the CI's lifecycle, internet exposure, how many services
-- own it and the criticality it inherits, its active relations, and its findings that are overdue / exempted -- the trend
-- reports read one row per CI per day. The data sync fills them.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.CiDaily', 'Lifecycle') IS NULL ALTER TABLE sidata.CiDaily ADD Lifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.CiDaily', 'InternetExposed') IS NULL ALTER TABLE sidata.CiDaily ADD InternetExposed BIT NULL;
IF COL_LENGTH('sidata.CiDaily', 'ServiceCount') IS NULL ALTER TABLE sidata.CiDaily ADD ServiceCount INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'ServiceCriticality') IS NULL ALTER TABLE sidata.CiDaily ADD ServiceCriticality NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.CiDaily', 'RelationCount') IS NULL ALTER TABLE sidata.CiDaily ADD RelationCount INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'OverdueFindings') IS NULL ALTER TABLE sidata.CiDaily ADD OverdueFindings INT NULL;
IF COL_LENGTH('sidata.CiDaily', 'ExemptedFindings') IS NULL ALTER TABLE sidata.CiDaily ADD ExemptedFindings INT NULL;

-- ---------------------------------------------------------------------------------------------
-- THE GRAPH'S READ VIEWS (#493 / #494 / #496). Created once (a change ships as a new view name).
--   vCiRelation       every relation of a CI, BOTH WAYS: Direction 'out' (the CI is the from side) or 'in' (another CI
--                     points at it) -- what attack-path questions read
--   vCiUnowned        the CIs no business service owns (not retired)
--   vCiFindingModel   one row per finding on its CI: the lifecycle, its status (open | reopened | exempted | fixed |
--                     closed), owner, services, SLA, due date, overdue, exemption, ticket, excluded
--   vServiceCi        service -> its CIs, with each CI's open, overdue and critical / high findings and its risk
--   vServiceFinding   service -> its CIs' findings (the finding model per service)
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.vCiRelation') IS NULL
EXEC ('CREATE VIEW sidata.vCiRelation AS
SELECT r.FromCiId AS CiId, N''out'' AS Direction, r.Kind, r.ToCiId AS OtherCiId, r.ToType, r.ToValue, r.Detail, r.Source, r.Confidence, r.State,
       r.FirstSeen, r.LastSeen, r.GoneAt, r.FromCiId, r.ToCiId
FROM sidata.CiRelation AS r
UNION ALL
SELECT r.ToCiId AS CiId, N''in'' AS Direction, r.Kind, r.FromCiId AS OtherCiId, N''ci'' AS ToType, r.FromCiId AS ToValue, r.Detail, r.Source, r.Confidence, r.State,
       r.FirstSeen, r.LastSeen, r.GoneAt, r.FromCiId, r.ToCiId
FROM sidata.CiRelation AS r
WHERE r.ToCiId IS NOT NULL');

IF OBJECT_ID('sidata.vCiUnowned') IS NULL
EXEC ('CREATE VIEW sidata.vCiUnowned AS
SELECT c.CiId, c.Name, c.Class, c.AssetType, c.Tier, c.Lifecycle, c.WeightedRiskScore, c.OpenFindings, c.LastSeen
FROM sidata.Ci AS c
WHERE ISNULL(c.Lifecycle, N'''') <> N''retired''
  AND NOT EXISTS (SELECT 1 FROM sidata.CiService AS s WHERE s.CiId = c.CiId)');

IF OBJECT_ID('sidata.vCiFindingModel') IS NULL
EXEC ('CREATE VIEW sidata.vCiFindingModel AS
SELECT s.OwnerKey, s.FindingKey, s.CiId, c.Name AS CiName, c.Class, c.Tier, s.FindingType, s.Title, s.Severity, s.State,
       CASE WHEN s.ExemptionId IS NOT NULL AND (s.ExemptedUntil IS NULL OR s.ExemptedUntil > SYSUTCDATETIME()) AND s.State <> N''closed'' THEN N''exempted''
            WHEN s.State = N''closed'' AND s.CloseReason = N''remediated'' THEN N''fixed''
            ELSE s.State END AS Status,
       s.FirstDetected, s.LastSeen, s.ClosedAt, s.CloseReason, s.ReopenedAt, s.ReopenCount, s.DetectedBy,
       s.Owner, s.OwnerSource, s.ServiceKeys, s.ServiceCriticality, s.SlaDays, s.DueAt,
       CASE WHEN s.DueAt IS NOT NULL AND s.DueAt < SYSUTCDATETIME() AND s.State <> N''closed'' AND s.Excluded = 0
                 AND NOT (s.ExemptionId IS NOT NULL AND (s.ExemptedUntil IS NULL OR s.ExemptedUntil > SYSUTCDATETIME())) THEN 1 ELSE 0 END AS Overdue,
       s.ExemptionId, s.ExemptionReason, s.ExemptedUntil, s.TicketState, s.TicketClosedAt, s.TicketCloseReason, s.Excluded
FROM sidata.CiFindingState AS s
LEFT JOIN sidata.Ci AS c ON c.CiId = s.CiId');

IF OBJECT_ID('sidata.vServiceCi') IS NULL
EXEC ('CREATE VIEW sidata.vServiceCi AS
SELECT sv.ServiceKey, sv.ServiceName, sv.Source, sv.MatchedBy, sv.Strictest, sv.Criticality, sv.Owner, c.CiId, c.Name, c.Class, c.AssetType, c.Tier, c.Lifecycle,
       c.RiskScore, c.WeightedRiskScore,
       ISNULL(f.OpenFindings, 0) AS OpenFindings, ISNULL(f.Overdue, 0) AS OverdueFindings, ISNULL(f.Critical, 0) AS OpenCritical, ISNULL(f.High, 0) AS OpenHigh
FROM sidata.CiService AS sv
JOIN sidata.Ci AS c ON c.CiId = sv.CiId
OUTER APPLY (SELECT COUNT(*) AS OpenFindings,
                    SUM(CASE WHEN m.Overdue = 1 THEN 1 ELSE 0 END) AS Overdue,
                    SUM(CASE WHEN LOWER(m.Severity) IN (N''critical'', N''very high'') THEN 1 ELSE 0 END) AS Critical,
                    SUM(CASE WHEN LOWER(m.Severity) = N''high'' THEN 1 ELSE 0 END) AS High
             FROM sidata.vCiFindingModel AS m
             WHERE m.CiId = sv.CiId AND m.Status IN (N''open'', N''reopened'') AND m.Excluded = 0) AS f');

IF OBJECT_ID('sidata.vServiceFinding') IS NULL
EXEC ('CREATE VIEW sidata.vServiceFinding AS
SELECT sv.ServiceKey, sv.ServiceName, m.*
FROM sidata.CiService AS sv
JOIN sidata.vCiFindingModel AS m ON m.CiId = sv.CiId');

-- ---------------------------------------------------------------------------------------------
-- DATA-QUALITY WARNINGS FROM A THREE-RUN FINGERPRINT (ADDED 2026-10-11, #577 step 2 -- owner: "it can base it on last 3 runs
-- and compare key numbers", "more of a warning, not a blocker"). Written once per pipeline run by the data sync's last step
-- (engine/pro-data/_shared/SI-DataQuality.ps1); read by the web app's Data quality panel (Operations > Data quality).
--   DataQualityRun      one row per fingerprinted run: the Risk Analysis Detailed collection it measured, how many key numbers,
--                       how many anomalies, learning (fewer than 3 earlier runs), the largest delta vs the expected range, and
--                       the ONE daily mail (when, to whom, sent | failed)
--   DataQualityMetric   the run's key numbers: assets per source, rows per Risk Analysis report, fill % of the key columns,
--                       active CIs per tier, active CIs, CIs not seen any more, the CI owner and asset type fill %
--   DataQualityAnomaly  each key number off the MEDIAN OF THE LAST 3 RUNS: the 3 earlier values (Earlier1 = the newest), the
--                       expected value, now, the change, the rule, the likely cause (cfg.ChangeLog) and the step to re-run from
-- Never blocks anything, never a guard event. Additive: a database without the tables measures nothing (said once per run).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.DataQualityRun') IS NULL
CREATE TABLE sidata.DataQualityRun (
    RunId            NVARCHAR(64)   NOT NULL CONSTRAINT PK_DataQualityRun PRIMARY KEY,
    CollectionTime   DATETIME2(3)   NULL,
    ComputedAt       DATETIME2(3)   NOT NULL CONSTRAINT DF_DataQualityRun_ComputedAt DEFAULT SYSUTCDATETIME(),
    Metrics          INT            NOT NULL CONSTRAINT DF_DataQualityRun_Metrics DEFAULT 0,
    Anomalies        INT            NOT NULL CONSTRAINT DF_DataQualityRun_Anomalies DEFAULT 0,
    Learning         BIT            NOT NULL CONSTRAINT DF_DataQualityRun_Learning DEFAULT 0,
    EarlierRuns      INT            NULL,
    LargestDeltaPct  FLOAT          NULL,
    MailedAt         DATETIME2(0)   NULL,
    MailTo           NVARCHAR(1000) NULL,
    MailState        NVARCHAR(16)   NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DataQualityRun_Computed' AND object_id = OBJECT_ID('sidata.DataQualityRun'))
CREATE INDEX IX_DataQualityRun_Computed ON sidata.DataQualityRun (ComputedAt) INCLUDE (CollectionTime, Anomalies, Learning, MailedAt, MailState);

IF OBJECT_ID('sidata.DataQualityMetric') IS NULL
CREATE TABLE sidata.DataQualityMetric (
    RunId       NVARCHAR(64)   NOT NULL,
    MetricKey   NVARCHAR(200)  NOT NULL,
    Kind        NVARCHAR(16)   NOT NULL,     -- assets | rows | fill | tier | retire
    Label       NVARCHAR(256)  NULL,
    Value       FLOAT          NOT NULL,     -- a count, or a fill in percent
    Step        NVARCHAR(64)   NULL,         -- the pipeline step that produces it (Re-run from here)
    CONSTRAINT PK_DataQualityMetric PRIMARY KEY (RunId, MetricKey)
);

IF OBJECT_ID('sidata.DataQualityAnomaly') IS NULL
CREATE TABLE sidata.DataQualityAnomaly (
    RunId       NVARCHAR(64)   NOT NULL,
    MetricKey   NVARCHAR(200)  NOT NULL,
    Kind        NVARCHAR(16)   NOT NULL,
    Label       NVARCHAR(256)  NULL,
    Direction   NVARCHAR(8)    NOT NULL,     -- drop | rise
    [Rule]      NVARCHAR(32)   NOT NULL,     -- asset-drop | report-zero | report-drop | fill-drop | tier-shift | retire-rise
    Earlier1    FLOAT          NULL,         -- the newest earlier run
    Earlier2    FLOAT          NULL,
    Earlier3    FLOAT          NULL,
    Expected    FLOAT          NULL,         -- the median of the three
    NowValue    FLOAT          NOT NULL,
    ChangePct   FLOAT          NULL,         -- % of expected; a fill: points; a tier / CIs to retire: % of all active CIs
    Cause       NVARCHAR(2000) NULL,         -- the likely cause, from cfg.ChangeLog
    Step        NVARCHAR(64)   NULL,
    CONSTRAINT PK_DataQualityAnomaly PRIMARY KEY (RunId, MetricKey)
);

-- THE LIKELY CAUSE AS ROWS (ADDED 2026-10-11, the Data quality view): the settings changes between the last run without a
-- warning and this one (copied from cfg.ChangeLog by the data sync, which reads the settings database), and which of them
-- concern which key number. The panel reads them by RunId and links each change to the audit trail. Additive: a database
-- without the two tables keeps the cause as the text on the anomaly (DataQualityAnomaly.Cause).
--   DataQualityChange   one row per settings change of the run's window: which setting, who, when
--   DataQualityCause    key number -> the changes that concern it (a number none concerns has no row: the panel then
--                       lists every change of the window)
IF OBJECT_ID('sidata.DataQualityChange') IS NULL
CREATE TABLE sidata.DataQualityChange (
    RunId       NVARCHAR(64)   NOT NULL,
    ChangeId    BIGINT         NOT NULL,     -- cfg.ChangeLog.ChangeId
    Name        NVARCHAR(128)  NOT NULL,
    Scope       NVARCHAR(64)   NULL,
    Kind        NVARCHAR(64)   NULL,
    Action      NVARCHAR(16)   NULL,
    ChangedAt   DATETIME2(0)   NOT NULL,
    ChangedBy   NVARCHAR(256)  NULL,
    CONSTRAINT PK_DataQualityChange PRIMARY KEY (RunId, ChangeId)
);

IF OBJECT_ID('sidata.DataQualityCause') IS NULL
CREATE TABLE sidata.DataQualityCause (
    RunId       NVARCHAR(64)   NOT NULL,
    MetricKey   NVARCHAR(200)  NOT NULL,
    ChangeId    BIGINT         NOT NULL,
    CONSTRAINT PK_DataQualityCause PRIMARY KEY (RunId, MetricKey, ChangeId)
);

-- ONE WARNING PER SOURCE (ADDED 2026-10-11 -- owner: "One warning per source"). The fields of ONE source that are filled
-- less in one run are ONE row in sidata.DataQualityAnomaly (MetricKey 'fill.src.<source>', [Rule] 'source-fill-drop', its
-- numbers = the average fill of those fields); the fields themselves are listed here, each with its 3 earlier values
-- (Earlier1 = the newest), its expected value, now and its change in points. A source with one dropped field stays one
-- ordinary anomaly row and has no row here. Additive: a database without the table keeps the warning without its list.
-- THE MAIL ONLY WHEN THE WARNINGS CHANGE (owner: "Only when it changes") needs no column: the warnings of a run are
-- compared with the anomaly rows of the last run whose MailState is 'sent'; DataQualityRun.MailState also says why a run
-- sent no mail (unchanged | day-limit | off | no-recipients: MailedAt stays NULL; failed: MailedAt = when it was tried).
IF OBJECT_ID('sidata.DataQualityAnomalyField') IS NULL
CREATE TABLE sidata.DataQualityAnomalyField (
    RunId       NVARCHAR(64)   NOT NULL,
    MetricKey   NVARCHAR(200)  NOT NULL,     -- the warning: fill.src.<source>
    FieldKey    NVARCHAR(200)  NOT NULL,     -- the key number of the field: fill.src.<source>.<field>
    Label       NVARCHAR(256)  NULL,
    Earlier1    FLOAT          NULL,         -- the newest earlier run
    Earlier2    FLOAT          NULL,
    Earlier3    FLOAT          NULL,
    Expected    FLOAT          NULL,         -- the median of the three
    NowValue    FLOAT          NOT NULL,
    ChangePct   FLOAT          NULL,         -- points
    CONSTRAINT PK_DataQualityAnomalyField PRIMARY KEY (RunId, MetricKey, FieldKey)
);

-- ---------------------------------------------------------------------------------------------
-- THE CI GRID'S FIELDS AS COLUMNS (ADDED 2026-10-11 -- owner: "why is the performance so bad", "takes 10 sec to open a
-- view"). The CIs page read every value it shows, filters or sorts that is not a column of sidata.Ci out of the CI
-- document (JSON_VALUE over DocJson, 85 MB for 8,799 CIs on internal): ~27 s of database time for one page, ~4 s more for
-- the filter choices. The fields of the default layout are now columns, filled by the data sync from DocJson
-- (SI-DataCi.ps1, Get-SIDataCiDocFieldsSql) whenever the CI's content hash moved; DocFieldsHash is the content hash
-- the columns were filled from (= ContentHash: the columns are current; anything else: the web app reads the document
-- for that row until the next data sync). Nullable, added in place; the indexes are created from text (the columns do
-- not exist yet when this one batch is compiled).
--   IX_Ci_Page   the CIs page's default order (weighted risk score, highest first) covering every grid column, so a page
--                never reads the wide row
--   IX_Ci_Type   the asset type / subtype filters and their value lists
IF COL_LENGTH('sidata.Ci', 'AssetSubtype') IS NULL
    ALTER TABLE sidata.Ci ADD AssetSubtype NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'OsName') IS NULL
    ALTER TABLE sidata.Ci ADD OsName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'OsPlatform') IS NULL
    ALTER TABLE sidata.Ci ADD OsPlatform NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'OsVersion') IS NULL
    ALTER TABLE sidata.Ci ADD OsVersion NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'OnboardingStatus') IS NULL
    ALTER TABLE sidata.Ci ADD OnboardingStatus NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Owner') IS NULL
    ALTER TABLE sidata.Ci ADD Owner NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Department') IS NULL
    ALTER TABLE sidata.Ci ADD Department NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Hostname') IS NULL
    ALTER TABLE sidata.Ci ADD Hostname NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'IpAddress') IS NULL
    ALTER TABLE sidata.Ci ADD IpAddress NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureResourceType') IS NULL
    ALTER TABLE sidata.Ci ADD AzureResourceType NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'IdentityType') IS NULL
    ALTER TABLE sidata.Ci ADD IdentityType NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Purpose') IS NULL
    ALTER TABLE sidata.Ci ADD Purpose NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AccountEnabled') IS NULL
    ALTER TABLE sidata.Ci ADD AccountEnabled BIT NULL;
IF COL_LENGTH('sidata.Ci', 'MfaRegistered') IS NULL
    ALTER TABLE sidata.Ci ADD MfaRegistered BIT NULL;
-- #579 the tier explanation (a sentence): kept out of IX_Ci_Page (long text, read for the shown rows only)
IF COL_LENGTH('sidata.Ci', 'TierExplanation') IS NULL
    ALTER TABLE sidata.Ci ADD TierExplanation NVARCHAR(4000) NULL;
IF COL_LENGTH('sidata.Ci', 'DocFieldsHash') IS NULL
    ALTER TABLE sidata.Ci ADD DocFieldsHash VARBINARY(32) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_Page' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_Page ON sidata.Ci (WeightedRiskScore DESC, CiId) INCLUDE (Name, Class, AssetType, AssetSubtype, Tier, TierSetBy, TierReason, Lifecycle, RiskScore, OpenFindings, RiskFactors, InternetExposed, CmdbId, CmdbName, CmdbCriticality, CriticalityFactor, LinkCount, LastSeen, CollectionTime, OsName, OsPlatform, OsVersion, OnboardingStatus, Owner, Department, Hostname, IpAddress, AzureResourceType, IdentityType, Purpose, AccountEnabled, MfaRegistered)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_Type' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_Type ON sidata.Ci (AssetType, AssetSubtype) INCLUDE (WeightedRiskScore)');

-- ---------------------------------------------------------------------------------------------
-- THE SUMMARY REPORT (#583, owner 2026-10-11: "where in the gui do i find the report ... where the findings are grouped with
-- the most important assets"): the rows of each complete Risk Analysis SUMMARY collection (SI_RiskAnalysis_Summary_CL) --
-- the same rows the RiskAnalysis_Summary workbook is built from -- copied by the data sync (engine/pro-data/_shared/
-- SI-DataSummary.ps1) for the web app's former Summary page (/Summary). Kept apart from sidata.Collection on purpose: a
-- Summary run has its own collection time, and every reader of sidata.Collection means the Detailed collections.
--   SummaryLoad    one row per loaded Summary collection; Status = 'Loading' until every row landed, then 'Complete'
--   SummaryRow     one row per Summary row (recommendation x tier x severity x risk factors x CMDB group), REAL columns --
--                  the page filters and orders on them (tier, rating rank, score) and never parses JSON per row
--   SummaryAsset   one row per impacted asset of a Summary row, in the row's order: the page lists the first ones inline
--                  and links each to its CI (AssetId = the CI id, or an id a CI carries)
-- Retention: the data sync removes Summary collections older than SI_Pro_DataRetentionDays (sidata.Summary* only).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.SummaryLoad') IS NULL
CREATE TABLE sidata.SummaryLoad (
    CollectionTime   DATETIME2(3)   NOT NULL CONSTRAINT PK_SummaryLoad PRIMARY KEY,
    RunId            NVARCHAR(64)   NULL,
    Status           NVARCHAR(16)   NOT NULL,
    [Rows]           INT            NULL,
    LoadedAt         DATETIME2(0)   NULL,
    SolutionVersion  NVARCHAR(64)   NULL
);

IF OBJECT_ID('sidata.SummaryRow') IS NULL
CREATE TABLE sidata.SummaryRow (
    CollectionTime                 DATETIME2(3)   NOT NULL,
    RowNo                          INT            NOT NULL,
    SecurityDomain                 NVARCHAR(128)  NULL,
    Category                       NVARCHAR(256)  NULL,
    Subcategory                    NVARCHAR(256)  NULL,
    ConfigurationName              NVARCHAR(1000) NULL,
    ConfigurationId                NVARCHAR(256)  NULL,
    Impact                         NVARCHAR(512)  NULL,
    SecuritySeverity               NVARCHAR(30)   NULL,
    CriticalityTier                TINYINT        NULL,
    CriticalityTierLevel           NVARCHAR(64)   NULL,
    RiskFactorConsequenceDetailed  NVARCHAR(1000) NULL,
    RiskFactorConsequence          FLOAT          NULL,
    RiskFactorProbabilityDetailed  NVARCHAR(1000) NULL,
    RiskFactorIds                  NVARCHAR(1000) NULL,
    RiskFactorProbability          FLOAT          NULL,
    RiskConsequenceScore           FLOAT          NULL,
    RiskProbabilityScore           FLOAT          NULL,
    RiskScoreTotal                 FLOAT          NULL,
    RiskScoreWeightFactor          FLOAT          NULL,
    RiskScoreWeightDetailed        NVARCHAR(1000) NULL,
    RiskScoreTotalWeighted         FLOAT          NULL,
    RiskRating                     NVARCHAR(16)   NULL,
    RatingRank                     TINYINT        NOT NULL,   -- Critical 1, High 2, Moderate 3, Low 4, else 5
    CmdbId                         NVARCHAR(256)  NULL,
    CmdbName                       NVARCHAR(400)  NULL,
    CmdbCriticality                NVARCHAR(64)   NULL,
    CmdbDataSensitivity            NVARCHAR(64)   NULL,
    ImpactedAssetCount             INT            NULL,
    ImpactedAssetsList             NVARCHAR(MAX)  NULL,       -- for the export, as the workbook shows it ("a, b")
    ImpactedAssetIds               NVARCHAR(MAX)  NULL,
    MoreDetails                    NVARCHAR(MAX)  NULL,
    ReportName                     NVARCHAR(256)  NULL,
    MitreTactics                   NVARCHAR(1000) NULL,
    MitreTechniques                NVARCHAR(2000) NULL,
    ComplianceTags                 NVARCHAR(2000) NULL,
    FixRemediation                 NVARCHAR(4000) NULL,       -- si_fix_remediation: how to fix (#590)
    FixRecommendedUpdate           NVARCHAR(2000) NULL,       -- si_fix_recommended_update, ';'-separated
    FixRecommendedUpdateId         NVARCHAR(2000) NULL,       -- si_fix_recommended_update_id, ';'-separated
    AffectedSoftware               NVARCHAR(MAX)  NULL,       -- si_affected_software, "Name Version (Vendor)" ';'-separated
    ConfigurationDescription       NVARCHAR(4000) NULL,
    RiskDescription                NVARCHAR(4000) NULL,
    CONSTRAINT PK_SummaryRow PRIMARY KEY CLUSTERED (CollectionTime, RowNo)
);

-- the page's default order: Tier 0 first, the most critical rating first, then the highest risk score
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryRow_Default' AND object_id = OBJECT_ID('sidata.SummaryRow'))
CREATE INDEX IX_SummaryRow_Default ON sidata.SummaryRow (CollectionTime, CriticalityTier, RatingRank, RiskScoreTotal DESC)
    INCLUDE (SecurityDomain, SecuritySeverity, RiskRating, ImpactedAssetCount);

IF OBJECT_ID('sidata.SummaryAsset') IS NULL
CREATE TABLE sidata.SummaryAsset (
    CollectionTime   DATETIME2(3)   NOT NULL,
    RowNo            INT            NOT NULL,
    Ordinal          INT            NOT NULL,
    AssetName        NVARCHAR(400)  NULL,
    AssetId          NVARCHAR(450)  NULL,
    CONSTRAINT PK_SummaryAsset PRIMARY KEY CLUSTERED (CollectionTime, RowNo, Ordinal)
);

-- an asset's Summary rows (the search on the page; "which recommendations hit this CI")
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryAsset_Asset' AND object_id = OBJECT_ID('sidata.SummaryAsset'))
CREATE INDEX IX_SummaryAsset_Asset ON sidata.SummaryAsset (CollectionTime, AssetId) INCLUDE (RowNo, AssetName);

-- ---------------------------------------------------------------------------------------------
-- EVERY FINDING CARRIES ITS FIX (#590): how to fix it, the security update Defender recommends (and its id) and the affected
-- software, as Risk Analysis writes them (si_fix_remediation, si_fix_recommended_update, si_fix_recommended_update_id,
-- si_affected_software). Added IN PLACE to an existing install, each guarded by COL_LENGTH. sidata.Finding's are filled by
-- the data sync from DetailJson when a collection's views' data is derived; sidata.SummaryRow's by the Summary load.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'FixRemediation') IS NULL
ALTER TABLE sidata.Finding ADD FixRemediation NVARCHAR(4000) NULL;

IF COL_LENGTH('sidata.Finding', 'FixRecommendedUpdate') IS NULL
ALTER TABLE sidata.Finding ADD FixRecommendedUpdate NVARCHAR(1000) NULL;

IF COL_LENGTH('sidata.Finding', 'FixRecommendedUpdateId') IS NULL
ALTER TABLE sidata.Finding ADD FixRecommendedUpdateId NVARCHAR(1000) NULL;

IF COL_LENGTH('sidata.Finding', 'AffectedSoftware') IS NULL
ALTER TABLE sidata.Finding ADD AffectedSoftware NVARCHAR(2000) NULL;

IF COL_LENGTH('sidata.SummaryRow', 'FixRemediation') IS NULL
ALTER TABLE sidata.SummaryRow ADD FixRemediation NVARCHAR(4000) NULL;

IF COL_LENGTH('sidata.SummaryRow', 'FixRecommendedUpdate') IS NULL
ALTER TABLE sidata.SummaryRow ADD FixRecommendedUpdate NVARCHAR(2000) NULL;

IF COL_LENGTH('sidata.SummaryRow', 'FixRecommendedUpdateId') IS NULL
ALTER TABLE sidata.SummaryRow ADD FixRecommendedUpdateId NVARCHAR(2000) NULL;

IF COL_LENGTH('sidata.SummaryRow', 'AffectedSoftware') IS NULL
ALTER TABLE sidata.SummaryRow ADD AffectedSoftware NVARCHAR(MAX) NULL;

IF COL_LENGTH('sidata.SummaryRow', 'ConfigurationDescription') IS NULL
ALTER TABLE sidata.SummaryRow ADD ConfigurationDescription NVARCHAR(4000) NULL;

IF COL_LENGTH('sidata.SummaryRow', 'RiskDescription') IS NULL
ALTER TABLE sidata.SummaryRow ADD RiskDescription NVARCHAR(4000) NULL;

-- ---------------------------------------------------------------------------------------------
-- WHAT A VIEW SHOWS BY DEFAULT IS PREPARED AND INDEXED (ADDED 2026-10-11 -- owner: "dont foget the caching in sql so
-- performance works flawless", "indexing", "again all views must be having the new requirement and performance fast").
-- A column of a view's default layout is a stored column the data sync fills; the JSON documents (sidata.Ci.DocJson,
-- sidata.Finding.DetailJson) are read only for a column a person adds on top, and then only for the rows of the page.
-- The list of these columns is ONE file: pro-management/src/SI.Management.Core/ProData/DataModel/view-stored-columns.json
-- (the web app and the data sync both read it; a test holds this file to it). Everything here is added IN PLACE, guarded,
-- nullable; the next data sync fills it (engine/pro-data/_shared/SI-DataViewContext.ps1).
--
-- (1) per-issue rows: a finding is matched by its CVE (IX_Finding_Cve) OR its configuration id -- the second half had no
--     index, so each key read the whole collection. Each half now seeks its own index.
-- ---------------------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Config' AND object_id = OBJECT_ID('sidata.Finding'))
CREATE INDEX IX_Finding_Config ON sidata.Finding (CollectionId, ConfigurationId) INCLUDE (AssetKey, AssetName, Cve, Severity, Tier, RiskScore);

-- (2) the finding context of ONE finding as columns (affected product / vendor / version, description, more details,
--     published, exploit words, category, subcategory, impact, CMDB group), next to the fix columns above. Filled per
--     collection from DetailJson, once, in measured ranges; Collection.ContextAt says when (NULL = not yet: the web app
--     reads that collection's context from the finding rows as before).
IF COL_LENGTH('sidata.Finding', 'AffectedProduct') IS NULL
    ALTER TABLE sidata.Finding ADD AffectedProduct NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'AffectedVendor') IS NULL
    ALTER TABLE sidata.Finding ADD AffectedVendor NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'AffectedVersion') IS NULL
    ALTER TABLE sidata.Finding ADD AffectedVersion NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'Description') IS NULL
    ALTER TABLE sidata.Finding ADD Description NVARCHAR(4000) NULL;
IF COL_LENGTH('sidata.Finding', 'MoreDetails') IS NULL
    ALTER TABLE sidata.Finding ADD MoreDetails NVARCHAR(4000) NULL;
IF COL_LENGTH('sidata.Finding', 'PublishedDate') IS NULL
    ALTER TABLE sidata.Finding ADD PublishedDate NVARCHAR(100) NULL;
IF COL_LENGTH('sidata.Finding', 'Exploit') IS NULL
    ALTER TABLE sidata.Finding ADD Exploit NVARCHAR(200) NULL;
IF COL_LENGTH('sidata.Finding', 'Category') IS NULL
    ALTER TABLE sidata.Finding ADD Category NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.Finding', 'Subcategory') IS NULL
    ALTER TABLE sidata.Finding ADD Subcategory NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.Finding', 'Impact') IS NULL
    ALTER TABLE sidata.Finding ADD Impact NVARCHAR(512) NULL;
IF COL_LENGTH('sidata.Finding', 'ContextCmdbId') IS NULL
    ALTER TABLE sidata.Finding ADD ContextCmdbId NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.Finding', 'ContextCmdbName') IS NULL
    ALTER TABLE sidata.Finding ADD ContextCmdbName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'ContextCmdbCriticality') IS NULL
    ALTER TABLE sidata.Finding ADD ContextCmdbCriticality NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.Collection', 'ContextAt') IS NULL
    ALTER TABLE sidata.Collection ADD ContextAt DATETIME2(0) NULL;

-- (3) IssueContext: PRE-COMPUTED per collection, one row per CVE / issue key (a CVE id or a configuration id): what the
--     one-row-per-CVE view, the exemptions, the top findings and the findings per finding key show about it -- the distinct
--     software list, vendor, versions, description, fix, remediation, more details, published, exploit words, category,
--     subcategory, impact, CMDB group, the first affected asset names and the exact number of affected assets. The page reads
--     its 50 rows by key (the primary key); it never reads the findings of a CVE. No foreign key: the retention removes a
--     collection's rows here itself.
IF OBJECT_ID('sidata.IssueContext') IS NULL
CREATE TABLE sidata.IssueContext (
    CollectionId     INT            NOT NULL,
    IssueKey         NVARCHAR(256)  NOT NULL,
    Findings         INT            NOT NULL,
    Assets           INT            NOT NULL,   -- distinct affected assets (exact)
    AssetNamesShown  INT            NOT NULL,   -- how many names AssetNames lists
    AssetNames       NVARCHAR(MAX)  NULL,       -- the first names, most risky first, ', '-separated
    Software         NVARCHAR(MAX)  NULL,       -- "product version (vendor)" items, '; '-separated, distinct
    Vendor           NVARCHAR(MAX)  NULL,
    Version          NVARCHAR(MAX)  NULL,
    Description      NVARCHAR(MAX)  NULL,
    Fix              NVARCHAR(MAX)  NULL,
    FixId            NVARCHAR(MAX)  NULL,
    Remediation      NVARCHAR(MAX)  NULL,
    MoreDetails      NVARCHAR(MAX)  NULL,
    Published        NVARCHAR(MAX)  NULL,
    Exploit          NVARCHAR(MAX)  NULL,
    Category         NVARCHAR(MAX)  NULL,
    Subcategory      NVARCHAR(MAX)  NULL,
    Impact           NVARCHAR(MAX)  NULL,
    CmdbId           NVARCHAR(MAX)  NULL,
    CmdbName         NVARCHAR(MAX)  NULL,
    CmdbCriticality  NVARCHAR(MAX)  NULL,
    CONSTRAINT PK_IssueContext PRIMARY KEY CLUSTERED (CollectionId, IssueKey)
);

-- (4) the CI context as columns of sidata.Ci, next to the CI grid's (above): who answers for the CI and where it lives --
--     every reference as id AND name -- its list fields, and its identifier VALUES and linked object ids ('; '-joined).
--     CtxHash = the content hash the columns were filled from and CtxSet = the list they were filled for: a CI whose pair is
--     not current is read from its document by the web app until the next data sync (so every moment is correct).
IF COL_LENGTH('sidata.Ci', 'OwnerObjectId') IS NULL
    ALTER TABLE sidata.Ci ADD OwnerObjectId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'OwnerUpn') IS NULL
    ALTER TABLE sidata.Ci ADD OwnerUpn NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureSubscriptionId') IS NULL
    ALTER TABLE sidata.Ci ADD AzureSubscriptionId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureSubscriptionName') IS NULL
    ALTER TABLE sidata.Ci ADD AzureSubscriptionName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureResourceGroup') IS NULL
    ALTER TABLE sidata.Ci ADD AzureResourceGroup NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureResourceGroupId') IS NULL
    ALTER TABLE sidata.Ci ADD AzureResourceGroupId NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagementGroupPath') IS NULL
    ALTER TABLE sidata.Ci ADD ManagementGroupPath NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagementGroupId') IS NULL
    ALTER TABLE sidata.Ci ADD ManagementGroupId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'TenantId') IS NULL
    ALTER TABLE sidata.Ci ADD TenantId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'TenantName') IS NULL
    ALTER TABLE sidata.Ci ADD TenantName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AppId') IS NULL
    ALTER TABLE sidata.Ci ADD AppId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AppName') IS NULL
    ALTER TABLE sidata.Ci ADD AppName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'SpObjectId') IS NULL
    ALTER TABLE sidata.Ci ADD SpObjectId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'DisplayName') IS NULL
    ALTER TABLE sidata.Ci ADD DisplayName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'GroupId') IS NULL
    ALTER TABLE sidata.Ci ADD GroupId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'GroupName') IS NULL
    ALTER TABLE sidata.Ci ADD GroupName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Components') IS NULL
    ALTER TABLE sidata.Ci ADD Components NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'LinkedObjects') IS NULL
    ALTER TABLE sidata.Ci ADD LinkedObjects NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'MdeDeviceId') IS NULL
    ALTER TABLE sidata.Ci ADD MdeDeviceId NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'AadDeviceId') IS NULL
    ALTER TABLE sidata.Ci ADD AadDeviceId NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureResourceId') IS NULL
    ALTER TABLE sidata.Ci ADD AzureResourceId NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'ExposureGraphNodeId') IS NULL
    ALTER TABLE sidata.Ci ADD ExposureGraphNodeId NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'LinkedObjectIds') IS NULL
    ALTER TABLE sidata.Ci ADD LinkedObjectIds NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'CtxHash') IS NULL
    ALTER TABLE sidata.Ci ADD CtxHash VARBINARY(32) NULL;
IF COL_LENGTH('sidata.Ci', 'CtxSet') IS NULL
    ALTER TABLE sidata.Ci ADD CtxSet NVARCHAR(16) NULL;
-- the indexed ones (a filter or a lookup on the value seeks); from text: the columns do not exist when this batch is compiled
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_OwnerObjectId' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_OwnerObjectId ON sidata.Ci (OwnerObjectId) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_AzureSubscriptionId' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_AzureSubscriptionId ON sidata.Ci (AzureSubscriptionId) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_AzureResourceGroup' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_AzureResourceGroup ON sidata.Ci (AzureResourceGroup) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_ManagementGroupId' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_ManagementGroupId ON sidata.Ci (ManagementGroupId) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_AppId' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_AppId ON sidata.Ci (AppId) INCLUDE (Name, Tier, WeightedRiskScore)');

-- (5) covering indexes the views' own statements had none of (each read the wide rows that carry the JSON document):
--   IX_CiFinding_Views  findings per CI / per finding key (the CI inventory tabs): every column they show, no DocJson
--   IX_CiRecord_Views   records per source: every column the grid shows, in its default order (name)
--   IX_Asset_Views      the asset a finding row joins for its kind(s), and the assets per department
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_Views' AND object_id = OBJECT_ID('sidata.CiFinding'))
CREATE INDEX IX_CiFinding_Views ON sidata.CiFinding (FindingKey, CiId) INCLUDE (AssetId, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, CollectionTime);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiRecord_Views' AND object_id = OBJECT_ID('sidata.CiRecord'))
CREATE INDEX IX_CiRecord_Views ON sidata.CiRecord (Name) INCLUDE (Provider, RecordType, Class, CiId, SourceLastSeen, CollectionTime, Complete);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Asset_Views' AND object_id = OBJECT_ID('sidata.Asset'))
    EXEC (N'CREATE INDEX IX_Asset_Views ON sidata.Asset (DepartmentId, AssetKey) INCLUDE (AssetName, AssetKind, AssetKinds, Tier, KeySource, FirstSeen, LastSeen)');

-- ---------------------------------------------------------------------------------------------
-- THE RICH CONTEXT IN EVERY VIEW, PREPARED AND INDEXED (ADDED 2026-10-11 -- owner: "rich context, single overview,
-- ability to prioritize", "better more than less", "again all views must be having the new requirement and performance
-- fast"). The context every source now delivers -- who answers for a CI (owner, manager, primary user, support and
-- assignment group, each as id AND name), where it lives (subscription, management group, tenant, environment), how it is
-- protected (MFA strength, Conditional Access, encryption, backup, pending updates, Defender plan), how it is used (sign-ins,
-- alerts, admin logons) -- is what the views open with, so it is stored as TYPED columns the data sync fills from the CI
-- document: a text, a number (INT / FLOAT), a yes / no (BIT) or a date (DATETIME2(3), UTC), so a filter or a sort compares
-- values and never text. The list is the same ONE file (view-stored-columns.json); a changed list refills every CI in the
-- next data sync (CtxSet). Added IN PLACE, guarded, nullable.
-- (1) the CI context of the three source lanes, as columns of sidata.Ci
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Ci', 'Environment') IS NULL
    ALTER TABLE sidata.Ci ADD Environment NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CostCenter') IS NULL
    ALTER TABLE sidata.Ci ADD CostCenter NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureTenantId') IS NULL
    ALTER TABLE sidata.Ci ADD AzureTenantId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureTenantName') IS NULL
    ALTER TABLE sidata.Ci ADD AzureTenantName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagementGroupName') IS NULL
    ALTER TABLE sidata.Ci ADD ManagementGroupName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagementGroupIdPath') IS NULL
    ALTER TABLE sidata.Ci ADD ManagementGroupIdPath NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'AzureLocation') IS NULL
    ALTER TABLE sidata.Ci ADD AzureLocation NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceOwner') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceOwner NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceOwnerId') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceOwnerId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceEnvironment') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceEnvironment NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceDepartment') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceDepartment NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceSupportGroup') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceSupportGroup NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceSupportGroupId') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceSupportGroupId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceAssignmentGroup') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceAssignmentGroup NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ServiceAssignmentGroupId') IS NULL
    ALTER TABLE sidata.Ci ADD ServiceAssignmentGroupId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbOwner') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbOwner NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbOwnerId') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbOwnerId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbEnvironment') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbEnvironment NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbSupportGroup') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbSupportGroup NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbSupportGroupId') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbSupportGroupId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbAssignmentGroup') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbAssignmentGroup NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CmdbAssignmentGroupId') IS NULL
    ALTER TABLE sidata.Ci ADD CmdbAssignmentGroupId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'NotLicensed') IS NULL
    ALTER TABLE sidata.Ci ADD NotLicensed NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'BackupProtected') IS NULL
    ALTER TABLE sidata.Ci ADD BackupProtected BIT NULL;
IF COL_LENGTH('sidata.Ci', 'BackupLastStatus') IS NULL
    ALTER TABLE sidata.Ci ADD BackupLastStatus NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'BackupLastTime') IS NULL
    ALTER TABLE sidata.Ci ADD BackupLastTime DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'BackupVaultId') IS NULL
    ALTER TABLE sidata.Ci ADD BackupVaultId NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'BackupVaultName') IS NULL
    ALTER TABLE sidata.Ci ADD BackupVaultName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'PendingCriticalPatches') IS NULL
    ALTER TABLE sidata.Ci ADD PendingCriticalPatches INT NULL;
IF COL_LENGTH('sidata.Ci', 'PendingSecurityPatches') IS NULL
    ALTER TABLE sidata.Ci ADD PendingSecurityPatches INT NULL;
IF COL_LENGTH('sidata.Ci', 'RebootPending') IS NULL
    ALTER TABLE sidata.Ci ADD RebootPending BIT NULL;
IF COL_LENGTH('sidata.Ci', 'DefenderPlan') IS NULL
    ALTER TABLE sidata.Ci ADD DefenderPlan NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'DefenderPlanTier') IS NULL
    ALTER TABLE sidata.Ci ADD DefenderPlanTier NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'PrivilegedAccessCount') IS NULL
    ALTER TABLE sidata.Ci ADD PrivilegedAccessCount INT NULL;
IF COL_LENGTH('sidata.Ci', 'PolicyNoncompliantCount') IS NULL
    ALTER TABLE sidata.Ci ADD PolicyNoncompliantCount INT NULL;
IF COL_LENGTH('sidata.Ci', 'LastChangeTime') IS NULL
    ALTER TABLE sidata.Ci ADD LastChangeTime DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'LastChangedByName') IS NULL
    ALTER TABLE sidata.Ci ADD LastChangedByName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'PowerState') IS NULL
    ALTER TABLE sidata.Ci ADD PowerState NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'DiagnosticSettingsEnabled') IS NULL
    ALTER TABLE sidata.Ci ADD DiagnosticSettingsEnabled BIT NULL;
IF COL_LENGTH('sidata.Ci', 'PrimaryUserId') IS NULL
    ALTER TABLE sidata.Ci ADD PrimaryUserId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'PrimaryUserUpn') IS NULL
    ALTER TABLE sidata.Ci ADD PrimaryUserUpn NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'PrimaryUserName') IS NULL
    ALTER TABLE sidata.Ci ADD PrimaryUserName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'PrimaryUser') IS NULL
    ALTER TABLE sidata.Ci ADD PrimaryUser NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'IsEncrypted') IS NULL
    ALTER TABLE sidata.Ci ADD IsEncrypted BIT NULL;
IF COL_LENGTH('sidata.Ci', 'IsCompliant') IS NULL
    ALTER TABLE sidata.Ci ADD IsCompliant BIT NULL;
IF COL_LENGTH('sidata.Ci', 'IntuneLastSync') IS NULL
    ALTER TABLE sidata.Ci ADD IntuneLastSync DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'IntuneStatus') IS NULL
    ALTER TABLE sidata.Ci ADD IntuneStatus NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'DeviceValue') IS NULL
    ALTER TABLE sidata.Ci ADD DeviceValue NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ExposureLevel') IS NULL
    ALTER TABLE sidata.Ci ADD ExposureLevel NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Alerts30d') IS NULL
    ALTER TABLE sidata.Ci ADD Alerts30d INT NULL;
IF COL_LENGTH('sidata.Ci', 'HighAlerts30d') IS NULL
    ALTER TABLE sidata.Ci ADD HighAlerts30d INT NULL;
IF COL_LENGTH('sidata.Ci', 'OnPublicNetwork') IS NULL
    ALTER TABLE sidata.Ci ADD OnPublicNetwork BIT NULL;
IF COL_LENGTH('sidata.Ci', 'LastAdminLogon') IS NULL
    ALTER TABLE sidata.Ci ADD LastAdminLogon DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'DeviceManufacturer') IS NULL
    ALTER TABLE sidata.Ci ADD DeviceManufacturer NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'DeviceModel') IS NULL
    ALTER TABLE sidata.Ci ADD DeviceModel NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'Upn') IS NULL
    ALTER TABLE sidata.Ci ADD Upn NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'MfaStrength') IS NULL
    ALTER TABLE sidata.Ci ADD MfaStrength NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'MfaDefaultMethod') IS NULL
    ALTER TABLE sidata.Ci ADD MfaDefaultMethod NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'CaMfaEnforced') IS NULL
    ALTER TABLE sidata.Ci ADD CaMfaEnforced BIT NULL;
IF COL_LENGTH('sidata.Ci', 'CaPolicyCount') IS NULL
    ALTER TABLE sidata.Ci ADD CaPolicyCount INT NULL;
IF COL_LENGTH('sidata.Ci', 'EntraRiskLevel') IS NULL
    ALTER TABLE sidata.Ci ADD EntraRiskLevel NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'EntraRiskState') IS NULL
    ALTER TABLE sidata.Ci ADD EntraRiskState NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'RiskDetections30d') IS NULL
    ALTER TABLE sidata.Ci ADD RiskDetections30d INT NULL;
IF COL_LENGTH('sidata.Ci', 'RolePaths') IS NULL
    ALTER TABLE sidata.Ci ADD RolePaths NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagerId') IS NULL
    ALTER TABLE sidata.Ci ADD ManagerId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagerUpn') IS NULL
    ALTER TABLE sidata.Ci ADD ManagerUpn NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagerName') IS NULL
    ALTER TABLE sidata.Ci ADD ManagerName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'LastSignIn') IS NULL
    ALTER TABLE sidata.Ci ADD LastSignIn DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'LastInteractiveSignIn') IS NULL
    ALTER TABLE sidata.Ci ADD LastInteractiveSignIn DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'LastNonInteractiveSignIn') IS NULL
    ALTER TABLE sidata.Ci ADD LastNonInteractiveSignIn DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'LastAccessReviewDate') IS NULL
    ALTER TABLE sidata.Ci ADD LastAccessReviewDate DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'Owners') IS NULL
    ALTER TABLE sidata.Ci ADD Owners NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'OwnerUpns') IS NULL
    ALTER TABLE sidata.Ci ADD OwnerUpns NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'OwnerIds') IS NULL
    ALTER TABLE sidata.Ci ADD OwnerIds NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Ci', 'CredentialExpiryDays') IS NULL
    ALTER TABLE sidata.Ci ADD CredentialExpiryDays INT NULL;
IF COL_LENGTH('sidata.Ci', 'CredentialFix') IS NULL
    ALTER TABLE sidata.Ci ADD CredentialFix NVARCHAR(4000) NULL;
IF COL_LENGTH('sidata.Ci', 'HasClientSecret') IS NULL
    ALTER TABLE sidata.Ci ADD HasClientSecret BIT NULL;
IF COL_LENGTH('sidata.Ci', 'HasFederatedCredential') IS NULL
    ALTER TABLE sidata.Ci ADD HasFederatedCredential BIT NULL;
IF COL_LENGTH('sidata.Ci', 'AttachedResource') IS NULL
    ALTER TABLE sidata.Ci ADD AttachedResource NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'AttachedResourceId') IS NULL
    ALTER TABLE sidata.Ci ADD AttachedResourceId NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'AttachedResourceName') IS NULL
    ALTER TABLE sidata.Ci ADD AttachedResourceName NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AttachedResourceType') IS NULL
    ALTER TABLE sidata.Ci ADD AttachedResourceType NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'ManagedIdentityKind') IS NULL
    ALTER TABLE sidata.Ci ADD ManagedIdentityKind NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'LastAppSignIn') IS NULL
    ALTER TABLE sidata.Ci ADD LastAppSignIn DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'LastDelegatedSignIn') IS NULL
    ALTER TABLE sidata.Ci ADD LastDelegatedSignIn DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'ConsentType') IS NULL
    ALTER TABLE sidata.Ci ADD ConsentType NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'TlsCertExpired') IS NULL
    ALTER TABLE sidata.Ci ADD TlsCertExpired BIT NULL;
IF COL_LENGTH('sidata.Ci', 'TlsSelfSigned') IS NULL
    ALTER TABLE sidata.Ci ADD TlsSelfSigned BIT NULL;
IF COL_LENGTH('sidata.Ci', 'TlsEarliestExpiry') IS NULL
    ALTER TABLE sidata.Ci ADD TlsEarliestExpiry DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Ci', 'OpenPortCount') IS NULL
    ALTER TABLE sidata.Ci ADD OpenPortCount INT NULL;
IF COL_LENGTH('sidata.Ci', 'ExposedServices') IS NULL
    ALTER TABLE sidata.Ci ADD ExposedServices NVARCHAR(MAX) NULL;
-- break glass: WHY an account is classified break glass (set on a break glass account and on no other) and the
-- attribute entry it carries -- what Risk factors > Break glass lists, by the index on the reason, never from a document
IF COL_LENGTH('sidata.Ci', 'BreakGlassReason') IS NULL
    ALTER TABLE sidata.Ci ADD BreakGlassReason NVARCHAR(800) NULL;
IF COL_LENGTH('sidata.Ci', 'BreakGlassAttribute') IS NULL
    ALTER TABLE sidata.Ci ADD BreakGlassAttribute NVARCHAR(400) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_Environment' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_Environment ON sidata.Ci (Environment) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_ManagementGroupName' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_ManagementGroupName ON sidata.Ci (ManagementGroupName) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_ServiceSupportGroup' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_ServiceSupportGroup ON sidata.Ci (ServiceSupportGroup) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_ServiceAssignmentGroup' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_ServiceAssignmentGroup ON sidata.Ci (ServiceAssignmentGroup) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_CmdbSupportGroup' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_CmdbSupportGroup ON sidata.Ci (CmdbSupportGroup) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_PendingCriticalPatches' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_PendingCriticalPatches ON sidata.Ci (PendingCriticalPatches) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_DefenderPlanTier' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_DefenderPlanTier ON sidata.Ci (DefenderPlanTier) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_PrimaryUserUpn' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_PrimaryUserUpn ON sidata.Ci (PrimaryUserUpn) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_DeviceValue' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_DeviceValue ON sidata.Ci (DeviceValue) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_Alerts30d' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_Alerts30d ON sidata.Ci (Alerts30d) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_MfaStrength' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_MfaStrength ON sidata.Ci (MfaStrength) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_EntraRiskLevel' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_EntraRiskLevel ON sidata.Ci (EntraRiskLevel) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_ManagerUpn' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_ManagerUpn ON sidata.Ci (ManagerUpn) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_LastInteractiveSignIn' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_LastInteractiveSignIn ON sidata.Ci (LastInteractiveSignIn) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_CredentialExpiryDays' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_CredentialExpiryDays ON sidata.Ci (CredentialExpiryDays) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_LastAppSignIn' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_LastAppSignIn ON sidata.Ci (LastAppSignIn) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_TlsEarliestExpiry' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_TlsEarliestExpiry ON sidata.Ci (TlsEarliestExpiry) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_BreakGlassReason' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_BreakGlassReason ON sidata.Ci (BreakGlassReason) INCLUDE (Name, Tier, WeightedRiskScore)');

-- (2) the finding context the sources add (EPSS, CVE tags, mitigation status, end of support, fix owner and due date,
--     evidence, attack paths, secure score ...) as columns of sidata.Finding, typed. The description and the remediation
--     get a column that holds the WHOLE text (the 4000-character columns above cut what a source says; they stay, and are
--     no longer what the views read).
IF COL_LENGTH('sidata.Finding', 'DescriptionFull') IS NULL
    ALTER TABLE sidata.Finding ADD DescriptionFull NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Finding', 'FixRemediationFull') IS NULL
    ALTER TABLE sidata.Finding ADD FixRemediationFull NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Finding', 'Epss') IS NULL
    ALTER TABLE sidata.Finding ADD Epss FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'CveTags') IS NULL
    ALTER TABLE sidata.Finding ADD CveTags NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Finding', 'CveMitigationStatus') IS NULL
    ALTER TABLE sidata.Finding ADD CveMitigationStatus NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'EosStatus') IS NULL
    ALTER TABLE sidata.Finding ADD EosStatus NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'EosDate') IS NULL
    ALTER TABLE sidata.Finding ADD EosDate DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Finding', 'FixOwner') IS NULL
    ALTER TABLE sidata.Finding ADD FixOwner NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'FixDueDate') IS NULL
    ALTER TABLE sidata.Finding ADD FixDueDate DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Finding', 'FixGracePeriod') IS NULL
    ALTER TABLE sidata.Finding ADD FixGracePeriod NVARCHAR(200) NULL;
IF COL_LENGTH('sidata.Finding', 'Evidence') IS NULL
    ALTER TABLE sidata.Finding ADD Evidence NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Finding', 'SourceFirstDetected') IS NULL
    ALTER TABLE sidata.Finding ADD SourceFirstDetected DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Finding', 'SecureScoreGain') IS NULL
    ALTER TABLE sidata.Finding ADD SecureScoreGain FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'SecureScoreControl') IS NULL
    ALTER TABLE sidata.Finding ADD SecureScoreControl NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'AttackPathCount') IS NULL
    ALTER TABLE sidata.Finding ADD AttackPathCount INT NULL;
IF COL_LENGTH('sidata.Finding', 'AttackPaths') IS NULL
    ALTER TABLE sidata.Finding ADD AttackPaths NVARCHAR(4000) NULL;
IF COL_LENGTH('sidata.Finding', 'CertificateExpiry') IS NULL
    ALTER TABLE sidata.Finding ADD CertificateExpiry DATETIME2(3) NULL;
IF COL_LENGTH('sidata.Finding', 'CvssVector') IS NULL
    ALTER TABLE sidata.Finding ADD CvssVector NVARCHAR(200) NULL;
IF COL_LENGTH('sidata.Finding', 'ExploitTypes') IS NULL
    ALTER TABLE sidata.Finding ADD ExploitTypes NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Finding', 'ExposedDevices') IS NULL
    ALTER TABLE sidata.Finding ADD ExposedDevices INT NULL;
IF COL_LENGTH('sidata.Finding', 'AffectedPath') IS NULL
    ALTER TABLE sidata.Finding ADD AffectedPath NVARCHAR(4000) NULL;
IF COL_LENGTH('sidata.Finding', 'StatusCause') IS NULL
    ALTER TABLE sidata.Finding ADD StatusCause NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'UserImpact') IS NULL
    ALTER TABLE sidata.Finding ADD UserImpact NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'RemediationEffort') IS NULL
    ALTER TABLE sidata.Finding ADD RemediationEffort NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'PortalLink') IS NULL
    ALTER TABLE sidata.Finding ADD PortalLink NVARCHAR(2000) NULL;
-- owner 2026-10-19 ("Component (finding)" shown by default): the component the finding concerns (si_component: OS, SQL,
-- Network, Hardware, Browser, Office, Application, Other), prepared like the category -- what the views filter and show
IF COL_LENGTH('sidata.Finding', 'Component') IS NULL
    ALTER TABLE sidata.Finding ADD Component NVARCHAR(64) NULL;
-- #772 the finding's ServiceNow sub-CI (the classification's one value)
IF COL_LENGTH('sidata.Finding', 'ContextSubCi') IS NULL
    ALTER TABLE sidata.Finding ADD ContextSubCi NVARCHAR(64) NULL;
-- #772 the OS family of the finding's asset (si_os_family)
IF COL_LENGTH('sidata.Finding', 'ContextOsFamily') IS NULL
    ALTER TABLE sidata.Finding ADD ContextOsFamily NVARCHAR(64) NULL;
-- #772 the finding's patch cycle
IF COL_LENGTH('sidata.Finding', 'ContextPatchCycle') IS NULL
    ALTER TABLE sidata.Finding ADD ContextPatchCycle NVARCHAR(64) NULL;

-- (3) the same on the per-issue row (sidata.IssueContext): a text is the distinct values over the key's findings, a number
--     the highest (the highest EPSS, the most attack paths) and a date the earliest (the earliest end of support, due date).
IF COL_LENGTH('sidata.IssueContext', 'Epss') IS NULL
    ALTER TABLE sidata.IssueContext ADD Epss FLOAT NULL;
IF COL_LENGTH('sidata.IssueContext', 'CveTags') IS NULL
    ALTER TABLE sidata.IssueContext ADD CveTags NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'CveMitigationStatus') IS NULL
    ALTER TABLE sidata.IssueContext ADD CveMitigationStatus NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'EosStatus') IS NULL
    ALTER TABLE sidata.IssueContext ADD EosStatus NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'EosDate') IS NULL
    ALTER TABLE sidata.IssueContext ADD EosDate DATETIME2(3) NULL;
IF COL_LENGTH('sidata.IssueContext', 'FixOwner') IS NULL
    ALTER TABLE sidata.IssueContext ADD FixOwner NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'FixDueDate') IS NULL
    ALTER TABLE sidata.IssueContext ADD FixDueDate DATETIME2(3) NULL;
IF COL_LENGTH('sidata.IssueContext', 'FixGracePeriod') IS NULL
    ALTER TABLE sidata.IssueContext ADD FixGracePeriod NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'Evidence') IS NULL
    ALTER TABLE sidata.IssueContext ADD Evidence NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'SourceFirstDetected') IS NULL
    ALTER TABLE sidata.IssueContext ADD SourceFirstDetected DATETIME2(3) NULL;
IF COL_LENGTH('sidata.IssueContext', 'SecureScoreGain') IS NULL
    ALTER TABLE sidata.IssueContext ADD SecureScoreGain FLOAT NULL;
IF COL_LENGTH('sidata.IssueContext', 'SecureScoreControl') IS NULL
    ALTER TABLE sidata.IssueContext ADD SecureScoreControl NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'AttackPathCount') IS NULL
    ALTER TABLE sidata.IssueContext ADD AttackPathCount INT NULL;
IF COL_LENGTH('sidata.IssueContext', 'AttackPaths') IS NULL
    ALTER TABLE sidata.IssueContext ADD AttackPaths NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'CertificateExpiry') IS NULL
    ALTER TABLE sidata.IssueContext ADD CertificateExpiry DATETIME2(3) NULL;
IF COL_LENGTH('sidata.IssueContext', 'CvssVector') IS NULL
    ALTER TABLE sidata.IssueContext ADD CvssVector NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'ExploitTypes') IS NULL
    ALTER TABLE sidata.IssueContext ADD ExploitTypes NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'ExposedDevices') IS NULL
    ALTER TABLE sidata.IssueContext ADD ExposedDevices INT NULL;
IF COL_LENGTH('sidata.IssueContext', 'AffectedPath') IS NULL
    ALTER TABLE sidata.IssueContext ADD AffectedPath NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'StatusCause') IS NULL
    ALTER TABLE sidata.IssueContext ADD StatusCause NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'UserImpact') IS NULL
    ALTER TABLE sidata.IssueContext ADD UserImpact NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'RemediationEffort') IS NULL
    ALTER TABLE sidata.IssueContext ADD RemediationEffort NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'PortalLink') IS NULL
    ALTER TABLE sidata.IssueContext ADD PortalLink NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'Component') IS NULL
    ALTER TABLE sidata.IssueContext ADD Component NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'SubCi') IS NULL
    ALTER TABLE sidata.IssueContext ADD SubCi NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'OsFamily') IS NULL
    ALTER TABLE sidata.IssueContext ADD OsFamily NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.IssueContext', 'PatchCycle') IS NULL
    ALTER TABLE sidata.IssueContext ADD PatchCycle NVARCHAR(MAX) NULL;

-- (4) which list a collection's context was prepared for (as sidata.Ci.CtxSet for a CI): a collection prepared for an
--     older list is prepared once more by the next data sync, and read from its finding rows by the web app until then.
IF COL_LENGTH('sidata.Collection', 'ContextSet') IS NULL
    ALTER TABLE sidata.Collection ADD ContextSet NVARCHAR(16) NULL;

-- (4b) when a collection's view data was written (the views' aggregates, the prepared context, the departments, the
--     counted aggregates): the collection views list a collection only from then on -- 'Complete' alone says its rows are
--     loaded, minutes earlier. Every other reader keeps reading 'Complete'. The data sync sets it for every complete
--     collection without it, so a run that died is finished by the next one. Once, when the column is added: every
--     collection that is complete already stays shown (one statement over one row per collection).
IF COL_LENGTH('sidata.Collection', 'ViewsReadyAt') IS NULL
BEGIN
    ALTER TABLE sidata.Collection ADD ViewsReadyAt DATETIME2(0) NULL;
    EXEC (N'UPDATE sidata.Collection SET ViewsReadyAt = ISNULL(LoadedAt, SYSUTCDATETIME()) WHERE Status = N''Complete''');
END

-- (5) ViewState: what the data sync last stored, as ONE value the web app's result caches are kept under (Name 'data':
--     a new value at the end of every data sync that wrote). A page of a view that was read for this value is not read
--     again until the value moves -- never kept by time alone.
--     Name 'sync': there while a data sync is running (Value = its start time, UTC) and taken away with the end mark; the
--     web app keeps the pages it has while it is there, and ignores a row older than its limit (a run that died).
IF OBJECT_ID('sidata.ViewState') IS NULL
CREATE TABLE sidata.ViewState (
    Name        NVARCHAR(64)   NOT NULL CONSTRAINT PK_ViewState PRIMARY KEY,
    Value       NVARCHAR(64)   NOT NULL,
    UpdatedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_ViewState_UpdatedAt DEFAULT SYSUTCDATETIME()
);

-- (6) indexes the views' own statements had none of:
--   IX_Finding_DepartmentRows  a department's findings with EVERY column its grid shows (the first department index does
--                              not carry the security domain, the responsibility detail and the exemption mark -- it stays)
--   IX_CiFinding_Collection    the newest collection time of the findings per CI (what the result caches ask on a page load)
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_DepartmentRows' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_DepartmentRows ON sidata.Finding (CollectionId, DepartmentId) INCLUDE (AssetKey, AssetName, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, ResponsibilitySource, SecurityDomain, ResponsibilityDetail, ExemptionId)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_Collection' AND object_id = OBJECT_ID('sidata.CiFinding'))
CREATE INDEX IX_CiFinding_Collection ON sidata.CiFinding (CollectionTime);
-- CONTINUOUS DISCOVERY (ADDED 2026-10-11): what every source offers, found again on every run
-- (engine\data-model\SI-SourceDiscovery.ps1). Two small tables the engine fills and the web app's "New context
-- available" page reads -- prepared rows, never a JSON document walked at page time. Additive and guarded.
--   SourceProperty         one row per source / record type / Azure resource type / record part / property: when it was
--                          first and last seen, how many records carried it in the newest run, a sample value, its value
--                          type, the SI fields that read it (MappedFields), the full-details source it is a column of
--                          (SourceSystem), whether SecurityInsight reads it (Collected = 0: the source offers it, not read
--                          yet) and a read permission it is known to need. Baseline = 1: it was there when its source /
--                          record type / part was discovered for the first time (the starting point, not "new").
--   SourceDiscoveryState   one row per source / record type / resource type / part / origin ('records' = from the objects
--                          the runs read, 'schema' = what the source says it offers): the first run (FirstRunId -- the
--                          starting point), the newest run and its record count, and when the source could not be asked,
--                          why (Error) and the read permission that would be needed.
-- The natural key is too long for an index key, so the primary key is its SHA-256 (KeyHash / TypeHash, computed by the engine).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.SourceProperty') IS NULL
CREATE TABLE sidata.SourceProperty (
    KeyHash          VARBINARY(32)  NOT NULL CONSTRAINT PK_SourceProperty PRIMARY KEY,
    Source           NVARCHAR(32)   NOT NULL,
    RecordType       NVARCHAR(64)   NOT NULL,
    ResourceType     NVARCHAR(128)  NOT NULL CONSTRAINT DF_SourceProperty_ResourceType DEFAULT N'',
    Part             NVARCHAR(64)   NOT NULL,
    Property         NVARCHAR(256)  NOT NULL,
    SourceSystem     NVARCHAR(32)   NULL,
    ValueType        NVARCHAR(16)   NULL,
    SampleValue      NVARCHAR(400)  NULL,
    Records          INT            NOT NULL CONSTRAINT DF_SourceProperty_Records DEFAULT 0,
    Collected        BIT            NOT NULL CONSTRAINT DF_SourceProperty_Collected DEFAULT 1,
    CollectedSince   DATETIME2(0)   NULL,
    Origin           NVARCHAR(16)   NOT NULL CONSTRAINT DF_SourceProperty_Origin DEFAULT N'records',
    Baseline         BIT            NOT NULL CONSTRAINT DF_SourceProperty_Baseline DEFAULT 0,
    MappedFields     NVARCHAR(400)  NULL,
    NeedsPermission  NVARCHAR(128)  NULL,
    FirstSeen        DATETIME2(0)   NOT NULL,
    LastSeen         DATETIME2(0)   NOT NULL,
    RunId            NVARCHAR(64)   NULL
);
-- the page: what is new, the newest first
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SourceProperty_New' AND object_id = OBJECT_ID('sidata.SourceProperty'))
CREATE INDEX IX_SourceProperty_New ON sidata.SourceProperty (Baseline, FirstSeen DESC) INCLUDE (Source, RecordType, ResourceType, Part, Property, Collected);
-- one property by its natural key (the page's two actions), and the counts per source
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SourceProperty_Source' AND object_id = OBJECT_ID('sidata.SourceProperty'))
CREATE INDEX IX_SourceProperty_Source ON sidata.SourceProperty (Source, RecordType, Part) INCLUDE (Baseline, Collected);

IF OBJECT_ID('sidata.SourceDiscoveryState') IS NULL
CREATE TABLE sidata.SourceDiscoveryState (
    TypeHash         VARBINARY(32)  NOT NULL CONSTRAINT PK_SourceDiscoveryState PRIMARY KEY,
    Source           NVARCHAR(32)   NOT NULL,
    RecordType       NVARCHAR(64)   NOT NULL,
    ResourceType     NVARCHAR(128)  NOT NULL CONSTRAINT DF_SourceDiscoveryState_ResourceType DEFAULT N'',
    Part             NVARCHAR(64)   NOT NULL,
    Origin           NVARCHAR(16)   NOT NULL,
    Records          INT            NOT NULL CONSTRAINT DF_SourceDiscoveryState_Records DEFAULT 0,
    Error            NVARCHAR(400)  NULL,
    NeedsPermission  NVARCHAR(128)  NULL,
    FirstRunId       NVARCHAR(64)   NOT NULL,
    RunId            NVARCHAR(64)   NOT NULL,
    FirstRunAt       DATETIME2(0)   NOT NULL,
    LastRunAt        DATETIME2(0)   NOT NULL
);
-- "how many records of this type" beside each property, and when a source was last asked
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SourceDiscoveryState_Type' AND object_id = OBJECT_ID('sidata.SourceDiscoveryState'))
CREATE INDEX IX_SourceDiscoveryState_Type ON sidata.SourceDiscoveryState (Source, RecordType, Part, Origin) INCLUDE (ResourceType, Records, LastRunAt);

-- Open alerts per device (the count and the highest severity among them -- from the security alerts of Microsoft Graph),
-- "Autopilot enrolled" from Intune, and the level inside Tier 0 in words: prepared, typed columns of sidata.Ci that the
-- CI views show by default (ProData/DataModel/view-stored-columns.json). Additive and guarded; an index over a column
-- added here is created through EXEC.
IF COL_LENGTH('sidata.Ci', 'OpenAlerts') IS NULL
    ALTER TABLE sidata.Ci ADD OpenAlerts INT NULL;
IF COL_LENGTH('sidata.Ci', 'OpenAlertsHighestSeverity') IS NULL
    ALTER TABLE sidata.Ci ADD OpenAlertsHighestSeverity NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Ci', 'AutopilotEnrolled') IS NULL
    ALTER TABLE sidata.Ci ADD AutopilotEnrolled BIT NULL;
IF COL_LENGTH('sidata.Ci', 'PrivilegeTierLevelText') IS NULL
    ALTER TABLE sidata.Ci ADD PrivilegeTierLevelText NVARCHAR(1000) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_OpenAlerts' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_OpenAlerts ON sidata.Ci (OpenAlerts) INCLUDE (Name, Tier, WeightedRiskScore)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_OpenAlertsHighestSeverity' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_OpenAlertsHighestSeverity ON sidata.Ci (OpenAlertsHighestSeverity) INCLUDE (Name, Tier, WeightedRiskScore)');
-- two device fields the CI views show by default (the last alert's title, why the device counts as internet exposed):
-- prepared like the rest, so no view reads them from the CI document
IF COL_LENGTH('sidata.Ci', 'LastAlertTitle') IS NULL
    ALTER TABLE sidata.Ci ADD LastAlertTitle NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Ci', 'InternetExposedReason') IS NULL
    ALTER TABLE sidata.Ci ADD InternetExposedReason NVARCHAR(1000) NULL;
-- #772 the OS family (si_os_family: Windows, Linux, macOS, iOS, Android, Network OS, Other, Unknown -- the classification's one
-- value): prepared and indexed, so the CI views filter Windows vs. Linux on a column
IF COL_LENGTH('sidata.Ci', 'OsFamily') IS NULL
    ALTER TABLE sidata.Ci ADD OsFamily NVARCHAR(64) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Ci_OsFamily' AND object_id = OBJECT_ID('sidata.Ci'))
    EXEC (N'CREATE INDEX IX_Ci_OsFamily ON sidata.Ci (OsFamily) INCLUDE (Name, Tier, WeightedRiskScore)');

-- ---------------------------------------------------------------------------------------------
-- A SOURCE ON ITS LAST GOOD COLLECTION (ADDED 2026-10-12). A collection that fails must not make the run stop, and must
-- not make anything look gone: the run goes on with that source's last good collection.
--   RecordCollection  one row per feed (provider + record type) and collection time, written when the collection's records
--                     were ALL in the database (the record writer's feed close): which collection step wrote it, how many
--                     records it holds, and its state -- 'good', or 'held' when the step that wrote it did not end well (its
--                     records then freeze what it did not reach instead of turning it 'not seen').
--   SourceState       one row per source (collection step): when it last collected completely, how its newest attempt
--                     ended, and since when it has been on its last good collection.
-- Two small tables (a handful of rows per run); nothing existing is changed or rebuilt.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.RecordCollection') IS NULL
CREATE TABLE sidata.RecordCollection (
    Provider        NVARCHAR(32)   NOT NULL,
    RecordType      NVARCHAR(32)   NOT NULL,
    CollectionTime  DATETIME2(3)   NOT NULL,
    Engine          NVARCHAR(32)   NOT NULL CONSTRAINT DF_RecordCollection_Engine DEFAULT N'',
    Records         INT            NULL,
    State           NVARCHAR(16)   NOT NULL CONSTRAINT DF_RecordCollection_State DEFAULT N'good',
    Reason          NVARCHAR(400)  NULL,
    UpdatedAt       DATETIME2(3)   NOT NULL CONSTRAINT DF_RecordCollection_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_RecordCollection PRIMARY KEY (Provider, RecordType, CollectionTime)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RecordCollection_Engine' AND object_id = OBJECT_ID('sidata.RecordCollection'))
CREATE INDEX IX_RecordCollection_Engine ON sidata.RecordCollection (Engine, CollectionTime) INCLUDE (State, Records);
IF OBJECT_ID('sidata.SourceState') IS NULL
CREATE TABLE sidata.SourceState (
    Source          NVARCHAR(32)   NOT NULL CONSTRAINT PK_SourceState PRIMARY KEY,
    LastGoodAt      DATETIME2(3)   NULL,
    LastAttemptAt   DATETIME2(3)   NULL,
    LastAttemptOk   BIT            NOT NULL CONSTRAINT DF_SourceState_LastAttemptOk DEFAULT 1,
    DroppedSince    DATETIME2(3)   NULL,
    Detail          NVARCHAR(400)  NULL,
    UpdatedAt       DATETIME2(3)   NOT NULL CONSTRAINT DF_SourceState_UpdatedAt DEFAULT SYSUTCDATETIME()
);
-- CollectionSource (ADDED 2026-10-12): a loaded collection that was calculated while a source was on its last good
-- collection -- which source, and from when its data was. Written by the data sync (one statement per sync); the web app
-- shows it when that collection is opened. No foreign key: the data sync clears the rows of collections that are gone.
IF OBJECT_ID('sidata.CollectionSource') IS NULL
CREATE TABLE sidata.CollectionSource (
    CollectionId    INT            NOT NULL,
    Source          NVARCHAR(32)   NOT NULL,
    LastGoodAt      DATETIME2(3)   NULL,
    MarkedUtc       DATETIME2(0)   NOT NULL CONSTRAINT DF_CollectionSource_MarkedUtc DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_CollectionSource PRIMARY KEY (CollectionId, Source)
);

-- ---------------------------------------------------------------------------------------------
-- RISK ANALYSIS WRITES ITS RESULT HERE (#638, ADDED 2026-10-13). Each query bucket's rows are scored and written as the
-- bucket finishes; nothing of the result is held in memory across buckets. The run's collection stays 'Loading' until
-- every bucket of every report is in (RaCompletedAt); the data sync then adds the CIs, the recommendations and the daily
-- aggregates and marks it 'Complete' -- nothing reads an incomplete run. Everything that needs the whole picture (the
-- order, the top lists, the KPIs, the trend, Log Analytics, the workbook) is read from these rows afterwards, in pages.
--   Ra* columns on sidata.Finding / sidata.SummaryRow: the report (its order in the run), the bucket the row came from
--   (a retried bucket replaces its own rows -- never doubles), the write order, the de-duplication key (a finding that two
--   buckets returned is kept once, the first), the sort score, whether the workbook / mail view shows it, the trace
--   identity parts (two assets that share a trace name get the asset id added at the end), the finding key (SI_Finding_CL)
--   and the asset id as Risk Analysis wrote it (the data sync maps it to the CI key).
--   sidata.RaStage: a Summary report's rows per bucket before a group that spans buckets is combined (the same rules
--   as before), then scored and written; removed when the report is done.
--   sidata.RaReportStatus (#641): per run and report the rows the source said the report holds (a count of the
--   unbucketed query), the rows retrieved and stored, and the verdict -- Complete | NotComplete | Unverified.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Collection', 'Source') IS NULL ALTER TABLE sidata.Collection ADD Source NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NULL ALTER TABLE sidata.Collection ADD RaCompletedAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Collection', 'RaPartialReason') IS NULL ALTER TABLE sidata.Collection ADD RaPartialReason NVARCHAR(2000) NULL;
IF COL_LENGTH('sidata.SummaryLoad', 'Source') IS NULL ALTER TABLE sidata.SummaryLoad ADD Source NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.Finding', 'RaReport') IS NULL ALTER TABLE sidata.Finding ADD RaReport INT NULL;
IF COL_LENGTH('sidata.Finding', 'RaBucket') IS NULL ALTER TABLE sidata.Finding ADD RaBucket NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.Finding', 'RaSeq') IS NULL ALTER TABLE sidata.Finding ADD RaSeq BIGINT NULL;
IF COL_LENGTH('sidata.Finding', 'RaDedup') IS NULL ALTER TABLE sidata.Finding ADD RaDedup BINARY(16) NULL;
IF COL_LENGTH('sidata.Finding', 'RaSort') IS NULL ALTER TABLE sidata.Finding ADD RaSort FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RaInView') IS NULL ALTER TABLE sidata.Finding ADD RaInView BIT NULL;
IF COL_LENGTH('sidata.Finding', 'RaTraceHash') IS NULL ALTER TABLE sidata.Finding ADD RaTraceHash BINARY(16) NULL;
IF COL_LENGTH('sidata.Finding', 'RaTraceKey') IS NULL ALTER TABLE sidata.Finding ADD RaTraceKey NVARCHAR(450) NULL;
IF COL_LENGTH('sidata.Finding', 'RaTraceSuffixed') IS NULL ALTER TABLE sidata.Finding ADD RaTraceSuffixed BIT NULL;
IF COL_LENGTH('sidata.Finding', 'RaFindingKey') IS NULL ALTER TABLE sidata.Finding ADD RaFindingKey NVARCHAR(900) NULL;
IF COL_LENGTH('sidata.Finding', 'RaAssetId') IS NULL ALTER TABLE sidata.Finding ADD RaAssetId NVARCHAR(400) NULL;
IF COL_LENGTH('sidata.Finding', 'RaAssetTier') IS NULL ALTER TABLE sidata.Finding ADD RaAssetTier TINYINT NULL;   -- the tier the row tells about its asset (an attack path: its source)
IF COL_LENGTH('sidata.SummaryRow', 'RaReport') IS NULL ALTER TABLE sidata.SummaryRow ADD RaReport INT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaBucket') IS NULL ALTER TABLE sidata.SummaryRow ADD RaBucket NVARCHAR(64) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaDedup') IS NULL ALTER TABLE sidata.SummaryRow ADD RaDedup BINARY(16) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaSort') IS NULL ALTER TABLE sidata.SummaryRow ADD RaSort FLOAT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaInView') IS NULL ALTER TABLE sidata.SummaryRow ADD RaInView BIT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTraceHash') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTraceHash BINARY(16) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTraceKey') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTraceKey NVARCHAR(450) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTraceSuffixed') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTraceSuffixed BIT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTrendSeverity') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTrendSeverity NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTrendTier') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTrendTier NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTrendDomain') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTrendDomain NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTrendScore') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTrendScore FLOAT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaExempt') IS NULL ALTER TABLE sidata.SummaryRow ADD RaExempt BIT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RaTrendAssetIds') IS NULL ALTER TABLE sidata.SummaryRow ADD RaTrendAssetIds NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RowJson') IS NULL ALTER TABLE sidata.SummaryRow ADD RowJson NVARCHAR(MAX) NULL;
IF OBJECT_ID('sidata.RaStage') IS NULL
CREATE TABLE sidata.RaStage (
    RunKey      NVARCHAR(64)   NOT NULL,   -- '<grain>|<collection time>'
    RaReport    INT            NOT NULL,
    RaBucket    NVARCHAR(64)   NOT NULL,
    RaSeq       BIGINT         NOT NULL,
    GroupHash   BINARY(16)     NOT NULL,
    RowJson     NVARCHAR(MAX)  NOT NULL,
    CONSTRAINT PK_RaStage PRIMARY KEY CLUSTERED (RunKey, RaReport, RaSeq)
);
IF OBJECT_ID('sidata.RaReportStatus') IS NULL
CREATE TABLE sidata.RaReportStatus (
    CollectionTime  DATETIME2(3)   NOT NULL,
    Grain           NVARCHAR(16)   NOT NULL,
    ReportName      NVARCHAR(256)  NOT NULL,
    ExpectedRows    BIGINT         NULL,       -- what the source's count of the unbucketed query said; NULL = it could not say
    RetrievedRows   BIGINT         NULL,       -- what the buckets returned (combined Summary groups for a Summary report)
    StoredRows      BIGINT         NULL,       -- what is stored after the report's scope and exclusion rules
    State           NVARCHAR(16)   NOT NULL,   -- Complete | NotComplete | Unverified
    Reason          NVARCHAR(2000) NULL,
    CheckedAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_RaReportStatus_CheckedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_RaReportStatus PRIMARY KEY (CollectionTime, Grain, ReportName)
);
-- #690 (34) ADDED 2026-10-15 (additive, nullable): the report's QUERY FINGERPRINT at this run -- SHA-256 of what the report
-- asks (its query as authored, before the run's substitutions, plus its tier / severity scope; Get-RAReportQueryFingerprint).
-- A finding that leaves a report whose fingerprint changed since the finding was last seen closes as 'report changed', never
-- as 'remediated' (absence is not remediation). NULL = not recorded (a run before this column) -- read as unknown.
IF COL_LENGTH('sidata.RaReportStatus', 'QueryHash') IS NULL ALTER TABLE sidata.RaReportStatus ADD QueryHash NVARCHAR(64) NULL;
-- #692 ADDED 2026-10-19 (additive, nullable): the report's fingerprint(s) from BEFORE a declared structure-only change
-- (data-model/report-fingerprint-carry.locked.json; ';'-separated; Get-RAReportQueryFingerprintCarry) -- the owner's
-- one-time change of 2026-10-19 (the generated output block in every report, the bucket filter on the two Defender
-- recommendation reports). A fingerprint that carries the one at a finding's last sighting is NOT a changed report: the
-- finding keeps its history and never closes as 'report changed' or 'remediated' because of it. NULL = no carry.
IF COL_LENGTH('sidata.RaReportStatus', 'QueryHashCarry') IS NULL ALTER TABLE sidata.RaReportStatus ADD QueryHashCarry NVARCHAR(400) NULL;
-- #877 ADDED 2026-10-22 (additive, nullable; owner: "Hold back that report"): a report HELD BACK by its run -- its rows of
-- that run had to go (the report failed, or it is not in the run) and could not be removed, even in measured batches. The
-- value is the report's write ordinal in the run (sidata.Finding.RaReport of that collection): those rows are never read as
-- the report -- the run's own reads leave them out, and the data sync removes them FIRST when it takes the collection in,
-- before anything is built from it or it is marked complete. The verdict is NotComplete (it keeps its last complete
-- result and closes nothing). NULL = nothing held back.
IF COL_LENGTH('sidata.RaReportStatus', 'HeldRaReport') IS NULL ALTER TABLE sidata.RaReportStatus ADD HeldRaReport INT NULL;
-- #901 ADDED 2026-10-26 (additive, nullable; owner: "a report fails alone, the job completes ... we use last known good
-- data"): a NotComplete report that SI DELIBERATELY held at its last complete result -- 'silent-source' (#900: a source it
-- reads went silent) or 'role-read' (#899: the Entra role read was not complete). Such a report does not make the run
-- partial for the publish (sidata.PublishedRunSet): the run publishes, the held report shows its carried last complete
-- result, marked, and the publish note names it. NULL = not a deliberate hold (a report that really failed, a lost slice,
-- a #877 hold-back): the run stays partial as before.
IF COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NULL ALTER TABLE sidata.RaReportStatus ADD HoldKind NVARCHAR(32) NULL;
-- #902 ADDED 2026-10-26 (additive, nullable; owner: "Approve, next release"): with a HoldKind (data-model/hold-kinds.locked.json)
-- the hold's facts, read by the uplink, the mail and the web app's Run reports page:
--   HeldRuns      how many runs of this grain in a row the report is held for the same kind, this run included (a run where
--                 it is not held writes NULL, so the next hold starts at 1). A Detailed hold of 3 runs or more is escalated:
--                 a real problem told to support -- the data is still the last complete result, nothing closes;
--   KeptResultAt  the collection time of the result it keeps (its newest Complete row before this run); NULL = none;
--   HoldNames     what the hold is about (the silent tables, ';'-separated) -- what an Admin may accept as empty.
IF COL_LENGTH('sidata.RaReportStatus', 'HeldRuns') IS NULL ALTER TABLE sidata.RaReportStatus ADD HeldRuns INT NULL;
IF COL_LENGTH('sidata.RaReportStatus', 'KeptResultAt') IS NULL ALTER TABLE sidata.RaReportStatus ADD KeptResultAt DATETIME2(3) NULL;
IF COL_LENGTH('sidata.RaReportStatus', 'HoldNames') IS NULL ALTER TABLE sidata.RaReportStatus ADD HoldNames NVARCHAR(400) NULL;
-- #900 ADDED 2026-10-25 (additive; owner: a finding never closes because a source went silent): per SOURCE TABLE the
-- reports read (a Defender / Sentinel table -- engine\risk-analysis\_shared\RA-SilentSource.ps1), its count at the last
-- run that counted it and its last NON-ZERO count. A table that counts 0 after it had rows is SILENT (SilentSince, and
-- what was said, SilentNote) until it has rows again: every report reading it is NotComplete and keeps its last complete
-- result. One row per table (a few dozen at most); the Summary and Detailed runs share it -- a table is a table.
IF OBJECT_ID('sidata.RaSourceCount') IS NULL
CREATE TABLE sidata.RaSourceCount (
    SourceTable      NVARCHAR(128)  NOT NULL CONSTRAINT PK_RaSourceCount PRIMARY KEY,
    LastRows         BIGINT         NULL,      -- the rows at the last run that counted it
    LastCountedAt    DATETIME2(3)   NULL,
    LastNonZeroRows  BIGINT         NULL,      -- the rows at the last run it had any; NULL = never had rows
    LastNonZeroAt    DATETIME2(3)   NULL,
    SilentSince      DATETIME2(3)   NULL,      -- NULL = not silent
    SilentNote       NVARCHAR(400)  NULL,      -- what the run says about it while it is silent
    UpdatedAt        DATETIME2(0)   NOT NULL CONSTRAINT DF_RaSourceCount_UpdatedAt DEFAULT SYSUTCDATETIME()
);
-- #673 PLAN B (ADDED 2026-10-14; used only with SI_RA_DefenderFilterInEngine / SI_RA_DefenderFilterCompare, both off): the
-- run's Defender recommendation list -- the keys of the (resource, recommendation) pairs the Defender recommendation reports
-- carry, one BIGINT per key (the KQL hash the Azure recommendation reports compare), keyed by the run ('<grain>|<time>').
-- Risk Analysis loads it once per run, filters each answer against it here, and removes it at the end of the run (a list a
-- failed run leaves behind is removed by the next load after two days).
IF OBJECT_ID('sidata.RaDefenderKey') IS NULL
CREATE TABLE sidata.RaDefenderKey (
    RunKey      NVARCHAR(64)   NOT NULL,
    K           BIGINT         NOT NULL,
    CreatedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_RaDefenderKey_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_RaDefenderKey PRIMARY KEY CLUSTERED (RunKey, K)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaOrder' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaOrder ON sidata.Finding (CollectionId, RaSort DESC, RaSeq) INCLUDE (RaReport, RaInView) WHERE RaSeq IS NOT NULL');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaBucket' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaBucket ON sidata.Finding (CollectionId, RaReport, RaBucket) WHERE RaSeq IS NOT NULL');
-- #881 the removal of ONE PART of a split report (RA-SqlStream.ps1 Remove-RAStreamSeqRanges: its write-number range
-- [@From, @To) of one report, DELETE TOP batches) had no index with RaSeq after the report: every batch read every row of the
-- whole report (live: "the database did not answer in time while removing what one part of the report stored", a CVE report
-- of 1,168,208 rows; at 500,000 devices one report is hundreds of millions). Now every batch seeks its own range.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaSeq' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaSeq ON sidata.Finding (CollectionId, RaReport, RaSeq) WHERE RaSeq IS NOT NULL');
-- #881 the findings per CI's database source (engine\pro-data\_shared\SI-DataCi.ps1 Get-SIDataCiDbSourceSql) asks every run
-- which complete collection holds keyed rows and counts them: without an index on the key it read every finding of every
-- collection. The keyed rows' collection ids alone answer both (on a large table built on its own, resumable).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaFindingKey' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaDedup' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaDedup ON sidata.Finding (CollectionId, RaReport, RaDedup, RaSeq) WHERE RaDedup IS NOT NULL');
-- ADDED 2026-10-21: "a finding two query slices both returned is kept once" walks a report in pages through its key index
-- (RA-SqlStream.ps1 Get-RAStreamDedupPageSql) -- a Summary report had no such index, so each page would have read the
-- report's rows whole. The run, the report, the key, the write order; only the rows Risk Analysis keyed.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryRow_RaDedup' AND object_id = OBJECT_ID('sidata.SummaryRow'))
    EXEC (N'CREATE INDEX IX_SummaryRow_RaDedup ON sidata.SummaryRow (CollectionTime, RaReport, RaDedup, RowNo) WHERE RaDedup IS NOT NULL');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryRow_RaOrder' AND object_id = OBJECT_ID('sidata.SummaryRow'))
    EXEC (N'CREATE INDEX IX_SummaryRow_RaOrder ON sidata.SummaryRow (CollectionTime, RaSort DESC, RowNo) INCLUDE (RaReport, RaInView) WHERE RaReport IS NOT NULL');
-- #741 (1) ADDED 2026-10-17: the end-of-report check "which findings share a trace name with another asset's finding"
-- (RA-SqlStream.ps1 Get-RAStreamTraceCandidatesSql) had no index: it read the trace columns of every row of the report
-- through the clustered index -- JSON included -- twice. At a school install (2026-10-16) it ran past the command timeout on
-- five reports ("Timeout expired" on ExecuteReader) and each failed. With these it is a seek on the run and the report, the
-- trace hashes grouped in index order; only the rows that really share a name are read whole.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaTrace' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaTrace ON sidata.Finding (CollectionId, RaReport, RaTraceHash) INCLUDE (RaTraceKey, RaTraceSuffixed) WHERE RaSeq IS NOT NULL');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryRow_RaTrace' AND object_id = OBJECT_ID('sidata.SummaryRow'))
    EXEC (N'CREATE INDEX IX_SummaryRow_RaTrace ON sidata.SummaryRow (CollectionTime, RaReport, RaTraceHash) INCLUDE (RaTraceKey, RaTraceSuffixed) WHERE RaReport IS NOT NULL');

-- ---------------------------------------------------------------------------------------------
-- ONE INCOMPLETE REPORT DOES NOT HOLD A WHOLE RUN -- PER-REPORT LOADING (ADDED 2026-10-14). A Risk Analysis run in which
-- one report could not be completed is loaded as soon as it is in: every report that IS complete is current, and a report
-- that is not complete (or missing) keeps its last complete rows, shown as "from <date>" -- never as current, never
-- dropped, never closed.
--   sidata.Collection.RaPartialScope: what the run's incompleteness covers, as Risk Analysis judged it at its end --
--     'reports' (every cause is a named report: its verdict is NotComplete in sidata.RaReportStatus), 'run' (something
--     that is not one report -- a Log Analytics post, a profile the run was built on), NULL (a complete run, or a run
--     written before this column: read as 'run'). Only 'reports' lets the other reports close what is gone.
--   sidata.Finding.CarriedFrom: set on a row the data sync CARRIED into this collection from the last collection in which
--     its report was complete (the time of that collection). NULL = this run's own row.
--   sidata.CollectionReportCarry: per collection and incomplete report, what was done -- the rows carried and from which
--     collection, or that no complete earlier result exists (this run's rows are shown, marked). No foreign key: the
--     data sync clears the rows of collections that are gone (as sidata.CollectionPartial).
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Collection', 'RaPartialScope') IS NULL ALTER TABLE sidata.Collection ADD RaPartialScope NVARCHAR(16) NULL;
-- #725 ADDED 2026-10-16 (additive, nullable): the moment Risk Analysis settled every verdict of the run (the guards, the
-- per-report verdicts, the Log Analytics post, the partial reason / scope -- persisted with it) and found nothing that holds
-- the run. Only a collection carrying it may be completed by the data sync when its run stopped before marking it in.
IF COL_LENGTH('sidata.Collection', 'RaVerdictsFinalAt') IS NULL ALTER TABLE sidata.Collection ADD RaVerdictsFinalAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NULL ALTER TABLE sidata.Finding ADD CarriedFrom DATETIME2(3) NULL;
IF OBJECT_ID('sidata.CollectionReportCarry') IS NULL
CREATE TABLE sidata.CollectionReportCarry (
    CollectionId       INT            NOT NULL,
    ReportName         NVARCHAR(256)  NOT NULL,
    FromCollectionId   INT            NULL,       -- the last collection in which the report was complete; NULL = none exists
    FromTime           DATETIME2(3)   NULL,
    CarriedRows        INT            NOT NULL,   -- the last complete rows carried in (a finding this run did return is kept as this run's row)
    ThisRunRows        INT            NOT NULL,   -- the rows this run stored for the report (kept, never removed)
    Reason             NVARCHAR(2000) NULL,       -- why the report is not complete (sidata.RaReportStatus)
    MarkedUtc          DATETIME2(0)   NOT NULL CONSTRAINT DF_CollectionReportCarry_MarkedUtc DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_CollectionReportCarry PRIMARY KEY (CollectionId, ReportName)
);

-- ---------------------------------------------------------------------------------------------
-- THE COLLECTIONS' OWN RETENTION (ADDED 2026-10-16). Per grain the data sync keeps the newest complete collection and the
-- complete one before it; the finding rows of every older collection, and of every collection a stopped run left
-- 'Loading' once a newer one of the same grain is complete, are removed (engine/_shared/data-sql/SI-DataSql.ps1,
-- Invoke-SIDataCollectionRetention). The collection row itself stays, MARKED:
--   RetiredAt   when its rows were removed (NULL = a collection with its rows). A marked collection is never loaded again,
--               never listed by the collection views and never derived again; its aggregates (the day totals behind the
--               trends, the facets, the departments, the services, the per-report verdicts) stay until the collection
--               passes SI_Pro_DataRetentionDays, as before.
--   RetiredWhy  'abandoned' (its run stopped before it was complete) | 'superseded' (older than the two newest complete).
-- No new index: every removal runs on the clustered keys (CollectionId / CollectionTime / RunKey).
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL ALTER TABLE sidata.Collection ADD RetiredAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Collection', 'RetiredWhy') IS NULL ALTER TABLE sidata.Collection ADD RetiredWhy NVARCHAR(32) NULL;
IF COL_LENGTH('sidata.SummaryLoad', 'RetiredAt') IS NULL ALTER TABLE sidata.SummaryLoad ADD RetiredAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.SummaryLoad', 'RetiredWhy') IS NULL ALTER TABLE sidata.SummaryLoad ADD RetiredWhy NVARCHAR(32) NULL;

-- ---------------------------------------------------------------------------------------------
-- THE LOG ANALYTICS COPY IS COMPLETE (ADDED 2026-10-18; owner 2026-10-17: deliver from SQL first, the Log Analytics copy
-- after). Risk Analysis completes and delivers a collection from the database first, then sends its copy to Log
-- Analytics, and marks the collection only when every row of the copy went out:
--   LaCopyAt   when the run's copy reached Log Analytics in full (NULL = no copy, a copy still going out, or a copy that
--              broke off -- the run then says so and is partial). Additive; nothing existing is changed.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Collection', 'LaCopyAt') IS NULL ALTER TABLE sidata.Collection ADD LaCopyAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.SummaryLoad', 'LaCopyAt') IS NULL ALTER TABLE sidata.SummaryLoad ADD LaCopyAt DATETIME2(0) NULL;

-- ---------------------------------------------------------------------------------------------
-- WEEKLY CONTEXT DISCOVERY FOR RISK ANALYSIS (ADDED 2026-10-18, engine\data-model\SI-ContextDiscovery.ps1). What the sources
-- hold that the chain source column -> provider mapping -> SI field -> output map does not carry yet, as PROPOSALS --
-- additions only (a mapping row, a new field, a new output column, a new attack-path route), never a rename. Additive.
--   ContextProposal       one row per proposal (Kind CARRY / MAP / NEW / ROUTE + Subject): the target, why, the fill rate,
--                         the evidence, when it was first and last found and whether this week still found it (StillSeen).
--                         Decision is the owner's ('proposed' until someone sets it) -- the engine never writes it.
--   ContextDiscoveryRun   one row per weekly run: how many proposals, how many new, which parts could be read.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.ContextProposal') IS NULL
CREATE TABLE sidata.ContextProposal (
    ProposalKey  NVARCHAR(400)  NOT NULL CONSTRAINT PK_ContextProposal PRIMARY KEY,
    Kind         NVARCHAR(16)   NOT NULL,
    Subject      NVARCHAR(300)  NOT NULL,
    Target       NVARCHAR(300)  NULL,
    Why          NVARCHAR(1000) NULL,
    FillPct      DECIMAL(5,1)   NULL,
    Evidence     NVARCHAR(1000) NULL,
    Decision     NVARCHAR(16)   NOT NULL CONSTRAINT DF_ContextProposal_Decision DEFAULT N'proposed',
    StillSeen    BIT            NOT NULL CONSTRAINT DF_ContextProposal_StillSeen DEFAULT 1,
    FirstSeen    DATETIME2(0)   NOT NULL,
    LastSeen     DATETIME2(0)   NOT NULL,
    RunId        NVARCHAR(64)   NOT NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ContextProposal_Open' AND object_id = OBJECT_ID('sidata.ContextProposal'))
CREATE INDEX IX_ContextProposal_Open ON sidata.ContextProposal (StillSeen, Kind) INCLUDE (Subject, Target, FillPct, Decision, FirstSeen);
IF OBJECT_ID('sidata.ContextDiscoveryRun') IS NULL
CREATE TABLE sidata.ContextDiscoveryRun (
    RunId          NVARCHAR(64)   NOT NULL CONSTRAINT PK_ContextDiscoveryRun PRIMARY KEY,
    RunAt          DATETIME2(0)   NOT NULL,
    Proposals      INT            NOT NULL,
    NewProposals   INT            NOT NULL,
    FillRateRead   BIT            NULL,
    EdgesRead      BIT            NULL,
    Note           NVARCHAR(1000) NULL
);

-- ---------------------------------------------------------------------------------------------
-- THE FACET COUNTS OF A LARGE COLLECTION, BUILT IN PARTS (ADDED 2026-10-19, engine\_shared\data-sql\SI-DataSql.ps1
-- Invoke-SIDataFacet). Each FindingId range of a collection stages its partial facet aggregate per (facet, value, CI); one
-- closing statement groups the staged rows into FindingFacet / FindingFacetCounted and the staged rows are removed. Counted
-- = 1 for the counted twin (exempted findings left out). A row left by a run that stopped part-way is removed by the next
-- build of that collection. Working rows only -- nothing reads them but the closing statement. Additive.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.FindingFacetStage') IS NULL
CREATE TABLE sidata.FindingFacetStage (
    CollectionId     INT            NOT NULL,
    Counted          BIT            NOT NULL,
    Facet            NVARCHAR(16)   NOT NULL,
    Value            NVARCHAR(256)  NOT NULL,
    AssetKey         NVARCHAR(400)  NULL,
    Findings         INT            NOT NULL,
    ScoreTotal       FLOAT          NULL,
    WeightedTotal    FLOAT          NULL,
    MaxScore         FLOAT          NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_FindingFacetStage' AND object_id = OBJECT_ID('sidata.FindingFacetStage'))
CREATE CLUSTERED INDEX CX_FindingFacetStage ON sidata.FindingFacetStage (CollectionId, Counted, Facet, Value);
-- ---------------------------------------------------------------------------------------------
-- SECURITY RECOMMENDATIONS, REMEDIATIONS AND KEY FIGURES (ADDED 2026-10-19, #636 -- the menu restructure). Additive,
-- guarded, nullable; the data sync fills them (engine\pro-data\_shared\SI-DataRemediation.ps1, SI-DataKeyFigures.ps1).
--
-- (1) Domain > Category > Subcategory as filter columns of BOTH finding tables (#592: every filter on a typed indexed
--     column). sidata.Finding already carries Category / Subcategory (the prepared context, view-stored-columns.json);
--     they get an index. sidata.CiFinding (the newest collection per CI) gets both columns, written by the data sync with
--     every finding collection it stores (from the finding's si_category / si_subcategory, else Category / Subcategory).
IF COL_LENGTH('sidata.CiFinding', 'Category') IS NULL
    ALTER TABLE sidata.CiFinding ADD Category NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.CiFinding', 'Subcategory') IS NULL
    ALTER TABLE sidata.CiFinding ADD Subcategory NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.CiFindingStage', 'Category') IS NULL AND OBJECT_ID('sidata.CiFindingStage') IS NOT NULL
    ALTER TABLE sidata.CiFindingStage ADD Category NVARCHAR(256) NULL;
IF COL_LENGTH('sidata.CiFindingStage', 'Subcategory') IS NULL AND OBJECT_ID('sidata.CiFindingStage') IS NOT NULL
    ALTER TABLE sidata.CiFindingStage ADD Subcategory NVARCHAR(256) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFinding_Category' AND object_id = OBJECT_ID('sidata.CiFinding'))
    EXEC (N'CREATE INDEX IX_CiFinding_Category ON sidata.CiFinding (SecurityDomain, Category, Subcategory) INCLUDE (CiId, FindingKey, Severity, RiskRating, Tier)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Category' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId, SecurityDomain, Category, Subcategory) INCLUDE (AssetKey, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating)');

-- (2) REMEDIATIONS (#636 approved plan: "one remediation = the same fix applied to many assets"). THE KEY, per finding,
--     the first rule that has a value (text trimmed, lower-cased, spaces removed, cut at 400):
--        update:<si_fix_recommended_update_id>   the security update(s) Defender recommends, by id (one KB = one fix)
--        update:<si_fix_recommended_update>      the update(s) by name when no id is given
--        config:<ConfigurationId>                one configuration change (a configuration id that is not a CVE)
--        software:<vendor>/<product>             a CVE without a named update: upgrading the software closes it
--        cve:<CVE id>                            a CVE that names neither update nor software
--        title:<finding title>                   anything else
--     The kind is the finding's si_remediation_type (patch | configuration | upgrade | policy | manual) when a source
--     says it, else from the rule: update -> patch, config -> configuration, software -> upgrade, cve -> patch, title ->
--     manual. The PowerShell twin of the rule is Get-SIRemediationKey (SI-DataRemediation.ps1); a test holds them equal.
--     Reporting only (read-only): nothing here changes a finding's source or closes anything.
--   Finding.RemediationKey   the key of each finding (the Detailed view filters a fix's findings on it)
--   Remediation              one row per collection + key: kind, what to do, effort, owner, assets reached, findings closed,
--                            risk removed (the weighted risk of its open findings), the best tier, status
--   RemediationAsset         one row per collection + asset + key for the 100 most important assets of the collection
--                            (tier first, then the most weighted risk): "Top 10 assets to fix" and what to do on each
--   Collection.RemediationAt when a collection got them (NULL = not yet: the pages say "being prepared")
IF COL_LENGTH('sidata.Finding', 'RemediationKey') IS NULL
    ALTER TABLE sidata.Finding ADD RemediationKey NVARCHAR(400) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Remediation' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_Remediation ON sidata.Finding (CollectionId, RemediationKey) INCLUDE (AssetKey, Severity, Tier, RiskScoreWeighted)');
IF COL_LENGTH('sidata.Collection', 'RemediationAt') IS NULL
    ALTER TABLE sidata.Collection ADD RemediationAt DATETIME2(0) NULL;
IF OBJECT_ID('sidata.Remediation') IS NULL
CREATE TABLE sidata.Remediation (
    CollectionId     INT            NOT NULL,
    RemediationKey   NVARCHAR(400)  NOT NULL,
    Kind             NVARCHAR(32)   NOT NULL,
    Fix              NVARCHAR(1000) NULL,       -- the fix in words: the update, the configuration, the software
    WhatToDo         NVARCHAR(4000) NULL,       -- how to fix (the source's remediation text of the most risky finding)
    Effort           NVARCHAR(16)   NULL,       -- Low | Moderate | High (the highest a finding of it carries)
    FixOwner         NVARCHAR(400)  NULL,       -- the fix owner when one is named; 'several (n)' when they differ
    DepartmentId     INT            NULL,       -- the one department of its findings (NULL = none or several)
    Departments      INT            NOT NULL,
    Assets           INT            NOT NULL,
    Tier0Assets      INT            NOT NULL,
    BestTier         TINYINT        NULL,
    Recommendations  INT            NOT NULL,   -- distinct CVEs / configurations it closes
    Findings         INT            NOT NULL,   -- open findings it closes (not exempted)
    ExemptedFindings INT            NOT NULL,
    CriticalFindings INT            NOT NULL,
    HighFindings     INT            NOT NULL,
    RiskRemoved      FLOAT          NOT NULL,   -- the weighted risk of the open findings it closes
    MaxRiskScore     FLOAT          NULL,
    HasExploit       BIT            NOT NULL,
    Status           NVARCHAR(16)   NOT NULL,   -- open | exempted
    CONSTRAINT PK_Remediation PRIMARY KEY CLUSTERED (CollectionId, RemediationKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Remediation_Reach' AND object_id = OBJECT_ID('sidata.Remediation'))
CREATE INDEX IX_Remediation_Reach ON sidata.Remediation (CollectionId, Assets DESC, RiskRemoved DESC) INCLUDE (Kind, Fix, Effort, Findings, Status);
IF OBJECT_ID('sidata.RemediationAsset') IS NULL
CREATE TABLE sidata.RemediationAsset (
    CollectionId     INT            NOT NULL,
    AssetRank        INT            NOT NULL,   -- 1 = the most important asset of the collection
    FixRank          INT            NOT NULL,   -- 1 = the fix on this asset that removes the most risk
    AssetKey         NVARCHAR(400)  NOT NULL,
    AssetName        NVARCHAR(400)  NULL,
    Tier             TINYINT        NULL,
    AssetRisk        FLOAT          NOT NULL,   -- the asset's open weighted risk
    RemediationKey   NVARCHAR(400)  NOT NULL,
    Kind             NVARCHAR(32)   NOT NULL,
    Fix              NVARCHAR(1000) NULL,
    Findings         INT            NOT NULL,
    RiskRemoved      FLOAT          NOT NULL,
    CONSTRAINT PK_RemediationAsset PRIMARY KEY CLUSTERED (CollectionId, AssetRank, FixRank)
);

-- (3) KEY FIGURES (#636, owner 2026-10-19: "core stats relevant for mgmt like Missing patches (cve's) on windows vs. linux,
--     servers vs clients and others"): Overview > Executive overview > Key figures reads ONLY this -- one row per
--     collection + block + figure + its two dimensions, written by the data sync from the stored findings per CI
--     (sidata.CiFinding), the CIs (sidata.Ci) and the finding lifecycle (sidata.CiFindingState). "Change since the last
--     report" = the same row of the collection before. A figure SI has no data for is a row with Available = 0 and the
--     reason, never a 0.
IF OBJECT_ID('sidata.KeyFigure') IS NULL
CREATE TABLE sidata.KeyFigure (
    CollectionId     INT            NOT NULL,
    Block            NVARCHAR(16)   NOT NULL,   -- patching | exposure | coverage | identity | cloud
    Figure           NVARCHAR(48)   NOT NULL,
    Dim1             NVARCHAR(200)  NOT NULL CONSTRAINT DF_KeyFigure_Dim1 DEFAULT N'',
    Dim2             NVARCHAR(120)  NOT NULL CONSTRAINT DF_KeyFigure_Dim2 DEFAULT N'',   -- the key stays under 900 bytes
    Value            FLOAT          NULL,
    Assets           INT            NULL,
    Total            INT            NULL,       -- the population the figure is a part of (a share = Assets / Total)
    Items            INT            NULL,       -- distinct CVEs / recommendations the figure holds
    VeryHigh         INT            NULL,       -- of the findings: Very High (Defender's critical)
    Servers          INT            NULL,       -- of the devices: servers
    Clients          INT            NULL,       -- of the devices: clients (workstations)
    Available        BIT            NOT NULL CONSTRAINT DF_KeyFigure_Available DEFAULT 1,
    Note             NVARCHAR(400)  NULL,
    CONSTRAINT PK_KeyFigure PRIMARY KEY CLUSTERED (CollectionId, Block, Figure, Dim1, Dim2)
);
IF COL_LENGTH('sidata.Collection', 'KeyFiguresAt') IS NULL
    ALTER TABLE sidata.Collection ADD KeyFiguresAt DATETIME2(0) NULL;

-- #636 (owner 2026-10-19, approved): the department NAME per finding row, so Security recommendations > Detailed filters
-- and sorts on it as a typed, indexed column (an immutable grid never joins cfg). The data sync writes it with the
-- department (SI-DataResponsibility.ps1); a department renamed re-resolves every collection (the policy fingerprint holds
-- the names). NULL = Unassigned.
IF COL_LENGTH('sidata.Finding', 'DepartmentName') IS NULL
    ALTER TABLE sidata.Finding ADD DepartmentName NVARCHAR(128) NULL;
-- (the column is added just above; the one guard is the index itself, so a large install builds it resumably)
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_DepartmentName' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_DepartmentName ON sidata.Finding (CollectionId, DepartmentName)');

-- ---------------------------------------------------------------------------------------------
-- ONE ROW PER CVE, PRE-COMPUTED PER COLLECTION (ADDED 2026-10-19 -- a large customer, 1,117,524 finding rows: Security
-- recommendations > Vulnerabilities "keeps loading and hangs for minutes", then stopped after 90 seconds. The page grouped
-- every finding of the collection by CVE on each request.) The data sync writes the per-CVE aggregate once per collection
-- (engine\pro-data\_shared\SI-DataViewContext.ps1, Invoke-SIDataCveSummary); the page pages, sorts and filters these rows
-- -- typed columns, the default sort (highest risk) and the severity order indexed -- and reads the close-loop's open items
-- for the rows of the page only.
--   CveSummary          every finding of the collection
--   CveSummaryCounted   the findings without an exemption mark (#264: the counted twin the pages read when exempted
--                       findings are left out -- the same columns)
--   CveSummaryState     one row per collection: when both were written (NULL row = not yet: the page says the list is
--                       being prepared, it never groups the finding rows itself)
-- No foreign key: the retention removes a collection's rows here itself. Additive; the next data sync fills every
-- complete collection, newest first.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.CveSummary') IS NULL
CREATE TABLE sidata.CveSummary (
    CollectionId   INT            NOT NULL,
    Cve            NVARCHAR(100)  NOT NULL,
    Title          NVARCHAR(1000) NULL,
    Severity       NVARCHAR(30)   NULL,       -- the most critical severity of the CVE's findings
    SeverityRank   INT            NOT NULL,   -- its rank (SeverityOrder: 0 = critical)
    Cvss           FLOAT          NULL,       -- the highest
    HasExploit     BIT            NOT NULL,   -- any finding has a known exploit
    Assets         INT            NOT NULL,   -- distinct affected assets (exact)
    Findings       INT            NOT NULL,
    MaxRisk        FLOAT          NULL,
    TotalRisk      FLOAT          NULL,
    Tier           NVARCHAR(12)   NOT NULL,   -- the most critical tier: '0'..'3' or 'Unclassified'
    Tier0Findings  INT            NOT NULL,
    CONSTRAINT PK_CveSummary PRIMARY KEY CLUSTERED (CollectionId, Cve)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CveSummary_Risk' AND object_id = OBJECT_ID('sidata.CveSummary'))
CREATE INDEX IX_CveSummary_Risk ON sidata.CveSummary (CollectionId, MaxRisk DESC, Cve);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CveSummary_Severity' AND object_id = OBJECT_ID('sidata.CveSummary'))
CREATE INDEX IX_CveSummary_Severity ON sidata.CveSummary (CollectionId, SeverityRank, Cvss DESC) INCLUDE (Tier, HasExploit);

IF OBJECT_ID('sidata.CveSummaryCounted') IS NULL
CREATE TABLE sidata.CveSummaryCounted (
    CollectionId   INT            NOT NULL,
    Cve            NVARCHAR(100)  NOT NULL,
    Title          NVARCHAR(1000) NULL,
    Severity       NVARCHAR(30)   NULL,
    SeverityRank   INT            NOT NULL,
    Cvss           FLOAT          NULL,
    HasExploit     BIT            NOT NULL,
    Assets         INT            NOT NULL,
    Findings       INT            NOT NULL,
    MaxRisk        FLOAT          NULL,
    TotalRisk      FLOAT          NULL,
    Tier           NVARCHAR(12)   NOT NULL,
    Tier0Findings  INT            NOT NULL,
    CONSTRAINT PK_CveSummaryCounted PRIMARY KEY CLUSTERED (CollectionId, Cve)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CveSummaryCounted_Risk' AND object_id = OBJECT_ID('sidata.CveSummaryCounted'))
CREATE INDEX IX_CveSummaryCounted_Risk ON sidata.CveSummaryCounted (CollectionId, MaxRisk DESC, Cve);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CveSummaryCounted_Severity' AND object_id = OBJECT_ID('sidata.CveSummaryCounted'))
CREATE INDEX IX_CveSummaryCounted_Severity ON sidata.CveSummaryCounted (CollectionId, SeverityRank, Cvss DESC) INCLUDE (Tier, HasExploit);

IF OBJECT_ID('sidata.CveSummaryState') IS NULL
CREATE TABLE sidata.CveSummaryState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_CveSummaryState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Cves           INT            NOT NULL,
    CountedCves    INT            NOT NULL,
    Findings       BIGINT         NOT NULL    -- the CVE findings the rows were built from (every one, exempted included)
);
-- ---------------------------------------------------------------------------------------------
-- ONE ROW PER CI, PRE-COMPUTED PER COLLECTION (ADDED 2026-10-19 -- a large customer, 1,117,524 finding rows / ~3,000 CIs:
-- Assets & services > Risk scores, Weighted risk score (its distribution tab) and Assets (CIs) at risk grouped every finding of the
-- collection by CI on each request -- 1.5 s on ring 1 by #284, worse at the large customer.) The data sync writes the per-CI
-- aggregate once per collection (engine\pro-data\_shared\SI-DataViewContext.ps1, Invoke-SIDataAssetRiskSummary); the pages
-- page, sort and filter these rows -- typed columns, the default sorts (total risk, total weighted) and the tier indexed.
--   AssetRiskSummary          every finding of the collection with a CI key
--   AssetRiskSummaryCounted   the findings without an exemption mark (#264: the counted twin the pages read when exempted
--                             findings are left out -- the same columns)
--   AssetRiskSummaryState     one row per collection: when both were written (no row = not yet: the page says the list is
--                             being prepared, it never groups the finding rows itself)
-- Tier is the most critical tier of the CI's findings (MIN of sidata.Finding.Tier), the page words it as before.
-- No foreign key: the retention removes a collection's rows here itself. Additive; the next data sync fills every
-- complete collection, newest first. Keyed by CollectionId, so whichever collection a page shows is selected by its id.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.AssetRiskSummary') IS NULL
CREATE TABLE sidata.AssetRiskSummary (
    CollectionId    INT            NOT NULL,
    AssetKey        NVARCHAR(400)  NOT NULL,
    AssetName       NVARCHAR(400)  NULL,       -- MAX of the findings' asset name (the page prefers sidata.Asset's)
    Tier            TINYINT        NULL,       -- the most critical tier of its findings
    Findings        BIGINT         NOT NULL,
    Vulnerabilities BIGINT         NOT NULL,   -- its findings with a CVE
    TotalRisk       FLOAT          NULL,
    MaxRisk         FLOAT          NULL,
    AvgRisk         FLOAT          NULL,
    TotalWeighted   FLOAT          NULL,
    MaxWeighted     FLOAT          NULL,
    AvgWeighted     FLOAT          NULL,
    CriticalRated   INT            NOT NULL,
    HighRated       INT            NOT NULL,
    TotalWeightedOrRisk FLOAT       NULL,       -- SUM(COALESCE(weighted, risk)): the CMDB asset pool's and lanes' weighted risk
    CONSTRAINT PK_AssetRiskSummary PRIMARY KEY CLUSTERED (CollectionId, AssetKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummary_Risk' AND object_id = OBJECT_ID('sidata.AssetRiskSummary'))
CREATE INDEX IX_AssetRiskSummary_Risk ON sidata.AssetRiskSummary (CollectionId, TotalRisk DESC) INCLUDE (Tier, MaxRisk);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummary_Weighted' AND object_id = OBJECT_ID('sidata.AssetRiskSummary'))
CREATE INDEX IX_AssetRiskSummary_Weighted ON sidata.AssetRiskSummary (CollectionId, TotalWeighted DESC) INCLUDE (Tier, MaxWeighted);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummary_Tier' AND object_id = OBJECT_ID('sidata.AssetRiskSummary'))
CREATE INDEX IX_AssetRiskSummary_Tier ON sidata.AssetRiskSummary (CollectionId, Tier, TotalRisk DESC);

IF OBJECT_ID('sidata.AssetRiskSummaryCounted') IS NULL
CREATE TABLE sidata.AssetRiskSummaryCounted (
    CollectionId    INT            NOT NULL,
    AssetKey        NVARCHAR(400)  NOT NULL,
    AssetName       NVARCHAR(400)  NULL,
    Tier            TINYINT        NULL,
    Findings        BIGINT         NOT NULL,
    Vulnerabilities BIGINT         NOT NULL,
    TotalRisk       FLOAT          NULL,
    MaxRisk         FLOAT          NULL,
    AvgRisk         FLOAT          NULL,
    TotalWeighted   FLOAT          NULL,
    MaxWeighted     FLOAT          NULL,
    AvgWeighted     FLOAT          NULL,
    CriticalRated   INT            NOT NULL,
    HighRated       INT            NOT NULL,
    TotalWeightedOrRisk FLOAT       NULL,       -- SUM(COALESCE(weighted, risk)): the CMDB asset pool's and lanes' weighted risk
    CONSTRAINT PK_AssetRiskSummaryCounted PRIMARY KEY CLUSTERED (CollectionId, AssetKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummaryCounted_Risk' AND object_id = OBJECT_ID('sidata.AssetRiskSummaryCounted'))
CREATE INDEX IX_AssetRiskSummaryCounted_Risk ON sidata.AssetRiskSummaryCounted (CollectionId, TotalRisk DESC) INCLUDE (Tier, MaxRisk);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummaryCounted_Weighted' AND object_id = OBJECT_ID('sidata.AssetRiskSummaryCounted'))
CREATE INDEX IX_AssetRiskSummaryCounted_Weighted ON sidata.AssetRiskSummaryCounted (CollectionId, TotalWeighted DESC) INCLUDE (Tier, MaxWeighted);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummaryCounted_Tier' AND object_id = OBJECT_ID('sidata.AssetRiskSummaryCounted'))
CREATE INDEX IX_AssetRiskSummaryCounted_Tier ON sidata.AssetRiskSummaryCounted (CollectionId, Tier, TotalRisk DESC);

IF OBJECT_ID('sidata.AssetRiskSummaryState') IS NULL
CREATE TABLE sidata.AssetRiskSummaryState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_AssetRiskSummaryState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Assets         INT            NOT NULL,
    CountedAssets  INT            NOT NULL,
    Findings       BIGINT         NOT NULL,   -- the findings with a CI key the rows were built from (exempted included)
    -- the Tier board's "Unclassified findings" line (was a scan of every finding of the collection per page open): the
    -- findings whose tier words Unclassified, their distinct CIs and those without a CI key -- every finding / counted
    UnclassifiedFindings            BIGINT NOT NULL,
    UnclassifiedAssets              BIGINT NOT NULL,
    UnclassifiedWithoutAsset        BIGINT NOT NULL,
    CountedUnclassifiedFindings     BIGINT NOT NULL,
    CountedUnclassifiedAssets       BIGINT NOT NULL,
    CountedUnclassifiedWithoutAsset BIGINT NOT NULL
);

-- ---------------------------------------------------------------------------------------------
-- THE DOMAIN -> CATEGORY PAIRS OF A COLLECTION (ADDED 2026-10-19 -- the Security owners page read every finding's
-- DetailJson (JSON_VALUE '$.Category') of the newest collection on each page open: 1.1 million JSON documents at a large
-- customer.) The data sync writes the distinct pairs once per collection (Invoke-SIDataDomainCategory); the page reads them.
-- No exempted variant: the page has no exempted toggle (a category exists whether or not its findings are exempted).
-- No state row = not written yet: the page says the categories from the data are being prepared (owners entered by hand
-- are shown as always) -- it never reads the findings itself.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.DomainCategory') IS NULL
CREATE TABLE sidata.DomainCategory (
    CollectionId   INT            NOT NULL,
    Domain         NVARCHAR(128)  NOT NULL,   -- sidata.Finding.SecurityDomain
    Category       NVARCHAR(128)  NOT NULL,   -- the Risk Analysis row's Category (DetailJson), as the page read it before
    CONSTRAINT PK_DomainCategory PRIMARY KEY CLUSTERED (CollectionId, Domain, Category)
);

IF OBJECT_ID('sidata.DomainCategoryState') IS NULL
CREATE TABLE sidata.DomainCategoryState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_DomainCategoryState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Pairs          INT            NOT NULL
);
-- #834 (ADDED 2026-10-20, measured at internal, a small database: the pairs' one SELECT DISTINCT over every finding's
-- DetailJson took 239 s per collection). The Risk Analysis row's Category, stored on the finding when its views' columns are
-- derived (Get-SIDataDeriveFindingSql: the same expression the pairs read -- LEFT(JSON_VALUE(DetailJson, '$.Category'), 128),
-- NULL for a row that is not valid JSON), so the pairs are read from this narrow index instead of every finding's JSON. A
-- collection derived before the column existed has it empty: its pairs are read from DetailJson as before. Additive; the
-- index has the one guard, so on a large table it is built online after the file (the schema runner's deferred index build).
IF COL_LENGTH('sidata.Finding', 'RaCategory') IS NULL
    ALTER TABLE sidata.Finding ADD RaCategory NVARCHAR(128) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaCategory' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaCategory ON sidata.Finding (CollectionId, SecurityDomain, RaCategory)');
-- #830 / #834 (ADDED 2026-10-20, the owner's rule: "the columns a step reads or filters are typed columns, filled once, and
-- indexed where filtered"). The Risk Analysis row's values the vulnerability connectors' snapshot and data quality read on
-- EVERY finding -- stored once, when the finding's views' columns are derived (Get-SIDataDeriveFindingSql -RowColumns: each
-- exactly the expression the readers used on DetailJson before, COALESCE(JSON_VALUE, JSON_QUERY) -- a list or an object as
-- its JSON text; a scope field already coalesced over its columns in the readers' order; NULL for a row that is not JSON),
-- so no reader scans every finding's JSON again (876,000 findings per collection at a large install). The values the
-- finding already carries typed (AssetName, ConfigurationId, Title, Severity, SecurityDomain, ReportName, RiskScore) are
-- read from their own columns. sidata.Collection.RaRowsAt = this collection's rows carry them (the derive sets it after its
-- last range); a collection derived before the columns existed has it NULL and is read from DetailJson as before.
-- IX_Finding_RaRows: the readers' one range per collection (CollectionId, FindingId) with every column they read, so a
-- page or a per-report count never touches the wide rows. Additive; the index has the one guard (built online after the
-- file on a large table: the schema runner's deferred index build).
IF COL_LENGTH('sidata.Finding', 'RaRowAssetId') IS NULL ALTER TABLE sidata.Finding ADD RaRowAssetId NVARCHAR(4000) NULL;                  -- AssetId
IF COL_LENGTH('sidata.Finding', 'RaRowSolutionVersion') IS NULL ALTER TABLE sidata.Finding ADD RaRowSolutionVersion NVARCHAR(4000) NULL;  -- SolutionVersion
IF COL_LENGTH('sidata.Finding', 'RaRowCriticalityTier') IS NULL ALTER TABLE sidata.Finding ADD RaRowCriticalityTier NVARCHAR(4000) NULL;  -- CriticalityTier
IF COL_LENGTH('sidata.Finding', 'RaRowSiComponent') IS NULL ALTER TABLE sidata.Finding ADD RaRowSiComponent NVARCHAR(4000) NULL;          -- si_component
IF COL_LENGTH('sidata.Finding', 'RaScopeRiskRating') IS NULL ALTER TABLE sidata.Finding ADD RaScopeRiskRating NVARCHAR(4000) NULL;        -- RiskRating, si_risk_rating
IF COL_LENGTH('sidata.Finding', 'RaScopeCategory') IS NULL ALTER TABLE sidata.Finding ADD RaScopeCategory NVARCHAR(4000) NULL;            -- si_category, Category
IF COL_LENGTH('sidata.Finding', 'RaScopeSubcategory') IS NULL ALTER TABLE sidata.Finding ADD RaScopeSubcategory NVARCHAR(4000) NULL;      -- si_subcategory, SubCategory, Subcategory
IF COL_LENGTH('sidata.Finding', 'RaScopeClass') IS NULL ALTER TABLE sidata.Finding ADD RaScopeClass NVARCHAR(4000) NULL;                  -- si_class, AssetClass
IF COL_LENGTH('sidata.Finding', 'RaScopeComponent') IS NULL ALTER TABLE sidata.Finding ADD RaScopeComponent NVARCHAR(4000) NULL;          -- si_component, Component
IF COL_LENGTH('sidata.Finding', 'RaScopePatchCycle') IS NULL ALTER TABLE sidata.Finding ADD RaScopePatchCycle NVARCHAR(4000) NULL;        -- si_patch_cycle
IF COL_LENGTH('sidata.Finding', 'RaScopeOsFamily') IS NULL ALTER TABLE sidata.Finding ADD RaScopeOsFamily NVARCHAR(4000) NULL;            -- si_os_family
IF COL_LENGTH('sidata.Finding', 'RaScopeSubCi') IS NULL ALTER TABLE sidata.Finding ADD RaScopeSubCi NVARCHAR(4000) NULL;                  -- si_servicenow_subci
IF COL_LENGTH('sidata.Finding', 'RaScopeAffectedProduct') IS NULL ALTER TABLE sidata.Finding ADD RaScopeAffectedProduct NVARCHAR(4000) NULL;  -- si_affected_product
IF COL_LENGTH('sidata.Finding', 'RaFillRiskFactorProbability') IS NULL ALTER TABLE sidata.Finding ADD RaFillRiskFactorProbability BIT NULL;  -- RiskFactor_Probability_Detailed filled
IF COL_LENGTH('sidata.Finding', 'RaFillRiskFactorConsequence') IS NULL ALTER TABLE sidata.Finding ADD RaFillRiskFactorConsequence BIT NULL;  -- RiskFactor_Consequence_Detailed filled
IF COL_LENGTH('sidata.Collection', 'RaRowsAt') IS NULL ALTER TABLE sidata.Collection ADD RaRowsAt DATETIME2(0) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaRows' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RaRows ON sidata.Finding (CollectionId, FindingId) INCLUDE (AssetName, ConfigurationId, Title, Severity, SecurityDomain, ReportName, RiskScore, CarriedFrom, RaRowAssetId, RaRowSolutionVersion, RaRowCriticalityTier, RaRowSiComponent, RaScopeRiskRating, RaScopeCategory, RaScopeSubcategory, RaScopeClass, RaScopeComponent, RaScopePatchCycle, RaScopeOsFamily, RaScopeSubCi, RaScopeAffectedProduct, RaFillRiskFactorProbability, RaFillRiskFactorConsequence)');
-- ---------------------------------------------------------------------------------------------
-- THE SUMMARY GROUPINGS OF THE DETAILED FINDINGS, PRE-COMPUTED PER COLLECTION (ADDED 2026-10-19, #636 -- the owner: "summary
-- could be build as views with the detailed data instead. it is just views with groupings of data instead, like group per
-- tier category"). The groupings of data-model\summary-groupings.locked.json (per recommendation with its affected assets,
-- per asset, tier, Domain > Category > Subcategory, risk rating, department, severity, report), computed by THE engine
-- function (engine\_shared\SI-SummaryGroupings.ps1 Invoke-SISummaryGrouping -- Community runs the same function on the run's
-- Detailed result) and written once per collection by the data sync (engine\pro-data\_shared\SI-DataSummaryGroups.ps1).
-- The grouped views page, sort and filter these rows; they never group the finding rows per request.
--   SummaryGroup          every finding of the collection; one row per (grouping, Key1, Key2, Key3) -- '' for an unused key
--   SummaryGroupCounted   the findings without an exemption mark (#264: the counted twin -- the same columns)
--   SummaryGroupState     one row per collection: when both were written and from which definition (its hash; a changed
--                         definition writes the collection again). No row = not yet: the view says it is being prepared.
-- The measure columns are the definition's measures, one for one (a test holds them together). Keyed by CollectionId, so
-- whichever collection a view shows (the published run) is selected by its id. No foreign key: the retention removes a
-- collection's rows here itself. Additive; the next data sync fills every complete collection, newest first.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.SummaryGroup') IS NULL
CREATE TABLE sidata.SummaryGroup (
    CollectionId             INT            NOT NULL,
    GroupingId               VARCHAR(40)    NOT NULL,   -- the grouping's id in the definition (recommendation, asset, tier, ...)
    Key1                     NVARCHAR(400)  NOT NULL,
    Key2                     NVARCHAR(256)  NOT NULL,
    Key3                     NVARCHAR(256)  NOT NULL,
    Label                    NVARCHAR(1000) NULL,       -- the name shown next to the key (a recommendation's title, an asset's name)
    Findings                 INT            NOT NULL,
    Assets                   INT            NOT NULL,   -- distinct affected assets (exact)
    Recommendations          INT            NOT NULL,   -- distinct recommendations / CVEs (configuration ids)
    MaxRisk                  FLOAT          NULL,
    TotalRisk                FLOAT          NULL,
    BestTier                 TINYINT        NULL,       -- the most critical tier (0..3; NULL = none classified)
    Tier0Findings            INT            NOT NULL,
    CriticalFindings         INT            NOT NULL,   -- severity Very High
    HighFindings             INT            NOT NULL,
    RatedCriticalFindings    INT            NOT NULL,   -- risk rating Critical
    RatedHighFindings        INT            NOT NULL,
    CriticalRecommendations  INT            NOT NULL,
    HighRecommendations      INT            NOT NULL,
    ExploitedRecommendations INT            NOT NULL,   -- distinct recommendations / CVEs with a known exploit
    AttributesJson           NVARCHAR(MAX)  NULL,       -- a grouping's attributes (the Summary report's columns), one JSON object
    GroupRowId               BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_SummaryGroup PRIMARY KEY CLUSTERED (CollectionId, GroupingId, GroupRowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryGroup_Findings' AND object_id = OBJECT_ID('sidata.SummaryGroup'))
CREATE INDEX IX_SummaryGroup_Findings ON sidata.SummaryGroup (CollectionId, GroupingId, Findings DESC) INCLUDE (Key1, Key2, Key3, Assets, MaxRisk);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryGroup_Key' AND object_id = OBJECT_ID('sidata.SummaryGroup'))
CREATE INDEX IX_SummaryGroup_Key ON sidata.SummaryGroup (CollectionId, GroupingId, Key1);

IF OBJECT_ID('sidata.SummaryGroupCounted') IS NULL
CREATE TABLE sidata.SummaryGroupCounted (
    CollectionId             INT            NOT NULL,
    GroupingId               VARCHAR(40)    NOT NULL,
    Key1                     NVARCHAR(400)  NOT NULL,
    Key2                     NVARCHAR(256)  NOT NULL,
    Key3                     NVARCHAR(256)  NOT NULL,
    Label                    NVARCHAR(1000) NULL,
    Findings                 INT            NOT NULL,
    Assets                   INT            NOT NULL,
    Recommendations          INT            NOT NULL,
    MaxRisk                  FLOAT          NULL,
    TotalRisk                FLOAT          NULL,
    BestTier                 TINYINT        NULL,
    Tier0Findings            INT            NOT NULL,
    CriticalFindings         INT            NOT NULL,
    HighFindings             INT            NOT NULL,
    RatedCriticalFindings    INT            NOT NULL,   -- risk rating Critical
    RatedHighFindings        INT            NOT NULL,
    CriticalRecommendations  INT            NOT NULL,
    HighRecommendations      INT            NOT NULL,
    ExploitedRecommendations INT            NOT NULL,
    AttributesJson           NVARCHAR(MAX)  NULL,
    GroupRowId               BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_SummaryGroupCounted PRIMARY KEY CLUSTERED (CollectionId, GroupingId, GroupRowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryGroupCounted_Findings' AND object_id = OBJECT_ID('sidata.SummaryGroupCounted'))
CREATE INDEX IX_SummaryGroupCounted_Findings ON sidata.SummaryGroupCounted (CollectionId, GroupingId, Findings DESC) INCLUDE (Key1, Key2, Key3, Assets, MaxRisk);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SummaryGroupCounted_Key' AND object_id = OBJECT_ID('sidata.SummaryGroupCounted'))
CREATE INDEX IX_SummaryGroupCounted_Key ON sidata.SummaryGroupCounted (CollectionId, GroupingId, Key1);

IF OBJECT_ID('sidata.SummaryGroupState') IS NULL
CREATE TABLE sidata.SummaryGroupState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_SummaryGroupState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    DefinitionHash VARCHAR(64)    NOT NULL,   -- the definition the rows were built from (data-model\summary-groupings.locked.json)
    Groups         INT            NOT NULL,
    CountedGroups  INT            NOT NULL,
    Findings       BIGINT         NOT NULL    -- the findings the rows were built from (every one, exempted included)
);
-- #812 (ADDED 2026-10-19): which groupings a collection's rows hold (';id;id;') -- the named views (Risk rating, MITRE, Compliance,
-- CVSS) say the collection is being prepared until their grouping is among them. NULL = written before the column existed.
IF COL_LENGTH('sidata.SummaryGroupState', 'Groupings') IS NULL
    ALTER TABLE sidata.SummaryGroupState ADD Groupings NVARCHAR(2000) NULL;
-- ADDED 2026-10-20 (owner: the Summary view "with output similar to what we had for the old summary report"): a grouping's
-- attributes (data-model\summary-groupings.locked.json 'attributes' -- domain, category, the most severe severity and rating,
-- the affected asset names, first seen, remediation) as one JSON object per row; NULL = a grouping without attributes, or a
-- row written before the column existed (the next data sync writes the collection again: the definition changed).
IF COL_LENGTH('sidata.SummaryGroup', 'AttributesJson') IS NULL
    ALTER TABLE sidata.SummaryGroup ADD AttributesJson NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.SummaryGroupCounted', 'AttributesJson') IS NULL
    ALTER TABLE sidata.SummaryGroupCounted ADD AttributesJson NVARCHAR(MAX) NULL;

-- =============================================================================================
-- ONE TRUSTED RUN (ADDED 2026-10-19; owner: "it is a big problem that we have a mix of old and new data, so trust is
-- broken to the solution. we need the views to use last know good run, where we can trust it apart all" / "and not show
-- some parts from recent run and some from last known good run"). Every page used to pick "the newest" on its own -- the
-- wall board a collection the data sync was still loading, the executive view an older run's mail view, the
-- Vulnerabilities list another day. Now ONE pointer per install names the run every view reads. It moves only when a
-- pipeline run is TRUSTED, in one transaction (sidata.PublishedRunSet), and nothing newer is shown until the next one.
--   PublishedRun          Name 'current' = THE PUBLISHED RUN: its Risk Analysis Detailed collection (DetailedCollectionId --
--                         the collection every view reads), its Summary collection (SummaryCollectionTime), the copies of
--                         its executive views of both grains (ExecViewDetailedId / ExecViewSummaryId ->
--                         RiskExecViewSnapshot), the build of the merged assets it ended with (CiBuildStart, the build's
--                         start as the build wrote it; CiCollectionTime, the newest CI time then), the pipeline run
--                         (FlowRunId, RunStartedUtc, RunEndedUtc), the version, how it was set (Source: 'run' = a trusted
--                         pipeline run | 'schedules' = an install whose jobs run on their own timers, at the first wake-up
--                         after a newer complete collection | 'update' = the update, once, on an install that had data but
--                         no pointer) and when (PublishedAt). Partial = 1 only when SI_Pro_PublishPartialRun allowed a run
--                         in which a report fell back to an earlier result -- strict by default: such a run does not publish.
--                         Name 'refused' = the newest pipeline run that ended and did NOT publish, and why (Note): what the
--                         banner and Operations say ("the newest run did not complete -- showing the last complete one").
--   RiskExecViewSnapshot  each grain's executive view AS THE PUBLISHED RUN WROTE IT. sidata.RiskExecView is still replaced
--                         by every newer run, also one in progress; the copy is never changed. Copies no pointer names are
--                         removed by the runner after SI_Pro_DataRetentionDays (engine/_shared/data-sql/SI-DataPublishedRun.ps1).
--   vPublishedCollection  the published Detailed collection -- or, on an install where no run was published yet (a new
--                         install's first collection), the newest complete one whose view data is written, as before.
--   vPublishedExecView    the published run's executive views -- or, with no published run yet, sidata.RiskExecView.
-- Additive: two tables, two views, one procedure (CREATE OR ALTER: code, re-applied by every update; no data changes).
-- An install with data but no pointer is published ONCE by the update, from the newest complete collection with its view
-- data written that no report fell back in; its executive views only when they belong to that collection (else the page
-- says there is none yet). The next trusted run replaces it.
-- =============================================================================================
IF OBJECT_ID('sidata.PublishedRun') IS NULL
CREATE TABLE sidata.PublishedRun (
    Name                   NVARCHAR(16)   NOT NULL CONSTRAINT PK_PublishedRun PRIMARY KEY,
    DetailedCollectionId   INT            NULL,
    DetailedCollectionTime DATETIME2(3)   NULL,
    SummaryCollectionTime  DATETIME2(3)   NULL,
    ExecViewDetailedId     BIGINT         NULL,
    ExecViewSummaryId      BIGINT         NULL,
    CiBuildStart           NVARCHAR(64)   NULL,
    CiCollectionTime       DATETIME2(3)   NULL,
    FlowRunId              NVARCHAR(64)   NULL,
    RunStartedUtc          DATETIME2(3)   NULL,
    RunEndedUtc            DATETIME2(3)   NULL,
    SolutionVersion        NVARCHAR(64)   NULL,
    Source                 NVARCHAR(16)   NOT NULL,
    [Partial]              BIT            NOT NULL CONSTRAINT DF_PublishedRun_Partial DEFAULT 0,
    Note                   NVARCHAR(400)  NULL,
    PublishedAt            DATETIME2(0)   NOT NULL CONSTRAINT DF_PublishedRun_PublishedAt DEFAULT SYSUTCDATETIME(),
    CopiedAt               DATETIME2(0)   NULL,       -- when the published copies of the CIs and assets were filled (NULL = not yet: the pages read the source)
    CiFindingTime          DATETIME2(3)   NULL,       -- review S2: set only when the findings per CI are NOT the published collection's (their own, older time)
    CONSTRAINT CK_PublishedRun_Name CHECK (Name IN ('current', 'refused')),
    CONSTRAINT CK_PublishedRun_Source CHECK (Source IN ('run', 'schedules', 'update'))
);
-- review S2: a published run whose findings per CI (sidata.CiFinding) are still an earlier collection's -- that part of the
-- data sync failed -- is published PARTIAL, and this says as of when the findings per CI are (the CI pages say so)
IF COL_LENGTH('sidata.PublishedRun', 'CiFindingTime') IS NULL
    ALTER TABLE sidata.PublishedRun ADD CiFindingTime DATETIME2(3) NULL;

IF OBJECT_ID('sidata.RiskExecViewSnapshot') IS NULL
CREATE TABLE sidata.RiskExecViewSnapshot (
    SnapshotId       BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_RiskExecViewSnapshot PRIMARY KEY,
    Grain            NVARCHAR(16)   NOT NULL,
    GeneratedAt      DATETIME2(3)   NOT NULL,
    CollectionTime   DATETIME2(3)   NULL,
    ReportTemplate   NVARCHAR(128)  NULL,
    Mode             NVARCHAR(16)   NOT NULL,
    Leader           NVARCHAR(16)   NOT NULL,
    FiguresFromGrain NVARCHAR(16)   NOT NULL,
    PayloadJson      NVARCHAR(MAX)  NOT NULL,
    SnapshotAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_RiskExecViewSnapshot_At DEFAULT SYSUTCDATETIME()
);

-- the published Detailed collection; with no published run yet, the newest complete one whose views are ready (or, while
-- no collection carries that mark, the newest complete one -- vLatestCollection's rule)
IF OBJECT_ID('sidata.vPublishedCollection') IS NULL
EXEC ('CREATE VIEW sidata.vPublishedCollection AS
SELECT c.CollectionId, c.CollectionTime, c.Kind, c.RunId, c.[Rows], c.LoadedAt, c.SolutionVersion, p.PublishedAt, CONVERT(bit, 1) AS Published
FROM sidata.PublishedRun AS p
JOIN sidata.Collection AS c ON c.CollectionId = p.DetailedCollectionId
WHERE p.Name = ''current''
UNION ALL
SELECT l.CollectionId, l.CollectionTime, l.Kind, l.RunId, l.[Rows], l.LoadedAt, l.SolutionVersion, CAST(NULL AS datetime2(0)), CONVERT(bit, 0)
FROM sidata.Collection AS l
WHERE NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p2 WHERE p2.Name = ''current'' AND p2.DetailedCollectionId IS NOT NULL)
  AND l.CollectionTime = (SELECT MAX(x.CollectionTime) FROM sidata.Collection AS x
                          WHERE x.Kind = ''Detailed'' AND x.Status = ''Complete'' AND x.RetiredAt IS NULL
                            AND (x.ViewsReadyAt IS NOT NULL OR NOT EXISTS (SELECT 1 FROM sidata.Collection AS r WHERE r.ViewsReadyAt IS NOT NULL)))
  AND l.Kind = ''Detailed'' AND l.Status = ''Complete''');

-- the published run's executive views; with no published run yet, the current ones as before
IF OBJECT_ID('sidata.vPublishedExecView') IS NULL
EXEC ('CREATE VIEW sidata.vPublishedExecView AS
SELECT s.Grain, s.GeneratedAt, s.CollectionTime, s.PayloadJson, CONVERT(bit, 1) AS Published
FROM sidata.PublishedRun AS p
JOIN sidata.RiskExecViewSnapshot AS s ON s.SnapshotId = p.ExecViewDetailedId OR s.SnapshotId = p.ExecViewSummaryId
WHERE p.Name = ''current''
UNION ALL
SELECT v.Grain, v.GeneratedAt, v.CollectionTime, v.PayloadJson, CONVERT(bit, 0)
FROM sidata.RiskExecView AS v
WHERE NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p2 WHERE p2.Name = ''current'' AND p2.DetailedCollectionId IS NOT NULL)');

-- ---------------------------------------------------------------------------------------------
-- ONE TRUSTED RUN FOR THE CIs (ADDED 2026-10-19; owner: "and not show some parts from recent run and some from last known
-- good run"). The CI build (#534, incremental, in place) and the data sync write sidata.Ci and its neighbours during every
-- run -- hours before the run is trusted. The pages read a PUBLISHED COPY of each instead, filled from the source in the same
-- transaction that moves the pointer (the publisher itself: sidata.PublishedRunSet calls sidata.PublishedCopyRefreshAll;
-- stale copies are caught up by sidata.PublishedCopyCatchUp): the CI build keeps writing the source exactly as before, and
-- the web app reads the copy once one is published (PublishedRun.CopiedAt), the source before that (a new install's first
-- collection). Retention keeps exactly two states: the copy (published) and the source (being built).
--   <Table>Pub            Ci, CiLink, CiFinding, CiService, CiRecord, CiFindingState, CiRelation, Asset, AssetIdentifier,
--                         AssetTag: the same columns and indexes as the source, created and kept in step by the schema apply
--                         (sidata.PublishedCopyEnsure: DDL needs the updater's rights; a run never changes a table's shape)
--   PublishedCopy         per copy: the rows and the milliseconds of its last fill, and when
--   v*Pub                 the CI views over the copies (vCi, vCiRelation, vCiUnowned, vCiFindingModel, vServiceCi,
--                         vServiceFinding); vCiDailyPub / vAssetMetadataPub = the daily CI rows / the full metadata up to the
--                         published copy (they keep history, so no copy is needed)
-- Not copied, read live as before: a person's own changes (sidata.CiOverride, sidata.CiChange), the CI build's own state
-- (sidata.CiBuildState) and the ticket state of the close-loop (vuln.*: ServiceNow's current state, not run data).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.PublishedCopy') IS NULL
CREATE TABLE sidata.PublishedCopy (
    TableName     NVARCHAR(64)   NOT NULL CONSTRAINT PK_PublishedCopy PRIMARY KEY,
    [Rows]        BIGINT         NOT NULL,
    Milliseconds  INT            NOT NULL,
    CopiedAt      DATETIME2(0)   NOT NULL CONSTRAINT DF_PublishedCopy_CopiedAt DEFAULT SYSUTCDATETIME()
);
-- the body of sidata.PublishedCopyEnsure is held once in @SIPubEnsure: the procedure is made from it, and the schema apply at
-- the end of this batch runs it itself (sp_executesql) -- the updater holds db_ddladmin, never EXECUTE on sidata (SUP-2026-00204)
DECLARE @SIPubEnsure nvarchar(max) = N'BEGIN
    -- the published copy sidata.<Table>Pub: created when missing, every column the source has (same type, same order;
    -- an identity is a plain column), every index the source has (same name, keys, order, included columns and filter;
    -- the primary key as a unique index). DDL: run by the schema apply only, never by a run.
    SET NOCOUNT ON;
    DECLARE @src int = OBJECT_ID(N''sidata.'' + @Table), @pubName sysname = @Table + N''Pub'', @pub int, @sql nvarchar(max) = N'''',
            @dbColl sysname = CONVERT(sysname, DATABASEPROPERTYEX(DB_NAME(), ''Collation''));
    IF @src IS NULL OR @Table NOT IN (N''Ci'', N''CiLink'', N''CiFinding'', N''CiService'', N''CiRecord'', N''CiFindingState'', N''CiRelation'', N''Asset'', N''AssetIdentifier'', N''AssetTag'') RETURN;
    DECLARE @cols TABLE (ColumnId int NOT NULL, Name sysname NOT NULL, TypeText nvarchar(300) NOT NULL, Nullable bit NOT NULL);
    INSERT @cols (ColumnId, Name, TypeText, Nullable)
    SELECT c.column_id, c.name,
           CASE WHEN t.name IN (N''nvarchar'', N''nchar'') THEN t.name + N''('' + CASE WHEN c.max_length = -1 THEN N''max'' ELSE CONVERT(nvarchar(10), c.max_length / 2) END + N'')''
                WHEN t.name IN (N''varchar'', N''char'', N''varbinary'', N''binary'') THEN t.name + N''('' + CASE WHEN c.max_length = -1 THEN N''max'' ELSE CONVERT(nvarchar(10), c.max_length) END + N'')''
                WHEN t.name IN (N''decimal'', N''numeric'') THEN t.name + N''('' + CONVERT(nvarchar(5), c.precision) + N'', '' + CONVERT(nvarchar(5), c.scale) + N'')''
                WHEN t.name IN (N''datetime2'', N''time'', N''datetimeoffset'') THEN t.name + N''('' + CONVERT(nvarchar(5), c.scale) + N'')''
                ELSE t.name END
           + CASE WHEN c.collation_name IS NOT NULL AND c.collation_name <> @dbColl THEN N'' COLLATE '' + c.collation_name ELSE N'''' END,
           c.is_nullable
    FROM sys.columns AS c JOIN sys.types AS t ON t.user_type_id = c.user_type_id
    WHERE c.object_id = @src AND c.is_computed = 0 AND t.name NOT IN (N''timestamp'', N''rowversion'');
    SET @pub = OBJECT_ID(N''sidata.'' + @pubName);
    IF @pub IS NULL
    BEGIN
        SELECT @sql = N''CREATE TABLE sidata.'' + QUOTENAME(@pubName) + N'' ('' + STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(Name) + N'' '' + TypeText + CASE WHEN Nullable = 1 THEN N'' NULL'' ELSE N'' NOT NULL'' END), N'', '') WITHIN GROUP (ORDER BY ColumnId) + N'');''
        FROM @cols;
        EXEC (@sql);
        SET @pub = OBJECT_ID(N''sidata.'' + @pubName);
    END
    -- a source without a unique key of its own (no unique index without an identity column): its copy keeps a hash of each
    -- row''s content (RowHash, indexed), by which the run refills only what changed
    IF (SELECT COUNT(*) FROM sys.indexes AS i WHERE i.object_id = @src AND i.is_unique = 1 AND i.type IN (1, 2) AND i.has_filter = 0
                   AND NOT EXISTS (SELECT 1 FROM sys.index_columns AS ic JOIN sys.columns AS x ON x.object_id = ic.object_id AND x.column_id = ic.column_id
                                   WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND x.is_identity = 1)) = 0
    BEGIN
        IF COL_LENGTH(N''sidata.'' + @pubName, N''RowHash'') IS NULL
        BEGIN
            SET @sql = N''ALTER TABLE sidata.'' + QUOTENAME(@pubName) + N'' ADD RowHash varbinary(32) NULL;'';
            EXEC (@sql);
        END
        IF (SELECT COUNT(*) FROM sys.indexes WHERE object_id = @pub AND name = N''IX_PublishedCopy_RowHash'') = 0
        BEGIN
            SET @sql = N''CREATE INDEX IX_PublishedCopy_RowHash ON sidata.'' + QUOTENAME(@pubName) + N'' (RowHash);'';
            EXEC (@sql);
        END
    END    -- the columns the source gained since (always nullable: the copy is filled from the source), then the indexes the copy
    -- does not have yet (the clustered one first) -- one statement at a time
    DECLARE @todo TABLE (N int IDENTITY(1, 1) NOT NULL, Stmt nvarchar(max) NOT NULL);
    INSERT @todo (Stmt)
    SELECT N''ALTER TABLE sidata.'' + QUOTENAME(@pubName) + N'' ADD '' + QUOTENAME(k.Name) + N'' '' + k.TypeText + N'' NULL;''
    FROM @cols AS k WHERE NOT EXISTS (SELECT 1 FROM sys.columns AS p WHERE p.object_id = @pub AND p.name = k.Name)
    ORDER BY k.ColumnId;
    DECLARE @i int = 1, @n int = (SELECT COUNT(*) FROM @todo);
    WHILE @i <= @n BEGIN SELECT @sql = Stmt FROM @todo WHERE N = @i; EXEC (@sql); SET @i += 1; END
    INSERT @todo (Stmt)
    SELECT N''CREATE '' + CASE WHEN i.is_unique = 1 THEN N''UNIQUE '' ELSE N'''' END + CASE WHEN i.type = 1 THEN N''CLUSTERED'' ELSE N''NONCLUSTERED'' END
           + N'' INDEX '' + QUOTENAME(i.name) + N'' ON sidata.'' + QUOTENAME(@pubName) + N'' ('' + k.Keys + N'')''
           + ISNULL(N'' INCLUDE ('' + inc.Incl + N'')'', N'''') + ISNULL(N'' WHERE '' + i.filter_definition, N'''') + N'';''
    FROM sys.indexes AS i
    CROSS APPLY (SELECT STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(c.name) + CASE WHEN ic.is_descending_key = 1 THEN N'' DESC'' ELSE N'''' END), N'', '') WITHIN GROUP (ORDER BY ic.key_ordinal) AS Keys
                 FROM sys.index_columns AS ic JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                 WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0) AS k
    OUTER APPLY (SELECT STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(c.name)), N'', '') WITHIN GROUP (ORDER BY ic.index_column_id) AS Incl
                 FROM sys.index_columns AS ic JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                 WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 1) AS inc
    WHERE i.object_id = @src AND i.type IN (1, 2) AND i.name IS NOT NULL AND i.is_hypothetical = 0
      AND NOT EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id = @pub AND x.name = i.name)
      AND NOT (i.type = 1 AND EXISTS (SELECT 1 FROM sys.indexes AS y WHERE y.object_id = @pub AND y.type = 1))
    ORDER BY i.type, i.index_id;
    SELECT @n = (SELECT MAX(N) FROM @todo);
    WHILE @i <= @n BEGIN SELECT @sql = Stmt FROM @todo WHERE N = @i; EXEC (@sql); SET @i += 1; END
END';
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyEnsure @Table sysname
AS
' + @SIPubEnsure);
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyFill @Table sysname, @Rows bigint = NULL OUTPUT
AS
BEGIN
    -- an EMPTY published copy takes its source''s rows, every column both have (kept for callers of earlier releases; the
    -- publisher refreshes the copies itself, sidata.PublishedCopyRefreshAll, in the transaction that moves the pointer). A copy that
    -- holds rows already, or that the schema apply has not created, is left as it is (@Rows NULL).
    SET NOCOUNT ON;
    DECLARE @src int = OBJECT_ID(N''sidata.'' + @Table), @pubName sysname = @Table + N''Pub'', @pub int, @cols nvarchar(max), @sql nvarchar(max), @has int = 0;
    SET @Rows = NULL;
    SET @pub = OBJECT_ID(N''sidata.'' + @pubName);
    IF @src IS NULL OR @pub IS NULL RETURN;
    SET @sql = N''SELECT @h = CASE WHEN EXISTS (SELECT 1 FROM sidata.'' + QUOTENAME(@pubName) + N'') THEN 1 ELSE 0 END;'';
    EXEC sp_executesql @sql, N''@h int OUTPUT'', @h = @has OUTPUT;
    IF @has = 1 RETURN;
    SELECT @cols = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(c.name)), N'', '') WITHIN GROUP (ORDER BY c.column_id)
    FROM sys.columns AS c
    WHERE c.object_id = @src AND c.is_computed = 0 AND EXISTS (SELECT 1 FROM sys.columns AS p WHERE p.object_id = @pub AND p.name = c.name);
    SET @sql = N''INSERT sidata.'' + QUOTENAME(@pubName) + N'' WITH (TABLOCK) ('' + @cols + N'') SELECT '' + @cols + N'' FROM sidata.'' + QUOTENAME(@Table) + N''; SET @r = @@ROWCOUNT;'';
    EXEC sp_executesql @sql, N''@r bigint OUTPUT'', @r = @Rows OUTPUT;
END');
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyFillAll @Copied int = NULL OUTPUT
AS
BEGIN
    -- every EMPTY published copy takes its source''s rows (the CIs, their links, findings, services, records, lifecycle and
    -- relations; the assets, their identifiers and tags); answers how many tables were copied and keeps the figures
    SET NOCOUNT ON;
    DECLARE @t TABLE (N int NOT NULL, Name sysname NOT NULL);
    INSERT @t (N, Name) VALUES (1, N''Ci''), (2, N''CiLink''), (3, N''CiFinding''), (4, N''CiService''), (5, N''CiRecord''), (6, N''CiFindingState''),
                               (7, N''CiRelation''), (8, N''Asset''), (9, N''AssetIdentifier''), (10, N''AssetTag'');
    DECLARE @i int = 1, @name sysname, @rows bigint, @at datetime2(3);
    SET @Copied = 0;
    WHILE @i <= 10
    BEGIN
        SELECT @name = Name FROM @t WHERE N = @i;
        SET @at = SYSUTCDATETIME();
        EXEC sidata.PublishedCopyFill @Table = @name, @Rows = @rows OUTPUT;
        IF @rows IS NOT NULL
        BEGIN
            SET @Copied += 1;
            MERGE sidata.PublishedCopy AS x
            USING (SELECT @name AS TableName) AS s ON x.TableName = s.TableName
            WHEN MATCHED THEN UPDATE SET [Rows] = @rows, Milliseconds = DATEDIFF(MILLISECOND, @at, SYSUTCDATETIME()), CopiedAt = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN INSERT (TableName, [Rows], Milliseconds) VALUES (@name, @rows, DATEDIFF(MILLISECOND, @at, SYSUTCDATETIME()));
        END
        SET @i += 1;
    END
END');
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyEnsureAll
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sidata.PublishedCopyEnsure @Table = N''Ci'';
    EXEC sidata.PublishedCopyEnsure @Table = N''CiLink'';
    EXEC sidata.PublishedCopyEnsure @Table = N''CiFinding'';
    EXEC sidata.PublishedCopyEnsure @Table = N''CiService'';
    EXEC sidata.PublishedCopyEnsure @Table = N''CiRecord'';
    EXEC sidata.PublishedCopyEnsure @Table = N''CiFindingState'';
    EXEC sidata.PublishedCopyEnsure @Table = N''CiRelation'';
    EXEC sidata.PublishedCopyEnsure @Table = N''Asset'';
    EXEC sidata.PublishedCopyEnsure @Table = N''AssetIdentifier'';
    EXEC sidata.PublishedCopyEnsure @Table = N''AssetTag'';
END');
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyRefreshRange @Table sysname, @HasFrom bit = 0, @From nvarchar(max) = NULL, @Size int = 10000,
    @HasTo bit = 0, @To nvarchar(max) = NULL, @Count int = 0,
    @Next nvarchar(max) = NULL OUTPUT, @Done bit = NULL OUTPUT, @Rows bigint = NULL OUTPUT
AS
BEGIN
    -- #881 ONE KEY RANGE OF ONE PUBLISHED COPY (sidata.<Table>Pub) made equal to its source, in its OWN short transaction when
    -- the caller holds none (live 2026-10-22, the largest tenant: the refresh of every copy as ONE statement per table in the
    -- publishing transaction ran 20+ minutes at the log-rate governor and held the pipeline''s start). The range goes by the
    -- first column of the table''s unique key that is not an identity (else of its clustered index): @HasFrom = 0 is the first
    -- range (with the rows that have no value there), then @From = the @Next of the range before (as text); @Size values of
    -- the column per range (the caller sizes it from the measured time of the range before). @Done = 1: this was the last
    -- range (open upwards). @Rows = the rows written; NULL = the copy or its source is not there (nothing refreshed).
    -- @HasTo = 1: the range ends at @To (the engine''s driver works out the bounds first and runs the ranges AT ONCE, each on
    -- its own connection). @Count > 0: nothing is written -- the next @Count bounds after @From, @Size values apart, come
    -- back as one result set (K, the bound as text); fewer than @Count = the column ends before (the last range is open).
    -- WRITES ONLY WHAT CHANGED, as before: by the key (gone rows removed, a changed content written whole, a time the run only
    -- moved -- CollectionTime / UpdatedAt / SeenAt / LastSeen / BuiltAt -- written alone, new rows added), else by the hash of
    -- each row''s content (RowHash: the CI links, the findings per CI). ONE REFRESHER at a time: the caller holds the
    -- session lock si-published-copy-refresh (sidata.PublishedCopyRefreshAll; the engine''s driver on a connection of its
    -- own) -- the ranges of one refresh never overlap, so they may run at once.
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51792, N''only a job identity may refresh the published copies -- nothing was changed'', 1;
    SELECT @Next = NULL, @Done = 1, @Rows = NULL;
    IF @Table NOT IN (N''Ci'', N''CiLink'', N''CiFinding'', N''CiService'', N''CiRecord'', N''CiFindingState'', N''CiRelation'', N''Asset'', N''AssetIdentifier'', N''AssetTag'') RETURN;
    DECLARE @src int = OBJECT_ID(N''sidata.'' + @Table), @pub int = OBJECT_ID(N''sidata.'' + @Table + N''Pub''), @kid int = NULL, @cx int = NULL,
            @S nvarchar(300) = N''sidata.'' + QUOTENAME(@Table), @P nvarchar(300) = N''sidata.'' + QUOTENAME(@Table + N''Pub''),
            @own bit = CASE WHEN @@TRANCOUNT = 0 THEN 1 ELSE 0 END,
            @lead sysname = NULL, @lt nvarchar(300) = NULL, @ls nvarchar(4) = N''0'', @z int = CASE WHEN ISNULL(@Size, 0) < 1 THEN 1 ELSE @Size END,
            @cnt bigint = 0, @hiText nvarchar(max) = NULL, @last bit = 0, @rng nvarchar(max) = N''1 = 1'', @rs nvarchar(max), @rp nvarchar(max), @pre nvarchar(max) = N'''',
            @cols nvarchar(max), @scols nvarchar(max), @on nvarchar(max), @cmpS nvarchar(max), @cmpP nvarchar(max), @set nvarchar(max),
            @volS nvarchar(max), @volP nvarchar(max), @volSet nvarchar(max), @hx nvarchar(max), @volAgg nvarchar(max), @volDiff nvarchar(max),
            @sql nvarchar(max), @r bigint = 0;
    IF @src IS NULL OR @pub IS NULL RETURN;
    DECLARE @vol TABLE (Name sysname NOT NULL PRIMARY KEY);
    INSERT @vol (Name) VALUES (N''CollectionTime''), (N''UpdatedAt''), (N''SeenAt''), (N''LastSeen''), (N''BuiltAt'');
    DECLARE @c TABLE (Name sysname NOT NULL, ColumnId int NOT NULL, IsKey bit NOT NULL, IsVol bit NOT NULL, IsIdent bit NOT NULL, TypeName sysname NOT NULL);
    -- every column both have (the schema apply keeps the copy''s columns in step with its source)
    SELECT TOP (1) @kid = i.index_id FROM sys.indexes AS i
    WHERE i.object_id = @src AND i.is_unique = 1 AND i.type IN (1, 2) AND i.has_filter = 0
      AND NOT EXISTS (SELECT 1 FROM sys.index_columns AS ic JOIN sys.columns AS x ON x.object_id = ic.object_id AND x.column_id = ic.column_id
                      WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND x.is_identity = 1)
    ORDER BY i.is_primary_key DESC, i.index_id;
    SELECT @cx = index_id FROM sys.indexes WHERE object_id = @src AND type = 1;
    INSERT @c (Name, ColumnId, IsKey, IsVol, IsIdent, TypeName)
    SELECT c.name, c.column_id,
           CASE WHEN EXISTS (SELECT 1 FROM sys.index_columns AS ic WHERE ic.object_id = @src AND ic.index_id = @kid AND ic.column_id = c.column_id AND ic.is_included_column = 0) THEN 1 ELSE 0 END,
           CASE WHEN EXISTS (SELECT 1 FROM @vol AS v WHERE v.Name = c.name) THEN 1 ELSE 0 END,
           c.is_identity, TYPE_NAME(c.user_type_id)
    FROM sys.columns AS c
    WHERE c.object_id = @src AND c.is_computed = 0 AND EXISTS (SELECT 1 FROM sys.columns AS p WHERE p.object_id = @pub AND p.name = c.name);
    SELECT @cols = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(Name)), N'', '') WITHIN GROUP (ORDER BY ColumnId),
           @scols = STRING_AGG(CONVERT(nvarchar(max), N''s.'' + QUOTENAME(Name)), N'', '') WITHIN GROUP (ORDER BY ColumnId) FROM @c;
    -- the column the ranges go by: the key''s first column, else the clustered index''s (the copy has the same indexes)
    SELECT TOP (1) @lead = c.name,
           @lt = CASE WHEN t.name IN (N''nvarchar'', N''nchar'') THEN t.name + N''('' + CASE WHEN c.max_length = -1 THEN N''max'' ELSE CONVERT(nvarchar(10), c.max_length / 2) END + N'')''
                      WHEN t.name IN (N''varchar'', N''char'', N''varbinary'', N''binary'') THEN t.name + N''('' + CASE WHEN c.max_length = -1 THEN N''max'' ELSE CONVERT(nvarchar(10), c.max_length) END + N'')''
                      WHEN t.name IN (N''decimal'', N''numeric'') THEN t.name + N''('' + CONVERT(nvarchar(5), c.precision) + N'', '' + CONVERT(nvarchar(5), c.scale) + N'')''
                      WHEN t.name IN (N''datetime2'', N''time'', N''datetimeoffset'') THEN t.name + N''('' + CONVERT(nvarchar(5), c.scale) + N'')''
                      ELSE t.name END,
           @ls = CASE WHEN t.name IN (N''binary'', N''varbinary'') THEN N''1''
                      WHEN t.name IN (N''datetime2'', N''datetime'', N''smalldatetime'', N''date'', N''time'', N''datetimeoffset'') THEN N''126'' ELSE N''0'' END
    FROM sys.index_columns AS ic
    JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
    JOIN sys.types AS t ON t.user_type_id = c.user_type_id
    WHERE ic.object_id = @src AND ic.index_id = ISNULL(@kid, @cx) AND ic.key_ordinal = 1 AND c.max_length <> -1
      AND EXISTS (SELECT 1 FROM @c AS k WHERE k.Name = c.name);
    IF @Count > 0
    BEGIN
        -- the bounds only: every @Size-th value after @From, @Count of them (a read; nothing written)
        IF @lead IS NULL BEGIN SELECT CAST(NULL AS nvarchar(max)) AS K WHERE 1 = 0; RETURN; END
        SET @sql = N''DECLARE @lo '' + @lt + N'' = CONVERT('' + @lt + N'', @f, '' + @ls + N''); ''
                 + N''SELECT CONVERT(nvarchar(max), t.k, '' + @ls + N'') AS K FROM (SELECT x.k, ROW_NUMBER() OVER (ORDER BY x.k) AS rn FROM (SELECT TOP (CONVERT(bigint, @z) * @c) s.''
                 + QUOTENAME(@lead) + N'' AS k FROM '' + @S + N'' AS s WHERE s.'' + QUOTENAME(@lead) + N'' IS NOT NULL''
                 + CASE WHEN @HasFrom = 1 THEN N'' AND s.'' + QUOTENAME(@lead) + N'' > @lo'' ELSE N'''' END + N'' ORDER BY s.'' + QUOTENAME(@lead) + N'') AS x) AS t''
                 + N'' WHERE t.rn % @z = 0 ORDER BY t.rn;'';
        EXEC sp_executesql @sql, N''@f nvarchar(max), @z int, @c int'', @f = @From, @z = @z, @c = @Count;
        RETURN;
    END
    IF @lead IS NULL SET @last = 1;
    ELSE IF @HasTo = 1
    BEGIN
        -- the bound the caller worked out
        SELECT @hiText = @To, @last = 0;
        SET @rng = CASE WHEN @HasFrom = 1 THEN N''~.'' + QUOTENAME(@lead) + N'' > @lo AND ~.'' + QUOTENAME(@lead) + N'' <= @hi''
                        ELSE N''(~.'' + QUOTENAME(@lead) + N'' <= @hi OR ~.'' + QUOTENAME(@lead) + N'' IS NULL)'' END;
        SET @pre = N''DECLARE @lo '' + @lt + N'' = CONVERT('' + @lt + N'', @f, '' + @ls + N''), @hi '' + @lt + N'' = CONVERT('' + @lt + N'', @t, '' + @ls + N''); '';
    END
    ELSE
    BEGIN
        -- this range''s upper bound: the @Size-th value of the column after @From (a seek); fewer left = the last range, open upwards
        SET @sql = N''DECLARE @lo '' + @lt + N'' = CONVERT('' + @lt + N'', @f, '' + @ls + N''); ''
                 + N''SELECT @n = COUNT_BIG(*), @h = CONVERT(nvarchar(max), MAX(t.k), '' + @ls + N'') FROM (SELECT TOP (@z) s.'' + QUOTENAME(@lead) + N'' AS k FROM '' + @S
                 + N'' AS s WHERE s.'' + QUOTENAME(@lead) + N'' IS NOT NULL'' + CASE WHEN @HasFrom = 1 THEN N'' AND s.'' + QUOTENAME(@lead) + N'' > @lo'' ELSE N'''' END
                 + N'' ORDER BY s.'' + QUOTENAME(@lead) + N'') AS t;'';
        EXEC sp_executesql @sql, N''@f nvarchar(max), @z int, @n bigint OUTPUT, @h nvarchar(max) OUTPUT'', @f = @From, @z = @z, @n = @cnt OUTPUT, @h = @hiText OUTPUT;
        IF @cnt < @z SELECT @last = 1, @hiText = NULL;
        -- the range on either side (~ = the alias): the first one has no lower bound and takes the rows without a value too
        SET @rng = CASE WHEN @HasFrom = 1 AND @last = 0 THEN N''~.'' + QUOTENAME(@lead) + N'' > @lo AND ~.'' + QUOTENAME(@lead) + N'' <= @hi''
                        WHEN @HasFrom = 1 THEN N''~.'' + QUOTENAME(@lead) + N'' > @lo''
                        WHEN @last = 0 THEN N''(~.'' + QUOTENAME(@lead) + N'' <= @hi OR ~.'' + QUOTENAME(@lead) + N'' IS NULL)''
                        ELSE N''1 = 1'' END;
        SET @pre = N''DECLARE @lo '' + @lt + N'' = CONVERT('' + @lt + N'', @f, '' + @ls + N''), @hi '' + @lt + N'' = CONVERT('' + @lt + N'', @t, '' + @ls + N''); '';
    END
    SELECT @rs = REPLACE(@rng, N''~.'', N''s.''), @rp = REPLACE(@rng, N''~.'', N''p.'');
    IF @kid IS NULL AND COL_LENGTH(N''sidata.'' + @Table + N''Pub'', N''RowHash'') IS NOT NULL
    BEGIN
        -- no key (the CI links; the findings per CI, written anew by every data sync with new ids): rows are told by a hash of
        -- their content (the copy keeps it in RowHash). Rows whose content is no longer there go, rows whose content is new
        -- come, the times a run only moved are written alone -- a finding seen again is not rewritten.
        SELECT @hx = N''HASHBYTES(N''''SHA2_256'''', CONVERT(nvarchar(max), N'''''''')'' + STRING_AGG(CONVERT(nvarchar(max), N'' + ISNULL(''
               + CASE WHEN TypeName IN (N''float'', N''real'') THEN N''CONVERT(nvarchar(64), s.'' + QUOTENAME(Name) + N'', 3)''
                      WHEN TypeName IN (N''datetime2'', N''datetime'', N''smalldatetime'', N''date'', N''time'', N''datetimeoffset'') THEN N''CONVERT(nvarchar(64), s.'' + QUOTENAME(Name) + N'', 126)''
                      WHEN TypeName IN (N''binary'', N''varbinary'') THEN N''CONVERT(nvarchar(max), s.'' + QUOTENAME(Name) + N'', 1)''
                      ELSE N''CONVERT(nvarchar(max), s.'' + QUOTENAME(Name) + N'')'' END
               + N'', N''''~'''') + N''''|''''''), N'''') WITHIN GROUP (ORDER BY ColumnId) + N'')''
        FROM @c WHERE IsIdent = 0 AND IsVol = 0;
        SELECT @volAgg = STRING_AGG(CONVERT(nvarchar(max), N''MAX(s.'' + QUOTENAME(Name) + N'') AS '' + QUOTENAME(Name)), N'', ''),
               @volSet = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(Name) + N'' = h.'' + QUOTENAME(Name)), N'', ''),
               @volDiff = STRING_AGG(CONVERT(nvarchar(max), N''EXISTS (SELECT h.'' + QUOTENAME(Name) + N'' EXCEPT SELECT p.'' + QUOTENAME(Name) + N'')''), N'' OR '')
        FROM @c WHERE IsIdent = 0 AND IsVol = 1;
        SET @sql = @pre + N''DECLARE @n bigint = 0; ''
                 -- the range''s contents in the source: each hash, how often, and the newest of the times a run moves
                 + N''SELECT '' + @hx + N'' AS H, COUNT_BIG(*) AS N'' + ISNULL(N'', '' + @volAgg, N'''') + N'' INTO #h FROM '' + @S + N'' AS s WHERE '' + @rs + N'' GROUP BY '' + @hx + N''; ''
                 + N''CREATE UNIQUE CLUSTERED INDEX CX_h ON #h (H); ''
                 + N''SELECT p.RowHash AS H, COUNT_BIG(*) AS N INTO #p FROM '' + @P + N'' AS p WHERE '' + @rp + N'' AND p.RowHash IS NOT NULL GROUP BY p.RowHash; ''
                 -- the contents to take anew: not in the copy, or not as often
                 + N''SELECT h.H INTO #m FROM #h AS h LEFT JOIN #p AS q ON q.H = h.H WHERE q.H IS NULL OR q.N <> h.N; ''
                 + N''DELETE p FROM '' + @P + N'' AS p WHERE '' + @rp + N'' AND (p.RowHash IS NULL OR NOT EXISTS (SELECT 1 FROM #h AS h WHERE h.H = p.RowHash) OR EXISTS (SELECT 1 FROM #m AS m WHERE m.H = p.RowHash)); SET @n += @@ROWCOUNT; ''
                 + N''INSERT '' + @P + N'' ('' + @cols + N'', RowHash) SELECT '' + @scols + N'', z.H FROM '' + @S
                 + N'' AS s CROSS APPLY (SELECT '' + @hx + N'' AS H) AS z JOIN #m AS m ON m.H = z.H WHERE '' + @rs + N''; SET @n += @@ROWCOUNT; ''
                 + CASE WHEN @volSet IS NULL THEN N'''' ELSE N''UPDATE p SET '' + @volSet + N'' FROM '' + @P + N'' AS p JOIN #h AS h ON h.H = p.RowHash WHERE '' + @rp + N'' AND ('' + @volDiff + N''); SET @n += @@ROWCOUNT; '' END
                 + N''SET @r = @n;'';
    END
    ELSE IF @kid IS NULL
        -- neither a key nor a hash: the range emptied and filled again
        SET @sql = @pre + N''DECLARE @n bigint = 0; DELETE p FROM '' + @P + N'' AS p WHERE '' + @rp + N''; SET @n += @@ROWCOUNT; INSERT '' + @P + N'' ('' + @cols
                 + N'') SELECT '' + @scols + N'' FROM '' + @S + N'' AS s WHERE '' + @rs + N''; SET @n += @@ROWCOUNT; SET @r = @n;'';
    ELSE
    BEGIN
        SELECT @on = STRING_AGG(CONVERT(nvarchar(max), N''p.'' + QUOTENAME(Name) + N'' = s.'' + QUOTENAME(Name)), N'' AND '') FROM @c WHERE IsKey = 1;
        SELECT @cmpS = STRING_AGG(CONVERT(nvarchar(max), N''s.'' + QUOTENAME(Name)), N'', '') WITHIN GROUP (ORDER BY ColumnId),
               @cmpP = STRING_AGG(CONVERT(nvarchar(max), N''p.'' + QUOTENAME(Name)), N'', '') WITHIN GROUP (ORDER BY ColumnId),
               @set = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(Name) + N'' = s.'' + QUOTENAME(Name)), N'', '') FROM @c WHERE IsKey = 0 AND IsVol = 0;
        SELECT @volS = STRING_AGG(CONVERT(nvarchar(max), N''s.'' + QUOTENAME(Name)), N'', '') WITHIN GROUP (ORDER BY ColumnId),
               @volP = STRING_AGG(CONVERT(nvarchar(max), N''p.'' + QUOTENAME(Name)), N'', '') WITHIN GROUP (ORDER BY ColumnId),
               @volSet = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(Name) + N'' = s.'' + QUOTENAME(Name)), N'', '') FROM @c WHERE IsKey = 0 AND IsVol = 1;
        SET @sql = @pre + N''DECLARE @n bigint = 0; ''
                 + N''DELETE p FROM '' + @P + N'' AS p WHERE '' + @rp + N'' AND NOT EXISTS (SELECT 1 FROM '' + @S + N'' AS s WHERE '' + @on + N''); SET @n += @@ROWCOUNT; ''
                 + CASE WHEN @set IS NULL THEN N'''' ELSE N''UPDATE p SET '' + @set + ISNULL(N'', '' + @volSet, N'''') + N'' FROM '' + @P + N'' AS p JOIN '' + @S
                      + N'' AS s ON '' + @on + N'' WHERE '' + @rs + N'' AND EXISTS (SELECT '' + @cmpS + N'' EXCEPT SELECT '' + @cmpP + N''); SET @n += @@ROWCOUNT; '' END
                 + CASE WHEN @volSet IS NULL THEN N'''' ELSE N''UPDATE p SET '' + @volSet + N'' FROM '' + @P + N'' AS p JOIN '' + @S
                      + N'' AS s ON '' + @on + N'' WHERE '' + @rs + N'' AND EXISTS (SELECT '' + @volS + N'' EXCEPT SELECT '' + @volP + N''); SET @n += @@ROWCOUNT; '' END
                 + N''INSERT '' + @P + N'' ('' + @cols + N'') SELECT '' + @scols + N'' FROM '' + @S + N'' AS s WHERE '' + @rs + N'' AND NOT EXISTS (SELECT 1 FROM ''
                 + @P + N'' AS p WHERE '' + @on + N''); SET @n += @@ROWCOUNT; SET @r = @n;'';
    END
    -- 2026-10-25 A SOURCE THAT KEEPS ITS OWN CONTENT HASH (sidata.CiFinding.ContentHash: the data only, not what every run
    -- moves): the copy''s RowHash IS that hash, and the rows are matched one to one by it and their place among rows with the
    -- same hash (H, Rn). A matched row keeps its row; its identity, CollectionTime and document are written from its source
    -- row where they differ (binary). The copy then holds exactly the source''s rows. A range with a source row whose hash is
    -- not known (NULL) is refreshed as before.
    IF @kid IS NULL AND COL_LENGTH(N''sidata.'' + @Table + N''Pub'', N''RowHash'') IS NOT NULL AND COL_LENGTH(N''sidata.'' + @Table, N''ContentHash'') IS NOT NULL
       AND COL_LENGTH(N''sidata.'' + @Table + N''Pub'', N''ContentHash'') IS NOT NULL AND EXISTS (SELECT 1 FROM @c WHERE IsIdent = 1)
    BEGIN
        DECLARE @idc nvarchar(300) = (SELECT TOP (1) QUOTENAME(Name) FROM @c WHERE IsIdent = 1 ORDER BY ColumnId), @rq nvarchar(max) = REPLACE(@rng, N''~.'', N''q.''),
                @cvSet nvarchar(max), @cvDiff nvarchar(max), @oldBody nvarchar(max);
        SELECT @cvSet = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(Name) + N'' = s.'' + QUOTENAME(Name)), N'', ''),
               @cvDiff = STRING_AGG(CONVERT(nvarchar(max), N''ISNULL(DATALENGTH(s.'' + QUOTENAME(Name) + N''), -1) <> ISNULL(DATALENGTH(p.'' + QUOTENAME(Name) + N''), -1) OR CAST(s.''
                         + QUOTENAME(Name) + N'' AS varbinary(max)) <> CAST(p.'' + QUOTENAME(Name) + N'' AS varbinary(max))''), N'' OR '')
        FROM @c WHERE IsIdent = 1 OR Name IN (N''CollectionTime'', N''DocJson'');
        SET @oldBody = SUBSTRING(@sql, DATALENGTH(@pre) / 2 + 1, 2147483647);
        SET @sql = @pre + N''IF EXISTS (SELECT 1 FROM '' + @S + N'' AS s WHERE '' + @rs + N'' AND s.ContentHash IS NULL) BEGIN '' + @oldBody + N'' END ELSE BEGIN ''
                 + N''DECLARE @m bigint = 0; ''
                 + N''SELECT s.'' + @idc + N'' AS SId, s.ContentHash AS H, ROW_NUMBER() OVER (PARTITION BY s.ContentHash ORDER BY s.'' + @idc + N'') AS Rn INTO #ch FROM '' + @S + N'' AS s WHERE '' + @rs + N''; ''
                 + N''CREATE UNIQUE CLUSTERED INDEX CX_ch ON #ch (H, Rn); ''
                 -- the copy''s rows without a match (no hash, a hash no longer there, or more often than in the source) go
                 + N'';WITH p AS (SELECT q.RowHash, ROW_NUMBER() OVER (PARTITION BY q.RowHash ORDER BY q.'' + @idc + N'') AS Rn FROM '' + @P + N'' AS q WHERE '' + @rq + N'') ''
                 + N''DELETE FROM p WHERE p.RowHash IS NULL OR NOT EXISTS (SELECT 1 FROM #ch AS h WHERE h.H = p.RowHash AND h.Rn = p.Rn); SET @m += @@ROWCOUNT; ''
                 -- a matched row: what the run moves, from its source row, only where it differs
                 + N'';WITH p AS (SELECT q.*, ROW_NUMBER() OVER (PARTITION BY q.RowHash ORDER BY q.'' + @idc + N'') AS Rn FROM '' + @P + N'' AS q WHERE '' + @rq + N'') ''
                 + N''UPDATE p SET '' + @cvSet + N'' FROM p JOIN #ch AS h ON h.H = p.RowHash AND h.Rn = p.Rn JOIN '' + @S + N'' AS s ON s.'' + @idc + N'' = h.SId WHERE '' + @cvDiff + N''; SET @m += @@ROWCOUNT; ''
                 -- the source rows the copy does not hold yet (as often as the source has them)
                 + N''INSERT '' + @P + N'' ('' + @cols + N'', RowHash) SELECT '' + @scols + N'', s.ContentHash FROM '' + @S + N'' AS s JOIN #ch AS h ON h.SId = s.'' + @idc
                 + N'' WHERE '' + @rs + N'' AND h.Rn > (SELECT COUNT_BIG(*) FROM '' + @P + N'' AS q WHERE '' + @rq + N'' AND q.RowHash = h.H); SET @m += @@ROWCOUNT; ''
                 + N''DROP TABLE #ch; SET @r = @m; END'';
    END
    IF @own = 1 BEGIN TRANSACTION;
    EXEC sp_executesql @sql, N''@f nvarchar(max), @t nvarchar(max), @r bigint OUTPUT'', @f = @From, @t = @hiText, @r = @r OUTPUT;
    IF @own = 1 COMMIT TRANSACTION;
    SELECT @Rows = ISNULL(@r, 0), @Next = @hiText, @Done = @last;
END');
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyRefreshAll @Copied int = NULL OUTPUT
AS
BEGIN
    -- THE ONE REFRESH OF THE PUBLISHED COPIES (sidata.<Table>Pub) from their sources, for the callers in the database (the
    -- catch-up sidata.PublishedCopyCatchUp, and through it the publisher sidata.PublishedRunSet once its pointer is committed)
    -- -- never a second copy implementation: every range is sidata.PublishedCopyRefreshRange, which the engine''s own driver
    -- (engine\_shared\data-sql\SI-DataPublishedRun.ps1, with a progress line per table) calls too. Answers how many of the ten
    -- tables were refreshed (10 = every copy equals its source) and keeps the figures per copy (sidata.PublishedCopy). No
    -- result set (the publisher may run inside INSERT ... EXEC).
    -- #881 IN KEY RANGES (live 2026-10-22: one statement per table in the publishing transaction, 20+ minutes at the log-rate
    -- governor at the largest tenant): range after range, each its own short transaction when this runs outside one; the
    -- next range sized from the measured time of the one before (about two seconds each, at most double the last).
    SET NOCOUNT ON;
    SET @Copied = 0;
    -- ONE REFRESHER at a time (the ranges of one refresh never overlap): another one running = nothing done here, nothing
    -- claimed -- the next catch-up refreshes
    DECLARE @l int;
    EXEC @l = sp_getapplock @Resource = N''si-published-copy-refresh'', @LockMode = N''Exclusive'', @LockOwner = N''Session'', @LockTimeout = 0;
    IF @l < 0 RETURN;
    DECLARE @t TABLE (N int NOT NULL, Name sysname NOT NULL);
    INSERT @t (N, Name) VALUES (1, N''Ci''), (2, N''CiLink''), (3, N''CiFinding''), (4, N''CiService''), (5, N''CiRecord''), (6, N''CiFindingState''),
                               (7, N''CiRelation''), (8, N''Asset''), (9, N''AssetIdentifier''), (10, N''AssetTag'');
    DECLARE @i int = 1, @name sysname, @has bit, @from nvarchar(max), @next nvarchar(max), @done bit, @r bigint, @rows bigint, @ok bit,
            @at datetime2(3), @b datetime2(3), @ms bigint, @size bigint, @target bigint = 2000;
    BEGIN TRY
    WHILE @i <= 10
    BEGIN
        SELECT @name = Name FROM @t WHERE N = @i;
        SELECT @has = 0, @from = NULL, @done = 0, @rows = 0, @ok = 1, @size = 10000, @at = SYSUTCDATETIME();
        WHILE @done = 0
        BEGIN
            SET @b = SYSUTCDATETIME();
            EXEC sidata.PublishedCopyRefreshRange @Table = @name, @HasFrom = @has, @From = @from, @Size = @size, @Next = @next OUTPUT, @Done = @done OUTPUT, @Rows = @r OUTPUT;
            IF @r IS NULL BEGIN SET @ok = 0; BREAK; END
            SET @rows += @r;
            SET @ms = DATEDIFF_BIG(MILLISECOND, @b, SYSUTCDATETIME());
            SET @size = CASE WHEN @ms <= 0 THEN 2 * @size WHEN @size * @target / @ms > 2 * @size THEN 2 * @size ELSE @size * @target / @ms END;
            IF @size < 1 SET @size = 1;
            IF @size > 2147483647 SET @size = 2147483647;
            SELECT @has = 1, @from = @next;
        END
        IF @ok = 1
        BEGIN
            MERGE sidata.PublishedCopy AS x
            USING (SELECT @name AS TableName) AS s ON x.TableName = s.TableName
            WHEN MATCHED THEN UPDATE SET [Rows] = @rows, Milliseconds = DATEDIFF(MILLISECOND, @at, SYSUTCDATETIME()), CopiedAt = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN INSERT (TableName, [Rows], Milliseconds) VALUES (@name, @rows, DATEDIFF(MILLISECOND, @at, SYSUTCDATETIME()));
            SET @Copied += 1;
        END
        SET @i += 1;
    END
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 AND @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        EXEC sp_releaseapplock @Resource = N''si-published-copy-refresh'', @LockOwner = N''Session'';
        THROW;
    END CATCH
    EXEC sp_releaseapplock @Resource = N''si-published-copy-refresh'', @LockOwner = N''Session'';
END');
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedCopyCatchUp @WhatIf bit = 0, @Stale bit = NULL OUTPUT, @Refreshed bit = NULL OUTPUT,
    @PublishedAt datetime2(0) = NULL OUTPUT, @CopiedAt datetime2(0) = NULL OUTPUT, @MarkFor datetime2(0) = NULL
AS
BEGIN
    -- THE SHOWN RUN''S COPIES CAUGHT UP. A published run whose copies were never filled (CopiedAt NULL) or are OLDER than its
    -- publish (CopiedAt < PublishedAt: every publish leaves them so -- #881, the copies are refreshed AFTER the pointer moved,
    -- range by range, never in the publishing transaction) is refreshed now from the source, only what changed
    -- (sidata.PublishedCopyRefreshAll: key ranges, each its own short transaction when this runs outside one), and then
    -- claimed (CopiedAt) under the publisher''s lock -- only for the publish the refresh was for (PublishedAt as it was when
    -- the refresh began: a publish meanwhile is caught up by the next call). Run by the publisher itself, the pipeline runner
    -- and the update. Idempotent: copies as new as the publish = nothing done. @WhatIf = 1: only says whether they are stale.
    -- @MarkFor (the engine refreshed the copies itself, range by range, for the publish of that PublishedAt --
    -- SI-DataPublishedRun.ps1): only the claim.
    -- Answers through its OUTPUT parameters only (no result set); @CopiedAt is the copies'' time as found (before a refresh).
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51791, N''only a job identity may refresh the published copies -- nothing was changed'', 1;
    DECLARE @own bit, @lock int, @copied int = 0, @for datetime2(0);
    SELECT @Stale = 0, @Refreshed = 0, @PublishedAt = NULL, @CopiedAt = NULL;
    SELECT @PublishedAt = PublishedAt, @CopiedAt = CopiedAt, @Stale = CASE WHEN CopiedAt IS NULL OR CopiedAt < PublishedAt THEN 1 ELSE 0 END
    FROM sidata.PublishedRun WHERE Name = N''current'' AND DetailedCollectionId IS NOT NULL;
    IF @Stale = 0 OR @WhatIf = 1 RETURN;
    IF @MarkFor IS NULL SELECT @for = @PublishedAt;
    ELSE SELECT @copied = 10, @for = @MarkFor;
    IF @MarkFor IS NULL EXEC sidata.PublishedCopyRefreshAll @Copied = @copied OUTPUT;
    IF @copied = 10
    BEGIN
        SET @own = CASE WHEN @@TRANCOUNT = 0 THEN 1 ELSE 0 END;
        IF @own = 1 BEGIN TRANSACTION;
        EXEC @lock = sp_getapplock @Resource = N''sidata.PublishedRun'', @LockMode = N''Exclusive'', @LockOwner = N''Transaction'', @LockTimeout = 60000;
        IF @lock >= 0
        BEGIN
            UPDATE sidata.PublishedRun SET CopiedAt = SYSUTCDATETIME() WHERE Name = N''current'' AND DetailedCollectionId IS NOT NULL AND PublishedAt = @for;
            IF @@ROWCOUNT > 0 SELECT @Refreshed = 1, @Stale = 0;
        END
        IF @own = 1 COMMIT TRANSACTION;
    END
END');
-- the copies made / brought up to date by the schema apply itself: the same body as sidata.PublishedCopyEnsureAll, run without
-- EXECUTE on the procedures
DECLARE @SIPubTable sysname;
DECLARE SIPubCopies CURSOR LOCAL FAST_FORWARD FOR
    SELECT v FROM (VALUES (N'Ci'), (N'CiLink'), (N'CiFinding'), (N'CiService'), (N'CiRecord'), (N'CiFindingState'), (N'CiRelation'), (N'Asset'), (N'AssetIdentifier'), (N'AssetTag')) AS x(v);
OPEN SIPubCopies;
FETCH NEXT FROM SIPubCopies INTO @SIPubTable;
WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC sp_executesql @SIPubEnsure, N'@Table sysname', @Table = @SIPubTable;
    FETCH NEXT FROM SIPubCopies INTO @SIPubTable;
END
CLOSE SIPubCopies;
DEALLOCATE SIPubCopies;

IF OBJECT_ID('sidata.vCiPub') IS NULL
EXEC ('CREATE VIEW sidata.vCiPub AS
SELECT a.AssetKey, a.AssetName, a.AssetKind, a.Tier, a.KeySource,
       (SELECT STRING_AGG(CAST(i.IdentifierType + N'':'' + i.IdentifierValue AS NVARCHAR(MAX)), N''; '')
          FROM sidata.AssetIdentifierPub i WHERE i.AssetKey = a.AssetKey) AS Identifiers,
       a.FirstSeen, a.LastSeen
FROM sidata.AssetPub a');

IF OBJECT_ID('sidata.vCiRelationPub') IS NULL
EXEC ('CREATE VIEW sidata.vCiRelationPub AS
SELECT r.FromCiId AS CiId, N''out'' AS Direction, r.Kind, r.ToCiId AS OtherCiId, r.ToType, r.ToValue, r.Detail, r.Source, r.Confidence, r.State,
       r.FirstSeen, r.LastSeen, r.GoneAt, r.FromCiId, r.ToCiId
FROM sidata.CiRelationPub AS r
UNION ALL
SELECT r.ToCiId AS CiId, N''in'' AS Direction, r.Kind, r.FromCiId AS OtherCiId, N''ci'' AS ToType, r.FromCiId AS ToValue, r.Detail, r.Source, r.Confidence, r.State,
       r.FirstSeen, r.LastSeen, r.GoneAt, r.FromCiId, r.ToCiId
FROM sidata.CiRelationPub AS r
WHERE r.ToCiId IS NOT NULL');

IF OBJECT_ID('sidata.vCiUnownedPub') IS NULL
EXEC ('CREATE VIEW sidata.vCiUnownedPub AS
SELECT c.CiId, c.Name, c.Class, c.AssetType, c.Tier, c.Lifecycle, c.WeightedRiskScore, c.OpenFindings, c.LastSeen
FROM sidata.CiPub AS c
WHERE ISNULL(c.Lifecycle, N'''') <> N''retired''
  AND NOT EXISTS (SELECT 1 FROM sidata.CiServicePub AS s WHERE s.CiId = c.CiId)');
IF OBJECT_ID('sidata.vCiFindingModelPub') IS NULL
EXEC ('CREATE VIEW sidata.vCiFindingModelPub AS
SELECT s.OwnerKey, s.FindingKey, s.CiId, c.Name AS CiName, c.Class, c.Tier, s.FindingType, s.Title, s.Severity, s.State,
       CASE WHEN s.ExemptionId IS NOT NULL AND (s.ExemptedUntil IS NULL OR s.ExemptedUntil > SYSUTCDATETIME()) AND s.State <> N''closed'' THEN N''exempted''
            WHEN s.State = N''closed'' AND s.CloseReason = N''remediated'' THEN N''fixed''
            ELSE s.State END AS Status,
       s.FirstDetected, s.LastSeen, s.ClosedAt, s.CloseReason, s.ReopenedAt, s.ReopenCount, s.DetectedBy,
       s.Owner, s.OwnerSource, s.ServiceKeys, s.ServiceCriticality, s.SlaDays, s.DueAt,
       CASE WHEN s.DueAt IS NOT NULL AND s.DueAt < SYSUTCDATETIME() AND s.State <> N''closed'' AND s.Excluded = 0
                 AND NOT (s.ExemptionId IS NOT NULL AND (s.ExemptedUntil IS NULL OR s.ExemptedUntil > SYSUTCDATETIME())) THEN 1 ELSE 0 END AS Overdue,
       s.ExemptionId, s.ExemptionReason, s.ExemptedUntil, s.TicketState, s.TicketClosedAt, s.TicketCloseReason, s.Excluded
FROM sidata.CiFindingStatePub AS s
LEFT JOIN sidata.CiPub AS c ON c.CiId = s.CiId');

IF OBJECT_ID('sidata.vServiceCiPub') IS NULL
EXEC ('CREATE VIEW sidata.vServiceCiPub AS
SELECT sv.ServiceKey, sv.ServiceName, sv.Source, sv.MatchedBy, sv.Strictest, sv.Criticality, sv.Owner, c.CiId, c.Name, c.Class, c.AssetType, c.Tier, c.Lifecycle,
       c.RiskScore, c.WeightedRiskScore,
       ISNULL(f.OpenFindings, 0) AS OpenFindings, ISNULL(f.Overdue, 0) AS OverdueFindings, ISNULL(f.Critical, 0) AS OpenCritical, ISNULL(f.High, 0) AS OpenHigh
FROM sidata.CiServicePub AS sv
JOIN sidata.CiPub AS c ON c.CiId = sv.CiId
OUTER APPLY (SELECT COUNT(*) AS OpenFindings,
                    SUM(CASE WHEN m.Overdue = 1 THEN 1 ELSE 0 END) AS Overdue,
                    SUM(CASE WHEN LOWER(m.Severity) IN (N''critical'', N''very high'') THEN 1 ELSE 0 END) AS Critical,
                    SUM(CASE WHEN LOWER(m.Severity) = N''high'' THEN 1 ELSE 0 END) AS High
             FROM sidata.vCiFindingModelPub AS m
             WHERE m.CiId = sv.CiId AND m.Status IN (N''open'', N''reopened'') AND m.Excluded = 0) AS f');

IF OBJECT_ID('sidata.vServiceFindingPub') IS NULL
EXEC ('CREATE VIEW sidata.vServiceFindingPub AS
SELECT sv.ServiceKey, sv.ServiceName, m.*
FROM sidata.CiServicePub AS sv
JOIN sidata.vCiFindingModelPub AS m ON m.CiId = sv.CiId');

IF OBJECT_ID('sidata.vCiDailyPub') IS NULL
EXEC ('CREATE VIEW sidata.vCiDailyPub AS
SELECT d.* FROM sidata.CiDaily AS d
WHERE d.[Day] <= ISNULL((SELECT CONVERT(date, p.CopiedAt) FROM sidata.PublishedRun AS p WHERE p.Name = N''current''), d.[Day])');

IF OBJECT_ID('sidata.vAssetMetadataPub') IS NULL
EXEC ('CREATE VIEW sidata.vAssetMetadataPub AS
SELECT m.* FROM sidata.AssetMetadata AS m
WHERE m.CollectionTime <= ISNULL((SELECT CONVERT(datetime2(3), p.CopiedAt) FROM sidata.PublishedRun AS p WHERE p.Name = N''current''), m.CollectionTime)');

-- #901 A COLLECTION WHOSE ONLY INCOMPLETENESS IS REPORTS SI DELIBERATELY HELD (owner: "a report fails alone, the job
-- completes ... we use last known good data"): 1 when Risk Analysis judged it per report (RaPartialScope 'reports'), EVERY
-- NotComplete Detailed report of it carries a HoldKind (a silent source #900, an incomplete role read #899 -- never a #877
-- hold-back, a lost slice or a report that failed), every such report was carried by the data sync, and each carry has a
-- last complete result (FromCollectionId). Anything else -- or an older schema without the column -- is 0: partial as before.
IF COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NOT NULL
EXEC (N'CREATE OR ALTER FUNCTION sidata.CollectionHeldOnly (@cid INT) RETURNS BIT
AS
BEGIN
    DECLARE @t DATETIME2(3), @scope NVARCHAR(16);
    SELECT @t = CollectionTime, @scope = RaPartialScope FROM sidata.Collection WHERE CollectionId = @cid;
    IF @t IS NULL OR ISNULL(@scope, N'''') <> N''reports'' RETURN 0;
    IF NOT EXISTS (SELECT 1 FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = N''Detailed'' AND State = N''NotComplete'') RETURN 0;
    IF EXISTS (SELECT 1 FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = N''Detailed'' AND State = N''NotComplete''
               AND (NULLIF(HoldKind, N'''') IS NULL OR HeldRaReport IS NOT NULL)) RETURN 0;
    IF EXISTS (SELECT 1 FROM sidata.RaReportStatus AS s WHERE s.CollectionTime = @t AND s.Grain = N''Detailed'' AND s.State = N''NotComplete''
               AND NOT EXISTS (SELECT 1 FROM sidata.CollectionReportCarry AS rc WHERE rc.CollectionId = @cid AND rc.ReportName = s.ReportName AND rc.FromCollectionId IS NOT NULL)) RETURN 0;
    IF EXISTS (SELECT 1 FROM sidata.CollectionReportCarry AS rc WHERE rc.CollectionId = @cid
               AND NOT EXISTS (SELECT 1 FROM sidata.RaReportStatus AS s WHERE s.CollectionTime = @t AND s.Grain = N''Detailed'' AND s.ReportName = rc.ReportName
                               AND s.State = N''NotComplete'' AND NULLIF(s.HoldKind, N'''') IS NOT NULL)) RETURN 0;
    RETURN 1;
END');

-- THE PUBLISHER. One call = one decision, in one transaction under one application lock (two publishers never interleave):
-- the pointer moves to the run's own complete result, or it stays and the reason is answered (and, for a pipeline run,
-- kept as the 'refused' row). @Source 'run' (the pipeline runner, only for a run of the whole pipeline in which every step
-- that ran succeeded): the run's OWN Risk Analysis Detailed collection (taken between @RunStartedUtc and @RunEndedUtc) is
-- complete, not retired, not empty, its view data and day totals are written; no report of it fell back to an earlier result
-- (sidata.CollectionPartial, sidata.CollectionReportCarry, Collection.RaPartialScope) unless @AllowPartial; for each grain
-- in @Grains (the Risk Analysis steps that ran) the run wrote its executive view and (Summary) its summary is loaded
-- complete; with @NeedCiBuild the build of the merged assets finished in this run. @Source 'schedules' / 'update': the
-- newest collection that meets the same rules (for 'schedules', newer than the published one; 'update' only when nothing
-- is published), its executive views and summary only when they belong to it -- what is missing is said in the note.
-- @RefuseWhy (the runner, for a run of the whole pipeline that did not end trusted): nothing is checked; the reason is kept.
-- When it publishes, it catches up the published copies of the CIs and assets itself right after its commit, range by range
-- (sidata.PublishedCopyCatchUp, #881) -- so EVERY path that publishes moves the CI pages too (2026-10-21: a hand publish moved
-- the pointer only, and the asset pages kept a copy from before the CI lifecycle). Inside a caller's transaction (the runner's
-- INSERT ... EXEC) the caller catches up.
-- Answers ONE row: Published, Reason, CollectionId, CollectionTime, Partial.
EXEC (N'CREATE OR ALTER PROCEDURE sidata.PublishedRunSet
    @Source NVARCHAR(16) = N''run'', @FlowRunId NVARCHAR(64) = NULL, @RunStartedUtc DATETIME2(3) = NULL, @RunEndedUtc DATETIME2(3) = NULL,
    @SolutionVersion NVARCHAR(64) = NULL, @Grains NVARCHAR(64) = N''Detailed,Summary'', @NeedCiBuild BIT = 0, @AllowPartial BIT = 0,
    @SnapshotKeepDays INT = 90, @RefuseWhy NVARCHAR(400) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51790, N''only a job identity may publish a run -- nothing was published'', 1;
    DECLARE @why NVARCHAR(400) = NULL, @note NVARCHAR(400) = N'''', @cid INT = NULL, @ct DATETIME2(3) = NULL, @loaded DATETIME2(0) = NULL,
            @sct DATETIME2(3) = NULL, @evd BIGINT = NULL, @evs BIGINT = NULL, @cib NVARCHAR(64) = NULL, @cit DATETIME2(3) = NULL,
            @partial BIT = 0, @prevTime DATETIME2(3) = NULL, @hasPrev BIT = 0, @lock INT, @copied INT = 0, @cft DATETIME2(3) = NULL,
            @needD BIT = CASE WHEN N'','' + ISNULL(@Grains, N'''') + N'','' LIKE N''%,Detailed,%'' THEN 1 ELSE 0 END,
            @needS BIT = CASE WHEN N'','' + ISNULL(@Grains, N'''') + N'','' LIKE N''%,Summary,%'' THEN 1 ELSE 0 END,
            @own BIT = CASE WHEN @@TRANCOUNT = 0 THEN 1 ELSE 0 END, @now DATETIME2(0) = SYSUTCDATETIME();
    IF @own = 1 BEGIN TRANSACTION;
    EXEC @lock = sp_getapplock @Resource = N''sidata.PublishedRun'', @LockMode = N''Exclusive'', @LockOwner = N''Transaction'', @LockTimeout = 60000;
    IF @lock < 0 SET @why = N''another publish was running'';
    -- a pipeline run that did not end trusted (a failed, stopped or cancelled run): only its reason is kept
    IF @why IS NULL AND NULLIF(@RefuseWhy, N'''') IS NOT NULL SET @why = LEFT(@RefuseWhy, 400);
    SELECT @prevTime = DetailedCollectionTime, @hasPrev = 1 FROM sidata.PublishedRun WHERE Name = N''current'' AND DetailedCollectionId IS NOT NULL;
    IF @why IS NULL AND @Source NOT IN (N''run'', N''schedules'', N''update'') SET @why = N''unknown source'';
    IF @why IS NULL AND @Source = N''run'' AND @RunStartedUtc IS NULL SET @why = N''the run has no start time'';
    IF @why IS NULL AND @Source = N''update'' AND @hasPrev = 1 SET @why = N''a run is already published'';
    IF @why IS NULL AND @Source = N''run''
    BEGIN
        -- the run''s OWN collection, whatever its state: what is wrong with it is said
        SELECT TOP (1) @cid = c.CollectionId, @ct = c.CollectionTime, @loaded = c.LoadedAt
        FROM sidata.Collection AS c
        WHERE c.Kind = N''Detailed'' AND c.CollectionTime >= @RunStartedUtc AND (@RunEndedUtc IS NULL OR c.CollectionTime <= @RunEndedUtc)
        ORDER BY c.CollectionTime DESC;
        IF @cid IS NULL SET @why = N''the run stored no Risk Analysis collection of its own'';
        ELSE IF NOT EXISTS (SELECT 1 FROM sidata.Collection WHERE CollectionId = @cid AND Status = N''Complete'' AND RetiredAt IS NULL) SET @why = N''the run''''s collection is not complete'';
        ELSE IF NOT EXISTS (SELECT 1 FROM sidata.Collection WHERE CollectionId = @cid AND [Rows] > 0) SET @why = N''the run''''s collection is empty'';
        ELSE IF NOT EXISTS (SELECT 1 FROM sidata.Collection WHERE CollectionId = @cid AND ViewsReadyAt IS NOT NULL) SET @why = N''the view data of the run''''s collection is not written'';
        ELSE IF NOT EXISTS (SELECT 1 FROM sidata.FindingDaily WHERE CollectionId = @cid) SET @why = N''the day totals of the run''''s collection are not written'';
    END
    ELSE IF @why IS NULL
    BEGIN
        SELECT TOP (1) @cid = c.CollectionId, @ct = c.CollectionTime, @loaded = c.LoadedAt
        FROM sidata.Collection AS c
        WHERE c.Kind = N''Detailed'' AND c.Status = N''Complete'' AND c.RetiredAt IS NULL AND c.[Rows] > 0 AND c.ViewsReadyAt IS NOT NULL
          AND EXISTS (SELECT 1 FROM sidata.FindingDaily AS d WHERE d.CollectionId = c.CollectionId)
          AND (@Source = N''update'' OR @prevTime IS NULL OR c.CollectionTime > @prevTime)
          AND (@AllowPartial = 1 OR sidata.CollectionHeldOnly(c.CollectionId) = 1 OR (c.RaPartialScope IS NULL
               AND NOT EXISTS (SELECT 1 FROM sidata.CollectionPartial AS cp WHERE cp.CollectionId = c.CollectionId)
               AND NOT EXISTS (SELECT 1 FROM sidata.CollectionReportCarry AS rc WHERE rc.CollectionId = c.CollectionId)))
        ORDER BY c.CollectionTime DESC;
        IF @cid IS NULL SET @why = CASE WHEN @Source = N''update'' THEN N''no complete collection with its view data written yet'' ELSE N''no newer complete collection'' END;
    END
    -- a report that fell back to an earlier result: the run is partial (strict unless @AllowPartial) -- #901: unless EVERY
    -- such report was DELIBERATELY held at its last complete result (sidata.CollectionHeldOnly): then the run publishes, and
    -- the note names the held reports (never a silent publish)
    IF @why IS NULL AND (EXISTS (SELECT 1 FROM sidata.CollectionPartial WHERE CollectionId = @cid)
                         OR EXISTS (SELECT 1 FROM sidata.CollectionReportCarry WHERE CollectionId = @cid)
                         OR EXISTS (SELECT 1 FROM sidata.Collection WHERE CollectionId = @cid AND RaPartialScope IS NOT NULL))
    BEGIN
        DECLARE @inc NVARCHAR(400) = NULL, @incN INT = 0;
        SELECT @incN = COUNT(*), @inc = LEFT(STRING_AGG(CONVERT(NVARCHAR(MAX), s.ReportName), N'', '') WITHIN GROUP (ORDER BY s.ReportName), 300)
        FROM sidata.RaReportStatus AS s JOIN sidata.Collection AS c ON c.CollectionTime = s.CollectionTime AND c.CollectionId = @cid
        WHERE s.Grain = N''Detailed'' AND s.State = N''NotComplete'';
        IF sidata.CollectionHeldOnly(@cid) = 1
            SET @note = @note + CONVERT(NVARCHAR(10), @incN) + N'' report(s) held at their last complete result: '' + ISNULL(@inc, N'''') + N''; '';
        ELSE
        BEGIN
            SET @partial = 1;
            IF @AllowPartial = 0 SET @why = N''a report of the run fell back to an earlier result'' + ISNULL(N'' ('' + @inc + N'')'', N'''') + N'' -- the last complete run stays shown'';
        END
    END
    -- the executive views this run wrote (a pipeline run: written since it started; otherwise: of this very collection)
    IF @why IS NULL AND @needD = 1
       AND NOT EXISTS (SELECT 1 FROM sidata.RiskExecView WHERE Grain = N''Detailed''
                       AND ((@Source = N''run'' AND GeneratedAt >= @RunStartedUtc) OR (@Source <> N''run'' AND CollectionTime = @ct)))
    BEGIN
        IF @Source = N''run'' SET @why = N''the run wrote no executive view (Detailed)'';
        ELSE SET @note = @note + N''no executive view (Detailed) of this collection; '';
    END
    IF @why IS NULL AND @needS = 1
    BEGIN
        SELECT TOP (1) @sct = l.CollectionTime FROM sidata.SummaryLoad AS l
        WHERE l.Status = N''Complete'' AND l.RetiredAt IS NULL
          AND ((@Source = N''run'' AND l.CollectionTime >= @RunStartedUtc AND (@RunEndedUtc IS NULL OR l.CollectionTime <= @RunEndedUtc))
               OR (@Source <> N''run'' AND l.CollectionTime <= ISNULL(CONVERT(datetime2(3), @loaded), @ct)))
        ORDER BY l.CollectionTime DESC;
        IF @sct IS NULL AND @Source = N''run'' SET @why = N''the run''''s Risk Analysis summary is not loaded completely'';
        ELSE IF @sct IS NULL SET @note = @note + N''no complete summary; '';
        IF @why IS NULL AND NOT EXISTS (SELECT 1 FROM sidata.RiskExecView WHERE Grain = N''Summary''
                       AND ((@Source = N''run'' AND GeneratedAt >= @RunStartedUtc) OR (@Source <> N''run'' AND @sct IS NOT NULL AND CollectionTime = @sct)))
        BEGIN
            IF @Source = N''run'' SET @why = N''the run wrote no executive view (Summary)'';
            ELSE SET @note = @note + N''no executive view (Summary) of this run; '';
        END
    END
    -- the build of the merged assets of this run
    IF @why IS NULL
    BEGIN
        SELECT @cib = LEFT(Value, 64) FROM sidata.CiBuildState WHERE Name = N''LastBuildStart'';
        SELECT @cit = MAX(CollectionTime) FROM sidata.Ci;
        IF @NeedCiBuild = 1 AND NOT EXISTS (SELECT 1 FROM sidata.CiBuildState WHERE Name = N''LastBuildStatus'' AND Value IN (N''ok'', N''partial''))
            SET @why = N''the build of the merged assets did not finish'';
        ELSE IF @NeedCiBuild = 1 AND ISNULL(CONVERT(datetime2(3), SWITCHOFFSET(TRY_CONVERT(datetimeoffset(7), @cib), 0)), ''19000101'') < @RunStartedUtc
            SET @why = N''the run did not build the merged assets'';
    END
    IF @why IS NULL
    BEGIN
        -- copies of the executive views as this run wrote them (never changed afterwards)
        IF @needD = 1
        BEGIN
            INSERT sidata.RiskExecViewSnapshot (Grain, GeneratedAt, CollectionTime, ReportTemplate, Mode, Leader, FiguresFromGrain, PayloadJson)
            SELECT Grain, GeneratedAt, CollectionTime, ReportTemplate, Mode, Leader, FiguresFromGrain, PayloadJson FROM sidata.RiskExecView
            WHERE Grain = N''Detailed'' AND ((@Source = N''run'' AND GeneratedAt >= @RunStartedUtc) OR (@Source <> N''run'' AND CollectionTime = @ct));
            IF @@ROWCOUNT > 0 SET @evd = SCOPE_IDENTITY();
        END
        IF @needS = 1
        BEGIN
            INSERT sidata.RiskExecViewSnapshot (Grain, GeneratedAt, CollectionTime, ReportTemplate, Mode, Leader, FiguresFromGrain, PayloadJson)
            SELECT Grain, GeneratedAt, CollectionTime, ReportTemplate, Mode, Leader, FiguresFromGrain, PayloadJson FROM sidata.RiskExecView
            WHERE Grain = N''Summary'' AND ((@Source = N''run'' AND GeneratedAt >= @RunStartedUtc) OR (@Source <> N''run'' AND @sct IS NOT NULL AND CollectionTime = @sct));
            IF @@ROWCOUNT > 0 SET @evs = SCOPE_IDENTITY();
        END
        IF @Source <> N''run'' SET @note = CASE @Source WHEN N''update'' THEN N''set by the update from the newest complete collection; '' ELSE N''set from the newest complete collection (jobs on their own schedules); '' END + @note;
        IF @partial = 1 SET @note = @note + N''a report fell back to an earlier result (allowed by SI_Pro_PublishPartialRun); '';
        -- review S2: the findings per CI (sidata.CiFinding) are the run''s only when they carry its Detailed collection''s time.
        -- When their part of the data sync failed they are still an earlier collection''s: the run is published (its new
        -- findings are right and are shown) but PARTIAL, and CiFindingTime says as of when the findings per CI are -- the CI
        -- pages never present that copy as current. (Data out and ServiceNow are held by the data sync itself.)
        IF OBJECT_ID(N''sidata.CiFinding'') IS NOT NULL SELECT @cft = MAX(CollectionTime) FROM sidata.CiFinding;
        IF @cft IS NOT NULL AND @ct IS NOT NULL AND @cft <> @ct
        BEGIN
            SET @partial = 1;
            SET @note = @note + N''the findings per CI are as of '' + CONVERT(nvarchar(19), @cft, 126) + N'', not this run (their part of the data sync failed); '';
        END
        ELSE SET @cft = NULL;
        MERGE sidata.PublishedRun AS t
        USING (SELECT N''current'' AS Name) AS s ON t.Name = s.Name
        WHEN MATCHED THEN UPDATE SET DetailedCollectionId = @cid, DetailedCollectionTime = @ct, SummaryCollectionTime = @sct, ExecViewDetailedId = @evd,
            ExecViewSummaryId = @evs, CiBuildStart = @cib, CiCollectionTime = @cit, FlowRunId = @FlowRunId, RunStartedUtc = @RunStartedUtc,
            RunEndedUtc = @RunEndedUtc, SolutionVersion = @SolutionVersion, Source = @Source, [Partial] = @partial, CiFindingTime = @cft,
            Note = NULLIF(LEFT(RTRIM(@note), 400), N''''), PublishedAt = @now,
            -- #881 the copies stay what they were (older than this publish: stale) until every range is refreshed; a copy
            -- claimed within this very second is moved a second back, so it reads stale (the times are whole seconds)
            CopiedAt = CASE WHEN t.CopiedAt >= @now THEN DATEADD(SECOND, -1, @now) ELSE t.CopiedAt END
        WHEN NOT MATCHED THEN INSERT (Name, DetailedCollectionId, DetailedCollectionTime, SummaryCollectionTime, ExecViewDetailedId, ExecViewSummaryId,
            CiBuildStart, CiCollectionTime, FlowRunId, RunStartedUtc, RunEndedUtc, SolutionVersion, Source, [Partial], CiFindingTime, Note)
            VALUES (N''current'', @cid, @ct, @sct, @evd, @evs, @cib, @cit, @FlowRunId, @RunStartedUtc, @RunEndedUtc, @SolutionVersion, @Source, @partial,
                    @cft, NULLIF(LEFT(RTRIM(@note), 400), N''''));
        -- #881 the published copies of the CIs and assets are NOT refreshed in this transaction any more (one statement per
        -- table over every row ran 20+ minutes at the log-rate governor at the largest tenant and held the pipeline''s start):
        -- CopiedAt stays as it was (older than this publish = stale), and the copies are caught up right after the commit
        -- below, range by range -- by this procedure when it owns its transaction, else by its caller (the runner''s batch
        -- runs it inside INSERT ... EXEC; the engine''s driver then refreshes, SI-DataPublishedRun.ps1). CopiedAt moves only
        -- when every range of every copy is done.
    END
    ELSE IF @Source = N''run'' AND @lock >= 0
    BEGIN
        MERGE sidata.PublishedRun AS t
        USING (SELECT N''refused'' AS Name) AS s ON t.Name = s.Name
        WHEN MATCHED THEN UPDATE SET DetailedCollectionId = @cid, DetailedCollectionTime = @ct, FlowRunId = @FlowRunId, RunStartedUtc = @RunStartedUtc,
            RunEndedUtc = @RunEndedUtc, SolutionVersion = @SolutionVersion, Source = @Source, [Partial] = @partial, Note = LEFT(@why, 400), PublishedAt = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (Name, DetailedCollectionId, DetailedCollectionTime, FlowRunId, RunStartedUtc, RunEndedUtc, SolutionVersion, Source, [Partial], Note)
            VALUES (N''refused'', @cid, @ct, @FlowRunId, @RunStartedUtc, @RunEndedUtc, @SolutionVersion, @Source, @partial, LEFT(@why, 400));
    END
    IF @own = 1 COMMIT TRANSACTION;
    -- whoever publishes (the run, the schedules, the update, a hand publish) moves the CI pages too: the copies caught up now,
    -- each range its own short transaction (sidata.PublishedCopyCatchUp). A refresh that fails leaves the publish as it is and
    -- the copies stale (CopiedAt older than the publish) -- the next catch-up refreshes them
    IF @own = 1 AND @why IS NULL
    BEGIN
        DECLARE @cs bit, @cr bit, @cp datetime2(0), @cc datetime2(0);
        BEGIN TRY
            EXEC sidata.PublishedCopyCatchUp @Stale = @cs OUTPUT, @Refreshed = @cr OUTPUT, @PublishedAt = @cp OUTPUT, @CopiedAt = @cc OUTPUT;
        END TRY
        BEGIN CATCH
            IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        END CATCH
    END
    SELECT CONVERT(bit, CASE WHEN @why IS NULL THEN 1 ELSE 0 END) AS Published, COALESCE(@why, NULLIF(RTRIM(@note), N'''')) AS Reason,
           @cid AS CollectionId, @ct AS CollectionTime, @partial AS [Partial];
END');

-- the publisher checks its caller itself (a job identity: db_datawriter / si_engine, or the owner) -- so every job identity
-- may call it, before and after the engine's least-privilege cut-over (the product's gated-procedure pattern)
IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::sidata.PublishedRunSet TO public;
-- the catch-up of stale copies, gated the same way: the pipeline runner (the engine) and the update's own step (the updater:
-- db_datawriter) call it
IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::sidata.PublishedCopyCatchUp TO public;
-- #881 one key range of one copy (the engine's driver runs the ranges at once, each on its own connection): gated the same way
IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::sidata.PublishedCopyRefreshRange TO public;
-- EXISTING INSTALLS: an install with complete data and no published run yet is published once by the PIPELINE RUNNER's
-- next wake-up after the update (engine\flow\Invoke-SIJobFlowRun.ps1, Source 'update': the newest complete collection
-- that meets the rules, its CI and asset copies filled in the same transaction). An install whose shown run is newer than
-- its copies (CopiedAt < PublishedAt) is caught up by the update's step 9g (setup\Invoke-SIContainerUpdate.ps1) and by
-- every wake-up of the runner (sidata.PublishedCopyCatchUp). Never here: the schema runs as the updater's own identity
-- (db_ddladmin, no EXECUTE on the product schemas -- SUP-2026-00204).

-- ---------------------------------------------------------------------------------------------
-- WHAT CHANGED, PRE-COMPUTED PER COLLECTION PAIR (ADDED 2026-10-19, #812 -- a large customer, 1,117,524 finding rows per
-- collection: /Collection/Changes grouped EVERY finding of BOTH collections per request -- twice for the counts -- and
-- joined them). The data sync writes, once per complete Detailed collection (B), its comparison with the previous complete
-- Detailed collection (A, the one the page opens with): engine\pro-data\_shared\SI-DataChanges.ps1 Invoke-SIDataChanges.
--   FindingChange / FindingChangeCounted   one row per finding key that is new, no longer reported or changed (an unchanged
--                                          finding is counted in ChangeCount, not listed); Counted = exempted findings left
--                                          out on both sides (#264), 'exempted' reasons included
--   AssetChange / AssetChangeCounted       one row per CI of either collection (unchanged included)
--   ChangeCount / ChangeCountCounted       the headline: findings and CIs per change
--   ChangeState                            the pair (CollectionId = B, PrevCollectionId = A) and when it was written; no row
--                                          = not yet (the page says the comparison is being prepared, it never compares the
--                                          finding rows itself)
-- Keyed by CollectionId (B). No foreign key: the retention removes a pair when either collection goes. Additive; the next
-- data sync fills every stored complete collection, newest first.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.FindingChange') IS NULL
CREATE TABLE sidata.FindingChange (
    CollectionId     INT            NOT NULL,   -- B: the collection shown
    PrevCollectionId INT            NOT NULL,   -- A: the collection it is compared with
    ChangeKey        NVARCHAR(1800) NOT NULL,   -- asset (key, else name) | issue | report
    Change           NVARCHAR(16)   NOT NULL,   -- new | gone | changed (unchanged is not listed)
    ChangeReason     NVARCHAR(16)   NULL,       -- absent | exempted | NULL
    AssetKey         NVARCHAR(400)  NULL,
    AssetName        NVARCHAR(400)  NULL,
    Issue            NVARCHAR(1000) NULL,
    Title            NVARCHAR(1000) NULL,
    ReportName       NVARCHAR(256)  NULL,
    SeverityBefore   NVARCHAR(30)   NULL,
    SeverityAfter    NVARCHAR(30)   NULL,
    RiskBefore       FLOAT          NULL,
    RiskAfter        FLOAT          NULL,
    RiskDelta        FLOAT          NULL,
    TierBefore       NVARCHAR(12)   NULL,
    TierAfter        NVARCHAR(12)   NULL,
    ChangeRowId      BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_FindingChange PRIMARY KEY CLUSTERED (CollectionId, ChangeRowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingChange_Delta' AND object_id = OBJECT_ID('sidata.FindingChange'))
CREATE INDEX IX_FindingChange_Delta ON sidata.FindingChange (CollectionId, RiskDelta DESC) INCLUDE (Change, TierAfter, SeverityAfter);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingChange_Change' AND object_id = OBJECT_ID('sidata.FindingChange'))
CREATE INDEX IX_FindingChange_Change ON sidata.FindingChange (CollectionId, Change, RiskDelta DESC) INCLUDE (TierAfter, SeverityAfter, ReportName);

IF OBJECT_ID('sidata.FindingChangeCounted') IS NULL
CREATE TABLE sidata.FindingChangeCounted (
    CollectionId     INT            NOT NULL,
    PrevCollectionId INT            NOT NULL,
    ChangeKey        NVARCHAR(1800) NOT NULL,
    Change           NVARCHAR(16)   NOT NULL,
    ChangeReason     NVARCHAR(16)   NULL,
    AssetKey         NVARCHAR(400)  NULL,
    AssetName        NVARCHAR(400)  NULL,
    Issue            NVARCHAR(1000) NULL,
    Title            NVARCHAR(1000) NULL,
    ReportName       NVARCHAR(256)  NULL,
    SeverityBefore   NVARCHAR(30)   NULL,
    SeverityAfter    NVARCHAR(30)   NULL,
    RiskBefore       FLOAT          NULL,
    RiskAfter        FLOAT          NULL,
    RiskDelta        FLOAT          NULL,
    TierBefore       NVARCHAR(12)   NULL,
    TierAfter        NVARCHAR(12)   NULL,
    ChangeRowId      BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_FindingChangeCounted PRIMARY KEY CLUSTERED (CollectionId, ChangeRowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingChangeCounted_Delta' AND object_id = OBJECT_ID('sidata.FindingChangeCounted'))
CREATE INDEX IX_FindingChangeCounted_Delta ON sidata.FindingChangeCounted (CollectionId, RiskDelta DESC) INCLUDE (Change, TierAfter, SeverityAfter);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingChangeCounted_Change' AND object_id = OBJECT_ID('sidata.FindingChangeCounted'))
CREATE INDEX IX_FindingChangeCounted_Change ON sidata.FindingChangeCounted (CollectionId, Change, RiskDelta DESC) INCLUDE (TierAfter, SeverityAfter, ReportName);

IF OBJECT_ID('sidata.AssetChange') IS NULL
CREATE TABLE sidata.AssetChange (
    CollectionId     INT            NOT NULL,
    PrevCollectionId INT            NOT NULL,
    AssetKey         NVARCHAR(400)  NOT NULL,
    AssetName        NVARCHAR(400)  NULL,
    Change           NVARCHAR(16)   NOT NULL,   -- new | gone | changed | unchanged
    FindingsBefore   BIGINT         NULL,
    FindingsAfter    BIGINT         NULL,
    RiskBefore       FLOAT          NULL,
    RiskAfter        FLOAT          NULL,
    RiskDelta        FLOAT          NULL,
    TierBefore       NVARCHAR(12)   NULL,
    TierAfter        NVARCHAR(12)   NULL,
    CONSTRAINT PK_AssetChange PRIMARY KEY CLUSTERED (CollectionId, AssetKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetChange_Delta' AND object_id = OBJECT_ID('sidata.AssetChange'))
CREATE INDEX IX_AssetChange_Delta ON sidata.AssetChange (CollectionId, RiskDelta DESC) INCLUDE (Change, TierAfter);

IF OBJECT_ID('sidata.AssetChangeCounted') IS NULL
CREATE TABLE sidata.AssetChangeCounted (
    CollectionId     INT            NOT NULL,
    PrevCollectionId INT            NOT NULL,
    AssetKey         NVARCHAR(400)  NOT NULL,
    AssetName        NVARCHAR(400)  NULL,
    Change           NVARCHAR(16)   NOT NULL,
    FindingsBefore   BIGINT         NULL,
    FindingsAfter    BIGINT         NULL,
    RiskBefore       FLOAT          NULL,
    RiskAfter        FLOAT          NULL,
    RiskDelta        FLOAT          NULL,
    TierBefore       NVARCHAR(12)   NULL,
    TierAfter        NVARCHAR(12)   NULL,
    CONSTRAINT PK_AssetChangeCounted PRIMARY KEY CLUSTERED (CollectionId, AssetKey)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetChangeCounted_Delta' AND object_id = OBJECT_ID('sidata.AssetChangeCounted'))
CREATE INDEX IX_AssetChangeCounted_Delta ON sidata.AssetChangeCounted (CollectionId, RiskDelta DESC) INCLUDE (Change, TierAfter);
-- #881 the purge of a collection also removes the comparisons that name it as the EARLIER one (PrevCollectionId): without an
-- index that read every comparison row, in the purge's one transaction
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingChange_Prev' AND object_id = OBJECT_ID('sidata.FindingChange'))
CREATE INDEX IX_FindingChange_Prev ON sidata.FindingChange (PrevCollectionId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingChangeCounted_Prev' AND object_id = OBJECT_ID('sidata.FindingChangeCounted'))
CREATE INDEX IX_FindingChangeCounted_Prev ON sidata.FindingChangeCounted (PrevCollectionId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetChange_Prev' AND object_id = OBJECT_ID('sidata.AssetChange'))
CREATE INDEX IX_AssetChange_Prev ON sidata.AssetChange (PrevCollectionId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetChangeCounted_Prev' AND object_id = OBJECT_ID('sidata.AssetChangeCounted'))
CREATE INDEX IX_AssetChangeCounted_Prev ON sidata.AssetChangeCounted (PrevCollectionId);

IF OBJECT_ID('sidata.ChangeCount') IS NULL
CREATE TABLE sidata.ChangeCount (
    CollectionId     INT            NOT NULL,
    PrevCollectionId INT            NOT NULL,
    What             NVARCHAR(16)   NOT NULL,   -- findings | assets
    Change           NVARCHAR(16)   NOT NULL,   -- new | gone | changed | unchanged
    N                BIGINT         NOT NULL,
    CONSTRAINT PK_ChangeCount PRIMARY KEY CLUSTERED (CollectionId, What, Change)
);

IF OBJECT_ID('sidata.ChangeCountCounted') IS NULL
CREATE TABLE sidata.ChangeCountCounted (
    CollectionId     INT            NOT NULL,
    PrevCollectionId INT            NOT NULL,
    What             NVARCHAR(16)   NOT NULL,
    Change           NVARCHAR(16)   NOT NULL,
    N                BIGINT         NOT NULL,
    CONSTRAINT PK_ChangeCountCounted PRIMARY KEY CLUSTERED (CollectionId, What, Change)
);

IF OBJECT_ID('sidata.ChangeState') IS NULL
CREATE TABLE sidata.ChangeState (
    CollectionId     INT            NOT NULL CONSTRAINT PK_ChangeState PRIMARY KEY,
    PrevCollectionId INT            NOT NULL,
    BuiltAt          DATETIME2(0)   NOT NULL,
    FindingRows      BIGINT         NOT NULL,   -- the listed (new / gone / changed) finding rows, every finding
    AssetRows        INT            NOT NULL
);

-- ---------------------------------------------------------------------------------------------
-- THE WALL BOARD'S TOP TIER-0 ASSETS, PRE-COMPUTED PER COLLECTION (ADDED 2026-10-19, #812 -- the wall board grouped every
-- finding of the published collection by asset on each refresh, its tier test served by no index). One row per asset with
-- tier-0 findings: distinct Very High / High CVEs and the total risk score, the asset's own name (ProDataSql.Tier0TopText's
-- shape); Counted = exempted findings left out (#264). State: no row = not yet (the board says the list is being prepared).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.Tier0Asset') IS NULL
CREATE TABLE sidata.Tier0Asset (
    CollectionId   INT            NOT NULL,
    AssetKey       NVARCHAR(400)  NULL,         -- NULL: the tier-0 findings that name no asset (one row, as the page grouped them)
    AssetName      NVARCHAR(400)  NULL,
    AssetKind      NVARCHAR(16)   NULL,
    VeryHigh       INT            NOT NULL,
    High           INT            NOT NULL,
    RiskTotal      FLOAT          NULL,
    Tier0RowId     BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_Tier0Asset PRIMARY KEY CLUSTERED (CollectionId, Tier0RowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Tier0Asset_Top' AND object_id = OBJECT_ID('sidata.Tier0Asset'))
CREATE INDEX IX_Tier0Asset_Top ON sidata.Tier0Asset (CollectionId, VeryHigh DESC, High DESC, RiskTotal DESC) INCLUDE (AssetKey, AssetName, AssetKind);

IF OBJECT_ID('sidata.Tier0AssetCounted') IS NULL
CREATE TABLE sidata.Tier0AssetCounted (
    CollectionId   INT            NOT NULL,
    AssetKey       NVARCHAR(400)  NULL,
    AssetName      NVARCHAR(400)  NULL,
    AssetKind      NVARCHAR(16)   NULL,
    VeryHigh       INT            NOT NULL,
    High           INT            NOT NULL,
    RiskTotal      FLOAT          NULL,
    Tier0RowId     BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_Tier0AssetCounted PRIMARY KEY CLUSTERED (CollectionId, Tier0RowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Tier0AssetCounted_Top' AND object_id = OBJECT_ID('sidata.Tier0AssetCounted'))
CREATE INDEX IX_Tier0AssetCounted_Top ON sidata.Tier0AssetCounted (CollectionId, VeryHigh DESC, High DESC, RiskTotal DESC) INCLUDE (AssetKey, AssetName, AssetKind);

IF OBJECT_ID('sidata.Tier0AssetState') IS NULL
CREATE TABLE sidata.Tier0AssetState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_Tier0AssetState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Assets         INT            NOT NULL,
    CountedAssets  INT            NOT NULL
);


-- ---------------------------------------------------------------------------------------------
-- THE RAW ROWS' OPENING VIEW OFF AN INDEX (ADDED 2026-10-19, #812 -- a large customer, 1,117,524 findings per collection:
-- the first page of Raw rows counted and sorted every finding of the collection before returning 50). The page a view opens
-- with (no filter, no search, a DESC sort on the risk score, the CVSS or the weighted score) reads its keys off these indexes
-- (the clustered FindingId follows the score, so the order is the grid's own tie-break) and computes its rows for those keys
-- only (CollectionViewSql.Rows' GridKeyset); ExemptionId is carried so the exempted-findings-left-out view filters in the index.
-- ---------------------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RiskPage' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_RiskPage ON sidata.Finding (CollectionId, RiskScore DESC) INCLUDE (ExemptionId)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_CvssPage' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_CvssPage ON sidata.Finding (CollectionId, Cvss DESC) INCLUDE (ExemptionId)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_WeightedPage' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_WeightedPage ON sidata.Finding (CollectionId, RiskScoreWeighted DESC) INCLUDE (ExemptionId)');

-- ---------------------------------------------------------------------------------------------
-- REPORTS > OUTPUTS' PREVIEW COUNTS AND THE CI FINDINGS SUMMARY, PRE-COMPUTED (ADDED 2026-10-19, #812 -- a large customer,
-- 1,117,524 findings): the Outputs page grouped every finding of the published collection by report, domain, severity, tier
-- and CVE on each open (SqlReportStore.PreviewSql); Assets (CIs) > Findings per finding key grouped every row of
-- sidata.CiFinding by finding, tier, severity and CMDB group on each request (CiSql.SummarySpec). The data sync writes both
-- once per collection; the pages read them.
--   ReportPreviewCount / ReportPreviewState   the findings per (report, domain, severity, tier, CVE or not); every finding (the
--                                             page has no exempted toggle)
--   CiFindingSummary / CiFindingSummaryState  one row per finding x tier x severity x CMDB group of the CI findings, built
--                                             after the CI build of the run, under the collection the run published
-- No foreign key: the retention removes a collection's rows itself. Additive.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.ReportPreviewCount') IS NULL
CREATE TABLE sidata.ReportPreviewCount (
    CollectionId   INT            NOT NULL,
    RowId          INT            NOT NULL,
    ReportName     NVARCHAR(256)  NULL,
    SecurityDomain NVARCHAR(128)  NULL,
    Severity       NVARCHAR(30)   NULL,
    Tier           TINYINT        NULL,
    IsCve          BIT            NOT NULL,
    Findings       BIGINT         NOT NULL,
    CONSTRAINT PK_ReportPreviewCount PRIMARY KEY CLUSTERED (CollectionId, RowId)
);
IF OBJECT_ID('sidata.ReportPreviewState') IS NULL
CREATE TABLE sidata.ReportPreviewState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_ReportPreviewState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Groups         INT            NOT NULL,
    Findings       BIGINT         NOT NULL
);

IF OBJECT_ID('sidata.CiFindingSummary') IS NULL
CREATE TABLE sidata.CiFindingSummary (
    CollectionId   INT            NOT NULL,
    RowId          INT            NOT NULL,
    RowKey         NVARCHAR(600)  NOT NULL,   -- FindingKey|tier|severity|CMDB id (the grid's key)
    Domain         NVARCHAR(128)  NULL,
    FindingKey     NVARCHAR(256)  NOT NULL,
    Title          NVARCHAR(1000) NULL,
    Tier           TINYINT        NULL,
    Severity       NVARCHAR(16)   NULL,
    CmdbId         NVARCHAR(256)  NULL,
    CmdbName       NVARCHAR(400)  NULL,
    CiCount        BIGINT         NOT NULL,
    MaxRiskScore   FLOAT          NULL,
    WeightedTotal  FLOAT          NULL,
    RiskRating     NVARCHAR(16)   NULL,
    CONSTRAINT PK_CiFindingSummary PRIMARY KEY CLUSTERED (CollectionId, RowId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFindingSummary_Weighted' AND object_id = OBJECT_ID('sidata.CiFindingSummary'))
CREATE INDEX IX_CiFindingSummary_Weighted ON sidata.CiFindingSummary (CollectionId, WeightedTotal DESC) INCLUDE (Tier, Severity, CiCount);
IF OBJECT_ID('sidata.CiFindingSummaryState') IS NULL
CREATE TABLE sidata.CiFindingSummaryState (
    CollectionId   INT            NOT NULL CONSTRAINT PK_CiFindingSummaryState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Groups         INT            NOT NULL,
    CiFindings     BIGINT         NOT NULL    -- the sidata.CiFinding rows the summary was built from
);

-- ---------------------------------------------------------------------------------------------
-- THE FINDINGS BROWSER AND THE PIVOTS, PRE-COMPUTED PER COLLECTION (ADDED 2026-10-19, #812 -- a large customer, 1,117,524
-- finding rows: the findings browser counted and sorted every finding of the collection on each open, its tier x severity x
-- domain pivot grouped every finding with a distinct count of assets, and the Weighted risk score's Pivot tab grouped every
-- finding again for each request and each filter's choice list). The data sync writes once per collection
-- (engine\pro-data\_shared\SI-DataPivots.ps1, Invoke-SIDataFindingPivots):
--   Finding.ImportanceRank      the browser's default order ("most important first": tier, then risk score high -> low,
--                               asset, title -- ProDataSql.Sorts[importance]) as a number per finding of the collection;
--                               IX_Finding_Importance pages it as an index seek (never a sort of every finding)
--   FindingPivotCell            the browser's pivot cells (tier x severity x domain: findings, distinct assets), once over
--                               every report (ByReport = 0) and once per report (ByReport = 1) -- what a tier / severity /
--                               domain / report filter selects exactly; their sums are the browser's totals
--   FindingPivotCellCounted     the same without the exempted findings (#264 twin)
--   PivotCell                   the Weighted risk score pivot's cube: one row per CI x tier x domain x report x severity x
--                               department x CMDB service (ServicePrimary marks ONE row per finding group for the pivots
--                               that name no service field) x exempted-or-not -- findings, risk sum, weighted sum / highest /
--                               count; every pivot whose fields it carries is a GROUP BY over these rows (thousands, not a
--                               million), the distinct assets exact. The CMDB criticality and owner and the department's name
--                               are joined when the pivot is read (they change between data syncs).
--   FindingPivotState           one row per collection: when they were written (no row = not yet: the pages say the list /
--                               the pivot is being prepared -- never the per-request read of every finding)
-- No foreign key: the retention removes a collection's rows here itself. Additive; the next data sync fills every
-- complete collection, newest first. Keyed by CollectionId: whichever collection a page shows is selected by its id.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'ImportanceRank') IS NULL
ALTER TABLE sidata.Finding ADD ImportanceRank BIGINT NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_Importance' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_Importance ON sidata.Finding (CollectionId, ImportanceRank) INCLUDE (Tier, Severity, SecurityDomain, ReportName, ExemptionId) WHERE ImportanceRank IS NOT NULL');

IF OBJECT_ID('sidata.FindingPivotCell') IS NULL
CREATE TABLE sidata.FindingPivotCell (
    CollectionId    INT            NOT NULL,
    ByReport        BIT            NOT NULL,   -- 0 = over every report; 1 = the cells of one report (ReportName)
    ReportName      NVARCHAR(256)  NULL,
    Tier            NVARCHAR(12)   NOT NULL,   -- '0'..'3' or 'Unclassified' (ProDataSql.TierExpr)
    Severity        NVARCHAR(30)   NOT NULL,   -- '' = none
    SecurityDomain  NVARCHAR(128)  NOT NULL,   -- '' = none
    Findings        BIGINT         NOT NULL,
    Assets          BIGINT         NOT NULL,   -- distinct assets of the cell (exact)
    CellId          BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_FindingPivotCell PRIMARY KEY CLUSTERED (CollectionId, CellId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingPivotCell_Report' AND object_id = OBJECT_ID('sidata.FindingPivotCell'))
CREATE INDEX IX_FindingPivotCell_Report ON sidata.FindingPivotCell (CollectionId, ByReport, ReportName) INCLUDE (Tier, Severity, SecurityDomain, Findings, Assets);

IF OBJECT_ID('sidata.FindingPivotCellCounted') IS NULL
CREATE TABLE sidata.FindingPivotCellCounted (
    CollectionId    INT            NOT NULL,
    ByReport        BIT            NOT NULL,
    ReportName      NVARCHAR(256)  NULL,
    Tier            NVARCHAR(12)   NOT NULL,
    Severity        NVARCHAR(30)   NOT NULL,
    SecurityDomain  NVARCHAR(128)  NOT NULL,
    Findings        BIGINT         NOT NULL,
    Assets          BIGINT         NOT NULL,
    CellId          BIGINT IDENTITY(1, 1) NOT NULL,
    CONSTRAINT PK_FindingPivotCellCounted PRIMARY KEY CLUSTERED (CollectionId, CellId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingPivotCellCounted_Report' AND object_id = OBJECT_ID('sidata.FindingPivotCellCounted'))
CREATE INDEX IX_FindingPivotCellCounted_Report ON sidata.FindingPivotCellCounted (CollectionId, ByReport, ReportName) INCLUDE (Tier, Severity, SecurityDomain, Findings, Assets);

IF OBJECT_ID('sidata.PivotCell') IS NULL
CREATE TABLE sidata.PivotCell (
    CollectionId    INT            NOT NULL,
    CellId          BIGINT IDENTITY(1, 1) NOT NULL,
    Exempted        BIT            NOT NULL,   -- the cell's findings carry an exemption mark (left out of the counted pivots)
    ServicePrimary  BIT            NOT NULL,   -- the one row of its findings a pivot without a service field reads
    ServiceKey      NVARCHAR(256)  NULL,       -- the CMDB service (sidata.ServiceMember); NULL = in no service
    ServiceName     NVARCHAR(400)  NULL,
    AssetKey        NVARCHAR(400)  NULL,
    AssetName       NVARCHAR(400)  NULL,
    AssetKind       NVARCHAR(16)   NULL,
    Tier            TINYINT        NULL,
    SecurityDomain  NVARCHAR(128)  NULL,
    ReportName      NVARCHAR(256)  NULL,
    Severity        NVARCHAR(30)   NULL,
    DepartmentId    INT            NULL,
    Findings        BIGINT         NOT NULL,
    RiskSum         FLOAT          NULL,
    WeightedSum     FLOAT          NULL,
    WeightedMax     FLOAT          NULL,
    WeightedN       BIGINT         NOT NULL,   -- the findings with a weighted score (the average's divisor)
    CONSTRAINT PK_PivotCell PRIMARY KEY CLUSTERED (CollectionId, CellId)
);

IF OBJECT_ID('sidata.FindingPivotState') IS NULL
CREATE TABLE sidata.FindingPivotState (
    CollectionId    INT            NOT NULL CONSTRAINT PK_FindingPivotState PRIMARY KEY,
    BuiltAt         DATETIME2(0)   NOT NULL,
    Findings        BIGINT         NOT NULL,   -- every finding of the collection
    CountedFindings BIGINT         NOT NULL,   -- without the exempted ones
    Cells           INT            NOT NULL,   -- FindingPivotCell rows
    CubeRows        INT            NOT NULL    -- PivotCell rows
);

-- ---------------------------------------------------------------------------------------------
-- WHAT A PAGE OPENS WITH ON A COLD DATABASE, PRE-COMPUTED BY THE DATA SYNC (ADDED 2026-10-20, #839 -- measured on a small
-- Azure SQL database after a restart: Assets & services > Assets (CIs) failed on its first open after 47 s while the column
-- chooser's lists were read from the CI documents, the source objects, the identifiers and the findings; Changes & trends >
-- Vulnerabilities over time failed after 40 s on the open vulnerabilities by severity and tier).
--   ColumnChoice / ColumnChoiceState  the column chooser's lists, one row per (list, name): 'ci' = the top-level fields of a
--       sample of CI documents, 'id' = the identifier types, 'source' = the flattened property names of the newest objects of
--       each source, 'finding' = the top-level fields of a sample of the published run's findings (DataColumnSql's sample
--       statements). The state says when each list was written and from which data (DataMark: the list is written again only
--       when it moved). A list without a state row is not written yet: the chooser offers the columns without it and says
--       they appear after the next data sync -- the web app never reads the samples itself.
--   VulnOpenCount / VulnOpenCountState  the open vulnerability items per source, severity and asset tier (the tier words of
--       the pages), every item (Counted = 0) and leaving out those whose finding the newest complete collection marks
--       exempted (Counted = 1) -- ProDataSql.OpenVulnerabilities / OpenVulnerabilitiesCounted, written after the close-loop's
--       statistics. No state row = not counted yet.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.ColumnChoice') IS NULL
CREATE TABLE sidata.ColumnChoice (
    List           NVARCHAR(16)   NOT NULL,   -- ci | id | source | finding
    Name           NVARCHAR(400)  COLLATE Latin1_General_BIN2 NOT NULL,   -- as the data spells it (two spellings are two names)
    CONSTRAINT PK_ColumnChoice PRIMARY KEY CLUSTERED (List, Name)
);

IF OBJECT_ID('sidata.ColumnChoiceState') IS NULL
CREATE TABLE sidata.ColumnChoiceState (
    List           NVARCHAR(16)   NOT NULL CONSTRAINT PK_ColumnChoiceState PRIMARY KEY,
    BuiltAt        DATETIME2(0)   NOT NULL,
    Names          INT            NOT NULL,
    DataMark       NVARCHAR(400)  NULL        -- what the list was read from (the newest data it saw); NULL = unknown
);

IF OBJECT_ID('sidata.VulnOpenCount') IS NULL
CREATE TABLE sidata.VulnOpenCount (
    Source         NVARCHAR(60)   NOT NULL,   -- vuln.VulnerabilityItem.Source
    Counted        BIT            NOT NULL,   -- 1 = the items whose finding the newest complete collection marks exempted are left out
    Severity       NVARCHAR(30)   NOT NULL,   -- '(none)' when the item carries none
    Tier           NVARCHAR(12)   NOT NULL,   -- '0'..'3' | 'Unclassified' (the asset's tier, the pages' words)
    Items          BIGINT         NOT NULL,
    CONSTRAINT PK_VulnOpenCount PRIMARY KEY CLUSTERED (Source, Counted, Severity, Tier)
);

IF OBJECT_ID('sidata.VulnOpenCountState') IS NULL
CREATE TABLE sidata.VulnOpenCountState (
    Name           NVARCHAR(16)   NOT NULL CONSTRAINT PK_VulnOpenCountState PRIMARY KEY,   -- 'current'
    BuiltAt        DATETIME2(0)   NOT NULL,
    CollectionId   INT            NULL,       -- the collection whose exempted findings the counted variant leaves out
    OpenItems      BIGINT         NOT NULL    -- every open item, every source
);

-- =============================================================================================
-- #639 THE DATA OUT'S STAGING (engine/data-out/SI-DataOut.ps1): what an output holds is one page, never a set the size of
-- the output. Rows live for one run of one output (StageId) and are removed at its end; a run that stopped leaves rows the
-- next data out removes once they are a day old. Additive; also created by the data out itself when missing.
--   DataOutKeyStage           the keys one output has seen this run (and the keys it leaves out as disabled, the ones it
--                             keeps for a report the newest run could not complete) -- the items no longer sent are the
--                             ones it sent before (cfg.DataOutItem) that are not here. Ordinal keys, as the engine's.
--   DataOutSummaryStage       the open findings of the findings summary, one row each, a page at a time
--   DataOutSummaryGroupStage  the summary's groups, built from it set-based and read back a page at a time
-- =============================================================================================
IF OBJECT_ID(N'sidata.DataOutKeyStage') IS NULL
CREATE TABLE sidata.DataOutKeyStage (
    StageId   UNIQUEIDENTIFIER NOT NULL,
    ItemKey   NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
    StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_DataOutKeyStage_StagedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_DataOutKeyStage PRIMARY KEY (StageId, ItemKey)
);

IF OBJECT_ID(N'sidata.DataOutSummaryStage') IS NULL
CREATE TABLE sidata.DataOutSummaryStage (
    StageId   UNIQUEIDENTIFIER NOT NULL,
    Seq       BIGINT           NOT NULL,
    GroupKey  NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CiKey     NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
    Name      NVARCHAR(400)    NULL,
    Score     FLOAT            NULL,
    WScore    FLOAT            NULL,
    AttrJson  NVARCHAR(MAX)    NULL,
    StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_DataOutSummaryStage_StagedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_DataOutSummaryStage PRIMARY KEY (StageId, Seq)
);

IF OBJECT_ID(N'sidata.DataOutSummaryGroupStage') IS NULL
CREATE TABLE sidata.DataOutSummaryGroupStage (
    StageId   UNIQUEIDENTIFIER NOT NULL,
    FirstSeq  BIGINT           NOT NULL,
    GroupKey  NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CiCount   INT              NOT NULL,
    NamesJson NVARCHAR(MAX)    NULL,
    MaxScore  FLOAT            NULL,
    MaxWScore FLOAT            NULL,
    AttrJson  NVARCHAR(MAX)    NULL,
    StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_DataOutSummaryGroupStage_StagedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_DataOutSummaryGroupStage PRIMARY KEY (StageId, FirstSeq)
);

-- #639 CiFindingDbWork: the findings per CI made from the database IN KEY RANGES (engine/pro-data/_shared/SI-DataCi.ps1,
-- Invoke-SIDataCiFindingFromDbRanged) -- the collection's keyed rows projected here a page of ids at a time, then staged a
-- range of finding-key hashes at a time (every row of a key in one range), each range its own statement: never one
-- transaction over a 30 M-row collection. Emptied before and after each use. Also created by the data sync when missing.
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

-- #639 CiOwnerStage: the owner keys the finding lifecycle works with (the owners left out, the owners whose absent findings
-- may freeze, the owners that freeze this run) staged in chunks (engine/pro-data/_shared/SI-DataCiLifecycle.ps1) -- they went
-- as four JSON parameters, each the whole list. One StageId per lifecycle run, removed at its end. Also created when missing.
IF OBJECT_ID(N'sidata.CiOwnerStage') IS NULL
CREATE TABLE sidata.CiOwnerStage (
    StageId   UNIQUEIDENTIFIER NOT NULL,
    Kind      NCHAR(1)         NOT NULL,
    OwnerKey  NVARCHAR(450)    NOT NULL,
    StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_CiOwnerStage_StagedAt DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_CiOwnerStage' AND object_id = OBJECT_ID('sidata.CiOwnerStage'))
    CREATE CLUSTERED INDEX CX_CiOwnerStage ON sidata.CiOwnerStage (StageId, Kind, OwnerKey);
-- ---------------------------------------------------------------------------------------------
-- THE CI LIFECYCLE ON EVERY FINDING (ADDED 2026-10-21, #855 W10 -- owner: "we need to be able to trust all data" / "default
-- filter is active, so it should be active only"). Risk Analysis keeps producing findings for CIs that are not seen or retired;
-- every view decides what it counts from the CI's lifecycle, never from a day count of its own.
--   Finding.CiLifecycle       the lifecycle of the finding's CI when the collection was stored (active | not_seen | retired) --
--                             stamped by the data sync (engine\_shared\data-sql\SI-DataSql.ps1, Invoke-SIDataCiLifecycleStamp)
--                             from sidata.Ci by the finding's CI (the CI id = AssetKey, else the CI that carries it as a linked
--                             object: CiLink.NativeId -- the key figures' resolution). NULL = no CI carries the asset, or the
--                             collection was stored before the column existed: counted as ACTIVE (its asset is not known to be gone).
--   Collection.CiLifecycleAt  when the collection's findings were stamped (NULL = not stamped: every finding counts as active)
--   <aggregate>.CiLifecycle   the derived tables a view lets a person choose the lifecycle on carry it as a KEY (an asset has
--                             exactly one lifecycle, so the distinct-asset counts of two lifecycles add up): FindingDaily,
--                             AssetDaily, FindingPivotCell, PivotCell, CiFindingSummary (+ the counted twins); and as a column of
--                             the per-CI rows: AssetRiskSummary, Tier0Asset (+ the counted twins). NULL = built before the column.
--   Built over ACTIVE CIs only (their key cannot take a fourth column in an additive schema, or the view is a to-do list): the
--   facets (FindingFacet, DepartmentFacet, CveSummary), the Summary groupings (SummaryGroup) and the remediations
--   (Remediation, RemediationAsset) -- each page says so. Additive; the data sync runs the same statements
--   (Get-SIDataCiLifecycleColumnsSql) and stamps the newest collection once, then derives it again.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'CiLifecycle') IS NULL ALTER TABLE sidata.Finding ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.Collection', 'CiLifecycleAt') IS NULL ALTER TABLE sidata.Collection ADD CiLifecycleAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.FindingDaily', 'CiLifecycle') IS NULL ALTER TABLE sidata.FindingDaily ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.FindingDailyCounted', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.FindingDailyCounted') IS NOT NULL ALTER TABLE sidata.FindingDailyCounted ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.AssetDaily', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.AssetDaily') IS NOT NULL ALTER TABLE sidata.AssetDaily ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.AssetDailyCounted', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.AssetDailyCounted') IS NOT NULL ALTER TABLE sidata.AssetDailyCounted ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.FindingPivotCell', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.FindingPivotCell') IS NOT NULL ALTER TABLE sidata.FindingPivotCell ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.FindingPivotCellCounted', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.FindingPivotCellCounted') IS NOT NULL ALTER TABLE sidata.FindingPivotCellCounted ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.PivotCell', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.PivotCell') IS NOT NULL ALTER TABLE sidata.PivotCell ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.AssetRiskSummary', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.AssetRiskSummary') IS NOT NULL ALTER TABLE sidata.AssetRiskSummary ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.AssetRiskSummaryCounted', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.AssetRiskSummaryCounted') IS NOT NULL ALTER TABLE sidata.AssetRiskSummaryCounted ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.AssetRiskSummary', 'Unclassified') IS NULL AND OBJECT_ID('sidata.AssetRiskSummary') IS NOT NULL ALTER TABLE sidata.AssetRiskSummary ADD Unclassified BIGINT NULL;
IF COL_LENGTH('sidata.AssetRiskSummaryCounted', 'Unclassified') IS NULL AND OBJECT_ID('sidata.AssetRiskSummaryCounted') IS NOT NULL ALTER TABLE sidata.AssetRiskSummaryCounted ADD Unclassified BIGINT NULL;
IF COL_LENGTH('sidata.Tier0Asset', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.Tier0Asset') IS NOT NULL ALTER TABLE sidata.Tier0Asset ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.Tier0AssetCounted', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.Tier0AssetCounted') IS NOT NULL ALTER TABLE sidata.Tier0AssetCounted ADD CiLifecycle NVARCHAR(16) NULL;
IF COL_LENGTH('sidata.CiFindingSummary', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.CiFindingSummary') IS NOT NULL ALTER TABLE sidata.CiFindingSummary ADD CiLifecycle NVARCHAR(16) NULL;
-- W9: the vulnerabilities over time split their closes by reason -- fixed (Remediated), asset retired (AssetRetired), other
IF COL_LENGTH('sidata.VulnLifecycleDaily', 'ClosedFixed') IS NULL ALTER TABLE sidata.VulnLifecycleDaily ADD ClosedFixed INT NULL;
IF COL_LENGTH('sidata.VulnLifecycleDaily', 'ClosedRetired') IS NULL ALTER TABLE sidata.VulnLifecycleDaily ADD ClosedRetired INT NULL;
IF COL_LENGTH('sidata.VulnLifecycleDaily', 'ClosedOther') IS NULL ALTER TABLE sidata.VulnLifecycleDaily ADD ClosedOther INT NULL;
-- the views filter one collection's findings on the lifecycle (a person's "Not seen" / "Retired" choice is a seek)
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_CiLifecycle' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_CiLifecycle ON sidata.Finding (CollectionId, CiLifecycle) INCLUDE (AssetKey, Severity, Tier)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummary_Lifecycle' AND object_id = OBJECT_ID('sidata.AssetRiskSummary'))
    EXEC (N'CREATE INDEX IX_AssetRiskSummary_Lifecycle ON sidata.AssetRiskSummary (CollectionId, CiLifecycle, TotalRisk DESC) INCLUDE (Tier, MaxRisk)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AssetRiskSummaryCounted_Lifecycle' AND object_id = OBJECT_ID('sidata.AssetRiskSummaryCounted'))
    EXEC (N'CREATE INDEX IX_AssetRiskSummaryCounted_Lifecycle ON sidata.AssetRiskSummaryCounted (CollectionId, CiLifecycle, TotalRisk DESC) INCLUDE (Tier, MaxRisk)');
-- the per-day trends read one lifecycle's rows of a day
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingDaily_Lifecycle' AND object_id = OBJECT_ID('sidata.FindingDaily'))
    EXEC (N'CREATE INDEX IX_FindingDaily_Lifecycle ON sidata.FindingDaily ([Day], CiLifecycle) INCLUDE (Tier, Severity, Findings, Assets, ScoreTotal, ScoreMax)');

-- =============================================================================================
-- THE RISK ANALYSIS DETAILED MAIL WAITS FOR ITS PROTECTION SCORE (owner 2026-10-22: "one computation, never two that can differ").
-- A Pro Detailed run keeps its mail here, with the score's two places marked; the data sync sends it right after its key
-- figures, with the STORED score of that collection (the number the web app shows) -- or with the one line why there is none.
-- Claimed atomically (waiting -> sending), marked sent with the time, put back to waiting when the send failed: never lost,
-- never sent twice (engine\_shared\data-sql\SI-RaMailOutbox.ps1, which runs the SAME guarded statement before it keeps a mail).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.RaMailOutbox') IS NULL
CREATE TABLE sidata.RaMailOutbox (
    MailId           BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_RaMailOutbox PRIMARY KEY,
    CollectionId     INT            NOT NULL,
    CollectionTime   DATETIME2(3)   NOT NULL,
    CreatedAt        DATETIME2(3)   NOT NULL CONSTRAINT DF_RaMailOutbox_CreatedAt DEFAULT SYSUTCDATETIME(),
    Subject          NVARCHAR(1000) NOT NULL,
    BodyHtml         NVARCHAR(MAX)  NOT NULL,
    ToJson           NVARCHAR(MAX)  NOT NULL,
    FromAddress      NVARCHAR(400)  NULL,
    Priority         NVARCHAR(16)   NULL,
    AttachmentName   NVARCHAR(400)  NULL,
    AttachmentBase64 VARCHAR(MAX)   NULL,
    State            NVARCHAR(16)   NOT NULL CONSTRAINT DF_RaMailOutbox_State DEFAULT N'waiting',
    ClaimedAt        DATETIME2(3)   NULL,
    ClaimedBy        NVARCHAR(200)  NULL,
    Attempts         INT            NOT NULL CONSTRAINT DF_RaMailOutbox_Attempts DEFAULT 0,
    SentAt           DATETIME2(3)   NULL,
    SentBy           NVARCHAR(32)   NULL,
    Shown            NVARCHAR(1000) NULL,
    LastError        NVARCHAR(2000) NULL,
    CONSTRAINT CK_RaMailOutbox_State CHECK (State IN ('waiting', 'sending', 'sent'))
);

-- ---------------------------------------------------------------------------------------------
-- THE NARROW FINDINGS (2026-10-25, owner: "i need the performance improvement, but no loosing of data"). The derived steps
-- after the view context (the remediations, the findings per CI, ...) each scanned a collection's WIDE rows (DetailJson about
-- 3 KB a row; at the largest install 1.39 million rows, ~4 GB read from disk per scan). sidata.FindingNarrow holds, per
-- finding, the typed columns they read -- the SAME names and types as sidata.Finding (made from its own columns below) -- and
-- each value that lives only in the document as a column of its own, read once (Dj_<field> = JSON_VALUE(DetailJson,
-- '$.<field>') of a JSON document, DjIsJson = ISJSON). Filled by the data sync in FindingId ranges for a collection the first
-- time a step of THIS run needs it (after the view context, the last step that writes those columns), emptied at the run's
-- end -- never read across runs. A database without it: the steps read sidata.Finding as before.
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'FindingId') IS NOT NULL AND OBJECT_ID('sidata.FindingNarrow') IS NULL   -- made from text (EXEC): no CREATE of its own here
BEGIN
    DECLARE @nf TABLE (Name sysname NOT NULL PRIMARY KEY);
    INSERT @nf (Name) VALUES (N'AssetKey'), (N'AssetName'), (N'ReportName'), (N'SecurityDomain'), (N'ConfigurationId'), (N'Cve'), (N'Title'), (N'Severity'), (N'Tier'),
        (N'RiskScore'), (N'RiskScoreWeighted'), (N'RiskRating'), (N'ExemptionId'), (N'RemediationEffort'), (N'FixOwner'), (N'DepartmentId'), (N'HasExploit'),
        (N'FixRemediation'), (N'CiLifecycle'), (N'FixRecommendedUpdateId'), (N'FixRecommendedUpdate'), (N'AffectedVendor'), (N'AffectedProduct'),
        (N'RaFindingKey'), (N'RaSeq'), (N'RaAssetId'), (N'Category'), (N'Subcategory'), (N'ComplianceTags'), (N'Cvss'), (N'MitreTactics'), (N'MitreTechniques'), (N'SourceFirstDetected');
    DECLARE @nsql nvarchar(max) = N'CREATE TABLE sidata.FindingNarrow (CollectionId INT NOT NULL, FindingId BIGINT NOT NULL, '
        + (SELECT STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(c.name) + N' ' +
               CASE WHEN t.name IN (N'nvarchar', N'nchar') THEN t.name + N'(' + CASE WHEN c.max_length = -1 THEN N'max' ELSE CONVERT(nvarchar(10), c.max_length / 2) END + N')'
                    WHEN t.name IN (N'varchar', N'char', N'varbinary', N'binary') THEN t.name + N'(' + CASE WHEN c.max_length = -1 THEN N'max' ELSE CONVERT(nvarchar(10), c.max_length) END + N')'
                    WHEN t.name IN (N'decimal', N'numeric') THEN t.name + N'(' + CONVERT(nvarchar(5), c.precision) + N', ' + CONVERT(nvarchar(5), c.scale) + N')'
                    WHEN t.name IN (N'datetime2', N'time', N'datetimeoffset') THEN t.name + N'(' + CONVERT(nvarchar(5), c.scale) + N')'
                    ELSE t.name END
               + CASE WHEN c.collation_name IS NOT NULL THEN N' COLLATE ' + c.collation_name ELSE N'' END + N' NULL'), N', ') WITHIN GROUP (ORDER BY c.column_id)
           FROM sys.columns AS c JOIN sys.types AS t ON t.user_type_id = c.user_type_id JOIN @nf AS n ON n.Name = c.name
           WHERE c.object_id = OBJECT_ID('sidata.Finding'))
        + N', DjIsJson BIT NULL, Dj_si_remediation_type NVARCHAR(4000) NULL, Dj_RiskScoreTotal_Weighted NVARCHAR(4000) NULL, Dj_si_component NVARCHAR(4000) NULL,'
        + N' Dj_RiskFactor_Probability_Detailed NVARCHAR(4000) NULL, Dj_RiskFactor_Consequence_Detailed NVARCHAR(4000) NULL, Dj_si_servicenow_subci NVARCHAR(4000) NULL,'
        + N' Dj_si_patch_cycle NVARCHAR(4000) NULL, Dj_si_cve_published NVARCHAR(4000) NULL, Dj_si_category NVARCHAR(4000) NULL, Dj_Category NVARCHAR(4000) NULL,'
        + N' Dj_si_subcategory NVARCHAR(4000) NULL, Dj_Subcategory NVARCHAR(4000) NULL, CONSTRAINT PK_FindingNarrow PRIMARY KEY CLUSTERED (CollectionId, FindingId));';
    -- only when sidata.Finding carries every one of them (the schema above adds them all)
    IF (SELECT COUNT(*) FROM sys.columns AS c JOIN @nf AS n ON n.Name = c.name WHERE c.object_id = OBJECT_ID('sidata.Finding')) = (SELECT COUNT(*) FROM @nf)
        EXEC (@nsql);
END

-- ---------------------------------------------------------------------------------------------
-- THE SET-BASED "STILL SEEN" COMPARE (2026-10-25, plan item 1; engine/asset-cmdb/_shared/SI-VulnSetBased.ps1). The close-loop
-- builds the desired record of every finding of the collection IN SQL, compares it with the stored record by a content hash
-- of the fields it sends, and refreshes every record that is still reported and unchanged in one statement -- the steady
-- state, nearly every record of every run. Everything else (new, changed, reopened, absent, closed) goes through the plan as
-- before. Working tables only, one connector run each (SbRun), emptied at the end of the run: never product data. They live in sidata (the engine role may empty them there; it never deletes from vuln).
--   VulnSbSeen       the records refreshed as seen this run, with the values the refresh writes
--   VulnSbFinding  the collection rows those records were built from (left out of the plan's page reads)
--   VulnSbKey        the CI keys that still need the plan (a row or a record not refreshed set-based), with their rows
--   VulnSbExclude  what the run keeps on the plan path: CI keys ('key'), finding ids ('cid'), records ('sys')
-- A database without these tables (they are made by this file, in the database the collection is in) runs the close-loop exactly as before.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('sidata.VulnSbSeen') IS NULL
CREATE TABLE sidata.VulnSbSeen (
    SbRun        UNIQUEIDENTIFIER NOT NULL,
    SysId        UNIQUEIDENTIFIER NOT NULL,
    CiKey        NVARCHAR(400)    NOT NULL,
    FindingKey   NVARCHAR(100)    NOT NULL,
    FindingType  NVARCHAR(32)     NULL,
    Report       NVARCHAR(256)    NULL,
    Severity     NVARCHAR(30)     NULL,
    AssetId      NVARCHAR(400)    NULL,
    Title        NVARCHAR(400)    NULL,
    Component    NVARCHAR(32)     NULL,
    SubCi        NVARCHAR(64)     NULL,
    OsFamily     NVARCHAR(64)     NULL,
    PatchCycle   NVARCHAR(64)     NULL,
    ContentHash  BINARY(32)       NOT NULL,
    CreatedAt    DATETIME2(0)     NOT NULL CONSTRAINT DF_VulnSbSeen_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_VulnSbSeen PRIMARY KEY (SbRun, SysId)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VulnSbSeen_Key' AND object_id = OBJECT_ID('sidata.VulnSbSeen'))
CREATE INDEX IX_VulnSbSeen_Key ON sidata.VulnSbSeen (SbRun, CiKey) INCLUDE (Report, FindingType);

IF OBJECT_ID('sidata.VulnSbFinding') IS NULL
CREATE TABLE sidata.VulnSbFinding (
    SbRun        UNIQUEIDENTIFIER NOT NULL,
    CollectionId INT              NOT NULL,
    FindingId    BIGINT           NOT NULL,
    CONSTRAINT PK_VulnSbFinding PRIMARY KEY (SbRun, CollectionId, FindingId)
);

IF OBJECT_ID('sidata.VulnSbKey') IS NULL
CREATE TABLE sidata.VulnSbKey (
    SbRun        UNIQUEIDENTIFIER NOT NULL,
    CiKey        NVARCHAR(400)    NOT NULL,
    [Rows]       BIGINT           NOT NULL,
    CONSTRAINT PK_VulnSbKey PRIMARY KEY (SbRun, CiKey)
);

IF OBJECT_ID('sidata.VulnSbExclude') IS NULL
CREATE TABLE sidata.VulnSbExclude (
    SbRun        UNIQUEIDENTIFIER NOT NULL,
    Kind         NVARCHAR(3)      NOT NULL,   -- key | cid | sys
    Value        NVARCHAR(400)    NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VulnSbExclude' AND object_id = OBJECT_ID('sidata.VulnSbExclude'))
CREATE CLUSTERED INDEX IX_VulnSbExclude ON sidata.VulnSbExclude (SbRun, Kind, Value);

-- ---------------------------------------------------------------------------------------------
-- THE RISK SCORE'S PARTS AS COLUMNS (ADDED 2026-10-29; owner: "it should be possible to see the Risk Score calculations as
-- columns" -- in the Detailed and the Summary rows, by default). Risk Analysis writes every part of a finding's score on its
-- row (RiskConsequenceBase / RiskProbabilityBase, RiskFactor_*_Impacts "Name=n;...", the sides, the factor points, the
-- weight); the data sync copies them into typed columns, so the views show, sort and filter them without reading the row's
-- JSON. Per side (Asset = the consequence side, Vuln = the probability side):
--   Risk<Side>Base      the base (the risk index); a row written before the bases were recorded: the side minus its points
--   Risk<Side>Side      the side's score (base + the points of its factors)
--   Risk<Side>Points    the points of its factors, as Risk Analysis summed them
--   Risk<Side>Factors   the factors with their points as Risk Analysis wrote them ("Name=n;..."), or -- an older row -- their names
--   Risk<Side>Derived   1 = the base was worked out (an older row), 0 = recorded
--   RiskWeightPct / RiskWeightBy   the weight (in %) and what set it
-- sidata.Collection.RiskPartsAt is set when every finding of the collection carries them (RiskPartsUpto: how far a fill that
-- stopped at its time budget came); the data sync fills a new collection when it derives it and earlier collections newest
-- first, within a time budget per run (Invoke-SIDataRiskPartsBackfill). The two sides are indexed (the views sort on them).
-- sidata.SummaryRow gets the parts it did not carry (its side scores and factor points already are columns).
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('sidata.Finding', 'RiskAssetBase') IS NULL ALTER TABLE sidata.Finding ADD RiskAssetBase FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskAssetSide') IS NULL ALTER TABLE sidata.Finding ADD RiskAssetSide FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskAssetPoints') IS NULL ALTER TABLE sidata.Finding ADD RiskAssetPoints FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskAssetFactors') IS NULL ALTER TABLE sidata.Finding ADD RiskAssetFactors NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Finding', 'RiskAssetDerived') IS NULL ALTER TABLE sidata.Finding ADD RiskAssetDerived BIT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskVulnBase') IS NULL ALTER TABLE sidata.Finding ADD RiskVulnBase FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskVulnSide') IS NULL ALTER TABLE sidata.Finding ADD RiskVulnSide FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskVulnPoints') IS NULL ALTER TABLE sidata.Finding ADD RiskVulnPoints FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskVulnFactors') IS NULL ALTER TABLE sidata.Finding ADD RiskVulnFactors NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.Finding', 'RiskVulnDerived') IS NULL ALTER TABLE sidata.Finding ADD RiskVulnDerived BIT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskWeightPct') IS NULL ALTER TABLE sidata.Finding ADD RiskWeightPct FLOAT NULL;
IF COL_LENGTH('sidata.Finding', 'RiskWeightBy') IS NULL ALTER TABLE sidata.Finding ADD RiskWeightBy NVARCHAR(1000) NULL;
IF COL_LENGTH('sidata.Collection', 'RiskPartsAt') IS NULL ALTER TABLE sidata.Collection ADD RiskPartsAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Collection', 'RiskPartsUpto') IS NULL ALTER TABLE sidata.Collection ADD RiskPartsUpto BIGINT NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_AssetSidePage' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_AssetSidePage ON sidata.Finding (CollectionId, RiskAssetSide DESC) INCLUDE (ExemptionId)');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_VulnSidePage' AND object_id = OBJECT_ID('sidata.Finding'))
    EXEC (N'CREATE INDEX IX_Finding_VulnSidePage ON sidata.Finding (CollectionId, RiskVulnSide DESC) INCLUDE (ExemptionId)');

IF COL_LENGTH('sidata.SummaryRow', 'RiskAssetBase') IS NULL ALTER TABLE sidata.SummaryRow ADD RiskAssetBase FLOAT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RiskAssetFactors') IS NULL ALTER TABLE sidata.SummaryRow ADD RiskAssetFactors NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RiskAssetDerived') IS NULL ALTER TABLE sidata.SummaryRow ADD RiskAssetDerived BIT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RiskVulnBase') IS NULL ALTER TABLE sidata.SummaryRow ADD RiskVulnBase FLOAT NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RiskVulnFactors') IS NULL ALTER TABLE sidata.SummaryRow ADD RiskVulnFactors NVARCHAR(MAX) NULL;
IF COL_LENGTH('sidata.SummaryRow', 'RiskVulnDerived') IS NULL ALTER TABLE sidata.SummaryRow ADD RiskVulnDerived BIT NULL;
