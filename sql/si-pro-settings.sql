-- si-pro-settings.sql -- the PRO SETTINGS STORE, SecurityInsight Pro (REQUIREMENTS §9.2, Pro-1).
--
-- In Pro every setting lives here instead of in the custom .ps1 files; the launcher reads it at run start as the
-- closest configuration layer (launcher\_lib\Initialize-LauncherConfig.ps1 -> engine\pro-settings\SI-ProSettings.ps1)
-- and the run FAILS when it cannot (operator decision 2026-10-02). It lives in the one Pro database beside the `vuln`
-- schema of the vulnerability close-loop.
--
-- A secret's VALUE never enters this database: a secret setting stores only the Key Vault secret NAME.
-- Every change is appended to cfg.ChangeLog in the same transaction as the change itself.
--
-- ADDITIVE AND IDEMPOTENT ONLY: every statement is guarded, so re-running is a no-op, and no destructive verb appears
-- in this file (a test refuses one).

IF SCHEMA_ID('cfg') IS NULL EXEC ('CREATE SCHEMA cfg');

-- ---------------------------------------------------------------------------------------------
-- One row per (setting, scope). Scope = 'solution' or 'engine:<engine folder>'; an engine row wins for that engine.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.Setting') IS NULL
CREATE TABLE cfg.Setting (
    Name               NVARCHAR(128)   NOT NULL,
    Scope              NVARCHAR(64)    NOT NULL,
    ValueJson          NVARCHAR(MAX)   NULL,     -- the value as JSON (true, 25, "text", ["a","b"]); NULL for a secret
    KeyVaultSecretName NVARCHAR(256)   NULL,     -- a secret setting: the Key Vault secret holding the value
    UpdatedAt          DATETIME2(0)    NOT NULL CONSTRAINT DF_Setting_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy          NVARCHAR(256)   NOT NULL,
    RowVersion         ROWVERSION      NOT NULL,
    CONSTRAINT PK_Setting PRIMARY KEY (Name, Scope),
    CONSTRAINT CK_Setting_Scope CHECK (Scope = 'solution' OR Scope LIKE 'engine:%'),
    CONSTRAINT CK_Setting_OneKind CHECK (ValueJson IS NULL OR KeyVaultSecretName IS NULL)
);

-- ---------------------------------------------------------------------------------------------
-- Every change, append-only: who set what, when, from what to what, and why. Nothing updates or removes a row here.
-- (Pro-1b adds a nullable Kind column below, for document changes.)
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.ChangeLog') IS NULL
CREATE TABLE cfg.ChangeLog (
    ChangeId    BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ChangeLog PRIMARY KEY,
    Name        NVARCHAR(128)   NOT NULL,
    Scope       NVARCHAR(64)    NOT NULL,
    Action      NVARCHAR(16)    NOT NULL,    -- Set | Reset
    OldValue    NVARCHAR(MAX)   NULL,        -- ValueJson, or 'keyvault:<name>' for a secret reference
    NewValue    NVARCHAR(MAX)   NULL,
    ChangedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_ChangeLog_ChangedAt DEFAULT SYSUTCDATETIME(),
    ChangedBy   NVARCHAR(256)   NOT NULL,
    Reason      NVARCHAR(400)   NULL,
    CONSTRAINT CK_ChangeLog_Action CHECK (Action IN ('Set', 'Reset'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ChangeLog_Name' AND object_id = OBJECT_ID('cfg.ChangeLog'))
CREATE INDEX IX_ChangeLog_Name ON cfg.ChangeLog (Name, Scope, ChangedAt);

-- ---------------------------------------------------------------------------------------------
-- Pro-1b: structured settings as documents (REQUIREMENTS §9.2 B). One row per (Kind, Key):
--   exclusions  Key = 'global' or a Risk Analysis report name   Body = the exclusion JSON
--   weights     Key = 'solution'                                Body = the risk-weights JSON
--   rule        Key = '<engine>/<rule id>'                      Body = the tier rule YAML
-- Validated by the Community Settings page's own rules, by the writer AND again at run start.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.Document') IS NULL
CREATE TABLE cfg.Document (
    Kind        NVARCHAR(16)    NOT NULL,
    [Key]       NVARCHAR(128)   NOT NULL,
    Body        NVARCHAR(MAX)   NOT NULL,
    UpdatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_Document_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy   NVARCHAR(256)   NOT NULL,
    [Version]   ROWVERSION      NOT NULL,
    CONSTRAINT PK_Document PRIMARY KEY (Kind, [Key]),
    CONSTRAINT CK_Document_Kind CHECK (Kind IN ('exclusions', 'weights', 'rule'))
);

-- A document change is logged in cfg.ChangeLog like a setting change: Name = the document key, Scope = 'document',
-- and Kind (added here, nullable -- every earlier row is a setting and keeps NULL).
IF COL_LENGTH('cfg.ChangeLog', 'Kind') IS NULL
ALTER TABLE cfg.ChangeLog ADD Kind NVARCHAR(16) NULL;

-- ---------------------------------------------------------------------------------------------
-- THE WEB APP'S ROLE MAPPING (#253, Configuration > Access (roles + scopes), SuperAdmin only): an Entra user or group (by object id) -> Reader,
-- Delegated, Admin or SuperAdmin, on top of the Entra app role that gates sign-in (the higher of the two applies).
-- ScopeJson = a Delegated assignment's scope as (scope type, value) pairs:
--   {"entries":[{"type":"domain","value":"Identity"},{"type":"tier","value":"2"}]}
-- Roles and scope types are validated by the web app, NOT by a CHECK, so a new role (the external advisors, #258) or
-- scope type (a department, #254) needs no schema change -- widening a CHECK would mean dropping it.
-- One row per identity. Every write is logged in cfg.ChangeLog (Name 'access/<object id>', Scope 'access', Kind 'access').
-- No rows = everyone has exactly their Entra app role.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.AccessAssignment') IS NULL
CREATE TABLE cfg.AccessAssignment (
    PrincipalId     NVARCHAR(64)    NOT NULL CONSTRAINT PK_AccessAssignment PRIMARY KEY,
    PrincipalType   NVARCHAR(8)     NOT NULL,
    DisplayName     NVARCHAR(256)   NOT NULL,
    Role            NVARCHAR(16)    NOT NULL,
    ScopeJson       NVARCHAR(MAX)   NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_AccessAssignment_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy       NVARCHAR(256)   NOT NULL,
    RowVersion      ROWVERSION      NOT NULL,
    CONSTRAINT CK_AccessAssignment_Type CHECK (PrincipalType IN ('User', 'Group')),
    CONSTRAINT CK_AccessAssignment_Scope CHECK (ScopeJson IS NULL OR ISJSON(ScopeJson) = 1)
);

-- #765 (owner 2026-10-19: "SI decides" + "mail forward on accounts like in pim"): a person's own mail address as Entra
-- gives it (their mail, else their sign-in name -- what a recipient list names them by), and the address SecurityInsight
-- mail to them goes to instead (NULL = their own). The web app validates the forward before it is written; the one mail
-- transport (engine\_shared\SI-MailTransport.ps1, Send-SIMail) reads both. Additive: nullable, no default.
IF COL_LENGTH('cfg.AccessAssignment', 'AccountMail') IS NULL
ALTER TABLE cfg.AccessAssignment ADD AccountMail NVARCHAR(320) NULL;

IF COL_LENGTH('cfg.AccessAssignment', 'ForwardTo') IS NULL
ALTER TABLE cfg.AccessAssignment ADD ForwardTo NVARCHAR(320) NULL;

-- #765: the Entra app roles carried over into cfg.AccessAssignment (SI decides the role; an Entra app role is only a
-- migration source). One row per (identity, app role), written the moment it was carried over: from then on that app role
-- adds nothing on its own -- removing the person on the Access page removes their access. An app role an administrator
-- gives LATER (another one) is carried over once more. Written by the web app only; product code never deletes a row.
IF OBJECT_ID('cfg.AccessCarriedOver') IS NULL
CREATE TABLE cfg.AccessCarriedOver (
    PrincipalId     NVARCHAR(64)    NOT NULL,
    Role            NVARCHAR(16)    NOT NULL,
    CarriedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_AccessCarriedOver_CarriedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_AccessCarriedOver PRIMARY KEY (PrincipalId, Role)
);

-- =============================================================================================
-- Phase C (REQUIREMENTS §9.3.3 C): ALL CONFIGURATION IN SQL, WITH VENDOR TEMPLATES.
-- In Pro the shipped *.locked files are replaced by TEMPLATES: the vendor's baseline, one row per ITEM, published by
-- setup\Publish-SITemplates.ps1 (Version = the release's VERSION). A customer's own state per item lives in
-- cfg.ItemOverride: no row (or State 'inherit') = the template as published; 'override' = the customer's body; 'disable'
-- = the item is left out of the run. A new release republishes the templates and never touches cfg.ItemOverride, so
-- every override survives the version bump; BaseHash records which template body an override was made against.
--
-- Kinds (validated by engine\pro-settings\SI-ProConfig.ps1, NOT by a CHECK constraint -- see below):
--   rareport      report/<ReportName> | template/<ReportName>   one Risk Analysis report or report template (JSON)
--   riskindex     row/<dimensions>                              one risk index row (JSON)
--   rule          <engine>/<rule id>                            one tier rule (YAML text, Format 'yaml')
--   assettagging  tag/<STEM--SI> | config                       one asset-tagging rule | asset-tagging.config.json
--   cmdbownership defaults | assettype/<siAssetType>            the CMDB ownership map
--   servicemodel  model                                         the service model (replaced wholesale)
--   schemaoverlay endpoint | identity | azure | publicip         a profile-schema overlay (customer only)
--   decision      asset | correlation                           an asset / correlation decisions file (YAML, customer only)
--   naming        <setting name>                                a table / DCR naming convention (the default the code had)
--   weights       model | report/<ReportName>                   risk-model sections beside the factors | per-report weights
-- 🔑 Why a NEW table for the customer state instead of widening cfg.Document: cfg.Document's Kind carries
-- CHECK (Kind IN ('exclusions','weights','rule')), and widening a CHECK means dropping it -- a destructive verb this file
-- may never contain. For the same reason the new tables carry NO kind CHECK: the kind list will grow, and the code that
-- reads the rows refuses an unknown kind at run start (fail closed). cfg.Document keeps its three kinds unchanged and
-- stays the home of the customer's own exclusions, weights and tier rules.
-- 🔑 Why BodyJson + Format: a tier rule and a decisions file are YAML whose comments matter to the people who wrote
-- them; Format says how to read BodyJson ('json' or 'yaml').
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.Template') IS NULL
CREATE TABLE cfg.Template (
    TemplateId   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Template PRIMARY KEY,
    Kind         NVARCHAR(32)    NOT NULL,
    ItemKey      NVARCHAR(128)   NOT NULL,
    [Version]    NVARCHAR(32)    NOT NULL,   -- the SecurityInsight release that published this body
    BodyJson     NVARCHAR(MAX)   NOT NULL,
    Format       NVARCHAR(8)     NOT NULL CONSTRAINT DF_Template_Format DEFAULT 'json',
    SortOrder    INT             NOT NULL CONSTRAINT DF_Template_SortOrder DEFAULT 0,
    BodyHash     CHAR(64)        NOT NULL,   -- SHA-256 of BodyJson (UTF-8), checked at run start
    PublishedAt  DATETIME2(0)    NOT NULL CONSTRAINT DF_Template_PublishedAt DEFAULT SYSUTCDATETIME(),
    Source       NVARCHAR(400)   NOT NULL,   -- the shipped file it came from (relative path)
    RetiredAt    DATETIME2(0)    NULL,       -- set when a newer release no longer ships the item (never removed)
    RowVersion   ROWVERSION      NOT NULL,
    CONSTRAINT UQ_Template_Item UNIQUE (Kind, ItemKey),
    CONSTRAINT CK_Template_Format CHECK (Format IN ('json', 'yaml'))
);

IF OBJECT_ID('cfg.ItemOverride') IS NULL
CREATE TABLE cfg.ItemOverride (
    Kind         NVARCHAR(32)    NOT NULL,
    ItemKey      NVARCHAR(128)   NOT NULL,
    State        NVARCHAR(16)    NOT NULL,   -- inherit | override | disable
    BodyJson     NVARCHAR(MAX)   NULL,       -- the customer's body (override only)
    Format       NVARCHAR(8)     NOT NULL CONSTRAINT DF_ItemOverride_Format DEFAULT 'json',
    BaseVersion  NVARCHAR(32)    NULL,       -- the template version the override was made against (NULL = own item)
    BaseHash     CHAR(64)        NULL,       -- that template's BodyHash -> "the template changed since you overrode it"
    UpdatedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_ItemOverride_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy    NVARCHAR(256)   NOT NULL,
    RowVersion   ROWVERSION      NOT NULL,
    CONSTRAINT PK_ItemOverride PRIMARY KEY (Kind, ItemKey),
    CONSTRAINT CK_ItemOverride_State CHECK (State IN ('inherit', 'override', 'disable')),
    CONSTRAINT CK_ItemOverride_Body CHECK (State <> 'override' OR BodyJson IS NOT NULL),
    CONSTRAINT CK_ItemOverride_Format CHECK (Format IN ('json', 'yaml'))
);

-- ---------------------------------------------------------------------------------------------
-- "Exempt this finding" (the management GUI): one row per exemption, never removed -- revoking sets RevokedAt.
-- An expired or revoked row is not applied. Scope (the GUI's words):
--   finding  one issue on one asset     AssetKey + (Cve or ConfigurationId)
--   issue    one issue on every asset   Cve or ConfigurationId, no AssetKey
--   asset    every issue of one asset   AssetKey, no Cve / ConfigurationId
-- ReportName narrows any of them to one Risk Analysis report (NULL = every report).
-- Every write is logged in cfg.ChangeLog (Name 'exemption/<id>', Scope 'exemption', Kind 'exemption').
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.Exemption') IS NULL
CREATE TABLE cfg.Exemption (
    ExemptionId     BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Exemption PRIMARY KEY,
    Scope           NVARCHAR(16)    NOT NULL,   -- finding | issue | asset
    ReportName      NVARCHAR(128)   NULL,
    ConfigurationId NVARCHAR(128)   NULL,
    Cve             NVARCHAR(32)    NULL,
    AssetKey        NVARCHAR(256)   NULL,       -- SI_CorrelationId, or SI_AssetId when the asset has no ledger id
    Reason          NVARCHAR(400)   NOT NULL,
    ExpiresAt       DATETIME2(0)    NULL,
    CreatedBy       NVARCHAR(256)   NOT NULL,
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_Exemption_CreatedAt DEFAULT SYSUTCDATETIME(),
    RevokedAt       DATETIME2(0)    NULL,
    RevokedBy       NVARCHAR(256)   NULL,
    CONSTRAINT CK_Exemption_Scope CHECK (Scope IN ('finding', 'issue', 'asset')),
    CONSTRAINT CK_Exemption_What CHECK (
        (Scope = 'finding' AND AssetKey IS NOT NULL AND (Cve IS NOT NULL OR ConfigurationId IS NOT NULL)) OR
        (Scope = 'issue'   AND AssetKey IS NULL     AND (Cve IS NOT NULL OR ConfigurationId IS NOT NULL)) OR
        (Scope = 'asset'   AND AssetKey IS NOT NULL AND Cve IS NULL AND ConfigurationId IS NULL))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Exemption_Active' AND object_id = OBJECT_ID('cfg.Exemption'))
CREATE INDEX IX_Exemption_Active ON cfg.Exemption (RevokedAt, ExpiresAt);

-- =============================================================================================
-- TEMPLATE VERSIONING (phase C, adopted from PIM4EntraPS -- engine\pro-settings\SI-TemplateVersioning.ps1).
-- ContentHash = SHA-256 of what the item DOES: the body parsed, comments, key order, `_*` keys and description-only
-- fields left out. A documentation edit leaves it unchanged; BodyHash stays the raw-body integrity check. An override's
-- BaseHash records the ContentHash it was made against: when the template's ContentHash moves, the item reads
-- "upgrade available" and is never merged automatically. NULL on rows published before this column; the next publish
-- fills it (Publish-SITemplates refreshes every row without one).
-- ---------------------------------------------------------------------------------------------
IF COL_LENGTH('cfg.Template', 'ContentHash') IS NULL
ALTER TABLE cfg.Template ADD ContentHash CHAR(64) NULL;

-- Every content a template ever had, once (append-only): what "what changed since you overrode it" is diffed against.
IF OBJECT_ID('cfg.TemplateRevision') IS NULL
CREATE TABLE cfg.TemplateRevision (
    Kind         NVARCHAR(32)    NOT NULL,
    ItemKey      NVARCHAR(128)   NOT NULL,
    ContentHash  CHAR(64)        NOT NULL,
    [Version]    NVARCHAR(32)    NOT NULL,   -- the release that first published this content
    BodyJson     NVARCHAR(MAX)   NOT NULL,
    Format       NVARCHAR(8)     NOT NULL CONSTRAINT DF_TemplateRevision_Format DEFAULT 'json',
    PublishedAt  DATETIME2(0)    NOT NULL CONSTRAINT DF_TemplateRevision_PublishedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_TemplateRevision PRIMARY KEY (Kind, ItemKey, ContentHash),
    CONSTRAINT CK_TemplateRevision_Format CHECK (Format IN ('json', 'yaml'))
);

-- State recorded ON THE INSTALL, one row per name. 'TemplateFingerprint' = the template-set fingerprint last published
-- AND verified (read back) on this install: publishing a set whose fingerprint differs needs -AcceptTemplateChange.
-- Every write has its cfg.ChangeLog row (Scope 'install').
IF OBJECT_ID('cfg.InstallState') IS NULL
CREATE TABLE cfg.InstallState (
    Name        NVARCHAR(64)    NOT NULL CONSTRAINT PK_InstallState PRIMARY KEY,
    Value       NVARCHAR(400)   NOT NULL,
    [Version]   NVARCHAR(32)    NULL,       -- the release the value belongs to
    UpdatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_InstallState_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy   NVARCHAR(256)   NOT NULL
);

-- COMPONENTS OF THE INSTALLED CODE (CR3, #657; framework 12.11e item 3): one row per component -- a collection per source,
-- the correlation, Risk Analysis per report, data out per channel (config\release-scopes.locked.json). The UPDATER writes
-- the fingerprint of each after it installed a release (engine\_shared\SI-ReleaseControl.ps1, Save-SIReleaseScopeRecords):
-- a changed one gets ChangedUtc / ChangedVersion and GoodDays 0 = TESTING; the engines count a good daily run at the end of
-- each run (Update-SIReleaseScopeRun); 3 good days = STABLE. ChangedUtc NULL = never changed since the install recorded it.
IF OBJECT_ID('cfg.ReleaseScope') IS NULL
CREATE TABLE cfg.ReleaseScope (
    Scope           NVARCHAR(200)   NOT NULL CONSTRAINT PK_ReleaseScope PRIMARY KEY,
    Hash            CHAR(64)        NOT NULL,
    ChangedUtc      DATETIME2(0)    NULL,
    ChangedVersion  NVARCHAR(50)    NULL,
    GoodDays        INT             NOT NULL CONSTRAINT DF_ReleaseScope_GoodDays DEFAULT 0,
    LastGoodDay     DATE            NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_ReleaseScope_UpdatedAt DEFAULT SYSUTCDATETIME()
);

-- TEMPLATE PACKS (#235): a template version released per ring, independently of the code. The updater stages here the
-- pack its update ring approves (Origin 'feed'), the publisher the templates shipped with the installed code ('shipped');
-- the web app's Template releases page reads it and an Admin releases all of it, or only selected detection methods.
-- PackJson is the pack file EXACTLY as received -- Sha256 is the SHA-256 of its UTF-8 text, checked again by every reader.
-- A version is staged once and never changed (a pack is immutable once published). Every stage is logged in
-- cfg.ChangeLog (Name 'template-release', Kind 'pack-staged'); a verified release adds Kind 'released' and, for a whole
-- pack, cfg.InstallState 'TemplatePack'.
IF OBJECT_ID('cfg.TemplatePackStaged') IS NULL
CREATE TABLE cfg.TemplatePackStaged (
    PackVersion  NVARCHAR(32)    NOT NULL CONSTRAINT PK_TemplatePackStaged PRIMARY KEY,
    CodeVersion  NVARCHAR(32)    NOT NULL,   -- the release whose code built the pack
    Sha256       CHAR(64)        NOT NULL,
    Fingerprint  NVARCHAR(64)    NOT NULL,   -- the template-set fingerprint of the pack's items
    Ring         NVARCHAR(8)     NULL,       -- the ring that approved it (feed), NULL otherwise
    Origin       NVARCHAR(16)    NOT NULL,   -- feed | shipped | file
    IsFull       BIT             NOT NULL,
    ItemCount    INT             NOT NULL,
    ScopeJson    NVARCHAR(MAX)   NULL,       -- what a partial pack covers: kinds, detection methods, items
    PackJson     NVARCHAR(MAX)   NOT NULL,
    StagedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_TemplatePackStaged_StagedAt DEFAULT SYSUTCDATETIME(),
    StagedBy     NVARCHAR(256)   NOT NULL,
    CONSTRAINT CK_TemplatePackStaged_Origin CHECK (Origin IN ('feed', 'shipped', 'file')),
    CONSTRAINT CK_TemplatePackStaged_PackJson CHECK (ISJSON(PackJson) = 1)
);

-- Phase E (REQUIREMENTS §9.3.3 E): CONNECTORS DEFINED IN SQL.
-- One row per connector -- where the vulnerability close-loop sends its results (engine\asset-cmdb\_shared\SI-Connector.ps1).
--   Kind       sql | servicenow | rest           validated in code, no CHECK: the list will grow (see Phase C's note)
--   Direction  vulnerability | cmdb
--   Mode       whatif (plan, log, send nothing) | apply
--   SettingsJson    non-secret settings (a sql target's server + database, a ServiceNow table, ...)
--   SecretRefsJson  logical name -> Key Vault secret NAME. A secret's VALUE never enters this database.
--   MappingJson     a rest connector's auth + operations (listOpen / create / update / close / reopen) -- a new
--                   third-party system is a mapping, not code
-- No rows = the SI_VulnSync_* settings run as before. Every write is logged in cfg.ChangeLog
-- (Name 'connector/<name>', Scope 'connector', Kind 'connector').
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.Connector') IS NULL
CREATE TABLE cfg.Connector (
    ConnectorId     INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Connector PRIMARY KEY,
    Name            NVARCHAR(64)    NOT NULL,
    Kind            NVARCHAR(32)    NOT NULL,
    Direction       NVARCHAR(16)    NOT NULL CONSTRAINT DF_Connector_Direction DEFAULT 'vulnerability',
    Enabled         BIT             NOT NULL CONSTRAINT DF_Connector_Enabled DEFAULT 0,
    Mode            NVARCHAR(8)     NOT NULL CONSTRAINT DF_Connector_Mode DEFAULT 'whatif',
    AllowCreate     BIT             NOT NULL CONSTRAINT DF_Connector_AllowCreate DEFAULT 0,
    AllowClose      BIT             NOT NULL CONSTRAINT DF_Connector_AllowClose DEFAULT 0,
    SettingsJson    NVARCHAR(MAX)   NULL,
    SecretRefsJson  NVARCHAR(MAX)   NULL,
    MappingJson     NVARCHAR(MAX)   NULL,
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_Connector_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy       NVARCHAR(256)   NOT NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_Connector_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy       NVARCHAR(256)   NOT NULL,
    RowVersion      ROWVERSION      NOT NULL,
    CONSTRAINT UQ_Connector_Name UNIQUE (Name),
    CONSTRAINT CK_Connector_Mode CHECK (Mode IN ('whatif', 'apply')),
    CONSTRAINT CK_Connector_SettingsJson CHECK (SettingsJson IS NULL OR ISJSON(SettingsJson) = 1),
    CONSTRAINT CK_Connector_SecretRefsJson CHECK (SecretRefsJson IS NULL OR ISJSON(SecretRefsJson) = 1),
    CONSTRAINT CK_Connector_MappingJson CHECK (MappingJson IS NULL OR ISJSON(MappingJson) = 1)
);

-- One row per connector per close-loop run: what it planned, what landed, and how it ended
-- (success | partial | halted | whatif | failed | refused). Append-only; read by the GUI's Connector status page.
IF OBJECT_ID('cfg.ConnectorRun') IS NULL
CREATE TABLE cfg.ConnectorRun (
    ConnectorRunId  BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ConnectorRun PRIMARY KEY,
    ConnectorId     INT             NULL,       -- NULL = the SI_VulnSync_* settings (no connector row)
    ConnectorName   NVARCHAR(64)    NOT NULL,
    Kind            NVARCHAR(32)    NOT NULL,
    RunId           NVARCHAR(64)    NOT NULL,
    StartedAt       DATETIME2(0)    NOT NULL,
    EndedAt         DATETIME2(0)    NULL,
    Mode            NVARCHAR(8)     NOT NULL,
    AllowCreate     BIT             NOT NULL,
    AllowClose      BIT             NOT NULL,
    Outcome         NVARCHAR(16)    NOT NULL,
    PlanOpen        INT             NOT NULL CONSTRAINT DF_ConnectorRun_PlanOpen DEFAULT 0,
    PlanReopen      INT             NOT NULL CONSTRAINT DF_ConnectorRun_PlanReopen DEFAULT 0,
    PlanUpdate      INT             NOT NULL CONSTRAINT DF_ConnectorRun_PlanUpdate DEFAULT 0,
    PlanClose       INT             NOT NULL CONSTRAINT DF_ConnectorRun_PlanClose DEFAULT 0,
    Held            INT             NOT NULL CONSTRAINT DF_ConnectorRun_Held DEFAULT 0,
    Opened          INT             NOT NULL CONSTRAINT DF_ConnectorRun_Opened DEFAULT 0,
    Reopened        INT             NOT NULL CONSTRAINT DF_ConnectorRun_Reopened DEFAULT 0,
    Updated         INT             NOT NULL CONSTRAINT DF_ConnectorRun_Updated DEFAULT 0,
    Closed          INT             NOT NULL CONSTRAINT DF_ConnectorRun_Closed DEFAULT 0,
    Errors          INT             NOT NULL CONSTRAINT DF_ConnectorRun_Errors DEFAULT 0,
    NotSent         INT             NOT NULL CONSTRAINT DF_ConnectorRun_NotSent DEFAULT 0,
    HaltReason      NVARCHAR(400)   NULL,
    Error           NVARCHAR(2000)  NULL
);

-- A long step's time per phase (2026-10-25, engine/_shared/SI-StepPhase.ps1): Risk Analysis, the vulnerability close-loop
-- and the data sync write how long each phase took and how many rows it handled -- the step logs of an install cannot be
-- read through the Support app, its database can. Measurement only; append-only for the engine. Execution joins cfg.FlowStepRun.
IF OBJECT_ID('cfg.StepPhaseTime') IS NULL
CREATE TABLE cfg.StepPhaseTime (
    StepPhaseTimeId BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_StepPhaseTime PRIMARY KEY,
    Execution       NVARCHAR(128)   NULL,
    Job             NVARCHAR(64)    NOT NULL,
    Phase           NVARCHAR(128)   NOT NULL,
    Seconds         FLOAT           NOT NULL,
    [Rows]          BIGINT          NULL,
    AtUtc           DATETIME2(3)    NOT NULL CONSTRAINT DF_StepPhaseTime_At DEFAULT SYSUTCDATETIME()
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_StepPhaseTime_Execution' AND object_id = OBJECT_ID('cfg.StepPhaseTime'))
CREATE INDEX IX_StepPhaseTime_Execution ON cfg.StepPhaseTime (Execution, AtUtc);

-- A step's progress (2026-10-29, engine/_shared/SI-StepPhase.ps1 Write-SIStepProgress): ONE row per job execution -- its newest
-- sign of progress (every batch a long step writes moves LastUtc, at most every 5 minutes; the heartbeat and the pipeline runner
-- tell a step that moves from one that stands still, a warning only) and, where the engine knows it, what it does now and done /
-- total (Operations > Jobs shows it on the running step). Measurement only; Execution joins cfg.FlowStepRun.
IF OBJECT_ID('cfg.StepProgress') IS NULL
CREATE TABLE cfg.StepProgress (
    Execution       NVARCHAR(128)   NOT NULL CONSTRAINT PK_StepProgress PRIMARY KEY,
    Job             NVARCHAR(64)    NOT NULL,
    Phase           NVARCHAR(200)   NULL,
    Done            BIGINT          NULL,
    Total           BIGINT          NULL,
    LastUtc         DATETIME2(3)    NOT NULL CONSTRAINT DF_StepProgress_Last DEFAULT SYSUTCDATETIME(),
    Beats           BIGINT          NOT NULL CONSTRAINT DF_StepProgress_Beats DEFAULT 0
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConnectorRun_Name' AND object_id = OBJECT_ID('cfg.ConnectorRun'))
CREATE INDEX IX_ConnectorRun_Name ON cfg.ConnectorRun (ConnectorName, StartedAt);

-- A rest connector's CORRELATION KEY: the external id of every item it created <-> the SI finding (asset + CVE).
-- The connector reads only these rows as "its" items, so it can only update, close or reopen what it created itself --
-- an item someone else created in the other system is never touched. Rows are never removed: a closed item is what a
-- reopen is matched against.
IF OBJECT_ID('cfg.ConnectorItem') IS NULL
CREATE TABLE cfg.ConnectorItem (
    ConnectorId     INT             NOT NULL,
    ExternalId      NVARCHAR(256)   NOT NULL,
    CorrelationId   NVARCHAR(400)   NOT NULL,
    Cve             NVARCHAR(100)   NOT NULL,
    AssetName       NVARCHAR(400)   NULL,
    Severity        NVARCHAR(30)    NULL,
    State           NVARCHAR(20)    NOT NULL,
    FirstSeen       DATETIME2(0)    NOT NULL,
    LastSeen        DATETIME2(0)    NOT NULL,
    ClosedAt        DATETIME2(0)    NULL,
    CloseReason     NVARCHAR(400)   NULL,
    CreatedRunId    NVARCHAR(64)    NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_ConnectorItem_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_ConnectorItem PRIMARY KEY (ConnectorId, ExternalId),
    CONSTRAINT UQ_ConnectorItem_Finding UNIQUE (ConnectorId, CorrelationId, Cve),
    CONSTRAINT CK_ConnectorItem_State CHECK (State IN ('Open', 'Closed'))
);

-- THE WEB APP'S COLLECTION VIEWS (#241): "connector changes" reads the runs and the items changed in the window of one
-- collection (by time, across every connector). Covering on the time column, so neither reads the whole table.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConnectorRun_StartedAt' AND object_id = OBJECT_ID('cfg.ConnectorRun'))
CREATE INDEX IX_ConnectorRun_StartedAt ON cfg.ConnectorRun (StartedAt) INCLUDE (ConnectorName, Kind, Mode, Outcome, Opened, Reopened, Updated, Closed, Errors);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConnectorItem_UpdatedAt' AND object_id = OBJECT_ID('cfg.ConnectorItem'))
CREATE INDEX IX_ConnectorItem_UpdatedAt ON cfg.ConnectorItem (UpdatedAt) INCLUDE (State, Cve, AssetName, Severity, FirstSeen, ClosedAt);

-- #429 (operator 2026-10-07: "where is the logs for the connector changes -- what object, what ci, what field, before and now";
-- "time"; "we cannot have hidden connectors doing changes without telling customers"): THE CONNECTOR ITEM CHANGE LOG.
-- One row per item a connector wrote (or failed to write) in one run, for EVERY connector -- the vulnerability connectors,
-- the SQL CMDB connector, the ServiceNow hand-offs:
--   ChangedAt    the moment the write for THIS item returned (UTC; shown in the viewer's time zone), not the run's start
--   Action       opened | reopened | updated | closed | absence counted | created | retired | reactivated | written |
--                not opened | not updated | not closed | not reopened (a failure: Error says why)
--   ObjectName / ObjectKey   WHAT: the SecurityInsight asset (name + its CI key / SI id); Finding = the finding key (CVE, ...)
--   TargetTable / TargetKey  WHERE: the target table and the record's key there (sys_id, SQL key)
--   Field / ValueBefore / ValueNow   WHICH field, BEFORE and NOW -- ONE ROW PER CHANGED FIELD of the item (an item written
--                without a field -- a failure, a staged row -- is one row with no field). Only the fields SecurityInsight
--                sends, values cut to 400 characters: no payload copies. A "still seen" refresh that changes nothing is not
--                a change and is not logged.
-- Append-only for the connector jobs; rows older than the configuration-backup retention (SI_Pro_ConfigBackupRetentionDays,
-- default 90 days -- the change journal's rule, CONFIG-1 #404) are removed by cfg.ConnectorChangeRetentionApply, which each
-- connector job calls after it has written its rows.
IF OBJECT_ID('cfg.ConnectorChange') IS NULL
CREATE TABLE cfg.ConnectorChange (
    ChangeId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ConnectorChange PRIMARY KEY,
    ConnectorName   NVARCHAR(64)    NOT NULL,
    RunId           NVARCHAR(64)    NOT NULL,
    ChangedAt       DATETIME2(3)    NOT NULL,
    Action          NVARCHAR(24)    NOT NULL,
    ObjectName      NVARCHAR(400)   NULL,
    ObjectKey       NVARCHAR(400)   NULL,
    Finding         NVARCHAR(256)   NULL,
    TargetTable     NVARCHAR(200)   NULL,
    TargetKey       NVARCHAR(256)   NULL,
    Field           NVARCHAR(128)   NULL,
    ValueBefore     NVARCHAR(400)   NULL,
    ValueNow        NVARCHAR(400)   NULL,
    Reason          NVARCHAR(400)   NULL,
    Error           NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConnectorChange_ChangedAt' AND object_id = OBJECT_ID('cfg.ConnectorChange'))
CREATE INDEX IX_ConnectorChange_ChangedAt ON cfg.ConnectorChange (ChangedAt) INCLUDE (ConnectorName, RunId, Action, ObjectName, ObjectKey, Finding, TargetTable, TargetKey, Field);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConnectorChange_Run' AND object_id = OBJECT_ID('cfg.ConnectorChange'))
CREATE INDEX IX_ConnectorChange_Run ON cfg.ConnectorChange (ConnectorName, RunId);

-- #429: a "still seen" refresh is counted apart from an update (Updated = a field SecurityInsight sends really changed).
IF COL_LENGTH('cfg.ConnectorRun', 'Unchanged') IS NULL
ALTER TABLE cfg.ConnectorRun ADD Unchanged INT NOT NULL CONSTRAINT DF_ConnectorRun_Unchanged DEFAULT 0;

-- #406 (owner 2026-10-19: "just release auto"): the records a run closed because the CI lifecycle RETIRED their asset (not
-- seen past its category's grace period, or every source said it is gone) -- closed outside the close limit, counted here.
IF COL_LENGTH('cfg.ConnectorRun', 'RetiredClosed') IS NULL
ALTER TABLE cfg.ConnectorRun ADD RetiredClosed INT NOT NULL CONSTRAINT DF_ConnectorRun_RetiredClosed DEFAULT 0;

-- #429: the ONE removal of connector change rows -- older than the configuration-backup retention (default 90 days).
-- Runs only for a job identity (db_datawriter) or the owner, a batch at a time.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.ConnectorChangeRetentionApply @Batch INT = 5000
AS
BEGIN
    SET NOCOUNT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51425, N''only a connector job may apply the connector change log retention -- nothing was removed'', 1;
    DECLARE @days INT = (SELECT TOP (1) TRY_CONVERT(INT, JSON_VALUE(N''['' + s.ValueJson + N'']'', ''$[0]'')) FROM cfg.Setting AS s
                         WHERE s.Name = N''SI_Pro_ConfigBackupRetentionDays'' AND s.Scope = N''solution'' AND s.ValueJson IS NOT NULL AND ISJSON(N''['' + s.ValueJson + N'']'') = 1);
    IF @days IS NULL OR @days < 1 SET @days = 90;
    IF @Batch IS NULL OR @Batch < 1 SET @Batch = 5000;
    DELETE TOP (@Batch) FROM cfg.ConnectorChange WHERE ChangedAt < DATEADD(DAY, -@days, SYSUTCDATETIME());
    SELECT @@ROWCOUNT AS N;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.ConnectorChangeRetentionApply TO public;

-- DATA OUT (ADDED 2026-10-10, V3-DATA-MODEL 2.12): what each data-out connector (config/data-out.locked.json: the CI and
-- findings workbooks, the ServiceNow Import Set hand-offs) sent last time, one row per output and item -- the BEFORE its
-- next run compares with, so the item change log (cfg.ConnectorChange) carries each changed column before and now and a
-- ServiceNow hand-off sends only what is new or changed. RowJson = the row as sent (column -> text, the run's own columns
-- left out). Written by the data-out step only after its destination accepted everything; a removed item's row is deleted.
IF OBJECT_ID('cfg.DataOutItem') IS NULL
CREATE TABLE cfg.DataOutItem (
    OutputId    NVARCHAR(64)    NOT NULL,
    ItemKey     NVARCHAR(380)   NOT NULL,   -- a longer key is kept as its first part + a hash (the index key stays under 900 bytes)
    RowHash     CHAR(64)        NOT NULL,
    RowJson     NVARCHAR(MAX)   NULL,
    SentAt      DATETIME2(3)    NOT NULL,
    RunId       NVARCHAR(64)    NULL,
    CONSTRAINT PK_DataOutItem PRIMARY KEY (OutputId, ItemKey)
);

-- #914 THE BATCHES OF THE DATA-OUT CONTRACT (ADDED 2026-10-27): SecurityInsight's own record of every batch it sent to a
-- ServiceNow output -- the same id the staging status table and every data row carry (u_si_batch_id = '<run id>:<output>',
-- '...:test' for a test batch). State writing -> complete | failed | held; a batch still 'writing' when the next sync of the
-- same output starts is ended 'failed' with the reason (never two open batches per output). The counts per action are the
-- end row's; the Import* columns are the target's own import result, read back at the next sync (FeedbackAt). RequestToken =
-- the resync / test request the batch carried out (SI_DataOut_ServiceNowRequest). Additive; nothing is ever deleted here
-- by SecurityInsight except by the retention of the run history.
IF OBJECT_ID('cfg.DataOutBatch') IS NULL
CREATE TABLE cfg.DataOutBatch (
    BatchId          NVARCHAR(160)  NOT NULL CONSTRAINT PK_DataOutBatch PRIMARY KEY,
    OutputId         NVARCHAR(64)   NOT NULL,
    Connector        NVARCHAR(100)  NULL,
    RunId            NVARCHAR(64)   NOT NULL,
    State            NVARCHAR(16)   NOT NULL,
    Mode             NVARCHAR(16)   NOT NULL CONSTRAINT DF_DataOutBatch_Mode DEFAULT N'live',
    ContractVersion  NVARCHAR(16)   NOT NULL,
    TargetTable      NVARCHAR(80)   NULL,
    StartedAt        DATETIME2(3)   NOT NULL,
    FinishedAt       DATETIME2(3)   NULL,
    PlannedRows      BIGINT         NULL,
    SentRows         BIGINT         NULL,
    FailedRows       BIGINT         NULL,
    NewRows          BIGINT         NULL,
    UpdateRows       BIGINT         NULL,
    CloseRows        BIGINT         NULL,
    ReopenRows       BIGINT         NULL,
    HeldRows         BIGINT         NULL,
    OutOfScopeRows   BIGINT         NULL,
    ImportSetIds     NVARCHAR(MAX)  NULL,
    Reason           NVARCHAR(1000) NULL,
    RequestToken     NVARCHAR(100)  NULL,
    FeedbackAt       DATETIME2(3)   NULL,
    ImportInserted   BIGINT         NULL,
    ImportUpdated    BIGINT         NULL,
    ImportIgnored    BIGINT         NULL,
    ImportSkipped    BIGINT         NULL,
    ImportErrors     BIGINT         NULL,
    ImportPending    BIGINT         NULL,
    FeedbackNote     NVARCHAR(400)  NULL,
    CONSTRAINT CK_DataOutBatch_State CHECK (State IN ('writing', 'complete', 'failed', 'held')),
    CONSTRAINT CK_DataOutBatch_Mode CHECK (Mode IN ('live', 'resync', 'test'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DataOutBatch_Output' AND object_id = OBJECT_ID('cfg.DataOutBatch'))
CREATE INDEX IX_DataOutBatch_Output ON cfg.DataOutBatch (OutputId, State, StartedAt DESC) INCLUDE (Mode, FinishedAt, FeedbackAt, RequestToken);

-- =============================================================================================
-- THE CMDB (#256): business services, the assets that belong to them, and which source is authoritative.
--   cfg.CmdbService       one row per service. Source = the CMDB the row came from:
--                           SI                   homed in SecurityInsight -- added, edited and retired on the CMDB page
--                           External-CSV         imported from a CMDB.csv (the v2.2 format), read-only in SecurityInsight
--                           External-Connector   pulled from ServiceNow through the connector, read-only in SecurityInsight
--                         ServiceNumber: SI generates SVC-0001, SVC-0002, ... from cfg.CmdbServiceNumber (a sequence, so a
--                         number is never reused, not even after a retire or a rolled-back insert); an external row keeps
--                         the source's own id (CMDB.csv cmdbID, ServiceNow number). ExternalId: the id in the source (a
--                         migrated service: its v2.2 cmdbID). The CMDB.csv columns are columns; any other CSV column is kept
--                         verbatim in ExtraJson. Department names the owning department (#254). A service is RETIRED,
--                         never removed: RetiredAt is set and its history stays.
--   cfg.CmdbServiceAsset  one row per link (service <-> asset). Unlinking sets UnlinkedAt; linking again adds a new row, so
--                         the history of who linked what, when, stays. AssetKey = sidata.Asset.AssetKey. An asset may
--                         belong to several services.
--   cfg.CmdbImport        one row per import (a CSV upload, a scheduled CSV path, a connector pull, the one-time migration):
--                         what it added, changed, retired, linked, unlinked and rejected.
-- ONE SOURCE IS AUTHORITATIVE AT A TIME: the setting SIWeb_CmdbSource (scope 'engine:management-web'; SI when unset). Rows
-- of the other sources stay stored, unused; switching never copies or merges anything. cfg.vCmdbAssetService is the
-- CMDB's current membership; the data sync plugs it into THE service-membership resolver (Get-SIDataServiceSources,
-- sidata.ServiceMember per collection) as the authoritative source, so every consumer reads services one way.
-- Every change has its cfg.ChangeLog row (Scope 'cmdb').
-- No Source CHECK (the list may grow -- see phase C's note); the writers validate it.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.CmdbServiceNumber') IS NULL
CREATE SEQUENCE cfg.CmdbServiceNumber AS INT START WITH 1 INCREMENT BY 1 NO CYCLE;

IF OBJECT_ID('cfg.CmdbService') IS NULL
CREATE TABLE cfg.CmdbService (
    ServiceId        INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_CmdbService PRIMARY KEY,
    Source           NVARCHAR(24)    NOT NULL,
    ServiceNumber    NVARCHAR(64)    NOT NULL,
    ExternalId       NVARCHAR(128)   NULL,
    Name             NVARCHAR(256)   NOT NULL,
    Description      NVARCHAR(2000)  NULL,
    Owner            NVARCHAR(256)   NULL,
    OwnerMail        NVARCHAR(256)   NULL,
    Criticality      NVARCHAR(32)    NULL,      -- Critical | High | Medium | Low (risk weighting reads these words)
    DataSensitivity  NVARCHAR(32)    NULL,      -- Restricted | Confidential | Internal | Public
    Environment      NVARCHAR(64)    NULL,
    Department       NVARCHAR(128)   NULL,
    ExtraJson        NVARCHAR(MAX)   NULL,      -- every other CMDB.csv column, verbatim: {"column": "value"}
    CreatedAt        DATETIME2(0)    NOT NULL CONSTRAINT DF_CmdbService_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy        NVARCHAR(256)   NOT NULL,
    UpdatedAt        DATETIME2(0)    NOT NULL CONSTRAINT DF_CmdbService_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy        NVARCHAR(256)   NOT NULL,
    RetiredAt        DATETIME2(0)    NULL,
    RetiredBy        NVARCHAR(256)   NULL,
    RetireReason     NVARCHAR(400)   NULL,
    RowVersion       ROWVERSION      NOT NULL,
    CONSTRAINT UQ_CmdbService_Number UNIQUE (Source, ServiceNumber),
    CONSTRAINT CK_CmdbService_ExtraJson CHECK (ExtraJson IS NULL OR ISJSON(ExtraJson) = 1)
);

IF OBJECT_ID('cfg.CmdbServiceAsset') IS NULL
CREATE TABLE cfg.CmdbServiceAsset (
    LinkId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_CmdbServiceAsset PRIMARY KEY,
    ServiceId    INT             NOT NULL CONSTRAINT FK_CmdbServiceAsset_Service REFERENCES cfg.CmdbService (ServiceId),
    AssetKey     NVARCHAR(400)   NOT NULL,
    AssetName    NVARCHAR(400)   NULL,
    LinkedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_CmdbServiceAsset_LinkedAt DEFAULT SYSUTCDATETIME(),
    LinkedBy     NVARCHAR(256)   NOT NULL,
    UnlinkedAt   DATETIME2(0)    NULL,
    UnlinkedBy   NVARCHAR(256)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_CmdbServiceAsset_Current' AND object_id = OBJECT_ID('cfg.CmdbServiceAsset'))
CREATE UNIQUE INDEX UX_CmdbServiceAsset_Current ON cfg.CmdbServiceAsset (ServiceId, AssetKey) WHERE UnlinkedAt IS NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbServiceAsset_Asset' AND object_id = OBJECT_ID('cfg.CmdbServiceAsset'))
CREATE INDEX IX_CmdbServiceAsset_Asset ON cfg.CmdbServiceAsset (AssetKey) INCLUDE (ServiceId) WHERE UnlinkedAt IS NULL;

IF OBJECT_ID('cfg.CmdbImport') IS NULL
CREATE TABLE cfg.CmdbImport (
    ImportId           BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_CmdbImport PRIMARY KEY,
    Source             NVARCHAR(24)    NOT NULL,
    Kind               NVARCHAR(24)    NOT NULL,   -- migration | csv-upload | csv-path | connector
    Origin             NVARCHAR(400)   NULL,       -- the file name, the path or the connector
    Sha256             NVARCHAR(64)    NULL,       -- of the file(s) imported
    ImportedAt         DATETIME2(0)    NOT NULL CONSTRAINT DF_CmdbImport_ImportedAt DEFAULT SYSUTCDATETIME(),
    ImportedBy         NVARCHAR(256)   NOT NULL,
    Outcome            NVARCHAR(24)    NOT NULL,   -- Imported | Refused | AlreadyImported
    Message            NVARCHAR(400)   NULL,
    ServicesAdded      INT             NOT NULL CONSTRAINT DF_CmdbImport_ServicesAdded DEFAULT 0,
    ServicesUpdated    INT             NOT NULL CONSTRAINT DF_CmdbImport_ServicesUpdated DEFAULT 0,
    ServicesRetired    INT             NOT NULL CONSTRAINT DF_CmdbImport_ServicesRetired DEFAULT 0,
    ServicesSkipped    INT             NOT NULL CONSTRAINT DF_CmdbImport_ServicesSkipped DEFAULT 0,
    ServicesUnchanged  INT             NOT NULL CONSTRAINT DF_CmdbImport_ServicesUnchanged DEFAULT 0,
    LinksAdded         INT             NOT NULL CONSTRAINT DF_CmdbImport_LinksAdded DEFAULT 0,
    LinksRemoved       INT             NOT NULL CONSTRAINT DF_CmdbImport_LinksRemoved DEFAULT 0,
    LinksRejected      INT             NOT NULL CONSTRAINT DF_CmdbImport_LinksRejected DEFAULT 0,
    RejectedJson       NVARCHAR(MAX)   NULL        -- the links that were not imported, and why (at most 500)
);

-- The authoritative source: the SIWeb_CmdbSource setting, SI when it is not set.
IF OBJECT_ID('cfg.vCmdbSource') IS NULL
EXEC ('CREATE VIEW cfg.vCmdbSource AS
SELECT COALESCE((SELECT TOP (1) CASE WHEN ISJSON(N''['' + s.ValueJson + N'']'') = 1 THEN JSON_VALUE(N''['' + s.ValueJson + N'']'', ''$[0]'') END FROM cfg.Setting AS s
                 WHERE s.Name = N''SIWeb_CmdbSource'' AND s.Scope = N''engine:management-web''), N''SI'') AS ActiveSource');

-- The services of the authoritative source that are not retired.
IF OBJECT_ID('cfg.vCmdbService') IS NULL
EXEC ('CREATE VIEW cfg.vCmdbService AS
SELECT s.ServiceId, s.Source, s.ServiceNumber, s.ExternalId, s.Name, s.Description, s.Owner, s.OwnerMail, s.Criticality, s.DataSensitivity,
       s.Environment, s.Department, s.ExtraJson,
       CASE s.Criticality WHEN N''Critical'' THEN 1 WHEN N''High'' THEN 2 WHEN N''Medium'' THEN 3 WHEN N''Low'' THEN 4 ELSE 9 END AS CriticalityRank
FROM cfg.CmdbService AS s
JOIN cfg.vCmdbSource AS a ON a.ActiveSource = s.Source
WHERE s.RetiredAt IS NULL');

-- The CMDB's current membership: one row per (asset, service) of the authoritative source -- an asset in two services
-- has two rows. The data sync's 'cmdb' service source reads it (engine\_shared\data-sql\SI-DataSql.ps1).
IF OBJECT_ID('cfg.vCmdbAssetService') IS NULL
EXEC ('CREATE VIEW cfg.vCmdbAssetService AS
SELECT m.AssetKey, s.ServiceId, s.ServiceNumber, s.Name AS ServiceName, s.Criticality, s.CriticalityRank, s.DataSensitivity, s.Environment,
       s.Owner, s.OwnerMail, s.Department, s.Source, m.LinkedAt
FROM cfg.CmdbServiceAsset AS m
JOIN cfg.vCmdbService AS s ON s.ServiceId = m.ServiceId
WHERE m.UnlinkedAt IS NULL');

-- One import -- the one-time migration of a v2.2 CMDB.csv into the SecurityInsight CMDB, or a snapshot of an external
-- CMDB (a CSV or the connector) -- in ONE transaction with its cfg.CmdbImport and cfg.ChangeLog rows. @Payload:
--   {"services":[{"number","externalId","name","description","owner","ownerMail","criticality","dataSensitivity",
--                 "environment","department","extra":{...}}], "links":[{"number","assetKey","assetName"}], "linksIncluded":true}
-- A snapshot makes the source's services exactly the file's: new ones added, changed ones updated, missing ones RETIRED
-- (never removed); with linksIncluded its links too (missing ones unlinked). A migration (@Source 'SI') runs once:
-- every service gets a new SVC number (its cmdbID kept as ExternalId). A link's asset is matched by AssetKey, then by a
-- unique identifier, then by a unique asset name; one that does not match is reported, not stored. Both the web app
-- and the PowerShell import call THIS procedure, so the two cannot import differently. Called by the SecurityInsight
-- writers only; a later change ships as a new procedure name (this file never alters an object).
IF OBJECT_ID('cfg.CmdbImportSnapshot') IS NULL
EXEC (N'CREATE PROCEDURE cfg.CmdbImportSnapshot
    @Source NVARCHAR(24), @Kind NVARCHAR(24), @Origin NVARCHAR(400), @Sha256 NVARCHAR(64), @Payload NVARCHAR(MAX), @By NVARCHAR(256), @Reason NVARCHAR(400)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME(), @outcome NVARCHAR(24) = N''Imported'', @why NVARCHAR(400) = NULL, @importId BIGINT;
    DECLARE @added INT = 0, @updated INT = 0, @retired INT = 0, @skipped INT = 0, @unchanged INT = 0, @linksAdded INT = 0, @linksRemoved INT = 0, @linksRejected INT = 0, @rejected NVARCHAR(MAX) = NULL;
    IF @Source NOT IN (N''SI'', N''External-CSV'', N''External-Connector'') SELECT @outcome = N''Refused'', @why = N''unknown CMDB source'';
    ELSE IF @Kind NOT IN (N''migration'', N''csv-upload'', N''csv-path'', N''connector'') SELECT @outcome = N''Refused'', @why = N''unknown import kind'';
    ELSE IF ISJSON(@Payload) <> 1 SELECT @outcome = N''Refused'', @why = N''the import is not valid JSON'';
    ELSE IF @Source = N''SI'' AND @Kind <> N''migration'' SELECT @outcome = N''Refused'', @why = N''the SecurityInsight CMDB is edited on the CMDB page; only the one-time migration of a CMDB.csv imports into it'';
    ELSE IF @Source <> N''SI'' AND @Kind = N''migration'' SELECT @outcome = N''Refused'', @why = N''a migration imports into the SecurityInsight CMDB only'';
    ELSE IF @Kind = N''migration'' AND EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N''CmdbMigration'') SELECT @outcome = N''AlreadyImported'', @why = (SELECT N''a CMDB.csv was already imported: '' + Value FROM cfg.InstallState WHERE Name = N''CmdbMigration'');
    IF @outcome <> N''Imported''
    BEGIN
        INSERT cfg.CmdbImport (Source, Kind, Origin, Sha256, ImportedBy, Outcome, Message) VALUES (@Source, @Kind, @Origin, @Sha256, @By, @outcome, @why);
        SELECT @outcome AS Outcome, @why AS Message, CONVERT(BIGINT, SCOPE_IDENTITY()) AS ImportId, 0 AS ServicesAdded, 0 AS ServicesUpdated, 0 AS ServicesRetired, 0 AS ServicesSkipped, 0 AS ServicesUnchanged, 0 AS LinksAdded, 0 AS LinksRemoved, 0 AS LinksRejected, CONVERT(NVARCHAR(MAX), NULL) AS RejectedJson;
        RETURN;
    END;
    DECLARE @svc TABLE (Ord INT NOT NULL, Number NVARCHAR(64) NOT NULL, ExternalId NVARCHAR(128) NULL, Name NVARCHAR(256) NOT NULL, Description NVARCHAR(2000) NULL, Owner NVARCHAR(256) NULL, OwnerMail NVARCHAR(256) NULL, Criticality NVARCHAR(32) NULL, DataSensitivity NVARCHAR(32) NULL, Environment NVARCHAR(64) NULL, Department NVARCHAR(128) NULL, ExtraJson NVARCHAR(MAX) NULL);
    INSERT @svc (Ord, Number, ExternalId, Name, Description, Owner, OwnerMail, Criticality, DataSensitivity, Environment, Department, ExtraJson)
    SELECT CONVERT(INT, j.[key]), w.number, NULLIF(w.externalId, N''''), w.name, NULLIF(w.description, N''''), NULLIF(w.owner, N''''), NULLIF(w.ownerMail, N''''), NULLIF(w.criticality, N''''), NULLIF(w.dataSensitivity, N''''), NULLIF(w.environment, N''''), NULLIF(w.department, N''''), CASE WHEN w.extra IS NULL OR w.extra = N''{}'' THEN NULL ELSE w.extra END
    FROM OPENJSON(@Payload, N''$.services'') AS j
    CROSS APPLY OPENJSON(j.value) WITH (number NVARCHAR(64) N''$.number'', externalId NVARCHAR(128) N''$.externalId'', name NVARCHAR(256) N''$.name'', description NVARCHAR(2000) N''$.description'', owner NVARCHAR(256) N''$.owner'', ownerMail NVARCHAR(256) N''$.ownerMail'', criticality NVARCHAR(32) N''$.criticality'', dataSensitivity NVARCHAR(32) N''$.dataSensitivity'', environment NVARCHAR(64) N''$.environment'', department NVARCHAR(128) N''$.department'', extra NVARCHAR(MAX) N''$.extra'' AS JSON) AS w
    WHERE NULLIF(w.number, N'''') IS NOT NULL AND NULLIF(w.name, N'''') IS NOT NULL;
    IF EXISTS (SELECT Number FROM @svc GROUP BY Number HAVING COUNT(*) > 1)
    BEGIN
        SELECT @outcome = N''Refused'', @why = N''a service number appears more than once in the import'';
        INSERT cfg.CmdbImport (Source, Kind, Origin, Sha256, ImportedBy, Outcome, Message) VALUES (@Source, @Kind, @Origin, @Sha256, @By, @outcome, @why);
        SELECT @outcome AS Outcome, @why AS Message, CONVERT(BIGINT, SCOPE_IDENTITY()) AS ImportId, 0 AS ServicesAdded, 0 AS ServicesUpdated, 0 AS ServicesRetired, 0 AS ServicesSkipped, 0 AS ServicesUnchanged, 0 AS LinksAdded, 0 AS LinksRemoved, 0 AS LinksRejected, CONVERT(NVARCHAR(MAX), NULL) AS RejectedJson;
        RETURN;
    END;
    DECLARE @linksIncluded BIT = CASE WHEN LOWER(COALESCE(JSON_VALUE(@Payload, N''$.linksIncluded''), N''false'')) = N''true'' THEN 1 ELSE 0 END;
    DECLARE @lnk TABLE (Number NVARCHAR(64) NULL, AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL, ServiceId INT NULL, ResolvedKey NVARCHAR(400) NULL);
    INSERT @lnk (Number, AssetKey, AssetName)
    SELECT NULLIF(w.number, N''''), NULLIF(w.assetKey, N''''), NULLIF(w.assetName, N'''')
    FROM OPENJSON(@Payload, N''$.links'') WITH (number NVARCHAR(64) N''$.number'', assetKey NVARCHAR(400) N''$.assetKey'', assetName NVARCHAR(400) N''$.assetName'') AS w;
    BEGIN TRAN;
    IF @Kind = N''migration''
    BEGIN
        DECLARE @todo TABLE (Ord INT NOT NULL PRIMARY KEY);
        INSERT @todo (Ord) SELECT v.Ord FROM @svc AS v WHERE NOT EXISTS (SELECT 1 FROM cfg.CmdbService AS s WHERE s.Source = N''SI'' AND s.ExternalId = v.Number);
        SET @skipped = (SELECT COUNT(*) FROM @svc) - (SELECT COUNT(*) FROM @todo);
        DECLARE @num TABLE (Ord INT NOT NULL PRIMARY KEY, Seq INT NOT NULL);
        INSERT @num (Ord, Seq) SELECT t.Ord, NEXT VALUE FOR cfg.CmdbServiceNumber OVER (ORDER BY t.Ord) FROM @todo AS t;
        INSERT cfg.CmdbService (Source, ServiceNumber, ExternalId, Name, Description, Owner, OwnerMail, Criticality, DataSensitivity, Environment, Department, ExtraJson, CreatedBy, UpdatedBy)
        SELECT N''SI'', N''SVC-'' + CASE WHEN n.Seq < 10000 THEN RIGHT(N''0000'' + CONVERT(NVARCHAR(12), n.Seq), 4) ELSE CONVERT(NVARCHAR(12), n.Seq) END,
               v.Number, v.Name, v.Description, v.Owner, v.OwnerMail, v.Criticality, v.DataSensitivity, v.Environment, v.Department, v.ExtraJson, @By, @By
        FROM @svc AS v JOIN @num AS n ON n.Ord = v.Ord;
        SET @added = @@ROWCOUNT;
        UPDATE l SET ServiceId = s.ServiceId FROM @lnk AS l JOIN cfg.CmdbService AS s ON s.Source = N''SI'' AND s.ExternalId = l.Number AND s.RetiredAt IS NULL;
    END
    ELSE
    BEGIN
        UPDATE s SET Name = v.Name, ExternalId = v.ExternalId, Description = v.Description, Owner = v.Owner, OwnerMail = v.OwnerMail, Criticality = v.Criticality, DataSensitivity = v.DataSensitivity,
                     Environment = v.Environment, Department = v.Department, ExtraJson = v.ExtraJson, RetiredAt = NULL, RetiredBy = NULL, RetireReason = NULL, UpdatedAt = @now, UpdatedBy = @By
        FROM cfg.CmdbService AS s JOIN @svc AS v ON s.Source = @Source AND s.ServiceNumber = v.Number
        WHERE s.RetiredAt IS NOT NULL OR EXISTS (SELECT s.Name, s.ExternalId, s.Description, s.Owner, s.OwnerMail, s.Criticality, s.DataSensitivity, s.Environment, s.Department, s.ExtraJson
                                                 EXCEPT SELECT v.Name, v.ExternalId, v.Description, v.Owner, v.OwnerMail, v.Criticality, v.DataSensitivity, v.Environment, v.Department, v.ExtraJson);
        SET @updated = @@ROWCOUNT;
        INSERT cfg.CmdbService (Source, ServiceNumber, ExternalId, Name, Description, Owner, OwnerMail, Criticality, DataSensitivity, Environment, Department, ExtraJson, CreatedBy, UpdatedBy)
        SELECT @Source, v.Number, v.ExternalId, v.Name, v.Description, v.Owner, v.OwnerMail, v.Criticality, v.DataSensitivity, v.Environment, v.Department, v.ExtraJson, @By, @By
        FROM @svc AS v WHERE NOT EXISTS (SELECT 1 FROM cfg.CmdbService AS s WHERE s.Source = @Source AND s.ServiceNumber = v.Number);
        SET @added = @@ROWCOUNT;
        UPDATE s SET RetiredAt = @now, RetiredBy = @By, RetireReason = N''not in the latest import'', UpdatedAt = @now, UpdatedBy = @By
        FROM cfg.CmdbService AS s
        WHERE s.Source = @Source AND s.RetiredAt IS NULL AND NOT EXISTS (SELECT 1 FROM @svc AS v WHERE v.Number = s.ServiceNumber);
        SET @retired = @@ROWCOUNT;
        SET @unchanged = (SELECT COUNT(*) FROM @svc) - @added - @updated;
        UPDATE l SET ServiceId = s.ServiceId FROM @lnk AS l JOIN cfg.CmdbService AS s ON s.Source = @Source AND s.ServiceNumber = l.Number AND s.RetiredAt IS NULL;
    END;
    IF SCHEMA_ID(N''sidata'') IS NOT NULL AND OBJECT_ID(N''sidata.Asset'') IS NOT NULL
    BEGIN
        UPDATE l SET ResolvedKey = a.AssetKey FROM @lnk AS l JOIN sidata.Asset AS a ON a.AssetKey = l.AssetKey WHERE l.AssetKey IS NOT NULL;
        UPDATE l SET ResolvedKey = x.AssetKey
        FROM @lnk AS l
        CROSS APPLY (SELECT MIN(i.AssetKey) AS AssetKey, COUNT(DISTINCT i.AssetKey) AS N FROM sidata.AssetIdentifier AS i WHERE i.IdentifierValue = LOWER(l.AssetKey)) AS x
        WHERE l.ResolvedKey IS NULL AND l.AssetKey IS NOT NULL AND x.N = 1;
        UPDATE l SET ResolvedKey = x.AssetKey
        FROM @lnk AS l
        CROSS APPLY (SELECT MIN(a.AssetKey) AS AssetKey, COUNT(*) AS N FROM sidata.Asset AS a WHERE a.AssetName = l.AssetName) AS x
        WHERE l.ResolvedKey IS NULL AND l.AssetName IS NOT NULL AND x.N = 1;
    END;
    SET @linksRejected = (SELECT COUNT(*) FROM @lnk WHERE ServiceId IS NULL OR ResolvedKey IS NULL);
    SET @rejected = (SELECT TOP (500) l.Number AS number, l.AssetKey AS assetKey, l.AssetName AS assetName,
                            CASE WHEN l.ServiceId IS NULL THEN N''no such service in this import'' ELSE N''the asset is not known to SecurityInsight (or its name is not unique)'' END AS why
                     FROM @lnk AS l WHERE l.ServiceId IS NULL OR l.ResolvedKey IS NULL FOR JSON PATH);
    IF @Kind <> N''migration'' AND @linksIncluded = 1
    BEGIN
        UPDATE m SET UnlinkedAt = @now, UnlinkedBy = @By
        FROM cfg.CmdbServiceAsset AS m JOIN cfg.CmdbService AS s ON s.ServiceId = m.ServiceId
        WHERE s.Source = @Source AND m.UnlinkedAt IS NULL
          AND NOT EXISTS (SELECT 1 FROM @lnk AS l WHERE l.ServiceId = m.ServiceId AND l.ResolvedKey = m.AssetKey);
        SET @linksRemoved = @@ROWCOUNT;
    END;
    INSERT cfg.CmdbServiceAsset (ServiceId, AssetKey, AssetName, LinkedBy)
    SELECT l.ServiceId, l.ResolvedKey, MAX(l.AssetName), @By
    FROM @lnk AS l
    WHERE l.ServiceId IS NOT NULL AND l.ResolvedKey IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM cfg.CmdbServiceAsset AS m WHERE m.ServiceId = l.ServiceId AND m.AssetKey = l.ResolvedKey AND m.UnlinkedAt IS NULL)
    GROUP BY l.ServiceId, l.ResolvedKey;
    SET @linksAdded = @@ROWCOUNT;
    INSERT cfg.CmdbImport (Source, Kind, Origin, Sha256, ImportedBy, Outcome, Message, ServicesAdded, ServicesUpdated, ServicesRetired, ServicesSkipped, ServicesUnchanged, LinksAdded, LinksRemoved, LinksRejected, RejectedJson)
    VALUES (@Source, @Kind, @Origin, @Sha256, @By, @outcome, @Reason, @added, @updated, @retired, @skipped, @unchanged, @linksAdded, @linksRemoved, @linksRejected, @rejected);
    SET @importId = CONVERT(BIGINT, SCOPE_IDENTITY());
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (N''cmdb/import/'' + CONVERT(NVARCHAR(20), @importId), N''cmdb'', N''cmdb-import'', N''Set'', NULL,
            (SELECT @Source AS source, @Kind AS kind, @Origin AS origin, @added AS servicesAdded, @updated AS servicesUpdated, @retired AS servicesRetired, @skipped AS servicesSkipped,
                    @linksAdded AS linksAdded, @linksRemoved AS linksRemoved, @linksRejected AS linksRejected FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
            @By, @Reason);
    IF @Kind = N''migration''
        INSERT cfg.InstallState (Name, Value, UpdatedBy)
        VALUES (N''CmdbMigration'', LEFT(CONVERT(NVARCHAR(30), @now, 120) + N'': '' + CONVERT(NVARCHAR(12), @added) + N'' service(s), '' + CONVERT(NVARCHAR(12), @linksAdded) + N'' link(s) from '' + COALESCE(@Origin, N''a CMDB.csv''), 400), @By);
    COMMIT;
    SELECT @outcome AS Outcome, @why AS Message, @importId AS ImportId, @added AS ServicesAdded, @updated AS ServicesUpdated, @retired AS ServicesRetired, @skipped AS ServicesSkipped, @unchanged AS ServicesUnchanged,
           @linksAdded AS LinksAdded, @linksRemoved AS LinksRemoved, @linksRejected AS LinksRejected, @rejected AS RejectedJson;
END');

-- =============================================================================================

-- ASSET RESPONSIBILITY (REQUIREMENTS #254, phase 1): departments own assets and security recommendations.
-- The data sync resolves every finding to a department (sidata.Finding.DepartmentId + its SOURCE) with this precedence:
--   1. a RECOMMENDATION override (cfg.ResponsibilityOverride, Scope 'recommendation': one ConfigurationId / CVE, every asset)
--   2. an ASSET override (Scope 'asset')
--   3. the policy: its sources in the order the settings name (SI_Pro_Responsibility_Sources, default tags then rules) --
--      the platform tags named in SI_Pro_Responsibility_TagNames, then the SI definitions in cfg.ResponsibilityRule
--   4. the default department (SI_Pro_Responsibility_DefaultDepartment), else Unassigned.
-- A department is never removed (findings already stamped with it keep pointing at it): retiring sets RetiredAt, and a
-- retired department takes part in no resolution. Every write here is logged in cfg.ChangeLog (Kind 'department' or
-- 'responsibility'). The tables carry no kind / role CHECK: the lists grow (see the note on cfg.Template above).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.Department') IS NULL
CREATE TABLE cfg.Department (
    DepartmentId           INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Department PRIMARY KEY,
    Name                   NVARCHAR(128)   NOT NULL,
    Mail                   NVARCHAR(256)   NULL,       -- the department's shared mailbox (optional)
    Description            NVARCHAR(400)   NULL,
    MatchValues            NVARCHAR(1000)  NULL,       -- ';'-separated tag values that also mean this department (a cost centre number, an owner name)
    MaintenanceWindowsJson NVARCHAR(MAX)   NULL,       -- captured now; used by the remediation flows of a later phase
    CreatedAt              DATETIME2(0)    NOT NULL CONSTRAINT DF_Department_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy              NVARCHAR(256)   NOT NULL,
    UpdatedAt              DATETIME2(0)    NOT NULL CONSTRAINT DF_Department_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy              NVARCHAR(256)   NOT NULL,
    RetiredAt              DATETIME2(0)    NULL,
    RetiredBy              NVARCHAR(256)   NULL,
    RowVersion             ROWVERSION      NOT NULL,
    CONSTRAINT UQ_Department_Name UNIQUE (Name),
    CONSTRAINT CK_Department_Windows CHECK (MaintenanceWindowsJson IS NULL OR ISJSON(MaintenanceWindowsJson) = 1)
);

-- The department's PEOPLE, one row per (person, role). Role (validated in code, no CHECK -- the list grows):
--   technical-owner  fixes things; receives the operational reviews (a later phase)
--   business-owner   accountable; receives the monthly status report
--   technical-approver  approves planning a fix into the department's maintenance window (#335)
--   business-approver   approves accepting a risk raised from the department -- its exemption requests (#335)
--   (approver           the single approver role before #335 -- READ as business-approver by the web app; the schema
--                        never rewrites data -- the next save of the department's people table stores it as business-approver)
--   delegate         works on the department's findings
--   advisor          an external consultant / company trusted by the owners (reviews and second checks come later)
-- A person is an Entra user or group (ObjectId) OR, for someone without an Entra object (an external advisor before a
-- guest account exists), only a mail address. IsExternal marks people from outside the organisation.
IF OBJECT_ID('cfg.DepartmentMember') IS NULL
CREATE TABLE cfg.DepartmentMember (
    MemberId      INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DepartmentMember PRIMARY KEY,
    DepartmentId  INT             NOT NULL CONSTRAINT FK_DepartmentMember_Department REFERENCES cfg.Department (DepartmentId),
    Role          NVARCHAR(24)    NOT NULL,
    ObjectId      NVARCHAR(64)    NULL,
    PrincipalType NVARCHAR(8)     NOT NULL,
    DisplayName   NVARCHAR(256)   NOT NULL,
    Mail          NVARCHAR(256)   NULL,
    Company       NVARCHAR(256)   NULL,
    IsExternal    BIT             NOT NULL CONSTRAINT DF_DepartmentMember_IsExternal DEFAULT 0,
    AddedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_DepartmentMember_AddedAt DEFAULT SYSUTCDATETIME(),
    AddedBy       NVARCHAR(256)   NOT NULL,
    CONSTRAINT CK_DepartmentMember_Type CHECK (PrincipalType IN ('user', 'group', 'mail')),
    CONSTRAINT CK_DepartmentMember_Who CHECK (ObjectId IS NOT NULL OR Mail IS NOT NULL)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_DepartmentMember_Object' AND object_id = OBJECT_ID('cfg.DepartmentMember'))
CREATE UNIQUE INDEX UX_DepartmentMember_Object ON cfg.DepartmentMember (DepartmentId, Role, ObjectId) WHERE ObjectId IS NOT NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_DepartmentMember_Mail' AND object_id = OBJECT_ID('cfg.DepartmentMember'))
CREATE UNIQUE INDEX UX_DepartmentMember_Mail ON cfg.DepartmentMember (DepartmentId, Role, Mail) WHERE ObjectId IS NULL;

-- sign-in: which departments does this object id (a user, or a group in the token) belong to
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DepartmentMember_ObjectId' AND object_id = OBJECT_ID('cfg.DepartmentMember'))
CREATE INDEX IX_DepartmentMember_ObjectId ON cfg.DepartmentMember (ObjectId) INCLUDE (DepartmentId, Role);

-- The SI DEFINITIONS of the responsibility policy: first matching rule (lowest SortOrder) wins. Kind (validated in code):
--   name     the asset name matches Pattern (* and ? wildcards)
--   kind     the asset kind equals Pattern (endpoint | identity | azure | publicip)
--   service  the CMDB / business service the profile placed the asset in matches Pattern
--   group    a group the asset is in matches Pattern (Defender machine group, Azure resource group / subscription)
--   tag      any platform tag matches Pattern ("Name=Value", or the value alone)
IF OBJECT_ID('cfg.ResponsibilityRule') IS NULL
CREATE TABLE cfg.ResponsibilityRule (
    RuleId        INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ResponsibilityRule PRIMARY KEY,
    Kind          NVARCHAR(16)    NOT NULL,
    Pattern       NVARCHAR(400)   NOT NULL,
    DepartmentId  INT             NOT NULL CONSTRAINT FK_ResponsibilityRule_Department REFERENCES cfg.Department (DepartmentId),
    SortOrder     INT             NOT NULL,
    Enabled       BIT             NOT NULL CONSTRAINT DF_ResponsibilityRule_Enabled DEFAULT 1,
    Note          NVARCHAR(400)   NULL,
    CreatedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_ResponsibilityRule_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy     NVARCHAR(256)   NOT NULL,
    UpdatedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_ResponsibilityRule_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy     NVARCHAR(256)   NOT NULL
);

-- OVERRIDES: one row per override, never removed -- revoking stamps RevokedAt (as cfg.Exemption). At most one ACTIVE
-- override per asset and per recommendation. RecommendationKey = the finding's ConfigurationId (a CVE id on a CVE finding).
IF OBJECT_ID('cfg.ResponsibilityOverride') IS NULL
CREATE TABLE cfg.ResponsibilityOverride (
    OverrideId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ResponsibilityOverride PRIMARY KEY,
    Scope             NVARCHAR(16)    NOT NULL,
    AssetKey          NVARCHAR(400)   NULL,
    RecommendationKey NVARCHAR(256)   NULL,
    DepartmentId      INT             NOT NULL CONSTRAINT FK_ResponsibilityOverride_Department REFERENCES cfg.Department (DepartmentId),
    Reason            NVARCHAR(400)   NOT NULL,
    CreatedAt         DATETIME2(0)    NOT NULL CONSTRAINT DF_ResponsibilityOverride_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy         NVARCHAR(256)   NOT NULL,
    RevokedAt         DATETIME2(0)    NULL,
    RevokedBy         NVARCHAR(256)   NULL,
    CONSTRAINT CK_ResponsibilityOverride_What CHECK (
        (Scope = 'asset' AND AssetKey IS NOT NULL AND RecommendationKey IS NULL) OR
        (Scope = 'recommendation' AND RecommendationKey IS NOT NULL AND AssetKey IS NULL))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ResponsibilityOverride_Active' AND object_id = OBJECT_ID('cfg.ResponsibilityOverride'))
CREATE UNIQUE INDEX UX_ResponsibilityOverride_Active ON cfg.ResponsibilityOverride (Scope, AssetKey, RecommendationKey) WHERE RevokedAt IS NULL;

-- The business owners' MONTHLY REPORT: one row per department per month it was sent for, so a day the relay failed is
-- tried again on the next daily run and a month is never sent twice.
IF OBJECT_ID('cfg.DepartmentReport') IS NULL
CREATE TABLE cfg.DepartmentReport (
    DepartmentId  INT             NOT NULL,
    [Month]       CHAR(7)         NOT NULL,   -- yyyy-MM, the month reported on
    SentAt        DATETIME2(0)    NOT NULL CONSTRAINT DF_DepartmentReport_SentAt DEFAULT SYSUTCDATETIME(),
    Recipients    INT             NOT NULL,
    CONSTRAINT PK_DepartmentReport PRIMARY KEY (DepartmentId, [Month])
);

-- EXEMPTIONS AS A GOVERNED FLOW (#252): owners and approvers per security domain, request -> approve, review, mail.
-- 🔑 cfg.Exemption stays THE table the engines read, and only APPROVED exemptions are ever written to it: a request
-- lives in cfg.ExemptionRequest (+ its items) until an approver decides it, and approval writes the cfg.Exemption rows.
-- An engine that knows nothing of requests therefore cannot apply one that is still waiting or was rejected.
-- States: request requested | approved | rejected; an approved exemption is active until it expires (ExpiresAt) or is
-- ended (RevokedAt -- the existing "revoke"). Every step is logged in cfg.ChangeLog (Scope 'exemption').
-- ---------------------------------------------------------------------------------------------

-- Who is accountable for, and who decides, the exemptions of a security domain (Endpoint, Identity, Azure, PublicIP, or
-- any domain the data has; '*' = every domain). One row per person per role; removing someone stamps RemovedAt (a
-- re-added person clears it). Logged in cfg.ChangeLog (Name 'domain-role/<domain>/<role>', Scope 'domain-role').
--   owner     accountable: receives the monthly review and the expiry warnings, and reviews (extend / end / keep)
--   approver  decides requests (approve / reject, with a comment)
IF OBJECT_ID('cfg.DomainRole') IS NULL
CREATE TABLE cfg.DomainRole (
    Domain      NVARCHAR(64)    NOT NULL,
    Role        NVARCHAR(16)    NOT NULL,
    Principal   NVARCHAR(256)   NOT NULL,   -- the person's UPN / e-mail address, lower case
    AddedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_DomainRole_AddedAt DEFAULT SYSUTCDATETIME(),
    AddedBy     NVARCHAR(256)   NOT NULL,
    RemovedAt   DATETIME2(0)    NULL,
    RemovedBy   NVARCHAR(256)   NULL,
    CONSTRAINT PK_DomainRole PRIMARY KEY (Domain, Role, Principal),
    CONSTRAINT CK_DomainRole_Role CHECK (Role IN ('owner', 'approver'))
);

-- One request: the same reason, end date and approver for 1..N findings of ONE security domain (a bulk request over
-- several domains is split into one request per domain, so each domain's approvers decide their own part).
IF OBJECT_ID('cfg.ExemptionRequest') IS NULL
CREATE TABLE cfg.ExemptionRequest (
    RequestId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ExemptionRequest PRIMARY KEY,
    Domain          NVARCHAR(64)    NOT NULL,
    Reason          NVARCHAR(400)   NOT NULL,
    ExpiresAt       DATETIME2(0)    NULL,       -- NULL only when open-ended exemptions are allowed (a setting, off by default)
    Approver        NVARCHAR(256)   NULL,       -- the approver the requester asked (NULL = any approver of the domain)
    State           NVARCHAR(16)    NOT NULL CONSTRAINT DF_ExemptionRequest_State DEFAULT 'requested',
    RequestedBy     NVARCHAR(256)   NOT NULL,
    RequestedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_ExemptionRequest_RequestedAt DEFAULT SYSUTCDATETIME(),
    DecidedBy       NVARCHAR(256)   NULL,
    DecidedAt       DATETIME2(0)    NULL,
    DecisionComment NVARCHAR(400)   NULL,
    ItemCount       INT             NOT NULL,
    Source          NVARCHAR(32)    NULL,       -- where it was asked from: findings | collection | direct
    CONSTRAINT CK_ExemptionRequest_State CHECK (State IN ('requested', 'approved', 'rejected'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ExemptionRequest_State' AND object_id = OBJECT_ID('cfg.ExemptionRequest'))
CREATE INDEX IX_ExemptionRequest_State ON cfg.ExemptionRequest (State, Domain, RequestedAt);

-- The findings of a request, in the exemption's own words (scope + what). ExemptionId = the cfg.Exemption row the item
-- became when the request was approved (or the active one that already covered it).
IF OBJECT_ID('cfg.ExemptionRequestItem') IS NULL
CREATE TABLE cfg.ExemptionRequestItem (
    RequestId       BIGINT          NOT NULL,
    ItemNo          INT             NOT NULL,
    Scope           NVARCHAR(16)    NOT NULL,
    ReportName      NVARCHAR(128)   NULL,
    ConfigurationId NVARCHAR(128)   NULL,
    Cve             NVARCHAR(32)    NULL,
    AssetKey        NVARCHAR(256)   NULL,
    AssetName       NVARCHAR(400)   NULL,
    Title           NVARCHAR(400)   NULL,
    ExemptionId     BIGINT          NULL,
    CONSTRAINT PK_ExemptionRequestItem PRIMARY KEY (RequestId, ItemNo),
    CONSTRAINT CK_ExemptionRequestItem_Scope CHECK (Scope IN ('finding', 'issue', 'asset')),
    CONSTRAINT CK_ExemptionRequestItem_What CHECK (
        (Scope = 'finding' AND AssetKey IS NOT NULL AND (Cve IS NOT NULL OR ConfigurationId IS NOT NULL)) OR
        (Scope = 'issue'   AND AssetKey IS NULL     AND (Cve IS NOT NULL OR ConfigurationId IS NOT NULL)) OR
        (Scope = 'asset'   AND AssetKey IS NOT NULL AND Cve IS NULL AND ConfigurationId IS NULL))
);

-- cfg.Exemption, additive: which request it came from, its security domain, who approved it and when, and the last
-- review (an owner's extend or keep). NULL on every row made before #252 -- such a row reads "approved by its creator"
-- and belongs to the '*' (every domain) owners until it has a domain.
IF COL_LENGTH('cfg.Exemption', 'RequestId') IS NULL
ALTER TABLE cfg.Exemption ADD RequestId BIGINT NULL;

IF COL_LENGTH('cfg.Exemption', 'Domain') IS NULL
ALTER TABLE cfg.Exemption ADD Domain NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.Exemption', 'ApprovedBy') IS NULL
ALTER TABLE cfg.Exemption ADD ApprovedBy NVARCHAR(256) NULL;

IF COL_LENGTH('cfg.Exemption', 'ApprovedAt') IS NULL
ALTER TABLE cfg.Exemption ADD ApprovedAt DATETIME2(0) NULL;

IF COL_LENGTH('cfg.Exemption', 'ReviewedBy') IS NULL
ALTER TABLE cfg.Exemption ADD ReviewedBy NVARCHAR(256) NULL;

IF COL_LENGTH('cfg.Exemption', 'ReviewedAt') IS NULL
ALTER TABLE cfg.Exemption ADD ReviewedAt DATETIME2(0) NULL;

-- SECURITY DOMAIN OWNERS (level 1) AND SECURITY CATEGORY OWNERS (level 2) (#283). Level 1 = cfg.DomainRole above (the
-- finding's SecurityDomain). Level 2 = the finding's Category inside that domain, exactly as the Risk Analysis reports
-- carry it (Identity / Authentication, Endpoint / Vulnerabilities, ...). Its own table, because cfg.DomainRole's key
-- (Domain, Role, Principal) cannot take a category without being dropped and this file only adds. Owners at either
-- level decide the requests of their scope -- the category's owners when it has any, else the domain's -- and receive
-- the monthly review of their scope. Role 'owner' (validated by the web app, no CHECK: a list that grows needs no
-- schema change). Removing someone stamps RemovedAt. Logged in cfg.ChangeLog (Name
-- 'domain-role/<domain>/<category>/owner', Scope 'domain-role', Kind 'domain-role').
IF OBJECT_ID('cfg.CategoryRole') IS NULL
CREATE TABLE cfg.CategoryRole (
    Domain      NVARCHAR(64)    NOT NULL,
    Category    NVARCHAR(128)   NOT NULL,
    Role        NVARCHAR(16)    NOT NULL,
    Principal   NVARCHAR(256)   NOT NULL,   -- the person's UPN / e-mail address, lower case
    AddedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_CategoryRole_AddedAt DEFAULT SYSUTCDATETIME(),
    AddedBy     NVARCHAR(256)   NOT NULL,
    RemovedAt   DATETIME2(0)    NULL,
    RemovedBy   NVARCHAR(256)   NULL,
    CONSTRAINT PK_CategoryRole PRIMARY KEY (Domain, Category, Role, Principal)
);

-- A request's Category = the category whose owners decide it (NULL = the domain's owners / approvers decide it); an
-- item's and an exemption's Category = the finding's own category, so the monthly review of a category owner lists
-- exactly the exemptions of that category. NULL on every row made before #283.
IF COL_LENGTH('cfg.ExemptionRequest', 'Category') IS NULL
ALTER TABLE cfg.ExemptionRequest ADD Category NVARCHAR(128) NULL;

IF COL_LENGTH('cfg.ExemptionRequestItem', 'Category') IS NULL
ALTER TABLE cfg.ExemptionRequestItem ADD Category NVARCHAR(128) NULL;

IF COL_LENGTH('cfg.Exemption', 'Category') IS NULL
ALTER TABLE cfg.Exemption ADD Category NVARCHAR(128) NULL;

-- #391: a request made on a DEPARTMENT's own page records that department and who it was routed to, for the audit:
-- Routing 'department-business-approver' = asked of (and decided by) that department's business approvers;
-- 'department-no-business-approver' = the department had none, so the domain / category owners decide it. NULL on
-- every request made anywhere else (and on every row made before #391).
IF COL_LENGTH('cfg.ExemptionRequest', 'DepartmentId') IS NULL
ALTER TABLE cfg.ExemptionRequest ADD DepartmentId INT NULL;

IF COL_LENGTH('cfg.ExemptionRequest', 'Routing') IS NULL
ALTER TABLE cfg.ExemptionRequest ADD Routing NVARCHAR(32) NULL;

-- THE EXEMPTION MAIL OUTBOX. The web app never talks to a mail server: it QUEUES a request mail (to the approvers) and
-- a decision mail (to the requester) here, and the close-loop mail job sends them through the Risk Analysis SMTP
-- transports -- the one mail path -- and stamps SentAt. The same job queues and sends the expiry warnings and the
-- monthly review (Kind expiry | review) and records them here, which is also how it knows what it already sent:
-- PeriodKey 'yyyy-MM' for a monthly review, ItemsJson [{"id":..,"expiresAt":".."}] for an expiry warning -- per recipient
-- in ToList (#283: one review and one warning per OWNER, covering every domain and category they own).
IF OBJECT_ID('cfg.ExemptionMail') IS NULL
CREATE TABLE cfg.ExemptionMail (
    MailId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ExemptionMail PRIMARY KEY,
    Kind        NVARCHAR(16)    NOT NULL,   -- request | decision | expiry | review
    RequestId   BIGINT          NULL,
    Domain      NVARCHAR(64)    NULL,
    PeriodKey   NVARCHAR(16)    NULL,
    ToList      NVARCHAR(2000)  NOT NULL,   -- addresses separated by ';'
    Subject     NVARCHAR(400)   NOT NULL,
    BodyHtml    NVARCHAR(MAX)   NOT NULL,
    ItemsJson   NVARCHAR(MAX)   NULL,
    QueuedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_ExemptionMail_QueuedAt DEFAULT SYSUTCDATETIME(),
    QueuedBy    NVARCHAR(256)   NOT NULL,
    SentAt      DATETIME2(0)    NULL,
    Attempts    INT             NOT NULL CONSTRAINT DF_ExemptionMail_Attempts DEFAULT 0,
    LastError   NVARCHAR(1000)  NULL,
    CONSTRAINT CK_ExemptionMail_Kind CHECK (Kind IN ('request', 'decision', 'expiry', 'review')),
    CONSTRAINT CK_ExemptionMail_ItemsJson CHECK (ItemsJson IS NULL OR ISJSON(ItemsJson) = 1)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ExemptionMail_Pending' AND object_id = OBJECT_ID('cfg.ExemptionMail'))
CREATE INDEX IX_ExemptionMail_Pending ON cfg.ExemptionMail (SentAt, Kind, Domain);

-- =============================================================================================
-- ASSET RESPONSIBILITY, PHASE 2 + 3 (REQUIREMENTS #254): the GOVERNANCE LOG per finding, the technical owners'
-- notifications and monthly review, and the REMEDIATION FLOWS per department x category / subcategory.
-- A finding is identified across collections by (AssetKey, RecommendationKey) -- RecommendationKey = the finding's
-- ConfigurationId, else its CVE id (the key the overrides of phase 1 use). Statuses and flow actions are validated in
-- code, no CHECK (the lists grow). Nothing here is ever removed: an entry is appended, a flow is retired. Every web write
-- is ONE transaction with its cfg.ChangeLog row (Kind 'governance' / 'remediation').
-- SecurityInsight stays READ-ONLY toward Defender / Intune / Entra / ARM: "Auto in the maintenance window" records an
-- approved, SCHEDULED state here and tells the technical owners -- it never pushes a change to a platform.
-- ---------------------------------------------------------------------------------------------
-- The LOG: every comment and every status change, append-only. Status NULL = a comment that does not change the status.
--   Source      web | flow (a remediation flow applied it) | sync (the mail job, after a data sync)
--   Status      open | in-progress | planned | fixed-pending-verification | accepted | escalated | not-applicable
--   FlowId      the remediation flow that produced it (cfg.RemediationFlow), when one did
--   ScheduledFor the start of the maintenance window an 'Auto' flow scheduled the fix for (UTC)
--   ExemptionRequestId  'accepted' = the exemption request (#252) it raised; the risk is accepted only once approved
IF OBJECT_ID('cfg.GovernanceEntry') IS NULL
CREATE TABLE cfg.GovernanceEntry (
    EntryId             BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_GovernanceEntry PRIMARY KEY,
    AssetKey            NVARCHAR(400)   NOT NULL,
    RecommendationKey   NVARCHAR(256)   NOT NULL,
    DepartmentId        INT             NULL,       -- the department responsible when it was written (NULL = Unassigned)
    Status              NVARCHAR(32)    NULL,
    Comment             NVARCHAR(2000)  NOT NULL,
    Source              NVARCHAR(16)    NOT NULL,
    FlowId              INT             NULL,
    ScheduledFor        DATETIME2(0)    NULL,
    ExemptionRequestId  BIGINT          NULL,
    CollectionId        INT             NULL,       -- the collection the finding was seen in when it was written
    CreatedAt           DATETIME2(0)    NOT NULL CONSTRAINT DF_GovernanceEntry_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy           NVARCHAR(256)   NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GovernanceEntry_Finding' AND object_id = OBJECT_ID('cfg.GovernanceEntry'))
CREATE INDEX IX_GovernanceEntry_Finding ON cfg.GovernanceEntry (AssetKey, RecommendationKey, CreatedAt);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GovernanceEntry_Department' AND object_id = OBJECT_ID('cfg.GovernanceEntry'))
CREATE INDEX IX_GovernanceEntry_Department ON cfg.GovernanceEntry (DepartmentId, CreatedAt) INCLUDE (Status, Source);

-- The CURRENT status of each finding that has one: the newest log entry with a status, kept in the same transaction as
-- the entry, so the department page reads one row per finding instead of the whole log.
IF OBJECT_ID('cfg.GovernanceState') IS NULL
CREATE TABLE cfg.GovernanceState (
    AssetKey            NVARCHAR(400)   NOT NULL,
    RecommendationKey   NVARCHAR(256)   NOT NULL,
    DepartmentId        INT             NULL,
    Status              NVARCHAR(32)    NOT NULL,
    ScheduledFor        DATETIME2(0)    NULL,
    FlowId              INT             NULL,
    ExemptionRequestId  BIGINT          NULL,
    LastEntryId         BIGINT          NOT NULL,
    UpdatedAt           DATETIME2(0)    NOT NULL CONSTRAINT DF_GovernanceState_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy           NVARCHAR(256)   NOT NULL,
    CONSTRAINT PK_GovernanceState PRIMARY KEY (AssetKey, RecommendationKey)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GovernanceState_Department' AND object_id = OBJECT_ID('cfg.GovernanceState'))
CREATE INDEX IX_GovernanceState_Department ON cfg.GovernanceState (DepartmentId, Status) INCLUDE (ScheduledFor, UpdatedAt);

-- The REMEDIATION FLOWS: what a department does with a category (the security domain) / subcategory (the report) of
-- findings. NULL department / '*' category / '*' subcategory = every one; the most specific flow wins, then SortOrder.
--   Action  auto-window     SI schedules the fix for the department's next maintenance window and tells the technical owners
--           manual          the technical owners implement it by hand
--           escalate-vendor the finding goes to the vendor contact below for review (a mail, recorded in the log)
--           accept-risk     the risk is accepted through the exemption flow (#252) -- an approver decides
--           not-applicable  recorded as not applicable for the department (the finding itself stays visible)
-- Retired, never removed (log entries point at it).
IF OBJECT_ID('cfg.RemediationFlow') IS NULL
CREATE TABLE cfg.RemediationFlow (
    FlowId          INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RemediationFlow PRIMARY KEY,
    DepartmentId    INT             NULL,
    Category        NVARCHAR(128)   NOT NULL,   -- a security domain (Endpoint, Identity, Azure, PublicIP, ...) or '*'
    Subcategory     NVARCHAR(256)   NOT NULL,   -- a Risk Analysis report name, or '*'
    Action          NVARCHAR(24)    NOT NULL,
    VendorName      NVARCHAR(256)   NULL,
    VendorMail      NVARCHAR(256)   NULL,
    Note            NVARCHAR(400)   NULL,
    SortOrder       INT             NOT NULL,
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_RemediationFlow_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy       NVARCHAR(256)   NOT NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_RemediationFlow_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy       NVARCHAR(256)   NOT NULL,
    RetiredAt       DATETIME2(0)    NULL,
    RetiredBy       NVARCHAR(256)   NULL
);

-- The TECHNICAL OWNERS' notifications: one row per department per collection notified, so a collection is never
-- announced twice and a day the relay failed is tried again on the next run.
IF OBJECT_ID('cfg.GovernanceNotice') IS NULL
CREATE TABLE cfg.GovernanceNotice (
    DepartmentId    INT             NOT NULL,
    CollectionId    INT             NOT NULL,
    SentAt          DATETIME2(0)    NOT NULL CONSTRAINT DF_GovernanceNotice_SentAt DEFAULT SYSUTCDATETIME(),
    Items           INT             NOT NULL,
    Recipients      INT             NOT NULL,
    CONSTRAINT PK_GovernanceNotice PRIMARY KEY (DepartmentId, CollectionId)
);

-- The TECHNICAL OWNERS' monthly review: one row per department per month sent (as cfg.DepartmentReport is for the
-- business owners).
IF OBJECT_ID('cfg.TechnicalReview') IS NULL
CREATE TABLE cfg.TechnicalReview (
    DepartmentId    INT             NOT NULL,
    [Month]         CHAR(7)         NOT NULL,   -- yyyy-MM, the month reviewed
    SentAt          DATETIME2(0)    NOT NULL CONSTRAINT DF_TechnicalReview_SentAt DEFAULT SYSUTCDATETIME(),
    Recipients      INT             NOT NULL,
    CONSTRAINT PK_TechnicalReview PRIMARY KEY (DepartmentId, [Month])
);

-- The GOVERNANCE MAIL OUTBOX (vendor escalations). The web app never talks to a mail server: an escalation writes its
-- log entry AND queues its mail here in one transaction; the close-loop mail job sends it through the Risk Analysis SMTP
-- transports and stamps SentAt (Kind 'vendor').
IF OBJECT_ID('cfg.GovernanceMail') IS NULL
CREATE TABLE cfg.GovernanceMail (
    MailId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_GovernanceMail PRIMARY KEY,
    Kind        NVARCHAR(16)    NOT NULL,
    EntryId     BIGINT          NULL,       -- the cfg.GovernanceEntry it belongs to
    ToList      NVARCHAR(2000)  NOT NULL,   -- addresses separated by ';'
    Subject     NVARCHAR(400)   NOT NULL,
    BodyHtml    NVARCHAR(MAX)   NOT NULL,
    QueuedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_GovernanceMail_QueuedAt DEFAULT SYSUTCDATETIME(),
    QueuedBy    NVARCHAR(256)   NOT NULL,
    SentAt      DATETIME2(0)    NULL,
    Attempts    INT             NOT NULL CONSTRAINT DF_GovernanceMail_Attempts DEFAULT 0,
    LastError   NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GovernanceMail_Pending' AND object_id = OBJECT_ID('cfg.GovernanceMail'))
CREATE INDEX IX_GovernanceMail_Pending ON cfg.GovernanceMail (SentAt, Kind);

-- =============================================================================================
-- EXTERNAL ADVISORS AND DEPARTMENT SIGN-IN (REQUIREMENTS #258). Operator decisions 2026-10-04:
--   * advisors -- an outside consultant (a person) or consultancy (a company) -- are linked to a department and act as a
--     trusted advisor for its owners: they see that department only, and may comment, recommend and approve there;
--   * a MAGIC LINK (per person, short-lived, single use, revocable, scoped to the department, every step audited) signs
--     a person in; APPROVE through a magic link needs a SECOND CHECK -- a one-time code mailed to the same mailbox (or an
--     Entra sign-in instead of the link);
--   * OAuth for externals = an Entra B2B guest in this tenant (their home tenant's MFA, Conditional Access applies);
--     department owners may sign in either way with the same rules.
-- 🔑 Only HASHES of link tokens and one-time codes are stored (SHA-256; a code's hash is salted). The mail that carries a
-- link or a code goes through its own outbox (cfg.SignInMail), whose sender blanks the mail's body once it is sent.
-- Every write is one transaction with its cfg.ChangeLog row: Scope 'department', Kind 'department' (advisors, like the
-- department's people) or 'signin' (links, sessions, codes; Name 'department-signin/<id>').
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.DepartmentAdvisor') IS NULL
CREATE TABLE cfg.DepartmentAdvisor (
    AdvisorId     INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DepartmentAdvisor PRIMARY KEY,
    DepartmentId  INT             NOT NULL CONSTRAINT FK_DepartmentAdvisor_Department REFERENCES cfg.Department (DepartmentId),
    Kind          NVARCHAR(8)     NOT NULL,   -- person | company (validated in code; the list may grow)
    DisplayName   NVARCHAR(256)   NOT NULL,   -- the person, or the company's name
    Company       NVARCHAR(256)   NULL,
    Mail          NVARCHAR(256)   NULL,       -- where links and codes go (a company: its advisory mailbox)
    ObjectId      NVARCHAR(64)    NULL,       -- the B2B guest's object id in this tenant, once invited (optional)
    IsExternal    BIT             NOT NULL CONSTRAINT DF_DepartmentAdvisor_IsExternal DEFAULT 1,
    Note          NVARCHAR(400)   NULL,
    AddedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_DepartmentAdvisor_AddedAt DEFAULT SYSUTCDATETIME(),
    AddedBy       NVARCHAR(256)   NOT NULL,
    RevokedAt     DATETIME2(0)    NULL,       -- revoked, never deleted: comments and sign-ins keep pointing at the row
    RevokedBy     NVARCHAR(256)   NULL,
    RevokeReason  NVARCHAR(400)   NULL,
    CONSTRAINT CK_DepartmentAdvisor_Who CHECK (Mail IS NOT NULL OR ObjectId IS NOT NULL)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_DepartmentAdvisor_Mail' AND object_id = OBJECT_ID('cfg.DepartmentAdvisor'))
CREATE UNIQUE INDEX UX_DepartmentAdvisor_Mail ON cfg.DepartmentAdvisor (DepartmentId, Mail) WHERE RevokedAt IS NULL AND Mail IS NOT NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DepartmentAdvisor_Who' AND object_id = OBJECT_ID('cfg.DepartmentAdvisor'))
CREATE INDEX IX_DepartmentAdvisor_Who ON cfg.DepartmentAdvisor (Mail, ObjectId) INCLUDE (DepartmentId, RevokedAt);

-- One row per issued SIGN-IN LINK; the redeemed link IS the session (RedeemedAt .. SessionExpiresAt). PersonKind 'advisor'
-- -> cfg.DepartmentAdvisor.AdvisorId, 'member' -> cfg.DepartmentMember.MemberId. TokenHash = SHA-256 of the token. Origin:
-- admin (sent from the department's admin page) | request (asked for by the person, from a mail's link).
-- OtpConfirmedAt = the session's second check (the one-time code) passed: it may approve from then on.
IF OBJECT_ID('cfg.DepartmentSignIn') IS NULL
CREATE TABLE cfg.DepartmentSignIn (
    SignInId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DepartmentSignIn PRIMARY KEY,
    DepartmentId      INT             NOT NULL CONSTRAINT FK_DepartmentSignIn_Department REFERENCES cfg.Department (DepartmentId),
    PersonKind        NVARCHAR(8)     NOT NULL,
    PersonId          INT             NOT NULL,
    Mail              NVARCHAR(256)   NOT NULL,
    TokenHash         BINARY(32)      NOT NULL,
    Origin            NVARCHAR(16)    NOT NULL,
    TargetPath        NVARCHAR(400)   NULL,
    IssuedAt          DATETIME2(0)    NOT NULL,
    IssuedBy          NVARCHAR(256)   NOT NULL,
    ExpiresAt         DATETIME2(0)    NOT NULL,
    RedeemedAt        DATETIME2(0)    NULL,
    SessionExpiresAt  DATETIME2(0)    NULL,
    OtpConfirmedAt    DATETIME2(0)    NULL,
    RevokedAt         DATETIME2(0)    NULL,
    RevokedBy         NVARCHAR(256)   NULL,
    CONSTRAINT UQ_DepartmentSignIn_Token UNIQUE (TokenHash)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DepartmentSignIn_Person' AND object_id = OBJECT_ID('cfg.DepartmentSignIn'))
CREATE INDEX IX_DepartmentSignIn_Person ON cfg.DepartmentSignIn (PersonKind, PersonId, IssuedAt) INCLUDE (DepartmentId, RevokedAt);

-- The ONE-TIME CODES of the second check: salted SHA-256 only, 10 minutes, at most 5 tries, used once.
IF OBJECT_ID('cfg.DepartmentSignInCode') IS NULL
CREATE TABLE cfg.DepartmentSignInCode (
    CodeId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DepartmentSignInCode PRIMARY KEY,
    SignInId      BIGINT          NOT NULL CONSTRAINT FK_DepartmentSignInCode_SignIn REFERENCES cfg.DepartmentSignIn (SignInId),
    Salt          BINARY(16)      NOT NULL,
    CodeHash      BINARY(32)      NOT NULL,
    IssuedAt      DATETIME2(0)    NOT NULL,
    ExpiresAt     DATETIME2(0)    NOT NULL,
    Attempts      INT             NOT NULL CONSTRAINT DF_DepartmentSignInCode_Attempts DEFAULT 0,
    UsedAt        DATETIME2(0)    NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DepartmentSignInCode_SignIn' AND object_id = OBJECT_ID('cfg.DepartmentSignInCode'))
CREATE INDEX IX_DepartmentSignInCode_SignIn ON cfg.DepartmentSignInCode (SignInId, IssuedAt);

-- THE SIGN-IN MAIL OUTBOX: the web app queues a link (Kind 'sign-in') or a one-time code ('sign-in-code') here; the
-- close-loop mail job sends it with the exemption mails, through the same SMTP path, and BLANKS ITS BODY once sent -- so
-- the secret is in the database only until the mail goes out. Its own table, not cfg.ExemptionMail: that outbox keeps
-- its bodies (its Kind CHECK is left as it is), and a sign-in mail older than a day is never sent (the link is dead).
IF OBJECT_ID('cfg.SignInMail') IS NULL
CREATE TABLE cfg.SignInMail (
    MailId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_SignInMail PRIMARY KEY,
    Kind        NVARCHAR(16)    NOT NULL,   -- sign-in | sign-in-code (validated in code)
    ToList      NVARCHAR(2000)  NOT NULL,
    Subject     NVARCHAR(400)   NOT NULL,
    BodyHtml    NVARCHAR(MAX)   NOT NULL,
    QueuedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_SignInMail_QueuedAt DEFAULT SYSUTCDATETIME(),
    QueuedBy    NVARCHAR(256)   NOT NULL,
    SentAt      DATETIME2(0)    NULL,
    Attempts    INT             NOT NULL CONSTRAINT DF_SignInMail_Attempts DEFAULT 0,
    LastError   NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SignInMail_Pending' AND object_id = OBJECT_ID('cfg.SignInMail'))
CREATE INDEX IX_SignInMail_Pending ON cfg.SignInMail (SentAt, QueuedAt);

-- =============================================================================================
-- FINDING COMMENTS (#258): the comments, recommendations and approvals that advisors, department people and the
-- security team leave on ONE finding. FindingKey = '<asset key>|<recommendation key>' (the recommendation key is the
-- finding's ConfigurationId, or its CVE id) -- stable across collections, so the thread follows the finding from run to
-- run. Kind (validated in code): comment | recommend | approve. AuthMethod: how the author signed in (oauth | magiclink |
-- magiclink+otp); SignInId names the sign-in link session when there was one. Never updated, never deleted.
-- A minimal, self-contained table: the governance log of #254 phase 2 is built in parallel and may absorb it (its rows
-- carry everything a governance entry needs). Each write has its cfg.ChangeLog row (Scope 'finding', Kind 'finding-comment').
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.FindingComment') IS NULL
CREATE TABLE cfg.FindingComment (
    CommentId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_FindingComment PRIMARY KEY,
    FindingKey         NVARCHAR(700)   NOT NULL,
    AssetKey           NVARCHAR(400)   NOT NULL,
    RecommendationKey  NVARCHAR(256)   NOT NULL,
    DepartmentId       INT             NULL,
    Kind               NVARCHAR(16)    NOT NULL,
    Body               NVARCHAR(2000)  NOT NULL,
    Author             NVARCHAR(256)   NOT NULL,
    AuthorRole         NVARCHAR(24)    NOT NULL,
    AuthMethod         NVARCHAR(16)    NOT NULL,
    SignInId           BIGINT          NULL,
    CreatedAt          DATETIME2(0)    NOT NULL CONSTRAINT DF_FindingComment_CreatedAt DEFAULT SYSUTCDATETIME()
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingComment_Finding' AND object_id = OBJECT_ID('cfg.FindingComment'))
CREATE INDEX IX_FindingComment_Finding ON cfg.FindingComment (FindingKey, CreatedAt);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingComment_Department' AND object_id = OBJECT_ID('cfg.FindingComment'))
CREATE INDEX IX_FindingComment_Department ON cfg.FindingComment (DepartmentId, CreatedAt);

-- =============================================================================================
-- FOLLOW-UP TASKS ON ONE FINDING (#265): "waiting for X to come back", assigned to a person and due on a date, on ONE
-- vulnerability on ONE asset -- keyed by (AssetKey, RecommendationKey) like the governance log and the finding
-- comments, so a task follows the finding from collection to collection. Never deleted: a task is completed or
-- cancelled (and may be reopened); every change is appended to cfg.FindingTaskHistory and has its cfg.ChangeLog row
-- (Scope 'finding', Kind 'finding-task', Name 'finding-task/<id>') in the same transaction.
--   AssigneeKind  user | group (an Entra object id) | member (cfg.DepartmentMember.MemberId) | advisor
--                 (cfg.DepartmentAdvisor.AdvisorId) -- validated in code, no CHECK (the list may grow)
--   AssigneeKey   '<kind>:<id>' in lower case: what "My tasks" matches against the signed-in person (their object id,
--                 the groups in their token, the department person a sign-in link stands for)
--   Status        open | done | cancelled (validated in code)
--   DueDate       the day it is due (UTC date); RemindAt an optional earlier day for the digest mail
--   CreatedByKey  the creator's own key ('user:<oid>', 'member:<id>', 'advisor:<id>' or 'name:<upn>'): "Delegated tasks"
-- When the vulnerability close-loop (vuln.VulnerabilityItem) closes the finding, the task is shown as "finding
-- resolved -- close the task?" -- it is never closed or removed automatically.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.FindingTask') IS NULL
CREATE TABLE cfg.FindingTask (
    TaskId             BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_FindingTask PRIMARY KEY,
    AssetKey           NVARCHAR(400)   NOT NULL,
    RecommendationKey  NVARCHAR(256)   NOT NULL,
    AssetName          NVARCHAR(400)   NULL,
    FindingTitle       NVARCHAR(400)   NULL,
    DepartmentId       INT             NULL,       -- the finding's department when the task was created (NULL = Unassigned)
    Title              NVARCHAR(200)   NOT NULL,
    Note               NVARCHAR(2000)  NULL,
    AssigneeKind       NVARCHAR(16)    NOT NULL,
    AssigneeId         NVARCHAR(64)    NOT NULL,
    AssigneeKey        NVARCHAR(96)    NOT NULL,
    AssigneeName       NVARCHAR(256)   NOT NULL,
    AssigneeMail       NVARCHAR(256)   NULL,
    DueDate            DATE            NOT NULL,
    RemindAt           DATE            NULL,
    Status             NVARCHAR(16)    NOT NULL,
    CreatedAt          DATETIME2(0)    NOT NULL CONSTRAINT DF_FindingTask_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy          NVARCHAR(256)   NOT NULL,
    CreatedByKey       NVARCHAR(300)   NOT NULL,
    CompletedAt        DATETIME2(0)    NULL,
    CompletedBy        NVARCHAR(256)   NULL,
    CompletionNote     NVARCHAR(2000)  NULL,
    UpdatedAt          DATETIME2(0)    NOT NULL CONSTRAINT DF_FindingTask_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy          NVARCHAR(256)   NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingTask_Assignee' AND object_id = OBJECT_ID('cfg.FindingTask'))
CREATE INDEX IX_FindingTask_Assignee ON cfg.FindingTask (AssigneeKey, Status, DueDate);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingTask_Creator' AND object_id = OBJECT_ID('cfg.FindingTask'))
CREATE INDEX IX_FindingTask_Creator ON cfg.FindingTask (CreatedByKey, Status, DueDate);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingTask_Finding' AND object_id = OBJECT_ID('cfg.FindingTask'))
CREATE INDEX IX_FindingTask_Finding ON cfg.FindingTask (AssetKey, RecommendationKey, CreatedAt);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingTask_Due' AND object_id = OBJECT_ID('cfg.FindingTask'))
CREATE INDEX IX_FindingTask_Due ON cfg.FindingTask (Status, DueDate) INCLUDE (DepartmentId, AssigneeKey);

-- Every change of a task, append-only: created | completed | cancelled | reopened, with the status it left the task in,
-- the note given, who and when. The finding's thread shows these rows.
IF OBJECT_ID('cfg.FindingTaskHistory') IS NULL
CREATE TABLE cfg.FindingTaskHistory (
    HistoryId   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_FindingTaskHistory PRIMARY KEY,
    TaskId      BIGINT          NOT NULL,
    Action      NVARCHAR(16)    NOT NULL,
    Status      NVARCHAR(16)    NOT NULL,
    Note        NVARCHAR(2000)  NULL,
    ChangedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_FindingTaskHistory_ChangedAt DEFAULT SYSUTCDATETIME(),
    ChangedBy   NVARCHAR(256)   NOT NULL,
    ChangedByKey NVARCHAR(300)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FindingTaskHistory_Task' AND object_id = OBJECT_ID('cfg.FindingTaskHistory'))
CREATE INDEX IX_FindingTaskHistory_Task ON cfg.FindingTaskHistory (TaskId, ChangedAt);

-- The daily due / overdue digest (SI_Pro_TaskDigest_SendMail, off by default): one row per assignee per day sent,
-- written only AFTER the mail went out, so a day the relay fails is tried again and nobody gets two.
IF OBJECT_ID('cfg.FindingTaskDigest') IS NULL
CREATE TABLE cfg.FindingTaskDigest (
    AssigneeKey NVARCHAR(96)    NOT NULL,
    DigestDay   DATE            NOT NULL,
    SentAt      DATETIME2(0)    NOT NULL CONSTRAINT DF_FindingTaskDigest_SentAt DEFAULT SYSUTCDATETIME(),
    Items       INT             NOT NULL,
    CONSTRAINT PK_FindingTaskDigest PRIMARY KEY (AssigneeKey, DigestDay)
);

-- =============================================================================================
-- THE AUDIT TRAIL (#260, framework DOCS\REQUIREMENTS.md AUDIT-1): one row per event, append-only, ONE trail per
-- install. Every surface writes here: the web app (one 'event' row per mutating request -- success, refusal or error --
-- and per export, sign-in event, print), the jobs / setup / engines (Write-SIAuditEvent, engine\pro-settings\SI-Audit.ps1)
-- and, through the trigger below, EVERY cfg.ChangeLog row ('change' rows, in the SAME transaction as the change).
-- 🔑 Why a NEW table and not new columns on cfg.ChangeLog: ChangeLog's Action carries CHECK (Action IN ('Set','Reset'))
-- and NOT NULL Name / Scope -- a refusal, an export or a sign-in event is none of those, and widening the CHECK means
-- dropping it (a verb this file never uses). ChangeLog stays exactly what its ~60 writers and its readers (Change
-- history per setting, the deviation report, the magic-link nonces, the template releases) expect; the trigger copies
-- each of its rows into this table, so the ONE trail is complete without touching a writer, and a ChangeLog row and its
-- audit row commit or roll back together.
--   RecordType  event = what a person / job / setup did (one per request or step); change = a stored value changed
--               (copied from cfg.ChangeLog); a change and its event share CorrelationId
--   Action      dotted domain.object.verb from the CLOSED list config\audit-actions.locked.json (change rows:
--               <category>.change.set | <category>.change.reset, category from the CASE below)
--   Actor       UPN / object id / job identity / the sign-in link's person -- never a shared process identity
--   ActorSource web | job | engine | setup | api | portal
--   Outcome     ok | error | refused | held (+ OutcomeText, secrets removed)
--   BeforeJson / AfterJson   the state before / after, or the request -- secrets and tokens NEVER included
--   WhatIf      1 = a plan / dry run, never read as a change
--   ScopeDomain / ScopeDepartmentId  what the target belongs to -- the Delegated user's view of the trail filters on it
--   TsUtc       set HERE (SYSUTCDATETIME), never by a writer
-- Append-only: no product code updates or deletes a row (a test greps for it), and the DATABASE refuses it too (#289,
-- the DENY below). Rows older than SI_Pro_AuditRetentionMonths (not set = kept forever; at least 13) are removed ONLY
-- by the data sync's retention step through cfg.AuditRetentionApply, which records itself here. The web app's identity
-- gets INSERT + SELECT only (role si_audit_writer below).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.AuditEvent') IS NULL
CREATE TABLE cfg.AuditEvent (
    Id                 BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditEvent PRIMARY KEY,
    TsUtc              DATETIME2(3)    NOT NULL CONSTRAINT DF_AuditEvent_TsUtc DEFAULT SYSUTCDATETIME(),
    RecordType         NVARCHAR(8)     NOT NULL CONSTRAINT DF_AuditEvent_RecordType DEFAULT N'event',
    Action             NVARCHAR(64)    NOT NULL,
    Actor              NVARCHAR(256)   NOT NULL,
    ActorSource        NVARCHAR(16)    NULL,
    Target             NVARCHAR(400)   NULL,
    Reason             NVARCHAR(400)   NULL,
    Outcome            NVARCHAR(16)    NOT NULL,
    OutcomeText        NVARCHAR(1000)  NULL,
    BeforeJson         NVARCHAR(MAX)   NULL,
    AfterJson          NVARCHAR(MAX)   NULL,
    CorrelationId      NVARCHAR(64)    NULL,
    WhatIf             BIT             NOT NULL CONSTRAINT DF_AuditEvent_WhatIf DEFAULT 0,
    ScopeDomain        NVARCHAR(64)    NULL,
    ScopeDepartmentId  INT             NULL,
    ChangeLogId        BIGINT          NULL,
    CONSTRAINT CK_AuditEvent_RecordType CHECK (RecordType IN (N'event', N'change')),
    CONSTRAINT CK_AuditEvent_Outcome CHECK (Outcome IN (N'ok', N'error', N'refused', N'held')),
    CONSTRAINT CK_AuditEvent_ActorSource CHECK (ActorSource IS NULL OR ActorSource IN (N'web', N'job', N'engine', N'setup', N'api', N'portal'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuditEvent_TsUtc' AND object_id = OBJECT_ID('cfg.AuditEvent'))
CREATE INDEX IX_AuditEvent_TsUtc ON cfg.AuditEvent (TsUtc);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuditEvent_Correlation' AND object_id = OBJECT_ID('cfg.AuditEvent'))
CREATE INDEX IX_AuditEvent_Correlation ON cfg.AuditEvent (CorrelationId, RecordType);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuditEvent_ChangeLog' AND object_id = OBJECT_ID('cfg.AuditEvent'))
CREATE INDEX IX_AuditEvent_ChangeLog ON cfg.AuditEvent (ChangeLogId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuditEvent_Action' AND object_id = OBJECT_ID('cfg.AuditEvent'))
CREATE INDEX IX_AuditEvent_Action ON cfg.AuditEvent (Action, TsUtc);

-- Every cfg.ChangeLog row becomes a 'change' row of the trail, in the inserting transaction. The web app and the
-- PowerShell writers put the request's correlation id, source and scope into SESSION_CONTEXT (si.audit.*) before a
-- write, so a change row joins the event that caused it. A value that is not on the closed lists is dropped, never
-- refused -- the trigger must not be able to fail a change. The category CASE is the same text as in the mapping of the
-- existing rows below (a test compares the two and the category list in config\audit-actions.locked.json).
IF OBJECT_ID('cfg.TR_ChangeLog_Audit') IS NULL
EXEC (N'CREATE TRIGGER cfg.TR_ChangeLog_Audit ON cfg.ChangeLog AFTER INSERT AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    DECLARE @dom NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.domain'') AS NVARCHAR(64));
    DECLARE @dep INT = TRY_CONVERT(INT, CAST(SESSION_CONTEXT(N''si.audit.department'') AS NVARCHAR(16)));
    IF @src NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @src = NULL;
    INSERT cfg.AuditEvent (RecordType, Action, Actor, ActorSource, Target, Reason, Outcome, BeforeJson, AfterJson, CorrelationId, ScopeDomain, ScopeDepartmentId, ChangeLogId)
    SELECT N''change'',
           /*AUDIT-CATEGORY*/ CASE WHEN c.Scope = N''solution'' OR c.Scope LIKE N''engine:%'' THEN N''setting'' WHEN c.Scope = N''install'' AND c.Name = N''LicenceRequest'' THEN N''licence'' WHEN c.Scope = N''install'' THEN N''template'' WHEN c.Scope = N''department'' AND c.Kind = N''signin'' THEN N''signin'' WHEN c.Scope = N''domain-role'' THEN N''domainrole'' WHEN c.Scope = N''magic-link'' THEN N''magiclink'' WHEN c.Scope IN (N''document'', N''item'', N''template'', N''access'', N''exemption'', N''cmdb'', N''connector'', N''department'', N''finding'', N''governance'', N''remediation'', N''responsibility'', N''job'') THEN c.Scope ELSE N''other'' END /*END-AUDIT-CATEGORY*/
             + N''.change.'' + CASE WHEN c.Action = N''Reset'' THEN N''reset'' ELSE N''set'' END,
           LEFT(c.ChangedBy, 256), @src, LEFT(c.Name + N'' ('' + c.Scope + N'')'', 400), LEFT(c.Reason, 400), N''ok'',
           CASE WHEN c.OldValue IS NULL THEN NULL WHEN ISJSON(c.OldValue) = 1 THEN c.OldValue ELSE N''"'' + STRING_ESCAPE(c.OldValue, ''json'') + N''"'' END,
           CASE WHEN c.NewValue IS NULL THEN NULL WHEN ISJSON(c.NewValue) = 1 THEN c.NewValue ELSE N''"'' + STRING_ESCAPE(c.NewValue, ''json'') + N''"'' END,
           @cid, @dom,
           COALESCE(@dep, CASE WHEN c.Scope = N''department'' AND c.Name LIKE N''department/%'' THEN TRY_CONVERT(INT, SUBSTRING(c.Name, 12, 12)) END),
           c.ChangeId
    FROM inserted AS c;
END');

-- The change history written BEFORE the trail existed, mapped in once (idempotent: a row already carried is skipped).
-- Its time is the change's own; nothing else is invented -- no correlation, no source.
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('cfg.AuditEvent') AND name = 'ChangeLogId')
INSERT cfg.AuditEvent (TsUtc, RecordType, Action, Actor, Target, Reason, Outcome, BeforeJson, AfterJson, ScopeDepartmentId, ChangeLogId)
SELECT c.ChangedAt, N'change',
       /*AUDIT-CATEGORY*/ CASE WHEN c.Scope = N'solution' OR c.Scope LIKE N'engine:%' THEN N'setting' WHEN c.Scope = N'install' AND c.Name = N'LicenceRequest' THEN N'licence' WHEN c.Scope = N'install' THEN N'template' WHEN c.Scope = N'department' AND c.Kind = N'signin' THEN N'signin' WHEN c.Scope = N'domain-role' THEN N'domainrole' WHEN c.Scope = N'magic-link' THEN N'magiclink' WHEN c.Scope IN (N'document', N'item', N'template', N'access', N'exemption', N'cmdb', N'connector', N'department', N'finding', N'governance', N'remediation', N'responsibility', N'job') THEN c.Scope ELSE N'other' END /*END-AUDIT-CATEGORY*/
         + N'.change.' + CASE WHEN c.Action = N'Reset' THEN N'reset' ELSE N'set' END,
       LEFT(c.ChangedBy, 256), LEFT(c.Name + N' (' + c.Scope + N')', 400), LEFT(c.Reason, 400), N'ok',
       CASE WHEN c.OldValue IS NULL THEN NULL WHEN ISJSON(c.OldValue) = 1 THEN c.OldValue ELSE N'"' + STRING_ESCAPE(c.OldValue, 'json') + N'"' END,
       CASE WHEN c.NewValue IS NULL THEN NULL WHEN ISJSON(c.NewValue) = 1 THEN c.NewValue ELSE N'"' + STRING_ESCAPE(c.NewValue, 'json') + N'"' END,
       CASE WHEN c.Scope = N'department' AND c.Name LIKE N'department/%' THEN TRY_CONVERT(INT, SUBSTRING(c.Name, 12, 12)) END,
       c.ChangeId
FROM cfg.ChangeLog AS c
WHERE NOT EXISTS (SELECT 1 FROM cfg.AuditEvent AS a WHERE a.ChangeLogId = c.ChangeId);

-- The WRITER's role: INSERT + SELECT on the trail, and NOTHING that changes or removes a row. The web app's identity is
-- made a member by pro-management\deploy\Deploy-SIManagement.ps1 (its GRANT hint); the data sync's retention step runs
-- as the job identity (db_datawriter), not as a member of this role.
IF DATABASE_PRINCIPAL_ID(N'si_audit_writer') IS NULL
EXEC (N'CREATE ROLE si_audit_writer');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT INSERT, SELECT ON OBJECT::cfg.AuditEvent TO si_audit_writer;

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT INSERT, SELECT ON OBJECT::cfg.ChangeLog TO si_audit_writer;

-- #289 (framework AUDIT-1.3): APPEND-ONLY IN THE DATABASE ITSELF, not only by convention. Nobody but the database owner
-- may change or remove a row of the trail (cfg.AuditEvent) or of the change history it is built from (cfg.ChangeLog --
-- which also holds the used magic-link nonces, so a removed row would make a used link work again; its writers only
-- INSERT, and the nonce check only reads, with UPDLOCK, which needs no UPDATE right).
-- 🔑 DENY, not a trigger: SecurityInsight's runtime identities are ordinary users -- the jobs / engines db_datareader +
-- db_datawriter, the web app db_datareader + named grants + si_audit_writer, the MCP server and support db_datareader;
-- none is db_ddladmin or owner, so a DENY binds every one of them (a DENY wins over db_datawriter). The DENY is to
-- PUBLIC, so it also binds an identity added later, by any name, without a per-install step. (PIM uses an INSTEAD OF
-- trigger because its runtime identities are db_ddladmin and could undo a DENY; SecurityInsight's cannot.)
-- Honest limit: the database owner (the server's Entra admin group, i.e. setup) is never bound by a DENY.
IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
DENY UPDATE, DELETE ON OBJECT::cfg.AuditEvent TO public;

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
DENY UPDATE, DELETE ON OBJECT::cfg.ChangeLog TO public;

-- The ONE removal of trail rows: the data sync's audited retention step calls this procedure. It is owned by the schema's
-- owner, so its own DELETE passes the DENY (ownership chaining) -- and it decides what may go, not the caller: at least
-- 13 months (AUDIT-1.3), never a cutoff younger than that many months before the SERVER's clock, at most @Batch rows,
-- and only for a caller that holds db_datawriter (the job identity) or owns the database. Anything else is refused with
-- THROW and nothing is removed. Static SQL only: dynamic SQL would break the ownership chain.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.AuditRetentionApply @Months INT, @Cutoff DATETIME2(3) = NULL, @Batch INT = 5000
AS
BEGIN
    SET NOCOUNT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51289, N''only the data sync job may apply the audit trail retention -- nothing was removed'', 1;
    IF @Months IS NULL OR @Months < 13
        THROW 51290, N''the audit trail is kept at least 13 months -- nothing was removed'', 1;
    IF @Batch IS NULL OR @Batch < 1 SET @Batch = 5000;
    DECLARE @Floor DATETIME2(3) = DATEADD(MONTH, -@Months, SYSUTCDATETIME());
    IF @Cutoff IS NULL OR @Cutoff > @Floor SET @Cutoff = @Floor;
    DELETE TOP (@Batch) FROM cfg.AuditEvent WHERE TsUtc < @Cutoff;
    SELECT @@ROWCOUNT AS N;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.AuditRetentionApply TO public;

-- #302 (framework AUDIT-1.1): WHO ASKED FOR A CHANGE THAT A JOB CARRIES OUT. When the web app hands work to a job -- a
-- staged change committed (settings, documents, rules, tags, schema overlays, reports, CMDB links, connectors, template
-- conformance), a setting saved, an exemption request approved, a held close set released, a template release, a job or
-- the flow started now -- it records HERE, AT COMMIT, one row per changed target: the commit's correlation id (the same id
-- as the web event and its change rows), the stored row's key, the person who initiated it and the approver when an
-- approval applied. The job's audit writer (Write-SIAuditEvent) looks the row up -- by the correlation id the web app
-- passed in the job's environment (SI_AUDIT_CID), or by the target key -- and writes Actor = that person, After.appliedBy
-- = the job, After.jobRun = its run, After.approvedBy, CorrelationId = the commit id. Keyed by the TARGET, not by the live
-- row, so a removed row is still attributed after it is gone. A change no person asked for (a schedule, an expiry, a
-- retention, the close-loop's own closes) finds no row and keeps the job as the actor.
--   Kind   change   = put in force by the jobs' settings layer at their next run (settings.change.apply)
--          start    = a job execution a person started (its env carries SI_AUDIT_CID)
--          release  = a held vulnerability close set released (guard.release.apply)
--          flow     = the job flow's definition changed (the flow runner names who set it)
-- Append-only like the trail: the web app INSERTs (WebWriteGrants), the jobs INSERT (a release from a VM's command line)
-- and SELECT; nobody updates or deletes a row (the DENY below; the newest row of a target wins).
IF OBJECT_ID('cfg.ChangeAttribution') IS NULL
CREATE TABLE cfg.ChangeAttribution (
    AttributionId   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ChangeAttribution PRIMARY KEY,
    CorrelationId   NVARCHAR(64)    NOT NULL,
    TargetKey       NVARCHAR(400)   NOT NULL,
    Kind            NVARCHAR(16)    NOT NULL CONSTRAINT DF_ChangeAttribution_Kind DEFAULT N'change',
    Op              NVARCHAR(16)    NOT NULL CONSTRAINT DF_ChangeAttribution_Op DEFAULT N'set',
    Title           NVARCHAR(400)   NULL,
    Actor           NVARCHAR(256)   NOT NULL,
    ApprovedBy      NVARCHAR(256)   NULL,
    Source          NVARCHAR(16)    NOT NULL CONSTRAINT DF_ChangeAttribution_Source DEFAULT N'web',
    CreatedAt       DATETIME2(3)    NOT NULL CONSTRAINT DF_ChangeAttribution_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_ChangeAttribution_Kind CHECK (Kind IN (N'change', N'start', N'release', N'flow')),
    CONSTRAINT CK_ChangeAttribution_Op CHECK (Op IN (N'set', N'remove', N'start', N'approve'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ChangeAttribution_Target' AND object_id = OBJECT_ID('cfg.ChangeAttribution'))
CREATE INDEX IX_ChangeAttribution_Target ON cfg.ChangeAttribution (TargetKey, CreatedAt DESC);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ChangeAttribution_Correlation' AND object_id = OBJECT_ID('cfg.ChangeAttribution'))
CREATE INDEX IX_ChangeAttribution_Correlation ON cfg.ChangeAttribution (CorrelationId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ChangeAttribution_Kind' AND object_id = OBJECT_ID('cfg.ChangeAttribution'))
CREATE INDEX IX_ChangeAttribution_Kind ON cfg.ChangeAttribution (Kind, CreatedAt);

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
DENY UPDATE, DELETE ON OBJECT::cfg.ChangeAttribution TO public;

-- =====================================================================================================================
-- #269 THE DAILY JOB FLOW. Additive and guarded (an existing install only gains these tables).
--   cfg.JobFlow      the ONE flow definition (FlowId 'daily'): Mode flow | schedules and the definition JSON (the shape
--                    engine\_shared\SI-JobFlow.ps1 and the web app read: startTime, cadence, steps[job, enabled,
--                    withPrevious, onFailure, timeoutMinutes]). Written by Operations > Jobs (MERGE + a cfg.ChangeLog row,
--                    Scope 'job', Name 'flow'); read by the flow runner (caj-si-flow).
--   cfg.FlowRun      one row per flow run, written by the runner: trigger (schedule | catch-up | interval | manual |
--                    rerun), state, start / end, the heartbeat (a fresh one = a runner is alive: nothing starts twice),
--                    the time-of-day slot it ran for and the last slot carried forward (SCHED-1.1), a note (a blocked start).
--   cfg.FlowStepRun  one row per step of a run: state (Waiting | Starting | Running | Success | Failed | TimedOut |
--                    Interrupted | Skipped | Disabled), the job execution it started, start / end, error class + text,
--                    how many times it was started and why it was started again (a container that never started).
-- The runner writes as the jobs' identity (db_datareader + db_datawriter); the web app only READS the runs.
-- =====================================================================================================================
IF OBJECT_ID('cfg.JobFlow') IS NULL
CREATE TABLE cfg.JobFlow (
    FlowId          NVARCHAR(32)    NOT NULL CONSTRAINT PK_JobFlow PRIMARY KEY,
    Mode            NVARCHAR(16)    NOT NULL CONSTRAINT DF_JobFlow_Mode DEFAULT N'flow',
    DefinitionJson  NVARCHAR(MAX)   NOT NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_JobFlow_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy       NVARCHAR(256)   NULL,
    CONSTRAINT CK_JobFlow_Mode CHECK (Mode IN (N'flow', N'schedules')),
    CONSTRAINT CK_JobFlow_Json CHECK (ISJSON(DefinitionJson) = 1)
);

IF OBJECT_ID('cfg.FlowRun') IS NULL
CREATE TABLE cfg.FlowRun (
    FlowRunId       NVARCHAR(64)    NOT NULL CONSTRAINT PK_FlowRun PRIMARY KEY,
    FlowId          NVARCHAR(32)    NOT NULL CONSTRAINT DF_FlowRun_FlowId DEFAULT N'daily',
    Day             NVARCHAR(10)    NOT NULL,
    Trg             NVARCHAR(16)    NOT NULL,
    FromStep        NVARCHAR(64)    NULL,
    State           NVARCHAR(16)    NOT NULL,
    StartedUtc      DATETIME2(0)    NOT NULL,
    EndedUtc        DATETIME2(0)    NULL,
    HeartbeatUtc    DATETIME2(0)    NULL,
    StopReason      NVARCHAR(1000)  NULL,
    SlotUtc         DATETIME2(0)    NULL,
    LastSlotUtc     DATETIME2(0)    NULL,
    Note            NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FlowRun_Started' AND object_id = OBJECT_ID('cfg.FlowRun'))
CREATE INDEX IX_FlowRun_Started ON cfg.FlowRun (FlowId, StartedUtc DESC);

IF OBJECT_ID('cfg.FlowStepRun') IS NULL
CREATE TABLE cfg.FlowStepRun (
    FlowRunId       NVARCHAR(64)    NOT NULL,
    StepOrder       INT             NOT NULL,
    GroupNo         INT             NOT NULL,
    Job             NVARCHAR(64)    NOT NULL,
    State           NVARCHAR(16)    NOT NULL,
    Execution       NVARCHAR(128)   NULL,
    StartedUtc      DATETIME2(0)    NULL,
    EndedUtc        DATETIME2(0)    NULL,
    ErrorClass      NVARCHAR(64)    NULL,
    Error           NVARCHAR(1000)  NULL,
    CONSTRAINT PK_FlowStepRun PRIMARY KEY (FlowRunId, StepOrder),
    CONSTRAINT FK_FlowStepRun_Run FOREIGN KEY (FlowRunId) REFERENCES cfg.FlowRun (FlowRunId)
);

-- How many times the step's job was started, and why it was started again: a container that never started the engine
-- (an Azure platform problem) is started again by the runner (working rule 4); a failure of the engine never is.
IF COL_LENGTH('cfg.FlowStepRun', 'Attempts') IS NULL
ALTER TABLE cfg.FlowStepRun ADD Attempts INT NULL;

IF COL_LENGTH('cfg.FlowStepRun', 'RetryReason') IS NULL
ALTER TABLE cfg.FlowStepRun ADD RetryReason NVARCHAR(1000) NULL;

-- =====================================================================================================================
-- #306 PIPELINES AND STAGES. Additive and guarded (an existing install only gains columns and tables).
--   cfg.JobFlow keeps its name: its DefinitionJson is now schema 2 (a pipeline of stages -- collect, correlate, deliver --
--   each with its steps, the start time AND its time zone); a schema-1 definition is read as a pipeline (migrated in
--   memory, losslessly) until it is saved again.
--   cfg.FlowRun   + Scope (pipeline | stage | step | from-step), Target (the stage id / the job), RequestedBy (who asked
--                   for a Run now), RequestId (the queue request it served): the run names what was run and by whom.
--   cfg.FlowStepRun + Stage: the stage each step ran in.
--   cfg.PipelineLock  ONE row (LockId 'install'): the install's run lock. Every run -- scheduled or Run now, pipeline,
--                   stage or step -- takes it; the holder beats it on every save of its run record, and a lock whose
--                   heartbeat is older than 15 minutes is taken over (its runner stopped).
--   cfg.PipelineQueue the requests that wait for the lock, oldest first: Queued -> Running -> Done (Outcome = the run's
--                   state) or Cancelled (by a person, while still Queued). The same request (scope + target) is kept once
--                   while it waits (UX_PipelineQueue_Waiting). The web app writes Queued rows and cancels them; the runner
--                   (caj-si-flow, woken every 5 minutes or started by the web app) takes them.
-- =====================================================================================================================
IF COL_LENGTH('cfg.FlowRun', 'Scope') IS NULL
ALTER TABLE cfg.FlowRun ADD Scope NVARCHAR(16) NULL;

IF COL_LENGTH('cfg.FlowRun', 'Target') IS NULL
ALTER TABLE cfg.FlowRun ADD Target NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.FlowRun', 'RequestedBy') IS NULL
ALTER TABLE cfg.FlowRun ADD RequestedBy NVARCHAR(256) NULL;

IF COL_LENGTH('cfg.FlowRun', 'RequestId') IS NULL
ALTER TABLE cfg.FlowRun ADD RequestId BIGINT NULL;

IF COL_LENGTH('cfg.FlowStepRun', 'Stage') IS NULL
ALTER TABLE cfg.FlowStepRun ADD Stage NVARCHAR(32) NULL;

IF OBJECT_ID('cfg.PipelineLock') IS NULL
CREATE TABLE cfg.PipelineLock (
    LockId          NVARCHAR(32)    NOT NULL CONSTRAINT PK_PipelineLock PRIMARY KEY,
    Holder          NVARCHAR(128)   NULL,
    What            NVARCHAR(200)   NULL,
    FlowRunId       NVARCHAR(64)    NULL,
    AcquiredUtc     DATETIME2(0)    NULL,
    HeartbeatUtc    DATETIME2(0)    NULL
);

IF OBJECT_ID('cfg.PipelineQueue') IS NULL
CREATE TABLE cfg.PipelineQueue (
    Id              BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_PipelineQueue PRIMARY KEY,
    PipelineId      NVARCHAR(32)    NOT NULL CONSTRAINT DF_PipelineQueue_PipelineId DEFAULT N'daily',
    Scope           NVARCHAR(16)    NOT NULL,
    Target          NVARCHAR(64)    NOT NULL CONSTRAINT DF_PipelineQueue_Target DEFAULT N'',
    Trg             NVARCHAR(16)    NOT NULL,
    RequestedBy     NVARCHAR(256)   NULL,
    RequestedUtc    DATETIME2(0)    NOT NULL CONSTRAINT DF_PipelineQueue_RequestedUtc DEFAULT SYSUTCDATETIME(),
    SlotUtc         DATETIME2(0)    NULL,
    Note            NVARCHAR(1000)  NULL,
    State           NVARCHAR(16)    NOT NULL CONSTRAINT DF_PipelineQueue_State DEFAULT N'Queued',
    FlowRunId       NVARCHAR(64)    NULL,
    Outcome         NVARCHAR(16)    NULL,
    StartedUtc      DATETIME2(0)    NULL,
    EndedUtc        DATETIME2(0)    NULL,
    CancelledBy     NVARCHAR(256)   NULL,
    CONSTRAINT CK_PipelineQueue_Scope CHECK (Scope IN (N'pipeline', N'stage', N'step', N'from-step')),
    CONSTRAINT CK_PipelineQueue_State CHECK (State IN (N'Queued', N'Running', N'Done', N'Cancelled'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_PipelineQueue_Waiting' AND object_id = OBJECT_ID('cfg.PipelineQueue'))
CREATE UNIQUE INDEX UX_PipelineQueue_Waiting ON cfg.PipelineQueue (PipelineId, Scope, Target) WHERE State = N'Queued';

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PipelineQueue_State' AND object_id = OBJECT_ID('cfg.PipelineQueue'))
CREATE INDEX IX_PipelineQueue_State ON cfg.PipelineQueue (PipelineId, State, Id);

-- =====================================================================================================================
-- #700 CANCEL THE RUNNING PIPELINE RUN. Additive and guarded (an existing install gains two nullable columns when the
-- update applies this schema again -- its database step runs before any roll).
--   cfg.FlowRun + Version     the SecurityInsight version the run STARTED on (the runner writes it once): the updater cancels
--                             a run that started on another version, so a run never finishes on the wrong release.
--               + CancelledBy who cancelled the run (Operations > Jobs, a support start of the runner, the update). A
--                             cancelled run has State 'Cancelled' (no CHECK on the column) and StopReason "cancelled by
--                             <who>: <why>"; it is a finished run -- the scheduler never resumes it, and a runner that is
--                             still alive never saves it back (engine\_shared\SI-JobFlow.ps1 SaveRun).
-- =====================================================================================================================
IF COL_LENGTH('cfg.FlowRun', 'Version') IS NULL
ALTER TABLE cfg.FlowRun ADD Version NVARCHAR(32) NULL;

IF COL_LENGTH('cfg.FlowRun', 'CancelledBy') IS NULL
ALTER TABLE cfg.FlowRun ADD CancelledBy NVARCHAR(256) NULL;

-- #700 CANCEL FROM THE WEB APP (Operations > Jobs): the web app cancels the RUNNING run only through this procedure -- one
-- run, never the table. It holds no right on cfg.FlowRun / cfg.PipelineLock / cfg.PipelineQueue for this (the runner keeps
-- writing its run records itself). One transaction: the run (Cancelled, who, why, the end), its queue request (Done,
-- Outcome Cancelled) and the lock held for it (released); a run that has ended is left as it is. Outcomes: NotFound,
-- NotRunning, Cancelled (+ Holder = the runner that held the lock, Running = the steps still starting / running).
-- Static SQL only (CancelledBy exists: added just above), so the ownership chain covers every table it writes.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.FlowRunCancelSet @FlowRunId NVARCHAR(64), @By NVARCHAR(256), @Why NVARCHAR(1000)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51451, N''only the web app may cancel a pipeline run'', 1;
    IF @By IS NULL OR LTRIM(RTRIM(@By)) = N'''' THROW 51452, N''cancelling a run must name who cancelled it'', 1;
    BEGIN TRAN;
    DECLARE @state nvarchar(16) = (SELECT State FROM cfg.FlowRun WITH (UPDLOCK, HOLDLOCK) WHERE FlowRunId = @FlowRunId);
    IF @state IS NULL BEGIN COMMIT; SELECT N''NotFound'' AS Outcome, CAST(NULL AS nvarchar(128)) AS Holder, 0 AS Running; RETURN; END
    IF @state IN (N''Succeeded'', N''Failed'', N''Stopped'', N''Cancelled'') BEGIN COMMIT; SELECT N''NotRunning'' AS Outcome, CAST(NULL AS nvarchar(128)) AS Holder, 0 AS Running; RETURN; END
    UPDATE cfg.FlowRun SET State = N''Cancelled'', StopReason = @Why, EndedUtc = SYSUTCDATETIME(), CancelledBy = LEFT(@By, 256) WHERE FlowRunId = @FlowRunId;
    DECLARE @holder nvarchar(128) = NULL;
    SELECT @holder = Holder FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = N''install'' AND FlowRunId = @FlowRunId;
    UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N''install'' AND Holder IS NOT NULL AND FlowRunId = @FlowRunId;
    UPDATE cfg.PipelineQueue SET State = N''Done'', Outcome = N''Cancelled'', EndedUtc = SYSUTCDATETIME() WHERE FlowRunId = @FlowRunId AND State = N''Running'';
    DECLARE @running int = (SELECT COUNT(*) FROM cfg.FlowStepRun WHERE FlowRunId = @FlowRunId AND State IN (N''Starting'', N''Running''));
    COMMIT;
    SELECT N''Cancelled'' AS Outcome, @holder AS Holder, @running AS Running;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.FlowRunCancelSet TO public;

-- A RUN THAT HAS ENDED IS FINAL -- for every writer, older code included (live 2026-10-19, ring 2): a pipeline run cancelled
-- through cfg.FlowRunCancelSet was written back to Running, again and again, by a runner of older code whose container
-- outlived its stop -- its save set the state without looking (the guard lived only in the newest runner's MERGE). A run
-- in Succeeded / Failed / Stopped / Cancelled never changes state again: the update is refused (the writer's statement
-- fails; today's runner never sends one -- its MERGE keeps an ended run as it is).
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_FlowRun_Final ON cfg.FlowRun AFTER UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM inserted i JOIN deleted d ON d.FlowRunId = i.FlowRunId
               WHERE d.State IN (N''Succeeded'', N''Failed'', N''Stopped'', N''Cancelled'') AND i.State <> d.State)
        THROW 51461, N''cfg.FlowRun: a run that has ended (Succeeded, Failed, Stopped, Cancelled) is final -- its state is never changed again'', 1;
END');

-- A QUEUED REQUEST IS TAKEN ONLY BY THE RUNNER THAT HOLDS THE INSTALL LOCK (live 2026-10-19, ring 2): the same runner of older
-- code, its run cancelled and its lock released, went on to the next queued request -- and would have run it, for days, on
-- the code of a release before. Today's runner names itself in the session (si.pipeline.holder) when it takes a request: a
-- claim (Queued -> Running) by a runner that is not the lock's holder is refused. A claim that names nobody (a runner of
-- a release before this one) is refused while the lock is FREE -- its lock was released by a cancel -- and still accepted
-- while a runner holds the lock (an install mid-update keeps running). A refused runner starts nothing. Every other change
-- of the queue is left as it is.
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_PipelineQueue_Claim ON cfg.PipelineQueue AFTER UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF (SELECT COUNT(*) FROM inserted i JOIN deleted d ON d.Id = i.Id WHERE i.State = N''Running'' AND d.State <> N''Running'') = 0 RETURN;
    DECLARE @me NVARCHAR(128) = NULLIF(CAST(SESSION_CONTEXT(N''si.pipeline.holder'') AS NVARCHAR(128)), N'''');
    DECLARE @holder NVARCHAR(128) = (SELECT Holder FROM cfg.PipelineLock WHERE LockId = N''install'');
    IF @holder IS NULL OR (@me IS NOT NULL AND @me <> @holder)
        THROW 51462, N''cfg.PipelineQueue: a queued request is taken only by the runner that holds the install lock -- this runner does not (its lock was released by a cancel, or taken over); it starts nothing'', 1;
END');

-- CR8 (framework 12.11f item 1, SI #659): a change of a job's TRIGGER the web app asks for when it holds start-only rights
-- on the jobs (Jobs:ChangeMode = request). The web app only INSERTS the request; the pipeline runner (caj-si-flow, its own
-- identity) applies it on its next wake-up -- the trigger and the tags only, read back -- and records the outcome.
--   Action  to-manual (off its timer, the cron remembered) | to-schedule (Cron given, or the remembered one)
--   Outcome applied | failed | refused (not one of the install's jobs / not a valid request) | expired (older than a day)
IF OBJECT_ID('cfg.JobTriggerRequest') IS NULL
CREATE TABLE cfg.JobTriggerRequest (
    RequestId       BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_JobTriggerRequest PRIMARY KEY,
    JobName         NVARCHAR(64)    NOT NULL,
    Action          NVARCHAR(16)    NOT NULL,
    Cron            NVARCHAR(100)   NULL,
    RequestedBy     NVARCHAR(256)   NOT NULL,
    RequestedUtc    DATETIME2(0)    NOT NULL CONSTRAINT DF_JobTriggerRequest_RequestedUtc DEFAULT SYSUTCDATETIME(),
    AppliedUtc      DATETIME2(0)    NULL,
    Outcome         NVARCHAR(16)    NULL,
    Detail          NVARCHAR(1000)  NULL,
    CONSTRAINT CK_JobTriggerRequest_Action CHECK (Action IN (N'to-manual', N'to-schedule'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_JobTriggerRequest_Pending' AND object_id = OBJECT_ID('cfg.JobTriggerRequest'))
CREATE INDEX IX_JobTriggerRequest_Pending ON cfg.JobTriggerRequest (AppliedUtc, RequestId);

-- #931: a job start's own values without a start override (Azure Container Apps: a start with containers needs
-- Microsoft.App/jobs/write, which the web app must not hold). The web app writes Action 'start-env' with the values as a
-- JSON object (EnvJson) and starts the job with no body; the job's entrypoint claims the row (ExecutionName = its own
-- execution) and sets only the names allowed for that job (engine\_shared\SI-JobStartRequest.ps1). Additive: nullable.
IF COL_LENGTH('cfg.JobTriggerRequest', 'EnvJson') IS NULL
ALTER TABLE cfg.JobTriggerRequest ADD EnvJson NVARCHAR(4000) NULL;

IF COL_LENGTH('cfg.JobTriggerRequest', 'ExecutionName') IS NULL
ALTER TABLE cfg.JobTriggerRequest ADD ExecutionName NVARCHAR(128) NULL;

-- The action list grows without dropping anything (the schema stays additive): the first list is switched off and a
-- second, wider one added. Nothing is removed and no row is changed.
IF COL_LENGTH('cfg.JobTriggerRequest', 'Action') IS NOT NULL AND EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_JobTriggerRequest_Action'
           AND parent_object_id = OBJECT_ID('cfg.JobTriggerRequest') AND is_disabled = 0 AND definition NOT LIKE '%start-env%')
ALTER TABLE cfg.JobTriggerRequest NOCHECK CONSTRAINT CK_JobTriggerRequest_Action;

IF COL_LENGTH('cfg.JobTriggerRequest', 'Action') IS NOT NULL AND (SELECT COUNT(*) FROM sys.check_constraints WHERE name = 'CK_JobTriggerRequest_Actions'
           AND parent_object_id = OBJECT_ID('cfg.JobTriggerRequest')) = 0
ALTER TABLE cfg.JobTriggerRequest ADD CONSTRAINT CK_JobTriggerRequest_Actions CHECK (Action IN (N'to-manual', N'to-schedule', N'start-env'));

-- CR8 step 2, OBSERVE ONLY (framework 12.11f item 2, SI #659): every change a person makes in the web app is recorded with
-- the person's signed Entra token as the web app received it (Token, TokenSource bearer | session | none) and the time it
-- was captured. The pipeline runner verifies it (signature against Entra's published keys, issuer, audience, issued <=
-- captured <= expires, the person) and records the verdict -- verified | would-refuse -- then CLEARS the token. Nothing is
-- refused yet: the engine only says what it would refuse. The web app inserts; the MCP server is denied any read.
IF OBJECT_ID('cfg.SignedRequest') IS NULL
CREATE TABLE cfg.SignedRequest (
    Id              BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_SignedRequest PRIMARY KEY,
    CorrelationId   NVARCHAR(64)    NULL,
    Action          NVARCHAR(128)   NOT NULL,
    Actor           NVARCHAR(256)   NOT NULL,
    TokenSource     NVARCHAR(16)    NOT NULL,
    Token           NVARCHAR(MAX)   NULL,
    Audience        NVARCHAR(64)    NULL,
    CapturedUtc     DATETIME2(0)    NOT NULL CONSTRAINT DF_SignedRequest_CapturedUtc DEFAULT SYSUTCDATETIME(),
    VerifiedUtc     DATETIME2(0)    NULL,
    Verdict         NVARCHAR(16)    NULL,
    Detail          NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SignedRequest_Pending' AND object_id = OBJECT_ID('cfg.SignedRequest'))
CREATE INDEX IX_SignedRequest_Pending ON cfg.SignedRequest (VerifiedUtc, Id);

-- =============================================================================================
-- #277: GUARD EVENTS. Every guard that holds, refuses or halts a step to protect data writes one row here
-- (engine\_shared\SI-Guard.ps1 Send-SIGuardEvent; the web app's own guards through Guards\GuardEvents.cs). The web app's
-- Operations > Guards (safety checks) view reads it; a row the web app writes waits as MailState / TelemetryState 'pending' until the mail
-- job sends it (Invoke-SIGuardOutbox). cfg.GuardState keeps each guard's episode for the once-a-day mail
-- ("still tripping, N times"). Additive, no CHECK: outcomes and states are the catalog's (config\guard-catalog.locked.json).
-- =============================================================================================
IF OBJECT_ID('cfg.GuardEvent') IS NULL
CREATE TABLE cfg.GuardEvent (
    Id              BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_GuardEvent PRIMARY KEY,
    TsUtc           DATETIME2(3)    NOT NULL CONSTRAINT DF_GuardEvent_TsUtc DEFAULT SYSUTCDATETIME(),
    GuardId         NVARCHAR(80)    NOT NULL,
    GuardKey        NVARCHAR(500)   NOT NULL,
    Area            NVARCHAR(40)    NOT NULL,
    Job             NVARCHAR(40)    NULL,
    Engine          NVARCHAR(64)    NULL,
    Source          NVARCHAR(16)    NOT NULL,
    Outcome         NVARCHAR(16)    NOT NULL,
    Severity        NVARCHAR(16)    NOT NULL,
    Protected       NVARCHAR(400)   NULL,
    Subject         NVARCHAR(400)   NULL,
    Detail          NVARCHAR(2000)  NULL,
    MeasuredText    NVARCHAR(1000)  NULL,
    ValuesJson      NVARCHAR(MAX)   NULL,
    HeldCount       BIGINT          NOT NULL CONSTRAINT DF_GuardEvent_Held DEFAULT 0,
    ActionText      NVARCHAR(2000)  NULL,
    Link            NVARCHAR(400)   NULL,
    RunId           NVARCHAR(64)    NULL,
    TripCount       INT             NOT NULL CONSTRAINT DF_GuardEvent_Trips DEFAULT 1,
    FirstSeenUtc    DATETIME2(0)    NULL,
    MailState       NVARCHAR(16)    NOT NULL,
    MailTo          NVARCHAR(1000)  NULL,
    TelemetryState  NVARCHAR(16)    NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GuardEvent_Ts' AND object_id = OBJECT_ID('cfg.GuardEvent'))
CREATE INDEX IX_GuardEvent_Ts ON cfg.GuardEvent (TsUtc DESC);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GuardEvent_Pending' AND object_id = OBJECT_ID('cfg.GuardEvent'))
CREATE INDEX IX_GuardEvent_Pending ON cfg.GuardEvent (MailState, TelemetryState) INCLUDE (Id);

IF OBJECT_ID('cfg.GuardState') IS NULL
CREATE TABLE cfg.GuardState (
    GuardKey        NVARCHAR(500)   NOT NULL CONSTRAINT PK_GuardState PRIMARY KEY,
    GuardId         NVARCHAR(80)    NOT NULL,
    FirstSeenUtc    DATETIME2(0)    NOT NULL,
    LastSeenUtc     DATETIME2(0)    NOT NULL,
    TripCount       INT             NOT NULL,
    LastMailUtc     DATETIME2(0)    NULL
);

-- ---------------------------------------------------------------------------------------------
-- THE HELD CLOSE SET OF A HALTED VULNERABILITY CONNECTOR RUN (operator decision 2026-10-04: "we cannot block").
-- When the close limit halts a run, the closes it held are stored here (one row per connector and run: the finding ids,
-- and the counts per asset and per CVE). An Admin releases THAT set once -- Operations > Guards (safety checks), the link in the guard
-- mail, or Invoke-SIVulnLoop.ps1 -ReleaseHeldCloses <runId> on a VM -- and the connector's next run (or the one the
-- release starts) closes exactly the released findings that are still absent, after re-checking that the results are
-- complete. A release is never a setting change; it expires after 7 days. held -> released -> applied | expired.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.GuardRelease') IS NULL
CREATE TABLE cfg.GuardRelease (
    ReleaseId       BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_GuardRelease PRIMARY KEY,
    GuardId         NVARCHAR(80)    NOT NULL,
    Connector       NVARCHAR(128)   NOT NULL,
    ConnectorKind   NVARCHAR(20)    NULL,
    RunId           NVARCHAR(64)    NOT NULL,
    HeldUtc         DATETIME2(0)    NOT NULL CONSTRAINT DF_GuardRelease_HeldUtc DEFAULT SYSUTCDATETIME(),
    ExpiresUtc      DATETIME2(0)    NOT NULL,
    HeldCount       INT             NOT NULL,
    SummaryJson     NVARCHAR(MAX)   NULL,
    ItemsJson       NVARCHAR(MAX)   NOT NULL,
    State           NVARCHAR(20)    NOT NULL CONSTRAINT DF_GuardRelease_State DEFAULT 'held',
    ReleasedBy      NVARCHAR(256)   NULL,
    ReleasedUtc     DATETIME2(0)    NULL,
    AppliedUtc      DATETIME2(0)    NULL,
    AppliedRunId    NVARCHAR(64)    NULL,
    AppliedText     NVARCHAR(1000)  NULL,
    CONSTRAINT UQ_GuardRelease_Run UNIQUE (Connector, RunId),
    CONSTRAINT CK_GuardRelease_State CHECK (State IN ('held', 'released', 'applied', 'expired'))
);

-- ---------------------------------------------------------------------------------------------
-- ACKNOWLEDGED GUARD EVENTS (operator 2026-10-05: "how can i release these guards"). Every guard event can be
-- acknowledged once a person has read it (Operations > Guards (safety checks), audited guard.event.acknowledge); acknowledged events are
-- hidden by default. An acknowledgement also covers later REPEATS of exactly the same event -- the same guard key and the
-- same detail (DetailHash = SHA2_256 of the detail text) -- so a situation that re-trips on every run until it ages out
-- (rows without a collection time, say) is acknowledged once. A different detail is a new situation and shows again.
-- Rows are only added (the web app's role: INSERT); an acknowledgement is never a release and changes nothing else.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.GuardAck') IS NULL
CREATE TABLE cfg.GuardAck (
    AckId           BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_GuardAck PRIMARY KEY,
    EventId         BIGINT          NOT NULL,
    GuardKey        NVARCHAR(500)   NOT NULL,
    DetailHash      VARBINARY(32)   NOT NULL,
    AckBy           NVARCHAR(256)   NOT NULL,
    AckUtc          DATETIME2(0)    NOT NULL CONSTRAINT DF_GuardAck_AckUtc DEFAULT SYSUTCDATETIME(),
    Note            NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GuardAck_Key' AND object_id = OBJECT_ID('cfg.GuardAck'))
CREATE INDEX IX_GuardAck_Key ON cfg.GuardAck (GuardKey, DetailHash) INCLUDE (AckBy, AckUtc);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GuardAck_Event' AND object_id = OBJECT_ID('cfg.GuardAck'))
CREATE INDEX IX_GuardAck_Event ON cfg.GuardAck (EventId) INCLUDE (AckBy, AckUtc);

-- =============================================================================================
-- THE MANAGEMENT SUMMARY REPORT (#291): report definitions (Configuration > Reports & outputs > Management summary)
-- and their outbox. A definition chooses its sections (kpi, domains, timeline), the report data (Summary | Detailed),
-- recipients and a weekly / monthly schedule (Day: weekday 1 = Monday .. 7, or day of month 1..28; TimeUtc HH:mm).
-- LastPeriodKey is the period last sent ('2026-W41' / '2026-10'): the web app's scheduler CLAIMS a period by moving it
-- (UPDATE ... WHERE LastPeriodKey <> @Key), so a period is sent once, and a run of missed periods is caught up once.
-- The mail job sends cfg.ReportMail through the one SMTP path with the exemption and sign-in mails.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.MgmtReport') IS NULL
CREATE TABLE cfg.MgmtReport (
    ReportId        BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_MgmtReport PRIMARY KEY,
    Name            NVARCHAR(100)   NOT NULL,
    Grain           NVARCHAR(16)    NOT NULL,
    Sections        NVARCHAR(100)   NOT NULL,
    Recipients      NVARCHAR(2000)  NOT NULL,
    Cadence         NVARCHAR(16)    NOT NULL,
    [Day]           INT             NOT NULL,
    TimeUtc         NVARCHAR(5)     NOT NULL,
    Enabled         BIT             NOT NULL CONSTRAINT DF_MgmtReport_Enabled DEFAULT 1,
    LastPeriodKey   NVARCHAR(16)    NULL,
    LastSentAt      DATETIME2(0)    NULL,
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_MgmtReport_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy       NVARCHAR(256)   NOT NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_MgmtReport_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy       NVARCHAR(256)   NOT NULL,
    RemovedAt       DATETIME2(0)    NULL,
    CONSTRAINT CK_MgmtReport_Grain CHECK (Grain IN ('Summary', 'Detailed')),
    CONSTRAINT CK_MgmtReport_Cadence CHECK (Cadence IN ('weekly', 'monthly'))
);

IF OBJECT_ID('cfg.ReportMail') IS NULL
CREATE TABLE cfg.ReportMail (
    MailId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ReportMail PRIMARY KEY,
    ReportId    BIGINT          NOT NULL,
    PeriodKey   NVARCHAR(16)    NULL,       -- NULL = sent now by a person
    ToList      NVARCHAR(2000)  NOT NULL,
    Subject     NVARCHAR(400)   NOT NULL,
    BodyHtml    NVARCHAR(MAX)   NOT NULL,
    QueuedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_ReportMail_QueuedAt DEFAULT SYSUTCDATETIME(),
    QueuedBy    NVARCHAR(256)   NOT NULL,
    SentAt      DATETIME2(0)    NULL,
    Attempts    INT             NOT NULL CONSTRAINT DF_ReportMail_Attempts DEFAULT 0,
    LastError   NVARCHAR(1000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ReportMail_Pending' AND object_id = OBJECT_ID('cfg.ReportMail'))
CREATE INDEX IX_ReportMail_Pending ON cfg.ReportMail (SentAt, QueuedAt);

-- THE WEB APP'S SIGN-IN KEY RING (#345): the ASP.NET data-protection keys that encrypt the sign-in cookie and every form's
-- antiforgery token, shared by every revision and replica of the web app (Auth\SqlKeyRing.cs). On the container's disk a
-- new revision had new keys, so a deploy signed every open page out and refused its next save. One row per key, written
-- once by the web app (INSERT only; ASP.NET expires a key, it never changes or removes one). KeyXml is the key as ASP.NET
-- writes it -- the MCP server's identity is DENIED SELECT on this table (Deploy-SIManagement.ps1).
IF OBJECT_ID('cfg.WebKeyRing') IS NULL
CREATE TABLE cfg.WebKeyRing (
    FriendlyName    NVARCHAR(200)   NOT NULL CONSTRAINT PK_WebKeyRing PRIMARY KEY,
    KeyXml          NVARCHAR(MAX)   NOT NULL,
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_WebKeyRing_CreatedAt DEFAULT SYSUTCDATETIME()
);

-- =============================================================================================
-- SAVED PIVOT VIEWS (#360): the weighted risk page's pivot builder (Assets & services > Risk scores > Weighted, per service > Pivot) saved
-- under a name. One row per (Owner, Name) in force; Owner = the signed-in account that saved it. Shared = 1 (set only by
-- an Admin) lists it for every reader. State = the pivot as URL parameters (pr / pc / pv / pf / pfv.* / psort / pdir):
-- field and measure KEYS from the page's fixed list, never SQL -- read back through the same whitelist as the URL.
-- A removal stamps RemovedAt; nothing is deleted.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.PivotView') IS NULL
CREATE TABLE cfg.PivotView (
    ViewId      BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_PivotView PRIMARY KEY,
    Name        NVARCHAR(100)   NOT NULL,
    Owner       NVARCHAR(256)   NOT NULL,
    Shared      BIT             NOT NULL CONSTRAINT DF_PivotView_Shared DEFAULT 0,
    State       NVARCHAR(2000)  NOT NULL,
    CreatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_PivotView_CreatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_PivotView_UpdatedAt DEFAULT SYSUTCDATETIME(),
    RemovedAt   DATETIME2(0)    NULL,
    RemovedBy   NVARCHAR(256)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PivotView_Owner' AND object_id = OBJECT_ID('cfg.PivotView'))
CREATE INDEX IX_PivotView_Owner ON cfg.PivotView (Owner, Name) WHERE RemovedAt IS NULL;

-- =============================================================================================
-- GRID COLUMN LAYOUTS (V3-DATA-MODEL 2.13): which columns a grid shows. Scope 'tenant' (UserKey '') = the default an Admin
-- sets for everyone; Scope 'user' = one person's own (UserKey = their sign-in name). View = the grid ('cis' = the CIs).
-- ColumnsJson = a JSON array of column KEYS from the web app's fixed column catalog, never SQL; a key the catalog no
-- longer knows is dropped when read. "Reset to the tenant default" removes the person's own row.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.ColumnLayout') IS NULL
CREATE TABLE cfg.ColumnLayout (
    Scope       NVARCHAR(16)    NOT NULL,
    UserKey     NVARCHAR(256)   NOT NULL CONSTRAINT DF_ColumnLayout_UserKey DEFAULT N'',
    [View]      NVARCHAR(64)    NOT NULL,
    ColumnsJson NVARCHAR(MAX)   NOT NULL,
    UpdatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_ColumnLayout_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy   NVARCHAR(256)   NULL,
    CONSTRAINT PK_ColumnLayout PRIMARY KEY (Scope, UserKey, [View]),
    CONSTRAINT CK_ColumnLayout_Scope CHECK (Scope IN (N'tenant', N'user'))
);

-- ---------------------------------------------------------------------------------------------
-- WHAT EACH PERSON FINE-TUNES ON A DATA VIEW, next to their columns (cfg.ColumnLayout). Additive and guarded: an existing
-- install only gains the two tables; until they exist the web app shows every view as before and says a save is not
-- possible yet.
--   cfg.ViewState    one row per person and view: the last sort / filters / search (StateJson = a JSON object of the
--                    view's own address parameters, {"sort":["Risk"],"f.Tier":["0","1"]}; never SQL, never the page
--                    number or the selected rows), the column widths (WidthsJson = {"<column key>": pixels}) and the
--                    named layout in use (LayoutId; a layout that was deleted simply is not in use any more).
--   cfg.ViewLayout   named layouts of a view ("Patch planning"): the columns in their order, the sort / filters and the
--                    widths. Scope 'user' = one person's own (UserKey = their sign-in name); Scope 'shared' (UserKey '')
--                    = published by an Admin for everyone, changed by an Admin only (the web app checks).
-- Every read is by key: (UserKey, View) and (View, Scope, UserKey).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cfg.ViewState') IS NULL
CREATE TABLE cfg.ViewState (
    UserKey     NVARCHAR(256)   NOT NULL,
    [View]      NVARCHAR(64)    NOT NULL,
    StateJson   NVARCHAR(MAX)   NULL,
    WidthsJson  NVARCHAR(MAX)   NULL,
    LayoutId    INT             NULL,
    UpdatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_ViewState_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_ViewState PRIMARY KEY (UserKey, [View])
);

IF OBJECT_ID('cfg.ViewLayout') IS NULL
CREATE TABLE cfg.ViewLayout (
    LayoutId    INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ViewLayout PRIMARY KEY,
    Scope       NVARCHAR(16)    NOT NULL,
    UserKey     NVARCHAR(256)   NOT NULL CONSTRAINT DF_ViewLayout_UserKey DEFAULT N'',
    [View]      NVARCHAR(64)    NOT NULL,
    Name        NVARCHAR(80)    NOT NULL,
    ColumnsJson NVARCHAR(MAX)   NOT NULL,
    StateJson   NVARCHAR(MAX)   NULL,
    WidthsJson  NVARCHAR(MAX)   NULL,
    UpdatedAt   DATETIME2(0)    NOT NULL CONSTRAINT DF_ViewLayout_UpdatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedBy   NVARCHAR(256)   NULL,
    CONSTRAINT CK_ViewLayout_Scope CHECK (Scope IN (N'user', N'shared'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ViewLayout_Name' AND object_id = OBJECT_ID('cfg.ViewLayout'))
CREATE UNIQUE INDEX UX_ViewLayout_Name ON cfg.ViewLayout ([View], Scope, UserKey, Name);

-- owner 2026-10-19 ("pinned views to the menu"): cfg.ViewPin -- a named layout pinned to the menu. Scope 'user' (UserKey =
-- the person's sign-in name) = in that person's "My views"; Scope 'tenant' (UserKey '') = pinned by an Admin for everyone
-- (a published layout only -- the web app checks). Path = the page the layout belongs to (its own parameters, never a
-- sort or filter: those are the layout's). Deleting the layout removes its pins. Additive: an install without it shows no
-- pinned views and a pin says the table is not there yet.
IF OBJECT_ID('cfg.ViewPin') IS NULL
CREATE TABLE cfg.ViewPin (
    Scope       NVARCHAR(16)    NOT NULL,
    UserKey     NVARCHAR(256)   NOT NULL CONSTRAINT DF_ViewPin_UserKey DEFAULT N'',
    LayoutId    INT             NOT NULL,
    [Path]      NVARCHAR(512)   NOT NULL,
    PinnedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_ViewPin_PinnedAt DEFAULT SYSUTCDATETIME(),
    PinnedBy    NVARCHAR(256)   NULL,
    CONSTRAINT PK_ViewPin PRIMARY KEY (Scope, UserKey, LayoutId),
    CONSTRAINT CK_ViewPin_Scope CHECK (Scope IN (N'user', N'tenant'))
);

-- =====================================================================================================================
-- #404 (framework CONFIG-1): THE CHANGE JOURNAL, CONFIGURATION BACKUPS, SECOND-PERSON APPROVALS, COLLECTION RESEND /
-- CONNECTOR UNDO, AND THE GUARD RELEASE OF GUARD-1.6. Additive and guarded (an existing install only gains these).
--   cfg.ConfigJournal    CONFIG-1.1: one row per changed configuration record per commit -- the full record before and
--                        after, Add / Modify / Remove, InitiatedBy / ApprovedBy, Source (gui / api / import / restore /
--                        undo / sync / template), UndoOf, CommitId = the audit trail's CorrelationId (SESSION_CONTEXT
--                        si.audit.cid). Written ONLY by the journal triggers generated at the end of this file (one per
--                        table of config\config-entities.locked.json), inside the writing statement's transaction: the
--                        change and its journal row land together or not at all. Append-only in the database (the DENY
--                        below, the AUDIT-1.3 model SI already uses); rows go only through cfg.ConfigJournalRetentionApply,
--                        which refuses a period shorter than the backup retention (an undo must keep its evidence).
--   cfg.ConfigBackup     CONFIG-1.3: one row per backup (scheduled / manual / import). Content = the configuration set
--                        in force (cfg.vConfigSnapshot) as JSON, COMPRESSed; SameAsBackupId instead of a copy when nothing
--                        changed since the newest backup ("no change" is recorded, not copied). Written ONLY through the
--                        owner-chained procedures below (take, import, pin, prune): every identity is DENIED direct writes.
--   cfg.ConfigApproval   CONFIG-1.5: a restore or a guard release waiting for a second SuperAdmin, when the setting
--                        SI_Pro_ConfigSecondPerson asks for one (default off).
--   cfg.CollectionSend   #404 part 2: a person's request to send an earlier collection into a connector again, or to
--                        undo the connector's last run; the connector's job carries it out through its normal path and
--                        guards and records the outcome here.
-- =====================================================================================================================
IF OBJECT_ID('cfg.ConfigJournal') IS NULL
CREATE TABLE cfg.ConfigJournal (
    JournalId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ConfigJournal PRIMARY KEY,
    CommitId        NVARCHAR(64)    NOT NULL,
    CommittedUtc    DATETIME2(3)    NOT NULL CONSTRAINT DF_ConfigJournal_CommittedUtc DEFAULT SYSUTCDATETIME(),
    Entity          NVARCHAR(32)    NOT NULL,
    EntityKey       NVARCHAR(900)   NOT NULL,
    Op              NVARCHAR(8)     NOT NULL,
    BeforeJson      NVARCHAR(MAX)   NULL,
    AfterJson       NVARCHAR(MAX)   NULL,
    InitiatedBy     NVARCHAR(256)   NOT NULL,
    ApprovedBy      NVARCHAR(256)   NULL,
    Source          NVARCHAR(16)    NOT NULL,
    ActorSource     NVARCHAR(16)    NULL,
    UndoOf          NVARCHAR(64)    NULL,
    Reason          NVARCHAR(400)   NULL,
    CONSTRAINT CK_ConfigJournal_Op CHECK (Op IN (N'Add', N'Modify', N'Remove'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConfigJournal_Commit' AND object_id = OBJECT_ID('cfg.ConfigJournal'))
CREATE INDEX IX_ConfigJournal_Commit ON cfg.ConfigJournal (CommitId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConfigJournal_Record' AND object_id = OBJECT_ID('cfg.ConfigJournal'))
CREATE INDEX IX_ConfigJournal_Record ON cfg.ConfigJournal (Entity, EntityKey, JournalId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConfigJournal_Time' AND object_id = OBJECT_ID('cfg.ConfigJournal'))
CREATE INDEX IX_ConfigJournal_Time ON cfg.ConfigJournal (CommittedUtc) INCLUDE (CommitId, InitiatedBy, Source);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConfigJournal_Who' AND object_id = OBJECT_ID('cfg.ConfigJournal'))
CREATE INDEX IX_ConfigJournal_Who ON cfg.ConfigJournal (InitiatedBy, CommittedUtc);

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
DENY UPDATE, DELETE ON OBJECT::cfg.ConfigJournal TO public;

-- The ONE removal of journal rows (the configuration backup job, when SI_Pro_ConfigJournalRetentionDays is set; not set =
-- kept, the default). Refuses a period shorter than the backup retention it reads itself (SI_Pro_ConfigBackupRetentionDays,
-- default 90), runs only for the job identity (db_datawriter) or the owner, removes a batch at a time. Owner-chained.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.ConfigJournalRetentionApply @Days INT, @Batch INT = 5000
AS
BEGIN
    SET NOCOUNT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51404, N''only the configuration backup job may apply the change journal retention -- nothing was removed'', 1;
    DECLARE @backup INT = (SELECT TOP (1) TRY_CONVERT(INT, JSON_VALUE(N''['' + s.ValueJson + N'']'', ''$[0]'')) FROM cfg.Setting AS s
                           WHERE s.Name = N''SI_Pro_ConfigBackupRetentionDays'' AND s.Scope = N''solution'' AND s.ValueJson IS NOT NULL AND ISJSON(N''['' + s.ValueJson + N'']'') = 1);
    IF @backup IS NULL OR @backup < 1 SET @backup = 90;
    IF @Days IS NULL OR @Days < @backup
        THROW 51405, N''the change journal is kept at least as long as the configuration backups -- nothing was removed'', 1;
    IF @Batch IS NULL OR @Batch < 1 SET @Batch = 5000;
    DELETE TOP (@Batch) FROM cfg.ConfigJournal WHERE CommittedUtc < DATEADD(DAY, -@Days, SYSUTCDATETIME());
    SELECT @@ROWCOUNT AS N;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.ConfigJournalRetentionApply TO public;

IF OBJECT_ID('cfg.ConfigBackup') IS NULL
CREATE TABLE cfg.ConfigBackup (
    BackupId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ConfigBackup PRIMARY KEY,
    TakenUtc          DATETIME2(3)    NOT NULL CONSTRAINT DF_ConfigBackup_TakenUtc DEFAULT SYSUTCDATETIME(),
    TakenBy           NVARCHAR(256)   NOT NULL,
    TriggerKind       NVARCHAR(16)    NOT NULL,
    ContentHash       CHAR(64)        NOT NULL,
    SameAsBackupId    BIGINT          NULL,
    Content           VARBINARY(MAX)  NULL,
    EntityCountsJson  NVARCHAR(4000)  NULL,
    ProductVersion    NVARCHAR(32)    NULL,
    Note              NVARCHAR(400)   NULL,
    CommitId          NVARCHAR(64)    NULL,
    Pinned            BIT             NOT NULL CONSTRAINT DF_ConfigBackup_Pinned DEFAULT 0,
    PinnedBy          NVARCHAR(256)   NULL,
    PinnedUtc         DATETIME2(0)    NULL,
    PinNote           NVARCHAR(400)   NULL,
    CONSTRAINT CK_ConfigBackup_Content CHECK (Content IS NOT NULL OR SameAsBackupId IS NOT NULL)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConfigBackup_Taken' AND object_id = OBJECT_ID('cfg.ConfigBackup'))
CREATE INDEX IX_ConfigBackup_Taken ON cfg.ConfigBackup (TakenUtc DESC) INCLUDE (Pinned, SameAsBackupId);

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
DENY INSERT, UPDATE, DELETE ON OBJECT::cfg.ConfigBackup TO public;

-- Who may take / import / pin a backup: the jobs (db_datawriter), the web app (its audit writer role) and the owner.
-- TAKE: the configuration in force (cfg.vConfigSnapshot, generated below) as one JSON array ordered by entity and key,
-- hashed; the same hash as the newest backup = a "no change" row pointing at the backup that holds the content.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.ConfigBackupTake @TakenBy NVARCHAR(256), @Trigger NVARCHAR(16), @Note NVARCHAR(400) = NULL, @CommitId NVARCHAR(64) = NULL, @ProductVersion NVARCHAR(32) = NULL
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51406, N''only the configuration backup job or the web app may take a configuration backup'', 1;
    IF @Trigger IS NULL OR @Trigger NOT IN (N''scheduled'', N''manual'', N''pre-restore'') SET @Trigger = N''manual'';
    DECLARE @json NVARCHAR(MAX) = (SELECT s.Entity AS e, s.EntityKey AS k, JSON_QUERY(s.RecordJson) AS r FROM cfg.vConfigSnapshot AS s ORDER BY s.Entity, s.EntityKey FOR JSON PATH, INCLUDE_NULL_VALUES);
    IF @json IS NULL SET @json = N''[]'';
    DECLARE @hash CHAR(64) = LOWER(CONVERT(CHAR(64), HASHBYTES(''SHA2_256'', CAST(@json AS VARBINARY(MAX))), 2));
    DECLARE @counts NVARCHAR(4000) = (SELECT s.Entity AS e, COUNT(*) AS n FROM cfg.vConfigSnapshot AS s GROUP BY s.Entity ORDER BY s.Entity FOR JSON PATH);
    DECLARE @lastHash CHAR(64), @lastContent BIGINT, @id BIGINT;
    BEGIN TRAN;
    SELECT TOP (1) @lastHash = b.ContentHash, @lastContent = COALESCE(b.SameAsBackupId, b.BackupId) FROM cfg.ConfigBackup AS b WITH (UPDLOCK, HOLDLOCK) ORDER BY b.BackupId DESC;
    IF @lastHash = @hash
        INSERT cfg.ConfigBackup (TakenBy, TriggerKind, ContentHash, SameAsBackupId, Content, EntityCountsJson, ProductVersion, Note, CommitId)
        VALUES (LEFT(@TakenBy, 256), @Trigger, @hash, @lastContent, NULL, @counts, @ProductVersion, @Note, @CommitId);
    ELSE
        INSERT cfg.ConfigBackup (TakenBy, TriggerKind, ContentHash, SameAsBackupId, Content, EntityCountsJson, ProductVersion, Note, CommitId)
        VALUES (LEFT(@TakenBy, 256), @Trigger, @hash, NULL, COMPRESS(@json), @counts, @ProductVersion, @Note, @CommitId);
    SET @id = SCOPE_IDENTITY();
    COMMIT;
    SELECT @id AS BackupId, @hash AS ContentHash, CASE WHEN @lastHash = @hash THEN 1 ELSE 0 END AS NoChange, @counts AS EntityCountsJson;
END');

-- IMPORT: a backup file another environment (or this one) exported, after the web app checked its format and signature.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.ConfigBackupImport @ContentJson NVARCHAR(MAX), @TakenBy NVARCHAR(256), @Note NVARCHAR(400) = NULL, @CommitId NVARCHAR(64) = NULL, @ProductVersion NVARCHAR(32) = NULL
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51407, N''only the web app may import a configuration backup'', 1;
    IF @ContentJson IS NULL OR ISJSON(@ContentJson) <> 1 OR LEFT(LTRIM(@ContentJson), 1) <> N''[''
        THROW 51408, N''the backup file does not hold a configuration set -- nothing was imported'', 1;
    DECLARE @hash CHAR(64) = LOWER(CONVERT(CHAR(64), HASHBYTES(''SHA2_256'', CAST(@ContentJson AS VARBINARY(MAX))), 2));
    DECLARE @counts NVARCHAR(4000) = (SELECT j.e AS e, COUNT(*) AS n FROM OPENJSON(@ContentJson) WITH (e NVARCHAR(32) ''$.e'') AS j GROUP BY j.e ORDER BY j.e FOR JSON PATH);
    INSERT cfg.ConfigBackup (TakenBy, TriggerKind, ContentHash, SameAsBackupId, Content, EntityCountsJson, ProductVersion, Note, CommitId)
    VALUES (LEFT(@TakenBy, 256), N''import'', @hash, NULL, COMPRESS(@ContentJson), @counts, @ProductVersion, @Note, @CommitId);
    SELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS BackupId, @hash AS ContentHash, @counts AS EntityCountsJson;
END');

-- PIN / UNPIN: a pinned backup is kept past the retention (e.g. before a large change).
EXEC (N'CREATE OR ALTER PROCEDURE cfg.ConfigBackupPin @BackupId BIGINT, @Pinned BIT, @By NVARCHAR(256), @Note NVARCHAR(400) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51409, N''only the web app may pin a configuration backup'', 1;
    UPDATE cfg.ConfigBackup SET Pinned = @Pinned, PinnedBy = CASE WHEN @Pinned = 1 THEN LEFT(@By, 256) END,
           PinnedUtc = CASE WHEN @Pinned = 1 THEN SYSUTCDATETIME() END, PinNote = CASE WHEN @Pinned = 1 THEN @Note END
    WHERE BackupId = @BackupId AND Pinned <> @Pinned;
    SELECT @@ROWCOUNT AS Changed;
END');

-- PRUNE: backups older than @Days that are not pinned -- but never a backup whose content a KEPT backup still points at
-- ("no change" rows hold no copy). Answers the removed rows (the caller records config.backup.prune). Job / owner only.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.ConfigBackupPrune @Days INT
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51410, N''only the configuration backup job may prune configuration backups -- nothing was removed'', 1;
    IF @Days IS NULL OR @Days < 1
        THROW 51411, N''a configuration backup is kept at least 1 day -- nothing was removed'', 1;
    DECLARE @cut DATETIME2(3) = DATEADD(DAY, -@Days, SYSUTCDATETIME());
    DECLARE @gone TABLE (BackupId BIGINT, TakenUtc DATETIME2(3));
    DELETE b OUTPUT deleted.BackupId, deleted.TakenUtc INTO @gone
    FROM cfg.ConfigBackup AS b
    WHERE b.TakenUtc < @cut AND b.Pinned = 0
      AND NOT EXISTS (SELECT 1 FROM cfg.ConfigBackup AS k WHERE k.SameAsBackupId = b.BackupId AND (k.TakenUtc >= @cut OR k.Pinned = 1));
    SELECT BackupId, TakenUtc FROM @gone ORDER BY BackupId;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.ConfigBackupTake TO public;

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.ConfigBackupImport TO public;

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.ConfigBackupPin TO public;

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.ConfigBackupPrune TO public;

-- INSTALL KEY, CLAIM AGAIN: after Invardia reset this install's key, an Admin on Settings > Updates asks the updater to
-- claim it ONCE more (a claim answered 409 is held and never repeated by itself). The web app writes only this one row of
-- cfg.InstallState, only through this procedure (it holds no write right on the table); the updater takes the request
-- away (reads and deletes it in one statement) BEFORE it claims, so one request is one claim -- never a loop.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.InstallKeyClaimAgainRequest @RequestedBy NVARCHAR(256)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51412, N''only the web app may ask for the install key to be claimed again'', 1;
    IF @RequestedBy IS NULL OR LTRIM(RTRIM(@RequestedBy)) = N'''' THROW 51413, N''the request must name who asked'', 1;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N''InstallKeyClaimAgain'')
        UPDATE cfg.InstallState SET Value = N''requested'', [Version] = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = LEFT(@RequestedBy, 256) WHERE Name = N''InstallKeyClaimAgain'';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N''InstallKeyClaimAgain'', N''requested'', NULL, LEFT(@RequestedBy, 256));
    COMMIT;
    SELECT N''Requested'' AS Outcome, SYSUTCDATETIME() AS RequestedAt;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.InstallKeyClaimAgainRequest TO public;

-- CR4 (#654) THE STRICTER PERIOD, ENDED EARLY: for 24 hours after a release that changed engine code the safety checks'
-- limits are halved (cfg.InstallState 'EngineFingerprint', written by the updater). A SuperAdmin may end that period early,
-- with a reason, on Operations > Guards (safety checks) (audited guard.strict.end-early). The web app writes only this one row of
-- cfg.InstallState ('GuardStrictEnd': { hash, strictFrom, endedAt, by, role, reason } -- it names the period it ends, so it
-- never ends a later one), only through this procedure; it holds no write right on the table.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.GuardStrictEndSet @Value NVARCHAR(400), @By NVARCHAR(256)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51441, N''only the web app may end the stricter period of the safety checks'', 1;
    IF @By IS NULL OR LTRIM(RTRIM(@By)) = N'''' THROW 51442, N''ending the stricter period must name who ended it'', 1;
    IF @Value IS NULL OR ISJSON(@Value) <> 1 OR JSON_VALUE(@Value, ''$.hash'') IS NULL OR JSON_VALUE(@Value, ''$.strictFrom'') IS NULL
        THROW 51443, N''the end must name the period it ends (hash and strictFrom)'', 1;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N''GuardStrictEnd'')
        UPDATE cfg.InstallState SET Value = @Value, [Version] = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = LEFT(@By, 256) WHERE Name = N''GuardStrictEnd'';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N''GuardStrictEnd'', @Value, NULL, LEFT(@By, 256));
    COMMIT;
    SELECT N''Ended'' AS Outcome, SYSUTCDATETIME() AS EndedAt;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.GuardStrictEndSet TO public;

-- MAIL-1, THE EXCHANGE ADMINISTRATOR'S CONFIRMATION: the guided mail setup (Settings > E-mail > Set up mail) records that
-- an Exchange administrator scoped Mail.Send to the shared mailbox. The web app writes only this one row of
-- cfg.InstallState, only through this procedure -- it holds no write right on the table, so it can never overwrite the
-- licence, the ring, the update state or the restriction the mail job PROVED ('MailRestriction').
EXEC (N'CREATE OR ALTER PROCEDURE cfg.MailRestrictionAttestationSet @Value NVARCHAR(400), @By NVARCHAR(256)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51414, N''only the web app may record the mail restriction confirmation'', 1;
    IF @Value IS NULL OR LTRIM(RTRIM(@Value)) = N'''' THROW 51415, N''the confirmation must have a value'', 1;
    IF @By IS NULL OR LTRIM(RTRIM(@By)) = N'''' THROW 51416, N''the confirmation must name who gave it'', 1;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N''MailRestrictionAttestation'')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = LEFT(@By, 256) WHERE Name = N''MailRestrictionAttestation'';
    ELSE
        INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N''MailRestrictionAttestation'', @Value, LEFT(@By, 256));
    COMMIT;
    SELECT N''Saved'' AS Outcome;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.MailRestrictionAttestationSet TO public;

-- #732 ONE METHOD EVERYWHERE: the update moves an install whose jobs run on their own timers to the pipeline, and the stored
-- pipeline (cfg.JobFlow, FlowId 'daily') must then say 'flow' -- or, when a later step fails, say again what it said. The
-- engine / updater code sets ONLY the mode, ONLY through this procedure (no write right on the table; the definition and its
-- journal are the web app's). Runs only for a job identity (db_datawriter / si_engine) or the owner. No stored pipeline =
-- nothing to set (Updated 0): the default pipeline a new install runs is already 'flow'.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.JobFlowSetMode @Mode NVARCHAR(16), @By NVARCHAR(256)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51480, N''only a job identity may set how the pipeline runs -- nothing was changed'', 1;
    IF @Mode IS NULL OR @Mode NOT IN (N''flow'', N''schedules'') THROW 51481, N''the pipeline runs as flow or schedules'', 1;
    IF @By IS NULL OR LTRIM(RTRIM(@By)) = N'''' THROW 51482, N''setting how the pipeline runs must name who set it'', 1;
    UPDATE cfg.JobFlow SET Mode = @Mode, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = LEFT(@By, 256) WHERE FlowId = N''daily'';
    SELECT @@ROWCOUNT AS Updated;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.JobFlowSetMode TO public;

IF OBJECT_ID('cfg.ConfigApproval') IS NULL
CREATE TABLE cfg.ConfigApproval (
    ApprovalId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ConfigApproval PRIMARY KEY,
    Kind            NVARCHAR(24)    NOT NULL,       -- restore | guard-release
    Title           NVARCHAR(400)   NOT NULL,
    PayloadJson     NVARCHAR(MAX)   NOT NULL,
    Reason          NVARCHAR(1000)  NULL,
    RequestedBy     NVARCHAR(256)   NOT NULL,
    RequestedUtc    DATETIME2(0)    NOT NULL CONSTRAINT DF_ConfigApproval_RequestedUtc DEFAULT SYSUTCDATETIME(),
    ExpiresUtc      DATETIME2(0)    NOT NULL,
    CorrelationId   NVARCHAR(64)    NULL,
    State           NVARCHAR(16)    NOT NULL CONSTRAINT DF_ConfigApproval_State DEFAULT N'pending',
    DecidedBy       NVARCHAR(256)   NULL,
    DecidedUtc      DATETIME2(0)    NULL,
    DecisionNote    NVARCHAR(1000)  NULL,
    OutcomeText     NVARCHAR(2000)  NULL,
    CONSTRAINT CK_ConfigApproval_Payload CHECK (ISJSON(PayloadJson) = 1)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ConfigApproval_State' AND object_id = OBJECT_ID('cfg.ConfigApproval'))
CREATE INDEX IX_ConfigApproval_State ON cfg.ConfigApproval (State, RequestedUtc DESC);

IF OBJECT_ID('cfg.CollectionSend') IS NULL
CREATE TABLE cfg.CollectionSend (
    SendId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_CollectionSend PRIMARY KEY,
    Kind            NVARCHAR(16)    NOT NULL,       -- resend | undo
    Connector       NVARCHAR(64)    NOT NULL,
    ConnectorKind   NVARCHAR(32)    NULL,
    CollectionId    INT             NULL,           -- resend: sidata.Collection
    CollectionTime  DATETIME2(3)    NULL,
    TargetRunId     NVARCHAR(64)    NULL,           -- undo: the connector run it reverses
    Reason          NVARCHAR(1000)  NOT NULL,
    RequestedBy     NVARCHAR(256)   NOT NULL,
    RequestedUtc    DATETIME2(0)    NOT NULL CONSTRAINT DF_CollectionSend_RequestedUtc DEFAULT SYSUTCDATETIME(),
    CorrelationId   NVARCHAR(64)    NULL,
    State           NVARCHAR(16)    NOT NULL CONSTRAINT DF_CollectionSend_State DEFAULT N'requested',
    RunId           NVARCHAR(64)    NULL,           -- the connector run that carried it out
    StartedUtc      DATETIME2(0)    NULL,
    DoneUtc         DATETIME2(0)    NULL,
    OutcomeText     NVARCHAR(2000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CollectionSend_Connector' AND object_id = OBJECT_ID('cfg.CollectionSend'))
CREATE INDEX IX_CollectionSend_Connector ON cfg.CollectionSend (Connector, RequestedUtc DESC);

-- GUARD-1.6: a release is explicit and narrow -- one guard, one scope (the held set of one run), ONE run or until a time
-- (at most 24 hours), and the exact plan it releases. CurrentPlanHash is the held plan's SHA-256 as it is NOW (guard,
-- connector, run, count and the held items); a release stores the hash the SuperAdmin saw (PlanHash) and every apply path
-- checks the two are equal -- a changed plan needs a new release. ReleaseUntilUtc ends the release by itself.
IF COL_LENGTH('cfg.GuardRelease', 'ReleaseReason') IS NULL
ALTER TABLE cfg.GuardRelease ADD ReleaseReason NVARCHAR(1000) NULL;

IF COL_LENGTH('cfg.GuardRelease', 'PlanHash') IS NULL
ALTER TABLE cfg.GuardRelease ADD PlanHash CHAR(64) NULL;

IF COL_LENGTH('cfg.GuardRelease', 'ReleaseUntilUtc') IS NULL
ALTER TABLE cfg.GuardRelease ADD ReleaseUntilUtc DATETIME2(0) NULL;

IF COL_LENGTH('cfg.GuardRelease', 'ReleaseScope') IS NULL
ALTER TABLE cfg.GuardRelease ADD ReleaseScope NVARCHAR(16) NULL;

IF COL_LENGTH('cfg.GuardRelease', 'ReleaseCorrelationId') IS NULL
ALTER TABLE cfg.GuardRelease ADD ReleaseCorrelationId NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardRelease', 'ReleaseApprovedBy') IS NULL
ALTER TABLE cfg.GuardRelease ADD ReleaseApprovedBy NVARCHAR(256) NULL;

IF COL_LENGTH('cfg.GuardRelease', 'CurrentPlanHash') IS NULL
ALTER TABLE cfg.GuardRelease ADD CurrentPlanHash AS LOWER(CONVERT(CHAR(64), HASHBYTES('SHA2_256', CAST(CONCAT(GuardId, N'|', Connector, N'|', RunId, N'|', HeldCount, N'|', ItemsJson) AS VARBINARY(MAX))), 2));

-- =============================================================================================
-- #733 GUARDS HEAL THEMSELVES, SAY WHICH RELEASE THEY TRIPPED ON, AND THE OWNER CAN ACCEPT ONE AT EVERY INSTALL (owner
-- 2026-10-17; engine\_shared\SI-GuardHeal.ps1). Additive and safe to repeat; the engine writes every new column through a
-- statement guarded by COL_LENGTH, so an install the update has not reached yet keeps working exactly as before.
--   cfg.GuardEvent  SiVersion / PreviousVersion / Attribution: the version a trip happened on, the one before it, and the
--                   plain sentence ("the first run after the update to <v> (from <p>)"). A row with Outcome 'cleared' is a
--                   clear: "Back to normal in run <id> on version <v>", or the owner's acceptance.
--   cfg.GuardState  Version / PreviousVersion / FirstRunId / MarkerKind: an episode's version, or a version marker (key
--                   'ver|<guard key>': the version a check last ran on, the run that was the first on it); ClearedUtc /
--                   ClearedRunId / ClearedVersion / ClearedHow (passed | released | accepted): the episode is closed.
--   cfg.GuardAccept the owner's audited acceptance of one guard situation (guard id + version range, or one guard key),
--                   written ONLY by cfg.GuardAcceptSet (no direct table writes).
-- =============================================================================================
IF COL_LENGTH('cfg.GuardEvent', 'SiVersion') IS NULL
ALTER TABLE cfg.GuardEvent ADD SiVersion NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardEvent', 'PreviousVersion') IS NULL
ALTER TABLE cfg.GuardEvent ADD PreviousVersion NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardEvent', 'Attribution') IS NULL
ALTER TABLE cfg.GuardEvent ADD Attribution NVARCHAR(400) NULL;

IF COL_LENGTH('cfg.GuardState', 'Version') IS NULL
ALTER TABLE cfg.GuardState ADD [Version] NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardState', 'PreviousVersion') IS NULL
ALTER TABLE cfg.GuardState ADD PreviousVersion NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardState', 'FirstRunId') IS NULL
ALTER TABLE cfg.GuardState ADD FirstRunId NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardState', 'MarkerKind') IS NULL
ALTER TABLE cfg.GuardState ADD MarkerKind NVARCHAR(16) NULL;

IF COL_LENGTH('cfg.GuardState', 'ClearedRunId') IS NULL
ALTER TABLE cfg.GuardState ADD ClearedRunId NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardState', 'ClearedVersion') IS NULL
ALTER TABLE cfg.GuardState ADD ClearedVersion NVARCHAR(64) NULL;

IF COL_LENGTH('cfg.GuardState', 'ClearedHow') IS NULL
ALTER TABLE cfg.GuardState ADD ClearedHow NVARCHAR(16) NULL;

-- ClearedUtc last: the engine's guarded statement looks for it, so it appears only once every other column is there
IF COL_LENGTH('cfg.GuardState', 'ClearedUtc') IS NULL
ALTER TABLE cfg.GuardState ADD ClearedUtc DATETIME2(0) NULL;

IF OBJECT_ID('cfg.GuardAccept') IS NULL
CREATE TABLE cfg.GuardAccept (
    AcceptId        BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_GuardAccept PRIMARY KEY,
    GuardId         NVARCHAR(80)    NOT NULL,
    GuardKey        NVARCHAR(500)   NULL,
    FromVersion     NVARCHAR(64)    NULL,
    ToVersion       NVARCHAR(64)    NULL,
    CausedByVersion NVARCHAR(64)    NULL,
    Reason          NVARCHAR(1000)  NOT NULL,
    AcceptedBy      NVARCHAR(256)   NOT NULL,
    OwnerApproval   NVARCHAR(400)   NULL,
    Source          NVARCHAR(16)    NOT NULL,
    CorrelationId   NVARCHAR(64)    NULL,
    AcceptedUtc     DATETIME2(0)    NOT NULL CONSTRAINT DF_GuardAccept_AcceptedUtc DEFAULT SYSUTCDATETIME(),
    EventsCovered   INT             NOT NULL CONSTRAINT DF_GuardAccept_Events DEFAULT 0,
    EpisodesCleared INT             NOT NULL CONSTRAINT DF_GuardAccept_Episodes DEFAULT 0,
    SetsReleased    INT             NOT NULL CONSTRAINT DF_GuardAccept_Sets DEFAULT 0,
    RevokedUtc      DATETIME2(0)    NULL,
    CONSTRAINT CK_GuardAccept_Source CHECK (Source IN (N'support', N'mail', N'web'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_GuardAccept_Guard' AND object_id = OBJECT_ID('cfg.GuardAccept'))
CREATE INDEX IX_GuardAccept_Guard ON cfg.GuardAccept (GuardId) INCLUDE (GuardKey, FromVersion, ToVersion, AcceptedUtc, RevokedUtc);

-- A version as a sortable key: its numeric part ('3.0.0.2138', '3.0.0-rc.12+0dc9062' -> 3.0.0.0), four parts of ten digits.
-- NULL for no version, or more than four parts. The same rule as SI-GuardHeal.ps1 ConvertTo-SIGuardVersionParts.
EXEC (N'CREATE OR ALTER FUNCTION cfg.GuardVersionKey (@v NVARCHAR(64)) RETURNS NVARCHAR(64)
AS
BEGIN
    DECLARE @s NVARCHAR(64) = LTRIM(RTRIM(ISNULL(@v, N'''')));
    DECLARE @i INT = PATINDEX(N''%[^0-9.]%'', @s);
    IF @i > 0 SET @s = LEFT(@s, @i - 1);
    WHILE LEN(@s) > 0 AND RIGHT(@s, 1) = N''.'' SET @s = LEFT(@s, LEN(@s) - 1);
    IF LEN(@s) = 0 OR LEFT(@s, 1) = N''.'' OR CHARINDEX(N''..'', @s) > 0 RETURN NULL;
    DECLARE @n INT = LEN(@s) - LEN(REPLACE(@s, N''.'', N''''));
    IF @n > 3 RETURN NULL;
    WHILE @n < 3 BEGIN SET @s = @s + N''.0''; SET @n = @n + 1; END;
    RETURN RIGHT(REPLICATE(N''0'', 10) + PARSENAME(@s, 4), 10) + N''.'' + RIGHT(REPLICATE(N''0'', 10) + PARSENAME(@s, 3), 10) + N''.''
         + RIGHT(REPLICATE(N''0'', 10) + PARSENAME(@s, 2), 10) + N''.'' + RIGHT(REPLICATE(N''0'', 10) + PARSENAME(@s, 1), 10);
END');

-- THE OWNER'S ACCEPTANCE AT ONE INSTALL (setup\Invoke-SIGuardAcceptEverywhere.ps1 runs it at every install through the
-- Invardia Support app; Invardia's guard-mail link calls the same path). @PlanOnly = 1 changes nothing and answers what it
-- WOULD accept. Otherwise, in one transaction: the acceptance row (who, when, why, the owner's own words, the version that
-- caused it); every OPEN trip of the guard (and key) on a version inside the range acknowledged (cfg.GuardAck); every open
-- episode cleared (ClearedHow 'accepted', one cfg.GuardEvent row Outcome 'cleared' that the mail job reports to Invardia);
-- with @ReleaseHeld = 1 every held set of those trips released THROUGH THE RELEASE PATH'S OWN CHECKS (still held, not
-- expired, bound to the plan as it is now, for one run or 24 hours at most -- the connector re-checks completeness before
-- it applies anything); and one audit event 'guard.event.accept'. A range without an upper bound covers only what has
-- tripped so far. Only the owner (db_owner: the Support app through the admin group) or the web app may run it.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.GuardAcceptSet
    @GuardId NVARCHAR(80), @GuardKey NVARCHAR(500) = NULL, @FromVersion NVARCHAR(64) = NULL, @ToVersion NVARCHAR(64) = NULL,
    @CausedByVersion NVARCHAR(64) = NULL, @Reason NVARCHAR(1000) = NULL, @By NVARCHAR(256) = NULL, @OwnerApproval NVARCHAR(400) = NULL,
    @Source NVARCHAR(16) = N''support'', @CorrelationId NVARCHAR(64) = NULL, @ReleaseHeld BIT = 0, @PlanOnly BIT = 0,
    @ExpectedPlanHash CHAR(64) = NULL
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51471, N''only the owner (through the Invardia Support app) or the web app may accept a guard'', 1;
    IF @GuardId IS NULL OR @GuardId NOT LIKE N''_%._%._%'' THROW 51472, N''name the guard to accept (its id, area.object.what)'', 1;
    SET @GuardKey = NULLIF(LTRIM(RTRIM(@GuardKey)), N'''');
    SET @FromVersion = NULLIF(LTRIM(RTRIM(@FromVersion)), N''''); SET @ToVersion = NULLIF(LTRIM(RTRIM(@ToVersion)), N'''');
    DECLARE @fk NVARCHAR(64) = cfg.GuardVersionKey(@FromVersion), @tk NVARCHAR(64) = cfg.GuardVersionKey(@ToVersion);
    IF (@FromVersion IS NOT NULL AND @fk IS NULL) OR (@ToVersion IS NOT NULL AND @tk IS NULL) THROW 51473, N''a version must read like 3.0.0.2138'', 1;
    IF @Source NOT IN (N''support'', N''mail'', N''web'') THROW 51474, N''the source must be support, mail or web'', 1;
    IF @PlanOnly = 0
    BEGIN
        IF @Reason IS NULL OR LEN(LTRIM(RTRIM(@Reason))) < 10 THROW 51475, N''say why the guard is accepted (at least 10 characters)'', 1;
        IF @By IS NULL OR LTRIM(RTRIM(@By)) = N'''' THROW 51476, N''the acceptance must name who accepted it'', 1;
        IF @Source IN (N''support'', N''mail'') AND (@OwnerApproval IS NULL OR LEN(LTRIM(RTRIM(@OwnerApproval))) < 5)
            THROW 51477, N''an acceptance for every install needs the owner''''s approval in his own words'', 1;
    END;
    DECLARE @ev TABLE (Id BIGINT PRIMARY KEY, GuardKey NVARCHAR(500), DetailHash VARBINARY(32), RunId NVARCHAR(64), SiVersion NVARCHAR(64));
    INSERT @ev (Id, GuardKey, DetailHash, RunId, SiVersion)
    SELECT e.Id, e.GuardKey, HASHBYTES(''SHA2_256'', ISNULL(e.Detail, N'''')), e.RunId, e.SiVersion
    FROM cfg.GuardEvent AS e
    WHERE e.GuardId = @GuardId AND e.Outcome <> N''cleared'' AND (@GuardKey IS NULL OR e.GuardKey = @GuardKey)
      AND (@fk IS NULL OR cfg.GuardVersionKey(e.SiVersion) >= @fk) AND (@tk IS NULL OR cfg.GuardVersionKey(e.SiVersion) <= @tk)
      AND NOT EXISTS (SELECT 1 FROM cfg.GuardAck AS a WHERE a.EventId = e.Id OR (a.GuardKey = e.GuardKey AND a.DetailHash = HASHBYTES(''SHA2_256'', ISNULL(e.Detail, N''''))));
    DECLARE @ep TABLE (GuardKey NVARCHAR(500) PRIMARY KEY);
    INSERT @ep (GuardKey)
    SELECT s.GuardKey FROM cfg.GuardState AS s
    WHERE s.GuardId = @GuardId AND s.GuardKey NOT LIKE N''ver|%'' AND s.GuardKey NOT LIKE N''cause|%'' AND s.TripCount > 0
      AND (@GuardKey IS NULL OR s.GuardKey = @GuardKey) AND (s.ClearedUtc IS NULL OR s.ClearedUtc < s.LastSeenUtc)
      AND (@fk IS NULL OR cfg.GuardVersionKey(s.[Version]) >= @fk) AND (@tk IS NULL OR cfg.GuardVersionKey(s.[Version]) <= @tk);
    DECLARE @rs TABLE (ReleaseId BIGINT PRIMARY KEY);
    IF @ReleaseHeld = 1
        INSERT @rs (ReleaseId)
        SELECT r.ReleaseId FROM cfg.GuardRelease AS r
        WHERE r.GuardId = @GuardId AND r.State = N''held'' AND r.ExpiresUtc > SYSUTCDATETIME()
          AND EXISTS (SELECT 1 FROM @ev AS x WHERE x.RunId = r.RunId);
    DECLARE @nEv INT = (SELECT COUNT(*) FROM @ev), @nEp INT = (SELECT COUNT(*) FROM @ep), @nRs INT = (SELECT COUNT(*) FROM @rs);
    -- the plan as the person saw it: the trips, the episodes and each held set with its own plan hash; the accept refuses a
    -- plan that changed since (like a release: a changed plan needs a new look)
    DECLARE @plan NVARCHAR(MAX) = CONCAT(N''guard='', @GuardId, N''|key='', @GuardKey, N''|from='', @FromVersion, N''|to='', @ToVersion, N''|release='', @ReleaseHeld,
        N''|ev='', ISNULL((SELECT CONCAT(x.Id, N'';'') FROM @ev AS x ORDER BY x.Id FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), N''''),
        N''|ep='', ISNULL((SELECT CONCAT(p.GuardKey, N'';'') FROM @ep AS p ORDER BY p.GuardKey FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), N''''),
        N''|rs='', ISNULL((SELECT CONCAT(r.ReleaseId, N'':'', r.CurrentPlanHash, N'';'') FROM @rs AS x JOIN cfg.GuardRelease AS r ON r.ReleaseId = x.ReleaseId ORDER BY r.ReleaseId FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), N''''));
    DECLARE @planHash CHAR(64) = LOWER(CONVERT(CHAR(64), HASHBYTES(''SHA2_256'', CAST(@plan AS VARBINARY(MAX))), 2));
    DECLARE @keys NVARCHAR(2000) = LEFT(ISNULL(STUFF((SELECT N''; '' + k.GuardKey FROM (SELECT GuardKey FROM @ev UNION SELECT GuardKey FROM @ep) AS k ORDER BY k.GuardKey FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), 1, 2, N''''), N''''), 2000);
    DECLARE @vers NVARCHAR(1000) = LEFT(ISNULL(STUFF((SELECT DISTINCT N''; '' + ISNULL(x.SiVersion, N''(not recorded)'') FROM @ev AS x FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), 1, 2, N''''), N''''), 1000);
    IF @PlanOnly = 1
    BEGIN
        SELECT N''Plan'' AS Outcome, CAST(NULL AS BIGINT) AS AcceptId, @nEv AS EventsCovered, @nEp AS EpisodesCleared, @nRs AS SetsReleased, @keys AS GuardKeys, @vers AS Versions, @planHash AS PlanHash;
        RETURN;
    END;
    -- ONCE: the same acceptance (guard, key, range, the owner''s words) made in the last 60 minutes is answered, never made twice
    DECLARE @prev BIGINT = (SELECT TOP (1) a.AcceptId FROM cfg.GuardAccept AS a
        WHERE a.GuardId = @GuardId AND ISNULL(a.GuardKey, N'''') = ISNULL(@GuardKey, N'''') AND ISNULL(a.FromVersion, N'''') = ISNULL(@FromVersion, N'''')
          AND ISNULL(a.ToVersion, N'''') = ISNULL(@ToVersion, N'''') AND ISNULL(a.OwnerApproval, N'''') = ISNULL(LEFT(@OwnerApproval, 400), N'''')
          AND a.RevokedUtc IS NULL AND a.AcceptedUtc >= DATEADD(MINUTE, -60, SYSUTCDATETIME()) ORDER BY a.AcceptId DESC);
    IF @prev IS NOT NULL
    BEGIN
        SELECT N''Already'' AS Outcome, a.AcceptId, a.EventsCovered, a.EpisodesCleared, a.SetsReleased, @keys AS GuardKeys, @vers AS Versions, @planHash AS PlanHash FROM cfg.GuardAccept AS a WHERE a.AcceptId = @prev;
        RETURN;
    END;
    IF @ReleaseHeld = 1 AND @ExpectedPlanHash IS NULL THROW 51478, N''releasing held sets needs the plan it was shown (@ExpectedPlanHash from @PlanOnly = 1)'', 1;
    IF @ExpectedPlanHash IS NOT NULL AND LOWER(@ExpectedPlanHash) <> @planHash THROW 51479, N''the plan changed since it was shown -- plan again, look, and accept again'', 1;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME(), @aid BIGINT;
    BEGIN TRAN;
    INSERT cfg.GuardAccept (GuardId, GuardKey, FromVersion, ToVersion, CausedByVersion, Reason, AcceptedBy, OwnerApproval, Source, CorrelationId, AcceptedUtc)
    VALUES (@GuardId, @GuardKey, @FromVersion, @ToVersion, NULLIF(LTRIM(RTRIM(@CausedByVersion)), N''''), LEFT(@Reason, 1000), LEFT(@By, 256), LEFT(@OwnerApproval, 400), @Source, @CorrelationId, @now);
    SET @aid = CAST(SCOPE_IDENTITY() AS BIGINT);
    INSERT cfg.GuardAck (EventId, GuardKey, DetailHash, AckBy, Note)
    SELECT x.Id, x.GuardKey, x.DetailHash, LEFT(@By + N'' (accepted)'', 256), LEFT(N''Accepted: '' + @Reason, 1000) FROM @ev AS x;
    INSERT cfg.GuardEvent (GuardId, GuardKey, Area, Job, Engine, Source, Outcome, Severity, Protected, Subject, Detail, MeasuredText, ValuesJson,
                           HeldCount, ActionText, Link, RunId, TripCount, FirstSeenUtc, MailState, MailTo, TelemetryState, SiVersion, Attribution)
    SELECT @GuardId, p.GuardKey, l.Area, l.Job, l.Engine, CASE WHEN @Source = N''web'' THEN N''web'' ELSE N''setup'' END, N''cleared'', N''info'', l.Protected, l.Subject,
           LEFT(N''Accepted by '' + @By + N'': '' + @Reason, 2000), NULL, NULL, 0, NULL, NULL, @CorrelationId, s.TripCount, s.FirstSeenUtc, N''off'', NULL, N''pending'',
           l.SiVersion, LEFT(N''Accepted for '' + CASE WHEN @FromVersion IS NULL AND @ToVersion IS NULL THEN N''every version so far'' ELSE N''versions '' + ISNULL(@FromVersion, N''(any)'') + N'' to '' + ISNULL(@ToVersion, N''(any)'') END
                + ISNULL(N''; caused by '' + NULLIF(LTRIM(RTRIM(@CausedByVersion)), N''''), N''''), 400)
    FROM @ep AS p
    JOIN cfg.GuardState AS s ON s.GuardKey = p.GuardKey
    CROSS APPLY (SELECT TOP (1) e.Area, e.Job, e.Engine, e.Protected, e.Subject, e.SiVersion FROM cfg.GuardEvent AS e WHERE e.GuardKey = p.GuardKey AND e.Outcome <> N''cleared'' ORDER BY e.Id DESC) AS l;
    UPDATE s SET ClearedUtc = @now, ClearedRunId = @CorrelationId, ClearedVersion = NULL, ClearedHow = N''accepted''
    FROM cfg.GuardState AS s JOIN @ep AS p ON p.GuardKey = s.GuardKey;
    UPDATE r SET State = N''released'', ReleasedBy = LEFT(@By, 256), ReleasedUtc = @now, ReleaseReason = LEFT(N''accepted at every install: '' + @Reason, 1000), PlanHash = r.CurrentPlanHash,
                 ReleaseUntilUtc = CASE WHEN r.ExpiresUtc < DATEADD(HOUR, 24, @now) THEN r.ExpiresUtc ELSE DATEADD(HOUR, 24, @now) END, ReleaseScope = N''run'',
                 ReleaseCorrelationId = @CorrelationId, ReleaseApprovedBy = LEFT(N''the owner: '' + ISNULL(@OwnerApproval, N''''), 256)
    FROM cfg.GuardRelease AS r JOIN @rs AS x ON x.ReleaseId = r.ReleaseId
    WHERE r.State = N''held'' AND r.ExpiresUtc > SYSUTCDATETIME();
    SET @nRs = @@ROWCOUNT;
    UPDATE cfg.GuardAccept SET EventsCovered = @nEv, EpisodesCleared = @nEp, SetsReleased = @nRs WHERE AcceptId = @aid;
    INSERT cfg.AuditEvent (RecordType, Action, Actor, ActorSource, Target, Reason, Outcome, OutcomeText, BeforeJson, AfterJson, CorrelationId, WhatIf)
    VALUES (N''event'', N''guard.event.accept'', LEFT(@By, 256), CASE WHEN @Source = N''web'' THEN N''web'' ELSE N''setup'' END,
            LEFT(@GuardId + ISNULL(N'' ('' + @GuardKey + N'')'', N''''), 400), LEFT(@Reason, 400), N''ok'',
            LEFT(CONCAT(@nEv, N'' trip(s) acknowledged, '', @nEp, N'' episode(s) cleared, '', @nRs, N'' held set(s) released for one run''), 1000), NULL,
            CONCAT(N''{"guard":"'', STRING_ESCAPE(@GuardId, ''json''), N''","key":'', CASE WHEN @GuardKey IS NULL THEN N''null'' ELSE N''"'' + STRING_ESCAPE(@GuardKey, ''json'') + N''"'' END,
                   N'',"from":'', CASE WHEN @FromVersion IS NULL THEN N''null'' ELSE N''"'' + STRING_ESCAPE(@FromVersion, ''json'') + N''"'' END,
                   N'',"to":'', CASE WHEN @ToVersion IS NULL THEN N''null'' ELSE N''"'' + STRING_ESCAPE(@ToVersion, ''json'') + N''"'' END,
                   N'',"causedBy":'', CASE WHEN NULLIF(LTRIM(RTRIM(@CausedByVersion)), N'''') IS NULL THEN N''null'' ELSE N''"'' + STRING_ESCAPE(LTRIM(RTRIM(@CausedByVersion)), ''json'') + N''"'' END,
                   N'',"source":"'', @Source, N''","acceptId":'', @aid, N'',"events":'', @nEv, N'',"episodes":'', @nEp, N'',"sets":'', @nRs,
                   N'',"ownerApproval":"'', STRING_ESCAPE(ISNULL(@OwnerApproval, N''''), ''json''), N''"}''),
            @CorrelationId, 0);
    COMMIT;
    SELECT N''Accepted'' AS Outcome, @aid AS AcceptId, @nEv AS EventsCovered, @nEp AS EpisodesCleared, @nRs AS SetsReleased, @keys AS GuardKeys, @vers AS Versions, @planHash AS PlanHash;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.GuardAcceptSet TO public;

-- =============================================================================================
-- THE VERIFICATION SERVICE (docs\V3-DATA-MODEL.md 2.11): settings and plans SecurityInsight's data depends on that are
-- NOT enabled in the customer's Microsoft estate (engine\verification\, the checks in config\verification-checks.locked.json).
-- The engine writes runs, check results and findings; only the web app writes decisions. A finding is keyed
-- '<checkId>|<scope key>' and is RESOLVED only by a run in which its check ran -- a check that could not read its source
-- is 'not-checked' and touches no finding.
IF OBJECT_ID('cfg.VerificationRun') IS NULL
CREATE TABLE cfg.VerificationRun (
    RunId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_VerificationRun PRIMARY KEY,
    StartedAt      DATETIME2(0)    NOT NULL CONSTRAINT DF_VerificationRun_StartedAt DEFAULT SYSUTCDATETIME(),
    FinishedAt     DATETIME2(0)    NULL,
    Outcome        NVARCHAR(24)    NULL,
    CatalogVersion NVARCHAR(16)    NULL,
    SummaryJson    NVARCHAR(MAX)   NULL
);

IF OBJECT_ID('cfg.VerificationCheckRun') IS NULL
CREATE TABLE cfg.VerificationCheckRun (
    RunId          BIGINT          NOT NULL,
    CheckId        NVARCHAR(64)    NOT NULL,
    State          NVARCHAR(16)    NOT NULL CONSTRAINT CK_VerificationCheckRun_State CHECK (State IN (N'ok', N'gaps', N'not-checked')),
    Reason         NVARCHAR(1000)  NULL,
    Findings       INT             NOT NULL CONSTRAINT DF_VerificationCheckRun_Findings DEFAULT 0,
    CONSTRAINT PK_VerificationCheckRun PRIMARY KEY (RunId, CheckId)
);

IF OBJECT_ID('cfg.VerificationFinding') IS NULL
CREATE TABLE cfg.VerificationFinding (
    FindingKey     NVARCHAR(450)   NOT NULL CONSTRAINT PK_VerificationFinding PRIMARY KEY,
    CheckId        NVARCHAR(64)    NOT NULL,
    ScopeKind      NVARCHAR(16)    NOT NULL,
    ScopeKey       NVARCHAR(400)   NOT NULL,
    ScopeName      NVARCHAR(400)   NULL,
    Severity       NVARCHAR(16)    NOT NULL,
    Detail         NVARCHAR(2000)  NULL,
    [Status]       NVARCHAR(16)    NOT NULL CONSTRAINT CK_VerificationFinding_Status CHECK ([Status] IN (N'open', N'resolved')),
    FirstSeenAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_VerificationFinding_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_VerificationFinding_LastSeenAt DEFAULT SYSUTCDATETIME(),
    ResolvedAt     DATETIME2(0)    NULL,
    LastRunId      BIGINT          NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VerificationFinding_Check' AND object_id = OBJECT_ID('cfg.VerificationFinding'))
CREATE INDEX IX_VerificationFinding_Check ON cfg.VerificationFinding (CheckId, [Status]);

IF OBJECT_ID('cfg.VerificationFindingEvent') IS NULL
CREATE TABLE cfg.VerificationFindingEvent (
    EventId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_VerificationFindingEvent PRIMARY KEY,
    FindingKey     NVARCHAR(450)   NOT NULL,
    RunId          BIGINT          NOT NULL,
    [Event]        NVARCHAR(16)    NOT NULL CONSTRAINT CK_VerificationFindingEvent_Event CHECK ([Event] IN (N'opened', N'reopened', N'resolved')),
    At             DATETIME2(0)    NOT NULL CONSTRAINT DF_VerificationFindingEvent_At DEFAULT SYSUTCDATETIME(),
    Detail         NVARCHAR(2000)  NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VerificationFindingEvent_Key' AND object_id = OBJECT_ID('cfg.VerificationFindingEvent'))
CREATE INDEX IX_VerificationFindingEvent_Key ON cfg.VerificationFindingEvent (FindingKey, At);

-- A decision on a finding: IGNORED (not a gap for this organisation, e.g. no other cloud) or ACCEPTED (a known gap whose
-- risk is accepted for now), with who, when, why and the reviewer; due for review at ReviewDueAt (180 days). Append-only:
-- a review or a change is a NEW row that replaces the old one (the old one gets RevokedAt / RevokedBy), so the history of
-- every decision stays. Why not cfg.Exemption: an exemption hides a FINDING of a report from its scores; this is a gap
-- in the data itself, keyed by the check, with its own review -- and cfg.Exemption's Scope CHECK has no place for it.
IF OBJECT_ID('cfg.VerificationDecision') IS NULL
CREATE TABLE cfg.VerificationDecision (
    DecisionId     BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_VerificationDecision PRIMARY KEY,
    FindingKey     NVARCHAR(450)   NOT NULL,
    CheckId        NVARCHAR(64)    NOT NULL,
    Decision       NVARCHAR(16)    NOT NULL CONSTRAINT CK_VerificationDecision_Decision CHECK (Decision IN (N'ignored', N'accepted')),
    Reason         NVARCHAR(2000)  NOT NULL CONSTRAINT CK_VerificationDecision_Reason CHECK (LEN(Reason) >= 3),
    [Owner]        NVARCHAR(256)   NULL,
    DecidedBy      NVARCHAR(256)   NOT NULL,
    DecidedAt      DATETIME2(0)    NOT NULL CONSTRAINT DF_VerificationDecision_DecidedAt DEFAULT SYSUTCDATETIME(),
    ReviewDueAt    DATETIME2(0)    NOT NULL,
    ReplacesDecisionId BIGINT      NULL,
    RevokedAt      DATETIME2(0)    NULL,
    RevokedBy      NVARCHAR(256)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VerificationDecision_Key' AND object_id = OBJECT_ID('cfg.VerificationDecision'))
CREATE INDEX IX_VerificationDecision_Key ON cfg.VerificationDecision (FindingKey, RevokedAt);

-- =============================================================================================
-- THE DATA HEALTH MODEL (CR2, REQUIREMENTS #656 -- SecurityInsight only): every day the engine checks its own data
-- (engine\data-health\, read-only toward the sources) -- per source a random 10 % of the records looked up in the newest
-- collection, and a random 10 % of the devices with vulnerability findings re-asked from Defender -- and keeps the
-- install's state: Healthy | Unhealthy (three anomalous cycles in a row -> Unhealthy, one good cycle -> Healthy).
-- While Unhealthy every data-out channel plans only; a SuperAdmin may let ONE channel through, with a reason, until the
-- data is Healthy again (cfg.DataHealthOverride, written by the web app ONLY through cfg.DataHealthOverrideSet; the
-- engine clears every open override when the data is Healthy again). An install without these tables holds nothing.
IF OBJECT_ID('cfg.DataHealthCycle') IS NULL
CREATE TABLE cfg.DataHealthCycle (
    CycleId              BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DataHealthCycle PRIMARY KEY,
    StartedAt            DATETIME2(0)    NOT NULL CONSTRAINT DF_DataHealthCycle_StartedAt DEFAULT SYSUTCDATETIME(),
    FinishedAt           DATETIME2(0)    NULL,
    Anomalous            BIT             NULL,
    Complete             BIT             NULL,
    [State]              NVARCHAR(16)    NULL,       -- the install's state AFTER this cycle
    StateChanged         BIT             NULL,
    ConsecutiveAnomalous INT             NULL,
    SummaryJson          NVARCHAR(MAX)   NULL
);

IF OBJECT_ID('cfg.DataHealthResult') IS NULL
CREATE TABLE cfg.DataHealthResult (
    CycleId          BIGINT          NOT NULL,
    Kind             NVARCHAR(16)    NOT NULL CONSTRAINT CK_DataHealthResult_Kind CHECK (Kind IN (N'source', N'report')),
    Name             NVARCHAR(256)   NOT NULL,       -- the source id, or the Risk Analysis report
    Label            NVARCHAR(256)   NULL,
    Sampled          BIGINT          NOT NULL CONSTRAINT DF_DataHealthResult_Sampled DEFAULT 0,
    Found            BIGINT          NOT NULL CONSTRAINT DF_DataHealthResult_Found DEFAULT 0,     -- a report: matched
    Missing          BIGINT          NOT NULL CONSTRAINT DF_DataHealthResult_Missing DEFAULT 0,
    FieldMismatches  BIGINT          NOT NULL CONSTRAINT DF_DataHealthResult_FieldMismatches DEFAULT 0,  -- a report: extra (no longer in Defender)
    MarginPercent    FLOAT           NULL,
    MarginMinimum    INT             NULL,
    Allowed          BIGINT          NULL,
    Verdict          NVARCHAR(16)    NOT NULL CONSTRAINT CK_DataHealthResult_Verdict CHECK (Verdict IN (N'ok', N'anomalous', N'not-checked', N'not-used')),
    Reason           NVARCHAR(1000)  NULL,
    CONSTRAINT PK_DataHealthResult PRIMARY KEY (CycleId, Kind, Name)
);

-- #747: DRIFT -- the part of Missing + FieldMismatches (a report: missing + extra) explained by a change in the source
-- AFTER the collection (a CVE fixed or published since, a field the source changed since). Said and stored, never counted
-- against the margin. A subset of those columns; they keep their meaning.
IF COL_LENGTH('cfg.DataHealthResult', 'Drift') IS NULL
ALTER TABLE cfg.DataHealthResult ADD Drift BIGINT NOT NULL CONSTRAINT DF_DataHealthResult_Drift DEFAULT 0;

-- the records of a cycle that did not match: for the install's own Data health page; never sent anywhere
IF OBJECT_ID('cfg.DataHealthMissing') IS NULL
CREATE TABLE cfg.DataHealthMissing (
    MissingId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DataHealthMissing PRIMARY KEY,
    CycleId          BIGINT          NOT NULL,
    Kind             NVARCHAR(16)    NOT NULL,
    Name             NVARCHAR(256)   NOT NULL,
    RecordKey        NVARCHAR(450)   NULL,
    RecordName       NVARCHAR(400)   NULL,
    Problem          NVARCHAR(400)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DataHealthMissing_Cycle' AND object_id = OBJECT_ID('cfg.DataHealthMissing'))
CREATE INDEX IX_DataHealthMissing_Cycle ON cfg.DataHealthMissing (CycleId, Kind, Name);

IF OBJECT_ID('cfg.DataHealthState') IS NULL
CREATE TABLE cfg.DataHealthState (
    Id                   INT             NOT NULL CONSTRAINT PK_DataHealthState PRIMARY KEY CONSTRAINT CK_DataHealthState_One CHECK (Id = 1),
    [State]              NVARCHAR(16)    NOT NULL CONSTRAINT CK_DataHealthState_State CHECK ([State] IN (N'Healthy', N'Unhealthy')),
    Since                DATETIME2(0)    NOT NULL,
    ConsecutiveAnomalous INT             NOT NULL CONSTRAINT DF_DataHealthState_Consecutive DEFAULT 0,
    LastCycleId          BIGINT          NULL,
    LastCycleAt          DATETIME2(0)    NULL
);

IF OBJECT_ID('cfg.DataHealthOverride') IS NULL
CREATE TABLE cfg.DataHealthOverride (
    OverrideId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_DataHealthOverride PRIMARY KEY,
    Channel          NVARCHAR(64)    NOT NULL,       -- the data-out channel (a connector name)
    SetBy            NVARCHAR(256)   NOT NULL,
    SetByRole        NVARCHAR(32)    NOT NULL CONSTRAINT DF_DataHealthOverride_Role DEFAULT N'SuperAdmin',
    Reason           NVARCHAR(1000)  NOT NULL CONSTRAINT CK_DataHealthOverride_Reason CHECK (LEN(Reason) >= 10),
    SinceUtc         DATETIME2(0)    NOT NULL CONSTRAINT DF_DataHealthOverride_Since DEFAULT SYSUTCDATETIME(),
    ClearedAt        DATETIME2(0)    NULL,
    ClearedBy        NVARCHAR(256)   NULL,
    ClearedReason    NVARCHAR(400)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DataHealthOverride_Open' AND object_id = OBJECT_ID('cfg.DataHealthOverride'))
CREATE INDEX IX_DataHealthOverride_Open ON cfg.DataHealthOverride (ClearedAt, Channel);

-- A SuperAdmin lets ONE data-out channel through while the data is Unhealthy (@Clear = 1: takes the override back). The web
-- app checks the role; the procedure checks the rest: the data is Unhealthy, a reason of at least 10 characters, one open
-- override per channel. The web app holds no write right on the table.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.DataHealthOverrideSet @Channel NVARCHAR(64), @Reason NVARCHAR(1000), @By NVARCHAR(256), @Role NVARCHAR(32) = N''SuperAdmin'', @Clear BIT = 0
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_audit_writer''), 0) <> 1
        THROW 51451, N''only the web app may let a data-out channel through'', 1;
    IF @By IS NULL OR LTRIM(RTRIM(@By)) = N'''' THROW 51452, N''the override must name who made it'', 1;
    IF @Channel IS NULL OR LTRIM(RTRIM(@Channel)) = N'''' THROW 51453, N''the override must name the channel'', 1;
    BEGIN TRAN;
    IF @Clear = 1
    BEGIN
        UPDATE cfg.DataHealthOverride SET ClearedAt = SYSUTCDATETIME(), ClearedBy = LEFT(@By, 256), ClearedReason = LEFT(ISNULL(@Reason, N''taken back''), 400)
        WHERE ClearedAt IS NULL AND Channel = @Channel;
        COMMIT;
        SELECT N''Cleared'' AS Outcome, SYSUTCDATETIME() AS At;
        RETURN;
    END
    IF @Reason IS NULL OR LEN(LTRIM(RTRIM(@Reason))) < 10 THROW 51454, N''the override needs a reason of at least 10 characters'', 1;
    IF (SELECT COUNT(*) FROM cfg.DataHealthState WITH (UPDLOCK, HOLDLOCK) WHERE Id = 1 AND [State] = N''Unhealthy'') = 0
        THROW 51455, N''the data is not Unhealthy -- nothing is held, so there is nothing to let through'', 1;
    IF EXISTS (SELECT 1 FROM cfg.DataHealthOverride WITH (UPDLOCK, HOLDLOCK) WHERE ClearedAt IS NULL AND Channel = @Channel)
        THROW 51456, N''this channel is already let through'', 1;
    INSERT cfg.DataHealthOverride (Channel, SetBy, SetByRole, Reason) VALUES (LTRIM(RTRIM(@Channel)), LEFT(@By, 256), LEFT(ISNULL(@Role, N''SuperAdmin''), 32), @Reason);
    COMMIT;
    SELECT N''Set'' AS Outcome, SYSUTCDATETIME() AS At;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.DataHealthOverrideSet TO public;

-- THE SECRET HAND-OVER: the web app never writes a secret (owner 2026-10-10: "can we commit this to the engine and then
-- the engine commits it, so the gui keeps read only"). The updater keeps an RSA key in the install's Key Vault (a KEY,
-- never exportable: it decrypts only inside the vault) and publishes its PUBLIC half here. The web app encrypts a pasted
-- secret in memory (an AES-256-GCM data key, wrapped with RSA-OAEP-256 by that public key) and leaves ONLY the ciphertext
-- in cfg.PendingSecret; the updater decrypts the data key in the vault, writes the secret, points the setting at the
-- secret's NAME and removes the row. A row it cannot store keeps a plain-language reason (FailureText) until it is stored
-- or replaced. Neither table ever holds a secret in clear text; neither is configuration (never backed up or restored).
IF OBJECT_ID('cfg.SecretHandoverKey') IS NULL
CREATE TABLE cfg.SecretHandoverKey (
    KeyVersion   NVARCHAR(64)    NOT NULL CONSTRAINT PK_SecretHandoverKey PRIMARY KEY,   -- the Key Vault key's version
    KeyName      NVARCHAR(127)   NOT NULL,
    PublicJwk    NVARCHAR(4000)  NOT NULL,   -- the PUBLIC half only: {"kty":"RSA","n":"...","e":"..."}
    IsCurrent    BIT             NOT NULL CONSTRAINT DF_SecretHandoverKey_IsCurrent DEFAULT 1,
    PublishedAt  DATETIME2(0)    NOT NULL CONSTRAINT DF_SecretHandoverKey_PublishedAt DEFAULT SYSUTCDATETIME(),
    PublishedBy  NVARCHAR(256)   NOT NULL,
    CONSTRAINT CK_SecretHandoverKey_Jwk CHECK (ISJSON(PublicJwk) = 1)
);

IF OBJECT_ID('cfg.PendingSecret') IS NULL
CREATE TABLE cfg.PendingSecret (
    PendingId     BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_PendingSecret PRIMARY KEY,
    SettingName   NVARCHAR(128)   NOT NULL,   -- the setting that will name the secret (e.g. OpenAI_apiKey)
    SecretName    NVARCHAR(127)   NOT NULL,   -- the Key Vault secret the updater writes
    KeyVersion    NVARCHAR(64)    NOT NULL,   -- the hand-over key version that wrapped the data key
    WrappedKey    NVARCHAR(1024)  NOT NULL,   -- base64url: RSA-OAEP-256 of the 32-byte data key
    Nonce         NVARCHAR(32)    NOT NULL,   -- base64url: the 12-byte AES-GCM nonce
    Tag           NVARCHAR(32)    NOT NULL,   -- base64url: the 16-byte AES-GCM tag
    Ciphertext    NVARCHAR(MAX)   NOT NULL,   -- base64url: AES-256-GCM of the secret (UTF-8)
    CreatedBy     NVARCHAR(256)   NOT NULL,
    CreatedAt     DATETIME2(0)    NOT NULL CONSTRAINT DF_PendingSecret_CreatedAt DEFAULT SYSUTCDATETIME(),
    Attempts      INT             NOT NULL CONSTRAINT DF_PendingSecret_Attempts DEFAULT 0,
    LastAttemptAt DATETIME2(0)    NULL,
    FailureText   NVARCHAR(400)   NULL        -- why the updater could not store it, in plain words; NULL = waiting
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PendingSecret_Setting' AND object_id = OBJECT_ID('cfg.PendingSecret'))
CREATE INDEX IX_PendingSecret_Setting ON cfg.PendingSecret (SettingName, CreatedAt DESC);

-- =============================================================================================
-- THE SERVICENOW CHECKS (owner 2026-10-20: "verify connection. verify table schema matches + get alerts"). One row per check
-- of one ServiceNow output (the CI hand-off, the vulnerable items): the connection, the Import Set table, its columns as
-- ServiceNow describes them (sys_dictionary) and the REST Insert Multiple column mapping -- written by the ENGINE identity
-- (the output's run before it sends, the daily check in the verification job, and the "Verify" the web app starts on the
-- mail job: the web app holds no Key Vault right, so it never signs in to ServiceNow itself). The web app reads the newest
-- row per output and compares the columns with the ones in force. No secret is ever stored here: no key, no user, no password.
--   Trigger    run | daily | verify
--   Outcome    ok | warning | failed
IF OBJECT_ID('cfg.ServiceNowCheck') IS NULL
CREATE TABLE cfg.ServiceNowCheck (
    CheckId      BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ServiceNowCheck PRIMARY KEY,
    [Output]     NVARCHAR(64)    NOT NULL,
    Connector    NVARCHAR(64)    NULL,
    TableName    NVARCHAR(128)   NULL,
    [Trigger]    NVARCHAR(16)    NOT NULL,
    RequestedBy  NVARCHAR(256)   NULL,
    CheckedAt    DATETIME2(0)    NOT NULL CONSTRAINT DF_ServiceNowCheck_CheckedAt DEFAULT SYSUTCDATETIME(),
    Outcome      NVARCHAR(16)    NOT NULL,
    Summary      NVARCHAR(1000)  NULL,
    ResultJson   NVARCHAR(MAX)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ServiceNowCheck_Output' AND object_id = OBJECT_ID('cfg.ServiceNowCheck'))
CREATE INDEX IX_ServiceNowCheck_Output ON cfg.ServiceNowCheck ([Output], CheckId DESC) INCLUDE (CheckedAt, Outcome);

-- =============================================================================================
-- #757 THE PERFORMANCE PAGE'S SAMPLES (owner 2026-10-18: "add performance and stats in si gui so customer can see it. new
-- page" / "so they can choose to scale up down"). The web app holds NO Azure right (CR8): the load of the databases and the
-- web app over the last days, and the sizes the install runs, are read by the half-hourly heartbeat job with the engine
-- identity (the same Azure Monitor metrics it and the write pacing already read) and kept here, one row per hour per
-- metric. Operations > Performance reads them; nothing else does.
--   Kind     database | webapp | job
--   Name     the database's role (pro, data, identity), the web app's name, a job's name
--   Metric   the Azure Monitor metric as Azure names it (cpu_percent, log_write_percent, physical_data_read_percent,
--            dtu_consumption_percent, storage, UsageNanoCores, WorkingSetBytes) -- or a size the install runs:
--            size.sku (Text = S3 / P1 / GP_Gen5_2; Avg = its DTU or vCores), size.maxBytes, size.cpu, size.memoryGi
--   Avg/Max  the hour's average and highest value; Text only for size.sku
-- Kept 30 days (sizes 2 days); written and pruned ONLY through cfg.PerfSampleSave (a job identity or the owner).
-- =============================================================================================
IF OBJECT_ID('cfg.PerfSample') IS NULL
CREATE TABLE cfg.PerfSample (
    TimeUtc   DATETIME2(0)    NOT NULL,
    Kind      NVARCHAR(16)    NOT NULL CONSTRAINT CK_PerfSample_Kind CHECK (Kind IN (N'database', N'webapp', N'job')),
    Name      NVARCHAR(128)   NOT NULL,
    Metric    NVARCHAR(64)    NOT NULL,
    [Avg]     FLOAT           NULL,
    [Max]     FLOAT           NULL,
    [Text]    NVARCHAR(64)    NULL,
    CONSTRAINT PK_PerfSample PRIMARY KEY (Kind, Name, Metric, TimeUtc)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PerfSample_Time' AND object_id = OBJECT_ID('cfg.PerfSample'))
CREATE INDEX IX_PerfSample_Time ON cfg.PerfSample (TimeUtc) INCLUDE (Kind, Name, Metric);

-- One call per heartbeat tick that read anything: @Rows = a JSON array of { t, kind, name, metric, avg, max, text }. An hour
-- already stored is replaced (a re-read hour is the same hour), a new one added; then rows older than 30 days (a size: 2
-- days) go. Idempotent: the same call twice leaves the same rows. Runs only for a job identity (db_datawriter / si_engine)
-- or the owner; the web app only reads the table.
EXEC (N'CREATE OR ALTER PROCEDURE cfg.PerfSampleSave @Rows NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_datawriter''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''si_engine''), 0) <> 1 AND ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) <> 1
        THROW 51490, N''only a job identity may record the performance samples -- nothing was written'', 1;
    DECLARE @r TABLE (TimeUtc DATETIME2(0) NOT NULL, Kind NVARCHAR(16) NOT NULL, Name NVARCHAR(128) NOT NULL, Metric NVARCHAR(64) NOT NULL,
                      [Avg] FLOAT NULL, [Max] FLOAT NULL, [Text] NVARCHAR(64) NULL, PRIMARY KEY (Kind, Name, Metric, TimeUtc));
    IF @Rows IS NOT NULL AND ISJSON(@Rows) = 1
        INSERT @r (TimeUtc, Kind, Name, Metric, [Avg], [Max], [Text])
        SELECT x.TimeUtc, x.Kind, x.Name, x.Metric, MAX(x.[Avg]), MAX(x.[Max]), MAX(x.[Text])
        FROM OPENJSON(@Rows) WITH (TimeUtc DATETIME2(0) ''$.t'', Kind NVARCHAR(16) ''$.kind'', Name NVARCHAR(128) ''$.name'', Metric NVARCHAR(64) ''$.metric'',
                                   [Avg] FLOAT ''$.avg'', [Max] FLOAT ''$.max'', [Text] NVARCHAR(64) ''$.text'') AS x
        WHERE x.TimeUtc IS NOT NULL AND x.Kind IN (N''database'', N''webapp'', N''job'') AND LEN(x.Name) > 0 AND LEN(x.Metric) > 0
        GROUP BY x.TimeUtc, x.Kind, x.Name, x.Metric;
    BEGIN TRAN;
    UPDATE p SET p.[Avg] = r.[Avg], p.[Max] = r.[Max], p.[Text] = r.[Text]
    FROM cfg.PerfSample AS p WITH (UPDLOCK, HOLDLOCK) JOIN @r AS r ON r.Kind = p.Kind AND r.Name = p.Name AND r.Metric = p.Metric AND r.TimeUtc = p.TimeUtc;
    DECLARE @updated INT = @@ROWCOUNT;
    INSERT cfg.PerfSample (TimeUtc, Kind, Name, Metric, [Avg], [Max], [Text])
    SELECT r.TimeUtc, r.Kind, r.Name, r.Metric, r.[Avg], r.[Max], r.[Text] FROM @r AS r
    WHERE NOT EXISTS (SELECT 1 FROM cfg.PerfSample AS p WHERE p.Kind = r.Kind AND p.Name = r.Name AND p.Metric = r.Metric AND p.TimeUtc = r.TimeUtc);
    DECLARE @added INT = @@ROWCOUNT;
    DELETE FROM cfg.PerfSample WHERE TimeUtc < DATEADD(day, -30, SYSUTCDATETIME()) OR (Metric LIKE N''size.%'' AND TimeUtc < DATEADD(day, -2, SYSUTCDATETIME()));
    DECLARE @pruned INT = @@ROWCOUNT;
    COMMIT;
    SELECT @added AS Added, @updated AS Updated, @pruned AS Pruned;
END');

IF IS_ROLEMEMBER(N'db_owner') = 1 OR IS_ROLEMEMBER(N'db_securityadmin') = 1
GRANT EXECUTE ON OBJECT::cfg.PerfSampleSave TO public;

-- =============================================================================================
-- #640 BUCKET SIZING -- THE CORE OF RISK ANALYSIS. How many buckets (slices) each Risk Analysis report's query is split
-- into lives in the database only (owner 2026-10-13: "config about sizing should of course be in sql only").
--   cfg.RaBucketState    per report + template + query fingerprint: the last known count and when a run last DECIDED it
--                        (probed it, raised it, sized it down, or sized it from a measurement). A changed query = a new
--                        fingerprint = sized again; the run removes the report's other fingerprints.
--   cfg.RaBucketHistory  one row per report per run: the count it started with and ended with, how it was decided, the
--                        measured result (rows; the largest bucket's rows and bytes; the largest request), the usual count
--                        (median of the report's earlier rows) and the jump flag. The run keeps the newest 30 per report.
--   cfg.RaBucketReset    a ONE-TIME reset an Admin staged on Operations > Risk Analysis query splitting (Review & commit):
--                        the next run of that template forgets the report's count (NULL = every report), sizes it again
--                        and records AppliedUtc -- consumed once.
--   cfg.RaBucketImport   per template: the counts an install learned before this table existed were imported once.
-- Written by the Risk Analysis jobs (db_datawriter); the web app reads them and inserts reset rows only.
-- =============================================================================================
IF OBJECT_ID('cfg.RaBucketState') IS NULL
CREATE TABLE cfg.RaBucketState (
    Template        NVARCHAR(128)   NOT NULL,
    ReportName      NVARCHAR(256)   NOT NULL,
    Fingerprint     NVARCHAR(64)    NOT NULL,
    BucketCount     INT             NOT NULL,
    ConfirmedUtc    DATETIME2(0)    NULL,
    UpdatedUtc      DATETIME2(0)    NOT NULL CONSTRAINT DF_RaBucketState_UpdatedUtc DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_RaBucketState PRIMARY KEY (Template, ReportName, Fingerprint)
);

IF OBJECT_ID('cfg.RaBucketHistory') IS NULL
CREATE TABLE cfg.RaBucketHistory (
    Id                   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RaBucketHistory PRIMARY KEY,
    Template             NVARCHAR(128)   NOT NULL,
    ReportName           NVARCHAR(256)   NOT NULL,
    Fingerprint          NVARCHAR(64)    NULL,
    RunId                NVARCHAR(64)    NULL,
    RunUtc               DATETIME2(0)    NOT NULL CONSTRAINT DF_RaBucketHistory_RunUtc DEFAULT SYSUTCDATETIME(),
    StartCount           INT             NOT NULL,
    BucketCount          INT             NOT NULL,
    Decided              NVARCHAR(16)    NOT NULL,
    ResultRows           BIGINT          NULL,
    MaxBucketRows        BIGINT          NULL,
    MaxBucketBytes       BIGINT          NULL,
    MaxRequestBytes      BIGINT          NULL,
    RequestRows          BIGINT          NULL,
    RequestBytesPerRow   INT             NULL,
    RequestOverheadBytes INT             NULL,
    UsualCount           INT             NULL,
    Jump                 BIT             NOT NULL CONSTRAINT DF_RaBucketHistory_Jump DEFAULT 0
);

-- #833: the slice TIME is measured like the rows and the bytes -- the longest slice of the run (whole seconds) and the
-- count its slices ran at -- so a report far inside every limit (time included) is sized down to 1, and a changed query
-- starts from its measured need. NULL on rows written before; the engine reads and writes them only once they exist.
IF COL_LENGTH('cfg.RaBucketHistory', 'MaxBucketSeconds') IS NULL
ALTER TABLE cfg.RaBucketHistory ADD MaxBucketSeconds INT NULL;

IF COL_LENGTH('cfg.RaBucketHistory', 'RanCount') IS NULL
ALTER TABLE cfg.RaBucketHistory ADD RanCount INT NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RaBucketHistory_Report' AND object_id = OBJECT_ID('cfg.RaBucketHistory'))
CREATE INDEX IX_RaBucketHistory_Report ON cfg.RaBucketHistory (Template, ReportName, Id DESC);

IF OBJECT_ID('cfg.RaBucketReset') IS NULL
CREATE TABLE cfg.RaBucketReset (
    ResetId         BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RaBucketReset PRIMARY KEY,
    Template        NVARCHAR(128)   NOT NULL,
    ReportName      NVARCHAR(256)   NULL,        -- NULL = every report of the template
    RequestedUtc    DATETIME2(0)    NOT NULL CONSTRAINT DF_RaBucketReset_RequestedUtc DEFAULT SYSUTCDATETIME(),
    RequestedBy     NVARCHAR(256)   NOT NULL,
    Reason          NVARCHAR(400)   NULL,
    AppliedUtc      DATETIME2(0)    NULL,        -- set by the run that consumed it
    AppliedRunId    NVARCHAR(64)    NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RaBucketReset_Pending' AND object_id = OBJECT_ID('cfg.RaBucketReset'))
CREATE INDEX IX_RaBucketReset_Pending ON cfg.RaBucketReset (Template, AppliedUtc);

IF OBJECT_ID('cfg.RaBucketImport') IS NULL
CREATE TABLE cfg.RaBucketImport (
    Template        NVARCHAR(128)   NOT NULL CONSTRAINT PK_RaBucketImport PRIMARY KEY,
    ImportedUtc     DATETIME2(0)    NOT NULL CONSTRAINT DF_RaBucketImport_ImportedUtc DEFAULT SYSUTCDATETIME(),
    Entries         INT             NOT NULL,
    Source          NVARCHAR(200)   NULL
);

-- #902 (5) A SOURCE THAT IS EMPTY FOR GOOD (owner 2026-10-26: "Approve, next release"): an Admin / SuperAdmin accepts, PER
-- REPORT, that a source table the report reads is empty for good (the feature was turned off). Only for a report held for a
-- source that went silent -- a SUCCESSFUL count of zero (data-model/hold-kinds.locked.json acceptEmpty), never for a read
-- that failed. While active, the report is not held for that table: it shows empty and complete, and its findings close as
-- 'Report changed' (its query fingerprint carries the acceptance), never as fixed. The run clears it (ClearedHow): rows-back
-- (the table has rows again), not-read (the report no longer reads the table); the Admin: revoked. Every write is one
-- transaction with its cfg.ChangeLog row (Name 'source-accept/<report>/<table>', Scope 'riskanalysis', Kind 'sourceaccept').
IF OBJECT_ID('cfg.RaSourceAccept') IS NULL
CREATE TABLE cfg.RaSourceAccept (
    AcceptId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RaSourceAccept PRIMARY KEY,
    ReportName      NVARCHAR(256)   NOT NULL,
    SourceTable     NVARCHAR(128)   NOT NULL,
    Reason          NVARCHAR(400)   NOT NULL,
    AcceptedBy      NVARCHAR(256)   NOT NULL,
    AcceptedUtc     DATETIME2(0)    NOT NULL CONSTRAINT DF_RaSourceAccept_AcceptedUtc DEFAULT SYSUTCDATETIME(),
    ClearedUtc      DATETIME2(0)    NULL,
    ClearedHow      NVARCHAR(16)    NULL,        -- rows-back | not-read | revoked
    ClearedBy       NVARCHAR(256)   NULL,
    ClearedRunId    NVARCHAR(64)    NULL
);

-- one ACTIVE acceptance per report and table
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_RaSourceAccept_Active' AND object_id = OBJECT_ID('cfg.RaSourceAccept'))
CREATE UNIQUE INDEX UX_RaSourceAccept_Active ON cfg.RaSourceAccept (ReportName, SourceTable) WHERE ClearedUtc IS NULL;
-- >>> GENERATED CONFIG JOURNAL (engine\pro-settings\Build-SIConfigJournalSql.ps1 from config\config-entities.locked.json) -- do not edit by hand

-- the journal of setting (cfg.Setting)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_Setting_Journal ON cfg.Setting AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''setting'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [Name], [Scope] FROM inserted UNION SELECT [Name], [Scope] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Name], N''|'', i.[Scope]), 900) AS K, 1 AS L, (SELECT i.[Name] AS [Name], i.[Scope] AS [Scope], i.[ValueJson] AS [ValueJson], i.[KeyVaultSecretName] AS [KeyVaultSecretName], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Name] AS [Name], i.[Scope] AS [Scope], i.[ValueJson] AS [ValueJson], i.[KeyVaultSecretName] AS [KeyVaultSecretName] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[Name] = x.[Name] AND i.[Scope] = x.[Scope]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Name], N''|'', d.[Scope]), 900) AS K, 1 AS L, (SELECT d.[Name] AS [Name], d.[Scope] AS [Scope], d.[ValueJson] AS [ValueJson], d.[KeyVaultSecretName] AS [KeyVaultSecretName], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Name] AS [Name], d.[Scope] AS [Scope], d.[ValueJson] AS [ValueJson], d.[KeyVaultSecretName] AS [KeyVaultSecretName] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[Name] = x.[Name] AND d.[Scope] = x.[Scope]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of document (cfg.Document)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_Document_Journal ON cfg.Document AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''document'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [Kind], [Key] FROM inserted UNION SELECT [Kind], [Key] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Kind], N''|'', i.[Key]), 900) AS K, 1 AS L, (SELECT i.[Kind] AS [Kind], i.[Key] AS [Key], i.[Body] AS [Body], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Kind] AS [Kind], i.[Key] AS [Key], i.[Body] AS [Body] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[Kind] = x.[Kind] AND i.[Key] = x.[Key]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Kind], N''|'', d.[Key]), 900) AS K, 1 AS L, (SELECT d.[Kind] AS [Kind], d.[Key] AS [Key], d.[Body] AS [Body], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Kind] AS [Kind], d.[Key] AS [Key], d.[Body] AS [Body] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[Kind] = x.[Kind] AND d.[Key] = x.[Key]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of access (cfg.AccessAssignment)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_AccessAssignment_Journal ON cfg.AccessAssignment AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''access'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [PrincipalId] FROM inserted UNION SELECT [PrincipalId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[PrincipalId], N''''), 900) AS K, 1 AS L, (SELECT i.[PrincipalId] AS [PrincipalId], i.[PrincipalType] AS [PrincipalType], i.[DisplayName] AS [DisplayName], i.[Role] AS [Role], i.[ScopeJson] AS [ScopeJson], i.[AccountMail] AS [AccountMail], i.[ForwardTo] AS [ForwardTo], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[PrincipalId] AS [PrincipalId], i.[PrincipalType] AS [PrincipalType], i.[DisplayName] AS [DisplayName], i.[Role] AS [Role], i.[ScopeJson] AS [ScopeJson], i.[AccountMail] AS [AccountMail], i.[ForwardTo] AS [ForwardTo] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[PrincipalId] = x.[PrincipalId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[PrincipalId], N''''), 900) AS K, 1 AS L, (SELECT d.[PrincipalId] AS [PrincipalId], d.[PrincipalType] AS [PrincipalType], d.[DisplayName] AS [DisplayName], d.[Role] AS [Role], d.[ScopeJson] AS [ScopeJson], d.[AccountMail] AS [AccountMail], d.[ForwardTo] AS [ForwardTo], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[PrincipalId] AS [PrincipalId], d.[PrincipalType] AS [PrincipalType], d.[DisplayName] AS [DisplayName], d.[Role] AS [Role], d.[ScopeJson] AS [ScopeJson], d.[AccountMail] AS [AccountMail], d.[ForwardTo] AS [ForwardTo] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[PrincipalId] = x.[PrincipalId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of override (cfg.ItemOverride)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_ItemOverride_Journal ON cfg.ItemOverride AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''override'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [Kind], [ItemKey] FROM inserted UNION SELECT [Kind], [ItemKey] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Kind], N''|'', i.[ItemKey]), 900) AS K, 1 AS L, (SELECT i.[Kind] AS [Kind], i.[ItemKey] AS [ItemKey], i.[State] AS [State], i.[BodyJson] AS [BodyJson], i.[Format] AS [Format], i.[BaseVersion] AS [BaseVersion], i.[BaseHash] AS [BaseHash], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Kind] AS [Kind], i.[ItemKey] AS [ItemKey], i.[State] AS [State], i.[BodyJson] AS [BodyJson], i.[Format] AS [Format], i.[BaseVersion] AS [BaseVersion], i.[BaseHash] AS [BaseHash] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[Kind] = x.[Kind] AND i.[ItemKey] = x.[ItemKey]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Kind], N''|'', d.[ItemKey]), 900) AS K, 1 AS L, (SELECT d.[Kind] AS [Kind], d.[ItemKey] AS [ItemKey], d.[State] AS [State], d.[BodyJson] AS [BodyJson], d.[Format] AS [Format], d.[BaseVersion] AS [BaseVersion], d.[BaseHash] AS [BaseHash], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Kind] AS [Kind], d.[ItemKey] AS [ItemKey], d.[State] AS [State], d.[BodyJson] AS [BodyJson], d.[Format] AS [Format], d.[BaseVersion] AS [BaseVersion], d.[BaseHash] AS [BaseHash] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[Kind] = x.[Kind] AND d.[ItemKey] = x.[ItemKey]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of exemption (cfg.Exemption)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_Exemption_Journal ON cfg.Exemption AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''exemption'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [ExemptionId] FROM inserted UNION SELECT [ExemptionId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[ExemptionId], N''''), 900) AS K, CASE WHEN i.[RevokedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[ExemptionId] AS [ExemptionId], i.[Scope] AS [Scope], i.[ReportName] AS [ReportName], i.[ConfigurationId] AS [ConfigurationId], i.[Cve] AS [Cve], i.[AssetKey] AS [AssetKey], i.[Reason] AS [Reason], i.[ExpiresAt] AS [ExpiresAt], i.[CreatedBy] AS [CreatedBy], i.[CreatedAt] AS [CreatedAt], i.[RevokedAt] AS [RevokedAt], i.[RevokedBy] AS [RevokedBy], i.[RequestId] AS [RequestId], i.[Domain] AS [Domain], i.[ApprovedBy] AS [ApprovedBy], i.[ApprovedAt] AS [ApprovedAt], i.[ReviewedBy] AS [ReviewedBy], i.[ReviewedAt] AS [ReviewedAt], i.[Category] AS [Category] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[ExemptionId] AS [ExemptionId], i.[Scope] AS [Scope], i.[ReportName] AS [ReportName], i.[ConfigurationId] AS [ConfigurationId], i.[Cve] AS [Cve], i.[AssetKey] AS [AssetKey], i.[Reason] AS [Reason], i.[ExpiresAt] AS [ExpiresAt], i.[CreatedBy] AS [CreatedBy], i.[RevokedAt] AS [RevokedAt], i.[RevokedBy] AS [RevokedBy], i.[RequestId] AS [RequestId], i.[Domain] AS [Domain], i.[ApprovedBy] AS [ApprovedBy], i.[ApprovedAt] AS [ApprovedAt], i.[Category] AS [Category] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[ExemptionId] = x.[ExemptionId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[ExemptionId], N''''), 900) AS K, CASE WHEN d.[RevokedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[ExemptionId] AS [ExemptionId], d.[Scope] AS [Scope], d.[ReportName] AS [ReportName], d.[ConfigurationId] AS [ConfigurationId], d.[Cve] AS [Cve], d.[AssetKey] AS [AssetKey], d.[Reason] AS [Reason], d.[ExpiresAt] AS [ExpiresAt], d.[CreatedBy] AS [CreatedBy], d.[CreatedAt] AS [CreatedAt], d.[RevokedAt] AS [RevokedAt], d.[RevokedBy] AS [RevokedBy], d.[RequestId] AS [RequestId], d.[Domain] AS [Domain], d.[ApprovedBy] AS [ApprovedBy], d.[ApprovedAt] AS [ApprovedAt], d.[ReviewedBy] AS [ReviewedBy], d.[ReviewedAt] AS [ReviewedAt], d.[Category] AS [Category] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[ExemptionId] AS [ExemptionId], d.[Scope] AS [Scope], d.[ReportName] AS [ReportName], d.[ConfigurationId] AS [ConfigurationId], d.[Cve] AS [Cve], d.[AssetKey] AS [AssetKey], d.[Reason] AS [Reason], d.[ExpiresAt] AS [ExpiresAt], d.[CreatedBy] AS [CreatedBy], d.[RevokedAt] AS [RevokedAt], d.[RevokedBy] AS [RevokedBy], d.[RequestId] AS [RequestId], d.[Domain] AS [Domain], d.[ApprovedBy] AS [ApprovedBy], d.[ApprovedAt] AS [ApprovedAt], d.[Category] AS [Category] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[ExemptionId] = x.[ExemptionId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of connector (cfg.Connector)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_Connector_Journal ON cfg.Connector AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''connector'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [ConnectorId] FROM inserted UNION SELECT [ConnectorId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Name], N''''), 900) AS K, 1 AS L, (SELECT i.[ConnectorId] AS [ConnectorId], i.[Name] AS [Name], i.[Kind] AS [Kind], i.[Direction] AS [Direction], i.[Enabled] AS [Enabled], i.[Mode] AS [Mode], i.[AllowCreate] AS [AllowCreate], i.[AllowClose] AS [AllowClose], i.[SettingsJson] AS [SettingsJson], i.[SecretRefsJson] AS [SecretRefsJson], i.[MappingJson] AS [MappingJson], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Name] AS [Name], i.[Kind] AS [Kind], i.[Direction] AS [Direction], i.[Enabled] AS [Enabled], i.[Mode] AS [Mode], i.[AllowCreate] AS [AllowCreate], i.[AllowClose] AS [AllowClose], i.[SettingsJson] AS [SettingsJson], i.[SecretRefsJson] AS [SecretRefsJson], i.[MappingJson] AS [MappingJson] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[ConnectorId] = x.[ConnectorId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Name], N''''), 900) AS K, 1 AS L, (SELECT d.[ConnectorId] AS [ConnectorId], d.[Name] AS [Name], d.[Kind] AS [Kind], d.[Direction] AS [Direction], d.[Enabled] AS [Enabled], d.[Mode] AS [Mode], d.[AllowCreate] AS [AllowCreate], d.[AllowClose] AS [AllowClose], d.[SettingsJson] AS [SettingsJson], d.[SecretRefsJson] AS [SecretRefsJson], d.[MappingJson] AS [MappingJson], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Name] AS [Name], d.[Kind] AS [Kind], d.[Direction] AS [Direction], d.[Enabled] AS [Enabled], d.[Mode] AS [Mode], d.[AllowCreate] AS [AllowCreate], d.[AllowClose] AS [AllowClose], d.[SettingsJson] AS [SettingsJson], d.[SecretRefsJson] AS [SecretRefsJson], d.[MappingJson] AS [MappingJson] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[ConnectorId] = x.[ConnectorId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of department (cfg.Department)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_Department_Journal ON cfg.Department AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''department'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [DepartmentId] FROM inserted UNION SELECT [DepartmentId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[DepartmentId], N''''), 900) AS K, CASE WHEN i.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[DepartmentId] AS [DepartmentId], i.[Name] AS [Name], i.[Mail] AS [Mail], i.[Description] AS [Description], i.[MatchValues] AS [MatchValues], i.[MaintenanceWindowsJson] AS [MaintenanceWindowsJson], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy], i.[RetiredAt] AS [RetiredAt], i.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[DepartmentId] AS [DepartmentId], i.[Name] AS [Name], i.[Mail] AS [Mail], i.[Description] AS [Description], i.[MatchValues] AS [MatchValues], i.[MaintenanceWindowsJson] AS [MaintenanceWindowsJson], i.[RetiredAt] AS [RetiredAt], i.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[DepartmentId] = x.[DepartmentId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[DepartmentId], N''''), 900) AS K, CASE WHEN d.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[DepartmentId] AS [DepartmentId], d.[Name] AS [Name], d.[Mail] AS [Mail], d.[Description] AS [Description], d.[MatchValues] AS [MatchValues], d.[MaintenanceWindowsJson] AS [MaintenanceWindowsJson], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy], d.[RetiredAt] AS [RetiredAt], d.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[DepartmentId] AS [DepartmentId], d.[Name] AS [Name], d.[Mail] AS [Mail], d.[Description] AS [Description], d.[MatchValues] AS [MatchValues], d.[MaintenanceWindowsJson] AS [MaintenanceWindowsJson], d.[RetiredAt] AS [RetiredAt], d.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[DepartmentId] = x.[DepartmentId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of member (cfg.DepartmentMember)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_DepartmentMember_Journal ON cfg.DepartmentMember AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''member'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [MemberId] FROM inserted UNION SELECT [MemberId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[DepartmentId], N''|'', i.[Role], N''|'', i.[PrincipalType], N''|'', i.[ObjectId], N''|'', i.[Mail]), 900) AS K, 1 AS L, (SELECT i.[MemberId] AS [MemberId], i.[DepartmentId] AS [DepartmentId], i.[Role] AS [Role], i.[ObjectId] AS [ObjectId], i.[PrincipalType] AS [PrincipalType], i.[DisplayName] AS [DisplayName], i.[Mail] AS [Mail], i.[Company] AS [Company], i.[IsExternal] AS [IsExternal], i.[AddedAt] AS [AddedAt], i.[AddedBy] AS [AddedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[DepartmentId] AS [DepartmentId], i.[Role] AS [Role], i.[ObjectId] AS [ObjectId], i.[PrincipalType] AS [PrincipalType], i.[DisplayName] AS [DisplayName], i.[Mail] AS [Mail], i.[Company] AS [Company], i.[IsExternal] AS [IsExternal] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[MemberId] = x.[MemberId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[DepartmentId], N''|'', d.[Role], N''|'', d.[PrincipalType], N''|'', d.[ObjectId], N''|'', d.[Mail]), 900) AS K, 1 AS L, (SELECT d.[MemberId] AS [MemberId], d.[DepartmentId] AS [DepartmentId], d.[Role] AS [Role], d.[ObjectId] AS [ObjectId], d.[PrincipalType] AS [PrincipalType], d.[DisplayName] AS [DisplayName], d.[Mail] AS [Mail], d.[Company] AS [Company], d.[IsExternal] AS [IsExternal], d.[AddedAt] AS [AddedAt], d.[AddedBy] AS [AddedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[DepartmentId] AS [DepartmentId], d.[Role] AS [Role], d.[ObjectId] AS [ObjectId], d.[PrincipalType] AS [PrincipalType], d.[DisplayName] AS [DisplayName], d.[Mail] AS [Mail], d.[Company] AS [Company], d.[IsExternal] AS [IsExternal] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[MemberId] = x.[MemberId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of responsibilityrule (cfg.ResponsibilityRule)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_ResponsibilityRule_Journal ON cfg.ResponsibilityRule AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''responsibilityrule'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [RuleId] FROM inserted UNION SELECT [RuleId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[DepartmentId], N''|'', i.[Kind], N''|'', i.[Pattern]), 900) AS K, 1 AS L, (SELECT i.[RuleId] AS [RuleId], i.[Kind] AS [Kind], i.[Pattern] AS [Pattern], i.[DepartmentId] AS [DepartmentId], i.[SortOrder] AS [SortOrder], i.[Enabled] AS [Enabled], i.[Note] AS [Note], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Kind] AS [Kind], i.[Pattern] AS [Pattern], i.[DepartmentId] AS [DepartmentId], i.[SortOrder] AS [SortOrder], i.[Enabled] AS [Enabled], i.[Note] AS [Note] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[RuleId] = x.[RuleId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[DepartmentId], N''|'', d.[Kind], N''|'', d.[Pattern]), 900) AS K, 1 AS L, (SELECT d.[RuleId] AS [RuleId], d.[Kind] AS [Kind], d.[Pattern] AS [Pattern], d.[DepartmentId] AS [DepartmentId], d.[SortOrder] AS [SortOrder], d.[Enabled] AS [Enabled], d.[Note] AS [Note], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Kind] AS [Kind], d.[Pattern] AS [Pattern], d.[DepartmentId] AS [DepartmentId], d.[SortOrder] AS [SortOrder], d.[Enabled] AS [Enabled], d.[Note] AS [Note] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[RuleId] = x.[RuleId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of responsibilityoverride (cfg.ResponsibilityOverride)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_ResponsibilityOverride_Journal ON cfg.ResponsibilityOverride AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''responsibilityoverride'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [OverrideId] FROM inserted UNION SELECT [OverrideId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Scope], N''|'', i.[AssetKey], N''|'', i.[RecommendationKey]), 900) AS K, CASE WHEN i.[RevokedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[OverrideId] AS [OverrideId], i.[Scope] AS [Scope], i.[AssetKey] AS [AssetKey], i.[RecommendationKey] AS [RecommendationKey], i.[DepartmentId] AS [DepartmentId], i.[Reason] AS [Reason], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[RevokedAt] AS [RevokedAt], i.[RevokedBy] AS [RevokedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Scope] AS [Scope], i.[AssetKey] AS [AssetKey], i.[RecommendationKey] AS [RecommendationKey], i.[DepartmentId] AS [DepartmentId], i.[Reason] AS [Reason], i.[RevokedAt] AS [RevokedAt], i.[RevokedBy] AS [RevokedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[OverrideId] = x.[OverrideId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Scope], N''|'', d.[AssetKey], N''|'', d.[RecommendationKey]), 900) AS K, CASE WHEN d.[RevokedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[OverrideId] AS [OverrideId], d.[Scope] AS [Scope], d.[AssetKey] AS [AssetKey], d.[RecommendationKey] AS [RecommendationKey], d.[DepartmentId] AS [DepartmentId], d.[Reason] AS [Reason], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[RevokedAt] AS [RevokedAt], d.[RevokedBy] AS [RevokedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Scope] AS [Scope], d.[AssetKey] AS [AssetKey], d.[RecommendationKey] AS [RecommendationKey], d.[DepartmentId] AS [DepartmentId], d.[Reason] AS [Reason], d.[RevokedAt] AS [RevokedAt], d.[RevokedBy] AS [RevokedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[OverrideId] = x.[OverrideId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of domainrole (cfg.DomainRole)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_DomainRole_Journal ON cfg.DomainRole AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''domainrole'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [Domain], [Role], [Principal] FROM inserted UNION SELECT [Domain], [Role], [Principal] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Domain], N''|'', i.[Role], N''|'', i.[Principal]), 900) AS K, CASE WHEN i.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[Domain] AS [Domain], i.[Role] AS [Role], i.[Principal] AS [Principal], i.[AddedAt] AS [AddedAt], i.[AddedBy] AS [AddedBy], i.[RemovedAt] AS [RemovedAt], i.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Domain] AS [Domain], i.[Role] AS [Role], i.[Principal] AS [Principal], i.[RemovedAt] AS [RemovedAt], i.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[Domain] = x.[Domain] AND i.[Role] = x.[Role] AND i.[Principal] = x.[Principal]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Domain], N''|'', d.[Role], N''|'', d.[Principal]), 900) AS K, CASE WHEN d.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[Domain] AS [Domain], d.[Role] AS [Role], d.[Principal] AS [Principal], d.[AddedAt] AS [AddedAt], d.[AddedBy] AS [AddedBy], d.[RemovedAt] AS [RemovedAt], d.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Domain] AS [Domain], d.[Role] AS [Role], d.[Principal] AS [Principal], d.[RemovedAt] AS [RemovedAt], d.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[Domain] = x.[Domain] AND d.[Role] = x.[Role] AND d.[Principal] = x.[Principal]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of categoryrole (cfg.CategoryRole)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_CategoryRole_Journal ON cfg.CategoryRole AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''categoryrole'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [Domain], [Category], [Role], [Principal] FROM inserted UNION SELECT [Domain], [Category], [Role], [Principal] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Domain], N''|'', i.[Category], N''|'', i.[Role], N''|'', i.[Principal]), 900) AS K, CASE WHEN i.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[Domain] AS [Domain], i.[Category] AS [Category], i.[Role] AS [Role], i.[Principal] AS [Principal], i.[AddedAt] AS [AddedAt], i.[AddedBy] AS [AddedBy], i.[RemovedAt] AS [RemovedAt], i.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Domain] AS [Domain], i.[Category] AS [Category], i.[Role] AS [Role], i.[Principal] AS [Principal], i.[RemovedAt] AS [RemovedAt], i.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[Domain] = x.[Domain] AND i.[Category] = x.[Category] AND i.[Role] = x.[Role] AND i.[Principal] = x.[Principal]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Domain], N''|'', d.[Category], N''|'', d.[Role], N''|'', d.[Principal]), 900) AS K, CASE WHEN d.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[Domain] AS [Domain], d.[Category] AS [Category], d.[Role] AS [Role], d.[Principal] AS [Principal], d.[AddedAt] AS [AddedAt], d.[AddedBy] AS [AddedBy], d.[RemovedAt] AS [RemovedAt], d.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Domain] AS [Domain], d.[Category] AS [Category], d.[Role] AS [Role], d.[Principal] AS [Principal], d.[RemovedAt] AS [RemovedAt], d.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[Domain] = x.[Domain] AND d.[Category] = x.[Category] AND d.[Role] = x.[Role] AND d.[Principal] = x.[Principal]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of remediationflow (cfg.RemediationFlow)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_RemediationFlow_Journal ON cfg.RemediationFlow AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''remediationflow'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [FlowId] FROM inserted UNION SELECT [FlowId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[FlowId], N''''), 900) AS K, CASE WHEN i.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[FlowId] AS [FlowId], i.[DepartmentId] AS [DepartmentId], i.[Category] AS [Category], i.[Subcategory] AS [Subcategory], i.[Action] AS [Action], i.[VendorName] AS [VendorName], i.[VendorMail] AS [VendorMail], i.[Note] AS [Note], i.[SortOrder] AS [SortOrder], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy], i.[RetiredAt] AS [RetiredAt], i.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[FlowId] AS [FlowId], i.[DepartmentId] AS [DepartmentId], i.[Category] AS [Category], i.[Subcategory] AS [Subcategory], i.[Action] AS [Action], i.[VendorName] AS [VendorName], i.[VendorMail] AS [VendorMail], i.[Note] AS [Note], i.[SortOrder] AS [SortOrder], i.[RetiredAt] AS [RetiredAt], i.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[FlowId] = x.[FlowId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[FlowId], N''''), 900) AS K, CASE WHEN d.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[FlowId] AS [FlowId], d.[DepartmentId] AS [DepartmentId], d.[Category] AS [Category], d.[Subcategory] AS [Subcategory], d.[Action] AS [Action], d.[VendorName] AS [VendorName], d.[VendorMail] AS [VendorMail], d.[Note] AS [Note], d.[SortOrder] AS [SortOrder], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy], d.[RetiredAt] AS [RetiredAt], d.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[FlowId] AS [FlowId], d.[DepartmentId] AS [DepartmentId], d.[Category] AS [Category], d.[Subcategory] AS [Subcategory], d.[Action] AS [Action], d.[VendorName] AS [VendorName], d.[VendorMail] AS [VendorMail], d.[Note] AS [Note], d.[SortOrder] AS [SortOrder], d.[RetiredAt] AS [RetiredAt], d.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[FlowId] = x.[FlowId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of advisor (cfg.DepartmentAdvisor)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_DepartmentAdvisor_Journal ON cfg.DepartmentAdvisor AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''advisor'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [AdvisorId] FROM inserted UNION SELECT [AdvisorId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[AdvisorId], N''''), 900) AS K, CASE WHEN i.[RevokedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[AdvisorId] AS [AdvisorId], i.[DepartmentId] AS [DepartmentId], i.[Kind] AS [Kind], i.[DisplayName] AS [DisplayName], i.[Company] AS [Company], i.[Mail] AS [Mail], i.[ObjectId] AS [ObjectId], i.[IsExternal] AS [IsExternal], i.[Note] AS [Note], i.[AddedAt] AS [AddedAt], i.[AddedBy] AS [AddedBy], i.[RevokedAt] AS [RevokedAt], i.[RevokedBy] AS [RevokedBy], i.[RevokeReason] AS [RevokeReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[AdvisorId] AS [AdvisorId], i.[DepartmentId] AS [DepartmentId], i.[Kind] AS [Kind], i.[DisplayName] AS [DisplayName], i.[Company] AS [Company], i.[Mail] AS [Mail], i.[ObjectId] AS [ObjectId], i.[IsExternal] AS [IsExternal], i.[Note] AS [Note], i.[RevokedAt] AS [RevokedAt], i.[RevokedBy] AS [RevokedBy], i.[RevokeReason] AS [RevokeReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[AdvisorId] = x.[AdvisorId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[AdvisorId], N''''), 900) AS K, CASE WHEN d.[RevokedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[AdvisorId] AS [AdvisorId], d.[DepartmentId] AS [DepartmentId], d.[Kind] AS [Kind], d.[DisplayName] AS [DisplayName], d.[Company] AS [Company], d.[Mail] AS [Mail], d.[ObjectId] AS [ObjectId], d.[IsExternal] AS [IsExternal], d.[Note] AS [Note], d.[AddedAt] AS [AddedAt], d.[AddedBy] AS [AddedBy], d.[RevokedAt] AS [RevokedAt], d.[RevokedBy] AS [RevokedBy], d.[RevokeReason] AS [RevokeReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[AdvisorId] AS [AdvisorId], d.[DepartmentId] AS [DepartmentId], d.[Kind] AS [Kind], d.[DisplayName] AS [DisplayName], d.[Company] AS [Company], d.[Mail] AS [Mail], d.[ObjectId] AS [ObjectId], d.[IsExternal] AS [IsExternal], d.[Note] AS [Note], d.[RevokedAt] AS [RevokedAt], d.[RevokedBy] AS [RevokedBy], d.[RevokeReason] AS [RevokeReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[AdvisorId] = x.[AdvisorId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of cmdbservice (cfg.CmdbService)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_CmdbService_Journal ON cfg.CmdbService AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''cmdbservice'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [ServiceId] FROM inserted UNION SELECT [ServiceId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[ServiceId], N''''), 900) AS K, CASE WHEN i.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[ServiceId] AS [ServiceId], i.[Source] AS [Source], i.[ServiceNumber] AS [ServiceNumber], i.[ExternalId] AS [ExternalId], i.[Name] AS [Name], i.[Description] AS [Description], i.[Owner] AS [Owner], i.[OwnerMail] AS [OwnerMail], i.[Criticality] AS [Criticality], i.[DataSensitivity] AS [DataSensitivity], i.[Environment] AS [Environment], i.[Department] AS [Department], i.[ExtraJson] AS [ExtraJson], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy], i.[RetiredAt] AS [RetiredAt], i.[RetiredBy] AS [RetiredBy], i.[RetireReason] AS [RetireReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[ServiceId] AS [ServiceId], i.[Source] AS [Source], i.[ServiceNumber] AS [ServiceNumber], i.[ExternalId] AS [ExternalId], i.[Name] AS [Name], i.[Description] AS [Description], i.[Owner] AS [Owner], i.[OwnerMail] AS [OwnerMail], i.[Criticality] AS [Criticality], i.[DataSensitivity] AS [DataSensitivity], i.[Environment] AS [Environment], i.[Department] AS [Department], i.[ExtraJson] AS [ExtraJson], i.[RetiredAt] AS [RetiredAt], i.[RetiredBy] AS [RetiredBy], i.[RetireReason] AS [RetireReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[ServiceId] = x.[ServiceId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[ServiceId], N''''), 900) AS K, CASE WHEN d.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[ServiceId] AS [ServiceId], d.[Source] AS [Source], d.[ServiceNumber] AS [ServiceNumber], d.[ExternalId] AS [ExternalId], d.[Name] AS [Name], d.[Description] AS [Description], d.[Owner] AS [Owner], d.[OwnerMail] AS [OwnerMail], d.[Criticality] AS [Criticality], d.[DataSensitivity] AS [DataSensitivity], d.[Environment] AS [Environment], d.[Department] AS [Department], d.[ExtraJson] AS [ExtraJson], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy], d.[RetiredAt] AS [RetiredAt], d.[RetiredBy] AS [RetiredBy], d.[RetireReason] AS [RetireReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[ServiceId] AS [ServiceId], d.[Source] AS [Source], d.[ServiceNumber] AS [ServiceNumber], d.[ExternalId] AS [ExternalId], d.[Name] AS [Name], d.[Description] AS [Description], d.[Owner] AS [Owner], d.[OwnerMail] AS [OwnerMail], d.[Criticality] AS [Criticality], d.[DataSensitivity] AS [DataSensitivity], d.[Environment] AS [Environment], d.[Department] AS [Department], d.[ExtraJson] AS [ExtraJson], d.[RetiredAt] AS [RetiredAt], d.[RetiredBy] AS [RetiredBy], d.[RetireReason] AS [RetireReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[ServiceId] = x.[ServiceId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of cmdblink (cfg.CmdbServiceAsset)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_CmdbServiceAsset_Journal ON cfg.CmdbServiceAsset AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''cmdblink'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [LinkId] FROM inserted UNION SELECT [LinkId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[ServiceId], N''|'', i.[AssetKey]), 900) AS K, CASE WHEN i.[UnlinkedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[LinkId] AS [LinkId], i.[ServiceId] AS [ServiceId], i.[AssetKey] AS [AssetKey], i.[AssetName] AS [AssetName], i.[LinkedAt] AS [LinkedAt], i.[LinkedBy] AS [LinkedBy], i.[UnlinkedAt] AS [UnlinkedAt], i.[UnlinkedBy] AS [UnlinkedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[ServiceId] AS [ServiceId], i.[AssetKey] AS [AssetKey], i.[AssetName] AS [AssetName], i.[UnlinkedAt] AS [UnlinkedAt], i.[UnlinkedBy] AS [UnlinkedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[LinkId] = x.[LinkId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[ServiceId], N''|'', d.[AssetKey]), 900) AS K, CASE WHEN d.[UnlinkedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[LinkId] AS [LinkId], d.[ServiceId] AS [ServiceId], d.[AssetKey] AS [AssetKey], d.[AssetName] AS [AssetName], d.[LinkedAt] AS [LinkedAt], d.[LinkedBy] AS [LinkedBy], d.[UnlinkedAt] AS [UnlinkedAt], d.[UnlinkedBy] AS [UnlinkedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[ServiceId] AS [ServiceId], d.[AssetKey] AS [AssetKey], d.[AssetName] AS [AssetName], d.[UnlinkedAt] AS [UnlinkedAt], d.[UnlinkedBy] AS [UnlinkedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[LinkId] = x.[LinkId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of jobflow (cfg.JobFlow)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_JobFlow_Journal ON cfg.JobFlow AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''jobflow'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [FlowId] FROM inserted UNION SELECT [FlowId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[FlowId], N''''), 900) AS K, 1 AS L, (SELECT i.[FlowId] AS [FlowId], i.[Mode] AS [Mode], i.[DefinitionJson] AS [DefinitionJson], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[FlowId] AS [FlowId], i.[Mode] AS [Mode], i.[DefinitionJson] AS [DefinitionJson] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[FlowId] = x.[FlowId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[FlowId], N''''), 900) AS K, 1 AS L, (SELECT d.[FlowId] AS [FlowId], d.[Mode] AS [Mode], d.[DefinitionJson] AS [DefinitionJson], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[FlowId] AS [FlowId], d.[Mode] AS [Mode], d.[DefinitionJson] AS [DefinitionJson] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[FlowId] = x.[FlowId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of mgmtreport (cfg.MgmtReport)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_MgmtReport_Journal ON cfg.MgmtReport AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''mgmtreport'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [ReportId] FROM inserted UNION SELECT [ReportId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[ReportId], N''''), 900) AS K, CASE WHEN i.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[ReportId] AS [ReportId], i.[Name] AS [Name], i.[Grain] AS [Grain], i.[Sections] AS [Sections], i.[Recipients] AS [Recipients], i.[Cadence] AS [Cadence], i.[Day] AS [Day], i.[TimeUtc] AS [TimeUtc], i.[Enabled] AS [Enabled], i.[CreatedAt] AS [CreatedAt], i.[CreatedBy] AS [CreatedBy], i.[UpdatedAt] AS [UpdatedAt], i.[UpdatedBy] AS [UpdatedBy], i.[RemovedAt] AS [RemovedAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[ReportId] AS [ReportId], i.[Name] AS [Name], i.[Grain] AS [Grain], i.[Sections] AS [Sections], i.[Recipients] AS [Recipients], i.[Cadence] AS [Cadence], i.[Day] AS [Day], i.[TimeUtc] AS [TimeUtc], i.[Enabled] AS [Enabled], i.[RemovedAt] AS [RemovedAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[ReportId] = x.[ReportId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[ReportId], N''''), 900) AS K, CASE WHEN d.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[ReportId] AS [ReportId], d.[Name] AS [Name], d.[Grain] AS [Grain], d.[Sections] AS [Sections], d.[Recipients] AS [Recipients], d.[Cadence] AS [Cadence], d.[Day] AS [Day], d.[TimeUtc] AS [TimeUtc], d.[Enabled] AS [Enabled], d.[CreatedAt] AS [CreatedAt], d.[CreatedBy] AS [CreatedBy], d.[UpdatedAt] AS [UpdatedAt], d.[UpdatedBy] AS [UpdatedBy], d.[RemovedAt] AS [RemovedAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[ReportId] AS [ReportId], d.[Name] AS [Name], d.[Grain] AS [Grain], d.[Sections] AS [Sections], d.[Recipients] AS [Recipients], d.[Cadence] AS [Cadence], d.[Day] AS [Day], d.[TimeUtc] AS [TimeUtc], d.[Enabled] AS [Enabled], d.[RemovedAt] AS [RemovedAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[ReportId] = x.[ReportId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of pivotview (cfg.PivotView)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_PivotView_Journal ON cfg.PivotView AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''pivotview'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [ViewId] FROM inserted UNION SELECT [ViewId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Owner], N''|'', i.[Name]), 900) AS K, CASE WHEN i.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[ViewId] AS [ViewId], i.[Name] AS [Name], i.[Owner] AS [Owner], i.[Shared] AS [Shared], i.[State] AS [State], i.[CreatedAt] AS [CreatedAt], i.[UpdatedAt] AS [UpdatedAt], i.[RemovedAt] AS [RemovedAt], i.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Name] AS [Name], i.[Owner] AS [Owner], i.[Shared] AS [Shared], i.[State] AS [State], i.[RemovedAt] AS [RemovedAt], i.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[ViewId] = x.[ViewId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Owner], N''|'', d.[Name]), 900) AS K, CASE WHEN d.[RemovedAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[ViewId] AS [ViewId], d.[Name] AS [Name], d.[Owner] AS [Owner], d.[Shared] AS [Shared], d.[State] AS [State], d.[CreatedAt] AS [CreatedAt], d.[UpdatedAt] AS [UpdatedAt], d.[RemovedAt] AS [RemovedAt], d.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Name] AS [Name], d.[Owner] AS [Owner], d.[Shared] AS [Shared], d.[State] AS [State], d.[RemovedAt] AS [RemovedAt], d.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[ViewId] = x.[ViewId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of guardack (cfg.GuardAck)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_GuardAck_Journal ON cfg.GuardAck AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''guardack'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [AckId] FROM inserted UNION SELECT [AckId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[AckId], N''''), 900) AS K, 1 AS L, (SELECT i.[AckId] AS [AckId], i.[EventId] AS [EventId], i.[GuardKey] AS [GuardKey], i.[DetailHash] AS [DetailHash], i.[AckBy] AS [AckBy], i.[AckUtc] AS [AckUtc], i.[Note] AS [Note] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[AckId] AS [AckId], i.[EventId] AS [EventId], i.[GuardKey] AS [GuardKey], i.[DetailHash] AS [DetailHash], i.[AckBy] AS [AckBy], i.[Note] AS [Note] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[AckId] = x.[AckId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[AckId], N''''), 900) AS K, 1 AS L, (SELECT d.[AckId] AS [AckId], d.[EventId] AS [EventId], d.[GuardKey] AS [GuardKey], d.[DetailHash] AS [DetailHash], d.[AckBy] AS [AckBy], d.[AckUtc] AS [AckUtc], d.[Note] AS [Note] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[AckId] AS [AckId], d.[EventId] AS [EventId], d.[GuardKey] AS [GuardKey], d.[DetailHash] AS [DetailHash], d.[AckBy] AS [AckBy], d.[Note] AS [Note] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[AckId] = x.[AckId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- the journal of template (cfg.Template)
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_Template_Journal ON cfg.Template AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.audit.cid'') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N''-'', N'''');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.audit.source'') AS NVARCHAR(16));
    IF @asrc NOT IN (N''web'', N''job'', N''engine'', N''setup'', N''api'', N''portal'') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N''si.cfg.source'') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN (N''gui'', N''api'', N''import'', N''restore'', N''undo'', N''sync'', N''template'')
        SET @src = CASE @asrc WHEN N''web'' THEN N''gui'' WHEN N''portal'' THEN N''gui'' WHEN N''api'' THEN N''api'' WHEN N''setup'' THEN N''import'' ELSE N''sync'' END;
    SET @src = N''template'';
    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N''si.cfg.initiatedBy'') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N''si.audit.actor'') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N''si.cfg.approvedBy'') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N''si.cfg.undoOf'') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N''si.cfg.reason'') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N''template'', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N''Add'' WHEN a.J IS NULL THEN N''Remove'' WHEN b.L = 1 AND a.L = 0 THEN N''Remove'' WHEN b.L = 0 AND a.L = 1 THEN N''Add'' ELSE N''Modify'' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT [TemplateId] FROM inserted UNION SELECT [TemplateId] FROM deleted) AS x
    OUTER APPLY (SELECT LEFT(CONCAT(i.[Kind], N''|'', i.[ItemKey]), 900) AS K, CASE WHEN i.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT i.[TemplateId] AS [TemplateId], i.[Kind] AS [Kind], i.[ItemKey] AS [ItemKey], i.[Version] AS [Version], i.[BodyJson] AS [BodyJson], i.[Format] AS [Format], i.[SortOrder] AS [SortOrder], i.[BodyHash] AS [BodyHash], i.[ContentHash] AS [ContentHash], i.[PublishedAt] AS [PublishedAt], i.[Source] AS [Source], i.[RetiredAt] AS [RetiredAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT i.[Kind] AS [Kind], i.[ItemKey] AS [ItemKey], i.[BodyJson] AS [BodyJson], i.[Format] AS [Format], i.[SortOrder] AS [SortOrder], i.[Source] AS [Source], i.[RetiredAt] AS [RetiredAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM inserted AS i WHERE i.[TemplateId] = x.[TemplateId]) AS a
    OUTER APPLY (SELECT LEFT(CONCAT(d.[Kind], N''|'', d.[ItemKey]), 900) AS K, CASE WHEN d.[RetiredAt] IS NULL THEN 1 ELSE 0 END AS L, (SELECT d.[TemplateId] AS [TemplateId], d.[Kind] AS [Kind], d.[ItemKey] AS [ItemKey], d.[Version] AS [Version], d.[BodyJson] AS [BodyJson], d.[Format] AS [Format], d.[SortOrder] AS [SortOrder], d.[BodyHash] AS [BodyHash], d.[ContentHash] AS [ContentHash], d.[PublishedAt] AS [PublishedAt], d.[Source] AS [Source], d.[RetiredAt] AS [RetiredAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT d.[Kind] AS [Kind], d.[ItemKey] AS [ItemKey], d.[BodyJson] AS [BodyJson], d.[Format] AS [Format], d.[SortOrder] AS [SortOrder], d.[Source] AS [Source], d.[RetiredAt] AS [RetiredAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS C FROM deleted AS d WHERE d.[TemplateId] = x.[TemplateId]) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END');

-- every record in force of every backup entity: what a configuration backup holds
EXEC (N'CREATE OR ALTER VIEW cfg.vConfigSnapshot AS
SELECT N''setting'' AS Entity, LEFT(CONCAT(t.[Name], N''|'', t.[Scope]), 900) AS EntityKey, (SELECT t.[Name] AS [Name], t.[Scope] AS [Scope], t.[ValueJson] AS [ValueJson], t.[KeyVaultSecretName] AS [KeyVaultSecretName], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.Setting AS t
UNION ALL
SELECT N''document'' AS Entity, LEFT(CONCAT(t.[Kind], N''|'', t.[Key]), 900) AS EntityKey, (SELECT t.[Kind] AS [Kind], t.[Key] AS [Key], t.[Body] AS [Body], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.Document AS t
UNION ALL
SELECT N''access'' AS Entity, LEFT(CONCAT(t.[PrincipalId], N''''), 900) AS EntityKey, (SELECT t.[PrincipalId] AS [PrincipalId], t.[PrincipalType] AS [PrincipalType], t.[DisplayName] AS [DisplayName], t.[Role] AS [Role], t.[ScopeJson] AS [ScopeJson], t.[AccountMail] AS [AccountMail], t.[ForwardTo] AS [ForwardTo], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.AccessAssignment AS t
UNION ALL
SELECT N''override'' AS Entity, LEFT(CONCAT(t.[Kind], N''|'', t.[ItemKey]), 900) AS EntityKey, (SELECT t.[Kind] AS [Kind], t.[ItemKey] AS [ItemKey], t.[State] AS [State], t.[BodyJson] AS [BodyJson], t.[Format] AS [Format], t.[BaseVersion] AS [BaseVersion], t.[BaseHash] AS [BaseHash], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.ItemOverride AS t
UNION ALL
SELECT N''exemption'' AS Entity, LEFT(CONCAT(t.[ExemptionId], N''''), 900) AS EntityKey, (SELECT t.[ExemptionId] AS [ExemptionId], t.[Scope] AS [Scope], t.[ReportName] AS [ReportName], t.[ConfigurationId] AS [ConfigurationId], t.[Cve] AS [Cve], t.[AssetKey] AS [AssetKey], t.[Reason] AS [Reason], t.[ExpiresAt] AS [ExpiresAt], t.[CreatedBy] AS [CreatedBy], t.[CreatedAt] AS [CreatedAt], t.[RevokedAt] AS [RevokedAt], t.[RevokedBy] AS [RevokedBy], t.[RequestId] AS [RequestId], t.[Domain] AS [Domain], t.[ApprovedBy] AS [ApprovedBy], t.[ApprovedAt] AS [ApprovedAt], t.[ReviewedBy] AS [ReviewedBy], t.[ReviewedAt] AS [ReviewedAt], t.[Category] AS [Category] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.Exemption AS t WHERE t.[RevokedAt] IS NULL
UNION ALL
SELECT N''connector'' AS Entity, LEFT(CONCAT(t.[Name], N''''), 900) AS EntityKey, (SELECT t.[ConnectorId] AS [ConnectorId], t.[Name] AS [Name], t.[Kind] AS [Kind], t.[Direction] AS [Direction], t.[Enabled] AS [Enabled], t.[Mode] AS [Mode], t.[AllowCreate] AS [AllowCreate], t.[AllowClose] AS [AllowClose], t.[SettingsJson] AS [SettingsJson], t.[SecretRefsJson] AS [SecretRefsJson], t.[MappingJson] AS [MappingJson], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.Connector AS t
UNION ALL
SELECT N''department'' AS Entity, LEFT(CONCAT(t.[DepartmentId], N''''), 900) AS EntityKey, (SELECT t.[DepartmentId] AS [DepartmentId], t.[Name] AS [Name], t.[Mail] AS [Mail], t.[Description] AS [Description], t.[MatchValues] AS [MatchValues], t.[MaintenanceWindowsJson] AS [MaintenanceWindowsJson], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy], t.[RetiredAt] AS [RetiredAt], t.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.Department AS t WHERE t.[RetiredAt] IS NULL
UNION ALL
SELECT N''member'' AS Entity, LEFT(CONCAT(t.[DepartmentId], N''|'', t.[Role], N''|'', t.[PrincipalType], N''|'', t.[ObjectId], N''|'', t.[Mail]), 900) AS EntityKey, (SELECT t.[MemberId] AS [MemberId], t.[DepartmentId] AS [DepartmentId], t.[Role] AS [Role], t.[ObjectId] AS [ObjectId], t.[PrincipalType] AS [PrincipalType], t.[DisplayName] AS [DisplayName], t.[Mail] AS [Mail], t.[Company] AS [Company], t.[IsExternal] AS [IsExternal], t.[AddedAt] AS [AddedAt], t.[AddedBy] AS [AddedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.DepartmentMember AS t
UNION ALL
SELECT N''responsibilityrule'' AS Entity, LEFT(CONCAT(t.[DepartmentId], N''|'', t.[Kind], N''|'', t.[Pattern]), 900) AS EntityKey, (SELECT t.[RuleId] AS [RuleId], t.[Kind] AS [Kind], t.[Pattern] AS [Pattern], t.[DepartmentId] AS [DepartmentId], t.[SortOrder] AS [SortOrder], t.[Enabled] AS [Enabled], t.[Note] AS [Note], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.ResponsibilityRule AS t
UNION ALL
SELECT N''responsibilityoverride'' AS Entity, LEFT(CONCAT(t.[Scope], N''|'', t.[AssetKey], N''|'', t.[RecommendationKey]), 900) AS EntityKey, (SELECT t.[OverrideId] AS [OverrideId], t.[Scope] AS [Scope], t.[AssetKey] AS [AssetKey], t.[RecommendationKey] AS [RecommendationKey], t.[DepartmentId] AS [DepartmentId], t.[Reason] AS [Reason], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[RevokedAt] AS [RevokedAt], t.[RevokedBy] AS [RevokedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.ResponsibilityOverride AS t WHERE t.[RevokedAt] IS NULL
UNION ALL
SELECT N''domainrole'' AS Entity, LEFT(CONCAT(t.[Domain], N''|'', t.[Role], N''|'', t.[Principal]), 900) AS EntityKey, (SELECT t.[Domain] AS [Domain], t.[Role] AS [Role], t.[Principal] AS [Principal], t.[AddedAt] AS [AddedAt], t.[AddedBy] AS [AddedBy], t.[RemovedAt] AS [RemovedAt], t.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.DomainRole AS t WHERE t.[RemovedAt] IS NULL
UNION ALL
SELECT N''categoryrole'' AS Entity, LEFT(CONCAT(t.[Domain], N''|'', t.[Category], N''|'', t.[Role], N''|'', t.[Principal]), 900) AS EntityKey, (SELECT t.[Domain] AS [Domain], t.[Category] AS [Category], t.[Role] AS [Role], t.[Principal] AS [Principal], t.[AddedAt] AS [AddedAt], t.[AddedBy] AS [AddedBy], t.[RemovedAt] AS [RemovedAt], t.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.CategoryRole AS t WHERE t.[RemovedAt] IS NULL
UNION ALL
SELECT N''remediationflow'' AS Entity, LEFT(CONCAT(t.[FlowId], N''''), 900) AS EntityKey, (SELECT t.[FlowId] AS [FlowId], t.[DepartmentId] AS [DepartmentId], t.[Category] AS [Category], t.[Subcategory] AS [Subcategory], t.[Action] AS [Action], t.[VendorName] AS [VendorName], t.[VendorMail] AS [VendorMail], t.[Note] AS [Note], t.[SortOrder] AS [SortOrder], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy], t.[RetiredAt] AS [RetiredAt], t.[RetiredBy] AS [RetiredBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.RemediationFlow AS t WHERE t.[RetiredAt] IS NULL
UNION ALL
SELECT N''advisor'' AS Entity, LEFT(CONCAT(t.[AdvisorId], N''''), 900) AS EntityKey, (SELECT t.[AdvisorId] AS [AdvisorId], t.[DepartmentId] AS [DepartmentId], t.[Kind] AS [Kind], t.[DisplayName] AS [DisplayName], t.[Company] AS [Company], t.[Mail] AS [Mail], t.[ObjectId] AS [ObjectId], t.[IsExternal] AS [IsExternal], t.[Note] AS [Note], t.[AddedAt] AS [AddedAt], t.[AddedBy] AS [AddedBy], t.[RevokedAt] AS [RevokedAt], t.[RevokedBy] AS [RevokedBy], t.[RevokeReason] AS [RevokeReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.DepartmentAdvisor AS t WHERE t.[RevokedAt] IS NULL
UNION ALL
SELECT N''cmdbservice'' AS Entity, LEFT(CONCAT(t.[ServiceId], N''''), 900) AS EntityKey, (SELECT t.[ServiceId] AS [ServiceId], t.[Source] AS [Source], t.[ServiceNumber] AS [ServiceNumber], t.[ExternalId] AS [ExternalId], t.[Name] AS [Name], t.[Description] AS [Description], t.[Owner] AS [Owner], t.[OwnerMail] AS [OwnerMail], t.[Criticality] AS [Criticality], t.[DataSensitivity] AS [DataSensitivity], t.[Environment] AS [Environment], t.[Department] AS [Department], t.[ExtraJson] AS [ExtraJson], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy], t.[RetiredAt] AS [RetiredAt], t.[RetiredBy] AS [RetiredBy], t.[RetireReason] AS [RetireReason] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.CmdbService AS t WHERE t.[RetiredAt] IS NULL
UNION ALL
SELECT N''cmdblink'' AS Entity, LEFT(CONCAT(t.[ServiceId], N''|'', t.[AssetKey]), 900) AS EntityKey, (SELECT t.[LinkId] AS [LinkId], t.[ServiceId] AS [ServiceId], t.[AssetKey] AS [AssetKey], t.[AssetName] AS [AssetName], t.[LinkedAt] AS [LinkedAt], t.[LinkedBy] AS [LinkedBy], t.[UnlinkedAt] AS [UnlinkedAt], t.[UnlinkedBy] AS [UnlinkedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.CmdbServiceAsset AS t WHERE t.[UnlinkedAt] IS NULL
UNION ALL
SELECT N''jobflow'' AS Entity, LEFT(CONCAT(t.[FlowId], N''''), 900) AS EntityKey, (SELECT t.[FlowId] AS [FlowId], t.[Mode] AS [Mode], t.[DefinitionJson] AS [DefinitionJson], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.JobFlow AS t
UNION ALL
SELECT N''mgmtreport'' AS Entity, LEFT(CONCAT(t.[ReportId], N''''), 900) AS EntityKey, (SELECT t.[ReportId] AS [ReportId], t.[Name] AS [Name], t.[Grain] AS [Grain], t.[Sections] AS [Sections], t.[Recipients] AS [Recipients], t.[Cadence] AS [Cadence], t.[Day] AS [Day], t.[TimeUtc] AS [TimeUtc], t.[Enabled] AS [Enabled], t.[CreatedAt] AS [CreatedAt], t.[CreatedBy] AS [CreatedBy], t.[UpdatedAt] AS [UpdatedAt], t.[UpdatedBy] AS [UpdatedBy], t.[RemovedAt] AS [RemovedAt] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.MgmtReport AS t WHERE t.[RemovedAt] IS NULL
UNION ALL
SELECT N''pivotview'' AS Entity, LEFT(CONCAT(t.[Owner], N''|'', t.[Name]), 900) AS EntityKey, (SELECT t.[ViewId] AS [ViewId], t.[Name] AS [Name], t.[Owner] AS [Owner], t.[Shared] AS [Shared], t.[State] AS [State], t.[CreatedAt] AS [CreatedAt], t.[UpdatedAt] AS [UpdatedAt], t.[RemovedAt] AS [RemovedAt], t.[RemovedBy] AS [RemovedBy] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS RecordJson FROM cfg.PivotView AS t WHERE t.[RemovedAt] IS NULL');

-- <<< GENERATED CONFIG JOURNAL
