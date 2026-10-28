-- si-cmdbsync-schema.sql -- the SQL CMDB CONNECTOR, SecurityInsight Pro (#271).
--
-- Every asset (CI) SecurityInsight knows, written by the job caj-si-asset-cmdb-sql
-- (engine/asset-cmdb/Invoke-SICmdbSql.ps1) into SI's own Pro database -- the twin of the SQL vulnerability connector
-- (#195): plan first, never from a partial snapshot, absence over N runs before a CI is retired, and NOTHING IS EVER
-- DELETED (a CI that is gone is retired and keeps its history; one that comes back is reactivated).
--
-- THE SHAPE:
--   ConfigurationItem            one row per CI key: the identity ledger's SI_CorrelationId when the correlation map
--                                carries a LEDGER id for the asset, else SI_AssetId -- the data backend's key
--                                (sidata.Asset.AssetKey), so a CI joins the findings, departments and services
--   ConfigurationItemIdentifier  every identifier the correlation map knows for the CI; a vanished one is stamped
--                                RemovedAt, never removed
--   ConfigurationItemService     the CI's business services; a link that no longer holds is stamped UnlinkedAt
--   ConfigurationItemHistory     what changed, when and in which run (created / updated per field / retired / reactivated)
--   SyncRun                      one row per run: the snapshot it read, the counts, the outcome and why
--   SyncStage                    the planned changes of a run in flight; applied in ONE transaction and then cleared
--   vConfigurationItem           the reporting view (Power BI): one row per CI, identifiers as "type:value; ..."
--
-- KINDS: endpoint and azure by default -- the ServiceNow CMDB connector's rule (engine/asset-cmdb/Invoke-SICmdb.ps1,
-- SERVICENOW-CMDB-SCHEMA §4): whether an Entra identity is a CI is unsettled, so identity is never written here;
-- a public IP is a property in that model and is written here only when SI_Pro_CmdbSql_Kinds lists 'publicip'.
--
-- GRANTS: none in this file. The job's identity writes through db_datawriter (Bootstrap prints the statement for it);
-- the web app's identity reads through db_datareader, which it already holds in the Pro database.
--
-- ADDITIVE AND IDEMPOTENT ONLY: every statement is guarded, so re-running is a no-op, and no destructive verb appears in
-- this file (Test-SISchemaIsAdditive refuses one). Applied by setup\Initialize-SIDataSql.ps1 together with
-- si-data-schema.sql. A later change to the view ships as a NEW view name, never as an ALTER of this one. The ONE
-- exception: a column APPENDED to a ServiceNow import view (snowstage.vImportCi u_data_sensitivity, u_si_state; snowstage.vImportVulnerableItem), guarded, every
-- earlier column unchanged and in place -- see the statement and SIv3-SnowHandoffSql.Tests.ps1, which holds it to that.

IF SCHEMA_ID('cmdbsync') IS NULL EXEC ('CREATE SCHEMA cmdbsync');

-- ---------------------------------------------------------------------------------------------
-- SyncRun: one row per run of the connector (a plan-only run writes nothing, so it has none).
--   Outcome  applied  -- the plan was written (created / updated / ... may all be 0)
--            refused  -- the snapshot was not shown complete, or a guard held the run: NOTHING was changed; Reason says why
--            error    -- the run failed; nothing of its plan was written (the apply is one transaction)
--   SnapshotKey  per kind, the newest snapshot the run read ("azure=2026-10-04T05:00:00Z; endpoint=..."): a run that
--                reads the SAME snapshot as the last applied one counts no absence
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.SyncRun') IS NULL
CREATE TABLE cmdbsync.SyncRun (
    SyncRunId        BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CmdbSyncRun PRIMARY KEY,
    RunId            NVARCHAR(64)   NOT NULL,
    StartedAt        DATETIME2(3)   NOT NULL,
    EndedAt          DATETIME2(3)   NULL,
    Outcome          NVARCHAR(16)   NOT NULL,
    Reason           NVARCHAR(1000) NULL,
    SnapshotKey      NVARCHAR(400)  NULL,
    Kinds            NVARCHAR(100)  NULL,
    RetireAfterRuns  INT            NULL,
    Desired          INT            NULL,
    Created          INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Created DEFAULT 0,
    Updated          INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Updated DEFAULT 0,
    Unchanged        INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Unchanged DEFAULT 0,
    Absent           INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Absent DEFAULT 0,
    Retired          INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Retired DEFAULT 0,
    Reactivated      INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Reactivated DEFAULT 0,
    Held             INT            NOT NULL CONSTRAINT DF_CmdbSyncRun_Held DEFAULT 0,
    SolutionVersion  NVARCHAR(64)   NULL,
    CONSTRAINT CK_CmdbSyncRun_Outcome CHECK (Outcome IN ('applied', 'refused', 'error'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_CmdbSyncRun_RunId' AND object_id = OBJECT_ID('cmdbsync.SyncRun'))
CREATE UNIQUE INDEX UX_CmdbSyncRun_RunId ON cmdbsync.SyncRun (RunId);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbSyncRun_Started' AND object_id = OBJECT_ID('cmdbsync.SyncRun'))
CREATE INDEX IX_CmdbSyncRun_Started ON cmdbsync.SyncRun (StartedAt DESC) INCLUDE (Outcome, SnapshotKey);

-- #914 THE ONE CONTRACT (ADDED 2026-10-27, in place, guarded): the run is a BATCH with the same words as the ServiceNow
-- staging status table. A run inserts its row FIRST with BatchState 'writing' (and Outcome 'error', Reason 'writing': a run
-- that never ends reads as an error); the apply's ONE transaction turns it into Outcome 'applied' + BatchState 'complete'
-- together with every CI change; refused = 'held', error = 'failed'. A 'writing' row of an earlier run is ended 'failed' when
-- the next run starts (never two open batches). Readers act ONLY on a 'complete' batch (snowstage.vImportBatch).
--   SiBatchId        '<run id>:cmdb-sql' -- the same id the CIs it wrote carry (ConfigurationItem.SiBatchId)
--   ContractVersion  the data contract's version ('1'; add only -- a rename or a removal needs a new version)
--   Mode             live | resync
--   OutOfScope       the CIs the asset scope left out (left exactly as they are)
--   LandedRows       what the apply statement wrote (the CI rows created, updated, reactivated, counted absent or retired)
-- The existing counts are kept: Created (= new), Updated (= update), Reactivated (= reopen), Retired (= close), Held.
IF COL_LENGTH('cmdbsync.SyncRun', 'SiBatchId') IS NULL ALTER TABLE cmdbsync.SyncRun ADD SiBatchId NVARCHAR(100) NULL;
IF COL_LENGTH('cmdbsync.SyncRun', 'BatchState') IS NULL ALTER TABLE cmdbsync.SyncRun ADD BatchState NVARCHAR(16) NULL;
IF COL_LENGTH('cmdbsync.SyncRun', 'ContractVersion') IS NULL ALTER TABLE cmdbsync.SyncRun ADD ContractVersion NVARCHAR(16) NULL;
IF COL_LENGTH('cmdbsync.SyncRun', 'Mode') IS NULL ALTER TABLE cmdbsync.SyncRun ADD Mode NVARCHAR(16) NULL;
IF COL_LENGTH('cmdbsync.SyncRun', 'OutOfScope') IS NULL ALTER TABLE cmdbsync.SyncRun ADD OutOfScope INT NULL;
IF COL_LENGTH('cmdbsync.SyncRun', 'LandedRows') IS NULL ALTER TABLE cmdbsync.SyncRun ADD LandedRows INT NULL;

-- ---------------------------------------------------------------------------------------------
-- ConfigurationItem: the CI, current state. AbsentRuns counts the complete runs in a row the CI was not seen; at
-- SI_Pro_CmdbSql_RetireAfterRuns it is retired (State 'retired', RetiredAt). Seen again = reactivated, AbsentRuns 0.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.ConfigurationItem') IS NULL
CREATE TABLE cmdbsync.ConfigurationItem (
    CiKey            NVARCHAR(400)  NOT NULL CONSTRAINT PK_CmdbConfigurationItem PRIMARY KEY,
    KeySource        NVARCHAR(16)   NOT NULL,   -- 'ledger' (SI_CorrelationId) | 'asset' (SI_AssetId)
    Name             NVARCHAR(400)  NULL,
    Kind             NVARCHAR(16)   NOT NULL,   -- endpoint | azure | publicip (the CI's most descriptive source)
    Tier             TINYINT        NULL,       -- 0 (most critical) .. 3
    Criticality      NVARCHAR(32)   NULL,       -- a profile rule's override, else the most critical of the CI's business services
    Owner            NVARCHAR(256)  NULL,
    OwnerMail        NVARCHAR(256)  NULL,
    Department       NVARCHAR(128)  NULL,
    Services         NVARCHAR(2000) NULL,       -- the service names, most critical first, "; "-separated
    Sources          NVARCHAR(200)  NULL,       -- the kinds that saw the CI, "; "-separated
    FirstSeen        DATETIME2(3)   NOT NULL,
    LastSeen         DATETIME2(3)   NOT NULL,
    State            NVARCHAR(16)   NOT NULL CONSTRAINT DF_CmdbConfigurationItem_State DEFAULT 'active',
    AbsentRuns       INT            NOT NULL CONSTRAINT DF_CmdbConfigurationItem_AbsentRuns DEFAULT 0,
    RetiredAt        DATETIME2(3)   NULL,
    CreatedAt        DATETIME2(0)   NOT NULL CONSTRAINT DF_CmdbConfigurationItem_CreatedAt DEFAULT SYSUTCDATETIME(),
    LastChangedAt    DATETIME2(3)   NOT NULL,
    LastRunId        NVARCHAR(64)   NOT NULL,
    CONSTRAINT CK_CmdbConfigurationItem_State CHECK (State IN ('active', 'retired')),
    CONSTRAINT CK_CmdbConfigurationItem_KeySource CHECK (KeySource IN ('ledger', 'asset')),
    CONSTRAINT CK_CmdbConfigurationItem_Kind CHECK (Kind IN ('endpoint', 'azure', 'publicip'))
);

-- DataSensitivity (2026-10-05): the CI's data sensitivity, with the same precedence as Criticality -- a profile rule's
-- override wins over the CMDB record, field by field (then the most critical service that names one). Added IN PLACE,
-- guarded, so re-running is a no-op; the connector writes it only where the column exists.
IF COL_LENGTH('cmdbsync.ConfigurationItem', 'DataSensitivity') IS NULL
ALTER TABLE cmdbsync.ConfigurationItem ADD DataSensitivity NVARCHAR(32) NULL;

-- #914 SiBatchId: the batch (cmdbsync.SyncRun.SiBatchId) that last wrote the CI -- created, updated, reactivated, counted
-- absent or retired. Added in place, guarded; NULL on a CI written before. The connector writes it where the column exists.
IF COL_LENGTH('cmdbsync.ConfigurationItem', 'SiBatchId') IS NULL
ALTER TABLE cmdbsync.ConfigurationItem ADD SiBatchId NVARCHAR(100) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbConfigurationItem_State' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItem'))
CREATE INDEX IX_CmdbConfigurationItem_State ON cmdbsync.ConfigurationItem (State, Kind) INCLUDE (Name, Tier, Department, LastSeen);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbConfigurationItem_Name' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItem'))
CREATE INDEX IX_CmdbConfigurationItem_Name ON cmdbsync.ConfigurationItem (Name);

-- ---------------------------------------------------------------------------------------------
-- ConfigurationItemIdentifier: the CI's identifiers (MDE device id, ARM id, Entra device id, ... and SI_AssetId itself),
-- lower-cased as published. RemovedAt = the run that no longer saw it; seen again = a new row.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.ConfigurationItemIdentifier') IS NULL
CREATE TABLE cmdbsync.ConfigurationItemIdentifier (
    CiIdentifierId   BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CmdbCiIdentifier PRIMARY KEY,
    CiKey            NVARCHAR(400)  NOT NULL,
    IdentifierType   NVARCHAR(64)   NOT NULL,
    IdentifierValue  NVARCHAR(256)  NOT NULL,
    FirstSeen        DATETIME2(3)   NOT NULL,
    LastSeen         DATETIME2(3)   NOT NULL,
    RemovedAt        DATETIME2(3)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_CmdbCiIdentifier_Current' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItemIdentifier'))
CREATE UNIQUE INDEX UX_CmdbCiIdentifier_Current ON cmdbsync.ConfigurationItemIdentifier (CiKey, IdentifierType, IdentifierValue) WHERE RemovedAt IS NULL;

-- reverse lookup: which CI carries this identifier
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbCiIdentifier_Value' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItemIdentifier'))
CREATE INDEX IX_CmdbCiIdentifier_Value ON cmdbsync.ConfigurationItemIdentifier (IdentifierValue, IdentifierType) INCLUDE (CiKey) WHERE RemovedAt IS NULL;

-- ---------------------------------------------------------------------------------------------
-- ConfigurationItemService: the CI's business services (the authoritative CMDB's links, else the service Risk
-- Analysis carried for it). ServiceKey = the service number (SVC-0001) or the source's id.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.ConfigurationItemService') IS NULL
CREATE TABLE cmdbsync.ConfigurationItemService (
    CiServiceId      BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CmdbCiService PRIMARY KEY,
    CiKey            NVARCHAR(400)  NOT NULL,
    ServiceKey       NVARCHAR(256)  NOT NULL,
    ServiceName      NVARCHAR(400)  NULL,
    Source           NVARCHAR(32)   NULL,
    LinkedAt         DATETIME2(3)   NOT NULL,
    UnlinkedAt       DATETIME2(3)   NULL,
    LinkedRunId      NVARCHAR(64)   NOT NULL,
    UnlinkedRunId    NVARCHAR(64)   NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_CmdbCiService_Current' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItemService'))
CREATE UNIQUE INDEX UX_CmdbCiService_Current ON cmdbsync.ConfigurationItemService (CiKey, ServiceKey) WHERE UnlinkedAt IS NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbCiService_Service' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItemService'))
CREATE INDEX IX_CmdbCiService_Service ON cmdbsync.ConfigurationItemService (ServiceKey) INCLUDE (CiKey, ServiceName) WHERE UnlinkedAt IS NULL;

-- ---------------------------------------------------------------------------------------------
-- ConfigurationItemHistory: one row per change. Change created | updated | retired | reactivated; for 'updated' one row
-- per field with its old and new value (Field 'Identifiers' / 'Services' hold the whole "; "-separated set).
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.ConfigurationItemHistory') IS NULL
CREATE TABLE cmdbsync.ConfigurationItemHistory (
    HistoryId        BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CmdbCiHistory PRIMARY KEY,
    CiKey            NVARCHAR(400)  NOT NULL,
    RunId            NVARCHAR(64)   NOT NULL,
    ChangedAt        DATETIME2(3)   NOT NULL,
    Change           NVARCHAR(16)   NOT NULL,
    Field            NVARCHAR(64)   NULL,
    OldValue         NVARCHAR(4000) NULL,
    NewValue         NVARCHAR(4000) NULL,
    CONSTRAINT CK_CmdbCiHistory_Change CHECK (Change IN ('created', 'updated', 'retired', 'reactivated'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbCiHistory_Ci' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItemHistory'))
CREATE INDEX IX_CmdbCiHistory_Ci ON cmdbsync.ConfigurationItemHistory (CiKey, ChangedAt) INCLUDE (Change, Field);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbCiHistory_Run' AND object_id = OBJECT_ID('cmdbsync.ConfigurationItemHistory'))
CREATE INDEX IX_CmdbCiHistory_Run ON cmdbsync.ConfigurationItemHistory (RunId);

-- ---------------------------------------------------------------------------------------------
-- SyncStage: a run's planned changes travel here in chunks (one JSON array per row) and are applied from here in ONE
-- transaction, which then clears the run's rows. A run that died leaves its rows; the next run clears them first.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.SyncStage') IS NULL
CREATE TABLE cmdbsync.SyncStage (
    RunId            NVARCHAR(64)   NOT NULL,
    Seq              INT            NOT NULL,
    Json             NVARCHAR(MAX)  NOT NULL,
    StagedAt         DATETIME2(0)   NOT NULL CONSTRAINT DF_CmdbSyncStage_StagedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_CmdbSyncStage PRIMARY KEY (RunId, Seq),
    CONSTRAINT CK_CmdbSyncStage_Json CHECK (ISJSON(Json) = 1)
);

-- ---------------------------------------------------------------------------------------------
-- AN ASSET SECURITYINSIGHT NO LONGER SEES (#406, operator decisions 2026-10-06). One row per CI KEY -- devices, Azure
-- resources AND identities (the key every hand-off carries, engine\_shared\data-sql\SI-CiKey.ps1) -- written by the SQL
-- CMDB job (engine\asset-cmdb\_shared\SI-AssetLifecycle.ps1):
--   active    seen by its profile within SI_Pro_CmdbSql_SeenWithinDays (8)
--   not-seen  not seen for longer than that, but still inside the grace period of its CATEGORY
--   retired   not seen for longer than the grace period (automatic, audited), or retired early by an Admin on the web
--             app's "Not seen anymore" page; seen again = active again (audited)
-- The grace period is a Pro setting per category (client-pc, server, service-principal, user, azure-vm, azure-resource;
-- default 30 days each: SI_Pro_AssetRetire_GraceDays and SI_Pro_AssetRetire_GraceDays_<Category>). LastSeen is KEPT here and
-- only ever moves forward, so "not seen for 31 days" is known even when Log Analytics holds less.
-- Consumers: the vulnerability close-loop closes the open findings of a retired asset as AssetRetired (never as fixed) and
-- reopens them when it comes back; the SQL CMDB connector retires its CI; the ServiceNow hand-off carries the state as
-- u_si_state (snowstage.HandoffCi.SiState) and moves u_changed_at on a change. SecurityInsight never retires or deletes a
-- CI in ServiceNow. Nothing here is ever deleted.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.AssetLifecycle') IS NULL
CREATE TABLE cmdbsync.AssetLifecycle (
    CiKey            NVARCHAR(400)  NOT NULL CONSTRAINT PK_CmdbAssetLifecycle PRIMARY KEY,
    Kind             NVARCHAR(16)   NULL,       -- endpoint | azure | identity; NULL = known only from its open findings
    ClassHint        NVARCHAR(16)   NULL,       -- device | azure-resource | identity
    Category         NVARCHAR(32)   NOT NULL,   -- client-pc | server | service-principal | user | azure-vm | azure-resource | other
    Name             NVARCHAR(400)  NULL,
    FirstSeen        DATETIME2(3)   NOT NULL,
    LastSeen         DATETIME2(3)   NOT NULL,   -- the newest sighting by any of the CI's profiles; never moves back
    State            NVARCHAR(16)   NOT NULL,   -- active | not-seen | retired
    StateChangedAt   DATETIME2(3)   NOT NULL,
    GraceDays        INT            NOT NULL,   -- the grace period of its category when last evaluated
    RetireAt         DATETIME2(3)   NULL,       -- LastSeen + GraceDays: when it retires unless it is seen again
    RetiredAt        DATETIME2(3)   NULL,
    RetiredBy        NVARCHAR(256)  NULL,       -- 'SecurityInsight (grace period)' or the Admin who retired it early
    RetireReason     NVARCHAR(400)  NULL,
    LastRunId        NVARCHAR(64)   NULL,
    UpdatedAt        DATETIME2(3)   NOT NULL CONSTRAINT DF_CmdbAssetLifecycle_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_CmdbAssetLifecycle_State CHECK (State IN ('active', 'not-seen', 'retired'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbAssetLifecycle_State' AND object_id = OBJECT_ID('cmdbsync.AssetLifecycle'))
CREATE INDEX IX_CmdbAssetLifecycle_State ON cmdbsync.AssetLifecycle (State, Category) INCLUDE (Name, LastSeen, RetireAt, RetiredAt);

-- every state change, append-only: the job's and an Admin's alike
IF OBJECT_ID('cmdbsync.AssetLifecycleEvent') IS NULL
CREATE TABLE cmdbsync.AssetLifecycleEvent (
    EventId          BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_CmdbAssetLifecycleEvent PRIMARY KEY,
    CiKey            NVARCHAR(400)  NOT NULL,
    Change           NVARCHAR(16)   NOT NULL,   -- not-seen | retired | retired-early | reactivated
    FromState        NVARCHAR(16)   NULL,
    ToState          NVARCHAR(16)   NOT NULL,
    Reason           NVARCHAR(400)  NULL,
    Actor            NVARCHAR(256)  NOT NULL,
    RunId            NVARCHAR(64)   NULL,
    [At]             DATETIME2(3)   NOT NULL CONSTRAINT DF_CmdbAssetLifecycleEvent_At DEFAULT SYSUTCDATETIME()
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CmdbAssetLifecycleEvent_Ci' AND object_id = OBJECT_ID('cmdbsync.AssetLifecycleEvent'))
CREATE INDEX IX_CmdbAssetLifecycleEvent_Ci ON cmdbsync.AssetLifecycleEvent (CiKey, [At]) INCLUDE (Change, ToState);
-- ---------------------------------------------------------------------------------------------
-- THE REPORTING VIEW (Power BI). Created through EXEC because CREATE VIEW must start its own batch.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('cmdbsync.vConfigurationItem') IS NULL
EXEC ('CREATE VIEW cmdbsync.vConfigurationItem AS
SELECT c.CiKey, c.KeySource, c.Name, c.Kind, c.Tier, c.Criticality, c.Owner, c.OwnerMail, c.Department, c.Services, c.Sources,
       (SELECT STRING_AGG(CAST(i.IdentifierType + N'':'' + i.IdentifierValue AS NVARCHAR(MAX)), N''; '')
          FROM cmdbsync.ConfigurationItemIdentifier i WHERE i.CiKey = c.CiKey AND i.RemovedAt IS NULL) AS Identifiers,
       c.FirstSeen, c.LastSeen, c.State, c.AbsentRuns, c.RetiredAt, c.LastChangedAt, c.LastRunId, r.StartedAt AS LastRunAt
FROM cmdbsync.ConfigurationItem c
LEFT JOIN cmdbsync.SyncRun r ON r.RunId = c.LastRunId');

-- =============================================================================================
-- THE SERVICENOW HAND-OFF (#300) -- schema snowstage. STAGING, NOT A CMDB.
--
-- SecurityInsight never writes a ServiceNow CI or vulnerable item by default. It delivers here, and ServiceNow's own
-- machinery pulls: a JDBC data source on the customer's MID Server reads the vImport* views into an Import Set table,
-- and the customer's transform map / IntegrationHub ETL hands each row to IRE (discovery source "SecurityInsight") or
-- to the Vulnerability Response import. Every rule that changes a CI is the customer's.
--
--   HandoffCi          one row per CI key (SI_CorrelationId), ALL THREE kinds: device | azure-resource | identity
--   HandoffCiKeyValue  the CI's key-values (Azure tags, Defender machine tags); a vanished one is stamped RemovedAt
--   HandoffCiRelation  the CI's relations from the ARM properties (VM -> disk / NIC / user-assigned identity)
--   vImportCi, vImportCiKeyValue, vImportCiRelation   import-ready: every column is the Import Set column (u_*), 1:1
--                      with the documented transform map (SERVICENOW-CMDB-SCHEMA.md)
--   vProposedCi        assets SI sees that no CMDB CI is known to match, with the correlation evidence -- a REPORT for
--                      the customer's CMDB team, never a create (option 1: SI creates no CI)
--
-- DELTA: every view carries u_changed_at. It moves only when the CI's content changed (u_row_hash), not when it was
-- merely seen again, so a data source filtered "u_changed_at > last run" sends only what changed.
-- The tables are filled by engine\asset-cmdb\_shared\SI-CmdbHandoff.ps1 (Write-SIHandoffRows); the column contract is
-- Get-SIHandoffColumnContract there, and a test holds these views to it.
-- =============================================================================================
IF SCHEMA_ID('snowstage') IS NULL EXEC ('CREATE SCHEMA snowstage');

IF OBJECT_ID('snowstage.HandoffCi') IS NULL
CREATE TABLE snowstage.HandoffCi (
    CiKey            NVARCHAR(400)  NOT NULL CONSTRAINT PK_SnowHandoffCi PRIMARY KEY,
    IdSource         NVARCHAR(16)   NOT NULL,   -- ledger | provisional | asset
    ClassHint        NVARCHAR(16)   NOT NULL,   -- device | azure-resource | identity
    ProposedClass    NVARCHAR(80)   NULL,       -- the ServiceNow class SI proposes; the transform map decides
    Name             NVARCHAR(400)  NULL,
    Fqdn             NVARCHAR(400)  NULL,
    DnsDomain        NVARCHAR(256)  NULL,
    SerialNumber     NVARCHAR(128)  NULL,
    MacAddress       NVARCHAR(64)   NULL,
    ObjectId         NVARCHAR(512)  NULL,       -- Azure vmId for a VM, else the ARM resource id; the Entra object id for an identity
    AzureResourceId  NVARCHAR(512)  NULL,
    AadDeviceId      NVARCHAR(64)   NULL,
    MdeDeviceId      NVARCHAR(64)   NULL,
    EntraObjectId    NVARCHAR(64)   NULL,
    Tier             TINYINT        NULL,
    TierReason       NVARCHAR(512)  NULL,
    Criticality      NVARCHAR(32)   NULL,
    ExposedInternet  BIT            NULL,
    CmdbMatch        NVARCHAR(16)   NOT NULL CONSTRAINT DF_SnowHandoffCi_CmdbMatch DEFAULT 'unknown',  -- matched | unmatched | unknown
    Evidence         NVARCHAR(2000) NULL,       -- which identifiers the correlation rests on
    LastSeen         DATETIME2(3)   NULL,
    SourceRun        NVARCHAR(64)   NULL,
    RunTime          DATETIME2(3)   NOT NULL,
    RowHash          NVARCHAR(64)   NOT NULL,   -- SHA-256 of the content (not of LastSeen / the run)
    ChangedAt        DATETIME2(3)   NOT NULL,   -- moves only when RowHash moves: the delta column
    CONSTRAINT CK_SnowHandoffCi_ClassHint CHECK (ClassHint IN ('device', 'azure-resource', 'identity')),
    CONSTRAINT CK_SnowHandoffCi_CmdbMatch CHECK (CmdbMatch IN ('matched', 'unmatched', 'unknown'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SnowHandoffCi_Changed' AND object_id = OBJECT_ID('snowstage.HandoffCi'))
CREATE INDEX IX_SnowHandoffCi_Changed ON snowstage.HandoffCi (ChangedAt) INCLUDE (ClassHint, CmdbMatch);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SnowHandoffCi_Resource' AND object_id = OBJECT_ID('snowstage.HandoffCi'))
CREATE INDEX IX_SnowHandoffCi_Resource ON snowstage.HandoffCi (AzureResourceId) INCLUDE (CiKey, ClassHint) WHERE AzureResourceId IS NOT NULL;

-- DataSensitivity (2026-10-05, #389): the asset's EFFECTIVE data sensitivity from its profile row (your asset-profile rule's
-- override wins over the CMDB record). Added IN PLACE, guarded; part of the row hash when set, so a change moves u_changed_at.
IF COL_LENGTH('snowstage.HandoffCi', 'DataSensitivity') IS NULL
ALTER TABLE snowstage.HandoffCi ADD DataSensitivity NVARCHAR(32) NULL;

-- SiState (2026-10-06, #406): the CI's state in SecurityInsight -- active | not-seen | retired (cmdbsync.AssetLifecycle). A change
-- moves ChangedAt, so a delta import sees it; NULL until the first lifecycle run (read as active, never a change).
IF COL_LENGTH('snowstage.HandoffCi', 'SiState') IS NULL
ALTER TABLE snowstage.HandoffCi ADD SiState NVARCHAR(16) NULL;

-- SiAssetType / SiAssetSubtype (2026-10-11, #562): the asset's SI type and subtype from the ONE classification (the profile row,
-- data-model/classification.locked.json -- e.g. Server / SQL Server, Database / SQL Database). Added IN PLACE, guarded; part of
-- the row hash when set, so the first run that carries them moves u_changed_at once.
IF COL_LENGTH('snowstage.HandoffCi', 'SiAssetType') IS NULL
ALTER TABLE snowstage.HandoffCi ADD SiAssetType NVARCHAR(64) NULL;
IF COL_LENGTH('snowstage.HandoffCi', 'SiAssetSubtype') IS NULL
ALTER TABLE snowstage.HandoffCi ADD SiAssetSubtype NVARCHAR(64) NULL;

-- SiBatchId / LastAction / Cleared (2026-10-27, #914): the database route carries the push's contract. SiBatchId = the batch
-- id of the hand-off batch that last wrote the row (<run>:cmdb-handoff, its snowstage.HandoffRun row); LastAction = new when that run
-- inserted it, reopen when its lifecycle step brought a retired CI back (NULL otherwise -- the view reads close from the state
-- and update for the rest); Cleared = u_si_cleared, the clearable columns the row carries empty. Added IN PLACE, guarded.
IF COL_LENGTH('snowstage.HandoffCi', 'SiBatchId') IS NULL
ALTER TABLE snowstage.HandoffCi ADD SiBatchId NVARCHAR(100) NULL;
IF COL_LENGTH('snowstage.HandoffCi', 'LastAction') IS NULL
ALTER TABLE snowstage.HandoffCi ADD LastAction NVARCHAR(16) NULL;
IF COL_LENGTH('snowstage.HandoffCi', 'Cleared') IS NULL
ALTER TABLE snowstage.HandoffCi ADD Cleared NVARCHAR(1000) NULL;

IF OBJECT_ID('snowstage.HandoffCiKeyValue') IS NULL
CREATE TABLE snowstage.HandoffCiKeyValue (
    CiKeyValueId     BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_SnowHandoffCiKeyValue PRIMARY KEY,
    CiKey            NVARCHAR(400)  NOT NULL,
    Source           NVARCHAR(32)   NOT NULL,   -- azure-tag | mde-tag
    KeyName          NVARCHAR(256)  NOT NULL,
    Value            NVARCHAR(2000) NULL,
    RemovedAt        DATETIME2(3)   NULL,
    ChangedAt        DATETIME2(3)   NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SnowHandoffCiKeyValue_Key' AND object_id = OBJECT_ID('snowstage.HandoffCiKeyValue'))
CREATE UNIQUE INDEX UX_SnowHandoffCiKeyValue_Key ON snowstage.HandoffCiKeyValue (CiKey, Source, KeyName);

IF OBJECT_ID('snowstage.HandoffCiRelation') IS NULL
CREATE TABLE snowstage.HandoffCiRelation (
    CiRelationId     BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_SnowHandoffCiRelation PRIMARY KEY,
    ParentKey        NVARCHAR(400)  NOT NULL,
    ChildObjectId    NVARCHAR(512)  NOT NULL,   -- the ARM id of the disk / NIC / identity, lower-cased
    ChildClassHint   NVARCHAR(80)   NULL,       -- the class SI proposes for the child
    RelationType     NVARCHAR(80)   NOT NULL,   -- a ServiceNow cmdb_rel_type name, e.g. 'Uses::Used by'
    Source           NVARCHAR(32)   NOT NULL,   -- arm
    RemovedAt        DATETIME2(3)   NULL,
    ChangedAt        DATETIME2(3)   NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SnowHandoffCiRelation_Pair' AND object_id = OBJECT_ID('snowstage.HandoffCiRelation'))
CREATE UNIQUE INDEX UX_SnowHandoffCiRelation_Pair ON snowstage.HandoffCiRelation (ParentKey, ChildObjectId, RelationType);

IF OBJECT_ID('snowstage.vImportCi') IS NULL
EXEC ('CREATE VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, COALESCE(h.Criticality, c.Criticality) AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       COALESCE(h.DataSensitivity, c.DataSensitivity) AS u_data_sensitivity,
       h.SiState AS u_si_state, h.SiAssetType AS u_si_asset_type, h.SiAssetSubtype AS u_si_asset_subtype,
       h.SiBatchId AS u_si_batch_id, COALESCE(CASE WHEN h.SiState = N''retired'' THEN N''close'' END, h.LastAction, N''update'') AS u_action, h.Cleared AS u_si_cleared
FROM snowstage.HandoffCi h
LEFT JOIN cmdbsync.ConfigurationItem c ON c.CiKey = h.CiKey');

-- u_data_sensitivity (2026-10-05, #389): a database whose vImportCi was created before the column gets it APPENDED in place --
-- the one change an import view takes without a new name, because ServiceNow's import set maps by column name: every
-- earlier column keeps its name, its value and its position, so an existing data source and transform map read exactly
-- what they read before. Any other change to a view still ships as a new view name. Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_data_sensitivity') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, COALESCE(h.Criticality, c.Criticality) AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       COALESCE(h.DataSensitivity, c.DataSensitivity) AS u_data_sensitivity
FROM snowstage.HandoffCi h
LEFT JOIN cmdbsync.ConfigurationItem c ON c.CiKey = h.CiKey');

-- u_si_state (2026-10-06, #406): the CI's state in SecurityInsight (active / not-seen / retired) APPENDED in place, the same way
-- as u_data_sensitivity: every earlier column keeps its name, its value and its position. Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_si_state') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL AND COL_LENGTH('snowstage.HandoffCi', 'SiState') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, COALESCE(h.Criticality, c.Criticality) AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       COALESCE(h.DataSensitivity, c.DataSensitivity) AS u_data_sensitivity,
       h.SiState AS u_si_state
FROM snowstage.HandoffCi h
LEFT JOIN cmdbsync.ConfigurationItem c ON c.CiKey = h.CiKey');

-- u_si_asset_type / u_si_asset_subtype (2026-10-11, #562): the asset's SI type and subtype, right after u_si_state, the same way
-- (ServiceNow's import set maps by column name: every earlier column keeps its name and value). Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_si_asset_subtype') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL AND COL_LENGTH('snowstage.HandoffCi', 'SiAssetSubtype') IS NOT NULL AND COL_LENGTH('snowstage.HandoffCi', 'SiState') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, COALESCE(h.Criticality, c.Criticality) AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       COALESCE(h.DataSensitivity, c.DataSensitivity) AS u_data_sensitivity,
       h.SiState AS u_si_state, h.SiAssetType AS u_si_asset_type, h.SiAssetSubtype AS u_si_asset_subtype
FROM snowstage.HandoffCi h
LEFT JOIN cmdbsync.ConfigurationItem c ON c.CiKey = h.CiKey');

-- u_si_batch_id / u_action / u_si_cleared (2026-10-27, #914): the one contract on the database route, APPENDED after
-- u_si_asset_subtype the same way (every earlier column keeps its name, value and place). Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_si_cleared') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL AND COL_LENGTH('snowstage.HandoffCi', 'Cleared') IS NOT NULL AND COL_LENGTH('snowstage.HandoffCi', 'SiAssetSubtype') IS NOT NULL AND COL_LENGTH('snowstage.HandoffCi', 'SiState') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, COALESCE(h.Criticality, c.Criticality) AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       COALESCE(h.DataSensitivity, c.DataSensitivity) AS u_data_sensitivity,
       h.SiState AS u_si_state, h.SiAssetType AS u_si_asset_type, h.SiAssetSubtype AS u_si_asset_subtype,
       h.SiBatchId AS u_si_batch_id, COALESCE(CASE WHEN h.SiState = N''retired'' THEN N''close'' END, h.LastAction, N''update'') AS u_action, h.Cleared AS u_si_cleared
FROM snowstage.HandoffCi h
LEFT JOIN cmdbsync.ConfigurationItem c ON c.CiKey = h.CiKey');

IF OBJECT_ID('snowstage.vImportCiKeyValue') IS NULL
EXEC ('CREATE VIEW snowstage.vImportCiKeyValue AS
SELECT k.CiKey AS u_si_correlation_id, k.KeyName AS u_key, k.Value AS u_value, k.Source AS u_source,
       CAST(CASE WHEN k.RemovedAt IS NULL THEN N''present'' ELSE N''removed'' END AS NVARCHAR(16)) AS u_state, k.ChangedAt AS u_changed_at
FROM snowstage.HandoffCiKeyValue k');

IF OBJECT_ID('snowstage.vImportCiRelation') IS NULL
EXEC ('CREATE VIEW snowstage.vImportCiRelation AS
SELECT r.ParentKey AS u_parent_correlation_id, c.CiKey AS u_child_correlation_id, r.ChildObjectId AS u_child_object_id,
       r.ChildClassHint AS u_child_class_hint, r.RelationType AS u_relation_type, r.Source AS u_source,
       CAST(CASE WHEN r.RemovedAt IS NULL THEN N''present'' ELSE N''removed'' END AS NVARCHAR(16)) AS u_state, r.ChangedAt AS u_changed_at
FROM snowstage.HandoffCiRelation r
LEFT JOIN snowstage.HandoffCi c ON c.AzureResourceId = r.ChildObjectId');

IF OBJECT_ID('snowstage.vProposedCi') IS NULL
EXEC ('CREATE VIEW snowstage.vProposedCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.SerialNumber AS u_serial_number, h.AzureResourceId AS u_azure_resource_id,
       h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id, h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier,
       h.CmdbMatch AS u_cmdb_match, h.Evidence AS u_evidence,
       CAST(CASE WHEN h.CmdbMatch = N''unmatched'' THEN N''SecurityInsight sees this asset and no CMDB CI matched it''
                 ELSE N''SecurityInsight sees this asset and it is not known to match a CMDB CI'' END
            + CASE WHEN h.IdSource <> N''ledger'' THEN N''; its correlation id is provisional, so it must not be created from yet'' ELSE N'''' END AS NVARCHAR(400)) AS u_reason,
       h.LastSeen AS u_last_seen, h.ChangedAt AS u_changed_at
FROM snowstage.HandoffCi h
WHERE h.CmdbMatch <> N''matched''');

-- =============================================================================================
-- ONE CI KEY (#406 / #409, 2026-10-06): this file re-states the vulnerability hand-off view WITH its join to the CI hand-off.
-- sql\si-vulnerability-target.sql is applied BEFORE this file (engine\pro-settings\SI-ProSchema.ps1), so on a fresh database
-- it creates snowstage.vImportVulnerableItem before snowstage.HandoffCi exists -- without the join, so u_class_hint could
-- only be guessed from the key. Now that the vulnerability rows carry the SAME CI key as the CI rows, the join resolves the
-- class: once both exist and the view has no join, it is re-stated with it -- the same columns, in the same order (the
-- text below is si-vulnerability-target.sql's own; SIv3-SnowHandoffSql.Tests.ps1 holds the two identical). Guarded: runs once.
-- =============================================================================================
IF OBJECT_ID('snowstage.vImportVulnerableItem') IS NOT NULL AND OBJECT_ID('snowstage.HandoffCi') IS NOT NULL
   AND COL_LENGTH('snowstage.vImportVulnerableItem', 'u_finding_type') IS NOT NULL
   AND COL_LENGTH('vuln.VulnerabilityItem', 'Component') IS NOT NULL
   AND COL_LENGTH('vuln.VulnerabilityItem', 'SubCi') IS NOT NULL
   AND COL_LENGTH('vuln.VulnerabilityItem', 'OsFamily') IS NOT NULL
   AND COL_LENGTH('vuln.VulnerabilityItem', 'PatchCycle') IS NOT NULL
   AND OBJECT_DEFINITION(OBJECT_ID('snowstage.vImportVulnerableItem')) NOT LIKE N'%snowstage.HandoffCi%'
EXEC ('ALTER VIEW snowstage.vImportVulnerableItem AS
SELECT v.CorrelationId AS u_si_correlation_id,
       CAST(COALESCE(h.ClassHint, CASE WHEN v.FindingType = N''identity'' THEN N''identity'' WHEN v.FindingType = N''azure-recommendation'' THEN N''azure-resource''
                                       WHEN v.CorrelationId LIKE N''/subscriptions/%'' THEN N''azure-resource''
                                       WHEN v.CorrelationId LIKE N''identity:%'' THEN N''identity'' ELSE N''device'' END) AS NVARCHAR(16)) AS u_class_hint,
       v.AssetName AS u_asset_name, v.CiId AS u_cmdb_ci, v.Cve AS u_vulnerability, v.Severity AS u_severity, v.State AS u_state,
       v.FirstSeen AS u_first_seen, v.LastSeen AS u_last_seen, v.ClosedAt AS u_closed_at, v.CloseReason AS u_close_reason,
       v.AbsentRuns AS u_absent_runs, v.Source AS u_source, CAST(v.SysId AS NVARCHAR(36)) AS u_source_record_id, v.UpdatedAt AS u_changed_at,
       v.FindingType AS u_finding_type, v.Title AS u_title, v.AssetId AS u_asset_id, v.Component AS u_si_component, v.SubCi AS u_si_servicenow_subci, v.OsFamily AS u_si_os_family, v.PatchCycle AS u_si_patch_cycle
FROM vuln.VulnerabilityItem v
LEFT JOIN snowstage.HandoffCi h ON h.CiKey = v.CorrelationId');

-- ---------------------------------------------------------------------------------------------
-- #914 THE ONE CONTRACT IN SECURITYINSIGHT'S OWN DATABASE (ADDED 2026-10-27, in place, guarded; LAST in this file, after
-- the re-statement above, so a re-statement can never leave the column out):
--   snowstage.vImportVulnerableItem  u_si_batch_id APPENDED -- the batch (vuln.SyncRun) that last changed the record; every
--                                    earlier column keeps its name, value and place
--   snowstage.vImportBatch           every batch of the two SQL connectors with its state and counts -- the same words as the
--                                    ServiceNow staging status table: u_si_batch_id, u_output (servicenow-ci for the CMDB SQL
--                                    connector, servicenow-vulnerable-item for the SQL vulnerability connector), u_state
--                                    (writing | complete | held | failed), the counts per action. Only where no other
--                                    vImportBatch is (a hand-off database keeps its own). THE RULE: import only rows whose
--                                    batch is complete.
-- ---------------------------------------------------------------------------------------------
-- #914 an existing database: u_si_batch_id, u_action and u_si_cleared APPENDED to the vulnerability view (guarded, runs once;
-- every earlier column keeps its name, value and place). The same text as the CREATE above, as ALTER.
IF COL_LENGTH('snowstage.vImportVulnerableItem', 'u_si_cleared') IS NULL AND OBJECT_ID('snowstage.vImportVulnerableItem') IS NOT NULL
   AND COL_LENGTH('vuln.VulnerabilityItem', 'Cleared') IS NOT NULL AND COL_LENGTH('vuln.VulnerabilityItem', 'PatchCycle') IS NOT NULL AND OBJECT_ID('snowstage.HandoffCi') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportVulnerableItem AS
SELECT v.CorrelationId AS u_si_correlation_id,
       CAST(COALESCE(h.ClassHint, CASE WHEN v.FindingType = N''identity'' THEN N''identity'' WHEN v.FindingType = N''azure-recommendation'' THEN N''azure-resource''
                                       WHEN v.CorrelationId LIKE N''/subscriptions/%'' THEN N''azure-resource''
                                       WHEN v.CorrelationId LIKE N''identity:%'' THEN N''identity'' ELSE N''device'' END) AS NVARCHAR(16)) AS u_class_hint,
       v.AssetName AS u_asset_name, v.CiId AS u_cmdb_ci, v.Cve AS u_vulnerability, v.Severity AS u_severity, v.State AS u_state,
       v.FirstSeen AS u_first_seen, v.LastSeen AS u_last_seen, v.ClosedAt AS u_closed_at, v.CloseReason AS u_close_reason,
       v.AbsentRuns AS u_absent_runs, v.Source AS u_source, CAST(v.SysId AS NVARCHAR(36)) AS u_source_record_id, v.UpdatedAt AS u_changed_at,
       v.FindingType AS u_finding_type, v.Title AS u_title, v.AssetId AS u_asset_id, v.Component AS u_si_component, v.SubCi AS u_si_servicenow_subci, v.OsFamily AS u_si_os_family, v.PatchCycle AS u_si_patch_cycle, v.SiBatchId AS u_si_batch_id,
       COALESCE(CASE WHEN v.State = N''Closed'' AND v.CloseReason = N''Out of scope'' THEN N''out_of_scope'' END, CASE WHEN v.State = N''Closed'' THEN N''close'' END, v.LastAction, CASE WHEN v.AbsentRuns = N''0'' THEN N''update'' END, N''held'') AS u_action,
       v.Cleared AS u_si_cleared
FROM vuln.VulnerabilityItem v
LEFT JOIN snowstage.HandoffCi h ON h.CiKey = v.CorrelationId');

IF COL_LENGTH('snowstage.vImportVulnerableItem', 'u_si_cleared') IS NULL AND OBJECT_ID('snowstage.vImportVulnerableItem') IS NOT NULL
   AND COL_LENGTH('vuln.VulnerabilityItem', 'Cleared') IS NOT NULL AND COL_LENGTH('vuln.VulnerabilityItem', 'PatchCycle') IS NOT NULL AND OBJECT_ID('snowstage.HandoffCi') IS NULL
EXEC ('ALTER VIEW snowstage.vImportVulnerableItem AS
SELECT v.CorrelationId AS u_si_correlation_id,
       CAST(CASE WHEN v.FindingType = N''identity'' THEN N''identity'' WHEN v.FindingType = N''azure-recommendation'' THEN N''azure-resource''
                 WHEN v.CorrelationId LIKE N''/subscriptions/%'' THEN N''azure-resource''
                 WHEN v.CorrelationId LIKE N''identity:%'' THEN N''identity'' ELSE N''device'' END AS NVARCHAR(16)) AS u_class_hint,
       v.AssetName AS u_asset_name, v.CiId AS u_cmdb_ci, v.Cve AS u_vulnerability, v.Severity AS u_severity, v.State AS u_state,
       v.FirstSeen AS u_first_seen, v.LastSeen AS u_last_seen, v.ClosedAt AS u_closed_at, v.CloseReason AS u_close_reason,
       v.AbsentRuns AS u_absent_runs, v.Source AS u_source, CAST(v.SysId AS NVARCHAR(36)) AS u_source_record_id, v.UpdatedAt AS u_changed_at,
       v.FindingType AS u_finding_type, v.Title AS u_title, v.AssetId AS u_asset_id, v.Component AS u_si_component, v.SubCi AS u_si_servicenow_subci, v.OsFamily AS u_si_os_family, v.PatchCycle AS u_si_patch_cycle, v.SiBatchId AS u_si_batch_id,
       COALESCE(CASE WHEN v.State = N''Closed'' AND v.CloseReason = N''Out of scope'' THEN N''out_of_scope'' END, CASE WHEN v.State = N''Closed'' THEN N''close'' END, v.LastAction, CASE WHEN v.AbsentRuns = N''0'' THEN N''update'' END, N''held'') AS u_action,
       v.Cleared AS u_si_cleared
FROM vuln.VulnerabilityItem v');

-- snowstage.HandoffRun (#914): the Pro database's CI hand-off write is ONE BATCH of its own, in the same words as
-- cmdbsync.SyncRun / vuln.SyncRun: 'writing' before the first chunk (an earlier batch still writing is ended 'failed'),
-- 'complete' only after the last chunk and the state signal, 'failed' on an error. Every snowstage.HandoffCi row the batch
-- writes carries its id (SiBatchId, <run id>:cmdb-handoff) from the write itself; vImportBatch lists the batch, so the reader
-- rule -- act only on rows whose u_si_batch_id is a complete batch -- holds on the hand-off views too. Never deleted.
IF OBJECT_ID('snowstage.HandoffRun') IS NULL AND SCHEMA_ID('snowstage') IS NOT NULL
CREATE TABLE snowstage.HandoffRun (
    SiBatchId        NVARCHAR(100)  NOT NULL CONSTRAINT PK_SnowHandoffRun PRIMARY KEY,
    RunId            NVARCHAR(64)   NOT NULL,
    Connector        NVARCHAR(100)  NOT NULL,
    BatchState       NVARCHAR(16)   NOT NULL,
    StartedAt        DATETIME2(3)   NOT NULL,
    EndedAt          DATETIME2(3)   NULL,
    Reason           NVARCHAR(1000) NULL,
    ContractVersion  NVARCHAR(16)   NULL,
    Mode             NVARCHAR(16)   NULL,
    NewRows          INT            NULL,
    UpdateRows       INT            NULL,
    CloseRows        INT            NULL,
    ReopenRows       INT            NULL,
    HeldRows         INT            NULL,
    OutOfScopeRows   INT            NULL,
    LandedRows       INT            NULL,
    SolutionVersion  NVARCHAR(64)   NULL,
    CONSTRAINT CK_SnowHandoffRun_State CHECK (BatchState IN ('writing', 'complete', 'failed', 'held'))
);
-- snowstage.vImportBatch (#914): the batches of the two SQL connectors in this database, and of the CI hand-off write (snowstage.HandoffRun), one row per batch, in the words of
-- the ServiceNow staging status table. THE READER RULE: act only on rows whose u_si_batch_id is a batch with u_state =
-- complete here. The CMDB SQL connector sets complete in the same transaction as its CI changes. The SQL vulnerability
-- connector writes record by record (no one transaction): its batch row is written first ('writing'), every record it
-- writes carries that batch id FROM THE WRITE ITSELF (vuln.VulnerabilityItem.SiBatchId -- never stamped later), and the
-- batch ends complete, failed or held. A record of a writing or failed batch is therefore always recognisable, and one the
-- newest run did not write keeps the id of the complete batch that last wrote it.
IF OBJECT_ID('snowstage.vImportBatch') IS NULL AND OBJECT_ID('vuln.SyncRun') IS NOT NULL AND COL_LENGTH('cmdbsync.SyncRun', 'BatchState') IS NOT NULL AND OBJECT_ID('snowstage.HandoffRun') IS NOT NULL
EXEC ('CREATE VIEW snowstage.vImportBatch AS
SELECT r.SiBatchId AS u_si_batch_id, r.SiBatchId AS u_batch_id, CAST(N''servicenow-ci'' AS NVARCHAR(40)) AS u_output, CAST(N''asset-cmdb-sql'' AS NVARCHAR(100)) AS u_connector,
       r.BatchState AS u_state, r.StartedAt AS u_started_at, r.EndedAt AS u_finished_at, CASE WHEN r.BatchState = N''complete'' THEN r.EndedAt END AS u_batch_time,
       r.Reason AS u_reason, r.ContractVersion AS u_si_contract_version, r.Mode AS u_si_mode,
       r.Created AS u_new_rows, r.Updated AS u_update_rows, r.Retired AS u_close_rows, r.Reactivated AS u_reopen_rows, r.Held AS u_held_rows,
       r.OutOfScope AS u_out_of_scope_rows, r.LandedRows AS u_landed_rows
FROM cmdbsync.SyncRun r WHERE r.SiBatchId IS NOT NULL
UNION ALL
SELECT s.SiBatchId, s.SiBatchId, CAST(N''servicenow-vulnerable-item'' AS NVARCHAR(40)), s.Connector, s.BatchState, s.StartedAt, s.EndedAt,
       CASE WHEN s.BatchState = N''complete'' THEN s.EndedAt END, s.Reason, s.ContractVersion, s.Mode,
       s.NewRows, s.UpdateRows, s.CloseRows, s.ReopenRows, s.HeldRows, s.OutOfScopeRows, s.LandedRows
FROM vuln.SyncRun s
UNION ALL
SELECT w.SiBatchId, w.SiBatchId, CAST(N''servicenow-ci'' AS NVARCHAR(40)), w.Connector, w.BatchState, w.StartedAt, w.EndedAt,
       CASE WHEN w.BatchState = N''complete'' THEN w.EndedAt END, w.Reason, w.ContractVersion, w.Mode,
       w.NewRows, w.UpdateRows, w.CloseRows, w.ReopenRows, w.HeldRows, w.OutOfScopeRows, w.LandedRows
FROM snowstage.HandoffRun w');

-- an existing database: vImportBatch takes the CI hand-off write's batches (the same columns, one more UNION ALL). Guarded: runs once.
IF OBJECT_ID('snowstage.vImportBatch') IS NOT NULL AND OBJECT_ID('snowstage.HandoffRun') IS NOT NULL AND OBJECT_DEFINITION(OBJECT_ID('snowstage.vImportBatch')) NOT LIKE N'%snowstage.HandoffRun%'
EXEC ('ALTER VIEW snowstage.vImportBatch AS
SELECT r.SiBatchId AS u_si_batch_id, r.SiBatchId AS u_batch_id, CAST(N''servicenow-ci'' AS NVARCHAR(40)) AS u_output, CAST(N''asset-cmdb-sql'' AS NVARCHAR(100)) AS u_connector,
       r.BatchState AS u_state, r.StartedAt AS u_started_at, r.EndedAt AS u_finished_at, CASE WHEN r.BatchState = N''complete'' THEN r.EndedAt END AS u_batch_time,
       r.Reason AS u_reason, r.ContractVersion AS u_si_contract_version, r.Mode AS u_si_mode,
       r.Created AS u_new_rows, r.Updated AS u_update_rows, r.Retired AS u_close_rows, r.Reactivated AS u_reopen_rows, r.Held AS u_held_rows,
       r.OutOfScope AS u_out_of_scope_rows, r.LandedRows AS u_landed_rows
FROM cmdbsync.SyncRun r WHERE r.SiBatchId IS NOT NULL
UNION ALL
SELECT s.SiBatchId, s.SiBatchId, CAST(N''servicenow-vulnerable-item'' AS NVARCHAR(40)), s.Connector, s.BatchState, s.StartedAt, s.EndedAt,
       CASE WHEN s.BatchState = N''complete'' THEN s.EndedAt END, s.Reason, s.ContractVersion, s.Mode,
       s.NewRows, s.UpdateRows, s.CloseRows, s.ReopenRows, s.HeldRows, s.OutOfScopeRows, s.LandedRows
FROM vuln.SyncRun s
UNION ALL
SELECT w.SiBatchId, w.SiBatchId, CAST(N''servicenow-ci'' AS NVARCHAR(40)), w.Connector, w.BatchState, w.StartedAt, w.EndedAt,
       CASE WHEN w.BatchState = N''complete'' THEN w.EndedAt END, w.Reason, w.ContractVersion, w.Mode,
       w.NewRows, w.UpdateRows, w.CloseRows, w.ReopenRows, w.HeldRows, w.OutOfScopeRows, w.LandedRows
FROM snowstage.HandoffRun w');