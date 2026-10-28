-- si-cmdb-handoff-target.sql -- THE SQL CMDB HAND-OFF CONNECTOR's database, SecurityInsight Pro.
--
-- A connector of kind sql with the cmdb direction (Configuration > Connectors (setup)) writes SecurityInsight's view of every
-- CI -- devices, Azure resources AND identities -- into THIS database, a database of the customer's choosing, and the
-- customer's ServiceNow pulls it: a JDBC data source on their MID Server reads the vImport* views into an Import Set table,
-- their transform map / IntegrationHub ETL hands each row to IRE (discovery source "SecurityInsight"). Every rule that
-- changes a CI is theirs. SecurityInsight needs no ServiceNow credential and creates no CI.
--
-- BATCHES. Every run writes ONE batch: all its rows carry the batch id, and the batch is marked complete LAST, in one
-- statement. The import views show only the NEWEST COMPLETE batch, so a JDBC import that runs while SecurityInsight is
-- writing reads the previous batch, whole -- never a half-written one. A batch that tripped the mass-change guard is
-- recorded as 'held' and never shown.
--
--   Batch               one row per run: state (writing | complete | held | failed), counts, why
--   BatchCi             one row per (batch, CI key): the standard match attributes, tier, owner, evidence, row hash
--   BatchCiKeyValue     the CI's key-values (Azure tags, Defender machine tags); one that vanished stays 'removed'
--   BatchCiRelation     the CI's relations from the ARM properties (VM -> disk / NIC / user-assigned identity)
--   vImportCi, vImportCiKeyValue, vImportCiRelation, vProposedCi   THE SAME COLUMNS as the Pro database's hand-off views
--                       (the transform map is the same either way), plus the owner and the batch at the end
--   vImportBatch        every batch with its state and counts
--
-- DELTA: u_changed_at moves only when the CI's content changed (u_row_hash), so a data source filtered
-- "u_changed_at > last import" sends only what changed.
--
-- Written by engine\asset-cmdb\_shared\SI-CmdbSqlConnector.ps1 (the job applies this file itself when the tables are
-- missing; that first run needs db_ddladmin, every later run db_datareader + db_datawriter). ADDITIVE AND IDEMPOTENT ONLY:
-- every statement is guarded, so re-running is a no-op, and no destructive verb appears in this file (a test refuses one).

IF SCHEMA_ID('snowstage') IS NULL EXEC ('CREATE SCHEMA snowstage');

IF OBJECT_ID('snowstage.Batch') IS NULL
CREATE TABLE snowstage.Batch (
    BatchId          NVARCHAR(64)   NOT NULL CONSTRAINT PK_SnowBatch PRIMARY KEY,   -- the SecurityInsight run id
    Connector        NVARCHAR(64)   NOT NULL,
    PreviousBatchId  NVARCHAR(64)   NULL,       -- the complete batch this one was compared with
    State            NVARCHAR(16)   NOT NULL,   -- writing | complete | held | failed
    StartedAt        DATETIME2(3)   NOT NULL,
    CompletedAt      DATETIME2(3)   NULL,       -- set LAST, with State = complete
    CiCount          INT            NOT NULL CONSTRAINT DF_SnowBatch_CiCount DEFAULT 0,
    KeyValueCount    INT            NOT NULL CONSTRAINT DF_SnowBatch_KeyValueCount DEFAULT 0,
    RelationCount    INT            NOT NULL CONSTRAINT DF_SnowBatch_RelationCount DEFAULT 0,
    NewCis           INT            NOT NULL CONSTRAINT DF_SnowBatch_NewCis DEFAULT 0,
    ChangedCis       INT            NOT NULL CONSTRAINT DF_SnowBatch_ChangedCis DEFAULT 0,
    DisappearedCis   INT            NOT NULL CONSTRAINT DF_SnowBatch_DisappearedCis DEFAULT 0,
    Reason           NVARCHAR(1000) NULL,
    SolutionVersion  NVARCHAR(64)   NULL,
    CONSTRAINT CK_SnowBatch_State CHECK (State IN ('writing', 'complete', 'held', 'failed'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SnowBatch_Complete' AND object_id = OBJECT_ID('snowstage.Batch'))
CREATE INDEX IX_SnowBatch_Complete ON snowstage.Batch (State, CompletedAt) INCLUDE (BatchId);

IF OBJECT_ID('snowstage.BatchCi') IS NULL
CREATE TABLE snowstage.BatchCi (
    BatchId          NVARCHAR(64)   NOT NULL,
    CiKey            NVARCHAR(400)  NOT NULL,   -- the stable SecurityInsight CI key (the identity ledger's correlation id)
    IdSource         NVARCHAR(16)   NOT NULL,   -- ledger | provisional | asset
    ClassHint        NVARCHAR(16)   NOT NULL,   -- device | azure-resource | identity
    ProposedClass    NVARCHAR(80)   NULL,       -- the ServiceNow class SecurityInsight proposes; the transform map decides
    Name             NVARCHAR(400)  NULL,
    Fqdn             NVARCHAR(400)  NULL,
    DnsDomain        NVARCHAR(256)  NULL,
    SerialNumber     NVARCHAR(128)  NULL,
    MacAddress       NVARCHAR(64)   NULL,
    ObjectId         NVARCHAR(512)  NULL,
    AzureResourceId  NVARCHAR(512)  NULL,
    AadDeviceId      NVARCHAR(64)   NULL,
    MdeDeviceId      NVARCHAR(64)   NULL,
    EntraObjectId    NVARCHAR(64)   NULL,
    Tier             TINYINT        NULL,
    TierReason       NVARCHAR(512)  NULL,
    Criticality      NVARCHAR(32)   NULL,
    ExposedInternet  BIT            NULL,
    CmdbMatch        NVARCHAR(16)   NOT NULL,   -- matched | unmatched | unknown
    Evidence         NVARCHAR(2000) NULL,
    Owner            NVARCHAR(256)  NULL,
    OwnerMail        NVARCHAR(256)  NULL,
    Department       NVARCHAR(128)  NULL,
    LastSeen         DATETIME2(3)   NULL,
    SourceRun        NVARCHAR(64)   NULL,
    RunTime          DATETIME2(3)   NOT NULL,
    RowHash          NVARCHAR(64)   NOT NULL,
    ChangedAt        DATETIME2(3)   NOT NULL,   -- carried from the previous batch while RowHash is unchanged
    CONSTRAINT PK_SnowBatchCi PRIMARY KEY (BatchId, CiKey),
    CONSTRAINT CK_SnowBatchCi_ClassHint CHECK (ClassHint IN ('device', 'azure-resource', 'identity')),
    CONSTRAINT CK_SnowBatchCi_CmdbMatch CHECK (CmdbMatch IN ('matched', 'unmatched', 'unknown'))
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SnowBatchCi_Resource' AND object_id = OBJECT_ID('snowstage.BatchCi'))
CREATE INDEX IX_SnowBatchCi_Resource ON snowstage.BatchCi (BatchId, AzureResourceId) INCLUDE (CiKey) WHERE AzureResourceId IS NOT NULL;

-- DataSensitivity (2026-10-05, #389): the CI's EFFECTIVE data sensitivity -- your asset-profile rule's override wins over
-- the CMDB record. Added IN PLACE, guarded; part of the row hash when set, so a change moves u_changed_at.
IF COL_LENGTH('snowstage.BatchCi', 'DataSensitivity') IS NULL
ALTER TABLE snowstage.BatchCi ADD DataSensitivity NVARCHAR(32) NULL;

-- SiState (2026-10-06, #406): the CI's state in SecurityInsight -- active | not-seen | retired. A CI SecurityInsight no longer
-- sees is CARRIED into every new batch with its state (not dropped), and its u_changed_at moves when the state changes, so a
-- delta import sees it. NULL on a row written before (read as active).
IF COL_LENGTH('snowstage.BatchCi', 'SiState') IS NULL
ALTER TABLE snowstage.BatchCi ADD SiState NVARCHAR(16) NULL;

-- SiAssetType / SiAssetSubtype (2026-10-11, #562): the asset's SI type and subtype from the ONE classification (the profile row,
-- data-model/classification.locked.json -- e.g. Server / SQL Server, Database / SQL Database). Added IN PLACE, guarded; part of
-- the row hash when set, so the first run that carries them moves u_changed_at once.
IF COL_LENGTH('snowstage.BatchCi', 'SiAssetType') IS NULL
ALTER TABLE snowstage.BatchCi ADD SiAssetType NVARCHAR(64) NULL;
IF COL_LENGTH('snowstage.BatchCi', 'SiAssetSubtype') IS NULL
ALTER TABLE snowstage.BatchCi ADD SiAssetSubtype NVARCHAR(64) NULL;

-- Action / Cleared (2026-10-27, #914): the database route carries the push's contract. Action = the CI's u_action in this
-- batch against the previous complete one (new | update | close | reopen); Cleared = u_si_cleared, the clearable columns the
-- batch carries empty (the target clears them). Added IN PLACE, guarded; NULL on a row written before.
IF COL_LENGTH('snowstage.BatchCi', 'Action') IS NULL
ALTER TABLE snowstage.BatchCi ADD Action NVARCHAR(16) NULL;
IF COL_LENGTH('snowstage.BatchCi', 'Cleared') IS NULL
ALTER TABLE snowstage.BatchCi ADD Cleared NVARCHAR(1000) NULL;

IF OBJECT_ID('snowstage.BatchCiKeyValue') IS NULL
CREATE TABLE snowstage.BatchCiKeyValue (
    BatchId          NVARCHAR(64)   NOT NULL,
    CiKey            NVARCHAR(400)  NOT NULL,
    Source           NVARCHAR(32)   NOT NULL,   -- azure-tag | mde-tag
    KeyName          NVARCHAR(256)  NOT NULL,
    Value            NVARCHAR(2000) NULL,
    State            NVARCHAR(16)   NOT NULL,   -- present | removed
    ChangedAt        DATETIME2(3)   NOT NULL,
    CONSTRAINT PK_SnowBatchCiKeyValue PRIMARY KEY (BatchId, CiKey, Source, KeyName),
    CONSTRAINT CK_SnowBatchCiKeyValue_State CHECK (State IN ('present', 'removed'))
);

IF OBJECT_ID('snowstage.BatchCiRelation') IS NULL
CREATE TABLE snowstage.BatchCiRelation (
    BatchId          NVARCHAR(64)   NOT NULL,
    ParentKey        NVARCHAR(400)  NOT NULL,
    ChildObjectId    NVARCHAR(512)  NOT NULL,   -- the ARM id of the disk / NIC / identity, lower-cased
    ChildClassHint   NVARCHAR(80)   NULL,
    RelationType     NVARCHAR(80)   NOT NULL,   -- a ServiceNow cmdb_rel_type name, e.g. 'Uses::Used by'
    Source           NVARCHAR(32)   NOT NULL,   -- arm
    State            NVARCHAR(16)   NOT NULL,   -- present | removed
    ChangedAt        DATETIME2(3)   NOT NULL,
    CONSTRAINT PK_SnowBatchCiRelation PRIMARY KEY (BatchId, ParentKey, ChildObjectId, RelationType),
    CONSTRAINT CK_SnowBatchCiRelation_State CHECK (State IN ('present', 'removed'))
);

IF OBJECT_ID('snowstage.vImportBatch') IS NULL
EXEC ('CREATE VIEW snowstage.vImportBatch AS
SELECT b.BatchId AS u_batch_id, b.Connector AS u_connector, b.State AS u_state, b.StartedAt AS u_started_at, b.CompletedAt AS u_batch_time,
       b.CiCount AS u_ci_count, b.KeyValueCount AS u_key_value_count, b.RelationCount AS u_relation_count, b.NewCis AS u_new_cis,
       b.ChangedCis AS u_changed_cis, b.DisappearedCis AS u_disappeared_cis, b.PreviousBatchId AS u_previous_batch_id, b.Reason AS u_reason,
       b.BatchId AS u_si_batch_id
FROM snowstage.Batch b');

IF OBJECT_ID('snowstage.vImportCi') IS NULL
EXEC ('CREATE VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, h.Criticality AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       h.DataSensitivity AS u_data_sensitivity, h.SiState AS u_si_state, h.SiAssetType AS u_si_asset_type, h.SiAssetSubtype AS u_si_asset_subtype,
       h.Owner AS u_owner, h.OwnerMail AS u_owner_mail, h.Department AS u_department, b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time,
       b.BatchId AS u_si_batch_id, COALESCE(h.Action, CASE WHEN h.SiState = N''retired'' THEN N''close'' ELSE N''update'' END) AS u_action, h.Cleared AS u_si_cleared
FROM snowstage.BatchCi h
JOIN snowstage.Batch b ON b.BatchId = h.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

-- u_data_sensitivity (2026-10-05, #389): a hand-off database whose vImportCi was created before the column gets it in place
-- (guarded, runs once). ServiceNow's import set maps by column name, so every earlier column reads exactly as before.
IF COL_LENGTH('snowstage.vImportCi', 'u_data_sensitivity') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, h.Criticality AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       h.DataSensitivity AS u_data_sensitivity,
       h.Owner AS u_owner, h.OwnerMail AS u_owner_mail, h.Department AS u_department, b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time
FROM snowstage.BatchCi h
JOIN snowstage.Batch b ON b.BatchId = h.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

-- u_si_state (2026-10-06, #406): the CI's state in SecurityInsight, right after u_data_sensitivity (the same place as in the Pro
-- database's view, before the owner and batch columns). Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_si_state') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL AND COL_LENGTH('snowstage.BatchCi', 'SiState') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, h.Criticality AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       h.DataSensitivity AS u_data_sensitivity, h.SiState AS u_si_state,
       h.Owner AS u_owner, h.OwnerMail AS u_owner_mail, h.Department AS u_department, b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time
FROM snowstage.BatchCi h
JOIN snowstage.Batch b ON b.BatchId = h.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

-- u_si_asset_type / u_si_asset_subtype (2026-10-11, #562): the asset's SI type and subtype, right after u_si_state, the same way
-- (ServiceNow's import set maps by column name: every earlier column keeps its name and value). Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_si_asset_subtype') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL AND COL_LENGTH('snowstage.BatchCi', 'SiAssetSubtype') IS NOT NULL AND COL_LENGTH('snowstage.BatchCi', 'SiState') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, h.Criticality AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       h.DataSensitivity AS u_data_sensitivity, h.SiState AS u_si_state, h.SiAssetType AS u_si_asset_type, h.SiAssetSubtype AS u_si_asset_subtype,
       h.Owner AS u_owner, h.OwnerMail AS u_owner_mail, h.Department AS u_department, b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time
FROM snowstage.BatchCi h
JOIN snowstage.Batch b ON b.BatchId = h.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

-- u_si_batch_id / u_action / u_si_cleared (2026-10-27, #914): the one contract on the database route, APPENDED after
-- u_batch_time (u_si_batch_id carries the same batch id as u_batch_id, which stays). Guarded: runs once.
IF COL_LENGTH('snowstage.vImportCi', 'u_si_cleared') IS NULL AND OBJECT_ID('snowstage.vImportCi') IS NOT NULL AND COL_LENGTH('snowstage.BatchCi', 'Cleared') IS NOT NULL AND COL_LENGTH('snowstage.BatchCi', 'SiAssetSubtype') IS NOT NULL AND COL_LENGTH('snowstage.BatchCi', 'SiState') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.DnsDomain AS u_dns_domain, h.SerialNumber AS u_serial_number, h.MacAddress AS u_mac_address,
       h.ObjectId AS u_object_id, h.AzureResourceId AS u_azure_resource_id, h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id,
       h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier, h.TierReason AS u_tier_reason, h.Criticality AS u_criticality,
       h.ExposedInternet AS u_exposed_internet, h.LastSeen AS u_last_seen, h.SourceRun AS u_source_run, h.RunTime AS u_run_time,
       CAST(N''SecurityInsight'' AS NVARCHAR(32)) AS u_discovery_source, h.RowHash AS u_row_hash, h.ChangedAt AS u_changed_at,
       h.DataSensitivity AS u_data_sensitivity, h.SiState AS u_si_state, h.SiAssetType AS u_si_asset_type, h.SiAssetSubtype AS u_si_asset_subtype,
       h.Owner AS u_owner, h.OwnerMail AS u_owner_mail, h.Department AS u_department, b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time,
       b.BatchId AS u_si_batch_id, COALESCE(h.Action, CASE WHEN h.SiState = N''retired'' THEN N''close'' ELSE N''update'' END) AS u_action, h.Cleared AS u_si_cleared
FROM snowstage.BatchCi h
JOIN snowstage.Batch b ON b.BatchId = h.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

IF OBJECT_ID('snowstage.vImportCiKeyValue') IS NULL
EXEC ('CREATE VIEW snowstage.vImportCiKeyValue AS
SELECT k.CiKey AS u_si_correlation_id, k.KeyName AS u_key, k.Value AS u_value, k.Source AS u_source, k.State AS u_state, k.ChangedAt AS u_changed_at,
       b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time, b.BatchId AS u_si_batch_id
FROM snowstage.BatchCiKeyValue k
JOIN snowstage.Batch b ON b.BatchId = k.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

IF OBJECT_ID('snowstage.vImportCiRelation') IS NULL
EXEC ('CREATE VIEW snowstage.vImportCiRelation AS
SELECT r.ParentKey AS u_parent_correlation_id, c.CiKey AS u_child_correlation_id, r.ChildObjectId AS u_child_object_id,
       r.ChildClassHint AS u_child_class_hint, r.RelationType AS u_relation_type, r.Source AS u_source, r.State AS u_state, r.ChangedAt AS u_changed_at,
       b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time, b.BatchId AS u_si_batch_id
FROM snowstage.BatchCiRelation r
JOIN snowstage.Batch b ON b.BatchId = r.BatchId
LEFT JOIN snowstage.BatchCi c ON c.BatchId = r.BatchId AND c.AzureResourceId = r.ChildObjectId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

IF OBJECT_ID('snowstage.vProposedCi') IS NULL
EXEC ('CREATE VIEW snowstage.vProposedCi AS
SELECT h.CiKey AS u_si_correlation_id, h.IdSource AS u_id_source, h.ClassHint AS u_class_hint, h.ProposedClass AS u_proposed_class,
       h.Name AS u_name, h.Fqdn AS u_fqdn, h.SerialNumber AS u_serial_number, h.AzureResourceId AS u_azure_resource_id,
       h.AadDeviceId AS u_aad_device_id, h.MdeDeviceId AS u_mde_device_id, h.EntraObjectId AS u_entra_object_id, h.Tier AS u_tier,
       h.CmdbMatch AS u_cmdb_match, h.Evidence AS u_evidence,
       CAST(CASE WHEN h.CmdbMatch = N''unmatched'' THEN N''SecurityInsight sees this asset and no CMDB CI matched it''
                 ELSE N''SecurityInsight sees this asset and it is not known to match a CMDB CI'' END
            + CASE WHEN h.IdSource <> N''ledger'' THEN N''; its correlation id is provisional, so it must not be created from yet'' ELSE N'''' END AS NVARCHAR(400)) AS u_reason,
       h.LastSeen AS u_last_seen, h.ChangedAt AS u_changed_at, b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time
FROM snowstage.BatchCi h
JOIN snowstage.Batch b ON b.BatchId = h.BatchId
WHERE h.CmdbMatch <> N''matched''
  AND b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

-- u_si_batch_id (2026-10-27, #914): the contract's batch id APPENDED to the batch, key-value and relation views of an
-- existing database (the same value as u_batch_id, which stays). Guarded: each runs once.
IF COL_LENGTH('snowstage.vImportBatch', 'u_si_batch_id') IS NULL AND OBJECT_ID('snowstage.vImportBatch') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportBatch AS
SELECT b.BatchId AS u_batch_id, b.Connector AS u_connector, b.State AS u_state, b.StartedAt AS u_started_at, b.CompletedAt AS u_batch_time,
       b.CiCount AS u_ci_count, b.KeyValueCount AS u_key_value_count, b.RelationCount AS u_relation_count, b.NewCis AS u_new_cis,
       b.ChangedCis AS u_changed_cis, b.DisappearedCis AS u_disappeared_cis, b.PreviousBatchId AS u_previous_batch_id, b.Reason AS u_reason,
       b.BatchId AS u_si_batch_id
FROM snowstage.Batch b');

IF COL_LENGTH('snowstage.vImportCiKeyValue', 'u_si_batch_id') IS NULL AND OBJECT_ID('snowstage.vImportCiKeyValue') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCiKeyValue AS
SELECT k.CiKey AS u_si_correlation_id, k.KeyName AS u_key, k.Value AS u_value, k.Source AS u_source, k.State AS u_state, k.ChangedAt AS u_changed_at,
       b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time, b.BatchId AS u_si_batch_id
FROM snowstage.BatchCiKeyValue k
JOIN snowstage.Batch b ON b.BatchId = k.BatchId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');

IF COL_LENGTH('snowstage.vImportCiRelation', 'u_si_batch_id') IS NULL AND OBJECT_ID('snowstage.vImportCiRelation') IS NOT NULL
EXEC ('ALTER VIEW snowstage.vImportCiRelation AS
SELECT r.ParentKey AS u_parent_correlation_id, c.CiKey AS u_child_correlation_id, r.ChildObjectId AS u_child_object_id,
       r.ChildClassHint AS u_child_class_hint, r.RelationType AS u_relation_type, r.Source AS u_source, r.State AS u_state, r.ChangedAt AS u_changed_at,
       b.BatchId AS u_batch_id, b.CompletedAt AS u_batch_time, b.BatchId AS u_si_batch_id
FROM snowstage.BatchCiRelation r
JOIN snowstage.Batch b ON b.BatchId = r.BatchId
LEFT JOIN snowstage.BatchCi c ON c.BatchId = r.BatchId AND c.AzureResourceId = r.ChildObjectId
WHERE b.BatchId = (SELECT TOP (1) x.BatchId FROM snowstage.Batch x WHERE x.State = N''complete'' ORDER BY x.CompletedAt DESC, x.BatchId DESC)');
