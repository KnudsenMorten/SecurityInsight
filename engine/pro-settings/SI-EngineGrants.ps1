#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE ENGINE IDENTITY'S LEAST-PRIVILEGE DATABASE ROLE `si_engine` (#672; framework
    DOCS/REQUIREMENTS.md §12.23 SQL-ACCESS P3 / P7 / P8).

    WHY. Until #672 the engine's managed identity (id-si-<label>, shared by every engine job) was db_datareader +
    db_datawriter on the WHOLE Pro database: it could read the web app's sign-in key ring and the secret hand-over, and
    rewrite access assignments, settings and the audit trail's neighbours. The owner: "make it consistent and with the
    best possible security least priv". This file is the ONE list of what the engine may do -- the same shape as the web
    app's narrow grants (pro-management\deploy\SI-ManagementGrants.ps1):
      * SCHEMA-level where the engine owns the data (sidata, vuln, cmdbsync, snowstage);
      * OBJECT-level in cfg: SELECT on what it reads, INSERT / UPDATE / DELETE / EXECUTE only on what it writes;
      * a DENY where a schema grant would reach data the engine must never write (sidata.CiOverride = an Admin's own);
      * no DDL, no security right, no fixed-role membership.

    WHO APPLIES IT (framework §12.23 P8 -- the UPDATER CHANGES NO SECURITY):
      new installs   setup\_shared\SI-GuidedInstallPro.ps1: the engine user goes into si_engine ONLY (no broad roles);
      existing ones  setup\Move-SIEngineToLeastPrivilege.ps1, run per environment through the Invardia Support app
                     (every statement through Invoke-InvardiaSupportSql), with a rollback record;
      every update   container\updater\_shared\SI-UpdaterDatabase.ps1 only CHECKS (Get-SIEngineAccessDrift): a warning,
                     never a block, never a grant.

    THE INVENTORY (Get-SIEngineSqlReference) reads the engine's own code -- engine\, container\ (not the updater) and
    launcher\ -- for every statement on a product table, view or procedure, with its file and line. What runs under ANOTHER
    identity (setup run by a person, the updater) is listed in $script:SIEngineNotEngine with the reason. The static test
    (tests\pester\SIv3-EngineSqlLeastPriv.Tests.ps1) fails when the engine's code needs a right this list does not give;
    the cut-over's check and the updater's drift check use the same comparison against the database's real grants.
    Strict-mode safe; PS 5.1.
#>

$script:SIEngineRole = 'si_engine'

# The schemas whose data the engine owns: the verbs on the WHOLE schema (a new table of the schema is covered at once).
$script:SIEngineSchemaGrants = @(
    @{ Schema = 'sidata';    Verbs = 'SELECT, INSERT, UPDATE, DELETE' }   # the data sync, Risk Analysis' stream to SQL, the CI build
    @{ Schema = 'vuln';      Verbs = 'SELECT, INSERT, UPDATE' }           # the vulnerability loop (never deletes: the event log is append-only)
    @{ Schema = 'cmdbsync';  Verbs = 'SELECT, INSERT, UPDATE' }           # the CMDB sync (DELETE only on its staging table, below)
    @{ Schema = 'snowstage'; Verbs = 'SELECT, INSERT, UPDATE' }           # the ServiceNow hand-off tables (DELETE only on the batch tables, below)
)

# Data inside an owned schema that is NOT the engine's to write: DENY beats the schema grant (and db_datawriter, while an
# install still has it). An Admin's manual CI override is written by the web app only; the engine reads it.
$script:SIEngineDenies = @(
    @{ Object = 'sidata.CiOverride'; Verbs = 'INSERT, UPDATE, DELETE' }
)

# Object-level grants: every cfg table / view / procedure the engine touches, with exactly the verbs its code uses
# (and the deletes inside the owned schemas that the schema grant leaves out).
$script:SIEngineObjectGrants = @(
    # ---- reads only: settings, templates, departments, CMDB and the web app's decisions the engine applies ----
    @{ Object = 'cfg.AccessAssignment';        Verbs = 'SELECT' }   # the guards' mail goes to the SuperAdmins (never a write: see NeverGranted)
    @{ Object = 'cfg.CategoryRole';            Verbs = 'SELECT' }
    @{ Object = 'cfg.CmdbServiceAsset';        Verbs = 'SELECT' }
    @{ Object = 'cfg.Connector';               Verbs = 'SELECT' }
    @{ Object = 'cfg.Department';              Verbs = 'SELECT' }
    @{ Object = 'cfg.DepartmentAdvisor';       Verbs = 'SELECT' }
    @{ Object = 'cfg.DepartmentMember';        Verbs = 'SELECT' }
    @{ Object = 'cfg.Document';                Verbs = 'SELECT' }
    @{ Object = 'cfg.DomainRole';              Verbs = 'SELECT' }
    @{ Object = 'cfg.Exemption';               Verbs = 'SELECT' }
    @{ Object = 'cfg.ExemptionRequestItem';    Verbs = 'SELECT' }
    @{ Object = 'cfg.FindingComment';          Verbs = 'SELECT' }   # the asset merge counts the settings rows that name an asset
    @{ Object = 'cfg.FindingTask';             Verbs = 'SELECT' }
    @{ Object = 'cfg.ItemOverride';            Verbs = 'SELECT' }
    @{ Object = 'cfg.JobFlow';                 Verbs = 'SELECT' }
    @{ Object = 'cfg.RemediationFlow';         Verbs = 'SELECT' }
    @{ Object = 'cfg.ResponsibilityOverride';  Verbs = 'SELECT' }
    @{ Object = 'cfg.ResponsibilityRule';      Verbs = 'SELECT' }
    @{ Object = 'cfg.Setting';                 Verbs = 'SELECT' }
    @{ Object = 'cfg.VerificationDecision';    Verbs = 'SELECT' }
    @{ Object = 'cfg.vCmdbAssetService';       Verbs = 'SELECT' }
    @{ Object = 'cfg.vCmdbService';            Verbs = 'SELECT' }
    @{ Object = 'cfg.vCmdbSource';             Verbs = 'SELECT' }
    # ---- the engine's own records: run / guard / connector / mail / report state ----
    @{ Object = 'cfg.AuditEvent';              Verbs = 'SELECT, INSERT' }           # Write-SIAuditEvent (UPDATE / DELETE are DENIED to public)
    @{ Object = 'cfg.ChangeAttribution';       Verbs = 'SELECT, INSERT' }           # the vulnerability loop's "who changed it"
    @{ Object = 'cfg.ChangeLog';               Verbs = 'SELECT, INSERT' }           # the governance schedule's change line
    @{ Object = 'cfg.CollectionSend';          Verbs = 'SELECT, UPDATE' }           # a resend request taken / done
    @{ Object = 'cfg.ConnectorChange';         Verbs = 'SELECT, INSERT' }           # the item change log (before / now)
    @{ Object = 'cfg.ConnectorItem';           Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.ConnectorRun';            Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.DataOutItem';             Verbs = 'SELECT, INSERT, UPDATE, DELETE' }   # what data-out sent; a removed item's row goes
    @{ Object = 'cfg.DataOutBatch';            Verbs = 'SELECT, INSERT, UPDATE' }           # #914 one row per data-out batch (writing -> complete / failed / held, the read-back); never deleted
    @{ Object = 'cfg.DepartmentReport';        Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.ExemptionMail';           Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.FindingTaskDigest';       Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.FlowRun';                 Verbs = 'SELECT, INSERT, UPDATE' }   # the job flow runner (MERGE)
    @{ Object = 'cfg.FlowStepRun';             Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.GovernanceEntry';         Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.GovernanceMail';          Verbs = 'SELECT, UPDATE' }
    @{ Object = 'cfg.GovernanceNotice';        Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.GovernanceState';         Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.GuardAccept';             Verbs = 'SELECT' }                   # the owner's acceptance (written only by cfg.GuardAcceptSet)
    @{ Object = 'cfg.GuardEvent';              Verbs = 'SELECT, INSERT, UPDATE' }   # Send-SIGuardEvent
    @{ Object = 'cfg.GuardRelease';            Verbs = 'SELECT, INSERT, UPDATE' }   # a release consumed by the run it was for
    @{ Object = 'cfg.GuardState';              Verbs = 'SELECT, INSERT, UPDATE' }   # (MERGE)
    @{ Object = 'cfg.InstallState';            Verbs = 'SELECT, INSERT, UPDATE' }   # the tenant record (data sync), the licence-superseded mark (telemetry), the proven mail restriction (close-loop mail), the tenant size the collections counted (job sizing)
    @{ Object = 'cfg.PipelineLock';            Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.PipelineQueue';           Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.RaBucketHistory';         Verbs = 'SELECT, INSERT, DELETE' }
    @{ Object = 'cfg.RaBucketImport';          Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.RaBucketReset';           Verbs = 'SELECT, UPDATE' }           # a reset is consumed by the run
    @{ Object = 'cfg.RaSourceAccept';          Verbs = 'SELECT, UPDATE' }           # #902: an Admin's acceptance of an empty source -- read by the run, cleared when the source has rows again
    @{ Object = 'cfg.JobTriggerRequest';       Verbs = 'SELECT, UPDATE' }           # CR8: the pipeline runner applies a job trigger request and records it
    @{ Object = 'cfg.SignedRequest';           Verbs = 'SELECT, UPDATE' }           # CR8 step 2: the pipeline runner verifies the signed tokens (observe only) and clears them
    @{ Object = 'cfg.RaBucketState';           Verbs = 'SELECT, INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.ReleaseScope';            Verbs = 'SELECT, UPDATE' }           # CR3: a run counts its components' good daily runs (the updater writes the rows)
    @{ Object = 'cfg.ReportMail';              Verbs = 'SELECT, UPDATE' }
    @{ Object = 'cfg.SignInMail';              Verbs = 'SELECT, UPDATE' }
    @{ Object = 'cfg.StepPhaseTime';           Verbs = 'SELECT, INSERT' }           # a long step's time per phase (Write-SIStepPhase); append-only for the engine
    @{ Object = 'cfg.TechnicalReview';         Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.VerificationCheckRun';    Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.VerificationFinding';     Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.VerificationFindingEvent'; Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.VerificationRun';         Verbs = 'SELECT, INSERT, UPDATE' }
    # CR2 (#656): the daily data health check (in the verification job) and the data-out writers' hold
    @{ Object = 'cfg.DataHealthCycle';         Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.DataHealthResult';        Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.DataHealthMissing';       Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.DataHealthState';         Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.DataHealthOverride';      Verbs = 'SELECT, UPDATE' }           # clears the open overrides when Healthy again; never makes one (the web app's)
    # the ServiceNow checks: an output's run, the daily check and the web app's Verify (on the mail job) record each check
    @{ Object = 'cfg.ServiceNowCheck';         Verbs = 'SELECT, INSERT' }
    # #757: the heartbeat's hourly load samples for Operations > Performance (written and pruned only through cfg.PerfSampleSave)
    @{ Object = 'cfg.PerfSample';              Verbs = 'SELECT' }
    # ---- caj-si-templates (setup\Publish-SITemplates.ps1 -FromStaged / -RollbackToVersion, started by the web app after an
    #      Admin accepted a template release) runs as the ENGINE identity today: it installs the accepted templates ----
    @{ Object = 'cfg.Template';                Verbs = 'SELECT, INSERT, UPDATE' }
    @{ Object = 'cfg.TemplateRevision';        Verbs = 'SELECT, INSERT' }
    @{ Object = 'cfg.TemplatePackStaged';      Verbs = 'SELECT' }
    # ---- procedures: the only way the engine removes audit / journal / backup / change-log rows ----
    @{ Object = 'cfg.AuditRetentionApply';           Verbs = 'EXECUTE' }
    @{ Object = 'cfg.CmdbImportSnapshot';            Verbs = 'EXECUTE' }        # the CMDB import job (setup's Import-SICmdbCsv too)
    @{ Object = 'cfg.ConfigBackupPrune';             Verbs = 'EXECUTE' }
    @{ Object = 'cfg.ConfigBackupTake';              Verbs = 'EXECUTE' }
    @{ Object = 'cfg.ConfigJournalRetentionApply';   Verbs = 'EXECUTE' }
    @{ Object = 'cfg.ConnectorChangeRetentionApply'; Verbs = 'EXECUTE' }
    @{ Object = 'cfg.JobFlowSetMode';                Verbs = 'EXECUTE' }        # #732: the move to the pipeline sets the stored mode (and puts it back)
    @{ Object = 'cfg.PerfSampleSave';                Verbs = 'EXECUTE' }        # #757: the heartbeat's load samples (adds / replaces an hour, prunes after 30 days)
    @{ Object = 'sidata.PublishedRunSet';            Verbs = 'EXECUTE' }        # one trusted run: the pipeline runner moves the published-run pointer (the run's own data checked inside)
    @{ Object = 'sidata.PublishedCopyCatchUp';       Verbs = 'EXECUTE' }        # the shown run's copies of the merged assets caught up when older than it (gated inside)
    @{ Object = 'sidata.PublishedCopyRefreshRange';  Verbs = 'EXECUTE' }        # #881 one key range of one copy -- the driver runs the ranges at once (gated inside)
    # ---- deletes inside the owned schemas that the schema grant does not give ----
    @{ Object = 'cmdbsync.SyncStage';          Verbs = 'DELETE' }
    @{ Object = 'snowstage.BatchCi';           Verbs = 'DELETE' }
    @{ Object = 'snowstage.BatchCiKeyValue';   Verbs = 'DELETE' }
    @{ Object = 'snowstage.BatchCiRelation';   Verbs = 'DELETE' }
)

# #881 database-level, READ-ONLY rights on the database's own load (never data, never security): what the pacing of the large
# writers reads (engine\_shared\data-sql\SI-SqlPacing.ps1) and the parallel fills' size (Get-SIDataFillWorkers). The signed
# grant procedure never gives a database-level right (its rules are frozen), so setup, the cut-over and every update grant
# it in a batch of its own (Get-SIEngineDatabaseGrantSql, never inside a transaction); refused = a warning, nothing fails.
$script:SIEngineDatabaseGrants = @('VIEW DATABASE PERFORMANCE STATE')

# Never the engine's, whatever a later change to the lists above says (the static test enforces it): the sign-in key
# ring, the secret hand-over, who may sign in, the audit trail's history and the settings the web app writes.
$script:SIEngineNeverGranted = @(
    @{ Object = 'cfg.WebKeyRing';        Verbs = 'SELECT, INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.PendingSecret';     Verbs = 'SELECT, INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.SecretHandoverKey'; Verbs = 'SELECT, INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.AccessAssignment';  Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.AuditEvent';        Verbs = 'UPDATE, DELETE' }
    @{ Object = 'cfg.ChangeLog';         Verbs = 'UPDATE, DELETE' }
    @{ Object = 'cfg.ConfigJournal';     Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.ConfigBackup';      Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.Setting';           Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.Document';          Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.ItemOverride';      Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.Template';          Verbs = 'DELETE' }
    @{ Object = 'cfg.Connector';         Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.Exemption';         Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'sidata.CiOverride';     Verbs = 'INSERT, UPDATE, DELETE' }
)

# Code under engine\ that does NOT run as the engine identity -- left out of the inventory, with the reason. A function
# named here and called from an engine job would make the static test's real-rights run fail, not pass quietly.
$script:SIEngineNotEngine = @(
    @{ File = 'engine/pro-settings/SI-ProSchema.ps1';           Function = '*';  Why = 'the schema + updater access: the updater and setup' }
    @{ File = 'engine/pro-settings/SI-EngineGrants.ps1';        Function = '*';  Why = 'this file: setup, the cut-over script and the updater''s check' }
    @{ File = 'engine/pro-settings/SI-GrantProcedure.ps1';      Function = '*';  Why = 'the signed grant procedure: the admin run (setup, the cut-over) and the updater' }
    @{ File = 'engine/pro-settings/SI-ProOverrideMigration.ps1'; Function = '*'; Why = 'setup\Publish-SITemplates.ps1' }
    @{ File = 'engine/asset-cmdb/_shared/SI-SnowTestPack.ps1';  Function = '*';  Why = 'setup\New-SIServiceNowTestPack.ps1 (reads the schema text, runs nothing)' }
    @{ File = 'engine/asset-cmdb/_shared/SI-Connector.ps1';     Function = 'Set-SIConnector';               Why = 'setup\Import-SIProSettings.ps1' }
    @{ File = 'engine/pro-settings/SI-ProSettings.ps1';         Function = 'Set-SIProSetting';              Why = 'setup\Set-SIProSetting.ps1 / Import-SIProSettings.ps1' }
    @{ File = 'engine/pro-settings/SI-ProSettings.ps1';         Function = 'Set-SIProDocument';             Why = 'setup\Import-SIProSettings.ps1' }
    @{ File = 'engine/pro-settings/SI-ProConfig.ps1';           Function = 'Set-SIProItem';                 Why = 'setup\Import-SIProSettings.ps1 / Publish-SITemplates.ps1' }
    @{ File = 'engine/pro-settings/SI-ProConfig.ps1';           Function = 'New-SIProExemption';            Why = 'no engine caller (the web app writes exemptions)' }
    @{ File = 'engine/pro-settings/SI-ProConfig.ps1';           Function = 'Revoke-SIProExemption';         Why = 'no engine caller (the web app writes exemptions)' }
    @{ File = 'engine/pro-settings/SI-ProConfig.ps1';           Function = 'Invoke-SIProConfigurationMigration'; Why = 'setup\Publish-SITemplates.ps1' }
    @{ File = 'engine/pro-settings/SI-TemplatePacks.ps1';       Function = 'Save-SIProTemplatePackStaged';  Why = 'staging a pack: setup / the updater (the template job only installs a staged one)' }
    @{ File = 'engine/pro-settings/SI-TemplateVersioning.ps1';  Function = 'Approve-SIProTemplateUpgrade';  Why = 'no engine caller (setup / the web app)' }
    @{ File = 'engine/pro-settings/SI-ConfigJournal.ps1';       Function = 'Get-SIConfigTriggerSql';        Why = 'schema text (the triggers in sql\si-pro-settings.sql)' }
    @{ File = 'engine/pro-settings/SI-ConfigJournal.ps1';       Function = 'Get-SIConfigSnapshotViewSql';   Why = 'schema text (the view in sql\si-pro-settings.sql)' }
    @{ File = 'engine/_shared/SI-InstallNames.ps1';             Function = 'Save-SIInstallNamesRecord';     Why = 'the updater' }
    @{ File = 'engine/_shared/SI-TelemetryEndpoints.ps1';       Function = 'Save-SIInstallEndpointsRow';    Why = 'the updater' }
    @{ File = 'engine/_shared/SI-InstallRing.ps1';              Function = 'Get-SIInstallRingSql';          Why = 'setup\Set-SIInstallRing.ps1 and the updater' }
    @{ File = 'engine/_shared/SI-ReleaseControl.ps1';           Function = 'Get-SIReleaseScopeSaveSql';     Why = 'the updater (Save-SIReleaseScopeRecords: the component fingerprints of the release it installed)' }
)

# Scripts OUTSIDE engine\ that an engine job runs under the engine identity (container\_shared\SI-ContainerConfig.ps1
# Get-SIContainerEngineDispatch): caj-si-templates runs setup\Publish-SITemplates.ps1.
$script:SIEngineExtraFiles = @('setup/Publish-SITemplates.ps1')

# A quoted 'schema.Name' that is NOT a statement (a label in an audit row): file + object, with the reason.
$script:SIEngineNotSqlText = @(
    @{ File = 'engine/pro-settings/SI-ConfigJournal.ps1'; Object = 'cfg.ConfigBackup'; Why = 'the audit row''s Target text; the backup is written only by its procedures' }
)

# The procedures that let only "a job identity" in (IS_ROLEMEMBER db_datawriter, sql\si-pro-settings.sql): since #672 they
# let si_engine in too. Without that the engine's retention / backup steps are refused once the broad roles are gone, so
# the cut-over's check reads each definition and refuses to remove the broad roles while one is still the old text.
$script:SIEngineGatedProcedures = @('cfg.AuditRetentionApply', 'cfg.ConfigBackupPrune', 'cfg.ConfigBackupTake', 'cfg.ConfigJournalRetentionApply', 'cfg.ConnectorChangeRetentionApply', 'cfg.JobFlowSetMode', 'cfg.PerfSampleSave')

$script:SIEngineProductSchemas = @('sidata', 'cfg', 'cmdbsync', 'vuln', 'snowstage')

function Get-SIEngineGrantList {
    <# PURE. The shipped grant list as rows @{ Kind = schema | object | deny; Target; Permission } (one per verb). #>
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($g in $script:SIEngineSchemaGrants) { foreach ($v in ($g.Verbs -split ',\s*')) { $rows.Add([pscustomobject]@{ Kind = 'schema'; Target = $g.Schema; Permission = $v }) } }
    foreach ($g in $script:SIEngineObjectGrants) { foreach ($v in ($g.Verbs -split ',\s*')) { $rows.Add([pscustomobject]@{ Kind = 'object'; Target = $g.Object; Permission = $v }) } }
    foreach ($g in $script:SIEngineDenies) { foreach ($v in ($g.Verbs -split ',\s*')) { $rows.Add([pscustomobject]@{ Kind = 'deny'; Target = $g.Object; Permission = $v }) } }
    , $rows.ToArray()
}

function Get-SIEngineGrantSql {
    <#
        PURE. THE GRANT SCRIPT -- one batch, idempotent, safe on a database one schema version behind (every grant only
        when its schema / object exists): the role si_engine, its schema grants, its object grants and its DENYs; with
        -UserName also that user's membership of the role. NEVER a fixed-role membership, never a DDL or security right,
        never a CREATE USER (Get-SIEngineDatabaseAccessSql does that for a new install).
    #>
    param([string]$UserName)
    $r = $script:SIEngineRole
    $sql = "IF DATABASE_PRINCIPAL_ID(N'$r') IS NULL EXEC (N'CREATE ROLE [$r]');`n"
    foreach ($g in $script:SIEngineSchemaGrants) {
        $sql += "IF SCHEMA_ID(N'$($g.Schema)') IS NOT NULL EXEC (N'GRANT $($g.Verbs) ON SCHEMA::[$($g.Schema)] TO [$r]');`n"
    }
    foreach ($g in $script:SIEngineObjectGrants) {
        $sql += "IF OBJECT_ID(N'$($g.Object)') IS NOT NULL EXEC (N'GRANT $($g.Verbs) ON OBJECT::$($g.Object) TO [$r]');`n"
    }
    foreach ($g in $script:SIEngineDenies) {
        $sql += "IF OBJECT_ID(N'$($g.Object)') IS NOT NULL EXEC (N'DENY $($g.Verbs) ON OBJECT::$($g.Object) TO [$r]');`n"
    }
    if ($UserName) {
        $n = $UserName.Replace(']', ']]').Replace("'", "''")
        $sql += "IF DATABASE_PRINCIPAL_ID(N'$($UserName.Replace("'", "''"))') IS NOT NULL EXEC (N'ALTER ROLE [$r] ADD MEMBER [$($n.Replace("'", "''"))]');`n"
    }
    $sql
}

function Get-SIEngineDatabaseGrantSql {
    <#
        PURE. #881 THE ENGINE ROLE'S DATABASE-LEVEL READ RIGHTS ($script:SIEngineDatabaseGrants: the database's own load, for
        the pacing of the large writers and the size of the parallel fills) -- ALWAYS ITS OWN BATCH, never inside the schema's
        or another transaction: a refused GRANT is caught and answered, never an uncommittable transaction. One row:
        Granted (1 = granted now, 3 = held already, 2 = nothing to do here -- no role, or a server that does not know the
        right, 0 = refused) and Reason. Run by setup, the cut-over and every update; a refusal is a warning, never a stop.
    #>
    $r = $script:SIEngineRole
    $p = $script:SIEngineDatabaseGrants[0]
    @"
SET NOCOUNT ON;
DECLARE @g int = 0, @why nvarchar(400) = N'';
IF DATABASE_PRINCIPAL_ID(N'$r') IS NULL SELECT @g = 2, @why = N'the role $r is not in this database';
ELSE IF NOT EXISTS (SELECT 1 FROM sys.fn_builtin_permissions(N'DATABASE') WHERE permission_name = N'$p') SELECT @g = 2, @why = N'this SQL Server does not know the right $p';
ELSE IF EXISTS (SELECT 1 FROM sys.database_permissions WHERE class = 0 AND grantee_principal_id = DATABASE_PRINCIPAL_ID(N'$r') AND permission_name = N'$p' AND state IN ('G', 'W')) SET @g = 3;
ELSE
BEGIN
    BEGIN TRY EXEC (N'GRANT $p TO [$r]'); SET @g = 1; END TRY
    BEGIN CATCH SELECT @g = 0, @why = LEFT(ERROR_MESSAGE(), 400); END CATCH
END
SELECT @g AS Granted, @why AS Reason;
"@
}

function Format-SIEngineDatabaseGrantLine {
    <# PURE. The one plain line about Get-SIEngineDatabaseGrantSql's answer (-Granted, -Reason); '' when there is nothing to say. #>
    param($Granted, [string]$Reason = '')
    $p = $script:SIEngineDatabaseGrants[0]
    switch ([string]$Granted) {
        '1' { return ('engine database rights: {0} granted to the role {1} (the database''s own load: the pacing of the large writes)' -f $p, $script:SIEngineRole) }
        '0' { return ('WARNING: engine database rights: {0} could not be granted to the role {1} ({2}) -- the engine paces its large writes on its own measured statement time; an admin grants it through the Support app (setup\Move-SIEngineToLeastPrivilege.ps1, step grants)' -f $p, $script:SIEngineRole, $Reason) }
    }
    ''
}

function Get-SIEngineDatabaseAccessSql {
    <#
        PURE. A NEW install's statements for the engine identity (setup, as the server's Entra admin): its contained user
        by its client id (reused whatever its name -- found by SID), the role and its grants, and the membership. NO
        db_datareader / db_datawriter: framework §12.23 P3, from day one. Returns the user's name and roles as a row.
    #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId,
          # REMOVE-ME with SI_Setup_EngineLeastPrivilege: today's broad roles as well (the default until a fresh test
          # install has proven the role alone -- owner / PIM / Invardia, 2026-10-14)
          [switch]$KeepBroadRoles)
    $sid = '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $n = $UserName.Replace(']', ']]'); $q = $UserName.Replace("'", "''")
    $r = $script:SIEngineRole
    $broad = if ($KeepBroadRoles) { "SET @s = N'ALTER ROLE db_datareader ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);`r`nSET @s = N'ALTER ROLE db_datawriter ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);`r`n" } else { '' }
    @"
DECLARE @n sysname = (SELECT name FROM sys.database_principals WHERE sid = $sid);
IF @n IS NULL BEGIN CREATE USER [$n] WITH SID = $sid, TYPE = E; SET @n = N'$q'; END
$(Get-SIEngineGrantSql)DECLARE @s nvarchar(400) = N'ALTER ROLE [$r] ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
$broad
SELECT @n AS UserName, IS_ROLEMEMBER(N'$r', @n) AS EngineRole, IS_ROLEMEMBER(N'db_datareader', @n) AS DataReader, IS_ROLEMEMBER(N'db_datawriter', @n) AS DataWriter;
"@
}

function Get-SIEngineAccessStateSql {
    <#
        PURE. ONE read-only statement: the engine user's role memberships, and every permission the role si_engine and
        public hold (schema / object, GRANT or DENY). Rows: Kind = member | perm; Name (role); Class; Target; Permission; State.
        Needs only VIEW DEFINITION-level catalog reads (the admin group, the updater).
    #>
    param([Parameter(Mandatory)][string]$UserName)
    $u = $UserName.Replace("'", "''"); $r = $script:SIEngineRole
    $gates = ($script:SIEngineGatedProcedures | ForEach-Object { "(N'$_')" }) -join ', '
    @"
SELECT N'member' AS Kind, rp.name AS Name, CAST(NULL AS nvarchar(60)) AS Class, CAST(NULL AS nvarchar(300)) AS Target, CAST(NULL AS nvarchar(128)) AS Permission, CAST(NULL AS nvarchar(60)) AS State
FROM sys.database_role_members AS m JOIN sys.database_principals AS rp ON rp.principal_id = m.role_principal_id
WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(N'$u')
UNION ALL
SELECT N'perm', gp.name, p.class_desc,
       CASE p.class WHEN 3 THEN SCHEMA_NAME(p.major_id) WHEN 1 THEN OBJECT_SCHEMA_NAME(p.major_id) + N'.' + OBJECT_NAME(p.major_id) WHEN 0 THEN N'DATABASE' END,
       p.permission_name, p.state_desc
FROM sys.database_permissions AS p JOIN sys.database_principals AS gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name IN (N'$r', N'public') AND p.class IN (0, 1, 3)
UNION ALL
SELECT N'gate', v.n, NULL, NULL, NULL,
       CASE WHEN OBJECT_ID(v.n) IS NULL THEN N'absent' WHEN CHARINDEX(N'$r', OBJECT_DEFINITION(OBJECT_ID(v.n))) > 0 THEN N'engine' ELSE N'old' END
FROM (VALUES $gates) AS v(n)
UNION ALL
SELECT N'user', USER_NAME(DATABASE_PRINCIPAL_ID(N'$u')), NULL, NULL, NULL, CASE WHEN DATABASE_PRINCIPAL_ID(N'$u') IS NULL THEN N'missing' ELSE N'present' END;
"@
}

function ConvertFrom-SIEngineAccessRows {
    <# PURE. Rows of Get-SIEngineAccessStateSql (hashtables, PSObjects or DataRows) -> @{ UserPresent; Roles; Granted (schema/object grant rows); Denied; Gates (procedure + engine | old | absent) }. #>
    param([object[]]$Rows = @())
    $get = { param($r, $k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } elseif ($r -is [System.Data.DataRow]) { $r[$k] } else { $r.$k } }
    $gates = New-Object System.Collections.Generic.List[object]
    $roles = New-Object System.Collections.Generic.List[string]; $granted = New-Object System.Collections.Generic.List[object]; $denied = New-Object System.Collections.Generic.List[object]
    $present = $false
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $kind = [string](& $get $r 'Kind')
        if ($kind -eq 'member') { $roles.Add([string](& $get $r 'Name')) }
        elseif ($kind -eq 'gate') { $gates.Add([pscustomobject]@{ Procedure = [string](& $get $r 'Name'); State = [string](& $get $r 'State') }) }
        elseif ($kind -eq 'user') { $present = ([string](& $get $r 'State')) -eq 'present' }
        elseif ($kind -eq 'perm') {
            $class = [string](& $get $r 'Class')
            $row = [pscustomobject]@{ Grantee = [string](& $get $r 'Name'); Kind = $(if ($class -like 'SCHEMA*') { 'schema' } elseif ($class -like 'DATABASE') { 'database' } else { 'object' })
                                      Target = [string](& $get $r 'Target'); Permission = [string](& $get $r 'Permission') }
            if ([string](& $get $r 'State') -like 'DENY*') { $denied.Add($row) } else { $granted.Add($row) }
        }
    }
    [pscustomobject]@{ UserPresent = $present; Roles = $roles.ToArray(); Granted = $granted.ToArray(); Denied = $denied.ToArray(); Gates = $gates.ToArray() }
}

function Test-SIEngineHasPermission {
    <#
        PURE. Would the role (+ public) be allowed -Permission on -Object, given -Granted / -Denied rows (@{ Kind = schema |
        object; Target; Permission })? A DENY on the object or its schema wins. MERGE needs INSERT + UPDATE (the caller
        expands it).
    #>
    param([Parameter(Mandatory)][string]$Object, [Parameter(Mandatory)][string]$Permission, [object[]]$Granted = @(), [object[]]$Denied = @())
    $schema = ($Object -split '\.')[0]
    # VIEW = the object is visible at all (OBJECT_ID / COL_LENGTH answer NULL for an object the caller holds no right on)
    $hit = { param($rows) @($rows | Where-Object { $_ -and ($_.Permission -eq $Permission -or ($Permission -eq 'VIEW' -and $_.Kind -ne 'database')) -and (($_.Kind -eq 'object' -and $_.Target -ieq $Object) -or ($_.Kind -eq 'schema' -and $_.Target -ieq $schema)) }).Count -gt 0 }
    if ($Permission -ne 'VIEW' -and (& $hit $Denied)) { return $false }
    & $hit $Granted
}

function Get-SIEngineShippedAccess {
    <# PURE. The shipped list as the Granted / Denied rows Test-SIEngineHasPermission takes. #>
    $l = Get-SIEngineGrantList
    [pscustomobject]@{ Granted = @($l | Where-Object { $_.Kind -ne 'deny' }); Denied = @($l | Where-Object { $_.Kind -eq 'deny' } | ForEach-Object { [pscustomobject]@{ Kind = 'object'; Target = $_.Target; Permission = $_.Permission } }) }
}

function Test-SIEngineNotEngineCode {
    <# PURE. Is code in -File (relative, '/') inside -Function left out of the inventory? #>
    param([Parameter(Mandatory)][string]$File, [string]$Function)
    foreach ($x in $script:SIEngineNotEngine) {
        if ($x.File -ieq $File -and ($x.Function -eq '*' -or $x.Function -ieq $Function)) { return $true }
    }
    $false
}

function Get-SIEngineSqlReference {
    <#
        THE INVENTORY. Every statement on a product object (schemas sidata, cfg, cmdbsync, vuln, snowstage) in the engine's
        code under -SIRoot (engine\, container\ but not container\updater\, launcher\), with its file, line and enclosing
        function, minus $script:SIEngineNotEngine. Rows @{ File; Line; Function; Verb; Object; Permission }:
          Verb SELECT (FROM / JOIN / APPLY / a quoted name: OBJECT_ID needs the object visible), INSERT, UPDATE, DELETE,
          MERGE (-> INSERT + UPDATE, + DELETE with WHEN NOT MATCHED BY SOURCE ... DELETE), EXECUTE, TRUNCATE (-> ALTER: never
          granted), DDL (CREATE / ALTER / DROP: never granted -- must be guarded so it never runs on a current schema).
        A template name (sidata.{TABLE}, sidata.$t) is reported as '<schema>.*' (a schema grant covers it; a cfg one cannot).
        UPDATE / DELETE through an alias (UPDATE x SET ... FROM <table> x) resolve to the table; an alias of a table
        variable or #temp table is not a product object and is left out.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $schemas = ($script:SIEngineProductSchemas -join '|')
    $obj = "(?:\[?(?<s>$schemas)\]?\.\[?(?<o>[A-Za-z_]\w*|\$\w+|\{\w+\}|\$\(\`$\w+\)|\{\d+\})\]?)"
    $roots = @('engine', 'container', 'launcher') | ForEach-Object { [IO.Path]::Combine($SIRoot, $_) } | Where-Object { Test-Path -LiteralPath $_ }
    $files = @(Get-ChildItem -LiteralPath $roots -Recurse -File -Include *.ps1, *.psm1 | Where-Object { $_.FullName -notmatch '[\\/]container[\\/]updater[\\/]' })
    foreach ($x in $script:SIEngineExtraFiles) { $p = [IO.Path]::Combine($SIRoot, $x); if (Test-Path -LiteralPath $p) { $files += Get-Item -LiteralPath $p } }
    $files = @($files | Sort-Object FullName -Unique)
    $pats = @(
        @{ V = 'INSERT';   R = "(?i)\bINSERT\s+(?:INTO\s+)?$obj" }
        @{ V = 'UPDATE';   R = "(?i)\bUPDATE\s+$obj\s+SET\b" }
        @{ V = 'DELETE';   R = "(?i)\bDELETE\s+(?:TOP\s*\(\s*@?\w+\s*\)\s+)?(?:FROM\s+)?$obj" }
        @{ V = 'MERGE';    R = "(?i)\bMERGE\s+(?:INTO\s+)?(?:TOP\s*\(\s*@?\w+\s*\)\s+)?$obj" }
        @{ V = 'EXECUTE';  R = "(?i)\bEXEC(?:UTE)?\s+(?:@\w+\s*=\s*)?$obj" }
        @{ V = 'TRUNCATE'; R = "(?i)\bTRUNCATE\s+TABLE\s+$obj" }
        @{ V = 'SELECT';   R = "(?i)\b(?:FROM|JOIN|APPLY)\s+$obj" }
        @{ V = 'VIEW';     R = "(?i)['""]$obj['""]" }
        @{ V = 'DDL';      R = "(?i)\b(?:CREATE|ALTER|DROP)\s+(?:TABLE|VIEW|PROCEDURE|PROC|TRIGGER|(?:UNIQUE\s+)?(?:CLUSTERED\s+|NONCLUSTERED\s+)?INDEX\s+\w+\s+ON)\s+$obj" }
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($SIRoot.TrimEnd('\', '/').Length + 1).Replace('\', '/')
        $t = [IO.File]::ReadAllText($f.FullName)
        # the line of every offset, and the function every line is in
        $starts = New-Object System.Collections.Generic.List[int]; $starts.Add(0)
        for ($i = 0; $i -lt $t.Length; $i++) { if ($t[$i] -eq "`n") { $starts.Add($i + 1) } }
        $lineOf = { param($ix) $lo = 0; $hi = $starts.Count - 1; while ($lo -lt $hi) { $mid = [int][Math]::Ceiling(($lo + $hi) / 2); if ($starts[$mid] -le $ix) { $lo = $mid } else { $hi = $mid - 1 } }; $lo + 1 }
        $fnAt = @{}; $cur = ''
        $lines = $t -split "`n"
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*function\s+(?:global:|script:)?([\w-]+)') { $cur = $Matches[1] }; $fnAt[$i + 1] = $cur }
        $add = {
            param($ix, $verb, $s, $o)
            $line = & $lineOf $ix
            $fn = [string]$fnAt[$line]
            if (Test-SIEngineNotEngineCode -File $rel -Function $fn) { return }
            # a quoted 'vuln.cve' is a JSON path, not an object: SI's objects are PascalCase (views vPascal)
            if ($verb -eq 'VIEW' -and $o -cnotmatch '^(?:[A-Z]|v[A-Z])') { return }
            if ($verb -eq 'VIEW' -and @($script:SIEngineNotSqlText | Where-Object { $_.File -ieq $rel -and $_.Object -ieq ('{0}.{1}' -f $s, $o) }).Count) { return }
            $name = if ($o -match '^[A-Za-z_]\w*$') { '{0}.{1}' -f $s.ToLowerInvariant(), $o } else { '{0}.*' -f $s.ToLowerInvariant() }
            $perms = switch ($verb) { 'MERGE' { @('INSERT', 'UPDATE') } 'TRUNCATE' { @('ALTER') } 'DDL' { @('DDL') } default { @($verb) } }
            if ($verb -eq 'MERGE') {
                $win = $t.Substring($ix, [Math]::Min(4000, $t.Length - $ix))
                $end = [regex]::Match($win, '(?s)^.*?;'); $stmt = if ($end.Success) { $end.Value } else { $win }
                if ($stmt -match '(?i)\bTHEN\s+DELETE\b') { $perms += 'DELETE' }
            }
            foreach ($p in $perms) { $out.Add([pscustomobject]@{ File = $rel; Line = $line; Function = $fn; Verb = $verb; Object = $name; Permission = $p }) }
        }
        foreach ($p in $pats) { foreach ($m in [regex]::Matches($t, $p.R)) { & $add $m.Index $p.V $m.Groups['s'].Value $m.Groups['o'].Value } }
        foreach ($m in [regex]::Matches($t, '(?i)\b(UPDATE|DELETE)\s+(?!TOP\b)(?<a>[A-Za-z_]\w{0,10})\s+(?:SET|FROM|OUTPUT|WHERE)\b')) {
            $a = $m.Groups['a'].Value
            if ($a -match "^(?i)($schemas|FROM)$") { continue }
            $win = $t.Substring($m.Index, [Math]::Min(3000, $t.Length - $m.Index))
            $mm = [regex]::Match($win, "(?i)$obj\s+(?:AS\s+)?$a\b")
            if ($mm.Success) { & $add $m.Index $m.Groups[1].Value.ToUpperInvariant() $mm.Groups['s'].Value $mm.Groups['o'].Value }
        }
    }
    , @($out | Sort-Object File, Line, Object, Permission -Unique)
}

function Get-SIEngineRequiredPermission {
    <# PURE. The inventory folded to one row per object and permission: @{ Object; Permission; Sites (file:line, ...) }. DDL left out. #>
    param([object[]]$References = @())
    $h = [ordered]@{}
    foreach ($r in @($References | Where-Object { $_ -and $_.Permission -ne 'DDL' })) {
        $k = '{0}|{1}' -f $r.Object.ToLowerInvariant(), $r.Permission
        if (-not $h.Contains($k)) { $h[$k] = [pscustomobject]@{ Object = $r.Object; Permission = $r.Permission; Sites = (New-Object System.Collections.Generic.List[string]) } }
        $h[$k].Sites.Add(('{0}:{1}' -f $r.File, $r.Line))
    }
    , @($h.Values | Sort-Object Object, Permission)
}

function Test-SIEngineGrantCoverage {
    <#
        PURE. Every permission the engine's statements need (-Required, Get-SIEngineRequiredPermission) against what the role
        holds (-Granted / -Denied rows: the shipped list, or the database's real grants). '<schema>.*' (a template name)
        needs the SCHEMA grant. Returns @{ Ok; Refused = @{ Object; Permission; Sites } }.
    #>
    param([object[]]$Required = @(), [object[]]$Granted = @(), [object[]]$Denied = @())
    $refused = New-Object System.Collections.Generic.List[object]
    foreach ($q in @($Required | Where-Object { $_ })) {
        $ok = if ($q.Object -like '*.`*') {
            $s = ($q.Object -split '\.')[0]
            @($Granted | Where-Object { $_.Kind -eq 'schema' -and $_.Target -ieq $s -and ($_.Permission -eq $q.Permission -or $q.Permission -eq 'VIEW') }).Count -gt 0
        } else { Test-SIEngineHasPermission -Object $q.Object -Permission $q.Permission -Granted $Granted -Denied $Denied }
        if (-not $ok) { $refused.Add($q) }
    }
    [pscustomobject]@{ Ok = ($refused.Count -eq 0); Refused = $refused.ToArray() }
}

function Format-SIEngineRefused {
    <# PURE. The refused statements in plain words, one line each (first three sites). #>
    param([object[]]$Refused = @())
    @($Refused | ForEach-Object { '{0} on {1} -- needed by {2}' -f $_.Permission, $_.Object, ((@($_.Sites) | Select-Object -First 3) -join ', ') })
}

function Get-SIEngineAccessDrift {
    <#
        THE UPDATER'S CHECK (framework §12.23 P8: the updater changes no security; it checks and warns, never blocks).
        -State: ConvertFrom-SIEngineAccessRows of the database; -Required: the RELEASE's inventory. Returns @{ Status; Lines }:
          missing      the engine user is not in the database (nothing to compare);
          not-moved    the user still has db_datareader / db_datawriter -- the cut-over has not run (or only its first run): said once, no warning;
          ok           the user is in si_engine only and the role allows every statement of this release;
          drift        anything else, each in plain words: a statement the role would refuse (with file:line), a role the
                       user should not have (db_owner, db_ddladmin, db_securityadmin, ...), or the user not in si_engine.
    #>
    param([Parameter(Mandatory)]$State, [object[]]$Required = @(), [string]$UserName = 'the engine identity')
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $State.UserPresent) { return [pscustomobject]@{ Status = 'missing'; Lines = @("$UserName has no user in the Pro database -- nothing to check") } }
    $roles = @($State.Roles)
    $broad = @($roles | Where-Object { $_ -in 'db_datareader', 'db_datawriter' })
    $extra = @($roles | Where-Object { $_ -notin @('db_datareader', 'db_datawriter', $script:SIEngineRole) })
    $inRole = $roles -contains $script:SIEngineRole
    if ($extra.Count) { $lines.Add(('{0} is also in {1} -- the engine needs none of these; remove them through the Support app' -f $UserName, ($extra -join ', '))) }
    if ($inRole) {
        $cov = Test-SIEngineGrantCoverage -Required $Required -Granted @($State.Granted) -Denied @($State.Denied)
        if (-not $cov.Ok) {
            $lines.Add(('the role {0} would refuse {1} statement(s) of this release -- run setup\Move-SIEngineToLeastPrivilege.ps1 (step 1, the grants) through the Support app:' -f $script:SIEngineRole, $cov.Refused.Count))
            foreach ($l in (Format-SIEngineRefused -Refused $cov.Refused)) { $lines.Add('  ' + $l) }
        }
    } elseif (-not $broad.Count) {
        $lines.Add(('{0} is neither in {1} nor in db_datareader / db_datawriter -- the engine cannot read or write; run setup\Move-SIEngineToLeastPrivilege.ps1 through the Support app' -f $UserName, $script:SIEngineRole))
    }
    $old = @(@($State.PSObject.Properties['Gates'] | ForEach-Object { $_.Value }) | ForEach-Object { $_ } | Where-Object { $_ -and $_.State -eq 'old' } | ForEach-Object { $_.Procedure })
    if ($old.Count -and $inRole -and -not $broad.Count) { $lines.Add(('{0} still let(s) only db_datawriter in -- the engine''s retention / backup step is refused; apply this release''s schema' -f ($old -join ', '))) }
    if ($lines.Count) { return [pscustomobject]@{ Status = 'drift'; Lines = $lines.ToArray() } }
    if ($broad.Count) {
        $how = if ($inRole) { 'it is in {0} too: the cut-over''s second run (-RemoveBroadRoles) has not run' -f $script:SIEngineRole } else { 'the cut-over (setup\Move-SIEngineToLeastPrivilege.ps1) has not run' }
        return [pscustomobject]@{ Status = 'not-moved'; Lines = @(('{0} still has {1} -- {2}' -f $UserName, ($broad -join ' + '), $how)) }
    }
    [pscustomobject]@{ Status = 'ok'; Lines = @(('{0} has exactly the agreed rights (role {1}; every statement of this release allowed)' -f $UserName, $script:SIEngineRole)) }
}

function Test-SIEngineCutoverReady {
    <#
        PURE. THE CUT-OVER'S PROOF (setup\Move-SIEngineToLeastPrivilege.ps1 step 3): with -State read from the database and
        -Required = this release's inventory, would the engine keep working with si_engine ALONE? Every one must hold:
        the user is there and in si_engine; the ROLE's grants (+ public's; the broad roles do NOT count) allow every
        statement; no gated procedure still lets only db_datawriter in. Returns @{ Ok; Lines; Refused }.
    #>
    param([Parameter(Mandatory)]$State, [object[]]$Required = @(), [string]$UserName = 'the engine identity')
    $lines = New-Object System.Collections.Generic.List[string]
    $refused = @()
    if (-not $State.UserPresent) { $lines.Add("$UserName has no user in this database") }
    elseif (@($State.Roles) -notcontains $script:SIEngineRole) { $lines.Add(('{0} is not in the role {1} yet (step 2)' -f $UserName, $script:SIEngineRole)) }
    $cov = Test-SIEngineGrantCoverage -Required $Required -Granted @($State.Granted) -Denied @($State.Denied)
    if (-not $cov.Ok) {
        $refused = @($cov.Refused)
        $lines.Add(('the role {0} would refuse {1} statement(s) the engine runs:' -f $script:SIEngineRole, $refused.Count))
        foreach ($l in (Format-SIEngineRefused -Refused $refused)) { $lines.Add('  ' + $l) }
    }
    foreach ($g in @($State.Gates | Where-Object { $_ -and $_.State -eq 'old' })) {
        $lines.Add(('{0} still lets only db_datawriter in -- apply this release''s schema first (the update does it)' -f $g.Procedure))
    }
    [pscustomobject]@{ Ok = ($lines.Count -eq 0); Lines = $lines.ToArray(); Refused = $refused }
}

function Test-SIEngineLeastPrivilegeSetup {
    <#
        REMOVE-ME once a fresh test install has proven the role alone (decided 2026-10-14 by SI, PIM and Invardia: no setup
        change reaches new installs before that). PURE. Is SI_Setup_EngineLeastPrivilege ON for this install? Read from the
        install's values (-Values: the guided install's answers / install-parameters.json), else the environment
        (-Env, default the process). OFF BY DEFAULT: only 'true' / '1' / 'yes' / 'on' turns it on.
          OFF  a new install gives the engine today's db_datareader + db_datawriter AND si_engine with its grants (harmless:
               it prepares the cut-over);
          ON   si_engine ONLY.
    #>
    param([System.Collections.IDictionary]$Values, [System.Collections.IDictionary]$Env)
    $name = 'SI_Setup_EngineLeastPrivilege'
    $v = $null
    if ($Values -and $Values.Contains($name)) { $v = $Values[$name] }
    if ($null -eq $v -or "$v".Trim() -eq '') { $v = if ($Env) { if ($Env.Contains($name)) { $Env[$name] } else { $null } } else { [Environment]::GetEnvironmentVariable($name) } }
    "$v".Trim() -match '^(?i)(true|1|yes|on)$'
}
