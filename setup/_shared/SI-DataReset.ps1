#Requires -Version 5.1
<#
    SecurityInsight Pro -- A FRESH START OF THE DATA: empty the install's DATA in place, keep its plumbing.
    (setup\Reset-SIData.ps1 is the thin wrapper a person runs; everything that decides and every statement lives here.)

    WHY. An install whose scope was wrong for a while carries CIs, findings and history that should never have been
    collected. When the customer does not use SecurityInsight yet and asks for a clean start, the data is emptied and the
    scheduled pipeline fills it again from the sources. The install itself -- its databases, identities, users, roles,
    grants, the signed grant procedure, settings and templates -- is not touched: SQL access is never lost.

    WHAT IS EMPTIED (derived, never a hand list that can drift):
      * the Pro database: EVERY table of every DATA schema. The data schemas are the schemas the Pro schema files create
        (Get-SIProSchemaFileList in engine\pro-settings\SI-ProSchema.ps1) other than 'cfg' -- today sidata, vuln, cmdbsync
        and snowstage. The tables are the ones those files create in them PLUS every table the database holds in them that
        the files do not name (the published copies sidata.<Table>Pub and other tables made at run time): a data schema
        holds data only.
      * the identity ledger database ONLY with -IncludeIdentityLedger (opt-in): every table sql\si-identity-schema.sql
        creates, except si.SchemaVersion. By default the ledger is KEPT: nothing outside SecurityInsight holds its ids, it
        is not what makes the runs slow, the catch-up of the last collections keeps matching ids, and a ledger row for an
        object that is out of scope makes no CI.
      * four run-history tables of 'cfg' that describe the emptied data (each is under notConfiguration in
        config\config-entities.locked.json -- never configuration; a test holds the list to that):
          cfg.ConnectorRun     the connectors' run results over the emptied findings (the Connector status page).
          cfg.ConnectorChange  the per-item change log of the connectors (field before / now) over the emptied CIs and
                               findings -- the largest cfg table at a big install, and every row names a key that is gone.
          cfg.DataOutItem      what each data-out output sent last time, per item: the BEFORE its next run compares with.
                               Kept, the first fresh run would report every old CI as removed.
          cfg.DataOutBatch     the data-out batches over the emptied data (their counts and import results).

    WHAT IS KEPT (everything else), notably:
      * every cfg table not listed above: the configuration set (cfg.Setting, cfg.Template, the overrides, access,
        connectors, departments ... -- config\config-entities.locked.json), the template revisions and staged packs, the
        change journal (cfg.ConfigJournal), the audit trail (cfg.AuditEvent, cfg.ChangeLog), cfg.InstallState (schema version,
        ring, licence request), the support consent / grant tables, the pipeline's lock, queue and run records.
        Kept on purpose although they are run records:
          cfg.FlowRun / cfg.FlowStepRun  the pipeline runner's slot and catch-up memory, the updater's run gate, the
                               heartbeat's status and support's diagnosis read them; one row per run / step, no CI data.
          cfg.PerfSample / cfg.StepPhaseTime / cfg.StepProgress  measurements of the load and of each phase's time -- they
                               hold no CI data and are the before / after comparison of the running time (PerfSample prunes
                               itself after 30 days).
          cfg.ConnectorItem    a REST connector's key to every item it created in ANOTHER system: emptied, it could no
                               longer update or close them.
          person-made records on findings (comments, tasks, governance, exemption requests): kept, never removed silently.
      * the identity ledger (unless -IncludeIdentityLedger): stable ids; an object out of scope makes no CI. Its
        si.SchemaVersion (the recorded approval of the ledger's schema, SCHEMA-1) is kept in every case.
      * every database user, role, grant, DENY and procedure: TRUNCATE / DELETE touch rows only.

    HOW. TRUNCATE where no foreign key from another table points at the table; else DELETE in batches (each batch its own
    statement, paced, the batch size measured and adapted -- a single huge DELETE would fill the log). A TRUNCATE that the
    database refuses falls back to the batches. A table referenced by others is emptied after them. Identity values
    CONTINUE where they were (a TRUNCATE is reseeded to the next value): an id is never handed out twice, so a kept record
    that names an old id (a comment, a resend request) can never point at a new, unrelated row.

    WHEN. PLAN by default: per table the rows and MB that would go, what is kept, and anything that holds the reset.
    -Apply refuses while the install is busy -- the 3.0.57 liveness rule (engine\_shared\SI-ExecutionLiveness.ps1): an
    execution is RUNNING only while it beats a lock row of cfg.PipelineLock ('install' = a pipeline run, an update, the
    index build; 'updater'; 'housekeeping'), so a held row with a fresh beat (15 minutes; never beaten: 30 minutes from
    when it was taken) is a running job -- or while the newest pipeline run is not ended or a step is Starting / Running
    (the updater's run gate, container\updater\_shared\SI-UpdaterRunGate.ps1), or while data-out holds sidata.DataOutLock.
    It then TAKES the install lock (cfg.PipelineLock 'install', the lock every run and update takes) for the whole reset,
    beats it, and releases it at the end, so no run, update or index build starts meanwhile.
    It also refuses when another system holds SecurityInsight's keys (a live ServiceNow / REST output has sent data:
    cfg.DataOutBatch live batches, cfg.ConnectorItem rows or a servicenow / rest connector in apply mode) unless
    -AcceptExternalKeysLost: the fresh data gets new keys and that system would see new records next to its old ones.

    IDEMPOTENT. A second -Apply on an emptied install changes nothing and says so. After -Apply it READS BACK: every
    emptied table has 0 rows, no kept table has fewer rows than before, and the two identity scope settings
    (SI_Identity_SkipNeverSyncedDisabledAd, SI_Identity_SkipDeletedGroups) are on -- a stored false is said, never changed;
    no row = the shipped default, on (launcher\_lib\SecurityInsight.shared-defaults.ps1; an install that never stored a
    setting gets the default -- the rule of engine\_shared\SI-DisabledAssets.ps1). Recorded on the audit trail
    (data.store.reset, actor source setup) with the rows per table; one log line per table.

    THE SEAM: -Invoke / -IdentityInvoke { param([string]$sql, $params, [string]$mode) } -- the (sql, params, mode
    'reader' | 'scalar' | 'nonquery') seam of every Pro store (New-SIProSettingsStore), or the Invardia Support app's SQL
    (New-SIDataResetSupportStore). Every statement carries a /*si-datareset:<name>*/ marker. PS 5.1 and 7; no module.
#>

if (-not (Get-Command -Name Get-SIProSchemaFileList -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'pro-settings', 'SI-ProSchema.ps1'))
}
if (-not (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'pro-settings', 'SI-Audit.ps1'))
}

$script:SIDataResetRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Get-SIDataResetContract {
    <# PURE. The names and numbers of the reset (a function, so every scope that dot-sources this file reads the same). #>
    [pscustomobject]@{
        ConfigSchema        = 'cfg'
        IdentitySchemaFile  = 'sql/si-identity-schema.sql'
        # the cfg tables that are run history of the emptied data -- see the header for each reason
        RunHistory          = [ordered]@{
            'cfg.ConnectorRun'    = 'the connectors'' run results over the emptied findings'
            'cfg.ConnectorChange' = 'the connectors'' per-item change log over the emptied CIs and findings'
            'cfg.DataOutItem'     = 'what each data-out output sent last time (the before of its next run) -- kept, the first fresh run would report every old CI as removed'
            'cfg.DataOutBatch'    = 'the data-out batches over the emptied data'
        }
        LedgerKeptWhy       = 'the identity ledger: stable ids; an object out of scope makes no CI'
        IdentityKeep        = [ordered]@{ 'si.SchemaVersion' = 'the recorded approval of the identity ledger''s schema' }
        # tables in a data schema that hold what a PERSON decided: emptied with the rest, but said when they hold rows
        PersonEntered       = @('sidata.CiOverride', 'sidata.CiSuspectDecision', 'sidata.CiSuspectDecisionRecord', 'sidata.ContextProposal')
        IdentitySettings    = @('SI_Identity_SkipNeverSyncedDisabledAd', 'SI_Identity_SkipDeletedGroups')
        RunEnded            = @('Succeeded', 'Failed', 'Stopped', 'Cancelled')
        InstallLock         = 'install'
        HolderPrefix        = 'setup:Reset-SIData:'
        What                = 'a fresh start of SecurityInsight data (setup\Reset-SIData.ps1)'
        BeatStaleMinutes    = 15
        NeverBeatMinutes    = 30
        BeatEverySeconds    = 60
        BatchStartRows      = 5000
        BatchMinRows        = 500
        BatchMaxRows        = 200000
        BatchFastSeconds    = 2
        BatchSlowSeconds    = 10
        PauseMilliseconds   = 250
        AuditAction         = 'data.store.reset'
        # #1148: a statement (the lock's take / beat / release included) that meets a passing answer -- the Support app's
        # rate limit (429), its audit log that could not record it, the network, a transient Azure SQL answer -- is sent
        # again after these waits (seconds); a database refusal (a foreign key, a permission) is never retried
        RetryWaitsSeconds   = @(5, 15, 30, 60, 120)
        # #1148: the quick empties go as FEW statements: this many tables per statement (one audited action per batch)
        TruncateBatchTables = 25
    }
}

function Test-SIDataResetRetryable {
    <#
        PURE. #1148: is this failed statement's answer a PASSING one, so the same statement may be sent again? Yes: the
        Invardia Support app's rate limit (429 / tooManyRequests / throttled), its audit log that could not record the action
        (it refuses fail-closed: nothing ran), a gateway / service answer (502 / 503 / 504, timed out), a transport / network
        error, and Azure SQL's transient answers (a deadlock victim 1205, 40613, 40501, 40197, 49918-49920, 4060, 10928 /
        10929, 10053 / 10054). Never: the database's own refusal -- a foreign key (4712), a permission, a syntax or object
        error -- that one is the answer.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    $m = "$Message"
    if (-not $m.Trim()) { return $false }
    if ($m -match '(?i)FOREIGN KEY|\b4712\b|permission was denied|does not have permission|Cannot find the object|Invalid object name|Incorrect syntax') { return $false }
    [bool]($m -match '(?i)\b429\b|too ?many ?requests|throttl|rate.?limit|could not be recorded in the customer''s audit log|audit log .*(could not|unavailable)|\b50[234]\b|service unavailable|bad gateway|gateway time-?out|timed out|timeout expired|transport-level error|network-related|forcibly closed|connection reset|chosen as the deadlock victim|\b(1205|40613|40501|40197|49918|49919|49920|4060|10928|10929|10053|10054)\b|is not currently available|try again later')
}

function Invoke-SIDataResetCall {
    <#
        #1148: ONE statement through -Invoke, sent again after each -Waits (seconds; default the contract's) while its answer
        is a passing one (Test-SIDataResetRetryable), each retry said through -Log; any other answer, or the last one, is
        thrown as it came. -Mode reader returns the rows flat (as Invoke-SIDataResetRows). -Pause { param([int]$ms) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, $Params, [string]$Mode = 'reader', [string]$What = 'a statement',
          [scriptblock]$Log, [scriptblock]$Pause, [int[]]$Waits)
    if ($null -eq $Params) { $Params = @{} }
    if (-not $PSBoundParameters.ContainsKey('Waits')) { $Waits = @((Get-SIDataResetContract).RetryWaitsSeconds) }
    $try = 0
    while ($true) {
        try {
            if ($Mode -eq 'reader') { return @(& $Invoke $Sql $Params 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
            return (& $Invoke $Sql $Params $Mode)
        } catch {
            $em = (([string]$_.Exception.Message) -split "`n")[0]
            if ($try -ge @($Waits).Count -or -not (Test-SIDataResetRetryable -Message ([string]$_.Exception.Message))) { throw }
            $w = [int]$Waits[$try]; $try++
            if ($Log) { $null = & $Log 'WARN' ('  {0}: a passing answer ({1}) -- sent again in {2} s (try {3} of {4})' -f $What, $em, $w, ($try + 1), (@($Waits).Count + 1)) }
            if ($Pause) { & $Pause ($w * 1000) } else { Start-Sleep -Seconds $w }
        }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE TABLE LIST -- derived from the shipped schema files
# ---------------------------------------------------------------------------------------------------------------------
function Get-SIDataResetSqlObjects {
    <# PURE (reads one file). The schemas and tables a schema file CREATEs: @{ Schemas = @(); Tables = @('schema.Table') }.
       A dynamically built name (sidata.'' + ...) is not a name and is left out. #>
    param([Parameter(Mandatory)][string]$Path)
    $text = [IO.File]::ReadAllText($Path)
    $schemas = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($text, '(?i)\bCREATE\s+SCHEMA\s+\[?(?<s>[A-Za-z_]\w*)\]?')) {
        $s = $m.Groups['s'].Value
        if (-not ($schemas -contains $s)) { $schemas.Add($s) }
    }
    $tables = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($text, '(?i)\bCREATE\s+TABLE\s+\[?(?<s>[A-Za-z_]\w*)\]?\.\[?(?<t>[A-Za-z_]\w*)\]?')) {
        $n = '{0}.{1}' -f $m.Groups['s'].Value, $m.Groups['t'].Value
        if (-not ($tables -contains $n)) { $tables.Add($n) }
    }
    [pscustomobject]@{ Schemas = $schemas.ToArray(); Tables = $tables.ToArray() }
}

function Get-SIDataResetCatalog {
    <#
        PURE (reads the shipped files). What the reset empties and keeps, from the files:
          DataSchemas     the schemas the Pro schema files create, other than cfg
          DataTables      the tables the files create in a data schema (the database may hold more -- added at plan time)
          ConfigTables    the tables the files create in cfg
          RunHistory      the cfg run-history tables (ordered name -> reason), checked against config-entities.locked.json:
                          each must be a cfg table of the files, listed under notConfiguration and never an entity -- else
                          this throws (a reset never empties configuration)
          IdentityTables  the identity ledger's tables to empty; IdentityKeep the ones kept (name -> reason)
          ConfigReasons   cfg table -> why it is kept (the configuration set, or its notConfiguration reason)
        -SchemaFiles: the Pro schema files (relative paths; default Get-SIProSchemaFileList) -- the test seam.
    #>
    param([string]$SIRoot = $script:SIDataResetRoot, [string[]]$SchemaFiles, [string]$IdentityFile, [string]$EntitiesFile)
    $c = Get-SIDataResetContract
    if (-not $SchemaFiles) { $SchemaFiles = @(Get-SIProSchemaFileList | ForEach-Object { [string]$_.File }) }
    if (-not $IdentityFile) { $IdentityFile = $c.IdentitySchemaFile }
    if (-not $EntitiesFile) { $EntitiesFile = 'config/config-entities.locked.json' }
    $full = { param([string]$rel) if ([IO.Path]::IsPathRooted($rel)) { $rel } else { [IO.Path]::Combine($SIRoot, ($rel -replace '[\\/]', [IO.Path]::DirectorySeparatorChar)) } }

    $schemas = New-Object System.Collections.Generic.List[string]
    $allTables = New-Object System.Collections.Generic.List[string]
    foreach ($f in $SchemaFiles) {
        $o = Get-SIDataResetSqlObjects -Path (& $full $f)
        foreach ($s in $o.Schemas) { if (-not ($schemas -contains $s)) { $schemas.Add($s) } }
        foreach ($t in $o.Tables) { if (-not ($allTables -contains $t)) { $allTables.Add($t) } }
    }
    if (-not ($schemas -contains $c.ConfigSchema)) { throw ('the Pro schema files create no ''{0}'' schema -- the configuration cannot be told from the data; nothing is planned' -f $c.ConfigSchema) }
    $dataSchemas = @($schemas | Where-Object { $_ -ne $c.ConfigSchema } | Sort-Object)
    $dataTables = @($allTables | Where-Object { $dataSchemas -contains ($_ -split '\.')[0] } | Sort-Object -Unique)
    $cfgTables = @($allTables | Where-Object { ($_ -split '\.')[0] -eq $c.ConfigSchema } | Sort-Object -Unique)

    # the configuration set: every cfg table is an entity (configuration) or listed under notConfiguration with its reason
    $ent = [IO.File]::ReadAllText((& $full $EntitiesFile)) | ConvertFrom-Json
    $entityTables = @($ent.entities | ForEach-Object { [string]$_.table })
    $notCfg = @{}; foreach ($n in @($ent.notConfiguration)) { $notCfg[[string]$n.table] = [string]$n.why }
    foreach ($t in @($c.RunHistory.Keys)) {
        if ($entityTables -contains $t) { throw ('{0} is configuration (config\config-entities.locked.json) -- a reset never empties configuration' -f $t) }
        if (-not $notCfg.ContainsKey($t)) { throw ('{0} is not listed under notConfiguration in config\config-entities.locked.json -- not known to be run history; nothing is planned' -f $t) }
        if (-not ($cfgTables -contains $t)) { throw ('{0} is not a table of the Pro schema files -- nothing is planned' -f $t) }
    }
    $reasons = [ordered]@{}
    foreach ($t in $cfgTables) {
        if ($c.RunHistory.Contains($t)) { continue }
        $reasons[$t] = if ($entityTables -contains $t) { 'configuration' } elseif ($notCfg.ContainsKey($t)) { $notCfg[$t] } else { 'a cfg table (kept)' }
    }

    $idObj = Get-SIDataResetSqlObjects -Path (& $full $IdentityFile)
    $idTables = @($idObj.Tables | Where-Object { -not $c.IdentityKeep.Contains($_) } | Sort-Object)
    [pscustomobject]@{
        DataSchemas    = $dataSchemas
        DataTables     = $dataTables
        ConfigTables   = $cfgTables
        RunHistory     = $c.RunHistory
        IdentitySchemas = @($idObj.Schemas)
        IdentityTables = $idTables
        IdentityKeep   = $c.IdentityKeep
        ConfigReasons  = $reasons
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS -- pure text, one marker each
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-SIDataResetQuoted {
    <# PURE. 'schema.Table' -> '[schema].[Table]'; refuses anything that is not two plain names. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^(?<s>[A-Za-z_]\w*)\.(?<t>[A-Za-z_]\w*)$') { throw "not a table name: $Name" }
    '[{0}].[{1}]' -f $Matches['s'], $Matches['t']
}

function Get-SIDataResetSql {
    <#
        PURE. The statements. -Name: Location | Inventory (-Schemas) | ForeignKeys | Gate (params @Holder, @What; -Claim takes the lock, else read only) |
        Beat / Release (@Holder, @What) | External | Settings | Truncate / Reseed / DeleteBatch / Count (-Table, -Value, -Rows)
        | CountMany (-Tables).
    #>
    param([Parameter(Mandatory)][ValidateSet('Location', 'Inventory', 'ForeignKeys', 'Gate', 'Beat', 'Release', 'External', 'Settings', 'Truncate', 'TruncateBatch', 'AbortResumable', 'Reseed', 'DeleteBatch', 'CountMany')][string]$Name,
          [string[]]$Schemas = @(), [string]$Table, [decimal]$Value = 0, [int]$Rows = 0, [string[]]$Tables = @(), [switch]$Claim,
          # TruncateBatch: the tables, each @{ Name; HasIdentity; IdentCurrent; IdentIncr } (a plan entry)
          [object[]]$Batch = @())
    $c = Get-SIDataResetContract
    switch ($Name) {
        'Location' { @'
/*si-datareset:location*/ SET NOCOUNT ON;
DECLARE @data nvarchar(max) = NULL, @ledgerDb nvarchar(max) = NULL, @ledgerSrv nvarchar(max) = NULL;
IF OBJECT_ID(N'cfg.Setting') IS NOT NULL
BEGIN
    SELECT @data = ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name = N'SI_Pro_DataSqlDatabase';
    SELECT @ledgerDb = ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name = N'SI_LedgerDatabase';
    SELECT @ledgerSrv = ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name = N'SI_LedgerSqlServer';
END
SELECT DB_NAME() AS DatabaseName, @data AS DataDatabase, @ledgerDb AS LedgerDatabase, @ledgerSrv AS LedgerServer;
'@ }
        'Inventory' {
            $in = (@($Schemas | ForEach-Object { if ($_ -notmatch '^[A-Za-z_]\w*$') { throw "not a schema name: $_" }; "N'$_'" })) -join ', '
            if (-not $in) { $in = "N''" }
@"
/*si-datareset:inventory*/ SET NOCOUNT ON;
SELECT s.name AS SchemaName, t.name AS TableName,
       CAST(ISNULL((SELECT SUM(p.rows) FROM sys.partitions AS p WHERE p.object_id = t.object_id AND p.index_id IN (0, 1)), 0) AS bigint) AS RowCnt,
       CAST(ISNULL((SELECT SUM(a.total_pages) FROM sys.partitions AS p JOIN sys.allocation_units AS a
                     ON a.container_id = CASE WHEN a.type IN (1, 3) THEN p.hobt_id ELSE p.partition_id END
                    WHERE p.object_id = t.object_id), 0) * 8 / 1024.0 AS decimal(18, 1)) AS SizeMB,
       CAST(OBJECTPROPERTY(t.object_id, 'TableHasIdentity') AS int) AS HasIdentity,
       CAST(IDENT_CURRENT(QUOTENAME(s.name) + N'.' + QUOTENAME(t.name)) AS decimal(38, 0)) AS IdentCurrent,
       CAST(IDENT_INCR(QUOTENAME(s.name) + N'.' + QUOTENAME(t.name)) AS decimal(38, 0)) AS IdentIncr
FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE t.is_ms_shipped = 0 AND s.name IN ($in)
ORDER BY s.name, t.name;
"@ }
        'ForeignKeys' { @'
/*si-datareset:foreignkeys*/ SET NOCOUNT ON;
SELECT ps.name + N'.' + pt.name AS ParentTable, rs.name + N'.' + rt.name AS RefTable
FROM sys.foreign_keys AS fk
JOIN sys.tables AS pt ON pt.object_id = fk.parent_object_id JOIN sys.schemas AS ps ON ps.schema_id = pt.schema_id
JOIN sys.tables AS rt ON rt.object_id = fk.referenced_object_id JOIN sys.schemas AS rs ON rs.schema_id = rt.schema_id
WHERE fk.parent_object_id <> fk.referenced_object_id;
'@ }
        'Gate' {
            # -Claim: one transaction -- the lock rows first (UPDLOCK, so no runner takes the lock between the read and the
            # claim), then the runs, then the claim. Without it: the same checks, read only (the plan and -WhatIf write nothing).
            $ended = (@($c.RunEnded | ForEach-Object { "N'$_'" })) -join ', '
            $hint = if ($Claim) { ' WITH (UPDLOCK, HOLDLOCK)' } else { '' }
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine($(if ($Claim) { '/*si-datareset:gate*/ SET NOCOUNT ON; SET XACT_ABORT ON;' } else { '/*si-datareset:check*/ SET NOCOUNT ON;' }))
            [void]$sb.AppendLine(@"
DECLARE @now datetime2(0) = SYSUTCDATETIME();
DECLARE @verdict nvarchar(8) = NULL, @kind nvarchar(16) = NULL, @busy nvarchar(600) = NULL, @mode nvarchar(16) = NULL;
DECLARE @runId nvarchar(64), @runState nvarchar(16), @runStarted datetime2(0);
IF OBJECT_ID(N'cfg.JobFlow') IS NOT NULL SELECT @mode = Mode FROM cfg.JobFlow WHERE FlowId = N'daily';
"@)
            if ($Claim) {
                [void]$sb.AppendLine(@"
BEGIN TRAN;
IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = N'$($c.InstallLock)')
    INSERT cfg.PipelineLock (LockId) VALUES (N'$($c.InstallLock)');
"@)
            }
            [void]$sb.AppendLine(@"
-- a held row with a fresh beat is a RUNNING execution (the liveness rule); never beaten: running for $($c.NeverBeatMinutes) minutes from when it was taken
IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL
    SELECT TOP (1) @kind = N'lock',
           @busy = N'the lock ''' + LockId + N''' is held by ' + ISNULL(Holder, N'?') + ISNULL(N' (' + What + N')', N'')
                 + N', last sign of life ' + ISNULL(CONVERT(nvarchar(19), HeartbeatUtc, 120) + N'Z', N'none yet (taken ' + ISNULL(CONVERT(nvarchar(19), AcquiredUtc, 120) + N'Z', N'?') + N')')
      FROM cfg.PipelineLock$hint
     WHERE Holder IS NOT NULL AND Holder <> @Holder
       AND ((HeartbeatUtc IS NOT NULL AND HeartbeatUtc >= DATEADD(minute, -$($c.BeatStaleMinutes), @now))
            OR (HeartbeatUtc IS NULL AND AcquiredUtc >= DATEADD(minute, -$($c.NeverBeatMinutes), @now)))
     ORDER BY HeartbeatUtc DESC;
IF @busy IS NULL AND OBJECT_ID(N'cfg.FlowRun') IS NOT NULL
BEGIN
    SELECT TOP (1) @runId = FlowRunId, @runState = State, @runStarted = StartedUtc FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;
    IF @runId IS NOT NULL AND ISNULL(@runState, N'') NOT IN ($ended)
        SELECT @kind = N'run', @busy = N'pipeline run ' + @runId + N' is ' + ISNULL(@runState, N'?') + N' since ' + ISNULL(CONVERT(nvarchar(19), @runStarted, 120) + N'Z', N'?')
    ELSE IF OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
        SELECT TOP (1) @kind = N'step', @busy = N'step ' + Job + N' of pipeline run ' + FlowRunId + N' is ' + State
          FROM cfg.FlowStepRun WHERE State IN (N'Starting', N'Running') ORDER BY FlowRunId DESC;
END
IF @busy IS NULL AND OBJECT_ID(N'sidata.DataOutLock') IS NOT NULL
    SELECT TOP (1) @kind = N'dataout', @busy = N'data-out work holds the findings (' + ISNULL(Kind, N'?') + N', ' + Holder + N') until ' + CONVERT(nvarchar(19), UntilUtc, 120) + N'Z'
      FROM sidata.DataOutLock WHERE ISNULL(Holder, N'') <> N'' AND UntilUtc > SYSUTCDATETIME();
"@)
            if ($Claim) {
                [void]$sb.AppendLine(@"
IF @busy IS NOT NULL SET @verdict = N'Busy'
ELSE IF OBJECT_ID(N'cfg.PipelineLock') IS NULL SET @verdict = N'NoLock'
ELSE
BEGIN
    UPDATE cfg.PipelineLock
       SET Holder = @Holder, What = @What, FlowRunId = NULL,
           AcquiredUtc = CASE WHEN Holder = @Holder THEN AcquiredUtc ELSE SYSUTCDATETIME() END, HeartbeatUtc = SYSUTCDATETIME()
     WHERE LockId = N'$($c.InstallLock)' AND (Holder IS NULL OR Holder = @Holder OR HeartbeatUtc IS NULL OR HeartbeatUtc < DATEADD(minute, -$($c.BeatStaleMinutes), @now));
    IF @@ROWCOUNT = 1 SET @verdict = N'Go' ELSE SELECT @verdict = N'Busy', @kind = N'lock', @busy = N'the install lock could not be taken';
END
COMMIT;
"@)
            } else {
                [void]$sb.AppendLine("IF @busy IS NOT NULL SET @verdict = N'Busy' ELSE SET @verdict = N'Free';")
            }
            [void]$sb.Append('SELECT @verdict AS Verdict, @kind AS BusyKind, @busy AS BusyText, @mode AS FlowMode;')
            $sb.ToString()
        }
        'Beat' { "/*si-datareset:beat*/ SET NOCOUNT ON; UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), What = @What WHERE LockId = N'$($c.InstallLock)' AND Holder = @Holder; SELECT @@ROWCOUNT AS Held;" }
        'Release' { "/*si-datareset:release*/ SET NOCOUNT ON; IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N'$($c.InstallLock)' AND Holder = @Holder; SELECT @@ROWCOUNT AS Released;" }
        'External' { @'
/*si-datareset:external*/ SET NOCOUNT ON;
DECLARE @batches bigint = 0, @items bigint = 0, @live int = 0;
IF OBJECT_ID(N'cfg.DataOutBatch') IS NOT NULL SELECT @batches = COUNT_BIG(*) FROM cfg.DataOutBatch WHERE Mode = N'live';
IF OBJECT_ID(N'cfg.ConnectorItem') IS NOT NULL SELECT @items = COUNT_BIG(*) FROM cfg.ConnectorItem;
IF OBJECT_ID(N'cfg.Connector') IS NOT NULL SELECT @live = COUNT(*) FROM cfg.Connector WHERE Enabled = 1 AND Mode = N'apply' AND Kind IN (N'servicenow', N'rest');
SELECT @batches AS LiveBatches, @items AS ConnectorItems, @live AS LiveConnectors;
'@ }
        'Settings' {
            $in = (@($c.IdentitySettings | ForEach-Object { "N'$_'" })) -join ', '
            "/*si-datareset:settings*/ SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT Name, Scope, ValueJson FROM cfg.Setting WHERE Name IN ($in);"
        }
        'Truncate' { '/*si-datareset:truncate*/ TRUNCATE TABLE {0};' -f (ConvertTo-SIDataResetQuoted $Table) }
        'TruncateBatch' {
            # #1148: SEVERAL quick empties as ONE statement (one audited action per batch, not one per table): a paused
            # resumable index build on any of them aborted first (it blocks TRUNCATE; outside the transaction -- ALTER INDEX
            # ... ABORT cannot run inside one), then ONE transaction: each TRUNCATE and its reseed (the ids continue where they
            # were). XACT_ABORT: any refusal rolls the whole batch back -- the caller then empties its tables one by one.
            # Answers how many paused index builds were aborted.
            $items = @($Batch | Where-Object { $_ })
            if (-not $items.Count) { throw 'a batch needs at least one table' }
            $ids = (@($items | ForEach-Object { "OBJECT_ID(N'{0}')" -f (ConvertTo-SIDataResetQuoted ([string]$_.Name)).Replace("'", "''") })) -join ', '
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('/*si-datareset:truncatebatch*/ SET NOCOUNT ON; SET XACT_ABORT ON;')
            [void]$sb.AppendLine("DECLARE @s nvarchar(max) = N'', @n int = 0;")
            [void]$sb.AppendLine("IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL")
            [void]$sb.AppendLine("    SELECT @s = @s + N'ALTER INDEX ' + QUOTENAME(name) + N' ON ' + QUOTENAME(OBJECT_SCHEMA_NAME(object_id)) + N'.' + QUOTENAME(OBJECT_NAME(object_id)) + N' ABORT; ', @n = @n + 1")
            [void]$sb.AppendLine("      FROM sys.index_resumable_operations WHERE object_id IN ($ids);")
            [void]$sb.AppendLine('IF @n > 0 EXEC (@s);')
            [void]$sb.AppendLine('BEGIN TRAN;')
            foreach ($it in $items) {
                $q = ConvertTo-SIDataResetQuoted ([string]$it.Name)
                [void]$sb.AppendLine(('TRUNCATE TABLE {0};' -f $q))
                if ($it.HasIdentity -and $null -ne $it.IdentCurrent) {
                    $inc = if ($null -ne $it.IdentIncr) { [decimal]$it.IdentIncr } else { [decimal]1 }
                    [void]$sb.AppendLine(("DBCC CHECKIDENT (N'{0}', RESEED, {1}) WITH NO_INFOMSGS;" -f $q.Replace("'", "''"), ([decimal]::Truncate([decimal]$it.IdentCurrent + $inc)).ToString([Globalization.CultureInfo]::InvariantCulture)))
                }
            }
            [void]$sb.AppendLine('COMMIT;')
            [void]$sb.Append('SELECT @n AS Aborted;')
            $sb.ToString()
        }
        'AbortResumable' {
            # a PAUSED resumable index build / rebuild on the table (the index build job pauses when a run starts) makes SQL refuse
            # TRUNCATE ("... in resumable index rebuild state"): it is aborted first -- on an emptied table the half-built index
            # has no value, and the index build job makes it again. Answers how many were aborted.
            $q = ConvertTo-SIDataResetQuoted $Table
            @"
/*si-datareset:abortresumable*/ SET NOCOUNT ON;
DECLARE @s nvarchar(max) = N'', @n int = 0;
IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL
    SELECT @s = @s + N'ALTER INDEX ' + QUOTENAME(name) + N' ON $q ABORT; ', @n = @n + 1
      FROM sys.index_resumable_operations WHERE object_id = OBJECT_ID(N'$($q.Replace("'", "''"))');
IF @n > 0 EXEC (@s);
SELECT @n AS Aborted;
"@
        }
        'Reseed' {
            $q = ConvertTo-SIDataResetQuoted $Table
            "/*si-datareset:reseed*/ DBCC CHECKIDENT (N'{0}', RESEED, {1}) WITH NO_INFOMSGS;" -f $q.Replace("'", "''"), ([decimal]::Truncate($Value)).ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        'DeleteBatch' {
            if ($Rows -lt 1) { throw 'a batch needs at least one row' }
            '/*si-datareset:deletebatch*/ SET NOCOUNT ON; DELETE TOP ({0}) FROM {1}; SELECT @@ROWCOUNT AS N;' -f $Rows, (ConvertTo-SIDataResetQuoted $Table)
        }
        'CountMany' {
            if (-not @($Tables).Count) { return "/*si-datareset:countmany*/ SELECT CAST(N'' AS nvarchar(260)) AS T, CAST(0 AS bigint) AS N WHERE 1 = 0;" }
            $parts = @($Tables | ForEach-Object { "SELECT N'{0}' AS T, (SELECT COUNT_BIG(*) FROM {1}) AS N" -f $_, (ConvertTo-SIDataResetQuoted $_) })
            "/*si-datareset:countmany*/ SET NOCOUNT ON;`n" + ($parts -join "`nUNION ALL ") + ';'
        }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  SMALL HELPERS
# ---------------------------------------------------------------------------------------------------------------------
function Get-SIDataResetField {
    <# PURE. One field of a row (hashtable, DataRow or object); DBNull = $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row -is [System.Data.DataRow]) { if ($Row.Table.Columns.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [DBNull]) { return $null }
    $v
}

function Invoke-SIDataResetRows {
    <# The rows of one reader call as a flat array (a reader answers ONE array -- unrolled here). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, $Params)
    if ($null -eq $Params) { $Params = @{} }
    @(& $Invoke $Sql $Params 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}

function ConvertFrom-SIDataResetSettingText {
    <# PURE. A setting's ValueJson ("text", true) -> its plain text ('' for none). #>
    param([AllowNull()][string]$ValueJson)
    $s = "$ValueJson".Trim()
    if (-not $s) { return '' }
    try { $v = $s | ConvertFrom-Json -ErrorAction Stop; return "$v".Trim() } catch { return $s.Trim('"').Trim() }
}

function Format-SIDataResetNumber { param($Value, [int]$Decimals = 0) ([decimal]$Value).ToString(('N{0}' -f $Decimals), [Globalization.CultureInfo]::InvariantCulture) }

function Get-SIDataResetInventory {
    <# The tables of -Schemas in one database: name -> @{ Name; Rows; SizeMB; HasIdentity; IdentCurrent; IdentIncr }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string[]]$Schemas)
    $map = [ordered]@{}
    foreach ($r in (Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name Inventory -Schemas $Schemas))) {
        $n = '{0}.{1}' -f [string](Get-SIDataResetField $r 'SchemaName'), [string](Get-SIDataResetField $r 'TableName')
        $ic = Get-SIDataResetField $r 'IdentCurrent'; $ii = Get-SIDataResetField $r 'IdentIncr'
        $map[$n] = [pscustomobject]@{
            Name = $n; Rows = [long](Get-SIDataResetField $r 'RowCnt'); SizeMB = [decimal](Get-SIDataResetField $r 'SizeMB')
            HasIdentity = ([int](Get-SIDataResetField $r 'HasIdentity') -eq 1)
            IdentCurrent = $(if ($null -ne $ic) { [decimal]$ic } else { $null }); IdentIncr = $(if ($null -ne $ii) { [decimal]$ii } else { [decimal]1 })
        }
    }
    $map
}

function Get-SIDataResetOrder {
    <#
        PURE. The order and method per table: a table some OTHER table points at (foreign key) is emptied with batched
        DELETEs after every table of the set that points at it; every other table is TRUNCATEd. -Edges: @{ ParentTable;
        RefTable } (parent points at ref). Returns @( @{ Name; Method = 'truncate' | 'delete'; ReferencedBy = @() } ).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Tables, [AllowEmptyCollection()][object[]]$Edges = @())
    $set = @{}; foreach ($t in $Tables) { $set[$t.ToLowerInvariant()] = $t }
    $refBy = @{}
    foreach ($e in @($Edges)) {
        $ref = [string](Get-SIDataResetField $e 'RefTable'); $par = [string](Get-SIDataResetField $e 'ParentTable')
        if (-not $ref -or -not $par -or $ref -ieq $par) { continue }
        $k = $ref.ToLowerInvariant()
        if (-not $refBy.ContainsKey($k)) { $refBy[$k] = New-Object System.Collections.Generic.List[string] }
        if (-not ($refBy[$k] -contains $par)) { $refBy[$k].Add($par) }
    }
    $done = @{}; $out = New-Object System.Collections.Generic.List[object]
    $left = New-Object System.Collections.Generic.List[string]; foreach ($t in ($Tables | Sort-Object)) { $left.Add($t) }
    while ($left.Count) {
        $ready = @($left | Where-Object {
            $k = $_.ToLowerInvariant()
            -not $refBy.ContainsKey($k) -or -not @($refBy[$k] | Where-Object { $set.ContainsKey($_.ToLowerInvariant()) -and -not $done.ContainsKey($_.ToLowerInvariant()) }).Count })
        if (-not $ready.Count) { $ready = @($left[0]) }   # a cycle: go on in name order (the DELETE says what holds it)
        foreach ($t in $ready) {
            $k = $t.ToLowerInvariant()
            $by = if ($refBy.ContainsKey($k)) { @($refBy[$k]) } else { @() }
            $out.Add([pscustomobject]@{ Name = $t; Method = $(if ($by.Count) { 'delete' } else { 'truncate' }); ReferencedBy = $by })
            $done[$k] = $true; [void]$left.Remove($t)
        }
    }
    $out.ToArray()
}

function Get-SIDataResetSettingState {
    <# PURE. The two identity scope settings from their cfg.Setting rows: @( @{ Name; On; Text } ). No row = the shipped default, on. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    foreach ($n in (Get-SIDataResetContract).IdentitySettings) {
        $mine = @($Rows | Where-Object { [string](Get-SIDataResetField $_ 'Name') -eq $n })
        $off = @($mine | Where-Object { (ConvertFrom-SIDataResetSettingText ([string](Get-SIDataResetField $_ 'ValueJson'))) -ieq 'false' })
        if (-not $mine.Count) { [pscustomobject]@{ Name = $n; On = $true; Text = 'not stored: the shipped default applies (on)' } }
        elseif ($off.Count) { [pscustomobject]@{ Name = $n; On = $false; Text = ('OFF ({0}) -- a stored choice, left as it is' -f ((@($off | ForEach-Object { [string](Get-SIDataResetField $_ 'Scope') })) -join ', ')) } }
        else { [pscustomobject]@{ Name = $n; On = $true; Text = 'on (stored)' } }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE INVARDIA SUPPORT APP'S SQL AS A STORE
# ---------------------------------------------------------------------------------------------------------------------
function New-SIDataResetSupportStore {
    <#
        A store over the Invardia Support app's audited SQL (Invoke-InvardiaSupportSql; open the Support session first).
        It takes no parameters: each one is DECLAREd before the statement, as a literal -- the statements are the same text
        as on the direct path. Rows come back as they are (DataRow / object); Get-SIDataResetField reads every shape.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Reason)
    if (-not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) { throw 'the Invardia Support session is not open in this shell: Invoke-InvardiaSupportSql was not found (Connect-InvardiaSupport.ps1)' }
    $sqlArgs = @{ Server = $(if ($Server -match '\.') { $Server } else { $Server + '.database.windows.net' }); Database = $Database; Reason = $Reason }
    $inv = {
        param([string]$sql, $params, [string]$mode)
        $decl = New-Object System.Text.StringBuilder
        if ($params) {
            foreach ($k in @($params.Keys)) {
                $v = $params[$k]
                if ($k -notmatch '^[A-Za-z][A-Za-z0-9_]{0,63}$') { throw "not a parameter name: $k" }
                if ($null -eq $v) { [void]$decl.AppendLine("DECLARE @$k NVARCHAR(MAX) = NULL;") }
                elseif ($v -is [bool]) { [void]$decl.AppendLine(('DECLARE @{0} BIT = {1};' -f $k, [int]$v)) }
                elseif ($v -is [int] -or $v -is [long]) { [void]$decl.AppendLine(('DECLARE @{0} BIGINT = {1};' -f $k, [long]$v)) }
                else { [void]$decl.AppendLine(("DECLARE @{0} NVARCHAR(MAX) = N'{1}';" -f $k, ([string]$v).Replace("'", "''"))) }
            }
        }
        $res = Invoke-InvardiaSupportSql @sqlArgs -Query ($decl.ToString() + $sql)
        $rows = @(@(if ($null -ne $res -and $res.PSObject.Properties['Rows']) { $res.Rows } else { $res }) | Where-Object { $null -ne $_ })
        if ($mode -eq 'scalar') {
            if (-not $rows.Count) { return $null }
            $r0 = $rows[0]
            if ($r0 -is [System.Data.DataRow]) { return $r0.ItemArray[0] }
            return @($r0.PSObject.Properties)[0].Value
        }
        , @($rows)
    }.GetNewClosure()
    [pscustomobject]@{ Name = ('{0}/{1} (Invardia Support app)' -f $sqlArgs.Server, $Database); Invoke = $inv }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE RESET
# ---------------------------------------------------------------------------------------------------------------------
function Invoke-SIDataReset {
    <#
        PLAN (default) or -Apply. -Invoke: the Pro database; -IdentityInvoke: the identity ledger database (optional:
        read to list it as kept; emptied only with -IncludeIdentityLedger, which needs it). -Reason: why (at least 10 characters, on the audit
        trail). -AcceptExternalKeysLost: go on although another system holds SecurityInsight's keys. -Log { param($level,
        $text) }; -Pause { param([int]$ms) } (test seam); -SIRoot / -SchemaFiles (test seams for the derived list).
        Returns @{ Mode = plan | nothing | refused | applied; Refused; Empty; Kept; Missing; Busy; External; Settings;
        ReadBack; Removed; Audited }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [scriptblock]$IdentityInvoke,
        # opt-in: empty the identity ledger too (default: kept -- stable ids; an object out of scope makes no CI)
        [switch]$IncludeIdentityLedger,
        [string]$Reason = '',
        [switch]$Apply,
        [switch]$AcceptExternalKeysLost,
        [string]$Actor,
        [string]$StoreName = 'the Pro database',
        [string]$IdentityStoreName = 'the identity ledger database',
        [scriptblock]$Log,
        [scriptblock]$Pause,
        [string]$SIRoot = $script:SIDataResetRoot,
        [string[]]$SchemaFiles
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$text) $col = switch ($level) { 'WARN' { 'Yellow' } 'OK' { 'Green' } 'ERROR' { 'Red' } default { 'Gray' } }; Write-Host $text -ForegroundColor $col } }
    if (-not $Pause) { $Pause = { param([int]$ms) if ($ms -gt 0) { Start-Sleep -Milliseconds $ms } } }
    $userLog = $Log
    # (no closure: $userLog is found in this function's scope by every caller below it, the audit writer included)
    $Log = { param([string]$level, [string]$text) $null = & $userLog $level $text }
    $c = Get-SIDataResetContract
    $why = "$Reason".Trim()
    if ($why.Length -gt 400) { $why = $why.Substring(0, 400) }
    $catArgs = @{ SIRoot = $SIRoot }; if ($SchemaFiles) { $catArgs['SchemaFiles'] = $SchemaFiles }
    $cat = Get-SIDataResetCatalog @catArgs
    $holder = $c.HolderPrefix + [guid]::NewGuid().ToString('N').Substring(0, 12)

    $result = [pscustomobject]@{ Mode = 'plan'; Refused = ''; Empty = @(); Kept = @(); Missing = @(); Busy = ''; FlowMode = ''; External = $null
        Settings = @(); ReadBack = $null; Removed = @(); RowsToRemove = [long]0; MBToRemove = [decimal]0; Audited = $false; Holder = $holder }

    # ---- WHERE: the data must be in THIS database --------------------------------------------------------------------
    $loc = @(Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name Location)) | Select-Object -First 1
    $dbName = [string](Get-SIDataResetField $loc 'DatabaseName')
    $dataDb = ConvertFrom-SIDataResetSettingText ([string](Get-SIDataResetField $loc 'DataDatabase'))
    $dataElsewhere = [bool]($dataDb -and $dbName -and $dataDb -ine $dbName)

    # ---- WHAT: the inventory of both databases, the plan ---------------------------------------------------------------
    $build = {
        $inv = Get-SIDataResetInventory -Invoke $Invoke -Schemas (@($cat.DataSchemas) + @($c.ConfigSchema))
        $idInv = if ($IdentityInvoke) { Get-SIDataResetInventory -Invoke $IdentityInvoke -Schemas @($cat.IdentitySchemas) } else { [ordered]@{} }
        $edges = Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name ForeignKeys)
        $proEmpty = New-Object System.Collections.Generic.List[string]
        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($t in $cat.DataTables) { if ($inv.Contains($t)) { $proEmpty.Add($t) } else { $missing.Add($t) } }
        # a table of a data schema the files do not name (a published copy, a table made at run time): data too
        foreach ($k in @($inv.Keys)) { if ((@($cat.DataSchemas) -contains ($k -split '\.')[0]) -and -not ($proEmpty -contains $k)) { $proEmpty.Add($k) } }
        foreach ($t in @($cat.RunHistory.Keys)) { if ($inv.Contains($t)) { $proEmpty.Add($t) } else { $missing.Add($t) } }
        $order = Get-SIDataResetOrder -Tables $proEmpty.ToArray() -Edges $edges
        $empty = New-Object System.Collections.Generic.List[object]
        foreach ($o in $order) {
            $i = $inv[$o.Name]
            $why2 = if ($cat.RunHistory.Contains($o.Name)) { 'run history: ' + $cat.RunHistory[$o.Name] }
                    elseif (@($cat.DataTables) -contains $o.Name) { 'data schema ' + ($o.Name -split '\.')[0] }
                    else { 'data schema ' + ($o.Name -split '\.')[0] + ' (made at run time)' }
            $empty.Add([pscustomobject]@{ Db = 'pro'; Name = $o.Name; Method = $o.Method; ReferencedBy = $o.ReferencedBy; Rows = $i.Rows; SizeMB = $i.SizeMB
                HasIdentity = $i.HasIdentity; IdentCurrent = $i.IdentCurrent; IdentIncr = $i.IdentIncr; Why = $why2
                PersonEntered = [bool](@($c.PersonEntered) -contains $o.Name) })
        }
        foreach ($t in $cat.IdentityTables) {
            if (-not $IdentityInvoke -or -not $IncludeIdentityLedger) { continue }
            if (-not $idInv.Contains($t)) { $missing.Add('identity:' + $t); continue }
            $i = $idInv[$t]
            $empty.Add([pscustomobject]@{ Db = 'identity'; Name = $t; Method = 'truncate'; ReferencedBy = @(); Rows = $i.Rows; SizeMB = $i.SizeMB
                HasIdentity = $i.HasIdentity; IdentCurrent = $i.IdentCurrent; IdentIncr = $i.IdentIncr; Why = 'the identity ledger'; PersonEntered = $false })
        }
        $kept = New-Object System.Collections.Generic.List[object]
        foreach ($k in @($inv.Keys)) {
            if (($k -split '\.')[0] -ne $c.ConfigSchema -or $cat.RunHistory.Contains($k)) { continue }
            $kept.Add([pscustomobject]@{ Db = 'pro'; Name = $k; Rows = $inv[$k].Rows; SizeMB = $inv[$k].SizeMB
                Why = $(if ($cat.ConfigReasons.Contains($k)) { $cat.ConfigReasons[$k] } else { 'a cfg table (kept)' }) })
        }
        foreach ($k in @($idInv.Keys)) {
            if ($IncludeIdentityLedger -and (@($cat.IdentityTables) -contains $k)) { continue }
            $kept.Add([pscustomobject]@{ Db = 'identity'; Name = $k; Rows = $idInv[$k].Rows; SizeMB = $idInv[$k].SizeMB
                Why = $(if ($cat.IdentityKeep.Contains($k)) { $cat.IdentityKeep[$k] } elseif (@($cat.IdentityTables) -contains $k) { $c.LedgerKeptWhy } else { 'not an identity ledger data table (kept)' }) })
        }
        if (-not $IdentityInvoke) { $kept.Add([pscustomobject]@{ Db = 'identity'; Name = '(the identity ledger database, not read)'; Rows = [long]0; SizeMB = [decimal]0; Why = $c.LedgerKeptWhy }) }
        # a foreign key from a KEPT table onto an emptied one: its rows would hold the reset
        $emptySet = @{}; foreach ($e in $empty) { if ($e.Db -eq 'pro') { $emptySet[$e.Name.ToLowerInvariant()] = $true } }
        $outside = @($edges | Where-Object { $emptySet.ContainsKey(([string](Get-SIDataResetField $_ 'RefTable')).ToLowerInvariant()) -and -not $emptySet.ContainsKey(([string](Get-SIDataResetField $_ 'ParentTable')).ToLowerInvariant()) } |
            ForEach-Object { $p = [string](Get-SIDataResetField $_ 'ParentTable'); [pscustomobject]@{ Parent = $p; Ref = [string](Get-SIDataResetField $_ 'RefTable'); Rows = $(if ($inv.Contains($p)) { $inv[$p].Rows } else { 0 }) } })
        [pscustomobject]@{ Empty = $empty.ToArray(); Kept = $kept.ToArray(); Missing = $missing.ToArray(); Outside = $outside }
    }
    $plan = & $build
    $result.Empty = $plan.Empty; $result.Kept = $plan.Kept; $result.Missing = $plan.Missing
    $result.RowsToRemove = [long](($plan.Empty | Measure-Object -Property Rows -Sum).Sum)
    $result.MBToRemove = [decimal](($plan.Empty | Measure-Object -Property SizeMB -Sum).Sum)

    $gate = @(Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name Gate) -Params @{ Holder = $holder }) | Select-Object -First 1
    $result.Busy = if ([string](Get-SIDataResetField $gate 'Verdict') -eq 'Busy') { [string](Get-SIDataResetField $gate 'BusyText') } else { '' }
    $result.FlowMode = [string](Get-SIDataResetField $gate 'FlowMode')
    $ext = @(Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name External)) | Select-Object -First 1
    $result.External = [pscustomobject]@{ LiveBatches = [long](Get-SIDataResetField $ext 'LiveBatches'); ConnectorItems = [long](Get-SIDataResetField $ext 'ConnectorItems'); LiveConnectors = [int](Get-SIDataResetField $ext 'LiveConnectors') }
    $extHeld = ($result.External.LiveBatches -gt 0 -or $result.External.ConnectorItems -gt 0 -or $result.External.LiveConnectors -gt 0)
    $result.Settings = @(Get-SIDataResetSettingState -Rows (Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name Settings)))

    # ---- SAY IT ---------------------------------------------------------------------------------------------------------
    & $Log 'INFO' ('A fresh start of the data at {0}{1}' -f $StoreName, $(if ($IdentityInvoke -and $IncludeIdentityLedger) { ' and ' + $IdentityStoreName } else { ' (the identity ledger is kept)' }))
    & $Log 'INFO' ('EMPTIED ({0} table(s), {1} row(s), {2} MB):' -f @($plan.Empty).Count, (Format-SIDataResetNumber $result.RowsToRemove), (Format-SIDataResetNumber $result.MBToRemove 1))
    foreach ($e in $plan.Empty) {
        & $Log 'INFO' ('  EMPTY  {0,-9} {1,-44} {2,14} rows {3,12} MB  {4,-8}  {5}' -f $e.Db, $e.Name, (Format-SIDataResetNumber $e.Rows), (Format-SIDataResetNumber $e.SizeMB 1), $e.Method, $e.Why)
        if ($e.PersonEntered -and $e.Rows -gt 0) { & $Log 'WARN' ('         {0} holds {1} row(s) a person decided -- they go with the data' -f $e.Name, (Format-SIDataResetNumber $e.Rows)) }
    }
    & $Log 'INFO' ('KEPT ({0} table(s)):' -f @($plan.Kept).Count)
    foreach ($k in $plan.Kept) { & $Log 'INFO' ('  KEEP   {0,-9} {1,-44} {2,14} rows {3,12} MB  {4}' -f $k.Db, $k.Name, (Format-SIDataResetNumber $k.Rows), (Format-SIDataResetNumber $k.SizeMB 1), $k.Why) }
    & $Log 'INFO' '  KEEP   every database user, role, grant and procedure -- only rows are removed'
    foreach ($m in $plan.Missing) { & $Log 'INFO' ('  (not in this database yet: {0} -- nothing to empty)' -f $m) }
    if ($IncludeIdentityLedger -and -not $IdentityInvoke) { & $Log 'WARN' '-IncludeIdentityLedger, but the identity ledger database was not given: -Apply refuses' }
    foreach ($s in $result.Settings) { & $Log $(if ($s.On) { 'INFO' } else { 'WARN' }) ('  setting {0}: {1}' -f $s.Name, $s.Text) }
    if ($result.Busy) { & $Log 'WARN' ('BUSY: {0} -- -Apply waits until it has ended (stop a stuck run with setup\Stop-SIRunAndUpdate.ps1)' -f $result.Busy) }
    if ($result.FlowMode -eq 'schedules') { & $Log 'WARN' 'the jobs run on their own timers (schedules mode): they do not ask the install lock -- start -Apply between their runs (the read-back says if one wrote meanwhile)' }
    if ($extHeld) { & $Log 'WARN' ('ANOTHER SYSTEM HOLDS SECURITYINSIGHT''S KEYS: {0} live data-out batch(es), {1} connector item(s), {2} live ServiceNow / REST connector(s) -- the fresh data gets new keys{3}' -f $result.External.LiveBatches, $result.External.ConnectorItems, $result.External.LiveConnectors, $(if ($AcceptExternalKeysLost) { ' (accepted: -AcceptExternalKeysLost)' } else { '; -Apply refuses without -AcceptExternalKeysLost' })) }
    if ($dataElsewhere) { & $Log 'WARN' ('the data of this install is kept in the database {0} (SI_Pro_DataSqlDatabase), not in {1} -- -Apply refuses' -f $dataDb, $dbName) }
    foreach ($o in @($plan.Outside | Where-Object { $_.Rows -gt 0 })) { & $Log 'WARN' ('the kept table {0} ({1} rows) points at {2} -- -Apply refuses' -f $o.Parent, (Format-SIDataResetNumber $o.Rows), $o.Ref) }

    if (-not $Apply) {
        & $Log 'INFO' '[PLAN] nothing was changed. Run again with -Apply to empty the tables above.'
        return $result
    }

    # ---- REFUSE when it is not safe --------------------------------------------------------------------------------------
    $refuse = {
        param([string]$text)
        $result.Mode = 'refused'; $result.Refused = $text
        & $Log 'ERROR' ('[REFUSED] {0} -- nothing was changed.' -f $text)
        $result
    }
    if ($why.Length -lt 10) { return (& $refuse 'say why (-Reason, at least 10 characters): it is kept on the audit trail') }
    if ($IncludeIdentityLedger -and -not $IdentityInvoke) { return (& $refuse '-IncludeIdentityLedger needs the identity ledger database') }
    if ($dataElsewhere) { return (& $refuse ('the data is kept in the database {0}, not in {1}' -f $dataDb, $dbName)) }
    $blocking = @($plan.Outside | Where-Object { $_.Rows -gt 0 })
    if ($blocking.Count) { return (& $refuse ('kept tables point at tables the reset empties: {0}' -f ((@($blocking | ForEach-Object { '{0} -> {1}' -f $_.Parent, $_.Ref })) -join ', '))) }
    if ($extHeld -and -not $AcceptExternalKeysLost) { return (& $refuse 'another system holds SecurityInsight''s keys (a live ServiceNow / REST output) -- confirm with -AcceptExternalKeysLost') }
    if ($result.RowsToRemove -le 0) {
        $result.Mode = 'nothing'
        & $Log 'OK' '[OK]   every table the reset empties is already empty -- nothing to do (nothing was changed).'
        return $result
    }
    if ($result.Busy) { return (& $refuse ('the install is busy: {0}' -f $result.Busy)) }

    # ---- TAKE THE INSTALL LOCK --------------------------------------------------------------------------------------------
    # #1148: every statement from here on goes through Invoke-SIDataResetCall -- a passing answer (the Support app's 429, its
    # audit log, the network) is sent again after a short growing wait, said; a database refusal is the answer
    $call = { param([scriptblock]$inv, [string]$sql, $params, [string]$mode, [string]$what) Invoke-SIDataResetCall -Invoke $inv -Sql $sql -Params $params -Mode $mode -What $what -Log $Log -Pause $Pause }
    $claim = @(& $call $Invoke (Get-SIDataResetSql -Name Gate -Claim) @{ Holder = $holder; What = $c.What } 'reader' 'the install lock') | Select-Object -First 1
    $verdict = [string](Get-SIDataResetField $claim 'Verdict')
    if ($verdict -eq 'NoLock') { return (& $refuse 'this database has no install lock (cfg.PipelineLock) yet -- update the install first') }
    if ($verdict -ne 'Go') { return (& $refuse ('the install is busy: {0}' -f [string](Get-SIDataResetField $claim 'BusyText'))) }
    & $Log 'INFO' ('the install lock is held for the reset ({0}): no run, update or index build starts meanwhile' -f $holder)

    $removed = New-Object System.Collections.Generic.List[object]
    $beatClock = [Diagnostics.Stopwatch]::StartNew()
    $beat = {
        param([switch]$Force)
        if (-not $Force -and $beatClock.Elapsed.TotalSeconds -lt $c.BeatEverySeconds) { return }
        $h = @(& $call $Invoke (Get-SIDataResetSql -Name Beat) @{ Holder = $holder; What = $c.What } 'reader' 'the install lock''s beat') | Select-Object -First 1
        if ([int](Get-SIDataResetField $h 'Held') -ne 1) { throw 'the install lock was taken from the reset -- stopped; run again to finish (it goes on where it stopped)' }
        $beatClock.Restart()
    }
    $failed = $null
    try {
        # counts again under the lock: the plan's numbers may have moved since
        $plan = & $build
        $keptBefore = @{}; foreach ($k in $plan.Kept) { $keptBefore[$k.Db + ':' + $k.Name] = $k.Rows }
        # ONE table, on its own (the delete tables, an empty table, and a quick-empty batch that a foreign key refused)
        $one = {
            param($e)
            & $beat -Force
            $inv2 = if ($e.Db -eq 'identity') { $IdentityInvoke } else { $Invoke }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $method = $e.Method; $gone = [long]0
            if ($e.Rows -le 0) {
                $method = 'empty'
            } elseif ($method -eq 'truncate') {
                # a paused resumable index build on the table blocks TRUNCATE: aborted first, said once
                $ab = @(& $call $inv2 (Get-SIDataResetSql -Name AbortResumable -Table $e.Name) @{} 'reader' ('{0}: the paused index builds' -f $e.Name)) | Select-Object -First 1
                $abN = [int](Get-SIDataResetField $ab 'Aborted')
                if ($abN -gt 0) { & $Log 'INFO' ('  {0}: {1} paused index build(s) aborted first (they block the quick empty; the index build job makes them again)' -f $e.Name, $abN) }
                try {
                    $null = & $call $inv2 (Get-SIDataResetSql -Name Truncate -Table $e.Name) @{} 'nonquery' ('{0}: the quick empty' -f $e.Name)
                    $gone = $e.Rows
                    if ($e.HasIdentity -and $null -ne $e.IdentCurrent) {
                        # continue the ids where they were: a kept record that names an old id never meets a new row
                        $null = & $call $inv2 (Get-SIDataResetSql -Name Reseed -Table $e.Name -Value ($e.IdentCurrent + $e.IdentIncr)) @{} 'nonquery' ('{0}: the ids continue' -f $e.Name)
                    }
                } catch {
                    $em = (([string]$_.Exception.Message) -split "`n")[0]
                    # batches ONLY when a foreign key holds the table (SQL 4712); any other answer -- the Support app's audit, a
                    # lock, the network, a paused index build -- stops the reset: run again and it goes on where it stopped
                    # (a refusal that is not the database's own must never turn a quick empty into hours of batches)
                    if ($em -notmatch '(?i)referenced by a FOREIGN KEY') { throw ('{0}: the quick empty was not done ({1})' -f $e.Name, $em) }
                    & $Log 'WARN' ('  {0}: a foreign key holds the quick empty ({1}) -- emptied in batches instead' -f $e.Name, $em)
                    $method = 'delete'
                }
            }
            if ($method -eq 'delete') {
                $batch = [int]$c.BatchStartRows
                while ($true) {
                    & $beat
                    $bw = [Diagnostics.Stopwatch]::StartNew()
                    $r = @(& $call $inv2 (Get-SIDataResetSql -Name DeleteBatch -Table $e.Name -Rows $batch) @{} 'reader' ('{0}: a batch of rows' -f $e.Name)) | Select-Object -First 1
                    $n = [long](Get-SIDataResetField $r 'N')
                    $gone += $n
                    if ($n -lt $batch) { break }
                    # measure and adapt: a quick batch doubles, a slow one halves -- the log never takes one huge statement
                    $secs = $bw.Elapsed.TotalSeconds
                    if ($secs -lt $c.BatchFastSeconds) { $batch = [int][Math]::Min($c.BatchMaxRows, $batch * 2) }
                    elseif ($secs -gt $c.BatchSlowSeconds) { $batch = [int][Math]::Max($c.BatchMinRows, [Math]::Floor($batch / 2)) }
                    & $Pause ([int]$c.PauseMilliseconds)
                }
            }
            $removed.Add([pscustomobject]@{ Db = $e.Db; Name = $e.Name; Method = $method; Rows = $gone; SizeMB = $e.SizeMB; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1) })
            & $Log 'INFO' ('  emptied {0,-9} {1,-44} {2,14} row(s)  {3,-8} {4,7} s' -f $e.Db, $e.Name, (Format-SIDataResetNumber $gone), $method, (Format-SIDataResetNumber ([Math]::Round($sw.Elapsed.TotalSeconds, 1)) 1))
        }
        # #1148: THE QUICK EMPTIES FIRST, AS FEW STATEMENTS (one audited action per batch of tables, not one per table). No
        # table of the set points at a quick-empty table (that is what makes it one), so emptying them before the delete
        # tables keeps the order; the delete tables follow one by one, in the plan's order. Per-table rows stay in the
        # log, the result and the audit row.
        $quick = @($plan.Empty | Where-Object { $_.Method -eq 'truncate' -and $_.Rows -gt 0 })
        $size = [Math]::Max(1, [int]$c.TruncateBatchTables)
        foreach ($db in 'pro', 'identity') {
            $mine = @($quick | Where-Object { $_.Db -eq $db })
            if (-not $mine.Count) { continue }
            $inv2 = if ($db -eq 'identity') { $IdentityInvoke } else { $Invoke }
            $nb = [int][Math]::Ceiling($mine.Count / $size)
            for ($b = 0; $b -lt $nb; $b++) {
                $chunk = @($mine[($b * $size)..([Math]::Min($mine.Count, ($b + 1) * $size) - 1)])
                & $beat -Force
                $sw = [Diagnostics.Stopwatch]::StartNew()
                try {
                    $ab = @(& $call $inv2 (Get-SIDataResetSql -Name TruncateBatch -Batch $chunk) @{} 'reader' ('the quick empty of {0} table(s) (batch {1} of {2})' -f $chunk.Count, ($b + 1), $nb)) | Select-Object -First 1
                } catch {
                    $em = (([string]$_.Exception.Message) -split "`n")[0]
                    # ONLY the database's own refusal by a foreign key sends the batch's tables one by one (each with its own
                    # fallback to batches); any other answer stops the reset -- run again and it goes on where it stopped
                    if ($em -notmatch '(?i)referenced by a FOREIGN KEY') { throw ('{0}: the quick empty was not done ({1})' -f ((@($chunk | ForEach-Object { $_.Name })) -join ', '), $em) }
                    & $Log 'WARN' ('  batch {0} of {1}: a foreign key holds a quick empty ({2}) -- its {3} table(s) are emptied one by one' -f ($b + 1), $nb, $em, $chunk.Count)
                    foreach ($e in $chunk) { & $one $e }
                    continue
                }
                $abN = [int](Get-SIDataResetField $ab 'Aborted')
                if ($abN -gt 0) { & $Log 'INFO' ('  batch {0} of {1}: {2} paused index build(s) aborted first (they block the quick empty; the index build job makes them again)' -f ($b + 1), $nb, $abN) }
                $per = [Math]::Round($sw.Elapsed.TotalSeconds / $chunk.Count, 1)
                foreach ($e in $chunk) {
                    $removed.Add([pscustomobject]@{ Db = $e.Db; Name = $e.Name; Method = 'truncate'; Rows = $e.Rows; SizeMB = $e.SizeMB; Seconds = $per })
                    & $Log 'INFO' ('  emptied {0,-9} {1,-44} {2,14} row(s)  {3,-8} {4,7} s  (batch {5} of {6})' -f $e.Db, $e.Name, (Format-SIDataResetNumber $e.Rows), 'truncate', (Format-SIDataResetNumber $per 1), ($b + 1), $nb)
                }
            }
        }
        foreach ($e in @($plan.Empty | Where-Object { -not ($_.Method -eq 'truncate' -and $_.Rows -gt 0) })) { & $one $e }
        $result.Removed = $removed.ToArray()

        # ---- READ BACK ------------------------------------------------------------------------------------------------
        $notEmpty = New-Object System.Collections.Generic.List[string]
        foreach ($db in 'pro', 'identity') {
            $names = @($plan.Empty | Where-Object { $_.Db -eq $db } | ForEach-Object { $_.Name })
            if (-not $names.Count) { continue }
            $inv3 = if ($db -eq 'identity') { $IdentityInvoke } else { $Invoke }
            foreach ($r in (Invoke-SIDataResetRows -Invoke $inv3 -Sql (Get-SIDataResetSql -Name CountMany -Tables $names))) {
                if ([long](Get-SIDataResetField $r 'N') -ne 0) { $notEmpty.Add(('{0}:{1} ({2} rows)' -f $db, [string](Get-SIDataResetField $r 'T'), [long](Get-SIDataResetField $r 'N'))) }
            }
        }
        $after = & $build
        $fewer = New-Object System.Collections.Generic.List[string]; $grew = New-Object System.Collections.Generic.List[string]
        foreach ($k in $after.Kept) {
            $key = $k.Db + ':' + $k.Name
            if (-not $keptBefore.ContainsKey($key)) { continue }
            if ($k.Rows -lt $keptBefore[$key]) { $fewer.Add(('{0} ({1} -> {2})' -f $key, $keptBefore[$key], $k.Rows)) }
            elseif ($k.Rows -gt $keptBefore[$key]) { $grew.Add(('{0} (+{1})' -f $key, ($k.Rows - $keptBefore[$key]))) }
        }
        $result.Settings = @(Get-SIDataResetSettingState -Rows (Invoke-SIDataResetRows -Invoke $Invoke -Sql (Get-SIDataResetSql -Name Settings)))
        $result.ReadBack = [pscustomobject]@{ Ok = (-not $notEmpty.Count -and -not $fewer.Count); NotEmpty = $notEmpty.ToArray(); KeptFewer = $fewer.ToArray(); KeptGrew = $grew.ToArray()
            KeptChecked = $keptBefore.Count; Settings = $result.Settings }
        if ($notEmpty.Count) { & $Log 'ERROR' ('[READ BACK] not empty after the reset: {0} -- something wrote meanwhile; run again' -f ($notEmpty -join ', ')) }
        else { & $Log 'OK' ('[READ BACK] all {0} emptied table(s) have 0 rows' -f @($plan.Empty).Count) }
        if ($fewer.Count) { & $Log 'ERROR' ('[READ BACK] kept tables have FEWER rows than before: {0}' -f ($fewer -join ', ')) }
        else { & $Log 'OK' ('[READ BACK] all {0} kept table(s) have their rows (none fewer){1}' -f $keptBefore.Count, $(if ($grew.Count) { '; written meanwhile: ' + ($grew -join ', ') } else { '' })) }
        foreach ($s in $result.Settings) { & $Log $(if ($s.On) { 'OK' } else { 'WARN' }) ('[READ BACK] {0}: {1}' -f $s.Name, $s.Text) }
        $result.Mode = 'applied'
    } catch {
        $failed = $_
        $result.Removed = $removed.ToArray()
        $result.Mode = 'failed'
    } finally {
        # #1148 (live 2026-11-07: the release met the same 429 and the lock stayed held 15 minutes): the release is sent again
        # on a passing answer before it gives up
        try { $null = & $call $Invoke (Get-SIDataResetSql -Name Release) @{ Holder = $holder; What = $c.What } 'reader' 'the install lock''s release' } catch { & $Log 'WARN' ('the install lock could not be released ({0}) -- it frees itself {1} minutes after its last beat' -f $_.Exception.Message, $c.BeatStaleMinutes) }
    }

    # ---- THE AUDIT TRAIL -----------------------------------------------------------------------------------------------
    $tableRows = @($result.Removed | ForEach-Object { [ordered]@{ db = $_.Db; table = $_.Name; method = $_.Method; rows = $_.Rows; mb = $_.SizeMB } })
    $outcome = if ($failed) { 'error' } elseif ($result.ReadBack -and -not $result.ReadBack.Ok) { 'error' } else { 'ok' }
    $text = if ($failed) { ('Reset-SIData: stopped after {0} table(s): {1}' -f $tableRows.Count, $failed.Exception.Message) }
            else { ('Reset-SIData: {0} table(s) emptied, {1} row(s); read back {2}' -f $tableRows.Count, (Format-SIDataResetNumber (($result.Removed | Measure-Object -Property Rows -Sum).Sum)), $(if ($result.ReadBack.Ok) { 'ok' } else { 'NOT ok' })) }
    $auditArgs = @{ Invoke = $Invoke; Action = $c.AuditAction; ActorSource = 'setup'; Target = '/data'; Reason = $why; Outcome = $outcome; OutcomeText = $text
        After = [ordered]@{ tables = $tableRows; identityLedger = $(if ($IncludeIdentityLedger) { 'emptied' } else { 'kept' }); externalKeysAccepted = [bool]($extHeld -and $AcceptExternalKeysLost); readBack = $result.ReadBack } }
    if ($Actor) { $auditArgs['Actor'] = $Actor }
    $result.Audited = [bool](Write-SIAuditEvent @auditArgs -Log $Log)
    if ($failed) {
        & $Log 'ERROR' ('[STOPPED] {0} -- {1} table(s) were emptied before it; run again to finish (it goes on where it stopped).' -f $failed.Exception.Message, $removed.Count)
        throw $failed
    }
    if ($result.ReadBack.Ok) { & $Log 'OK' ('[OK]   the data is emptied and read back. The next scheduled pipeline run fills it again from the sources.') }
    $result
}
