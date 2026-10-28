#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE CHANGE JOURNAL AND THE CONFIGURATION BACKUP (REQUIREMENTS #404, framework CONFIG-1).

    THE CONFIGURATION SET is config\config-entities.locked.json: every customer-made configuration record in the Pro database
    (settings, documents, access, template overrides, exemptions, connectors, departments and their people, responsibility
    rules, domain / category roles, remediation flows, advisors, the CMDB service model and its links, the pipeline, the
    management reports, saved pivot views) plus two that are journaled only (guard acknowledgements; the templates the
    product installs, Source = template).

    CONFIG-1.1 -- ONE JOURNAL ROW PER CHANGED RECORD, IN THE SAME TRANSACTION. Every entity's table carries a trigger
    (generated here, written into the GENERATED CONFIG JOURNAL block of sql\si-pro-settings.sql) that writes one
    cfg.ConfigJournal row per changed record: the full record before and after, Add / Modify / Remove, who initiated it, who
    approved it, the source, the commit it undoes. A trigger runs inside the writing statement's transaction, so a change
    can never exist without its journal row and a failed journal write rolls the change back -- and EVERY writer journals:
    the web app, the jobs, setup, the updater, a person with a SQL editor. The commit id is SESSION_CONTEXT 'si.audit.cid'
    -- the same value the web app and New-SIAuditInvoke already stamp for the audit trail (AUDIT-1 CorrelationId).
    A write with no context still journals: a fresh commit id, the database login as the initiator, source 'sync'.

    CONFIG-1.3 -- THE BACKUP is cfg.vConfigSnapshot (every record in force of every backup entity, one JSON per record --
    the trigger's record shape) taken by cfg.ConfigBackupTake: compressed, hashed, and recorded as "no change" (pointing at
    the backup that holds the content) when nothing changed. Pruned only by cfg.ConfigBackupPrune (audited by the caller),
    never a pinned backup, never content a kept backup still points at.

    Pure functions except the -Invoke seams ((sql, params, mode) like every Pro engine). PS 5.1 and pwsh 7; no modules.
#>

$script:SIConfigCatalogCache = $null

function Get-SIConfigEntityCatalog {
    <# The configuration set (config\config-entities.locked.json) as parsed JSON. -SIRoot: the SecurityInsight folder. #>
    param([string]$SIRoot, [string]$Path)
    if (-not $Path) {
        if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        $Path = [System.IO.Path]::Combine($SIRoot, 'config', 'config-entities.locked.json')
    }
    if ($script:SIConfigCatalogCache -and $script:SIConfigCatalogCache.Path -eq $Path) { return $script:SIConfigCatalogCache.Value }
    $v = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $script:SIConfigCatalogCache = @{ Path = $Path; Value = $v }
    $v
}

function Get-SIConfigSqlName {
    <# PURE. cfg.Setting -> Setting (the trigger's name part). #>
    param([Parameter(Mandatory)][string]$Table)
    ($Table -split '\.')[-1]
}

function Get-SIConfigKeyExpression {
    <# PURE. The record key as text: the key columns joined with '|' (a NULL part reads as empty). #>
    param([Parameter(Mandatory)]$Entity, [Parameter(Mandatory)][string]$Alias)
    $parts = @($Entity.key | ForEach-Object { '{0}.[{1}]' -f $Alias, $_ })
    if ($parts.Count -eq 1) { return ('LEFT(CONCAT({0}, N''''), 900)' -f $parts[0]) }
    'LEFT(CONCAT(' + ($parts -join ', N''|'', ') + '), 900)'
}

function Get-SIConfigJsonExpression {
    <# PURE. One record as JSON, the columns in catalog order (-Content: without the meta columns). #>
    param([Parameter(Mandatory)]$Entity, [Parameter(Mandatory)][string]$Alias, [switch]$Content)
    $meta = @($Entity.meta)
    $cols = @($Entity.columns | Where-Object { -not $Content -or $meta -notcontains $_ })
    $sel = ($cols | ForEach-Object { '{0}.[{1}] AS [{1}]' -f $Alias, $_ }) -join ', '
    '(SELECT ' + $sel + ' FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES)'
}

function Get-SIConfigLiveExpression {
    <# PURE. 1 while the record is in force (no soft removal, or its 'at' column is NULL), else 0. #>
    param([Parameter(Mandatory)]$Entity, [Parameter(Mandatory)][string]$Alias)
    if ($Entity.soft -and $Entity.soft.at) { return ('CASE WHEN {0}.[{1}] IS NULL THEN 1 ELSE 0 END' -f $Alias, $Entity.soft.at) }
    '1'
}

function Get-SIConfigTriggerSql {
    <#
        PURE. The journal trigger of one entity (plain T-SQL, CREATE OR ALTER so a new release re-states it). The pairs of
        before / after rows are matched on the table's primary key; a record whose content (the meta columns left out,
        compared byte for byte) and in-force state did not change writes nothing.
    #>
    param([Parameter(Mandatory)]$Entity, [string[]]$Sources = @('gui', 'api', 'import', 'restore', 'undo', 'sync', 'template'))
    $name = Get-SIConfigSqlName $Entity.table
    $pk = @($Entity.pk)
    $pkList = ($pk | ForEach-Object { '[{0}]' -f $_ }) -join ', '
    $joinI = ($pk | ForEach-Object { 'i.[{0}] = x.[{0}]' -f $_ }) -join ' AND '
    $joinD = ($pk | ForEach-Object { 'd.[{0}] = x.[{0}]' -f $_ }) -join ' AND '
    $srcList = ($Sources | ForEach-Object { "N'$_'" }) -join ', '
    $forced = if ($Entity.PSObject.Properties['source'] -and $Entity.source) { "    SET @src = N'$($Entity.source)';`n" } else { '' }
    $ka = Get-SIConfigKeyExpression -Entity $Entity -Alias 'i'; $kb = Get-SIConfigKeyExpression -Entity $Entity -Alias 'd'
    $la = Get-SIConfigLiveExpression -Entity $Entity -Alias 'i'; $lb = Get-SIConfigLiveExpression -Entity $Entity -Alias 'd'
    $ja = Get-SIConfigJsonExpression -Entity $Entity -Alias 'i'; $jb = Get-SIConfigJsonExpression -Entity $Entity -Alias 'd'
    $ca = Get-SIConfigJsonExpression -Entity $Entity -Alias 'i' -Content; $cb = Get-SIConfigJsonExpression -Entity $Entity -Alias 'd' -Content
@"
CREATE OR ALTER TRIGGER cfg.TR_$($name)_Journal ON $($Entity.table) AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @cid NVARCHAR(64) = CAST(SESSION_CONTEXT(N'si.audit.cid') AS NVARCHAR(64));
    IF @cid IS NULL SET @cid = REPLACE(CONVERT(NVARCHAR(36), NEWID()), N'-', N'');
    DECLARE @asrc NVARCHAR(16) = CAST(SESSION_CONTEXT(N'si.audit.source') AS NVARCHAR(16));
    IF @asrc NOT IN (N'web', N'job', N'engine', N'setup', N'api', N'portal') SET @asrc = NULL;
    DECLARE @src NVARCHAR(16) = CAST(SESSION_CONTEXT(N'si.cfg.source') AS NVARCHAR(16));
    IF @src IS NULL OR @src NOT IN ($srcList)
        SET @src = CASE @asrc WHEN N'web' THEN N'gui' WHEN N'portal' THEN N'gui' WHEN N'api' THEN N'api' WHEN N'setup' THEN N'import' ELSE N'sync' END;
$forced    DECLARE @by NVARCHAR(256) = LEFT(COALESCE(CAST(SESSION_CONTEXT(N'si.cfg.initiatedBy') AS NVARCHAR(256)), CAST(SESSION_CONTEXT(N'si.audit.actor') AS NVARCHAR(256)), ORIGINAL_LOGIN()), 256);
    DECLARE @apr NVARCHAR(256) = CAST(SESSION_CONTEXT(N'si.cfg.approvedBy') AS NVARCHAR(256));
    DECLARE @undo NVARCHAR(64) = CAST(SESSION_CONTEXT(N'si.cfg.undoOf') AS NVARCHAR(64));
    DECLARE @why NVARCHAR(400) = CAST(SESSION_CONTEXT(N'si.cfg.reason') AS NVARCHAR(400));
    INSERT cfg.ConfigJournal (CommitId, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, ActorSource, UndoOf, Reason)
    SELECT @cid, N'$($Entity.entity)', COALESCE(a.K, b.K),
           CASE WHEN b.J IS NULL THEN N'Add' WHEN a.J IS NULL THEN N'Remove' WHEN b.L = 1 AND a.L = 0 THEN N'Remove' WHEN b.L = 0 AND a.L = 1 THEN N'Add' ELSE N'Modify' END,
           b.J, a.J, @by, @apr, @src, @asrc, @undo, @why
    FROM (SELECT $pkList FROM inserted UNION SELECT $pkList FROM deleted) AS x
    OUTER APPLY (SELECT $ka AS K, $la AS L, $ja AS J, $ca AS C FROM inserted AS i WHERE $joinI) AS a
    OUTER APPLY (SELECT $kb AS K, $lb AS L, $jb AS J, $cb AS C FROM deleted AS d WHERE $joinD) AS b
    WHERE a.J IS NULL OR b.J IS NULL OR a.L <> b.L OR a.C COLLATE Latin1_General_BIN2 <> b.C COLLATE Latin1_General_BIN2;
END
"@
}

function Get-SIConfigSnapshotViewSql {
    <# PURE. cfg.vConfigSnapshot: every backup entity's records IN FORCE, one row each (Entity, EntityKey, RecordJson). #>
    param([Parameter(Mandatory)]$Catalog)
    $parts = foreach ($e in @($Catalog.entities | Where-Object { $_.backup })) {
        $k = Get-SIConfigKeyExpression -Entity $e -Alias 't'
        $j = Get-SIConfigJsonExpression -Entity $e -Alias 't'
        $w = if ($e.soft -and $e.soft.at) { (' WHERE t.[{0}] IS NULL' -f $e.soft.at) } else { '' }
        "SELECT N'$($e.entity)' AS Entity, $k AS EntityKey, $j AS RecordJson FROM $($e.table) AS t$w"
    }
    "CREATE OR ALTER VIEW cfg.vConfigSnapshot AS`n" + ($parts -join "`nUNION ALL`n")
}

function ConvertTo-SIConfigExecBatch {
    <# PURE. One statement as EXEC (N'...'): quotes doubled, no blank line inside (the schema splits batches on blank lines). #>
    param([Parameter(Mandatory)][string]$Sql)
    $body = ($Sql -replace "`r", '') -replace "(?m)^\s*\n", ''
    "EXEC (N'" + $body.TrimEnd("`n").Replace("'", "''") + "');"
}

function Get-SIConfigJournalSql {
    <#
        PURE. The GENERATED CONFIG JOURNAL block of sql\si-pro-settings.sql: one trigger per entity, then the snapshot view.
        Build-SIConfigJournalSql.ps1 writes it; a test compares the file with this output, so the two never drift.
    #>
    param([Parameter(Mandatory)]$Catalog)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("-- >>> GENERATED CONFIG JOURNAL (engine\pro-settings\Build-SIConfigJournalSql.ps1 from config\config-entities.locked.json) -- do not edit by hand`n")
    foreach ($e in @($Catalog.entities)) {
        [void]$sb.Append("`n-- the journal of $($e.entity) ($($e.table))`n")
        [void]$sb.Append((ConvertTo-SIConfigExecBatch -Sql (Get-SIConfigTriggerSql -Entity $e -Sources @($Catalog.sources)))).Append("`n")
    }
    [void]$sb.Append("`n-- every record in force of every backup entity: what a configuration backup holds`n")
    [void]$sb.Append((ConvertTo-SIConfigExecBatch -Sql (Get-SIConfigSnapshotViewSql -Catalog $Catalog))).Append("`n")
    [void]$sb.Append("`n-- <<< GENERATED CONFIG JOURNAL`n")
    $sb.ToString()
}

function Get-SIConfigSchemaColumns {
    <#
        PURE. The columns of every cfg table as the schema file declares them (CREATE TABLE + ALTER TABLE ... ADD), so a
        test can prove every column of a journaled table is either recorded or deliberately ignored.
    #>
    param([Parameter(Mandatory)][string]$Sql)
    $t = @{}
    foreach ($m in [regex]::Matches($Sql, '(?ms)^CREATE TABLE (cfg\.\w+) \((.*?)^\);')) {
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($l in ($m.Groups[2].Value -split "`n")) { if ($l -match '^\s{4}(\[?\w+\]?)\s+\w+' -and $Matches[1] -ne 'CONSTRAINT') { $list.Add($Matches[1].Trim('[', ']')) } }
        $t[$m.Groups[1].Value] = $list
    }
    foreach ($m in [regex]::Matches($Sql, '(?m)^ALTER TABLE (cfg\.\w+) ADD (\[?\w+\]?) ')) { if ($t.ContainsKey($m.Groups[1].Value)) { $t[$m.Groups[1].Value].Add($m.Groups[2].Value.Trim('[', ']')) } }
    $t
}

# ------------------------------------------------------------------------------------------------------------------------
# THE CONTEXT A POWERSHELL WRITER STAMPS (the web app stamps the same keys from its request's audit scope)
# ------------------------------------------------------------------------------------------------------------------------
function Get-SIConfigSessionContextSql {
    <# The SESSION_CONTEXT the journal triggers read beyond the audit trail's: who, the source, the approver, undo-of. #>
@'
EXEC sys.sp_set_session_context @key = N'si.audit.actor', @value = @CfgActor;
EXEC sys.sp_set_session_context @key = N'si.cfg.source', @value = @CfgSource;
EXEC sys.sp_set_session_context @key = N'si.cfg.approvedBy', @value = @CfgApprovedBy;
EXEC sys.sp_set_session_context @key = N'si.cfg.undoOf', @value = @CfgUndoOf;
EXEC sys.sp_set_session_context @key = N'si.cfg.reason', @value = @CfgReason;
'@
}

function New-SIConfigInvoke {
    <#
        Wraps an -Invoke seam so every batch it runs is journaled as ONE commit: the commit id (= the audit correlation id),
        the actor source, the person (-Actor), the journal source (-Source: import / sync / template / restore / undo), an
        approver and the commit an undo reverses. Pure wrapper.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CorrelationId,
        [string]$ActorSource = 'job', [string]$Actor, [ValidateSet('', 'gui', 'api', 'import', 'restore', 'undo', 'sync', 'template')][string]$Source = '',
        [string]$ApprovedBy, [string]$UndoOf, [string]$Reason
    )
    $inner = $Invoke
    $prefix = (Get-SIAuditSessionContextSqlLocal) + (Get-SIConfigSessionContextSql)
    $ctx = @{ AuditCid = $CorrelationId; AuditSource = $ActorSource; CfgActor = $Actor; CfgSource = $Source; CfgApprovedBy = $ApprovedBy; CfgUndoOf = $UndoOf; CfgReason = $Reason }
    {
        param([string]$sql, $p, [string]$mode)
        $q = [ordered]@{}
        if ($p) { foreach ($k in @($p.Keys)) { $q[$k] = $p[$k] } }
        foreach ($k in @($ctx.Keys)) { $q[$k] = $(if ([string]::IsNullOrEmpty([string]$ctx[$k])) { $null } else { $ctx[$k] }) }
        & $inner ($prefix + $sql) $q $mode
    }.GetNewClosure()
}

function Get-SIAuditSessionContextSqlLocal {
    # the audit trail's two keys (the same text as SI-Audit.ps1 Get-SIAuditSessionContextSql), here so this file stands alone
@'
EXEC sys.sp_set_session_context @key = N'si.audit.cid', @value = @AuditCid;
EXEC sys.sp_set_session_context @key = N'si.audit.source', @value = @AuditSource;
'@
}

# ------------------------------------------------------------------------------------------------------------------------
# CONFIG-1.3 -- THE BACKUP: take, prune, export, import
# ------------------------------------------------------------------------------------------------------------------------
$script:SIConfigBackupDefaultDays = 90

function Resolve-SIConfigBackupRetentionDays {
    <# PURE. SI_Pro_ConfigBackupRetentionDays -> @{ Days; Problem }. Not set = 90; a whole number of at least 1; else 90, said. #>
    param($Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return [pscustomobject]@{ Days = $script:SIConfigBackupDefaultDays; Problem = '' } }
    $n = 0
    if (-not [int]::TryParse("$Value".Trim(), [ref]$n) -or $n -lt 1) {
        return [pscustomobject]@{ Days = $script:SIConfigBackupDefaultDays; Problem = ("SI_Pro_ConfigBackupRetentionDays = '{0}' is not a whole number of at least 1 -- backups are kept {1} days" -f $Value, $script:SIConfigBackupDefaultDays) }
    }
    [pscustomobject]@{ Days = $n; Problem = '' }
}

function Resolve-SIConfigJournalRetentionDays {
    <#
        PURE. SI_Pro_ConfigJournalRetentionDays -> @{ Days; Problem }. Not set = $null: the journal is kept (the default).
        Never shorter than the backup retention (CONFIG-1.1): a shorter value is refused and the journal is kept.
    #>
    param($Value, [int]$BackupDays = 90)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return [pscustomobject]@{ Days = $null; Problem = '' } }
    $n = 0
    if (-not [int]::TryParse("$Value".Trim(), [ref]$n)) { return [pscustomobject]@{ Days = $null; Problem = ("SI_Pro_ConfigJournalRetentionDays = '{0}' is not a whole number -- the change journal is kept" -f $Value) } }
    if ($n -lt $BackupDays) { return [pscustomobject]@{ Days = $null; Problem = ("SI_Pro_ConfigJournalRetentionDays = {0} is shorter than the backup retention ({1} days) -- the change journal is kept, or an undo would lose its evidence" -f $n, $BackupDays) } }
    [pscustomobject]@{ Days = $n; Problem = '' }
}

function Get-SIConfigBackupTakeSql { "IF OBJECT_ID(N'cfg.ConfigBackupTake') IS NULL SELECT CAST(-1 AS BIGINT) AS BackupId; ELSE EXEC cfg.ConfigBackupTake @TakenBy = @TakenBy, @Trigger = @Trigger, @Note = @Note, @CommitId = @CommitId, @ProductVersion = @ProductVersion;" }
function Get-SIConfigBackupPruneSql { "IF OBJECT_ID(N'cfg.ConfigBackupPrune') IS NULL SELECT CAST(-1 AS BIGINT) AS BackupId, CAST(NULL AS DATETIME2(3)) AS TakenUtc; ELSE EXEC cfg.ConfigBackupPrune @Days = @Days;" }
function Get-SIConfigJournalPruneSql { "IF OBJECT_ID(N'cfg.ConfigJournalRetentionApply') IS NULL SELECT -1 AS N; ELSE EXEC cfg.ConfigJournalRetentionApply @Days = @Days, @Batch = @Batch;" }

function Invoke-SIConfigBackup {
    <#
        THE DAILY BACKUP (the caj-si-config-backup job, and "Back up now" started from the web app): one backup through
        cfg.ConfigBackupTake -- a copy, or "no change" when the configuration is what the newest backup holds -- then the
        audited prune (config.backup.prune) and the journal retention when one is set. Records config.backup.take with what it
        holds. A failure is recorded and thrown (the job fails visibly). Returns @{ BackupId; NoChange; Counts; Pruned; Problem }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [ValidateSet('scheduled', 'manual')][string]$Trigger = 'scheduled',
        [string]$Actor, [string]$CorrelationId, [string]$ProductVersion, [string]$Note,
        $RetentionDays, $JournalRetentionDays, [switch]$NoPrune, [scriptblock]$Log
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    if (-not $CorrelationId) { $CorrelationId = [guid]::NewGuid().ToString('N') }
    if (-not $Actor) { $Actor = if (Get-Command -Name Get-SIAuditActor -ErrorAction SilentlyContinue) { Get-SIAuditActor -Job 'configuration backup' } else { 'configuration backup' } }
    $audit = { param([string]$action, [string]$outcome, [string]$text, $after, [switch]$NoAttr)
        if (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue) {
            [void](Write-SIAuditEvent -Invoke $Invoke -Action $action -Actor $Actor -ActorSource 'job' -Target 'cfg.ConfigBackup' -Outcome $outcome -OutcomeText $text -After $after -CorrelationId $CorrelationId -NoAttribution:$NoAttr -Log $Log)
        } }
    $res = [ordered]@{ BackupId = $null; NoChange = $false; Counts = $null; Pruned = 0; Problem = '' }
    try {
        $rows = @(& $Invoke (Get-SIConfigBackupTakeSql) @{ TakenBy = $Actor; Trigger = $Trigger; Note = $Note; CommitId = $CorrelationId; ProductVersion = $ProductVersion } 'reader' | ForEach-Object { $_ })
        $r = if ($rows.Count) { $rows[0] } else { $null }
        $id = if ($r) { [long](Get-SIConfigRowValue $r 'BackupId') } else { -1 }
        if ($id -lt 0) { throw 'the Pro database has no configuration backup yet -- apply sql\si-pro-settings.sql (it only adds)' }
        $res.BackupId = $id; $res.NoChange = [bool][int](Get-SIConfigRowValue $r 'NoChange'); $res.Counts = [string](Get-SIConfigRowValue $r 'EntityCountsJson')
        & $Log 'OK' ("backup    : #{0} {1} ({2})" -f $id, $(if ($res.NoChange) { 'no change since the newest backup -- recorded, not copied again' } else { 'taken' }), $res.Counts)
        & $audit 'config.backup.take' 'ok' $(if ($res.NoChange) { 'no change -- recorded, not copied' } else { 'taken' }) ([ordered]@{ backupId = $id; trigger = $Trigger; noChange = $res.NoChange; records = $res.Counts })
    } catch {
        $res.Problem = $_.Exception.Message
        & $audit 'config.backup.take' 'error' $res.Problem ([ordered]@{ trigger = $Trigger })
        throw
    }
    if ($NoPrune) { return [pscustomobject]$res }
    $ret = Resolve-SIConfigBackupRetentionDays -Value $RetentionDays
    if ($ret.Problem) { & $Log 'WARN' ('backup    : ' + $ret.Problem) }
    $gone = @(& $Invoke (Get-SIConfigBackupPruneSql) @{ Days = [int]$ret.Days } 'reader' | ForEach-Object { $_ } | Where-Object { $_ -and [long](Get-SIConfigRowValue $_ 'BackupId') -ge 0 })
    $res.Pruned = $gone.Count
    if ($gone.Count) {
        $ids = @($gone | ForEach-Object { [long](Get-SIConfigRowValue $_ 'BackupId') })
        & $Log 'INFO' ("backup    : {0} backup(s) older than {1} days removed (pinned backups are kept)" -f $gone.Count, $ret.Days)
        & $audit 'config.backup.prune' 'ok' ('{0} backup(s) older than {1} days removed' -f $gone.Count, $ret.Days) ([ordered]@{ retentionDays = [int]$ret.Days; removed = $gone.Count; backupIds = $ids })
    }
    $jr = Resolve-SIConfigJournalRetentionDays -Value $JournalRetentionDays -BackupDays ([int]$ret.Days)
    if ($jr.Problem) { & $Log 'WARN' ('journal   : ' + $jr.Problem) }
    elseif ($null -ne $jr.Days) {
        $total = 0
        while ($true) {
            $n = [long](& $Invoke (Get-SIConfigJournalPruneSql) @{ Days = [int]$jr.Days; Batch = 5000 } 'scalar')
            if ($n -le 0) { break }
            $total += $n
        }
        if ($total -gt 0) { & $audit 'config.journal.prune' 'ok' ('{0} journal row(s) older than {1} days removed' -f $total, $jr.Days) ([ordered]@{ retentionDays = [int]$jr.Days; removed = $total }) }
    }
    [pscustomobject]$res
}

function Get-SIConfigRowValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$Name] } elseif ($Row -is [System.Data.DataRow]) { $Row[$Name] } else { $Row.$Name }
    if ($v -is [System.DBNull]) { $null } else { $v }
}
