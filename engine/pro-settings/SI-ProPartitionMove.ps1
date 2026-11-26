#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE MOVE OF AN EXISTING INSTALL'S LARGE TABLES ONTO ONE PARTITION PER COLLECTION (#1038 part 2,
    owner 2026-11-01: "can this be improved by other design"; the clean-up deleted ~1 M rows per old collection, hours on an
    S7 it saturated). A new install creates sidata.Finding, sidata.Recommendation and sidata.IssueContext on the partition
    scheme PS_SICollection (sql\si-data-schema.sql); an existing install's tables are moved here -- "existing installs reach
    new-install state". Once all three are moved, removing an old collection empties its partition (seconds,
    sidata.CollectionPartitionRemove); until then the clean-up removes rows as before.

    WHO RUNS IT (#1317, 2026-11-23 -- moved off the updater). THE INDEX BUILD JOB caj-si-index-build, in an IDLE WINDOW only
    (the pipeline runner starts it when no run, data sync or data out goes and no update waits; it holds the install's lock,
    gives way to an update at once, and stops at the window's end), and only while SI_Data_RetireByPartition is on
    (Invoke-SIPartitionHousekeeping below). Its rights are the UPDATER's identity's (the job runs as it): db_ddladmin +
    db_datareader + db_datawriter -- CREATE TABLE / INDEX / TRIGGER, IDENTITY_INSERT, sp_rename, ALTER PARTITION FUNCTION /
    SCHEME, TRUNCATE ... WITH (PARTITIONS), DROP of its OWN tables only. Catalog views only (no VIEW DATABASE STATE). Never the
    engine's identity: the engine's rights are unchanged. A move that cannot finish says so in one plain line (and in
    sidata.PartitionMove); the install keeps working on the old table meanwhile. (Built first 2026-11-01 on the branch
    si-v3-design/finding-partitions as a step of the updater, with two procedures that run as the owner; the updater could
    not make those, so they are gone: the job does the work with its own rights.)

    CONVERTING A LARGE TABLE (tens of millions of rows) is never one statement: the copy goes collection by collection in key
    ranges sized for ~5 s each, slowed down when the database slows, ONLY the kept collections (a retired collection's rows
    are not copied), resumable at any range (the copy is in the database), stopped at the window's end or when an update
    wants to go, and measured (rows per second in its line and in sidata.PartitionMove).

    THE OWNER'S RULES (2026-11-01): never lose a row; never lose SQL access; additive and resumable; paced; a swap only when
    the counts per collection match exactly; the old table kept until a check passes, dropped in a later step.

    THE STEPS, per table (IssueContext, then Recommendation, then Finding -- smallest first), each idle window going on from where
    the last one stopped (the state is the database itself):
      1. PREFLIGHT  the table can be moved without changing what anyone sees: its clustered key is (CollectionId, <one key>),
                    no other trigger, no foreign key pointing at it, no grant on the table itself (every reader holds its
                    rights on the schema, so a renamed table keeps them), only row-store indexes. Else 'blocked' + why.
      2. THE COPY   sidata.<T>_Partitioned beside the table: the same columns (SELECT ... INTO, the identity kept), its
                    primary key and every index on the scheme (aligned), and a trigger on the OLD table that notes every
                    collection whose rows change from now on (sidata.PartitionMoveTouched). A column or index the release
                    added since is added to the copy (a column that cannot be added the same way starts the copy over).
      3. COPY       collection by collection, in key ranges (one INSERT ... SELECT TOP (n) ... ORDER BY key each), each range
                    sized for a steady time and slowed down while the database is slow (the writers' measured rule): only
                    the collections that are still shown or kept (not retired; the published one always) -- a retired
                    collection's rows are what the clean-up removes anyway. A collection that changed after it was copied
                    is copied again (its note is cleared first, then its copied rows, then it is copied).
                    Each collection gets its own partition (the boundaries c and c+1) before its rows go in.
      4. SWAP       when every kept collection is copied and none changed since: ONE short transaction holds the old table,
                    compares the rows per collection (old = copy, exactly), sets the copy's identity at or above the old
                    one's, renames the old table to <T>_Unpartitioned and the copy to <T> (their keys and foreign keys too),
                    and removes the trigger. Any difference = no swap; the next idle window goes on.
      5. CHECK      a LATER idle window: every complete, kept collection has the same rows in the new table as in the old one.
      6. DROP       a later idle window again: the old table is dropped.
    PURE except the -Invoke seam (sql, params, mode reader | scalar | nonquery). Strict-mode safe; PS 5.1.
#>

$script:SIPartitionMoveTables = @('IssueContext', 'Recommendation', 'Finding')

# #1316 x #1317: SecurityInsight's OWN nonclustered columnstore index of a table (engine\_shared\SI-IndexBuild.ps1
# $script:SIColumnstore, SI_Data_ColumnstoreIndexes). It never blocks the move: one built on the OLD table before the move is
# dropped right before the copy starts (it is only an index -- no result changes, the row-store indexes stay) and its
# cfg.IndexBuild row set back to 'waiting'; the index build job builds it again ALIGNED on the scheme once the table is on it
# (it waits while the move is pending). Any other non-row-store index still blocks.
$script:SIPartitionMoveColumnstore = @{ Finding = 'NCCI_Finding_Load' }

function Get-SIPartitionMoveColumnstoreName {
    <# PURE. SI's own columnstore index of -Table ('' = none). #>
    param([Parameter(Mandatory)][string]$Table)
    if ($script:SIPartitionMoveColumnstore.ContainsKey($Table)) { [string]$script:SIPartitionMoveColumnstore[$Table] } else { '' }
}

function Get-SIPartitionMoveColumnstoreDropSql {
    <#
        PURE. Rule 2: SI's own columnstore index on the OLD (not partitioned) table dropped, and its cfg.IndexBuild row set
        back to 'waiting' (it is built again aligned after the swap). Only that name, only a nonclustered columnstore index
        (type 6), only while the table is NOT on the scheme; a lock that does not come within 30 s = not now (the window says
        so and goes on next time). Answers 1 when it dropped one, else 0.
    #>
    param([Parameter(Mandatory)]$Names)
    $ix = Get-SIPartitionMoveColumnstoreName -Table $Names.Table
    if (-not $ix) { return '' }
    @"
SET NOCOUNT ON;
SET LOCK_TIMEOUT 30000;
DECLARE @f int = OBJECT_ID(N'$($Names.Live)', N'U'), @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection'), @d int = 0;
IF @f IS NOT NULL AND EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = @f AND name = N'$ix' AND type = 6)
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = @f AND index_id IN (0, 1) AND data_space_id = ISNULL(@ps, -1))
BEGIN
    DROP INDEX [$($ix.Replace(']', ']]'))] ON sidata.[$(([string]$Names.Table).Replace(']', ']]'))];
    SET @d = 1;
    IF OBJECT_ID(N'cfg.IndexBuild', N'U') IS NOT NULL
        UPDATE cfg.IndexBuild SET State = N'waiting', SinceUtc = SYSUTCDATETIME(), ForcedUtc = NULL, UpdatedUtc = SYSUTCDATETIME(), UpdatedBy = N'caj-si-index-build',
               Why = N'dropped for the move of $($Names.Live) onto the collection partitions -- built again aligned on them after the move'
         WHERE TableName = N'$($Names.Live)' AND IndexName = N'$ix';
END
SELECT @d;
"@
}

function Get-SIPartitionMoveNames {
    <# PURE. The names of one table's move. #>
    param([Parameter(Mandatory)][ValidateSet('IssueContext', 'Recommendation', 'Finding')][string]$Table)
    [pscustomobject]@{ Table = $Table; Live = ('sidata.' + $Table); Copy = ($Table + '_Partitioned'); Old = ($Table + '_Unpartitioned'); Trigger = ('TR_' + $Table + '_PartitionMove') }
}

function ConvertTo-SIPartitionMoveRows {
    <# PURE. A reader seam's answer as a list of rows (IDictionary or objects), $null left out. #>
    param($Raw)
    @(@($Raw) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}

function Get-SIPartitionMoveValue {
    <# PURE. One field of a row (IDictionary, DataRow or object); DBNull = $null. #>
    param($Row, [Parameter(Mandatory)][string]$Name)
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row -is [System.Data.DataRow]) { $v = $Row[$Name] }
    elseif ($null -ne $Row -and $Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Format-SIPartitionMoveColumnType {
    <#
        PURE. The T-SQL type of one column from the catalog (TypeName, MaxLength, Prec, Scale) -- the types the product's
        tables use. $null for anything else (the caller then starts the copy over instead of guessing).
    #>
    param([Parameter(Mandatory)]$Column)
    $t = ([string](Get-SIPartitionMoveValue $Column 'TypeName')).ToLowerInvariant()
    $len = [int](Get-SIPartitionMoveValue $Column 'MaxLength'); $p = [int](Get-SIPartitionMoveValue $Column 'Prec'); $s = [int](Get-SIPartitionMoveValue $Column 'Scale')
    switch ($t) {
        { $_ -in 'bigint', 'int', 'smallint', 'tinyint', 'bit', 'float', 'real', 'date', 'datetime', 'smalldatetime', 'uniqueidentifier', 'money' } { return $t }
        { $_ -in 'datetime2', 'time', 'datetimeoffset' } { return ('{0}({1})' -f $t, $s) }
        { $_ -in 'decimal', 'numeric' } { return ('{0}({1}, {2})' -f $t, $p, $s) }
        { $_ -in 'nvarchar', 'nchar' } { if ($len -eq -1) { return ('{0}(MAX)' -f $t) }; return ('{0}({1})' -f $t, [int]($len / 2)) }
        { $_ -in 'varchar', 'char', 'varbinary', 'binary' } { if ($len -eq -1) { return ('{0}(MAX)' -f $t) }; return ('{0}({1})' -f $t, $len) }
    }
    $null
}

function Get-SIPartitionMoveColumnsSql {
    "SELECT c.column_id AS Id, c.name AS Name, TYPE_NAME(c.user_type_id) AS TypeName, c.max_length AS MaxLength, c.precision AS Prec, c.scale AS Scale, c.is_nullable AS Nullable, c.is_identity AS IsIdentity, c.is_computed AS IsComputed FROM sys.columns AS c WHERE c.object_id = OBJECT_ID(@Obj, N'U') ORDER BY c.column_id;"
}

function Get-SIPartitionMoveIndexesSql {
    <# The row-store indexes of one table with their columns (the partitioning column a partitioned index adds by itself is left out). #>
    @'
SELECT i.name AS Name, i.index_id AS Id, i.type AS Type, i.is_unique AS Uq, i.is_primary_key AS Pk, i.has_filter AS HasFilter, i.filter_definition AS Filter,
       c.name AS Col, ic.key_ordinal AS KeyOrd, ic.is_included_column AS Incl, ic.is_descending_key AS Descending
FROM sys.indexes AS i
JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE i.object_id = OBJECT_ID(@Obj, N'U') AND i.is_hypothetical = 0 AND i.index_id > 0 AND (ic.key_ordinal > 0 OR ic.is_included_column = 1)
ORDER BY i.index_id, ic.is_included_column, ic.key_ordinal, ic.index_column_id;
'@
}

function ConvertTo-SIPartitionMoveIndexes {
    <# PURE. Get-SIPartitionMoveIndexesSql's rows -> one item per index: @{ Name; Type; Unique; Pk; Filter; KeyCols (@{ Col; Desc }); Includes }. #>
    param([object[]]$Rows = @())
    $by = [ordered]@{}
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $n = [string](Get-SIPartitionMoveValue $r 'Name')
        if (-not $by.Contains($n)) {
            $f = Get-SIPartitionMoveValue $r 'Filter'
            $by[$n] = [pscustomobject]@{ Name = $n; Type = [int](Get-SIPartitionMoveValue $r 'Type'); Unique = [bool](Get-SIPartitionMoveValue $r 'Uq'); Pk = [bool](Get-SIPartitionMoveValue $r 'Pk')
                                         Filter = $(if ([bool](Get-SIPartitionMoveValue $r 'HasFilter') -and $f) { [string]$f } else { '' })
                                         KeyCols = (New-Object System.Collections.Generic.List[object]); Includes = (New-Object System.Collections.Generic.List[string]) }
        }
        $col = [string](Get-SIPartitionMoveValue $r 'Col')
        if ([bool](Get-SIPartitionMoveValue $r 'Incl')) { $by[$n].Includes.Add($col) }
        else { $by[$n].KeyCols.Add([pscustomobject]@{ Col = $col; Desc = [bool](Get-SIPartitionMoveValue $r 'Descending') }) }
    }
    @($by.Values)
}

function Get-SIPartitionMoveIndexSql {
    <# PURE. CREATE INDEX for one nonclustered index (-Index: ConvertTo-SIPartitionMoveIndexes) on the copy, aligned on the scheme. #>
    param([Parameter(Mandatory)]$Index, [Parameter(Mandatory)][string]$Copy)
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    $keys = (@($Index.KeyCols.ToArray()) | ForEach-Object { '{0}{1}' -f (& $q $_.Col), $(if ($_.Desc) { ' DESC' } else { '' }) }) -join ', '
    $inc = if (@($Index.Includes).Count) { ' INCLUDE (' + ((@($Index.Includes) | ForEach-Object { & $q $_ }) -join ', ') + ')' } else { '' }
    $where = if ($Index.Filter) { ' WHERE ' + $Index.Filter } else { '' }
    'CREATE {0}NONCLUSTERED INDEX {1} ON sidata.{2} ({3}){4}{5} ON PS_SICollection ([CollectionId]);' -f $(if ($Index.Unique) { 'UNIQUE ' } else { '' }), (& $q $Index.Name), (& $q $Copy), $keys, $inc, $where
}

function Get-SIPartitionMoveStateSql {
    <# ONE row about one table's move: the scheme, the live table (partitioned = every index on the scheme), the copy, the old table, and the recorded state. #>
    @'
SET NOCOUNT ON;
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @lv int = OBJECT_ID(@Live, N'U'), @cpy int = OBJECT_ID(N'sidata.' + @Copy, N'U'), @odt int = OBJECT_ID(N'sidata.' + @Old, N'U');
DECLARE @st nvarchar(32) = NULL, @sw datetime2(0) = NULL, @ck datetime2(0) = NULL;
IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NOT NULL
    SELECT @st = State, @sw = SwappedAt, @ck = CheckedAt FROM sidata.PartitionMove WHERE TableName = @Name;
SELECT CASE WHEN @ps IS NULL OR OBJECT_ID(N'sidata.PartitionMove', N'U') IS NULL OR OBJECT_ID(N'sidata.PartitionMoveTouched', N'U') IS NULL THEN 0 ELSE 1 END AS Ready,
       CASE WHEN @lv IS NULL THEN 0 ELSE 1 END AS Live,
       CASE WHEN @lv IS NOT NULL AND @ps IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = @lv AND is_hypothetical = 0 AND data_space_id <> @ps) THEN 1 ELSE 0 END AS Partitioned,
       CASE WHEN @cpy IS NULL THEN 0 ELSE 1 END AS CopyExists,
       CASE WHEN @odt IS NULL THEN 0 ELSE 1 END AS OldExists,
       @st AS State, @sw AS SwappedAt, @ck AS CheckedAt;
'@
}

function Get-SIPartitionMovePreflightSql {
    <# What stops a table from being moved without changing what anyone sees: one row per finding (K; N). None = it can be moved. #>
    @'
SET NOCOUNT ON;
DECLARE @lv int = OBJECT_ID(@Live, N'U');
SELECT N'trigger' AS K, t.name AS N FROM sys.triggers AS t WHERE t.parent_id = @lv AND t.name <> @Trigger
UNION ALL SELECT N'referenced', fk.name FROM sys.foreign_keys AS fk WHERE fk.referenced_object_id = @lv
UNION ALL SELECT N'grant', CONVERT(nvarchar(128), p.permission_name) COLLATE DATABASE_DEFAULT FROM sys.database_permissions AS p WHERE p.class = 1 AND p.major_id = @lv
UNION ALL SELECT N'index', i.name FROM sys.indexes AS i WHERE i.object_id = @lv AND i.type NOT IN (0, 1, 2) AND i.is_hypothetical = 0 AND NOT (i.type = 6 AND i.name = ISNULL(@Ncci, N''))
UNION ALL SELECT N'heap', N'' FROM sys.indexes AS i WHERE i.object_id = @lv AND i.index_id = 0
UNION ALL SELECT N'schemabound', OBJECT_NAME(d.referencing_id) FROM sys.sql_expression_dependencies AS d WHERE d.referenced_id = @lv AND d.is_schema_bound_reference = 1;
'@
}

function Get-SIPartitionMoveKey {
    <#
        PURE. The table's clustered key as the move needs it -- (CollectionId, <one column>) -- from its indexes
        (ConvertTo-SIPartitionMoveIndexes) and columns. Returns @{ Ok; Column; Type; Why; PkName }.
    #>
    param([object[]]$Indexes = @(), [object[]]$Columns = @())
    $cx = @($Indexes | Where-Object { $_.Type -eq 1 }) | Select-Object -First 1
    if (-not $cx) { return [pscustomobject]@{ Ok = $false; Column = ''; Type = ''; PkName = ''; Why = 'the table has no clustered key' } }
    $k = @($cx.KeyCols.ToArray())
    if ($k.Count -ne 2 -or $k[0].Col -ne 'CollectionId' -or $k[0].Desc -or $k[1].Desc -or -not $cx.Pk) {
        return [pscustomobject]@{ Ok = $false; Column = ''; Type = ''; PkName = ''; Why = ('its clustered key is not (CollectionId, one key): ' + ((@($k) | ForEach-Object { $_.Col }) -join ', ')) }
    }
    $col = @($Columns | Where-Object { [string](Get-SIPartitionMoveValue $_ 'Name') -eq $k[1].Col }) | Select-Object -First 1
    $type = if ($col) { Format-SIPartitionMoveColumnType -Column $col } else { $null }
    if (-not $type) { return [pscustomobject]@{ Ok = $false; Column = $k[1].Col; Type = ''; PkName = ''; Why = 'the type of its key column is not known' } }
    [pscustomobject]@{ Ok = $true; Column = $k[1].Col; Type = $type; PkName = $cx.Name; Why = '' }
}

function Get-SIPartitionMoveCreateSql {
    <#
        PURE. The copy beside the table, ONE transaction: the same columns (SELECT INTO keeps the identity), its primary key and
        every nonclustered index on the scheme, the default / check constraints (named <name>_Partitioned until the swap), the
        trigger on the OLD table that notes every collection whose rows change from now on, and the state row.
    #>
    param([Parameter(Mandatory)]$Names, [Parameter(Mandatory)]$Key, [object[]]$Indexes = @(), [object[]]$Constraints = @())
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('SET NOCOUNT ON;')
    [void]$sb.AppendLine('SET XACT_ABORT ON;')
    [void]$sb.AppendLine('SET LOCK_TIMEOUT 30000;')
    [void]$sb.AppendLine('BEGIN TRANSACTION;')
    [void]$sb.AppendLine(('SELECT * INTO sidata.{0} FROM sidata.{1} WHERE 1 = 0;' -f (& $q $Names.Copy), (& $q $Names.Table)))
    [void]$sb.AppendLine(('ALTER TABLE sidata.{0} ADD CONSTRAINT {1} PRIMARY KEY CLUSTERED ([CollectionId], {2}) ON PS_SICollection ([CollectionId]);' -f (& $q $Names.Copy), (& $q ($Key.PkName + '_Partitioned')), (& $q $Key.Column)))
    foreach ($c in @($Constraints | Where-Object { $null -ne $_ })) {
        $kind = [string](Get-SIPartitionMoveValue $c 'Kind'); $nm = [string](Get-SIPartitionMoveValue $c 'Name') + '_Partitioned'; $def = [string](Get-SIPartitionMoveValue $c 'Definition'); $col = [string](Get-SIPartitionMoveValue $c 'Col')
        if ($kind -eq 'D') { [void]$sb.AppendLine(('ALTER TABLE sidata.{0} ADD CONSTRAINT {1} DEFAULT {2} FOR {3};' -f (& $q $Names.Copy), (& $q $nm), $def, (& $q $col))) }
        elseif ($kind -eq 'C') { [void]$sb.AppendLine(('ALTER TABLE sidata.{0} ADD CONSTRAINT {1} CHECK {2};' -f (& $q $Names.Copy), (& $q $nm), $def)) }
    }
    foreach ($ix in @($Indexes | Where-Object { $_ -and $_.Type -eq 2 })) { [void]$sb.AppendLine((Get-SIPartitionMoveIndexSql -Index $ix -Copy $Names.Copy)) }
    $trg = @"
CREATE TRIGGER sidata.$(& $q $Names.Trigger) ON sidata.$(& $q $Names.Table) AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT sidata.PartitionMoveTouched (TableName, CollectionId)
    SELECT N'$($Names.Table)', x.CollectionId FROM (SELECT CollectionId FROM inserted UNION SELECT CollectionId FROM deleted) AS x
    WHERE NOT EXISTS (SELECT 1 FROM sidata.PartitionMoveTouched AS t WHERE t.TableName = N'$($Names.Table)' AND t.CollectionId = x.CollectionId);
END
"@
    [void]$sb.AppendLine(("IF OBJECT_ID(N'sidata.{0}', N'TR') IS NULL EXEC (N'{1}');" -f $Names.Trigger, $trg.Replace("'", "''")))
    [void]$sb.AppendLine(("DELETE FROM sidata.PartitionMoveTouched WHERE TableName = N'{0}';" -f $Names.Table))
    [void]$sb.AppendLine(("IF EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName = N'{0}') UPDATE sidata.PartitionMove SET State = N'copying', Note = NULL, UpdatedAt = SYSUTCDATETIME() WHERE TableName = N'{0}';" -f $Names.Table))
    [void]$sb.AppendLine(("ELSE INSERT sidata.PartitionMove (TableName, State) VALUES (N'{0}', N'copying');" -f $Names.Table))
    [void]$sb.AppendLine('COMMIT TRANSACTION;')
    $sb.ToString()
}

function Get-SIPartitionMoveLobSql {
    <#
        PURE. The copy keeps its documents out of the row when the table does (sql\si-data-schema.sql, "THE DOCUMENTS ARE STORED
        OUT OF THE ROW", 2026-11-05) -- SELECT ... INTO does not carry that option. Idempotent; a metadata change only.
    #>
    param([Parameter(Mandatory)]$Names)
    @"
IF EXISTS (SELECT 1 FROM sys.tables WHERE object_id = OBJECT_ID(N'sidata.$($Names.Table)') AND large_value_types_out_of_row = 1)
   AND EXISTS (SELECT 1 FROM sys.tables WHERE object_id = OBJECT_ID(N'sidata.$($Names.Copy)') AND large_value_types_out_of_row = 0)
    EXEC sys.sp_tableoption @TableNamePattern = N'sidata.$($Names.Copy)', @OptionName = N'large value types out of row', @OptionValue = N'1';
"@
}

function Get-SIPartitionMoveConstraintsSql {
    <# The default and check constraints of one table (Kind D / C; Name; Definition; Col) -- copied to the copy. Foreign keys are added at the swap. #>
    @'
SELECT N'D' AS Kind, d.name AS Name, d.definition AS Definition, c.name AS Col FROM sys.default_constraints AS d JOIN sys.columns AS c ON c.object_id = d.parent_object_id AND c.column_id = d.parent_column_id WHERE d.parent_object_id = OBJECT_ID(@Obj, N'U')
UNION ALL SELECT N'C', k.name, k.definition, NULL FROM sys.check_constraints AS k WHERE k.parent_object_id = OBJECT_ID(@Obj, N'U');
'@
}

function Get-SIPartitionMoveForeignKeysSql {
    <# The foreign keys of one table (one column each in this product): Name; Col; RefSchema; RefTable; RefCol. #>
    @'
SELECT fk.name AS Name, pc.name AS Col, OBJECT_SCHEMA_NAME(fk.referenced_object_id) AS RefSchema, OBJECT_NAME(fk.referenced_object_id) AS RefTable, rc.name AS RefCol,
       (SELECT COUNT(*) FROM sys.foreign_key_columns AS z WHERE z.constraint_object_id = fk.object_id) AS Cols
FROM sys.foreign_keys AS fk
JOIN sys.foreign_key_columns AS k ON k.constraint_object_id = fk.object_id
JOIN sys.columns AS pc ON pc.object_id = k.parent_object_id AND pc.column_id = k.parent_column_id
JOIN sys.columns AS rc ON rc.object_id = k.referenced_object_id AND rc.column_id = k.referenced_column_id
WHERE fk.parent_object_id = OBJECT_ID(@Obj, N'U');
'@
}

# ---------------------------------------------------------------------------------------------------------------------
#  STABILITY (2026-11-23 review): every statement of the move is BOUNDED (a statement time limit, the window's deadline and
#  the stop seam before every range and in every loop), ONE mover at a time (a lease row), counts and checksums per kept
#  collection only (never a whole-table scan, never retired rows), the swap holds the table only to re-read the trigger's
#  notes, room for the copy checked before it is made, and a move that cannot converge gives up and cleans up after itself.
# ---------------------------------------------------------------------------------------------------------------------
$script:SIPartitionStatementSeconds = 120   # the longest one statement of the move may run (a range is sized for ~5 s)
$script:SIPartitionLeaseSeconds = 180       # a mover lease not beaten for this long is free (above one statement's limit)
$script:SIPartitionGiveUpWindows = 12       # windows in a row in which runs changed copied rows again -> the move gives up
$script:SIPartitionBatchBytes = 64MB        # one copy range never carries more than about this much data
$script:SIPartitionSpaceMargin = 0.10       # the share of the database's maximum size kept free after the copy is made
$script:SIPartitionTerminalStates = @('blocked', 'gave-up', 'check-differs', 'waiting-space')

function New-SIPartitionBoundedInvoke {
    <#
        PURE. The -Invoke seam with a statement time limit: it hands -Seconds to the store's optional 4th argument
        (TimeoutSeconds; a seam without it ignores it). Every statement of the move goes through it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$Seconds = $script:SIPartitionStatementSeconds)
    $siBoundedInner = $Invoke; $siBoundedSeconds = $Seconds
    { param($s, $p, $m) & $siBoundedInner $s $p $m $siBoundedSeconds }.GetNewClosure()
}

function Get-SIPartitionLeaseSql {
    <#
        ONE MOVER AT A TIME (review item 2): the updater's bounded step and the index build job must never move the same table
        at once. A lease row (sidata.PartitionMove '(mover)': State held | free, Note = the holder, UpdatedAt = its last beat)
        -- one connection per statement, so a session app lock cannot hold across them; the row does. -Mode Enter / Beat:
        taken or kept when free, held by the same holder, or not beaten for @Stale seconds; answers 1 when this holder holds it.
        -Mode Exit: given up (only by its holder).
    #>
    param([Parameter(Mandatory)][ValidateSet('Enter', 'Exit')][string]$Mode)
    if ($Mode -eq 'Exit') { return "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NOT NULL UPDATE sidata.PartitionMove SET State = N'free', UpdatedAt = SYSUTCDATETIME() WHERE TableName = N'(mover)' AND Note = @H AND State = N'held';" }
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NULL BEGIN SELECT 0; RETURN; END
DECLARE @st int = TRY_CONVERT(int, @Stale); IF @st IS NULL OR @st < 30 SET @st = 180;
BEGIN TRANSACTION;
IF NOT EXISTS (SELECT 1 FROM sidata.PartitionMove WITH (UPDLOCK, HOLDLOCK) WHERE TableName = N'(mover)')
    INSERT sidata.PartitionMove (TableName, State, Note) VALUES (N'(mover)', N'held', @H);
ELSE
    UPDATE sidata.PartitionMove SET State = N'held', Note = @H, UpdatedAt = SYSUTCDATETIME()
    WHERE TableName = N'(mover)' AND (State <> N'held' OR Note = @H OR UpdatedAt < DATEADD(second, -@st, SYSUTCDATETIME()));
SELECT CASE WHEN EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName = N'(mover)' AND State = N'held' AND Note = @H) THEN 1 ELSE 0 END;
COMMIT TRANSACTION;
'@
}

function Enter-SIPartitionLease {
    <# Takes (or beats) the mover lease for -Holder. $true when held. Never throws ($false). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Holder, [int]$StaleSeconds = $script:SIPartitionLeaseSeconds)
    try { [int](& $Invoke (Get-SIPartitionLeaseSql -Mode Enter) @{ H = $Holder; Stale = [string]$StaleSeconds } 'scalar') -eq 1 } catch { $false }
}

function Exit-SIPartitionLease {
    <# Gives the mover lease up (only when -Holder holds it). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Holder)
    try { $null = & $Invoke (Get-SIPartitionLeaseSql -Mode Exit) @{ H = $Holder } 'nonquery' } catch { }
}

function Get-SIPartitionMoveIdsSql {
    <#
        BOUNDED (review item 3): the collections that hold rows in the OLD table, by seeks on its clustered key (one per
        collection: a skip scan), never a scan of its rows; answered with whether each is KEPT (not retired, or the published
        run's, or not known in sidata.Collection -- then it is copied rather than lost). One row per collection.
    #>
    param([Parameter(Mandatory)]$Names)
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    @"
SET NOCOUNT ON;
DECLARE @pub int = NULL;
IF OBJECT_ID(N'sidata.PublishedRun', N'U') IS NOT NULL
    EXEC sp_executesql N'SELECT TOP (1) @p = DetailedCollectionId FROM sidata.PublishedRun WHERE Name = N''current''', N'@p int OUTPUT', @p = @pub OUTPUT;
DECLARE @ids TABLE (C int NOT NULL PRIMARY KEY);
-- one seek per collection on the clustered key (a skip scan), never a scan of the rows
DECLARE @nx int = (SELECT MIN(CollectionId) FROM sidata.$(& $q $Names.Table));
WHILE @nx IS NOT NULL
BEGIN
    INSERT @ids (C) VALUES (@nx);
    SET @nx = (SELECT MIN(x.CollectionId) FROM sidata.$(& $q $Names.Table) AS x WHERE x.CollectionId > @nx);
END
SELECT i.C AS CollectionId, CASE WHEN c.CollectionId IS NULL OR c.RetiredAt IS NULL OR c.CollectionId = ISNULL(@pub, -1) THEN 1 ELSE 0 END AS Kept,
       CASE WHEN c.CollectionId IS NOT NULL AND c.Status = N'Complete' THEN 1 ELSE 0 END AS Complete
FROM @ids AS i LEFT JOIN sidata.Collection AS c ON c.CollectionId = i.C ORDER BY i.C;
"@
}

function Get-SIPartitionMoveCountOneSql {
    <#
        BOUNDED: ONE kept collection's rows in the old table and in the copy (seeks on the clustered key of each), whether a run
        changed it after it was copied (the trigger's note), and whether its copy was VERIFIED (rows + checksum) at this count.
        A copy that is not there counts 0.
    #>
    param([Parameter(Mandatory)]$Names)
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    @"
SET NOCOUNT ON;
DECLARE @c int = CONVERT(int, @CollectionId), @o bigint, @k bigint = 0;
SELECT @o = COUNT_BIG(*) FROM sidata.$(& $q $Names.Table) WHERE CollectionId = @c;
IF OBJECT_ID(N'sidata.$($Names.Copy)', N'U') IS NOT NULL
    EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM sidata.$(& $q $Names.Copy) WHERE CollectionId = @c', N'@c int, @n bigint OUTPUT', @c = @c, @n = @k OUTPUT;
SELECT @c AS CollectionId, @o AS Old, @k AS Copied, 1 AS Kept,
       CASE WHEN EXISTS (SELECT 1 FROM sidata.PartitionMoveTouched AS t WHERE t.TableName = N'$($Names.Table)' AND t.CollectionId = @c) THEN 1 ELSE 0 END AS Touched,
       CASE WHEN OBJECT_ID(N'sidata.PartitionMoveVerified', N'U') IS NOT NULL
                 AND EXISTS (SELECT 1 FROM sidata.PartitionMoveVerified AS v WHERE v.TableName = N'$($Names.Table)' AND v.CollectionId = @c AND v.[Rows] = @o) THEN 1 ELSE 0 END AS Verified;
"@
}

function Read-SIPartitionMoveCounts {
    <#
        BOUNDED counts for the plan: the kept collections of the old table (Get-SIPartitionMoveIdsSql), then one statement each
        (Get-SIPartitionMoveCountOneSql) -- never the retired ones, never one scan of the whole table. Stops at -DeadlineUtc or
        at a stop reason (-StopNow): the result says Incomplete, and the plan is then not ready. Returns @{ Rows; Incomplete;
        Ids (every collection with its Kept / Complete) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Names, [datetime]$DeadlineUtc = [datetime]::MaxValue, [scriptblock]$StopNow)
    $ids = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionMoveIdsSql -Names $Names) @{} 'reader')
    $rows = New-Object System.Collections.Generic.List[object]; $inc = $false
    foreach ($i in @($ids | Where-Object { [int](Get-SIPartitionMoveValue $_ 'Kept') -eq 1 })) {
        if ([datetime]::UtcNow -ge $DeadlineUtc) { $inc = $true; break }
        if ($StopNow) { $w = [string](& $StopNow); if ($w) { $inc = $true; break } }
        $r = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionMoveCountOneSql -Names $Names) @{ CollectionId = [string](Get-SIPartitionMoveValue $i 'CollectionId') } 'reader') | Select-Object -First 1
        if ($r) { $rows.Add($r) }
    }
    [pscustomobject]@{ Rows = $rows.ToArray(); Incomplete = $inc; Ids = @($ids) }
}

function Get-SIPartitionMovePlan {
    <#
        PURE. What this window does for one table, from the counts (Read-SIPartitionMoveCounts' Rows): @{ Reset (collections
        copied again from the start: changed after they were copied, or more rows copied than the old table holds); Copy
        (collections with rows still to copy, ascending); Done (kept collections copied exactly -- by count); Verify (Done ones
        whose copy is not verified by checksum yet); ScopeRows; CopiedRows; Ready ($true = every kept collection is copied
        exactly, VERIFIED and none changed) }. A collection that is not kept (retired) is never copied.
    #>
    param([object[]]$Rows = @(), [switch]$Incomplete)
    $reset = New-Object System.Collections.Generic.List[int]; $copy = New-Object System.Collections.Generic.List[int]; $done = New-Object System.Collections.Generic.List[int]
    $verify = New-Object System.Collections.Generic.List[int]
    $scope = 0L; $copied = 0L
    foreach ($r in @($Rows | Where-Object { $null -ne $_ } | Sort-Object { [int](Get-SIPartitionMoveValue $_ 'CollectionId') })) {
        $c = [int](Get-SIPartitionMoveValue $r 'CollectionId'); $o = [long](Get-SIPartitionMoveValue $r 'Old'); $k = [long](Get-SIPartitionMoveValue $r 'Copied')
        $kept = [int](Get-SIPartitionMoveValue $r 'Kept') -eq 1; $touched = [int](Get-SIPartitionMoveValue $r 'Touched') -eq 1
        $ver = [int](Get-SIPartitionMoveValue $r 'Verified') -eq 1
        if (-not $kept -or $o -eq 0) { continue }
        $scope += $o
        if ($touched -or $k -gt $o) { $reset.Add($c); $copy.Add($c); continue }
        if ($k -eq $o) { $done.Add($c); $copied += $k; if (-not $ver) { $verify.Add($c) }; continue }
        $copied += $k
        $copy.Add($c)
    }
    [pscustomobject]@{ Reset = $reset.ToArray(); Copy = $copy.ToArray(); Done = $done.ToArray(); Verify = $verify.ToArray(); ScopeRows = $scope; CopiedRows = $copied
                       Ready = ($copy.Count -eq 0 -and $verify.Count -eq 0 -and -not $Incomplete) }
}

function Get-SIPartitionMoveSplitSql {
    <#
        The partition of ONE collection (@CollectionId): the boundaries c and c+1 -- only an EMPTY partition is cut, so no row
        ever moves. Answers ready | not-empty.
    #>
    @'
SET NOCOUNT ON;
SET LOCK_TIMEOUT 30000;
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @v int = CONVERT(int, @CollectionId), @k int = 0, @p int, @out nvarchar(32) = N'ready';
IF @pf IS NULL OR @ps IS NULL BEGIN SELECT N'none'; RETURN; END
WHILE @k < 2
BEGIN
    IF (SELECT COUNT(*) FROM sys.partition_range_values AS r WHERE r.function_id = @pf AND CONVERT(int, r.value) = @v) = 0
    BEGIN
        SET @p = $PARTITION.PF_SICollection(@v);
        -- (catalog views only: the job's identity has no VIEW DATABASE STATE)
        IF EXISTS (SELECT 1 FROM sys.partitions AS s JOIN sys.indexes AS x ON x.object_id = s.object_id AND x.index_id = s.index_id
                   WHERE x.data_space_id = @ps AND s.index_id IN (0, 1) AND s.partition_number = @p AND s.rows > 0)
        BEGIN SET @out = N'not-empty'; BREAK; END
        ALTER PARTITION SCHEME PS_SICollection NEXT USED [PRIMARY];
        ALTER PARTITION FUNCTION PF_SICollection() SPLIT RANGE (@v);
    END
    SET @v = @v + 1; SET @k = @k + 1;
END
SELECT @out;
'@
}

function Get-SIPartitionMoveCopySql {
    <#
        PURE. ONE key range of one collection into the copy: the next @Batch rows after the copy's own last key of the
        collection (the copy is filled in key order, so where it stands is where it goes on), the identity values kept.
        Answers the rows copied.
    #>
    param([Parameter(Mandatory)]$Names, [Parameter(Mandatory)]$Key, [Parameter(Mandatory)][string[]]$Columns, [bool]$Identity = $false)
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    $cols = ($Columns | ForEach-Object { & $q $_ }) -join ', '
    $k = & $q $Key.Column
    $on = if ($Identity) { "SET IDENTITY_INSERT sidata.$(& $q $Names.Copy) ON;" } else { '' }
    $off = if ($Identity) { "SET IDENTITY_INSERT sidata.$(& $q $Names.Copy) OFF;" } else { '' }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c int = CONVERT(int, @CollectionId), @n int = CONVERT(int, @Batch), @done bigint = 0;
DECLARE @a $($Key.Type) = (SELECT MAX($k) FROM sidata.$(& $q $Names.Copy) WHERE CollectionId = @c);
$on
IF @a IS NULL
    INSERT sidata.$(& $q $Names.Copy) ($cols) SELECT TOP (@n) $cols FROM sidata.$(& $q $Names.Table) WHERE CollectionId = @c ORDER BY $k;
ELSE
    INSERT sidata.$(& $q $Names.Copy) ($cols) SELECT TOP (@n) $cols FROM sidata.$(& $q $Names.Table) WHERE CollectionId = @c AND $k > @a ORDER BY $k;
SET @done = @@ROWCOUNT;
$off
SELECT @done;
"@
}

function Get-SIPartitionMoveResetSql {
    <# One batch of a collection's rows in the COPY removed (the copy is the move's own table) before it is copied again --
       its note and its verification go with it. Answers the rows removed. #>
    param([Parameter(Mandatory)]$Names)
    "SET NOCOUNT ON; DELETE FROM sidata.PartitionMoveTouched WHERE TableName = N'$($Names.Table)' AND CollectionId = CONVERT(int, @CollectionId); IF OBJECT_ID(N'sidata.PartitionMoveVerified', N'U') IS NOT NULL DELETE FROM sidata.PartitionMoveVerified WHERE TableName = N'$($Names.Table)' AND CollectionId = CONVERT(int, @CollectionId); DELETE TOP (50000) FROM sidata.[$(([string]$Names.Copy).Replace(']', ']]'))] WHERE CollectionId = CONVERT(int, @CollectionId); SELECT @@ROWCOUNT;"
}

function Get-SIPartitionMoveTouchSql {
    <# One collection noted as changed (it is copied again from the start in the next window) -- the self-heal of a copy that
       cannot go on from where it stands. #>
    param([Parameter(Mandatory)]$Names)
    "SET NOCOUNT ON; IF NOT EXISTS (SELECT 1 FROM sidata.PartitionMoveTouched WHERE TableName = N'$($Names.Table)' AND CollectionId = CONVERT(int, @CollectionId)) INSERT sidata.PartitionMoveTouched (TableName, CollectionId) VALUES (N'$($Names.Table)', CONVERT(int, @CollectionId));"
}

function Get-SIPartitionMoveRowHashExpr {
    <#
        PURE. The checksum of ONE row (DATA QUALITY, acceptance (6g) of #1314: count + hash read back): BINARY_CHECKSUM over
        every column that is not a large value (case and every byte count), plus the checksum of a SHA-256 of each large value
        (nvarchar(max) / varbinary(max): the documents, e.g. DetailJson) -- a value a release writes (a column added WITH
        VALUES) or a run changes shows as a different sum. -Columns: Get-SIPartitionMoveColumnsSql's rows; -Alias the table's.
    #>
    param([Parameter(Mandatory)][object[]]$Columns, [string]$Alias = 't')
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    $plain = New-Object System.Collections.Generic.List[string]; $large = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Columns | Where-Object { $null -ne $_ })) {
        $nm = [string](Get-SIPartitionMoveValue $c 'Name'); $ty = ([string](Get-SIPartitionMoveValue $c 'TypeName')).ToLowerInvariant(); $len = [int](Get-SIPartitionMoveValue $c 'MaxLength')
        if ($ty -in 'xml', 'text', 'ntext', 'image', 'sql_variant', 'geography', 'geometry', 'hierarchyid') { $large.Add(('CONVERT(nvarchar(max), {0}.{1})' -f $Alias, (& $q $nm))); continue }
        if ($len -eq -1) { $large.Add(('{0}.{1}' -f $Alias, (& $q $nm))); continue }
        $plain.Add(('{0}.{1}' -f $Alias, (& $q $nm)))
    }
    $e = 'CAST(BINARY_CHECKSUM({0}) AS bigint)' -f ($plain -join ', ')
    foreach ($l in $large) { $e += (' + ISNULL(CAST(BINARY_CHECKSUM(HASHBYTES(''SHA2_256'', {0})) AS bigint), 0)' -f $l) }
    $e
}

function Get-SIPartitionMoveHashRangeSql {
    <#
        PURE. BOUNDED: ONE key range of one collection compared between two tables -- -A (the reference: the old table) and -B
        (the copy, or after the swap the new table): the range is the next @Batch keys of -A after @After (@HasAfter = 0 = from
        the first); rows and the sum of the row checksums (Get-SIPartitionMoveRowHashExpr) of each in that range. Answers ONE
        row: Hi (the range's last key; NULL = nothing left), AN, BN, AH, BH.
    #>
    param([Parameter(Mandatory)][string]$A, [Parameter(Mandatory)][string]$B, [Parameter(Mandatory)]$Key, [Parameter(Mandatory)][object[]]$Columns)
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    $k = & $q $Key.Column
    $ha = Get-SIPartitionMoveRowHashExpr -Columns $Columns -Alias 'a'
    $hb = Get-SIPartitionMoveRowHashExpr -Columns $Columns -Alias 'b'
    @"
SET NOCOUNT ON;
DECLARE @c int = CONVERT(int, @CollectionId), @n int = CONVERT(int, @Batch), @has bit = CONVERT(bit, @HasAfter);
DECLARE @a $($Key.Type) = CASE WHEN @has = 1 THEN CONVERT($($Key.Type), @After) END, @hi $($Key.Type);
SELECT @hi = MAX(x.K) FROM (SELECT TOP (@n) $k AS K FROM sidata.$(& $q $A) WHERE CollectionId = @c AND (@has = 0 OR $k > @a) ORDER BY $k) AS x;
IF @hi IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(512)) AS Hi, CAST(0 AS bigint) AS AN, (SELECT COUNT_BIG(*) FROM sidata.$(& $q $B) AS b WHERE b.CollectionId = @c AND (@has = 0 OR b.$k > @a)) AS BN, CAST(0 AS bigint) AS AH, CAST(0 AS bigint) AS BH;
    RETURN;
END
SELECT CONVERT(nvarchar(512), @hi) AS Hi,
       (SELECT COUNT_BIG(*) FROM sidata.$(& $q $A) AS a WHERE a.CollectionId = @c AND (@has = 0 OR a.$k > @a) AND a.$k <= @hi) AS AN,
       (SELECT COUNT_BIG(*) FROM sidata.$(& $q $B) AS b WHERE b.CollectionId = @c AND (@has = 0 OR b.$k > @a) AND b.$k <= @hi) AS BN,
       (SELECT ISNULL(SUM($ha), 0) FROM sidata.$(& $q $A) AS a WHERE a.CollectionId = @c AND (@has = 0 OR a.$k > @a) AND a.$k <= @hi) AS AH,
       (SELECT ISNULL(SUM($hb), 0) FROM sidata.$(& $q $B) AS b WHERE b.CollectionId = @c AND (@has = 0 OR b.$k > @a) AND b.$k <= @hi) AS BH;
"@
}

function Invoke-SIPartitionMoveCompare {
    <#
        ONE collection (-CollectionId) compared between -A and -B range by range (Get-SIPartitionMoveHashRangeSql): rows and
        checksum in every range. Each range is sized for -TargetMs, inside -DeadlineUtc and the stop seam (-StopNow). Returns
        @{ Outcome (same | different | stopped); Rows (of A); Detail }. Never throws (an error = 'stopped' with the Detail).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$A, [Parameter(Mandatory)][string]$B, [Parameter(Mandatory)]$Key,
          [Parameter(Mandatory)][object[]]$Columns, [Parameter(Mandatory)][string]$CollectionId, [datetime]$DeadlineUtc = [datetime]::MaxValue,
          [scriptblock]$StopNow, [long]$BatchSize = 2000, [long]$TargetMs = 5000)
    $sql = Get-SIPartitionMoveHashRangeSql -A $A -B $B -Key $Key -Columns $Columns
    $after = ''; $has = 0; $rows = 0L; $size = [long][Math]::Max(100L, $BatchSize)
    try {
        while ($true) {
            if ([datetime]::UtcNow -ge $DeadlineUtc) { return [pscustomobject]@{ Outcome = 'stopped'; Rows = $rows; Detail = 'the window''s time is used' } }
            if ($StopNow) { $w = [string](& $StopNow); if ($w) { return [pscustomobject]@{ Outcome = 'stopped'; Rows = $rows; Detail = $w } } }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = ConvertTo-SIPartitionMoveRows (& $Invoke $sql @{ CollectionId = $CollectionId; Batch = [string]$size; HasAfter = [string]$has; After = $after } 'reader') | Select-Object -First 1
            $sw.Stop()
            $an = [long](Get-SIPartitionMoveValue $r 'AN'); $bn = [long](Get-SIPartitionMoveValue $r 'BN'); $ah = [long](Get-SIPartitionMoveValue $r 'AH'); $bh = [long](Get-SIPartitionMoveValue $r 'BH')
            $hi = Get-SIPartitionMoveValue $r 'Hi'
            if ($an -ne $bn) { return [pscustomobject]@{ Outcome = 'different'; Rows = $rows; Detail = ('{0} rows against {1} in one key range' -f $an, $bn) } }
            if ($ah -ne $bh) { return [pscustomobject]@{ Outcome = 'different'; Rows = $rows; Detail = 'the same rows, other values (the checksum differs) in one key range' } }
            if ($null -eq $hi) { return [pscustomobject]@{ Outcome = 'same'; Rows = $rows; Detail = '' } }
            $rows += $an; $after = [string]$hi; $has = 1
            $size = Get-SIPartitionMoveNextSize -Current $size -ElapsedMs ([long]$sw.ElapsedMilliseconds) -TargetMs $TargetMs
        }
    } catch { [pscustomobject]@{ Outcome = 'stopped'; Rows = $rows; Detail = $_.Exception.Message } }
}

function Get-SIPartitionMoveVerifiedSaveSql {
    <# One collection's copy recorded as verified (rows + checksum) at -Rows rows. #>
    "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.PartitionMoveVerified', N'U') IS NOT NULL BEGIN DELETE FROM sidata.PartitionMoveVerified WHERE TableName = @T AND CollectionId = CONVERT(int, @CollectionId); INSERT sidata.PartitionMoveVerified (TableName, CollectionId, [Rows]) VALUES (@T, CONVERT(int, @CollectionId), CONVERT(bigint, @Rows)); END"
}

function Get-SIPartitionMoveSwapSql {
    <#
        PURE. THE SWAP, one SHORT transaction (review item 4): every kept collection was compared BEFORE it -- rows and
        checksum (Invoke-SIPartitionMoveCompare, recorded in sidata.PartitionMoveVerified) -- so under the exclusive lock only
        the trigger's notes are read again: a note for this table (a write since the compare, anything the trigger saw) = no
        swap ('changed'). Then: the copy's identity at or above the old one's; SI's own columnstore index on the OLD table
        dropped here, inside the swap (review item 5: never before the copy -- it serves the readers until this moment) and its
        cfg.IndexBuild row set back to 'waiting' (built again aligned on the new table); the renames (tables, primary keys,
        foreign keys, default / check constraints); the trigger removed; the state. Answers ONE row (Outcome swapped | changed;
        ScopeRows; Detail; Columnstore (1 = it dropped the old table's columnstore index)).
    #>
    param([Parameter(Mandatory)]$Names, [Parameter(Mandatory)]$Key, [bool]$Identity = $false, [object[]]$ForeignKeys = @(), [object[]]$Constraints = @(), [long]$ScopeRows = 0)
    $q = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
    $lit = { param($s) "N'" + ([string]$s).Replace("'", "''") + "'" }
    $t = $Names.Table; $cp = $Names.Copy; $od = $Names.Old
    $renames = New-Object System.Text.StringBuilder
    [void]$renames.AppendLine(("EXEC sp_rename {0}, {1};" -f (& $lit ('sidata.' + $t)), (& $lit $od)))
    [void]$renames.AppendLine(("EXEC sp_rename {0}, {1};" -f (& $lit ('sidata.' + $cp)), (& $lit $t)))
    [void]$renames.AppendLine(("EXEC sp_rename {0}, {1}, N'OBJECT';" -f (& $lit ('sidata.' + $Key.PkName)), (& $lit ($Key.PkName + '_Unpartitioned'))))
    [void]$renames.AppendLine(("EXEC sp_rename {0}, {1}, N'OBJECT';" -f (& $lit ('sidata.' + $Key.PkName + '_Partitioned')), (& $lit $Key.PkName)))
    foreach ($c in @(@($ForeignKeys) + @($Constraints) | Where-Object { $null -ne $_ })) {
        $nm = [string](Get-SIPartitionMoveValue $c 'Name')
        [void]$renames.AppendLine(("EXEC sp_rename {0}, {1}, N'OBJECT';" -f (& $lit ('sidata.' + $nm)), (& $lit ($nm + '_Unpartitioned'))))
        [void]$renames.AppendLine(("EXEC sp_rename {0}, {1}, N'OBJECT';" -f (& $lit ('sidata.' + $nm + '_Partitioned')), (& $lit $nm)))
    }
    $reseed = ''
    if ($Identity) {
        $reseed = @"
DECLARE @io numeric(38, 0) = IDENT_CURRENT(N'sidata.$t'), @ic numeric(38, 0) = IDENT_CURRENT(N'sidata.$cp');
IF @io IS NOT NULL AND (@ic IS NULL OR @io > @ic)
BEGIN
    DECLARE @rs nvarchar(400) = N'DBCC CHECKIDENT (N''sidata.$cp'', RESEED, ' + CONVERT(nvarchar(40), @io) + N') WITH NO_INFOMSGS;';
    EXEC (@rs);
END
"@
    }
    $ix = Get-SIPartitionMoveColumnstoreName -Table $t
    $cs = ''
    if ($ix) {
        $cs = @"
IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID(N'sidata.$t', N'U') AND name = N'$ix' AND type = 6)
BEGIN
    DROP INDEX [$($ix.Replace(']', ']]'))] ON sidata.[$(([string]$t).Replace(']', ']]'))];
    SET @csd = 1;
    IF OBJECT_ID(N'cfg.IndexBuild', N'U') IS NOT NULL
        UPDATE cfg.IndexBuild SET State = N'waiting', SinceUtc = SYSUTCDATETIME(), ForcedUtc = NULL, UpdatedUtc = SYSUTCDATETIME(), UpdatedBy = N'caj-si-index-build',
               Why = N'dropped at the move of sidata.$t onto the collection partitions -- built again aligned on them'
         WHERE TableName = N'sidata.$t' AND IndexName = N'$ix';
END
"@
    }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET LOCK_TIMEOUT 30000;
DECLARE @x int, @chg int = 0, @csd int = 0, @scope bigint = CONVERT(bigint, $([long]$ScopeRows));
BEGIN TRANSACTION;
SELECT TOP (1) @x = 1 FROM sidata.$(& $q $t) WITH (TABLOCKX, HOLDLOCK);
SELECT TOP (1) @x = 1 FROM sidata.$(& $q $cp) WITH (TABLOCKX, HOLDLOCK);
-- only the trigger's notes: nothing was written to the table since every kept collection was compared
SELECT @chg = COUNT(*) FROM sidata.PartitionMoveTouched WHERE TableName = N'$t';
IF @chg > 0
BEGIN
    ROLLBACK TRANSACTION;
    SELECT N'changed' AS Outcome, @scope AS ScopeRows, CONVERT(nvarchar(400), CONCAT(@chg, N' collection(s) changed since they were compared')) AS Detail, 0 AS Columnstore;
    RETURN;
END
$reseed
$cs
$($renames.ToString())
IF OBJECT_ID(N'sidata.$($Names.Trigger)', N'TR') IS NOT NULL EXEC (N'DROP TRIGGER sidata.$(& $q $Names.Trigger)');
DELETE FROM sidata.PartitionMoveTouched WHERE TableName = N'$t';
UPDATE sidata.PartitionMove SET State = N'swapped', ScopeRows = @scope, CopiedRows = @scope, SwappedAt = SYSUTCDATETIME(), Note = NULL, Attempts = 0, UpdatedAt = SYSUTCDATETIME() WHERE TableName = N'$t';
COMMIT TRANSACTION;
SELECT N'swapped' AS Outcome, @scope AS ScopeRows, CONVERT(nvarchar(400), NULL) AS Detail, @csd AS Columnstore;
"@
}

function Get-SIPartitionMoveNextSize {
    <# PURE. The next range's size from the last one's measured time: aim -TargetMs, shrink at once when slower, grow at most
       double -- and never more than -MaxRows (the bytes cap: about SIPartitionBatchBytes of data; 0 = no cap). #>
    param([long]$Current, [long]$ElapsedMs, [long]$TargetMs = 5000, [long]$Minimum = 100, [long]$MaxRows = 0)
    if ($Current -lt $Minimum) { $Current = $Minimum }
    $limit = [double]2.0 * [double]$Current
    $want = if ($ElapsedMs -le 0) { $limit } else { [Math]::Min($limit, [Math]::Floor([double]$Current * ([double]$TargetMs / [double]$ElapsedMs))) }
    if ($MaxRows -gt 0) { $want = [Math]::Min($want, [double][Math]::Max($Minimum, $MaxRows)) }
    [long][Math]::Max([double]$Minimum, $want)
}

function Get-SIPartitionMovePause {
    <#
        PURE. The writers' measured rule (SI-SqlPacing.ps1, source 3): a range that took far longer than the ranges before it is
        the database slowing down -- above 1.7 x their median: a pause as long as that range and half the next size; below
        1.4 x: no pause. Returns @{ PauseMs; Shrink }.
    #>
    param([long[]]$Times = @(), [long]$LastMs = 0)
    $prev = @($Times | Where-Object { $_ -gt 0 })
    if ($prev.Count -lt 3 -or $LastMs -le 0) { return [pscustomobject]@{ PauseMs = 0L; Shrink = $false } }
    $s = @($prev | Sort-Object); $med = [double]$s[[int][Math]::Floor(($s.Count - 1) / 2)]
    if ($med -le 0) { return [pscustomobject]@{ PauseMs = 0L; Shrink = $false } }
    if ($LastMs -ge 1.7 * $med) { return [pscustomobject]@{ PauseMs = $LastMs; Shrink = $true } }
    [pscustomobject]@{ PauseMs = 0L; Shrink = $false }
}

function Set-SIPartitionMoveNote {
    <# Records one table's state and its plain note (sidata.PartitionMove); -Attempt adds one to its windows without
       convergence, -ClearAttempts sets them to 0. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$State, [string]$Note = '', $ScopeRows = $null, $CopiedRows = $null, [switch]$Checked,
          [switch]$Attempt, [switch]$ClearAttempts)
    try {
        $ck = if ($Checked) { ', CheckedAt = SYSUTCDATETIME()' } else { '' }
        $at = if ($Attempt) { ", Attempts = ISNULL(Attempts, 0) + 1" } elseif ($ClearAttempts) { ', Attempts = 0' } else { '' }
        $atCol = if ($Attempt -or $ClearAttempts) { "IF COL_LENGTH('sidata.PartitionMove', 'Attempts') IS NULL SET @a = N'';" } else { '' }
        $sql = @"
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NOT NULL
BEGIN
    DECLARE @a nvarchar(200) = N'$($at.Replace("'", "''"))';
    $atCol
    IF EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName = @T)
    BEGIN
        DECLARE @u nvarchar(max) = N'UPDATE sidata.PartitionMove SET State = @S, Note = NULLIF(@N, N''''), ScopeRows = COALESCE(TRY_CONVERT(bigint, @SR), ScopeRows), CopiedRows = COALESCE(TRY_CONVERT(bigint, @CR), CopiedRows)$ck' + @a + N', UpdatedAt = SYSUTCDATETIME() WHERE TableName = @T';
        EXEC sp_executesql @u, N'@T nvarchar(128), @S nvarchar(32), @N nvarchar(1000), @SR nvarchar(40), @CR nvarchar(40)', @T = @T, @S = @S, @N = @N, @SR = @SR, @CR = @CR;
    END
    ELSE
        INSERT sidata.PartitionMove (TableName, State, Note, ScopeRows, CopiedRows) VALUES (@T, @S, NULLIF(@N, N''), TRY_CONVERT(bigint, @SR), TRY_CONVERT(bigint, @CR));
END
"@
        $null = & $Invoke $sql @{ T = $Table; S = $State; N = $(if ($Note.Length -gt 1000) { $Note.Substring(0, 1000) } else { $Note }); SR = $(if ($null -ne $ScopeRows) { [string]$ScopeRows } else { '' }); CR = $(if ($null -ne $CopiedRows) { [string]$CopiedRows } else { '' }) } 'nonquery'
    } catch { }
}

function Get-SIPartitionMoveSpaceSql {
    <#
        ROOM FOR THE COPY (review item 5): the table's used bytes and rows (catalog), the database's maximum size
        (DATABASEPROPERTYEX MaxSizeInBytes; else the data files' max_size, NULL when any of them grows without a limit) and the
        bytes it uses now (FILEPROPERTY SpaceUsed of its data files). ONE row: TableBytes; TableRows; MaxBytes; UsedBytes.
    #>
    @'
SET NOCOUNT ON;
DECLARE @t int = OBJECT_ID(@Live, N'U');
DECLARE @tb bigint = (SELECT CONVERT(bigint, ISNULL(SUM(a.used_pages), 0)) * 8192 FROM sys.partitions AS p JOIN sys.allocation_units AS a ON a.container_id = CASE WHEN a.type = 2 THEN p.partition_id ELSE p.hobt_id END WHERE p.object_id = @t);
DECLARE @tr bigint = (SELECT CONVERT(bigint, ISNULL(SUM(p.rows), 0)) FROM sys.partitions AS p WHERE p.object_id = @t AND p.index_id IN (0, 1));
DECLARE @mx bigint = TRY_CONVERT(bigint, DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes'));
IF @mx IS NULL OR @mx <= 0
    SELECT @mx = CASE WHEN MIN(CONVERT(bigint, max_size)) < 0 THEN NULL ELSE SUM(CONVERT(bigint, max_size)) * 8192 END FROM sys.database_files WHERE type = 0;
DECLARE @ub bigint = (SELECT SUM(CONVERT(bigint, FILEPROPERTY(name, 'SpaceUsed'))) * 8192 FROM sys.database_files WHERE type = 0);
SELECT @tb AS TableBytes, @tr AS TableRows, @mx AS MaxBytes, @ub AS UsedBytes;
'@
}

function Test-SIPartitionMoveRoom {
    <#
        PURE. Does the copy of -KeptRows rows fit? Need = the table's used bytes x KeptRows / TableRows x 1.25 (the copy carries
        the same row-store indexes); it fits when the database keeps -Margin of its maximum free after it. Unknown maximum
        (no limit) = fits. Returns @{ Fits; NeedMb; FreeMb; Text }.
    #>
    param($Space, [long]$KeptRows, [double]$Margin = $script:SIPartitionSpaceMargin)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $tb = [double](Get-SIPartitionMoveValue $Space 'TableBytes'); $tr = [double](Get-SIPartitionMoveValue $Space 'TableRows')
    $mx = Get-SIPartitionMoveValue $Space 'MaxBytes'; $ub = [double](Get-SIPartitionMoveValue $Space 'UsedBytes')
    $need = if ($tr -gt 0) { $tb * ([double]$KeptRows / $tr) * 1.25 } else { 0.0 }
    if ($null -eq $mx -or [double]$mx -le 0) { return [pscustomobject]@{ Fits = $true; NeedMb = [Math]::Round($need / 1MB); FreeMb = $null; Text = 'the database grows without a set limit' } }
    $free = [double]$mx - $ub - ([double]$mx * $Margin)
    $fits = $need -le $free
    $freeOk = [Math]::Max([double]0, [double]$free)
    [pscustomobject]@{ Fits = $fits; NeedMb = [Math]::Round($need / 1MB); FreeMb = [Math]::Round($freeOk / 1MB)
                       Text = [string]::Format($inv, 'the copy needs about {0:N0} MB; {1:N0} MB are free with {2:P0} of the maximum kept free', $need / 1MB, $freeOk / 1MB, $Margin) }
}

function Invoke-SIPartitionMoveCleanup {
    <#
        THE MOVE LEFT CLEAN (review item 5): the trigger on the old table dropped, the copy dropped, the notes and verifications
        removed, the state -State (gave-up | stopped) with -Why. Only for a table that is NOT on the partitions yet (the copy
        is the move's own table; the live table is never touched). Never throws; $true when it cleaned something.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('IssueContext', 'Recommendation', 'Finding')][string]$Table,
          [Parameter(Mandatory)][ValidateSet('gave-up', 'stopped')][string]$State, [string]$Why = '')
    $n = Get-SIPartitionMoveNames -Table $Table
    try {
        $sql = @"
SET NOCOUNT ON;
SET LOCK_TIMEOUT 30000;
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection'), @did int = 0;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID(N'$($n.Live)', N'U') AND index_id IN (0, 1) AND data_space_id = ISNULL(@ps, -1))
BEGIN
    IF OBJECT_ID(N'sidata.$(([string]$n.Trigger).Replace("'", "''"))', N'TR') IS NOT NULL BEGIN EXEC (N'DROP TRIGGER sidata.[$(([string]$n.Trigger).Replace(']', ']]').Replace("'", "''"))]'); SET @did = 1; END
    IF OBJECT_ID(N'sidata.$(([string]$n.Copy).Replace("'", "''"))', N'U') IS NOT NULL BEGIN EXEC (N'DROP TABLE sidata.[$(([string]$n.Copy).Replace(']', ']]').Replace("'", "''"))]'); SET @did = 1; END
    IF OBJECT_ID(N'sidata.PartitionMoveTouched', N'U') IS NOT NULL DELETE FROM sidata.PartitionMoveTouched WHERE TableName = N'$Table';
    IF OBJECT_ID(N'sidata.PartitionMoveVerified', N'U') IS NOT NULL DELETE FROM sidata.PartitionMoveVerified WHERE TableName = N'$Table';
END
SELECT @did;
"@
        $did = [int](& $Invoke $sql @{} 'scalar') -eq 1
        if ($did -or $State -eq 'gave-up') { Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State $State -Note $Why -ClearAttempts }
        $did
    } catch { $false }
}

function Invoke-SIPartitionMoveStop {
    <# SI_Data_RetireByPartition switched OFF mid-move: every table's move is left clean (Invoke-SIPartitionMoveCleanup,
       'stopped'). Returns the plain lines. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($t in $script:SIPartitionMoveTables) {
        if (Invoke-SIPartitionMoveCleanup -Invoke $Invoke -Table $t -State 'stopped' -Why 'SI_Data_RetireByPartition was switched off -- the copy and its trigger were removed; switched on again, the move starts over') {
            $lines.Add(('partitions: {0}: the move stopped -- SI_Data_RetireByPartition is off: its copy and trigger were removed (nothing current changed)' -f $t))
        }
    }
    $lines.ToArray()
}

function Invoke-SIProPartitionMoveTable {
    <#
        ONE table's move for this window (the steps in the header). -DeadlineUtc: no new range after it. -Sleep (ms): the pause
        seam. -ShouldStop: asked before every range and in every loop ('' = go on). Returns @{ Table; State (partitioned |
        copying | swapped | checked | done | blocked | gave-up | check-differs | waiting-space | failed); Text; ScopeRows;
        CopiedRows; RowsThisRun; RowsPerSecond; StopWhy; Columnstore }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('IssueContext', 'Recommendation', 'Finding')][string]$Table,
          [datetime]$DeadlineUtc = [datetime]::MaxValue, [datetime]$StartedUtc = [datetime]::UtcNow, [scriptblock]$Sleep = { param($ms) Start-Sleep -Milliseconds ([int]$ms) },
          [long]$BatchSize = 5000, [long]$TargetMs = 5000, [scriptblock]$ShouldStop)
    $n = Get-SIPartitionMoveNames -Table $Table
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $res = [pscustomobject]@{ Table = $Table; State = 'failed'; Text = ''; ScopeRows = 0L; CopiedRows = 0L; RowsThisRun = 0L; RowsPerSecond = 0.0; StopWhy = ''; Columnstore = '' }
    $rows = { param($sql, $p) ConvertTo-SIPartitionMoveRows (& $Invoke $sql $p 'reader') }
    # the stop seam: the deadline, then the caller's reason -- asked before every range and in every loop
    $stopNow = {
        if ([datetime]::UtcNow -ge $DeadlineUtc) { return 'the window''s time is used' }
        if (-not $ShouldStop) { return '' }
        $w = ''; try { $w = [string](& $ShouldStop) } catch { $w = ('whether the job must stop could not be read ({0})' -f $_.Exception.Message) }; $w
    }
    $waitNext = { param([string]$why, [string]$state = 'copying', [switch]$Attempt)
        $res.State = 'copying'; $res.StopWhy = $why
        $res.Text = ('{0} -- the next window goes on; the install works on the old table meanwhile' -f $why)
        if ($Attempt) { Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State $state -Note $res.Text -Attempt } else { Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State $state -Note $res.Text }
        $res }
    try {
        $st = & $rows (Get-SIPartitionMoveStateSql) @{ Live = $n.Live; Copy = $n.Copy; Old = $n.Old; Name = $Table } | Select-Object -First 1
        if (-not $st -or [int](Get-SIPartitionMoveValue $st 'Ready') -ne 1) { $res.State = 'blocked'; $res.Text = 'the database does not carry the collection partitions yet (the schema step adds them)'; return $res }
        if ([int](Get-SIPartitionMoveValue $st 'Live') -ne 1) { $res.State = 'blocked'; $res.Text = 'the table is not there'; return $res }
        $state = [string](Get-SIPartitionMoveValue $st 'State')
        $sw = Get-SIPartitionMoveValue $st 'SwappedAt'; $ck = Get-SIPartitionMoveValue $st 'CheckedAt'
        if ($state -in 'gave-up', 'check-differs') {
            $res.State = $state; $res.Text = ('the move ended earlier: {0} -- nothing is done until support looks at it; old collections are removed a little at a time' -f $(if ($state -eq 'gave-up') { 'it gave up (runs changed the copied rows faster than it could finish)' } else { 'the check after the swap found differences, the old table is kept' }))
            return $res
        }
        if ([int](Get-SIPartitionMoveValue $st 'Partitioned') -eq 1) {
            # ---- 5 / 6: the check, then the drop -- each in a LATER window than the step before it ----
            if ([int](Get-SIPartitionMoveValue $st 'OldExists') -ne 1) { $res.State = $(if ($state) { 'done' } else { 'partitioned' }); $res.Text = 'on the collection partitions'; if ($state -ne 'done') { Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'done' -Note $(if ($state) { '' } else { 'made on the collection partitions' }) }; return $res }
            if ($state -eq 'checked' -and $null -ne $ck -and ([datetime]$ck) -lt $StartedUtc.ToUniversalTime().AddSeconds(-1)) {
                $null = & $Invoke ("SET LOCK_TIMEOUT 30000; DROP TABLE sidata.[{0}];" -f ([string]$n.Old).Replace(']', ']]')) @{} 'nonquery'
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'done' -Note 'the old table was dropped after the check passed'
                $res.State = 'done'; $res.Text = 'moved; the old table was dropped (its check passed in an earlier window)'; return $res
            }
            if ($state -eq 'swapped' -and ($null -eq $sw -or ([datetime]$sw) -lt $StartedUtc.ToUniversalTime().AddSeconds(-1))) {
                $chk = Invoke-SIPartitionMoveCheck -Invoke $Invoke -Names $n -DeadlineUtc $DeadlineUtc -StopNow $stopNow
                if ($chk.Outcome -eq 'same') {
                    Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'checked' -Checked -Note 'every complete, kept collection has the same rows and values as in the old table -- the old table is dropped in a later window'
                    $res.State = 'checked'; $res.Text = 'moved; the check passed (rows and checksums) -- the old table is dropped in a later window'; return $res
                }
                if ($chk.Outcome -eq 'stopped') { $res.State = 'swapped'; $res.StopWhy = $chk.Detail; $res.Text = ('moved; the check goes on in the next window ({0})' -f $chk.Detail); return $res }
                # review item 7: a TERMINAL state -- the work query skips it (no restart every wake-up), support is told
                $why = [string]::Format($inv, 'the check after the swap found {0} -- the old table {1} is kept until support looks at it', $chk.Detail, $n.Old)
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'check-differs' -Note $why
                $res.State = 'check-differs'; $res.Text = ('WARNING: ' + $why); return $res
            }
            $res.State = $(if ($state) { $state } else { 'swapped' }); $res.Text = 'moved; the check and the removal of the old table come in later windows'; return $res
        }
        if ([int](Get-SIPartitionMoveValue $st 'OldExists') -eq 1) { $res.State = 'blocked'; $res.Text = ('a table {0} is there already and the table is not on the partitions -- nothing is done (looked at by hand)' -f $n.Old); Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'blocked' -Note $res.Text; return $res }

        # ---- 1. PREFLIGHT ----
        $why = New-Object System.Collections.Generic.List[string]
        foreach ($p in (& $rows (Get-SIPartitionMovePreflightSql) @{ Live = $n.Live; Trigger = $n.Trigger; Ncci = (Get-SIPartitionMoveColumnstoreName -Table $Table) })) {
            $k = [string](Get-SIPartitionMoveValue $p 'K'); $v = [string](Get-SIPartitionMoveValue $p 'N')
            switch ($k) {
                'trigger'    { $why.Add(('it has a trigger of its own ({0})' -f $v)) }
                'referenced' { $why.Add(('a foreign key points at it ({0})' -f $v)) }
                'grant'      { $why.Add(('a right is granted on the table itself ({0}) -- a renamed table would take it along' -f $v)) }
                'index'      { $why.Add(('it has an index that is not a row-store index ({0})' -f $v)) }
                'heap'       { $why.Add('it has no clustered key') }
                'schemabound' { $why.Add(('an object is bound to its schema ({0}) -- the table cannot be renamed under it' -f $v)) }
            }
        }
        $cols = & $rows (Get-SIPartitionMoveColumnsSql) @{ Obj = $n.Live }
        $idx = ConvertTo-SIPartitionMoveIndexes -Rows (& $rows (Get-SIPartitionMoveIndexesSql) @{ Obj = $n.Live })
        $key = Get-SIPartitionMoveKey -Indexes $idx -Columns $cols
        if (-not $key.Ok) { $why.Add($key.Why) }
        foreach ($ix in @($idx | Where-Object { $_.Type -eq 2 -and $_.Unique -and -not (@($_.KeyCols.ToArray()) | Where-Object { $_.Col -eq 'CollectionId' }) })) { $why.Add(('a unique index without CollectionId ({0}) cannot be aligned' -f $ix.Name)) }
        if (@($cols | Where-Object { [int](Get-SIPartitionMoveValue $_ 'IsComputed') -eq 1 }).Count) { $why.Add('it has a computed column') }
        if ($why.Count) {
            $res.State = 'blocked'; $res.Text = 'cannot be moved without changing what readers see: ' + ($why -join '; ') + ' -- the clean-up keeps removing rows one by one'
            Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'blocked' -Note $res.Text; return $res
        }
        $colNames = @($cols | ForEach-Object { [string](Get-SIPartitionMoveValue $_ 'Name') })
        $identity = @($cols | Where-Object { [int](Get-SIPartitionMoveValue $_ 'IsIdentity') -eq 1 }).Count -gt 0
        $cons = & $rows (Get-SIPartitionMoveConstraintsSql) @{ Obj = $n.Live }
        $fks = & $rows (Get-SIPartitionMoveForeignKeysSql) @{ Obj = $n.Live }
        if (@($fks | Where-Object { [int](Get-SIPartitionMoveValue $_ 'Cols') -ne 1 }).Count) {
            $res.State = 'blocked'; $res.Text = 'a foreign key of more than one column -- not moved'; Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'blocked' -Note $res.Text; return $res
        }

        # ---- 2. THE COPY (made once; a column the table gained since the copy was made = the copy starts over) ----
        $copyThere = [int](Get-SIPartitionMoveValue $st 'CopyExists') -eq 1
        if ($copyThere) {
            $ccols = & $rows (Get-SIPartitionMoveColumnsSql) @{ Obj = ('sidata.' + $n.Copy) }
            $cnames = @($ccols | ForEach-Object { [string](Get-SIPartitionMoveValue $_ 'Name') })
            # DATA QUALITY: a column added to the table after the copy was made (WITH VALUES: its old rows carry a value the copy
            # never saw) -- or one the copy has that the table lost -- restarts the copy; never a plain NULL column added to it
            if (@($colNames | Where-Object { $cnames -notcontains $_ }).Count -or @($cnames | Where-Object { $colNames -notcontains $_ }).Count) {
                $null = Invoke-SIPartitionMoveCleanup -Invoke $Invoke -Table $Table -State 'stopped' -Why 'the table gained or lost a column since its copy was made -- the copy starts over'
                $copyThere = $false
                $res.Columnstore = ''
            } else {
                $cidx = @(ConvertTo-SIPartitionMoveIndexes -Rows (& $rows (Get-SIPartitionMoveIndexesSql) @{ Obj = ('sidata.' + $n.Copy) }) | ForEach-Object { $_.Name })
                foreach ($ix in @($idx | Where-Object { $_.Type -eq 2 -and $cidx -notcontains $_.Name })) { $null = & $Invoke (Get-SIPartitionMoveIndexSql -Index $ix -Copy $n.Copy) @{} 'nonquery' }
            }
        }
        $cnt = Read-SIPartitionMoveCounts -Invoke $Invoke -Names $n -DeadlineUtc $DeadlineUtc -StopNow $stopNow
        if (-not $copyThere) {
            if ($cnt.Incomplete) { return (& $waitNext ('the kept collections were not all counted before the copy is made ({0})' -f (& $stopNow))) }
            # ROOM FOR THE COPY before it is made: refused with one line when it would not fit with the margin
            $kept = [long](@($cnt.Rows | ForEach-Object { [long](Get-SIPartitionMoveValue $_ 'Old') } | Measure-Object -Sum).Sum)
            $room = Test-SIPartitionMoveRoom -Space ((& $rows (Get-SIPartitionMoveSpaceSql) @{ Live = $n.Live }) | Select-Object -First 1) -KeptRows $kept
            if (-not $room.Fits) {
                $res.State = 'waiting-space'
                $res.Text = ('the copy is not made: {0} -- it waits until old collections free the room (they are removed a little at a time meanwhile); the next update tries again' -f $room.Text)
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'waiting-space' -Note $res.Text
                return $res
            }
            $null = & $Invoke (Get-SIPartitionMoveCreateSql -Names $n -Key $key -Indexes $idx -Constraints $cons) @{} 'nonquery'
            $cnt = Read-SIPartitionMoveCounts -Invoke $Invoke -Names $n -DeadlineUtc $DeadlineUtc -StopNow $stopNow
        }
        # the documents out of the row, as on the table (SELECT ... INTO does not carry the option)
        $null = & $Invoke (Get-SIPartitionMoveLobSql -Names $n) @{} 'nonquery'
        # the bytes cap of one range: about SIPartitionBatchBytes of the table's average row
        $sp = (& $rows (Get-SIPartitionMoveSpaceSql) @{ Live = $n.Live }) | Select-Object -First 1
        $avg = if ([double](Get-SIPartitionMoveValue $sp 'TableRows') -gt 0) { [double](Get-SIPartitionMoveValue $sp 'TableBytes') / [double](Get-SIPartitionMoveValue $sp 'TableRows') } else { 0.0 }
        $maxRows = if ($avg -gt 0) { [long][Math]::Max(100, [Math]::Floor($script:SIPartitionBatchBytes / $avg)) } else { 0L }

        # ---- 3. COPY, collection by collection, in key ranges ----
        $plan = Get-SIPartitionMovePlan -Rows $cnt.Rows -Incomplete:$cnt.Incomplete
        $res.ScopeRows = $plan.ScopeRows
        # what runs changed since the last window (copied again now) -- counted for the convergence rule below
        $resetsAtStart = @($plan.Reset).Count
        $copySql = Get-SIPartitionMoveCopySql -Names $n -Key $key -Columns $colNames -Identity $identity
        $size = [long][Math]::Max(100L, $BatchSize); if ($maxRows -gt 0) { $size = [Math]::Min($size, [Math]::Max(100L, $maxRows)) }
        $times = New-Object System.Collections.Generic.List[long]; $moved = 0L; $stopped = $false
        $copyWatch = [Diagnostics.Stopwatch]::StartNew()
        foreach ($c in @($plan.Copy)) {
            $sw0 = & $stopNow; if ($sw0) { $res.StopWhy = $sw0; $stopped = $true; break }
            if (@($plan.Reset) -contains $c) {
                # bounded: the deadline and the stop seam between the batches
                while ([long](& $Invoke (Get-SIPartitionMoveResetSql -Names $n) @{ CollectionId = [string]$c } 'scalar') -gt 0) { $swr = & $stopNow; if ($swr) { $res.StopWhy = $swr; $stopped = $true; break } }
                if ($stopped) { break }
            }
            $null = & $Invoke (Get-SIPartitionMoveSplitSql) @{ CollectionId = [string]$c } 'scalar'
            $first = $true
            while ($true) {
                $sw1 = & $stopNow; if ($sw1) { $res.StopWhy = $sw1; $stopped = $true; break }
                $sw2 = [Diagnostics.Stopwatch]::StartNew()
                $got = [long](& $Invoke $copySql @{ CollectionId = [string]$c; Batch = [string]$size } 'scalar')
                $sw2.Stop(); $ms = [long]$sw2.ElapsedMilliseconds
                $moved += $got
                # SELF-HEAL (review item 2): nothing more to copy after the copy's own last key, though it holds fewer rows than
                # the table -- the copy cannot go on from where it stands: the collection is copied again from the start
                if ($first -and $got -eq 0 -and @($plan.Reset) -notcontains $c) {
                    $null = & $Invoke (Get-SIPartitionMoveTouchSql -Names $n) @{ CollectionId = [string]$c } 'nonquery'
                }
                $first = $false
                if ($got -lt $size) { break }
                $pace = Get-SIPartitionMovePause -Times $times.ToArray() -LastMs $ms
                $times.Add($ms); if ($times.Count -gt 20) { $times.RemoveAt(0) }
                $size = Get-SIPartitionMoveNextSize -Current $size -ElapsedMs $ms -TargetMs $TargetMs -MaxRows $maxRows
                if ($pace.Shrink) { $size = [long][Math]::Max(100L, [Math]::Floor($size / 2)) }
                if ($pace.PauseMs -gt 0) { & $Sleep $pace.PauseMs }
            }
            if ($stopped) { break }
        }
        $copyWatch.Stop()
        $res.RowsThisRun = $moved
        $res.RowsPerSecond = if ($copyWatch.Elapsed.TotalSeconds -ge 1 -and $moved -gt 0) { [Math]::Round([double]$moved / $copyWatch.Elapsed.TotalSeconds, 1) } else { 0.0 }

        # ---- 3b. VERIFY every collection copied by count: rows AND checksum, range by range (data quality) ----
        $cnt = Read-SIPartitionMoveCounts -Invoke $Invoke -Names $n -DeadlineUtc $DeadlineUtc -StopNow $stopNow
        $plan = Get-SIPartitionMovePlan -Rows $cnt.Rows -Incomplete:$cnt.Incomplete
        $differ = 0
        foreach ($c in @($plan.Verify)) {
            if (& $stopNow) { break }
            $cmp = Invoke-SIPartitionMoveCompare -Invoke $Invoke -A $n.Table -B $n.Copy -Key $key -Columns $cols -CollectionId ([string]$c) -DeadlineUtc $DeadlineUtc -StopNow $stopNow
            if ($cmp.Outcome -eq 'same') {
                $oldRow = @($cnt.Rows | Where-Object { [int](Get-SIPartitionMoveValue $_ 'CollectionId') -eq $c }) | Select-Object -First 1
                $oldN = if ($oldRow) { [long](Get-SIPartitionMoveValue $oldRow 'Old') } else { [long]$cmp.Rows }
                $null = & $Invoke (Get-SIPartitionMoveVerifiedSaveSql) @{ T = $Table; CollectionId = [string]$c; Rows = [string]$oldN } 'nonquery'
            } elseif ($cmp.Outcome -eq 'different') {
                $differ++
                $null = & $Invoke (Get-SIPartitionMoveTouchSql -Names $n) @{ CollectionId = [string]$c } 'nonquery'
            } else { break }
        }
        $cnt = Read-SIPartitionMoveCounts -Invoke $Invoke -Names $n -DeadlineUtc $DeadlineUtc -StopNow $stopNow
        $plan = Get-SIPartitionMovePlan -Rows $cnt.Rows -Incomplete:$cnt.Incomplete
        $res.ScopeRows = $plan.ScopeRows; $res.CopiedRows = $plan.CopiedRows
        if (-not $plan.Ready) {
            $res.State = 'copying'
            # CONVERGENCE (review item 5): a window in which runs changed copied rows again (copied again at its start, or found
            # different when verified) counts; after SIPartitionGiveUpWindows of them in a row the move gives up and leaves no
            # copy, no trigger behind (said why). Also when this window was cut short.
            $churn = ($resetsAtStart + $differ + @($plan.Reset).Count) -gt 0
            $giveUp = {
                param([string]$Note)
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'copying' -Note $Note -Attempt
                $att = 0; try { $att = [int](& $Invoke "SELECT ISNULL((SELECT TOP (1) CASE WHEN COL_LENGTH('sidata.PartitionMove', 'Attempts') IS NULL THEN 0 ELSE Attempts END FROM sidata.PartitionMove WHERE TableName = @T), 0)" @{ T = $Table } 'scalar') } catch { $att = 0 }
                if ($att -ge $script:SIPartitionGiveUpWindows) {
                    $gw = [string]::Format($inv, 'gave up after {0} windows in a row in which runs changed rows it had copied -- the copy and its trigger were removed (the room is free again); old collections are removed a little at a time; support decides when to try again', $att)
                    $null = Invoke-SIPartitionMoveCleanup -Invoke $Invoke -Table $Table -State 'gave-up' -Why $gw
                    $res.State = 'gave-up'; $res.Text = ('WARNING: ' + $gw)
                }
            }
            # counts cut short by the stop / the deadline: say why, and keep the recorded totals (never "0 of 0")
            if ($cnt.Incomplete -and -not $res.StopWhy) { $res.StopWhy = [string](& $stopNow); if (-not $res.StopWhy) { $res.StopWhy = 'the counts were cut short' } }
            if ($cnt.Incomplete) {
                $res.Text = ('copying onto the collection partitions: {0:N0} rows this window -- the next window goes on (stopped: {1}); the install works on the old table meanwhile' -f $moved, $res.StopWhy)
                if ($churn) { & $giveUp $res.Text } else { Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'copying' -Note $res.Text -ClearAttempts }
                return $res
            }
            $left = [Math]::Max(0L, [long]$plan.ScopeRows - [long]$plan.CopiedRows)
            $rate = if ($res.RowsPerSecond -gt 0) { [string]::Format($inv, '; {0:N0} rows a second this window, about {1:N0} min of copying left', $res.RowsPerSecond, [Math]::Ceiling(([double]$left / $res.RowsPerSecond) / 60.0)) } else { '' }
            $res.Text = [string]::Format($inv, 'copying onto the collection partitions: {0:N0} of {1:N0} rows ({2:N0} this window{5}; {3} collection(s) still to copy, {7} to verify{4}) -- the next window goes on{6}; the install works on the old table meanwhile',
                $plan.CopiedRows, $plan.ScopeRows, $moved, @($plan.Copy).Count, $(if (@($plan.Reset).Count -or $differ) { [string]::Format($inv, ', {0} of them changed by a run (or not the same values) after they were copied', @($plan.Reset).Count + $differ) } else { '' }), $rate,
                $(if ($res.StopWhy) { ' (stopped: ' + $res.StopWhy + ')' } else { '' }), @($plan.Verify).Count)
            if ($churn) {
                & $giveUp $res.Text
                if ($res.State -ne 'gave-up') { Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'copying' -Note $res.Text -ScopeRows $plan.ScopeRows -CopiedRows $plan.CopiedRows }
            } else {
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'copying' -Note $res.Text -ScopeRows $plan.ScopeRows -CopiedRows $plan.CopiedRows -ClearAttempts
            }
            return $res
        }

        # ---- 4. THE SWAP ----
        $sw2w = & $stopNow
        if ($sw2w) { $res.State = 'copying'; $res.StopWhy = $sw2w; $res.Text = ('every kept collection is copied and verified; the swap waits for the next window ({0})' -f $sw2w); Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'ready' -Note $res.Text -ScopeRows $plan.ScopeRows -CopiedRows $plan.CopiedRows; return $res }
        # a paused index build on the old table blocks its rename: stopped (the index is built again on the new table by the
        # index build job); a running one waits for a later window
        $builds = & $rows "SET NOCOUNT ON; DECLARE @b TABLE (I nvarchar(300) NOT NULL, S nvarchar(60) NOT NULL); IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL INSERT @b (I, S) EXEC (N'SELECT name, state_desc FROM sys.index_resumable_operations WHERE object_id = OBJECT_ID(N''$($n.Live)'')'); SELECT I, S FROM @b;" @{}
        if (@($builds | Where-Object { [string](Get-SIPartitionMoveValue $_ 'S') -eq 'RUNNING' }).Count) {
            $res.State = 'copying'; $res.Text = 'every kept collection is copied, but an index is being built on the table -- the swap waits for a later window'
            Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'ready' -Note $res.Text; return $res
        }
        foreach ($b in @($builds | Where-Object { [string](Get-SIPartitionMoveValue $_ 'S') -eq 'PAUSED' })) { $null = & $Invoke ('ALTER INDEX [{0}] ON {1} ABORT;' -f ([string](Get-SIPartitionMoveValue $b 'I')).Replace(']', ']]'), $n.Live) @{} 'nonquery' }
        # the foreign keys on the copy, checked against every row (the copy's own rows of a collection removed meanwhile go
        # first) -- bounded: the deadline and the stop seam between the batches
        # every name from the catalog is bracket-quoted (']' -> ']]'), and quoted again inside a string literal ("'" -> "''")
        $qn = { param($s) '[' + ([string]$s).Replace(']', ']]') + ']' }
        foreach ($fk in @($fks)) {
            $fn = & $qn ([string](Get-SIPartitionMoveValue $fk 'Name') + '_Partitioned')
            $col = & $qn (Get-SIPartitionMoveValue $fk 'Col'); $rs = & $qn (Get-SIPartitionMoveValue $fk 'RefSchema'); $rt = & $qn (Get-SIPartitionMoveValue $fk 'RefTable'); $rc = & $qn (Get-SIPartitionMoveValue $fk 'RefCol')
            $cpq = & $qn $n.Copy
            while ([long](& $Invoke ("SET NOCOUNT ON; DELETE TOP (50000) k FROM sidata.{0} AS k WHERE NOT EXISTS (SELECT 1 FROM {1}.{2} AS r WHERE r.{3} = k.{4}); SELECT @@ROWCOUNT;" -f $cpq, $rs, $rt, $rc, $col) @{} 'scalar') -gt 0) {
                $swf = & $stopNow; if ($swf) { return (& $waitNext ('the swap waits: {0}' -f $swf) 'ready') }
            }
            $swf2 = & $stopNow; if ($swf2) { return (& $waitNext ('the swap waits: {0}' -f $swf2) 'ready') }
            $null = & $Invoke ("IF OBJECT_ID(N'sidata.{0}', N'F') IS NULL ALTER TABLE sidata.{1} WITH CHECK ADD CONSTRAINT {2} FOREIGN KEY ({3}) REFERENCES {4}.{5} ({6});" -f $fn.Replace("'", "''"), $cpq, $fn, $col, $rs, $rt, $rc) @{} 'nonquery'
        }        $swr = & $rows (Get-SIPartitionMoveSwapSql -Names $n -Key $key -Identity $identity -ForeignKeys $fks -Constraints $cons -ScopeRows $plan.ScopeRows) @{} | Select-Object -First 1
        $sw3 = Get-SIPartitionMoveValue $swr 'Outcome'
        if ([string]$sw3 -ne 'swapped') {
            $res.State = 'copying'
            $res.Text = 'every kept collection was copied and verified, but at the swap a run had changed a collection since it was compared -- nothing was swapped; the next window copies what changed and tries again'
            Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'copying' -Note $res.Text -Attempt; return $res
        }
        if ([int](Get-SIPartitionMoveValue $swr 'Columnstore') -eq 1) {
            $res.Columnstore = ('its columnstore index {0} was dropped for the move at the swap (it is built again aligned on the collection partitions after it; results are the same without it)' -f (Get-SIPartitionMoveColumnstoreName -Table $Table))
        }
        foreach ($v in (& $rows "SELECT DISTINCT QUOTENAME(OBJECT_SCHEMA_NAME(d.referencing_id)) + N'.' + QUOTENAME(OBJECT_NAME(d.referencing_id)) AS V FROM sys.sql_expression_dependencies AS d JOIN sys.views AS w ON w.object_id = d.referencing_id WHERE d.referenced_schema_name = N'sidata' AND d.referenced_entity_name = @T;" @{ T = $Table })) {
            try { $null = & $Invoke 'EXEC sp_refreshview @V;' @{ V = [string](Get-SIPartitionMoveValue $v 'V') } 'nonquery' } catch { }
        }
        $res.State = 'swapped'
        $res.Text = [string]::Format($inv, 'moved onto the collection partitions: {0:N0} rows of {1} kept collection(s), the same per collection in rows and checksums; the old table is kept as {2} until a later window checks it', $plan.ScopeRows, @($plan.Done).Count, $n.Old)
        # the check in the SAME window when its time allows -- nothing can have written the new table yet (the window holds the
        # install's lock), so a difference found now is real; what is not checked now goes on in the next window
        if (-not (& $stopNow)) {
            $chk = Invoke-SIPartitionMoveCheck -Invoke $Invoke -Names $n -DeadlineUtc $DeadlineUtc -StopNow $stopNow
            if ($chk.Outcome -eq 'same') {
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'checked' -Checked -Note 'every complete, kept collection has the same rows and values as in the old table -- the old table is dropped in a later window'
                $res.State = 'checked'; $res.Text += '; the check passed at once (rows and checksums) -- the old table is dropped in a later window'
            } elseif ($chk.Outcome -eq 'different') {
                $why = [string]::Format($inv, 'the check after the swap found {0} -- the old table {1} is kept until support looks at it', $chk.Detail, $n.Old)
                Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'check-differs' -Note $why
                $res.State = 'check-differs'; $res.Text = ('WARNING: ' + $why)
            }
        }
        return $res
    } catch {
        $res.State = 'failed'
        $res.Text = 'the move stopped (' + $_.Exception.Message + ') -- nothing current is affected; the install works on the old table and the next window goes on'
        Set-SIPartitionMoveNote -Invoke $Invoke -Table $Table -State 'copying' -Note $res.Text
        return $res
    }
}

function Invoke-SIPartitionMoveCheck {
    <#
        AFTER the swap (a later window): every complete, kept collection compared between the old table and the new one, rows
        AND checksums, range by range (Invoke-SIPartitionMoveCompare), bounded by -DeadlineUtc / -StopNow; what was checked is
        kept (sidata.PartitionMoveVerified '<table>#check'), so the next window goes on. Returns @{ Outcome (same | different |
        stopped); Detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Names, [datetime]$DeadlineUtc = [datetime]::MaxValue, [scriptblock]$StopNow)
    $rows = { param($sql, $p) ConvertTo-SIPartitionMoveRows (& $Invoke $sql $p 'reader') }
    $tag = $Names.Table + '#check'
    $cols = & $rows (Get-SIPartitionMoveColumnsSql) @{ Obj = $Names.Live }
    $key = Get-SIPartitionMoveKey -Indexes (ConvertTo-SIPartitionMoveIndexes -Rows (& $rows (Get-SIPartitionMoveIndexesSql) @{ Obj = $Names.Live })) -Columns $cols
    if (-not $key.Ok) { return [pscustomobject]@{ Outcome = 'different'; Detail = ('the new table''s key is not as expected ({0})' -f $key.Why) } }
    $oldNames = [pscustomobject]@{ Table = $Names.Old; Copy = $Names.Table; Live = ('sidata.' + $Names.Old) }
    $ids = @(ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionMoveIdsSql -Names $oldNames) @{} 'reader') | Where-Object { [int](Get-SIPartitionMoveValue $_ 'Kept') -eq 1 -and [int](Get-SIPartitionMoveValue $_ 'Complete') -eq 1 })
    $done = @(& $rows "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.PartitionMoveVerified', N'U') IS NULL SELECT CAST(NULL AS int) AS CollectionId WHERE 1 = 0; ELSE SELECT CollectionId FROM sidata.PartitionMoveVerified WHERE TableName = @T;" @{ T = $tag } | ForEach-Object { [int](Get-SIPartitionMoveValue $_ 'CollectionId') })
    foreach ($i in $ids) {
        $c = [int](Get-SIPartitionMoveValue $i 'CollectionId')
        if ($done -contains $c) { continue }
        $cmp = Invoke-SIPartitionMoveCompare -Invoke $Invoke -A $Names.Old -B $Names.Table -Key $key -Columns $cols -CollectionId ([string]$c) -DeadlineUtc $DeadlineUtc -StopNow $StopNow
        if ($cmp.Outcome -eq 'stopped') { return [pscustomobject]@{ Outcome = 'stopped'; Detail = $cmp.Detail } }
        if ($cmp.Outcome -eq 'different') { return [pscustomobject]@{ Outcome = 'different'; Detail = ('collection {0}: {1}' -f $c, $cmp.Detail) } }
        $null = & $Invoke (Get-SIPartitionMoveVerifiedSaveSql) @{ T = $tag; CollectionId = [string]$c; Rows = [string]$cmp.Rows } 'nonquery'
    }
    [pscustomobject]@{ Outcome = 'same'; Detail = '' }
}

function Invoke-SIProPartitionMove {
    <#
        THE MOVE of an existing install (the steps in the header), every table smallest first, inside -BudgetMinutes from
        -StartedUtc (or -DeadlineUtc when given: the idle window's end). -ShouldStop: asked before every range and before a swap
        ('' = go on; a reason = stop there -- an update wants to go, the install's lock was taken). NEVER throws. Returns
        @{ Status (done | progress | blocked | failed | skipped); Tables (each Invoke-SIProPartitionMoveTable result); Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$BudgetMinutes = 10, [scriptblock]$Log = { param($m) },
          [datetime]$StartedUtc = [datetime]::UtcNow, [scriptblock]$Sleep = { param($ms) Start-Sleep -Milliseconds ([int]$ms) }, [long]$BatchSize = 5000,
          $DeadlineUtc = $null, [scriptblock]$ShouldStop)
    $out = [pscustomobject]@{ Status = 'skipped'; Tables = @(); Lines = @() }
    try {
        $deadline = if ($null -ne $DeadlineUtc) { ([datetime]$DeadlineUtc).ToUniversalTime() } else { $StartedUtc.ToUniversalTime().AddMinutes([Math]::Max(1, $BudgetMinutes)) }
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($t in $script:SIPartitionMoveTables) {
            $r = Invoke-SIProPartitionMoveTable -Invoke $Invoke -Table $t -DeadlineUtc $deadline -StartedUtc $StartedUtc -Sleep $Sleep -BatchSize $BatchSize -ShouldStop $ShouldStop
            $list.Add($r)
            if ($r.Columnstore) { & $Log ('partitions: {0}: {1}' -f $t, $r.Columnstore) }
            $line = 'partitions: {0}: {1}' -f $t, $r.Text
            & $Log $line
            # one table at a time: the next waits until this one is on the partitions (a failed or blocked one is said and
            # the next is still tried -- they do not depend on each other)
            if ($r.State -in 'copying', 'waiting-space', 'gave-up', 'check-differs') { break }
        }
        $out.Tables = $list.ToArray()
        $out.Lines = @($list | ForEach-Object { if ($_.Columnstore) { 'partitions: {0}: {1}' -f $_.Table, $_.Columnstore }; 'partitions: {0}: {1}' -f $_.Table, $_.Text })
        $states = @($list | ForEach-Object { $_.State })
        $out.Status = if (@($states | Where-Object { $_ -eq 'failed' }).Count) { 'failed' }
                      elseif (@($states | Where-Object { $_ -in $script:SIPartitionTerminalStates }).Count) { 'blocked' }
                      elseif ($list.Count -eq $script:SIPartitionMoveTables.Count -and -not @($states | Where-Object { $_ -notin 'partitioned', 'done' }).Count) { 'done' }
                      else { 'progress' }
    } catch { $out.Status = 'failed'; $out.Lines = @('partitions: the move stopped ({0}) -- the install works on the old tables; the next idle window goes on' -f $_.Exception.Message); & $Log $out.Lines[0] }
    $out
}

# =====================================================================================================================
#  #1317 RETENTION BY PARTITION -- what the index build job does in an idle window while SI_Data_RetireByPartition is on
#  (owner 2026-11-23, SCALE-2 #1314 (6f): "partition retention could drop the wrong collection -> the same guard as today's
#  marking (the published run and kept collections can never be targeted), row counts read back, product code only, the
#  rights stay with the database setup job"). Three parts, each inside the window and stopped the moment an update wants to go:
#    (a) BOUNDARIES AHEAD -- empty boundaries for the next collection ids (sidata.Collection's identity), so every new
#        collection lands ALONE in its own partition without anyone having to cut one while a run writes. A boundary is cut
#        only where no row has an id at or above it (no row ever moves); the highest one is recorded (sidata.PartitionMove
#        '(boundaries)') so the pipeline runner knows when more are needed.
#    (b) A RETIRED COLLECTION LEAVES BY ITS PARTITION -- sidata.Finding, sidata.Recommendation and sidata.IssueContext
#        emptied in ONE transaction (TRUNCATE ... WITH (PARTITIONS)), only when THE GUARD of today's marking holds, read
#        again inside the transaction under the publisher's app lock: marked retired; never the published run's collection
#        (sidata.PublishedRun, sidata.vPublishedCollection); never the newest complete collection or the one before it (two
#        complete, unmarked collections newer than it); never one of the kept collections (the newest -Keep complete ones --
#        the data sync's own decision, sidata.ViewState 'keep-collections', wins); never one a kept collection's report carries
#        rows from (sidata.CollectionReportCarry). ROW COUNTS READ BEFORE AND AFTER: the collection's rows = its partition's
#        rows (else it is not alone: 'not-alone'), every other partition's rows the same after, the partition's rows 0 after --
#        any difference rolls the transaction back and leaves every row ('mismatch'). The emptied range is then folded into
#        the one before it (only an empty partition is ever folded; never one an id still to come falls in).
#    (c) the MOVE of an existing install's tables (above), while they are not on the partitions yet.
#  Whatever a partition cannot take (a collection sharing one, a refused guard, a lock held longer than a few seconds, a
#  table not moved yet) is left to today's paced removal by the pipeline runner's wake-ups -- the fallback, unchanged. The
#  collection row itself, its staged rows and its summary rows are removed by that same paced removal, which then finds the
#  three large tables already empty.
# =====================================================================================================================

$script:SIPartitionAhead = 16        # empty boundaries kept ahead of the next collection id (a run makes one or two ids)

function Test-SIPartitionSwitchOn {
    <# PURE. SI_Data_RetireByPartition: ON by default (owner 2026-11-23: a feature that adds value ships on) -- not set or
       empty = on; off only for $false / 0 / 'false' / 'off' / 'no'. #>
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return $Value }
    -not (("$Value".Trim().ToLowerInvariant()) -in @('0', 'false', 'off', 'no', '$false'))
}

function Get-SIPartitionAheadSql {
    <#
        (a) The empty boundaries ahead: from the identity's current value up to @Ahead ids above it, each one not there yet cut
        ONLY when no row of any table on the scheme has an id at or above it (so no row moves -- a metadata change). Waits at
        most a few seconds for a lock ('busy'). Records the highest boundary (sidata.PartitionMove '(boundaries)'). Answers ONE
        row: Outcome (ready | busy | failed | none); Cut; Highest; Detail.
    #>
    @'
SET NOCOUNT ON;
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
IF @pf IS NULL OR @ps IS NULL OR OBJECT_ID(N'sidata.Collection', N'U') IS NULL
BEGIN SELECT CAST(N'none' AS nvarchar(32)) AS Outcome, 0 AS Cut, CAST(NULL AS int) AS Highest, CAST(N'the partition function or scheme is not there' AS nvarchar(400)) AS Detail; RETURN; END
DECLARE @ah int = TRY_CONVERT(int, @Ahead); IF @ah IS NULL OR @ah < 1 SET @ah = 16;
DECLARE @from bigint = ISNULL(CONVERT(bigint, IDENT_CURRENT(N'sidata.Collection')), 1);
IF @from < 1 SET @from = 1;
-- the highest id any table on the scheme holds, by ITS OWN partitioning column (#1332: the finding states are on the scheme
-- by HomeCollectionId) -- one seek at the end of each clustered key; every name quoted
DECLARE @top bigint = 0, @t nvarchar(300), @pc nvarchar(300), @q nvarchar(max), @m bigint;
DECLARE tl CURSOR LOCAL FAST_FORWARD FOR
    SELECT QUOTENAME(OBJECT_SCHEMA_NAME(x.object_id)) + N'.' + QUOTENAME(OBJECT_NAME(x.object_id)), QUOTENAME(c.name)
    FROM sys.indexes AS x
    JOIN sys.index_columns AS ic ON ic.object_id = x.object_id AND ic.index_id = x.index_id AND ic.partition_ordinal = 1
    JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
    WHERE x.data_space_id = @ps AND x.index_id IN (0, 1);
OPEN tl; FETCH NEXT FROM tl INTO @t, @pc;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @q = N'SELECT @m = MAX(' + @pc + N') FROM ' + @t + N';'; SET @m = NULL;
    EXEC sp_executesql @q, N'@m bigint OUTPUT', @m = @m OUTPUT;
    IF @m > @top SET @top = @m;
    FETCH NEXT FROM tl INTO @t, @pc;
END
CLOSE tl; DEALLOCATE tl;
DECLARE @v bigint = @from, @cut int = 0, @out nvarchar(32) = N'ready', @detail nvarchar(400) = NULL, @vi int;
SET LOCK_TIMEOUT 5000;
WHILE @v <= @from + @ah AND @v < 2147483647
BEGIN
    IF @v > @top AND NOT EXISTS (SELECT 1 FROM sys.partition_range_values AS r WHERE r.function_id = @pf AND CONVERT(bigint, r.value) = @v)
    BEGIN
        BEGIN TRY
            SET @vi = CONVERT(int, @v);
            ALTER PARTITION SCHEME PS_SICollection NEXT USED [PRIMARY];
            ALTER PARTITION FUNCTION PF_SICollection() SPLIT RANGE (@vi);
            SET @cut += 1;
        END TRY
        BEGIN CATCH
            SET @out = CASE WHEN ERROR_NUMBER() = 1222 THEN N'busy' ELSE N'failed' END;
            SET @detail = LEFT(ERROR_MESSAGE(), 400);
            BREAK;
        END CATCH
    END
    SET @v += 1;
END
DECLARE @hi int = (SELECT MAX(CONVERT(int, r.value)) FROM sys.partition_range_values AS r WHERE r.function_id = @pf);
IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName = N'(boundaries)')
        UPDATE sidata.PartitionMove SET State = @out, ScopeRows = @hi, Note = @detail, UpdatedAt = SYSUTCDATETIME() WHERE TableName = N'(boundaries)';
    ELSE INSERT sidata.PartitionMove (TableName, State, ScopeRows, Note) VALUES (N'(boundaries)', @out, @hi, @detail);
END
SELECT @out AS Outcome, @cut AS Cut, @hi AS Highest, @detail AS Detail;
'@
}

function Get-SIPartitionCandidatesSql {
    <# (b) The marked Detailed collections that still hold rows in one of the three tables, oldest first (one seek each). #>
    @'
SET NOCOUNT ON;
IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL BEGIN SELECT CAST(NULL AS int) AS CollectionId WHERE 1 = 0; RETURN; END
SELECT m.CollectionId FROM sidata.Collection AS m
WHERE m.Kind = N'Detailed' AND m.RetiredAt IS NOT NULL
  AND (EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = m.CollectionId)
    OR EXISTS (SELECT 1 FROM sidata.Recommendation AS r WHERE r.CollectionId = m.CollectionId)
    OR EXISTS (SELECT 1 FROM sidata.IssueContext AS i WHERE i.CollectionId = m.CollectionId))
ORDER BY m.CollectionTime, m.CollectionId;
'@
}

function Get-SIPartitionRemoveSql {
    <#
        (b) ONE retired Detailed collection (@CollectionId) leaves by its partition -- THE GUARD and the counts in the header
        above, all inside ONE transaction. @Keep: the kept complete collections (the data sync's stored decision wins when it
        is there; never below 2). @MarkedBefore: '' or ISO text (only a mark made before it). Answers ONE row: Outcome
        (truncated | not-partitioned | not-alone | refused | mismatch | busy | failed); Findings; Recommendations; IssueRows
        (the rows emptied, counted before); Merged; Detail (the plain reason).
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c int = TRY_CONVERT(int, @CollectionId), @kp int = TRY_CONVERT(int, @Keep);
DECLARE @mb datetime2(0) = TRY_CONVERT(datetime2(0), NULLIF(@MarkedBefore, N''), 126);
DECLARE @outcome nvarchar(32) = NULL, @detail nvarchar(400) = NULL, @f bigint = 0, @r bigint = 0, @i bigint = 0, @merged int = 0;
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @tf int = OBJECT_ID(N'sidata.Finding', N'U'), @tr int = OBJECT_ID(N'sidata.Recommendation', N'U'), @ti int = OBJECT_ID(N'sidata.IssueContext', N'U');
-- the data sync's own keep decision ('<count>|<mark>'), else the caller's; never below 2
IF OBJECT_ID(N'sidata.ViewState', N'U') IS NOT NULL
BEGIN
    DECLARE @ks nvarchar(400) = (SELECT TOP (1) Value FROM sidata.ViewState WHERE Name = N'keep-collections');
    DECLARE @kn int = TRY_CONVERT(int, LEFT(@ks, CHARINDEX(N'|', @ks + N'|') - 1));
    IF @kn >= 2 SET @kp = @kn;
END
IF @kp IS NULL OR @kp < 2 SET @kp = 2;
IF @c IS NULL BEGIN SET @outcome = N'refused'; SET @detail = N'no collection named'; END
-- every index of the three tables on the scheme (aligned) -- else the rows are removed in paced ranges, as before
IF @outcome IS NULL AND (@pf IS NULL OR @ps IS NULL OR @tf IS NULL OR @tr IS NULL OR @ti IS NULL
       OR EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id IN (@tf, @tr, @ti) AND x.is_hypothetical = 0 AND x.data_space_id <> @ps))
BEGIN SET @outcome = N'not-partitioned'; SET @detail = N'the tables are not on the collection partitions yet'; END
DECLARE @p int, @lo int, @hi int, @pt nvarchar(12), @lk int, @ct datetime2(3), @cs nvarchar(16);
DECLARE @fc bigint, @rc bigint, @ic bigint, @fp bigint, @rp bigint, @ip bigint, @fo bigint, @ro bigint, @io bigint;
DECLARE @fa bigint, @ra bigint, @ia bigint, @fo2 bigint, @ro2 bigint, @io2 bigint;
IF @outcome IS NULL
BEGIN
    SET @p = $PARTITION.PF_SICollection(@c);
    SET @lo = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p - 1);
    SET @hi = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p);
    SET @pt = CONVERT(nvarchar(12), @p);
    SET LOCK_TIMEOUT 5000;
    BEGIN TRY
        BEGIN TRANSACTION;
        -- ONE TRUSTED RUN: under the publisher's own app lock (shared), as the paced removal and the marking
        IF OBJECT_ID(N'sidata.PublishedRun', N'U') IS NOT NULL
        BEGIN
            EXEC @lk = sp_getapplock @Resource = N'sidata.PublishedRun', @LockMode = N'Shared', @LockOwner = N'Transaction', @LockTimeout = 10000;
            IF @lk < 0 BEGIN SET @outcome = N'busy'; SET @detail = N'the publisher holds its lock'; END
        END
        SELECT @ct = m.CollectionTime, @cs = m.Status FROM sidata.Collection AS m WITH (UPDLOCK, HOLDLOCK)
        WHERE m.CollectionId = @c AND m.Kind = N'Detailed' AND m.RetiredAt IS NOT NULL
          AND (@mb IS NULL OR (m.RetiredAt < @mb AND m.RetiredWhy IN (N'superseded', N'abandoned', N'stopped run', N'untrusted')));
        -- (1) marked retired (the same mark the paced removal requires)
        IF @outcome IS NULL AND @ct IS NULL BEGIN SET @outcome = N'refused'; SET @detail = N'the collection is not marked for removal'; END
        -- (2) never the published run's collection
        IF @outcome IS NULL AND OBJECT_ID(N'sidata.PublishedRun', N'U') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.PublishedRun AS x WHERE x.DetailedCollectionId = @c)
        BEGIN SET @outcome = N'refused'; SET @detail = N'the published run''s collection -- never removed'; END
        IF @outcome IS NULL AND OBJECT_ID(N'sidata.vPublishedCollection', N'V') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.vPublishedCollection AS v WHERE v.CollectionId = @c)
        BEGIN SET @outcome = N'refused'; SET @detail = N'the collection the views show -- never removed'; END
        -- (3) never the newest complete collection or the one before it
        IF @outcome IS NULL AND (SELECT COUNT(*) FROM sidata.Collection AS y WHERE y.Kind = N'Detailed' AND y.Status = N'Complete' AND y.RetiredAt IS NULL AND y.CollectionTime > @ct) < 2
        BEGIN SET @outcome = N'refused'; SET @detail = N'fewer than two complete collections are newer -- the newest and the one before it are never removed'; END
        -- (4) never one of the kept collections (the newest @kp complete ones)
        IF @outcome IS NULL AND @cs = N'Complete' AND (SELECT COUNT(*) FROM sidata.Collection AS y WHERE y.Kind = N'Detailed' AND y.Status = N'Complete' AND y.CollectionTime > @ct) < @kp
        BEGIN SET @outcome = N'refused'; SET @detail = CONCAT(N'one of the newest ', @kp, N' complete collections -- kept'); END
        -- (5) never one a kept collection's report carries rows from
        IF @outcome IS NULL AND OBJECT_ID(N'sidata.CollectionReportCarry', N'U') IS NOT NULL
           AND EXISTS (SELECT 1 FROM sidata.CollectionReportCarry AS k JOIN sidata.Collection AS y ON y.CollectionId = k.CollectionId WHERE k.FromCollectionId = @c AND y.RetiredAt IS NULL)
        BEGIN SET @outcome = N'refused'; SET @detail = N'a kept collection''s report shows its rows'; END
        IF @outcome IS NULL
        BEGIN
            -- COUNTS BEFORE: the collection's rows and its partition's rows (seeks on the clustered key), and every other
            -- partition's rows (the catalog)
            SELECT @fc = COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @c;
            SELECT @rc = COUNT_BIG(*) FROM sidata.Recommendation WHERE CollectionId = @c;
            SELECT @ic = COUNT_BIG(*) FROM sidata.IssueContext WHERE CollectionId = @c;
            SELECT @fp = COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId >= ISNULL(@lo, -2147483648) AND (@hi IS NULL OR CollectionId < @hi);
            SELECT @rp = COUNT_BIG(*) FROM sidata.Recommendation WHERE CollectionId >= ISNULL(@lo, -2147483648) AND (@hi IS NULL OR CollectionId < @hi);
            SELECT @ip = COUNT_BIG(*) FROM sidata.IssueContext WHERE CollectionId >= ISNULL(@lo, -2147483648) AND (@hi IS NULL OR CollectionId < @hi);
            SELECT @fo = ISNULL(SUM(CASE WHEN s.object_id = @tf THEN s.rows END), 0), @ro = ISNULL(SUM(CASE WHEN s.object_id = @tr THEN s.rows END), 0), @io = ISNULL(SUM(CASE WHEN s.object_id = @ti THEN s.rows END), 0)
            FROM sys.partitions AS s WHERE s.object_id IN (@tf, @tr, @ti) AND s.index_id IN (0, 1) AND s.partition_number <> @p;
            IF @fp <> @fc OR @rp <> @rc OR @ip <> @ic
            BEGIN SET @outcome = N'not-alone'; SET @detail = N'its partition also holds another collection''s rows'; END
        END
        IF @outcome IS NULL
        BEGIN
            EXEC (N'TRUNCATE TABLE sidata.IssueContext WITH (PARTITIONS (' + @pt + N'))');
            EXEC (N'TRUNCATE TABLE sidata.Recommendation WITH (PARTITIONS (' + @pt + N'))');
            EXEC (N'TRUNCATE TABLE sidata.Finding WITH (PARTITIONS (' + @pt + N'))');
            -- COUNTS AFTER: the partition holds no row, every other partition holds what it held
            SELECT @fa = COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId >= ISNULL(@lo, -2147483648) AND (@hi IS NULL OR CollectionId < @hi);
            SELECT @ra = COUNT_BIG(*) FROM sidata.Recommendation WHERE CollectionId >= ISNULL(@lo, -2147483648) AND (@hi IS NULL OR CollectionId < @hi);
            SELECT @ia = COUNT_BIG(*) FROM sidata.IssueContext WHERE CollectionId >= ISNULL(@lo, -2147483648) AND (@hi IS NULL OR CollectionId < @hi);
            SELECT @fo2 = ISNULL(SUM(CASE WHEN s.object_id = @tf THEN s.rows END), 0), @ro2 = ISNULL(SUM(CASE WHEN s.object_id = @tr THEN s.rows END), 0), @io2 = ISNULL(SUM(CASE WHEN s.object_id = @ti THEN s.rows END), 0)
            FROM sys.partitions AS s WHERE s.object_id IN (@tf, @tr, @ti) AND s.index_id IN (0, 1) AND s.partition_number <> @p;
            IF @fa <> 0 OR @ra <> 0 OR @ia <> 0 OR @fo2 <> @fo OR @ro2 <> @ro OR @io2 <> @io
            BEGIN
                SET @outcome = N'mismatch';
                SET @detail = LEFT(CONCAT(N'left ', @fa, N'/', @ra, N'/', @ia, N'; other partitions ', @fo, N'->', @fo2, N', ', @ro, N'->', @ro2, N', ', @io, N'->', @io2), 400);
            END
            ELSE BEGIN SET @outcome = N'truncated'; SET @f = @fc; SET @r = @rc; SET @i = @ic; END
        END
        IF @outcome = N'truncated' COMMIT TRANSACTION; ELSE IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        SET @outcome = CASE WHEN ERROR_NUMBER() = 1222 THEN N'busy' ELSE N'failed' END;
        SET @detail = LEFT(ERROR_MESSAGE(), 400);
        SET @f = 0; SET @r = 0; SET @i = 0;
    END CATCH
    -- the emptied range folded into the one before it (best effort): only when the partition that starts at its boundary
    -- holds no row in any table on the scheme (so no row moves) and every id it covers is given out already (no collection
    -- still to come can land there)
    IF @outcome = N'truncated' AND @lo IS NOT NULL AND @hi IS NOT NULL AND CONVERT(bigint, @hi) - 1 <= CONVERT(bigint, IDENT_CURRENT(N'sidata.Collection'))
       AND NOT EXISTS (SELECT 1 FROM sys.partitions AS s JOIN sys.indexes AS x ON x.object_id = s.object_id AND x.index_id = s.index_id
                       WHERE x.data_space_id = @ps AND s.index_id IN (0, 1) AND s.partition_number = @p AND s.rows > 0)
    BEGIN
        BEGIN TRY
            ALTER PARTITION FUNCTION PF_SICollection() MERGE RANGE (@lo);
            SET @merged = 1;
        END TRY
        BEGIN CATCH
            IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        END CATCH
    END
END
SELECT ISNULL(@outcome, N'failed') AS Outcome, @f AS Findings, @r AS Recommendations, @i AS IssueRows, @merged AS Merged, @detail AS Detail;
'@
}

function Invoke-SIPartitionRemove {
    <#
        (b) ONE collection by its partition (Get-SIPartitionRemoveSql). NEVER throws: an error is Outcome 'failed' with its
        Detail -- the paced removal takes the collection then. Rows are counted as removed ONLY when the partition WAS emptied.
        Returns @{ CollectionId; Outcome; Findings; Recommendations; IssueRows; Merged; Detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CollectionId, [int]$Keep = 2, $MarkedBeforeUtc = $null)
    $out = [pscustomobject]@{ CollectionId = $CollectionId; Outcome = 'failed'; Findings = 0L; Recommendations = 0L; IssueRows = 0L; Merged = 0; Detail = '' }
    try {
        $mb = if ($null -ne $MarkedBeforeUtc) { ([datetime]$MarkedBeforeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } else { '' }
        $row = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionRemoveSql) @{ CollectionId = $CollectionId; Keep = [string][Math]::Max(2, $Keep); MarkedBefore = $mb } 'reader') | Select-Object -First 1
        if ($null -eq $row) { $out.Detail = 'no answer'; return $out }
        $o = [string](Get-SIPartitionMoveValue $row 'Outcome'); $out.Outcome = $(if ($o) { $o } else { 'failed' })
        foreach ($k in 'Findings', 'Recommendations', 'IssueRows') { $v = Get-SIPartitionMoveValue $row $k; if ($null -ne $v) { $out.$k = [long]$v } }
        $m = Get-SIPartitionMoveValue $row 'Merged'; if ($null -ne $m) { $out.Merged = [int]$m }
        $out.Detail = [string](Get-SIPartitionMoveValue $row 'Detail')
        if ($out.Outcome -ne 'truncated') { $out.Findings = 0L; $out.Recommendations = 0L; $out.IssueRows = 0L }
    } catch { $out.Outcome = 'failed'; $out.Detail = $_.Exception.Message; $out.Findings = 0L; $out.Recommendations = 0L; $out.IssueRows = 0L }
    $out
}

function Format-SIPartitionOutcome {
    <# PURE. The plain words of a step that did not empty a partition (or cut a boundary). #>
    param([string]$Outcome, [string]$Detail = '')
    $d = if ("$Detail".Trim()) { ' (' + "$Detail".Trim() + ')' } else { '' }
    switch ($Outcome) {
        'not-partitioned' { 'the tables are not on the collection partitions yet' }
        'not-alone'       { 'its partition also holds another collection (it was made before its own partition was)' }
        'refused'         { 'the guard refused it' + $d }
        'mismatch'        { 'the row counts after did not match -- rolled back, every row kept' + $d }
        'busy'            { 'a lock was held longer than a few seconds' }
        default           { 'it could not be done' + $(if ($d) { $d } else { ' (no reason given)' }) }
    }
}

function Get-SIPartitionLeftSaveSql {
    <# The collections a partition could not take (',id,id,' or ''; the pipeline runner does not start the job again for them
       alone) and how many left by their partition this window: sidata.PartitionMove '(removal)'. #>
    "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NOT NULL BEGIN IF EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName = N'(removal)') UPDATE sidata.PartitionMove SET State = N'ready', Note = NULLIF(LEFT(@S, 1000), N''), CopiedRows = TRY_CONVERT(bigint, @N), UpdatedAt = SYSUTCDATETIME() WHERE TableName = N'(removal)'; ELSE INSERT sidata.PartitionMove (TableName, State, Note, CopiedRows) VALUES (N'(removal)', N'ready', NULLIF(LEFT(@S, 1000), N''), TRY_CONVERT(bigint, @N)); END"
}

# =====================================================================================================================
#  #1332 THE FINDING HISTORY LEAVES BY PARTITION (owner 2026-11-23 "Yes, all": 30 days of history; a collection no longer
#  stored in full is FROZEN as it was published; prio 1 never fewer rows; a failed move = rolled back + warning, never partial).
#  The history's two large tables are on PS_SICollection (sql\si-data-schema.sql): sidata.FindingStateMember by CollectionId,
#  sidata.FindingState by HomeCollectionId (the collection a state was made in, or -- once that one left -- the newest
#  collection that still holds it). So:
#    * #1317's CUT and FOLD see the history's rows: a boundary is cut and a range folded only where no row of ANY table on the
#      scheme is (Get-SIPartitionAheadSql reads each table's own partitioning column) -- a range the history still holds is
#      never folded, and no history row ever moves by a fold. The history's own step folds a range once it emptied it.
#    * THE MEMBERS of a partition leave in ONE transaction (TRUNCATE ... WITH (PARTITIONS)) only when EVERY collection in it
#      is out of the history -- THE GUARD, read again inside the transaction under the publisher's app lock: never the
#      published run's collection, never a kept collection (not marked retired), never one a kept collection's report carries
#      rows from, never one inside SI_Data_HistoryDays (default 30; 0 = the history follows the kept collections) whose
#      history was VERIFIED -- the frozen collections; an unverified history is never kept frozen. Counts before and after
#      (the partition's rows 0, every other partition the same) or the transaction rolls back and every row stays.
#    * THE STATES of a partition leave only when no collection of its range is in the history any more (no member, no history
#      row, none kept, none published, every id given out) and NO STATE of it is held by a member: the states a newer
#      collection still holds are first MOVED FORWARD to the newest collection holding them (chunked UPDATEs of the home
#      column, each in its own transaction with a checksum of every column of every moved row before and after -- a
#      difference rolls the chunk back), then the partition -- now holding only states no collection holds -- is emptied in
#      ONE transaction with the same counts. Never a row delete. A state held by a kept, published or frozen collection is
#      never removed (it is held by a member).
#  Each step stops at the window's end or when an update wants to go; the next window goes on (the state is the database).
# =====================================================================================================================

$script:SIHistoryDaysDefault = 30

function Read-SIHistoryPartitionDays {
    <# The history window in days: $global:SI_Data_HistoryDays, else the solution setting (cfg.Setting), else 30 (the owner's
       decision). 0 = the history follows the kept collections. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Value = (Get-Variable -Name 'SI_Data_HistoryDays' -Scope Global -ValueOnly -ErrorAction SilentlyContinue))
    $v = $Value
    if ($null -eq $v -or "$v".Trim() -eq '') {
        try { $v = & $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT TOP (1) ValueJson FROM cfg.Setting WHERE Name = N'SI_Data_HistoryDays' AND Scope = N'solution';" @{} 'scalar' } catch { $v = $null }
    }
    if ($null -ne $v -and -not ($v -is [System.DBNull]) -and "$v" -match '^\s*"?(\d{1,5})"?\s*$') { return [int]$Matches[1] }
    $script:SIHistoryDaysDefault
}

function Get-SIHistoryPartitionPlanSql {
    <# The partitions of the two history tables that hold rows, with their range (Lo NULL = the first; a partition without
       an upper boundary -- the newest ids -- is never listed): T (member | state), P, Lo, Hi, Rows. Tables not on the
       scheme with EVERY index: not listed (Ready = 0 on the first row's flags). Catalog views only. #>
    @'
SET NOCOUNT ON;
SET LOCK_TIMEOUT 5000;
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @tm int = OBJECT_ID(N'sidata.FindingStateMember', N'U'), @ts int = OBJECT_ID(N'sidata.FindingState', N'U');
DECLARE @rm bit = CASE WHEN @ps IS NOT NULL AND @tm IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id = @tm AND x.is_hypothetical = 0 AND x.data_space_id <> @ps) THEN 1 ELSE 0 END;
DECLARE @rs bit = CASE WHEN @ps IS NOT NULL AND @ts IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id = @ts AND x.is_hypothetical = 0 AND x.data_space_id <> @ps) THEN 1 ELSE 0 END;
SELECT x.T, x.P, CONVERT(int, lo.value) AS Lo, CONVERT(int, hi.value) AS Hi, x.[Rows]
FROM (SELECT N'member' AS T, s.partition_number AS P, s.rows AS [Rows] FROM sys.partitions AS s WHERE @rm = 1 AND s.object_id = @tm AND s.index_id = 1 AND s.rows > 0
      UNION ALL
      SELECT N'state', s.partition_number, s.rows FROM sys.partitions AS s WHERE @rs = 1 AND s.object_id = @ts AND s.index_id = 1 AND s.rows > 0) AS x
LEFT JOIN sys.partition_range_values AS lo ON lo.function_id = @pf AND lo.boundary_id = x.P - 1
JOIN sys.partition_range_values AS hi ON hi.function_id = @pf AND hi.boundary_id = x.P
ORDER BY CASE x.T WHEN N'member' THEN 0 ELSE 1 END, x.P;
'@
}

function Get-SIHistoryMemberRemoveSql {
    <#
        THE MEMBERS of ONE partition (the one @At falls in) leave the history -- THE GUARD (header above) and the counts, in ONE
        transaction; then the emptied range folded into the one before it when no table on the scheme holds a row there and
        every id it covers is given out. @Days: the history window. Answers ONE row: Outcome (truncated | refused |
        not-partitioned | mismatch | busy | failed); Collections (the ids, ','-joined); Members (the rows emptied, counted
        before); Merged; Detail.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @atv int = TRY_CONVERT(int, @At), @dw int = TRY_CONVERT(int, @Days);
IF @dw IS NULL OR @dw < 0 SET @dw = 30;
DECLARE @outcome nvarchar(32) = NULL, @detail nvarchar(400) = NULL, @ids nvarchar(400) = NULL, @n bigint = 0, @merged int = 0;
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @tm int = OBJECT_ID(N'sidata.FindingStateMember', N'U');
IF @atv IS NULL BEGIN SET @outcome = N'refused'; SET @detail = N'no partition named'; END
IF @outcome IS NULL AND (@pf IS NULL OR @ps IS NULL OR @tm IS NULL OR EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id = @tm AND x.is_hypothetical = 0 AND x.data_space_id <> @ps))
BEGIN SET @outcome = N'not-partitioned'; SET @detail = N'the history''s members are not on the collection partitions'; END
DECLARE @p int, @lo int, @hi int, @pt nvarchar(12), @lk int, @mc bigint, @mo bigint, @ma bigint, @mo2 bigint, @why nvarchar(400);
DECLARE @c TABLE (C int NOT NULL PRIMARY KEY);
IF @outcome IS NULL
BEGIN
    SET @p = $PARTITION.PF_SICollection(@atv);
    SET @lo = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p - 1);
    SET @hi = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p);
    SET @pt = CONVERT(nvarchar(12), @p);
    IF @hi IS NULL BEGIN SET @outcome = N'refused'; SET @detail = N'the partition of the newest ids -- never emptied'; END
END
IF @outcome IS NULL
BEGIN
    SET LOCK_TIMEOUT 5000;
    BEGIN TRY
        BEGIN TRANSACTION;
        IF OBJECT_ID(N'sidata.PublishedRun', N'U') IS NOT NULL
        BEGIN
            EXEC @lk = sp_getapplock @Resource = N'sidata.PublishedRun', @LockMode = N'Shared', @LockOwner = N'Transaction', @LockTimeout = 10000;
            IF @lk < 0 BEGIN SET @outcome = N'busy'; SET @detail = N'the publisher holds its lock'; END
        END
        -- the collections the partition holds members of (one seek each on the clustered key)
        DECLARE @nx int = (SELECT MIN(CollectionId) FROM sidata.FindingStateMember WITH (UPDLOCK, HOLDLOCK) WHERE CollectionId >= ISNULL(@lo, -2147483648) AND CollectionId < @hi);
        WHILE @nx IS NOT NULL
        BEGIN
            INSERT @c (C) VALUES (@nx);
            SET @nx = (SELECT MIN(CollectionId) FROM sidata.FindingStateMember WHERE CollectionId > @nx AND CollectionId < @hi);
        END
        SET @ids = LEFT((SELECT STRING_AGG(CONVERT(nvarchar(12), C), N',') WITHIN GROUP (ORDER BY C) FROM @c), 400);
        IF @outcome IS NULL AND NOT EXISTS (SELECT 1 FROM @c) BEGIN SET @outcome = N'refused'; SET @detail = N'the partition holds no member'; END
        -- THE GUARD, per collection (re-read here, the collection rows locked)
        IF @outcome IS NULL
        BEGIN
            SELECT TOP (1) @why = g.Why FROM (
                SELECT k.C, CASE
                    WHEN EXISTS (SELECT 1 FROM sidata.PublishedRun AS x WHERE x.DetailedCollectionId = k.C) THEN CONCAT(N'collection ', k.C, N' is the published run''s -- never removed')
                    WHEN OBJECT_ID(N'sidata.vPublishedCollection', N'V') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.vPublishedCollection AS v WHERE v.CollectionId = k.C) THEN CONCAT(N'collection ', k.C, N' is the one the views show -- never removed')
                    WHEN m.CollectionId IS NOT NULL AND m.RetiredAt IS NULL THEN CONCAT(N'collection ', k.C, N' is kept')
                    WHEN OBJECT_ID(N'sidata.CollectionReportCarry', N'U') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.CollectionReportCarry AS r JOIN sidata.Collection AS y ON y.CollectionId = r.CollectionId WHERE r.FromCollectionId = k.C AND y.RetiredAt IS NULL) THEN CONCAT(N'a kept collection''s report shows rows of collection ', k.C)
                    WHEN @dw > 0 AND m.CollectionId IS NOT NULL AND m.CollectionTime >= DATEADD(day, -@dw, SYSUTCDATETIME()) AND h.State = N'verified' THEN CONCAT(N'collection ', k.C, N' is inside the ', @dw, N' days of history (frozen as it was published)')
                    ELSE NULL END AS Why
                FROM @c AS k
                LEFT JOIN sidata.Collection AS m WITH (UPDLOCK, HOLDLOCK) ON m.CollectionId = k.C
                LEFT JOIN sidata.HistoryRun AS h ON h.CollectionId = k.C) AS g
            WHERE g.Why IS NOT NULL ORDER BY g.C;
            IF @why IS NOT NULL BEGIN SET @outcome = N'refused'; SET @detail = @why; END
        END
        IF @outcome IS NULL
        BEGIN
            SELECT @mc = COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId >= ISNULL(@lo, -2147483648) AND CollectionId < @hi;
            SELECT @mo = ISNULL(SUM(s.rows), 0) FROM sys.partitions AS s WHERE s.object_id = @tm AND s.index_id = 1 AND s.partition_number <> @p;
            EXEC (N'TRUNCATE TABLE sidata.FindingStateMember WITH (PARTITIONS (' + @pt + N'))');
            SELECT @ma = COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId >= ISNULL(@lo, -2147483648) AND CollectionId < @hi;
            SELECT @mo2 = ISNULL(SUM(s.rows), 0) FROM sys.partitions AS s WHERE s.object_id = @tm AND s.index_id = 1 AND s.partition_number <> @p;
            IF @ma <> 0 OR @mo2 <> @mo
            BEGIN SET @outcome = N'mismatch'; SET @detail = LEFT(CONCAT(N'left ', @ma, N'; other partitions ', @mo, N'->', @mo2), 400); END
            ELSE
            BEGIN
                -- the collections' own small history rows go with them (their change set, their compares, their record)
                DELETE d FROM sidata.FindingStateDelta AS d WHERE d.CollectionId IN (SELECT C FROM @c) OR d.PrevCollectionId IN (SELECT C FROM @c);
                DELETE x FROM sidata.HistoryCompare AS x WHERE x.CollectionId IN (SELECT C FROM @c);
                DELETE x FROM sidata.HistoryRun AS x WHERE x.CollectionId IN (SELECT C FROM @c);
                SET @outcome = N'truncated'; SET @n = @mc;
            END
        END
        IF @outcome = N'truncated' COMMIT TRANSACTION; ELSE IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        SET @outcome = CASE WHEN ERROR_NUMBER() = 1222 THEN N'busy' ELSE N'failed' END;
        SET @detail = LEFT(ERROR_MESSAGE(), 400); SET @n = 0;
    END CATCH
    IF @outcome = N'truncated' AND @lo IS NOT NULL AND CONVERT(bigint, @hi) - 1 <= CONVERT(bigint, IDENT_CURRENT(N'sidata.Collection'))
       AND NOT EXISTS (SELECT 1 FROM sys.partitions AS s JOIN sys.indexes AS x ON x.object_id = s.object_id AND x.index_id = s.index_id
                       WHERE x.data_space_id = @ps AND s.index_id IN (0, 1) AND s.partition_number = @p AND s.rows > 0)
    BEGIN
        BEGIN TRY ALTER PARTITION FUNCTION PF_SICollection() MERGE RANGE (@lo); SET @merged = 1; END TRY
        BEGIN CATCH IF XACT_STATE() <> 0 ROLLBACK TRANSACTION; END CATCH
    END
END
SELECT ISNULL(@outcome, N'failed') AS Outcome, @ids AS Collections, @n AS Members, @merged AS Merged, @detail AS Detail;
'@
}

function Get-SIHistoryStateGuardSql {
    <# PURE. The guard of a STATE partition ([@lo, @hi)): a reason why its states may not leave yet, else NULL (into @why). #>
    @'
SET @why = CASE
    WHEN @hi IS NULL THEN N'the partition of the newest ids -- never emptied'
    WHEN CONVERT(bigint, @hi) - 1 > CONVERT(bigint, IDENT_CURRENT(N'sidata.Collection')) THEN N'a collection still to come lands in it'
    WHEN EXISTS (SELECT 1 FROM sidata.FindingStateMember WITH (UPDLOCK, HOLDLOCK) WHERE CollectionId >= ISNULL(@lo, -2147483648) AND CollectionId < @hi) THEN N'a collection of its range is still in the history'
    WHEN EXISTS (SELECT 1 FROM sidata.HistoryRun AS h WHERE h.CollectionId >= ISNULL(@lo, -2147483648) AND h.CollectionId < @hi) THEN N'a collection of its range still has its history record'
    WHEN EXISTS (SELECT 1 FROM sidata.HistoryRun AS h WHERE h.State = N'writing') THEN N'a collection''s history is being written'
    WHEN EXISTS (SELECT 1 FROM sidata.Collection AS c WHERE c.CollectionId >= ISNULL(@lo, -2147483648) AND c.CollectionId < @hi AND c.RetiredAt IS NULL) THEN N'a kept collection is in its range'
    WHEN OBJECT_ID(N'sidata.PublishedRun', N'U') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.PublishedRun AS x WHERE x.DetailedCollectionId >= ISNULL(@lo, -2147483648) AND x.DetailedCollectionId < @hi) THEN N'the published run''s collection is in its range'
    ELSE NULL END;
'@
}

function Get-SIHistoryStateForwardSql {
    <#
        ONE CHUNK of the states of ONE partition (the one @At falls in) that a newer collection still holds, MOVED FORWARD to the
        newest collection holding each (their home column only -- the state, its id and every other column stay), in ONE
        transaction with a checksum of every column but the home of every moved row before and after (a difference, or a count
        that is not the same, rolls the chunk back). @Batch: the chunk's size. Answers ONE row: Outcome (moved | none |
        refused | not-partitioned | mismatch | busy | failed); Moved; Detail.
    #>
    $guard = Get-SIHistoryStateGuardSql
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @atv int = TRY_CONVERT(int, @At), @bn int = TRY_CONVERT(int, @Batch);
IF @bn IS NULL OR @bn < 1 SET @bn = 5000;
DECLARE @outcome nvarchar(32) = NULL, @detail nvarchar(400) = NULL, @moved bigint = 0, @why nvarchar(400);
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @ts int = OBJECT_ID(N'sidata.FindingState', N'U');
IF @atv IS NULL OR @pf IS NULL OR @ps IS NULL OR @ts IS NULL OR EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id = @ts AND x.is_hypothetical = 0 AND x.data_space_id <> @ps)
BEGIN SELECT N'not-partitioned' AS Outcome, CONVERT(bigint, 0) AS Moved, N'the finding states are not on the collection partitions' AS Detail; RETURN; END
DECLARE @p int = `$PARTITION.PF_SICollection(@atv);
DECLARE @lo int = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p - 1);
DECLARE @hi int = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p);
CREATE TABLE #r (StateId bigint NOT NULL PRIMARY KEY, H0 int NOT NULL, T int NOT NULL, Before varbinary(32) NULL, After varbinary(32) NULL);
SET LOCK_TIMEOUT 5000;
BEGIN TRY
    BEGIN TRANSACTION;
$guard
    IF @why IS NOT NULL BEGIN SET @outcome = N'refused'; SET @detail = @why; END
    IF @outcome IS NULL
    BEGIN
        INSERT #r (StateId, H0, T, Before)
        SELECT TOP (@bn) s.StateId, s.HomeCollectionId, t.T,
               HASHBYTES('SHA2_256', CAST(JSON_MODIFY((SELECT s.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES), '$.HomeCollectionId', NULL) AS varbinary(max)))
        FROM sidata.FindingState AS s WITH (UPDLOCK, HOLDLOCK)
        CROSS APPLY (SELECT MAX(m.CollectionId) AS T FROM sidata.FindingStateMember AS m WITH (UPDLOCK, HOLDLOCK) WHERE m.StateId = s.StateId) AS t
        WHERE s.HomeCollectionId >= ISNULL(@lo, -2147483648) AND s.HomeCollectionId < @hi AND t.T IS NOT NULL
        ORDER BY s.StateId;
        IF NOT EXISTS (SELECT 1 FROM #r) SET @outcome = N'none';
        ELSE IF EXISTS (SELECT 1 FROM #r WHERE T < @hi) BEGIN SET @outcome = N'mismatch'; SET @detail = N'a state would stay in the range'; END
        ELSE
        BEGIN
            UPDATE s SET HomeCollectionId = r.T FROM sidata.FindingState AS s JOIN #r AS r ON r.StateId = s.StateId AND s.HomeCollectionId = r.H0;
            SET @moved = @@ROWCOUNT;
            UPDATE r SET After = HASHBYTES('SHA2_256', CAST(JSON_MODIFY((SELECT s.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES), '$.HomeCollectionId', NULL) AS varbinary(max)))
            FROM #r AS r JOIN sidata.FindingState AS s ON s.StateId = r.StateId AND s.HomeCollectionId = r.T;
            IF @moved <> (SELECT COUNT_BIG(*) FROM #r) OR EXISTS (SELECT 1 FROM #r WHERE After IS NULL OR After <> Before)
               OR EXISTS (SELECT 1 FROM sidata.FindingState AS s JOIN #r AS r ON r.StateId = s.StateId AND s.HomeCollectionId = r.H0)
            BEGIN SET @outcome = N'mismatch'; SET @detail = LEFT(CONCAT(N'moved ', @moved, N' of ', (SELECT COUNT_BIG(*) FROM #r), N'; the checksum of a moved state differed'), 400); END
            ELSE SET @outcome = N'moved';
        END
    END
    IF @outcome IN (N'moved', N'none') COMMIT TRANSACTION; ELSE IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
    SET @outcome = CASE WHEN ERROR_NUMBER() = 1222 THEN N'busy' ELSE N'failed' END;
    SET @detail = LEFT(ERROR_MESSAGE(), 400);
END CATCH
SELECT @outcome AS Outcome, CASE WHEN @outcome = N'moved' THEN @moved ELSE CONVERT(bigint, 0) END AS Moved, @detail AS Detail;
"@
}

function Get-SIHistoryStateRemoveSql {
    <#
        THE STATES of ONE partition (the one @At falls in) leave -- only when the guard holds AND no state of it is held by any
        member (both read again under lock) -- in ONE transaction with the counts (the partition's rows 0 after, every other
        partition the same); then the fold, as for the members. Answers ONE row: Outcome (truncated | held | refused |
        not-partitioned | mismatch | busy | failed); States (counted before); Merged; Detail.
    #>
    $guard = Get-SIHistoryStateGuardSql
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @atv int = TRY_CONVERT(int, @At);
DECLARE @outcome nvarchar(32) = NULL, @detail nvarchar(400) = NULL, @n bigint = 0, @merged int = 0, @why nvarchar(400);
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @ts int = OBJECT_ID(N'sidata.FindingState', N'U');
IF @atv IS NULL OR @pf IS NULL OR @ps IS NULL OR @ts IS NULL OR EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id = @ts AND x.is_hypothetical = 0 AND x.data_space_id <> @ps)
BEGIN SELECT N'not-partitioned' AS Outcome, CONVERT(bigint, 0) AS States, 0 AS Merged, N'the finding states are not on the collection partitions' AS Detail; RETURN; END
DECLARE @p int = `$PARTITION.PF_SICollection(@atv);
DECLARE @lo int = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p - 1);
DECLARE @hi int = (SELECT CONVERT(int, v.value) FROM sys.partition_range_values AS v WHERE v.function_id = @pf AND v.boundary_id = @p);
DECLARE @pt nvarchar(12) = CONVERT(nvarchar(12), @p), @sc bigint, @so bigint, @sa bigint, @so2 bigint;
SET LOCK_TIMEOUT 5000;
BEGIN TRY
    BEGIN TRANSACTION;
$guard
    IF @why IS NOT NULL BEGIN SET @outcome = N'refused'; SET @detail = @why; END
    IF @outcome IS NULL AND EXISTS (SELECT 1 FROM sidata.FindingState AS s WHERE s.HomeCollectionId >= ISNULL(@lo, -2147483648) AND s.HomeCollectionId < @hi
                                    AND EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m WITH (UPDLOCK, HOLDLOCK) WHERE m.StateId = s.StateId))
    BEGIN SET @outcome = N'held'; SET @detail = N'a newer collection still holds a state of it (moved forward first)'; END
    IF @outcome IS NULL
    BEGIN
        SELECT @sc = COUNT_BIG(*) FROM sidata.FindingState WHERE HomeCollectionId >= ISNULL(@lo, -2147483648) AND HomeCollectionId < @hi;
        SELECT @so = ISNULL(SUM(s.rows), 0) FROM sys.partitions AS s WHERE s.object_id = @ts AND s.index_id = 1 AND s.partition_number <> @p;
        EXEC (N'TRUNCATE TABLE sidata.FindingState WITH (PARTITIONS (' + @pt + N'))');
        SELECT @sa = COUNT_BIG(*) FROM sidata.FindingState WHERE HomeCollectionId >= ISNULL(@lo, -2147483648) AND HomeCollectionId < @hi;
        SELECT @so2 = ISNULL(SUM(s.rows), 0) FROM sys.partitions AS s WHERE s.object_id = @ts AND s.index_id = 1 AND s.partition_number <> @p;
        IF @sa <> 0 OR @so2 <> @so
        BEGIN SET @outcome = N'mismatch'; SET @detail = LEFT(CONCAT(N'left ', @sa, N'; other partitions ', @so, N'->', @so2), 400); END
        ELSE BEGIN SET @outcome = N'truncated'; SET @n = @sc; END
    END
    IF @outcome = N'truncated' COMMIT TRANSACTION; ELSE IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
    SET @outcome = CASE WHEN ERROR_NUMBER() = 1222 THEN N'busy' ELSE N'failed' END;
    SET @detail = LEFT(ERROR_MESSAGE(), 400); SET @n = 0;
END CATCH
IF @outcome = N'truncated' AND @lo IS NOT NULL AND CONVERT(bigint, @hi) - 1 <= CONVERT(bigint, IDENT_CURRENT(N'sidata.Collection'))
   AND NOT EXISTS (SELECT 1 FROM sys.partitions AS s JOIN sys.indexes AS x ON x.object_id = s.object_id AND x.index_id = s.index_id
                   WHERE x.data_space_id = @ps AND s.index_id IN (0, 1) AND s.partition_number = @p AND s.rows > 0)
BEGIN
    BEGIN TRY ALTER PARTITION FUNCTION PF_SICollection() MERGE RANGE (@lo); SET @merged = 1; END TRY
    BEGIN CATCH IF XACT_STATE() <> 0 ROLLBACK TRANSACTION; END CATCH
END
SELECT ISNULL(@outcome, N'failed') AS Outcome, @n AS States, @merged AS Merged, @detail AS Detail;
"@
}

function Invoke-SIHistoryPartitionRetention {
    <#
        THE HISTORY'S PARTITION STEP (the index build job's idle window / the update's bounded step, after #1317's retired
        collections): every member partition whose collections are all out of the history is emptied; then every state
        partition whose range left the history: its held states moved forward in chunks, then the partition emptied. Each
        statement ONE transaction; stopped at -DeadlineUtc or by -ShouldStop ('' = go on); NEVER throws. -Days: the history
        window (Read-SIHistoryPartitionDays when < 0). Returns @{ Status (done | progress | nothing | not-partitioned | failed);
        Lines; Collections (the ids that left); Members; Moved; States; Problems (the rolled-back steps, with why) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$Days = -1, [datetime]$DeadlineUtc = ([datetime]::UtcNow.AddMinutes(10)),
          [scriptblock]$ShouldStop, [long]$BatchSize = 5000, [scriptblock]$Log = { param($m) })
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $out = [pscustomobject]@{ Status = 'nothing'; Lines = @(); Collections = @(); Members = 0L; Moved = 0L; States = 0L; Problems = @() }
    $lines = New-Object System.Collections.Generic.List[string]; $problems = New-Object System.Collections.Generic.List[object]; $gone = New-Object System.Collections.Generic.List[string]
    $say = { param([string]$m) $lines.Add($m); try { $null = & $Log $m } catch { } }
    $stop = { if ([datetime]::UtcNow -ge $DeadlineUtc) { return 'the window''s time is used' }; if (-not $ShouldStop) { return '' }; $w = ''; try { $w = [string](& $ShouldStop) } catch { $w = 'whether to stop could not be read' }; $w }
    $did = $false; $more = $false; $failed = $false
    try {
        if ($Days -lt 0) { $Days = Read-SIHistoryPartitionDays -Invoke $Invoke }
        $plan = @(ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIHistoryPartitionPlanSql) @{} 'reader'))
        if (-not $plan.Count) { $out.Lines = $lines.ToArray(); return $out }
        # (1) the members, partition by partition (oldest first)
        foreach ($r in @($plan | Where-Object { [string](Get-SIPartitionMoveValue $_ 'T') -eq 'member' })) {
            $w = & $stop; if ($w) { $more = $true; & $say ('history: stopped -- {0}; the next window goes on' -f $w); break }
            $at = [string]([long](Get-SIPartitionMoveValue $r 'Hi') - 1)
            $x = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIHistoryMemberRemoveSql) @{ At = $at; Days = [string]$Days } 'reader') | Select-Object -First 1
            $o = [string](Get-SIPartitionMoveValue $x 'Outcome')
            if ($o -eq 'truncated') {
                $did = $true; $ids = [string](Get-SIPartitionMoveValue $x 'Collections'); foreach ($i in @($ids.Split(',') | Where-Object { $_ })) { $gone.Add($i) }
                $mm = [long](Get-SIPartitionMoveValue $x 'Members'); $out.Members += $mm
                & $say ([string]::Format($inv, 'history: collection(s) {0} left the finding history by their partition -- {1:N0} member row(s) (counted before; none left after, every other partition the same){2}', $ids, $mm, $(if ([int](Get-SIPartitionMoveValue $x 'Merged')) { '; the empty range folded into the one before it' } else { '' })))
            } elseif ($o -in 'mismatch', 'failed', 'busy') {
                if ($o -ne 'busy') { $failed = $true }
                $problems.Add([pscustomobject]@{ Part = 'members'; At = $at; Outcome = $o; Detail = [string](Get-SIPartitionMoveValue $x 'Detail') })
                & $say ('history: WARNING the members of the partition at {0} were not removed -- {1} -- rolled back, every row kept; the next window tries again' -f $at, (Format-SIPartitionOutcome -Outcome $o -Detail ([string](Get-SIPartitionMoveValue $x 'Detail'))))
            }
        }
        # (2) the states, partition by partition: held ones moved forward, then the partition emptied
        if (-not $more) {
            $plan = @(ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIHistoryPartitionPlanSql) @{} 'reader'))
            foreach ($r in @($plan | Where-Object { [string](Get-SIPartitionMoveValue $_ 'T') -eq 'state' })) {
                $at = [string]([long](Get-SIPartitionMoveValue $r 'Hi') - 1)
                $movedHere = 0L; $refused = $false; $size = [Math]::Max(1L, $BatchSize)
                while ($true) {
                    $w = & $stop; if ($w) { $more = $true; break }
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    $y = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIHistoryStateForwardSql) @{ At = $at; Batch = [string]$size } 'reader') | Select-Object -First 1
                    $yo = [string](Get-SIPartitionMoveValue $y 'Outcome')
                    if ($yo -eq 'moved') { $k = [long](Get-SIPartitionMoveValue $y 'Moved'); $movedHere += $k; $out.Moved += $k; $did = $true; $size = Get-SIPartitionMoveNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -Minimum 1 -MaxRows 5000; continue }
                    if ($yo -eq 'none') { break }
                    $refused = $true
                    if ($yo -in 'mismatch', 'failed', 'busy') {
                        if ($yo -ne 'busy') { $failed = $true }
                        $problems.Add([pscustomobject]@{ Part = 'states moved forward'; At = $at; Outcome = $yo; Detail = [string](Get-SIPartitionMoveValue $y 'Detail') })
                        & $say ('history: WARNING the finding states of the partition at {0} were not moved forward -- {1} -- rolled back, every state kept; the next window tries again' -f $at, (Format-SIPartitionOutcome -Outcome $yo -Detail ([string](Get-SIPartitionMoveValue $y 'Detail'))))
                    }
                    break
                }
                if ($more) { if ($movedHere) { & $say ([string]::Format($inv, 'history: {0:N0} finding state(s) still held by a newer collection moved forward (checksum the same); stopped -- the next window goes on', $movedHere)) }; & $say 'history: stopped -- the window''s time is used or an update wants to go; the next window goes on'; break }
                if ($refused) { continue }
                $z = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIHistoryStateRemoveSql) @{ At = $at } 'reader') | Select-Object -First 1
                $zo = [string](Get-SIPartitionMoveValue $z 'Outcome')
                if ($zo -eq 'truncated') {
                    $did = $true; $k = [long](Get-SIPartitionMoveValue $z 'States'); $out.States += $k
                    & $say ([string]::Format($inv, 'history: {0:N0} finding state(s) no collection holds any more left by their partition, {1:N0} still held moved forward first (checksum the same; none left after, every other partition the same){2}', $k, $movedHere, $(if ([int](Get-SIPartitionMoveValue $z 'Merged')) { '; the empty range folded into the one before it' } else { '' })))
                } elseif ($zo -in 'mismatch', 'failed', 'busy') {
                    if ($zo -ne 'busy') { $failed = $true }
                    $problems.Add([pscustomobject]@{ Part = 'states'; At = $at; Outcome = $zo; Detail = [string](Get-SIPartitionMoveValue $z 'Detail') })
                    & $say ('history: WARNING the finding states of the partition at {0} were not removed -- {1} -- rolled back, every state kept; the next window tries again' -f $at, (Format-SIPartitionOutcome -Outcome $zo -Detail ([string](Get-SIPartitionMoveValue $z 'Detail'))))
                }
            }
        }
    } catch {
        $failed = $true
        & $say ('history: WARNING the history''s partition step stopped ({0}) -- every row is kept; the next window tries again' -f $_.Exception.Message)
    }
    $out.Lines = $lines.ToArray(); $out.Collections = $gone.ToArray(); $out.Problems = $problems.ToArray()
    $out.Status = if ($failed) { 'failed' } elseif ($more) { 'progress' } elseif ($did) { 'done' } else { 'nothing' }
    $out
}

function Invoke-SIHistoryMigrationStep {
    <#
        THE MIGRATION OUTSIDE A RUN (the index build job's idle window, the update's bounded step): the finding history's
        oldest-first loop (engine\pro-data\_shared\SI-DataHistory.ps1 Invoke-SIDataHistory -OutsideRun), loaded from the
        release's own copy when not loaded; SI_Data_HistoryModel off = nothing. Bounded by -DeadlineUtc and -ShouldStop, never
        while a pipeline run holds the install's lock (it checks itself), resumable at every range. NEVER throws. Returns
        Invoke-SIDataHistory's result, or @{ Status = 'skipped'; Lines } when the history code is not there.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$DeadlineUtc = ([datetime]::UtcNow.AddMinutes(10)), [scriptblock]$ShouldStop,
          [scriptblock]$Log = { param($m) }, [long]$FirstSize = 5000)
    try {
        if (-not (Get-Command -Name Invoke-SIDataHistory -ErrorAction SilentlyContinue)) {
            $hp = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'pro-data', '_shared', 'SI-DataHistory.ps1')
            if (-not (Test-Path -LiteralPath $hp)) { return [pscustomobject]@{ Status = 'skipped'; Written = 0; Lines = @() } }
            . $hp
        }
        $mode = Read-SIDataHistoryMode -Invoke $Invoke
        if ($mode.Mode -eq 'off') { return [pscustomobject]@{ Status = 'off'; Written = 0; Lines = @() } }
        # the caller's log captured under its own name: inside Invoke-SIDataHistory "$Log" is this block itself
        $siMigrationLog = $Log
        $logIt = { param($l, $m) try { $null = & $siMigrationLog $m } catch { } }.GetNewClosure()
        Invoke-SIDataHistory -Invoke $Invoke -Mode $mode.Mode -Log $logIt -OutsideRun -DeadlineUtc $DeadlineUtc -ShouldStop $ShouldStop -FirstSize $FirstSize
    } catch {
        $l = ('history     : the migration of the finding history stopped ({0}) -- the stored rows serve as before; the next window goes on' -f $_.Exception.Message)
        try { $null = & $Log $l } catch { }
        [pscustomobject]@{ Status = 'failed'; Written = 0; Lines = @($l) }
    }
}

function Invoke-SIPartitionHousekeeping {
    <#
        THE INDEX BUILD JOB'S PARTITION STEP (an idle window, SI_Data_RetireByPartition on): (a) the boundaries ahead, (c) the
        move while a table is not on the partitions, (b) every retired collection a partition can take, (d) the finding
        history's partitions (Invoke-SIHistoryPartitionRetention), (e) the history's migration (Invoke-SIHistoryMigrationStep;
        -Migrate $false = not) -- each inside -DeadlineUtc and stopped by -ShouldStop ('' = go on). -Keep: the kept complete collections (SI_Data_KeepCollections;
        the data sync's stored decision wins inside the statement). NEVER throws. Returns @{ Status (done | progress | nothing
        | failed); Lines (plain, one per part / collection); Removed (Invoke-SIPartitionRemove results that emptied a
        partition); Left (the ones left to the paced removal, with why); Move (Invoke-SIProPartitionMove's result or $null) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$DeadlineUtc = ([datetime]::UtcNow.AddMinutes(30)), [scriptblock]$ShouldStop,
          [scriptblock]$Log = { param($m) }, [int]$Keep = 2, [int]$Ahead = $script:SIPartitionAhead,
          [scriptblock]$Sleep = { param($ms) Start-Sleep -Milliseconds ([int]$ms) }, [long]$BatchSize = 5000,
          [string]$Holder = '', [int]$StatementSeconds = $script:SIPartitionStatementSeconds, [bool]$Migrate = $true)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $out = [pscustomobject]@{ Status = 'nothing'; Lines = @(); Removed = @(); Left = @(); Move = $null; History = $null; Migration = $null }
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param([string]$m) $lines.Add($m); try { $null = & $Log $m } catch { } }
    # BOUNDED (review item 3): every statement of this step carries a time limit
    $Invoke = New-SIPartitionBoundedInvoke -Invoke $Invoke -Seconds $StatementSeconds
    # ONE MOVER AT A TIME (review item 2): the lease is taken first and beaten with every stop question (at most every
    # 20 s); lost = stop at once. A second mover (the update's step while the job works, or the other way round) waits.
    if (-not "$Holder".Trim()) { $Holder = 'mover:' + [guid]::NewGuid().ToString('n').Substring(0, 12) }
    if (-not (Enter-SIPartitionLease -Invoke $Invoke -Holder $Holder)) {
        & $say 'partitions: another mover works on the collection partitions now (the update''s step or the index build job) -- this one does nothing and the next window goes on'
        $out.Status = 'progress'; $out.Lines = $lines.ToArray(); return $out
    }
    $siPtLease = [pscustomobject]@{ Last = [datetime]::UtcNow; Lost = $false }
    $outerStop = $ShouldStop; $leaseInvoke = $Invoke; $leaseHolder = $Holder
    $ShouldStop = {
        if ($siPtLease.Lost) { return 'another mover took the collection partitions over' }
        if (([datetime]::UtcNow - $siPtLease.Last).TotalSeconds -ge 20) {
            $siPtLease.Last = [datetime]::UtcNow
            if (-not (Enter-SIPartitionLease -Invoke $leaseInvoke -Holder $leaseHolder)) { $siPtLease.Lost = $true; return 'another mover took the collection partitions over' }
        }
        if ($outerStop) { return [string](& $outerStop) }
        ''
    }
    $stop = { if (-not $ShouldStop) { return '' }; $w = ''; try { $w = [string](& $ShouldStop) } catch { $w = ('whether the job must stop could not be read ({0})' -f $_.Exception.Message) }; $w }
    $did = $false; $failed = $false; $more = $false
    try {
        # (a) the boundaries ahead (cheap; first, so a collection made after this window lands alone)
        $a = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionAheadSql) @{ Ahead = [string]$Ahead } 'reader') | Select-Object -First 1
        $ao = [string](Get-SIPartitionMoveValue $a 'Outcome'); $ac = [int](Get-SIPartitionMoveValue $a 'Cut')
        if ($ao -eq 'none' -or -not $ao) {
            & $say 'partitions: the database does not carry the collection partitions yet (the schema step of the next update adds them) -- nothing done'
            $out.Lines = $lines.ToArray(); return $out
        }
        if ($ac -gt 0) { $did = $true }
        & $say ([string]::Format($inv, 'partitions: boundaries ahead of the next collections: {0} cut, the highest {1}{2}', $ac, (Get-SIPartitionMoveValue $a 'Highest'),
            $(if ($ao -ne 'ready') { ' -- ' + (Format-SIPartitionOutcome -Outcome $ao -Detail ([string](Get-SIPartitionMoveValue $a 'Detail'))) + '; the next idle window cuts the rest' } else { '' })))
        if ($ao -eq 'failed') { $failed = $true }

        # (c) the move, while a table is not on the partitions (or its move is not recorded done)
        $notDone = @(foreach ($t in $script:SIPartitionMoveTables) {
            $st = ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionMoveStateSql) @{ Live = ('sidata.' + $t); Copy = ($t + '_Partitioned'); Old = ($t + '_Unpartitioned'); Name = $t } 'reader') | Select-Object -First 1
            if (-not $st -or [int](Get-SIPartitionMoveValue $st 'Partitioned') -ne 1 -or [int](Get-SIPartitionMoveValue $st 'OldExists') -eq 1 -or [string](Get-SIPartitionMoveValue $st 'State') -ne 'done') { $t }
        })
        if ($notDone.Count) {
            $w0 = & $stop
            if ($w0) { $more = $true; & $say ('partitions: the move waits -- {0}' -f $w0) }
            else {
                $mv = Invoke-SIProPartitionMove -Invoke $Invoke -DeadlineUtc $DeadlineUtc -ShouldStop $ShouldStop -Log { param($m) } -Sleep $Sleep -BatchSize $BatchSize
                $out.Move = $mv
                foreach ($l in @($mv.Lines)) { & $say $l }
                if ($mv.Status -eq 'failed') { $failed = $true }
                if ($mv.Status -notin 'done', 'blocked') { $more = $true }
                $did = $true
            }
        }

        # (b) the retired collections, oldest first
        $cands = @(ConvertTo-SIPartitionMoveRows (& $Invoke (Get-SIPartitionCandidatesSql) @{} 'reader') | ForEach-Object { [string](Get-SIPartitionMoveValue $_ 'CollectionId') } | Where-Object { $_ })
        $removed = New-Object System.Collections.Generic.List[object]; $left = New-Object System.Collections.Generic.List[object]
        foreach ($c in $cands) {
            if ([datetime]::UtcNow -ge $DeadlineUtc) { $more = $true; & $say 'partitions: the window''s time is used -- the next idle window goes on'; break }
            $w = & $stop; if ($w) { $more = $true; & $say ('partitions: stopped -- {0}' -f $w); break }
            $r = Invoke-SIPartitionRemove -Invoke $Invoke -CollectionId $c -Keep $Keep
            if ($r.Outcome -eq 'truncated') {
                $removed.Add($r); $did = $true
                & $say ([string]::Format($inv, 'partitions: collection {0} left by its partition -- findings {1:N0}, recommendations {2:N0}, prepared issue rows {3:N0} (counted before; none left after, every other partition the same){4}', $c, $r.Findings, $r.Recommendations, $r.IssueRows, $(if ($r.Merged) { '; its empty range folded into the one before it' } else { '' })))
            } else {
                $left.Add($r)
                & $say ('partitions: collection {0} is left to the paced removal -- {1}' -f $c, (Format-SIPartitionOutcome -Outcome $r.Outcome -Detail $r.Detail))
                if ($r.Outcome -in 'failed', 'mismatch') { $failed = $true }
            }
        }
        $out.Removed = $removed.ToArray(); $out.Left = $left.ToArray()
        if (-not $cands.Count) { & $say 'partitions: no retired collection holds rows' }
        try {
            $skip = (@($left | ForEach-Object { $_.CollectionId }) -join ',')
            $null = & $Invoke (Get-SIPartitionLeftSaveSql) @{ S = $(if ($skip) { ',' + $skip + ',' } else { '' }); N = [string]$removed.Count } 'nonquery'
        } catch { }

        # (d) #1332 the finding history leaves by partition (30 days by default; frozen collections kept; never row deletes)
        $wd = & $stop
        if ($wd) { $more = $true; & $say ('history: the partition step waits -- {0}' -f $wd) }
        else {
            $hr = Invoke-SIHistoryPartitionRetention -Invoke $Invoke -DeadlineUtc $DeadlineUtc -ShouldStop $ShouldStop -BatchSize $BatchSize -Log { param($m) }
            $out.History = $hr
            foreach ($l in @($hr.Lines)) { & $say $l }
            if ($hr.Status -eq 'failed') { $failed = $true } elseif ($hr.Status -eq 'progress') { $more = $true } elseif ($hr.Status -eq 'done') { $did = $true }
        }
        # (e) #1332 the migration of an existing install's history (oldest first, resumable, never while a run holds the lock)
        $we = & $stop
        if ($we) { $more = $true }
        elseif ($Migrate) {
            $hm = Invoke-SIHistoryMigrationStep -Invoke $Invoke -DeadlineUtc $DeadlineUtc -ShouldStop $ShouldStop -Log { param($m) }
            $out.Migration = $hm
            foreach ($l in @($hm.Lines)) { & $say $l }
            if ([string]$hm.Status -in 'progress', 'waiting') { $more = $true } elseif ([string]$hm.Status -eq 'failed') { $failed = $true } elseif ([long]$hm.Written -gt 0) { $did = $true }
        }
    } catch {
        $failed = $true
        & $say ('partitions: the step stopped ({0}) -- nothing current is affected; the paced removal goes on as before and the next idle window tries again' -f $_.Exception.Message)
    }
    Exit-SIPartitionLease -Invoke $leaseInvoke -Holder $leaseHolder
    $out.Lines = $lines.ToArray()
    $out.Status = if ($failed) { 'failed' } elseif ($more) { 'progress' } elseif ($did) { 'done' } else { 'nothing' }
    $out
}
