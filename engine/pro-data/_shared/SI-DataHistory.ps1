#Requires -Version 5.1
<#
    THE FINDING HISTORY MODEL (REQUIREMENTS #1332, with #1334; design note SCALE-3 #1330 track B; docs\DESIGN.md
    "Finding history model"). One setting, SI_Data_HistoryModel = on (the default, owner 2026-11-23) | shadow | off.

    BESIDE sidata.Finding, never instead of it. After the last writer of a collection's rows (the data sync's remediation
    tasks), every kept complete Detailed collection is ALSO recorded as:
      sidata.FindingState        one row per DISTINCT finding state, content-addressed by a SHA-256 over every column of
                                 sidata.Finding but the row's identity and the per-run columns, and the document's BYTES with
                                 the run's own fields emptied in place (JSON_MODIFY keeps their position);
      sidata.FindingStateMember  one NARROW row per finding: its CollectionId + FindingId (the same values as in
                                 sidata.Finding -- links and work tables stay valid), its state, its key's hash, the per-run
                                 columns (ImportanceRank, the Risk Analysis ordering / tracing columns) and the emptied run
                                 fields' values;
      sidata.FindingStateDelta   the states whose count changed against the collection before it -- a KEYS-ONLY compare of
                                 two memberships, so a gone finding is found by the full key compare, never a change set.
    sidata.FindingAt(@CollectionId) gives a collection back with exactly sidata.Finding's columns.

    PRIO 1 (SCALE-2 #1314 (5)): every run compares, row for row, every column, byte for byte:
      collection  sidata.Finding of the collection vs sidata.FindingAt of it (per FindingId, a SHA-256 of every column);
      changes     What changed built from the change set (only the finding keys whose states moved are grouped) vs the
                  stored full build (sidata.FindingChange / FindingChangeCounted / ChangeCount 'findings').
    The old model (the full rows, the full builds) is built every run as the check. ANY difference = HistoryRun 'differs',
    a WARNING of the run (the run's report opens the fix request; finding ids and column names only, never a value), and
    the old model's rows are the ones in place before publish -- a difference never publishes unverified data. A collection
    that differs is never the base of a change set.
    Mode on: the history is written, verified and used for the change set; shadow: the same, said as troubleshooting; off:
    nothing of this file is read or written. A database without the tables of this build = off, said.
    Migration of an existing install: the kept collections without a current history are written OLDEST FIRST through the
    same path, in FindingId ranges (sized from the measured time of the one before, paced by the database's own load),
    resumable from HistoryRun.UptoFindingId after a stop, a lost connection or the time budget.
    STORAGE (#1332 storage lane, owner 2026-11-23 "Yes, all"): the members and the states live on the collection partitions
    (PS_SICollection: members by CollectionId, states by HomeCollectionId), so #1317's cut and fold see them (an empty
    partition only) and the history LEAVES BY PARTITION in the index build job's idle window / the update's bounded step
    (engine\pro-settings\SI-ProPartitionMove.ps1 Invoke-SIHistoryPartitionRetention) -- never row deletes there. History window
    = SI_Data_HistoryDays, DEFAULT 30 (owner decision 3; 0 = the history follows the kept collections). A collection no longer
    stored in full is FROZEN as it was published (decision 4): its history is never written again; only a VERIFIED history is
    kept frozen (an unverified one leaves with the collection's rows). A database whose history is not on the partitions (an
    unreleased build), or SI_Data_RetireByPartition off: the data sync's paced removal below, the same rules.
    THE MIGRATION (the oldest-first loop below) also runs OUTSIDE a run (-OutsideRun: the index build job's idle window, the
    update's 4 / 8-minute step): bounded by -DeadlineUtc and -ShouldStop at every range, resumable at every range (the write's
    UptoFindingId, the compare's VerifyUpto + its running checksum), never while a pipeline run holds the install's lock
    (cfg.PipelineLock 'install' with a run's FlowRunId and a beat in the last 15 minutes), with one progress line per
    collection; a collection counts as migrated only when its checksum on both sides is equal and every row compared the same.
    Never fails the data sync: a failure is said, recorded 'failed', and the old model serves as before.
    PowerShell 5.1 and 7 (no ?. / ??). No PowerShell module: every statement through the data sync's seam.
#>

if (-not (Get-Command -Name Get-SIDataChangedSetColumnPart -ErrorAction SilentlyContinue) -or -not $script:SIDataRowWriter) { . (Join-Path $PSScriptRoot 'SI-DataChangedSet.ps1') }
if (-not (Get-Command -Name Get-SIDataChangesSql -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataChanges.ps1') }
# #1332 the readers on the history: which collection is served from it, and the compare of what every reader returns
if (-not (Get-Command -Name Invoke-SIDataHistoryServe -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataHistoryServe.ps1') }

$script:SIDataHistory = [ordered]@{
    Setting      = 'SI_Data_HistoryModel'
    DaysSetting  = 'SI_Data_HistoryDays'
    # the state hash's own rule (another rule = another ColumnSet = written again). hm2 (2026-11-24, #1354): the release that
    # wrote a row is no longer part of its state -- under hm1 every finding was a new state in every collection after a release
    Rule         = 'hm2'
    # the columns of sidata.Finding the RUN moves (kept on the member, never in the state). The last three (#1354): the ROW'S
    # WRITER (SI-DataChangedSet.ps1 $script:SIDataRowWriter, the one list the finding hash leaves out too) -- which release wrote
    # the row and how the insert typed it (#1318); they describe the writer, not the finding, and move with every release
    Member       = @('ImportanceRank', 'RaSeq', 'RaSort', 'RaBucket', 'RaDedup', 'RaReport', 'RaInView', 'RaTraceHash', 'RaTraceKey', 'RaTraceSuffixed') + @($script:SIDataRowWriter.Columns)
    Identity     = @('FindingId', 'CollectionId')
    # #1332 readers: the PAGE KEYS -- state columns ALSO copied onto the member (sql\si-data-schema.sql @SIHistKeys, the same
    # list), so the history is read off the member's narrow indexes; sidata.FindingAt takes them from the member
    PageKeys     = @('AssetKey', 'Severity', 'Tier', 'RiskScore', 'RiskScoreWeighted', 'Cvss', 'ExemptionId', 'Cve', 'ConfigurationId', 'RiskAssetSide', 'RiskVulnSide',
                     # the columns the top pages SHOW (the findings list, the CI page): a shown row needs no state
                     'AssetName', 'RiskRating', 'Title', 'ReportName', 'SecurityDomain', 'CiLifecycle', 'HasExploit', 'Category', 'Subcategory', 'DepartmentName')
    # the document's fields the run moves: emptied in the state when their value is plain (a string of [0-9A-Za-z:.+ _-] or a
    # whole number), put back from the member; any other value stays in the state as it is (the state then changes per run)
    # (#1354: SolutionVersion = the release that wrote the row, the document's twin of RaRowSolutionVersion; the same list and
    # order as sql\si-data-schema.sql @SIHistRf)
    RunFields    = @('CollectionTime', 'TimeGenerated', 'si_collection_time', '_TimeReceived', '_ItemId', '_BilledSize') + @($script:SIDataRowWriter.DocFields)
    # the collection's marks of a later rewrite of its rows (a history older than any of them is written again)
    Stamps       = @('DerivedAt', 'ResolvedAt', 'ServicesDerivedAt', 'ExemptedDerivedAt', 'CorrelatedAt', 'ContextAt', 'CiLifecycleAt', 'RiskPartsAt', 'TypedAt', 'RaRowsAt', 'RemediationAt')
    FirstSize    = 5000
    TargetMs     = 5000
    BudgetSeconds = 3600          # the OLDER kept collections (the migration) are paced by it; the newest is never left
    DaysDefault  = 30             # owner decision 3 (2026-11-23): 30 days of history
    RunLockMinutes = 15           # a run's beat on the install's lock younger than this = the run holds it (SI-CollectionRunGate)
    StopEverySeconds = 20         # outside a run: the lock is read again at most this often
}

function Get-SIDataHistoryContract { $script:SIDataHistory }

# ---------------------------------------------------------------------------------------------------------------------
#  THE SWITCH
# ---------------------------------------------------------------------------------------------------------------------

function ConvertTo-SIDataHistoryMode {
    <# PURE. A stored value -> 'off' | 'shadow' | 'on'. ON BY DEFAULT (owner 2026-11-23): only the exact words off / shadow
       switch it; anything else -- empty, not set, a typo -- is on. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return 'on' }
    $v = ("$Value".Trim() -replace '^"|"$', '').Trim().ToLowerInvariant()
    if ($v -in 'off', 'false', '0') { return 'off' }
    if ($v -eq 'shadow') { return 'shadow' }
    'on'
}

function Get-SIDataHistorySchemaCheckSql {
    <# 1 when the database has every object this build uses (sql\si-data-schema.sql), else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.FindingState') IS NOT NULL AND OBJECT_ID('sidata.FindingStateMember') IS NOT NULL AND OBJECT_ID('sidata.HistoryRun') IS NOT NULL AND OBJECT_ID('sidata.HistoryCompare') IS NOT NULL AND OBJECT_ID('sidata.FindingStateDelta') IS NOT NULL AND OBJECT_ID('sidata.FindingAt') IS NOT NULL AND OBJECT_ID('sidata.PublishedRun') IS NOT NULL AND OBJECT_ID('sidata.ChangeState') IS NOT NULL AND COL_LENGTH('sidata.FindingState', 'HomeCollectionId') IS NOT NULL AND COL_LENGTH('sidata.HistoryRun', 'SumHistory') IS NOT NULL THEN 1 ELSE 0 END"
}

function Read-SIDataHistorySetting {
    <# One solution setting's stored value (cfg.Setting), $null when not set or not readable. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Name)
    try {
        $rows = @(@(& $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT ValueJson FROM cfg.Setting WHERE Name = @N AND Scope = N'solution';" @{ N = $Name } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $rows.Count) { return $null }
        return (Get-SIDataChangedSetRowValue $rows[0] 'ValueJson')
    } catch { return $null }
}

function Read-SIDataHistoryMode {
    <# The install's switch: the job's own value when set (-Value, $global:SI_Data_HistoryModel), else the solution setting.
       Not set / not readable = the default, ON. A database without this build's objects = off, said. @{ Mode; Source }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Value = $global:SI_Data_HistoryModel)
    if ($null -ne $Value -and "$Value".Trim() -ne '') { $o = [pscustomobject]@{ Mode = (ConvertTo-SIDataHistoryMode $Value); Source = 'job' } }
    else {
        $v = Read-SIDataHistorySetting -Invoke $Invoke -Name $script:SIDataHistory.Setting
        $o = [pscustomobject]@{ Mode = (ConvertTo-SIDataHistoryMode $v); Source = $(if ($null -eq $v) { 'the default' } else { 'setting' }) }
    }
    if ($o.Mode -ne 'off') {
        $ready = $false
        try { $ready = ([string](& $Invoke (Get-SIDataHistorySchemaCheckSql) @{} 'scalar') -eq '1') } catch { $ready = $false }
        if (-not $ready) { $o = [pscustomobject]@{ Mode = 'off'; Source = 'the database does not have its tables yet (the next schema apply adds them)' } }
    }
    $o
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE COLUMNS
# ---------------------------------------------------------------------------------------------------------------------

function Read-SIDataHistoryColumns {
    <# sidata.Finding's columns in their order and FindingState's. @{ All; State; Missing; Set } -- State = the state columns
       (every Finding column but the identity and the member's), in ordinal name order for the hash; Missing = state columns
       FindingState does not have yet (the next schema apply adds them: nothing is written until then); Set = the column
       list's identity. Throws on a name that is not a plain identifier. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $rows = @(@(& $Invoke "SELECT c.name AS N, c.column_id AS I, CASE WHEN COL_LENGTH(N'sidata.FindingState', c.name) IS NULL THEN 0 ELSE 1 END AS S, CASE WHEN COL_LENGTH(N'sidata.FindingStateMember', c.name) IS NULL THEN 0 ELSE 1 END AS M FROM sys.columns AS c JOIN sys.types AS t ON t.user_type_id = c.user_type_id WHERE c.object_id = OBJECT_ID(N'sidata.Finding') AND c.is_computed = 0 AND t.name NOT IN (N'timestamp', N'rowversion') ORDER BY c.column_id;" @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $all = New-Object System.Collections.Generic.List[string]; $state = New-Object System.Collections.Generic.List[string]; $missing = New-Object System.Collections.Generic.List[string]
    $member = New-Object System.Collections.Generic.List[string]
    $skip = @($script:SIDataHistory.Member) + @($script:SIDataHistory.Identity)
    foreach ($r in $rows) {
        $n = [string](Get-SIDataChangedSetRowValue $r 'N')
        if (-not (Test-SIDataChangedSetColumnName $n)) { throw 'a column name of sidata.Finding is not a plain identifier' }
        $all.Add($n)
        # #1354 a per-run column the member does not have yet (moved there by a later build): the next schema apply adds it
        if ($script:SIDataHistory.Member -contains $n) {
            $member.Add($n)
            $mv0 = Get-SIDataChangedSetRowValue $r 'M'
            if ($null -ne $mv0 -and [int]$mv0 -ne 1) { $missing.Add('member ' + $n) }
        }
        if ($skip -contains $n) { continue }
        $state.Add($n)
        if ([int](Get-SIDataChangedSetRowValue $r 'S') -ne 1) { $missing.Add($n) }
        # a page key the member does not have yet: the next schema apply adds it (nothing is written until then)
        $mv = Get-SIDataChangedSetRowValue $r 'M'
        if ($script:SIDataHistory.PageKeys -contains $n -and $null -ne $mv -and [int]$mv -ne 1) { $missing.Add('member ' + $n) }
    }
    $sorted = $state.ToArray(); [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $keys = @($script:SIDataHistory.PageKeys | Where-Object { $sorted -contains $_ })
    $set = Get-SIDataChangedSetSha -Length 16 -Text ('{0}|{1}|{2}|keys:{3}' -f $script:SIDataHistory.Rule, ($sorted -join ','), ($script:SIDataHistory.RunFields -join ','), ($keys -join ','))
    [pscustomobject]@{ All = $all.ToArray(); State = [string[]]$sorted; Member = [string[]]$member.ToArray(); Missing = $missing.ToArray(); Set = $set }
}

function Get-SIDataHistoryKeyHashExpr {
    <# PURE. The finding key's hash exactly as What changed builds K (SI-DataChanges.ps1: the CI, the issue and the report,
       upper-cased, right-trimmed, NCHAR(31) between). -Alias: the sidata.Finding alias. #>
    param([string]$Alias = 'f')
    if (-not (Test-SIDataChangedSetColumnName $Alias)) { throw 'not a plain alias' }
    $a = $Alias
    "HASHBYTES('SHA2_256', CONCAT(UPPER(RTRIM(COALESCE($a.AssetKey, N'name:' + LOWER(COALESCE($a.AssetName, N''))))), NCHAR(31), UPPER(RTRIM(COALESCE($a.Cve, $a.ConfigurationId, $a.Title, N''))), NCHAR(31), UPPER(RTRIM(COALESCE($a.ReportName, N'')))))"
}

function Get-SIDataHistoryStripApply {
    <# PURE. The APPLY chain that empties the run's own fields in a finding's document (-Alias: the sidata.Finding alias):
       j.J = a single JSON object (no key named twice); r.RV = the plain run fields' values as [{k,t,v}] (NULL = none);
       d<n>.D = the document after the n-th field. The result is d<count>.D. #>
    param([string]$Alias = 'f')
    $a = $Alias
    $rf = (@($script:SIDataHistory.RunFields | ForEach-Object { if ($_ -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$') { throw 'a run field is not a plain name' }; "N'$_'" })) -join ', '
    $first = "SUBSTRING($a.DetailJson, PATINDEX(N'%[^' + CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) + N']%', $a.DetailJson), 1)"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(" CROSS APPLY (SELECT CASE WHEN $a.DetailJson IS NOT NULL AND $first = N'{' AND ISJSON($a.DetailJson) = 1 THEN 1 ELSE 0 END AS J0) AS j0")
    [void]$sb.Append(" OUTER APPLY (SELECT COUNT_BIG(*) AS N, COUNT_BIG(DISTINCT o.[key] COLLATE Latin1_General_BIN2) AS D FROM OPENJSON(CASE WHEN j0.J0 = 1 THEN $a.DetailJson END) AS o) AS jk")
    [void]$sb.Append(" CROSS APPLY (SELECT CASE WHEN j0.J0 = 1 AND jk.N = jk.D THEN 1 ELSE 0 END AS J) AS j")
    [void]$sb.Append(" OUTER APPLY (SELECT (SELECT o.[key] AS k, o.[type] AS t, o.[value] AS v FROM OPENJSON(CASE WHEN j.J = 1 THEN $a.DetailJson END) AS o WHERE o.[key] COLLATE Latin1_General_BIN2 IN ($rf) AND ((o.[type] = 1 AND LEN(o.[value]) BETWEEN 1 AND 200 AND o.[value] COLLATE Latin1_General_BIN2 NOT LIKE N'%[^-0-9A-Za-z:.+ _]%') OR (o.[type] = 2 AND LEN(o.[value]) BETWEEN 1 AND 18 AND o.[value] COLLATE Latin1_General_BIN2 NOT LIKE N'%[^0-9-]%' AND o.[value] NOT LIKE N'_%-%' AND o.[value] <> N'-' AND (o.[value] = N'0' OR (o.[value] NOT LIKE N'0%' AND o.[value] NOT LIKE N'-0%')))) ORDER BY o.[key] COLLATE Latin1_General_BIN2 FOR JSON PATH) AS RV) AS r")
    [void]$sb.Append(" CROSS APPLY (SELECT $a.DetailJson AS D) AS d0")
    $i = 0
    foreach ($k in $script:SIDataHistory.RunFields) {
        $i++
        [void]$sb.Append((" CROSS APPLY (SELECT CASE WHEN r.RV IS NOT NULL AND CHARINDEX(N'""k"":""{0}""', r.RV) > 0 THEN JSON_MODIFY(d{1}.D, N'$.""{0}""', N'') ELSE d{1}.D END AS D) AS d{2}" -f $k, ($i - 1), $i))
    }
    $sb.ToString()
}

function Get-SIDataHistoryStateHashExpr {
    <# PURE. The state's SHA-256 (-Columns: the state columns in ordinal name order, DetailJson among them -- its emptied bytes
       are hashed, from the strip chain's result). #>
    param([Parameter(Mandatory)][string[]]$Columns, [string]$Alias = 'f')
    $last = 'd{0}.D' -f @($script:SIDataHistory.RunFields).Count
    $parts = foreach ($c in $Columns) {
        if ($c -eq 'DetailJson') { "CASE WHEN $last IS NULL THEN 0x00 ELSE 0x01 + CAST(DATALENGTH($last) AS binary(4)) + CAST($last AS varbinary(max)) END" }
        else { Get-SIDataChangedSetColumnPart -Alias $Alias -Column $c }
    }
    "HASHBYTES('SHA2_256', CAST('$($script:SIDataHistory.Rule)' AS varbinary(8)) + " + (@($parts) -join ' + ') + ')'
}

function Get-SIDataHistoryWriteRangeSql {
    <#
        PURE. ONE FindingId range (@After < FindingId <= @Upto) of one collection (@CollectionId) into the history: the state of
        every finding (a new hash = a new FindingState row, one per distinct hash), its member row (the range's members are
        replaced: a resumed range is written once), the states' first / last seen, and the resume mark -- ONE transaction.
        Answers the members written.
    #>
    param([Parameter(Mandatory)][string[]]$StateColumns, [string[]]$MemberColumns = @($script:SIDataHistory.Member))
    $hash = Get-SIDataHistoryStateHashExpr -Columns $StateColumns
    $key = Get-SIDataHistoryKeyHashExpr -Alias 'f'
    $apply = Get-SIDataHistoryStripApply -Alias 'f'
    $last = 'd{0}.D' -f @($script:SIDataHistory.RunFields).Count
    $plain = @($StateColumns | Where-Object { $_ -ne 'DetailJson' })
    $ins = (@($plain | ForEach-Object { '[{0}]' -f $_ })) -join ', '
    $sel = (@($plain | ForEach-Object { 'f.[{0}]' -f $_ })) -join ', '
    # the member's own columns (those sidata.Finding has, -MemberColumns) + the page keys (copies of state columns: the
    # readers' indexes are on the member)
    $mlist = @($script:SIDataHistory.Member | Where-Object { $MemberColumns -contains $_ }) + @($script:SIDataHistory.PageKeys | Where-Object { $StateColumns -contains $_ })
    $mcols = (@($mlist | ForEach-Object { '[{0}]' -f $_ })) -join ', '
    $msel = (@($mlist | ForEach-Object { 'f.[{0}]' -f $_ })) -join ', '
    $docIns = ''; $docSel = ''
    if ($StateColumns -contains 'DetailJson') { $docIns = ', [DetailJson]'; $docSel = ', h.Doc' }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @C INT = CONVERT(int, @CollectionId), @A BIGINT = CONVERT(bigint, @After), @U BIGINT = CONVERT(bigint, @Upto);
CREATE TABLE #h (FindingId BIGINT NOT NULL PRIMARY KEY, StateHash BINARY(32) NOT NULL, KeyHash BINARY(32) NOT NULL, Doc NVARCHAR(MAX) NULL, RunValues NVARCHAR(2000) NULL);
INSERT #h (FindingId, StateHash, KeyHash, Doc, RunValues)
SELECT f.FindingId, $hash, $key, $last, r.RV
FROM sidata.Finding AS f$apply
WHERE f.CollectionId = @C AND f.FindingId > @A AND f.FindingId <= @U;
CREATE INDEX ix ON #h (StateHash);
BEGIN TRAN;
INSERT sidata.FindingState (HomeCollectionId, StateHash, KeyHash, FirstCollectionId, LastCollectionId, $ins$docIns)
SELECT @C, h.StateHash, h.KeyHash, @C, @C, $sel$docSel
FROM #h AS h JOIN sidata.Finding AS f ON f.CollectionId = @C AND f.FindingId = h.FindingId
WHERE h.FindingId = (SELECT MIN(x.FindingId) FROM #h AS x WHERE x.StateHash = h.StateHash)
  AND NOT EXISTS (SELECT 1 FROM sidata.FindingState AS s WITH (UPDLOCK, HOLDLOCK) WHERE s.StateHash = h.StateHash);
DECLARE @new BIGINT = @@ROWCOUNT;
DELETE FROM sidata.FindingStateMember WHERE CollectionId = @C AND FindingId > @A AND FindingId <= @U /* one-statement-ok: one FindingId range of one collection */;
INSERT sidata.FindingStateMember (CollectionId, FindingId, StateId, KeyHash, $mcols, RunValues)
SELECT @C, f.FindingId, s.StateId, h.KeyHash, $msel, h.RunValues
FROM #h AS h JOIN sidata.Finding AS f ON f.CollectionId = @C AND f.FindingId = h.FindingId JOIN sidata.FindingState AS s ON s.StateHash = h.StateHash;
DECLARE @m BIGINT = @@ROWCOUNT;
UPDATE s SET LastCollectionId = CASE WHEN s.LastCollectionId < @C THEN @C ELSE s.LastCollectionId END,
             FirstCollectionId = CASE WHEN s.FirstCollectionId > @C THEN @C ELSE s.FirstCollectionId END
FROM sidata.FindingState AS s WHERE s.StateHash IN (SELECT StateHash FROM #h) AND (s.LastCollectionId < @C OR s.FirstCollectionId > @C) /* one-statement-ok: only the states of this one FindingId range (#h) */;
UPDATE sidata.HistoryRun SET UptoFindingId = @U, Members = ISNULL(Members, 0) + @m, NewStates = ISNULL(NewStates, 0) + @new WHERE CollectionId = @C;
COMMIT;
SELECT @m;
"@
}

function Get-SIDataHistoryStampHashExpr {
    <# The collection's marks as ONE hash (-Alias: the sidata.Collection alias; -Have: the marks this database has): status,
       kind, time, every rewrite mark, and the importance rank's build time (it writes onto the rows) -- NULL kept apart. #>
    param([Parameter(Mandatory)][string]$Alias, [string[]]$Have = @())
    if (-not (Test-SIDataChangedSetColumnName $Alias)) { throw 'not a plain alias' }
    $parts = @("ISNULL(CONVERT(nvarchar(16), $Alias.Status), N'-')", "ISNULL(CONVERT(nvarchar(16), $Alias.Kind), N'-')", "ISNULL(CONVERT(nvarchar(30), $Alias.CollectionTime, 126), N'-')", "ISNULL(CONVERT(nvarchar(30), $Alias.RetiredAt, 126), N'-')")
    foreach ($s in @($script:SIDataHistory.Stamps | Where-Object { $Have -contains $_ })) { $parts += ("ISNULL(CONVERT(nvarchar(30), {0}.[{1}], 126), N'-')" -f $Alias, $s) }
    $parts += "ISNULL((SELECT CONVERT(nvarchar(30), MAX(ps.BuiltAt), 126) FROM sidata.FindingPivotState AS ps WHERE ps.CollectionId = $Alias.CollectionId), N'-')"
    "HASHBYTES('SHA2_256', CONCAT(" + ($parts -join ", N'|', ") + '))'
}

function Get-SIDataHistoryStampColumns {
    <# The marks sidata.Collection has (of the contract's Stamps, + RetiredAt which the hash always reads). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $in = (@($script:SIDataHistory.Stamps | ForEach-Object { "N'$_'" })) -join ', '
    $rows = @(@(& $Invoke "SELECT c.name AS N FROM sys.columns AS c WHERE c.object_id = OBJECT_ID(N'sidata.Collection') AND c.name IN ($in);" @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    , [string[]]@($rows | ForEach-Object { [string](Get-SIDataChangedSetRowValue $_ 'N') })
}

function Get-SIDataHistoryRowHashExpr {
    <# PURE. One row's SHA-256 over EVERY column (-Columns, in sidata.Finding's order), NULL-marked and length-prefixed --
       the byte-exact, case-sensitive compare of the two models (never EXCEPT under the case-insensitive collation). #>
    param([Parameter(Mandatory)][string[]]$Columns, [string]$Alias = 'f')
    "HASHBYTES('SHA2_256', " + ((@($Columns | ForEach-Object { Get-SIDataChangedSetColumnPart -Alias $Alias -Column $_ })) -join ' + ') + ')'
}

function Get-SIDataHistoryVerifyRangeSql {
    <# PURE. ONE FindingId range of one collection: sidata.Finding vs sidata.FindingAt, per FindingId, every column. Answers
       the rows that differ (missing on either side, or another hash) and up to 5 of them with the columns that differ. #>
    param([Parameter(Mandatory)][string[]]$Columns)
    $h = Get-SIDataHistoryRowHashExpr -Columns $Columns -Alias 'f'
    # #1434 only the columns the hash reads go into the history rows' table (tempdb)
    $sel = (@($Columns | ForEach-Object { 'f.[{0}]' -f $_ })) -join ', '
    $cmp = (@($Columns | ForEach-Object { "CASE WHEN ({0}) = ({1}) THEN N'' ELSE N'{2};' END" -f (Get-SIDataChangedSetColumnPart -Alias 'a' -Column $_), (Get-SIDataChangedSetColumnPart -Alias 'b' -Column $_), $_ })) -join ', '
    @"
SET NOCOUNT ON;
DECLARE @C INT = CONVERT(int, @CollectionId), @A BIGINT = CONVERT(bigint, @After), @U BIGINT = CONVERT(bigint, @Upto);
SELECT f.FindingId, $h AS H INTO #o FROM sidata.Finding AS f WHERE f.CollectionId = @C AND f.FindingId > @A AND f.FindingId <= @U;
-- #1434 the history's rows are read ONCE into a table of their own (only the columns the hash reads) and hashed from there:
-- hashed straight off sidata.FindingAt, the document's rebuild (a chain of JSON_MODIFY steps) was worked out again for every
-- place the hash names the column (runner: 5,000 findings 32.7-36.1 s straight, 16.3-16.9 s through the table -- the same values
-- hashed, the same answer)
SELECT $sel INTO #nr FROM sidata.FindingAt(@C) AS f WHERE f.FindingId > @A AND f.FindingId <= @U;
SELECT f.FindingId, $h AS H INTO #n FROM #nr AS f;
DROP TABLE #nr;
SELECT COALESCE(o.FindingId, n.FindingId) AS FindingId, CASE WHEN o.FindingId IS NULL OR n.FindingId IS NULL THEN 1 ELSE 0 END AS Missing
INTO #d FROM #o AS o FULL JOIN #n AS n ON n.FindingId = o.FindingId WHERE o.FindingId IS NULL OR n.FindingId IS NULL OR o.H <> n.H;
SELECT (SELECT COUNT_BIG(*) FROM #o) AS N, (SELECT COUNT_BIG(*) FROM #n) AS NN, (SELECT COUNT_BIG(*) FROM #d) AS D,
       (SELECT CONCAT(ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 1, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 8, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 15, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 22, 7)))), 0)) FROM #o) AS SO,
       (SELECT CONCAT(ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 1, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 8, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 15, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(H, 22, 7)))), 0)) FROM #n) AS SN,
       (SELECT STRING_AGG(CONVERT(nvarchar(max), x.T), N'; ') FROM (SELECT TOP (5) CONCAT(N'finding ', d.FindingId, N': ', CASE WHEN d.Missing = 1 THEN N'missing' ELSE (SELECT CONCAT($cmp) FROM sidata.Finding AS a CROSS JOIN sidata.FindingAt(@C) AS b WHERE a.CollectionId = @C AND a.FindingId = d.FindingId AND b.FindingId = d.FindingId) END) AS T FROM #d AS d ORDER BY d.FindingId) AS x) AS Detail;
"@
}

function Get-SIDataHistoryDeltaSql {
    <# PURE. The change set of one collection (@CollectionId) against @Prev: per state, its count in each (keys only, the two
       memberships), only where they differ -- replacing what the collection held. Answers @{ Opened; Closed }. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @C INT = CONVERT(int, @CollectionId), @P INT = CONVERT(int, @Prev);
BEGIN TRAN;
DELETE FROM sidata.FindingStateDelta WHERE CollectionId = @C /* one-statement-ok: one collection's change set (only what changed) */;
INSERT sidata.FindingStateDelta (CollectionId, PrevCollectionId, StateId, KeyHash, NPrev, NNow)
SELECT @C, @P, COALESCE(b.StateId, a.StateId), COALESCE(b.KeyHash, a.KeyHash), ISNULL(a.N, 0), ISNULL(b.N, 0)
FROM (SELECT StateId, MIN(KeyHash) AS KeyHash, COUNT(*) AS N FROM sidata.FindingStateMember WHERE CollectionId = @P GROUP BY StateId) AS a
FULL JOIN (SELECT StateId, MIN(KeyHash) AS KeyHash, COUNT(*) AS N FROM sidata.FindingStateMember WHERE CollectionId = @C GROUP BY StateId) AS b ON b.StateId = a.StateId
WHERE ISNULL(a.N, 0) <> ISNULL(b.N, 0);
DECLARE @o BIGINT = (SELECT ISNULL(SUM(CONVERT(bigint, NNow - NPrev)), 0) FROM sidata.FindingStateDelta WHERE CollectionId = @C AND NNow > NPrev);
DECLARE @x BIGINT = (SELECT ISNULL(SUM(CONVERT(bigint, NPrev - NNow)), 0) FROM sidata.FindingStateDelta WHERE CollectionId = @C AND NPrev > NNow);
UPDATE sidata.HistoryRun SET PrevCollectionId = @P, Opened = @o, Closed = @x WHERE CollectionId = @C;
COMMIT;
SELECT @o AS Opened, @x AS Closed;
'@
}

function Get-SIDataHistoryChangesCheckSql {
    <#
        PURE. #1334 WHAT CHANGED FROM THE CHANGE SET, checked against the stored full build: THE SAME statement as
        Get-SIDataChangesSql, with three differences -- (1) only the finding keys whose states moved (sidata.FindingStateDelta
        of B against A) are grouped from the two collections' rows; (2) the newer collection's CIs for the 'absent' reason are
        read from ALL of its rows (the narrow columns), not from the grouped keys; (3) instead of writing, the listed rows
        (both variants) and the 'findings' counts -- the unchanged keys counted from the memberships -- are compared, every
        column byte for byte, with sidata.FindingChange / FindingChangeCounted / ChangeCount / ChangeCountCounted of the pair.
        Answers @{ Rows; Differences; Detail }; Differences -1 = the stored pair is another or missing (not checked).
    #>
    $full = Get-SIDataChangesSql
    $kFrom = "FROM sidata.Finding AS f`nJOIN (VALUES (@A, CONVERT(tinyint, 0)), (@CollectionId, CONVERT(tinyint, 1))) AS s (C, Side) ON f.CollectionId = s.C`nLEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey`nGROUP BY s.Side, COALESCE(f.AssetKey"
    $full = $full -replace "`r`n", "`n"
    $i = $full.IndexOf($kFrom)
    if ($i -lt 0) { throw 'What changed''s statement is not the one this check was written for' }
    $kTo = "FROM sidata.Finding AS f`nJOIN (VALUES (@A, CONVERT(tinyint, 0)), (@CollectionId, CONVERT(tinyint, 1))) AS s (C, Side) ON f.CollectionId = s.C`nJOIN sidata.FindingStateMember AS hm ON hm.CollectionId = f.CollectionId AND hm.FindingId = f.FindingId`nJOIN #dk AS dk ON dk.K = hm.KeyHash`nLEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey`nGROUP BY s.Side, COALESCE(f.AssetKey"
    $full = $full.Substring(0, $i) + $kTo + $full.Substring($i + $kFrom.Length)
    $ba = 'SELECT Counted, AssetKey INTO #ba FROM #v WHERE Side = 1 AND AssetKey IS NOT NULL GROUP BY Counted, AssetKey;'
    if (-not $full.Contains($ba)) { throw 'What changed''s statement is not the one this check was written for (the CIs)' }
    $full = $full.Replace($ba, "SELECT x.Counted, x.AssetKey INTO #ba FROM (SELECT CONVERT(bit, 0) AS Counted, COALESCE(f.AssetKey, N'') AS AssetKey FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId UNION SELECT CONVERT(bit, 1), COALESCE(f.AssetKey, N'') FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.ExemptionId IS NULL) AS x GROUP BY x.Counted, x.AssetKey;")
    # #1334 the CI rows (AssetChange): a CI a changed finding stands on is grouped from the two collections' rows; every other
    # CI from the narrow members and their states (the same columns: name, risk, tier, exemption) -- never the wide rows
    $aFrom = "FROM sidata.Finding AS f`nJOIN (VALUES (@A, CONVERT(tinyint, 0)), (@CollectionId, CONVERT(tinyint, 1))) AS s (C, Side) ON f.CollectionId = s.C`nLEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey`nWHERE f.AssetKey IS NOT NULL`nGROUP BY s.Side, f.AssetKey;"
    $ai = $full.IndexOf($aFrom)
    if ($ai -lt 0) { throw 'What changed''s statement is not the one this check was written for (the CI rows)' }
    $aTo = "FROM (SELECT f.CollectionId, f.AssetKey, f.AssetName, f.RiskScore, f.Tier, f.ExemptionId FROM sidata.Finding AS f WHERE f.CollectionId IN (@A, @CollectionId) AND f.AssetKey IS NOT NULL AND EXISTS (SELECT 1 FROM #dca AS dc WHERE dc.AssetKey = f.AssetKey)`n      UNION ALL`n      SELECT m.CollectionId, st.AssetKey, st.AssetName, st.RiskScore, st.Tier, st.ExemptionId FROM sidata.FindingStateMember AS m JOIN sidata.FindingState AS st ON st.StateId = m.StateId WHERE m.CollectionId IN (@A, @CollectionId) AND st.AssetKey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM #dca AS dc WHERE dc.AssetKey = st.AssetKey)) AS f`nJOIN (VALUES (@A, CONVERT(tinyint, 0)), (@CollectionId, CONVERT(tinyint, 1))) AS s (C, Side) ON f.CollectionId = s.C`nLEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey`nGROUP BY s.Side, f.AssetKey;"
    $full = $full.Substring(0, $ai) + $aTo + $full.Substring($ai + $aFrom.Length)
    $declA = 'IF @A IS NULL BEGIN SELECT -1; RETURN; END;'
    if (-not $full.Contains($declA)) { throw 'What changed''s statement is not the one this check was written for (the pair)' }
    $pre = @'
IF @A IS NULL OR NOT EXISTS (SELECT 1 FROM sidata.ChangeState AS cs WHERE cs.CollectionId = @CollectionId AND cs.PrevCollectionId = @A)
   OR NOT EXISTS (SELECT 1 FROM sidata.HistoryRun AS hr WHERE hr.CollectionId = @CollectionId AND hr.PrevCollectionId = @A AND hr.State IN (N'written', N'verified'))
BEGIN SELECT CONVERT(bigint, -1) AS [Rows], CONVERT(bigint, -1) AS Differences, CAST(NULL AS nvarchar(1000)) AS Detail; RETURN; END;
SELECT DISTINCT KeyHash AS K INTO #dk FROM sidata.FindingStateDelta WHERE CollectionId = @CollectionId AND PrevCollectionId = @A;
CREATE CLUSTERED INDEX cx ON #dk (K);
SELECT DISTINCT st.AssetKey INTO #dca FROM sidata.FindingStateDelta AS d JOIN sidata.FindingState AS st ON st.StateId = d.StateId WHERE d.CollectionId = @CollectionId AND d.PrevCollectionId = @A AND st.AssetKey IS NOT NULL;
'@
    $full = $full.Replace($declA, $pre)
    $j = $full.IndexOf('BEGIN TRAN;')
    if ($j -lt 0) { throw 'What changed''s statement is not the one this check was written for (the write)' }
    $cols = @('ChangeKey', 'Change', 'ChangeReason', 'AssetKey', 'AssetName', 'Issue', 'Title', 'ReportName', 'SeverityBefore', 'SeverityAfter', 'RiskBefore', 'RiskAfter', 'RiskDelta', 'TierBefore', 'TierAfter')
    $hx = { param($al) "HASHBYTES('SHA2_256', " + ((@($cols | ForEach-Object { Get-SIDataChangedSetColumnPart -Alias $al -Column $_ })) -join ' + ') + ')' }
    $acols = @('AssetKey', 'AssetName', 'Change', 'FindingsBefore', 'FindingsAfter', 'RiskBefore', 'RiskAfter', 'RiskDelta', 'TierBefore', 'TierAfter')
    $hxa = { param($al) "HASHBYTES('SHA2_256', " + ((@($acols | ForEach-Object { Get-SIDataChangedSetColumnPart -Alias $al -Column $_ })) -join ' + ') + ')' }
    $tail = @"
-- the unchanged keys the change set did not group: their states are the same in both, so they are unchanged in both variants
DECLARE @unch0 BIGINT = (SELECT COUNT_BIG(DISTINCT m.KeyHash) FROM sidata.FindingStateMember AS m WHERE m.CollectionId = @CollectionId AND NOT EXISTS (SELECT 1 FROM #dk AS dk WHERE dk.K = m.KeyHash));
DECLARE @unch1 BIGINT = (SELECT COUNT_BIG(DISTINCT m.KeyHash) FROM sidata.FindingStateMember AS m JOIN sidata.FindingState AS s ON s.StateId = m.StateId WHERE m.CollectionId = @CollectionId AND s.ExemptionId IS NULL AND NOT EXISTS (SELECT 1 FROM #dk AS dk WHERE dk.K = m.KeyHash));
SELECT c.Counted, $(& $hx 'c') AS H INTO #new FROM #fc AS c WHERE c.Change <> N'unchanged';
SELECT CONVERT(bit, 0) AS Counted, $(& $hx 'x') AS H INTO #old FROM sidata.FindingChange AS x WHERE x.CollectionId = @CollectionId
UNION ALL SELECT CONVERT(bit, 1), $(& $hx 'x') FROM sidata.FindingChangeCounted AS x WHERE x.CollectionId = @CollectionId;
SELECT c.Counted, c.Change, COUNT_BIG(*) + CASE WHEN c.Change = N'unchanged' THEN CASE WHEN c.Counted = 1 THEN @unch1 ELSE @unch0 END ELSE 0 END AS N INTO #cnt FROM #fc AS c GROUP BY c.Counted, c.Change;
INSERT #cnt (Counted, Change, N) SELECT v.Counted, N'unchanged', v.N FROM (VALUES (CONVERT(bit, 0), @unch0), (CONVERT(bit, 1), @unch1)) AS v (Counted, N) WHERE v.N > 0 AND NOT EXISTS (SELECT 1 FROM #cnt AS q WHERE q.Counted = v.Counted AND q.Change = N'unchanged');
SELECT CONVERT(bit, 0) AS Counted, x.Change, x.N INTO #ocnt FROM sidata.ChangeCount AS x WHERE x.CollectionId = @CollectionId AND x.What = N'findings'
UNION ALL SELECT CONVERT(bit, 1), x.Change, x.N FROM sidata.ChangeCountCounted AS x WHERE x.CollectionId = @CollectionId AND x.What = N'findings';
DECLARE @dr BIGINT = (SELECT COUNT_BIG(*) FROM (SELECT Counted, H, COUNT(*) AS N FROM #new GROUP BY Counted, H) AS a FULL JOIN (SELECT Counted, H, COUNT(*) AS N FROM #old GROUP BY Counted, H) AS b ON b.Counted = a.Counted AND b.H = a.H WHERE a.H IS NULL OR b.H IS NULL OR a.N <> b.N);
DECLARE @dc BIGINT = (SELECT COUNT_BIG(*) FROM #cnt AS a FULL JOIN #ocnt AS b ON b.Counted = a.Counted AND b.Change = a.Change COLLATE DATABASE_DEFAULT WHERE a.Change IS NULL OR b.Change IS NULL OR a.N <> b.N);
SELECT c.Counted, $(& $hxa 'c') AS H INTO #anew FROM #ac AS c;
SELECT CONVERT(bit, 0) AS Counted, $(& $hxa 'x') AS H INTO #aold FROM sidata.AssetChange AS x WHERE x.CollectionId = @CollectionId
UNION ALL SELECT CONVERT(bit, 1), $(& $hxa 'x') FROM sidata.AssetChangeCounted AS x WHERE x.CollectionId = @CollectionId;
DECLARE @da BIGINT = (SELECT COUNT_BIG(*) FROM (SELECT Counted, H, COUNT(*) AS N FROM #anew GROUP BY Counted, H) AS a FULL JOIN (SELECT Counted, H, COUNT(*) AS N FROM #aold GROUP BY Counted, H) AS b ON b.Counted = a.Counted AND b.H = a.H WHERE a.H IS NULL OR b.H IS NULL OR a.N <> b.N);
SELECT c.Counted, c.Change, COUNT_BIG(*) AS N INTO #acnt FROM #ac AS c GROUP BY c.Counted, c.Change;
SELECT CONVERT(bit, 0) AS Counted, x.Change, x.N INTO #oacnt FROM sidata.ChangeCount AS x WHERE x.CollectionId = @CollectionId AND x.What = N'assets'
UNION ALL SELECT CONVERT(bit, 1), x.Change, x.N FROM sidata.ChangeCountCounted AS x WHERE x.CollectionId = @CollectionId AND x.What = N'assets';
SET @dc = @dc + (SELECT COUNT_BIG(*) FROM #acnt AS a FULL JOIN #oacnt AS b ON b.Counted = a.Counted AND b.Change = a.Change COLLATE DATABASE_DEFAULT WHERE a.Change IS NULL OR b.Change IS NULL OR a.N <> b.N);
SET @dr = @dr + @da;
SELECT (SELECT COUNT_BIG(*) FROM #new) AS [Rows], @dr + @dc AS Differences,
       CASE WHEN @dr + @dc = 0 THEN CAST(NULL AS nvarchar(1000)) ELSE CONCAT(N'listed rows differing: ', @dr, N'; counts differing: ', @dc) END AS Detail;
"@
    $full.Substring(0, $j) + $tail
}

function Get-SIDataHistoryPendingSql {
    <# The kept complete Detailed collections, OLDEST FIRST, with their history row (NULL = none) and their marks' hash now.
       #1359 Checked = 1 when every check from the change set (what changed, the summary groups, the key figures) has an outcome
       recorded since the collection was verified that is not 'failed' (a verified collection without them gets only those). #>
    param([string[]]$Have = @())
    $sh = Get-SIDataHistoryStampHashExpr -Alias 'c' -Have $Have
    $checked = "CASE WHEN h.State = N'verified' AND h.VerifiedAt IS NOT NULL AND NOT EXISTS (SELECT 1 FROM (VALUES (N'changes'), (N'summary-groups'), (N'key-figures')) AS r (R) WHERE NOT EXISTS (SELECT 1 FROM sidata.HistoryCompare AS q WHERE q.CollectionId = c.CollectionId AND q.Reader = r.R AND q.At >= h.VerifiedAt AND q.Outcome <> N'failed')) THEN 1 ELSE 0 END"
    "SET NOCOUNT ON; SELECT c.CollectionId, c.CollectionTime, $sh AS Stamp, h.State, h.StampHash, h.ColumnSet, h.UptoFindingId, h.VerifyUpto, $checked AS Checked, (SELECT COUNT_BIG(*) FROM sidata.FindingStateMember AS hm WHERE hm.CollectionId = c.CollectionId) AS HM, (SELECT MIN(f.FindingId) FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId) AS Lo, (SELECT MAX(f.FindingId) FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId) AS Hi, (SELECT COUNT_BIG(*) FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId) AS N FROM sidata.Collection AS c LEFT JOIN sidata.HistoryRun AS h ON h.CollectionId = c.CollectionId WHERE c.Kind = N'Detailed' AND c.Status = N'Complete' AND c.RetiredAt IS NULL ORDER BY c.CollectionTime, c.CollectionId;"
}

function ConvertTo-SIDataHistoryBytes {
    <# PURE. A binary value (byte[] / DBNull / $null) as hex text, '' when none -- to compare two hashes. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return '' }
    if ($Value -is [byte[]]) { return [System.BitConverter]::ToString($Value) }
    if ($Value -is [object[]] -and @($Value | Where-Object { $_ -isnot [byte] }).Count -eq 0) { return [System.BitConverter]::ToString([byte[]]$Value) }
    [string]$Value
}

function Reset-SIDataHistoryCollection {
    <# A collection's history is written again: its change set and members go (paced), its row starts over. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)]$Stamp, [Parameter(Mandatory)][string]$ColumnSet, $Lo)
    $c = [string]$CollectionId
    # #1332 readers: the collection is no longer served from its history BEFORE anything of it goes (its readers read the
    # stored rows from this moment until it is written and compared again)
    $was = & $Invoke "SET NOCOUNT ON; DECLARE @n int = 0; IF COL_LENGTH(N'sidata.HistoryRun', N'Serves') IS NOT NULL EXEC sys.sp_executesql N'UPDATE sidata.HistoryRun SET Serves = 0 WHERE CollectionId = CONVERT(int, @C) AND Serves = 1; SET @n = @@ROWCOUNT;', N'@C nvarchar(20), @n int OUTPUT', @C = @C, @n = @n OUTPUT; SELECT @n;" @{ C = $c } 'scalar'
    # the readers' seams decide from lists at most this old (SI-FindingSource.ps1 CacheSeconds): the members of a collection they
    # read from its history go only after every seam has seen that it is not served any more
    if ($null -ne $was -and -not ($was -is [System.DBNull]) -and [int]$was -gt 0) {
        $wait = 20; if (Get-Command -Name Get-SIFindingSourceContract -ErrorAction SilentlyContinue) { $wait = [int](Get-SIFindingSourceContract).CacheSeconds + 5 }
        Start-Sleep -Seconds $wait
    }
    $null = & $Invoke 'SET NOCOUNT ON; DELETE FROM sidata.FindingStateDelta WHERE CollectionId = CONVERT(int, @C);' @{ C = $c } 'nonquery'
    # the states ONLY this collection holds go with it and are made again from its rows: a state that differed (or that a
    # rewrite left behind) is never matched again by its hash; a state another collection holds stays (it was checked there).
    # The members go FIRST (every member's state is there: FK_FindingStateMember_State), then every state no member refers to
    # any more -- exactly the states only this collection held (a new state is written in the same transaction as its members)
    while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.FindingStateMember WHERE CollectionId = CONVERT(int, @C); SELECT @@ROWCOUNT;' @{ C = $c } 'scalar') -gt 0) { }
    while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (20000) s FROM sidata.FindingState AS s WHERE NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS o WHERE o.StateId = s.StateId); SELECT @@ROWCOUNT;' @{ C = $c } 'scalar') -gt 0) { }
    $upto = if ($null -eq $Lo -or $Lo -is [System.DBNull]) { '0' } else { [string]([long]$Lo - 1) }
    $null = & $Invoke @'
SET NOCOUNT ON;
DELETE FROM sidata.HistoryRun WHERE CollectionId = CONVERT(int, @C);
INSERT sidata.HistoryRun (CollectionId, State, UptoFindingId, Members, NewStates, StampHash, ColumnSet) VALUES (CONVERT(int, @C), N'writing', CONVERT(bigint, @Upto), 0, 0, CASE WHEN @Stamp = N'' THEN NULL ELSE CONVERT(binary(32), @Stamp, 2) END, @Set);
'@ @{ C = $c; Upto = $upto; Stamp = (ConvertTo-SIDataHistoryBytes $Stamp).Replace('-', ''); Set = $ColumnSet } 'nonquery'
}

function Invoke-SIDataHistoryWrite {
    <# One collection into the history: from its resume mark (or from the start), in FindingId ranges, then 'written' once every
       finding is a member (else it throws). Returns @{ Members; NewStates }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)]$Columns,
          [Parameter(Mandatory)]$Lo, [Parameter(Mandatory)]$Hi, [Parameter(Mandatory)][long]$Findings, [long]$Upto,
          [long]$FirstSize = $script:SIDataHistory.FirstSize, [long]$TargetMs = $script:SIDataHistory.TargetMs, [scriptblock]$Log = { param($l, $m) },
          [scriptblock]$StopNow)
    $c = [string]$CollectionId
    if ($null -ne $Lo -and -not ($Lo -is [System.DBNull])) {
        $from = [Math]::Max([long]$Lo, $Upto + 1)
        if ($from -le [long]$Hi) {
            $mc = @($script:SIDataHistory.Member); if ($Columns.PSObject.Properties['Member'] -and $null -ne $Columns.Member) { $mc = @($Columns.Member) }
            $sql = Get-SIDataHistoryWriteRangeSql -StateColumns $Columns.State -MemberColumns $mc
            # ONE range per statement (one transaction each: its states, members and resume mark together); before every range
            # the stop question (the window's end, an update that wants to go, a run that took the install's lock) -- a stop
            # leaves the collection 'writing' at its mark, and the next window goes on from there
            $after = $from - 1; $size = [Math]::Max(1L, $FirstSize); $lastMs = 0L
            $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
            $sized = [bool](Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue)
            while ($after -lt [long]$Hi) {
                if ($StopNow) { $why = [string](& $StopNow); if ($why) { return [pscustomobject]@{ Members = 0L; NewStates = 0L; Stopped = $why; Upto = $after } } }
                if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) } }
                $upto = [long][Math]::Min([double]$Hi, [double]$after + [double]$size)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $null = & $Invoke $sql @{ CollectionId = $c; After = [string]$after; Upto = [string]$upto } 'scalar'
                $lastMs = $sw.ElapsedMilliseconds
                $after = $upto
                if ($sized) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
            }
        }
    }
    $r = @(@(& $Invoke 'SET NOCOUNT ON; SELECT (SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = CONVERT(int, @C)) AS M, (SELECT NewStates FROM sidata.HistoryRun WHERE CollectionId = CONVERT(int, @C)) AS S;' @{ C = $c } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $m = [long](Get-SIDataChangedSetRowValue $r 'M')
    if ($m -ne $Findings) { throw ('the history of the collection holds {0:N0} member(s) for {1:N0} finding(s)' -f $m, $Findings) }
    $null = & $Invoke "SET NOCOUNT ON; UPDATE sidata.HistoryRun SET State = N'written', Members = CONVERT(bigint, @M), WrittenAt = SYSUTCDATETIME() WHERE CollectionId = CONVERT(int, @C);" @{ C = $c; M = [string]$m } 'nonquery'
    $s = Get-SIDataChangedSetRowValue $r 'S'
    [pscustomobject]@{ Members = $m; NewStates = $(if ($null -eq $s) { 0L } else { [long]$s }); Stopped = ''; Upto = $Hi }
}

function Invoke-SIDataHistoryVerify {
    <# The collection compared row for row: sidata.Finding vs sidata.FindingAt, every column, in FindingId ranges, and its
       CHECKSUM on both sides (Add-SIDataHistorySum). RESUMABLE (#1332 storage): after every range the mark, the rows, the
       differences and both running checksums are kept in HistoryRun (VerifyUpto ...); -Resume goes on from them; -StopNow is
       asked before every range (a stop = @{ Stopped = why }, the collection stays 'written'). Verified ONLY when every row is
       the same, the members are the rows, and the two checksums are equal. Records HistoryCompare 'collection' and HistoryRun
       verified / differs. Returns @{ Rows; Differences; Detail; Stopped; Checksum; Upto }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)]$Columns, $Lo, $Hi,
          [long]$FirstSize = $script:SIDataHistory.FirstSize, [long]$TargetMs = $script:SIDataHistory.TargetMs, [scriptblock]$Log = { param($l, $m) },
          [scriptblock]$StopNow, [switch]$Resume)
    $c = [string]$CollectionId; $rows = 0L; $diff = 0L; $detail = New-Object System.Collections.Generic.List[string]
    $sumO = '0|0|0|0|0'; $sumN = '0|0|0|0|0'
    $after = $(if ($null -ne $Lo -and -not ($Lo -is [System.DBNull])) { [long]$Lo - 1 } else { 0L })
    $resumed = $false
    if ($Resume) {
        $st = @(@(& $Invoke 'SET NOCOUNT ON; SELECT VerifyUpto, VerifyRows, VerifyDiff, SumStored, SumHistory, Diff FROM sidata.HistoryRun WHERE CollectionId = CONVERT(int, @C) AND VerifyUpto IS NOT NULL;' @{ C = $c } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if ($st) {
            $after = [Math]::Max($after, [long](Get-SIDataChangedSetRowValue $st 'VerifyUpto')); $rows = [long](Get-SIDataChangedSetRowValue $st 'VerifyRows'); $diff = [long](Get-SIDataChangedSetRowValue $st 'VerifyDiff')
            $sumO = [string](Get-SIDataChangedSetRowValue $st 'SumStored'); $sumN = [string](Get-SIDataChangedSetRowValue $st 'SumHistory')
            $t0 = [string](Get-SIDataChangedSetRowValue $st 'Diff'); if ($t0) { $detail.Add($t0) }
            $resumed = $true
        }
    }
    if (-not $resumed) { $null = & $Invoke 'SET NOCOUNT ON; UPDATE sidata.HistoryRun SET VerifyUpto = NULL, VerifyRows = NULL, VerifyDiff = NULL, SumStored = NULL, SumHistory = NULL WHERE CollectionId = CONVERT(int, @C);' @{ C = $c } 'nonquery' }
    $nNew = $rows
    if ($null -ne $Lo -and -not ($Lo -is [System.DBNull])) {
        $sql = Get-SIDataHistoryVerifyRangeSql -Columns $Columns.All
        $size = [Math]::Max(1L, $FirstSize); $lastMs = 0L
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
        while ($after -lt [long]$Hi) {
            if ($StopNow) { $why = [string](& $StopNow); if ($why) { return [pscustomobject]@{ Rows = $rows; Differences = $diff; Detail = ($detail -join '; '); Stopped = $why; Checksum = ''; Upto = $after } } }
            if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) } }
            $upto = [long][Math]::Min([double]$Hi, [double]$after + [double]$size)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = @(@(& $Invoke $sql @{ CollectionId = $c; After = [string]$after; Upto = [string]$upto } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            $lastMs = $sw.ElapsedMilliseconds
            $n = [long](Get-SIDataChangedSetRowValue $r 'N'); $rows += $n; $d = [long](Get-SIDataChangedSetRowValue $r 'D'); $diff += $d
            $nn = [long](Get-SIDataChangedSetRowValue $r 'NN')
            $sumO = Add-SIDataHistorySum -A $sumO -B ('{0}|{1}' -f $n, (Get-SIDataChangedSetRowValue $r 'SO'))
            $sumN = Add-SIDataHistorySum -A $sumN -B ('{0}|{1}' -f $nn, (Get-SIDataChangedSetRowValue $r 'SN'))
            if ($d -gt 0 -and $detail.Count -lt 5) { $t = [string](Get-SIDataChangedSetRowValue $r 'Detail'); if ($t) { $detail.Add($t) } }
            $after = $upto
            $dt = ($detail -join '; '); if ($dt.Length -gt 1000) { $dt = $dt.Substring(0, 997) + '...' }
            $null = & $Invoke 'SET NOCOUNT ON; UPDATE sidata.HistoryRun SET VerifyUpto = CONVERT(bigint, @U), VerifyRows = CONVERT(bigint, @R), VerifyDiff = CONVERT(bigint, @D), SumStored = @SO, SumHistory = @SN, Diff = @T WHERE CollectionId = CONVERT(int, @C);' @{ C = $c; U = [string]$after; R = [string]$rows; D = [string]$diff; SO = $sumO; SN = $sumN; T = $(if ($dt) { $dt } else { $null }) } 'nonquery'
            if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
        }
    }
    $members = [long](& $Invoke 'SET NOCOUNT ON; SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = CONVERT(int, @C);' @{ C = $c } 'scalar')
    if ($members -ne $rows) { $diff += [Math]::Abs($members - $rows); $detail.Add(('{0:N0} member(s) for {1:N0} finding(s)' -f $members, $rows)) }
    if ($sumO -ne $sumN -and $diff -eq 0) { $diff += 1; $detail.Add('the checksums of the two sides differ') }
    $text = ($detail -join '; '); if ($text.Length -gt 1000) { $text = $text.Substring(0, 997) + '...' }
    $outcome = if ($diff -eq 0) { 'same' } else { 'differs' }
    $state = if ($diff -eq 0) { 'verified' } else { 'differs' }
    $null = & $Invoke @'
SET NOCOUNT ON;
INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), N'collection', CONVERT(bigint, @R), CONVERT(bigint, @D), @O, @T);
UPDATE sidata.HistoryRun SET State = @S, Differences = CONVERT(bigint, @D), Diff = @T, VerifyUpto = NULL, VerifyRows = CONVERT(bigint, @R), VerifyDiff = CONVERT(bigint, @D), SumStored = @SO, SumHistory = @SN,
       VerifiedAt = CASE WHEN @S = N'verified' THEN SYSUTCDATETIME() ELSE VerifiedAt END WHERE CollectionId = CONVERT(int, @C);
'@ @{ C = $c; R = [string]$rows; D = [string]$diff; O = $outcome; T = $(if ($text) { $text } else { $null }); S = $state; SO = $sumO; SN = $sumN } 'nonquery'
    [pscustomobject]@{ Rows = $rows; Differences = $diff; Detail = $text; Stopped = ''; Checksum = $sumN; Upto = $Hi }
}

function Add-SIDataHistorySum {
    <# PURE. Two checksums 'rows|s1|s2|s3|s4' added (decimal, exact): the collection's checksum is the same whatever ranges it
       was read in. An empty / malformed side counts as 0. #>
    param([string]$A, [string]$B)
    $pa = @("$A".Split('|')); $pb = @("$B".Split('|'))
    $out = for ($i = 0; $i -lt 5; $i++) {
        $x = [decimal]0; $y = [decimal]0
        if ($i -lt $pa.Count) { [void][decimal]::TryParse($pa[$i], [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$x) }
        if ($i -lt $pb.Count) { [void][decimal]::TryParse($pb[$i], [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$y) }
        ($x + $y).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    $out -join '|'
}

function Get-SIDataHistoryCollectionSumSql {
    <# PURE. The checksum of one collection in ONE statement ('rows|s1|s2|s3|s4', the same rule as the compare): -From 'stored'
       (sidata.Finding) or 'history' (sidata.FindingAt). For a test and for support; the run compares in ranges. #>
    param([Parameter(Mandatory)][string[]]$Columns, [ValidateSet('stored', 'history')][string]$From = 'history')
    $h = Get-SIDataHistoryRowHashExpr -Columns $Columns -Alias 'f'
    $src = if ($From -eq 'stored') { 'sidata.Finding AS f WHERE f.CollectionId = CONVERT(int, @CollectionId)' } else { 'sidata.FindingAt(CONVERT(int, @CollectionId)) AS f' }
    "SET NOCOUNT ON; SELECT $h AS H INTO #x FROM $src; SELECT CONCAT(COUNT_BIG(*), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(x.H, 1, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(x.H, 8, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(x.H, 15, 7)))), 0), N'|', ISNULL(SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(x.H, 22, 7)))), 0)) FROM #x AS x;"
}

function Get-SIDataHistoryPrevSql {
    <# The collection the change set of @CollectionId is against: What changed's pair (the listed previous collection), when its
       history is written or verified and its marks did not move since (a 'differs' / stale one is never a base). #>
    $prev = Get-SIDataChangePrevSql -Of 'b'
    "SET NOCOUNT ON; SELECT pv.CollectionId FROM sidata.Collection AS b CROSS APPLY ($prev) AS pv JOIN sidata.HistoryRun AS h ON h.CollectionId = pv.CollectionId AND h.State IN (N'written', N'verified') WHERE b.CollectionId = CONVERT(int, @CollectionId);"
}

function Invoke-SIDataHistoryChangesCheck {
    <# #1334 What changed from the change set vs the stored full build of the pair. Records HistoryCompare 'changes'.
       Returns @{ Rows; Differences; Detail; Outcome }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId)
    $c = [string]$CollectionId
    $r = @(@(& $Invoke (Get-SIDataHistoryChangesCheckSql) @{ CollectionId = [int]$CollectionId } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $rows = [long](Get-SIDataChangedSetRowValue $r 'Rows'); $d = [long](Get-SIDataChangedSetRowValue $r 'Differences'); $t = [string](Get-SIDataChangedSetRowValue $r 'Detail')
    $outcome = if ($d -lt 0) { 'not-ready' } elseif ($d -eq 0) { 'same' } else { 'differs' }
    $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), N'changes', CONVERT(bigint, @R), CONVERT(bigint, @D), @O, @T);" @{ C = $c; R = [string]([Math]::Max(0L, $rows)); D = [string]([Math]::Max(0L, $d)); O = $outcome; T = $(if ($t) { $t } else { $null }) } 'nonquery'
    if ($d -gt 0) { $null = & $Invoke "SET NOCOUNT ON; UPDATE sidata.HistoryRun SET State = N'differs', Differences = ISNULL(Differences, 0) + CONVERT(bigint, @D), Diff = LEFT(CONCAT(Diff, N' what changed: ', @T), 1000) WHERE CollectionId = CONVERT(int, @C);" @{ C = $c; D = [string]$d; T = $t } 'nonquery' }
    [pscustomobject]@{ Rows = $rows; Differences = $d; Detail = $t; Outcome = $outcome }
}

function Invoke-SIDataHistorySummaryGroupsCheck {
    <# #1334 the summary groups FROM THE CHANGES (Get-SISummaryGroupingSqlText -Changes: the groups a changed finding stands in
       computed again, every other group carried from @Prev's stored rows) vs the stored full build, every column. Records
       HistoryCompare 'summary-groups'. Returns @{ Rows; Differences; Detail; Outcome; Recomputed }. Not loaded / no plan =
       not-ready. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, $Prev, $Plan)
    $c = [string]$CollectionId
    if ($null -eq $Prev -or $Prev -is [System.DBNull] -or -not (Get-Command -Name Get-SISummaryGroupingSqlText -ErrorAction SilentlyContinue)) {
        # #1359 recorded too: a collection without a pair has its checks made (Pending: Checked), never made again every run
        $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), N'summary-groups', 0, 0, N'not-ready', NULL);" @{ C = $c } 'nonquery'
        return [pscustomobject]@{ Rows = 0L; Differences = -1L; Detail = $null; Outcome = 'not-ready'; Recomputed = 0L }
    }
    if (-not $Plan) { $Plan = Get-SISummaryGroupingPlan }
    $sql = Get-SISummaryGroupingSqlText -Plan $Plan -Groupings @($Plan.Groupings) -Changes
    $r = @(@(& $Invoke $sql @{ CollectionId = [int]$CollectionId; Prev = [string]$Prev; Hash = [string]$Plan.Hash } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $rows = [long](Get-SIDataChangedSetRowValue $r 'Rows'); $d = [long](Get-SIDataChangedSetRowValue $r 'Differences'); $t = [string](Get-SIDataChangedSetRowValue $r 'Detail')
    $rc = Get-SIDataChangedSetRowValue $r 'Recomputed'
    $outcome = if ($d -lt 0) { 'not-ready' } elseif ($d -eq 0) { 'same' } else { 'differs' }
    $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), N'summary-groups', CONVERT(bigint, @R), CONVERT(bigint, @D), @O, @T);" @{ C = $c; R = [string]([Math]::Max(0L, $rows)); D = [string]([Math]::Max(0L, $d)); O = $outcome; T = $(if ($t) { $t } else { $null }) } 'nonquery'
    if ($d -gt 0) { $null = & $Invoke "SET NOCOUNT ON; UPDATE sidata.HistoryRun SET State = N'differs', Differences = ISNULL(Differences, 0) + CONVERT(bigint, @D), Diff = LEFT(CONCAT(Diff, N' summary groups: ', @T), 1000) WHERE CollectionId = CONVERT(int, @C);" @{ C = $c; D = [string]$d; T = $t } 'nonquery' }
    [pscustomobject]@{ Rows = $rows; Differences = $d; Detail = $t; Outcome = $outcome; Recomputed = $(if ($null -eq $rc) { 0L } else { [long]$rc }) }
}

function Invoke-SIDataHistoryChecks {
    <#
        #1359 THE CHECKS FROM THE CHANGE SET of one verified collection -- what changed, the summary groups, the key figures --
        each timed, each on its own: a check that cannot finish (a statement timeout, a lost connection) is recorded as
        HistoryCompare Outcome 'failed' (Detail = the error without a value) and is made again by the next data sync (Pending:
        Checked = 0); it never makes the collection's history 'failed' -- the history is written and compared row for row, so it
        stays the base of the next collection's change set. A real difference still sets the collection 'differs' (unchanged).
        Returns @{ Changes; SummaryGroups; KeyFigures; Seconds = @{ Changes; SummaryGroups; KeyFigures } }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId)
    $c = [string]$CollectionId
    $secs = [ordered]@{ Changes = 0L; SummaryGroups = 0L; KeyFigures = 0L }
    $one = {
        param([string]$Reader, [scriptblock]$Do)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = & $Do }
        catch {
            $e = Get-SIDataChangedSetSafeError $_
            try { $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), @R, NULL, NULL, N'failed', LEFT(@T, 1000));" @{ C = $c; R = $Reader; T = $e } 'nonquery' } catch { }
            $r = [pscustomobject]@{ Rows = 0L; Differences = -1L; Detail = $e; Outcome = 'failed'; Recomputed = 0L; Carried = 0L }
        }
        $sw.Stop()
        , @($r, [long][Math]::Round($sw.Elapsed.TotalSeconds))
    }
    $a = & $one 'changes' { Invoke-SIDataHistoryChangesCheck -Invoke $Invoke -CollectionId $CollectionId }
    $secs.Changes = $a[1]
    # #1334 the summary groups / key figures from the changes against the pair of the change set
    $sgPrev = $null; $sgErr = $null
    try { $sgPrev = & $Invoke 'SET NOCOUNT ON; SELECT PrevCollectionId FROM sidata.HistoryRun WHERE CollectionId = CONVERT(int, @C);' @{ C = $c } 'scalar' } catch { $sgErr = $_ }
    $b = & $one 'summary-groups' { if ($sgErr) { throw $sgErr }; Invoke-SIDataHistorySummaryGroupsCheck -Invoke $Invoke -CollectionId $CollectionId -Prev $sgPrev }
    $secs.SummaryGroups = $b[1]
    # figure by figure: carried where none of a figure's inputs moved
    $k = & $one 'key-figures' { if ($sgErr) { throw $sgErr }; Invoke-SIDataHistoryKeyFiguresCheck -Invoke $Invoke -CollectionId $CollectionId -Prev $sgPrev }
    $secs.KeyFigures = $k[1]
    [pscustomobject]@{ Changes = $a[0]; SummaryGroups = $b[0]; KeyFigures = $k[0]; Seconds = [pscustomobject]$secs }
}

function Get-SIDataHistoryKeyFiguresCheckSql {
    <#
        PURE. #1334 THE KEY FIGURES FROM THE CHANGE SET, figure by figure, against the collection before it (@Prev), compared with
        the collection's stored full build (sidata.KeyFigure), every column byte for byte. A figure is CARRIED from @Prev's
        stored rows only when NONE of its inputs moved since @Prev's figures were built (Collection.KeyFiguresAt, less one
        second: it is stored to the second); every other figure is the full build's own rows:
          lifecycle figures  patching / opened_30d, fixed_30d, mean_days_to_fix -- sidata.CiFindingState: no row of a CVE finding
                             marked (ChangedAt) or gone (CiFindingStateGone) since, and no row whose first-detected / closed time
                             crossed a window edge between the two collection times (the window moves with the run time);
          CI figures         coverage / *, identity / users_without_mfa -- the CI rows both builds read are the same multiset
                             (sidata.KeyFigureInput: each build's fingerprint of its #d); the stale admins are not carried;
          both               the same settings (the collection's 'meta' rows equal), the collection after @Prev, and the
                             lifecycle's own marks written since before @Prev's figures were built;
          every other figure (the findings' figures, the patches, the protection score, the headline) is the full build's:
                             they read the findings and their asset-to-CI mapping through CiLink / RecordIdentifier / CiRecord,
                             which have no complete change signal.
        Answers [Rows], Differences (-1 = not checked: no stored figures of either), Detail, Carried (the figures carried).
    #>
    $cols = @('Block', 'Figure', 'Dim1', 'Dim2', 'Value', 'Assets', 'Total', 'Available', 'Note', 'Items', 'VeryHigh', 'Servers', 'Clients')
    $h = { param($a) "HASHBYTES('SHA2_256', " + ((@($cols | ForEach-Object { Get-SIDataChangedSetColumnPart -Alias $a -Column $_ })) -join ' + ') + ')' }
    @"
SET NOCOUNT ON;
DECLARE @C INT = CONVERT(int, @CollectionId), @P INT = CONVERT(int, @Prev);
DECLARE @tP datetime2(3), @tC datetime2(3), @tb datetime2(3);
SELECT @tP = CollectionTime, @tb = DATEADD(second, -1, CONVERT(datetime2(3), KeyFiguresAt)) FROM sidata.Collection WHERE CollectionId = @P;
SELECT @tC = CollectionTime FROM sidata.Collection WHERE CollectionId = @C;
IF @tb IS NULL OR @tC IS NULL OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure WHERE CollectionId = @P) OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure WHERE CollectionId = @C)
BEGIN SELECT CONVERT(bigint, -1) AS [Rows], CONVERT(bigint, -1) AS Differences, CAST(NULL AS nvarchar(1000)) AS Detail, CONVERT(bigint, 0) AS Carried; RETURN; END;
-- the settings the two builds used (their 'meta' rows), and the windows
DECLARE @metaSame bit = CASE WHEN EXISTS (SELECT $(& $h 'a') FROM sidata.KeyFigure AS a WHERE a.CollectionId = @P AND a.Block = N'meta'
                                          EXCEPT SELECT $(& $h 'b') FROM sidata.KeyFigure AS b WHERE b.CollectionId = @C AND b.Block = N'meta')
                               OR EXISTS (SELECT $(& $h 'b') FROM sidata.KeyFigure AS b WHERE b.CollectionId = @C AND b.Block = N'meta'
                                          EXCEPT SELECT $(& $h 'a') FROM sidata.KeyFigure AS a WHERE a.CollectionId = @P AND a.Block = N'meta') THEN 0 ELSE 1 END;
DECLARE @R int = (SELECT TOP (1) CONVERT(int, Value) FROM sidata.KeyFigure WHERE CollectionId = @C AND Block = N'meta' AND Figure = N'window' AND Dim1 = N'recent_days');
DECLARE @M int = (SELECT TOP (1) CONVERT(int, Value) FROM sidata.KeyFigure WHERE CollectionId = @C AND Block = N'meta' AND Figure = N'window' AND Dim1 = N'mttr_days');
DECLARE @S int = (SELECT TOP (1) CONVERT(int, Value) FROM sidata.KeyFigure WHERE CollectionId = @C AND Block = N'meta' AND Figure = N'window' AND Dim1 = N'stale_admin_days');
-- the lifecycle's own marks were written since before @Prev's figures were built (the first run that wrote them says when:
-- sidata.CiBuildState 'LifecycleMarksSince', SI-DataCiLifecycle.ps1 Set-SIDataLifecycleMarks)
DECLARE @lcSince datetime2(3) = (SELECT TOP (1) TRY_CONVERT(datetime2(3), Value, 127) FROM sidata.CiBuildState WHERE Name = N'LifecycleMarksSince');
DECLARE @base bit = CASE WHEN @metaSame = 1 AND @tC > @tP THEN 1 ELSE 0 END;
DECLARE @lcOk bit = CASE WHEN @base = 1 AND @lcSince < @tb
    AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState WHERE FindingKey LIKE N'CVE-%' AND ChangedAt > @tb)
    AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingStateGone WHERE FindingKey LIKE N'CVE-%' AND GoneAt > @tb) THEN 1 ELSE 0 END;
-- the CI rows both builds read (sidata.KeyFigureInput, recorded by each build from its own #d): the same multiset
DECLARE @ciOk bit = CASE WHEN @base = 1 AND EXISTS (SELECT 1 FROM sidata.KeyFigureInput AS a JOIN sidata.KeyFigureInput AS b ON b.CollectionId = @C
    WHERE a.CollectionId = @P AND a.CiRows = b.CiRows AND a.CiFp1 = b.CiFp1 AND a.CiFp2 = b.CiFp2) THEN 1 ELSE 0 END;
-- the window edges: a row whose time lies where the window moved between the two collection times
DECLARE @openedOk bit = CASE WHEN @lcOk = 1 AND @R IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState WHERE FindingKey LIKE N'CVE-%'
    AND ((FirstDetected > DATEADD(day, -@R, @tP) AND FirstDetected <= DATEADD(day, -@R, @tC)) OR (FirstDetected > @tP AND FirstDetected <= @tC))) THEN 1 ELSE 0 END;
DECLARE @fixedOk bit = CASE WHEN @lcOk = 1 AND @R IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState WHERE FindingKey LIKE N'CVE-%'
    AND ((ClosedAt > DATEADD(day, -@R, @tP) AND ClosedAt <= DATEADD(day, -@R, @tC)) OR (ClosedAt > @tP AND ClosedAt <= @tC))) THEN 1 ELSE 0 END;
DECLARE @mttrOk bit = CASE WHEN @lcOk = 1 AND @M IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState WHERE FindingKey LIKE N'CVE-%'
    AND ((ClosedAt > DATEADD(day, -@M, @tP) AND ClosedAt <= DATEADD(day, -@M, @tC)) OR (ClosedAt > @tP AND ClosedAt <= @tC))) THEN 1 ELSE 0 END;
-- (the stale admins are not carried: their window moves with the run time over the last sign-ins as each build READ them,
-- which only the build itself holds -- the full build's row is used)
CREATE TABLE #carry (Block NVARCHAR(16) COLLATE DATABASE_DEFAULT NOT NULL, Figure NVARCHAR(48) COLLATE DATABASE_DEFAULT NOT NULL);
INSERT #carry (Block, Figure) SELECT v.B, v.F FROM (VALUES
    (N'patching', N'opened_30d', @openedOk), (N'patching', N'fixed_30d', @fixedOk), (N'patching', N'mean_days_to_fix', @mttrOk),
    (N'coverage', N'not_onboarded', @ciOk), (N'coverage', N'not_onboarded_status', @ciOk), (N'coverage', N'not_seen_30d', @ciOk), (N'coverage', N'azure_vm_no_agent', @ciOk),
    (N'identity', N'users_without_mfa', @ciOk)) AS v (B, F, Ok) WHERE v.Ok = 1;
-- the figures from the change set: the carried ones from @Prev's rows, every other one the full build's
SELECT $(& $h 'k') AS H INTO #new FROM sidata.KeyFigure AS k
WHERE (k.CollectionId = @P AND EXISTS (SELECT 1 FROM #carry AS c WHERE c.Block = k.Block AND c.Figure = k.Figure))
   OR (k.CollectionId = @C AND NOT EXISTS (SELECT 1 FROM #carry AS c WHERE c.Block = k.Block AND c.Figure = k.Figure));
SELECT $(& $h 'k') AS H INTO #old FROM sidata.KeyFigure AS k WHERE k.CollectionId = @C;
DECLARE @d bigint = (SELECT COUNT_BIG(*) FROM (SELECT H, COUNT(*) AS N FROM #new GROUP BY H) AS a FULL JOIN (SELECT H, COUNT(*) AS N FROM #old GROUP BY H) AS b ON b.H = a.H
                     WHERE a.H IS NULL OR b.H IS NULL OR a.N <> b.N);
SELECT (SELECT COUNT_BIG(*) FROM #new) AS [Rows], @d AS Differences,
       CASE WHEN @d = 0 THEN CAST(NULL AS nvarchar(1000)) ELSE (SELECT LEFT(CONCAT(N'carried figures: ', STRING_AGG(CONVERT(nvarchar(max), c.Block + N'/' + c.Figure), N', ')), 1000) FROM #carry AS c) END AS Detail,
       (SELECT COUNT_BIG(*) FROM #carry) AS Carried;
"@
}

function Invoke-SIDataHistoryKeyFiguresCheck {
    <# #1334 the key figures from the change set (Get-SIDataHistoryKeyFiguresCheckSql) vs the stored full build. Records
       HistoryCompare 'key-figures'. Returns @{ Rows; Differences; Detail; Outcome; Carried }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, $Prev)
    $c = [string]$CollectionId
    if ($null -eq $Prev -or $Prev -is [System.DBNull]) {
        # #1359 recorded too (see Invoke-SIDataHistorySummaryGroupsCheck)
        $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), N'key-figures', 0, 0, N'not-ready', NULL);" @{ C = $c } 'nonquery'
        return [pscustomobject]@{ Rows = 0L; Differences = -1L; Detail = $null; Outcome = 'not-ready'; Carried = 0L }
    }
    $r = @(@(& $Invoke (Get-SIDataHistoryKeyFiguresCheckSql) @{ CollectionId = $c; Prev = [string]$Prev } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $rows = [long](Get-SIDataChangedSetRowValue $r 'Rows'); $d = [long](Get-SIDataChangedSetRowValue $r 'Differences'); $t = [string](Get-SIDataChangedSetRowValue $r 'Detail')
    $cr = Get-SIDataChangedSetRowValue $r 'Carried'
    $outcome = if ($d -lt 0) { 'not-ready' } elseif ($d -eq 0) { 'same' } else { 'differs' }
    $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), N'key-figures', CONVERT(bigint, @R), CONVERT(bigint, @D), @O, @T);" @{ C = $c; R = [string]([Math]::Max(0L, $rows)); D = [string]([Math]::Max(0L, $d)); O = $outcome; T = $(if ($t) { $t } else { $null }) } 'nonquery'
    if ($d -gt 0) { $null = & $Invoke "SET NOCOUNT ON; UPDATE sidata.HistoryRun SET State = N'differs', Differences = ISNULL(Differences, 0) + CONVERT(bigint, @D), Diff = LEFT(CONCAT(Diff, N' key figures: ', @T), 1000) WHERE CollectionId = CONVERT(int, @C);" @{ C = $c; D = [string]$d; T = $t } 'nonquery' }
    [pscustomobject]@{ Rows = $rows; Differences = $d; Detail = $t; Outcome = $outcome; Carried = $(if ($null -eq $cr) { 0L } else { [long]$cr }) }
}
function Invoke-SIDataHistoryRetention {
    <# THE FALLBACK (the history is not on the partitions, no boundary was cut yet, or SI_Data_RetireByPartition is off --
       Test-SIDataHistoryOnPartitions; otherwise the index build job / the update's step removes the history by partition).
       The members of a collection whose rows are gone (removed or retired) leave, paced, unless -Days keeps them (0 = they
       follow the collections) -- a FROZEN collection is kept only when its history was verified; never the published
       collection. Then the states no member refers to, paced. Returns @{ Collections; States; ByPartition }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$Days = 0, [scriptblock]$Log = { param($l, $m) }, [switch]$Force)
    if (-not $Force -and (Test-SIDataHistoryOnPartitions -Invoke $Invoke)) { return [pscustomobject]@{ Collections = 0; States = 0L; ByPartition = $true } }
    $gone = @(@(& $Invoke @'
SET NOCOUNT ON;
SELECT h.CollectionId FROM sidata.HistoryRun AS h LEFT JOIN sidata.Collection AS c ON c.CollectionId = h.CollectionId
WHERE (c.CollectionId IS NULL OR c.RetiredAt IS NOT NULL OR c.Status <> N'Complete')
  AND NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N'current' AND p.DetailedCollectionId = h.CollectionId)
  AND (CONVERT(int, @Days) <= 0 OR c.CollectionId IS NULL OR c.CollectionTime < DATEADD(day, -CONVERT(int, @Days), SYSUTCDATETIME()) OR h.State <> N'verified');
'@ @{ Days = [string]$Days } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $n = 0
    foreach ($g in $gone) {
        $cid = [string](Get-SIDataChangedSetRowValue $g 'CollectionId')
        while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.FindingStateMember WHERE CollectionId = CONVERT(int, @C) AND NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N''current'' AND p.DetailedCollectionId = CONVERT(int, @C)); SELECT @@ROWCOUNT;' @{ C = $cid } 'scalar') -gt 0) { }
        $null = & $Invoke 'SET NOCOUNT ON; DELETE FROM sidata.FindingStateDelta WHERE CollectionId = CONVERT(int, @C) OR PrevCollectionId = CONVERT(int, @C); DELETE FROM sidata.HistoryRun WHERE CollectionId = CONVERT(int, @C) AND NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m WHERE m.CollectionId = CONVERT(int, @C)); DELETE FROM sidata.HistoryCompare WHERE CollectionId = CONVERT(int, @C);' @{ C = $cid } 'nonquery'
        $n++
    }
    # a state no member refers to any more can only come from a collection that left above: looked for only then
    $states = 0L
    if ($n -gt 0) {
        do {
            $k = [long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (20000) s FROM sidata.FindingState AS s WHERE NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m WHERE m.StateId = s.StateId) AND NOT EXISTS (SELECT 1 FROM sidata.HistoryRun AS h WHERE h.State = N''writing''); SELECT @@ROWCOUNT;' @{} 'scalar')
            $states += $k
        } while ($k -gt 0)
    }
    if ($n -or $states) { & $Log 'INFO' ("history     : {0} collection(s) left the history with their rows, {1:N0} finding state(s) no collection holds any more were removed" -f $n, $states) }
    [pscustomobject]@{ Collections = $n; States = $states; ByPartition = $false }
}

function Get-SIDataHistoryOnPartitionsSql {
    <# 1 when the history leaves by partition: both history tables have EVERY index on PS_SICollection and at least one
       boundary is cut (no boundary = one partition, which no partition step can ever empty), else 0. #>
    @'
SET NOCOUNT ON;
DECLARE @ps int = (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection');
DECLARE @pf int = (SELECT function_id FROM sys.partition_functions WHERE name = N'PF_SICollection');
SELECT CASE WHEN @ps IS NULL OR @pf IS NULL THEN 0
            WHEN OBJECT_ID(N'sidata.FindingStateMember', N'U') IS NULL OR OBJECT_ID(N'sidata.FindingState', N'U') IS NULL THEN 0
            WHEN EXISTS (SELECT 1 FROM sys.indexes AS x WHERE x.object_id IN (OBJECT_ID(N'sidata.FindingStateMember'), OBJECT_ID(N'sidata.FindingState')) AND x.is_hypothetical = 0 AND x.data_space_id <> @ps) THEN 0
            WHEN NOT EXISTS (SELECT 1 FROM sys.partition_range_values AS v WHERE v.function_id = @pf) THEN 0
            ELSE 1 END;
'@
}

function Test-SIDataHistoryOnPartitions {
    <# The history leaves by partition (Get-SIDataHistoryOnPartitionsSql) AND SI_Data_RetireByPartition is on (on by default:
       off only for false / 0 / off / no). Not readable = $false (the paced removal serves). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Switch = (Get-Variable -Name 'SI_Data_RetireByPartition' -Scope Global -ValueOnly -ErrorAction SilentlyContinue))
    try {
        if ($null -eq $Switch -or "$Switch".Trim() -eq '') { $Switch = Read-SIDataHistorySetting -Invoke $Invoke -Name 'SI_Data_RetireByPartition' }
        if ($null -ne $Switch) {
            if ($Switch -is [bool]) { if (-not $Switch) { return $false } }
            elseif ((("$Switch".Trim() -replace '^"|"$', '').Trim().ToLowerInvariant()) -in @('0', 'false', 'off', 'no', '$false')) { return $false }
        }
        return ([string](& $Invoke (Get-SIDataHistoryOnPartitionsSql) @{} 'scalar') -eq '1')
    } catch { return $false }
}

function Read-SIDataHistoryDays {
    <# The history window in days: the job's own value ($global:SI_Data_HistoryDays), else the solution setting, else the
       DEFAULT 30 (owner decision 3). 0 = the history follows the kept collections. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Value = (Get-Variable -Name 'SI_Data_HistoryDays' -Scope Global -ValueOnly -ErrorAction SilentlyContinue))
    $v = $Value
    if ($null -eq $v -or "$v".Trim() -eq '') { $v = Read-SIDataHistorySetting -Invoke $Invoke -Name $script:SIDataHistory.DaysSetting }
    if ($null -ne $v -and "$v" -match '^\s*"?(\d{1,5})"?\s*$') { return [int]$Matches[1] }
    [int]$script:SIDataHistory.DaysDefault
}

function Get-SIDataHistoryRunLockSql {
    <# 1 when a PIPELINE RUN holds the install's lock (cfg.PipelineLock 'install': a holder with a run's FlowRunId and a beat
       younger than @Minutes), else 0. Not there = 0. The index build job and an update hold it without a FlowRunId. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.PipelineLock', N'U') IS NULL BEGIN SELECT 0; RETURN; END
DECLARE @m int = TRY_CONVERT(int, @Minutes), @r int = 0;
IF @m IS NULL OR @m < 1 SET @m = 15;
IF COL_LENGTH(N'cfg.PipelineLock', N'FlowRunId') IS NOT NULL
    EXEC sp_executesql N'SELECT @r = CASE WHEN EXISTS (SELECT 1 FROM cfg.PipelineLock WHERE LockId = N''install'' AND Holder IS NOT NULL AND FlowRunId IS NOT NULL AND HeartbeatUtc >= DATEADD(minute, -@m, SYSUTCDATETIME())) THEN 1 ELSE 0 END', N'@m int, @r int OUTPUT', @m = @m, @r = @r OUTPUT;
SELECT @r;
'@
}

function Test-SIDataHistoryRunHoldsLock {
    <# $true when a pipeline run holds the install's lock (Get-SIDataHistoryRunLockSql). A read that fails = $true: the
       migration outside a run never goes on when it cannot tell. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try { [string](& $Invoke (Get-SIDataHistoryRunLockSql) @{ Minutes = [string]$script:SIDataHistory.RunLockMinutes } 'scalar') -eq '1' } catch { $true }
}

function Get-SIDataHistoryWarningText {
    <# PURE. The run's warning for the history step's result, or '' when there is nothing to say. Ids and column names only. #>
    param($Result)
    if ($null -eq $Result) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($d in @(Get-SIDataChangedSetRowValue $Result 'Differing')) {
        if (-not $d) { continue }
        $out.Add(('the finding history of the collection of {0} differed from the stored rows ({1} -- {2:N0} difference(s): {3}) -- the stored rows and the full builds are what is shown and sent; nothing different was published' -f (Get-SIDataChangedSetRowValue $d 'When'), (Get-SIDataChangedSetRowValue $d 'Reader'), [long](Get-SIDataChangedSetRowValue $d 'Differences'), (Get-SIDataChangedSetRowValue $d 'Detail')))
    }
    if ([string](Get-SIDataChangedSetRowValue $Result 'Status') -eq 'failed') {
        $out.Add(('the finding history was not completed this run ({0}) -- the stored rows and the full builds are what is shown and sent; it goes on from where it stopped next run' -f (Get-SIDataChangedSetRowValue $Result 'Error')))
    }
    $out.ToArray()
}

function Invoke-SIDataHistory {
    <#
    .SYNOPSIS  The data sync's history step (after the remediation tasks): every kept complete Detailed collection's history
               written (oldest first -- the migration of an existing install is this same loop), checked row for row, its
               change set and What changed from it checked; then the retention. Never throws.
    .NOTES     -Mode: the switch (Read-SIDataHistoryMode). -BudgetSeconds paces the OLDER collections only: the newest is never
               left to a later run. -OutsideRun (the index build job's idle window, the update's bounded step): EVERY
               collection obeys -DeadlineUtc and -ShouldStop ('' = go on) before every range, nothing starts or goes on while a
               pipeline run holds the install's lock (Test-SIDataHistoryRunHoldsLock, read again at most every 20 s), a stop
               says where the collection stands in one progress line and the next window goes on from there; the retention is
               left to the partition step. A collection whose stored rows are gone but whose history is there is FROZEN: never
               written again (decision 4). #1359: the checks from the change set (Invoke-SIDataHistoryChecks: one statement each
               over the whole collection) run in the data sync only -- a bounded window writes and compares row for row, the
               next data sync makes the checks of every verified collection that lacks them (Pending: Checked); a check that
               cannot finish is recorded 'failed' and made again, the collection stays verified (the base of the next change
               set). Returns @{ Status (ok | progress | waiting | off | dry-run | no-schema | failed);
               Mode; Collections; Written; Verified; Frozen; Differences; Differing; Error; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Mode = 'on', [switch]$DryRun, [scriptblock]$Log,
          [int]$BudgetSeconds = $script:SIDataHistory.BudgetSeconds, [long]$FirstSize = $script:SIDataHistory.FirstSize, [int]$Days = -1,
          [switch]$OutsideRun, $DeadlineUtc = $null, [scriptblock]$ShouldStop)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $res = [ordered]@{ Status = 'ok'; Mode = $Mode; Collections = 0; Written = 0; Verified = 0; Frozen = 0; Differences = 0L; Differing = @(); Error = $null; Lines = @() }
    if ($Mode -eq 'off') { $res.Status = 'off'; return [pscustomobject]$res }
    if ($DryRun) { $res.Status = 'dry-run'; return [pscustomobject]$res }
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param([string]$l, [string]$m) $lines.Add($m); & $Log $l $m }
    $differing = New-Object System.Collections.Generic.List[object]
    # THE STOP QUESTION: the window's end, the caller's reason (an update wants to go), and outside a run the install's lock
    $siHistStop = [pscustomobject]@{ LockAt = [datetime]::MinValue; Why = '' }
    $deadline = if ($null -ne $DeadlineUtc) { ([datetime]$DeadlineUtc).ToUniversalTime() } else { $null }
    $histInvoke = $Invoke; $histOutside = [bool]$OutsideRun; $histOuter = $ShouldStop
    $stopNow = {
        if ($siHistStop.Why) { return $siHistStop.Why }
        if ($null -ne $deadline -and [datetime]::UtcNow -ge $deadline) { $siHistStop.Why = 'the window''s time is used'; return $siHistStop.Why }
        if ($histOuter) { $w = ''; try { $w = [string](& $histOuter) } catch { $w = 'whether to stop could not be read' }; if ($w) { $siHistStop.Why = $w; return $w } }
        if ($histOutside -and ([datetime]::UtcNow - $siHistStop.LockAt).TotalSeconds -ge $script:SIDataHistory.StopEverySeconds) {
            $siHistStop.LockAt = [datetime]::UtcNow
            if (Test-SIDataHistoryRunHoldsLock -Invoke $histInvoke) { $siHistStop.Why = 'a pipeline run holds the install''s lock'; return $siHistStop.Why }
        }
        ''
    }
    try {
        if ($OutsideRun) {
            $w0 = & $stopNow
            if ($w0) { & $say 'INFO' ("history     : the migration of the finding history waits -- {0}; nothing was written" -f $w0); $res.Status = 'waiting'; $res.Lines = $lines.ToArray(); return [pscustomobject]$res }
        }
        $cols = Read-SIDataHistoryColumns -Invoke $Invoke
        if ($cols.Missing.Count) {
            & $say 'WARN' ("history     : the finding history waits for the next update -- {0} column(s) of the findings are not in the history table yet; the stored rows serve as before" -f $cols.Missing.Count)
            $res.Status = 'no-schema'; $res.Lines = $lines.ToArray(); return [pscustomobject]$res
        }
        if ($Days -lt 0) { $Days = Read-SIDataHistoryDays -Invoke $Invoke }
        $have = Get-SIDataHistoryStampColumns -Invoke $Invoke
        $pending = @(@(& $Invoke (Get-SIDataHistoryPendingSql -Have $have) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $i = 0; $stopped = ''
        foreach ($p in $pending) {
            $i++
            $cid = [long](Get-SIDataChangedSetRowValue $p 'CollectionId'); $when = Get-SIDataChangedSetRowValue $p 'CollectionTime'
            $whenText = if ($when -is [datetime]) { $when.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { [string]$when }
            $newest = ($i -eq $pending.Count)
            $state = [string](Get-SIDataChangedSetRowValue $p 'State')
            # binary values in plain assignments only: a function's output unrolls a byte[] into object[]
            if ($p -is [System.Collections.IDictionary]) { $stampNow = $p['Stamp']; $stampWas = $p['StampHash'] } else { $stampNow = $p.Stamp; $stampWas = $p.StampHash }
            $current = ($state -in 'written', 'verified') -and ((ConvertTo-SIDataHistoryBytes $stampNow) -eq (ConvertTo-SIDataHistoryBytes $stampWas)) -and ([string](Get-SIDataChangedSetRowValue $p 'ColumnSet') -eq $cols.Set)
            $res.Collections++
            $n = [long](Get-SIDataChangedSetRowValue $p 'N'); $hm = [long](Get-SIDataChangedSetRowValue $p 'HM')
            # FROZEN (decision 4): the stored rows are gone, the history holds it -- it is what was published, never written again
            if ($n -eq 0 -and $hm -gt 0) { $res.Frozen++; continue }
            # #1359 a verified collection whose checks from the change set are not all recorded (a bounded window wrote and
            # verified it, or a check could not finish) gets ONLY those checks -- in the data sync, never in a bounded window
            $checksOnly = $false
            if ($current -and $state -eq 'verified') {
                if ($OutsideRun -or [string](Get-SIDataChangedSetRowValue $p 'Checked') -eq '1') { continue }
                $checksOnly = $true
            }
            if (-not $OutsideRun -and -not $newest -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { & $say 'INFO' ("history     : the older collections' history follows on the next run(s) (from the collection of {0})" -f $whenText); break }
            if ($OutsideRun) { $w1 = & $stopNow; if ($w1) { $stopped = $w1; & $say 'INFO' ("history     : migration -- stopped before the collection of {0} ({1}); the next window goes on" -f $whenText, $w1); break } }
            $lo = Get-SIDataChangedSetRowValue $p 'Lo'; $hi = Get-SIDataChangedSetRowValue $p 'Hi'
            $stopArg = $(if ($OutsideRun -or $null -ne $deadline -or $ShouldStop) { $stopNow } else { $null })
            try {
              if (-not $checksOnly) {
                $resumeVerify = $current -and $state -eq 'written' -and $null -ne (Get-SIDataChangedSetRowValue $p 'VerifyUpto')
                if (-not $current) {
                    $resume = ($state -eq 'writing') -and ((ConvertTo-SIDataHistoryBytes $stampNow) -eq (ConvertTo-SIDataHistoryBytes $stampWas)) -and ([string](Get-SIDataChangedSetRowValue $p 'ColumnSet') -eq $cols.Set)
                    $upto = 0L
                    if ($resume) { $u = Get-SIDataChangedSetRowValue $p 'UptoFindingId'; if ($null -ne $u) { $upto = [long]$u } }
                    else { Reset-SIDataHistoryCollection -Invoke $Invoke -CollectionId $cid -Stamp $stampNow -ColumnSet $cols.Set -Lo $lo; if ($null -ne $lo -and -not ($lo -is [System.DBNull])) { $upto = [long]$lo - 1 } }
                    $w = Invoke-SIDataHistoryWrite -Invoke $Invoke -CollectionId $cid -Columns $cols -Lo $lo -Hi $hi -Findings $n -Upto $upto -FirstSize $FirstSize -Log $Log -StopNow $stopArg
                    if ($w.Stopped) {
                        $stopped = [string]$w.Stopped
                        $done = [long](& $Invoke 'SET NOCOUNT ON; SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = CONVERT(int, @C);' @{ C = [string]$cid } 'scalar')
                        & $say 'INFO' ("history     : migration -- the collection of {0}: {1:N0} of {2:N0} finding(s) written ({3} %), stopped ({4}); the next window goes on from there" -f $whenText, $done, $n, $(if ($n -gt 0) { [Math]::Floor(100.0 * $done / $n) } else { 100 }), $stopped)
                        break
                    }
                    $res.Written++
                    $prev = & $Invoke (Get-SIDataHistoryPrevSql) @{ CollectionId = [string]$cid } 'scalar'
                    $dl = $null
                    if ($null -ne $prev -and -not ($prev -is [System.DBNull])) { $dl = @(@(& $Invoke (Get-SIDataHistoryDeltaSql) @{ CollectionId = [string]$cid; Prev = [string]$prev } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1 }
                    & $say 'INFO' ("history     : the collection of {0}: {1:N0} finding(s), {2:N0} new state(s){3}{4}" -f $whenText, $w.Members, $w.NewStates, $(if ($resume) { ' (resumed)' } else { '' }), $(if ($dl) { (', {0:N0} opened / {1:N0} closed against the collection before it' -f [long](Get-SIDataChangedSetRowValue $dl 'Opened'), [long](Get-SIDataChangedSetRowValue $dl 'Closed')) } else { '' }))
                }
                $v = Invoke-SIDataHistoryVerify -Invoke $Invoke -CollectionId $cid -Columns $cols -Lo $lo -Hi $hi -FirstSize $FirstSize -Log $Log -StopNow $stopArg -Resume:$resumeVerify
                if ($v.Stopped) {
                    $stopped = [string]$v.Stopped
                    & $say 'INFO' ("history     : migration -- the collection of {0}: written, {1:N0} of {2:N0} finding(s) compared ({3} %), stopped ({4}); the next window goes on from there" -f $whenText, $v.Rows, $n, $(if ($n -gt 0) { [Math]::Floor(100.0 * $v.Rows / $n) } else { 100 }), $stopped)
                    break
                }
                if ($v.Differences -gt 0) { $differing.Add([pscustomobject]@{ When = $whenText; Reader = 'the collection'; Differences = $v.Differences; Detail = $v.Detail }) }
                else { $res.Verified++ }
                $vText = $(if ($v.Differences -gt 0) { ('{0:N0} difference(s)' -f $v.Differences) } else { 'the same, checksum equal on both sides' })
              } else {
                $v = [pscustomobject]@{ Differences = 0L }
                $vText = 'the same (compared before)'
              }
                # #1359 a bounded window (the update's step, the index build job) writes and compares row for row in ranges only:
                # the checks from the change set are each ONE statement over the whole collection (the summary groups compute
                # every group a changed finding stands in again), so they are never started under a window's statement limit
                # -- the next data sync makes them (no statement limit there). Before, the update's 120 s limit stopped the
                # summary groups' check of a large collection and the collection's history ended 'failed'.
                if ($OutsideRun) {
                    & $say $(if ($v.Differences -gt 0) { 'WARN' } else { 'OK' }) ("history     : migration -- the collection of {0} compared row for row with the stored rows: {1}; the checks from the change set follow in the next data sync" -f $whenText, $vText)
                    continue
                }
                $ck = Invoke-SIDataHistoryChecks -Invoke $Invoke -CollectionId $cid
                $ch = $ck.Changes; $sg = $ck.SummaryGroups; $kf = $ck.KeyFigures
                if ($ch.Differences -gt 0) { $differing.Add([pscustomobject]@{ When = $whenText; Reader = 'what changed'; Differences = $ch.Differences; Detail = $ch.Detail }) }
                if ($sg.Differences -gt 0) { $differing.Add([pscustomobject]@{ When = $whenText; Reader = 'the summary groups'; Differences = $sg.Differences; Detail = $sg.Detail }) }
                if ($kf.Differences -gt 0) { $differing.Add([pscustomobject]@{ When = $whenText; Reader = 'the key figures'; Differences = $kf.Differences; Detail = $kf.Detail }) }
                $res.Differences += [Math]::Max(0L, [long]$v.Differences) + [Math]::Max(0L, [long]$ch.Differences) + [Math]::Max(0L, [long]$sg.Differences) + [Math]::Max(0L, [long]$kf.Differences)
                $sayOutcome = { param($o) switch ($o.Outcome) { 'same' { 'the same' } 'not-ready' { 'not checked (no stored build of the pair or no change set yet)' } 'failed' { ('not finished ({0}) -- made again next run' -f $o.Detail) } default { ('{0:N0} difference(s)' -f $o.Differences) } } }
                $warn = $v.Differences -gt 0 -or $ch.Differences -gt 0 -or $sg.Differences -gt 0 -or $kf.Differences -gt 0 -or @($ch, $sg, $kf | Where-Object { $_.Outcome -eq 'failed' }).Count -gt 0
                & $say $(if ($warn) { 'WARN' } else { 'OK' }) ("history     : the collection of {0} compared row for row with the stored rows: {1}; from the change set -- what changed (findings and CIs): {2}; the summary groups ({3:N0} group row(s) computed again, the rest carried): {4}; the key figures ({5:N0} figure(s) carried): {6} (the checks took {7:N0} s: {8:N0} / {9:N0} / {10:N0})" -f $whenText, $vText, (& $sayOutcome $ch), [long]$sg.Recomputed, (& $sayOutcome $sg), [long]$kf.Carried, (& $sayOutcome $kf), ($ck.Seconds.Changes + $ck.Seconds.SummaryGroups + $ck.Seconds.KeyFigures), $ck.Seconds.Changes, $ck.Seconds.SummaryGroups, $ck.Seconds.KeyFigures)
            } catch {
                $err = Get-SIDataChangedSetSafeError $_
                try { $null = & $Invoke "SET NOCOUNT ON; UPDATE sidata.HistoryRun SET State = CASE WHEN State = N'writing' THEN N'writing' ELSE N'failed' END, Diff = @T WHERE CollectionId = CONVERT(int, @C);" @{ C = [string]$cid; T = $err } 'nonquery' } catch { }
                throw
            }
        }
        if ($stopped) { $res.Status = 'progress' }
        if ($OutsideRun) {
            $vk = [long](& $Invoke "SET NOCOUNT ON; SELECT COUNT_BIG(*) FROM sidata.HistoryRun AS h JOIN sidata.Collection AS c ON c.CollectionId = h.CollectionId WHERE h.State = N'verified' AND c.Kind = N'Detailed' AND c.Status = N'Complete' AND c.RetiredAt IS NULL;" @{} 'scalar')
            & $say 'INFO' ("history     : migration -- {0} of {1} kept collection(s) verified by checksum{2}" -f $vk, ($pending.Count), $(if ($stopped) { '; the rest goes on in the next window' } elseif ($vk -lt $pending.Count) { '' } else { '; nothing waits' }))
        } else {
            try { $null = Invoke-SIDataHistoryRetention -Invoke $Invoke -Days $Days -Log $Log } catch { & $say 'WARN' ("history     : the history's retention was not done this run ({0}); it is tried again next run" -f (Get-SIDataChangedSetSafeError $_)) }
        }
    } catch {
        # the whole error stays in this process only (a test reads it; never logged, recorded or sent: it can quote a value)
        $script:SIDataHistoryLastError = $_
        $res.Status = 'failed'; $res.Error = Get-SIDataChangedSetSafeError $_
        & $say 'WARN' ("history     : the finding history was not completed this run -- {0}. The stored rows and the full builds serve as before; it goes on from where it stopped next run." -f $res.Error)
    }
    $res.Differing = $differing.ToArray()
    $res.Lines = $lines.ToArray()
    [pscustomobject]$res
}
