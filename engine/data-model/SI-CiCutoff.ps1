#Requires -Version 5.1
<#
    #1100 THE ONE-TIME CI CUT-OFF (owner 2026-11-04: "is it possible that we can do a one-time cut-off and then ignore older
    runs? i accept the ci cut-off but just to get all 4 in a completed state" / "i dont think we should expose the setting,
    but leave it as an hidden feature for customer to run from a script or through support app").

    WHY: the CI build groups every record collected within its look-back (SI_ActiveStaleDays, default 30). A record an old
    collection left behind -- accounts a setting now leaves out, no longer collected -- stays "current" for that whole
    window, so a large install rebuilds CIs from records nobody collects any more.

    THE STATE: ONE row in cfg.InstallState, Name 'CiCutoff', Value = compact JSON { cutoffUtc, setBy, reason, setUtc } (and
    cleared = true once -Clear took it back; the row is kept, it is the record). HIDDEN on purpose: not a setting (not in
    config\settings.catalog.locked.json, not on the web Settings page, not over MCP). Written only by
    setup\Set-SICiCutoff.ps1 (directly, or through the Invardia Support app's audited SQL) -- Get-SICiCutoffWriteSql is
    that ONE statement.

    THE RULE (the CI build, SI-CiBuildSql.ps1 / SI-CiBuildRun.ps1, Resolve-SICiCutoff):
      * in force while cutoffUtc lies inside the look-back (newer than now - LookbackDays) and not in the future. Then the
        look-back's lower bound is MAX(now - LookbackDays, cutoffUtc): a record collected BEFORE the cut-off is not current
        (not grouped) -- but only for a FEED (provider + record type) that has been collected again at or after the
        cut-off (Get-SICiCutoffFeedSql): a source that has not collected since keeps its records until it has, so a
        cut-off set a minute before the next collection never empties a source.
      * a CI that is not retired, that no current record builds any more, that has a record of the look-back collected
        before the cut-off and NO record collected at or after it, is RETIRED AT ONCE (Get-SICiCutoffRetireSql) -- never
        deleted; si_lifecycle_reason "one-time cut-off <date>: <reason>", recorded in sidata.CiChange. A CI one record
        collected after the cut-off still builds stays active. Records are never deleted here (retention cleans them).
      * once cutoffUtc is older than the look-back it changes nothing any more: the build ignores it and says so in one
        line. It is NOT removed (the row is the record).
    PURE apart from the SQL text. PowerShell 5.1: no ?. / ??, no ternary.
#>

$script:SICiCutoff = @{
    StateName = 'CiCutoff'
    # cfg.InstallState.Value is NVARCHAR(400)
    MaxValue  = 400
}

function ConvertTo-SICiCutoffSqlTime {
    <# PURE. A [datetime] (UTC) as a T-SQL DATETIME2(3) expression -- built from a [datetime], never from text a person typed. #>
    param([Parameter(Mandatory)][datetime]$Utc)
    $u = if ($Utc.Kind -eq [DateTimeKind]::Local) { $Utc.ToUniversalTime() } else { $Utc }
    "CONVERT(DATETIME2(3), '{0}', 126)" -f $u.ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
}

function Format-SICiCutoffTime {
    <# PURE. The cut-off as people read it: 2026-11-04 08:00 UTC. #>
    param([Parameter(Mandatory)][datetime]$Utc)
    $Utc.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function ConvertTo-SICiCutoffValue {
    <# PURE. The state row's value: compact JSON, at most 400 characters (the reason is shortened first, then who set it). #>
    param([Parameter(Mandatory)][datetime]$CutoffUtc, [string]$Reason = '', [string]$SetBy = '', [Parameter(Mandatory)][datetime]$SetUtc, [switch]$Cleared)
    $iso = { param([datetime]$d) $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $why = ([string]$Reason).Trim(); $by = ([string]$SetBy).Trim()
    if ($by.Length -gt 120) { $by = $by.Substring(0, 120) }
    while ($true) {
        $o = [ordered]@{ cutoffUtc = (& $iso $CutoffUtc); setBy = $by; reason = $why; setUtc = (& $iso $SetUtc) }
        if ($Cleared) { $o['cleared'] = $true }
        $j = ConvertTo-Json -InputObject $o -Compress
        $over = $j.Length - $script:SICiCutoff.MaxValue
        if ($over -le 0) { return $j }
        if ($why.Length -gt 0) { $why = $why.Substring(0, [Math]::Max(0, $why.Length - $over)).TrimEnd() }
        elseif ($by.Length -gt 0) { $by = $by.Substring(0, [Math]::Max(0, $by.Length - $over)) }
        else { throw 'the cut-off could not be written in 400 characters' }
    }
}

function ConvertFrom-SICiCutoffValue {
    <# PURE. The state row's value -> @{ CutoffUtc; Reason; SetBy; SetUtc; Cleared }, or $null (no row, unreadable, no cutoffUtc). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { $o = $Value | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if ($null -eq $o -or -not $o.PSObject.Properties['cutoffUtc']) { return $null }
    $parse = {
        param($v)
        if ($null -eq $v) { return $null }
        if ($v -is [datetime]) { return $v.ToUniversalTime() }
        $d = [datetime]::MinValue
        if ([datetime]::TryParse([string]$v, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal), [ref]$d)) { return $d }
        $null
    }
    $cut = & $parse $o.cutoffUtc
    if ($null -eq $cut) { return $null }
    [pscustomobject]@{
        CutoffUtc = [datetime]::SpecifyKind($cut, [DateTimeKind]::Utc)
        Reason    = $(if ($o.PSObject.Properties['reason']) { [string]$o.reason } else { '' })
        SetBy     = $(if ($o.PSObject.Properties['setBy']) { [string]$o.setBy } else { '' })
        SetUtc    = $(if ($o.PSObject.Properties['setUtc']) { & $parse $o.setUtc } else { $null })
        Cleared   = [bool]($o.PSObject.Properties['cleared'] -and $o.cleared -eq $true)
    }
}

function Resolve-SICiCutoff {
    <#
        PURE. Whether the cut-off is in force for a build at -Now with -LookbackDays. -State: ConvertFrom-SICiCutoffValue.
        Answers @{ Set; Applied; Expired; Future; Cleared; CutoffUtc; Reason; Line } -- Line = the one line the build says
        when it is set but not applied ('' otherwise).
    #>
    param($State, [Parameter(Mandatory)][datetime]$Now, [int]$LookbackDays = 30)
    $out = [pscustomobject]@{ Set = $false; Applied = $false; Expired = $false; Future = $false; Cleared = $false; CutoffUtc = $null; Reason = ''; Line = '' }
    if ($null -eq $State) { return $out }
    if ($State.Cleared) { $out.Cleared = $true; return $out }
    if ($LookbackDays -le 0) { $LookbackDays = 30 }
    $out.Set = $true; $out.CutoffUtc = $State.CutoffUtc; $out.Reason = [string]$State.Reason
    $nowU = $Now.ToUniversalTime()
    if ($State.CutoffUtc -le $nowU.AddDays(-$LookbackDays)) {
        $out.Expired = $true
        $out.Line = 'CIs: the one-time CI cut-off has passed the look-back window -- no longer applied (cut-off {0}, look-back {1} day(s); the record is kept).' -f (Format-SICiCutoffTime $State.CutoffUtc), $LookbackDays
        return $out
    }
    if ($State.CutoffUtc -gt $nowU) {
        $out.Future = $true
        $out.Line = 'CIs: the one-time CI cut-off {0} is in the future -- not applied.' -f (Format-SICiCutoffTime $State.CutoffUtc)
        return $out
    }
    $out.Applied = $true
    $out
}

function Get-SICiCutoffReadSql {
    <# The state row (no table, no row = no answer). #>
    "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'$($script:SICiCutoff.StateName)';"
}

function Read-SICiCutoff {
    <#
        The build's read of the state through its SQL seam ({ param($Sql, $Params, $Mode) }). Answers Resolve-SICiCutoff's
        object. A read that fails = not applied this build, said in -Log (never a failed build).
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][datetime]$Now, [int]$LookbackDays = 30, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) } }
    try {
        $rows = @(& $Sql (Get-SICiCutoffReadSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        $v = $null
        if ($rows.Count -gt 0) {
            $r = $rows[0]
            if ($r -is [string]) { $v = $r }
            elseif ($r -is [System.Collections.IDictionary]) { $v = [string]$r['Value'] }
            elseif ($r.PSObject.Properties['Value']) { $v = [string]$r.Value }
        }
        Resolve-SICiCutoff -State (ConvertFrom-SICiCutoffValue -Value $v) -Now $Now -LookbackDays $LookbackDays
    } catch {
        & $Log 'WARN' ('CIs: the one-time CI cut-off could not be read ({0}) -- not applied this build.' -f $_.Exception.Message)
        Resolve-SICiCutoff -State $null -Now $Now -LookbackDays $LookbackDays
    }
}

function Get-SICiCutoffFeedSql {
    <#
        The feeds (provider + record type) collected again at or after the cut-off, into @cutFeeds -- only their records
        before the cut-off are left out. -CutoffUtc $null = the empty declaration (no cut-off).
    #>
    param([AllowNull()]$CutoffUtc)
    $d = 'DECLARE @cutFeeds TABLE (Provider NVARCHAR(32) NOT NULL, RecordType NVARCHAR(32) NOT NULL, PRIMARY KEY (Provider, RecordType));'
    if ($null -eq $CutoffUtc) { return $d }
    $c = ConvertTo-SICiCutoffSqlTime -Utc ([datetime]$CutoffUtc)
    @"
$d
DECLARE @cut DATETIME2(3) = $c;
INSERT @cutFeeds (Provider, RecordType) SELECT DISTINCT Provider, ISNULL(RecordType, N'') FROM sidata.CiRecord WHERE CollectionTime >= @cut;
"@
}

function Get-SICiCutoffKeepClause {
    <# PURE. The predicate a record (alias -Alias) must ALSO meet to be current while the cut-off is in force ('' = none). #>
    param([AllowNull()]$CutoffUtc, [string]$Alias = 'r', [string]$Feeds = '@cutFeeds')
    if ($null -eq $CutoffUtc) { return '' }
    " AND ($Alias.CollectionTime >= @cut OR NOT EXISTS (SELECT 1 FROM $Feeds cf WHERE cf.Provider = $Alias.Provider AND cf.RecordType = ISNULL($Alias.RecordType, N'')))"
}

# the feeds collected again since the cut-off as a derived table -- the read-only plan fills no table variable
$script:SICiCutoffFeedsDerived = "(SELECT DISTINCT Provider, ISNULL(RecordType, N'') AS RecordType FROM sidata.CiRecord WHERE CollectionTime >= @cut)"

function Get-SICiCutoffRetireSql {
    <#
        AFTER A BUILD THAT FINISHED, while the cut-off is in force (after the merged-CI retire, before the retire brake):
        a CI that is not retired, that NO current record builds (no record of the grouping -- sidata.CiGroupMember --
        points to it), with a record of the look-back that has a strong identifier and was collected BEFORE the cut-off,
        and NO record at all collected at or after it, is RETIRED AT ONCE -- never deleted: Lifecycle and the document say
        'retired', si_lifecycle_reason "one-time cut-off <date>: <reason>", the content hash is cleared (recorded again,
        a CI is rebuilt whole, active), the change is recorded (sidata.CiChange). @run = the run id, @cutReason = the
        reason. Answers Retired.
        -PlanOnly: the same choice, READ ONLY (the script's plan): answers Retired = how many would retire now, and
        UpperBound = how many would once every source has collected again after the cut-off.
    #>
    param([Parameter(Mandatory)][datetime]$CutoffUtc, [int]$LookbackDays = 30, [switch]$PlanOnly)
    if ($LookbackDays -le 0) { $LookbackDays = 30 }
    $label = 'one-time cut-off ' + (Format-SICiCutoffTime $CutoffUtc)
    $feeds = Get-SICiCutoffFeedSql -CutoffUtc $CutoffUtc
    $keep = Get-SICiCutoffKeepClause -CutoffUtc $CutoffUtc -Alias 'r'
    $current = "r.CollectionTime >= @lb AND ISNULL(r.RecordType, N'') <> N'cmdb_ci' AND EXISTS (SELECT 1 FROM sidata.RecordIdentifier ri WHERE ri.RecordKey = r.RecordKey)$keep"
    $cand = @"
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, N'') <> N'retired'
  AND EXISTS (SELECT 1 FROM sidata.CiRecord r0 WHERE r0.CiId = c.CiId AND r0.CollectionTime >= @lb AND r0.CollectionTime < @cut
              AND ISNULL(r0.RecordType, N'') <> N'cmdb_ci' AND EXISTS (SELECT 1 FROM sidata.RecordIdentifier ri0 WHERE ri0.RecordKey = r0.RecordKey))
  AND NOT EXISTS (SELECT 1 FROM sidata.CiRecord r1 WHERE r1.CiId = c.CiId AND r1.CollectionTime >= @cut)
"@
    if ($PlanOnly) {
        # READ ONLY (no statement but SELECT -- not even a table variable is filled): the grouping as the build would make it
        # with the cut-off (the same current-record rule), not CiGroupMember
        $d = $script:SICiCutoffFeedsDerived
        $c = ConvertTo-SICiCutoffSqlTime -Utc $CutoffUtc
        $currentRo = "r.CollectionTime >= @lb AND ISNULL(r.RecordType, N'') <> N'cmdb_ci' AND EXISTS (SELECT 1 FROM sidata.RecordIdentifier ri WHERE ri.RecordKey = r.RecordKey)" + (Get-SICiCutoffKeepClause -CutoffUtc $CutoffUtc -Alias 'r' -Feeds $d)
        return @"
SET NOCOUNT ON;
DECLARE @lb DATETIME2(3) = DATEADD(day, -$LookbackDays, SYSUTCDATETIME());
DECLARE @cut DATETIME2(3) = $c;
SELECT
  (SELECT COUNT(*) $cand
      AND NOT EXISTS (SELECT 1 FROM sidata.CiRecord r WHERE r.CiId = c.CiId AND $currentRo)) AS Retired,
  (SELECT COUNT(*) $cand) AS UpperBound,
  (SELECT COUNT(*) FROM sidata.CiRecord r WHERE r.CollectionTime >= @lb AND r.CollectionTime < @cut AND ISNULL(r.RecordType, N'') <> N'cmdb_ci'
      AND EXISTS (SELECT 1 FROM $d cf WHERE cf.Provider = r.Provider AND cf.RecordType = ISNULL(r.RecordType, N''))) AS RecordsIgnored,
  (SELECT COUNT(*) FROM (SELECT DISTINCT Provider, ISNULL(RecordType, N'') AS RecordType FROM sidata.CiRecord WHERE CollectionTime >= @lb AND CollectionTime < @cut) f
      WHERE NOT EXISTS (SELECT 1 FROM $d cf WHERE cf.Provider = f.Provider AND cf.RecordType = f.RecordType)) AS FeedsWaiting;
"@
    }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @lb DATETIME2(3) = DATEADD(day, -$LookbackDays, SYSUTCDATETIME());
$feeds
DECLARE @why NVARCHAR(1000) = LEFT(N'${label}: ' + ISNULL(@cutReason, N''), 1000);
DECLARE @r TABLE (CiId NVARCHAR(64) NOT NULL PRIMARY KEY, OldLifecycle NVARCHAR(16) NULL);
INSERT @r (CiId, OldLifecycle)
SELECT c.CiId, c.Lifecycle $cand
  AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE r.CiId = c.CiId);
BEGIN TRANSACTION;
IF OBJECT_ID('sidata.CiChange') IS NOT NULL
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT x.CiId, N'si_lifecycle', x.OldLifecycle, N'retired', N'ci_build', LEFT(@why, 512), LEFT(@run, 64)
    FROM @r x;
UPDATE c SET Lifecycle = N'retired', ContentHash = NULL, UpdatedAt = SYSUTCDATETIME(),
       DocJson = CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_MODIFY(JSON_MODIFY(JSON_MODIFY(c.DocJson, '`$.si_lifecycle', N'retired'),
                      '`$.si_lifecycle_since', CONVERT(NVARCHAR(30), SYSUTCDATETIME(), 127) + N'Z'),
                      '`$.si_lifecycle_reason', @why)
                 ELSE c.DocJson END
FROM sidata.Ci c JOIN @r x ON x.CiId = c.CiId /* one-statement-ok: only the CIs this cut-off retires (@r) */;
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM @r) AS Retired;
"@
}

function Format-SICiCutoffBuildLine {
    <# PURE. The one line a build says while the cut-off is in force. #>
    param([Parameter(Mandatory)][datetime]$CutoffUtc, [string]$Reason, [int]$Ignored, [int]$Retired, [switch]$DryRun)
    'CIs: one-time CI cut-off {0} ({1}): {2} record(s) before it ignored, {3} CI(s) retired{4}' -f (Format-SICiCutoffTime $CutoffUtc), $(if ($Reason) { $Reason } else { 'no reason given' }), $Ignored, $Retired, $(if ($DryRun) { ' -- DRY RUN, nothing retired' } else { '' })
}

function Get-SICiCutoffWriteSql {
    <#
        THE ONE WRITE of the state row (setup\Set-SICiCutoff.ps1, and the same text through the Invardia Support app):
        @Value = ConvertTo-SICiCutoffValue, @By = who. Inserts or updates cfg.InstallState 'CiCutoff' and READS IT BACK:
        Outcome Written | NoTable, Value (as stored), Old (the value before). Never a DELETE: -Clear writes cleared = true.
    #>
    $n = $script:SICiCutoff.StateName
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL BEGIN SELECT N'NoTable' AS Outcome, CAST(NULL AS NVARCHAR(400)) AS Value, CAST(NULL AS NVARCHAR(400)) AS Old; RETURN; END;
BEGIN TRANSACTION;
DECLARE @old NVARCHAR(400) = (SELECT Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'$n');
IF @old IS NULL AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$n')
    INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'$n', LEFT(@Value, 400), NULL, LEFT(@By, 256));
ELSE
    UPDATE cfg.InstallState SET Value = LEFT(@Value, 400), UpdatedAt = SYSUTCDATETIME(), UpdatedBy = LEFT(@By, 256) WHERE Name = N'$n';
COMMIT TRANSACTION;
SELECT N'Written' AS Outcome, s.Value, @old AS Old FROM cfg.InstallState s WHERE s.Name = N'$n';
"@
}
