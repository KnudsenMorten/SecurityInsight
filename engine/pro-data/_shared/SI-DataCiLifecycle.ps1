#Requires -Version 5.1
<#
    SecurityInsight -- FINDINGS PER CI WITH THEIR LIFECYCLE, AND THE CI TREND (#464, V3-DATA-MODEL 2.8.2 / 2.8.3), set-based in
    the install database after the data sync stored the newest findings (sidata.CiFinding, from SI_Finding_CL -- Risk
    Analysis's findings, already DE-DUPLICATED per (CI, finding key): the same CVE from Defender vulnerability management,
    Exposure Graph and a scanner on one CI is ONE finding, every report that found it in si_detected_by, RA-Findings.ps1).

      LIFECYCLE   sidata.CiFindingState, one row per (owner, finding key) -- owner = the CI, or 'asset:<id>' when no CI holds
                  the finding: first detected, last seen, open | reopened | closed, close reason. A finding seen again after a
                  close is REOPENED (counted). A finding absent from SI_VulnSync_CloseAfterRuns (default 2) COMPLETE Risk
                  Analysis runs in a row closes: asset_retired (its CI is retired), no_longer_monitored (its CI is not seen /
                  gone from the database), rekeyed (a finding under an asset key that this collection reports under a CI
                  instead -- proven by the stored findings: the CI's finding names the same asset id and finding key; a
                  change of key, not a fix; an empty CI id counts as none), report changed (#690 (34): a report that found it asks something else now -- its
                  query fingerprint, sidata.RaReportStatus QueryHash, differs from the one at the finding's last sighting, or
                  the report is no longer run -- so its absence says nothing about a fix) or remediated. An INCOMPLETE run (or one whose completeness cannot be shown) changes
                  nothing -- unknown never closes (the vulnerability loop's rule, Test-SIVulnSnapshotComplete). The same
                  collection twice is processed once (sidata.CiBuildState FindingStateSnapshot).
      TREND       sidata.CiDaily of today: open findings by severity and the risk-factor count (the new columns; a database
                  the updater has not updated yet skips them); #495 the CI's lifecycle, internet exposure, services, the
                  criticality it inherits, its active relations and its overdue / exempted findings.
      HISTORY     #495 every finding opened, reopened or closed on a CI is a sidata.CiChange row (field 'finding').
      ONE MODEL   #494 the lifecycle row joined with what the other parts know of the finding (Get-SIDataFindingModelSql):
                  type and title, owner (the CI's most critical service's owner, else its CMDB owner, else its own owner),
                  the services it inherits, the SLA by severity (SI_Pro_FindingSla_<severity>Days) and the due date, the
                  exemption (reason, expiry), the close-loop ticket (vuln.VulnerabilityItem) and Excluded (#533: a disabled
                  asset left out by a setting -- kept as it was). Read through sidata.vCiFindingModel / vServiceFinding.
      RETENTION   sidata.CiChange older than SI_Pro_CiChangeRetentionDays (730), sidata.CiDaily older than
                  SI_Pro_CiDailyRetentionDays (400), closed lifecycle rows older than SI_Pro_FindingStateRetentionDays (365).

    Every statement is guarded: a database without the tables answers zeros, never an error. PS 5.1: no ?. / ??.
#>

function ConvertTo-SIDataFindingStateItems {
    <# PURE. The stored-finding items (Invoke-SIDataCiSync's) -> the lifecycle input: owner key, finding key, CI, severity, detectors. #>
    param([AllowEmptyCollection()][object[]]$Items = @())
    foreach ($f in $Items) {
        if ($null -eq $f) { continue }
        $key = [string]$f.FindingKey; if (-not $key) { continue }
        $ci = [string]$f.CiId; $aid = [string]$f.AssetId
        $owner = if ($ci) { $ci } elseif ($aid) { 'asset:' + $aid.ToLowerInvariant() } else { '' }
        if (-not $owner) { continue }
        [ordered]@{ OwnerKey = $owner; FindingKey = $key; CiId = $ci; Severity = [string]$f.Severity; DetectedBy = [string]$f.DetectedBy; ExemptionId = [string]$f.ExemptionId }
    }
}

function ConvertTo-SIDataFindingAliasItems {
    <#
        PURE. #464 -- the key changes the recommendation equivalence made: for every stored finding merged under a canonical
        key, one { o (owner); a (the provider's own key, the alias); c (the canonical key) } per alias. The lifecycle step
        carries an existing row under an alias onto the canonical key (Get-SIDataFindingStateSql -WithEquivalence).
    #>
    param([AllowEmptyCollection()][object[]]$Items = @())
    foreach ($f in $Items) {
        if ($null -eq $f) { continue }
        $key = [string](Get-SIItemValueOrNull $f 'FindingKey'); $al = [string](Get-SIItemValueOrNull $f 'Aliases')
        if (-not $key -or -not $al) { continue }
        $ci = [string](Get-SIItemValueOrNull $f 'CiId'); $aid = [string](Get-SIItemValueOrNull $f 'AssetId')
        $owner = if ($ci) { $ci } elseif ($aid) { 'asset:' + $aid.ToLowerInvariant() } else { '' }
        if (-not $owner) { continue }
        foreach ($a in ($al -split '\s*;\s*')) { if ($a -and $a -ne $key) { [ordered]@{ o = $owner; a = $a; c = $key } } }
    }
}

function Get-SIDataFindingStateSql {
    <#
        The lifecycle step, ONE statement. @j = the newest collection's findings (ConvertTo-SIDataFindingStateItems), @snap = its
        collection time (ISO), @complete = 1 when the producing Risk Analysis run(s) were complete, @closeAfter = complete runs a
        finding must be absent to close. Answers one row: Opened, Seen, Reopened, Closed, Absent, Frozen, Skipped, Carried,
        Repaired. ONE result set, the last statement -- read it with Get-SIDataSeamRows (the seam answers its rows as one array).
        REPAIR -- a collection that was processed before (Skipped = 1) whose findings have no lifecycle record: the missing
        records are added (Repaired), first detected = that collection's time; nothing is counted absent or closed.
        #533 rule 4 -- -WithDisabledOwners: the statement also takes @disabledOwners, a JSON array of OWNER keys (CI id, or
        'asset:<id>') whose asset is disabled and left out by a setting (Get-SIDataFindingFrozenOwners). An open finding of
        such an owner that is absent is FROZEN: no absence counted, never closed (counted in Frozen); enabled again, the same
        row carries on. Without the switch the statement is exactly as before.
        #464 rule 4 -- -WithEquivalence: the statement also takes @equivalence (ConvertTo-SIDataFindingAliasItems): a lifecycle
        row still under a provider's own key that the recommendation equivalence now keys on a canonical id is CARRIED onto
        that key before anything else -- FirstDetected, LastSeen and the reopen count kept, several alias rows folded into
        one (the earliest first detection), never closed and reopened because the key changed (counted in Carried).
    #>
    # #639 -FromStage: the input is read from sidata.CiFindingLifecycleStage (staged in chunks, page by page: the findings as
    # Kind f, the equivalence's key changes as Kind a) instead of @j / @equivalence -- never the whole collection as ONE JSON
    # string in one parameter. Everything else in the statement is the same.
    # -WithFrozenReports (per report): the statement also takes @frozenReports, a JSON array of report names this run could
    # not complete (Resolve-SIReportScopedComplete) -- an absent finding one of them found is FROZEN (counted in Frozen).
    # -Ranged (2026-10-29, with -FromStage): the same statement for ONE OwnerKey range (@RangeLo / @RangeHi, its /*R:..*/
    # markers; Invoke-SIDataFindingStateRanged) -- every lifecycle row and staged finding of an owner is in its owner's range,
    # so each row ends exactly as in the one statement. Each range is its own transaction and writes its mark (the snapshot
    # and the last owner key done, sidata.CiBuildState) in it; only the LAST range moves FindingStateSnapshot. A range run
    # again for the same snapshot (a statement retried after its commit) writes nothing; an absence is counted only on a
    # row this snapshot has not touched yet (LastSnapshot < @t) -- a finding closes one run later at worst, never earlier.
    param([switch]$WithDisabledOwners, [switch]$WithEquivalence, [switch]$FromStage, [switch]$WithFrozenReports, [switch]$Ranged)
    $sql = @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.CiFindingState') IS NULL
BEGIN
    SELECT 0 AS Opened, 0 AS Seen, 0 AS Reopened, 0 AS Closed, 0 AS Absent, 0 AS Frozen, 1 AS Skipped, N'no table' AS Note;
    RETURN;
END
DECLARE @t DATETIME2(3) = TRY_CONVERT(DATETIME2(3), @snap, 127);
DECLARE @last DATETIME2(3) = (SELECT TOP 1 TRY_CONVERT(DATETIME2(3), Value, 127) FROM sidata.CiBuildState WHERE Name = N'FindingStateSnapshot');
IF @t IS NULL OR (@last IS NOT NULL AND @t <= @last)
BEGIN
    -- REPAIR: the collection was processed before, yet a finding of it has no lifecycle record -- it gets one now (first
    -- detected = the collection's time). Only records are ADDED: nothing is counted absent, nothing is closed or reopened.
    DECLARE @missing INT = 0;
    IF @t IS NOT NULL AND @t = @last
    BEGIN
        INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot, AbsentRuns, Severity, DetectedBy, ExemptionId)
        SELECT LEFT(x.OwnerKey, 450), LEFT(x.FindingKey, 256), NULLIF(MAX(x.CiId), N''), N'open', @t, @t, @t, 0, MAX(x.Severity), LEFT(MAX(x.DetectedBy), 2000), NULLIF(MAX(x.ExemptionId), N'')
        FROM OPENJSON(@j) WITH (OwnerKey NVARCHAR(MAX), FindingKey NVARCHAR(MAX), CiId NVARCHAR(64), Severity NVARCHAR(16), DetectedBy NVARCHAR(MAX), ExemptionId NVARCHAR(64)) x
        WHERE x.OwnerKey IS NOT NULL AND x.FindingKey IS NOT NULL/*R:x.OwnerKey*/
          AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState s WHERE s.OwnerKey = LEFT(x.OwnerKey, 450) AND s.FindingKey = LEFT(x.FindingKey, 256))
        GROUP BY LEFT(x.OwnerKey, 450), LEFT(x.FindingKey, 256);
        SET @missing = @@ROWCOUNT;
    END
    SELECT 0 AS Opened, 0 AS Seen, 0 AS Reopened, 0 AS Closed, 0 AS Absent, 0 AS Frozen, 1 AS Skipped, N'collection already processed' AS Note, 0 AS Carried, @missing AS Repaired;
    RETURN;
END
DECLARE @after INT = TRY_CONVERT(INT, @closeAfter); IF @after IS NULL OR @after < 1 SET @after = 2;/*RSKIP*/
-- the collection's findings: a #temp table (it has statistics -- the table variable this was planned every join below as
-- one row, at a large install 1.47 million), keyed as before; in the database's collation, as the table variable was
IF OBJECT_ID('tempdb..#lcf') IS NOT NULL DROP TABLE #lcf;
CREATE TABLE #lcf (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT,
    Severity NVARCHAR(16) COLLATE DATABASE_DEFAULT, DetectedBy NVARCHAR(2000) COLLATE DATABASE_DEFAULT, ExemptionId NVARCHAR(64) COLLATE DATABASE_DEFAULT,
    PRIMARY KEY (OwnerKey, FindingKey));
-- an empty CI id is NO CI id: '' is not NULL, and a finding no CI holds kept '' as its CI and closed as 'no longer
-- monitored' (no CI row has the id '') instead of with its real reason
INSERT #lcf SELECT LEFT(x.OwnerKey, 450), LEFT(x.FindingKey, 256), NULLIF(MAX(x.CiId), N''), MAX(x.Severity), LEFT(MAX(x.DetectedBy), 2000), MAX(x.ExemptionId)
FROM OPENJSON(@j) WITH (OwnerKey NVARCHAR(MAX), FindingKey NVARCHAR(MAX), CiId NVARCHAR(64), Severity NVARCHAR(16), DetectedBy NVARCHAR(MAX), ExemptionId NVARCHAR(64)) x
WHERE x.OwnerKey IS NOT NULL AND x.FindingKey IS NOT NULL/*R:x.OwnerKey*/
GROUP BY LEFT(x.OwnerKey, 450), LEFT(x.FindingKey, 256);
DECLARE @opened INT = 0, @seen INT = 0, @reopened INT = 0, @closed INT = 0, @absent INT = 0, @frozen INT = 0;
DECLARE @fz TABLE (OwnerKey NVARCHAR(450) NOT NULL PRIMARY KEY);
/*SI_DISABLED_OWNERS*/
-- per report: the reports this run could not complete -- an absent finding one of them found (or one that names no report)
-- is FROZEN like a left-out asset's: no absence counted, never closed
DECLARE @fr TABLE (Name NVARCHAR(256) NOT NULL PRIMARY KEY);
/*SI_FROZEN_REPORTS*/
DECLARE @carried INT = 0;
-- #690 (34) REPORT CHANGED: per LastSeen of an open finding, the reports whose query fingerprint (sidata.RaReportStatus
-- QueryHash) at this collection differs from the one recorded at the latest earlier collection up to that LastSeen -- or
-- that are not in this collection at all while it recorded fingerprints (the report was removed). An absent finding one of
-- them found closes as 'report changed', never 'remediated'. Unknown (no fingerprint on either side) = as before.
-- #692 A STRUCTURE-ONLY CHANGE IS NOT A CHANGE: a report whose fingerprint now CARRIES the one at the finding's last
-- sighting (sidata.RaReportStatus QueryHashCarry -- the fingerprint it had before a declared structure-only change, the
-- owner's one-time change of 2026-10-19) asks the same as before: its findings keep their history and close only as they
-- would have. A database without the column reads as before.
DECLARE @rc TABLE (Seen DATETIME2(3) NOT NULL, Name NVARCHAR(256) NOT NULL, PRIMARY KEY (Seen, Name));
DECLARE @rcCarry NVARCHAR(200) = CASE WHEN COL_LENGTH('sidata.RaReportStatus', 'QueryHashCarry') IS NOT NULL THEN N'MAX(r.QueryHashCarry)' ELSE N'CAST(NULL AS NVARCHAR(400))' END;
DECLARE @rcSql NVARCHAR(MAX) = N'
;WITH seen AS (SELECT DISTINCT s.LastSeen AS Seen FROM sidata.CiFindingState s WHERE s.State <> N''closed'' AND s.LastSeen < @t/*R:s.OwnerKey*/),
cur AS (SELECT r.ReportName, MAX(r.QueryHash) AS H, ' + @rcCarry + N' AS C FROM sidata.RaReportStatus r
        WHERE r.Grain = N''Detailed'' AND r.CollectionTime BETWEEN DATEADD(second, -5, @t) AND DATEADD(second, 5, @t) GROUP BY r.ReportName),
prev AS (SELECT x.Seen, p.ReportName, p.QueryHash FROM seen x
         CROSS APPLY (SELECT r.ReportName, r.QueryHash, ROW_NUMBER() OVER (PARTITION BY r.ReportName ORDER BY r.CollectionTime DESC) AS rn
                      FROM sidata.RaReportStatus r
                      WHERE r.Grain = N''Detailed'' AND r.QueryHash IS NOT NULL AND r.CollectionTime <= DATEADD(second, 5, x.Seen)
                        AND r.CollectionTime < DATEADD(second, -5, @t) AND r.CollectionTime >= DATEADD(day, -400, x.Seen)) p
         WHERE p.rn = 1)
SELECT DISTINCT p.Seen, LEFT(p.ReportName, 256) FROM prev p LEFT JOIN cur c ON c.ReportName = p.ReportName
WHERE (c.ReportName IS NOT NULL AND c.H IS NOT NULL AND c.H <> p.QueryHash
       AND NOT (c.C IS NOT NULL AND CHARINDEX(N'';'' + p.QueryHash + N'';'', N'';'' + REPLACE(c.C, N'' '', N'''') + N'';'') > 0))
   OR (c.ReportName IS NULL AND EXISTS (SELECT 1 FROM cur WHERE cur.H IS NOT NULL));';
IF @complete = N'1' AND OBJECT_ID('sidata.RaReportStatus') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'QueryHash') IS NOT NULL
    INSERT @rc EXEC sp_executesql @rcSql, N'@t DATETIME2(3)/*RPL*/', @t = @t/*RPV*/;
/*SI_EQUIVALENCE_DECL*/
-- #406 OWNER DECISION 2026-10-19 ("Close as asset retired"): the CIs SecurityInsight has RETIRED (sidata.Ci Lifecycle). A
-- finding on such a CI is closed as 'asset_retired' -- also one this collection still reports -- and is neither seen nor
-- reopened while the CI stays retired. A CI that is active again (reactivated) reopens its still-reported findings as usual,
-- the history says 'asset reactivated'.
DECLARE @ret TABLE (CiId NVARCHAR(64) NOT NULL PRIMARY KEY);
IF OBJECT_ID('sidata.Ci') IS NOT NULL INSERT @ret SELECT CiId FROM sidata.Ci WHERE Lifecycle = N'retired';
DECLARE @reo TABLE (OwnerKey NVARCHAR(450) NOT NULL, FindingKey NVARCHAR(256) NOT NULL, WasReason NVARCHAR(64) NULL, PRIMARY KEY (OwnerKey, FindingKey));
DECLARE @retiredClosed INT = 0, @rekeyed INT = 0;
-- REKEYED: an open finding under an asset key ('asset:<id>', no CI) that this collection reports under a CI instead -- the
-- stored finding (sidata.CiFinding) of that CI names the same asset id and the same finding key, and the CI's finding is in
-- this collection. Its absence under the old key is a change of key, not a fix: it closes (after the usual absences) as
-- 'rekeyed', while the CI's own record carries on. Only what the stored findings PROVE; anything else closes as before.
IF OBJECT_ID('tempdb..#rk') IS NOT NULL DROP TABLE #rk;
CREATE TABLE #rk (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, PRIMARY KEY (OwnerKey, FindingKey));
IF @complete = N'1' AND OBJECT_ID('sidata.CiFinding') IS NOT NULL
    INSERT #rk (OwnerKey, FindingKey)
    SELECT DISTINCT s.OwnerKey, s.FindingKey
    FROM sidata.CiFindingState s
    JOIN sidata.CiFinding cf ON cf.FindingKey = s.FindingKey AND NULLIF(cf.CiId, N'') IS NOT NULL AND NULLIF(cf.AssetId, N'') IS NOT NULL
                            AND N'asset:' + LOWER(cf.AssetId) = s.OwnerKey
    JOIN #lcf f ON f.OwnerKey = cf.CiId AND f.FindingKey = cf.FindingKey
    WHERE s.State <> N'closed' AND s.OwnerKey LIKE N'asset:%' AND NULLIF(s.CiId, N'') IS NULL/*R:s.OwnerKey*/
      AND NOT EXISTS (SELECT 1 FROM #lcf x WHERE x.OwnerKey = s.OwnerKey AND x.FindingKey = s.FindingKey);
BEGIN TRANSACTION;
/*SI_EQUIVALENCE*/
-- SEEN AGAIN, in two parts (the end state is the one update of before): the times this collection moves, on every finding
-- seen again; the finding's own values (CI, severity, detectors, exemption) only where one of them differs -- told apart
-- exactly (binary, with the length: a change of case or of a trailing space is a change)
UPDATE s SET LastSeen = @t, LastSnapshot = @t, AbsentRuns = 0
FROM sidata.CiFindingState s JOIN #lcf f ON f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey
WHERE s.State <> N'closed' AND NOT EXISTS (SELECT 1 FROM @ret r WHERE r.CiId = ISNULL(NULLIF(f.CiId, N''), s.CiId));
SET @seen = @@ROWCOUNT;
UPDATE s SET CiId = ISNULL(f.CiId, s.CiId), Severity = f.Severity, DetectedBy = f.DetectedBy, ExemptionId = NULLIF(f.ExemptionId, N'') /* one-statement-ok: the second half of the one seen-again update of before (same rows, only where a value differs), inside the lifecycle's one transaction */
FROM sidata.CiFindingState s JOIN #lcf f ON f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey
WHERE s.State <> N'closed' AND NOT EXISTS (SELECT 1 FROM @ret r WHERE r.CiId = ISNULL(NULLIF(f.CiId, N''), s.CiId))
  AND EXISTS (SELECT s.CiId COLLATE Latin1_General_BIN2, DATALENGTH(s.CiId), s.Severity COLLATE Latin1_General_BIN2, DATALENGTH(s.Severity),
                     s.DetectedBy COLLATE Latin1_General_BIN2, DATALENGTH(s.DetectedBy), s.ExemptionId COLLATE Latin1_General_BIN2, DATALENGTH(s.ExemptionId)
              EXCEPT
              SELECT ISNULL(f.CiId, s.CiId) COLLATE Latin1_General_BIN2, DATALENGTH(ISNULL(f.CiId, s.CiId)), f.Severity COLLATE Latin1_General_BIN2, DATALENGTH(f.Severity),
                     f.DetectedBy COLLATE Latin1_General_BIN2, DATALENGTH(f.DetectedBy), NULLIF(f.ExemptionId, N'') COLLATE Latin1_General_BIN2, DATALENGTH(NULLIF(f.ExemptionId, N'')));
UPDATE s SET State = N'reopened', ReopenedAt = @t, ReopenCount = s.ReopenCount + 1, ClosedAt = NULL, CloseReason = NULL, LastSeen = @t, LastSnapshot = @t, AbsentRuns = 0,
       CiId = ISNULL(f.CiId, s.CiId), Severity = f.Severity, DetectedBy = f.DetectedBy, ExemptionId = NULLIF(f.ExemptionId, N'')
OUTPUT inserted.OwnerKey, inserted.FindingKey, deleted.CloseReason INTO @reo (OwnerKey, FindingKey, WasReason)
FROM sidata.CiFindingState s JOIN #lcf f ON f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey
WHERE s.State = N'closed' AND NOT EXISTS (SELECT 1 FROM @ret r WHERE r.CiId = ISNULL(NULLIF(f.CiId, N''), s.CiId));
SET @reopened = @@ROWCOUNT;
INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot, AbsentRuns, Severity, DetectedBy, ExemptionId)
SELECT f.OwnerKey, f.FindingKey, NULLIF(f.CiId, N''), N'open', @t, @t, @t, 0, f.Severity, f.DetectedBy, NULLIF(f.ExemptionId, N'')
FROM #lcf f WHERE NOT EXISTS (SELECT 1 FROM sidata.CiFindingState s WHERE s.OwnerKey = f.OwnerKey AND s.FindingKey = f.FindingKey)
  AND NOT EXISTS (SELECT 1 FROM @ret r WHERE r.CiId = f.CiId);
SET @opened = @@ROWCOUNT;
-- a NEW finding on a retired CI gets its record, closed as asset_retired at once (it is known, never counted open)
INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot, AbsentRuns, Severity, DetectedBy, ExemptionId, ClosedAt, CloseReason)
SELECT f.OwnerKey, f.FindingKey, f.CiId, N'closed', @t, @t, @t, 0, f.Severity, f.DetectedBy, NULLIF(f.ExemptionId, N''), @t, N'asset_retired'
FROM #lcf f WHERE EXISTS (SELECT 1 FROM @ret r WHERE r.CiId = f.CiId)
  AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState s WHERE s.OwnerKey = f.OwnerKey AND s.FindingKey = f.FindingKey);
SET @retiredClosed = @@ROWCOUNT;
-- every open finding of a retired CI closes now as asset_retired -- still reported or not; a still-reported one records
-- that this collection saw it (LastSeen) -- whatever the run's completeness: the retirement is the CI's decision, not an absence
UPDATE s SET State = N'closed', ClosedAt = @t, CloseReason = N'asset_retired', LastSnapshot = @t, AbsentRuns = 0,
       LastSeen = CASE WHEN EXISTS (SELECT 1 FROM #lcf f WHERE f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey) THEN @t ELSE s.LastSeen END
FROM sidata.CiFindingState s JOIN @ret r ON r.CiId = s.CiId
WHERE s.State <> N'closed'/*R:s.OwnerKey*/;
SET @retiredClosed = @retiredClosed + @@ROWCOUNT;
IF @complete = N'1'
BEGIN
    UPDATE s SET AbsentRuns = s.AbsentRuns + 1, LastSnapshot = @t,
           State = CASE WHEN s.AbsentRuns + 1 >= @after THEN N'closed' ELSE s.State END,
           ClosedAt = CASE WHEN s.AbsentRuns + 1 >= @after THEN @t ELSE s.ClosedAt END,
           CloseReason = CASE WHEN s.AbsentRuns + 1 < @after THEN s.CloseReason
                              WHEN NULLIF(s.CiId, N'') IS NOT NULL AND c.Lifecycle = N'retired' THEN N'asset_retired'
                              WHEN NULLIF(s.CiId, N'') IS NOT NULL AND (c.CiId IS NULL OR c.Lifecycle = N'not_seen') THEN N'no_longer_monitored'
                              -- the same finding is reported under a CI now (proven above) -- a change of key, not a fix
                              WHEN EXISTS (SELECT 1 FROM #rk k WHERE k.OwnerKey = s.OwnerKey AND k.FindingKey = s.FindingKey) THEN N'rekeyed'
                              -- #690 (34): it left because a report that found it changed (or was removed) -- not a fix
                              WHEN EXISTS (SELECT 1 FROM @rc g WHERE g.Seen = s.LastSeen
                                             AND CHARINDEX(N';' + REPLACE(g.Name, N' ', N'') + N';', N';' + REPLACE(ISNULL(s.DetectedBy, N''), N' ', N'') + N';') > 0) THEN N'report changed'
                              ELSE N'remediated' END
    FROM sidata.CiFindingState s LEFT JOIN sidata.Ci c ON c.CiId = s.CiId
    WHERE s.State <> N'closed'/*R:s.OwnerKey*//*ABS*/ AND NOT EXISTS (SELECT 1 FROM #lcf f WHERE f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey)
      AND NOT EXISTS (SELECT 1 FROM @fr r WHERE s.DetectedBy IS NULL OR s.DetectedBy = N'' OR CHARINDEX(N';' + REPLACE(r.Name, N' ', N'') + N';', N';' + REPLACE(s.DetectedBy, N' ', N'') + N';') > 0)
      AND NOT EXISTS (SELECT 1 FROM @fz z WHERE z.OwnerKey = s.OwnerKey);
    SET @absent = @@ROWCOUNT;
    -- #533: absent findings of a disabled, left-out asset are FROZEN -- untouched above (no count, no close)
    SELECT @frozen = COUNT(*) FROM sidata.CiFindingState s
    WHERE s.State <> N'closed'/*R:s.OwnerKey*/ AND NOT EXISTS (SELECT 1 FROM #lcf f WHERE f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey)
      AND EXISTS (SELECT 1 FROM @fz z WHERE z.OwnerKey = s.OwnerKey);
    -- per report: so are the absent findings of a report this run could not complete (counted once)
    SET @frozen = @frozen + (SELECT COUNT(*) FROM sidata.CiFindingState s
        WHERE s.State <> N'closed'/*R:s.OwnerKey*/ AND NOT EXISTS (SELECT 1 FROM #lcf f WHERE f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey)
          AND NOT EXISTS (SELECT 1 FROM @fz z WHERE z.OwnerKey = s.OwnerKey)
          AND EXISTS (SELECT 1 FROM @fr r WHERE s.DetectedBy IS NULL OR s.DetectedBy = N'' OR CHARINDEX(N';' + REPLACE(r.Name, N' ', N'') + N';', N';' + REPLACE(s.DetectedBy, N' ', N'') + N';') > 0));
    SELECT @closed = COUNT(*) FROM sidata.CiFindingState WHERE State = N'closed' AND ClosedAt = @t/*R:OwnerKey*/;
    SELECT @rekeyed = COUNT(*) FROM sidata.CiFindingState WHERE State = N'closed' AND ClosedAt = @t AND CloseReason = N'rekeyed'/*R:OwnerKey*/;
END
ELSE
BEGIN
    SELECT @frozen = COUNT(*) FROM sidata.CiFindingState s
    WHERE s.State <> N'closed'/*R:s.OwnerKey*/ AND NOT EXISTS (SELECT 1 FROM #lcf f WHERE f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey);
    SET @closed = @retiredClosed;
END
-- #495 HISTORY PER CI: every finding opened, reopened or closed on a CI in this collection is a change of the CI
IF OBJECT_ID('sidata.CiChange') IS NOT NULL
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT s.CiId, N'finding',
           CASE WHEN s.ReopenedAt = @t THEN N'closed' WHEN s.State = N'closed' THEN N'open' END,
           CASE WHEN s.State = N'closed' THEN N'closed' WHEN s.ReopenedAt = @t THEN N'reopened' ELSE N'open' END,
           LEFT(s.DetectedBy, 64),
           LEFT(CONCAT(s.FindingKey, CASE WHEN s.State = N'closed' THEN CONCAT(N' -- ', s.CloseReason)
                                          WHEN EXISTS (SELECT 1 FROM @reo o WHERE o.OwnerKey = s.OwnerKey AND o.FindingKey = s.FindingKey AND o.WasReason = N'asset_retired') THEN N' -- asset reactivated'
                                          ELSE N'' END), 512), NULL
    FROM sidata.CiFindingState s
    WHERE NULLIF(s.CiId, N'') IS NOT NULL/*R:s.OwnerKey*/
      AND ((s.FirstDetected = @t AND s.State = N'open' AND s.ReopenCount = 0) OR s.ReopenedAt = @t OR (s.State = N'closed' AND s.ClosedAt = @t));
/*SNAP{*/MERGE sidata.CiBuildState AS b USING (SELECT N'FindingStateSnapshot' AS Name, CONVERT(NVARCHAR(400), @t, 127) AS Value) AS v ON b.Name = v.Name
WHEN MATCHED THEN UPDATE SET Value = v.Value, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (v.Name, v.Value);/*}SNAP*/
COMMIT TRANSACTION;
DROP TABLE #lcf;
DROP TABLE #rk;
SELECT @opened AS Opened, @seen AS Seen, @reopened AS Reopened, @closed AS Closed, @absent AS Absent, @frozen AS Frozen, 0 AS Skipped, N'' AS Note, @carried AS Carried, 0 AS Repaired,
       @retiredClosed AS RetiredClosed, (SELECT COUNT(*) FROM @reo WHERE WasReason = N'asset_retired') AS Reactivated, @rekeyed AS Rekeyed;
'@
    $fill = ''
    if ($WithDisabledOwners) {
        $fill = 'INSERT @fz SELECT DISTINCT LEFT(z.k, 450) FROM OPENJSON(ISNULL(@disabledOwners, N''[]'')) WITH (k NVARCHAR(MAX) ''$'') z WHERE z.k IS NOT NULL AND z.k <> N'''';'
        # #639: or the owner keys staged in chunks (sidata.CiOwnerStage) -- @disabledOwners is then { stage, kind }, never the list
        $fill += "`n" + (Get-SIDataCiOwnerStageFillSql -Table '@fz' -Column 'OwnerKey' -Param '@disabledOwners')
    }
    $eqDecl = ''; $eqStep = ''
    if ($WithEquivalence) {
        # #464 rule 4: a finding the recommendation equivalence now keys on its canonical id keeps its history. @equivalence =
        # [ { o: owner, a: the provider's own key (alias), c: the canonical key } ] (ConvertTo-SIDataFindingAliasItems).
        $eqDecl = @'
DECLARE @eq TABLE (OwnerKey NVARCHAR(450) NOT NULL, Alias NVARCHAR(256) NOT NULL, Canonical NVARCHAR(256) NOT NULL, PRIMARY KEY (OwnerKey, Alias));
INSERT @eq SELECT LEFT(x.o, 450), LEFT(x.a, 256), MAX(LEFT(x.c, 256))
FROM OPENJSON(ISNULL(@equivalence, N'[]')) WITH (o NVARCHAR(MAX), a NVARCHAR(MAX), c NVARCHAR(MAX)) x
WHERE x.o IS NOT NULL AND x.a IS NOT NULL AND x.c IS NOT NULL AND x.a <> x.c/*R:x.o*/
GROUP BY LEFT(x.o, 450), LEFT(x.a, 256);
DECLARE @mv TABLE (OwnerKey NVARCHAR(450) NOT NULL, Alias NVARCHAR(256) NOT NULL, Canonical NVARCHAR(256) NOT NULL, PRIMARY KEY (OwnerKey, Alias));
'@
        $eqStep = @'
-- #464: the lifecycle rows still under a provider's own key that the equivalence now keys on the canonical id
INSERT @mv SELECT s.OwnerKey, s.FindingKey, e.Canonical FROM sidata.CiFindingState s JOIN @eq e ON e.OwnerKey = s.OwnerKey AND e.Alias = s.FindingKey;
IF EXISTS (SELECT 1 FROM @mv)
BEGIN
    -- 1. no row under the canonical key yet: the EARLIEST alias row takes the canonical key (its FirstDetected and state stay)
    ;WITH pick AS (
        SELECT m.OwnerKey, m.Alias, m.Canonical, ROW_NUMBER() OVER (PARTITION BY m.OwnerKey, m.Canonical ORDER BY s.FirstDetected, m.Alias) AS rn
        FROM @mv m JOIN sidata.CiFindingState s ON s.OwnerKey = m.OwnerKey AND s.FindingKey = m.Alias
        WHERE NOT EXISTS (SELECT 1 FROM sidata.CiFindingState c WHERE c.OwnerKey = m.OwnerKey AND c.FindingKey = m.Canonical))
    UPDATE s SET FindingKey = p.Canonical
    FROM sidata.CiFindingState s JOIN pick p ON p.OwnerKey = s.OwnerKey AND p.Alias = s.FindingKey
    WHERE p.rn = 1;
    SET @carried = @@ROWCOUNT;
    DELETE m FROM @mv m WHERE NOT EXISTS (SELECT 1 FROM sidata.CiFindingState s WHERE s.OwnerKey = m.OwnerKey AND s.FindingKey = m.Alias);
    -- 2. the other alias rows fold into the canonical row: the earliest first detection, the latest sighting, the most
    --    reopens; an alias still open keeps the finding open (a closed canonical row is opened again WITHOUT a reopen)
    UPDATE c SET FirstDetected = CASE WHEN a.FirstDetected < c.FirstDetected THEN a.FirstDetected ELSE c.FirstDetected END,
                 LastSeen = CASE WHEN a.LastSeen > c.LastSeen THEN a.LastSeen ELSE c.LastSeen END,
                 ReopenCount = CASE WHEN a.ReopenCount > c.ReopenCount THEN a.ReopenCount ELSE c.ReopenCount END,
                 AbsentRuns = CASE WHEN c.State = N'closed' AND a.OpenN > 0 THEN a.MinAbsent ELSE c.AbsentRuns END,
                 ClosedAt = CASE WHEN c.State = N'closed' AND a.OpenN > 0 THEN NULL ELSE c.ClosedAt END,
                 CloseReason = CASE WHEN c.State = N'closed' AND a.OpenN > 0 THEN NULL ELSE c.CloseReason END,
                 State = CASE WHEN c.State = N'closed' AND a.OpenN > 0 THEN N'open' ELSE c.State END
    FROM sidata.CiFindingState c
    JOIN (SELECT m.OwnerKey, m.Canonical, MIN(s.FirstDetected) AS FirstDetected, MAX(s.LastSeen) AS LastSeen, MAX(s.ReopenCount) AS ReopenCount,
                 SUM(CASE WHEN s.State <> N'closed' THEN 1 ELSE 0 END) AS OpenN, MIN(CASE WHEN s.State <> N'closed' THEN s.AbsentRuns END) AS MinAbsent
          FROM @mv m JOIN sidata.CiFindingState s ON s.OwnerKey = m.OwnerKey AND s.FindingKey = m.Alias
          GROUP BY m.OwnerKey, m.Canonical) a ON a.OwnerKey = c.OwnerKey AND a.Canonical = c.FindingKey;
    DELETE s FROM sidata.CiFindingState s JOIN @mv m ON m.OwnerKey = s.OwnerKey AND m.Alias = s.FindingKey;
    SET @carried = @carried + @@ROWCOUNT;
END
'@
    }
    $frFill = ''
    if ($WithFrozenReports) { $frFill = 'INSERT @fr SELECT DISTINCT LEFT(z.k, 256) FROM OPENJSON(ISNULL(@frozenReports, N''[]'')) WITH (k NVARCHAR(MAX) ''$'') z WHERE z.k IS NOT NULL AND z.k <> N'''';' }
    $out = $sql.Replace('/*SI_DISABLED_OWNERS*/', $fill).Replace('/*SI_FROZEN_REPORTS*/', $frFill).Replace('/*SI_EQUIVALENCE_DECL*/', $eqDecl).Replace('/*SI_EQUIVALENCE*/', $eqStep)
    $out = Convert-SIDataFindingStateRangeText -Sql $out -Ranged:$Ranged
    if ($FromStage) {
        $out = $out.Replace('OPENJSON(@j) WITH (OwnerKey NVARCHAR(MAX), FindingKey NVARCHAR(MAX), CiId NVARCHAR(64), Severity NVARCHAR(16), DetectedBy NVARCHAR(MAX), ExemptionId NVARCHAR(64)) x',
                            "(SELECT OwnerKey, FindingKey, CiId, Severity, DetectedBy, ExemptionId FROM sidata.CiFindingLifecycleStage WHERE Kind = N'f') x")
        $out = $out.Replace("OPENJSON(ISNULL(@equivalence, N'[]')) WITH (o NVARCHAR(MAX), a NVARCHAR(MAX), c NVARCHAR(MAX)) x",
                            "(SELECT OwnerKey AS o, FindingKey AS a, Canonical AS c FROM sidata.CiFindingLifecycleStage WHERE Kind = N'a') x")
    }
    $out
}

function Convert-SIDataFindingStateRangeText {
    <#
        PURE. The lifecycle statement's range markers: without -Ranged every marker goes and the statement is the one of
        before; with -Ranged the range's own parts are written in (the /*R:..*/ predicates stay for Expand-SIDataRangeMarker):
        the skip of a range already done for this snapshot, the absence only on a row this snapshot has not touched yet, the
        rekey's proof read from the staged input (an owner of another range), and the marks instead of the one snapshot move.
    #>
    param([Parameter(Mandatory)][string]$Sql, [switch]$Ranged)
    if (-not $Ranged) {
        return [regex]::Replace($Sql, '/\*(R:[A-Za-z0-9_\.\[\]]+|RPL|RPV|RP|ABS|RSKIP|SNAP\{|\}SNAP)\*/', '')
    }
    $skip = @"

DECLARE @rangeSnap NVARCHAR(400) = (SELECT TOP (1) Value FROM sidata.CiBuildState WHERE Name = N'FindingStateRangeSnap');
DECLARE @rangeKey NVARCHAR(400) = (SELECT TOP (1) Value FROM sidata.CiBuildState WHERE Name = N'FindingStateRangeKey');
IF @rangeSnap = CONVERT(NVARCHAR(400), @snap) AND @RangeHi IS NOT NULL AND @rangeKey >= @RangeHi
BEGIN
    SELECT 0 AS Opened, 0 AS Seen, 0 AS Reopened, 0 AS Closed, 0 AS Absent, 0 AS Frozen, 0 AS Skipped, N'range done' AS Note, 0 AS Carried, 0 AS Repaired,
           0 AS RetiredClosed, 0 AS Reactivated, 0 AS Rekeyed;
    RETURN;
END
"@
    $m = [regex]::Match($Sql, '/\*SNAP\{\*/(?<merge>.*?)/\*\}SNAP\*/', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { throw 'the lifecycle statement is not in the shape its ranges are cut from' }
    $marks = @"
IF @RangeLast = N'1'
BEGIN
$($m.Groups['merge'].Value)
    DELETE FROM sidata.CiBuildState WHERE Name IN (N'FindingStateRangeSnap', N'FindingStateRangeKey');
END
ELSE
    MERGE sidata.CiBuildState AS b USING (SELECT N'FindingStateRangeSnap' AS Name, CONVERT(NVARCHAR(400), @snap) AS Value UNION ALL SELECT N'FindingStateRangeKey', CONVERT(NVARCHAR(400), @RangeHi)) AS v ON b.Name = v.Name
    WHEN MATCHED THEN UPDATE SET Value = v.Value, UpdatedAt = SYSUTCDATETIME()
    WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (v.Name, v.Value);
"@
    $out = $Sql.Substring(0, $m.Index) + $marks + $Sql.Substring($m.Index + $m.Length)
    $join = 'JOIN #lcf f ON f.OwnerKey = cf.CiId AND f.FindingKey = cf.FindingKey'
    if ($out.IndexOf($join) -lt 0) { throw 'the lifecycle statement is not in the shape its ranges are cut from' }
    $out = $out.Replace($join, "JOIN sidata.CiFindingLifecycleStage f ON f.Kind = N'f' AND f.OwnerKey = cf.CiId AND f.FindingKey = cf.FindingKey")
    $out.Replace('/*RSKIP*/', $skip).Replace('/*ABS*/', ' AND s.LastSnapshot < @t')
}

function Get-SIDataCiStagedFrozenOwnersSql {
    <#
        #533 rule 4 with the staged input (#639): the OWNER keys in @freeze (JSON array) that have an OPEN lifecycle row absent
        from this collection (sidata.CiFindingLifecycleStage, Kind f) -- the same answer Get-SIDataFindingFrozenOwners gives
        from the open rows and the items in memory, computed in SQL so neither is held by the job.
    #>
    @'
IF OBJECT_ID('sidata.CiFindingState') IS NULL OR OBJECT_ID('sidata.CiFindingLifecycleStage') IS NULL
    SELECT CAST(NULL AS NVARCHAR(450)) AS OwnerKey WHERE 1 = 0;
ELSE IF ISJSON(@freeze) = 1 AND LEFT(LTRIM(@freeze), 1) = N'{' AND OBJECT_ID('sidata.CiOwnerStage') IS NOT NULL
    SELECT DISTINCT s.OwnerKey
    FROM sidata.CiFindingState AS s
    JOIN (SELECT DISTINCT o.OwnerKey AS k FROM sidata.CiOwnerStage AS o WHERE o.StageId = TRY_CONVERT(uniqueidentifier, JSON_VALUE(@freeze, '$.stage')) AND o.Kind = JSON_VALUE(@freeze, '$.kind')) AS z ON z.k = s.OwnerKey
    WHERE s.State <> N'closed'
      AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingLifecycleStage AS f WHERE f.Kind = N'f' AND f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey);
ELSE
    SELECT DISTINCT s.OwnerKey
    FROM sidata.CiFindingState AS s
    JOIN (SELECT DISTINCT LEFT(z.k, 450) AS k FROM OPENJSON(ISNULL(@freeze, N'[]')) WITH (k NVARCHAR(MAX) '$') z WHERE z.k IS NOT NULL AND z.k <> N'') AS z ON z.k = s.OwnerKey
    WHERE s.State <> N'closed'
      AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingLifecycleStage AS f WHERE f.Kind = N'f' AND f.OwnerKey = s.OwnerKey AND f.FindingKey = s.FindingKey);
'@
}

# =====================================================================================================================
#  #639 THE OWNER KEYS IN ONE STAGING TABLE (sidata.CiOwnerStage), WRITTEN IN CHUNKS: the owners left out (r), the owners
#  whose absent findings may freeze (f) and the owners that freeze this run (o) went to the lifecycle, the one-time repair
#  and the finding model as FOUR JSON parameters, each the whole list. With the table they are staged in chunks and the
#  parameter carries only { "stage": <id>, "kind": <r|f|o> }; a database without the table is sent the list as before.
# =====================================================================================================================

function Get-SIDataCiOwnerStageTableSql {
    <# The staging table (the same text as sql/si-data-schema.sql; additive), then a marker row when it is there. #>
    @'
IF OBJECT_ID(N'sidata.CiOwnerStage') IS NULL
CREATE TABLE sidata.CiOwnerStage (
    StageId   UNIQUEIDENTIFIER NOT NULL,
    Kind      NCHAR(1)         NOT NULL,
    OwnerKey  NVARCHAR(450)    NOT NULL,
    StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_CiOwnerStage_StagedAt DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_CiOwnerStage' AND object_id = OBJECT_ID('sidata.CiOwnerStage'))
    CREATE CLUSTERED INDEX CX_CiOwnerStage ON sidata.CiOwnerStage (StageId, Kind, OwnerKey);
IF OBJECT_ID(N'sidata.CiOwnerStage') IS NOT NULL SELECT N'si-owner-stage' AS Ready;
'@
}

function Get-SIDataCiOwnerStageFillSql {
    <# PURE. The statement line that fills a statement's owner table from the staging table when its parameter is
       { stage, kind } (guarded: a database without the table never runs it). #>
    param([Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Column, [Parameter(Mandatory)][string]$Param)
    ("IF OBJECT_ID('sidata.CiOwnerStage') IS NOT NULL AND ISJSON({2}) = 1 AND LEFT(LTRIM({2}), 1) = N'{{' " +
     "INSERT {0} ({1}) SELECT DISTINCT o.OwnerKey FROM sidata.CiOwnerStage AS o WHERE o.StageId = TRY_CONVERT(uniqueidentifier, JSON_VALUE({2}, '`$.stage')) AND o.Kind = JSON_VALUE({2}, '`$.kind');") -f $Table, $Column, $Param
}

function New-SIDataCiOwnerStage {
    <# A staging of owner keys for one lifecycle run, or $null when the database cannot say it has the table (the lists go as
       parameters as before). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $a = & $Invoke (Get-SIDataCiOwnerStageTableSql) @{} 'reader'
        if (@(@($a) | Where-Object { $_ -is [System.Collections.IDictionary] -and [string]$_['Ready'] -eq 'si-owner-stage' }).Count -eq 0) { return $null }
        # what a run that stopped left behind (a day old)
        while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.CiOwnerStage WHERE StagedAt < DATEADD(day, -1, SYSUTCDATETIME()); SELECT @@ROWCOUNT;' @{} 'scalar') -gt 0) { }
        return @{ Invoke = $Invoke; Id = [guid]::NewGuid().ToString(); Kinds = @{} }
    } catch { return $null }
}

function ConvertTo-SIDataCiOwnerParam {
    <#
        The value of one owner-list parameter: with a staging (-Stage, New-SIDataCiOwnerStage) the keys are written to it in
        chunks of 5,000 under -Kind (once per kind) and the parameter is { "stage": <id>, "kind": <kind> }; without one, the
        JSON array as before.
    #>
    param($Stage, [Parameter(Mandatory)][string]$Kind, [AllowEmptyCollection()][string[]]$Keys = @())
    $ks = @($Keys | Where-Object { $_ })
    if ($null -eq $Stage) { return (ConvertTo-Json -InputObject @($ks) -Compress) }
    if (-not $Stage.Kinds.ContainsKey($Kind)) {
        for ($i = 0; $i -lt $ks.Count; $i += 5000) {
            $part = @($ks[$i..([Math]::Min($i + 5000, $ks.Count) - 1)])
            [void](& $Stage.Invoke "INSERT sidata.CiOwnerStage (StageId, Kind, OwnerKey) SELECT CONVERT(uniqueidentifier, @StageId), @Kind, LEFT(z.k, 450) FROM OPENJSON(@klist) WITH (k NVARCHAR(MAX) '$') z WHERE z.k IS NOT NULL AND z.k <> N'';" @{ StageId = $Stage.Id; Kind = $Kind; klist = (ConvertTo-Json -InputObject ([string[]]$part) -Compress) } 'nonquery')
        }
        $Stage.Kinds[$Kind] = $ks.Count
    }
    ConvertTo-Json -InputObject ([ordered]@{ stage = $Stage.Id; kind = $Kind }) -Compress
}

function Clear-SIDataCiOwnerStage {
    param($Stage)
    if ($null -eq $Stage) { return }
    try { while ([long](& $Stage.Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.CiOwnerStage WHERE StageId = CONVERT(uniqueidentifier, @StageId); SELECT @@ROWCOUNT;' @{ StageId = $Stage.Id } 'scalar') -gt 0) { } } catch { }
}

function Get-SIDataSeamRows {
    <#
        The rows of a statement read through the database seam, ONE BY ONE. The data sync's seam (New-SIDataSqlInvoke) answers
        its rows as ONE array object (', $rows'): '@(& $Invoke ...)' then holds the whole answer as a single item, and a
        caller that reads a column of "the first row" reads nothing -- every count 0, no row of a list. That is how the
        finding lifecycle reported "0 new, 0 seen again" over 12,000 stored findings and how the owners to freeze were never
        found (2026-10-12). A seam that answers the rows themselves (the tests') is read the same way.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, $Params = @{})
    $answer = & $Invoke $Sql $Params 'rows'
    foreach ($x in @($answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [array]) { foreach ($y in $x) { if ($null -ne $y) { $y } } } else { $x }
    }
}

function Get-SIDataFindingFreezeRepairSql {
    <#
        ONE-TIME REPAIR. Until 2026-10-12 the owners whose absent findings must freeze were never found (Get-SIDataSeamRows),
        so the open findings of an asset that is left out (disabled and left out by a setting, or outside the collection
        scope) were counted absent and CLOSED AS FIXED after the usual complete runs -- absence is not a fix. This statement
        puts them back: a finding of an owner in @owners (every owner left out NOW) that was closed as 'remediated' (or, #690
        (34), as 'report changed' -- an absence close like it) on or
        after @since is open again as it was -- first detected and the reopen count kept, NOT counted as a reopen -- and the
        change is a row of the CI's history. It runs once: sidata.CiBuildState 'FindingFreezeRepair' holds when; a close made
        after that is never touched (from then on such a finding freezes while it is open). Other close reasons are kept.
        Answers one row: Reopened, Skipped.
    #>
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.CiFindingState') IS NULL OR OBJECT_ID('sidata.CiBuildState') IS NULL
   OR EXISTS (SELECT 1 FROM sidata.CiBuildState WHERE Name = N'FindingFreezeRepair')
BEGIN
    SELECT 0 AS Reopened, 1 AS Skipped;
    RETURN;
END
DECLARE @from DATETIME2(3) = TRY_CONVERT(DATETIME2(3), @since, 127);
IF @from IS NULL
BEGIN
    SELECT 0 AS Reopened, 1 AS Skipped;
    RETURN;
END
DECLARE @o TABLE (OwnerKey NVARCHAR(450) NOT NULL PRIMARY KEY);
INSERT @o SELECT DISTINCT LEFT(z.k, 450) FROM OPENJSON(ISNULL(@owners, N'[]')) WITH (k NVARCHAR(MAX) '$') z WHERE z.k IS NOT NULL AND z.k <> N'';
/*ownstage:@o:@owners*/
DECLARE @r TABLE (CiId NVARCHAR(64) NULL, FindingKey NVARCHAR(256) NOT NULL, DetectedBy NVARCHAR(2000) NULL);
DECLARE @n INT = 0;
BEGIN TRANSACTION;
UPDATE s SET State = CASE WHEN s.ReopenedAt IS NOT NULL THEN N'reopened' ELSE N'open' END, ClosedAt = NULL, CloseReason = NULL, AbsentRuns = 0
OUTPUT inserted.CiId, inserted.FindingKey, inserted.DetectedBy INTO @r (CiId, FindingKey, DetectedBy)
FROM sidata.CiFindingState s JOIN @o o ON o.OwnerKey = s.OwnerKey
WHERE s.State = N'closed' AND s.CloseReason IN (N'remediated', N'report changed') AND s.ClosedAt >= @from;
SET @n = @@ROWCOUNT;
IF OBJECT_ID('sidata.CiChange') IS NOT NULL
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT r.CiId, N'finding', N'closed', N'open', LEFT(r.DetectedBy, 64),
           LEFT(CONCAT(r.FindingKey, N' -- closed while the asset was left out; open again as it was'), 512), NULL
    FROM @r r WHERE NULLIF(r.CiId, N'') IS NOT NULL;
INSERT sidata.CiBuildState (Name, Value) VALUES (N'FindingFreezeRepair', CONVERT(NVARCHAR(400), SYSUTCDATETIME(), 127));
COMMIT TRANSACTION;
SELECT @n AS Reopened, 0 AS Skipped;
'@).Replace('/*ownstage:@o:@owners*/', (Get-SIDataCiOwnerStageFillSql -Table '@o' -Column 'OwnerKey' -Param '@owners'))
}

function Get-SIDataFindingFrozenOwners {
    <#
        PURE. #533 rule 4 -- the OWNER keys whose absent open findings this run must FREEZE. -OpenStates: the open lifecycle rows
        (OwnerKey, FindingKey); -Items: this collection's findings (ConvertTo-SIDataFindingStateItems' input); -DisabledOwners:
        the owner keys of disabled assets left out by a setting (Get-SIDataDisabledOwnerKeys). Of the open findings ABSENT from
        this collection, Split-SIAbsentByDisabled keeps those of a disabled owner apart; their owners are returned (distinct).
    #>
    param([AllowEmptyCollection()][object[]]$OpenStates = @(), [AllowEmptyCollection()][object[]]$Items = @(), [AllowEmptyCollection()][string[]]$DisabledOwners = @())
    if (@($DisabledOwners).Count -eq 0) { return }
    if (-not (Get-Command -Name Split-SIAbsentByDisabled -ErrorAction SilentlyContinue)) {
        . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-DisabledAssets.ps1'))
    }
    $present = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($i in @(ConvertTo-SIDataFindingStateItems -Items @($Items))) { [void]$present.Add(('{0}|{1}' -f $i.OwnerKey, $i.FindingKey)) }
    $absent = @(foreach ($s in @($OpenStates)) {
            if ($null -eq $s) { continue }
            $o = [string](Get-SIItemValueOrNull $s 'OwnerKey'); $k = [string](Get-SIItemValueOrNull $s 'FindingKey')
            if ($o -and -not $present.Contains(('{0}|{1}' -f $o, $k))) { [pscustomobject]@{ OwnerKey = $o; FindingKey = $k } }
        })
    $split = Split-SIAbsentByDisabled -Items $absent -FrozenKeys @($DisabledOwners) -KeyOf { param($x) $x.OwnerKey }
    # the owner keys as items: the caller's @(...) is the list of keys (one wrapped array would be sent as [[...]] and
    # freeze nothing)
    @($split.Frozen | ForEach-Object { $_.OwnerKey }) | Sort-Object -Unique
}

function Get-SIDataDisabledOwnerKeys {
    <#
        PURE. #533 -- the lifecycle OWNER keys of disabled assets: 'asset:<id lower>' for each SI_AssetId, and the CI id (the
        correlation map's SI_CorrelationId -- the CI key) each one is a member of. -MapRows: SI_AssetId, SI_CorrelationId.
    #>
    param([AllowEmptyCollection()][string[]]$AssetIds = @(), [AllowEmptyCollection()][object[]]$MapRows = @())
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($AssetIds)) { if ($a) { [void]$ids.Add($a.Trim()) } }
    $out = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in $ids) { [void]$out.Add('asset:' + $a.ToLowerInvariant()) }
    foreach ($m in @($MapRows)) {
        if ($null -eq $m) { continue }
        $aid = [string](Get-SIItemValueOrNull $m 'SI_AssetId'); $ci = [string](Get-SIItemValueOrNull $m 'SI_CorrelationId')
        if ($aid -and $ci -and $ids.Contains($aid.Trim())) { [void]$out.Add($ci.Trim()) }
    }
    # the keys as items: the caller's @(...) is the list of keys (one wrapped array bound to [string[]] is ONE joined key)
    @($out)
}

function Get-SIDataCiDailyDetailSql {
    <#
        Today's sidata.CiDaily rows get the open findings by severity (not exempted) and the risk-factor count -- dynamic SQL so a
        database without the new columns compiles and skips. Answers the rows updated.
        #855 W7: only OPEN findings count, as the CI's own totals (Get-SIDataCiTotalsSql): a finding whose lifecycle row is
        closed is not, and a RETIRED CI has none.
    #>
    param([switch]$Ranged)
    $sql = @'
SET NOCOUNT ON;
IF COL_LENGTH('sidata.CiDaily', 'FactorCount') IS NULL OR COL_LENGTH('sidata.CiDaily', 'OpenCritical') IS NULL BEGIN SELECT 0; RETURN; END
EXEC sp_executesql N'
UPDATE d SET OpenCritical = ISNULL(s.Crit, 0), OpenHigh = ISNULL(s.High, 0), OpenMedium = ISNULL(s.Med, 0), OpenLow = ISNULL(s.Low, 0),
       FactorCount = CASE WHEN ISNULL(c.RiskFactors, N'''') = N'''' THEN 0 ELSE LEN(c.RiskFactors) - LEN(REPLACE(c.RiskFactors, N'';'', N'''')) + 1 END
FROM sidata.CiDaily d JOIN sidata.Ci c ON c.CiId = d.CiId
LEFT JOIN (SELECT CiId, SUM(CASE WHEN Severity = N''critical'' THEN 1 ELSE 0 END) AS Crit, SUM(CASE WHEN Severity = N''high'' THEN 1 ELSE 0 END) AS High,
                  SUM(CASE WHEN Severity = N''medium'' THEN 1 ELSE 0 END) AS Med, SUM(CASE WHEN Severity = N''low'' THEN 1 ELSE 0 END) AS Low
           FROM sidata.CiFinding AS f WHERE f.CiId IS NOT NULL AND ISNULL(f.ExemptionId, N'''') = N''''/*R:f.CiId*/
             AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingState AS x WHERE x.OwnerKey = f.CiId AND x.FindingKey = f.FindingKey AND x.State = N''closed'')
           GROUP BY f.CiId) s ON s.CiId = d.CiId AND ISNULL(c.Lifecycle, N'''') <> N''retired''
WHERE d.[Day] = CONVERT(date, SYSUTCDATETIME())/*R:d.CiId*/;
SELECT @@ROWCOUNT;'/*RP*/;
'@
    if ($Ranged) { return $sql }
    Convert-SIDataFindingStateRangeText -Sql $sql
}

function Get-SIDataFindingSlaDays {
    <#
        PURE. #494 the SLA in days per severity from the settings SI_Pro_FindingSla_CriticalDays / _HighDays / _MediumDays /
        _LowDays (defaults 15 / 30 / 90 / 180; 0 = no due date for that severity; anything not a whole number 0-3650 = the
        default). Answers @{ critical; high; medium; low }.
    #>
    param($Critical = $global:SI_Pro_FindingSla_CriticalDays, $High = $global:SI_Pro_FindingSla_HighDays, $Medium = $global:SI_Pro_FindingSla_MediumDays,
          $Low = $global:SI_Pro_FindingSla_LowDays)
    $one = {
        param($v, [int]$d)
        $x = 0
        if ($null -ne $v -and "$v".Trim() -ne '' -and [int]::TryParse(([string]$v).Trim(), [ref]$x) -and $x -ge 0 -and $x -le 3650) { return $x }
        $d
    }
    [ordered]@{ critical = (& $one $Critical 15); high = (& $one $High 30); medium = (& $one $Medium 90); low = (& $one $Low 180) }
}

function Get-SIDataFindingModelSql {
    <#
        #494 FINDINGS PER CI -- ONE MODEL. After the lifecycle step, the open lifecycle rows (and those closed at this
        collection) get what the other parts know of the finding, set-based, written only where a value differs:
          FindingType, Title     the finding as stored (sidata.CiFinding)
          Owner, OwnerSource     the owner of the CI's most critical business service (si_service_owner, 'service'), else the
                                 CI's CMDB owner (si_cmdb_owner, 'cmdb'), else the CI's own owner (si_owner, 'ci')
          ServiceKeys, ServiceCriticality   the services that own the CI (sidata.CiService) and the criticality it inherits
          SlaDays, DueAt         the SLA of the severity (@crit / @high / @med / @low days; 0 = none) from the first detection,
                                 or from the last reopen
          ExemptionReason, ExemptedUntil    the exemption in force (cfg.Exemption, Pro)
          TicketState / ClosedAt / CloseReason   the vulnerability close-loop's record (vuln.VulnerabilityItem, Pro)
          Excluded               #533: the asset is disabled and left out by a setting (@dis = its owner keys) -- its findings
                                 are kept as they were, never resolved or closed
        Every part a database does not carry is skipped (dynamic SQL); a database without the new columns answers Skipped = 1.
    #>
    # -Ranged (2026-10-29): ONE OwnerKey range of the states (/*R:s.OwnerKey*/; Invoke-SIDataFindingModel) -- each state is
    # written from its own CI, finding and exemption, so the ranges write exactly what the one statement wrote
    param([switch]$Ranged)
    $sql = (@'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiFindingState') IS NULL OR COL_LENGTH('sidata.CiFindingState', 'DueAt') IS NULL OR COL_LENGTH('sidata.CiFindingState', 'Excluded') IS NULL
BEGIN
    SELECT 0 AS Updated, 0 AS Exempted, 0 AS Tickets, 1 AS Skipped;
    RETURN;
END
DECLARE @n INT = 0, @ne INT = 0, @nt INT = 0;
DECLARE @cr INT = TRY_CONVERT(INT, @crit), @hi INT = TRY_CONVERT(INT, @high), @me INT = TRY_CONVERT(INT, @med), @lo INT = TRY_CONVERT(INT, @low);
DECLARE @last DATETIME2(3) = (SELECT TOP 1 TRY_CONVERT(DATETIME2(3), Value, 127) FROM sidata.CiBuildState WHERE Name = N'FindingStateSnapshot');
IF @last IS NULL SET @last = '19000101';
CREATE TABLE #fz (OwnerKey NVARCHAR(450) NOT NULL PRIMARY KEY);
INSERT #fz SELECT DISTINCT LEFT(z.k, 450) FROM OPENJSON(ISNULL(@dis, N'[]')) WITH (k NVARCHAR(MAX) '$') z WHERE z.k IS NOT NULL AND z.k <> N'';
/*ownstage:#fz:@dis*/
-- per CI once (not per finding): its owner, the services that own it, the criticality it inherits
CREATE TABLE #o (CiId NVARCHAR(64) NOT NULL PRIMARY KEY, Owner NVARCHAR(256) NULL, OwnerSource NVARCHAR(16) NULL, ServiceKeys NVARCHAR(1000) NULL, ServiceCriticality NVARCHAR(64) NULL);
INSERT #o (CiId, Owner, OwnerSource, ServiceCriticality)
SELECT c.CiId,
       LEFT(COALESCE(NULLIF(JSON_VALUE(c.DocJson, '$.si_service_owner'), N''), NULLIF(JSON_VALUE(c.DocJson, '$.si_cmdb_owner'), N''), NULLIF(JSON_VALUE(c.DocJson, '$.si_owner'), N'')), 256),
       CASE WHEN NULLIF(JSON_VALUE(c.DocJson, '$.si_service_owner'), N'') IS NOT NULL THEN N'service'
            WHEN NULLIF(JSON_VALUE(c.DocJson, '$.si_cmdb_owner'), N'') IS NOT NULL THEN N'cmdb'
            WHEN NULLIF(JSON_VALUE(c.DocJson, '$.si_owner'), N'') IS NOT NULL THEN N'ci' END,
       LEFT(JSON_VALUE(c.DocJson, '$.si_service_criticality'), 64)
FROM sidata.Ci c
WHERE ISJSON(c.DocJson) = 1 AND c.CiId IN (SELECT s.CiId FROM sidata.CiFindingState s WHERE s.CiId IS NOT NULL AND (s.State <> N'closed' OR s.ClosedAt >= @last)/*R:s.OwnerKey*/);
IF OBJECT_ID('sidata.CiService') IS NOT NULL
    UPDATE o SET ServiceKeys = LEFT((SELECT STRING_AGG(CAST(cs.ServiceKey AS NVARCHAR(MAX)), N';') WITHIN GROUP (ORDER BY cs.ServiceKey) FROM sidata.CiService cs WHERE cs.CiId = o.CiId), 1000)
    FROM #o o;
-- the new columns are written through dynamic SQL: this statement compiles on a database the updater has not updated yet
EXEC sp_executesql N'
UPDATE s SET
    FindingType = COALESCE(LEFT(f.FindingType, 32), s.FindingType),
    Title = COALESCE(LEFT(f.Title, 400), s.Title),
    Owner = o.Owner, OwnerSource = o.OwnerSource, ServiceKeys = o.ServiceKeys, ServiceCriticality = o.ServiceCriticality,
    SlaDays = x.Sla,
    DueAt = CASE WHEN x.Sla > 0 THEN DATEADD(day, x.Sla, COALESCE(s.ReopenedAt, s.FirstDetected)) END,
    Excluded = CASE WHEN s.State <> N''closed'' AND EXISTS (SELECT 1 FROM #fz z WHERE z.OwnerKey = s.OwnerKey) THEN 1 ELSE 0 END,
    ModelAt = SYSUTCDATETIME()
FROM sidata.CiFindingState s
LEFT JOIN #o o ON o.CiId = s.CiId
-- #881 the two cases apart (the one OR made every state scan the findings per CI): a state of a CI seeks the clustered key
-- (CiId, FindingKey) -- only a state without a CI reads by its asset id -- the same candidates, the same newest one
OUTER APPLY (SELECT TOP (1) u.FindingType, u.Title FROM (
                 SELECT TOP (1) cf.FindingType, cf.Title, cf.CollectionTime FROM sidata.CiFinding cf
                 WHERE s.CiId IS NOT NULL AND cf.CiId = s.CiId AND cf.FindingKey = s.FindingKey ORDER BY cf.CollectionTime DESC
                 UNION ALL
                 SELECT TOP (1) cf.FindingType, cf.Title, cf.CollectionTime FROM sidata.CiFinding cf
                 WHERE s.CiId IS NULL AND cf.FindingKey = s.FindingKey AND N''asset:'' + LOWER(cf.AssetId) = s.OwnerKey ORDER BY cf.CollectionTime DESC) u
             ORDER BY u.CollectionTime DESC) f
CROSS APPLY (SELECT CASE LOWER(REPLACE(REPLACE(ISNULL(s.Severity, N''''), N'' '', N''''), N''-'', N''''))
                        WHEN N''critical'' THEN @crit WHEN N''veryhigh'' THEN @crit WHEN N''high'' THEN @high
                        WHEN N''mediumhigh'' THEN @med WHEN N''medium'' THEN @med WHEN N''moderate'' THEN @med WHEN N''low'' THEN @low ELSE NULL END AS Sla) x
WHERE (s.State <> N''closed'' OR s.ClosedAt >= @last)/*R:s.OwnerKey*/
  AND (ISNULL(s.Owner, N'''') <> ISNULL(o.Owner, N'''') OR ISNULL(s.OwnerSource, N'''') <> ISNULL(o.OwnerSource, N'''')
       OR ISNULL(s.ServiceKeys, N'''') <> ISNULL(o.ServiceKeys, N'''') OR ISNULL(s.ServiceCriticality, N'''') <> ISNULL(o.ServiceCriticality, N'''')
       OR ISNULL(s.SlaDays, -1) <> ISNULL(x.Sla, -1)
       OR ISNULL(s.DueAt, ''19000101'') <> ISNULL(CASE WHEN x.Sla > 0 THEN DATEADD(day, x.Sla, COALESCE(s.ReopenedAt, s.FirstDetected)) END, ''19000101'')
       OR s.Excluded <> CASE WHEN s.State <> N''closed'' AND EXISTS (SELECT 1 FROM #fz z WHERE z.OwnerKey = s.OwnerKey) THEN 1 ELSE 0 END
       OR (f.Title IS NOT NULL AND ISNULL(s.Title, N'''') <> LEFT(f.Title, 400)) OR (f.FindingType IS NOT NULL AND ISNULL(s.FindingType, N'''') <> LEFT(f.FindingType, 32)));
SET @n = @@ROWCOUNT;',
    N'@crit INT, @high INT, @med INT, @low INT, @last DATETIME2(3), @n INT OUTPUT/*RPL*/',
    @crit = @cr, @high = @hi, @med = @me, @low = @lo, @last = @last, @n = @n OUTPUT/*RPV*/;
-- the exemption in force (Pro: cfg.Exemption)
IF OBJECT_ID('cfg.Exemption') IS NOT NULL
    EXEC sp_executesql N'
UPDATE s SET ExemptionReason = CASE WHEN s.ExemptionId IS NULL THEN NULL ELSE LEFT(e.Reason, 400) END,
             ExemptedUntil = CASE WHEN s.ExemptionId IS NULL THEN NULL ELSE e.ExpiresAt END
FROM sidata.CiFindingState s
LEFT JOIN cfg.Exemption e ON CONVERT(NVARCHAR(64), e.ExemptionId) = s.ExemptionId AND e.RevokedAt IS NULL
WHERE s.State <> N''closed''/*R:s.OwnerKey*/
  AND (ISNULL(s.ExemptionReason, N'''') <> ISNULL(CASE WHEN s.ExemptionId IS NULL THEN NULL ELSE LEFT(e.Reason, 400) END, N'''')
       OR ISNULL(s.ExemptedUntil, ''19000101'') <> ISNULL(CASE WHEN s.ExemptionId IS NULL THEN NULL ELSE e.ExpiresAt END, ''19000101''));
SET @ne = @@ROWCOUNT;', N'@ne INT OUTPUT/*RPL*/', @ne = @ne OUTPUT/*RPV*/;
-- the vulnerability close-loop's record of the same finding (Pro: vuln.VulnerabilityItem -- the CI key and the finding key)
IF OBJECT_ID('vuln.VulnerabilityItem') IS NOT NULL
    EXEC sp_executesql N'
UPDATE s SET TicketState = v.State, TicketClosedAt = v.ClosedAt, TicketCloseReason = LEFT(v.CloseReason, 400)
FROM sidata.CiFindingState s
CROSS APPLY (SELECT TOP (1) vi.State, vi.ClosedAt, vi.CloseReason FROM vuln.VulnerabilityItem vi
             WHERE vi.CorrelationId = s.CiId AND vi.Cve = LEFT(s.FindingKey, 100) ORDER BY vi.UpdatedAt DESC) v
WHERE s.CiId IS NOT NULL/*R:s.OwnerKey*/
  AND (ISNULL(s.TicketState, N'''') <> ISNULL(v.State, N'''') OR ISNULL(s.TicketClosedAt, ''19000101'') <> ISNULL(v.ClosedAt, ''19000101'')
       OR ISNULL(s.TicketCloseReason, N'''') <> ISNULL(LEFT(v.CloseReason, 400), N''''));
SET @nt = @@ROWCOUNT;', N'@nt INT OUTPUT/*RPL*/', @nt = @nt OUTPUT/*RPV*/;
SELECT @n AS Updated, @ne AS Exempted, @nt AS Tickets, 0 AS Skipped;
'@).Replace('/*ownstage:#fz:@dis*/', (Get-SIDataCiOwnerStageFillSql -Table '#fz' -Column 'OwnerKey' -Param '@dis'))
    if ($Ranged) { return $sql }
    Convert-SIDataFindingStateRangeText -Sql $sql
}

function Get-SIDataCiDailyGraphSql {
    <#
        #495 today's sidata.CiDaily rows get the CI's lifecycle, internet exposure, how many services own it, the criticality
        it inherits, its active relations and its overdue / exempted findings -- dynamic SQL so a database without the
        columns (or the graph tables) skips. Answers the rows updated.
    #>
    param([switch]$Ranged)
    $sql = @'
SET NOCOUNT ON;
IF COL_LENGTH('sidata.CiDaily', 'RelationCount') IS NULL OR OBJECT_ID('sidata.CiService') IS NULL OR OBJECT_ID('sidata.CiRelation') IS NULL
   OR COL_LENGTH('sidata.CiFindingState', 'DueAt') IS NULL BEGIN SELECT 0; RETURN; END
EXEC sp_executesql N'
UPDATE d SET Lifecycle = c.Lifecycle, InternetExposed = c.InternetExposed,
       ServiceCount = (SELECT COUNT(*) FROM sidata.CiService sv WHERE sv.CiId = d.CiId),
       ServiceCriticality = LEFT(JSON_VALUE(c.DocJson, ''$.si_service_criticality''), 64),
       RelationCount = (SELECT COUNT(*) FROM sidata.CiRelation r WHERE (r.FromCiId = d.CiId OR r.ToCiId = d.CiId) AND r.State = N''active''),
       OverdueFindings = (SELECT COUNT(*) FROM sidata.CiFindingState s WHERE s.CiId = d.CiId AND s.State <> N''closed'' AND s.Excluded = 0 AND s.DueAt < SYSUTCDATETIME()
                            AND NOT (s.ExemptionId IS NOT NULL AND (s.ExemptedUntil IS NULL OR s.ExemptedUntil > SYSUTCDATETIME()))),
       ExemptedFindings = (SELECT COUNT(*) FROM sidata.CiFindingState s WHERE s.CiId = d.CiId AND s.State <> N''closed''
                            AND s.ExemptionId IS NOT NULL AND (s.ExemptedUntil IS NULL OR s.ExemptedUntil > SYSUTCDATETIME()))
FROM sidata.CiDaily d JOIN sidata.Ci c ON c.CiId = d.CiId
WHERE d.[Day] = CONVERT(date, SYSUTCDATETIME()) AND ISJSON(c.DocJson) = 1/*R:d.CiId*/;
SELECT @@ROWCOUNT;'/*RP*/;
'@
    if ($Ranged) { return $sql }
    Convert-SIDataFindingStateRangeText -Sql $sql
}

function Get-SIDataCiRetentionSql {
    <#
        The history tables kept as long as set: @change / @daily / @state = days. Answers the rows removed. ONE BATCH of at
        most -Batch rows per table (a literal whole number): the caller repeats it until a batch removes less than that
        (Invoke-SIDataCiRetention -- every expired row goes, however many; owner 2026-10-22: "i accept no limits").
    #>
    param([int]$Batch = 50000)
    $b = [Math]::Max(1, $Batch)
    $text = @'
SET NOCOUNT ON;
DECLARE @n INT = 0;
IF OBJECT_ID('sidata.CiChange') IS NOT NULL BEGIN DELETE TOP (50000) FROM sidata.CiChange WHERE ChangedAt < DATEADD(day, -TRY_CONVERT(INT, @change), SYSUTCDATETIME()); SET @n += @@ROWCOUNT; END
IF OBJECT_ID('sidata.CiDaily') IS NOT NULL BEGIN DELETE TOP (50000) FROM sidata.CiDaily WHERE [Day] < DATEADD(day, -TRY_CONVERT(INT, @daily), CONVERT(date, SYSUTCDATETIME())); SET @n += @@ROWCOUNT; END
IF OBJECT_ID('sidata.CiFindingState') IS NOT NULL BEGIN DELETE TOP (50000) FROM sidata.CiFindingState WHERE State = N'closed' AND ClosedAt < DATEADD(day, -TRY_CONVERT(INT, @state), SYSUTCDATETIME()); SET @n += @@ROWCOUNT; END
SELECT @n;
'@
    $text.Replace('TOP (50000)', ('TOP ({0})' -f $b))
}

function Invoke-SIDataCiRetention {
    <#
        Removes EVERY expired history row (Get-SIDataCiRetentionSql), batch after batch until a batch removes less than its
        size -- never one batch per run (a large install adds more rows a day than one batch). The batch is sized from the
        measured time of the one before (aim -TargetMs; Get-SIDataNextSize -- a measurement, not a ceiling) and paced by
        the database's own load (SI-SqlPacing.ps1). One progress line a minute while it runs. Answers the rows removed.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][hashtable]$Params, [scriptblock]$Log, [long]$TargetMs = 5000, [long]$Batch = 50000)
    if (-not $Log) { $Log = { param($l, $m) } }
    $total = 0L; $clock = [Diagnostics.Stopwatch]::StartNew(); $said = 0.0; $lastMs = 0L
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    while ($true) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $Batch = [Math]::Max(1000L, [long][Math]::Floor($Batch / 2)) } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $v = & $Invoke (Get-SIDataCiRetentionSql -Batch ([int][Math]::Min([double][int]::MaxValue, [double]$Batch))) $Params 'scalar'
        $n = 0L; if ($null -ne $v -and -not ($v -is [System.DBNull])) { $n = [long]$v }
        $lastMs = $sw.ElapsedMilliseconds
        $total += $n
        if ($n -lt $Batch) { break }
        if (($clock.Elapsed.TotalSeconds - $said) -ge 60) { $said = $clock.Elapsed.TotalSeconds; & $Log 'INFO' ("v3 model    : history kept as long as set -- {0:N0} expired row(s) removed so far" -f $total) }
        $Batch = Get-SIDataNextSize -Current $Batch -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1000
    }
    $total
}

function Get-SIDataRetentionDays {
    <# PURE. A whole number of days from a setting value, or the default (also for anything below 1). #>
    param($Value, [int]$Default)
    $n = 0
    if ($null -ne $Value -and [int]::TryParse(([string]$Value).Trim(), [ref]$n) -and $n -ge 1) { return $n }
    $Default
}

function Test-SIDataFindingCollectionComplete {
    <#
        Was the finding collection (-SnapshotTime) produced by COMPLETE Risk Analysis runs? The vulnerability loop's rule
        (Test-SIVulnSnapshotComplete over the run-health END heartbeats). Anything that cannot be shown -- no reader, no heartbeat,
        an error -- is NOT complete: unknown never closes a finding. Returns @{ Complete; Reason; FrozenReports }.
        -Invoke (the data database, 'reader'): PER REPORT -- a run that is partial only because named reports could not be
        completed is complete for every other report; FrozenReports names those reports (Resolve-SIReportScopedComplete).
    #>
    param([AllowNull()]$SnapshotTime, [scriptblock]$ReadOrSkip, [datetime]$Now = [datetime]::UtcNow, [scriptblock]$Invoke)
    try {
        $snap = $null
        if ($SnapshotTime -is [datetime]) { $snap = $SnapshotTime } elseif ($SnapshotTime) { $snap = [datetime]::Parse([string]$SnapshotTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
        if ($null -eq $snap) { return [pscustomobject]@{ Complete = $false; Reason = 'the collection has no time' } }
        if (-not $ReadOrSkip) { return [pscustomobject]@{ Complete = $false; Reason = 'no run-health reader' } }
        if (-not (Get-Command -Name Test-SIVulnSnapshotComplete -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'asset-cmdb', '_shared', 'SI-VulnDesired.ps1'))
        }
        $a = & $ReadOrSkip (Get-SIVulnRunHealthKql) 'SI_RunHealth_CL'
        $runs = @(@($a) | Where-Object { $_ } | ForEach-Object {
                $st = $null; try { $st = [datetime]::Parse([string]$_.StartedAt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { }
                [pscustomobject]@{ StartedAt = $st; DurationSec = $_.DurationSec; ExitReason = [string]$_.ExitReason } })
        $v = Test-SIVulnSnapshotComplete -SnapshotTime $snap.ToUniversalTime() -Runs $runs -Now $Now
        if (-not $v.Complete -and $Invoke -and (Get-Command -Name Resolve-SIReportScopedComplete -ErrorAction SilentlyContinue)) {
            $rep = Read-SIReportCompleteness -Invoke $Invoke -SnapshotTime $snap -Mode reader
            return (Resolve-SIReportScopedComplete -Complete $v -SnapshotTime $snap.ToUniversalTime() -Runs $runs -Reports $rep -Now $Now)
        }
        return [pscustomobject]@{ Complete = [bool]$v.Complete; Reason = [string]$v.Reason; FrozenReports = [string[]]@() }
    } catch {
        return [pscustomobject]@{ Complete = $false; Reason = ('completeness could not be shown -- {0}' -f $_.Exception.Message) }
    }
}

function Get-SIDataFindingFreezeRepairSince {
    <# PURE. The one-time repair looks at closes from the day the freeze of a left-out asset's findings was shipped: before it nothing claimed to freeze them. #>
    '2026-10-10T00:00:00.000'
}

# =====================================================================================================================
#  ONE-TIME REPAIR OF STALE OPEN LIFECYCLE ROWS (REMOVE-ME once it has run everywhere: the setting, these two functions
#  and their call in Invoke-SIDataCiLifecycle). Before the empty-CI-id fix, a finding no CI holds could keep '' as its
#  CI id, and a finding moved from an asset key to a CI key stayed open under the old key while it was frozen. Setting
#  SI_Pro_LifecycleStaleOpenRepair: off (the default) = nothing; count = read only, says per install how many rows it would
#  change and what they would become; apply = once (sidata.CiBuildState 'LifecycleStaleOpenRepair'), in one transaction,
#  after the lifecycle of a COMPLETE collection: an empty CI id becomes none (nothing visible changes), and an open
#  finding under an asset key that the newest collection reports open under the CI its stored finding names closes as
#  'rekeyed'. Nothing is deleted; every other open row is only counted -- it goes through the normal absence rule.
# =====================================================================================================================

function Get-SIDataLifecycleStaleOpenRepairMode {
    <# PURE. off | count | apply from the setting value (anything else = off). #>
    param($Value = $(Get-Variable -Name SI_Pro_LifecycleStaleOpenRepair -Scope Global -ValueOnly -ErrorAction SilentlyContinue))
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if ($v -in 'count', 'apply') { return $v }
    'off'
}

function Get-SIDataLifecycleStaleOpenRepairSql {
    <#
        The repair's ONE statement. @apply = '1' changes the rows (once), anything else only counts. Answers one row:
        Skipped, Note, EmptyCiId (rows whose CI id is '' -- they get none), Rekeyed (open under an asset key, not in the
        newest processed collection, open under the CI the stored finding links that asset to and seen in it -- they close
        as 'rekeyed'), LinkedOpen / UnlinkedOpen (the other open asset-key rows absent from the newest collection whose
        asset the stored findings or the CI links tie to exactly one CI / to none or several -- counted only), NoDetectedBy
        (open rows absent from the newest collection that name no report -- counted only), Applied.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.CiFindingState') IS NULL OR OBJECT_ID('sidata.CiBuildState') IS NULL OR OBJECT_ID('sidata.CiFinding') IS NULL OR OBJECT_ID('sidata.CiLink') IS NULL
BEGIN
    SELECT 1 AS Skipped, N'the database does not have the lifecycle tables' AS Note, 0 AS EmptyCiId, 0 AS Rekeyed, 0 AS LinkedOpen, 0 AS UnlinkedOpen, 0 AS NoDetectedBy, 0 AS Applied;
    RETURN;
END
IF EXISTS (SELECT 1 FROM sidata.CiBuildState WHERE Name = N'LifecycleStaleOpenRepair')
BEGIN
    SELECT 1 AS Skipped, N'already applied' AS Note, 0 AS EmptyCiId, 0 AS Rekeyed, 0 AS LinkedOpen, 0 AS UnlinkedOpen, 0 AS NoDetectedBy, 0 AS Applied;
    RETURN;
END
DECLARE @last DATETIME2(3) = (SELECT TOP 1 TRY_CONVERT(DATETIME2(3), Value, 127) FROM sidata.CiBuildState WHERE Name = N'FindingStateSnapshot');
IF @last IS NULL
BEGIN
    SELECT 1 AS Skipped, N'no finding collection was processed yet' AS Note, 0 AS EmptyCiId, 0 AS Rekeyed, 0 AS LinkedOpen, 0 AS UnlinkedOpen, 0 AS NoDetectedBy, 0 AS Applied;
    RETURN;
END
DECLARE @empty INT = (SELECT COUNT(*) FROM sidata.CiFindingState WHERE CiId = N'');
CREATE TABLE #rk (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, PRIMARY KEY (OwnerKey, FindingKey));
INSERT #rk (OwnerKey, FindingKey)
SELECT DISTINCT s.OwnerKey, s.FindingKey
FROM sidata.CiFindingState s
JOIN sidata.CiFinding cf ON cf.FindingKey = s.FindingKey AND NULLIF(cf.CiId, N'') IS NOT NULL AND NULLIF(cf.AssetId, N'') IS NOT NULL
                        AND N'asset:' + LOWER(cf.AssetId) = s.OwnerKey
JOIN sidata.CiFindingState c ON c.OwnerKey = cf.CiId AND c.FindingKey = cf.FindingKey AND c.State <> N'closed' AND c.LastSeen = @last
WHERE s.State <> N'closed' AND s.OwnerKey LIKE N'asset:%' AND NULLIF(s.CiId, N'') IS NULL AND s.LastSeen < @last;
-- the other open asset-key rows absent from the newest collection, by how many CIs their asset is tied to
CREATE TABLE #o (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
INSERT #o (OwnerKey)
SELECT DISTINCT s.OwnerKey FROM sidata.CiFindingState s
WHERE s.State <> N'closed' AND s.OwnerKey LIKE N'asset:%' AND NULLIF(s.CiId, N'') IS NULL AND s.LastSeen < @last
  AND NOT EXISTS (SELECT 1 FROM #rk k WHERE k.OwnerKey = s.OwnerKey AND k.FindingKey = s.FindingKey);
CREATE TABLE #m (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL);
INSERT #m (OwnerKey, CiId)
SELECT DISTINCT o.OwnerKey, cf.CiId FROM #o o JOIN sidata.CiFinding cf ON N'asset:' + LOWER(cf.AssetId) = o.OwnerKey
WHERE NULLIF(cf.CiId, N'') IS NOT NULL AND NULLIF(cf.AssetId, N'') IS NOT NULL;
INSERT #m (OwnerKey, CiId)
SELECT DISTINCT o.OwnerKey, l.CiId FROM #o o JOIN sidata.CiLink l ON l.NativeId = SUBSTRING(o.OwnerKey, 7, 450);
DECLARE @linked INT = 0, @unlinked INT = 0, @nodet INT = 0, @applied INT = 0;
SELECT @linked = ISNULL(SUM(CASE WHEN x.N = 1 THEN 1 ELSE 0 END), 0), @unlinked = ISNULL(SUM(CASE WHEN x.N = 1 THEN 0 ELSE 1 END), 0)
FROM (SELECT s.OwnerKey, (SELECT COUNT(DISTINCT m.CiId) FROM #m m WHERE m.OwnerKey = s.OwnerKey) AS N
      FROM sidata.CiFindingState s JOIN #o o ON o.OwnerKey = s.OwnerKey
      WHERE s.State <> N'closed' AND NULLIF(s.CiId, N'') IS NULL AND s.LastSeen < @last
        AND NOT EXISTS (SELECT 1 FROM #rk k WHERE k.OwnerKey = s.OwnerKey AND k.FindingKey = s.FindingKey)) x;
SELECT @nodet = COUNT(*) FROM sidata.CiFindingState s WHERE s.State <> N'closed' AND s.LastSeen < @last AND ISNULL(s.DetectedBy, N'') = N'';
DECLARE @rekeyed INT = (SELECT COUNT(*) FROM #rk);
IF @apply = N'1'
BEGIN
    -- in TOP batches, each its own short transaction (however many rows an install has): both steps are idempotent -- a
    -- repair that stops half-way is completed by the next run (the cleared ids are not '' any more, the closed rows are
    -- not open any more); the mark that it ran is written only after both
    WHILE 1 = 1
    BEGIN
        UPDATE TOP (50000) sidata.CiFindingState SET CiId = NULL WHERE CiId = N'';
        IF @@ROWCOUNT < 50000 BREAK;
    END
    WHILE 1 = 1
    BEGIN
        UPDATE TOP (50000) s SET State = N'closed', ClosedAt = @last, CloseReason = N'rekeyed'
        FROM sidata.CiFindingState s JOIN #rk k ON k.OwnerKey = s.OwnerKey AND k.FindingKey = s.FindingKey
        WHERE s.State <> N'closed';
        IF @@ROWCOUNT < 50000 BREAK;
    END
    INSERT sidata.CiBuildState (Name, Value)
    VALUES (N'LifecycleStaleOpenRepair', LEFT(CONCAT(CONVERT(NVARCHAR(30), SYSUTCDATETIME(), 127), N' empty CI id ', @empty, N'; rekeyed ', @rekeyed), 400));
    SET @applied = 1;
END
DROP TABLE #rk; DROP TABLE #o; DROP TABLE #m;
SELECT 0 AS Skipped, N'' AS Note, @empty AS EmptyCiId, @rekeyed AS Rekeyed, @linked AS LinkedOpen, @unlinked AS UnlinkedOpen, @nodet AS NoDetectedBy, @applied AS Applied;
'@
}

function Invoke-SIDataLifecycleStaleOpenRepair {
    <#
        The repair in the data sync, after the lifecycle step (REMOVE-ME, see above). -Mode off | count | apply; apply only
        with -Complete (a complete collection) -- otherwise it counts. Never throws; answers the counts (or $null when off).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Mode = (Get-SIDataLifecycleStaleOpenRepairMode), [bool]$Complete = $false, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    if ($Mode -notin 'count', 'apply') { return $null }
    $apply = ($Mode -eq 'apply' -and $Complete)
    try {
        $r = @(Get-SIDataSeamRows -Invoke $Invoke -Sql (Get-SIDataLifecycleStaleOpenRepairSql) -Params @{ apply = $(if ($apply) { '1' } else { '0' }) } |
               Where-Object { $null -ne (Get-SIItemValueOrNull $_ 'Skipped') }) | Select-Object -First 1
        if (-not $r) { & $Log 'WARN' 'v3 model    : stale lifecycle repair -- the database gave no answer; nothing was changed'; return $null }
        $o = [ordered]@{ Mode = $Mode; Applied = ([int](Get-SIItemValueOrNull $r 'Applied') -eq 1); Skipped = ([int](Get-SIItemValueOrNull $r 'Skipped') -eq 1); Note = [string](Get-SIItemValueOrNull $r 'Note') }
        foreach ($k in 'EmptyCiId', 'Rekeyed', 'LinkedOpen', 'UnlinkedOpen', 'NoDetectedBy') { $o[$k] = [int](Get-SIItemValueOrNull $r $k) }
        if ($o.Skipped) { & $Log 'INFO' ('v3 model    : stale lifecycle repair ({0}) -- nothing to do: {1}' -f $Mode, $o.Note); return [pscustomobject]$o }
        $what = ('{0} row(s) with an empty CI id {1} none (nothing visible changes); {2} open finding(s) under an old asset key, open under their CI in the newest collection, {3} as rekeyed (not a fix); ' +
                 '{4} open finding(s) under an asset key tied to one CI are counted absent from the next run when that CI''s sources are current; {5} under an asset key tied to no CI (or to several) stay as they are while a source is on its last good collection; ' +
                 '{6} open finding(s) that name no report stay as they are while a report is not complete') -f $o.EmptyCiId, $(if ($o.Applied) { 'got' } else { 'would get' }), $o.Rekeyed, $(if ($o.Applied) { 'closed' } else { 'would close' }), $o.LinkedOpen, $o.UnlinkedOpen, $o.NoDetectedBy
        if ($o.Applied) { & $Log 'WARN' ('v3 model    : stale lifecycle repair APPLIED (once) -- {0}' -f $what) }
        elseif ($Mode -eq 'apply') { & $Log 'INFO' ('v3 model    : stale lifecycle repair waits for a complete collection (counted only, nothing changed) -- {0}' -f $what) }
        else { & $Log 'INFO' ('v3 model    : stale lifecycle repair, count only (nothing changed) -- {0}' -f $what) }
        return [pscustomobject]$o
    } catch {
        & $Log 'WARN' ('v3 model    : stale lifecycle repair not run -- {0}. Nothing was changed.' -f $_.Exception.Message)
        return $null
    }
}

function Test-SIDataLifecycleRanged {
    <# A real database's seam with the range helpers loaded (SI-DataCi.ps1): the lifecycle steps run in key ranges. #>
    param($Invoke)
    [bool]((Get-Command -Name Test-SIDataRangedSeam -ErrorAction SilentlyContinue) -and (Test-SIDataRangedSeam $Invoke))
}

function Invoke-SIDataFindingStateRanged {
    <#
        2026-10-29 THE FINDING LIFECYCLE IN OWNERKEY RANGES (Get-SIDataFindingStateSql -FromStage -Ranged): one range of the
        lifecycle rows' owners at a time (the first open below, the last open above, so a staged owner new to the lifecycle is
        in a range too), each ONE command and its own transaction with its mark; the range's size from the measured time of the
        one before; one log line per range. A run that stopped part-way goes on after the last owner key its mark holds, when
        the mark is of the same snapshot. The bounds are cut to the 400 characters the mark can hold (any value cuts the keys
        into ranges, so every owner is still in exactly one). -Params: the statement's own; -Snap: the snapshot (ISO text, as
        the statement's @snap). Answers ONE row: the counts summed over the ranges (Skipped = 1 when the collection was
        processed before: only missing records were added). Throws when a range gives no answer.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [Parameter(Mandatory)][hashtable]$Params,
          [Parameter(Mandatory)][string]$Snap, [scriptblock]$Log, [long]$FirstTake = 50000, [long]$TargetMs = 5000,
          # tests only: stop after this many ranges, as a run that ends part-way
          [int]$StopAfterRanges = 0)
    $sum = [ordered]@{ Opened = 0L; Seen = 0L; Reopened = 0L; Closed = 0L; Absent = 0L; Frozen = 0L; Carried = 0L; Repaired = 0L; RetiredClosed = 0L; Reactivated = 0L; Rekeyed = 0L }
    $skipped = 0; $note = ''
    $one = { param($q) $v = & $Invoke $q @{} 'scalar'; if ($null -eq $v -or $v -is [System.DBNull]) { '' } else { [string]$v } }
    $hasLo = $false; $lo = $null
    $ms = & $one "IF OBJECT_ID('sidata.CiBuildState') IS NULL SELECT N'' ELSE SELECT ISNULL((SELECT TOP (1) Value FROM sidata.CiBuildState WHERE Name = N'FindingStateRangeSnap'), N'');"
    $mk = & $one "IF OBJECT_ID('sidata.CiBuildState') IS NULL SELECT N'' ELSE SELECT ISNULL((SELECT TOP (1) Value FROM sidata.CiBuildState WHERE Name = N'FindingStateRangeKey'), N'');"
    if ($ms -and $ms -eq $Snap -and $mk) {
        $hasLo = $true; $lo = $mk
        if ($Log) { & $Log 'INFO' 'v3 model    : finding lifecycle -- goes on where the last run left this collection (the owners before its mark are done)' }
    }
    if ($Invoke.PSObject.Properties['SIRangeFirstTake'] -and [long]$Invoke.SIRangeFirstTake -gt 0) { $FirstTake = [long]$Invoke.SIRangeFirstTake }
    $take = [Math]::Max(1L, $FirstTake); $i = 0; $lastMs = 0L
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    $val = { param($row, $n) if ($null -eq $row) { $null } elseif ($row -is [System.Collections.IDictionary]) { $v = $row[$n]; if ($v -is [System.DBNull]) { $null } else { $v } } else { $p = $row.PSObject.Properties[$n]; if ($p) { $v = $p.Value; if ($v -is [System.DBNull]) { $null } else { $v } } else { $null } } }
    while ($true) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $take = [Math]::Max(1L, [long][Math]::Floor($take / 2)) } }
        $lop = ''; if ($hasLo) { $lop = ' AND OwnerKey > @RangeLo' }
        $b = @(Get-SIDataSeamRows -Invoke $Invoke -Sql ("SELECT LEFT(MAX(x.k), 400) AS Hi, COUNT_BIG(*) AS N, CASE WHEN @RangeLo IS NULL OR LEFT(MAX(x.k), 400) > @RangeLo THEN 1 ELSE 0 END AS Adv FROM (SELECT TOP (CONVERT(bigint, @Take)) OwnerKey AS k FROM sidata.CiFindingState WHERE 1 = 1{0} ORDER BY OwnerKey) AS x;" -f $lop) -Params @{ Take = [string]$take; RangeLo = $lo }) | Select-Object -First 1
        $hi = & $val $b 'Hi'; $n = & $val $b 'N'; if ($null -eq $n) { $n = 0 }; $adv = [int](& $val $b 'Adv')
        $last = ([long]$n -lt $take) -or ($null -eq $hi)
        # a cut bound that does not go past the last one (owner keys over 400 characters sharing their first 400): a larger range
        if (-not $last -and $adv -ne 1) { $take = $take * 2; continue }
        $i++
        $range = [pscustomobject]@{ Index = $i; HasLo = $hasLo; Lo = $lo; HasHi = (-not $last); Hi = $(if ($last) { $null } else { [string]$hi }) }
        $p = @{}; foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] }
        $null = Add-SIDataRangeParams -Params $p -Range $range
        $p['RangeLast'] = $(if ($last) { '1' } else { '0' })
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rows = @(Get-SIDataSeamRows -Invoke $Invoke -Sql (Expand-SIDataRangeMarker -Sql $Sql -Range $range) -Params $p)
        $lastMs = $sw.ElapsedMilliseconds
        $r = @($rows | Where-Object { $null -ne (& $val $_ 'Skipped') }) | Select-Object -First 1
        if (-not $r) { throw ('the database gave no answer for the finding lifecycle''s range {0}' -f $i) }
        foreach ($k in @($sum.Keys)) { $v = & $val $r $k; if ($null -ne $v) { $sum[$k] += [long]$v } }
        if ([int](& $val $r 'Skipped') -eq 1) { $skipped = 1; $note = [string](& $val $r 'Note') }
        if ($Log) { & $Log 'INFO' ('v3 model    : finding lifecycle -- range {0}: {1:N0} new, {2:N0} seen again, {3:N0} reopened, {4:N0} closed, {5:N0} absent -- {6:N1} s' -f $i, [long](& $val $r 'Opened'), [long](& $val $r 'Seen'), [long](& $val $r 'Reopened'), [long](& $val $r 'Closed'), [long](& $val $r 'Absent'), ($lastMs / 1000.0)) }
        if ($last) { break }
        if ($StopAfterRanges -gt 0 -and $i -ge $StopAfterRanges) { throw ('stopped after {0} range(s) (a test of a run that ends part-way)' -f $i) }
        $hasLo = $true; $lo = [string]$hi
        if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $take = Get-SIDataNextSize -Current $take -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
    }
    $o = [ordered]@{}; foreach ($k in $sum.Keys) { $o[$k] = [int]$sum[$k] }
    $o['Skipped'] = $skipped; $o['Note'] = $note
    # #960 THE ROW ITSELF, never wrapped: the caller collects it with @(...) and reads 'Skipped' with Get-SIItemValueOrNull --
    # ', @(row)' made its first item an array, every count was lost and the run said "nothing was closed" after the closes
    # were written (live 2026-10-30, every 3.0.9 data sync)
    [pscustomobject]$o
}

function Invoke-SIDataFindingModel {
    <# 2026-10-29 The one finding model (Get-SIDataFindingModelSql): per OwnerKey range of the states on a real database (each
       range one command, written only where a value differs), the one statement otherwise. Answers ONE row: Updated,
       Exempted, Tickets summed; Skipped = 1 on a database without the model's columns. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][hashtable]$Params, [scriptblock]$Log)
    if (-not (Test-SIDataLifecycleRanged $Invoke)) { return @(Get-SIDataSeamRows -Invoke $Invoke -Sql (Get-SIDataFindingModelSql) -Params $Params) | Select-Object -First 1 }
    $sql = Get-SIDataFindingModelSql -Ranged; $inv = $Invoke; $prm = $Params
    $ans = Invoke-SIDataKeyRanges -Invoke $Invoke -Table 'sidata.CiFindingState' -Column 'OwnerKey' -What 'v3 model    : the finding model' -Log $Log -FirstTake 50000 -Step {
        param($r)
        $p = @{}; foreach ($k in $prm.Keys) { $p[$k] = $prm[$k] }
        $null = Add-SIDataRangeParams -Params $p -Range $r
        $row = @(Get-SIDataSeamRows -Invoke $inv -Sql (Expand-SIDataRangeMarker -Sql $sql -Range $r) -Params $p) | Select-Object -First 1
        $u = [int](Get-SIItemValueOrNull $row 'Updated'); $e = [int](Get-SIItemValueOrNull $row 'Exempted'); $t = [int](Get-SIItemValueOrNull $row 'Tickets')
        [pscustomobject]@{ Updated = $u; Exempted = $e; Tickets = $t; Skipped = [int](Get-SIItemValueOrNull $row 'Skipped'); Text = ('{0:N0} written, {1:N0} exemption(s), {2:N0} ticket state(s)' -f $u, $e, $t) }
    }
    $o = [ordered]@{ Updated = 0; Exempted = 0; Tickets = 0; Skipped = 0 }
    foreach ($a in @($ans)) { $o.Updated += $a.Updated; $o.Exempted += $a.Exempted; $o.Tickets += $a.Tickets; if ($a.Skipped -eq 1) { $o.Skipped = 1 } }
    [pscustomobject]$o
}

function Invoke-SIDataCiLifecycle {
    <#
        After the findings were stored: the lifecycle, today's trend detail, the retention. Never throws; returns a summary.
        -Invoke the database seam; -Items the stored-finding items; -SnapshotTime their collection time; -Complete the verdict.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][object[]]$Items = @(), $SnapshotTime, [bool]$Complete = $false, [scriptblock]$Log,
          # #533: owner keys of disabled assets left out by a setting (Get-SIDataDisabledOwnerKeys) -- their absent findings freeze
          [AllowEmptyCollection()][string[]]$DisabledOwners = @(),
          # $false when the owners that are left out could not be read this run: the one-time repair of findings closed while
          # their asset was left out then waits for a run that knows them
          [bool]$OwnersKnown = $true,
          # owner keys whose absent findings freeze THIS RUN ONLY, for a reason that is not "left out by a setting": what rests
          # on a source that is on its last good collection (Get-SISourceDropoutOwners). Frozen exactly like the owners above,
          # but never part of the one-time repair (their earlier closes were real)
          [AllowEmptyCollection()][string[]]$SourceOwners = @(),
          # per report: the reports this run could not complete (Test-SIDataFindingCollectionComplete's FrozenReports) -- the
          # absent findings they found freeze this run; everything else closes as usual
          [AllowEmptyCollection()][string[]]$FrozenReports = @(),
          # #639: this collection's input is already in sidata.CiFindingLifecycleStage (staged page by page by the data sync):
          # nothing is read from -Items. Without it, -Items are staged here in chunks when the database has the staging table
          # (a database without it -- not updated yet -- is sent the input as before)
          [switch]$Staged)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $out = [ordered]@{ Opened = 0; Seen = 0; Reopened = 0; Closed = 0; Absent = 0; Frozen = 0; Carried = 0; Skipped = $true; Daily = 0; Purged = 0; FrozenOwners = 0
                       Repaired = 0; RetiredClosed = 0; Reactivated = 0; Rekeyed = 0; StaleRepair = $null; Unclosed = 0; Answered = $false; ModelUpdated = 0; ModelExempted = 0; ModelTickets = 0; DailyGraph = 0
                       # #639 what kept the lifecycle from being updated this run ('' = nothing) -- the data sync's run record says it
                       Problem = '' }
    $frozenOwners = @()
    # #639 the owner lists staged in chunks (sidata.CiOwnerStage) where the database has the table
    $ownStage = $null
    if (@($DisabledOwners).Count -or @($SourceOwners).Count) { $ownStage = New-SIDataCiOwnerStage -Invoke $Invoke }
    try {
        $snapIso = ''
        if ($SnapshotTime -is [datetime]) { $snapIso = $SnapshotTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff') } elseif ($SnapshotTime) { $snapIso = [string]$SnapshotTime }
        # ONE-TIME REPAIR, before anything is read: the findings of an asset left out NOW that were closed as fixed while the
        # owners to freeze were never found are open again (not counted as reopened). Not when the owners are unknown.
        if ($OwnersKnown) {
            $fr = @(Get-SIDataSeamRows -Invoke $Invoke -Sql (Get-SIDataFindingFreezeRepairSql) -Params @{ owners = (ConvertTo-SIDataCiOwnerParam -Stage $ownStage -Kind 'r' -Keys ([string[]]@($DisabledOwners))); since = (Get-SIDataFindingFreezeRepairSince) }) | Select-Object -First 1
            if ($fr -and $null -ne (Get-SIItemValueOrNull $fr 'Reopened') -and [int](Get-SIItemValueOrNull $fr 'Skipped') -ne 1) { $out.Unclosed = [int](Get-SIItemValueOrNull $fr 'Reopened') }
            if ($out.Unclosed -gt 0) {
                & $Log 'WARN' ("v3 model    : finding lifecycle -- {0} finding(s) of account(s) or device(s) that are left out had been closed as fixed although nothing showed a fix; they are open again as they were (first detected kept, not counted as reopened) and stay as they are while the asset is left out" -f $out.Unclosed)
            }
        }
        if ($snapIso -and (@($Items).Count -gt 0 -or $Staged)) {
            $after = Get-SIDataRetentionDays -Value $global:SI_VulnSync_CloseAfterRuns -Default 2
            # #639: the input through the staging table, in chunks -- never the whole collection as ONE JSON string
            $useStage = [bool]$Staged
            if (-not $useStage) {
                if (-not (Get-Command -Name Get-SIDataCiLifecycleStageCheckSql -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataCi.ps1') }
                $hasStage = $false
                try { $hasStage = ([string](& $Invoke (Get-SIDataCiLifecycleStageCheckSql) @{} 'scalar') -eq '1') } catch { $hasStage = $false }
                if ($hasStage) { $null = Write-SIDataCiLifecycleStage -Invoke $Invoke -Items @($Items) -First $true; $useStage = $true }
            }
            # #533 rule 4: which owners' absent findings freeze this run (the open rows absent from this collection, split by
            # Split-SIAbsentByDisabled against the disabled owners)
            $freezeKeys = @(@($DisabledOwners) + @($SourceOwners) | Where-Object { $_ })
            if ($freezeKeys.Count -gt 0) {
                if ($useStage) {
                    # computed in SQL against the staged input: neither the open rows nor the collection is held here
                    $frozenOwners = @(Get-SIDataSeamRows -Invoke $Invoke -Sql (Get-SIDataCiStagedFrozenOwnersSql) -Params @{ freeze = (ConvertTo-SIDataCiOwnerParam -Stage $ownStage -Kind 'f' -Keys ([string[]]@($freezeKeys))) } |
                            ForEach-Object { [string](Get-SIItemValueOrNull $_ 'OwnerKey') } | Where-Object { $_ } | Sort-Object -Unique)
                } else {
                    $open = @(Get-SIDataSeamRows -Invoke $Invoke -Sql "IF OBJECT_ID('sidata.CiFindingState') IS NULL SELECT CAST(NULL AS NVARCHAR(450)) AS OwnerKey, CAST(NULL AS NVARCHAR(256)) AS FindingKey WHERE 1 = 0 ELSE SELECT OwnerKey, FindingKey FROM sidata.CiFindingState WHERE State <> N'closed'")
                    $frozenOwners = @(Get-SIDataFindingFrozenOwners -OpenStates $open -Items $Items -DisabledOwners $freezeKeys)
                }
            }
            $out.FrozenOwners = $frozenOwners.Count
            $lp = @{ snap = $snapIso; complete = $(if ($Complete) { '1' } else { '0' }); closeAfter = [string]$after; disabledOwners = (ConvertTo-SIDataCiOwnerParam -Stage $ownStage -Kind 'o' -Keys ([string[]]@($frozenOwners))) }
            if (-not $useStage) {
                # (a database not updated yet: the input as before; #464 rule 4: the key changes of the recommendation
                # equivalence -- the lifecycle rows under an alias are carried)
                $lp['j'] = ConvertTo-Json -InputObject @(ConvertTo-SIDataFindingStateItems -Items $Items) -Compress -Depth 4
                $lp['equivalence'] = ConvertTo-Json -InputObject @(ConvertTo-SIDataFindingAliasItems -Items $Items) -Compress -Depth 3
            }
            $frz = @($FrozenReports | Where-Object { "$_".Trim() })
            if ($frz.Count) { $lp['frozenReports'] = ConvertTo-Json -InputObject @($frz) -Compress }
            if ($useStage -and (Test-SIDataLifecycleRanged $Invoke)) {
                # 2026-10-29 a real database: one OwnerKey range at a time, each its own transaction (one transaction over every
                # lifecycle row ran past the platform's limit at the largest installs)
                $rows = @(Invoke-SIDataFindingStateRanged -Invoke $Invoke -Sql (Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage -WithFrozenReports:($frz.Count -gt 0) -Ranged) -Params $lp -Snap $snapIso -Log $Log)
            } else {
                $rows = @(Get-SIDataSeamRows -Invoke $Invoke -Sql (Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage:$useStage -WithFrozenReports:($frz.Count -gt 0)) -Params $lp)
            }
            if ($useStage) { try { Clear-SIDataCiStage -Invoke $Invoke -Table 'sidata.CiFindingLifecycleStage' } catch { } }
            # the answer is the row that carries the counts -- anything else (no row, a row without them) is NOT "0 new": it
            # is said as such, never reported as a lifecycle that found nothing
            $r = @($rows | Where-Object { $null -ne (Get-SIItemValueOrNull $_ 'Skipped') }) | Select-Object -First 1
            if ($r) {
                $out.Answered = $true
                foreach ($k in 'Opened', 'Seen', 'Reopened', 'Closed', 'Absent', 'Frozen', 'Carried', 'Repaired', 'RetiredClosed', 'Reactivated', 'Rekeyed') { $v = Get-SIItemValueOrNull $r $k; if ($null -ne $v -and $v -isnot [System.DBNull]) { $out[$k] = [int]$v } }
                $out.Skipped = ([int](Get-SIItemValueOrNull $r 'Skipped')) -eq 1
            } else {
                $out.Problem = 'the database gave no answer for this collection'
                & $Log 'WARN' 'v3 model    : finding lifecycle -- the database gave no answer for this collection, so what was new, seen again or closed is not known this run. The findings are stored; it is read again on the next run.'
            }
        } else { $out.Answered = $true }
        # REMOVE-ME with the setting: the one-time repair of stale open rows (off by default; count = read only)
        if ($out.Answered) { $out.StaleRepair = Invoke-SIDataLifecycleStaleOpenRepair -Invoke $Invoke -Complete $Complete -Log $Log }
        # #494 the one finding model: owner, services, SLA and due date, exemption, ticket, excluded
        $sla = Get-SIDataFindingSlaDays
        $fm = @(Invoke-SIDataFindingModel -Invoke $Invoke -Log $Log -Params @{ dis = (ConvertTo-SIDataCiOwnerParam -Stage $ownStage -Kind 'o' -Keys ([string[]]@($frozenOwners))); crit = [string]$sla.critical; high = [string]$sla.high
                                                          med = [string]$sla.medium; low = [string]$sla.low }) | Select-Object -First 1
        if ($fm -and [int](Get-SIItemValueOrNull $fm 'Skipped') -ne 1) { $out.ModelUpdated = [int](Get-SIItemValueOrNull $fm 'Updated'); $out.ModelExempted = [int](Get-SIItemValueOrNull $fm 'Exempted'); $out.ModelTickets = [int](Get-SIItemValueOrNull $fm 'Tickets') }
        if (Test-SIDataLifecycleRanged $Invoke) {
            $out.Daily = [int](Invoke-SIDataCiRangedStatement -Invoke $Invoke -Sql (Get-SIDataCiDailyDetailSql -Ranged) -What 'v3 model    : today''s trend row of the CIs' -Log $Log)
        } else { $out.Daily = [int](& $Invoke (Get-SIDataCiDailyDetailSql) @{} 'scalar') }
        # #495 the daily row's graph detail (lifecycle, exposure, services, relations, overdue / exempted findings)
        if (Test-SIDataLifecycleRanged $Invoke) {
            $out.DailyGraph = [int](Invoke-SIDataCiRangedStatement -Invoke $Invoke -Sql (Get-SIDataCiDailyGraphSql -Ranged) -What 'v3 model    : today''s trend row''s graph detail' -Log $Log)
        } else { $out.DailyGraph = [int](& $Invoke (Get-SIDataCiDailyGraphSql) @{} 'scalar') }
        $out.Purged = [long](Invoke-SIDataCiRetention -Invoke $Invoke -Log $Log -Params @{ change = [string](Get-SIDataRetentionDays $global:SI_Pro_CiChangeRetentionDays 730); daily = [string](Get-SIDataRetentionDays $global:SI_Pro_CiDailyRetentionDays 400)
                                                                    state = [string](Get-SIDataRetentionDays $global:SI_Pro_FindingStateRetentionDays 365) })
        if ($out.ModelUpdated -gt 0 -or $out.ModelExempted -gt 0 -or $out.ModelTickets -gt 0) {
            & $Log 'INFO' ("v3 model    : findings per CI -- {0} finding(s) got their owner, services, SLA or due date, {1} their exemption, {2} their ticket state" -f $out.ModelUpdated, $out.ModelExempted, $out.ModelTickets)
        }
        if (-not $out.Answered) { }   # said above: no answer is not "0 new"
        elseif ($out.Skipped) {
            if ($out.Repaired -gt 0) { & $Log 'WARN' ("v3 model    : finding lifecycle -- {0} finding(s) of the collection already processed had no lifecycle record and got one (first detected = the time of that collection); nothing was counted absent or closed" -f $out.Repaired) }
            else { & $Log 'INFO' 'v3 model    : finding lifecycle -- nothing new to process (the collection was already processed, or the database is not updated yet)' }
        }
        else {
            if ($out.Carried -gt 0) { & $Log 'INFO' ("v3 model    : finding lifecycle -- {0} finding(s) now reported under one shared recommendation keep their history (first detected carried over)" -f $out.Carried) }
            # #406 owner 2026-10-19: a retired asset's findings close as asset retired, also those still reported
            if ($out.RetiredClosed -gt 0) { & $Log 'INFO' ("v3 model    : finding lifecycle -- {0} finding(s) of retired assets closed as asset retired (also those still reported -- never as fixed)" -f $out.RetiredClosed) }
            if ($out.Rekeyed -gt 0) { & $Log 'INFO' ("v3 model    : finding lifecycle -- {0} finding(s) under an old asset key closed as rekeyed: the same finding is reported under its CI now (not a fix; the CI's record carries on)" -f $out.Rekeyed) }
            if ($out.Reactivated -gt 0) { & $Log 'INFO' ("v3 model    : finding lifecycle -- {0} finding(s) reopened because their asset is active again (asset reactivated)" -f $out.Reactivated) }
            & $Log 'OK' ("v3 model    : finding lifecycle -- {0} new, {1} seen again, {2} reopened, {3} closed{4}" -f $out.Opened, $out.Seen, $out.Reopened, $out.Closed,
                $(if ($Complete) { $(if ($out.Frozen -gt 0 -and @($FrozenReports).Count) { ('; {0} absent finding(s) are kept as they are -- found by a report this run could not complete ({1}), or of a disabled account or device left out by a setting -- not resolved or closed' -f $out.Frozen, (@($FrozenReports) -join ', ')) }
                                   elseif ($out.Frozen -gt 0) { ('; {0} absent finding(s) of {1} disabled account(s) or device(s) left out by a setting are kept as they are (excluded, disabled -- not resolved or closed)' -f $out.Frozen, $out.FrozenOwners) } else { '' }) }
                  else { ('; {0} absent finding(s) left open: the Risk Analysis run was not shown complete' -f $out.Frozen) }))
        }
    } catch {
        $out.Problem = $_.Exception.Message
        & $Log 'WARN' ("v3 model    : the finding lifecycle was not updated this run -- {0}. The findings are stored; it is tried again on the next run." -f $_.Exception.Message)
    } finally { Clear-SIDataCiOwnerStage -Stage $ownStage }
    [pscustomobject]$out
}

function Get-SIItemValueOrNull {
    <# PURE. A property / key of a row, or $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { return $Row[$Name] }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}
