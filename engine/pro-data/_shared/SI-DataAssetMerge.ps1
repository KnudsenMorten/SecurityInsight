#Requires -Version 5.1
<#
    SecurityInsight Pro -- ONE ASSET PER DEVICE in the Pro database (#297, #298): the data sync merges the duplicate and
    phantom assets earlier loads stored into the asset that carries their id. Found 2026-10-05 on ring 1:
      #297  attack-path rows keyed on the Entra device id became phantom assets beside the real one (dc1 -> 367e007c,
            dc3 -> a85ab003, mgmt1 -> fa6a7a3b): the same path counted twice;
      #298  two assets for one Defender device (SonosZP keyed on its MDE device id beside the ledger asset that carries it;
            an asset keyed on an SI_AssetId stored before the ledger gave it its durable id).
    New loads resolve such ids at load (SI-DataModel.ps1, Resolve-SIDataFindingAssetId); this repairs what is stored.
    GUARDED (Select-SIDataAssetMerges: unambiguous only, never an asset a setting names, never a ledger asset, re-checked in
    the transaction), IDEMPOTENT (a merged asset is gone), dry-run aware, and returned for the audit trail
    (datasync.asset.merge, written by Invoke-SIDataSync.ps1). PS 5.1 safe.
#>
# ---------------------------------------------------------------------------------------------------------------------
#  REPAIR: duplicate and phantom assets (#297, #298)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataDuplicateAssetsSql {
    <#
        Asset pairs (From -> To): From is NOT a ledger asset and its key is an IDENTIFIER of another asset To (an Entra
        device id, a Defender device id, an SI_AssetId the ledger later gave a durable id). Owners = how many other assets
        carry that value (more than one: ambiguous, never merged). Refs = settings rows (exemptions, overrides, tasks,
        comments, service links) that name From: a merge would orphan them, so it is left for a person. -1 when the
        settings tables are not in this database (cannot be checked: not merged).
    #>
    $refTables = @('cfg.Exemption', 'cfg.ResponsibilityOverride', 'cfg.CmdbServiceAsset', 'cfg.ExemptionRequestItem', 'cfg.GovernanceEntry', 'cfg.GovernanceState', 'cfg.FindingComment', 'cfg.FindingTask')
    $refs = ($refTables | ForEach-Object { "CASE WHEN OBJECT_ID('$_') IS NULL THEN 0 ELSE 1 END" }) -join ' + '
    $count = ($refTables | ForEach-Object { "(SELECT COUNT_BIG(*) FROM $_ AS r WHERE r.AssetKey = d.FromKey)" }) -join ' + '
    @"
WITH d AS (
    SELECT p.AssetKey AS FromKey, MAX(p.AssetName) AS FromName, t.AssetKey AS ToKey, MAX(t.AssetName) AS ToName, MAX(t.KeySource) AS ToSource,
           MIN(i.IdentifierType) AS Via,
           (SELECT COUNT(DISTINCT i2.AssetKey) FROM sidata.AssetIdentifier AS i2 WHERE i2.IdentifierValue = LOWER(p.AssetKey) AND i2.AssetKey <> p.AssetKey) AS Owners,
           (SELECT COUNT_BIG(*) FROM sidata.Finding AS f WHERE f.AssetKey = p.AssetKey) AS Findings
    FROM sidata.Asset AS p
    JOIN sidata.AssetIdentifier AS i ON i.IdentifierValue = LOWER(p.AssetKey) AND i.AssetKey <> p.AssetKey
    JOIN sidata.Asset AS t ON t.AssetKey = i.AssetKey
    WHERE p.KeySource <> N'ledger'
    GROUP BY p.AssetKey, t.AssetKey
)
SELECT d.FromKey, d.FromName, d.ToKey, d.ToName, d.ToSource, d.Via, d.Owners, d.Findings, CAST(-1 AS bigint) AS Refs
FROM d WHERE ($refs) < $($refTables.Count)
UNION ALL
SELECT d.FromKey, d.FromName, d.ToKey, d.ToName, d.ToSource, d.Via, d.Owners, d.Findings, CAST(0 AS bigint) AS Refs
FROM d WHERE ($refs) = $($refTables.Count)
ORDER BY 1, 3;
"@
}

function Get-SIDataDuplicateRefsSql {
    <# The settings rows that name one asset key (run only when every settings table exists in this database). #>
    $refTables = @('cfg.Exemption', 'cfg.ResponsibilityOverride', 'cfg.CmdbServiceAsset', 'cfg.ExemptionRequestItem', 'cfg.GovernanceEntry', 'cfg.GovernanceState', 'cfg.FindingComment', 'cfg.FindingTask')
    'SELECT ' + (($refTables | ForEach-Object { "(SELECT COUNT_BIG(*) FROM $_ AS r WHERE r.AssetKey = @AssetKey)" }) -join ' + ') + ' AS Refs;'
}

function Select-SIDataAssetMerges {
    <#
        PURE. The candidate rows -> what is merged and what is not, and why. A From is merged only when exactly ONE other
        asset carries its key (Owners = 1), no settings row names it (Refs = 0), and its target is not itself merged away
        in this run. Returns @{ Merge = @(@{ From; FromName; To; ToName; Via; Findings }); Skip = @(@{ From; FromName; Reason }) }.
    #>
    param([AllowEmptyCollection()][object[]]$Candidates = @())
    $g = @{}
    foreach ($c in @($Candidates)) { if ($null -eq $c) { continue }; $k = ([string]$c.FromKey); if (-not $g.ContainsKey($k)) { $g[$k] = New-Object System.Collections.Generic.List[object] }; $g[$k].Add($c) }
    $froms = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $g.Keys) { [void]$froms.Add($k) }
    $merge = New-Object System.Collections.Generic.List[object]; $skip = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($g.Keys | Sort-Object)) {
        $rows = $g[$k].ToArray(); $c = $rows[0]
        $item = @{ From = $k; FromName = [string]$c.FromName }
        if ($rows.Count -gt 1 -or [long]$c.Owners -gt 1) { $skip.Add([pscustomobject]($item + @{ Reason = ('its id is carried by {0} other assets -- ambiguous, left as it is' -f [Math]::Max($rows.Count, [long]$c.Owners)) })); continue }
        if ([long]$c.Refs -lt 0) { $skip.Add([pscustomobject]($item + @{ Reason = 'the settings tables are not in this database, so it cannot be checked that no exemption, task or override names it -- left as it is' })); continue }
        if ([long]$c.Refs -gt 0) { $skip.Add([pscustomobject]($item + @{ Reason = ('{0} setting(s) (exemption, task, comment, override or service link) name it -- left for a person to move' -f [long]$c.Refs) })); continue }
        if ($froms.Contains([string]$c.ToKey)) { $skip.Add([pscustomobject]($item + @{ Reason = ('its match {0} is itself a duplicate -- merged on a later run' -f [string]$c.ToKey) })); continue }
        $merge.Add([pscustomobject]@{ From = $k; FromName = [string]$c.FromName; To = [string]$c.ToKey; ToName = [string]$c.ToName; Via = [string]$c.Via; Findings = [long]$c.Findings })
    }
    [pscustomobject]@{ Merge = $merge.ToArray(); Skip = $skip.ToArray() }
}

function Get-SIDataMergeAssetSql {
    <#
        ONE merge, one transaction: the From asset's findings, recommendations and identifiers move to To, its tags go
        (they are stored again for To on the next load), the asset row goes, and every collection that held its findings is
        derived again. Re-checked INSIDE the transaction: To exists, From exists and is not a ledger asset -- else nothing
        is changed. Returns one row per day touched (Day, Findings) -- none when nothing moved.
    #>
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM sidata.Asset WHERE AssetKey = @To) OR NOT EXISTS (SELECT 1 FROM sidata.Asset WHERE AssetKey = @From AND KeySource <> N'ledger')
BEGIN ROLLBACK; SELECT CAST(NULL AS nvarchar(10)) AS [Day], CAST(-1 AS int) AS Findings WHERE 1 = 0; RETURN; END;
CREATE TABLE #t (CollectionId int PRIMARY KEY);
INSERT #t (CollectionId) SELECT DISTINCT CollectionId FROM sidata.Finding WHERE AssetKey = @From;
UPDATE sidata.Finding SET AssetKey = @To WHERE AssetKey = @From;
DECLARE @n int = @@ROWCOUNT;
UPDATE sidata.Recommendation SET AssetKey = @To WHERE AssetKey = @From;
INSERT sidata.AssetIdentifier (AssetKey, IdentifierType, IdentifierValue, FirstSeen, LastSeen)
SELECT @To, i.IdentifierType, i.IdentifierValue, i.FirstSeen, i.LastSeen FROM sidata.AssetIdentifier AS i
WHERE i.AssetKey = @From AND NOT EXISTS (SELECT 1 FROM sidata.AssetIdentifier AS x WHERE x.AssetKey = @To AND x.IdentifierType = i.IdentifierType AND x.IdentifierValue = i.IdentifierValue);
DELETE FROM sidata.AssetIdentifier WHERE AssetKey = @From;
IF OBJECT_ID('sidata.AssetTag') IS NOT NULL EXEC sp_executesql N'DELETE FROM sidata.AssetTag WHERE AssetKey = @k', N'@k nvarchar(400)', @k = @From;
UPDATE a SET LastSeen = CASE WHEN f.LastSeen > a.LastSeen THEN f.LastSeen ELSE a.LastSeen END
FROM sidata.Asset AS a CROSS JOIN (SELECT LastSeen FROM sidata.Asset WHERE AssetKey = @From) AS f WHERE a.AssetKey = @To;
DELETE FROM sidata.Asset WHERE AssetKey = @From;
UPDATE c SET DerivedAt = NULL FROM sidata.Collection AS c JOIN #t AS t ON t.CollectionId = c.CollectionId;
IF COL_LENGTH('sidata.Collection', 'ServicesDerivedAt') IS NOT NULL
    EXEC (N'UPDATE c SET ServicesDerivedAt = NULL FROM sidata.Collection AS c JOIN #t AS t ON t.CollectionId = c.CollectionId');
IF COL_LENGTH('sidata.Collection', 'ResolvedVersion') IS NOT NULL
    EXEC (N'UPDATE c SET ResolvedVersion = NULL FROM sidata.Collection AS c JOIN #t AS t ON t.CollectionId = c.CollectionId');
COMMIT;
SELECT DISTINCT CONVERT(nvarchar(10), CAST(c.CollectionTime AS date), 23) AS [Day], @n AS Findings
FROM #t AS t JOIN sidata.Collection AS c ON c.CollectionId = t.CollectionId;
'@
}

function Invoke-SIDataDuplicateAssetMerge {
    <#
        #297/#298: merges every unambiguous duplicate / phantom asset into the asset that carries its id (see
        Get-SIDataDuplicateAssetsSql and Select-SIDataAssetMerges for the guards). -DryRun reports only. Idempotent: a
        merged asset is gone, so a second run finds nothing. Returns @{ Merged; Skipped; Findings; Days }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $raw = & $Invoke (Get-SIDataDuplicateAssetsSql) @{} 'reader'
    $cands = @(@($raw) | Where-Object { $_ } | ForEach-Object {
        [pscustomobject]@{ FromKey = [string]$_['FromKey']; FromName = [string]$_['FromName']; ToKey = [string]$_['ToKey']; ToName = [string]$_['ToName']; Via = [string]$_['Via']
                           Owners = [long]$_['Owners']; Findings = [long]$_['Findings']; Refs = [long]$_['Refs'] } })
    # the settings references, counted per candidate (the candidate list says only whether the tables exist)
    foreach ($c in $cands) { if ($c.Refs -eq 0) { $c.Refs = [long](& $Invoke (Get-SIDataDuplicateRefsSql) @{ AssetKey = $c.FromKey } 'scalar') } }
    $sel = Select-SIDataAssetMerges -Candidates $cands
    foreach ($s in $sel.Skip) { & $Log 'WARN' ("assets      : '{0}' ({1}) looks like a duplicate but is NOT merged: {2}." -f $s.FromName, $s.From, $s.Reason) }
    $res = [pscustomobject]@{ Merged = @(); Skipped = @($sel.Skip); Findings = 0L; Days = @() }
    if (-not @($sel.Merge).Count) { return $res }
    if ($DryRun) {
        foreach ($m in $sel.Merge) { & $Log 'INFO' ("assets      : '{0}' ({1}) would be merged into '{2}' ({3}), which carries its id as {4}; {5} finding(s) would move. Nothing is written." -f $m.FromName, $m.From, $m.ToName, $m.To, $m.Via, $m.Findings) }
        $res.Merged = @($sel.Merge); $res.Findings = [long](($sel.Merge | Measure-Object -Property Findings -Sum).Sum)
        return $res
    }
    $days = New-Object System.Collections.Generic.List[string]
    $done = New-Object System.Collections.Generic.List[object]
    foreach ($m in $sel.Merge) {
        # a reader answer is ONE array object: assigned first, then enumerated (as everywhere in the data sync)
        $mergeRaw = & $Invoke (Get-SIDataMergeAssetSql) @{ From = $m.From; To = $m.To } 'reader'
        $rows = @(@($mergeRaw) | Where-Object { $_ })
        $moved = if ($rows.Count) { [long]$rows[0]['Findings'] } else { 0L }
        foreach ($r in $rows) { $d = [string]$r['Day']; if ($d -and -not $days.Contains($d)) { $days.Add($d) } }
        $done.Add([pscustomobject]@{ From = $m.From; FromName = $m.FromName; To = $m.To; ToName = $m.ToName; Via = $m.Via; Findings = $moved })
        $res.Findings += $moved
        & $Log 'OK' ("assets      : '{0}' ({1}) merged into '{2}' ({3}), which carries its id as {4}; {5} finding(s) moved" -f $m.FromName, $m.From, $m.ToName, $m.To, $m.Via, $moved)
    }
    $res.Merged = $done.ToArray(); $res.Days = $days.ToArray()
    $res
}
