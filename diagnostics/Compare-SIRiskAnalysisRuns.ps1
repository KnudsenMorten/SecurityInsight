#Requires -Version 5.1
<#
.SYNOPSIS
    READ-ONLY. Compares the Risk Analysis run on the OLD path (result gathered in memory, loaded into SQL by the data sync
    from Log Analytics) with the run on the NEW path (#638: the result written to SQL a query slice at a time) -- the proof
    on the internal install that the new path gives the same result.

.DESCRIPTION
    Nothing is written anywhere. What it compares, and says plainly:
      1. Detailed: the rows per report, old collection vs new; then a row-level diff on the key (report, asset id,
         configuration id) of the score, severity, tier and trace id -- every row only in one of them, and every row that
         differs, up to -MaxDiffs listed;
      2. Summary: the groups per report (report, configuration, tier, severity, CMDB id / name) -- impacted asset count and
         scores, every group only in one or different;
      3. the KPI and the top 50 assets / findings (sidata.RiskExecView): the view kept now against the one saved by
         -SaveBefore before the new run (run once with -SaveBefore <file> BEFORE the run, then with -Before <file> after);
      4. the trend (SI_Trend_CL, with -WorkspaceId): the rollup row of the old run against the new run's;
      5. Log Analytics (with -WorkspaceId): the new collection's rows per report in SI_RiskAnalysis_<grain>_CL against the
         rows in SQL (Log Analytics gets every row too);
      6. #641: the new run's verdict per report (sidata.RaReportStatus) -- expected by the source, retrieved, stored, state,
         reason; with SI_RA_BucketProof = on for that run, the reason carries the bucket proof (buckets vs the whole query).
    The old and new collections are the newest of each kind unless -OldCollectionTime / -NewCollectionTime name them.

    SIGN-IN: -SqlAccessToken (a bearer token for https://database.windows.net/) or -SqlConnectionString; for Log Analytics
    -LaAccessToken (a bearer token for https://api.loganalytics.io). With the Invardia Support app: take the tokens from the
    support session. No PowerShell modules.

.EXAMPLE
    # before the release / the first new-path run:
    .\Compare-SIRiskAnalysisRuns.ps1 -SqlServer <sql-server-name> -SqlDatabase sidb -SqlAccessToken $t -SaveBefore .\before.json
    # after the new-path run:
    .\Compare-SIRiskAnalysisRuns.ps1 -SqlServer <sql-server-name> -SqlDatabase sidb -SqlAccessToken $t -Before .\before.json -WorkspaceId <guid> -LaAccessToken $la
#>
[CmdletBinding()]
param(
    [string]$SqlServer,
    [string]$SqlDatabase,
    [string]$SqlAccessToken,
    [string]$SqlConnectionString,
    [string]$WorkspaceId,
    [string]$LaAccessToken,
    [ValidateSet('Detailed', 'Summary', 'Both')][string]$Grain = 'Both',
    [datetime]$OldCollectionTime,
    [datetime]$NewCollectionTime,
    [string]$SaveBefore,
    [string]$Before,
    [int]$MaxDiffs = 50
)

$ErrorActionPreference = 'Stop'
$inv = [Globalization.CultureInfo]::InvariantCulture

function Invoke-CmpSql {
    param([string]$Sql, [hashtable]$P = @{})
    $cs = if ($SqlConnectionString) { $SqlConnectionString } else { 'Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;ApplicationIntent=ReadOnly;' -f $SqlServer, $SqlDatabase }
    $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
    if ($SqlAccessToken) { $cn.AccessToken = $SqlAccessToken }
    try {
        $cn.Open()
        $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
        foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $P[$k]) { [DBNull]::Value } else { $P[$k] })) }
        $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
        while ($rd.Read()) { $h = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $v = $rd.GetValue($i); $h[$rd.GetName($i)] = $(if ($v -is [DBNull]) { $null } else { $v }) }; $out.Add([pscustomobject]$h) }
        $rd.Close(); , $out.ToArray()
    } finally { $cn.Dispose() }
}
function Invoke-CmpKql([string]$Kql) {
    $body = @{ query = $Kql } | ConvertTo-Json -Compress
    $r = Invoke-RestMethod -Method Post -Uri ("https://api.loganalytics.io/v1/workspaces/{0}/query" -f $WorkspaceId) -Headers @{ Authorization = "Bearer $LaAccessToken" } -ContentType 'application/json' -Body $body
    $t = $r.tables[0]; $cols = @($t.columns | ForEach-Object { $_.name })
    @(foreach ($row in $t.rows) { $h = [ordered]@{}; for ($i = 0; $i -lt $cols.Count; $i++) { $h[$cols[$i]] = $row[$i] }; [pscustomobject]$h })
}
function Say([string]$Text) { Write-Host $Text }
function Head([string]$Text) { Write-Host ''; Write-Host ('==== {0} ' -f $Text).PadRight(100, '=') }
function SqlTime([datetime]$t) { $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv) }

if (-not $SqlConnectionString -and (-not $SqlServer -or -not $SqlDatabase -or -not $SqlAccessToken)) { throw 'give -SqlServer, -SqlDatabase and -SqlAccessToken (or -SqlConnectionString)' }
$hasNew = @(Invoke-CmpSql "SELECT CASE WHEN COL_LENGTH('sidata.Collection','Source') IS NOT NULL AND OBJECT_ID('sidata.RaReportStatus') IS NOT NULL THEN 1 ELSE 0 END AS ok")[0].ok -eq 1
if (-not $hasNew) { throw 'this database does not have the tables of the new path yet (the updater adds them) -- nothing to compare' }
$result = [ordered]@{ Detailed = $null; Summary = $null; ExecView = $null; Trend = $null; LogAnalytics = $null; Status = $null; Differences = 0 }

# ---- the exec view snapshot (KPI + top 50), saved BEFORE the new run ------------------------------------------------
$execNow = @(Invoke-CmpSql 'SELECT Grain, GeneratedAt, CollectionTime, PayloadJson FROM sidata.RiskExecView')
if ($SaveBefore) {
    # one value per column (a reader can hand a column back as a one-element list)
    $one = { param($v) @($v | Where-Object { $null -ne $_ -and $_ -isnot [System.DBNull] })[0] }
    $snap = @($execNow | ForEach-Object { $ga = & $one $_.GeneratedAt; $ca = & $one $_.CollectionTime
        [ordered]@{ Grain = [string](& $one $_.Grain); GeneratedAt = $(if ($ga) { ([datetime]$ga).ToString('o') }); CollectionTime = $(if ($ca) { ([datetime]$ca).ToString('o') }); PayloadJson = [string](& $one $_.PayloadJson) } })
    ConvertTo-Json -InputObject @($snap) -Depth 4 | Set-Content -LiteralPath $SaveBefore -Encoding UTF8
    Say ("saved the executive views kept now ({0} grain(s)) to {1} -- run again with -Before after the new run" -f $snap.Count, $SaveBefore)
}

$grains = if ($Grain -eq 'Both') { @('Detailed', 'Summary') } else { @($Grain) }
foreach ($g in $grains) {
    if ($g -eq 'Detailed') {
        Head 'DETAILED: rows per report (old path vs new path)'
        $oldC = if ($OldCollectionTime) { @(Invoke-CmpSql "SELECT TOP 1 CollectionId, CollectionTime, Status, [Rows] FROM sidata.Collection WHERE Kind='Detailed' AND CollectionTime = CONVERT(datetime2(3), @t, 126)" @{ t = (SqlTime $OldCollectionTime) }) }
                else { @(Invoke-CmpSql "SELECT TOP 1 CollectionId, CollectionTime, Status, [Rows] FROM sidata.Collection WHERE Kind='Detailed' AND Status='Complete' AND ISNULL(Source,'') <> 'risk-analysis' ORDER BY CollectionTime DESC") }
        $newC = if ($NewCollectionTime) { @(Invoke-CmpSql "SELECT TOP 1 CollectionId, CollectionTime, Status, [Rows], RaCompletedAt, RaPartialReason FROM sidata.Collection WHERE Kind='Detailed' AND CollectionTime = CONVERT(datetime2(3), @t, 126)" @{ t = (SqlTime $NewCollectionTime) }) }
                else { @(Invoke-CmpSql "SELECT TOP 1 CollectionId, CollectionTime, Status, [Rows], RaCompletedAt, RaPartialReason FROM sidata.Collection WHERE Kind='Detailed' AND Source = 'risk-analysis' ORDER BY CollectionTime DESC") }
        if (-not $oldC -or -not $newC) { Say 'one of the two Detailed collections is not there -- nothing to compare'; continue }
        $o = $oldC[0]; $n = $newC[0]
        Say ("old: collection {0} of {1:u} ({2}, {3} rows)" -f $o.CollectionId, $o.CollectionTime, $o.Status, $o.Rows)
        Say ("new: collection {0} of {1:u} ({2}, {3} rows, result in: {4}{5})" -f $n.CollectionId, $n.CollectionTime, $n.Status, $n.Rows, $(if ($n.RaCompletedAt) { 'yes' } else { 'NO' }), $(if ($n.RaPartialReason) { '; partial: ' + $n.RaPartialReason } else { '' }))
        $per = @(Invoke-CmpSql @'
SELECT COALESCE(o.R, n.R) AS Report, ISNULL(o.N, 0) AS OldRows, ISNULL(n.N, 0) AS NewRows FROM
 (SELECT ISNULL(ReportName, '') AS R, COUNT(*) AS N FROM sidata.Finding WHERE CollectionId = @o GROUP BY ReportName) o
 FULL JOIN (SELECT ISNULL(ReportName, '') AS R, COUNT(*) AS N FROM sidata.Finding WHERE CollectionId = @n GROUP BY ReportName) n ON o.R = n.R
ORDER BY 1
'@ @{ o = [int]$o.CollectionId; n = [int]$n.CollectionId })
        $per | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        $diffReports = @($per | Where-Object { $_.OldRows -ne $_.NewRows })
        Say ("{0} report(s), {1} with a different row count" -f $per.Count, $diffReports.Count)
        $keyCte = @'
WITH o AS (SELECT ISNULL(ReportName,'') AS R, LOWER(COALESCE(JSON_VALUE(DetailJson,'$.SI_AssetId'), JSON_VALUE(DetailJson,'$.AssetId'), AssetKey, '')) AS A, ISNULL(ConfigurationId,'') AS C,
                  RiskScore AS S, Severity AS V, Tier AS T, JSON_VALUE(DetailJson,'$.TraceID') AS I FROM sidata.Finding WHERE CollectionId = @o),
     n AS (SELECT ISNULL(ReportName,'') AS R, LOWER(COALESCE(JSON_VALUE(DetailJson,'$.SI_AssetId'), JSON_VALUE(DetailJson,'$.AssetId'), AssetKey, '')) AS A, ISNULL(ConfigurationId,'') AS C,
                  RiskScore AS S, Severity AS V, Tier AS T, JSON_VALUE(DetailJson,'$.TraceID') AS I FROM sidata.Finding WHERE CollectionId = @n),
     d AS (SELECT COALESCE(o.R, n.R) AS Report, COALESCE(o.A, n.A) AS Asset, COALESCE(o.C, n.C) AS Config,
                  CASE WHEN o.R IS NULL THEN 'only in the NEW run' WHEN n.R IS NULL THEN 'only in the OLD run' ELSE 'differs' END AS Kind,
                  o.S AS OldScore, n.S AS NewScore, o.V AS OldSeverity, n.V AS NewSeverity, o.T AS OldTier, n.T AS NewTier, o.I AS OldTraceId, n.I AS NewTraceId
           FROM o FULL JOIN n ON o.R = n.R AND o.A = n.A AND o.C = n.C
           WHERE o.R IS NULL OR n.R IS NULL OR ISNULL(o.S, -1) <> ISNULL(n.S, -1) OR ISNULL(o.V, '') <> ISNULL(n.V, '') OR ISNULL(o.T, 255) <> ISNULL(n.T, 255) OR ISNULL(o.I, '') <> ISNULL(n.I, ''))
'@
        $kinds = @(Invoke-CmpSql ($keyCte + 'SELECT Kind, COUNT(*) AS Rows FROM d GROUP BY Kind') @{ o = [int]$o.CollectionId; n = [int]$n.CollectionId })
        Head 'DETAILED: row-level diff (key: report, asset id, configuration id)'
        if ($kinds.Count -eq 0) { Say 'EQUAL: every row of the old run is in the new run with the same score, severity, tier and trace id, and nothing else.' }
        else {
            $kinds | Format-Table -AutoSize | Out-String | Write-Host
            $rows = @(Invoke-CmpSql ($keyCte + ('SELECT TOP ({0}) * FROM d ORDER BY Kind, Report, Asset, Config' -f [int]$MaxDiffs)) @{ o = [int]$o.CollectionId; n = [int]$n.CollectionId })
            $rows | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
            $result.Differences += [long](($kinds | Measure-Object -Property Rows -Sum).Sum)
        }
        $result.Detailed = [pscustomobject]@{ Old = $o; New = $n; PerReport = $per; Kinds = $kinds }
        $statusTime = $n.CollectionTime
        $laTable = 'SI_RiskAnalysis_Detailed_CL'
    } else {
        Head 'SUMMARY: groups per report (old path vs new path)'
        $oldT = if ($OldCollectionTime) { $OldCollectionTime } else { (@(Invoke-CmpSql "SELECT TOP 1 CollectionTime FROM sidata.SummaryLoad WHERE Status='Complete' AND ISNULL(Source,'') <> 'risk-analysis' ORDER BY CollectionTime DESC") | Select-Object -First 1).CollectionTime }
        $newT = if ($NewCollectionTime) { $NewCollectionTime } else { (@(Invoke-CmpSql "SELECT TOP 1 CollectionTime FROM sidata.SummaryLoad WHERE Source = 'risk-analysis' ORDER BY CollectionTime DESC") | Select-Object -First 1).CollectionTime }
        if (-not $oldT -or -not $newT) { Say 'one of the two Summary collections is not there -- nothing to compare'; continue }
        Say ("old: {0:u}   new: {1:u}" -f $oldT, $newT)
        $p = @{ o = (SqlTime $oldT); n = (SqlTime $newT) }
        $cte = @'
WITH o AS (SELECT ISNULL(ReportName,'') AS R, ISNULL(ConfigurationId,'') AS C, ISNULL(CriticalityTier, 255) AS T, ISNULL(SecuritySeverity,'') AS V, ISNULL(CmdbId,'') AS CI, ISNULL(CmdbName,'') AS CN,
                  ImpactedAssetCount AS IA, RiskScoreTotal AS S, RiskScoreTotalWeighted AS W FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @o, 126)),
     n AS (SELECT ISNULL(ReportName,'') AS R, ISNULL(ConfigurationId,'') AS C, ISNULL(CriticalityTier, 255) AS T, ISNULL(SecuritySeverity,'') AS V, ISNULL(CmdbId,'') AS CI, ISNULL(CmdbName,'') AS CN,
                  ImpactedAssetCount AS IA, RiskScoreTotal AS S, RiskScoreTotalWeighted AS W FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @n, 126)),
     d AS (SELECT COALESCE(o.R, n.R) AS Report, COALESCE(o.C, n.C) AS Config, COALESCE(o.T, n.T) AS Tier, COALESCE(o.V, n.V) AS Severity, COALESCE(o.CN, n.CN) AS Cmdb,
                  CASE WHEN o.R IS NULL THEN 'only in the NEW run' WHEN n.R IS NULL THEN 'only in the OLD run' ELSE 'differs' END AS Kind,
                  o.IA AS OldAssets, n.IA AS NewAssets, o.S AS OldScore, n.S AS NewScore, o.W AS OldWeighted, n.W AS NewWeighted
           FROM o FULL JOIN n ON o.R = n.R AND o.C = n.C AND o.T = n.T AND o.V = n.V AND o.CI = n.CI AND o.CN = n.CN
           WHERE o.R IS NULL OR n.R IS NULL OR ISNULL(o.IA, -1) <> ISNULL(n.IA, -1) OR ISNULL(o.S, -1) <> ISNULL(n.S, -1) OR ISNULL(o.W, -1) <> ISNULL(n.W, -1))
'@
        $per = @(Invoke-CmpSql @'
SELECT COALESCE(o.R, n.R) AS Report, ISNULL(o.N, 0) AS OldGroups, ISNULL(n.N, 0) AS NewGroups FROM
 (SELECT ISNULL(ReportName,'') AS R, COUNT(*) AS N FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @o, 126) GROUP BY ReportName) o
 FULL JOIN (SELECT ISNULL(ReportName,'') AS R, COUNT(*) AS N FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @n, 126) GROUP BY ReportName) n ON o.R = n.R
ORDER BY 1
'@ $p)
        $per | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        $kinds = @(Invoke-CmpSql ($cte + 'SELECT Kind, COUNT(*) AS Groups FROM d GROUP BY Kind') $p)
        if ($kinds.Count -eq 0) { Say 'EQUAL: every Summary group of the old run is in the new run with the same impacted asset count and scores, and nothing else.' }
        else {
            $kinds | Format-Table -AutoSize | Out-String | Write-Host
            @(Invoke-CmpSql ($cte + ('SELECT TOP ({0}) * FROM d ORDER BY Kind, Report, Config' -f [int]$MaxDiffs)) $p) | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
            $result.Differences += [long](($kinds | Measure-Object -Property Groups -Sum).Sum)
        }
        $result.Summary = [pscustomobject]@{ Old = $oldT; New = $newT; PerReport = $per; Kinds = $kinds }
        $statusTime = $newT
        $laTable = 'SI_RiskAnalysis_Summary_CL'
    }

    # ---- #641 the new run's verdict per report ---------------------------------------------------------------------
    Head ("{0}: completeness per report in the new run" -f $g.ToUpperInvariant())
    $st = @(Invoke-CmpSql "SELECT ReportName, ExpectedRows, RetrievedRows, StoredRows, State, Reason FROM sidata.RaReportStatus WHERE Grain = @g AND CollectionTime = CONVERT(datetime2(3), @t, 126) ORDER BY State, ReportName" @{ g = $g; t = (SqlTime ([datetime]$statusTime)) })
    if ($st.Count -eq 0) { Say 'no verdicts stored for this run' } else { $st | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Write-Host }
    $nc = @($st | Where-Object { $_.State -eq 'NotComplete' }); if ($nc.Count) { Say ("{0} report(s) are NOT COMPLETE in the new run: {1}" -f $nc.Count, (($nc | ForEach-Object { $_.ReportName }) -join ', ')) }
    $proofDiff = @($st | Where-Object { [string]$_.Reason -match 'bucket proof: DIFFERENT' }); if ($proofDiff.Count) { Say ("BUCKET PROOF: {0} report(s) returned different rows bucketed vs whole: {1}" -f $proofDiff.Count, (($proofDiff | ForEach-Object { $_.ReportName }) -join ', ')) }
    $result.Status = $st

    # ---- Log Analytics: the new run's rows there per report = the rows in SQL ----------------------------------------
    if ($WorkspaceId -and $LaAccessToken) {
        Head ("{0}: Log Analytics ({1}) against SQL for the new run" -f $g.ToUpperInvariant(), $laTable)
        $ct = ([datetime]$statusTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)
        $la = @(Invoke-CmpKql ("{0} | where TimeGenerated > ago(3d) | where CollectionTime == datetime({1}) | summarize Rows = count() by Report = tostring(AssetDetectedInReportName) | order by Report asc" -f $laTable, $ct))
        $sqlPer = if ($g -eq 'Detailed') { @(Invoke-CmpSql "SELECT ISNULL(ReportName,'') AS Report, COUNT(*) AS Rows FROM sidata.Finding WHERE CollectionId = @c GROUP BY ReportName" @{ c = [int]$result.Detailed.New.CollectionId }) }
                  else { @(Invoke-CmpSql "SELECT ISNULL(ReportName,'') AS Report, COUNT(*) AS Rows FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @t, 126) GROUP BY ReportName" @{ t = (SqlTime ([datetime]$statusTime)) }) }
        $m = @{}; foreach ($x in $sqlPer) { $m[[string]$x.Report] = [long]$x.Rows }
        $laDiff = @(foreach ($x in $la) { $s = [long]$m[[string]$x.Report]; if ($s -ne [long]$x.Rows) { [pscustomobject]@{ Report = $x.Report; LogAnalytics = $x.Rows; Sql = $s } } })
        if ($laDiff.Count -eq 0) { Say ("EQUAL: Log Analytics holds the same rows per report as SQL ({0} report(s))" -f $la.Count) } else { $laDiff | Format-Table -AutoSize | Out-String | Write-Host; $result.Differences += $laDiff.Count }
        $result.LogAnalytics = $laDiff
    }
}

# ---- KPI + top 50 (the executive view) --------------------------------------------------------------------------------
if ($Before) {
    Head 'KPI AND TOP 50 (executive view kept before the new run vs now)'
    $bef = @(Get-Content -Raw -LiteralPath $Before | ConvertFrom-Json)
    $execDiff = New-Object System.Collections.Generic.List[string]
    foreach ($b in $bef) {
        $now = @($execNow | Where-Object { $_.Grain -eq $b.Grain }) | Select-Object -First 1
        if (-not $now) { $execDiff.Add(('{0}: no executive view now' -f $b.Grain)); continue }
        $pb = $b.PayloadJson | ConvertFrom-Json; $pn = $now.PayloadJson | ConvertFrom-Json
        Say ("{0}: KPI before {1} ({2}), now {3} ({4})" -f $b.Grain, $pb.Kpi.GlobalScore, $pb.Kpi.Band, $pn.Kpi.GlobalScore, $pn.Kpi.Band)
        if ([string]$pb.Kpi.GlobalScore -ne [string]$pn.Kpi.GlobalScore) { $execDiff.Add(('{0}: KPI {1} -> {2}' -f $b.Grain, $pb.Kpi.GlobalScore, $pn.Kpi.GlobalScore)) }
        foreach ($list in 'TopAssets', 'TopFindings') {
            $key = if ($list -eq 'TopAssets') { 'Asset' } else { 'ConfigurationId' }
            $lb = @($pb.$list | ForEach-Object { [string]$_.$key }); $ln = @($pn.$list | ForEach-Object { [string]$_.$key })
            $onlyB = @($lb | Where-Object { $ln -notcontains $_ }); $onlyN = @($ln | Where-Object { $lb -notcontains $_ })
            $moved = 0; for ($i = 0; $i -lt [Math]::Min($lb.Count, $ln.Count); $i++) { if ($lb[$i] -ne $ln[$i]) { $moved++ } }
            Say ("  {0}: {1} before, {2} now; {3} only before, {4} only now, {5} position(s) differ" -f $list, $lb.Count, $ln.Count, $onlyB.Count, $onlyN.Count, $moved)
            if ($onlyB.Count) { Say ('    only before: ' + ($onlyB -join ', ')) }
            if ($onlyN.Count) { Say ('    only now   : ' + ($onlyN -join ', ')) }
            if ($onlyB.Count -or $onlyN.Count) { $execDiff.Add(('{0} {1}: {2} only before, {3} only now' -f $b.Grain, $list, $onlyB.Count, $onlyN.Count)) }
        }
    }
    Say '  note: the data between the two runs is not the same snapshot -- a top-50 difference is a finding only when the row diff above is EQUAL'
    $result.ExecView = $execDiff.ToArray()
}

# ---- the trend --------------------------------------------------------------------------------------------------------
if ($WorkspaceId -and $LaAccessToken -and $result.Summary) {
    Head 'TREND (SI_Trend_CL): the old run''s rollup vs the new run''s'
    $fmt = { param($t) ([datetime]$t).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv) }
    $tr = @(Invoke-CmpKql ("SI_Trend_CL | where TimeGenerated > ago(30d) | where CollectionTime in (datetime({0}), datetime({1})) | project CollectionTime, Dimension, DimensionValue, Findings, Assets, ScoreTotal" -f (& $fmt $result.Summary.Old), (& $fmt $result.Summary.New)))
    $byKey = @{}
    foreach ($x in $tr) { $k = '{0}|{1}' -f $x.Dimension, $x.DimensionValue; if (-not $byKey.ContainsKey($k)) { $byKey[$k] = @{} }; $byKey[$k][([datetime]$x.CollectionTime).ToUniversalTime().ToString('o')] = $x }
    $oK = ([datetime]$result.Summary.Old).ToUniversalTime().ToString('o'); $nK = ([datetime]$result.Summary.New).ToUniversalTime().ToString('o')
    $td = @(foreach ($k in ($byKey.Keys | Sort-Object)) { $a = $byKey[$k][$oK]; $b = $byKey[$k][$nK]
        [pscustomobject]@{ Dimension = $k; OldFindings = $a.Findings; NewFindings = $b.Findings; OldAssets = $a.Assets; NewAssets = $b.Assets; OldScore = $a.ScoreTotal; NewScore = $b.ScoreTotal } })
    $td | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $result.Trend = $td
}

Head 'VERDICT'
if (-not $result.Detailed -and -not $result.Summary) { Say 'NOT COMPARED: neither the Detailed nor the Summary collections of both paths are there -- this says nothing about differences.' }
elseif ($result.Differences -eq 0) { Say 'NO DIFFERENCES in the rows, the groups and Log Analytics between the old and the new path.' }
else { Say ("{0} difference(s) -- listed above. Rows only in one run can be the estate changing between the runs: compare the row diff with what Defender shows for those assets." -f $result.Differences) }
[pscustomobject]$result
