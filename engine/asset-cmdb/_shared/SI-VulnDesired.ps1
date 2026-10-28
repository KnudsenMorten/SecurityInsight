#Requires -Version 5.1
<#
    SI v3 -- WHAT THE VULNERABILITY CLOSE-LOOP BELIEVES (#195): the desired set, whether it may be trusted, and
    what state each asset is in. Every decision here is a pure function over query results, so it is provable
    without a workspace; the KQL builders only fetch.

    THE THREE QUESTIONS A CLOSE HAS TO ANSWER
      1. Which (asset, CVE) pairs does SI report right now?           -> the newest Detailed snapshot of THIS
         edition. The 2.2 and 3.x engines can write the same table during an upgrade (measured 2026-10-01 on the
         internal tenant: snapshots alternated 2.2.460 / 3.0.0 hour by hour) and the two must never be mixed.
      2. Was that snapshot COMPLETE?                                   -> the Risk Analysis run that produced it
         ended 'success' (not 'success-partial', not missing). Unknown is NOT complete.
      3. Is the asset still there?                                     -> "Remediated" needs a LIVE asset. Alive
         means: it has other findings in the same snapshot, or the endpoint profile saw it recently. Low tiers are
         re-profiled weekly (tier cadence), so "in the latest profile run" would call every tier-3 machine missing.
#>

if (-not (Get-Command -Name 'Get-SIAssetLifecycleState' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'SI-ReconcileGuards.ps1')
}
# THE CI KEY (#406 / #409): a finding is keyed on its asset's CI key, the same key the CI hand-off rows carry
if (-not (Get-Command -Name 'Get-SICiKey' -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\data-sql\SI-CiKey.ps1') }
# #533: disabled accounts and devices (Test-SIAssetDisabled, Get-SIDisabledAssetPolicy)
if (-not (Get-Command -Name 'Get-SIDisabledAssetPolicy' -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-DisabledAssets.ps1')) }

# =====================================================================================================================
#  EVERY SECURITY RECOMMENDATION IS A VULNERABILITY (operator ruling 2026-10-06, verbatim: "any security recommendation
#  is a vulnerability - there is NO difference")
#
#  Until 2026-10-06 the close-loop's desired set was CVE-only (ConfigurationId startswith "CVE-"). Now EVERY finding Risk
#  Analysis reports on an asset is one record with the same lifecycle (open / update / reopen / close, the same guards):
#  a CVE, a Defender for Cloud recommendation, a Defender for Endpoint security configuration, an identity finding, an
#  attack path, an exposure.
#
#  THE FINDING KEY (vuln.VulnerabilityItem.Cve, u_vulnerability) is Risk Analysis' own ConfigurationId -- the stable id
#  the SOURCE gives the finding, and the same RecommendationKey the web app's tasks, exemptions and comments use:
#      CVE id              CVE-2026-19142                        (Defender vulnerability management; upper case)
#      Defender for Cloud  4ddff91a-b04a-01e9-e00f-339fc896324a  (the assessment key, one per recommendation)
#      Defender for Endpoint security configuration  scid-2518
#      SecurityInsight rule  IDENTITY-SPN-001, PUBLICIP-OPENPORT-8443, an attack path "src->target" (the rule's own id)
#  The record is (Source, CI key, finding key) -- unique per asset, so two sources never collide: their ids have
#  different shapes, and the same id from two reports on one asset IS one finding. A key longer than the column (100)
#  -- measured on ring 1: a recommendation published by its NAME, 120 characters -- is cut to its first 59 characters
#  + '~' + the SHA-1 of the whole id (upper case): 100 characters, stable, still readable.
#  NOT findings: the bookkeeping reports SecurityInsight writes ABOUT an asset, never a weakness ON it (an asset
#  excluded by tag, conflicting tier tags) -- $script:SIVulnBookkeepingReports.
# =====================================================================================================================
$script:SIVulnFindingKeyMax = 100
$script:SIVulnBookkeepingReports = @('Endpoint_ExcludedAssets_Detailed', 'Endpoint_ConflictingTierTags_Detailed')

function Get-SIVulnFindingKey {
    <# PURE. The finding key of one ConfigurationId (see above): a CVE upper case, anything else as the source gives it,
       cut + SHA-1 when longer than 100 characters. '' for an empty id. #>
    param([AllowEmptyString()][AllowNull()][string]$ConfigurationId)
    $c = ([string]$ConfigurationId).Trim()
    if (-not $c) { return '' }
    if ($c -match '^(?i)CVE-' -and $c.Length -le $script:SIVulnFindingKeyMax) { return $c.ToUpperInvariant() }
    if ($c.Length -le $script:SIVulnFindingKeyMax) { return $c }
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $h = (@($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($c.ToUpperInvariant())) | ForEach-Object { $_.ToString('x2') })) -join '' } finally { $sha.Dispose() }
    $c.Substring(0, $script:SIVulnFindingKeyMax - 41) + '~' + $h
}

function Test-SIVulnCveKey {
    <# PURE. Is the finding key a CVE id? #>
    param([AllowEmptyString()][AllowNull()][string]$Key)
    ([string]$Key).Trim() -match '^(?i)CVE-'
}

function Get-SIVulnFindingType {
    <#
        PURE. What kind of finding a record is (u_finding_type): cve | azure-recommendation | endpoint-recommendation |
        identity | attack-path | exposure | recommendation. From the key's shape, the report and the security domain.
        ServiceNow: a cve maps to sn_vul_nvd_entry, every other type to a third-party entry (sn_vul_third_party_entry)
        with the finding key as its id and u_title as its name.
    #>
    param([AllowEmptyString()][string]$Key, [AllowEmptyString()][string]$Domain = '', [AllowEmptyString()][string]$Report = '')
    if (Test-SIVulnCveKey $Key) { return 'cve' }
    $r = ([string]$Report).Trim().ToLowerInvariant(); $d = ([string]$Domain).Trim().ToLowerInvariant()
    if ($r -like 'attack_paths*') { return 'attack-path' }
    switch ($d) {
        'identity' { return 'identity' }
        'azure'    { return 'azure-recommendation' }
        'endpoint' { return 'endpoint-recommendation' }
        'publicip' { return 'exposure' }
    }
    'recommendation'
}

function Get-SIVulnDesiredKql {
    <#
        The newest Detailed snapshot of THIS edition, one row per (asset, finding) -- EVERY finding with an asset id and a
        ConfigurationId (operator ruling 2026-10-06: every security recommendation is a vulnerability). Tier / Domains /
        Reports are carried for the connectors' output scope (#274, SI-OutputScope.ps1); Title for the hand-off.
        THE SNAPSHOT is anchored on the newest run that published CVE findings (the full run), so an ad-hoc template that
        published a few rows of another kind, or a run of the other edition, can never become "the latest snapshot" --
        which would read as "everything else gone". Only an install that has no CVE finding at all in the look-back takes
        the newest snapshot of any finding.
    #>
    <#
        #404 part 2: -CollectionTime pins the snapshot to ONE earlier collection (a resend chosen by a person) instead of
        the newest; everything after the snapshot's choice is the same query.
    #>
    <#
        Owner 2026-10-19 (the connectors' scope filters): -ScopeFields = the SI fields the vulnerability connectors' scopes
        filter on (risk rating, class, component ...) -- each carried as F_<field>, the set of its values over the finding's
        rows (SI-OutputScope.ps1 reads it). A field the table does not have reads empty (column_ifexists).
    #>
    param([Parameter(Mandatory)][string]$EditionMajor, [int]$LookbackDays = 3, [Nullable[datetime]]$CollectionTime, [string[]]$ScopeFields = @())
    $extra = ''
    foreach ($sf in @($ScopeFields | Where-Object { $_ -match '^si_[a-z0-9_]{1,80}$' } | Sort-Object -Unique)) {
        $cols = if (Get-Command -Name Get-SIOutputScopeFilterColumns -ErrorAction SilentlyContinue) { @(Get-SIOutputScopeFilterColumns -Field $sf) } else { @($sf) }
        $cols = @($cols | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]{0,80}$' })
        $expr = if ($cols.Count -eq 1) { 'tostring(column_ifexists("{0}", ""))' -f $cols[0] } else { 'coalesce(' + ((@($cols | ForEach-Object { 'tostring(column_ifexists("{0}", ""))' -f $_ })) -join ', ') + ')' }
        $extra += (", F_{0} = make_set({1})" -f $sf, $expr)
    }
    $snapLine = if ($null -ne $CollectionTime) { 'let _snap = datetime({0});' -f ([datetime]$CollectionTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) }
                else { "let _cveSnap = toscalar(_rows | where ConfigurationId startswith `"CVE-`" | summarize max(CollectionTime));`nlet _anySnap = toscalar(_rows | summarize max(CollectionTime));`nlet _snap = iff(isnull(_cveSnap), _anySnap, _cveSnap);" }
    @"
let _rows = SI_RiskAnalysis_Detailed_CL
    | where TimeGenerated > ago($($LookbackDays)d)
    | where isnotempty(tostring(ConfigurationId))
    | where tostring(column_ifexists("SolutionVersion", "")) startswith "$EditionMajor.";
$snapLine
_rows
| where CollectionTime == _snap
| summarize Severity = take_any(SecuritySeverity), AssetName = take_any(AssetName), Title = take_any(tostring(column_ifexists("ConfigurationName", ""))), RiskScore = max(todouble(tostring(column_ifexists("RiskScoreTotal", "")))), Tier = min(toint(tostring(column_ifexists("CriticalityTier", "")))), Domains = make_set(tostring(column_ifexists("SecurityDomain", ""))), Components = make_set(tostring(column_ifexists("si_component", ""))), SubCis = make_set(tostring(column_ifexists("si_servicenow_subci", ""))), OsFamilies = make_set(tostring(column_ifexists("si_os_family", ""))), PatchCycles = make_set(tostring(column_ifexists("si_patch_cycle", ""))), Reports = make_set(coalesce(tostring(column_ifexists("AssetDetectedInReportName", "")), tostring(column_ifexists("ReportName", ""))))$extra by AssetId = tostring(AssetId), Cve = tostring(ConfigurationId), SnapshotTime = CollectionTime
"@
}

function Get-SIVulnSnapshotAssetsKql {
    <# Every asset with ANY finding in that same snapshot: evidence the asset is alive and being assessed. #>
    param([Parameter(Mandatory)][datetime]$SnapshotTime, [int]$LookbackDays = 3)
    $t = $SnapshotTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    @"
SI_RiskAnalysis_Detailed_CL
| where TimeGenerated > ago($($LookbackDays)d)
| where CollectionTime == datetime($t)
| where isnotempty(AssetId)
| summarize Tier = min(toint(tostring(column_ifexists("CriticalityTier", "")))) by AssetId = tostring(AssetId)
"@
}

# =====================================================================================================================
#  #830 (owner 2026-10-20, verbatim: "i dont understand why vulnerability connector, data sync, data quality use LA. it
#  make no sense, why not SQL only"): THE SNAPSHOT FROM THE DATABASE. Risk Analysis Detailed writes its result to the Pro
#  database itself (#638: sidata.Collection + sidata.Finding, each row's DetailJson = the very row the Log Analytics copy
#  carried). The report-row copy (SI_RiskAnalysis_Detailed_CL) is an optional output, OFF by default -- so the connector
#  reads the SAME rows here, and gives the caller the SAME shape Get-SIVulnDesiredKql / Get-SIVulnSnapshotAssetsKql gave:
#    * the collection: the newest Detailed collection of THIS edition in the look-back whose Risk Analysis result is
#      complete (the rows a copy was sent from) and that the retention did not remove -- anchored on the newest one with a
#      CVE finding (else the newest with any finding), exactly as the KQL anchored _snap; -CollectionTime pins one (a resend);
#    * its rows, a page at a time on the table's own key, each value read from the row as Risk Analysis wrote it (the Log
#      Analytics column names; a list or an object as its JSON text, as tostring() gave it); rows the data sync CARRIED in
#      from an earlier collection (CarriedFrom) were never in Log Analytics and are left out;
#    * grouped per (AssetId, ConfigurationId) as the KQL summarize did (Add-SIVulnSnapshotRows): Severity / AssetName /
#      Title = the first value given, RiskScore = the highest, Tier = the lowest, the sets = the distinct non-blank values
#      (sorted: the same set, in one order); every row with an AssetId also counts for the snapshot's assets (Tier = the
#      lowest), as Get-SIVulnSnapshotAssetsKql did over every row.
#  A resend of a collection the retention removed is refused in plain words (only the newest complete collections keep
#  their rows -- #717). The KQL builders stay for an install without the Pro database (the copy, when it is on).
# =====================================================================================================================
$script:SIVulnSnapshotCols = @('AssetId', 'ConfigurationId', 'SolutionVersion', 'SecuritySeverity', 'AssetName', 'ConfigurationName', 'RiskScoreTotal',
    'CriticalityTier', 'SecurityDomain', 'si_component', 'si_servicenow_subci', 'si_os_family', 'si_patch_cycle', 'AssetDetectedInReportName', 'ReportName')

function Get-SIVulnSnapshotScopeColumns {
    <# PURE. -ScopeFields -> [ordered] field -> its Log Analytics columns (the coalesce order Get-SIVulnDesiredKql used). #>
    param([string[]]$ScopeFields = @())
    $out = [ordered]@{}
    foreach ($sf in @($ScopeFields | Where-Object { $_ -match '^si_[a-z0-9_]{1,80}$' } | Sort-Object -Unique)) {
        $cols = if (Get-Command -Name Get-SIOutputScopeFilterColumns -ErrorAction SilentlyContinue) { @(Get-SIOutputScopeFilterColumns -Field $sf) } else { @($sf) }
        $out[$sf] = @($cols | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]{0,80}$' })
    }
    $out
}

function Get-SIVulnSnapshotSourceSql {
    <#
        PURE. The collection the snapshot is read from (see above), ONE row: CollectionId, CollectionTime (ISO text, ms),
        Retired (1 = its rows were removed by the retention: a pinned resend is refused). Parameters @Edition (the major
        version, e.g. '3'), @Since (ISO text: the look-back's start), @At (ISO text, a pinned collection; '' = the newest).
        Older databases without a column are read without that condition.
    #>
    @'
SET NOCOUNT ON;
DECLARE @done nvarchar(200) = CASE WHEN COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NOT NULL THEN N'(c.Status = N''Complete'' OR c.RaCompletedAt IS NOT NULL)' ELSE N'c.Status = N''Complete''' END;
DECLARE @ret nvarchar(200) = CASE WHEN COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL THEN N'CASE WHEN c.RetiredAt IS NULL THEN 0 ELSE 1 END' ELSE N'0' END;
DECLARE @own nvarchar(100) = CASE WHEN COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NOT NULL THEN N' AND f.CarriedFrom IS NULL' ELSE N'' END;
-- #830 / #834 Typed = 1: the collection's rows carry the row values as typed columns (sidata.Collection.RaRowsAt)
DECLARE @typed nvarchar(200) = CASE WHEN COL_LENGTH('sidata.Collection', 'RaRowsAt') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RaFillRiskFactorConsequence') IS NOT NULL THEN N'CASE WHEN c.RaRowsAt IS NOT NULL THEN 1 ELSE 0 END' ELSE N'0' END;
DECLARE @q nvarchar(max) = N'SELECT TOP (1) c.CollectionId, CONVERT(nvarchar(30), c.CollectionTime, 126) AS CollectionTime, ' + @ret + N' AS Retired, ' + @typed + N' AS Typed
FROM sidata.Collection AS c
WHERE c.Kind = N''Detailed'' AND ' + @done + N' AND c.SolutionVersion LIKE @Edition + N''.%''
  AND ((@At = N'''' AND c.CollectionTime >= TRY_CONVERT(datetime2(3), @Since, 126) AND ' + @ret + N' = 0
        AND EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId AND f.ConfigurationId <> N''''' + @own + N'))
    OR (@At <> N'''' AND c.CollectionTime = TRY_CONVERT(datetime2(3), @At, 126)))
ORDER BY CASE WHEN @At = N'''' AND EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId AND f.ConfigurationId LIKE N''CVE-%''' + @own + N') THEN 0 ELSE 1 END, c.CollectionTime DESC;';
EXEC sp_executesql @q, N'@Edition nvarchar(16), @Since nvarchar(30), @At nvarchar(30)', @Edition = @Edition, @Since = @Since, @At = @At;
'@
}

function Get-SIVulnSnapshotPageSql {
    <#
        PURE. One page of the collection's rows (@CollectionId), after @After on the table's own key (FindingId), at most
        @Take: FindingId, then one column per Log Analytics column the snapshot reads (c0, c1, ... in the order of
        -Columns), each read from the row as Risk Analysis wrote it -- a value as text, a list or an object as its JSON
        text, a missing one NULL. Never a carried row.
    #>
    param([Parameter(Mandatory)][string[]]$Columns,
          # #850: every row of one page of CI keys (@KeyList: a JSON array of sidata.Finding.AssetKey) instead of @After / @Take;
          # the row's AssetKey comes back as SI_PageKey
          [switch]$ByKeys)
    $sel = for ($i = 0; $i -lt $Columns.Count; $i++) {
        $c = $Columns[$i]; if ($c -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,120}$') { throw ("not a column name: '{0}'" -f $c) }
        ('COALESCE(JSON_VALUE(j.d, N''''$.{0}''''), JSON_QUERY(j.d, N''''$.{0}'''')) AS [c{1}]' -f $c, $i)
    }
    if ($ByKeys) {
        return @"
SET NOCOUNT ON;
DECLARE @own nvarchar(100) = CASE WHEN COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NOT NULL THEN N' AND f.CarriedFrom IS NULL' ELSE N'' END;
DECLARE @q nvarchar(max) = N'SELECT f.FindingId, f.AssetKey AS [SI_PageKey], $($sel -join ', ')
FROM sidata.Finding AS f CROSS APPLY (SELECT CASE WHEN ISJSON(f.DetailJson) = 1 THEN f.DetailJson END AS d) AS j
WHERE f.CollectionId = @CollectionId AND f.AssetKey IN (SELECT [value] FROM OPENJSON(@KeyList))' + @own + N'
ORDER BY f.FindingId;';
EXEC sp_executesql @q, N'@CollectionId int, @KeyList nvarchar(max)', @CollectionId = @CollectionId, @KeyList = @KeyList;
"@
    }
    @"
SET NOCOUNT ON;
DECLARE @own nvarchar(100) = CASE WHEN COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NOT NULL THEN N' AND f.CarriedFrom IS NULL' ELSE N'' END;
DECLARE @q nvarchar(max) = N'SELECT TOP (CONVERT(int, @Take)) f.FindingId, $($sel -join ', ')
FROM sidata.Finding AS f CROSS APPLY (SELECT CASE WHEN ISJSON(f.DetailJson) = 1 THEN f.DetailJson END AS d) AS j
WHERE f.CollectionId = @CollectionId AND f.FindingId > @After' + @own + N'
ORDER BY f.FindingId;';
EXEC sp_executesql @q, N'@CollectionId int, @After bigint, @Take int', @CollectionId = @CollectionId, @After = @After, @Take = @Take;
"@
}

# #830 / #834 a scope field -> the typed column that holds it already coalesced over its columns (si-data-schema.sql
# "RaRowAssetId ..."; the same list as $script:SIDataRowColumns in SI-DataSql.ps1). A field not listed is read from DetailJson.
$script:SIVulnScopeTypedColumns = @{
    si_risk_rating = 'RaScopeRiskRating'; si_category = 'RaScopeCategory'; si_subcategory = 'RaScopeSubcategory'; si_class = 'RaScopeClass'
    si_component = 'RaScopeComponent'; si_patch_cycle = 'RaScopePatchCycle'; si_os_family = 'RaScopeOsFamily'; si_servicenow_subci = 'RaScopeSubCi'
    si_affected_product = 'RaScopeAffectedProduct'
}

function Get-SIVulnSnapshotTypedPageSql {
    <#
        PURE. #830 / #834 one page of a collection whose rows carry the row values as typed columns -- the same values
        Get-SIVulnSnapshotPageSql read from DetailJson, under the Log Analytics column names, never one finding's JSON:
        the finding's own typed columns (AssetName, ConfigurationId, Title, Severity, SecurityDomain, ReportName, RiskScore)
        and the row columns the derive stored; each scope field (-ScopeFields) already coalesced, as [@<field>]. Served by
        IX_Finding_RaRows (CollectionId, FindingId + every column read). Never a carried row.
    #>
    param([string[]]$ScopeFields = @(),
          # #850: every row of one page of CI keys (@KeyList: a JSON array of sidata.Finding.AssetKey) instead of @After / @Take;
          # the row's AssetKey comes back as SI_PageKey
          [switch]$ByKeys)
    $sc = foreach ($sf in @($ScopeFields)) {
        $col = $script:SIVulnScopeTypedColumns[$sf]; if (-not $col) { throw ("no typed column holds the scope field '{0}'" -f $sf) }
        ', f.{0} AS [@{1}]' -f $col, $sf
    }
    $head = if ($ByKeys) { 'f.FindingId, f.AssetKey AS [SI_PageKey]' } else { 'TOP (CONVERT(int, @Take)) f.FindingId' }
    $cond = if ($ByKeys) { 'f.AssetKey IN (SELECT [value] FROM OPENJSON(@KeyList))' } else { 'f.FindingId > @After' }
    @"
SELECT $head, f.RaRowAssetId AS [AssetId], f.ConfigurationId AS [ConfigurationId], f.RaRowSolutionVersion AS [SolutionVersion],
       f.Severity AS [SecuritySeverity], f.AssetName AS [AssetName], f.Title AS [ConfigurationName], f.RiskScore AS [RiskScoreTotal],
       f.RaRowCriticalityTier AS [CriticalityTier], f.SecurityDomain AS [SecurityDomain], f.RaRowSiComponent AS [si_component],
       f.RaScopeSubCi AS [si_servicenow_subci], f.RaScopeOsFamily AS [si_os_family], f.RaScopePatchCycle AS [si_patch_cycle],
       f.ReportName AS [AssetDetectedInReportName]$($sc -join '')
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId AND $cond AND f.CarriedFrom IS NULL
ORDER BY f.FindingId;
"@
}

function New-SIVulnSnapshotAccumulator {
    <# The state Add-SIVulnSnapshotRows fills and Complete-SIVulnSnapshot turns into the KQL-shaped rows. #>
    param([Parameter(Mandatory)][string]$EditionMajor, [string[]]$ScopeFields = @())
    [pscustomobject]@{
        Edition = $EditionMajor; Scope = (Get-SIVulnSnapshotScopeColumns -ScopeFields $ScopeFields)
        Groups  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        Order   = New-Object System.Collections.Generic.List[string]
        Assets  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        AssetOrder = New-Object System.Collections.Generic.List[string]
        Rows    = 0L
    }
}

function Add-SIVulnSnapshotRows {
    <#
        PURE (over -Acc). One page of rows as Risk Analysis wrote them -- objects or dictionaries with the Log Analytics
        column names (AssetId, ConfigurationId, SolutionVersion, SecuritySeverity, AssetName, ConfigurationName,
        RiskScoreTotal, CriticalityTier, SecurityDomain, si_component, si_servicenow_subci, si_os_family, si_patch_cycle,
        AssetDetectedInReportName, ReportName and the scope fields' columns) -- folded in as the KQL summarize folded them.
    #>
    param([Parameter(Mandatory)]$Acc, [AllowEmptyCollection()][object[]]$Rows = @())
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $get = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } else { $v = $null } } else { $p = $r.PSObject.Properties[$n]; $v = if ($p) { $p.Value } else { $null } }; if ($null -eq $v -or $v -is [System.DBNull]) { '' } else { [string]$v } }
    $num = { param([string]$s) $d = 0.0; if ($s.Trim() -and [double]::TryParse($s.Trim(), [Globalization.NumberStyles]::Float, $inv, [ref]$d)) { $d } else { $null } }
    $int = { param([string]$s) $d = & $num $s; if ($null -eq $d) { $null } else { [int][Math]::Truncate($d) } }
    $edPrefix = $Acc.Edition + '.'
    foreach ($r0 in @($Rows)) {
        if ($null -eq $r0) { continue }
        $Acc.Rows++
        # #850: the row is read ONCE into a table of its values as $get reads them (a missing / null / DBNull value is '',
        # any other its text), so each value below is one lookup -- [string] of a name the row does not carry is '', as
        # $get answers; the scope fields below still read the row itself
        $r = @{}
        if ($r0 -is [System.Collections.IDictionary]) { foreach ($e in $r0.GetEnumerator()) { $x = $e.Value; $r[$e.Key] = $(if ($null -eq $x -or $x -is [System.DBNull]) { '' } else { [string]$x }) } }
        else { foreach ($p in $r0.PSObject.Properties) { $x = $p.Value; $r[$p.Name] = $(if ($null -eq $x -or $x -is [System.DBNull]) { '' } else { [string]$x }) } }
        $aid = [string]$r['AssetId']
        $tier = & $int ([string]$r['CriticalityTier'])
        # the snapshot's assets: every row with an asset id, whatever its finding (Get-SIVulnSnapshotAssetsKql)
        if ($aid -ne '') {
            if (-not $Acc.Assets.ContainsKey($aid)) { $Acc.Assets[$aid] = [pscustomobject]@{ AssetId = $aid; Tier = $tier }; $Acc.AssetOrder.Add($aid) }
            elseif ($null -ne $tier -and ($null -eq $Acc.Assets[$aid].Tier -or $tier -lt $Acc.Assets[$aid].Tier)) { $Acc.Assets[$aid].Tier = $tier }
        }
        $cid = [string]$r['ConfigurationId']
        if ($cid -eq '') { continue }
        # the edition: every row carries its run's SolutionVersion (the collection's own is checked by the source statement);
        # a row of another edition is never mixed in
        $sv = [string]$r['SolutionVersion']
        if ($sv -ne '' -and -not $sv.StartsWith($edPrefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $k = $aid + [char]0 + $cid
        $g = $null
        if (-not $Acc.Groups.TryGetValue($k, [ref]$g)) {
            $g = @{ AssetId = $aid; Cve = $cid; Severity = ''; AssetName = ''; Title = ''; RiskScore = $null; Tier = $null
                    Domains = New-Object System.Collections.Generic.List[string]; Components = New-Object System.Collections.Generic.List[string]
                    SubCis = New-Object System.Collections.Generic.List[string]; OsFamilies = New-Object System.Collections.Generic.List[string]
                    PatchCycles = New-Object System.Collections.Generic.List[string]; Reports = New-Object System.Collections.Generic.List[string]; F = @{} }
            foreach ($sf in $Acc.Scope.Keys) { $g.F[$sf] = New-Object System.Collections.Generic.List[string] }
            $Acc.Groups[$k] = $g; $Acc.Order.Add($k)
        }
        if ($g['Severity'] -eq '') { $g['Severity'] = [string]$r['SecuritySeverity'] }
        if ($g['AssetName'] -eq '') { $g['AssetName'] = [string]$r['AssetName'] }
        if ($g['Title'] -eq '') { $g['Title'] = [string]$r['ConfigurationName'] }
        $rs = & $num ([string]$r['RiskScoreTotal']); if ($null -ne $rs -and ($null -eq $g.RiskScore -or $rs -gt $g.RiskScore)) { $g.RiskScore = $rs }
        if ($null -ne $tier -and ($null -eq $g.Tier -or $tier -lt $g.Tier)) { $g.Tier = $tier }
        $g.Domains.Add([string]$r['SecurityDomain']); $g.Components.Add([string]$r['si_component']); $g.SubCis.Add([string]$r['si_servicenow_subci'])
        $g.OsFamilies.Add([string]$r['si_os_family']); $g.PatchCycles.Add([string]$r['si_patch_cycle'])
        $rep = [string]$r['AssetDetectedInReportName']; if ($rep -eq '') { $rep = [string]$r['ReportName'] }; $g.Reports.Add($rep)
        foreach ($sf in $Acc.Scope.Keys) {
            # #830 / #834 a typed read carries the field already coalesced ('@<field>'); a DetailJson read is coalesced here
            $pre = $null; if ($r0 -is [System.Collections.IDictionary]) { if ($r0.Contains('@' + $sf)) { $pre = $r0['@' + $sf] } } else { $pp = $r0.PSObject.Properties['@' + $sf]; if ($pp) { $pre = $pp.Value } }
            if ($null -ne $pre -or ($r0 -is [System.Collections.IDictionary] -and $r0.Contains('@' + $sf))) { $v = $(if ($null -eq $pre -or $pre -is [System.DBNull]) { '' } else { [string]$pre }) }
            else { $v = ''; foreach ($c in $Acc.Scope[$sf]) { $v = [string]$r[$c]; if ($v -ne '') { break } } }
            $g.F[$sf].Add($v)
        }
    }
}

function ConvertTo-SIVulnSnapshotSet {
    <# PURE. The values of a set as the KQL make_set came back (JSON array text): distinct, blanks left out, sorted. #>
    param([AllowEmptyCollection()][AllowNull()][System.Collections.Generic.List[string]]$Values)
    $u = @(@($Values) | Where-Object { $null -ne $_ -and $_.Trim() -ne '' } | Sort-Object -Unique -CaseSensitive)
    if ($u.Count -eq 0) { return '[]' }
    ConvertTo-Json -InputObject ([string[]]$u) -Compress
}

function Complete-SIVulnSnapshot {
    <#
        PURE (over -Acc). The KQL-shaped rows: Rows = one per (AssetId, Cve) with SnapshotTime, Severity, AssetName, Title,
        RiskScore, Tier, Domains, Components, SubCis, OsFamilies, PatchCycles, Reports (JSON array text) and F_<field>;
        Assets = one per AssetId with its lowest Tier. The accumulator is emptied as it is read.
    #>
    param([Parameter(Mandatory)]$Acc, [Parameter(Mandatory)][datetime]$SnapshotTime)
    $t = [datetime]::SpecifyKind($SnapshotTime, [DateTimeKind]::Utc)
    $rows = New-Object System.Collections.Generic.List[object]
    # #850: ConvertTo-SIVulnSnapshotSet is pure and its inputs repeat on nearly every finding (the same domain, report,
    # component ...): each distinct list is converted once per call (a page) -- keyed on the exact values, in order
    $memo = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $sep = [string][char]1
    $setOf = {
        param($vals)
        # the key: the values joined, in order -- exact only when no value carries the separator (then: no memo)
        $j = [string]::Join($sep, [string[]]$vals.ToArray()); $hit = $null
        if ($j.Split([char]1).Length -ne [Math]::Max(1, $vals.Count)) { return (ConvertTo-SIVulnSnapshotSet $vals) }
        $mk = [string]$vals.Count + $sep + $j
        if (-not $memo.TryGetValue($mk, [ref]$hit)) { $hit = ConvertTo-SIVulnSnapshotSet $vals; $memo[$mk] = $hit }
        $hit
    }
    foreach ($k in $Acc.Order) {
        $g = $Acc.Groups[$k]
        $o = [ordered]@{ AssetId = $g.AssetId; Cve = $g.Cve; SnapshotTime = $t; Severity = $g.Severity; AssetName = $g.AssetName; Title = $g.Title
                         RiskScore = $(if ($null -ne $g.RiskScore) { [string]$g.RiskScore } else { '' }); Tier = $g.Tier
                         Domains = (& $setOf $g.Domains); Components = (& $setOf $g.Components); SubCis = (& $setOf $g.SubCis)
                         OsFamilies = (& $setOf $g.OsFamilies); PatchCycles = (& $setOf $g.PatchCycles); Reports = (& $setOf $g.Reports) }
        foreach ($sf in $Acc.Scope.Keys) { $o['F_' + $sf] = & $setOf $g.F[$sf] }
        $rows.Add([pscustomobject]$o)
        $Acc.Groups[$k] = $null
    }
    $assets = @(foreach ($a in $Acc.AssetOrder) { $Acc.Assets[$a] })
    $Acc.Groups.Clear(); $Acc.Order.Clear(); $Acc.Assets.Clear(); $Acc.AssetOrder.Clear()
    [pscustomobject]@{ Rows = $rows.ToArray(); Assets = $assets }
}

function Read-SIVulnSnapshotSql {
    <#
        THE SNAPSHOT FROM THE DATABASE (see above). -Invoke: the Pro data database (sql, params, mode 'rows' -> the rows).
        Returns @{ Found; Retired; CollectionTime; Rows (the KQL-shaped rows); Assets; RowsRead }. Throws on a database
        failure (the caller stops, as a failed Log Analytics read stopped it).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$EditionMajor, [int]$LookbackDays = 3,
          [Nullable[datetime]]$CollectionTime, [string[]]$ScopeFields = @(), [datetime]$Now = [datetime]::UtcNow, [long]$PageRows = 5000,
          # read DetailJson even when the typed columns are there (the equality proof and the measurement compare the two)
          [switch]$ForceJson)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $fmt = { param([datetime]$d) $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv) }
    $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } else { $null } } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $unroll = { param($a) foreach ($x in @($a)) { if ($null -eq $x) { continue }; if ($x -is [System.Collections.IList] -and -not ($x -is [string]) -and -not ($x -is [System.Collections.IDictionary])) { foreach ($y in $x) { if ($null -ne $y) { $y } } } else { $x } } }
    $o = Open-SIVulnSnapshotSql -Invoke $Invoke -EditionMajor $EditionMajor -LookbackDays $LookbackDays -CollectionTime $CollectionTime -ScopeFields $ScopeFields -Now $Now -ForceJson:$ForceJson
    if (-not $o.Found) { return [pscustomobject]@{ Found = $false; Retired = $false; CollectionTime = $null; Rows = @(); Assets = @(); RowsRead = 0L } }
    $ct = $o.CollectionTime
    if ($o.Retired) { return [pscustomobject]@{ Found = $true; Retired = $true; CollectionTime = $ct; Rows = @(); Assets = @(); RowsRead = 0L } }
    $cid = $o.CollectionId
    $acc = New-SIVulnSnapshotAccumulator -EditionMajor $EditionMajor -ScopeFields $ScopeFields
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($c in $o.Columns) { $cols.Add($c) }
    $typed = $o.Typed
    $sql = if ($typed) { Get-SIVulnSnapshotTypedPageSql -ScopeFields @($acc.Scope.Keys) } else { Get-SIVulnSnapshotPageSql -Columns $cols.ToArray() }
    $after = 0L; $take = [long][Math]::Max(500L, $PageRows)
    while ($true) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $page = @(& $unroll (& $Invoke $sql @{ CollectionId = $cid; After = $after; Take = [int]$take } 'rows'))
        $sw.Stop()
        if ($page.Count -eq 0) { break }
        if ($typed) { Add-SIVulnSnapshotRows -Acc $acc -Rows @($page) }
        else {
            $named = foreach ($p in $page) {
                $h = @{}; for ($i = 0; $i -lt $cols.Count; $i++) { $h[$cols[$i]] = & $val $p ('c' + $i) }; $h
            }
            Add-SIVulnSnapshotRows -Acc $acc -Rows @($named)
        }
        $after = [long](& $val $page[$page.Count - 1] 'FindingId')
        if ($page.Count -lt $take) { break }
        # the next page from this one's measured time (about 5 s a page; at most double, at least half -- never a fixed cap)
        $ms = [Math]::Max(1.0, $sw.Elapsed.TotalMilliseconds)
        $take = [long][Math]::Max(500, [Math]::Min($take * 2, [Math]::Max($take / 2, $take * 5000.0 / $ms)))
    }
    $done = Complete-SIVulnSnapshot -Acc $acc -SnapshotTime $ct
    [pscustomobject]@{ Found = $true; Retired = $false; CollectionTime = $ct; Rows = @($done.Rows); Assets = @($done.Assets); RowsRead = [long]$acc.Rows; Typed = [bool]$typed }
}

# =====================================================================================================================
#  #850 (live 2026-10-21, a large install: "Reading what SecurityInsight reports" ran out of memory twice on 1.25 M
#  findings; owner: "memory issues must not be a problem in any step. env must work in millions of assets env"): THE
#  SNAPSHOT ONE PAGE OF CI KEYS AT A TIME. The collection is opened (Open-SIVulnSnapshotSql: which collection, how its rows
#  are read -- no row is read), its CI keys are listed in the database's own order a page at a time (sidata.Finding.AssetKey,
#  IX_Finding_Views: CollectionId, AssetKey -- with each key's row count, so a page is sized by its findings), and the rows
#  of one page of keys are read and folded exactly as before (Read-SIVulnSnapshotPage: Add-SIVulnSnapshotRows /
#  Complete-SIVulnSnapshot over that page only -- every row of a CI key is in the same page, so the fold is the same).
# =====================================================================================================================
function Open-SIVulnSnapshotSql {
    <#
        The collection the snapshot is read from (Get-SIVulnSnapshotSourceSql) without reading a row: @{ Found; Retired;
        CollectionId; CollectionTime; Typed; Columns (the DetailJson columns, in order); ScopeFields; EditionMajor }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$EditionMajor, [int]$LookbackDays = 3,
          [Nullable[datetime]]$CollectionTime, [string[]]$ScopeFields = @(), [datetime]$Now = [datetime]::UtcNow, [switch]$ForceJson)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $fmt = { param([datetime]$d) $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv) }
    $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } else { $null } } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $unroll = { param($a) foreach ($x in @($a)) { if ($null -eq $x) { continue }; if ($x -is [System.Collections.IList] -and -not ($x -is [string]) -and -not ($x -is [System.Collections.IDictionary])) { foreach ($y in $x) { if ($null -ne $y) { $y } } } else { $x } } }
    $at = if ($null -ne $CollectionTime) { & $fmt ([datetime]$CollectionTime) } else { '' }
    $src = @(& $unroll (& $Invoke (Get-SIVulnSnapshotSourceSql) @{ Edition = $EditionMajor; Since = (& $fmt $Now.AddDays(-[Math]::Max(1, $LookbackDays))); At = $at } 'rows')) | Select-Object -First 1
    $out = [ordered]@{ Found = $false; Retired = $false; CollectionId = 0; CollectionTime = $null; Typed = $false; Columns = @(); ScopeFields = @($ScopeFields); EditionMajor = $EditionMajor }
    if ($null -eq $src) { return [pscustomobject]$out }
    $out.Found = $true
    $ctText = [string](& $val $src 'CollectionTime')
    $out.CollectionTime = [datetime]::SpecifyKind([datetime]::Parse($ctText, $inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [DateTimeKind]::Utc)
    $out.Retired = ([string](& $val $src 'Retired') -in '1', 'True')
    $out.CollectionId = [int](& $val $src 'CollectionId')
    $scope = Get-SIVulnSnapshotScopeColumns -ScopeFields $ScopeFields
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($c in $script:SIVulnSnapshotCols) { if (-not $cols.Contains($c)) { $cols.Add($c) } }
    foreach ($sf in $scope.Keys) { foreach ($c in $scope[$sf]) { if (-not $cols.Contains($c)) { $cols.Add($c) } } }
    $out.Columns = $cols.ToArray()
    # #830 / #834 a collection derived with the typed row columns is read from them (never one finding's JSON); one derived
    # before them, or a scope field no typed column holds, from DetailJson as before
    $out.Typed = ([string](& $val $src 'Typed') -in '1', 'True') -and -not $ForceJson -and -not @($scope.Keys | Where-Object { -not $script:SIVulnScopeTypedColumns.ContainsKey($_) }).Count
    [pscustomobject]$out
}

function Get-SIVulnSnapshotKeysSql {
    <# PURE. #850 the next CI keys of the collection after @After (NULL = from the start), at most @Take, in the database's
       own order, each with its row count (K, N). Served by IX_Finding_Views (CollectionId, AssetKey). #>
    'SELECT TOP (CONVERT(int, @Take)) f.AssetKey AS K, COUNT_BIG(*) AS N FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NOT NULL AND (@After IS NULL OR f.AssetKey > @After) GROUP BY f.AssetKey ORDER BY f.AssetKey;'
}

function Get-SIVulnSnapshotKeyPresenceSql {
    <# PURE. #850 which of the CI keys in @KeyList (a JSON array) the collection has rows for -- the keys the snapshot's own
       pages already cover (Get-SIVulnSnapshotKeysSql lists every one of them). #>
    'SELECT DISTINCT f.AssetKey AS K FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.AssetKey IN (SELECT [value] FROM OPENJSON(@KeyList));'
}

function Get-SIVulnSnapshotReportsSql {
    <# PURE. #850 the reports behind the collection's findings (ReportName, Cve = 1 when it reported a CVE) -- what the
       report tier filters are read for, without reading the findings. #>
    'SELECT f.ReportName AS R, MAX(CASE WHEN f.ConfigurationId LIKE N''CVE-%'' THEN 1 ELSE 0 END) AS Cve FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.ReportName IS NOT NULL GROUP BY f.ReportName;'
}

function Read-SIVulnSnapshotKeys {
    <# #850 the next CI keys of the opened collection after -After: @{ Keys; Rows (their row count); Last; Done }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Snapshot, [AllowNull()][AllowEmptyString()][string]$After, [int]$Take = 5000)
    $rows = @(& $Invoke (Get-SIVulnSnapshotKeysSql) @{ CollectionId = [int]$Snapshot.CollectionId; After = $(if ($After) { $After } else { $null }); Take = [int]$Take } 'rows')
    $keys = New-Object System.Collections.Generic.List[string]; $n = 0L
    $counts = New-Object System.Collections.Generic.List[long]
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        foreach ($x in $(if ($r -is [System.Collections.IList] -and -not ($r -is [System.Collections.IDictionary])) { $r } else { , $r })) {
            $k = if ($x -is [System.Collections.IDictionary]) { $x['K'] } else { $x.K }; $c = if ($x -is [System.Collections.IDictionary]) { $x['N'] } else { $x.N }
            if ($null -ne $k -and "$k" -ne '') { $keys.Add([string]$k); $counts.Add([long]$c); $n += [long]$c }
        }
    }
    [pscustomobject]@{ Keys = $keys.ToArray(); Counts = $counts.ToArray(); Rows = $n; Last = $(if ($keys.Count) { $keys[$keys.Count - 1] } else { $After }); Done = ($keys.Count -lt $Take) }
}

function Test-SIVulnSnapshotKeysPresent {
    <# #850 the subset of -Keys the opened collection has rows for (a case-insensitive set). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Snapshot, [AllowEmptyCollection()][string[]]$Keys = @())
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $ks = @($Keys | Where-Object { $_ })
    if (-not $ks.Count) { return , $set }
    foreach ($r in @(& $Invoke (Get-SIVulnSnapshotKeyPresenceSql) @{ CollectionId = [int]$Snapshot.CollectionId; KeyList = (ConvertTo-Json -InputObject ([string[]]$ks) -Compress) } 'rows')) {
        if ($null -eq $r) { continue }
        foreach ($x in $(if ($r -is [System.Collections.IList] -and -not ($r -is [System.Collections.IDictionary])) { $r } else { , $r })) {
            $k = if ($x -is [System.Collections.IDictionary]) { $x['K'] } else { $x.K }; if ($k) { [void]$set.Add([string]$k) }
        }
    }
    , $set
}

function Read-SIVulnSnapshotPage {
    <#
        #850 the snapshot rows of ONE page of CI keys (-Keys: sidata.Finding.AssetKey values), folded exactly as
        Read-SIVulnSnapshotSql folds the whole collection: @{ Rows (the KQL-shaped rows); Assets; RowsRead; PageKeyOf
        (asset id lower -> the CI key the row was stored under) }. Throws on a database failure (the page is then unknown).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Snapshot, [AllowEmptyCollection()][string[]]$Keys = @())
    $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } else { $null } } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $unroll = { param($a) foreach ($x in @($a)) { if ($null -eq $x) { continue }; if ($x -is [System.Collections.IList] -and -not ($x -is [string]) -and -not ($x -is [System.Collections.IDictionary])) { foreach ($y in $x) { if ($null -ne $y) { $y } } } else { $x } } }
    $acc = New-SIVulnSnapshotAccumulator -EditionMajor ([string]$Snapshot.EditionMajor) -ScopeFields @($Snapshot.ScopeFields)
    $pageKeyOf = @{}
    $ks = @($Keys | Where-Object { $_ })
    if ($ks.Count) {
        $cols = @($Snapshot.Columns)
        $sql = if ($Snapshot.Typed) { Get-SIVulnSnapshotTypedPageSql -ScopeFields @($acc.Scope.Keys) -ByKeys } else { Get-SIVulnSnapshotPageSql -Columns $cols -ByKeys }
        $page = @(& $unroll (& $Invoke $sql @{ CollectionId = [int]$Snapshot.CollectionId; KeyList = (ConvertTo-Json -InputObject ([string[]]$ks) -Compress) } 'rows'))
        if (-not $Snapshot.Typed) {
            $page = @(foreach ($p in $page) { $h = @{ SI_PageKey = (& $val $p 'SI_PageKey') }; for ($i = 0; $i -lt $cols.Count; $i++) { $h[$cols[$i]] = & $val $p ('c' + $i) }; $h })
        }
        foreach ($p in $page) { $a = [string](& $val $p 'AssetId'); if ($a) { $pageKeyOf[$a.ToLowerInvariant()] = [string](& $val $p 'SI_PageKey') } }
        Add-SIVulnSnapshotRows -Acc $acc -Rows @($page)
        $page = $null
    }
    $done = Complete-SIVulnSnapshot -Acc $acc -SnapshotTime ([datetime]$Snapshot.CollectionTime)
    [pscustomobject]@{ Rows = @($done.Rows); Assets = @($done.Assets); RowsRead = [long]$acc.Rows; PageKeyOf = $pageKeyOf }
}

function Get-SIVulnReportTierFilter {
    <#
        #279 decision 3 -- PURE. The tiers one report admits, read from the report catalog TEXT (YAML, or the Pro catalog's
        JSON): a report's '_AssetTierFilter = dynamic([...])', when a catalog carries one (the shipped
        Device_Missing_CVEs_Detailed carried dynamic([0, 1, 2]) until #643 removed it -- the shipped catalog has none now, so
        nothing is out of scope by tier). Returns the tiers as int[]; $null when the report is not in the text, carries no filter, or the filter is
        empty (= every tier) -- "no restriction known" never makes anything out of scope.
    #>
    param([AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$ReportName)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $m = [regex]::Match($Text, ('ReportName"?\s*:\s*"?{0}(?![A-Za-z0-9_])' -f [regex]::Escape($ReportName)))
    if (-not $m.Success) { return $null }
    $rest = $Text.Substring($m.Index + $m.Length)
    $next = [regex]::Match($rest, 'ReportName"?\s*:')
    $block = if ($next.Success) { $rest.Substring(0, $next.Index) } else { $rest }
    $f = [regex]::Match($block, '_AssetTierFilter\s*=\s*dynamic\(\s*\[([^\]]*)\]\s*\)')
    if (-not $f.Success) { return $null }
    $tiers = @([regex]::Matches($f.Groups[1].Value, '\d+') | ForEach-Object { [int]$_.Value })
    if ($tiers.Count -eq 0) { return $null }
    , $tiers
}

function Get-SIVulnCveReportTiers {
    <#
        #279 decision 3 -- the tiers the vulnerability report(s) behind the snapshot admit, from the catalog Risk Analysis
        itself reads: the Pro catalog (SI_ProRaSettingsPath, the WHOLE catalog when present), else the custom, dev and
        locked YAML in that order (a report of the same name in a later file replaces the earlier one, so the first file
        that has it decides). -ReportNames: the report(s) the CVE rows came from. A report without a filter, or one that
        is not found, makes the answer $null (no tier is out of scope). Returns int[] (the union) or $null.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string[]]$ReportNames = @('Device_Missing_CVEs_Detailed'))
    $names = @($ReportNames | Where-Object { $_ } | Select-Object -Unique)
    if ($names.Count -eq 0) { $names = @('Device_Missing_CVEs_Detailed') }
    Get-SIVulnUnionTiers -TierMap (Get-SIVulnReportTierMap -SIRoot $SIRoot -ReportNames $names) -ReportNames $names
}

function Get-SIVulnUnionTiers {
    <# PURE. The union of the tiers -ReportNames admit (-TierMap: name -> int[] | $null). Any report without a known filter
       (or not in the map) makes the answer $null: "no restriction known" never puts anything out of scope. #>
    param([hashtable]$TierMap = @{}, [string[]]$ReportNames = @())
    $union = New-Object System.Collections.Generic.List[int]
    $names = @($ReportNames | Where-Object { $_ } | Select-Object -Unique)
    if ($names.Count -eq 0 -or $null -eq $TierMap) { return $null }
    foreach ($n in $names) {
        if (-not $TierMap.ContainsKey($n) -or $null -eq $TierMap[$n]) { return $null }
        foreach ($t in @($TierMap[$n])) { if (-not $union.Contains([int]$t)) { $union.Add([int]$t) } }
    }
    , $union.ToArray()
}

function Get-SIVulnScopeByReport {
    <#
        PURE. #279 decision 3, per REPORT (every finding is a vulnerability, 2026-10-06): the out-of-scope map New-SIVulnSyncPlan
        reads (-OutOfScopeAssets).
          '<asset>|<report lower>' -> why   an asset SEEN this run whose tier is outside what THAT report admits, while the
                                            report no longer reports anything on it -- its open records of that report close
                                            as out of scope (never as fixed);
          '<asset>'                -> why   the same for the CVE report(s) (-CveTiers): it judges a record written before
                                            2026-10-06, which carries no report.
        -TierMap: report -> tiers (Get-SIVulnReportTierMap). -Desired: this run's findings (CorrelationId = the CI key, Report,
        Cve). -Actual: the target's records (Report, CorrelationId; resolved through -AssetAlias). A report without a known
        filter puts nothing out of scope.
    #>
    param([hashtable]$TierMap = @{}, [AllowNull()][int[]]$CveTiers = $null, [AllowEmptyCollection()][object[]]$Desired = @(), [AllowEmptyCollection()][object[]]$Actual = @(),
          [hashtable]$AssetAlias = @{}, [hashtable]$SnapshotTiers = @{}, [hashtable]$ProfileTiers = @{}, [hashtable]$AssetState = @{})
    if ($null -eq $TierMap) { $TierMap = @{} }
    $val = { param($o, [string]$n) if ($null -eq $o) { '' } elseif ($o -is [System.Collections.IDictionary]) { [string]$o[$n] } elseif ($o.PSObject.Properties[$n]) { [string]$o.$n } else { '' } }
    $out = @{}
    # legacy: the CVE report(s) over every asset, reported = assets with a CVE finding this run
    $cveAssets = @($Desired | Where-Object { $_ -and (& $val $_ 'Cve') -match '^(?i)CVE-' } | ForEach-Object { ([string](& $val $_ 'CorrelationId')).ToLowerInvariant() } | Select-Object -Unique)
    $legacy = Get-SIVulnOutOfScopeAssets -ReportTiers $CveTiers -SnapshotTiers $SnapshotTiers -ProfileTiers $ProfileTiers -AssetState $AssetState -ReportedAssets $cveAssets
    foreach ($k in @($legacy.Keys)) { $out[$k] = $legacy[$k] }
    # per report: only the reports the target holds records of can close anything
    $reports = @($Actual | Where-Object { $_ } | ForEach-Object { (& $val $_ 'Report').Trim() } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($r in $reports) {
        $tiers = $null; if ($TierMap.ContainsKey($r)) { $tiers = $TierMap[$r] }
        if ($null -eq $tiers -or @($tiers).Count -eq 0) { continue }
        $rep = @($Desired | Where-Object { $_ -and [string]::Equals((& $val $_ 'Report'), $r, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { ([string](& $val $_ 'CorrelationId')).ToLowerInvariant() } | Select-Object -Unique)
        $one = Get-SIVulnOutOfScopeAssets -ReportTiers @($tiers) -SnapshotTiers $SnapshotTiers -ProfileTiers $ProfileTiers -AssetState $AssetState -ReportedAssets $rep
        foreach ($k in @($one.Keys)) { $out[($k + '|' + $r.ToLowerInvariant())] = ([string]$one[$k]).Replace('the vulnerability report covers', ('the report {0} covers' -f $r)) }
    }
    $out
}

function Get-SIVulnReportTierMap {
    <#
        Each report's tier filter, from the catalog Risk Analysis itself reads (see Get-SIVulnCveReportTiers), the files read
        ONCE for all names. Returns @{ '<report>' = int[] | $null } (null = not found, or no filter).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string[]]$ReportNames = @())
    $locked = if ($global:ReportSettingsFileLocked) { [string]$global:ReportSettingsFileLocked } else { 'RiskAnalysis_Queries_Locked.yaml' }
    $custom = if ($global:ReportSettingsFileCustom) { [string]$global:ReportSettingsFileCustom } else { 'RiskAnalysis_Queries_Custom.yaml' }
    $dev = if ($global:ReportSettingsFileDev) { [string]$global:ReportSettingsFileDev } else { 'RiskAnalysis_Queries_Dev.yaml' }
    $files = New-Object System.Collections.Generic.List[string]
    $pro = [string]$global:SI_ProRaSettingsPath
    if ($pro -and (Test-Path -LiteralPath ([System.IO.Path]::Combine($pro, $locked)))) { $files.Add([System.IO.Path]::Combine($pro, $locked)) }
    else {
        $sp = if ($global:SettingsPath) { [string]$global:SettingsPath } else { [System.IO.Path]::Combine($SIRoot, 'risk-analysis-detection') }
        foreach ($pair in @(@($custom, 'custom'), @($dev, 'dev'), @($locked, 'locked'))) {
            foreach ($c in @([System.IO.Path]::Combine($sp, $pair[1], $pair[0]), [System.IO.Path]::Combine($sp, $pair[0]))) { if (Test-Path -LiteralPath $c) { $files.Add($c); break } }
        }
    }
    $texts = @($files | ForEach-Object { [System.IO.File]::ReadAllText($_) })
    $map = @{}
    foreach ($n in @($ReportNames | Where-Object { $_ } | Select-Object -Unique)) {
        $tiers = $null
        foreach ($tx in $texts) {
            if (-not [regex]::IsMatch($tx, ('ReportName"?\s*:\s*"?{0}(?![A-Za-z0-9_])' -f [regex]::Escape($n)))) { continue }
            $tiers = Get-SIVulnReportTierFilter -Text $tx -ReportName $n; break
        }
        $map[$n] = $tiers
    }
    $map
}

function Get-SIVulnOutOfScopeAssets {
    <#
        #279 decision 3 -- PURE. The assets that are SEEN this run but have LEFT the vulnerability report's scope: their tier
        (in this snapshot's own rows; else the endpoint profile's, for an asset the profile saw recently) is outside the
        tiers the report admits (-ReportTiers). An asset with CVE findings in the snapshot is in scope by definition; an
        asset that is merely absent, or whose tier is unknown, is never out of scope. -ReportTiers $null = nothing is.
        Returns @{ '<asset id lower>' = 'why' }.
    #>
    param([AllowNull()][int[]]$ReportTiers, [hashtable]$SnapshotTiers = @{}, [hashtable]$ProfileTiers = @{},
          [hashtable]$AssetState = @{}, [AllowEmptyCollection()][string[]]$ReportedAssets = @())
    $out = @{}
    if ($null -eq $ReportTiers -or @($ReportTiers).Count -eq 0) { return $out }
    $reported = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $ReportedAssets) { if ($r) { [void]$reported.Add($r.Trim()) } }
    $cover = (@($ReportTiers) | Sort-Object) -join ', '
    $ids = @(@($SnapshotTiers.Keys) + @($ProfileTiers.Keys) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    foreach ($id in $ids) {
        if ($reported.Contains($id)) { continue }
        $tier = $null; $src = ''
        if ($SnapshotTiers.ContainsKey($id) -and $null -ne $SnapshotTiers[$id] -and "$($SnapshotTiers[$id])" -ne '') { $tier = [int]$SnapshotTiers[$id]; $src = 'in the newest results' }
        elseif ($ProfileTiers.ContainsKey($id) -and $null -ne $ProfileTiers[$id] -and "$($ProfileTiers[$id])" -ne '' -and [string]$AssetState[$id] -eq 'Active') { $tier = [int]$ProfileTiers[$id]; $src = 'in the endpoint profile' }
        if ($null -eq $tier) { continue }
        if (@($ReportTiers) -contains $tier) { continue }
        $out[$id] = ('the asset is still seen but is now tier {0} ({1}); the vulnerability report covers tier {2} -- closed as out of scope, not as fixed' -f $tier, $src, $cover)
    }
    $out
}

function Get-SIVulnEndpointStateKql {
    <# When the profiles last saw each asset, whether it is tag-excluded on its latest row, its tier (#279), and
       AssessedAt: when DEFENDER last saw / assessed the device (the endpoint profile's LastSeen = MDE machine lastSeen,
       else the Exposure Graph's) -- what corroborates a close (operator decision, 2026-10-04). Read from the profiles SI
       already writes: no new permission (Machine.Read.All only).
       Every finding is a vulnerability (2026-10-06), so an Azure resource's or an identity's finding needs its asset's
       state too: the endpoint, Azure AND identity profiles are read (isfuzzy -- a table not there yet reads as absent).
       AssessedAt comes from the ENDPOINT profile only: another profile's LastSeen means something else (a sign-in). #>
    param([int]$LookbackDays = 30)
    @"
union withsource=_SITable isfuzzy=true SI_Endpoint_Profile_CL, SI_Azure_Profile_CL, SI_Identity_Profile_CL
| where TimeGenerated > ago($($LookbackDays)d)
| extend _id = tostring(column_ifexists("SI_AssetId", ""))
| where isnotempty(_id)
| summarize arg_max(CollectionTime, *) by _id
| extend _assessed = iff(_SITable == "SI_Endpoint_Profile_CL", coalesce(todatetime(tostring(column_ifexists("LastSeen", ""))), todatetime(tostring(column_ifexists("EgLastSeen", "")))), datetime(null))
| extend _en = tostring(column_ifexists("AccountEnabled", ""))
| extend _en = iff(isempty(_en), tostring(todynamic(column_ifexists("Properties", dynamic(null))).collect.entra.AccountEnabled), _en)
| project AssetId = _id, LastSeen = CollectionTime, Excluded = tobool(column_ifexists("IsExcludedByTag", false)), Tier = toint(tostring(column_ifexists("Tier", ""))), AssessedAt = _assessed, Kind = _SITable, AccountEnabled = _en
"@
}

function Get-SIVulnCiKeyHistoryKql {
    <#
        #406 / #409 -- every CI key each asset carried in the correlation map over the look-back, with when it was last
        carried. A finding is keyed on its asset's CI key; when that key moves (a provisional id confirmed by the ledger, a
        correlation group re-formed) a record stored under the previous key is the SAME asset's finding: this read is what
        maps it on (Merge-SIVulnKeyAlias), exactly as #279's alias does for a moved SI_AssetId.
    #>
    param([int]$LookbackDays = 8)
    @"
SI_ObjectMap_CL
| where TimeGenerated > ago($($LookbackDays)d)
| extend _a = tostring(column_ifexists("SI_AssetId", "")), _k = tostring(column_ifexists("SI_CorrelationId", ""))
| where isnotempty(_a) and isnotempty(_k)
| summarize Seen = max(CollectionTime) by AssetId = _a, Key = _k
"@
}

function Merge-SIVulnKeyAlias {
    <#
        PURE. #406 / #409 -- the close-loop works in CI-KEY space: a record is (Source, CI key, finding key). Every id a
        target record may still be stored under, mapped to the CI key its asset has NOW:
          * a previous SI_AssetId (#279, -AssetAlias: old asset id -> current asset id)     -> the current asset's key;
          * an SI_AssetId whose asset has a correlation key (-KeyMap)                        -> that key -- the RE-KEY of
            every record written before 2026-10-06, when vulnerability records were keyed on SI_AssetId;
          * a correlation key the asset carried before (-KeyHistory: AssetId, Key, Seen)     -> the asset's key now.
        An id that is some asset's CURRENT key is never an alias (it is a key in its own right), and nothing maps to itself.
        Returns @{ '<old id lower>' = '<current CI key>' } -- the same shape #279's alias has, so the plan, the re-key and
        the scope read it unchanged.
    #>
    param([hashtable]$AssetAlias = @{}, [hashtable]$KeyMap = @{}, [AllowEmptyCollection()][object[]]$KeyHistory = @())
    if ($null -eq $AssetAlias) { $AssetAlias = @{} }
    if ($null -eq $KeyMap) { $KeyMap = @{} }
    $keyOf = { param([string]$aid) [string](Get-SICiKey -AssetId $aid -KeyMap $KeyMap).Key }
    $current = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($KeyMap.Keys)) { [void]$current.Add([string]$KeyMap[$a].Key) }
    $out = @{}
    $put = {
        param([string]$from, [string]$to)
        $f = ([string]$from).Trim(); $t = ([string]$to).Trim()
        if (-not $f -or -not $t -or [string]::Equals($f, $t, [StringComparison]::OrdinalIgnoreCase)) { return }
        if ($current.Contains($f)) { return }
        $out[$f.ToLowerInvariant()] = $t
    }
    foreach ($a in @($KeyMap.Keys)) { & $put ([string]$a) ([string]$KeyMap[$a].Key) }
    # the newest key each asset carried wins; an older one aliases to the asset's key NOW (its map entry, else the newest)
    $byAsset = @{}
    foreach ($h in @($KeyHistory)) {
        if ($null -eq $h) { continue }
        $a = ([string]$h.AssetId).Trim(); $k = ([string]$h.Key).Trim()
        if (-not $a -or -not $k) { continue }
        if (-not $byAsset.ContainsKey($a)) { $byAsset[$a] = New-Object System.Collections.Generic.List[object] }
        $seen = [datetime]::MinValue; try { if ($h.Seen) { $seen = ([datetime]$h.Seen).ToUniversalTime() } } catch { $seen = [datetime]::MinValue }
        $byAsset[$a].Add([pscustomobject]@{ Key = $k; Seen = $seen })
    }
    foreach ($a in @($byAsset.Keys)) {
        # .ToArray(): @() around a List[object] held in a hashtable throws "Argument types do not match" on pwsh 7
        $list = $byAsset[$a].ToArray()
        $now = if ($KeyMap.ContainsKey($a)) { [string]$KeyMap[$a].Key } else { [string](@($list | Sort-Object Seen -Descending)[0].Key) }
        foreach ($e in $list) { & $put $e.Key $now }
    }
    # #279 last: a previous asset id belongs to the asset that carries its identifiers NOW
    foreach ($old in @($AssetAlias.Keys)) { & $put ([string]$old) (& $keyOf ([string]$AssetAlias[$old])) }
    $out
}

function ConvertTo-SIVulnKeySpaceRows {
    <#
        PURE. Rows keyed by SI_AssetId (the desired-set rows, the snapshot's assets) -> the same rows keyed by the CI key:
        AssetId becomes the key, the asset id is kept as SI_AssetId. NEW objects; the input is not changed.
        #639 (7): the new rows are LEAN rows (New-SIVulnRowMaker, SI-VulnSync.ps1: one small .NET object per row with the
        same properties) -- the snapshot holds one row per finding; without a lean type, PSCustomObjects as before.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$KeyMap = @{})
    $out = New-Object System.Collections.Generic.List[object]
    $lean = [bool](Get-Command -Name New-SIVulnRowMaker -ErrorAction SilentlyContinue)
    $makers = @{}   # one maker per property list (the rows of one query share one)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $h = [ordered]@{}
        # #835: get_Keys() / get_Values(), never .Keys / .Values -- on a dictionary a KEY of that name (a column 'Keys' or
        # 'Values') wins over the property, and the row would be rebuilt from that one value
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in @($r.get_Keys())) { $h[[string]$k] = $r[$k] } } else { foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value } }
        $aid = [string]$h['AssetId']
        $h['SI_AssetId'] = $aid
        $h['AssetId'] = [string](Get-SICiKey -AssetId $aid -KeyMap $KeyMap).Key
        if (-not $lean) { $out.Add([pscustomobject]$h); continue }
        $names = [string[]]@($h.get_Keys())
        $mk = $names -join "`n"
        if (-not $makers.ContainsKey($mk)) { $makers[$mk] = New-SIVulnRowMaker -Names $names }
        $out.Add((ConvertTo-SIVulnRow -Maker $makers[$mk] -Values ([object[]]@($h.get_Values()))))
    }
    $out.ToArray()
}

function ConvertTo-SIVulnProfileKeySpace {
    <#
        PURE. Profile-state rows (Get-SIVulnEndpointStateKql: AssetId, LastSeen, Excluded, Tier, AssessedAt) -> one row per
        CI KEY: the member seen last decides LastSeen and Excluded, the tier is the most critical, AssessedAt the newest.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$KeyMap = @{})
    $by = @{}
    $utc = { param($v) if ($null -eq $v -or "$v" -eq '') { return $null }; try { ([datetime]$v).ToUniversalTime() } catch { $null } }
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not [string]$r.AssetId) { continue }
        $k = [string](Get-SICiKey -AssetId ([string]$r.AssetId) -KeyMap $KeyMap).Key
        $l = $k.ToLowerInvariant()
        $seen = & $utc $r.LastSeen
        $ass = $null; if ($r.PSObject.Properties['AssessedAt']) { $ass = & $utc $r.AssessedAt }
        $tier = $null; if ($r.PSObject.Properties['Tier'] -and $null -ne $r.Tier -and "$($r.Tier)" -ne '') { $tier = [int]$r.Tier }
        # #533: the account's enabled state in its own directory ('' = not said); a member that is DISABLED decides the CI key
        $en = ''; if ($r.PSObject.Properties['AccountEnabled'] -and $null -ne $r.AccountEnabled) { $en = [string]$r.AccountEnabled }
        if (-not $by.ContainsKey($l)) {
            $by[$l] = [pscustomobject]@{ AssetId = $k; LastSeen = $seen; Excluded = $r.Excluded; Tier = $tier; AssessedAt = $ass; SI_AssetId = [string]$r.AssetId; AccountEnabled = $en }
            continue
        }
        $c = $by[$l]
        if ($en -ieq 'false' -or ($en -and -not $c.AccountEnabled)) { $c.AccountEnabled = $en }
        if ($null -ne $seen -and ($null -eq $c.LastSeen -or $seen -gt $c.LastSeen)) { $c.LastSeen = $seen; $c.Excluded = $r.Excluded; $c.SI_AssetId = [string]$r.AssetId }
        if ($null -ne $tier -and ($null -eq $c.Tier -or $tier -lt $c.Tier)) { $c.Tier = $tier }
        if ($null -ne $ass -and ($null -eq $c.AssessedAt -or $ass -gt $c.AssessedAt)) { $c.AssessedAt = $ass }
    }
    @($by.Values)
}

function Get-SIVulnAssetAliasKql {
    <#
        #279 -- every durable identifier each asset carries, with the time the profile last saw it. The close-loop keys a
        finding on SI_AssetId, and SI_AssetId is NOT permanent by design: the NAME source drives the id (operator,
        2026-08-28, "id can change"), so when the top naming source stops naming a device the id moves to the next
        source's. Measured on ring 1, 2026-10-04: Entra returned 52 devices instead of 53, MGMT1 lost its Entra name,
        and its SI_AssetId moved from the Entra device id to the MDE machine id -- while EntityIds still listed BOTH.
        This read is what lets the loop recognise the old id as the same asset.
    #>
    param([int]$LookbackDays = 8)
    @"
union isfuzzy=true SI_Endpoint_Profile_CL, SI_Azure_Profile_CL
| where TimeGenerated > ago($($LookbackDays)d)
| extend _id = tostring(column_ifexists("SI_AssetId", "")), _eids = tostring(column_ifexists("EntityIds", ""))
| where isnotempty(_id) and isnotempty(_eids)
| summarize arg_max(CollectionTime, _eids) by _id
| project AssetId = _id, Seen = CollectionTime, EntityIds = _eids
"@
}

# The identifier types that identify ONE asset durably. A hostname (or anything else) is not one: two machines can share
# a name, and aliasing on a name would hand one machine's findings to another.
$script:SIVulnAliasIdTypes = @('MdeDeviceId', 'AadDeviceId', 'EgNodeId', 'ExposureGraphNodeId', 'AzureResourceId', 'AzureVmId')

function ConvertTo-SIVulnAssetAlias {
    <#
        PURE. Profile rows (AssetId, Seen, EntityIds json) -> @{ '<old id lower>' = '<current SI_AssetId>' }.

        Every row claims its own SI_AssetId and each durable identifier in its EntityIds. For one identifier the NEWEST
        claim wins -- the device's previous SI_AssetId still has its last row inside the window, and that row claims
        the new id right back; newest-wins is what makes the direction right (and turns round by itself if the id
        flips back). Two DIFFERENT assets claiming one identifier in the same snapshot is a real conflict: that
        identifier aliases nothing. Only identifiers whose winner is a different asset are returned -- an id that
        is still its own asset's current id is never an alias.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    $claims = @{}   # id lower -> @{ Id; Seen; Conflict }
    $claim = {
        param([string]$alias, [string]$owner, [datetime]$seen)
        $k = $alias.Trim().ToLowerInvariant()
        if (-not $k) { return }
        if (-not $claims.ContainsKey($k)) { $claims[$k] = @{ Id = $owner; Seen = $seen; Conflict = $false }; return }
        $c = $claims[$k]
        if ($c.Id -ieq $owner) { if ($seen -gt $c.Seen) { $c.Seen = $seen }; return }
        if ($seen -gt $c.Seen) { $claims[$k] = @{ Id = $owner; Seen = $seen; Conflict = $false } }
        elseif ($seen -eq $c.Seen) { $c.Conflict = $true }
    }
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $owner = ([string]$r.AssetId).Trim()
        if (-not $owner) { continue }
        $seen = [datetime]::MinValue
        try { if ($r.Seen) { $seen = ([datetime]$r.Seen).ToUniversalTime() } } catch { $seen = [datetime]::MinValue }
        & $claim $owner $owner $seen
        $eids = $r.EntityIds
        if ($eids -is [string]) {
            if ([string]::IsNullOrWhiteSpace($eids)) { continue }
            try { $eids = $eids | ConvertFrom-Json } catch { continue }
        }
        foreach ($e in @($eids)) {
            if ($null -eq $e) { continue }
            $t = [string]$e.type; $v = [string]$e.id
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            if (-not ($script:SIVulnAliasIdTypes | Where-Object { $_ -ieq $t })) { continue }
            & $claim $v $owner $seen
        }
    }
    $alias = @{}
    foreach ($k in $claims.Keys) {
        $c = $claims[$k]
        if ($c.Conflict) { continue }
        if ($k -ne ([string]$c.Id).ToLowerInvariant()) { $alias[$k] = [string]$c.Id }
    }
    $alias
}

function Resolve-SIVulnDesiredAlias {
    <#
        PURE. #429 -- ONE FINDING, ONE KEY, ON BOTH SIDES. The target's records are matched under the CI key their asset has
        NOW (-Alias: previous id -> current key, Merge-SIVulnKeyAlias); the desired set must be keyed the same way. Ring 1,
        2026-10-07: an attack-path finding came from Risk Analysis under the device's Entra id (a85ab003-...), which the
        correlation map does not carry, while the same device's other findings came under its CI key (22af10ec-...). The plan
        opened the finding under BOTH, the re-key then retired the twin as a duplicate, and the next run planned to OPEN it
        again under the retired record's key -- 40 such keys failed a chunk of 801 opens.
        Every desired CorrelationId that is a previous id / alias is replaced by the current key; a finding that then appears
        twice (the same CI key and finding key) is kept ONCE -- the row that already carried the current key wins (its asset
        id and name are the current ones), else the first. Returns @{ Desired; Resolved (rows re-keyed); Merged (twins dropped) }.
    #>
    param([AllowEmptyCollection()][object[]]$Desired = @(), [hashtable]$Alias = @{})
    $get = { param($o, [string]$n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $o.$n } }
    $set = { param($o, [string]$n, $v) if ($o -is [System.Collections.IDictionary]) { $o[$n] = $v } else { $o | Add-Member -NotePropertyName $n -NotePropertyValue $v -Force } }
    $resolved = 0; $merged = 0
    $byKey = [ordered]@{}
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        $id = ([string](& $get $d 'CorrelationId')).Trim()
        $wasAlias = $false
        if ($id -and $null -ne $Alias -and $Alias.Count -gt 0 -and $Alias.ContainsKey($id.ToLowerInvariant())) {
            $now = [string]$Alias[$id.ToLowerInvariant()]
            if ($now -and -not [string]::Equals($now, $id, [StringComparison]::OrdinalIgnoreCase)) {
                # a copy: the caller's row is not changed
                if ($d -is [System.Collections.IDictionary]) { $c = @{}; foreach ($k in @($d.Keys)) { $c[$k] = $d[$k] } } else { $c = [pscustomobject]@{}; foreach ($p in $d.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value } }
                & $set $c 'CorrelationId' $now
                $d = $c; $id = $now; $wasAlias = $true; $resolved++
            }
        }
        $k = ('{0}|{1}' -f $id.ToLowerInvariant(), ([string](& $get $d 'Cve')).Trim().ToUpperInvariant())
        if (-not $id) { $k = '#' + $byKey.Count }   # unkeyable rows pass through untouched (the plan skips them)
        if (-not $byKey.Contains($k)) { $byKey[$k] = @{ Row = $d; Alias = $wasAlias }; continue }
        $merged++
        if ($byKey[$k].Alias -and -not $wasAlias) { $byKey[$k] = @{ Row = $d; Alias = $false } }
    }
    [pscustomobject]@{ Desired = @($byKey.Values | ForEach-Object { $_.Row }); Resolved = $resolved; Merged = $merged }
}

function Resolve-SIVulnAssetId {
    <# PURE. The asset id a finding belongs to NOW: the current SI_AssetId when -Id is a previous one, else -Id. #>
    param([AllowEmptyString()][string]$Id, [hashtable]$Alias)
    if ([string]::IsNullOrWhiteSpace($Id) -or $null -eq $Alias -or $Alias.Count -eq 0) { return $Id }
    $k = $Id.Trim().ToLowerInvariant()
    if ($Alias.ContainsKey($k)) { return [string]$Alias[$k] }
    $Id
}

function Get-SIVulnRunHealthKql {
    <# The END heartbeats of recent Risk Analysis runs: start time, duration and verdict. #>
    param([int]$LookbackDays = 3)
    @"
SI_RunHealth_CL
| where TimeGenerated > ago($($LookbackDays)d)
| where Engine == "risk-analysis" and Phase == "End"
| project StartedAt = CollectionTime, DurationSec = toint(DurationSec), ExitReason = tostring(ExitReason), RunId = tostring(RunId)
"@
}

function Test-SIVulnSnapshotComplete {
    <#
        PURE. Was the snapshot produced by a complete Risk Analysis run? The rows carry their own stamp, the
        heartbeat carries the run's start and duration, so the producing run is the one whose window contains the
        snapshot. EVERY such run must have ended 'success' -- two overlapping runs (Summary and Detailed in
        parallel) both have to be clean, because the rows cannot say which one wrote them. No such run, an old
        snapshot, or any other verdict: NOT complete. Unknown is never complete; that is what keeps a close safe.
    #>
    param(
        [Parameter(Mandatory)][datetime]$SnapshotTime,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Runs,
        [datetime]$Now = [datetime]::UtcNow,
        [int]$MaxAgeHours = 26,
        [int]$SlackMinutes = 15
    )
    $snap = $SnapshotTime.ToUniversalTime()
    $age = ($Now.ToUniversalTime() - $snap).TotalHours
    if ($age -gt $MaxAgeHours) {
        return [pscustomobject]@{ Complete = $false; Reason = ('the newest snapshot is {0:N1} h old (limit {1} h)' -f $age, $MaxAgeHours) }
    }
    $containing = @($Runs | Where-Object {
        $_ -and $_.StartedAt -and
        ([datetime]$_.StartedAt).ToUniversalTime() -le $snap.AddMinutes($SlackMinutes) -and
        ([datetime]$_.StartedAt).ToUniversalTime().AddSeconds([double]$_.DurationSec).AddMinutes($SlackMinutes) -ge $snap
    })
    if ($containing.Count -eq 0) {
        return [pscustomobject]@{ Complete = $false; Reason = 'no Risk Analysis run-health record covers the snapshot -- completeness cannot be shown' }
    }
    $bad = @($containing | Where-Object { [string]$_.ExitReason -ne 'success' })
    if ($bad.Count -gt 0) {
        return [pscustomobject]@{ Complete = $false; Reason = ('the run that produced the snapshot ended ''{0}''' -f (($bad | ForEach-Object { [string]$_.ExitReason }) -join "', '")) }
    }
    [pscustomobject]@{ Complete = $true; Reason = ('{0} run(s) cover the snapshot, all ended ''success''' -f $containing.Count) }
}

# =====================================================================================================================
#  ONE INCOMPLETE REPORT DOES NOT HOLD A WHOLE RUN (owner 2026-10-14). A Risk Analysis run that ended 'success-partial'
#  ONLY because named reports could not be completed (its own judgement: sidata.Collection.RaPartialScope = 'reports';
#  the reports: verdict NotComplete in sidata.RaReportStatus) is complete for EVERY OTHER report: what is gone from those
#  closes as usual. What those reports found is FROZEN -- never counted absent, never closed (absence is not
#  remediation). Anything else stays as before: a run that failed, an unknown scope, a scope 'run' (a post or a profile the
#  run was built on), no verdicts, a database that cannot be read -- nothing closes.
# =====================================================================================================================
function Get-SIReportCompletenessSql {
    <# The Detailed collection at the snapshot time (within 5 seconds): its scope and its incomplete reports. Kind 'scope' / 'report' rows. #>
    @'
SET NOCOUNT ON;
DECLARE @t DATETIME2(3) = TRY_CONVERT(DATETIME2(3), @snap, 127);
IF @t IS NULL OR OBJECT_ID('sidata.Collection') IS NULL OR OBJECT_ID('sidata.RaReportStatus') IS NULL OR COL_LENGTH('sidata.Collection', 'RaPartialScope') IS NULL
BEGIN SELECT CAST(NULL AS NVARCHAR(16)) AS Kind, CAST(NULL AS NVARCHAR(256)) AS Name, CAST(NULL AS NVARCHAR(2000)) AS Detail WHERE 1 = 0; RETURN; END
DECLARE @ct DATETIME2(3) = NULL, @cid INT = NULL;
SELECT TOP (1) @ct = CollectionTime, @cid = CollectionId FROM sidata.Collection
WHERE Kind = N'Detailed' AND CollectionTime BETWEEN DATEADD(second, -5, @t) AND DATEADD(second, 5, @t)
ORDER BY ABS(DATEDIFF(millisecond, CollectionTime, @t));
IF @cid IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(16)) AS Kind, CAST(NULL AS NVARCHAR(256)) AS Name, CAST(NULL AS NVARCHAR(2000)) AS Detail WHERE 1 = 0; RETURN; END
DECLARE @scope NVARCHAR(16) = NULL;
EXEC sp_executesql N'SELECT @s = RaPartialScope FROM sidata.Collection WHERE CollectionId = @c', N'@c int, @s nvarchar(16) OUTPUT', @c = @cid, @s = @scope OUTPUT;
SELECT CAST(N'scope' AS NVARCHAR(16)) AS Kind, CAST(ISNULL(@scope, N'') AS NVARCHAR(256)) AS Name, CAST((SELECT COUNT(*) FROM sidata.RaReportStatus WHERE CollectionTime = @ct AND Grain = N'Detailed') AS NVARCHAR(2000)) AS Detail
UNION ALL
SELECT N'report', ReportName, Reason FROM sidata.RaReportStatus WHERE CollectionTime = @ct AND Grain = N'Detailed' AND State = N'NotComplete';
'@
}

function ConvertFrom-SIReportCompletenessRows {
    <# PURE. Get-SIReportCompletenessSql's rows -> @{ Known; Scope; Reports (names); Verdicts (count) }. No scope row = not known. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $g = { param($r, [string]$n) if ($r -is [System.Collections.IDictionary]) { $v = $r[$n] } elseif ($null -ne $r -and $r.PSObject.Properties[$n]) { $v = $r.$n } else { $v = $null }; if ($v -is [System.DBNull]) { $null } else { $v } }
    $scope = $null; $verdicts = 0; $names = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = [string](& $g $r 'Kind')
        if ($k -eq 'scope') { $scope = ([string](& $g $r 'Name')).Trim().ToLowerInvariant(); [int]::TryParse([string](& $g $r 'Detail'), [ref]$verdicts) | Out-Null }
        elseif ($k -eq 'report') { $n = ([string](& $g $r 'Name')).Trim(); if ($n -and -not $names.Contains($n)) { $names.Add($n) } }
    }
    [pscustomobject]@{ Known = ($null -ne $scope -and $verdicts -gt 0); Scope = [string]$scope; Reports = [string[]]$names.ToArray(); Verdicts = $verdicts }
}

function Read-SIReportCompleteness {
    <#
        The report verdicts of the Detailed collection at -SnapshotTime, from the data database. -Invoke: a (sql, params, mode)
        seam -- 'rows' (New-SIRecordSqlInvoke) or 'reader' (the data sync's). Never throws: a database that cannot be read
        answers Known = $false (nothing then closes per report).
    #>
    param([scriptblock]$Invoke, $SnapshotTime, [ValidateSet('rows', 'reader')][string]$Mode = 'rows')
    $none = [pscustomobject]@{ Known = $false; Scope = ''; Reports = [string[]]@(); Verdicts = 0 }
    if (-not $Invoke -or $null -eq $SnapshotTime -or "$SnapshotTime" -eq '') { return $none }
    try {
        $t = if ($SnapshotTime -is [datetime]) { $SnapshotTime.ToUniversalTime() } else { [datetime]::Parse([string]$SnapshotTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
        $rows = @(& $Invoke (Get-SIReportCompletenessSql) @{ snap = $t.ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) } $Mode | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        ConvertFrom-SIReportCompletenessRows -Rows $rows
    } catch { $none }
}

function Resolve-SIReportScopedComplete {
    <#
        PURE. The completeness verdict per report. -Complete: Test-SIVulnSnapshotComplete's verdict; -Runs: the run-health END
        records it was given; -Reports: Read-SIReportCompleteness. Returns @{ Complete; Reason; FrozenReports; Scoped }:
          already complete                                        -> as it is, nothing frozen;
          'success-partial' whose scope is 'reports' (known), with  -> Complete, FrozenReports = the incomplete reports
          incomplete reports, and nothing else wrong (the same rule
          read with those runs as 'success': age, covering run)
          anything else                                           -> as it is (not complete), nothing frozen.
    #>
    param([Parameter(Mandatory)]$Complete, [Parameter(Mandatory)][datetime]$SnapshotTime, [AllowEmptyCollection()][object[]]$Runs = @(), $Reports,
          [datetime]$Now = [datetime]::UtcNow, [int]$MaxAgeHours = 26)
    $as = { [pscustomobject]@{ Complete = [bool]$Complete.Complete; Reason = [string]$Complete.Reason; FrozenReports = [string[]]@(); Scoped = $false } }
    if ([bool]$Complete.Complete) { return (& $as) }
    if ($null -eq $Reports -or -not [bool]$Reports.Known -or [string]$Reports.Scope -ne 'reports' -or @($Reports.Reports).Count -eq 0) { return (& $as) }
    $asSuccess = @(@($Runs) | Where-Object { $_ } | ForEach-Object {
        $x = if ($_ -is [System.Collections.IDictionary]) { $h = @{}; foreach ($k in @($_.Keys)) { $h[$k] = $_[$k] }; [pscustomobject]$h } else { $_.PSObject.Copy() }
        if ([string]$x.ExitReason -eq 'success-partial') { $x.ExitReason = 'success' }; $x })
    $again = Test-SIVulnSnapshotComplete -SnapshotTime $SnapshotTime -Runs $asSuccess -Now $Now -MaxAgeHours $MaxAgeHours
    if (-not $again.Complete) { return (& $as) }
    $names = [string[]]@($Reports.Reports | Sort-Object -Unique)
    [pscustomobject]@{ Complete = $true; FrozenReports = $names; Scoped = $true
                       Reason = ('complete except {0} report(s) the run could not complete ({1}) -- what they found is kept as it is and never closed' -f $names.Count, ($names -join ', ')) }
}

function Test-SIReportFrozen {
    <#
        PURE. Does a record rest on a report that is frozen this run? -Reports: the record's report(s) (one name, a ';' / ','
        separated list, or an array). A record that names no report cannot be told apart, so it is frozen whenever any report
        is (unknown never closes).
    #>
    param($Reports, [AllowEmptyCollection()][string[]]$Frozen = @())
    $fz = @($Frozen | Where-Object { "$_".Trim() })
    if ($fz.Count -eq 0) { return $false }
    $names = @(@($Reports) | ForEach-Object { ([string]$_) -split '[;,]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($names.Count -eq 0) { return $true }
    foreach ($n in $names) { foreach ($f in $fz) { if ([string]::Equals($n, ([string]$f).Trim(), [StringComparison]::OrdinalIgnoreCase)) { return $true } } }
    $false
}

# =====================================================================================================================
#  #690 (34) A REPORT THAT CHANGED IS NOT A FIX. When a report's query is corrected, the findings the old query listed by
#  mistake disappear -- and an absence must never read as "remediated". Risk Analysis records per run and report the
#  fingerprint of what the report asks (sidata.RaReportStatus QueryHash, Get-RAReportQueryFingerprint); a record whose
#  report's fingerprint at the newest collection differs from the one at the record's last sighting (or whose report is not
#  in the newest collection at all) closes as 'Report changed' (Test-SIReportChangedSince, SI-VulnSync.ps1).
# =====================================================================================================================
function Get-SIReportQueryHistorySql {
    <#
        The report fingerprints from @since up to the collection at @snap (+5 s): every Detailed verdict with a fingerprint,
        and every verdict of the collection at @snap (with or without one -- a verdict without one is unknown, never "the
        report is gone"). A database without the column answers no rows (nothing reads as changed).
    #>
    @'
SET NOCOUNT ON;
DECLARE @t DATETIME2(3) = TRY_CONVERT(DATETIME2(3), @snap, 127), @from DATETIME2(3) = TRY_CONVERT(DATETIME2(3), @since, 127);
IF @t IS NULL OR OBJECT_ID('sidata.RaReportStatus') IS NULL OR COL_LENGTH('sidata.RaReportStatus', 'QueryHash') IS NULL
BEGIN SELECT CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS DATETIME2(3)) AS CollectionTime, CAST(NULL AS NVARCHAR(64)) AS QueryHash WHERE 1 = 0; RETURN; END
IF @from IS NULL OR @from > @t SET @from = DATEADD(day, -400, @t);
-- #692 the carry (the fingerprint a report had before a declared structure-only change) where the column exists
DECLARE @sql NVARCHAR(MAX) = N'SELECT ReportName, CollectionTime, QueryHash, ' + CASE WHEN COL_LENGTH('sidata.RaReportStatus', 'QueryHashCarry') IS NOT NULL THEN N'QueryHashCarry' ELSE N'CAST(NULL AS NVARCHAR(400))' END + N' AS QueryHashCarry FROM sidata.RaReportStatus
WHERE Grain = N''Detailed'' AND CollectionTime <= DATEADD(second, 5, @t)
  AND ((QueryHash IS NOT NULL AND CollectionTime >= DATEADD(day, -1, @from)) OR CollectionTime >= DATEADD(second, -5, @t))';
EXEC sp_executesql @sql, N'@t DATETIME2(3), @from DATETIME2(3)', @t = @t, @from = @from;
'@
}

function Read-SIReportQueryHistory {
    <#
        The report fingerprints for Test-SIReportChangedSince: @( @{ ReportName; CollectionTime (UTC); QueryHash; QueryHashCarry
        (#692 -- the fingerprint(s) it had before a declared structure-only change, ';'; '' = none) } ). -Since:
        the earliest last sighting the caller asks about. Never throws: a database that cannot be read answers no rows (no
        record then reads as "report changed" -- the close reasons are as before).
    #>
    param([scriptblock]$Invoke, $SnapshotTime, $Since = $null, [ValidateSet('rows', 'reader')][string]$Mode = 'rows')
    if (-not $Invoke -or $null -eq $SnapshotTime -or "$SnapshotTime" -eq '') { return @() }
    try {
        $iso = { param($v) $d = if ($v -is [datetime]) { $v.ToUniversalTime() } else { [datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }; $d.ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) }
        $p = @{ snap = (& $iso $SnapshotTime); since = $(if ($null -ne $Since -and "$Since" -ne '') { & $iso $Since } else { '' }) }
        @(& $Invoke (Get-SIReportQueryHistorySql) $p $Mode | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object {
            $g = { param($r, [string]$n) $v = if ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null }; if ($v -is [System.DBNull]) { $null } else { $v } }
            $t = & $g $_ 'CollectionTime'
            if ($t -is [datetime]) { $t = [datetime]::SpecifyKind($t, [DateTimeKind]::Utc) }
            [pscustomobject]@{ ReportName = [string](& $g $_ 'ReportName'); CollectionTime = $t; QueryHash = [string](& $g $_ 'QueryHash'); QueryHashCarry = [string](& $g $_ 'QueryHashCarry') } })
    } catch { @() }
}

function Get-SIVulnRowNames {
    <# PURE. A multi-value column of a desired-set row (make_set: JSON text, an array, or one value) as trimmed strings. #>
    param($Value)
    if ($null -eq $Value) { return @() }
    $v = $Value
    if ($v -is [string]) {
        $s = $v.Trim(); if (-not $s) { return @() }
        # PS 5.1 emits a JSON array from ConvertFrom-Json as ONE object: enumerate it, or the list becomes one joined string
        if ($s.StartsWith('[')) { try { $v = @(($s | ConvertFrom-Json -ErrorAction Stop) | ForEach-Object { $_ }) } catch { $v = @($s) } } else { $v = @($s) }
    }
    @(@($v) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
}

function ConvertTo-SIVulnDesired {
    <#
        PURE. Snapshot rows -> the plan's desired shape. A row with no asset id cannot be keyed, and a row with no
        ConfigurationId names no finding, so each is counted, not used. A row only a bookkeeping report carries
        ($script:SIVulnBookkeepingReports) is not a finding on the asset, and is counted apart.
        -KeyMap (ConvertTo-SICiKeyMap): the record's CorrelationId is the asset's CI KEY (#406 / #409), the asset id is kept
        as AssetId. Without it (or for an asset the map does not carry) the key is the asset id -- the shape before
        2026-10-06. Rows already in key space (ConvertTo-SIVulnKeySpaceRows: SI_AssetId set) keep their key.
        Every desired entry: CorrelationId (CI key), AssetId, Cve (the finding key, Get-SIVulnFindingKey), FindingType,
        Title, Report, Domain, Component (#561), SubCi (#772, the ServiceNow sub-CI), OsFamily (#772, the asset's OS family), PatchCycle (#772), Severity, AssetName, CiSysId, RiskScore.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [hashtable]$KeyMap = $null)
    $out = New-Object System.Collections.Generic.List[object]
    $noId = 0; $noFinding = 0; $bookkeeping = 0
    $val = { param($r, [string]$n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
    # #850: every value below is a PURE function of the row's own text values, and those repeat on nearly every finding (the
    # same reports, domain, component ... and the same finding key on many assets): each distinct input is worked out once
    # per call (a page) -- keyed on the exact values, in order; a value that is not text (or null) is worked out every time
    $memo = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $sb = New-Object System.Text.StringBuilder
    $memoKey = {
        param([string]$kind, [object[]]$vals)
        [void]$sb.Clear(); [void]$sb.Append($kind).Append('|')
        foreach ($x in $vals) { if ($null -eq $x) { [void]$sb.Append('~;') } elseif ($x -is [string]) { [void]$sb.Append($x.Length).Append(':').Append($x) } else { return $null } }
        $sb.ToString()
    }
    # the fields a finding takes from its row's multi-value columns (exactly as before #850, worked out from the raw values)
    $derive = {
        param([object[]]$v)
        $reports = @(Get-SIVulnRowNames $v[0])
        if (-not $reports.Count) { $reports = @(Get-SIVulnRowNames $v[1]) }
        $real = @($reports | Where-Object { $script:SIVulnBookkeepingReports -notcontains $_ } | Sort-Object)
        $domains = @(Get-SIVulnRowNames $v[2])
        if (-not $domains.Count) { $domains = @(Get-SIVulnRowNames $v[3]) }
        # #561 the finding's component (SQL, OS, ...): a specific value wins over Other; none = '' (a row from before #561)
        $comps = @(Get-SIVulnRowNames $v[4]); if (-not $comps.Count) { $comps = @(Get-SIVulnRowNames $v[5]) }
        # #772 the ServiceNow sub-CI (OS / SQL / Other, the customer's buckets): the same rule -- a specific bucket wins over Other
        $subcis = @(Get-SIVulnRowNames $v[6]); if (-not $subcis.Count) { $subcis = @(Get-SIVulnRowNames $v[7]) }
        # #772 the asset's OS family: a known family wins over Unknown / Other
        $fams = @(Get-SIVulnRowNames $v[8]); if (-not $fams.Count) { $fams = @(Get-SIVulnRowNames $v[9]) }
        # #772 the patch cycle: the most urgent the rows say (Catch-up, In monthly cycle, No fix available, then any)
        $pcs = @(Get-SIVulnRowNames $v[10]); if (-not $pcs.Count) { $pcs = @(Get-SIVulnRowNames $v[11]) }
        @{ Reports = $reports.Count; Real = $real.Count
           Domain = $(if ($domains.Count) { [string]$domains[0] } else { '' }); Report = $(if ($real.Count) { [string]$real[0] } else { '' })
           Component = [string](@(@($comps | Where-Object { $_ -ne 'Other' }) + @($comps) | Select-Object -First 1))
           SubCi = [string](@(@($subcis | Where-Object { $_ -ne 'Other' }) + @($subcis) | Select-Object -First 1))
           OsFamily = [string](@(@($fams | Where-Object { $_ -notin 'Unknown', 'Other' }) + @($fams | Where-Object { $_ -ne 'Unknown' }) + @($fams) | Select-Object -First 1))
           PatchCycle = [string](@(@($pcs | Where-Object { $_ -like 'Catch-up*' }) + @($pcs | Where-Object { $_ -eq 'In monthly cycle' }) + @($pcs | Where-Object { $_ -eq 'No fix available' }) + @($pcs) | Select-Object -First 1)) }
    }
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if ([string]::IsNullOrWhiteSpace([string](& $val $r 'AssetId'))) { $noId++; continue }
        $cidText = [string](& $val $r 'Cve')
        $hit = $null
        if ($memo.TryGetValue('K|' + $cidText, [ref]$hit)) { $key = $hit } else { $key = Get-SIVulnFindingKey $cidText; $memo['K|' + $cidText] = $key }
        if (-not $key) { $noFinding++; continue }
        $raw = [object[]]@((& $val $r 'Reports'), (& $val $r 'ReportName'), (& $val $r 'Domains'), (& $val $r 'SecurityDomain'), (& $val $r 'Components'), (& $val $r 'si_component'),
                           (& $val $r 'SubCis'), (& $val $r 'si_servicenow_subci'), (& $val $r 'OsFamilies'), (& $val $r 'si_os_family'), (& $val $r 'PatchCycles'), (& $val $r 'si_patch_cycle'))
        $mk = & $memoKey 'F' $raw
        $fld = $null
        if ($null -eq $mk -or -not $memo.TryGetValue($mk, [ref]$fld)) { $fld = & $derive $raw; if ($null -ne $mk) { $memo[$mk] = $fld } }
        if ($fld.Reports -and -not $fld.Real) { $bookkeeping++; continue }
        $domain = $fld.Domain
        $report = $fld.Report
        $aid = [string](& $val $r 'SI_AssetId')
        $corr = [string](& $val $r 'AssetId')
        if (-not $aid) { $aid = $corr; if ($null -ne $KeyMap) { $corr = [string](Get-SICiKey -AssetId $aid -KeyMap $KeyMap).Key } }
        $title = ([string](& $val $r 'Title')).Trim(); if ($title.Length -gt 400) { $title = $title.Substring(0, 400) }
        $tk = & $memoKey 'T' @($key, $domain, $report)
        $ftype = $null
        if (-not $memo.TryGetValue($tk, [ref]$ftype)) { $ftype = Get-SIVulnFindingType -Key $key -Domain $domain -Report $report; $memo[$tk] = $ftype }
        $entry = @{ CorrelationId = $corr; AssetId = $aid; Cve = $key; Severity = [string](& $val $r 'Severity')
                    AssetName = [string](& $val $r 'AssetName'); CiSysId = ''; RiskScore = [string](& $val $r 'RiskScore')
                    FindingType = $ftype; Title = $title; Report = $report; Domain = $domain; Component = $fld.Component; SubCi = $fld.SubCi; OsFamily = $fld.OsFamily; PatchCycle = $fld.PatchCycle }
        # #693 the affected software, for a meaning rule that links two findings (only when the snapshot carried it: F_si_affected_product)
        $affv = & $val $r 'F_si_affected_product'
        if ($null -ne $affv) {
            $ak = & $memoKey 'A' @($affv); $aff = $null
            if ($null -eq $ak -or -not $memo.TryGetValue($ak, [ref]$aff)) { $aff = @(Get-SIVulnRowNames $affv | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }); if ($null -ne $ak) { $memo[$ak] = $aff } }
            # every finding its own list (a copy), as before
            $entry['Affected'] = [object[]]$aff.Clone()
        }
        $out.Add($entry)
    }
    [pscustomobject]@{ Desired = $out.ToArray(); WithoutAssetId = $noId; WithoutFindingId = $noFinding; Bookkeeping = $bookkeeping }
}

function New-SIVulnTrimmedKeySet {
    <# PURE. #850 the case-insensitive set of -Keys, each trimmed, empty ones left out -- the one way the asset states, the
       plan and the run index build their key sets (so a set built once per run is the set a call would build). #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$Keys = @())
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($Keys)) { if ($x) { [void]$set.Add($x.Trim()) } }
    , $set
}

function Get-SIVulnAssetStates {
    <#
        PURE. CorrelationId (lower) -> lifecycle state, for every asset that has a finding in the snapshot OR an
        open record on the target. Alive = present in the snapshot, or seen by the endpoint profile within
        -ActiveDays (weekly tier cadence fits in the default 8). -SourceRan false (the endpoint profile has not
        run recently) makes every non-snapshot asset 'Unknown': a source that did not run says nothing.
        #406 -- -Retired: the CI keys SecurityInsight has RETIRED (cmdbsync.AssetLifecycle: not seen for longer than the
        grace period of the asset's category, or retired early by an Admin). That is the POSITIVE evidence the
        'Decommissioned' state needs, so their open findings close as AssetRetired -- never as fixed. An asset that is in
        this run's results, or that its profile saw within -ActiveDays, is NOT retired whatever the table says (it came
        back: the lifecycle reactivates it on its next run, and its findings reopen).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AssetIds,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$PresentInSnapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Profile,       # AssetId, LastSeen, Excluded
        [datetime]$Now = [datetime]::UtcNow,
        [bool]$SourceRan = $true,
        [int]$ActiveDays = 8,
        [int]$GraceDays = 14,
        [AllowEmptyCollection()][string[]]$Retired = @(),
        # #406 (owner 2026-10-19: "Close as asset retired"): the CIs the CORE CI lifecycle retired (Read-SICiRetiredKeys) --
        # Decommissioned even while this run still reports findings on them; active again in the core = not in this list
        [AllowEmptyCollection()][string[]]$RetiredCi = @(),
        # #850 (live 2026-10-24: every page rebuilt both sets from the whole run): New-SIVulnRunIndex, built ONCE per run from
        # the same -Retired / -RetiredCi -- its .Retired / .RetiredCi are used instead of building them here (the same sets)
        $RunIndex = $null
    )
    $retiredCiSet = $null; $retiredSet = $null
    if ($null -ne $RunIndex) { $retiredCiSet = $RunIndex.RetiredCi; $retiredSet = $RunIndex.Retired }
    if ($null -eq $retiredCiSet) { $retiredCiSet = New-SIVulnTrimmedKeySet -Keys $RetiredCi }
    $present = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $PresentInSnapshot) { if ($p) { [void]$present.Add($p) } }
    if ($null -eq $retiredSet) { $retiredSet = New-SIVulnTrimmedKeySet -Keys $Retired }
    $prof = @{}
    foreach ($p in $Profile) { if ($p -and $p.AssetId) { $prof[([string]$p.AssetId).ToLowerInvariant()] = $p } }
    $states = @{}
    foreach ($id in $AssetIds) {
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $k = $id.Trim().ToLowerInvariant()
        $p = $prof[$k]
        $excluded = [bool]($p -and $p.Excluded -eq $true)
        if ($retiredCiSet.Contains($id.Trim()) -and -not $excluded) {
            $states[$k] = Get-SIAssetLifecycleState -SeenThisRun $false -SourceRan $true -PositiveRemoval $true -DaysSinceSeen ([int]::MaxValue) -GraceDays $GraceDays
            continue
        }
        if ($present.Contains($id)) {
            $states[$k] = Get-SIAssetLifecycleState -SeenThisRun $true -ScopeExcluded $excluded
            continue
        }
        if ($p -and $p.LastSeen) {
            $days = [int][Math]::Floor(($Now.ToUniversalTime() - ([datetime]$p.LastSeen).ToUniversalTime()).TotalDays)
            $seen = ($days -le $ActiveDays)
            $states[$k] = Get-SIAssetLifecycleState -SeenThisRun $seen -SourceRan $SourceRan -ScopeExcluded $excluded -DaysSinceSeen $days -GraceDays $GraceDays `
                              -PositiveRemoval ($retiredSet.Contains($id.Trim()) -and -not $seen)
        } elseif ($retiredSet.Contains($id.Trim())) {
            # retired by the lifecycle (its own last-seen record, kept in SQL) and not seen in any profile since
            $states[$k] = Get-SIAssetLifecycleState -SeenThisRun $false -SourceRan $SourceRan -PositiveRemoval $true -DaysSinceSeen ([int]::MaxValue) -GraceDays $GraceDays
        } else {
            # Not in the snapshot and not in the profile window at all: if the profile ran, the asset has been
            # gone longer than the window -- past grace; if it did not, nothing is known.
            $states[$k] = Get-SIAssetLifecycleState -SeenThisRun $false -SourceRan $SourceRan -DaysSinceSeen ([int]::MaxValue) -GraceDays $GraceDays
        }
    }
    $states
}

function Get-SIVulnDisabledFrozenKeys {
    <#
        PURE. #533 -- the CI keys (lower case) of the assets whose account is DISABLED in this run's profiles
        (ConvertTo-SIVulnProfileKeySpace .AccountEnabled = 'false'), as left out by each setting: StateActions
        (SI_DisabledAssets_StateActions off -- every connector, the lifecycle and ticket open / close) and Connectors
        (SI_DisabledAssets_Connectors off -- connectors that send data out). An empty set where the stage includes them.
        Unknown is not disabled; inactivity is never read.
    #>
    param([AllowEmptyCollection()][object[]]$Profile = @(), $Policy)
    if (-not $Policy) { $Policy = Get-SIDisabledAssetPolicy }
    $mk = { New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
    $out = [pscustomobject]@{ StateActions = (& $mk); Connectors = (& $mk) }
    foreach ($p in @($Profile)) {
        if ($null -eq $p -or -not [string]$p.AssetId) { continue }
        if (-not (Test-SIAssetDisabled -Asset $p)) { continue }
        $k = ([string]$p.AssetId).Trim().ToLowerInvariant()
        if (-not $Policy.Effective.StateActions) { [void]$out.StateActions.Add($k) }
        if (-not $Policy.Effective.Connectors) { [void]$out.Connectors.Add($k) }
    }
    $out
}

function Get-SIVulnConnectorFrozenKeys {
    <#
        PURE. #533 -- the frozen keys for ONE connector: the StateActions set for every connector (the SQL lifecycle too);
        a connector that sends data OUT of SecurityInsight (servicenow, rest -- Jira, the risk register) adds the
        Connectors set. Stage = the setting the log line names.
    #>
    param([Parameter(Mandatory)]$Frozen, [string]$Kind)
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $Frozen.StateActions) { [void]$keys.Add($k) }
    $stage = 'StateActions'
    if (([string]$Kind).ToLowerInvariant() -ne 'sql') {
        $before = $keys.Count
        foreach ($k in $Frozen.Connectors) { [void]$keys.Add($k) }
        if ($keys.Count -gt $before -or ($Frozen.StateActions.Count -eq 0 -and $keys.Count -gt 0)) { $stage = 'Connectors' }
    }
    [pscustomobject]@{ Keys = $keys; Stage = $stage }
}

function Get-SIVulnOutOfScopeKeysSql {
    <# The CI keys whose every provider record is marked out of the collection scope (si_in_scope = false). Guarded. #>
    @'
IF OBJECT_ID('sidata.CiRecord') IS NULL SELECT CAST(NULL AS NVARCHAR(64)) AS CiId WHERE 1 = 0;
ELSE SELECT r.CiId FROM sidata.CiRecord AS r WHERE r.CiId IS NOT NULL
GROUP BY r.CiId
HAVING MIN(CASE WHEN LOWER(JSON_VALUE(r.DocJson, '$.si_in_scope')) = N'false' THEN 1 ELSE 0 END) = 1;
'@
}

function Read-SIVulnOutOfScopeKeys {
    <#
        CIs follow the collection scope (owner 2026-10-10): the CI keys (lower case) of the assets the scope settings leave out
        -- their open records are FROZEN like a disabled asset's ('OutOfScope': never a close candidate, outside the collapse
        floor and the ceiling). -Invoke: the (sql, params, mode) seam of the database. Returns @{ Keys; Known }; Known $false
        when the read fails -- the caller then closes nothing this run (unknown never closes).
    #>
    param([scriptblock]$Invoke)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if (-not $Invoke) { return [pscustomobject]@{ Keys = $set; Known = $true } }
    try {
        $rows = @(& $Invoke (Get-SIVulnOutOfScopeKeysSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        foreach ($r in $rows) {
            $v = if ($r -is [System.Collections.IDictionary]) { [string]$r['CiId'] } elseif ($r.PSObject.Properties['CiId']) { [string]$r.CiId } else { '' }
            if ($v) { [void]$set.Add($v.Trim().ToLowerInvariant()) }
        }
        return [pscustomobject]@{ Keys = $set; Known = $true }
    } catch { return [pscustomobject]@{ Keys = $set; Known = $false; Error = $_.Exception.Message } }
}

function Set-SIVulnOutOfScopeStates {
    <#
        PURE. Marks the out-of-scope assets 'OutOfScope' in the plan's asset states (in place; returns how many). A 'Disabled'
        asset stays 'Disabled' (the same freeze, the more specific reason); every other state -- also Retired -- is replaced:
        an asset the scope leaves out is not seen BECAUSE of a setting, so its findings are never closed.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$States, $Keys)
    $n = 0
    foreach ($k in @($Keys)) {
        if (-not $k) { continue }
        $lk = ([string]$k).Trim().ToLowerInvariant()
        if ($States.Contains($lk) -and [string]$States[$lk] -eq 'Disabled') { continue }
        $States[$lk] = 'OutOfScope'; $n++
    }
    $n
}

function New-SIVulnDisabledKeySet {
    <# PURE. #533 the frozen keys as Select-SIVulnDisabledDesired matches them (case-insensitive, trimmed) -- #850 built once
       per connector, never once per page. #>
    param($FrozenKeys)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in @($FrozenKeys)) { if ($k) { [void]$set.Add(([string]$k).Trim()) } }
    , $set
}

function Select-SIVulnDisabledDesired {
    <# PURE. #533 -- the desired findings without those of frozen (disabled, left out) assets: never opened or updated.
       -KeySet: New-SIVulnDisabledKeySet of the same -FrozenKeys, built once (#850); without it the set is built here. #>
    param([AllowEmptyCollection()][object[]]$Desired = @(), $FrozenKeys, $KeySet = $null)
    $set = $KeySet
    if ($null -eq $set) { $set = New-SIVulnDisabledKeySet -FrozenKeys $FrozenKeys }
    if ($set.Count -eq 0) { return [pscustomobject]@{ Desired = @($Desired); Removed = 0 } }
    $kept = @($Desired | Where-Object { $_ -and -not $set.Contains(([string]$_.CorrelationId).Trim()) })
    [pscustomobject]@{ Desired = $kept; Removed = (@($Desired).Count - $kept.Count) }
}
