#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE SUMMARY REPORT ROWS (REQUIREMENTS #583): SI_RiskAnalysis_Summary_CL -> the Pro database.

    The web app's former Summary page (/Summary; #636: Security recommendations > Summary now reads the stored groupings of the Detailed findings) showed the RiskAnalysis_Summary workbook's rows -- one row per
    recommendation x tier x severity x risk factors x CMDB group, with its impacted assets -- grouped by tier, the most
    critical risk first. These are the SAME rows the workbook is built from: Risk Analysis's Summary run posts them to
    SI_RiskAnalysis_Summary_CL, and this step copies each complete Summary collection into three tables
    (sql/si-data-schema.sql):
        sidata.SummaryLoad    one row per loaded Summary collection ('Loading' until every row landed, then 'Complete')
        sidata.SummaryRow     one row per Summary row, real typed columns (tier, rating rank, scores) -- the page filters
                              and orders on indexed columns, it never parses JSON per row
        sidata.SummaryAsset   one row per impacted asset of a Summary row (its name and id, in the row's order), so the
                              page lists the first assets inline and links each to its CI

    THE RULES (the same as the Detailed load, SI-DataSync.ps1):
      * only a collection whose Risk Analysis run is shown complete (run health, Get-SIDataLoadPlan) is loaded, and only
        WHOLE: a short write fails the load and the collection stays 'Loading' (never shown) until the next run loads it
        again; a load that died part way is removed and loaded again;
      * a collection is loaded once; a re-run loads nothing twice;
      * collections older than SI_Pro_DataRetentionDays are removed (sidata.Summary* only);
      * a table that does not exist yet (fresh install) is skipped with one line; a database without the Summary tables
        is told once (run setup\Initialize-SIDataSql.ps1 / the updater applies the schema). This step NEVER fails the
        data sync: the caller wraps it, and a failed collection is said and tried again on the next run.

    THE COLUMN NAMES: Risk Analysis's outputs carry si_ names (data-model/ra-output-names.locked.json). Every column is read
    through ONE helper (Get-SIDataSummaryColumnKql): the si_ name first, else the old name -- so rows written before and
    after the rename both load.

    Seams: -Query scriptblock (kql) -> rows; -Invoke scriptblock (sql, params, mode) -- as Invoke-SIDataSyncCore.
    PS 5.1 safe. No Set-StrictMode (it leaks into the caller's scope).
#>

# The Summary row's columns: SQL column -> (old Risk Analysis column, si_ column, kind). kind: text | number | tier | list.
$script:SIDataSummaryColumns = [ordered]@{
    SecurityDomain                = @('SecurityDomain', 'si_security_domain', 'text')
    Category                      = @('Category', 'si_category', 'text')
    Subcategory                   = @('Subcategory', 'si_subcategory', 'text')
    ConfigurationName             = @('ConfigurationName', 'si_title', 'text')
    ConfigurationId               = @('ConfigurationId', 'si_finding_key', 'text')
    Impact                        = @('Impact', 'si_impact', 'text')
    SecuritySeverity              = @('SecuritySeverity', 'si_severity', 'text')
    CriticalityTier               = @('CriticalityTier', 'si_tier', 'tier')
    CriticalityTierLevel          = @('CriticalityTierLevel', 'si_tier_level', 'text')
    RiskFactorConsequenceDetailed = @('RiskFactor_Consequence_Detailed', 'si_risk_factor_consequence_detailed', 'text')
    RiskFactorConsequence         = @('RiskFactor_Consequence', 'si_risk_factor_consequence', 'number')
    RiskFactorProbabilityDetailed = @('RiskFactor_Probability_Detailed', 'si_risk_factor_probability_detailed', 'text')
    RiskFactorIds                 = @('RiskFactorIds', 'si_risk_factor_ids', 'text')
    RiskFactorProbability         = @('RiskFactor_Probability', 'si_risk_factor_probability', 'number')
    RiskConsequenceScore          = @('RiskConsequenceScore', 'si_risk_consequence_score', 'number')
    RiskProbabilityScore          = @('RiskProbabilityScore', 'si_risk_probability_score', 'number')
    RiskScoreTotal                = @('RiskScoreTotal', 'si_risk_score', 'number')
    RiskScoreWeightFactor         = @('RiskScore_Weight_Factor', 'si_risk_score_weight_factor', 'number')
    RiskScoreWeightDetailed       = @('RiskScore_Weight_Detailed', 'si_risk_score_weight_detailed', 'text')
    RiskScoreTotalWeighted        = @('RiskScoreTotal_Weighted', 'si_weighted_risk_score', 'number')
    RiskRating                    = @('RiskRating', 'si_risk_rating', 'text')
    CmdbId                        = @('cmdbId', 'si_cmdb_id', 'text')
    CmdbName                      = @('cmdbName', 'si_cmdb_name', 'text')
    CmdbCriticality               = @('cmdbCriticality', 'si_cmdb_criticality', 'text')
    CmdbDataSensitivity           = @('cmdbDataSensitivity', 'si_cmdb_data_sensitivity', 'text')
    ImpactedAssetCount            = @('ImpactedAssetCount', 'si_impacted_asset_count', 'number')
    ImpactedAssetsList            = @('ImpactedAssetsList', 'si_impacted_assets_list', 'list')
    ImpactedAssetIds              = @('ImpactedAssetIds', 'si_impacted_asset_ids', 'list')
    MoreDetails                   = @('MoreDetails', 'si_more_details', 'text')
    ReportName                    = @('AssetDetectedInReportName', 'si_report_name', 'text')
    MitreTactics                  = @('MITRE_Tactics', 'si_mitre_tactics', 'text')
    MitreTechniques               = @('MITRE_Techniques', 'si_mitre_techniques', 'text')
    ComplianceTags                = @('ComplianceTags', 'si_compliance_tags', 'text')
    # #590 every finding carries its fix: how to fix, the recommended security update and its id, the affected software
    # (new columns, born si_), and a configuration recommendation's own description and risk
    FixRemediation                = @('si_fix_remediation', 'si_fix_remediation', 'text')
    FixRecommendedUpdate          = @('si_fix_recommended_update', 'si_fix_recommended_update', 'text')
    FixRecommendedUpdateId        = @('si_fix_recommended_update_id', 'si_fix_recommended_update_id', 'text')
    AffectedSoftware              = @('si_affected_software', 'si_affected_software', 'text')
    ConfigurationDescription      = @('ConfigurationDescription', 'si_configuration_description', 'text')
    RiskDescription               = @('RiskDescription', 'si_risk_description', 'text')
}

function Get-SIDataSummaryColumnKql {
    <#
        PURE. THE one read of a Risk Analysis output column: the si_ column when it carries a value, else the old column
        (column_ifexists both, so a table without either reads empty). A dynamic column (an array) reads as its JSON text.
    #>
    param([Parameter(Mandatory)][string]$Old, [Parameter(Mandatory)][string]$Si)
    'coalesce(tostring(column_ifexists("{0}", "")), tostring(column_ifexists("{1}", "")))' -f $Si, $Old
}

function Get-SIDataSummaryTimeKql {
    <# PURE. The row's collection time (si_collection_time first, else CollectionTime) as one KQL expression. #>
    'coalesce(todatetime(column_ifexists("si_collection_time", datetime(null))), todatetime(column_ifexists("CollectionTime", datetime(null))))'
}

function Get-SIDataSummaryCollectionsKql {
    <#
        PURE. Every Risk Analysis SUMMARY collection of this edition in the look-back window, one row per collection time,
        with its row count and size, oldest first -- the shape Get-SIDataLoadPlan reads (NoConfigurationId included).
    #>
    param([Parameter(Mandatory)][string]$EditionMajor, [int]$LookbackDays = 3, [string]$TableName = 'SI_RiskAnalysis_Summary_CL')
    $ver = Get-SIDataSummaryColumnKql -Old 'SolutionVersion' -Si 'si_solution_version'
    $cfg = Get-SIDataSummaryColumnKql -Old 'ConfigurationId' -Si 'si_finding_key'
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| extend _ct = $(Get-SIDataSummaryTimeKql), _ver = $ver
| where _ver startswith "$EditionMajor."
| where isnotnull(_ct)
| summarize Rows = count(), Bytes = sum(estimate_data_size(*)), SolutionVersion = take_any(_ver), NoConfigurationId = countif(isempty($cfg)) by CollectionTime = _ct
| order by CollectionTime asc
"@
}

function Get-SIDataSummaryRowsKql {
    <# PURE. The rows of ONE Summary collection, every column through Get-SIDataSummaryColumnKql. #>
    param([Parameter(Mandatory)][datetime]$CollectionTime, [Parameter(Mandatory)][string]$EditionMajor, [int]$LookbackDays = 3,
          [string]$TableName = 'SI_RiskAnalysis_Summary_CL',
          # #639 one PAGE (Get-SIDataPageFilter over the rows' own key _pk), or with -CountOnly how many rows it holds
          [string]$PageFilter = '', [switch]$CountOnly)
    $ver = Get-SIDataSummaryColumnKql -Old 'SolutionVersion' -Si 'si_solution_version'
    $cols = foreach ($k in $script:SIDataSummaryColumns.Keys) {
        $c = $script:SIDataSummaryColumns[$k]
        '    {0} = {1}' -f $k, (Get-SIDataSummaryColumnKql -Old $c[0] -Si $c[1])
    }
    # the row's own key: its Log Analytics item id, and the hash of the whole row (a row without an id)
    $pf =$(if ($PageFilter) { $PageFilter + "`n" } else { '' })
    $head = @"
$TableName
| where TimeGenerated > ago($($LookbackDays + 1)d)
| extend _ct = $(Get-SIDataSummaryTimeKql), _ver = $ver
| where _ct == $(ConvertTo-SIDataKqlTime -Time $CollectionTime)
| where _ver startswith "$EditionMajor."
| extend _pk = strcat(tostring(column_ifexists("_ItemId", "")), "|", tostring(hash(tostring(pack_all()))))

"@
    $head += $pf
    if ($CountOnly) {
        return ($head + "| summarize PageRows = count(), KeyMin = min(_pk), KeyMax = max(_pk)`n| project PageRows, OneKey = (KeyMin == KeyMax)")
    }
    $head + @"
| project
$($cols -join ",`n")
"@
}

function Split-SIDataSummaryList {
    <#
        PURE. An impacted-asset list as the strings it holds, in order: a JSON array (the dynamic column, '["a","b"]'), or
        the joined text the workbook shows ("a, b"). Empty -> nothing.
    #>
    param([AllowNull()][AllowEmptyString()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return , @() }
    $t = ([string]$Value).Trim()
    if (-not $t) { return , @() }
    if ($t.StartsWith('[')) {
        try {
            $o = ConvertFrom-Json -InputObject $t
            return , @(@($o) | ForEach-Object { if ($null -ne $_) { ([string]$_).Trim() } } | Where-Object { $_ })
        } catch { }
    }
    , @($t -split ',\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-SIDataSummaryRatingRank {
    <# PURE. The order of a risk rating, most critical first: Critical 1, High 2, Moderate / Medium 3, Low 4, anything else 5. #>
    param([AllowNull()][string]$Rating)
    switch -Regex (([string]$Rating).Trim()) {
        '^(?i)critical$' { return 1 }
        '^(?i)(very\s*)?high$' { return 2 }
        '^(?i)(moderate|medium)$' { return 3 }
        '^(?i)low$' { return 4 }
        default { return 5 }
    }
}

function ConvertTo-SIDataSummaryItems {
    <#
        PURE. The Log Analytics rows of one Summary collection -> the JSON objects the two inserts read: Rows (one per
        Summary row, RowNo 0..n-1) and Assets (one per impacted asset: RowNo, Ordinal, AssetName, AssetId -- names and ids
        paired by position; a name without an id, or an id without a name, is kept alone). The lists are stored joined with
        ", " (as the workbook shows them) for the export.
    #>
    # -StartRowNo: the first row's RowNo (Risk Analysis writes a run's rows in parts, each part numbered on from the last)
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [long]$StartRowNo = 0)
    $rowItems = New-Object System.Collections.Generic.List[string]
    $assetItems = New-Object System.Collections.Generic.List[string]
    $n = $StartRowNo
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $v = [ordered]@{ RowNo = $n }
        $names = @(); $ids = @()
        foreach ($k in $script:SIDataSummaryColumns.Keys) {
            $kind = $script:SIDataSummaryColumns[$k][2]
            $raw = $null; if ($r.PSObject.Properties[$k]) { $raw = $r.$k }
            switch ($kind) {
                'number' { $v[$k] = ConvertTo-SIDataNumber $raw }
                'tier'   { $v[$k] = ConvertTo-SIDataTier $raw }
                'list'   {
                    $items = Split-SIDataSummaryList $raw
                    if ($k -eq 'ImpactedAssetsList') { $names = $items } else { $ids = $items }
                    $v[$k] = $(if ($items.Count) { $items -join ', ' } else { $null })
                }
                default  { $t = [string]$raw; $v[$k] = $(if ($t.Trim()) { $t } else { $null }) }
            }
        }
        $v['RatingRank'] = Get-SIDataSummaryRatingRank -Rating ([string]$v['RiskRating'])
        # the count Risk Analysis computed; when it carried none, the assets the row lists
        if ($null -eq $v['ImpactedAssetCount']) { $v['ImpactedAssetCount'] = [Math]::Max($names.Count, $ids.Count) }
        $rowItems.Add((ConvertTo-SIDataJsonObject -Values $v))
        $m = [Math]::Max($names.Count, $ids.Count)
        for ($i = 0; $i -lt $m; $i++) {
            $nm = $null; if ($i -lt $names.Count) { $nm = $names[$i] }
            $id = $null; if ($i -lt $ids.Count) { $id = $ids[$i] }
            $assetItems.Add((ConvertTo-SIDataJsonObject -Values ([ordered]@{ RowNo = $n; Ordinal = $i; AssetName = $nm; AssetId = $id })))
        }
        $n++
    }
    [pscustomobject]@{ Rows = $rowItems.ToArray(); Assets = $assetItems.ToArray() }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS -- pure text, so their shape is testable
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataSummarySchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.SummaryLoad') IS NOT NULL AND OBJECT_ID('sidata.SummaryRow') IS NOT NULL AND OBJECT_ID('sidata.SummaryAsset') IS NOT NULL AND COL_LENGTH('sidata.SummaryRow', 'FixRemediation') IS NOT NULL AND COL_LENGTH('sidata.SummaryRow', 'RiskDescription') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataSummaryLoadedSql {
    # #638: with who wrote it -- a Summary collection Risk Analysis wrote itself (Source 'risk-analysis') is never loaded again
    @"
IF COL_LENGTH('sidata.SummaryLoad', 'Source') IS NULL
    SELECT CollectionTime, Status, CAST(NULL AS nvarchar(16)) AS Source FROM sidata.SummaryLoad WHERE CollectionTime >= CONVERT(datetime2(3), @Since, 126);
ELSE IF COL_LENGTH('sidata.SummaryLoad', 'RetiredAt') IS NULL
    EXEC sp_executesql N'SELECT CollectionTime, Status, Source FROM sidata.SummaryLoad WHERE CollectionTime >= CONVERT(datetime2(3), @Since, 126)', N'@Since nvarchar(40)', @Since = @Since;
ELSE EXEC sp_executesql N'SELECT CollectionTime, Status, Source, CASE WHEN RetiredAt IS NULL THEN 0 ELSE 1 END AS Retired FROM sidata.SummaryLoad WHERE CollectionTime >= CONVERT(datetime2(3), @Since, 126)', N'@Since nvarchar(40)', @Since = @Since;
"@
}

function Get-SIDataSummaryBeginSql {
    <# A load starts clean: whatever an earlier, unfinished load of this collection left is removed, then a 'Loading' row. #>
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
DELETE FROM sidata.SummaryAsset WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126);
DELETE FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126);
DELETE FROM sidata.SummaryLoad WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126);
INSERT sidata.SummaryLoad (CollectionTime, RunId, Status, SolutionVersion)
VALUES (CONVERT(datetime2(3), @CollectionTime, 126), NULLIF(@RunId, ''), 'Loading', NULLIF(@SolutionVersion, ''));
COMMIT;
SELECT 1;
'@
}

function Get-SIDataSummaryInsertRowSql {
    @'
INSERT sidata.SummaryRow (CollectionTime, RowNo, SecurityDomain, Category, Subcategory, ConfigurationName, ConfigurationId, Impact, SecuritySeverity,
    CriticalityTier, CriticalityTierLevel, RiskFactorConsequenceDetailed, RiskFactorConsequence, RiskFactorProbabilityDetailed, RiskFactorIds,
    RiskFactorProbability, RiskConsequenceScore, RiskProbabilityScore, RiskScoreTotal, RiskScoreWeightFactor, RiskScoreWeightDetailed,
    RiskScoreTotalWeighted, RiskRating, RatingRank, CmdbId, CmdbName, CmdbCriticality, CmdbDataSensitivity, ImpactedAssetCount,
    ImpactedAssetsList, ImpactedAssetIds, MoreDetails, ReportName, MitreTactics, MitreTechniques, ComplianceTags,
    FixRemediation, FixRecommendedUpdate, FixRecommendedUpdateId, AffectedSoftware, ConfigurationDescription, RiskDescription)
SELECT CONVERT(datetime2(3), @CollectionTime, 126), j.RowNo, j.SecurityDomain, j.Category, j.Subcategory, j.ConfigurationName, j.ConfigurationId, j.Impact,
    j.SecuritySeverity, j.CriticalityTier, j.CriticalityTierLevel, j.RiskFactorConsequenceDetailed, j.RiskFactorConsequence, j.RiskFactorProbabilityDetailed,
    j.RiskFactorIds, j.RiskFactorProbability, j.RiskConsequenceScore, j.RiskProbabilityScore, j.RiskScoreTotal, j.RiskScoreWeightFactor, j.RiskScoreWeightDetailed,
    j.RiskScoreTotalWeighted, j.RiskRating, ISNULL(j.RatingRank, 5), j.CmdbId, j.CmdbName, j.CmdbCriticality, j.CmdbDataSensitivity, j.ImpactedAssetCount,
    j.ImpactedAssetsList, j.ImpactedAssetIds, j.MoreDetails, j.ReportName, j.MitreTactics, j.MitreTechniques, j.ComplianceTags,
    j.FixRemediation, j.FixRecommendedUpdate, j.FixRecommendedUpdateId, j.AffectedSoftware, j.ConfigurationDescription, j.RiskDescription
FROM OPENJSON(@j) WITH (RowNo int, SecurityDomain nvarchar(128), Category nvarchar(256), Subcategory nvarchar(256), ConfigurationName nvarchar(1000),
    ConfigurationId nvarchar(256), Impact nvarchar(512), SecuritySeverity nvarchar(30), CriticalityTier tinyint, CriticalityTierLevel nvarchar(64),
    RiskFactorConsequenceDetailed nvarchar(1000), RiskFactorConsequence float, RiskFactorProbabilityDetailed nvarchar(1000), RiskFactorIds nvarchar(1000),
    RiskFactorProbability float, RiskConsequenceScore float, RiskProbabilityScore float, RiskScoreTotal float, RiskScoreWeightFactor float,
    RiskScoreWeightDetailed nvarchar(1000), RiskScoreTotalWeighted float, RiskRating nvarchar(16), RatingRank tinyint, CmdbId nvarchar(256),
    CmdbName nvarchar(400), CmdbCriticality nvarchar(64), CmdbDataSensitivity nvarchar(64), ImpactedAssetCount int, ImpactedAssetsList nvarchar(max),
    ImpactedAssetIds nvarchar(max), MoreDetails nvarchar(max), ReportName nvarchar(256), MitreTactics nvarchar(1000), MitreTechniques nvarchar(2000),
    ComplianceTags nvarchar(2000), FixRemediation nvarchar(4000), FixRecommendedUpdate nvarchar(2000), FixRecommendedUpdateId nvarchar(2000),
    AffectedSoftware nvarchar(max), ConfigurationDescription nvarchar(4000), RiskDescription nvarchar(4000)) j;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataSummaryInsertAssetSql {
    @'
INSERT sidata.SummaryAsset (CollectionTime, RowNo, Ordinal, AssetName, AssetId)
SELECT CONVERT(datetime2(3), @CollectionTime, 126), j.RowNo, j.Ordinal, j.AssetName, j.AssetId
FROM OPENJSON(@j) WITH (RowNo int, Ordinal int, AssetName nvarchar(400), AssetId nvarchar(450)) j;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataSummaryCompleteSql {
    # Only a 'Loading' collection whose rows equal what Log Analytics held is marked complete.
    @'
UPDATE sidata.SummaryLoad SET Status = 'Complete', [Rows] = @Rows, LoadedAt = SYSUTCDATETIME()
WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND Status = 'Loading'
  AND (SELECT COUNT_BIG(*) FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126)) = @Rows;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataSummaryPurgeSql {
    <#
        One batch of the Summary rows past retention (and of loads that died outside the look-back window). -Table from an
        allow-list, never input; children first.
    #>
    param([Parameter(Mandatory)][ValidateSet('SummaryAsset', 'SummaryRow', 'SummaryLoad')][string]$Table)
    if ($Table -eq 'SummaryLoad') {
        return "DELETE TOP (@Batch) FROM sidata.SummaryLoad WHERE (CollectionTime < CONVERT(datetime2(3), @Cutoff, 126) OR (Status = 'Loading' AND CollectionTime < CONVERT(datetime2(3), @StaleLoading, 126))) AND NOT EXISTS (SELECT 1 FROM sidata.SummaryRow r WHERE r.CollectionTime = sidata.SummaryLoad.CollectionTime); SELECT @@ROWCOUNT;"
    }
    "DELETE TOP (@Batch) t FROM sidata.$Table t WHERE t.CollectionTime < CONVERT(datetime2(3), @Cutoff, 126) OR EXISTS (SELECT 1 FROM sidata.SummaryLoad l WHERE l.CollectionTime = t.CollectionTime AND l.Status = 'Loading' AND l.CollectionTime < CONVERT(datetime2(3), @StaleLoading, 126)); SELECT @@ROWCOUNT;"
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STEP
# ------------------------------------------------------------------------------------------------------------------

function Invoke-SIDataSummaryLoad {
    <# One planned Summary collection: begin, read, write rows + assets, complete. Throws on a short read or write. #>
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Invoke,
          [Parameter(Mandatory)][string]$EditionMajor, [int]$LookbackDays = 3, [ref]$ChunkChars, [string]$TableName = 'SI_RiskAnalysis_Summary_CL')
    $at = Format-SIDataSqlTime -Time $Item.CollectionTime
    $runId = ''; if ($Item.Run -and $Item.Run.PSObject.Properties['RunId']) { $runId = [string]$Item.Run.RunId }
    [void](& $Invoke (Get-SIDataSummaryBeginSql) @{ CollectionTime = $at; RunId = $runId; SolutionVersion = [string]$Item.SolutionVersion } 'scalar')
    # #639 A PAGE AT A TIME (the rows were read as one answer): the collection's rows in pages of the rows' own key
    # (Read-SIDataPages: the number of pages from the measured size; a page too large to answer or to hold is read again in
    # halves), each page written before the next is read. Complete only when every row was read and written; a short read
    # leaves it 'Loading' (hidden) and the next run starts it clean (Get-SIDataSummaryBeginSql).
    # the page reader and the page filter are the data sync's (it loads them before this step)
    foreach ($fn in 'Read-SIDataPages', 'Get-SIDataPageFilter') { if (-not (Get-Command -Name $fn -ErrorAction SilentlyContinue)) { throw ("the Summary rows are read a page at a time, and the page reader ({0}) is not loaded" -f $fn) } }
    $bytes = 0.0
    if ($Item.PSObject.Properties['Bytes'] -and $null -ne $Item.Bytes) { $bv = ConvertTo-SIDataNumber $Item.Bytes; if ($null -ne $bv) { $bytes = [double]$bv } }
    $planned = Get-SIDataPartitionCount -Rows ([long]$Item.Rows) -Bytes $bytes
    $p = @{ CollectionTime = $at }
    $st = @{ Read = 0L; Written = 0L; Assets = 0L }
    $kqlOf = { param($cuts, $countOnly) Get-SIDataSummaryRowsKql -CollectionTime $Item.CollectionTime -EditionMajor $EditionMajor -LookbackDays $LookbackDays -TableName $TableName -PageFilter (Get-SIDataPageFilter -Cuts $cuts) -CountOnly:([bool]$countOnly) }
    $onRows = {
        param($pageRows)
        $rs = @($pageRows | Where-Object { $null -ne $_ })
        $items = ConvertTo-SIDataSummaryItems -Rows $rs -StartRowNo $st.Read
        $st.Read += $rs.Count
        $rs = $null
        $chars = 0L; foreach ($x in $items.Rows) { $chars += ([string]$x).Length }
        $st.Written += [long](Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataSummaryInsertRowSql) -Items $items.Rows -Params $p -ChunkChars $ChunkChars -What 'summary rows')
        if ($items.Assets.Count) { $st.Assets += [long](Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataSummaryInsertAssetSql) -Items $items.Assets -Params $p -ChunkChars $ChunkChars -What 'summary assets') }
        $chars
    }
    $null = Read-SIDataPages -Query $Query -KqlOf $kqlOf -Pages $planned -OnRows $onRows -What ('the Summary collection of {0} UTC' -f $at)
    if ([long]$st.Read -ne [long]$Item.Rows) {
        throw ("the Summary collection of {0} UTC read {1} row(s), Log Analytics listed {2} -- NOT loaded; tried again on the next run" -f $at, $st.Read, $Item.Rows)
    }
    $written = $st.Written; $assets = $st.Assets
    $done = [int](& $Invoke (Get-SIDataSummaryCompleteSql) @{ CollectionTime = $at; Rows = [int]$written } 'scalar')
    if ($done -ne 1) { throw ("the Summary collection of {0} UTC could not be marked complete (rows written {1}) -- it stays hidden; tried again on the next run" -f $at, $written) }
    [pscustomobject]@{ CollectionTime = $Item.CollectionTime; Rows = [long]$written; Assets = [long]$assets }
}

function Invoke-SIDataSummarySync {
    <#
        THE STEP: every complete Summary collection in the look-back window not loaded yet is loaded, then the Summary rows
        past retention are removed. Returns @{ Ready; Plan; Loaded; Held; Failed; Purged }. Never throws for one collection
        (said, tried again next run); throws only when Log Analytics or SQL fail outright -- the caller never lets that
        fail the data sync.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Query,
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [Parameter(Mandatory)][string]$EditionMajor,
        [Parameter(Mandatory)]$Settings,
        [switch]$DryRun,
        [datetime]$Now = [datetime]::UtcNow,
        [scriptblock]$Log,
        [string]$TableName = 'SI_RiskAnalysis_Summary_CL'
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $result = [ordered]@{ Ready = $false; Plan = @(); Loaded = @(); Held = @(); Failed = @(); Purged = 0L; DryRun = [bool]$DryRun; Problem = ''; ListDays = 0 }
    if ([int](& $Invoke (Get-SIDataSummarySchemaCheckSql) @{} 'scalar') -ne 1) {
        & $Log 'WARN' 'summary     : the database does not have the Summary report tables yet -- the updater adds them with the data schema; the Risk Analysis Summary rows stay empty until then.'
        return [pscustomobject]$result
    }
    $result.Ready = $true
    $lookback = [int]$Settings.LookbackDays; if ($lookback -lt 1) { $lookback = 3 }
    $readOrSkip = {
        param([string]$kql, [string]$table)
        try { , @(& $Query $kql) }
        catch {
            if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName $table) { & $Log 'WARN' ("summary     : {0} does not exist in this workspace yet -- skipped." -f $table); return $null }
            throw
        }
    }
    # #639 BACKFILL: what SQL holds is read over the whole retention window. A database that holds NO complete Summary
    # collection (a new install -- or one where no Summary collection was ever loaded, as at the large install until this
    # fix) lists every Summary collection Log Analytics still has inside the retention window, not only the look-back --
    # each one is loaded once, as usual (only a complete run's collection; the run health is read as far back).
    $retDays = [int]$Settings.RetentionDays; if ($retDays -lt $lookback) { $retDays = $lookback }
    $loadedRaw = & $Invoke (Get-SIDataSummaryLoadedSql) @{ Since = (Format-SIDataSqlTime -Time $Now.AddDays(-($retDays + 1))) } 'reader'
    $loaded = @(@($loadedRaw) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ CollectionId = $null; CollectionTime = $_['CollectionTime']; Status = $_['Status']; Source = $(if ($_ -is [System.Collections.IDictionary] -and $_.Contains('Source') -and $_['Source'] -isnot [System.DBNull]) { [string]$_['Source'] } else { '' })
        Retired = ($_ -is [System.Collections.IDictionary] -and $_.Contains('Retired') -and $_['Retired'] -isnot [System.DBNull] -and [int]$_['Retired'] -eq 1) } })
    $listDays = $lookback
    if ($retDays -gt $lookback -and @($loaded | Where-Object { [string]$_.Status -eq 'Complete' }).Count -eq 0) {
        $listDays = $retDays
        & $Log 'INFO' ("summary     : no Summary collection is in the database yet -- every complete Summary collection of the last {0} day(s) is loaded (once)" -f $listDays)
    }
    $result.ListDays = $listDays
    $collections = & $readOrSkip (Get-SIDataSummaryCollectionsKql -EditionMajor $EditionMajor -LookbackDays $listDays -TableName $TableName) $TableName
    if ($null -eq $collections) { $collections = @() }
    $runs = & $readOrSkip (Get-SIDataRunHealthKql -LookbackDays ($listDays + 1)) 'SI_RunHealth_CL'
    if ($null -eq $runs) { $runs = @() }
    # #639 (large install 2026-10-13: "4 ... Summary collection(s); 0 to load, 0 already loaded, 0 not complete" and an EMPTY
    # sidata.SummaryLoad): Get-SIDataLoadPlan answers its plan as ONE list (', $plan.ToArray()'). Wrapped in @(...) it became a
    # list holding that list as its ONE item -- no item had an Action, so every collection fell through every filter and no
    # Summary collection was ever loaded. ASSIGNED first, then enumerated (as the Detailed load does).
    $planRaw = Get-SIDataLoadPlan -Collections @($collections) -Loaded $loaded -Runs @($runs) -Now $Now -LookbackDays $listDays
    $plan = @(foreach ($p in @($planRaw)) { if ($null -ne $p) { $p } })
    $result.Plan = $plan
    $result.Held = @($plan | Where-Object { $_ -and [string]$_.Action -in @('Hold', 'Refuse') })
    $todo = @($plan | Where-Object { $_ -and [string]$_.Action -in @('Load', 'Reload') })
    $nSkip = @($plan | Where-Object { $_ -and [string]$_.Action -eq 'Skip' }).Count
    & $Log 'INFO' ("summary     : {0} Risk Analysis Summary collection(s) in the last {1} day(s); {2} to load, {3} already loaded, {4} not complete (not loaded)" -f @($collections).Count, $listDays, $todo.Count,
        $nSkip, $result.Held.Count)
    # every collection listed is accounted for -- loaded, already loaded or not complete. One that is none of them was dropped
    # without a word: that is a FAILED run (its rows are not in the database), never a quiet "0 to load"
    $nListed = @(@($collections) | Where-Object { $null -ne $_ }).Count
    $nPlanned = $todo.Count + $nSkip + $result.Held.Count
    if ($nPlanned -ne $nListed) {
        $result.Problem = ("{0} Summary collection(s) are in Log Analytics but only {1} were planned (to load {2}, already loaded {3}, not complete {4}) -- the others are NOT in the database" -f $nListed, $nPlanned, $todo.Count, $nSkip, $result.Held.Count)
        & $Log 'WARN' ('summary     : ' + $result.Problem)
    }
    if ($DryRun) {
        if ($todo.Count) { & $Log 'INFO' ("summary     : dry run -- {0} collection(s) would be loaded; nothing is written." -f $todo.Count) }
        return [pscustomobject]$result
    }
    $chunk = [long]0
    foreach ($item in $todo) {
        try {
            $one = Invoke-SIDataSummaryLoad -Item $item -Query $Query -Invoke $Invoke -EditionMajor $EditionMajor -LookbackDays $listDays -ChunkChars ([ref]$chunk) -TableName $TableName
            $result.Loaded += $one
            & $Log 'OK' ("summary     : the Summary collection of {0:yyyy-MM-dd HH:mm} UTC loaded -- {1} row(s), {2} impacted asset(s)" -f $one.CollectionTime, $one.Rows, $one.Assets)
        } catch {
            $result.Failed += [pscustomobject]@{ CollectionTime = $item.CollectionTime; Reason = $_.Exception.Message }
            & $Log 'WARN' ("summary     : {0}" -f $_.Exception.Message)
        }
    }
    # retention: sidata.Summary* only, children first, in batches
    $cutoff = Get-SIDataRetentionCutoff -RetentionDays ([int]$Settings.RetentionDays) -Now $Now
    $pp = @{ Cutoff = (Format-SIDataSqlTime -Time $cutoff); StaleLoading = (Format-SIDataSqlTime -Time $Now.ToUniversalTime().AddDays(-($lookback + 1))) }
    $batch = [long]5000
    foreach ($t in 'SummaryAsset', 'SummaryRow', 'SummaryLoad') {
        $result.Purged += Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataSummaryPurgeSql -Table $t) -Params $pp -BatchSize ([ref]$batch)
    }
    if ($result.Purged -gt 0) { & $Log 'OK' ("summary     : {0} Summary row(s) past retention removed" -f $result.Purged) }
    [pscustomobject]$result
}
