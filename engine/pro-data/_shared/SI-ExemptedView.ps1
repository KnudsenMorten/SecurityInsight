#Requires -Version 5.1
<#
    SecurityInsight Pro -- EXEMPTED FINDINGS AT READ TIME, for the PowerShell reports and mails (#264).

    An exemption never removes a finding: Risk Analysis marks the row (SI_ExemptionId ...) and the data sync copies the mark
    onto sidata.Finding (ExemptionId, ExemptedUntil, ExemptionRequestId). Whether a report SHOWS and COUNTS exempted
    findings is decided here, at read time, by ONE predicate -- the same one the web app uses
    (SI.Management.Core.ProData.Exempted):

        counted   = <alias>.ExemptionId IS NULL          exempted = <alias>.ExemptionId IS NOT NULL

    and, for the pre-computed aggregates, by reading the "...Counted" twin the data sync fills beside each table. A
    collection whose twins are not computed yet (Collection.ExemptedDerivedAt IS NULL -- loaded before #264, when Risk
    Analysis still dropped exempted rows, so its base table holds no exempted finding) is read from the base table.

    Settings (default OFF = exempted findings are not counted):
      SI_Exempted_CountInManagement     the management numbers -- Risk Analysis's workbook, summary and mail
      SI_Exempted_InDepartmentReports   the business owners' monthly report, the technical owners' digest and review
    PS 5.1 safe. Pure text builders; no database access here.
#>

# The pre-computed aggregates that have a counted twin, with their columns (the twin has the same columns, same order).
$script:SIExemptedTwins = @{
    FindingDaily    = '[Day], CollectionId, Tier, Severity, SecurityDomain, ReportName, Findings, Assets, ScoreTotal, ScoreMax'
    AssetDaily      = '[Day], CollectionId, GroupingId, Tier, Severity, SecurityDomain, ReportName, Assets'   # #295
    FindingFacet    = 'CollectionId, Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore'
    DepartmentFacet = 'CollectionId, DepartmentId, Severity, Tier, Findings, Assets, ScoreTotal, WeightedTotal'
    ServiceRisk     = 'CollectionId, ServiceKey, ServiceName, Assets, SharedAssets, Findings, WeightedTotal, WeightedPerAsset, RiskTotal, MaxWeighted, Critical, High, Medium, Low, Tier0, Tier1, Tier2, Tier3, TierUnclassified, TopAssetKey, TopAssetName, TopAssetWeighted, Sources'
    ServiceAsset    = 'CollectionId, ServiceKey, AssetKey, ServiceName, Source, AssetName, Tier, ServiceCount, Findings, Critical, High, Medium, Low, WeightedTotal, RiskTotal, MaxWeighted'
}

function ConvertTo-SIExemptedBool {
    <# PURE. A setting value as a bool ($true / 'true' / 1 / 'yes' / 'on'); anything else -- including not set -- is $false. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    @('true', '1', 'yes', 'on') -contains ([string]$Value).Trim().ToLowerInvariant()
}

function Get-SIExemptedSettings {
    <# PURE. @{ CountInManagement; InDepartmentReports } from the globals -- both OFF by default (exempted not counted). #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    [pscustomobject]@{
        CountInManagement   = [bool](ConvertTo-SIExemptedBool (& $g 'SI_Exempted_CountInManagement'))
        InDepartmentReports = [bool](ConvertTo-SIExemptedBool (& $g 'SI_Exempted_InDepartmentReports'))
    }
}

function Get-SIExemptedPredicate {
    <# PURE. THE predicate: a finding row (alias -Alias) that is counted -- it carries no exemption mark. -Exempted = the complement. #>
    param([string]$Alias = 'f', [switch]$Exempted)
    if ($Alias -notmatch '^[A-Za-z][A-Za-z0-9_]{0,15}$') { throw "not an alias: $Alias" }
    if ($Exempted) { return "$Alias.ExemptionId IS NOT NULL" }
    "$Alias.ExemptionId IS NULL"
}

function Get-SIExemptedAnd {
    <# PURE. ' AND <predicate>' to append to a WHERE over finding rows, or '' when exempted findings are included. #>
    param([string]$Alias = 'f', [switch]$Include)
    if ($Include) { return '' }
    ' AND ' + (Get-SIExemptedPredicate -Alias $Alias)
}

function Get-SIActiveCiAnd {
    <#
        PURE. #855 (owner 2026-10-21: "default filter is active, so it should be active only"): ' AND <predicate>' to append to a
        WHERE over finding rows (alias -Alias) so only the findings of ACTIVE CIs count -- sidata.Finding.CiLifecycle, stamped by
        the data sync from the CI's lifecycle; NULL (no CI, or a collection stored before the stamp) counts as active. The
        department report and the governance mails count what the web app's views count by default.
    #>
    param([string]$Alias = 'f')
    if ($Alias -notmatch '^[A-Za-z][A-Za-z0-9_]{0,15}$') { throw "not an alias: $Alias" }
    " AND ($Alias.CiLifecycle IS NULL OR $Alias.CiLifecycle = N'active')"
}

function Get-SIExemptedSource {
    <#
        PURE. The FROM source of a pre-computed aggregate, aliased: the base table when exempted findings are included,
        else its counted twin -- falling back, per collection, to the base table for a collection whose twin is not
        computed yet (ExemptedDerivedAt IS NULL).
    #>
    param([Parameter(Mandatory)][ValidateSet('FindingDaily', 'AssetDaily', 'FindingFacet', 'DepartmentFacet', 'ServiceRisk', 'ServiceAsset')][string]$Table,
          [Parameter(Mandatory)][string]$Alias, [switch]$Include)
    if ($Alias -notmatch '^[A-Za-z][A-Za-z0-9_]{0,15}$') { throw "not an alias: $Alias" }
    if ($Include) { return "sidata.$Table AS $Alias" }
    $cols = ($script:SIExemptedTwins[$Table] -split ',\s*' | ForEach-Object { 'x.' + $_.Trim() }) -join ', '
    "(SELECT $cols FROM sidata.${Table}Counted AS x JOIN sidata.Collection AS xc ON xc.CollectionId = x.CollectionId WHERE xc.ExemptedDerivedAt IS NOT NULL " +
    "UNION ALL SELECT $cols FROM sidata.$Table AS x JOIN sidata.Collection AS xc ON xc.CollectionId = x.CollectionId WHERE xc.ExemptedDerivedAt IS NULL) AS $Alias"
}

function Get-SIExemptedProbeSql {
    <# 1 when the database carries the mark and the counted twins (the reports apply the settings), else 0 (they count as before). #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ExemptedDerivedAt') IS NOT NULL AND OBJECT_ID('sidata.DepartmentFacetCounted') IS NOT NULL AND OBJECT_ID('sidata.vExemptedFinding') IS NOT NULL THEN 1 ELSE 0 END AS HasExemptionMark"
}

function Get-SIExemptedDepartmentCountSql {
    <# The exempted findings of one department in one collection -- the "N exempted not counted" line of a mail. #>
    "SELECT COUNT_BIG(*) AS N FROM sidata.vExemptedFinding AS v WHERE v.CollectionId = TRY_CONVERT(int, @CollectionId) AND v.DepartmentId = @DepartmentId;"
}

function Get-SIExemptedNoteText {
    <# PURE. The note a surface that EXCLUDES shows: "12 exempted findings are not counted." ('' for none). #>
    param([long]$Count)
    if ($Count -le 0) { return '' }
    if ($Count -eq 1) { return '1 exempted finding is not counted.' }
    ('{0} exempted findings are not counted.' -f $Count.ToString('N0', [Globalization.CultureInfo]::InvariantCulture))
}
