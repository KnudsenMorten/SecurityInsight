#Requires -Version 5.1
<#
    SecurityInsight Pro -- DATA-QUALITY WARNINGS from a three-run fingerprint (REQUIREMENTS #577 step 2, owner 2026-10-11:
    "it can base it on last 3 runs and compare key numbers" / "like anomaly detection" -- "more of a warning, not a blocker").

    WHERE IT IS COMPUTED -- ONE point, at the end of the data sync (engine\pro-data\Invoke-SIDataSync.ps1). The data sync is
    the last Deliver step that runs after everything that produces the numbers (the profilers, the CI build in the asset
    correlation job, both Risk Analysis runs) and it already holds both seams: Log Analytics (-Query) and the Pro database
    (-Invoke). So the fingerprint READS WHAT WAS PRODUCED, once per pipeline run, instead of every engine measuring itself:
      * assets per source           Log Analytics: the distinct assets of each profile table's newest collection
                                    (SI_Endpoint / SI_Identity / SI_Azure / SI_PublicIP _Profile_CL)
      * rows per Risk Analysis report  Log Analytics: the newest Summary and Detailed collection, rows per report (the same
                                    report name the data sync stores); the row-count guard's threshold reports
                                    (Get-RAThresholdReportNames) and report hand-offs (Get-RAReportSuccessorMap) are REUSED:
                                    a threshold report at 0 is a resolved finding, a report whose findings moved to a new
                                    receiving report is a different population -- neither is an anomaly
      * fill % of the key columns   Log Analytics, the newest Detailed collection: RiskFactor_Probability_Detailed,
                                    RiskFactor_Consequence_Detailed, the tier (CriticalityTier) and the SQL tag / component
                                    (si_component) -- "filled" is the column-fill guard's own definition (Get-RAColumnFillSnapshot:
                                    not empty, not blank); the Pro database: asset type and owner of the active CIs
      * assets per tier, CIs        the Pro database (sidata.Ci): active CIs per tier 0-3, active CIs, CIs not seen any more
                                    (they retire after their grace period), the CI owner fill %
      * assets per class            the Pro database (sidata.Ci): active CIs per asset type
      * fill % per source field     the Pro database (sidata.CiRecord, the current provider records): for every field of
                                    the field catalog (data-model\field-catalog.locked.json) that a source's mapping
                                    (data-model\mappings\<source>.locked.json) fills, how many of that source's records
                                    carry a value -- driven by the catalog and the mappings, never a hand-written list, so
                                    a field added to a source is watched from the next run on. A source that stops filling
                                    a field is a fill drop like any other.
    One row per pipeline run in sidata.DataQualityRun (+ its numbers in sidata.DataQualityMetric and its anomalies in
    sidata.DataQualityAnomaly). A run whose Risk Analysis Detailed collection was fingerprinted already (a data sync re-run
    that loaded nothing new) adds nothing.

    THE RULES -- each number against the MEDIAN OF THE LAST 3 RUNS (fewer than 3 earlier runs = learning, no warning):
      assets (per source, active CIs)   down 30 % or more          SI_Pro_DataQuality_AssetDropPercent
      a Risk Analysis report            at 0 rows, or down 50 % or more   SI_Pro_DataQuality_ReportDropPercent
      a key column's fill               down 30 points or more     SI_Pro_DataQuality_FillDropPoints
      a tier                            moved by 20 % or more of all active CIs (up or down)   SI_Pro_DataQuality_TierShiftPercent
      CIs not seen any more             up by 20 % or more of all active CIs (the same setting)
      an asset class (asset type)       moved by 20 % or more of all active CIs (the same setting)
    The likely cause: the settings changed since the last run without a warning -- the previous run, unless it warned too
    (cfg.ChangeLog: who, which setting, when), the ones that concern the number first. The changes are stored with the run
    (sidata.DataQualityChange) and the ones that concern a number are linked to it (sidata.DataQualityCause), so the panel
    links each one to the audit trail.

    ONE WARNING PER SOURCE (owner 2026-10-11: "One warning per source"): the fields of ONE source that are filled less in
    ONE run are one warning -- "<source> stopped filling N fields", the fields listed inside, each with its 3 earlier values
    and now (Join-SIDataQualitySourceAnomalies; stored in sidata.DataQualityAnomalyField). A source with a single dropped
    field stays that field's own warning. Every field stays a key number of the run, measured and stored as before.

    WHAT IT DOES WITH AN ANOMALY -- never blocks, never a guard event, never a mail per check:
      * the Data quality panel of the web app (Operations > Data quality) lists the latest run's anomalies;
      * the run health END record of the data sync carries one line per warning (Get-SIDataQualityRunHealthLines);
      * a mail ONLY WHEN THE SET OF WARNINGS CHANGES (owner 2026-10-11: "Only when it changes"): the warnings of this run
        are compared with the warnings of the last run that was MAILED (Compare-SIDataQualityMailSet). A warning that is
        new, or one that is gone, sends the mail; the same warnings day after day send nothing. When every number is back
        within its range after a mailed warning, one "back to normal" mail says so. At most one mail a day. Shaped like a
        cloud cost-anomaly alert (ConvertTo-SIDataQualityMail), through the one transport (Send-SIMail: the MAIL-2 layout
        and the PDF) to SI_Pro_DataQuality_Mail_To, else the guard mail's recipients (SI_GuardMail_To, MailTo, the Pro
        SuperAdmins). SI_Pro_DataQuality_Mail_Enabled turns it off. Each run keeps whether its mail went out and, if not,
        why (sidata.DataQualityRun.MailState: sent | failed | unchanged | day-limit | off | no-recipients).

    Writes only SecurityInsight's own database. No PowerShell modules; PS 5.1 syntax (the containers run pwsh 7).
#>

# the MAIL-2 layout (the mail), the row-count guard (its threshold reports and report hand-offs) -- loaded, not copied
$__siDqEngine = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:SIDataQualityEngineRoot = $__siDqEngine
if (-not (Get-Command -Name New-SIMailLayout -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($__siDqEngine, '_shared', 'SI-MailLayout.ps1')) }
# #636: the Risk Analysis Summary step is optional and off by default -- no Summary numbers and no Summary warnings while it is off
if (-not (Get-Command -Name Get-SISummaryStepState -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath ([System.IO.Path]::Combine($__siDqEngine, '_shared', 'SI-SummaryStep.ps1')))) { . ([System.IO.Path]::Combine($__siDqEngine, '_shared', 'SI-SummaryStep.ps1')) }
if (-not (Get-Command -Name Get-RAThresholdReportNames -ErrorAction SilentlyContinue)) {
    $__siDqRc = [System.IO.Path]::Combine($__siDqEngine, 'risk-analysis', '_shared', 'RA-RowCountGuard.ps1')
    if (Test-Path -LiteralPath $__siDqRc) { . $__siDqRc }
}

$script:SIDataQuality = @{
    Runs        = 3
    PanelPath   = '/Admin/DataQuality'
    JobsPath    = '/Admin/Jobs'
    Sources     = [ordered]@{
        endpoint = @{ Table = 'SI_Endpoint_Profile_CL'; Label = 'Assets from Defender for Endpoint (endpoint profiler)' }
        identity = @{ Table = 'SI_Identity_Profile_CL'; Label = 'Assets from Entra ID (identity profiler)' }
        azure    = @{ Table = 'SI_Azure_Profile_CL'; Label = 'Assets from Azure (azure profiler)' }
        publicip = @{ Table = 'SI_PublicIP_Profile_CL'; Label = 'Public IP addresses (public IP profiler)' }
    }
    RaTables    = [ordered]@{
        summary  = @{ Table = 'SI_RiskAnalysis_Summary_CL'; Step = 'risk-analysis'; Label = 'Summary' }
        detailed = @{ Table = 'SI_RiskAnalysis_Detailed_CL'; Step = 'risk-analysis-detailed'; Label = 'Detailed' }
    }
    # the key columns of the Detailed rows (column -> label); "filled" = not empty and not blank (Get-RAColumnFillSnapshot)
    RaFill      = [ordered]@{
        RiskFactor_Probability_Detailed = 'Fill: probability risk factors (RiskFactor_Probability_Detailed)'
        RiskFactor_Consequence_Detailed = 'Fill: consequence risk factors (RiskFactor_Consequence_Detailed)'
        CriticalityTier                 = 'Fill: tier (CriticalityTier)'
        si_component                    = 'Fill: SQL tag / component (si_component)'
    }
    # what a change log row must mention to concern a kind of number (Name, Scope, Kind of the cfg.ChangeLog row)
    Hints       = @{
        'assets.endpoint' = 'endpoint|defender|mde|device|disabled|exclu|scope'
        'assets.identity' = 'identity|entra|user|account|disabled|exclu|scope'
        'assets.azure'    = 'azure|subscription|arm|resource|exclu|scope'
        'assets.publicip' = 'publicip|public|shodan|exclu|scope'
        'rows'            = 'risk|report|template|exclu|weight|factor|bucket|exempt|query|kql'
        'fill'            = 'factor|tier|component|classification|mapping|risk|rule|owner|cmdb|asset_?type|template'
        'tier'            = 'tier|rule|criticality|classification|override|profil'
        'ci'              = 'ci|cmdb|correlat|retire|lifecycle|owner|stale|seen|disabled|override'
        'class'           = 'asset_?type|classification|class|mapping|rule|template|override'
    }
    # a source (the provider of a mapping file): its name for a person, and the pipeline step that collects it
    Providers   = @{
        mde        = @{ Label = 'Defender for Endpoint'; Step = 'endpoint' }
        intune     = @{ Label = 'Intune'; Step = 'endpoint' }
        entra      = @{ Label = 'Entra ID'; Step = 'identity' }
        ad         = @{ Label = 'Active Directory'; Step = 'identity' }
        mdi        = @{ Label = 'Defender for Identity'; Step = 'identity' }
        azure      = @{ Label = 'Azure'; Step = 'azure' }
        mdc        = @{ Label = 'Defender for Cloud'; Step = 'azure' }
        shodan     = @{ Label = 'Shodan'; Step = 'publicip' }
        # read by several steps, or by a connector that also WRITES: no single step to re-run from (the panel says so)
        eg         = @{ Label = 'the exposure graph'; Step = '' }
        cmdb       = @{ Label = 'the CMDB'; Step = '' }
        servicenow = @{ Label = 'ServiceNow'; Step = '' }
    }
    MailFooter  = 'A data-quality mail goes out only when the key numbers outside their expected range change -- a new one, or one that is back within its range -- and at most once a day. The limits: Settings > Guards (safety checks) > Data-quality warnings.'
    Invariant   = [System.Globalization.CultureInfo]::InvariantCulture
}

# =====================================================================================================================
#  Settings -- PURE
# =====================================================================================================================
function Get-SIDataQualitySettings {
    <#
        PURE. The thresholds and the mail switch, from -Globals (a hashtable; else the live globals). A value that is not a
        number from 1 to 100 falls back to its default (said in .Problems).
        Returns @{ AssetDropPercent; ReportDropPercent; FillDropPoints; TierShiftPercent; MailEnabled; MailTo; WebBaseUrl; Problems }.
    #>
    param([System.Collections.IDictionary]$Globals)
    $get = {
        param([string]$n)
        if ($Globals) { if ($Globals.Contains($n)) { return $Globals[$n] }; return $null }
        Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    }
    $problems = New-Object System.Collections.Generic.List[string]
    $num = {
        param([string]$n, [double]$default)
        $v = & $get $n
        if ($null -eq $v -or "$v".Trim() -eq '') { return $default }
        $d = 0.0
        if ([double]::TryParse("$v".Trim(), [System.Globalization.NumberStyles]::Float, $script:SIDataQuality.Invariant, [ref]$d) -and $d -ge 1 -and $d -le 100) { return $d }
        $problems.Add(("{0} = '{1}' is not a number from 1 to 100 -- {2} is used" -f $n, $v, $default))
        $default
    }
    $mailRaw = & $get 'SI_Pro_DataQuality_Mail_Enabled'
    $mailOn = $true
    if ($null -ne $mailRaw -and "$mailRaw".Trim() -ne '') { $mailOn = -not ("$mailRaw".Trim().ToLowerInvariant() -in @('false', '0', 'off', 'no', 'disabled', '$false')) }
    [pscustomobject]@{
        AssetDropPercent  = (& $num 'SI_Pro_DataQuality_AssetDropPercent' 30)
        ReportDropPercent = (& $num 'SI_Pro_DataQuality_ReportDropPercent' 50)
        FillDropPoints    = (& $num 'SI_Pro_DataQuality_FillDropPoints' 30)
        TierShiftPercent  = (& $num 'SI_Pro_DataQuality_TierShiftPercent' 20)
        MailEnabled       = $mailOn
        MailTo            = (& $get 'SI_Pro_DataQuality_Mail_To')
        WebBaseUrl        = "$(& $get 'SIWeb_PublicBaseUrl')".Trim().TrimEnd('/')
        Problems          = @($problems)
    }
}

# =====================================================================================================================
#  Measuring -- the statements (PURE) and the fingerprint (over the two seams)
# =====================================================================================================================
function Get-SIDataQualitySourceKql {
    <# PURE. The distinct assets of each profile table's NEWEST collection, one row per source (Source, Assets, Last). #>
    param([int]$LookbackDays = 3)
    $parts = foreach ($k in $script:SIDataQuality.Sources.Keys) {
        "($($script:SIDataQuality.Sources[$k].Table) | where TimeGenerated > ago($($LookbackDays)d) | extend Source = '$k')"
    }
@"
let P = union isfuzzy=true
 $($parts -join ",`n ")
| extend Aid = coalesce(tostring(column_ifexists("SI_AssetId", "")), tostring(column_ifexists("SI_AssetName", "")), tostring(column_ifexists("AssetName", "")));
P
| summarize Last = max(CollectionTime) by Source
| join kind=inner (P) on Source
| where CollectionTime == Last and isnotempty(Aid)
| summarize Assets = dcount(Aid, 4) by Source, Last
"@
}

function Get-SIDataQualityReportKql {
    <#
        PURE. The NEWEST collection of one Risk Analysis table: rows per report, and (-FillColumns) the filled rows of each
        key column per report -- filled = not empty and not blank, as the column-fill guard counts it.
    #>
    param([Parameter(Mandatory)][string]$Table, [string[]]$FillColumns = @(), [int]$LookbackDays = 3)
    $fills = @($FillColumns | ForEach-Object { ', F_{0} = countif(isnotempty(trim(@"\s", tostring(column_ifexists("{0}", "")))))' -f $_ }) -join ''
@"
let T = $Table | where TimeGenerated > ago($($LookbackDays)d);
let Last = toscalar(T | summarize max(CollectionTime));
T
| where CollectionTime == Last
| extend Report = coalesce(tostring(column_ifexists("AssetDetectedInReportName", "")), tostring(column_ifexists("ReportName", "")))
| summarize Rows = count()$fills by Report, CollectionTime
"@
}

function Get-SIDataQualityReportSql {
    <#
        PURE. #830 (owner 2026-10-20: Pro reads Risk Analysis Detailed from the database only) -- the SAME numbers as
        Get-SIDataQualityReportKql over SI_RiskAnalysis_Detailed_CL, from the Detailed result in the Pro database: the NEWEST
        Detailed collection of the last -LookbackDays whose Risk Analysis result is complete (Status 'Complete', or completed by
        Risk Analysis and waiting for the data sync -- the rows the Log Analytics copy was sent from), not removed by the
        retention; per report (sidata.Finding.ReportName -- the report, else the row's AssetDetectedInReportName, as the load
        stores it) its rows and, per -FillColumns, the rows whose column is filled: not empty and not blank, read from the row
        as Risk Analysis wrote it (DetailJson -- the very row the copy carries; a list or an object counts as filled, as its
        text does in Log Analytics). Rows the data sync CARRIED in from an earlier collection (CarriedFrom) were never in Log
        Analytics and are left out. Answers Report, CollectionTime (ISO text), Rows, F_<column>; no collection = no row.
    #>
    param([string[]]$FillColumns = @(), [int]$LookbackDays = 3, [switch]$ForceJson)
    $fillCols = @($FillColumns | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]{0,120}$' })
    $fills = foreach ($c in $fillCols) {
        (",`n       " + ('SUM(CASE WHEN LEN(TRIM(CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) FROM COALESCE(JSON_VALUE(j.d, N''$.{0}''), JSON_QUERY(j.d, N''$.{0}''), N''''))) > 0 THEN 1 ELSE 0 END) AS [F_{0}]' -f $c))
    }
    # #830 / #834 a collection whose rows carry the typed row columns (sidata.Collection.RaRowsAt) is counted from them --
    # the same rule over the same values, never one finding's JSON; a fill column no typed column holds = DetailJson
    $typedFill = @{
        CriticalityTier                 = 'CASE WHEN LEN(TRIM(CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) FROM COALESCE(f.RaRowCriticalityTier, N''''))) > 0 THEN 1 ELSE 0 END'
        si_component                    = 'CASE WHEN LEN(TRIM(CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) FROM COALESCE(f.RaRowSiComponent, N''''))) > 0 THEN 1 ELSE 0 END'
        RiskFactor_Probability_Detailed = 'CASE WHEN f.RaFillRiskFactorProbability = 1 THEN 1 ELSE 0 END'
        RiskFactor_Consequence_Detailed = 'CASE WHEN f.RaFillRiskFactorConsequence = 1 THEN 1 ELSE 0 END'
    }
    $canType = -not $ForceJson -and -not @($fillCols | Where-Object { -not $typedFill.ContainsKey($_) }).Count
    $tFills = foreach ($c in $fillCols) { if ($typedFill.ContainsKey($c)) { ",`n       SUM({0}) AS [F_{1}]" -f $typedFill[$c], $c } }
    $typedTest = if ($canType) { "COL_LENGTH('sidata.Collection', 'RaRowsAt') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RaFillRiskFactorConsequence') IS NOT NULL" } else { '1 = 0' }
    $days = [Math]::Max(1, $LookbackDays)
@"
SET NOCOUNT ON;
DECLARE @live nvarchar(400) =
      CASE WHEN COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL THEN N' AND c.RetiredAt IS NULL' ELSE N'' END
    + CASE WHEN COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NOT NULL THEN N' AND (c.Status = N''Complete'' OR c.RaCompletedAt IS NOT NULL)' ELSE N' AND c.Status = N''Complete''' END;
DECLARE @carried nvarchar(100) = CASE WHEN COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NOT NULL THEN N' AND f.CarriedFrom IS NULL' ELSE N'' END;
DECLARE @c int = NULL, @t datetime2(3) = NULL;
DECLARE @pick nvarchar(max) = N'SELECT TOP (1) @c = c.CollectionId, @t = c.CollectionTime FROM sidata.Collection AS c WHERE c.Kind = N''Detailed'' AND c.CollectionTime >= DATEADD(day, -$days, SYSUTCDATETIME())' + @live + N' ORDER BY c.CollectionTime DESC;';
EXEC sp_executesql @pick, N'@c int OUTPUT, @t datetime2(3) OUTPUT', @c = @c OUTPUT, @t = @t OUTPUT;
IF @c IS NULL RETURN;
DECLARE @typed bit = 0;
IF $typedTest
    EXEC sp_executesql N'SELECT @y = CASE WHEN RaRowsAt IS NOT NULL THEN 1 ELSE 0 END FROM sidata.Collection WHERE CollectionId = @c;', N'@c int, @y bit OUTPUT', @c = @c, @y = @typed OUTPUT;
IF @typed = 1
BEGIN
    DECLARE @tq nvarchar(max) = N'SELECT ISNULL(f.ReportName, N'''') AS Report, CONVERT(nvarchar(30), @t, 126) AS CollectionTime, COUNT_BIG(*) AS [Rows]$($tFills -join '' -replace "'", "''")
FROM sidata.Finding AS f
WHERE f.CollectionId = @c AND f.CarriedFrom IS NULL
GROUP BY f.ReportName;';
    EXEC sp_executesql @tq, N'@c int, @t datetime2(3)', @c = @c, @t = @t;
    RETURN;
END
DECLARE @q nvarchar(max) = N'SELECT ISNULL(f.ReportName, N'''') AS Report, CONVERT(nvarchar(30), @t, 126) AS CollectionTime, COUNT_BIG(*) AS [Rows]$($fills -join '' -replace "'", "''")
FROM sidata.Finding AS f CROSS APPLY (SELECT CASE WHEN ISJSON(f.DetailJson) = 1 THEN f.DetailJson END AS d) AS j
WHERE f.CollectionId = @c' + @carried + N'
GROUP BY f.ReportName;';
EXEC sp_executesql @q, N'@c int, @t datetime2(3)', @c = @c, @t = @t;
"@
}

function Get-SIDataQualityCiSql {
    <# PURE. The CI numbers from sidata.Ci: active, not seen any more, active per tier 0-3, asset type and owner filled. #>
@'
IF OBJECT_ID(N'sidata.Ci') IS NULL
    SELECT CAST(NULL AS int) AS Active WHERE 1 = 0;
ELSE
    SELECT COUNT_BIG(*) AS Total,
           SUM(CASE WHEN a.IsActive = 1 THEN 1 ELSE 0 END) AS Active,
           SUM(CASE WHEN c.Lifecycle = N'not_seen' THEN 1 ELSE 0 END) AS ToRetire,
           SUM(CASE WHEN a.IsActive = 1 AND c.Tier = 0 THEN 1 ELSE 0 END) AS Tier0,
           SUM(CASE WHEN a.IsActive = 1 AND c.Tier = 1 THEN 1 ELSE 0 END) AS Tier1,
           SUM(CASE WHEN a.IsActive = 1 AND c.Tier = 2 THEN 1 ELSE 0 END) AS Tier2,
           SUM(CASE WHEN a.IsActive = 1 AND c.Tier = 3 THEN 1 ELSE 0 END) AS Tier3,
           SUM(CASE WHEN a.IsActive = 1 AND NULLIF(LTRIM(RTRIM(c.AssetType)), N'') IS NOT NULL THEN 1 ELSE 0 END) AS AssetTypeFilled,
           SUM(CASE WHEN a.IsActive = 1 AND (NULLIF(LTRIM(RTRIM(o.SiOwner)), N'') IS NOT NULL OR NULLIF(LTRIM(RTRIM(o.CmdbOwner)), N'') IS NOT NULL) THEN 1 ELSE 0 END) AS OwnerFilled
    FROM sidata.Ci AS c
    CROSS APPLY (SELECT CASE WHEN ISNULL(c.Lifecycle, N'active') = N'active' THEN 1 ELSE 0 END AS IsActive) AS a
    CROSS APPLY (SELECT CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_VALUE(c.DocJson, '$.si_owner') END AS SiOwner,
                        CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_VALUE(c.DocJson, '$.si_cmdb_owner') END AS CmdbOwner) AS o;
'@
}

function Get-SIDataQualityClassSql {
    <# PURE. The active CIs per asset type (sidata.Ci). #>
@'
IF OBJECT_ID(N'sidata.Ci') IS NULL
    SELECT CAST(NULL AS nvarchar(64)) AS AssetType WHERE 1 = 0;
ELSE
    SELECT t.AssetType, COUNT_BIG(*) AS Assets
    FROM sidata.Ci AS k
    CROSS APPLY (SELECT ISNULL(NULLIF(LTRIM(RTRIM(k.AssetType)), N''), N'(no asset type)') AS AssetType) AS t
    WHERE ISNULL(k.Lifecycle, N'active') = N'active'
    GROUP BY t.AssetType;
'@
}

<#
    CLASSIFICATION INCOMPLETE (owner 2026-10-19, verbatim: "we can NOT have a finding without a risk rating. what could that
    be. i think i need to have this as an alert; same with unclassified assets or findings. goal is to put everything in tier
    0-3 and not have anything unclassified"). An ABSOLUTE rule, not a comparison with the last runs: any one of these above 0
    is a warning of the run -- from the first run on, never "learning" -- and it is gone on the first run where it is 0:
      classgap.finding.no_rating   findings of the newest complete (and derived) Detailed collection without a risk rating
      classgap.finding.no_tier     its findings without a tier 0-3
      classgap.finding.no_asset    its findings without an asset
      classgap.ci.no_tier          active CIs without a tier 0-3
    Each with its groups -- the report (findings) or the asset type (CIs) -- and the cause per group in words, kept as the
    warning's "fields" (sidata.DataQualityAnomalyField). WARN only, never a block, never a guard event (the owner's rule).
#>
$script:SIDataQualityClassGaps = [ordered]@{
    'finding.no_rating' = @{ Label = 'Classification incomplete: findings without a risk rating'; Step = 'risk-analysis-detailed'; Unit = 'finding(s)'
                             Cause = 'report {0} gave {1} finding(s) no risk rating -- the report emits none for them' }
    'finding.no_tier'   = @{ Label = 'Classification incomplete: findings without a tier 0-3'; Step = 'risk-analysis-detailed'; Unit = 'finding(s)'
                             Cause = 'report {0} gave {1} finding(s) no tier -- the asset (for an attack path: the target it reaches) has no CI with a tier' }
    'finding.no_asset'  = @{ Label = 'Classification incomplete: findings without an asset'; Step = 'risk-analysis-detailed'; Unit = 'finding(s)'
                             Cause = 'report {0} gave {1} finding(s) no asset -- the report names no asset for them' }
    'ci.no_tier'        = @{ Label = 'Classification incomplete: active CIs without a tier 0-3'; Step = 'asset-correlation'; Unit = 'CI(s)'
                             Cause = 'no tier rule matched {1} active CI(s) of type {0}' }
}

function Get-SIDataQualityClassificationSql {
    <#
        PURE. ONE read: the newest complete Detailed collection whose views' data is derived (its RiskRating column is filled
        by the derive -- a collection not derived yet is never read as "no risk rating"), its findings without a risk rating,
        a tier 0-3 or an asset per report (one pass over the collection), and the active CIs without a tier 0-3 per asset type.
        Rows (K, G, N): K = 'collection' (G = '', N = its id; no row = nothing to measure) or a gap key, G = the group.
    #>
@'
SET NOCOUNT ON;
DECLARE @c int = NULL;
IF OBJECT_ID(N'sidata.Collection') IS NOT NULL AND COL_LENGTH(N'sidata.Collection', N'DerivedAt') IS NOT NULL
    SELECT TOP (1) @c = CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' AND DerivedAt IS NOT NULL ORDER BY CollectionTime DESC;
DECLARE @o TABLE (K nvarchar(32) NOT NULL, G nvarchar(256) NOT NULL, N bigint NOT NULL);
IF @c IS NOT NULL AND COL_LENGTH(N'sidata.Finding', N'RiskRating') IS NOT NULL
BEGIN
    INSERT @o (K, G, N) VALUES (N'collection', N'', @c);
    INSERT @o (K, G, N)
    SELECT x.K, LEFT(ISNULL(NULLIF(LTRIM(RTRIM(f.ReportName)), N''), N'(no report name)'), 256), COUNT_BIG(*)
    FROM sidata.Finding AS f
    CROSS APPLY (VALUES (CASE WHEN NULLIF(LTRIM(RTRIM(f.RiskRating)), N'') IS NULL THEN N'finding.no_rating' END),
                        (CASE WHEN f.Tier IS NULL OR f.Tier < 0 OR f.Tier > 3 THEN N'finding.no_tier' END),
                        (CASE WHEN NULLIF(LTRIM(RTRIM(f.AssetKey)), N'') IS NULL THEN N'finding.no_asset' END)) AS x(K)
    WHERE f.CollectionId = @c AND x.K IS NOT NULL
    GROUP BY x.K, LEFT(ISNULL(NULLIF(LTRIM(RTRIM(f.ReportName)), N''), N'(no report name)'), 256);
END
IF OBJECT_ID(N'sidata.Ci') IS NOT NULL
BEGIN
    INSERT @o (K, G, N) VALUES (N'ci', N'', 1);
    INSERT @o (K, G, N)
    SELECT N'ci.no_tier', LEFT(ISNULL(NULLIF(LTRIM(RTRIM(k.AssetType)), N''), N'(no asset type)'), 256), COUNT_BIG(*)
    FROM sidata.Ci AS k
    WHERE ISNULL(k.Lifecycle, N'active') = N'active' AND (k.Tier IS NULL OR k.Tier < 0 OR k.Tier > 3)
    GROUP BY LEFT(ISNULL(NULLIF(LTRIM(RTRIM(k.AssetType)), N''), N'(no asset type)'), 256);
END
SELECT K, G, N FROM @o;
'@
}

function ConvertTo-SIDataQualityClassification {
    <#
        PURE. The read's rows -> @{ Metrics (a 'classgap' number per gap that could be measured: the findings' three when a
        derived collection was read, the CIs' when sidata.Ci exists -- 0 is a real 0 then); Groups (gap -> @( @{ Group; N } ),
        largest first); CollectionId }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $groups = [ordered]@{}; foreach ($k in $script:SIDataQualityClassGaps.Keys) { $groups[$k] = New-Object System.Collections.Generic.List[object] }
    $haveFindings = $false; $haveCi = $false; $cid = $null
    foreach ($r in @($Rows)) {
        $k = [string](Get-SIDataQualityValue $r 'K'); if (-not $k) { continue }
        $n = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r 'N'); if ($null -eq $n) { continue }
        if ($k -eq 'collection') { $haveFindings = $true; $cid = [long]$n; continue }
        if ($k -eq 'ci') { $haveCi = $true; continue }
        if (-not $groups.Contains($k)) { continue }
        $groups[$k].Add([pscustomobject]@{ Group = [string](Get-SIDataQualityValue $r 'G'); N = [double]$n })
    }
    $metrics = New-Object System.Collections.Generic.List[object]
    $outGroups = [ordered]@{}
    foreach ($k in $script:SIDataQualityClassGaps.Keys) {
        $measured = if ($k -like 'ci.*') { $haveCi } else { $haveFindings }
        if (-not $measured) { continue }
        $g = @($groups[$k] | Sort-Object @{ Expression = { [double]$_.N }; Descending = $true }, Group)
        $outGroups[$k] = $g
        $sum = 0.0; foreach ($x in $g) { $sum += [double]$x.N }
        $d = $script:SIDataQualityClassGaps[$k]
        $metrics.Add((New-SIDataQualityMetric -Key ('classgap.' + $k) -Kind 'classgap' -Label $d.Label -Value $sum -Step $d.Step))
    }
    [pscustomobject]@{ Metrics = $metrics.ToArray(); Groups = $outGroups; CollectionId = $cid }
}

function Find-SIDataQualityClassificationGaps {
    <#
        PURE. One warning per gap above 0 (rule 'classification-incomplete'), from the first run on: Now = how many, Expected
        = 0, its groups as .Fields (one per report / asset type, largest first, the cause in words as the label) and the
        cause = the largest groups in words ("and N more"). A gap at 0 is no warning -- the warning clears itself.
    #>
    param([AllowEmptyCollection()][object[]]$Metrics = @(), [System.Collections.IDictionary]$Groups)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in @($Metrics | Where-Object { $_ -and [string]$_.Kind -eq 'classgap' -and [double]$_.Value -gt 0 })) {
        $k = ([string]$m.Key).Substring('classgap.'.Length)
        $d = $script:SIDataQualityClassGaps[$k]; if (-not $d) { continue }
        $g = @(); if ($Groups -and $Groups.Contains($k)) { $g = @($Groups[$k]) }
        $fields = @(foreach ($x in $g) {
            $line = $d.Cause -f $x.Group, ([double]$x.N).ToString('N0', $script:SIDataQuality.Invariant)
            [pscustomobject]@{ Key = ('classgap.{0}.{1}' -f $k, $x.Group); Kind = 'classgap'; Label = $line; Earlier = @(); Expected = 0.0; Now = [double]$x.N; ChangePct = [double]$x.N }
        })
        $named = @($fields | Select-Object -First 3 | ForEach-Object { $_.Label })
        $more = $fields.Count - $named.Count
        $cause = if ($named.Count) { ((($named -join '; ') + $(if ($more -gt 0) { ('; and {0} more group(s)' -f $more) } else { '' })) + '.') } else { 'The groups could not be read.' }
        $cause = $cause.Substring(0, 1).ToUpperInvariant() + $cause.Substring(1)
        $out.Add([pscustomobject]@{
            Key = [string]$m.Key; Kind = 'classgap'; Label = [string]$m.Label; Step = [string]$m.Step; Rule = 'classification-incomplete'
            Direction = 'rise'; Earlier = @(); Expected = 0.0; Now = [double]$m.Value; ChangePct = [double]$m.Value; Cause = $cause; CauseChangeIds = @(); Fields = $fields
        })
    }
    @($out | Sort-Object @{ Expression = { [double]$_.Now }; Descending = $true }, Key)
}

function Get-SIDataQualityClassificationIssue {
    <#
        PURE. The run's one WARNING for the telemetry (Invardia raises a fix request from it): counts only -- no asset, no
        report, no name (Get-SIDataQualityClassificationGaps' warnings). '' when nothing is unclassified.
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @())
    $parts = @(foreach ($a in @($Anomalies | Where-Object { $_ -and [string]$_.Rule -eq 'classification-incomplete' })) {
        $k = ([string]$a.Key).Substring('classgap.'.Length)
        $what = switch ($k) { 'finding.no_rating' { 'findings without a risk rating' } 'finding.no_tier' { 'findings without a tier 0-3' } 'finding.no_asset' { 'findings without an asset' } 'ci.no_tier' { 'active CIs without a tier 0-3' } default { $k } }
        '{0} {1}' -f ([double]$a.Now).ToString('N0', $script:SIDataQuality.Invariant), $what
    })
    if (-not $parts.Count) { return '' }
    'classification incomplete: ' + ($parts -join ', ') + ' -- everything must be in tier 0-3 with a risk rating (Operations > Data quality names the reports and asset types and why)'
}

function Get-SIDataQualityFieldFillSql {
    <#
        PURE. The current provider records (sidata.CiRecord), counted ONCE: per source and record type how many records
        there are (Field = ''), and per field how many of them carry a value -- a value = present, not null, not blank, not
        an empty list or object (a false or a 0 IS a value). One pass over the record documents, at the end of the data sync.
    #>
@'
IF OBJECT_ID(N'sidata.CiRecord') IS NULL
    SELECT CAST(NULL AS nvarchar(32)) AS Provider WHERE 1 = 0;
ELSE
    SELECT r.Provider, ISNULL(r.RecordType, N'') AS RecordType, CAST(N'' AS nvarchar(128)) AS Field, COUNT_BIG(*) AS N
    FROM sidata.CiRecord AS r
    GROUP BY r.Provider, ISNULL(r.RecordType, N'')
    UNION ALL
    SELECT r.Provider, ISNULL(r.RecordType, N''), f.Field, COUNT_BIG(*)
    FROM sidata.CiRecord AS r
    CROSS APPLY OPENJSON(CASE WHEN ISJSON(r.DocJson) = 1 AND LEFT(LTRIM(r.DocJson), 1) = N'{' THEN r.DocJson END) AS j
    CROSS APPLY (SELECT CAST(LEFT(j.[key], 128) AS nvarchar(128)) AS Field) AS f
    WHERE j.[type] <> 0
      AND NOT (j.[type] = 1 AND LTRIM(RTRIM(j.[value])) = N'')
      AND NOT (j.[type] IN (4, 5) AND j.[value] IN (N'[]', N'{}'))
    GROUP BY r.Provider, ISNULL(r.RecordType, N''), f.Field;
'@
}

function Get-SIDataQualityFieldPlan {
    <#
        PURE (files in, objects out). WHICH source fills WHICH catalog field: every field of the field catalog that lives on
        the provider record (level record / both) and that a source's mapping fills, with the record types the mapping
        names (none = every record type of the source). -Root: the data-model folder (default: the run's, else the shipped
        one). A folder without the catalog or the mappings gives an empty plan -- never an error.
        Returns @( @{ Provider; Field; RecordTypes; AnyType } ).
    #>
    param([string]$Root)
    if (-not $Root) {
        if ($global:SI_DataModelRoot -and (Test-Path -LiteralPath ([string]$global:SI_DataModelRoot))) { $Root = [string]$global:SI_DataModelRoot }
        else { $Root = [System.IO.Path]::Combine((Split-Path -Parent $script:SIDataQualityEngineRoot), 'data-model') }
    }
    $out = New-Object System.Collections.Generic.List[object]
    $catFile = [System.IO.Path]::Combine($Root, 'field-catalog.locked.json')
    $mapDir = [System.IO.Path]::Combine($Root, 'mappings')
    if (-not (Test-Path -LiteralPath $catFile) -or -not (Test-Path -LiteralPath $mapDir)) { return $out.ToArray() }
    $onRecord = @{}
    $cat = [System.IO.File]::ReadAllText($catFile) | ConvertFrom-Json
    foreach ($f in @($cat.fields)) {
        if ($null -eq $f -or -not $f.name) { continue }
        if ([string]$f.level -in @('record', 'both')) { $onRecord[[string]$f.name] = $true }
    }
    $byKey = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $mapDir -Filter '*.locked.json' | Sort-Object Name)) {
        $doc = [System.IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
        $provider = [string]$doc.provider
        if (-not $provider) { continue }
        foreach ($m in @($doc.mappings)) {
            if ($null -eq $m) { continue }
            $field = [string]$m.field
            if (-not $field -or -not $onRecord.ContainsKey($field)) { continue }
            $key = $provider + '|' + $field
            if (-not $byKey.ContainsKey($key)) {
                $new = [pscustomobject]@{ Provider = $provider; Field = $field; RecordTypes = (New-Object System.Collections.Generic.List[string]); AnyType = $false }
                $byKey[$key] = $new; $out.Add($new)
            }
            $e = $byKey[$key]
            $types = @(@($m.recordTypes) | Where-Object { $_ })
            # a mapping item that names no record type fills the field on every record type of the source
            if (-not $types.Count) { $e.AnyType = $true }
            foreach ($t in $types) { if (-not $e.RecordTypes.Contains([string]$t)) { $e.RecordTypes.Add([string]$t) } }
        }
    }
    $out.ToArray()
}

function ConvertTo-SIDataQualityFieldFill {
    <#
        PURE. The fill metrics per source field from the plan (Get-SIDataQualityFieldPlan) and the counted rows
        (Get-SIDataQualityFieldFillSql): per source and field, the records that carry a value out of the source's records of
        the record types the mapping names. A source without such records is left out (nothing to measure); a field no
        record carries is 0 %.
    #>
    param([AllowEmptyCollection()][object[]]$Plan = @(), [AllowEmptyCollection()][object[]]$Rows = @())
    $total = @{}; $filled = @{}
    foreach ($r in @($Rows)) {
        $p = [string](Get-SIDataQualityValue $r 'Provider'); if (-not $p) { continue }
        $t = [string](Get-SIDataQualityValue $r 'RecordType')
        $f = [string](Get-SIDataQualityValue $r 'Field')
        $n = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r 'N'); if ($null -eq $n) { continue }
        if (-not $f) {
            if (-not $total.ContainsKey($p)) { $total[$p] = @{} }
            $total[$p][$t] = $n
        } else {
            $k = $p + '|' + $f
            if (-not $filled.ContainsKey($k)) { $filled[$k] = @{} }
            $filled[$k][$t] = $n
        }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Plan)) {
        $p = [string]$e.Provider
        if (-not $total.ContainsKey($p)) { continue }
        $types = if ($e.AnyType -or -not @($e.RecordTypes).Count) { @($total[$p].Keys) } else { @($e.RecordTypes | Where-Object { $total[$p].ContainsKey([string]$_) }) }
        $den = 0.0; $num = 0.0
        $have = $filled[$p + '|' + [string]$e.Field]
        foreach ($t in $types) {
            $den += [double]$total[$p][[string]$t]
            if ($have -and $have.ContainsKey([string]$t)) { $num += [double]$have[[string]$t] }
        }
        if ($den -le 0) { continue }
        $info = $script:SIDataQuality.Providers[$p]
        $label = if ($info) { $info.Label } else { $p }
        $step = if ($info) { $info.Step } else { '' }
        $out.Add((New-SIDataQualityMetric -Key ('fill.src.{0}.{1}' -f $p, $e.Field) -Kind 'fill' -Label ('Fill: {0} from {1}' -f $e.Field, $label) -Value ([math]::Min(100.0, 100.0 * $num / $den)) -Step $step))
    }
    $out.ToArray()
}

function Get-SIDataQualityValue {
    <# PURE. A column of a result row (hashtable, DataRow or object) -- $null when it is not there. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } else { return $null } }
    elseif ($Row -is [System.Data.DataRow]) { if ($Row.Table.Columns.Contains($Name)) { $v = $Row[$Name] } else { return $null } }
    else { $p = $Row.PSObject.Properties[$Name]; if (-not $p) { return $null }; $v = $p.Value }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Read-SIDataQualityRows {
    <#
        The rows of a 'reader' statement, one by one. The Pro database seam returns its rows as ONE array (`, $rows`), so
        a caller that wraps the call in @() or pipes it would see one item; this unrolls that one level.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    $out = & $Invoke $Sql $Params 'reader'
    foreach ($x in @($out)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IList] -and -not ($x -is [string])) { foreach ($y in $x) { if ($null -ne $y) { $y } } }
        else { $x }
    }
}

function ConvertTo-SIDataQualityNumber {
    <# PURE. A number from a result cell ($null when it is none). #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    $d = 0.0
    if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, $script:SIDataQuality.Invariant, [ref]$d)) { return $d }
    $null
}

function ConvertTo-SIDataQualityUtc {
    <# PURE. A moment as UTC: a local time is converted, a time without a zone (SQL datetime2) IS UTC. $null when none. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull] -or "$Value" -eq '') { return $null }
    try { $d = [datetime]$Value } catch { return $null }
    if ($d.Kind -eq [DateTimeKind]::Local) { return $d.ToUniversalTime() }
    if ($d.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($d, [DateTimeKind]::Utc) }
    $d
}

function New-SIDataQualityMetric {
    param([string]$Key, [string]$Kind, [string]$Label, [double]$Value, [string]$Step)
    [pscustomobject]@{ Key = $Key; Kind = $Kind; Label = $Label; Value = [math]::Round($Value, 2); Step = $Step }
}

function New-SIDataQualityFingerprint {
    <#
        The run's key numbers, read ONCE: Log Analytics through -Query ({ param($kql) rows }) and the Pro database through
        -Invoke (sql, params, mode). A source that cannot be read is left out (said in .Problems) -- the other numbers still
        count; a number left out is never compared. Returns @{ Metrics; CollectionTime (the Detailed collection); Problems }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Invoke, [int]$LookbackDays = 3, [string]$DataModelRoot)
    $metrics = New-Object System.Collections.Generic.List[object]
    $problems = New-Object System.Collections.Generic.List[string]
    # the key prefixes of a source that could not be read: never filled with zeros (a failed read is not "nothing produced")
    $unread = New-Object System.Collections.Generic.List[string]
    # the steps with no collection in the window -- not a failed read: nothing ran, so nothing is measured or compared
    $notRun = New-Object System.Collections.Generic.List[string]
    $collection = $null

    # assets per source
    try {
        foreach ($r in @(& $Query (Get-SIDataQualitySourceKql -LookbackDays $LookbackDays))) {
            $src = [string](Get-SIDataQualityValue $r 'Source')
            if (-not $src -or -not $script:SIDataQuality.Sources.Contains($src)) { continue }
            $n = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r 'Assets')
            if ($null -eq $n) { continue }
            $metrics.Add((New-SIDataQualityMetric -Key ('assets.' + $src) -Kind 'assets' -Label $script:SIDataQuality.Sources[$src].Label -Value $n -Step $src))
        }
    } catch { $problems.Add(('assets per source: ' + $_.Exception.Message)); $unread.Add('assets.') }

    # rows per Risk Analysis report, and the key columns' fill of the Detailed rows
    $sumStep = 'unknown'; try { $sumStep = Get-SISummaryStepState -Invoke $Invoke -StoredOnly } catch { $sumStep = 'unknown' }
    foreach ($grain in $script:SIDataQuality.RaTables.Keys) {
        if ($grain -eq 'summary' -and $sumStep -eq 'off') { continue }   # #636: a step that is off has no numbers to watch
        $t = $script:SIDataQuality.RaTables[$grain]
        $fillCols = @(); if ($grain -eq 'detailed') { $fillCols = @($script:SIDataQuality.RaFill.Keys) }
        try {
            # #830: the Detailed numbers from the Detailed result in the Pro database (never Log Analytics: the report-row copy
            # SI_RiskAnalysis_Detailed_CL is an optional output, off by default) -- the same numbers (Get-SIDataQualityReportSql)
            if ($grain -eq 'detailed') { $rows = @(Read-SIDataQualityRows $Invoke (Get-SIDataQualityReportSql -FillColumns $fillCols -LookbackDays $LookbackDays) @{}) }
            else { $rows = @(& $Query (Get-SIDataQualityReportKql -Table $t.Table -FillColumns $fillCols -LookbackDays $LookbackDays)) }
            # NO COLLECTION AT ALL in the look-back window = the step did not run (switched off at the install, or it did not
            # finish): nothing was measured, so nothing is compared -- never every report "0, expected N" (live 2026-10-23: a
            # Summary step that was off raised 41 "is 0" warnings against the runs from before it was switched off). One
            # report at 0 inside a collection that exists still warns (Add-SIDataQualityZeros).
            if (@($rows | Where-Object { $null -ne $_ }).Count -eq 0) {
                $notRun.Add(('Risk Analysis {0} rows: no {0} collection in the last {1} day(s) -- the step did not run, its report rows are not compared' -f $t.Label, $LookbackDays))
                $unread.Add(('rows.{0}.' -f $grain))
                continue
            }
            $total = 0.0; $filled = @{}; foreach ($c in $fillCols) { $filled[$c] = 0.0 }
            foreach ($r in $rows) {
                $rep = [string](Get-SIDataQualityValue $r 'Report')
                $n = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r 'Rows')
                if ($null -eq $n) { continue }
                if ($grain -eq 'detailed' -and $null -eq $collection) { $ct = Get-SIDataQualityValue $r 'CollectionTime'; if ($ct) { $collection = ConvertTo-SIDataQualityUtc $ct } }
                if (-not $rep) { $rep = '(no report name)' }
                $metrics.Add((New-SIDataQualityMetric -Key ('rows.{0}.{1}' -f $grain, $rep) -Kind 'rows' -Label ('Rows: {0} ({1})' -f $rep, $t.Label) -Value $n -Step $t.Step))
                $total += $n
                foreach ($c in $fillCols) { $f = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r ('F_' + $c)); if ($null -ne $f) { $filled[$c] += $f } }
            }
            if ($total -gt 0) {
                foreach ($c in $fillCols) {
                    $metrics.Add((New-SIDataQualityMetric -Key ('fill.' + $c) -Kind 'fill' -Label $script:SIDataQuality.RaFill[$c] -Value (100.0 * $filled[$c] / $total) -Step $t.Step))
                }
            }
        } catch { $problems.Add(('Risk Analysis {0} rows: {1}' -f $t.Label, $_.Exception.Message)); $unread.Add(('rows.{0}.' -f $grain)); $unread.Add('fill.') }
    }

    # the CIs: active, not seen any more, per tier, asset type and owner filled
    try {
        $ci = @(Read-SIDataQualityRows $Invoke (Get-SIDataQualityCiSql) @{}) | Select-Object -First 1
        $active = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $ci 'Active')
        if ($null -ne $active) {
            $metrics.Add((New-SIDataQualityMetric -Key 'ci.active' -Kind 'assets' -Label 'Active CIs' -Value $active -Step 'asset-correlation'))
            $retire = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $ci 'ToRetire'); if ($null -eq $retire) { $retire = 0 }
            $metrics.Add((New-SIDataQualityMetric -Key 'ci.to_retire' -Kind 'retire' -Label 'CIs not seen any more (to retire)' -Value $retire -Step 'asset-correlation'))
            foreach ($tier in 0..3) {
                $v = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $ci ('Tier' + $tier)); if ($null -eq $v) { $v = 0 }
                $metrics.Add((New-SIDataQualityMetric -Key ('tier.' + $tier) -Kind 'tier' -Label ('Active CIs in tier {0}' -f $tier) -Value $v -Step 'ptc'))
            }
            if ($active -gt 0) {
                $at = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $ci 'AssetTypeFilled'); if ($null -eq $at) { $at = 0 }
                $ow = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $ci 'OwnerFilled'); if ($null -eq $ow) { $ow = 0 }
                $metrics.Add((New-SIDataQualityMetric -Key 'fill.asset_type' -Kind 'fill' -Label 'Fill: asset type of the active CIs (si_asset_type)' -Value (100.0 * $at / $active) -Step 'asset-correlation'))
                $metrics.Add((New-SIDataQualityMetric -Key 'fill.ci_owner' -Kind 'fill' -Label 'Fill: owner of the active CIs (si_owner / CMDB owner)' -Value (100.0 * $ow / $active) -Step 'asset-correlation'))
            }
        }
    } catch { $problems.Add(('CIs: ' + $_.Exception.Message)); $unread.Add('ci.'); $unread.Add('tier.') }

    # the active CIs per asset class (asset type)
    try {
        foreach ($r in @(Read-SIDataQualityRows $Invoke (Get-SIDataQualityClassSql) @{})) {
            $type = [string](Get-SIDataQualityValue $r 'AssetType'); if (-not $type) { continue }
            $n = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r 'Assets'); if ($null -eq $n) { continue }
            $metrics.Add((New-SIDataQualityMetric -Key ('class.' + $type) -Kind 'class' -Label ('Active CIs of type {0}' -f $type) -Value $n -Step 'asset-correlation'))
        }
    } catch { $problems.Add(('assets per class: ' + $_.Exception.Message)); $unread.Add('class.') }

    # the fill of every catalog field per source that fills it (the field catalog and the mappings decide which)
    try {
        $plan = @(Get-SIDataQualityFieldPlan -Root $DataModelRoot)
        if ($plan.Count) {
            $fillRows = @(Read-SIDataQualityRows $Invoke (Get-SIDataQualityFieldFillSql) @{})
            foreach ($m in @(ConvertTo-SIDataQualityFieldFill -Plan $plan -Rows $fillRows)) { $metrics.Add($m) }
        }
    } catch { $problems.Add(('fill per source field: ' + $_.Exception.Message)); $unread.Add('fill.src.') }

    # the age of each source's last good collection, in days (0 = its newest collection completed) -- a number of the run,
    # never a warning by itself (kind 'age' has no rule); engine\_shared\SI-SourceState.ps1
    try {
        if (-not (Get-Command -Name Get-SISourceAgeDays -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($script:SIDataQualityEngineRoot, '_shared', 'SI-SourceState.ps1')) }
        $ageNow = [datetime]::UtcNow
        foreach ($r in @(Read-SIDataQualityRows $Invoke (Get-SISourceStateSql 'Read') @{})) {
            $src = ConvertFrom-SISourceStateRow $r
            if (-not $src -or -not $src.Source -or -not $src.LastAttemptUtc) { continue }
            $metrics.Add((New-SIDataQualityMetric -Key ('source_age.' + $src.Source) -Kind 'age' -Label ('Days since the last good collection: {0}' -f $src.Source) -Value (Get-SISourceAgeDays -Source $src -NowUtc $ageNow) -Step $src.Source))
        }
    } catch { $problems.Add(('age of the sources: ' + $_.Exception.Message)) }

    # classification incomplete (owner 2026-10-19): findings without a risk rating / tier 0-3 / asset, active CIs without a tier
    $classGroups = [ordered]@{}
    try {
        $cls = ConvertTo-SIDataQualityClassification -Rows @(Read-SIDataQualityRows $Invoke (Get-SIDataQualityClassificationSql) @{})
        foreach ($m in @($cls.Metrics)) { $metrics.Add($m) }
        $classGroups = $cls.Groups
    } catch { $problems.Add(('classification: ' + $_.Exception.Message)); $unread.Add('classgap.') }

    [pscustomobject]@{ Metrics = $metrics.ToArray(); CollectionTime = $collection; Problems = @($problems); NotRun = @($notRun); Unread = @($unread); ClassGroups = $classGroups }
}

# =====================================================================================================================
#  Comparing -- PURE
# =====================================================================================================================
function Get-SIDataQualityMedian {
    <# PURE. The median of the numbers ($null when there are none). #>
    param([AllowEmptyCollection()][double[]]$Values)
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $mid = [int][math]::Floor($v.Count / 2)
    if ($v.Count % 2 -eq 1) { return [double]$v[$mid] }
    ([double]$v[$mid - 1] + [double]$v[$mid]) / 2.0
}

function Test-SIDataQualityMissingIsZero {
    <# PURE. Whether a number that is not measured this run is 0 (a source, a report, a tier that produced nothing), not unknown. #>
    param([string]$Kind)
    $Kind -in @('assets', 'rows', 'tier', 'retire', 'class')
}

function Add-SIDataQualityZeros {
    <#
        PURE. A count the last earlier run had and this run did not produce is a 0, not a gap: a report that went to zero
        rows has no row in Log Analytics at all, so it would never be compared. Added while it is not 0 in all of the last
        3 runs (a report removed for good stops being carried). -History: newest first, each @{ Values (key -> number);
        Kinds / Labels / Steps (key -> text) }. -Unread: key prefixes of a source that could not be read this run -- a
        failed read is not a zero, so they are never filled.
    #>
    param([AllowEmptyCollection()][object[]]$Metrics = @(), [AllowEmptyCollection()][object[]]$History = @(), [AllowEmptyCollection()][string[]]$Unread = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in @($Metrics)) { $out.Add($m) }
    $h = @($History)
    if ($h.Count -eq 0) { return $out.ToArray() }
    $have = @{}; foreach ($m in $out) { $have[[string]$m.Key] = $true }
    $last = $h[0]
    foreach ($k in @($last.Values.Keys)) {
        if ($have.ContainsKey($k)) { continue }
        if (@($Unread | Where-Object { $_ -and $k.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count) { continue }
        $kind = [string]$last.Kinds[$k]
        if (-not (Test-SIDataQualityMissingIsZero $kind)) { continue }
        $recent = @($h | Select-Object -First $script:SIDataQuality.Runs | ForEach-Object { if ($_.Values.ContainsKey($k)) { [double]$_.Values[$k] } })
        if ($recent.Count -and -not @($recent | Where-Object { $_ -ne 0 }).Count) { continue }
        $out.Add((New-SIDataQualityMetric -Key $k -Kind $kind -Label ([string]$last.Labels[$k]) -Value 0 -Step ([string]$last.Steps[$k])))
    }
    $out.ToArray()
}

function Find-SIDataQualityAnomalies {
    <#
        PURE. Each number of -Metrics against the MEDIAN of the same number in the last 3 earlier runs (-History, newest
        first). Fewer than 3 earlier runs that carry the number = learning, no anomaly. -Settings from
        Get-SIDataQualitySettings. Returns @{ Learning (no run compared at all); EarlierRuns; Anomalies (newest-earlier first:
        Earlier = @(e1, e2, e3)) }. ChangePct: percent of the expected value (fill: points; a tier / CIs to retire: percent
        of the active CIs).
    #>
    param([AllowEmptyCollection()][object[]]$Metrics = @(), [AllowEmptyCollection()][object[]]$History = @(), [Parameter(Mandatory)]$Settings)
    $n = $script:SIDataQuality.Runs
    $h = @($History | Select-Object -First $n)
    $res = [ordered]@{ Learning = ($h.Count -lt $n); EarlierRuns = @($History).Count; Anomalies = @() }
    if ($res.Learning) { return [pscustomobject]$res }
    $now = @{}; foreach ($m in @($Metrics)) { $now[[string]$m.Key] = [double]$m.Value }
    # the active CIs (now, else their median) are the base of a tier move
    $activeNow = if ($now.ContainsKey('ci.active')) { $now['ci.active'] } else { 0 }
    $activeMed = Get-SIDataQualityMedian @($h | ForEach-Object { if ($_.Values.ContainsKey('ci.active')) { [double]$_.Values['ci.active'] } })
    $base = [math]::Max([double]$activeNow, $(if ($null -ne $activeMed) { [double]$activeMed } else { 0.0 }))
    $threshold = @{}; foreach ($r in @(Get-RAThresholdReportNamesSafe)) { $threshold[$r] = $true }
    $succ = Get-RAReportSuccessorMapSafe
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in @($Metrics)) {
        $k = [string]$m.Key
        $earlier = @($h | ForEach-Object { if ($_.Values.ContainsKey($k)) { [double]$_.Values[$k] } })
        if ($earlier.Count -lt $n) { continue }   # this number is still learning
        $exp = [double](Get-SIDataQualityMedian $earlier)
        $v = [double]$m.Value
        $rule = $null; $change = $null
        switch ([string]$m.Kind) {
            'assets' {
                if ($exp -gt 0) { $change = 100.0 * ($v - $exp) / $exp; if ($change -le -[double]$Settings.AssetDropPercent) { $rule = 'asset-drop' } }
            }
            'rows' {
                $rep = ($k -split '\.', 3)[2]
                if ($threshold.ContainsKey($rep)) { break }
                # a report whose findings moved to a receiving report that is new this run is a different population
                $moved = $false
                if ($succ -and $succ.ContainsKey($rep)) {
                    foreach ($to in @($succ[$rep])) {
                        $toKey = ('rows.{0}.{1}' -f ($k -split '\.', 3)[1], $to)
                        $toSeen = @($h | Where-Object { $_.Values.ContainsKey($toKey) -and [double]$_.Values[$toKey] -gt 0 }).Count
                        if ($now.ContainsKey($toKey) -and $now[$toKey] -gt 0 -and $toSeen -lt $n) { $moved = $true }
                    }
                }
                if ($moved) { break }
                if ($exp -gt 0) {
                    $change = 100.0 * ($v - $exp) / $exp
                    if ($v -eq 0) { $rule = 'report-zero' } elseif ($change -le -[double]$Settings.ReportDropPercent) { $rule = 'report-drop' }
                }
            }
            'fill' {
                $change = $v - $exp
                if ($change -le -[double]$Settings.FillDropPoints) { $rule = 'fill-drop' }
            }
            'tier' {
                if ($base -gt 0) { $change = 100.0 * ($v - $exp) / $base; if ([math]::Abs($change) -ge [double]$Settings.TierShiftPercent) { $rule = 'tier-shift' } }
            }
            'retire' {
                if ($base -gt 0) { $change = 100.0 * ($v - $exp) / $base; if ($change -ge [double]$Settings.TierShiftPercent) { $rule = 'retire-rise' } }
            }
            'class' {
                if ($base -gt 0) { $change = 100.0 * ($v - $exp) / $base; if ([math]::Abs($change) -ge [double]$Settings.TierShiftPercent) { $rule = 'class-shift' } }
            }
        }
        if (-not $rule) { continue }
        $out.Add([pscustomobject]@{
            Key = $k; Kind = [string]$m.Kind; Label = [string]$m.Label; Step = [string]$m.Step; Rule = $rule
            Direction = $(if ($v -lt $exp) { 'drop' } else { 'rise' })
            Earlier = @($earlier); Expected = [math]::Round($exp, 2); Now = $v; ChangePct = [math]::Round([double]$change, 1); Cause = ''; CauseChangeIds = @(); Fields = @()
        })
    }
    # most significant first
    $res.Anomalies = @($out | Sort-Object @{ Expression = { [math]::Abs([double]$_.ChangePct) }; Descending = $true }, Key)
    [pscustomobject]$res
}

function Get-SIDataQualityFields {
    <# PURE. The fields inside a one-per-source warning (none for any other warning). #>
    param($Anomaly)
    if ($null -eq $Anomaly) { return @() }
    $p = $Anomaly.PSObject.Properties['Fields']
    if (-not $p -or $null -eq $p.Value) { return @() }
    @($p.Value | Where-Object { $null -ne $_ })
}

function Get-SIDataQualityFieldName {
    <# PURE. The field's own name from the key of a source field's fill ("fill.src.<source>.<field>"); '' for any other key. #>
    param([string]$Key)
    if ($Key -match '^fill\.src\.[^.]+\.(.+)$') { return $Matches[1] }
    ''
}

function Get-SIDataQualityNumberCount {
    <# PURE. How many key numbers the warnings stand for: a one-per-source warning counts its fields. #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @())
    $n = 0
    foreach ($x in @($Anomalies)) { $f = @(Get-SIDataQualityFields $x); if ($f.Count) { $n += $f.Count } else { $n++ } }
    $n
}

function Join-SIDataQualitySourceAnomalies {
    <#
        PURE. ONE warning per source: the fields of one source that are filled less in this run ("fill.src.<source>.<field>",
        two or more of them) become ONE warning "<source> stopped filling N fields" -- key "fill.src.<source>", rule
        source-fill-drop, .Fields = the fields (largest drop first), each with its own 3 earlier values, expected value,
        now and change. The warning's own numbers are the AVERAGE fill of those fields: in each of the 3 earlier runs, their
        median (expected), now, and the change in points. A source with one dropped field keeps that field's warning; every
        other warning passes through. Most significant first, as Find-SIDataQualityAnomalies orders them.
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @())
    $a = @($Anomalies | Where-Object { $null -ne $_ })
    $bySource = [ordered]@{}
    foreach ($x in $a) {
        if ([string]$x.Key -notmatch '^fill\.src\.([^.]+)\..+$') { continue }
        $src = $Matches[1]
        if (-not $bySource.Contains($src)) { $bySource[$src] = New-Object System.Collections.Generic.List[object] }
        $bySource[$src].Add($x)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in $a) {
        if ([string]$x.Key -match '^fill\.src\.([^.]+)\..+$' -and $bySource[$Matches[1]].Count -gt 1) { continue }
        $out.Add($x)
    }
    foreach ($src in @($bySource.Keys)) {
        if ($bySource[$src].Count -lt 2) { continue }
        $list = @($bySource[$src] | Sort-Object @{ Expression = { [math]::Abs([double]$_.ChangePct) }; Descending = $true }, Key)
        $earlier = @(foreach ($i in 0..($script:SIDataQuality.Runs - 1)) {
            $vals = @($list | ForEach-Object { $e = @($_.Earlier); if ($e.Count -gt $i -and $null -ne $e[$i]) { [double]$e[$i] } })
            if ($vals.Count) { [math]::Round([double](($vals | Measure-Object -Average).Average), 2) }
        })
        $now = [math]::Round([double]((@($list | ForEach-Object { [double]$_.Now }) | Measure-Object -Average).Average), 2)
        $exp = Get-SIDataQualityMedian ([double[]]$earlier)
        if ($null -eq $exp) { $exp = [double]((@($list | ForEach-Object { [double]$_.Expected }) | Measure-Object -Average).Average) }
        $info = $script:SIDataQuality.Providers[$src]
        $name = if ($info) { [string]$info.Label } else { $src }
        # the name starts the sentence ("the CMDB" reads "The CMDB stopped filling ...")
        if ($name.Length) { $name = $name.Substring(0, 1).ToUpperInvariant() + $name.Substring(1) }
        $out.Add([pscustomobject]@{
            Key = ('fill.src.' + $src); Kind = 'fill'; Label = ('{0} stopped filling {1} fields' -f $name, $list.Count); Step = [string]$list[0].Step; Rule = 'source-fill-drop'
            Direction = 'drop'; Earlier = @($earlier); Expected = [math]::Round([double]$exp, 2); Now = $now; ChangePct = [math]::Round(($now - [double]$exp), 1)
            Cause = ''; CauseChangeIds = @(); Fields = $list
        })
    }
    @($out | Sort-Object @{ Expression = { [math]::Abs([double]$_.ChangePct) }; Descending = $true }, Key)
}

function Get-RAThresholdReportNamesSafe { if (Get-Command -Name Get-RAThresholdReportNames -ErrorAction SilentlyContinue) { @(Get-RAThresholdReportNames) } else { @() } }
function Get-RAReportSuccessorMapSafe { if (Get-Command -Name Get-RAReportSuccessorMap -ErrorAction SilentlyContinue) { Get-RAReportSuccessorMap } else { @{} } }

# =====================================================================================================================
#  The likely cause -- cfg.ChangeLog since the previous run (PURE over the rows)
# =====================================================================================================================
function Get-SIDataQualityChangeLogSql {
    <# The settings changes between the previous run and now (cfg.ChangeLog, newest first). #>
@'
IF OBJECT_ID(N'cfg.ChangeLog') IS NULL
    SELECT CAST(NULL AS nvarchar(128)) AS Name WHERE 1 = 0;
ELSE
    SELECT TOP (200) ChangeId, Name, Scope, Kind, Action, ChangedAt, ChangedBy, Reason
    FROM cfg.ChangeLog WHERE ChangedAt > @Since AND ChangedAt <= @Until ORDER BY ChangedAt DESC, ChangeId DESC;
'@
}

function Get-SIDataQualityHintKey {
    <# PURE. Which hint list a number's key uses. #>
    param([string]$Key)
    if ($Key -match '^assets\.') { return $Key }
    if ($Key -match '^rows\.') { return 'rows' }
    if ($Key -match '^fill\.') { return 'fill' }
    if ($Key -match '^tier\.') { return 'tier' }
    if ($Key -match '^class\.') { return 'class' }
    'ci'
}

function Get-SIDataQualityCauseChanges {
    <#
        PURE. The settings changes behind one anomaly (-Changes: cfg.ChangeLog rows of the window, newest first):
        .Relevant = the changes that concern the number (its hint words, its report's name, its source field's name);
        .All = every change of the window. The likely cause names .Relevant when there is one, else .All.
    #>
    param([Parameter(Mandatory)]$Anomaly, [AllowEmptyCollection()][object[]]$Changes = @())
    $all = @($Changes | Where-Object { $_ -and [string](Get-SIDataQualityValue $_ 'Name') })
    $key = [string]$Anomaly.Key
    $hint = $script:SIDataQuality.Hints[(Get-SIDataQualityHintKey $key)]
    $rep = ''
    if ($key -match '^rows\.[^.]+\.(.+)$') { $rep = [regex]::Escape($Matches[1]) }
    elseif ($key -match '^fill\.src\.([^.]+)\.(.+)$') { $rep = [regex]::Escape($Matches[2]) + '|mappings?/' + [regex]::Escape($Matches[1]) + '\b' }
    elseif ($key -match '^fill\.src\.([^.]+)$') {
        # one warning for a source's fields: the source's mapping, or any of the fields by its own name
        $src = $Matches[1]
        $names = @(Get-SIDataQualityFields $Anomaly | ForEach-Object { Get-SIDataQualityFieldName ([string]$_.Key) } | Where-Object { $_ } | ForEach-Object { [regex]::Escape($_) })
        $rep = (@($names) + @('mappings?/' + [regex]::Escape($src) + '\b')) -join '|'
    }
    $rel = @($all | Where-Object {
        $txt = '{0} {1} {2}' -f (Get-SIDataQualityValue $_ 'Name'), (Get-SIDataQualityValue $_ 'Scope'), (Get-SIDataQualityValue $_ 'Kind')
        ($hint -and $txt -match ('(?i)' + $hint)) -or ($rep -and $txt -match ('(?i)' + $rep))
    })
    [pscustomobject]@{ Relevant = $rel; All = $all }
}

function Get-SIDataQualityCause {
    <#
        PURE. The likely cause of one anomaly from the settings changes since the previous run (-Changes: cfg.ChangeLog rows,
        newest first): the changes that concern the number first (its hint words, or its report's name), else every change.
        At most 3 named ("and N more"). No change = says the source data itself changed.
    #>
    param([Parameter(Mandatory)]$Anomaly, [AllowEmptyCollection()][object[]]$Changes = @(), [string]$Since = 'the previous run')
    $found = Get-SIDataQualityCauseChanges -Anomaly $Anomaly -Changes $Changes
    $all = @($found.All)
    if (-not $all.Count) { return ('No setting was changed since {0}, so the source data itself changed -- or a collection was incomplete.' -f $Since) }
    $rel = @($found.Relevant)
    $use = if ($rel.Count) { $rel } else { $all }
    $named = @($use | Select-Object -First 3 | ForEach-Object {
        $at = Get-SIDataQualityValue $_ 'ChangedAt'
        $atU = ConvertTo-SIDataQualityUtc $at; $when = if ($atU) { $atU.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant) + ' UTC' } else { '' }
        $scope = [string](Get-SIDataQualityValue $_ 'Scope')
        '{0}{1} changed by {2}{3}' -f (Get-SIDataQualityValue $_ 'Name'), $(if ($scope -and $scope -ne 'solution') { ' (' + $scope + ')' } else { '' }), (Get-SIDataQualityValue $_ 'ChangedBy'), $(if ($when) { ' at ' + $when } else { '' })
    })
    $more = $use.Count - $named.Count
    $what = if (@(Get-SIDataQualityFields $Anomaly).Count) { 'this source' } else { 'this number' }
    $lead = if ($rel.Count) { ('Settings changed since {0} that concern {1}: ' -f $Since, $what) } else { ('Settings changed since {0}: ' -f $Since) }
    $lead + ($named -join '; ') + $(if ($more -gt 0) { ('; and {0} more' -f $more) } else { '' }) + '.'
}

# =====================================================================================================================
#  The words -- PURE (numbers in the install's regional format)
# =====================================================================================================================
function Format-SIDataQualityNumber {
    <# PURE. A number for a person: whole counts grouped, a fill % with one decimal. #>
    param($Value, [string]$Kind, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    if ($null -eq $Value) { return '' }
    $d = [double]$Value
    if ($Kind -eq 'fill') { return ($d.ToString('N1', $Culture) + ' %') }
    if ($d -eq [math]::Floor($d)) { return $d.ToString('N0', $Culture) }
    $d.ToString('N1', $Culture)
}

function Format-SIDataQualityChange {
    <# PURE. The change as it is read: "-62 %", "+25 % of all CIs", "-35 points". #>
    param($Anomaly, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $c = [double]$Anomaly.ChangePct
    $sign = if ($c -gt 0) { '+' } else { '' }
    switch ([string]$Anomaly.Kind) {
        'fill' { return ('{0}{1} points' -f $sign, $c.ToString('N1', $Culture)) }
        'tier' { return ('{0}{1} % of all active CIs' -f $sign, $c.ToString('N0', $Culture)) }
        'retire' { return ('{0}{1} % of all active CIs' -f $sign, $c.ToString('N0', $Culture)) }
        'class' { return ('{0}{1} % of all active CIs' -f $sign, $c.ToString('N0', $Culture)) }
        'classgap' { return ('{0} to classify' -f $c.ToString('N0', $Culture)) }
        default { return ('{0}{1} %' -f $sign, $c.ToString('N0', $Culture)) }
    }
}

function Format-SIDataQualityExpected {
    <# PURE. The three earlier values, oldest first, as the mail and the panel show them: "1,020 / 1,000 / 990". #>
    param($Anomaly, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $src = @($Anomaly.Earlier); $e = @(for ($i = $src.Count - 1; $i -ge 0; $i--) { $src[$i] })
    (@($e | ForEach-Object { Format-SIDataQualityNumber $_ $Anomaly.Kind $Culture }) -join ' / ')
}

function Get-SIDataQualityRunHealthLines {
    <#
        PURE. One line per warning for the run health END record (the run report). A one-per-source warning is one line:
        the source and how many fields, their average fill now and expected, and the field that dropped most.
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @(), [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    @($Anomalies | ForEach-Object {
        $f = @(Get-SIDataQualityFields $_)
        if ([string]$_.Rule -eq 'classification-incomplete') {
            'data quality: {0}: {1} -- {2}' -f $_.Label, (Format-SIDataQualityNumber $_.Now 'classgap' $Culture), $_.Cause
        } elseif ($f.Count) {
            'data quality: {0}: their average fill is {1}, expected {2} from the last 3 runs ({3}); the largest: {4} is {5}, expected {6} ({7})' -f $_.Label,
                (Format-SIDataQualityNumber $_.Now $_.Kind $Culture), (Format-SIDataQualityNumber $_.Expected $_.Kind $Culture), (Format-SIDataQualityChange $_ $Culture),
                $f[0].Label, (Format-SIDataQualityNumber $f[0].Now $f[0].Kind $Culture), (Format-SIDataQualityNumber $f[0].Expected $f[0].Kind $Culture), (Format-SIDataQualityChange $f[0] $Culture)
        } else {
            'data quality: {0} is {1}, expected {2} from the last 3 runs ({3})' -f $_.Label, (Format-SIDataQualityNumber $_.Now $_.Kind $Culture), (Format-SIDataQualityNumber $_.Expected $_.Kind $Culture), (Format-SIDataQualityChange $_ $Culture)
        }
    })
}

function Get-SIDataQualitySummaryLines {
    <#
        PURE. The lines of the run health END record: one per anomaly -- except the fields of ONE source that are filled
        less (a source that stops filling its fields drops many at once), which are one line per source naming the largest.
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @(), [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $a = @($Anomalies)
    $fields = @($a | Where-Object { [string]$_.Key -match '^fill\.src\.' })
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($l in @(Get-SIDataQualityRunHealthLines -Anomalies @($a | Where-Object { [string]$_.Key -notmatch '^fill\.src\.' }) -Culture $Culture)) { $lines.Add($l) }
    $bySource = [ordered]@{}
    foreach ($x in $fields) {
        $src = ([string]$x.Key -split '\.', 4)[2]
        if (-not $bySource.Contains($src)) { $bySource[$src] = New-Object System.Collections.Generic.List[object] }
        $bySource[$src].Add($x)
    }
    foreach ($src in @($bySource.Keys)) {
        $list = @($bySource[$src] | Sort-Object @{ Expression = { [math]::Abs([double]$_.ChangePct) }; Descending = $true })
        if ($list.Count -eq 1) { foreach ($l in @(Get-SIDataQualityRunHealthLines -Anomalies $list -Culture $Culture)) { $lines.Add($l) }; continue }
        $info = $script:SIDataQuality.Providers[$src]
        $name = if ($info) { $info.Label } else { $src }
        $lines.Add(('data quality: {0} fields from {1} are filled less than expected from the last 3 runs; the largest: {2} is {3}, expected {4} ({5})' -f `
            $list.Count, $name, $list[0].Label, (Format-SIDataQualityNumber $list[0].Now $list[0].Kind $Culture), (Format-SIDataQualityNumber $list[0].Expected $list[0].Kind $Culture), (Format-SIDataQualityChange $list[0] $Culture)))
    }
    $lines.ToArray()
}

function Get-SIDataQualityHeadline {
    <#
        PURE. The headline a person understands without knowing the check (owner 2026-10-21 on the old "Data quality alert: an
        unusual drop was detected": "Hard to understand"): what changed, and that nothing was lost -- "Fewer than usual in
        the latest data -- nothing was lost" (or "More than usual", "Unusual numbers" for both).
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @())
    $drops = @($Anomalies | Where-Object { $_.Direction -eq 'drop' }).Count
    $rises = @($Anomalies | Where-Object { $_.Direction -eq 'rise' }).Count
    $what = if ($drops -and $rises) { 'Unusual numbers' } elseif ($rises) { 'More than usual' } else { 'Fewer than usual' }
    "$what in the latest data -- nothing was lost"
}

function Get-SIDataQualityInShort {
    <#
        PURE. The three answers a reader needs first (owner 2026-10-21, SUP-2026-00231): what happened (in plain words, the
        biggest change with its numbers), is anything lost (no: a check only), does anyone have to act (usually not).
        Returns the three lines.
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @(), [string]$When = 'the latest run', [int]$Numbers = 0,
          [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $a = @($Anomalies)
    $largest = $a | Sort-Object @{ Expression = { [math]::Abs([double]$_.ChangePct) }; Descending = $true } | Select-Object -First 1
    $big = if ($largest) {
        (' The biggest: {0} -- {1} now, usually {2} ({3}).' -f [string]$largest.Label, (Format-SIDataQualityNumber $largest.Now $largest.Kind $Culture),
            (Format-SIDataQualityNumber $largest.Expected $largest.Kind $Culture), (Format-SIDataQualityChange $largest $Culture))
    } else { '' }
    @(
        ('What happened: in the run of {0}, {1} number{2} {3} clearly different from the last 3 runs.{4}' -f $When, $Numbers, $(if ($Numbers -eq 1) { '' } else { 's' }), $(if ($Numbers -eq 1) { 'was' } else { 'were' }), $big),
        'Is anything lost: no. This is a check only -- nothing was blocked or deleted. An asset a source no longer lists is kept for its grace period, never removed at once.',
        'Does anyone have to act: usually not. If you know why (for example devices or Azure resources were removed on purpose), nothing is needed -- the usual range follows the new level after three runs. If you do not know why, see "What you can do" below.'
    )
}

function ConvertTo-SIDataQualityMail {
    <#
        PURE. The ONE daily data-quality mail, shaped like a cloud cost-anomaly alert (owner 2026-10-11): the headline, one
        sentence (which run, compared with the expected range from the last 3 runs, please review recent changes), the
        likely cause, a run summary (anomaly detected yes; the largest delta vs the expected range), the "most significant
        changes" table (key number, expected = the 3 earlier values, now, change), what to do (correct the setting, Re-run
        from here; nothing was blocked) and a Details button to the Data quality panel. Built with the MAIL-2 layout
        (New-SIMailLayout); every value encoded. Returns @{ Subject; Html; Text }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Anomalies, $CollectionTime, [string]$WebBaseUrl, [string]$TenantTag,
          [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture, [int]$MaxRows = 10, [string]$RunId,
          [AllowEmptyCollection()][string[]]$Entered = @(), [AllowEmptyCollection()][string[]]$Left = @(), $LastMail)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $L = $script:SIMailLayout
    $a = @($Anomalies)
    # a one-per-source warning stands for its fields: the sentence and the summary count key numbers
    $numbers = Get-SIDataQualityNumberCount -Anomalies $a
    $headline = Get-SIDataQualityHeadline -Anomalies $a
    $ctU = ConvertTo-SIDataQualityUtc $CollectionTime; $when = if ($ctU) { $ctU.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant) + ' UTC' } else { 'the latest run' }
    # owner 2026-10-21 (SUP-2026-00231, "Hard to understand"): the three answers first -- what happened, is anything lost,
    # does anyone have to act -- then why, what you can do, and the numbers last
    $short = @(Get-SIDataQualityInShort -Anomalies $a -When $when -Numbers $numbers -Culture $Culture)
    $sentence = $short[0] -replace '^What happened: ', ''
    $largest = $a | Sort-Object @{ Expression = { [math]::Abs([double]$_.ChangePct) }; Descending = $true } | Select-Object -First 1
    $panel = if ("$WebBaseUrl" -match '^https://') { "$WebBaseUrl".TrimEnd('/') + $script:SIDataQuality.PanelPath } else { '' }
    # the Details button opens the panel on THIS run (its warnings, the likely cause with links, Re-run from here)
    if ($panel -and $RunId) { $panel += '?run=' + [uri]::EscapeDataString($RunId) }
    $h3 = { param($t) ConvertTo-SIMailHeadingHtml $t }

    $body = New-Object System.Text.StringBuilder
    # the numbers go LAST: built here, appended after "What you can do"
    $nums = New-Object System.Text.StringBuilder
    [void]$body.Append((& $h3 'In short'))
    [void]$body.Append(('<div style="{0}margin:0 0 16px 0;" data-mail-inshort>' -f $L.Font))
    foreach ($s in $short) {
        $i = $s.IndexOf(': ')
        [void]$body.Append((ConvertTo-SIMailLineHtml -Topic $s.Substring(0, $i) -Html (& $enc $s.Substring($i + 2))))
    }
    [void]$body.Append('</div>')
    # what is different from the last mail (this mail goes out only when the warnings change) -- not on the first mail
    $lmU = ConvertTo-SIDataQualityUtc $LastMail
    if ($lmU -and (@($Entered).Count -or @($Left).Count)) {
        [void]$body.Append((& $h3 'Since the last data-quality mail'))
        $since = @(('The last data-quality mail was about the run of {0} UTC.' -f $lmU.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant)))
        foreach ($n in @($Entered | Where-Object { $_ })) { $since += ('- New: {0}' -f $n) }
        foreach ($n in @($Left | Where-Object { $_ })) { $since += ('- Back within its expected range: {0}' -f $n) }
        [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text ($since[0] + "`n`n" + (@($since | Select-Object -Skip 1) -join "`n"))))
    }
    # likely cause -- each distinct cause once, the numbers it concerns named
    [void]$body.Append((& $h3 'Why this mail'))
    $causes = [ordered]@{}
    foreach ($x in $a) { $c = [string]$x.Cause; if (-not $c) { $c = 'Not known.' }; if (-not $causes.Contains($c)) { $causes[$c] = New-Object System.Collections.Generic.List[string] }; $causes[$c].Add([string]$x.Label) }
    if ($causes.Count -eq 1) { [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text (@($causes.Keys)[0]))) }
    else {
        $items = @($causes.Keys | ForEach-Object { '- ' + $_ + ' (' + (@($causes[$_] | Select-Object -First 3) -join ', ') + $(if ($causes[$_].Count -gt 3) { ', ...' } else { '' }) + ')' })
        [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text ($items -join "`n")))
    }
    # what to do
    [void]$body.Append((& $h3 'What you can do'))
    $steps = @(
        '- If a setting was changed just before (named under "Why this mail"), and the change was not meant to do this, correct the setting.',
        ('- Then open the Data quality panel (Details below) and use Re-run from here on the warning -- or on the step it names in Operations > Jobs -- so the numbers are measured again.'),
        '- If the change is expected (for example assets were removed on purpose), nothing needs doing: the usual range follows the new numbers after three runs.'
    )
    [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text ($steps -join "`n")))
    [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text 'Nothing was blocked: every step ran and delivered as usual. This is a warning only.'))
    # the numbers, last: one line per key number, then the run summary
    # most significant changes -- ONE line per key number (#728: no table), its fields as bullets under it
    [void]$nums.Append((& $h3 'The numbers'))
    [void]$nums.Append(('<div style="{0}margin:0 0 16px 0;" data-mail-changes>' -f $L.Font))
    foreach ($x in @($a | Select-Object -First $MaxRows)) {
        $line = ConvertTo-SIMailLineHtml -Topic ([string]$x.Label) -Html ('<strong>{0}</strong> now, expected {1} (last 3 runs), change {2}' -f `
            (& $enc (Format-SIDataQualityNumber $x.Now $x.Kind $Culture)), (& $enc (Format-SIDataQualityExpected $x $Culture)), (& $enc (Format-SIDataQualityChange $x $Culture)))
        [void]$nums.Append(($line -replace '^<p ', ('<p data-key="{0}" ' -f (& $enc $x.Key))))
        # ONE warning per source: its fields are listed under it, each with its 3 earlier values and now
        $fl = @(Get-SIDataQualityFields $x)
        if ($fl.Count) {
            [void]$nums.Append(('<ul style="{0}margin:-4px 0 12px 0;padding:0 0 0 22px;color:{1};font-size:13px;line-height:1.5;">' -f $L.Font, $L.Muted))
            foreach ($f in $fl) {
                $name = Get-SIDataQualityFieldName ([string]$f.Key); if (-not $name) { $name = [string]$f.Label }
                [void]$nums.Append(('<li data-field="{0}" style="margin:0 0 4px 0;">{1}: {2} now, expected {3}, change {4}</li>' -f `
                    (& $enc $f.Key), (& $enc $name), (& $enc (Format-SIDataQualityNumber $f.Now $f.Kind $Culture)), (& $enc (Format-SIDataQualityExpected $f $Culture)), (& $enc (Format-SIDataQualityChange $f $Culture))))
            }
            [void]$nums.Append('</ul>')
        }
    }
    [void]$nums.Append('</div>')
    if ($a.Count -gt $MaxRows) { [void]$nums.Append((ConvertTo-SIMailParagraphHtml -Text ('... and {0} more on the Data quality panel.' -f ($a.Count - $MaxRows)))) }
    # run summary
    $facts = [ordered]@{
        'Run'                         = $when
        'Anomaly detected'            = 'Yes'
        'Key numbers outside the range' = [string]$numbers
        'Largest delta vs expected'   = $(if ($largest) { (Format-SIDataQualityChange $largest $Culture) + ' (' + [string]$largest.Label + ')' } else { '' })
        'Compared with'               = 'The median of the last 3 runs'
    }
    [void]$nums.Append((ConvertTo-SIMailFactsHtml -Facts $facts -Title 'Run summary'))
    [void]$body.Append($nums.ToString())

    $layout = New-SIMailLayout -Title $headline -Summary $sentence -BodyHtml $body.ToString() -ButtonUrl $panel -ButtonText 'Details' `
        -Footer ($script:SIDataQuality.MailFooter + $(if ($TenantTag) { ' ' + $TenantTag } else { '' }))
    # MAIL-3 (#653): a data-quality alert carries the severity word Warning (the body keeps the headline as it is)
    $subject = 'Warning: ' + $headline
    if ($TenantTag) { $subject += (' | {0}' -f $TenantTag) }
    [pscustomobject]@{ Subject = $subject; Html = $layout.Html; Text = $layout.Text }
}

function ConvertTo-SIDataQualityNormalMail {
    <#
        PURE. The "back to normal" mail: sent ONCE, when a run has every key number within its expected range again after a
        data-quality mail about numbers outside it. Which run, what is back within its range (-Left: the names the last
        mail warned about), when the last mail was, and that nothing needs doing. The same layout and Details button as
        the alert (ConvertTo-SIDataQualityMail). Returns @{ Subject; Html; Text }.
    #>
    param([AllowEmptyCollection()][string[]]$Left = @(), $CollectionTime, $LastMail, [string]$WebBaseUrl, [string]$TenantTag, [string]$RunId)
    $L = $script:SIMailLayout
    $headline = 'Data quality: back to normal'
    $ctU = ConvertTo-SIDataQualityUtc $CollectionTime; $when = if ($ctU) { $ctU.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant) + ' UTC' } else { 'the latest run' }
    $lmU = ConvertTo-SIDataQualityUtc $LastMail
    $sentence = ('The pipeline run of {0} was compared with the expected range from the last 3 runs, and every key number is within it again.' -f $when)
    $panel = if ("$WebBaseUrl" -match '^https://') { "$WebBaseUrl".TrimEnd('/') + $script:SIDataQuality.PanelPath } else { '' }
    if ($panel -and $RunId) { $panel += '?run=' + [uri]::EscapeDataString($RunId) }
    $body = New-Object System.Text.StringBuilder
    $names = @($Left | Where-Object { $_ })
    if ($names.Count) {
        [void]$body.Append((ConvertTo-SIMailHeadingHtml 'Back within the expected range'))
        [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text (@($names | ForEach-Object { '- ' + $_ }) -join "`n")))
    }
    $facts = [ordered]@{
        'Run'                       = $when
        'Anomaly detected'          = 'No'
        'Last data-quality mail'    = $(if ($lmU) { 'About the run of ' + $lmU.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant) + ' UTC' } else { '' })
        'Compared with'             = 'The median of the last 3 runs'
    }
    [void]$body.Append((ConvertTo-SIMailFactsHtml -Facts $facts -Title 'Run summary'))
    [void]$body.Append((ConvertTo-SIMailParagraphHtml -Text 'Nothing needs doing. The next data-quality mail goes out when a key number leaves its expected range.'))
    $layout = New-SIMailLayout -Title $headline -Summary $sentence -BodyHtml $body.ToString() -ButtonUrl $panel -ButtonText 'Details' `
        -Footer ($script:SIDataQuality.MailFooter + $(if ($TenantTag) { ' ' + $TenantTag } else { '' }))
    $subject = $headline
    if ($TenantTag) { $subject += (' | {0}' -f $TenantTag) }
    [pscustomobject]@{ Subject = $subject; Html = $layout.Html; Text = $layout.Text }
}

# =====================================================================================================================
#  The mail only when the warnings change -- PURE
# =====================================================================================================================
function ConvertFrom-SIDataQualityLastMailedRows {
    <#
        PURE. The LastMailed statement's rows -> the last run a data-quality mail went out for: @{ RunId; ComputedAt;
        MailedAt; Keys (warning key -> its name) }. $null when no mail went out yet. A mailed run without warnings (the
        "back to normal" mail) has no keys.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $run = $null
    foreach ($r in @($Rows)) {
        $id = [string](Get-SIDataQualityValue $r 'RunId'); if (-not $id) { continue }
        if ($null -eq $run) { $run = [pscustomobject]@{ RunId = $id; ComputedAt = (ConvertTo-SIDataQualityUtc (Get-SIDataQualityValue $r 'ComputedAt')); MailedAt = (ConvertTo-SIDataQualityUtc (Get-SIDataQualityValue $r 'MailedAt')); Keys = @{} } }
        $k = [string](Get-SIDataQualityValue $r 'MetricKey'); if (-not $k) { continue }
        $label = [string](Get-SIDataQualityValue $r 'Label'); if (-not $label) { $label = $k }
        $run.Keys[$k] = $label
    }
    $run
}

function Compare-SIDataQualityMailSet {
    <#
        PURE. Whether this run's warnings differ from the warnings of the last MAILED run (-LastMailed, from
        ConvertFrom-SIDataQualityLastMailedRows; none = no mail went out yet, so any warning is new). Compared by the
        warning's key -- a source's fields as ONE key, so a source that drops one field more is not a change.
        A warning the last mail had whose numbers could not be READ this run (-Unread: key prefixes) is neither gone nor
        new: it is carried, so a failed read never sends "back to normal".
        Returns @{ Changed; Entered (names); Left (names); Carried (keys) }.
    #>
    param([AllowEmptyCollection()][object[]]$Anomalies = @(), $LastMailed, [AllowEmptyCollection()][string[]]$Unread = @())
    $now = @{}; $entered = New-Object System.Collections.Generic.List[string]
    $was = @{}
    if ($LastMailed -and $LastMailed.Keys -is [System.Collections.IDictionary]) { $was = $LastMailed.Keys }
    foreach ($x in @($Anomalies)) {
        $k = [string]$x.Key; if (-not $k) { continue }
        $now[$k] = $true
        if (-not $was.Contains($k)) { $entered.Add($(if ([string]$x.Label) { [string]$x.Label } else { $k })) }
    }
    $left = New-Object System.Collections.Generic.List[string]; $carried = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($was.Keys | Sort-Object)) {
        if ($now.ContainsKey([string]$k)) { continue }
        if (@($Unread | Where-Object { $_ -and ([string]$k).StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count) { $carried.Add([string]$k); continue }
        $left.Add([string]$was[$k])
    }
    [pscustomobject]@{ Changed = [bool]($entered.Count -or $left.Count); Entered = $entered.ToArray(); Left = $left.ToArray(); Carried = $carried.ToArray() }
}

# =====================================================================================================================
#  The store -- statements against sidata.DataQuality* (sql\si-data-schema.sql)
# =====================================================================================================================
function Get-SIDataQualitySql {
    param([Parameter(Mandatory)][ValidateSet('Exists', 'History', 'MailedToday', 'InsertRun', 'InsertMetrics', 'InsertAnomalies', 'MarkMailed', 'CauseTables', 'LastGood', 'InsertChanges', 'InsertCauses',
                                             'LastMailed', 'MarkNotMailed', 'FieldTable', 'InsertFields')][string]$Name)
    switch ($Name) {
        # the last run a data-quality mail went out for, with the warnings it was about (one row per warning; a mailed run
        # without warnings -- "back to normal" -- is one row without a key). The mail goes out only when this run differs.
        'LastMailed' { @'
SELECT r.RunId, r.ComputedAt, r.MailedAt, a.MetricKey, a.Label
FROM (SELECT TOP (1) RunId, ComputedAt, MailedAt FROM sidata.DataQualityRun
      WHERE MailState = N'sent' AND RunId <> @RunId ORDER BY ComputedAt DESC, RunId DESC) AS r
LEFT JOIN sidata.DataQualityAnomaly AS a ON a.RunId = r.RunId;
'@ }
        # why no mail went out for a run (unchanged | day-limit | off | no-recipients): the panel says it on the run
        'MarkNotMailed' { "UPDATE sidata.DataQualityRun SET MailState = @MailState WHERE RunId = @RunId AND MailedAt IS NULL;" }
        # the fields inside a one-per-source warning (added after the first tables: a database without it keeps the warning)
        'FieldTable' { "SELECT CASE WHEN OBJECT_ID(N'sidata.DataQualityAnomalyField') IS NOT NULL THEN 1 ELSE 0 END AS HasFieldTable;" }
        'InsertFields' { @'
INSERT sidata.DataQualityAnomalyField (RunId, MetricKey, FieldKey, Label, Earlier1, Earlier2, Earlier3, Expected, NowValue, ChangePct)
SELECT @RunId, LEFT(j.MetricKey, 200), LEFT(j.FieldKey, 200), LEFT(j.Label, 256), j.E1, j.E2, j.E3, j.Expected, j.NowValue, j.ChangePct
FROM OPENJSON(@j) WITH (MetricKey nvarchar(400) '$.k', FieldKey nvarchar(400) '$.f', Label nvarchar(400) '$.l',
                        E1 float '$.e1', E2 float '$.e2', E3 float '$.e3', Expected float '$.x', NowValue float '$.v', ChangePct float '$.c') AS j
WHERE j.MetricKey IS NOT NULL AND j.FieldKey IS NOT NULL;
SELECT @@ROWCOUNT AS N;
'@ }
        # the likely cause as rows (added after the first three tables: a database without them keeps the cause as text only)
        'CauseTables' { "SELECT CASE WHEN OBJECT_ID(N'sidata.DataQualityChange') IS NOT NULL AND OBJECT_ID(N'sidata.DataQualityCause') IS NOT NULL THEN 1 ELSE 0 END AS HasCauseTables;" }
        # when the newest run without a warning was measured (the start of the window the likely cause is looked for in)
        'LastGood' { "SELECT TOP (1) ComputedAt FROM sidata.DataQualityRun WHERE Anomalies = 0 ORDER BY ComputedAt DESC, RunId DESC;" }
        'InsertChanges' { @'
INSERT sidata.DataQualityChange (RunId, ChangeId, Name, Scope, Kind, Action, ChangedAt, ChangedBy)
SELECT @RunId, j.ChangeId, LEFT(j.Name, 128), LEFT(j.Scope, 64), LEFT(j.Kind, 64), LEFT(j.Action, 16), j.ChangedAt, LEFT(j.ChangedBy, 256)
FROM OPENJSON(@j) WITH (ChangeId bigint '$.id', Name nvarchar(400) '$.n', Scope nvarchar(200) '$.s', Kind nvarchar(200) '$.k', Action nvarchar(64) '$.a',
                        ChangedAt datetime2(0) '$.at', ChangedBy nvarchar(400) '$.by') AS j
WHERE j.ChangeId IS NOT NULL AND j.Name IS NOT NULL AND j.ChangedAt IS NOT NULL;
SELECT @@ROWCOUNT AS N;
'@ }
        'InsertCauses' { @'
INSERT sidata.DataQualityCause (RunId, MetricKey, ChangeId)
SELECT DISTINCT @RunId, LEFT(j.MetricKey, 200), j.ChangeId
FROM OPENJSON(@j) WITH (MetricKey nvarchar(400) '$.k', ChangeId bigint '$.id') AS j
WHERE j.MetricKey IS NOT NULL AND j.ChangeId IS NOT NULL;
SELECT @@ROWCOUNT AS N;
'@ }
        'Exists' { "SELECT CASE WHEN OBJECT_ID(N'sidata.DataQualityRun') IS NOT NULL AND OBJECT_ID(N'sidata.DataQualityMetric') IS NOT NULL AND OBJECT_ID(N'sidata.DataQualityAnomaly') IS NOT NULL THEN 1 ELSE 0 END AS HasTables;" }
        'History' { @'
SELECT r.RunId, r.CollectionTime, r.ComputedAt, m.MetricKey, m.Kind, m.Label, m.Value, m.Step
FROM (SELECT TOP (@Runs) RunId, CollectionTime, ComputedAt FROM sidata.DataQualityRun ORDER BY ComputedAt DESC, RunId DESC) AS r
LEFT JOIN sidata.DataQualityMetric AS m ON m.RunId = r.RunId
ORDER BY r.ComputedAt DESC, r.RunId DESC;
'@ }
        'MailedToday' { "SELECT COUNT_BIG(*) AS N FROM sidata.DataQualityRun WHERE MailState = N'sent' AND MailedAt >= @DayStart AND MailedAt < DATEADD(day, 1, @DayStart);" }
        'InsertRun' { @'
INSERT sidata.DataQualityRun (RunId, CollectionTime, ComputedAt, Metrics, Anomalies, Learning, EarlierRuns, LargestDeltaPct)
VALUES (@RunId, @CollectionTime, @ComputedAt, @Metrics, @Anomalies, @Learning, @EarlierRuns, @LargestDeltaPct);
'@ }
        'InsertMetrics' { @'
INSERT sidata.DataQualityMetric (RunId, MetricKey, Kind, Label, Value, Step)
SELECT @RunId, LEFT(j.MetricKey, 200), LEFT(j.Kind, 16), LEFT(j.Label, 256), j.Value, LEFT(j.Step, 64)
FROM OPENJSON(@j) WITH (MetricKey nvarchar(400) '$.k', Kind nvarchar(32) '$.t', Label nvarchar(400) '$.l', Value float '$.v', Step nvarchar(128) '$.s') AS j;
SELECT @@ROWCOUNT AS N;
'@ }
        'InsertAnomalies' { @'
INSERT sidata.DataQualityAnomaly (RunId, MetricKey, Kind, Label, Direction, [Rule], Earlier1, Earlier2, Earlier3, Expected, NowValue, ChangePct, Cause, Step)
SELECT @RunId, LEFT(j.MetricKey, 200), LEFT(j.Kind, 16), LEFT(j.Label, 256), LEFT(j.Direction, 8), LEFT(j.RuleId, 32), j.E1, j.E2, j.E3, j.Expected, j.NowValue, j.ChangePct, LEFT(j.Cause, 2000), LEFT(j.Step, 64)
FROM OPENJSON(@j) WITH (MetricKey nvarchar(400) '$.k', Kind nvarchar(32) '$.t', Label nvarchar(400) '$.l', Direction nvarchar(16) '$.d', RuleId nvarchar(64) '$.r',
                        E1 float '$.e1', E2 float '$.e2', E3 float '$.e3', Expected float '$.x', NowValue float '$.v', ChangePct float '$.c', Cause nvarchar(4000) '$.why', Step nvarchar(128) '$.s') AS j;
SELECT @@ROWCOUNT AS N;
'@ }
        'MarkMailed' { "UPDATE sidata.DataQualityRun SET MailedAt = SYSUTCDATETIME(), MailTo = LEFT(@MailTo, 1000), MailState = @MailState WHERE RunId = @RunId;" }
    }
}

function ConvertFrom-SIDataQualityHistoryRows {
    <# PURE. The History statement's rows -> earlier runs, newest first: @{ RunId; CollectionTime; ComputedAt; Values; Kinds; Labels; Steps }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $runs = New-Object System.Collections.Generic.List[object]
    $byId = @{}
    foreach ($r in @($Rows)) {
        $id = [string](Get-SIDataQualityValue $r 'RunId'); if (-not $id) { continue }
        if (-not $byId.ContainsKey($id)) {
            $run = [pscustomobject]@{ RunId = $id; CollectionTime = (Get-SIDataQualityValue $r 'CollectionTime'); ComputedAt = (Get-SIDataQualityValue $r 'ComputedAt'); Values = @{}; Kinds = @{}; Labels = @{}; Steps = @{} }
            $byId[$id] = $run; $runs.Add($run)
        }
        $k = [string](Get-SIDataQualityValue $r 'MetricKey'); if (-not $k) { continue }
        $v = ConvertTo-SIDataQualityNumber (Get-SIDataQualityValue $r 'Value'); if ($null -eq $v) { continue }
        $run = $byId[$id]
        $run.Values[$k] = $v; $run.Kinds[$k] = [string](Get-SIDataQualityValue $r 'Kind'); $run.Labels[$k] = [string](Get-SIDataQualityValue $r 'Label'); $run.Steps[$k] = [string](Get-SIDataQualityValue $r 'Step')
    }
    $runs.ToArray()
}

function Get-SIDataQualityRecipients {
    <# PURE. SI_Pro_DataQuality_Mail_To, else the guard mail's recipients (SI_GuardMail_To, MailTo, the Pro SuperAdmins). #>
    param([System.Collections.IDictionary]$Globals, $MailTo, [AllowNull()][string[]]$SuperAdminMails)
    $own = @()
    if (Get-Command -Name Split-SIGuardAddresses -ErrorAction SilentlyContinue) { $own = @(Split-SIGuardAddresses $MailTo) }
    else { $own = @(@($MailTo) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+$' }) }
    if ($own.Count) { return [pscustomobject]@{ To = $own; Source = 'SI_Pro_DataQuality_Mail_To' } }
    if (Get-Command -Name Get-SIGuardMailRecipients -ErrorAction SilentlyContinue) { return (Get-SIGuardMailRecipients -Globals $Globals -SuperAdminMails $SuperAdminMails) }
    [pscustomobject]@{ To = @(); Source = '' }
}

# =====================================================================================================================
#  The step -- what the data sync calls once per run. NEVER throws, never blocks, never a guard event.
# =====================================================================================================================
function Invoke-SIDataQuality {
    <#
        Measures the run's fingerprint, compares it with the last 3 runs, makes ONE warning of a source's fields, names the
        likely cause, stores the run, and sends the mail ONLY WHEN THE WARNINGS DIFFER FROM THE LAST MAILED RUN (a new
        warning, one that is gone, or all gone = "back to normal"), at most one a day. .MailState: sent | failed |
        unchanged | day-limit | off | no-recipients | '' (nothing to say).
        Seams: -Query (Log Analytics), -Invoke (the data database: sidata), -SettingsInvoke (the settings database: cfg.ChangeLog,
        the SuperAdmins; default -Invoke), -Send ({ param([string[]]$To, [string]$Subject, [string]$Html) } -> $true when sent;
        none = no mail), -Globals, -Now, -RunId. -DryRun: measures and compares, writes and sends nothing.
        Returns @{ Status; RunId; CollectionTime; Metrics; Anomalies; Learning; EarlierRuns; Lines; Mailed; MailNote; Problems }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$SettingsInvoke, [scriptblock]$Send,
          [System.Collections.IDictionary]$Globals, [string]$RunId = ([guid]::NewGuid().ToString()), [datetime]$Now = [datetime]::UtcNow,
          [int]$LookbackDays = 3, [switch]$DryRun, [scriptblock]$Log = { param($l, $m) }, [string]$DataModelRoot)
    $res = [ordered]@{ Status = ''; RunId = $RunId; CollectionTime = $null; Metrics = @(); Anomalies = @(); Learning = $true; EarlierRuns = 0; Lines = @(); Mailed = $false; MailNote = ''; MailState = ''; Problems = @(); NotRun = @() }
    if (-not $SettingsInvoke) { $SettingsInvoke = $Invoke }
    try {
        $settings = Get-SIDataQualitySettings -Globals $Globals
        foreach ($p in @($settings.Problems)) { & $Log 'WARN' ('data quality: ' + $p) }
        $has = 0; try { $has = [int](& $Invoke (Get-SIDataQualitySql 'Exists') @{} 'scalar') } catch { $has = 0 }
        if ($has -ne 1) {
            $res.Status = 'no-schema'
            & $Log 'INFO' 'data quality: the fingerprint tables are not in the database yet (setup and the updater apply sql\si-data-schema.sql) -- nothing measured this run'
            return [pscustomobject]$res
        }
        $fp = New-SIDataQualityFingerprint -Query $Query -Invoke $Invoke -LookbackDays $LookbackDays -DataModelRoot $DataModelRoot
        $res.Problems = @($fp.Problems); foreach ($p in @($fp.Problems)) { & $Log 'WARN' ('data quality: not measured -- ' + $p) }
        $res.NotRun = @($fp.NotRun); foreach ($p in @($fp.NotRun)) { & $Log 'INFO' ('data quality: not compared -- ' + $p) }
        $res.CollectionTime = $fp.CollectionTime
        if (-not @($fp.Metrics).Count) { $res.Status = 'nothing-measured'; & $Log 'INFO' 'data quality: no key number could be measured this run'; return [pscustomobject]$res }
        $history = @(ConvertFrom-SIDataQualityHistoryRows -Rows @(Read-SIDataQualityRows $Invoke (Get-SIDataQualitySql 'History') @{ Runs = ($script:SIDataQuality.Runs + 1) }))
        if ($history.Count -and $null -ne $fp.CollectionTime -and $history[0].CollectionTime) {
            $prevCt = ConvertTo-SIDataQualityUtc $history[0].CollectionTime
            if ($prevCt -and [math]::Abs(($prevCt - [datetime]$fp.CollectionTime).TotalSeconds) -lt 1) {
                $res.Status = 'same-collection'
                & $Log 'INFO' ('data quality: the Risk Analysis collection of {0:yyyy-MM-dd HH:mm} UTC was fingerprinted already -- nothing new to compare' -f [datetime]$fp.CollectionTime)
                return [pscustomobject]$res
            }
        }
        $metrics = @(Add-SIDataQualityZeros -Metrics @($fp.Metrics) -History $history -Unread @($fp.Unread))
        $res.Metrics = $metrics
        $cmp = Find-SIDataQualityAnomalies -Metrics $metrics -History $history -Settings $settings
        $res.Learning = [bool]$cmp.Learning; $res.EarlierRuns = [int]$cmp.EarlierRuns
        # ONE warning per source: the fields of one source that are filled less become one warning, the fields inside it
        $anomalies = @(Join-SIDataQualitySourceAnomalies -Anomalies @($cmp.Anomalies))
        $changes = @()
        if ($anomalies.Count) {
            # the window the likely cause is looked for in: since the last run WITHOUT a warning -- the previous run, unless
            # it warned too (a change made before yesterday's warning is still the cause of today's)
            $prev = if ($history.Count -and $history[0].ComputedAt) { ConvertTo-SIDataQualityUtc $history[0].ComputedAt } else { $null }
            $since = if ($prev) { $prev } else { $Now.AddDays(-1) }
            $sinceWords = 'the previous run'
            try {
                $good = & $Invoke (Get-SIDataQualitySql 'LastGood') @{} 'scalar'
                if ($good -is [datetime]) {
                    $goodUtc = ConvertTo-SIDataQualityUtc $good
                    if ($goodUtc -and $prev -and $goodUtc -lt $prev.AddSeconds(-1)) {
                        $since = $goodUtc
                        $sinceWords = 'the last run without a warning ({0} UTC)' -f $goodUtc.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant)
                    }
                }
            } catch { }
            try {
                $changes = @(Read-SIDataQualityRows $SettingsInvoke (Get-SIDataQualityChangeLogSql) @{ Since = $since; Until = $Now })
            } catch { & $Log 'WARN' ('data quality: the settings change log could not be read -- {0}' -f $_.Exception.Message) }
            foreach ($x in $anomalies) {
                $x.Cause = Get-SIDataQualityCause -Anomaly $x -Changes $changes -Since $sinceWords
                $x.CauseChangeIds = @(@((Get-SIDataQualityCauseChanges -Anomaly $x -Changes $changes).Relevant) | ForEach-Object { Get-SIDataQualityValue $_ 'ChangeId' } | Where-Object { $null -ne $_ })
            }
        }
        # classification incomplete: an absolute rule (any count above 0), from the first run on -- learning never hides it;
        # its cause is the groups (report / asset type), never the settings window
        $classGaps = @(Find-SIDataQualityClassificationGaps -Metrics $metrics -Groups $fp.ClassGroups)
        if ($classGaps.Count) { $anomalies = @(@($classGaps) + @($anomalies)) }
        $res['ClassificationIssue'] = Get-SIDataQualityClassificationIssue -Anomalies $classGaps
        $res.Anomalies = $anomalies
        $culture = if (Get-Command -Name Get-SIGuardCulture -ErrorAction SilentlyContinue) { Get-SIGuardCulture -Globals $Globals } else { [System.Globalization.CultureInfo]::InvariantCulture }
        $res.Lines = @(Get-SIDataQualitySummaryLines -Anomalies $anomalies -Culture $culture)
        if ($cmp.Learning) {
            & $Log 'INFO' ('data quality: {0} key numbers measured; learning ({1} earlier run(s), 3 are needed before anything is compared)' -f $metrics.Count, $cmp.EarlierRuns)
            foreach ($l in @(Get-SIDataQualityRunHealthLines -Anomalies $classGaps -Culture $culture)) { & $Log 'WARN' $l }
        }
        elseif (-not $anomalies.Count) { & $Log 'OK' ('data quality: {0} key numbers measured, all within the expected range of the last 3 runs' -f $metrics.Count) }
        else { foreach ($l in $res.Lines) { & $Log 'WARN' $l } }
        $res.Status = if ($anomalies.Count) { 'anomalies' } elseif ($cmp.Learning) { 'learning' } else { 'ok' }
        if ($DryRun) { $res.MailNote = 'dry run: nothing stored or sent'; return [pscustomobject]$res }

        # store the run, its numbers and its anomalies
        $largest = $null; if ($anomalies.Count) { $largest = [double]$anomalies[0].ChangePct }
        $null = & $Invoke (Get-SIDataQualitySql 'InsertRun') @{ RunId = $RunId; CollectionTime = $(if ($fp.CollectionTime) { [datetime]$fp.CollectionTime } else { [System.DBNull]::Value }); ComputedAt = $Now
            Metrics = $metrics.Count; Anomalies = $anomalies.Count; Learning = [bool]$cmp.Learning; EarlierRuns = [int]$cmp.EarlierRuns; LargestDeltaPct = $(if ($null -ne $largest) { $largest } else { [System.DBNull]::Value }) } 'nonquery'
        $mj = '[' + ((@($metrics | ForEach-Object { [ordered]@{ k = $_.Key; t = $_.Kind; l = $_.Label; v = [double]$_.Value; s = $_.Step } | ConvertTo-Json -Compress })) -join ',') + ']'
        $null = & $Invoke (Get-SIDataQualitySql 'InsertMetrics') @{ RunId = $RunId; j = $mj } 'scalar'
        # the likely cause as rows: the settings changes of the window, and which of them concern which number -- written
        # BEFORE the anomalies, so a run whose anomalies are stored has its causes too. A database without the two tables
        # (not updated yet) keeps the cause as the text on the anomaly; a failure here is said and never stops the rest.
        if ($anomalies.Count -and @($changes).Count) {
            try {
                $hasCause = 0; try { $hasCause = [int](& $Invoke (Get-SIDataQualitySql 'CauseTables') @{} 'scalar') } catch { $hasCause = 0 }
                $rowsOf = @($changes | Where-Object { $null -ne (Get-SIDataQualityValue $_ 'ChangeId') -and (ConvertTo-SIDataQualityUtc (Get-SIDataQualityValue $_ 'ChangedAt')) })
                if ($hasCause -eq 1 -and $rowsOf.Count) {
                    $cj = '[' + ((@($rowsOf | ForEach-Object {
                        [ordered]@{ id = [long](Get-SIDataQualityValue $_ 'ChangeId'); n = [string](Get-SIDataQualityValue $_ 'Name'); s = [string](Get-SIDataQualityValue $_ 'Scope'); k = [string](Get-SIDataQualityValue $_ 'Kind')
                            a = [string](Get-SIDataQualityValue $_ 'Action'); at = (ConvertTo-SIDataQualityUtc (Get-SIDataQualityValue $_ 'ChangedAt')).ToString('yyyy-MM-ddTHH:mm:ss', $script:SIDataQuality.Invariant)
                            by = [string](Get-SIDataQualityValue $_ 'ChangedBy') } | ConvertTo-Json -Compress
                    })) -join ',') + ']'
                    $null = & $Invoke (Get-SIDataQualitySql 'InsertChanges') @{ RunId = $RunId; j = $cj } 'scalar'
                    $links = @(foreach ($x in $anomalies) { foreach ($id in @($x.CauseChangeIds)) { [ordered]@{ k = [string]$x.Key; id = [long]$id } | ConvertTo-Json -Compress } })
                    if ($links.Count) { $null = & $Invoke (Get-SIDataQualitySql 'InsertCauses') @{ RunId = $RunId; j = ('[' + ($links -join ',') + ']') } 'scalar' }
                }
            } catch { & $Log 'WARN' ('data quality: the settings changes behind the warnings were not stored -- {0}. The warnings keep their likely cause as text.' -f $_.Exception.Message) }
        }
        # the fields inside a one-per-source warning -- written BEFORE the anomalies, like the causes. A database without the
        # table (not updated yet) keeps the warning itself; a failure here is said and never stops the rest.
        $fieldRows = @(foreach ($x in $anomalies) { foreach ($f in @(Get-SIDataQualityFields $x)) {
            $e = @($f.Earlier)
            [ordered]@{ k = [string]$x.Key; f = [string]$f.Key; l = [string]$f.Label; e1 = $e[0]; e2 = $e[1]; e3 = $e[2]; x = [double]$f.Expected; v = [double]$f.Now; c = [double]$f.ChangePct } | ConvertTo-Json -Compress
        } })
        if ($fieldRows.Count) {
            try {
                $hasFields = 0; try { $hasFields = [int](& $Invoke (Get-SIDataQualitySql 'FieldTable') @{} 'scalar') } catch { $hasFields = 0 }
                if ($hasFields -eq 1) { $null = & $Invoke (Get-SIDataQualitySql 'InsertFields') @{ RunId = $RunId; j = ('[' + ($fieldRows -join ',') + ']') } 'scalar' }
                else { & $Log 'INFO' 'data quality: the table for the fields inside a warning is not in the database yet (setup and the updater apply sql\si-data-schema.sql) -- the warning is stored without its list of fields' }
            } catch { & $Log 'WARN' ('data quality: the fields inside the warnings were not stored -- {0}. The warnings themselves are stored.' -f $_.Exception.Message) }
        }
        if ($anomalies.Count) {
            $aj = '[' + ((@($anomalies | ForEach-Object {
                $e = @($_.Earlier)
                [ordered]@{ k = $_.Key; t = $_.Kind; l = $_.Label; d = $_.Direction; r = $_.Rule; e1 = $e[0]; e2 = $e[1]; e3 = $e[2]; x = [double]$_.Expected; v = [double]$_.Now; c = [double]$_.ChangePct; why = $_.Cause; s = $_.Step } | ConvertTo-Json -Compress
            })) -join ',') + ']'
            $null = & $Invoke (Get-SIDataQualitySql 'InsertAnomalies') @{ RunId = $RunId; j = $aj } 'scalar'
        }

        # THE MAIL -- only when the warnings differ from the last run that was MAILED (a new warning, or one that is gone;
        # all gone = one "back to normal" mail), and at most one a day. Why no mail went out is kept on the run
        # (MailState), so the panel says it. A run still learning compares nothing, so it never mails.
        $skip = {
            param([string]$state, [string]$note, [string]$level = 'INFO')
            $res.MailNote = $note; $res.MailState = $state
            & $Log $level ('data quality: ' + $note)
            if ($state) { try { $null = & $Invoke (Get-SIDataQualitySql 'MarkNotMailed') @{ RunId = $RunId; MailState = $state } 'nonquery' } catch { } }
        }
        # a run still learning compares nothing, so it mails only what the absolute rule found (classification incomplete) --
        # or that such a warning the last mail carried is gone
        $lastMailed = $null
        $readLast = {
            try { ConvertFrom-SIDataQualityLastMailedRows -Rows @(Read-SIDataQualityRows $Invoke (Get-SIDataQualitySql 'LastMailed') @{ RunId = $RunId }) }
            catch { & $Log 'WARN' ('data quality: the last mailed run could not be read -- {0}. This run is treated as if no mail went out yet.' -f $_.Exception.Message); $null }
        }
        if ($cmp.Learning) {
            if ($classGaps.Count -or -not $settings.MailEnabled) { }
            else {
                $lastMailed = & $readLast
                $hadGap = $lastMailed -and $lastMailed.Keys -is [System.Collections.IDictionary] -and @($lastMailed.Keys.Keys | Where-Object { "$_" -like 'classgap.*' }).Count
                if (-not $hadGap) { return [pscustomobject]$res }
            }
        }
        if (-not $settings.MailEnabled) {
            if ($anomalies.Count) { & $skip 'off' 'the data-quality mail is off (SI_Pro_DataQuality_Mail_Enabled)' }
            return [pscustomobject]$res
        }
        if ($null -eq $lastMailed) { $lastMailed = & $readLast }
        $diff = Compare-SIDataQualityMailSet -Anomalies $anomalies -LastMailed $lastMailed -Unread @($fp.Unread)
        if (-not $diff.Changed) {
            # nothing to say: no warning now and none mailed -- or the same warnings as the last mail
            if ($anomalies.Count) {
                $of = if ($lastMailed -and $lastMailed.ComputedAt) { 'the mail of the run of {0} UTC' -f $lastMailed.ComputedAt.ToString('yyyy-MM-dd HH:mm', $script:SIDataQuality.Invariant) } else { 'the last mail' }
                & $skip 'unchanged' ('nothing changed since {0} -- no new mail; the panel shows this run' -f $of)
            }
            return [pscustomobject]$res
        }
        $dayStart = $Now.Date
        $sentToday = 0; try { $sentToday = [long](& $Invoke (Get-SIDataQualitySql 'MailedToday') @{ DayStart = $dayStart } 'scalar') } catch { }
        if ($sentToday -gt 0) { & $skip 'day-limit' 'a data-quality mail went out today already -- the panel shows this run; the next run mails what is different then'; return [pscustomobject]$res }
        if (-not $Send) { $res.MailNote = 'no mail transport in this session'; return [pscustomobject]$res }
        $admins = @()
        if (Get-Command -Name Get-SIGuardSql -ErrorAction SilentlyContinue) { try { $admins = @(Read-SIDataQualityRows $SettingsInvoke (Get-SIGuardSql 'SuperAdmins') @{} | ForEach-Object { [string](Get-SIDataQualityValue $_ 'Mail') }) } catch { } }
        $rcp = Get-SIDataQualityRecipients -Globals $Globals -MailTo $settings.MailTo -SuperAdminMails $admins
        if (-not @($rcp.To).Count) { & $skip 'no-recipients' 'the data-quality mail has no recipients (set SI_Pro_DataQuality_Mail_To, SI_GuardMail_To or MailTo) -- not sent' 'WARN'; return [pscustomobject]$res }
        $tag = if (Get-Command -Name Get-SIGuardTenantTag -ErrorAction SilentlyContinue) { Get-SIGuardTenantTag -Globals $Globals } else { '' }
        $lastAt = if ($lastMailed) { $lastMailed.ComputedAt } else { $null }
        $mail = if ($anomalies.Count) {
            ConvertTo-SIDataQualityMail -Anomalies $anomalies -CollectionTime $fp.CollectionTime -WebBaseUrl $settings.WebBaseUrl -TenantTag $tag -Culture $culture -RunId $RunId `
                -Entered @($diff.Entered) -Left @($diff.Left) -LastMail $lastAt
        } else {
            ConvertTo-SIDataQualityNormalMail -Left @($diff.Left) -CollectionTime $fp.CollectionTime -LastMail $lastAt -WebBaseUrl $settings.WebBaseUrl -TenantTag $tag -RunId $RunId
        }
        $ok = $false
        try { $ok = [bool](& $Send @($rcp.To) $mail.Subject $mail.Html) } catch { & $Log 'WARN' ('data quality: the mail was not sent -- {0}' -f $_.Exception.Message) }
        $res.Mailed = $ok
        $res.MailState = if ($ok) { 'sent' } else { 'failed' }
        $res.MailNote = if ($ok) { $(if ($anomalies.Count) { 'mailed to ' } else { 'back to normal: mailed to ' }) + (@($rcp.To) -join ', ') } else { 'the mail was not sent' }
        try { $null = & $Invoke (Get-SIDataQualitySql 'MarkMailed') @{ RunId = $RunId; MailTo = (@($rcp.To) -join ';'); MailState = $(if ($ok) { 'sent' } else { 'failed' }) } 'nonquery' } catch { }
        & $Log $(if ($ok) { 'OK' } else { 'WARN' }) ('data quality: ' + $res.MailNote)
    } catch {
        $res.Status = 'error'
        $res.MailNote = $_.Exception.Message
        & $Log 'WARN' ('data quality: not completed this run -- {0}. Nothing was blocked.' -f $_.Exception.Message)
    }
    [pscustomobject]$res
}
