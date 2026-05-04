#Requires -Version 5.1
<#
    Build-RiskAnalysis.ps1

    Authoring driver for the v2.2 Risk Analysis catalog.

    Pipeline (default = full rebuild):
      1. For every <Domain>_Locked.yaml under _source/, regenerate its
         <Domain>_Detailed_Locked.yaml sibling. The Detailed sibling
         preserves the same WHERE filters but expands OutputPropertyOrder
         with per-engine columns so dashboards can drill from Summary
         counts to the underlying asset list.
      2. Concatenate every Summary + Detailed YAML in _source/ into the
         single consolidated file the SecurityInsight_RiskAnalysis engine
         reads:
           v2.2/risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml
      3. Append two ReportTemplates at the bottom of that file
         (RiskAnalysis_Summary_Bucket + RiskAnalysis_Detailed_Bucket)
         which list every Summary / Detailed report. Templates drive the
         engine's output dispatch (XLSX bucket files etc.) -- v2.1 had
         them hand-maintained; here they're auto-generated from the
         catalog so they can never drift from Reports[].

    Switches:
      -SummaryOnly     skip step 1 entirely AND exclude Detailed yamls
                       in step 2 (locked file = Summary-only)
      -SkipDetailedGen skip step 1; step 2 still includes any Detailed
                       siblings already on disk
      -DetailedOnly    do step 1 only; do not rebuild the locked file

    Authoring loop:
      1. Edit a domain Summary in _source/<Domain>_Locked.yaml
      2. Run this script (no args = full rebuild)
      3. Commit
      4. Engine picks up changes on next run -- no engine code change.

    Engine contract (matches today, unchanged):
      <SettingsPath>/RiskAnalysis_Queries_Locked.yaml
      <SettingsPath>/RiskAnalysis_Queries_Custom.yaml
    Operator flips v2.1 -> v2.2 by re-pointing $global:SettingsPath at
    v2.2/risk-analysis-detection/.
#>

[CmdletBinding()]
param(
    [string]$SourceDir   = (Join-Path (Split-Path -Parent $PSScriptRoot) '_source'),
    [string]$LockedDir   = (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'risk-analysis-detection'),
    [string]$OutputFile  = $null,
    [switch]$SummaryOnly,
    [switch]$SkipDetailedGen,
    [switch]$DetailedOnly
)

if (-not (Get-Module -Name powershell-yaml)) {
    Import-Module powershell-yaml -Force -ErrorAction Stop
}
if (-not $OutputFile) {
    $OutputFile = Join-Path $LockedDir 'RiskAnalysis_Queries_Locked.yaml'
}

# ----------------------------------------------------------------------------
# Helpers used by both Step 1 (Detailed gen) and Step 2 (Consolidator).
# ----------------------------------------------------------------------------

# cosmetic post-processor -- inserts a blank line before each
# `- ReportName:` so reports are visually separated in the locked yaml.
# Skips the very first report (no blank line right after `Reports:`).
# Operates on the SERIALIZED yaml string, not the in-memory object.
function _SeparateReportsWithBlankLines([string]$yaml) {
    if ([string]::IsNullOrWhiteSpace($yaml)) { return $yaml }
    # Match `\n- ReportName:` (top-level list item start). Replace with `\n\n- ReportName:`.
    # The first occurrence might come right after `Reports:\n` -- that gets a blank
    # line too, which is fine cosmetically (and signals the start of the list).
    return ($yaml -replace "(?m)^- ReportName:", "`n- ReportName:")
}

# enforce legacy YAML key order for every report -- ReportName +
# ReportPurpose appear first, then SecurityDomain, then everything else.
# Matches v2.1 RiskAnalysis_Queries_Locked.yaml format so
# existing tooling (XLSX writers, dashboards, search-by-name) keeps working.
function _ReorderReportKeys {
    param([Parameter(Mandatory)]$Report)
    # full v2.1 legacy key order (per user direction). Every report
    # emits its keys in this exact order; any extra keys not listed here append
    # at the end alphabetically.
    $canonicalOrder = @(
        'ReportName',
        'ReportPurpose',
        'SecurityDomain',
        'CategoryInputName',
        'SubcategoryInputName',
        'ConfigurationIdInputName',
        'SecuritySeverityInputName',
        'CriticalityTierLevelInputName',
        'RiskConsequenceScoreOutputName',
        'RiskProbabilityScoreOutputName',
        'RiskScoreOutputName',
        'CriticalityTierLevelScope',
        'SecuritySeverityScope',
        'OutputPropertyOrder',
        'SortBy',
        'ReportQuery'
    )
    $ordered = [ordered]@{}
    $allKeys = if ($Report -is [System.Collections.IDictionary]) { @($Report.Keys) } else { @($Report.PSObject.Properties.Name) }
    foreach ($k in $canonicalOrder) {
        if ($allKeys -contains $k) {
            $v = if ($Report -is [System.Collections.IDictionary]) { $Report[$k] } else { $Report.$k }
            $ordered[$k] = $v
        }
    }
    # Any keys not in the canonical list (e.g. ReportTemplate per-report block,
    # or future fields) -- append at end in their original encounter order.
    foreach ($k in $allKeys) {
        if ($ordered.Contains($k)) { continue }
        $v = if ($Report -is [System.Collections.IDictionary]) { $Report[$k] } else { $Report.$k }
        $ordered[$k] = $v
    }
    return [pscustomobject]$ordered
}

# CMDB integration is OPTIONAL. Customers without
# $global:SI_EnableCmdbProvider have no cmdb* columns on their Profile_CL
# rows. Bare references like `cmdbDataSensitivity` would fail with KQL
# parse-time error "column not found".
#
# Defensive injection: at the TOP of every query that targets a Profile_CL
# table, alias each cmdb* column through column_ifexists so the rest of the
# query treats them as always-defined. If the column exists -> uses real
# value. If it doesn't -> empty string. Either way KQL parses + runs.
function _InjectCmdbDefensiveExtends([string]$kql) {
    if ($kql -match '__SI_CMDB_DEFENSIVE__') { return $kql }   # idempotent
    if ($kql -notmatch 'SI_\w+_Profile_CL') { return $kql }    # only Profile-targeting queries
    # Find the line that ends with `summarize arg_max(CollectionTime, *) by PrimaryEntityId`
    # and inject after.
    $marker = 'summarize arg_max(CollectionTime, *) by PrimaryEntityId'
    $idx = $kql.IndexOf($marker)
    if ($idx -lt 0) { return $kql }
    $endOfLine = $kql.IndexOf("`n", $idx)
    if ($endOfLine -lt 0) { $endOfLine = $kql.Length }
    $inject = "`n        | extend cmdbId               = tostring(column_ifexists('cmdbId', ''))" + `
              "`n        | extend cmdbName             = tostring(column_ifexists('cmdbName', ''))" + `
              "`n        | extend cmdbCriticality      = tostring(column_ifexists('cmdbCriticality', ''))" + `
              "`n        | extend cmdbDataSensitivity  = tostring(column_ifexists('cmdbDataSensitivity', ''))" + `
              "`n        | extend CmdbMatchPhase           = tostring(column_ifexists('CmdbMatchPhase', ''))" + `
              "`n        | extend CmdbMatchState           = tostring(column_ifexists('CmdbMatchState', ''))   // __SI_CMDB_DEFENSIVE__"
    return $kql.Substring(0, $endOfLine) + $inject + $kql.Substring($endOfLine)
}

# ----------------------------------------------------------------------------
# Step 1 -- Detailed-sibling generator
# ----------------------------------------------------------------------------

# Engine-specific extra columns the Detailed sibling pulls per row.
$extraDetailCols = @{
    'Identity'    = @('IdentityType','SecurityPrincipalType','AccountEnabled','LastSignInDateTime','LastPasswordChangeDateTime','EntraRoles_Permanent','EntraRoles_Eligible','EntraAppPermissions_Application','HasNoMfa','IsHighRiskPermissionGrant','RiskFactorCount','MfaState','PasswordPolicies','EmployeeId','Department','Country','MoreInfoUrl','Links')
    'Endpoint'    = @('Hostname','OsPlatform','OsVersion','MachineGroup','SensorHealthState','OnboardingStatus','EdrMode','RiskScore','ExposureLevel','EgLastSeen','EffectiveIpAddresses','PublicIp','DefenderAvStatus','UnsupportedOSDetected','UnsupportedOSReason','RiskFactorCount','MoreInfoUrl','Links')
    'Azure'       = @('ResourceType','Location','ResourceGroup','AzureSubscriptionId','cmdbName','cmdbCriticality','cmdbDataSensitivity','CmdbMatchPhase','IsPubliclyExposed','HasOpenAdminPort','HasNoSoftDelete','UnencryptedTraffic','RiskFactorCount','MoreInfoUrl','Links')
    'CrossEngine' = @('Engine','LinkedAzureResourceId','MoreInfoUrl','Links')
    'Hygiene'     = @('Engine','MoreInfoUrl','Links')
}

if ($SummaryOnly) {
    Write-Host "[1/2] Skipping Detailed generation (-SummaryOnly)"
} elseif ($SkipDetailedGen) {
    Write-Host "[1/2] Skipping Detailed generation (-SkipDetailedGen)"
} else {
    Write-Host "[1/2] Generating Detailed companions from $SourceDir..."
    $summarySources = @(Get-ChildItem $SourceDir -Filter '*_Locked.yaml' -File |
        Where-Object { $_.Name -notmatch 'Detailed' })
    foreach ($f in $summarySources) {
        try {
            $y = ConvertFrom-Yaml -Yaml (Get-Content $f.FullName -Raw)
        } catch {
            Write-Warning ("  skip {0} (parse error): {1}" -f $f.Name, $_.Exception.Message)
            continue
        }
        $detailed = New-Object System.Collections.ArrayList
        foreach ($r in @($y.Reports)) {
            if ($r.ReportName -match 'Detailed') { continue }
            $extras = $extraDetailCols[$r.SecurityDomain]
            if (-not $extras) { $extras = @('MoreInfoUrl','Links') }
            $detailedReport = [ordered]@{
                # drop legacy `_v22` -> `_Detailed_v22` rename. Source
                # files no longer carry the `_v22` suffix (per the no-version-in-names
                # feedback rule). Detailed companion just appends `_Detailed`.
                ReportName            = ([string]$r.ReportName + '_Detailed')
                ReportPurpose         = ('[Detailed companion] ' + [string]$r.ReportPurpose)
                SecurityDomain        = $r.SecurityDomain
                CategoryInputName     = $r.CategoryInputName
                SubcategoryInputName  = $r.SubcategoryInputName
                ConfigurationIdInputName     = $r.ConfigurationIdInputName
                SecuritySeverityInputName    = $r.SecuritySeverityInputName
                CriticalityTierLevelInputName= $r.CriticalityTierLevelInputName
                RiskConsequenceScoreOutputName = $r.RiskConsequenceScoreOutputName
                RiskProbabilityScoreOutputName = $r.RiskProbabilityScoreOutputName
                RiskScoreOutputName            = $r.RiskScoreOutputName
                CriticalityTierLevelScope      = $r.CriticalityTierLevelScope
                SecuritySeverityScope          = $r.SecuritySeverityScope
                OutputPropertyOrder            = (@($r.OutputPropertyOrder) + $extras | Select-Object -Unique)
                SortBy                         = $r.SortBy
                ReportQuery                    = $r.ReportQuery
            }
            [void]$detailed.Add((_ReorderReportKeys ([pscustomobject]$detailedReport)))
        }
        $outName = ($f.BaseName -replace '_Locked$','_Detailed_Locked.yaml')
        if ($outName -notmatch '\.yaml$') { $outName = $outName + '.yaml' }
        $outPath = Join-Path $SourceDir $outName
        $yamlOut = ConvertTo-Yaml -Data ([ordered]@{ Reports = $detailed.ToArray() })
        $yamlOut = _SeparateReportsWithBlankLines $yamlOut
        Set-Content -LiteralPath $outPath -Value $yamlOut -Encoding UTF8
        Write-Host ("      {0,-58}  {1,3} Detailed reports" -f $outName, $detailed.Count)
    }
}

if ($DetailedOnly) {
    Write-Host ""
    Write-Host "[2/2] Skipping locked-file rebuild (-DetailedOnly)"
    return
}

# ----------------------------------------------------------------------------
# Step 2 -- Consolidator
# ----------------------------------------------------------------------------

Write-Host ""
Write-Host "[2/2] Consolidating _source -> $OutputFile"

# enforce legacy YAML key order for every report -- ReportName +
# ReportPurpose appear first, then SecurityDomain, then everything else.
# Matches v2.1 RiskAnalysis_Queries_Locked.yaml format so
# existing tooling (XLSX writers, dashboards, search-by-name) keeps working.
$summaryFiles  = @(Get-ChildItem $SourceDir -Filter '*_Locked.yaml' -File |
    Where-Object { $_.Name -notmatch 'Detailed' })
$detailedFiles = if ($SummaryOnly) {
    @()
} else {
    @(Get-ChildItem $SourceDir -Filter '*_Detailed_Locked.yaml' -File)
}
$inputFiles = @($summaryFiles) + @($detailedFiles)
if ($inputFiles.Count -eq 0) { throw "No *_Locked.yaml files found under $SourceDir" }

$allReports = New-Object System.Collections.ArrayList

# Auto-inject bucket support per Report. v2.2 catalog uses bucketing
# universally (it scales to large fleets). Source yamls do NOT need to
# pre-include __BUCKET_FILTER__ -- the build inserts it. Bucket key is
# selected per SecurityDomain:
#   Endpoint    -> coalesce(AzureResourceId, MdeDeviceId, DisplayName)
#   Identity    -> coalesce(AppId, Upn, DisplayName)
#   Azure       -> coalesce(AzureResourceId, Name)
#   CrossEngine -> coalesce(AzureResourceId, Upn, AppId)
#   Hygiene     -> strcat(coalesce(Engine,''), ':', coalesce(ConfigurationId,''))
function _BucketKeyKql([string]$domain) {
    switch -Wildcard ($domain) {
        'Endpoint'    { 'coalesce(tostring(column_ifexists("AzureResourceId","")), tostring(column_ifexists("MdeDeviceId","")), tostring(column_ifexists("DisplayName","")))' }
        'Identity'    { 'coalesce(tostring(column_ifexists("AppId","")), tostring(column_ifexists("Upn","")), tostring(column_ifexists("DisplayName","")))' }
        'Azure'       { 'coalesce(tostring(column_ifexists("AzureResourceId","")), tostring(column_ifexists("Name","")))' }
        'CrossEngine' { 'coalesce(tostring(column_ifexists("AzureResourceId","")), tostring(column_ifexists("Upn","")), tostring(column_ifexists("AppId","")))' }
        'Hygiene'     { 'strcat(tostring(column_ifexists("Engine","")), ":", tostring(column_ifexists("ConfigurationId","")))' }
        default       { 'tostring(column_ifexists("ConfigurationId",""))' }
    }
}

# Inject `| extend DeviceKey = <key>` + `__BUCKET_FILTER__` right before
# the FINAL `| project ` clause. Skipped if the query already contains
# the placeholder (author opted-in manually) or no `| project ` is found.
function _InjectBucketSupport([string]$kql, [string]$domain) {
    if ($kql -match '__BUCKET_FILTER__') { return $kql }
    $bucketKey = _BucketKeyKql $domain
    $injection = ("| extend DeviceKey = {0}`n        __BUCKET_FILTER__`n" -f $bucketKey)
    # Inject BEFORE the last `| project ` clause (preserves all upstream filters)
    $idx = $kql.LastIndexOf('| project ')
    if ($idx -lt 0) {
        # No project clause -- append at end
        return ($kql + "`n        " + $injection)
    }
    return $kql.Substring(0, $idx) + $injection + '        ' + $kql.Substring($idx)
}

# declarative risk-score model lives in
# v2.2/risk-analysis-detection/riskscore_weighted.schema.custom.json. The consolidator reads
# it once + emits matching KQL for the four mapper tokens substituted into
# every report (severity, tier, cmdb-weight, risk-factor-detailed).
$script:_RiskScoreModel = $null
function _GetRiskScoreModel {
    if ($null -ne $script:_RiskScoreModel) { return $script:_RiskScoreModel }
    # schema lives at risk-analysis-detection/riskscore_weighted.schema.custom.json
    # (single file, customer-editable). 4 ups from tools/ -> v2.2 root, then sibling.
    $modelPath = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'risk-analysis-detection/riskscore_weighted.schema.custom.json'
    if (-not (Test-Path -LiteralPath $modelPath)) {
        Write-Warning "[risk-score] $modelPath not found -- mapper tokens won't be substituted"
        $script:_RiskScoreModel = $null
        return $null
    }
    $script:_RiskScoreModel = Get-Content -Raw -LiteralPath $modelPath | ConvertFrom-Json

    # schema is a single customer-editable file (no separate
    # locked + custom merge anymore). $modelPath above IS the customer file.
    # config $global:SI_RiskAnalysis_RiskScoreModelOverride still applies
    # for in-process overrides set by launcher / custom.ps1.
    if ($global:SI_RiskAnalysis_RiskScoreModelOverride) {
        Write-Host '      risk-score: applying $global:SI_RiskAnalysis_RiskScoreModelOverride from config'
        # Shallow merge of override block onto shipped model (customer can flip
        # whole sections like severityMapper).
        $ovr = $global:SI_RiskAnalysis_RiskScoreModelOverride
        foreach ($k in $ovr.PSObject.Properties.Name) {
            $script:_RiskScoreModel | Add-Member -MemberType NoteProperty -Name $k -Value $ovr.$k -Force
        }
    }
    return $script:_RiskScoreModel
}

# Build the KQL case() block for the severity-impact threshold mapper.
function _BuildSeverityMapperKql($model) {
    if (-not $model -or -not $model.severityMapper) { return $null }
    $m = $model.severityMapper
    $col = [string]$m.sourceColumn
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $arms = New-Object System.Collections.ArrayList
    foreach ($t in $m.thresholds) {
        $minStr = ([double]$t.min).ToString($inv)
        [void]$arms.Add(("toreal({0}) >= {1}, `"{2}`"" -f $col, $minStr, [string]$t.label))
    }
    [void]$arms.Add(('"' + ([string]$m.default) + '"'))
    return ('case({0})' -f ($arms -join ', '))
}

# Build the KQL case() block for the tier-to-label mapper.
function _BuildTierMapperKql($model) {
    if (-not $model -or -not $model.tierMapper) { return $null }
    $m = $model.tierMapper
    $col = [string]$m.sourceColumn
    $arms = New-Object System.Collections.ArrayList
    foreach ($p in $m.valueMap.PSObject.Properties) {
        [void]$arms.Add(("toint({0}) == {1}, `"{2}`"" -f $col, ([int]$p.Name), [string]$p.Value))
    }
    [void]$arms.Add(('"' + ([string]$m.default) + '"'))
    return ('case({0})' -f ($arms -join ', '))
}

# Build the KQL case() block for the criticality-multiplier mapper.
# Sources from cmdbCriticality ONLY. When CMDB integration is off OR
# cmdbCriticality is null/empty, the multiplier defaults to 1.0 (no
# amplification) -- so engine's WeightedRiskScore = RiskScore in that case.
function _BuildCriticalityMultiplierKql($model) {
    if (-not $model -or -not $model.criticalityMultiplierMapper) { return '1.0' }
    $m = $model.criticalityMultiplierMapper
    $col = [string]$m.sourceColumn
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $arms = New-Object System.Collections.ArrayList
    foreach ($p in $m.valueMap.PSObject.Properties) {
        $valStr = ([double]$p.Value).ToString($inv)
        [void]$arms.Add(("tostring(column_ifexists(`"{0}`",`"`")) == `"{1}`", {2}" -f $col, [string]$p.Name, $valStr))
    }
    [void]$arms.Add((([double]$m.default).ToString($inv)))
    return ('case({0})' -f ($arms -join ', '))
}

# Build the KQL coalesce(toreal, case, default) for impact normalization.
# Handles: numeric Impact, string severity ("Critical"/"High"/...), free-text, null.
function _BuildImpactNormalizerKql($model) {
    if (-not $model -or -not $model.impactNormalizer) {
        # Safe fallback if impactNormalizer block isn't in the model.
        return 'todouble(coalesce(toreal(column_ifexists("Impact", real(null))), 0.0))'
    }
    $m = $model.impactNormalizer
    $col = [string]$m.sourceColumn
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $stringArms = New-Object System.Collections.ArrayList
    foreach ($p in $m.stringMap.PSObject.Properties) {
        $valStr = ([double]$p.Value).ToString($inv)
        [void]$stringArms.Add(("tolower(tostring(column_ifexists(`"{0}`", `"`"))) == `"{1}`", {2}" -f $col, ([string]$p.Name).ToLowerInvariant(), $valStr))
    }
    $defaultStr = ([double]$m.default).ToString($inv)
    [void]$stringArms.Add($defaultStr)
    return ('coalesce(toreal(column_ifexists("{0}", real(null))), case({1}))' -f $col, ($stringArms -join ', '))
}

# Read the matching profile schema and return all bool fields with purpose=risk.
# These are auto-included in BOTH RiskFactor_Probability_Detailed AND RiskFactor_Probability.
$script:_ProfileSchemaCache = @{}
function _GetProfileRiskBoolFields([string]$engine) {
    $key = $engine.ToLowerInvariant()
    if ($script:_ProfileSchemaCache.ContainsKey($key)) { return $script:_ProfileSchemaCache[$key] }
    $schemaPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ('asset-profiling-schema/' + $key + '.schema.locked.json')
    $auto = New-Object System.Collections.ArrayList
    if (Test-Path -LiteralPath $schemaPath) {
        try {
            $schema = Get-Content -Raw -LiteralPath $schemaPath | ConvertFrom-Json
            foreach ($f in $schema.fields) {
                if ($f.type -eq 'bool' -and $f.purpose -eq 'risk') {
                    [void]$auto.Add([string]$f.name)
                }
            }
        } catch {
            Write-Warning ("[risk-score] failed to parse {0}: {1}" -f $schemaPath, $_.Exception.Message)
        }
    }
    $script:_ProfileSchemaCache[$key] = @($auto)
    return @($auto)
}

# Combined field list for an engine: auto (purpose=risk from schema) + explicit perEngineFields + customer extras.
# Dedup, order: auto first, then explicit, then customer.
function _GetRiskFactorFields($model, [string]$engine) {
    $key = $engine.ToLowerInvariant()
    $combined = New-Object System.Collections.ArrayList
    foreach ($f in (_GetProfileRiskBoolFields $key)) { [void]$combined.Add($f) }
    if ($model -and $model.riskFactorDetailedMapper -and $model.riskFactorDetailedMapper.perEngineFields) {
        foreach ($p in $model.riskFactorDetailedMapper.perEngineFields.PSObject.Properties) {
            if ($p.Name.ToLowerInvariant() -eq $key) {
                foreach ($f in @($p.Value)) {
                    if ($combined -notcontains $f) { [void]$combined.Add([string]$f) }
                }
                break
            }
        }
    }
    if ($global:SI_RiskAnalysis_RiskFactorFieldsExtra) {
        $extra = $global:SI_RiskAnalysis_RiskFactorFieldsExtra
        if ($extra -is [System.Collections.IDictionary] -and $extra.Contains($key)) {
            foreach ($f in @($extra[$key])) {
                if ($combined -notcontains $f) { [void]$combined.Add([string]$f) }
            }
        }
    }
    return @($combined)
}

# Build the KQL strcat_array(pack_array(...)) block for per-engine risk-factor-detailed.
function _BuildRiskFactorDetailedKql($model, [string]$engine) {
    $fields = _GetRiskFactorFields $model $engine
    if (-not $fields -or $fields.Count -eq 0) { return '""' }
    $packArgs = New-Object System.Collections.ArrayList
    foreach ($f in $fields) {
        [void]$packArgs.Add(("iff(tobool(column_ifexists(`"{0}`", false)) == true, `"{0}`", `"`")" -f $f))
    }
    return ('strcat_array(pack_array({0}), ", ")' -f ($packArgs -join ', '))
}

# Build the KQL sum-of-iffs block that counts how many of the SAME field list fired.
# Stays in sync with _BuildRiskFactorDetailedKql automatically.
function _BuildRiskFactorProbabilityKql($model, [string]$engine) {
    $fields = _GetRiskFactorFields $model $engine
    if (-not $fields -or $fields.Count -eq 0) { return '0' }
    $arms = New-Object System.Collections.ArrayList
    foreach ($f in $fields) {
        [void]$arms.Add(("toint(iff(tobool(column_ifexists(`"{0}`", false)) == true, 1, 0))" -f $f))
    }
    return ($arms -join ' + ')
}

# canonical risk-score injection. Replaces _InjectWeightedScore.
#
# For every report whose KQL has a final `| project ...` clause:
#   1. Build the 6 mapper KQL blocks from riskscore_weighted.schema.json.
#   2. Insert canonical extends BEFORE the final project so all canonical
#      output columns exist when the project runs:
#         | extend Impact                            = <impactNormalizer>
#         | extend SecuritySeverity                  = <severityMapper>
#         | extend CriticalityTier                   = toint(coalesce(Tier, 999))
#         | extend CriticalityTierLevel              = <tierMapper>
#         | extend RiskFactor_Consequence            = 0
#         | extend RiskFactor_Probability            = <riskFactorProbabilityMapper> (sum-of-iffs)
#         | extend RiskFactor_Probability_Detailed   = <riskFactorDetailedMapper>
#         | extend RiskFactor_Weight                 = <cmdbWeightMapper>
#   3. Append the canonical 13 columns to the existing project, preserving
#      report-author per-asset cols (SecurityDomain="Azure", ConfigurationName=Name,
#      ConfigurationId=AzureResourceId, Impact=<expr>, Category=..., Subcategory=...).
#   4. Remove from project: any RiskScoreTotal*, RiskConsequenceScore,
#      RiskProbabilityScore (engine computes those post-query).
#   5. SortBy RiskScoreTotal_Weighted (engine adds the column post-query).
#
# Idempotent: if the canonical sentinel `__SI_CANONICAL__` is already in the
# query, skip.
function _InjectCanonicalRiskColumns([string]$kql, [string]$securityDomain) {
    if ($kql -match '__SI_CANONICAL__') { return $kql }   # idempotent
    $idx = $kql.LastIndexOf('| project ')
    if ($idx -lt 0) { return $kql }                       # no project = no canonical injection

    $model = _GetRiskScoreModel
    if (-not $model) { return $kql }

    $domainKey = $securityDomain.ToLowerInvariant()
    # Map RA-catalog domain -> engine name for the per-engine risk-factor list.
    # crossengine/hygiene fall back to endpoint defaults (most signal there).
    $engineKey = switch ($domainKey) {
        'azure'    { 'azure' }
        'identity' { 'identity' }
        default    { 'endpoint' }
    }

    $impactNorm     = _BuildImpactNormalizerKql     $model
    $sevMapper      = _BuildSeverityMapperKql       $model
    $tierMapper     = _BuildTierMapperKql           $model
    $cmdbMapper     = _BuildCriticalityMultiplierKql $model
    $rfDetailedKql  = _BuildRiskFactorDetailedKql   $model $engineKey
    $rfProbKql      = _BuildRiskFactorProbabilityKql $model $engineKey

    $extendLines = @(
        ('| extend Impact                          = ' + $impactNorm),
        ('| extend SecuritySeverity                = ' + $sevMapper),
        '| extend CriticalityTier                 = toint(coalesce(column_ifexists("Tier", 999), 999))',
        ('| extend CriticalityTierLevel            = ' + $tierMapper),
        '| extend RiskFactor_Consequence          = 0',
        ('| extend RiskFactor_Probability          = ' + $rfProbKql),
        ('| extend RiskFactor_Probability_Detailed = ' + $rfDetailedKql),
        ('| extend RiskFactor_Weight               = ' + $cmdbMapper),
        '// __SI_CANONICAL__'
    )
    $extendBlock = ($extendLines -join "`n        ") + "`n        "

    # Step 1: insert canonical extends BEFORE the final project.
    $newKql = $kql.Substring(0, $idx) + $extendBlock + $kql.Substring($idx)

    # Step 2: patch the final project clause:
    #   - Drop any of the engine-side score columns from the project list
    #     (RiskConsequenceScore, RiskProbabilityScore, RiskScoreTotal,
    #      RiskScoreTotal_Weighted, RiskFactor_Probability_DetailedScore)
    #   - Append the canonical 8 risk columns at the end of the project
    #     (Impact, SecuritySeverity, CriticalityTier, CriticalityTierLevel,
    #      RiskFactor_Consequence, RiskFactor_Probability,
    #      RiskFactor_Probability_Detailed, RiskFactor_Weight)
    $projectStart = $newKql.IndexOf('| project ', $idx + $extendBlock.Length)
    if ($projectStart -ge 0) {
        # Find end of project clause (next `| ` at start of stripped line, or end of string).
        $projectEnd = [regex]::Match($newKql.Substring($projectStart + 1), '\n\s*\|\s', 'Multiline').Index
        if ($projectEnd -lt 0) { $projectEnd = $newKql.Length - $projectStart - 1 }
        $projectClause = $newKql.Substring($projectStart, $projectEnd + 1)
        $rest = $newKql.Substring($projectStart + $projectEnd + 1)

        # Strip engine-computed score columns from project clause.
        $stripPatterns = @(
            ',\s*RiskScoreTotal_Weighted\b',
            ',\s*RiskConsequenceScore\b',
            ',\s*RiskProbabilityScore\b',
            ',\s*RiskScoreTotal\b',
            ',\s*RiskFactor_Probability_DetailedScore\b'
        )
        foreach ($p in $stripPatterns) { $projectClause = [regex]::Replace($projectClause, $p, '') }

        # Drop any existing canonical column references (idempotent on re-run).
        $canonicalCols = @('SecuritySeverity','CriticalityTierLevel','RiskFactor_Consequence','RiskFactor_Probability','RiskFactor_Probability_Detailed','RiskFactor_Weight')
        foreach ($c in $canonicalCols) {
            $projectClause = [regex]::Replace($projectClause, ',\s*' + $c + '\b', '')
        }

        # Append the canonical 7 (Impact stays as report-author's expression if present;
        # otherwise the canonical Impact extend kicks in via the upstream extend).
        # CriticalityTier reuses raw Tier so it appears alongside CriticalityTierLevel.
        $appendCols = ', SecuritySeverity, CriticalityTier, CriticalityTierLevel, RiskFactor_Consequence, RiskFactor_Probability, RiskFactor_Probability_Detailed, RiskFactor_Weight'
        # Trim trailing whitespace + newlines, then append.
        $projectClause = $projectClause.TrimEnd("`n", " ", "`r") + $appendCols + "`n"

        $newKql = $newKql.Substring(0, $projectStart) + $projectClause + $rest
    }

    # Step 3: queries no longer reference RiskScoreTotal_Weighted.
    # Reverse any prior flip so the KQL sort uses RiskScoreTotal (the in-query
    # column). The engine computes RiskScoreTotal_Weighted post-query and sorts
    # the final output; the KQL-side sort is just a hint.
    $newKql = [regex]::Replace($newKql,
        '\|\s*sort\s+by\s+RiskScoreTotal_Weighted(\s+desc)?(?![A-Za-z0-9_,])',
        '| sort by RiskScoreTotal desc')

    return $newKql
}

foreach ($f in $inputFiles) {
    try {
        $y = ConvertFrom-Yaml -Yaml (Get-Content $f.FullName -Raw)
    } catch {
        Write-Warning ("      skip {0} (parse error): {1}" -f $f.Name, $_.Exception.Message)
        continue
    }
    $reports = @($y.Reports)
    foreach ($r in $reports) {
        # Inject bucket support + weighted-score into every query.
        if ($r.ReportQuery -and @($r.ReportQuery).Count -gt 0) {
            $newQueries = @()
            $weightedAdded = $false
            $injectedExtras = @()
            foreach ($q in @($r.ReportQuery)) {
                # defensive cmdb extends FIRST (CMDB is optional).
                # canonical risk-column injection replaces the
                # earlier weighted-score math. Engine computes RiskScoreTotal*
                # post-query; query just projects the inputs.
                $defensive  = _InjectCmdbDefensiveExtends ([string]$q)
                $bucketed   = _InjectBucketSupport $defensive ([string]$r.SecurityDomain)
                $canonical  = _InjectCanonicalRiskColumns $bucketed ([string]$r.SecurityDomain)
                $newQueries += $canonical
            }
            $r.ReportQuery = $newQueries

            # OutputPropertyOrder: enforce canonical column list. Drop legacy
            # engine-side score columns, append the canonical 8.
            if ($r.OutputPropertyOrder) {
                $dropCols = @('RiskScoreTotal','RiskScoreTotal_Weighted','RiskConsequenceScore','RiskProbabilityScore','RiskFactor_Probability_DetailedScore','cmdbCriticalityScore')
                $appendCols = @('Impact','SecuritySeverity','CriticalityTier','CriticalityTierLevel','RiskFactor_Consequence','RiskFactor_Probability','RiskFactor_Probability_Detailed','RiskFactor_Weight')
                $cols = @($r.OutputPropertyOrder | Where-Object { $_ -notin $dropCols })
                $newCols = New-Object System.Collections.ArrayList
                foreach ($c in $cols) {
                    if ($c -in $appendCols) { continue }   # we'll add it canonically at the end
                    [void]$newCols.Add($c)
                }
                foreach ($c in $appendCols) { [void]$newCols.Add($c) }
                $r.OutputPropertyOrder = $newCols.ToArray()
            }
            # reports and queries reference RiskScoreTotal only.
            # Engine computes RiskScoreTotal_Weighted = RiskScoreTotal * RiskFactor_Weight
            # post-query and appends it as an extra column; it's not a sort key here.
            if ($r.SortBy) {
                $sortCols = @($r.SortBy)
                if ($sortCols.Count -eq 1 -and $sortCols[0] -in 'RiskScoreTotal','RiskScoreTotal_Weighted') {
                    $r.SortBy = @('RiskScoreTotal')
                }
            } else {
                Add-Member -InputObject $r -MemberType NoteProperty -Name 'SortBy' -Value 'RiskScoreTotal' -Force
            }
        }
        # Bucketing parameters (UseQueryBucketing / DefaultBucketCount /
        # BucketPlaceholderToken) are now hardcoded constants in the engine.
        # No per-report ReportTemplate block is emitted.
        # reorder keys so ReportName appears first in the emitted
        # YAML, matching v2.1 legacy structure.
        [void]$allReports.Add((_ReorderReportKeys $r))
    }
    Write-Host ("      {0,-58}  {1,3} reports (bucket-injected)" -f $f.Name, $reports.Count)
}
# ----------------------------------------------------------------------------
# Step 3 -- Auto-generate ReportTemplates (Summary + Detailed buckets)
# ----------------------------------------------------------------------------
# Engine-output dispatch needs ReportTemplates[] at the bottom of the locked
# file. v2.1 hand-maintained these; v2.2 auto-generates them from Reports[]
# so they can never drift. Each template lists all reports of one purpose
# (Summary / Detailed) with the v2.1 query-bucketing defaults.
$summaryNames  = @($allReports | Where-Object { $_.ReportName -notmatch 'Detailed' } | ForEach-Object { $_.ReportName })
$detailedNames = @($allReports | Where-Object { $_.ReportName -match 'Detailed'    } | ForEach-Object { $_.ReportName })

# Bucketing parameters are now hardcoded constants in the engine. The
# locked yaml's ReportsIncluded list is therefore just report names. The
# helpers below preserve a stable shape-tolerant accessor for any future
# field plumbing, but we no longer emit UseQueryBucketing /
# DefaultBucketCount / BucketPlaceholderToken in any report block.

function _GetField($obj, $name, $default) {
    # Shape-tolerant: works for IDictionary (hashtable / ordered) AND PSCustomObject.
    if ($null -eq $obj) { return $default }
    if ($obj -is [System.Collections.IDictionary]) {
        if ($obj.Contains($name) -and $null -ne $obj[$name]) { return $obj[$name] }
        return $default
    }
    $p = $obj.PSObject.Properties[$name]
    if ($p -and $null -ne $p.Value) { return $p.Value }
    return $default
}

function _BucketedEntry {
    param($Report)
    # Bucketing keys are no longer emitted; entry is just the report name.
    [ordered]@{
        Name = [string]$Report.ReportName
    }
}

$summaryReports  = @($allReports | Where-Object { $_.ReportName -notmatch 'Detailed' })
$detailedReports = @($allReports | Where-Object { $_.ReportName -match 'Detailed'    })

$summaryTemplate = [ordered]@{
    ReportName       = 'RiskAnalysis_Summary_Bucket'
    ReportPurpose    = 'Summary'
    ReportsIncluded  = @($summaryReports  | ForEach-Object { _BucketedEntry $_ })
}
$detailedTemplate = [ordered]@{
    ReportName       = 'RiskAnalysis_Detailed_Bucket'
    ReportPurpose    = 'Detailed'
    ReportsIncluded  = @($detailedReports | ForEach-Object { _BucketedEntry $_ })
}

$consolidated = [ordered]@{
    Reports         = $allReports.ToArray()
    ReportTemplates = @($summaryTemplate, $detailedTemplate)
}
$consolidatedYaml = ConvertTo-Yaml -Data $consolidated
$consolidatedYaml = _SeparateReportsWithBlankLines $consolidatedYaml
Set-Content -LiteralPath $OutputFile -Value $consolidatedYaml -Encoding UTF8

Write-Host ("      ReportTemplates: Summary({0}) + Detailed({1})" -f $summaryNames.Count, $detailedNames.Count)

Write-Host ""
Write-Host ("DONE  {0}" -f $OutputFile)
Write-Host ("      Total reports: {0}" -f $allReports.Count)
Write-Host ""
Write-Host "Operator flip from v2.1 to v2.2 (no engine code change):"
Write-Host "  In config/SecurityInsight.custom.ps1, set:"
Write-Host '    $global:SettingsPath = "<repo>/SOLUTIONS/SecurityInsight/risk-analysis-detection"'
Write-Host "  Then re-run the SecurityInsight_RiskAnalysis launcher."
