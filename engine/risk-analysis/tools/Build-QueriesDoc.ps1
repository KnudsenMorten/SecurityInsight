#Requires -Version 5.1
<#
.SYNOPSIS
    Generates v2.2/DOCS/risk-analysis-detection.md from the Locked yaml catalog.

.DESCRIPTION
    Reads RiskAnalysis_Queries_Locked.yaml (160 reports) and
    emits a markdown chapter per Security Domain (Azure / Endpoint / Identity
    / Cross-engine / Hygiene / ...). Each report becomes a sub-section with:
      * ReportName
      * Mode (Summary / Detailed -- inferred from name suffix)
      * Purpose (verbatim ReportPurpose if present)
      * Source LA tables (parsed from KQL via regex on `\b<name>_CL\b`)
      * SecuritySeverity scope + CriticalityTier scope
      * Output columns (OutputPropertyOrder)
      * Bucketing (note: hardcoded constants in the engine since )
      * KQL (full ReportQuery, fenced)
      * MoreInfoUrl / RemediationUrl (if present)

    Re-run this whenever the Locked yaml changes (typically after a
    Build-RiskAnalysis.ps1 consolidation pass). The output is checked in
    so customers reading on GitHub see every query without parsing yaml.

.NOTES
    Generated artefact:  v2.2/DOCS/risk-analysis-detection.md
    Source of truth:     v2.2/risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml
    Developed by:        Morten Knudsen, Microsoft MVP
#>

[CmdletBinding()]
param(
    [Parameter()][string]$LockedYaml = (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml'),
    [Parameter()][string]$OutputPath = (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'DOCS/risk-analysis-detection.md')
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable powershell-yaml)) {
    throw "powershell-yaml module not installed. Run: Install-Module powershell-yaml -Scope CurrentUser"
}
Import-Module powershell-yaml -Force

$LockedYaml = (Resolve-Path -LiteralPath $LockedYaml).Path
$catalog = (Get-Content -Raw -LiteralPath $LockedYaml | ConvertFrom-Yaml)
$reports = @($catalog.Reports)
if (-not $reports -or $reports.Count -eq 0) { throw "No Reports found in $LockedYaml" }

# Domain order (alphabetical, but pin the cross-engine bucket last so domain-
# native sections come first).
$domainOrder = @('Azure','Endpoint','Identity','Hygiene','Cross-Engine')

function _Mode([string]$reportName) {
    if ($reportName -match '_Summary($|_)') { return 'Summary' }
    if ($reportName -match '_Detailed($|_)') { return 'Detailed' }
    if ($reportName -match '_Bucket') { return 'Bucketed' }
    return '(unknown)'
}

function _SourceTables([string]$kql) {
    if ([string]::IsNullOrWhiteSpace($kql)) { return @() }
    $matches = [regex]::Matches($kql, '\b([A-Za-z][A-Za-z0-9_]*_CL)\b')
    $tables = @{}
    foreach ($m in $matches) { $tables[$m.Groups[1].Value] = $true }
    # Also pick up Defender-XDR hunting tables (no _CL suffix). Heuristic:
    # the small set of tables RA queries touch.
    foreach ($xdr in @('DeviceInfo','IdentityInfo','AlertEvidence','ExposureGraphNodes','ExposureGraphEdges','DeviceTvmSecureConfigurationAssessment','DeviceTvmSoftwareVulnerabilities','DeviceProcessEvents','DeviceLogonEvents','SigninLogs','AuditLogs','AADUserRiskEvents','AADServicePrincipalRiskEvents')) {
        if ($kql -match ('\b' + [regex]::Escape($xdr) + '\b')) { $tables[$xdr] = $true }
    }
    return ($tables.Keys | Sort-Object)
}

function _Escape([string]$s) {
    if ($null -eq $s) { return '' }
    return ($s -replace '\|','\|' -replace "`r?`n",' ').Trim()
}

# Group reports by SecurityDomain (string column on every report). Reports
# that lack SecurityDomain land in a "(unspecified)" bucket.
$grouped = @{}
foreach ($r in $reports) {
    $dom = if ($r.SecurityDomain) { [string]$r.SecurityDomain } else { '(unspecified)' }
    if (-not $grouped.ContainsKey($dom)) { $grouped[$dom] = New-Object System.Collections.ArrayList }
    [void]$grouped[$dom].Add($r)
}

# Stable engine-friendly domain order (known names first, then anything else
# alphabetically).
$domainsSorted = @()
foreach ($d in $domainOrder) {
    if ($grouped.ContainsKey($d)) { $domainsSorted += $d }
}
foreach ($d in ($grouped.Keys | Sort-Object)) {
    if ($domainsSorted -notcontains $d) { $domainsSorted += $d }
}

$now = [datetime]::UtcNow.ToString('yyyy-MM-dd')
$srcVersionFile = Join-Path (Split-Path -Parent (Split-Path -Parent $LockedYaml)) 'VERSION'
$siVersion = if (Test-Path -LiteralPath $srcVersionFile) {
    (Get-Content -Raw -LiteralPath $srcVersionFile).Trim()
} else { '<unknown>' }

$sb = [System.Text.StringBuilder]::new(2MB)
[void]$sb.AppendLine('# SecurityInsight v2.2 -- Risk Analysis query catalog')
[void]$sb.AppendLine()
[void]$sb.AppendLine(('> Auto-generated from `v2.2/risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` by `v2.2/engine/risk-analysis/tools/Build-QueriesDoc.ps1`. Do not hand-edit. Re-run the generator after consolidation. Generated {0} for SI {1}.' -f $now, $siVersion))
[void]$sb.AppendLine()
[void]$sb.AppendLine(('Catalog summary: **{0} reports** across **{1} security domains**. Every report runs against the `SI_*_Profile_CL` Profile tables, with bucket placeholder `__BUCKET_FILTER__` so the engine can split queries that exceed Defender''s 30k-row ceiling.' -f $reports.Count, $domainsSorted.Count))
[void]$sb.AppendLine()

# Per-domain summary at the top
[void]$sb.AppendLine('## Reports per domain')
[void]$sb.AppendLine()
[void]$sb.AppendLine('| Domain | Reports | Summary | Detailed |')
[void]$sb.AppendLine('|---|---:|---:|---:|')
foreach ($d in $domainsSorted) {
    $rs = $grouped[$d]
    $nSum = ($rs | Where-Object { (_Mode $_.ReportName) -eq 'Summary' }).Count
    $nDet = ($rs | Where-Object { (_Mode $_.ReportName) -eq 'Detailed' }).Count
    [void]$sb.AppendLine(('| {0} | {1} | {2} | {3} |' -f $d, $rs.Count, $nSum, $nDet))
}
[void]$sb.AppendLine()

# Reading guide
[void]$sb.AppendLine('## How to read each report block')
[void]$sb.AppendLine()
[void]$sb.AppendLine('Each report below has:')
[void]$sb.AppendLine()
[void]$sb.AppendLine('- **Purpose** -- one-line summary of what the report flags (verbatim from `ReportPurpose` in the yaml).')
[void]$sb.AppendLine('- **Mode** -- `Summary` (one row per finding type) or `Detailed` (one row per affected asset).')
[void]$sb.AppendLine('- **Severity scope** -- which `SecuritySeverity` bands the report includes (Very High / High / Medium / Low / Informational).')
[void]$sb.AppendLine('- **Tier scope** -- which `CriticalityTierLevel` rows the report includes (Critical-tier-0 / High-tier-1 / Medium-tier-2 / Low-tier-3).')
[void]$sb.AppendLine('- **Source tables** -- the LA tables (`*_CL`) and Defender-XDR hunting tables the KQL reads. Most reports run against `SI_<Engine>_Profile_CL` (Profile snapshots, latest-CollectionTime via `summarize max(CollectionTime)`).')
[void]$sb.AppendLine('- **Output columns** -- the columns the report projects, in the order they appear in the XLSX/JSON output.')
[void]$sb.AppendLine('- **Bucketing** -- whether the engine auto-splits the query.')
[void]$sb.AppendLine('- **KQL** -- the full query. The `__BUCKET_FILTER__` placeholder is substituted at runtime.')
[void]$sb.AppendLine()
[void]$sb.AppendLine('---')
[void]$sb.AppendLine()

# Per-domain chapters
foreach ($d in $domainsSorted) {
    $rs = @($grouped[$d] | Sort-Object -Property ReportName)
    [void]$sb.AppendLine(('## {0}  ({1} reports)' -f $d, $rs.Count))
    [void]$sb.AppendLine()
    foreach ($r in $rs) {
        $name = [string]$r.ReportName
        $mode = _Mode $name
        $kqlText = if ($r.ReportQuery -is [array] -and $r.ReportQuery.Count -gt 0) {
            ($r.ReportQuery | ForEach-Object { [string]$_ }) -join "`n"
        } else { [string]$r.ReportQuery }
        $sources = _SourceTables $kqlText
        $sevScope = if ($r.SecuritySeverityScope) { (($r.SecuritySeverityScope | ForEach-Object { '`' + $_ + '`' }) -join ', ') } else { '_(any)_' }
        $tierScope = if ($r.CriticalityTierLevelScope) { (($r.CriticalityTierLevelScope | ForEach-Object { '`' + $_ + '`' }) -join ', ') } else { '_(any)_' }
        $cols = if ($r.OutputPropertyOrder) { (($r.OutputPropertyOrder | ForEach-Object { '`' + $_ + '`' }) -join ', ') } else { '_(unset)_' }
        $sortBy = if ($r.SortBy) { (($r.SortBy | ForEach-Object { '`' + $_ + '`' }) -join ', ') } else { '_(unset)_' }

        # Bucketing is hardcoded in the engine: enabled, count=2,
        # placeholder=__BUCKET_FILTER__ (AutoBucket grows count up as needed).
        $bucketing = '`enabled` (count=2, placeholder=`__BUCKET_FILTER__`, AutoBucket grows up to fit Defender 30k-row ceiling)'

        $purpose = if ($r.ReportPurpose) { ([string]$r.ReportPurpose).Trim() } else { '_(no ReportPurpose set in yaml)_' }
        $moreInfo = if ($r.MoreInfoUrl) { '`' + ([string]$r.MoreInfoUrl) + '`' } elseif ($r.RemediationUrl) { '`' + ([string]$r.RemediationUrl) + '`' } else { '' }

        [void]$sb.AppendLine(('### {0}' -f $name))
        [void]$sb.AppendLine()
        [void]$sb.AppendLine(('- **Mode**: `{0}`' -f $mode))
        [void]$sb.AppendLine(('- **Purpose**: {0}' -f ($purpose -replace "`r?`n",' ' | ForEach-Object { _Escape $_ })))
        if ($sources.Count -gt 0) {
            [void]$sb.AppendLine(('- **Source tables**: {0}' -f (($sources | ForEach-Object { '`' + $_ + '`' }) -join ', ')))
        }
        [void]$sb.AppendLine(('- **Severity scope**: {0}' -f $sevScope))
        [void]$sb.AppendLine(('- **Tier scope**: {0}' -f $tierScope))
        [void]$sb.AppendLine(('- **Output columns**: {0}' -f $cols))
        [void]$sb.AppendLine(('- **Sort by**: {0}' -f $sortBy))
        [void]$sb.AppendLine(('- **Bucketing**: {0}' -f $bucketing))
        if ($moreInfo) { [void]$sb.AppendLine(('- **More info**: {0}' -f $moreInfo)) }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('<details><summary>KQL</summary>')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('```kusto')
        [void]$sb.AppendLine($kqlText)
        [void]$sb.AppendLine('```')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('</details>')
        [void]$sb.AppendLine()
    }
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine()
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { $null = New-Item -Path $outDir -ItemType Directory -Force }
[System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ('risk-analysis-detection.md written: {0} ({1:N0} bytes, {2} reports across {3} domains)' -f `
    $OutputPath, (Get-Item $OutputPath).Length, $reports.Count, $domainsSorted.Count)
