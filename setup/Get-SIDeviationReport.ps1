<#
.SYNOPSIS
    What have we switched off, changed or exempted -- and why? One row per deviation from the shipped defaults.

.DESCRIPTION
    For a Community or VM install: reads the custom files (*.custom.*) and compares them with the shipped files they
    deviate from. Nothing is written to the installation -- the only file this script ever writes is the CSV you ask for.

    Covered:
      Setting            a value in config\SecurityInsight.custom.ps1 or launcher\<engine>\LauncherConfig.custom.ps1 that
                         differs from its shipped default (a value set by code is listed as "(set by code)"; a secret's
                         value is never read into the report)
      Exclusion          one row per excluded CVE / configuration id / asset tag, and CveMinAgeDays
                         (RiskAnalysisGlobalExclusions.custom.json, <Report>.exclude.custom.json)
      DisabledDetection  a tier rule turned off (mode: disable)
      TierMove           a custom rule that sets other tiers than the shipped rule
      ItemOverride       a custom rule that replaces or adds one, a Risk Analysis report in RiskAnalysis_Queries_Custom.yaml
      RiskWeights        weighted risk factors (riskscore_weighted.schema.custom.json)
    Who changed what and when comes from the Settings page's change log (logs\settings-changes.log) where it has the
    file, else from the file's last write time.

    SecurityInsight Pro shows the same report, from its settings database, on the web app's Deviations page.

.PARAMETER SIRoot
    The SecurityInsight folder. Default: the folder above this script.
.PARAMETER SettingsPath
    Where the Risk Analysis exclusion and weights files live. Default: <SIRoot>\risk-analysis-detection (the engine's own
    default).
.PARAMETER OverlayRoot
    The tier rule overlay folder, when the install keeps its rules outside the code tree (SI_EnrichmentDataRoot).
    Default: $global:SI_EnrichmentDataRoot when it is set.
.PARAMETER CatalogPath
    A settings catalog to take the shipped defaults (and which settings are secrets) from. Without it the shipped
    defaults files are read.
.PARAMETER Kind
    Only these kinds (Exemption, Exclusion, DisabledDetection, TierMove, ItemOverride, RiskWeights, Setting).
.PARAMETER AsCsv
    Write the report to a CSV file instead of the pipeline; returns the file.
.PARAMETER CsvPath
    The CSV file to write (with -AsCsv). Default: .\SecurityInsight-deviations-<UTC time>.csv

.EXAMPLE
    .\setup\Get-SIDeviationReport.ps1 | Format-Table Kind, Item, Scope, Current, ChangedBy
.EXAMPLE
    .\setup\Get-SIDeviationReport.ps1 -Kind Exclusion, DisabledDetection -AsCsv -CsvPath C:\Temp\deviations.csv

.LINK
    https://invardia.com/docs/si/scripts/Get-SIDeviationReport/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SIRoot,
    [string]$SettingsPath,
    [string]$OverlayRoot,
    [string]$CatalogPath,
    [ValidateSet('Exemption', 'Exclusion', 'DisabledDetection', 'TierMove', 'ItemOverride', 'RiskWeights', 'Setting')]
    [string[]]$Kind,
    [switch]$AsCsv,
    [string]$CsvPath,
    [int]$ExpiringDays = 30
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Get-SIDeviationReport' -Quiet:($false)
try {
$ErrorActionPreference = 'Stop'
if (-not $SIRoot) { $SIRoot = Split-Path -Parent $PSScriptRoot }
$SIRoot = (Resolve-Path -LiteralPath $SIRoot).ProviderPath.TrimEnd('\', '/')
. ([System.IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-DeviationReport.ps1'))

if (-not $OverlayRoot -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_EnrichmentDataRoot)) { $OverlayRoot = [string]$global:SI_EnrichmentDataRoot }

$data = Read-SICommunityDeviationInput -SIRoot $SIRoot -SettingsPath $SettingsPath -OverlayRoot $OverlayRoot -CatalogPath $CatalogPath
$rows = @(Get-SIDeviationReport -Community $data -ExpiringDays $ExpiringDays)
if ($Kind) { $rows = @($rows | Where-Object { $Kind -contains $_.Kind }) }
$cols = Get-SIDeviationColumns

if ($AsCsv) {
    if (-not $CsvPath) { $CsvPath = Join-Path (Get-Location).ProviderPath ('SecurityInsight-deviations-{0}.csv' -f [datetime]::UtcNow.ToString('yyyyMMdd-HHmm', [System.Globalization.CultureInfo]::InvariantCulture)) }
    $dir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($CsvPath))
    if ($WhatIfPreference) { Write-Host ('-WhatIf: would write {0} deviation(s) to {1}. Nothing was written.' -f $rows.Count, $CsvPath) -ForegroundColor Yellow; return }
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # UTF-8 with a BOM: Excel opens it with the right characters.
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($CsvPath), (ConvertTo-SIDeviationCsv -Rows $rows), (New-Object System.Text.UTF8Encoding($true)))
    Write-Verbose ('{0} deviation(s) written to {1}' -f $rows.Count, $CsvPath)
    return (Get-Item -LiteralPath $CsvPath)
}
$rows | Select-Object -Property $cols
} finally { Stop-SIScriptRun -Run $siRun }
