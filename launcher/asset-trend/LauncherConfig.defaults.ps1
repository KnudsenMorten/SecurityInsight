#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for the SecurityInsight asset-trend engine.

.DESCRIPTION
    Shipped with each release. Every value below is set ONLY when nothing else has set it, so a value
    you put in config\SecurityInsight.custom.ps1 or LauncherConfig.custom.ps1 always wins, whatever
    order the files load in. CLI switches on the launcher win last.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Trend
#>

# Summary = one point per report per day (small, keep for years). Detailed also rolls up the
# per-asset rows -- larger, and only worth it when you chart individual assets over time.
if ([string]::IsNullOrWhiteSpace([string]$global:SI_Trend_Grain)) { $global:SI_Trend_Grain = 'Summary' }

# How many weeks -ShowWeeklyRate looks back over.
if (-not $global:SI_Trend_Weeks) { $global:SI_Trend_Weeks = 12 }

# $true computes and prints the rollup without publishing it.
if ($null -eq $global:SI_Trend_DryRun) { $global:SI_Trend_DryRun = $false }
