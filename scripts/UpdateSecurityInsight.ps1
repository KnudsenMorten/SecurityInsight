<#
.SYNOPSIS
    UpdateSecurityInsight - engine script in the SecurityInsight solution.

.NOTES
    Solution       : SecurityInsight
    File           : UpdateSecurityInsight.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#########################################################################################################
# Downloading latest version of SecurityInsight files (with local rotating backup: last 5 versions)
#########################################################################################################

$global:GitHubUri = "https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/main"

# v2 layout: engines live under scripts/, data under data/. UpdateSecurityInsight
# mirrors the structure locally -- each entry is the relative path in the public repo
# and gets written to the same relative path under $PSScriptRoot's parent (solution root).
#
# SUBSCRIPTION SCOPE (what this updater tracks):
#   1. The four most-frequently-updated engines.
#   2. The two platform-curated "_Locked" data files (recommended tagging rules and
#      recommended RiskAnalysis queries).
#
# What this updater INTENTIONALLY does NOT touch:
#   * data/SecurityInsight_RiskIndex.csv           -- CUSTOMER-TUNABLE scoring weights;
#                                                     customers adjust the risk index to
#                                                     reflect their own priorities. Pull
#                                                     manually if you want the upstream
#                                                     version as a reference.
#   * data/SecurityInsight_IdentityTiering.json    -- CUSTOMER-TUNABLE tier catalogue;
#                                                     customers can override specific role
#                                                     tiers to match their governance model.
#                                                     Re-run Build_Tier_Definitions_JSON_File
#                                                     locally to rebuild, or pull manually
#                                                     from upstream if you want to reset.
#   * data/*_Custom.yaml                           -- your tagging + query customisations
#   * launchers/*/LauncherConfig.ps1               -- your SPN credentials (.gitignore'd)
#   * scripts/CriticalAssetTaggingMaintenance*.ps1
#   * scripts/Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1
#   * scripts/Onboarding_IdentityAssets_LogAnalytics.ps1
#     (these three scripts are one-shot or infrequently-changed; re-run manually
#      when needed rather than updating silently in the background)
#
# Add or remove entries below to adjust your subscription.
$Files = @(
    # --- Engines (the four most-frequently-updated scripts) ---
    "scripts/Build_Tier_Definitions_JSON_File.ps1",
    "scripts/CriticalAssetTagging.ps1",
    "scripts/IdentityAssetsCollectDefineTierIngestLog.ps1",
    "scripts/SecurityInsight_RiskAnalysis.ps1",

    # --- Platform-curated locked data files (overwritten on every update) ---
    "data/SecurityInsight_CriticalAssetTagging_Locked.yaml",
    "data/SecurityInsight_RiskAnalysis_Queries_Locked.yaml"
)

# Backup settings
$BackupRoot = $PSScriptRoot + "\BACKUP"
$KeepVersions = 10

# Ensure backup folder exists
if (-not (Test-Path -LiteralPath $BackupRoot)) {
    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
}

Write-Host "SecurityInsight"
Write-Host "Created by Morten Knudsen, Microsoft MVP (@knudsenmortendk - mok@mortenknudsen.net)"
Write-Host ""
Write-Host "Downloading latest version of SecurityInsight from"
Write-Host "$GitHubUri"
Write-Host ""

# v2 layout: the $File entries contain 'scripts/' or 'data/' prefixes, so the
# local write-path is anchored at the solution root (one level above this script),
# not at $PSScriptRoot directly.
$SolutionRoot = Split-Path -Parent $PSScriptRoot

foreach ($File in $Files) {
    Write-Host "Updating $File"
    $FileFullPath = Join-Path $SolutionRoot $File

    # Ensure target directory exists (scripts/, data/ subfolders)
    $FileDir = Split-Path -Parent $FileFullPath
    if (-not (Test-Path -LiteralPath $FileDir)) {
        New-Item -ItemType Directory -Path $FileDir -Force | Out-Null
    }

    # --- Backup existing local file (keep last N versions) ---
    if (Test-Path -LiteralPath $FileFullPath) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        # Flatten path separators in the backup name so every backup lives directly under BACKUP/
        $backupName = "{0}.{1}.bak" -f ($File -replace '[\\/]','_'), $timestamp
        $backupPath = Join-Path $BackupRoot $backupName

        Copy-Item -LiteralPath $FileFullPath -Destination $backupPath -Force

        # Trim backups for this file to last $KeepVersions
        $pattern = (($File -replace '[\\/]','_') -replace '\.', '\.') + "\.\d{8}-\d{6}\.bak$"

        $backups = Get-ChildItem -LiteralPath $BackupRoot -File |
            Where-Object { $_.Name -match $pattern } |
            Sort-Object LastWriteTime -Descending

        if ($backups.Count -gt $KeepVersions) {
            $backups | Select-Object -Skip $KeepVersions | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }

    # --- Download latest file (overwrite in place) ---
    Invoke-WebRequest "$GitHubUri/$File" -OutFile $FileFullPath
}
