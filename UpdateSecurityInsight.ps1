#########################################################################################################
# Downloading latest version of SecurityInsight files (with local rotating backup: last 5 versions)
#########################################################################################################

$global:GitHubUri = "https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/main"

$Files = @(
    "SecurityInsight_RiskAnalysis.ps1",
    "SecurityInsight_RiskAnalysis_Queries_Locked.yaml",
    "CriticalAssetTagging.ps1",
    "SecurityInsight_CriticalAssetTagging_Locked.yaml",
    "CriticalAssetTaggingMaintenance.ps1"
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

foreach ($File in $Files) {
    Write-Host "Updating $File"
    $FileFullPath = Join-Path $PSScriptRoot $File

    # --- Backup existing local file (keep last N versions) ---
    if (Test-Path -LiteralPath $FileFullPath) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupName = "{0}.{1}.bak" -f $File, $timestamp
        $backupPath = Join-Path $BackupRoot $backupName

        Copy-Item -LiteralPath $FileFullPath -Destination $backupPath -Force

        # Trim backups for this file to last $KeepVersions
        $pattern = ($File -replace '\.', '\.') + "\.\d{8}-\d{6}\.bak$"

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
