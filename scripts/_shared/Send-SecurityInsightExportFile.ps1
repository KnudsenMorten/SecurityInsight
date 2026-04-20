<#
.SYNOPSIS
    Shared UNC / Azure Storage blob upload helper for SecurityInsight engines.

.DESCRIPTION
    Dot-source this file then call Send-ExportFile -LocalPath <path> -Destination <url-or-unc>.

    Destination type is AUTO-DETECTED from the prefix:
      \\server\share\subpath\                             -> UNC (Copy-Item)
      https://<acct>.blob.core.windows.net/<container>/... -> Azure Storage blob (Set-AzStorageBlobContent)

    If the destination already holds a file with the same name, the existing copy
    is first renamed to <name>.<yyyy-MM-dd_HHmmss>.<ext>.bak before the new one
    is written. So the canonical path always holds the latest run; older runs
    become timestamped backups next to it.

    Requires the caller to define Write-Info / Write-Ok / Write-Warn functions
    (both RiskAnalysis + IAC engines already do so).

    Auth:
      UNC     -- caller's Windows identity needs write to the share.
      Azure   -- the SPN that ran the engine needs 'Storage Blob Data Contributor'
                 on the destination container (or its parent storage account).
#>

function Send-ExportFile {
    param([Parameter(Mandatory)][string]$LocalPath, [Parameter(Mandatory)][string]$Destination)
    if (-not (Test-Path -LiteralPath $LocalPath)) {
        Write-Warn "  export source not found: $LocalPath -- skipping"
        return
    }
    $fileName = Split-Path -Leaf $LocalPath

    if ($Destination -match '^\\\\') {
        Send-ExportFile-Unc -LocalPath $LocalPath -DestinationDir $Destination -FileName $fileName
    }
    elseif ($Destination -match '^https://([^.]+)\.blob\.core\.windows\.net/([^/]+)/?(.*)$') {
        Send-ExportFile-AzStorage -LocalPath $LocalPath -StorageAccount $Matches[1] -Container $Matches[2] -Prefix $Matches[3].TrimEnd('/') -FileName $fileName
    }
    else {
        Write-Warn ("  unrecognized ExportDestination scheme: '{0}' (expected '\\server\share\path\' or 'https://<acct>.blob.core.windows.net/<container>/[<prefix>/]')" -f $Destination)
    }
}

function Send-ExportFile-Unc {
    param([string]$LocalPath, [string]$DestinationDir, [string]$FileName)
    try {
        if (-not (Test-Path -LiteralPath $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        $destPath = Join-Path $DestinationDir $FileName
        if (Test-Path -LiteralPath $destPath) {
            $stamp      = Get-Date -Format 'yyyy-MM-dd_HHmmss'
            $ext        = [System.IO.Path]::GetExtension($FileName).TrimStart('.')
            $base       = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
            $backupName = "{0}.{1}.{2}.bak" -f $base, $stamp, $ext
            $backupPath = Join-Path $DestinationDir $backupName
            Move-Item -LiteralPath $destPath -Destination $backupPath -Force
            Write-Info ("  backed up existing -> {0}" -f $backupName)
        }
        Copy-Item -LiteralPath $LocalPath -Destination $destPath -Force
        Write-Ok ("  uploaded -> {0}" -f $destPath)
    } catch {
        Write-Warn ("  UNC upload of '{0}' failed: {1}" -f $FileName, $_.Exception.Message)
    }
}

function Send-ExportFile-AzStorage {
    param([string]$LocalPath, [string]$StorageAccount, [string]$Container, [string]$Prefix, [string]$FileName)
    try {
        try { Import-Module Az.Storage -ErrorAction Stop -WarningAction SilentlyContinue } catch {
            Write-Warn ("  Az.Storage module not available: {0}. Install with: Install-Module Az.Storage. Skipping upload." -f $_.Exception.Message)
            return
        }
        $blobName = if ($Prefix) { ($Prefix.Trim('/') + '/' + $FileName) } else { $FileName }
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount

        $existing = Get-AzStorageBlob -Context $ctx -Container $Container -Blob $blobName -ErrorAction SilentlyContinue
        if ($existing) {
            $stamp      = Get-Date -Format 'yyyy-MM-dd_HHmmss'
            $ext        = [System.IO.Path]::GetExtension($FileName).TrimStart('.')
            $base       = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
            $backupName = if ($Prefix) { ($Prefix.Trim('/') + '/' + ("{0}.{1}.{2}.bak" -f $base, $stamp, $ext)) } else { ("{0}.{1}.{2}.bak" -f $base, $stamp, $ext) }
            Start-AzStorageBlobCopy -Context $ctx -SrcContainer $Container -SrcBlob $blobName -DestContainer $Container -DestBlob $backupName -Force | Out-Null
            Write-Info ("  backed up existing -> {0}" -f $backupName)
        }

        Set-AzStorageBlobContent -Context $ctx -Container $Container -Blob $blobName -File $LocalPath -Force | Out-Null
        Write-Ok ("  uploaded -> https://{0}.blob.core.windows.net/{1}/{2}" -f $StorageAccount, $Container, $blobName)
    } catch {
        Write-Warn ("  Azure Storage upload of '{0}' failed: {1} (Storage Blob Data Contributor on the container required for the SecurityInsight SPN)" -f $FileName, $_.Exception.Message)
    }
}
