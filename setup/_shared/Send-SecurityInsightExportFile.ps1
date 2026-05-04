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
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$Destination,
        # Optional -- enables container auto-create + RBAC self-heal for Azure Storage
        [string]$IngestionSpnAppId,      # AAD App (client) ID of the engine's SPN
        [string]$IngestionSpnObjectId    # SPN ObjectId (optional; resolved from AppId when omitted)
    )
    if (-not (Test-Path -LiteralPath $LocalPath)) {
        Write-Warn "  export source not found: $LocalPath -- skipping"
        return
    }
    $fileName = Split-Path -Leaf $LocalPath

    if ($Destination -match '^\\\\') {
        Send-ExportFile-Unc -LocalPath $LocalPath -DestinationDir $Destination -FileName $fileName
    }
    elseif ($Destination -match '^https://([^.]+)\.blob\.core\.windows\.net/([^/]+)/?(.*)$') {
        Send-ExportFile-AzStorage -LocalPath $LocalPath `
            -StorageAccount       $Matches[1] `
            -Container            $Matches[2] `
            -Prefix               $Matches[3].TrimEnd('/') `
            -FileName             $fileName `
            -IngestionSpnAppId    $IngestionSpnAppId `
            -IngestionSpnObjectId $IngestionSpnObjectId
    }
    else {
        Write-Warn ("  unrecognized ExportDestination scheme: '{0}' (expected '\\server\share\path\' or 'https://<acct>.blob.core.windows.net/<container>/[<prefix>/]')" -f $Destination)
    }
}

function Ensure-SecurityInsightStorageContainer {
    <#
    Ensures a blob container exists in the given storage account. If the
    SecurityInsight SPN's ObjectId is supplied, also tries to grant it
    'Storage Blob Data Contributor' on the container (scoped) so future runs
    can read + write without RBAC handholding.

    Requires the CALLER to already have permission to manage the storage
    account (either Owner / Contributor on the storage account, or
    Storage Blob Data Contributor at account scope). If the caller's SPN
    lacks either, we warn clearly and return $false.
    #>
    param(
        [Parameter(Mandatory)] [object] $StorageContext,
        [Parameter(Mandatory)] [string] $StorageAccount,
        [Parameter(Mandatory)] [string] $Container,
        [string] $IngestionSpnObjectId
    )
    # Already present? Done.
    $existing = Get-AzStorageContainer -Context $StorageContext -Name $Container -ErrorAction SilentlyContinue
    if ($existing) { return $true }

    Write-Info ("  container '{0}' not found in '{1}' -- creating" -f $Container, $StorageAccount)
    try {
        New-AzStorageContainer -Context $StorageContext -Name $Container -ErrorAction Stop | Out-Null
        Write-Ok ("  created container '{0}'" -f $Container)
    } catch {
        Write-Warn ("  container creation failed: {0}" -f $_.Exception.Message)
        Write-Warn ("  Grant the running SPN 'Storage Blob Data Contributor' (data-plane) OR 'Contributor' (management-plane) on the storage account '{0}' and re-run." -f $StorageAccount)
        return $false
    }

    # Best-effort RBAC grant at container scope so the SPN can continue ingesting.
    if ($IngestionSpnObjectId) {
        try {
            $sa = Get-AzStorageAccount -ErrorAction SilentlyContinue | Where-Object { $_.StorageAccountName -eq $StorageAccount } | Select-Object -First 1
            if ($sa) {
                $containerScope = "$($sa.Id)/blobServices/default/containers/$Container"
                $already = Get-AzRoleAssignment -ObjectId $IngestionSpnObjectId -Scope $containerScope -RoleDefinitionName 'Storage Blob Data Contributor' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Scope -eq $containerScope }
                if (-not $already) {
                    New-AzRoleAssignment -ObjectId $IngestionSpnObjectId -RoleDefinitionName 'Storage Blob Data Contributor' -Scope $containerScope -ErrorAction Stop | Out-Null
                    Write-Ok ("  assigned 'Storage Blob Data Contributor' at {0}" -f $containerScope)
                    Write-Info "  waiting 30s for RBAC propagation..."
                    Start-Sleep -Seconds 30
                }
            } else {
                Write-Info ("  storage account '{0}' not visible to current context -- skipping RBAC grant (container was created successfully)" -f $StorageAccount)
            }
        } catch {
            Write-Warn ("  could not assign 'Storage Blob Data Contributor' to SPN: {0}" -f $_.Exception.Message)
            Write-Warn "  The container exists, but the SPN may need RBAC granted manually (caller likely lacks User Access Administrator/Owner on the storage account)."
        }
    }
    return $true
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
    param(
        [string]$LocalPath,
        [string]$StorageAccount,
        [string]$Container,
        [string]$Prefix,
        [string]$FileName,
        [string]$IngestionSpnAppId,
        [string]$IngestionSpnObjectId
    )
    try {
        try { Import-Module Az.Storage -ErrorAction Stop -WarningAction SilentlyContinue } catch {
            Write-Warn ("  Az.Storage module not available: {0}. Install with: Install-Module Az.Storage. Skipping upload." -f $_.Exception.Message)
            return
        }
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount

        # Resolve SPN ObjectId once (for container RBAC grant) -- optional
        if (-not $IngestionSpnObjectId -and $IngestionSpnAppId) {
            try {
                $spn = Get-AzADServicePrincipal -ApplicationId $IngestionSpnAppId -ErrorAction SilentlyContinue
                if ($spn) { $IngestionSpnObjectId = [string]$spn.Id }
            } catch { }
        }

        # Ensure container exists (creates + best-effort RBAC grant if missing)
        $ok = Ensure-SecurityInsightStorageContainer -StorageContext $ctx -StorageAccount $StorageAccount -Container $Container -IngestionSpnObjectId $IngestionSpnObjectId
        if (-not $ok) { return }

        $blobName = if ($Prefix) { ($Prefix.Trim('/') + '/' + $FileName) } else { $FileName }

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
