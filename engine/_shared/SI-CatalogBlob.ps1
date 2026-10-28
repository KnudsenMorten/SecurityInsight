#Requires -Version 5.1
<#
    SecurityInsight -- the tenant's privilege-tier catalog, shared through the SI storage account.

    WHY (#137, operator ruling 2026-09-29: "blob-backed catalog"). The privilege-tier classifier writes the
    tenant's catalog to privilege-tier-catalog\privilege-tier-catalog.custom.json. On a VM that file sits
    next to the profilers and they read it. In a CONTAINER each job runs on its own ephemeral disk: the
    classifier job's file vanished with its replica and the profiler jobs read only the catalog baked into
    the image, so the classifier's output reached nobody. The classifier now also publishes the catalog to
    blob, and a profiler refreshes its local copy from blob when the blob copy is newer.

    Contract:
      * Publish never fails the classifier -- the local file is already written; a failed upload is a warning.
      * Refresh never fails a profiler -- on any error it keeps whatever local copy it has and says so.
      * No storage account configured (a VM without one) = both are silent no-ops; behaviour is unchanged.
      * OAuth only (-UseConnectedAccount), the same as every other SI storage path. No account key.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }

$script:SICatalogBlobContainer = 'sicatalog'
$script:SICatalogBlobName      = 'privilege-tier-catalog.custom.json'

function Get-SICatalogStorageContext {
    param([string]$AccountName)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $null }
    return (New-SIAzStorageContext -StorageAccountName $AccountName -UseConnectedAccount -ErrorAction Stop)
}

function Publish-SICatalogToBlob {
    <# Upload the local catalog. Returns $true when published, $false otherwise (never throws). #>
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [string]$AccountName = [string]$global:SI_StorageAccount
    )
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $false }
    if (-not (Test-Path -LiteralPath $LocalPath)) { return $false }
    try {
        $ctx = Get-SICatalogStorageContext -AccountName $AccountName
        if (-not (Get-SIAzStorageContainer -Name $script:SICatalogBlobContainer -Context $ctx -ErrorAction SilentlyContinue)) {
            New-SIAzStorageContainer -Name $script:SICatalogBlobContainer -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
        }
        Set-SIAzStorageBlobContent -File $LocalPath -Container $script:SICatalogBlobContainer -Blob $script:SICatalogBlobName `
            -Context $ctx -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Warning ("The privilege-tier catalog was written locally but could not be shared to storage account '{0}': {1}. Container-hosted profilers will keep the previous copy until the next successful run." -f $AccountName, $_.Exception.Message)
        return $false
    }
}

function Update-SICatalogFromBlob {
    <#
        Refresh the local catalog from blob when the blob copy is NEWER than the local file (or there is no
        local file). Returns which copy is now in effect: 'storage', 'local', or 'none'. Never throws.
    #>
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [string]$AccountName = [string]$global:SI_StorageAccount
    )
    $localExists = Test-Path -LiteralPath $LocalPath
    $fallback    = $(if ($localExists) { 'local' } else { 'none' })
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $fallback }
    try {
        $ctx  = Get-SICatalogStorageContext -AccountName $AccountName
        $blob = Get-SIAzStorageBlob -Container $script:SICatalogBlobContainer -Blob $script:SICatalogBlobName -Context $ctx -ErrorAction SilentlyContinue
        if (-not $blob) { return $fallback }                     # nothing published yet
        $blobTime = ([datetimeoffset]$blob.LastModified).UtcDateTime
        if ($localExists -and ((Get-Item -LiteralPath $LocalPath).LastWriteTimeUtc -ge $blobTime)) { return 'local' }

        # Download next to the target, validate it parses, then swap it in -- never leave a half file.
        $dir = Split-Path -Parent $LocalPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $tmp = Join-Path $dir ('.catalog-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        try {
            Get-SIAzStorageBlobContent -Container $script:SICatalogBlobContainer -Blob $script:SICatalogBlobName -Context $ctx `
                -Destination $tmp -Force -ErrorAction Stop | Out-Null
            $null = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            Move-Item -LiteralPath $tmp -Destination $LocalPath -Force
            (Get-Item -LiteralPath $LocalPath).LastWriteTimeUtc = $blobTime
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        return 'storage'
    } catch {
        Write-Warning ("Could not refresh the privilege-tier catalog from storage account '{0}' ({1}); using the {2} copy." -f $AccountName, $_.Exception.Message, $(if ($localExists) { 'local' } else { 'shipped' }))
        return $fallback
    }
}
