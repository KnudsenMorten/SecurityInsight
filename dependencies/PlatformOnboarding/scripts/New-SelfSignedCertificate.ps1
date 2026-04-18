#Requires -Version 5.1
<#
.SYNOPSIS
    Create a self-signed certificate for SPN certificate-based auth. Writes the
    public key to a .cer file that can be uploaded via New-EntraApp.ps1, and
    installs the private key into the local Windows cert store so the launcher
    can find it by thumbprint.

.DESCRIPTION
    Platform-level onboarding helper. The resulting certificate is used by the
    community-vm and internal-vm launchers when $global:SpnCertificateThumbprint
    is set in LauncherConfig.ps1.

    Idempotent: if a cert with the same Subject already exists in the target
    store AND is not expiring within -MinRemainingDays, the script reuses it
    rather than creating a new one.

.PARAMETER Subject
    Certificate Subject (CN=...). Default: 'CN=SecurityInsight-SPN'. Use a
    distinct subject per SPN so multiple solutions can coexist in the same store.

.PARAMETER StoreLocation
    'CurrentUser' (default) or 'LocalMachine'. LocalMachine requires admin.

.PARAMETER ValidityDays
    Default: 365. Max: typically 2 years for self-signed.

.PARAMETER MinRemainingDays
    Reuse existing cert if it has more than N days left. Default: 60.

.PARAMETER CerOutputPath
    Where to write the public-key .cer. Default: SCRIPTS\Output\<subject>.cer.

.EXAMPLE
    .\New-SelfSignedCertificate.ps1 -Subject 'CN=SecurityInsight-SPN' -StoreLocation CurrentUser
#>
[CmdletBinding()]
param(
    [string]$Subject           = 'CN=SecurityInsight-SPN',
    [ValidateSet('CurrentUser','LocalMachine')]
    [string]$StoreLocation     = 'CurrentUser',
    [int]$ValidityDays         = 365,
    [int]$MinRemainingDays     = 60,
    [string]$CerOutputPath
)

$ErrorActionPreference = 'Stop'

$storePath = "Cert:\$StoreLocation\My"
Write-Host "[STEP] Looking for existing cert '$Subject' in $storePath" -ForegroundColor Cyan
$existing = Get-ChildItem -Path $storePath | Where-Object { $_.Subject -eq $Subject } | Sort-Object NotAfter -Descending

$cert = $null
if ($existing) {
    $top = $existing | Select-Object -First 1
    $remaining = ($top.NotAfter - (Get-Date)).TotalDays
    if ($remaining -ge $MinRemainingDays) {
        Write-Host ("[OK]   Reusing existing cert thumbprint={0} ({1:n0} days remaining)" -f $top.Thumbprint, $remaining) -ForegroundColor Green
        $cert = $top
    } else {
        Write-Host ("[INFO] Existing cert expires in {0:n0} days -- creating a fresh one." -f $remaining) -ForegroundColor Yellow
    }
}

if (-not $cert) {
    Write-Host ("[STEP] Creating new self-signed cert (validity {0} days)" -f $ValidityDays) -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate `
        -Subject $Subject `
        -CertStoreLocation $storePath `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays($ValidityDays)
    Write-Host ("[OK]   Cert created. Thumbprint: {0}" -f $cert.Thumbprint) -ForegroundColor Green
}

if (-not $CerOutputPath) {
    $outDir = Join-Path $PSScriptRoot 'Output'
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    $safe = ($Subject -replace '[^A-Za-z0-9._-]','_')
    $CerOutputPath = Join-Path $outDir "$safe.cer"
}

Write-Host "[STEP] Exporting public key to $CerOutputPath" -ForegroundColor Cyan
Export-Certificate -Cert $cert -FilePath $CerOutputPath -Force | Out-Null
Write-Host "[OK]   Public key exported." -ForegroundColor Green

Write-Host ""
Write-Host "================================================================"
Write-Host (" Next steps:")
Write-Host ("   1. Run New-EntraApp.ps1 -CertificatePublicKeyPath '$CerOutputPath'")
Write-Host ("      to upload the public key to the Entra app.")
Write-Host ("   2. Set in your LauncherConfig.ps1:")
Write-Host ("         `$global:SpnCertificateThumbprint = '{0}'" -f $cert.Thumbprint)
Write-Host ("         `$global:SpnClientId              = '<app-client-id>'")
Write-Host ("         `$global:SpnTenantId              = '<tenant-id>'")
Write-Host "================================================================"
