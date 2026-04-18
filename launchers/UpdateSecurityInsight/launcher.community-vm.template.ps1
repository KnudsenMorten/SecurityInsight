#Requires -Version 5.1
<#
.SYNOPSIS
    Community launcher for SecurityInsight\UpdateSecurityInsight (user VM / box).
.DESCRIPTION
    Dot-sources LauncherConfig.ps1 (user copies from LauncherConfig.sample.ps1)
    to set SPN tenant + client id + secret. No internal-only modules.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    throw "Launcher: cannot locate solution repo root walking up from '$Start'."
}
if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }

if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1' }
if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
    throw "Community launcher: $LauncherConfigPath not found. Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1 and fill in SPN values."
}
. $LauncherConfigPath


# ================================================================================
#  AUTHENTICATION  -- community launcher resolves the credential in this priority:
#     1. Managed Identity              ($global:UseManagedIdentity = $true)
#     2. SPN + Key Vault-stored secret ($global:SpnKeyVaultName + $global:SpnSecretName)
#     3. SPN + certificate thumbprint  ($global:SpnCertificateThumbprint)
#     4. SPN + plaintext secret        ($global:SpnClientSecret)  [TESTING ONLY]
#
#  Methods 1-3 are production-safe. Method 4 is kept for local labs / initial
#  validation only -- see the big warning in LauncherConfig.sample.ps1.
# ================================================================================
if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
    throw "Launcher: `$global:SpnTenantId is required (set it in LauncherConfig.ps1)."
}

# Helper: minimal Az + Graph module probe without forcing heavy imports.
$haveAz = (Get-Module -ListAvailable -Name 'Az.Accounts')
if (-not $haveAz) { throw "Launcher: Az.Accounts module not installed. Run 'Install-Module Az -Scope CurrentUser'." }
Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue

$haveKv = (Get-Module -ListAvailable -Name 'Az.KeyVault')
$haveMg = (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')

$authMethodUsed = $null

if ([bool]$global:UseManagedIdentity) {
    Write-Host "[LAUNCHER] Auth method: Managed Identity"
    Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
    if ($haveMg) {
        # Graph via MI requires the MI to have the Graph app permissions directly.
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
        Connect-MgGraph -Identity -NoWelcome -WarningAction SilentlyContinue | Out-Null
    }
    $authMethodUsed = 'ManagedIdentity'
}
elseif ($global:SpnKeyVaultName -and $global:SpnSecretName) {
    Write-Host ("[LAUNCHER] Auth method: SPN + Key Vault  (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
    if (-not $haveKv) { throw "Launcher: Az.KeyVault module not installed for Key Vault auth. Run 'Install-Module Az.KeyVault -Scope CurrentUser'." }
    if (-not $global:SpnClientId) { throw "Launcher: `$global:SpnClientId is required for SPN + KV auth." }
    Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue
    # 1) MI session to read the secret.
    Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
    $secretSecure = (Get-AzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
    if (-not $secretSecure) { throw "Launcher: Key Vault returned no value for '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
    # 2) Reconnect as the SPN with the KV-stored secret.
    Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
    $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
    Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
    # 3) Expose plaintext to engines that still call Connect-MicrosoftGraphPS themselves.
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
    try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($haveMg) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
        $credForGraph = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force))
        Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
    }
    $authMethodUsed = 'SPN-KeyVault'
}
elseif ($global:SpnCertificateThumbprint) {
    Write-Host ("[LAUNCHER] Auth method: SPN + certificate  (thumbprint='{0}')" -f $global:SpnCertificateThumbprint)
    if (-not $global:SpnClientId) { throw "Launcher: `$global:SpnClientId is required for SPN + certificate auth." }
    Connect-AzAccount -ServicePrincipal `
        -Tenant $global:SpnTenantId `
        -ApplicationId $global:SpnClientId `
        -CertificateThumbprint $global:SpnCertificateThumbprint `
        -WarningAction SilentlyContinue | Out-Null
    if ($haveMg) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
        Connect-MgGraph -TenantId $global:SpnTenantId `
                         -ClientId  $global:SpnClientId `
                         -CertificateThumbprint $global:SpnCertificateThumbprint `
                         -NoWelcome -WarningAction SilentlyContinue | Out-Null
    }
    $authMethodUsed = 'SPN-Certificate'
}
elseif ($global:SpnClientId -and $global:SpnClientSecret) {
    Write-Host "[LAUNCHER] Auth method: SPN + plaintext secret  [TESTING ONLY]" -ForegroundColor Yellow
    Write-Warning "Plaintext SPN secret in LauncherConfig.ps1 is fine for labs / initial validation but NOT recommended for production. Switch to Managed Identity, SPN+KeyVault, or SPN+certificate (see LauncherConfig.sample.ps1)."
    $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
    $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
    Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
    $authMethodUsed = 'SPN-PlaintextSecret'
    # Engines that need Graph will connect themselves using $global:SpnClientSecret.
}
else {
    throw @"
Launcher: no authentication method configured in LauncherConfig.ps1.
Pick one and populate the corresponding variables (see LauncherConfig.sample.ps1):
  Method 1: `$global:UseManagedIdentity = `$true
  Method 2: `$global:SpnKeyVaultName + `$global:SpnSecretName (+ SpnClientId)
  Method 3: `$global:SpnCertificateThumbprint (+ SpnClientId)
  Method 4: `$global:SpnClientSecret (+ SpnClientId)   [testing only]
"@
}

Write-Host ("[LAUNCHER] Auth established ({0}). Invoking engine..." -f $authMethodUsed)


$global:AutomationFramework = $false
$global:SettingsPath        = $PSScriptRoot
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

$engine = Join-Path $InstallPath 'SOLUTIONS\SecurityInsight\SCRIPTS\UpdateSecurityInsight.ps1'
if (-not (Test-Path -LiteralPath $engine)) { throw "Launcher: engine script not found at $engine." }
& $engine
