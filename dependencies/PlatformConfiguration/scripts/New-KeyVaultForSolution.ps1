#Requires -Version 5.1
<#
.SYNOPSIS
    Create (or reuse) an Azure Key Vault, store a solution's SPN secret in it,
    and optionally grant the VM's Managed Identity 'Key Vault Secrets User'.

.DESCRIPTION
    Platform-level onboarding helper. Bridges New-EntraApp.ps1 (which outputs a
    freshly-created secret) and the launcher's KeyVault-auth mode.

    Idempotent: reuses existing KV and existing secret name. Each re-run with a
    new -SecretValue creates a NEW version of the secret (KV keeps history).

.PARAMETER VaultName
    Short name of the Key Vault. Must be globally unique if new.

.PARAMETER ResourceGroup
    Resource group for the vault.

.PARAMETER Location
    Azure region (e.g. 'westeurope'). Only used if the vault does not exist.

.PARAMETER SecretName
    Name of the secret to create / update. e.g. 'SecurityInsight-Secret'.

.PARAMETER SecretValue
    Plaintext value of the secret (typically the SPN client secret from
    New-EntraApp.ps1 output). Stored as a SecureString at rest.

.PARAMETER GrantReaderObjectIds
    Optional array of objectIds (user / SP / MI) to grant 'Key Vault Secrets User'
    on this vault. Typically the MI of the VM that will run the launcher.

.PARAMETER EnableRbacAuthorization
    Default: $true. Creates KV with RBAC mode. Disable only for legacy access-policy
    tenants.

.EXAMPLE
    .\New-KeyVaultForSolution.ps1 `
        -VaultName kv-securityinsight-prod `
        -ResourceGroup rg-securityinsight `
        -Location westeurope `
        -SecretName SecurityInsight-Secret `
        -SecretValue '<secret from New-EntraApp output>' `
        -GrantReaderObjectIds @('<vm-mi-object-id>')

.NOTES
    Solution       : PlatformConfiguration
    File           : New-KeyVaultForSolution.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$Location,
    [Parameter(Mandatory)][string]$SecretName,
    [Parameter(Mandatory)][string]$SecretValue,
    [string[]]$GrantReaderObjectIds = @(),
    [bool]$EnableRbacAuthorization = $true
)
$ErrorActionPreference = 'Stop'

foreach ($m in 'Az.Accounts','Az.KeyVault','Az.Resources') {
    if (-not (Get-Module -ListAvailable -Name $m)) { Install-Module $m -Scope CurrentUser -Force -AllowClobber }
}
Import-Module Az.Accounts -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.KeyVault  -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Resources -WarningAction SilentlyContinue -ErrorAction Stop

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) { throw "New-KeyVaultForSolution: no Azure session. Launcher must connect first." }

Write-Host "[STEP] Resolving resource group $ResourceGroup" -ForegroundColor Cyan
$rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Host "[STEP] Creating resource group $ResourceGroup in $Location" -ForegroundColor Cyan
    $rg = New-AzResourceGroup -Name $ResourceGroup -Location $Location
}

Write-Host "[STEP] Resolving or creating Key Vault $VaultName" -ForegroundColor Cyan
$kv = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
if (-not $kv) {
    $kv = New-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroup -Location $Location -EnableRbacAuthorization:$EnableRbacAuthorization
    Write-Host "[OK]   Key Vault created: $($kv.ResourceId)" -ForegroundColor Green
} else {
    Write-Host "[OK]   Existing Key Vault: $($kv.ResourceId)" -ForegroundColor Green
}

Write-Host "[STEP] Writing secret $SecretName" -ForegroundColor Cyan
$secureVal = ConvertTo-SecureString $SecretValue -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $secureVal | Out-Null
Write-Host "[OK]   Secret written (new version)." -ForegroundColor Green

foreach ($oid in $GrantReaderObjectIds) {
    try {
        New-AzRoleAssignment -ObjectId $oid -RoleDefinitionName 'Key Vault Secrets User' -Scope $kv.ResourceId -ErrorAction Stop | Out-Null
        Write-Host "[OK]   Granted 'Key Vault Secrets User' to $oid" -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -match 'already|RoleAssignmentExists') { Write-Host "[INFO] $oid already has 'Key Vault Secrets User'." -ForegroundColor Gray }
        else { Write-Warning "Failed granting to ${oid}: $($_.Exception.Message)" }
    }
}

Write-Host ""
Write-Host "================================================================"
Write-Host (" Key Vault ready")
Write-Host ("   Vault      : {0}" -f $kv.VaultUri)
Write-Host ("   SecretName : {0}" -f $SecretName)
Write-Host (" Set in LauncherConfig.ps1:")
Write-Host ("   `$global:SpnTenantId      = '<tenant-id>'")
Write-Host ("   `$global:SpnClientId      = '<app-client-id>'")
Write-Host ("   `$global:SpnKeyVaultName  = '{0}'" -f $VaultName)
Write-Host ("   `$global:SpnSecretName    = '{0}'" -f $SecretName)
Write-Host "================================================================"
