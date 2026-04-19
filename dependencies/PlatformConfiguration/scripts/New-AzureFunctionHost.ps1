#Requires -Version 5.1
<#
.SYNOPSIS
    Provision an Azure Function App (PowerShell 7.4) with a system-assigned Managed
    Identity, bound to a storage account, and optionally linked to a Key Vault for
    secret retrieval. Used to host community-azure / internal-azure launchers.

.DESCRIPTION
    Platform-level onboarding helper. Idempotent: reuses existing RG, storage, and
    Function App with the same names. Prints the App Settings a launcher needs.

    After this script runs you still need to deploy the SecurityInsight (or other
    solution) code into the Function App's wwwroot/. See the solution README's
    "Azure Function / Logic App" section for the recommended layout.

.PARAMETER FunctionAppName
    Globally-unique Function App name.

.PARAMETER ResourceGroup
    Resource group name.

.PARAMETER Location
    Azure region for the Function App + storage. Must be Function-App-supported.

.PARAMETER StorageAccountName
    Storage account for the Function App backing store. Globally unique, 3-24
    lowercase alphanumeric.

.PARAMETER KeyVaultName
    Optional. If set, the function's MI is granted 'Key Vault Secrets User' on it
    and the KV name is added as an App Setting (PLATFORM_KEYVAULT).

.PARAMETER TenantId
    Tenant the function needs to query. Added as PLATFORM_TENANT_ID App Setting.

.PARAMETER SubscriptionIdForSolution
    Subscription the solution engines will query. Added as PLATFORM_SUBSCRIPTION_ID.

.EXAMPLE
    .\New-AzureFunctionHost.ps1 `
        -FunctionAppName fn-securityinsight-prod `
        -ResourceGroup rg-securityinsight-host `
        -Location westeurope `
        -StorageAccountName stsi0prod0a1b2c `
        -KeyVaultName kv-securityinsight-prod `
        -TenantId '<tenant-id>' -SubscriptionIdForSolution '<sub-id>'

.NOTES
    Solution       : PlatformConfiguration
    File           : New-AzureFunctionHost.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FunctionAppName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$Location,
    [Parameter(Mandatory)][string]$StorageAccountName,
    [string]$KeyVaultName,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionIdForSolution
)
$ErrorActionPreference = 'Stop'

foreach ($m in 'Az.Accounts','Az.Resources','Az.Storage','Az.Websites','Az.KeyVault') {
    if (-not (Get-Module -ListAvailable -Name $m)) { Install-Module $m -Scope CurrentUser -Force -AllowClobber }
}
Import-Module Az.Accounts  -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Resources -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Storage   -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Websites  -WarningAction SilentlyContinue -ErrorAction Stop

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) { throw "New-AzureFunctionHost: no Azure session. Launcher must connect first." }

Write-Host "[STEP] Resolving resource group" -ForegroundColor Cyan
$rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
if (-not $rg) { $rg = New-AzResourceGroup -Name $ResourceGroup -Location $Location }

Write-Host "[STEP] Resolving storage account" -ForegroundColor Cyan
$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $sa) {
    $sa = New-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -Location $Location -SkuName Standard_LRS -Kind StorageV2
    Write-Host "[OK]   Storage account created." -ForegroundColor Green
}

Write-Host "[STEP] Resolving / creating Function App" -ForegroundColor Cyan
$fn = Get-AzFunctionApp -ResourceGroupName $ResourceGroup -Name $FunctionAppName -ErrorAction SilentlyContinue
if (-not $fn) {
    $fn = New-AzFunctionApp -ResourceGroupName $ResourceGroup -Name $FunctionAppName `
        -Location $Location -StorageAccountName $StorageAccountName `
        -Runtime PowerShell -RuntimeVersion 7.4 -FunctionsVersion 4 `
        -OSType Windows -IdentityType SystemAssigned
    Write-Host "[OK]   Function App created with system-assigned MI." -ForegroundColor Green
} else {
    if ($fn.IdentityType -ne 'SystemAssigned') {
        Update-AzFunctionApp -ResourceGroupName $ResourceGroup -Name $FunctionAppName -IdentityType SystemAssigned | Out-Null
        $fn = Get-AzFunctionApp -ResourceGroupName $ResourceGroup -Name $FunctionAppName
    }
    Write-Host "[OK]   Existing Function App reused." -ForegroundColor Green
}

$miObjectId = $fn.IdentityPrincipalId
if (-not $miObjectId) {
    Start-Sleep -Seconds 10
    $fn = Get-AzFunctionApp -ResourceGroupName $ResourceGroup -Name $FunctionAppName
    $miObjectId = $fn.IdentityPrincipalId
}
if (-not $miObjectId) { throw "Failed to resolve system-assigned MI on Function App." }
Write-Host "[OK]   Function App MI objectId: $miObjectId" -ForegroundColor Green

# App settings
$settings = @{
    'PLATFORM_TENANT_ID'        = $TenantId
    'PLATFORM_SUBSCRIPTION_ID'  = $SubscriptionIdForSolution
}
if ($KeyVaultName) { $settings['PLATFORM_KEYVAULT']        = $KeyVaultName }
$settings['PLATFORM_STORAGE_ACCOUNT'] = $StorageAccountName

Write-Host "[STEP] Setting Function App settings" -ForegroundColor Cyan
Update-AzFunctionAppSetting -ResourceGroupName $ResourceGroup -Name $FunctionAppName -AppSetting $settings | Out-Null
Write-Host "[OK]   App settings set." -ForegroundColor Green

if ($KeyVaultName) {
    Import-Module Az.KeyVault -WarningAction SilentlyContinue -ErrorAction Stop
    $kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
    try {
        New-AzRoleAssignment -ObjectId $miObjectId -RoleDefinitionName 'Key Vault Secrets User' -Scope $kv.ResourceId -ErrorAction Stop | Out-Null
        Write-Host "[OK]   Granted 'Key Vault Secrets User' to Function MI on $KeyVaultName." -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -match 'already|RoleAssignmentExists') { Write-Host "[INFO] Already granted." -ForegroundColor Gray }
        else { throw }
    }
}

Write-Host ""
Write-Host "================================================================"
Write-Host (" Function App host ready")
Write-Host ("   Name        : {0}" -f $FunctionAppName)
Write-Host ("   MI objectId : {0}" -f $miObjectId)
Write-Host ("   Storage     : {0}" -f $StorageAccountName)
if ($KeyVaultName) {
Write-Host ("   Key Vault   : {0} (Secrets User granted)" -f $KeyVaultName)
}
Write-Host ""
Write-Host (" Next: deploy your solution's scripts + launchers into wwwroot/.")
Write-Host (" Each launcher.community-azure.template.ps1 reads PLATFORM_* env vars")
Write-Host (" automatically.")
Write-Host "================================================================"
