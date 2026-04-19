#Requires -Version 5.1
<#
.SYNOPSIS
    Enable system-assigned Managed Identity on an Azure VM or Arc-enabled server,
    optionally grant it Key Vault Secrets User + required Azure RBAC.

.DESCRIPTION
    Idempotent. Finds the VM by name + resource group, enables system-assigned MI
    if not already on, and waits for the identity's objectId to populate. Optional
    RBAC grants so the VM can immediately read its solution's secrets from KV.

.PARAMETER VmName
    Azure VM name (or Arc machine name).

.PARAMETER ResourceGroup
    Resource group containing the VM / Arc machine.

.PARAMETER IsArcMachine
    Switch. Treat target as an Azure Arc machine (Microsoft.HybridCompute/machines)
    instead of Azure VM (Microsoft.Compute/virtualMachines).

.PARAMETER KeyVaultName
    Optional. If set, grant the MI 'Key Vault Secrets User' on this vault.

.PARAMETER AzureRbacRoles
    Optional hashtable role->scope, same shape as New-EntraApp.ps1, but assigned
    to the VM's MI instead of an SPN.

.EXAMPLE
    .\Enable-VmManagedIdentity.ps1 -VmName vm-platform-01 -ResourceGroup rg-platform `
        -KeyVaultName kv-securityinsight-shared

.NOTES
    Solution       : PlatformConfiguration
    File           : Enable-VmManagedIdentity.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VmName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [switch]$IsArcMachine,
    [string]$KeyVaultName,
    [hashtable]$AzureRbacRoles = @{}
)
$ErrorActionPreference = 'Stop'

foreach ($m in 'Az.Accounts','Az.Compute','Az.ConnectedMachine','Az.KeyVault','Az.Resources') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "[STEP] Installing $m ..." -ForegroundColor Cyan
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
}
Import-Module Az.Accounts      -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Resources     -WarningAction SilentlyContinue -ErrorAction Stop

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) { throw "Enable-VmManagedIdentity: no Azure session. Launcher must connect first." }

if ($IsArcMachine) {
    Import-Module Az.ConnectedMachine -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Host "[STEP] Looking up Arc machine $VmName in $ResourceGroup" -ForegroundColor Cyan
    $arc = Get-AzConnectedMachine -Name $VmName -ResourceGroupName $ResourceGroup -ErrorAction Stop
    $objectId = $arc.IdentityPrincipalId
    if ([string]::IsNullOrWhiteSpace([string]$objectId)) {
        Write-Host "[STEP] Enabling system-assigned MI on Arc machine" -ForegroundColor Cyan
        Update-AzConnectedMachine -Name $VmName -ResourceGroupName $ResourceGroup -IdentityType SystemAssigned | Out-Null
        Start-Sleep -Seconds 10
        $arc      = Get-AzConnectedMachine -Name $VmName -ResourceGroupName $ResourceGroup
        $objectId = $arc.IdentityPrincipalId
    }
} else {
    Import-Module Az.Compute -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Host "[STEP] Looking up VM $VmName in $ResourceGroup" -ForegroundColor Cyan
    $vm = Get-AzVM -Name $VmName -ResourceGroupName $ResourceGroup -ErrorAction Stop
    $objectId = $vm.Identity.PrincipalId
    if ([string]::IsNullOrWhiteSpace([string]$objectId)) {
        Write-Host "[STEP] Enabling system-assigned MI on VM" -ForegroundColor Cyan
        Update-AzVM -ResourceGroupName $ResourceGroup -VM $vm -IdentityType SystemAssigned | Out-Null
        Start-Sleep -Seconds 10
        $vm       = Get-AzVM -Name $VmName -ResourceGroupName $ResourceGroup
        $objectId = $vm.Identity.PrincipalId
    }
}

if ([string]::IsNullOrWhiteSpace([string]$objectId)) { throw "Failed to enable or read system-assigned MI on $VmName." }
Write-Host "[OK]   Managed Identity objectId: $objectId" -ForegroundColor Green

if ($KeyVaultName) {
    Write-Host "[STEP] Resolving Key Vault $KeyVaultName" -ForegroundColor Cyan
    Import-Module Az.KeyVault -WarningAction SilentlyContinue -ErrorAction Stop
    $kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
    try {
        New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName 'Key Vault Secrets User' -Scope $kv.ResourceId -ErrorAction Stop | Out-Null
        Write-Host "[OK]   Granted 'Key Vault Secrets User' on $($kv.ResourceId)" -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -match 'already|RoleAssignmentExists') { Write-Host "[INFO] Already granted 'Key Vault Secrets User' on KV." -ForegroundColor Gray }
        else { throw }
    }
}

foreach ($roleName in $AzureRbacRoles.Keys) {
    $scope = $AzureRbacRoles[$roleName]
    try {
        New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop | Out-Null
        Write-Host "[OK]   Granted '$roleName' at $scope" -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -match 'already|RoleAssignmentExists') { Write-Host "[INFO] Already granted '$roleName' at $scope." -ForegroundColor Gray }
        else { Write-Warning "Failed granting '$roleName' at $scope -- $($_.Exception.Message)" }
    }
}

Write-Host ""
Write-Host "================================================================"
Write-Host (" VM Managed Identity ready")
Write-Host ("   Target   : {0} ({1}) in {2}" -f $VmName, $(if ($IsArcMachine) { 'Arc' } else { 'Azure VM' }), $ResourceGroup)
Write-Host ("   ObjectId : {0}" -f $objectId)
Write-Host (" Set in each solution's LauncherConfig.ps1:")
Write-Host ("   `$global:UseManagedIdentity = `$true")
Write-Host ("   `$global:SpnTenantId         = '<tenant-id>'")
Write-Host "================================================================"
