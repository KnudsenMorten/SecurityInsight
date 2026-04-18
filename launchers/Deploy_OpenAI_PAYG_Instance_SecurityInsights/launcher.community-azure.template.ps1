#Requires -Version 5.1
<#
.SYNOPSIS
    Community cloud launcher for Deploy_OpenAI  -- external user in a Function/LogicApp with their own MI + KV holding Modern-*-Azure.
#>
[CmdletBinding()]
param([string]$InstallPath)

$ErrorActionPreference = 'Stop'

function Resolve-AutomateITRepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    throw "Launcher: cannot locate AutomateIT repo root walking up from '$Start'."
}
if (-not $InstallPath) { $InstallPath = Resolve-AutomateITRepoRoot }

$overrideFile = Join-Path $PSScriptRoot 'launcher.override.ps1'
if (Test-Path -LiteralPath $overrideFile) { . $overrideFile }

#Requires -Modules @{ ModuleName='AutomateITPS'; ModuleVersion='0.1.0' }
Import-Module (Join-Path $InstallPath 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Force

$ctx = New-PlatformContext `
    -TenantId           $env:AUTOMATEIT_TENANT_ID `
    -SubscriptionId     $env:AUTOMATEIT_SUBSCRIPTION_ID `
    -KeyVaultName       $env:AUTOMATEIT_KEYVAULT `
    -StorageAccountName $env:AUTOMATEIT_STORAGE_ACCOUNT
Initialize-PlatformIdentity -Context $ctx -IgnoreMissing | Out-Null

if (-not $ctx.Identity.Modern.Azure.AppId -or -not $ctx.Identity.Modern.Azure.Secret) {
    throw "Cloud launcher: Modern-ApplicationId-Azure / Modern-Secret-Azure not present in KV '$($ctx.Tenant.KeyVaultName)'."
}

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ctx.Identity.Modern.Azure.Secret)
try   { $appSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$cred = [pscredential]::new($ctx.Identity.Modern.Azure.AppId, (ConvertTo-SecureString $appSecretPlain -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -TenantId $ctx.Tenant.Id -Credential $cred -Subscription '<primary-subscription-id>' | Out-Null

# Deploy -- customer values for the OpenAI account/deployment
$global:SubscriptionId    = '<primary-subscription-id>'
$global:ResourceGroupName = 'rg-security-insight'
$global:Location          = 'swedencentral'
$global:AccountName       = 'oai-security-insight'
$global:DeploymentName    = 'oai-security-insight'
$global:ModelName         = 'gpt-4.1-mini'
$global:ModelVersion      = 'latest'
$global:Capacity          = 100

try {
    $engine = Join-Path $InstallPath 'SOLUTIONS\SecurityInsight\SCRIPTS\Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1'
if (-not (Test-Path -LiteralPath $engine)) {
    throw "Launcher: engine script not found at $engine. Run Update-Platform.ps1 first."
}
& $engine
}
finally {
    $appSecretPlain = $null
    [System.GC]::Collect()
}
