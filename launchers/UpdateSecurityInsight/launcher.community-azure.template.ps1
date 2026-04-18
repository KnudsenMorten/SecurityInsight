#Requires -Version 5.1
#Requires -Modules @{ ModuleName='AutomateITPS'; ModuleVersion='0.1.0' }
<#
.SYNOPSIS
    Community cloud-native launcher for SecurityInsight\UpdateSecurityInsight.
.DESCRIPTION
    External user in Azure Function / Logic App / Hybrid Worker. MI + user's
    own KV holds Modern-ApplicationId-Azure + Modern-Secret-Azure. See
    CriticalAssetTagging\launcher.community-azure.template.ps1 for the
    full setup walkthrough.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
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
    throw "Cloud launcher: cannot locate solution repo root walking up from '$Start'."
}
if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }

$overrideFile = Join-Path $PSScriptRoot 'launcher.override.ps1'
if (Test-Path -LiteralPath $overrideFile) { . $overrideFile }

Import-Module (Join-Path $InstallPath 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Force

$ctx = New-PlatformContext `
    -TenantId           $env:PLATFORM_TENANT_ID `
    -SubscriptionId     $env:PLATFORM_SUBSCRIPTION_ID `
    -KeyVaultName       $env:PLATFORM_KEYVAULT `
    -StorageAccountName $env:PLATFORM_STORAGE_ACCOUNT

Initialize-PlatformIdentity -Context $ctx -IgnoreMissing | Out-Null

if (-not $ctx.Identity.Modern.Azure.AppId -or -not $ctx.Identity.Modern.Azure.Secret) {
    throw "Community cloud launcher: Modern-ApplicationId-Azure / Modern-Secret-Azure not present in KV '$($ctx.Tenant.KeyVaultName)'."
}

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ctx.Identity.Modern.Azure.Secret)
try   { $appSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$global:AutomationFramework = $false
$global:SettingsPath        = $PSScriptRoot
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings
$global:SpnTenantId         = $ctx.Tenant.Id
$global:SpnClientId         = $ctx.Identity.Modern.Azure.AppId
$global:SpnClientSecret     = $appSecretPlain

Write-PlatformLog -Context $ctx -Event 'engine.start' -Message 'UpdateSecurityInsight (community cloud) starting'

try {
    $engine = Join-Path $InstallPath 'SOLUTIONS\SecurityInsight\SCRIPTS\UpdateSecurityInsight.ps1'
    if (-not (Test-Path -LiteralPath $engine)) { throw "Cloud launcher: engine script not found at $engine." }
    & $engine
    Write-PlatformLog -Context $ctx -Event 'engine.end' -Message 'UpdateSecurityInsight (community cloud) completed'
}
catch {
    Write-PlatformLog -Context $ctx -Severity Error -Event 'engine.fail' -Message "UpdateSecurityInsight FAILED: $_" -Data @{ exception = $_.ToString(); stack = $_.ScriptStackTrace }
    throw
}
finally {
    $global:SpnClientSecret = $null
    $appSecretPlain = $null
    [System.GC]::Collect()
}
