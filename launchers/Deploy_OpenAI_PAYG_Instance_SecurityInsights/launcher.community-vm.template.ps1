#Requires -Version 5.1
<#
.SYNOPSIS
    Community launcher for Deploy_OpenAI  -- runs on an external user's box. Reads SPN credentials from LauncherConfig.ps1 (.gitignore'd).
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

$cfgPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1'
if (-not (Test-Path -LiteralPath $cfgPath)) {
    throw "Community launcher: $cfgPath not found. Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1 and fill in your test SPN."
}
. $cfgPath

if ($global:SpnTenantId -and $global:SpnClientId -and $global:SpnClientSecret) {
    $cred = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force))
    Connect-AzAccount -ServicePrincipal -TenantId $global:SpnTenantId -Credential $cred -Subscription '<primary-subscription-id>' | Out-Null
}

# Deploy -- customer values for the OpenAI account/deployment
$global:SubscriptionId    = '<primary-subscription-id>'
$global:ResourceGroupName = 'rg-security-insight'
$global:Location          = 'swedencentral'
$global:AccountName       = 'oai-security-insight'
$global:DeploymentName    = 'oai-security-insight'
$global:ModelName         = 'gpt-4.1-mini'
$global:ModelVersion      = 'latest'
$global:Capacity          = 100

$engine = Join-Path $InstallPath 'SOLUTIONS\SecurityInsight\SCRIPTS\Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1'
if (-not (Test-Path -LiteralPath $engine)) {
    throw "Launcher: engine script not found at $engine. Run Update-Platform.ps1 first."
}
& $engine
