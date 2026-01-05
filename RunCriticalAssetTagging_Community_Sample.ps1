param(
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $SettingsPath,

  [Parameter(Mandatory=$false)]
  [ValidateSet('PROD','TEST')]
  [string[]] $Scope,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework
)

#########################################################################################################
# Global Reset (clean reruns in same PowerShell session)
#########################################################################################################

# Core execution globals
$global:SettingsPath        = $null
$global:AutomationFramework = $null
$global:Scope               = $null

# SPN globals
$global:SpnTenantId         = $null
$global:SpnClientId         = $null
$global:SpnClientSecret     = $null

#########################################################################################################
# Default Variables
#########################################################################################################

$AutomationFramework_Default = $false                   # $false = Community edition
$SettingsPath_Default        = ''                       # you can hardcode folder, fx "C:\SCRIPTS\SecurityInsights_Test" - or leave as '', then it uses folder from script launch
$Scope_Default               = @('PROD','TEST')         # Defines which AssetTaggings to include from YAML file
$WhatIfMode                  = $false

#########################################################################################################
# Resolve runtime values (CMDLINE WINS, otherwise DEFAULT)
#########################################################################################################

$AutomationFramework = if ($PSBoundParameters.ContainsKey('AutomationFramework')) { [bool]$AutomationFramework } else { [bool]$AutomationFramework_Default }

if (-not $PSBoundParameters.ContainsKey('Scope') -or -not $Scope -or $Scope.Count -eq 0) {
  $Scope = [string[]]$Scope_Default
}

$SettingsPath = if ($PSBoundParameters.ContainsKey('SettingsPath')) { $SettingsPath } else { $SettingsPath_Default }
if ([string]::IsNullOrWhiteSpace($SettingsPath)) { $SettingsPath = $PSScriptRoot }
$SettingsPath = (Resolve-Path -LiteralPath $SettingsPath).Path

############################################################
# AutomationFrameWork = $False
# Community Edition variables - fit to your needs !
############################################################

<# PRE-REQ: ONBOARDING OF SERVICE PRINCIPAL IN ENTRA
    # Create new App Registration / service principal with a secret

    # Delegate API permissions - found under 'APIs my organization uses'. Remember: Grant Admin Control
        Microsoft Threat Protection
            AdvancedHunting.Read.All   (to run queries against Exposure Graph)

        Microsoft Graph
            ThreatHunting.Read.All     (to run queries against Exposure Graph)

        WindowsDefenderATP
            Machine.ReadWrite.All      (to set tag info on device)
#>

If (-not $AutomationFramework) {

    $global:SpnTenantId         = "<Your TenantId>"     # override per your SPN tenant if different
    $global:SpnClientId         = "<APP/CLIENT ID GUID>"
    $global:SpnClientSecret     = "<CLIENT SECRET VALUE>"
}

#########################################################################################################
# Publish resolved values to globals (main script reads these)
#########################################################################################################

$global:SettingsPath        = $SettingsPath
$global:Scope               = $Scope
$global:AutomationFramework = $AutomationFramework
$global:WhatIfMode          = $WhatIfMode

#########################################################################################################
# Optional: show config right away (helps troubleshooting)
#########################################################################################################

Write-Host ("[LAUNCHER] AutomationFramework={0}" -f $global:AutomationFramework)
Write-Host ("[LAUNCHER] SettingsPath={0}" -f $global:SettingsPath)
Write-Host ("[LAUNCHER] Scope={0}" -f ($global:Scope -join ', '))
Write-Host ""

#########################################################################################################
# Running Main program
#########################################################################################################

$ScriptPath = Join-Path $global:SettingsPath 'CriticalAssetTagging.ps1'
if (-not (Test-Path -LiteralPath $ScriptPath)) {
  throw "Main script not found: $ScriptPath"
}

. $ScriptPath
