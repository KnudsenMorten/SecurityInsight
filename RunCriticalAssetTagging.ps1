param(
  [Parameter(Mandatory=$false)]
  [string] $SettingsPath,

  [Parameter(Mandatory=$false)]
  [ValidateSet('PROD','TEST')]
  [string[]] $Scope,

  [Parameter(Mandatory=$false)]
  [switch] $SuppressErrors,

  [Parameter(Mandatory=$false)]
  [switch] $SuppressWarnings,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework
)

#########################################################################################################
# Global Reset (clean reruns in same PowerShell session)
#########################################################################################################

# Core execution globals
$global:SettingsPath        = $PSScriptRoot
$global:Scope               = @('PROD')

# SPN globals
$global:SpnTenantId         = $null
$global:SpnClientId         = $null
$global:SpnClientSecret     = $null

# YAML globals (engine will read these)
$global:LockedYamlFile      = $null
$global:CustomYamlFile      = $null
$global:LegacyYamlFile      = $null

#########################################################################################################
# Default Variables
#########################################################################################################

$AutomationFramework_Default = $false                   # $false = Community edition
$SettingsPath_Default        = ''                       # you can hardcode folder, fx "C:\SCRIPTS\SecurityInsights_Test" - or leave as '', then it uses folder from script launch
$Scope_Default               = @('PROD')                # Defines which AssetTaggings to include from YAML file

$SuppressErrors_Default      = $false
$SuppressWarnings_Default    = $false
$WhatIfMode                  = $false

# YAML defaults
$LockedYamlFile_Default      = 'SecurityInsight_CriticalAssetTagging_Locked.yaml'
$CustomYamlFile_Default      = 'SecurityInsight_CriticalAssetTagging_Custom.yaml'
$LegacyYamlFile_Default      = 'CriticalAssetTagging.yaml'

#########################################################################################################
# Resolve runtime values (CMDLINE WINS, otherwise DEFAULT)
#########################################################################################################


$AutomationFramework = if ($PSBoundParameters.ContainsKey('AutomationFramework')) { [bool]$AutomationFramework } else { [bool]$AutomationFramework_Default }
$SuppressErrors      = if ($PSBoundParameters.ContainsKey('SuppressErrors'))      { [bool]$SuppressErrors }      else { [bool]$SuppressErrors_Default }
$SuppressWarnings    = if ($PSBoundParameters.ContainsKey('SuppressWarning'))     { [bool]$SuppressWarnings }    else { [bool]$SuppressWarnings_Default }

if (-not $PSBoundParameters.ContainsKey('Scope') -or -not $Scope -or $Scope.Count -eq 0) {
  $Scope = [string[]]$Scope_Default
}

$SettingsPath = if ($PSBoundParameters.ContainsKey('SettingsPath')) { $SettingsPath } else { $SettingsPath_Default }
if ([string]::IsNullOrWhiteSpace($SettingsPath)) { $SettingsPath = $PSScriptRoot }
$SettingsPath = (Resolve-Path -LiteralPath $SettingsPath).Path

$LockedYamlFile = if ($PSBoundParameters.ContainsKey('LockedYamlFile') -and -not [string]::IsNullOrWhiteSpace($LockedYamlFile)) { $LockedYamlFile } else { $LockedYamlFile_Default }
$CustomYamlFile = if ($PSBoundParameters.ContainsKey('CustomYamlFile') -and -not [string]::IsNullOrWhiteSpace($CustomYamlFile)) { $CustomYamlFile } else { $CustomYamlFile_Default }
$LegacyYamlFile = if ($PSBoundParameters.ContainsKey('LegacyYamlFile') -and -not [string]::IsNullOrWhiteSpace($LegacyYamlFile)) { $LegacyYamlFile } else { $LegacyYamlFile_Default }

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
$global:SuppressErrors      = $SuppressErrors
$global:SuppressWarnings    = $SuppressWarnings
$global:WhatIfMode          = $WhatIfMode

$global:LockedYamlFile      = $LockedYamlFile
$global:CustomYamlFile      = $CustomYamlFile
$global:LegacyYamlFile      = $LegacyYamlFile

#########################################################################################################
# Optional: show config right away (helps troubleshooting)
#########################################################################################################

Write-Host ("[LAUNCHER] AutomationFramework={0}" -f $global:AutomationFramework)
Write-Host ("[LAUNCHER] SettingsPath={0}" -f $global:SettingsPath)
Write-Host ("[LAUNCHER] Scope={0}" -f ($global:Scope -join ', '))
Write-Host ("[LAUNCHER] SuppressErrors={0}" -f $global:SuppressErrors)
Write-Host ("[LAUNCHER] SuppressWarnings={0}" -f $global:SuppressWarnings)
Write-Host ("[LAUNCHER] LockedYamlFile={0}" -f $global:LockedYamlFile)
Write-Host ("[LAUNCHER] CustomYamlFile={0}" -f $global:CustomYamlFile)
Write-Host ("[LAUNCHER] LegacyYamlFile={0}" -f $global:LegacyYamlFile)
Write-Host ""

#########################################################################################################
# Running Main program
#########################################################################################################

$ScriptPath = Join-Path $global:SettingsPath 'CriticalAssetTagging.ps1'
if (-not (Test-Path -LiteralPath $ScriptPath)) {
  throw "Main script not found: $ScriptPath"
}

. $ScriptPath
