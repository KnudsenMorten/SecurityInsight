param(

  [Parameter(Mandatory=$false)]
  [switch] $UpdateFiles,

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
# Default Variables
#########################################################################################################

$UpdateFiles_Default = $false     # do you want to auto-update files from Morten Knudsen Github? Recommendation: set to $false and use the dedicated script (UpdateSecurityInsight.ps1) and test propertly !
$AutomationFramework_Default = $false    # Community edt: set to $false
$SettingsPath_Default = ''     # you can hardcode folder, fx "C:\SCRIPTS\SecurityInsights_Test" - or leave as '', then it uses folder from script launch
$Scope_Default = @("PROD","TEST")  # you can scope which AssetTaggings to apply from the YAML file (CriticalAssetTagging.yaml)

# Apply defaults ONLY when parameter not provided (prevents empty/$null and avoids confusing mixing)
if (-not $PSBoundParameters.ContainsKey('UpdateFiles')) { $UpdateFiles = [bool]$UpdateFiles_Default }
if (-not $PSBoundParameters.ContainsKey('SettingsPath') -or [string]::IsNullOrWhiteSpace($SettingsPath)) {

    if (-not [string]::IsNullOrWhiteSpace($SettingsPath_Default)) {
        # Default value is enabled
        $SettingsPath = $SettingsPath_Default
    }
    else {
        # Default not enabled -> run from where the script was started
        # (wrapper script location)
        $SettingsPath = $PSScriptRoot
    }
}

# Normalize (optional but nice)
$SettingsPath = (Resolve-Path -LiteralPath $SettingsPath).Path

if (-not $PSBoundParameters.ContainsKey('AutomationFramework')) { $AutomationFramework = [bool]$AutomationFramework_Default }
if (-not $PSBoundParameters.ContainsKey('Scope')) { $Scope = [string[]]$Scope_Default }


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
# Downloading latest version of Critical Asset Tagging files
#########################################################################################################

if ($UpdateFiles) {
    $global:GitHubUri = "https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/main"
    $Files = @("CriticalAssetTagging.ps1","CriticalAssetTagging.yaml")

    Write-Host "Critical Asset Tagging"
    Write-Host "Created by Morten Knudsen, Microsoft MVP (@knudsenmortendk - mok@mortenknudsen.net)"
    Write-Host ""
    Write-Host "Downloading latest version of Critical Asset Tagging engine from"
    Write-Host "$GitHubUri"
    Write-Host ""

    foreach ($File in $Files) {
        $FileFullPath = Join-Path $PSScriptRoot $File
        Remove-Item $FileFullPath -ErrorAction SilentlyContinue
        Invoke-WebRequest "$GitHubUri/$File" -OutFile $FileFullPath
    }
}

#########################################################################################################
# Running Main program
#########################################################################################################

$ScriptPath = Join-Path $SettingsPath "CriticalAssetTagging.ps1"

# Build params explicitly (no mixing)
$Params = @{}

# Always pass SettingsPath (your main request)
$Params.SettingsPath = $SettingsPath

# Pass the rest only when enabled / present
if ($AutomationFramework) { $Params.AutomationFramework = $true }
if ($Scope) { $Params.Scope = $Scope }

# dot-source the script so ALL variables above remain available to the called script
. $ScriptPath @Params