param(
  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework
)

#########################################################################################################
# Downloading latest version of Critical Asset Tagging files
#########################################################################################################

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

#########################################################################################################
# Running Main program
#########################################################################################################

#-----------------------------------------------------------------
# Default values (used only if not supplied on command line)
$Default_AutomationFramework = $true
#-----------------------------------------------------------------

# If the user did NOT provide the parameter, apply the default.
# For switches, check whether the parameter was bound.
if (-not $PSBoundParameters.ContainsKey('AutomationFramework')) { $AutomationFramework = [bool]$Default_AutomationFramework }

$ScriptPath = Join-Path $PSScriptRoot "CriticalAssetTagging.ps1"

$Params = @{}
if ($AutomationFramework) { $Params.AutomationFramework = $true }

& $ScriptPath @Params
