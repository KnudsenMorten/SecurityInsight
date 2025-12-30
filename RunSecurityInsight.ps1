param(
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $ReportTemplate,

  [Parameter(Mandatory=$false)]
  [switch] $Detailed,

  [Parameter(Mandatory=$false)]
  [switch] $Summary,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework
)

#########################################################################################################
# Downloading latest version of SecurityInsight files
#########################################################################################################

$global:GitHubUri = "https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/main"
$Files = @("SecurityInsight.ps1","SecurityInsight_RiskAnalysis.yaml","SecurityInsight_RiskIndex.csv")

Write-Host "SecurityInsight"
Write-Host "Created by Morten Knudsen, Microsoft MVP (@knudsenmortendk - mok@mortenknudsen.net)"
Write-Host ""
Write-Host "Downloading latest version of SecurityInsight/compiler from"
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
$Default_ReportTemplate      = "RiskAnalysis_Summary_v2"
$Default_Summary             = $true
$Default_Detailed            = $false
#-----------------------------------------------------------------

# If the user did NOT provide the parameter, apply the default.
# For switches, check whether the parameter was bound.
if (-not $PSBoundParameters.ContainsKey('AutomationFramework')) { $AutomationFramework = [bool]$Default_AutomationFramework }
if (-not $PSBoundParameters.ContainsKey('Summary'))             { $Summary             = [bool]$Default_Summary }
if (-not $PSBoundParameters.ContainsKey('Detailed'))            { $Detailed            = [bool]$Default_Detailed }
if (-not $PSBoundParameters.ContainsKey('ReportTemplate'))      { $ReportTemplate      = $Default_ReportTemplate }

$ScriptPath = Join-Path $PSScriptRoot "SecurityInsight.ps1"

$Params = @{}
if ($AutomationFramework) { $Params.AutomationFramework = $true }
if ($Summary)            { $Params.Summary = $true }
if ($Detailed)           { $Params.Detailed = $true }
if ($ReportTemplate)     { $Params.ReportTemplate = $ReportTemplate }

& $ScriptPath @Params
