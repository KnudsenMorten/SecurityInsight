#########################################################################################################
# Downloading latest version of SecurityInsight files
#########################################################################################################

$global:GitHubUri = "https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/main"
$Files = @("SecurityInsight_RiskAnalysis.ps1", `
           "RunRiskAnalysis_Automation_Framework.ps1", `
           "SecurityInsight_RiskAnalysis_Queries_Locked.yaml", `
           "CriticalAssetTagging.ps1", `
           "RunCriticalAssetTagging_Automation_Framework.ps1", `
           "SecurityInsight_CriticalAssetTagging_Locked.yaml", `
           "CriticalAssetTaggingMaintenance.ps1", `
           "RunCriticalAssetTaggingMaintenance_Automation_Framework.ps1" `
          )

Write-Host "SecurityInsight"
Write-Host "Created by Morten Knudsen, Microsoft MVP (@knudsenmortendk - mok@mortenknudsen.net)"
Write-Host ""
Write-Host "Downloading latest version of SecurityInsight from"
Write-Host "$GitHubUri"
Write-Host ""

foreach ($File in $Files) {
    Write-host "Updating $File"
    $FileFullPath = Join-Path $PSScriptRoot $File
    Remove-Item $FileFullPath -ErrorAction SilentlyContinue
    Invoke-WebRequest "$GitHubUri/$File" -OutFile $FileFullPath
}
