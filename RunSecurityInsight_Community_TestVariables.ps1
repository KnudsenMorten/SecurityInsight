param(
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $ReportTemplate,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework,

  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $SettingsPath,

  [Parameter(Mandatory=$false)]
  [switch] $BuildSummaryByAI
)

#########################################################################################################
# Global Reset (clean reruns in same PowerShell session)
#########################################################################################################

# Core execution globals
$global:SettingsPath                = $null
$global:ReportTemplate              = $null
$global:AutomationFramework         = $null
$global:OverwriteXlsx               = $null

# Mail globals (community edition section)
$global:SendMail                    = $null
$global:MailTo                      = $null
$global:Mail_SendAnonymous          = $null
$global:SMTPUser                    = $null
$global:SmtpServer                  = $null
$global:SMTPPort                    = $null
$global:SMTP_UseSSL                 = $null
$global:SmtpUsername                = $null
$global:SmtpPassword                = $null
$global:SecureCredentialsSMTP       = $null

# SPN globals
$global:SpnTenantId                 = $null
$global:SpnClientId                 = $null
$global:SpnClientSecret             = $null

# AI globals (main script reads Global:OpenAI_* and builds AI_Uri)
$global:BuildSummaryByAI            = $null
$global:OpenAI_apiKey               = $null
$global:OpenAI_endpoint             = $null
$global:OpenAI_deployment           = $null
$global:OpenAI_apiVersion           = $null
$global:OpenAI_MaxTokensPerRequest  = $null
$global:AI_MaxTokensPerRequest      = $null
$global:AI_Uri                      = $null

#########################################################################################################
# Defaults (single source of truth)
#########################################################################################################

$AutomationFramework_Default = $false                   # $false = Community edition
$SettingsPath_Default        = ''                       # you can hardcode folder, fx "C:\SCRIPTS\SecurityInsights_Test" - or leave as '', then it uses folder from script launch
$ReportTemplate_Default      = 'RiskAnalysis_Summary'   # default report template to use, if nothing specified
$OverwriteXlsx_Default       = $true                    # $true = overwrite excel output file
$BuildSummaryByAI_Default    = $true                    # $true = enable AI summary integration (require OpenAI PAYG instance deployment)

#########################################################################################################
# Resolve runtime values (CMDLINE WINS, otherwise DEFAULT)
#########################################################################################################

# Switches: cmdline presence wins, otherwise default.
# NOTE: also supports -AutomationFramework:$false etc.
$AutomationFramework = if ($PSBoundParameters.ContainsKey('AutomationFramework')) { [bool]$AutomationFramework } else { [bool]$AutomationFramework_Default }
$BuildSummaryByAI    = if ($PSBoundParameters.ContainsKey('BuildSummaryByAI'))    { [bool]$BuildSummaryByAI }    else { [bool]$BuildSummaryByAI_Default }

# Strings: cmdline wins; otherwise default
$SettingsPath = if ($PSBoundParameters.ContainsKey('SettingsPath')) { $SettingsPath } else { $SettingsPath_Default }
if ([string]::IsNullOrWhiteSpace($SettingsPath)) { $SettingsPath = $PSScriptRoot }
$SettingsPath = (Resolve-Path -LiteralPath $SettingsPath).Path

$ReportTemplate = if ($PSBoundParameters.ContainsKey('ReportTemplate')) { $ReportTemplate } else { $ReportTemplate_Default }

# OverwriteXlsx is only defaulted here (unless you later add it as param)
$OverwriteXlsx = [bool]$OverwriteXlsx_Default

#########################################################################################################
# Publish resolved values to globals (main script reads these)
#########################################################################################################

$global:SettingsPath        = $SettingsPath
$global:ReportTemplate      = $ReportTemplate
$global:AutomationFramework = $AutomationFramework
$global:OverwriteXlsx       = $OverwriteXlsx
$global:BuildSummaryByAI    = $BuildSummaryByAI

#########################################################################################################
# Optional: show config right away (helps troubleshooting)
#########################################################################################################

Write-Host ("[LAUNCHER] AutomationFramework={0} BuildSummaryByAI={1}" -f `
  $global:AutomationFramework, $global:BuildSummaryByAI)

Write-Host ("[LAUNCHER] SettingsPath={0}" -f $global:SettingsPath)
Write-Host ("[LAUNCHER] ReportTemplate={0}" -f $global:ReportTemplate)
Write-Host ""

#########################################################################################################
# Community Edition variables - fit to your needs
# Note: don’t hardcode secrets; prefer env vars or SecretManagement.
#########################################################################################################

if (-not $global:AutomationFramework) {

  # SPN
  $global:SpnTenantId        = "f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"     # override per your SPN tenant if different
  $global:SpnClientId        = "416ef8bc-1cbf-4d06-a759-6943fbde946a"
  $global:SpnClientSecret    = "1Ko8Q~Xxn4pG6Mq4ew4DWHarPFNDdp0FTdjstdqc"

  # Email Notifications
  $global:SendMail           = $true
  $global:MailTo             = @("mok@2linkit.net")
  $global:Mail_SendAnonymous = $false
  $global:SMTPUser           = "svc-automation@2linkit.net"
  $global:SmtpServer         = "smtp-relay.brevo.com"
  $global:SMTPPort           = 587
  $global:SMTP_UseSSL        = $true

  if (-not $global:Mail_SendAnonymous) {

    $global:SmtpUsername = "796b0a001@smtp-brevo.com"
    $global:SmtpPassword = "jLAGgBnb84krSONY"

    $SecurePassword = ConvertTo-SecureString $global:SmtpPassword -AsPlainText -Force
    $global:SecureCredentialsSMTP = New-Object System.Management.Automation.PSCredential (
      $global:SmtpUsername,
      $SecurePassword
    )
  }
}

#########################################################################################################
# BuildSummaryByAI defaults (globals main script already expects)
#########################################################################################################

if ($global:BuildSummaryByAI) {

  $Global:OpenAI_apiKey              = "Bi6k2y7INR15FWzjkko7Rc3K6ZUPgjunhaYmj4c92WHhqA6mNh3cJQQJ99CAACfhMk5XJ3w3AAABACOGBEoI"
  $Global:OpenAI_endpoint            = "https://security-insight.openai.azure.com"
  $Global:OpenAI_deployment          = "security-insight"
  $Global:OpenAI_apiVersion          = "2025-01-01-preview"
  $Global:OpenAI_MaxTokensPerRequest = 16384

  $global:AI_MaxTokensPerRequest = [int]$global:OpenAI_MaxTokensPerRequest
  Write-Host ("[LAUNCHER] AI Max Tokens Per Request: {0}" -f $global:AI_MaxTokensPerRequest)
}

#########################################################################################################
# Running Main program
#########################################################################################################

$ScriptPath = Join-Path $global:SettingsPath 'SecurityInsight.ps1'
if (-not (Test-Path -LiteralPath $ScriptPath)) {
  throw "Main script not found: $ScriptPath"
}

. $ScriptPath
