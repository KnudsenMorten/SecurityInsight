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
$BuildSummaryByAI_Default    = $false                   # $true = enable AI summary integration (require OpenAI PAYG instance deployment)

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

############################################################
# Variable: AutomationFrameWork = $False
# Community Edition variables - fit to your needs !
# Note: don’t hardcode secrets; prefer env vars or SecretManagement.
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

if (-not $global:AutomationFramework) {

    # SPN
    $global:SpnTenantId        = "<Your TenantId>"     # override per your SPN tenant if different
    $global:SpnClientId        = "<APP/CLIENT ID GUID>"
    $global:SpnClientSecret    = "<CLIENT SECRET VALUE>"

    # Email Notifications
    $global:SendMail           = $false # true/false
    $global:MailTo             = @()    # array of recipients
    $global:Mail_SendAnonymous = $false # $true = anonymous login against SMTP server
    $global:SMTPUser           = "<SMTP from address>"   # Default FROM address
    $global:SmtpServer         = "<SMTP server>"
    $global:SMTPPort           = 587
    $global:SMTP_UseSSL        = $true  # or $false

    if (-not $global:Mail_SendAnonymous) {

        # Consider to use an Azure Keyvault and retrieve credentials from there !
        $global:SmtpUsername   = "<SMTP username>"
        $global:SmtpPassword   = "<SMTP password>"

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

    $global:OpenAI_apiKey              = "<API Key>"     # sample: "xxxxxxxxxxxxxxxxxxxxx"
    $global:OpenAI_endpoint            = "<URL>"     # sample: "https://xxxxx.openai.azure.com"
    $global:OpenAI_deployment          = "<Open AI Deployment Name>"     # sample: "security-insight"
    $global:OpenAI_apiVersion          = "<OPEN AI Deployment API version for REST api>"     # sample: "2025-01-01-preview"
    $global:OpenAI_MaxTokensPerRequest = 16384  # Recommended: 16384 - Azure OpenAI max_tokens default - modify to your needs

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
