param(
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $ReportTemplate,

  [Parameter(Mandatory=$false)]
  [switch] $Detailed,

  [Parameter(Mandatory=$false)]
  [switch] $Summary,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework,

  [Parameter(Mandatory=$false)]
  [switch] $UpdateFiles,

  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $SettingsPath,

  [Parameter(Mandatory=$false)]
  [switch] $BuildSummaryByAI
)


#########################################################################################################
# Default Variables
#########################################################################################################

$UpdateFiles_Default = $false     # do you want to auto-update files from Morten Knudsen Github? Recommendation: set to $false and use the dedicated script (UpdateSecurityInsight.ps1) and test propertly !
$AutomationFramework_Default = $false    # Community edt: set to $false
$SettingsPath_Default = ''     # you can hardcode folder, fx "C:\SCRIPTS\SecurityInsights_Test" - or leave as '', then it uses folder from script launch
$ReportTemplate_Default = "RiskAnalysis_Summary"  # See options in the ReportTemplates-section in the YAML file (SecurityInsight_RiskAnalysis.yaml)
$OverwriteXlsx = $true # Overwrite existing Excel file if true

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
if (-not $PSBoundParameters.ContainsKey('ReportTemplate'))      { $ReportTemplate      = $ReportTemplate_Default }

#######################################################################
# Variables: AutomationFrameWork / AutomationFramework_Default = $true
# Morten Knudsen customer edition (locked)
#######################################################################
If ($AutomationFramework) {
    $Summary_Default = $true
    $Detailed_Default = $false

    if (-not $PSBoundParameters.ContainsKey('Summary'))   { $Summary  = [bool]$Summary_Default }
    if (-not $PSBoundParameters.ContainsKey('Detailed'))  { $Detailed = [bool]$Detailed_Default }
}

############################################################
# Variable: AutomationFrameWork = $False
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

    # Email Notifications
    $SendMail                   = $false # true/false
    $MailTo                     = @()    # array of recipients
    $Mail_SendAnonymous         = $false        # $true = anonymous login against SMTP server
    $SMTPUser                   = "<SMTP from address>"   # Default FROM address
    $SmtpServer                 = "<SMTP server>"
    $SMTPPort                   = 587        # or 587 / 465
    $SMTP_UseSSL                = $true      # or $false

    If (-not $Mail_SendAnonymous) {

        # Consider to use an Azure Keyvault and retrieve credentials from there !
        $SmtpUsername               = "<SMTP username>"
        $SmtpPassword               = "<SMTP password>"

        $SecurePassword = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
        $SecureCredentialsSMTP = New-Object System.Management.Automation.PSCredential (
            $SmtpUsername,
            $SecurePassword
        )
    }
}

############################################################
# Variable: $BuildSummaryByAI_Default
# Enable AI Summary Integration
# Set $BuildSummaryByAI_Default to $true + extra parms
############################################################
$BuildSummaryByAI_Default = $false

if ($PSBoundParameters.ContainsKey('BuildSummaryByAI')) {
    # User explicitly enabled it
    $BuildSummaryByAI = $true
}
else {
    # Not provided → fall back to default
    $BuildSummaryByAI = [bool]$BuildSummaryByAI_Default
}

If ($BuildSummaryByAI) {

    # AI (explicit values; keep as-is if you want, but consider storing secrets elsewhere)
    $AI_apiKey     = ""   # sample: "xxxxxxxxxxxxxxxxxxxxx"
    $AI_endpoint   = ""   # sample: "https://xxxxx.openai.azure.com"
    $AI_deployment = ""   # sample: "security-insight"
    $AI_apiVersion = ""   # sample: "2025-01-01-preview"
}


#########################################################################################################
# Downloading latest version of SecurityInsight files
#########################################################################################################

if ($UpdateFiles) {
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
}


#########################################################################################################
# Running Main program
#########################################################################################################

$ScriptPath = Join-Path $SettingsPath "SecurityInsight.ps1"

# Build params explicitly (no mixing)
$Params = @{}

# Always pass SettingsPath (your main request)
$Params.SettingsPath = $SettingsPath

# Pass the rest only when enabled / present
if ($AutomationFramework) { $Params.AutomationFramework = $true }
if ($Summary)            { $Params.Summary = $true }
if ($Detailed)           { $Params.Detailed = $true }
if ($SendMail)           { $Params.Sendmail = $true }
if ($MailTo)             { $Params.MailTo = $MailTo }
if ($ReportTemplate)     { $Params.ReportTemplate = $ReportTemplate }
if ($BuildSummaryByAI)   { $Params.BuildSummaryByAI = $true }

# dot-source the script so ALL variables above remain available to the called script
. $ScriptPath @Params
