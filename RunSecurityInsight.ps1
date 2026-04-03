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
  [string] $SettingsPath,

  [Parameter(Mandatory=$false)]
  [switch] $BuildSummaryByAI,

  # Adaptive bucketing
  [Parameter(Mandatory=$false)]
  [switch] $AutoBucketCount,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,512)]
  [int] $AutoBucketMax = 64,

  [Parameter(Mandatory=$false)]
  [switch] $AutoBucketCache,

  # Deletes OUTPUT\AutoBucketCache.json so it rebuilds
  [Parameter(Mandatory=$false)]
  [Alias('ResetCache')]
  [switch] $ResetCacheSwitch
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
$global:AI_apiKey                   = $null
$global:AI_deployment               = $null

#########################################################################################################
# OPTIONAL VARIABLE OVERRIDES (used only when no CLI switch is provided)
#########################################################################################################

# Allowed values: 'Auto', 'Summary', 'Detailed'
$RunMode_Default = 'Auto'

# Use $null to mean "no override". Use $true to force.
$Summary_Override  = $true
$Detailed_Override = $null

# Set to $true to delete OUTPUT\AutoBucketCache.json on startup (when CLI switch not used)
$ResetCache_Override = $null

#########################################################################################################
# Defaults (single source of truth)
#########################################################################################################

$AutomationFramework_Default = $false
$SettingsPath_Default        = ''
$OverwriteXlsx_Default       = $true
$BuildSummaryByAI_Default    = $false

$ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# Optional hard default template (leave as $null to use Summary/Detailed defaults below)
$ReportTemplate_Default = $null

$AutoBucketCount_Default = $true
$AutoBucketCache_Default = $true
$AutoBucketMax_Default   = 512

$ResetCache_Default      = $false
$DebugQueryHash_Default  = $false


#########################################################################################################
# Resolve runtime values (CMDLINE TRUE WINS, otherwise defaults)
#########################################################################################################

# IMPORTANT:
# - A switch can be passed as -Switch:$false; it then exists in $PSBoundParameters but is False.
# - We only treat cmdline as "winning" when the switch is explicitly True.

$AutomationFramework = $AutomationFramework_Default
if ($PSBoundParameters.ContainsKey('AutomationFramework')) { $AutomationFramework = [bool]$PSBoundParameters['AutomationFramework'] }

$BuildSummaryByAI = $BuildSummaryByAI_Default
if ($PSBoundParameters.ContainsKey('BuildSummaryByAI')) { $BuildSummaryByAI = [bool]$PSBoundParameters['BuildSummaryByAI'] }

$AutoBucketCount = $AutoBucketCount_Default
if ($PSBoundParameters.ContainsKey('AutoBucketCount')) { $AutoBucketCount = [bool]$PSBoundParameters['AutoBucketCount'] }

$AutoBucketMax = $AutoBucketMax_Default
if ($PSBoundParameters.ContainsKey('AutoBucketMax')) { $AutoBucketMax = [int]$PSBoundParameters['AutoBucketMax'] }

$AutoBucketCache = $AutoBucketCache_Default
if ($PSBoundParameters.ContainsKey('AutoBucketCache')) { $AutoBucketCache = [bool]$PSBoundParameters['AutoBucketCache'] }

$DebugQueryHash = $DebugQueryHash_Default
if ($PSBoundParameters.ContainsKey('DebugQueryHash')) { $DebugQueryHash = [bool]$PSBoundParameters['DebugQueryHash'] }

$ResetCache = $ResetCache_Default
if ($PSBoundParameters.ContainsKey('ResetCacheSwitch')) {
  $ResetCache = [bool]$PSBoundParameters['ResetCacheSwitch']
} elseif ($null -ne $ResetCache_Override) {
  $ResetCache = [bool]$ResetCache_Override
}

#########################################################################################################
# Mode resolution
#########################################################################################################

function Resolve-RunMode {
  param(
    [bool]$AutomationFrameworkFlag,
    [string]$RunModeDefault,
    $SummaryOverride,
    $DetailedOverride,
    [hashtable]$Bound
  )

  # 1) CMDLINE wins ONLY when explicitly True
  $cliSummary  = $Bound.ContainsKey('Summary')  -and [bool]$Bound['Summary']
  $cliDetailed = $Bound.ContainsKey('Detailed') -and [bool]$Bound['Detailed']

  if ($cliSummary -and $cliDetailed) {
    throw 'Parameters -Summary and -Detailed are mutually exclusive.'
  }
  if ($cliSummary)  { return @{ Summary=$true;  Detailed=$false } }
  if ($cliDetailed) { return @{ Summary=$false; Detailed=$true  } }

  # 2) Script overrides (only when explicitly True)
  if ($SummaryOverride -eq $true -and $DetailedOverride -eq $true) {
    throw 'Invalid override: Summary_Override and Detailed_Override cannot both be true.'
  }
  if ($DetailedOverride -eq $true) { return @{ Summary=$false; Detailed=$true  } }
  if ($SummaryOverride  -eq $true) { return @{ Summary=$true;  Detailed=$false } }

  # 3) In-script default mode
  $mode = ([string]$RunModeDefault).Trim()
  if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Auto' }

  switch ($mode.ToLowerInvariant()) {
    'detailed' { return @{ Summary=$false; Detailed=$true  } }
    'summary'  { return @{ Summary=$true;  Detailed=$false } }
    default    { }
  }

  # 4) Final fallback rule
  if ($AutomationFrameworkFlag) { return @{ Summary=$true;  Detailed=$false } }
  return @{ Summary=$false; Detailed=$false }
}

$modeResult = Resolve-RunMode `
  -AutomationFrameworkFlag $AutomationFramework `
  -RunModeDefault $RunMode_Default `
  -SummaryOverride $Summary_Override `
  -DetailedOverride $Detailed_Override `
  -Bound $PSBoundParameters

$Summary  = [bool]$modeResult.Summary
$Detailed = [bool]$modeResult.Detailed

#########################################################################################################
# SettingsPath
#########################################################################################################

$SettingsPathResolved = $SettingsPath_Default
if ($PSBoundParameters.ContainsKey('SettingsPath')) { $SettingsPathResolved = $SettingsPath }
if ([string]::IsNullOrWhiteSpace($SettingsPathResolved)) { $SettingsPathResolved = $PSScriptRoot }
$SettingsPathResolved = (Resolve-Path -LiteralPath $SettingsPathResolved).Path

#########################################################################################################
# ReportTemplate
#########################################################################################################

if ($PSBoundParameters.ContainsKey('ReportTemplate') -and -not [string]::IsNullOrWhiteSpace($ReportTemplate)) {
  # Explicit parameter always wins
} elseif (-not [string]::IsNullOrWhiteSpace($ReportTemplate_Default)) {
  $ReportTemplate = $ReportTemplate_Default
} elseif ($Summary -and -not $Detailed) {
  $ReportTemplate = $ReportTemplate_Default_Summary
} elseif ($Detailed -and -not $Summary) {
  $ReportTemplate = $ReportTemplate_Default_Detailed
} else {
  $ReportTemplate = $ReportTemplate_Default_Summary
}

if ([string]::IsNullOrWhiteSpace($ReportTemplate)) {
  throw 'No ReportTemplate could be resolved. Provide -ReportTemplate or set a default template variable.'
}

$OverwriteXlsx = [bool]$OverwriteXlsx_Default

#########################################################################################################
# Publish resolved values to globals (engine reads these)
#########################################################################################################

$global:SettingsPath        = $SettingsPathResolved
$global:ReportTemplate      = $ReportTemplate
$global:AutomationFramework = [bool]$AutomationFramework
$global:Summary             = [bool]$Summary
$global:Detailed            = [bool]$Detailed
$global:OverwriteXlsx       = [bool]$OverwriteXlsx
$global:BuildSummaryByAI    = [bool]$BuildSummaryByAI

$global:AutoBucketCount     = [bool]$AutoBucketCount
$global:AutoBucketMax       = [int]$AutoBucketMax
$global:AutoBucketCache     = [bool]$AutoBucketCache

$global:ResetCache          = [bool]$ResetCache
$global:DebugQueryHash      = [bool]$DebugQueryHash

# YAML settings file names (engine will default these too, but set here for strictmode-safe overview)
if (-not (Get-Variable -Name ReportSettingsFileLocked -Scope Global -ErrorAction SilentlyContinue)) {
  $global:ReportSettingsFileLocked = 'SecurityInsight_RiskAnalysis_Queries_Locked.yaml'
}
if (-not (Get-Variable -Name ReportSettingsFileCustom -Scope Global -ErrorAction SilentlyContinue)) {
  $global:ReportSettingsFileCustom = 'SecurityInsight_RiskAnalysis_Queries_Custom.yaml'
}

# Environments using StrictMode: ensure expected globals exist
if (-not (Get-Variable -Name ShowConfig -Scope Global -ErrorAction SilentlyContinue)) { $global:ShowConfig = $false }
if (-not (Get-Variable -Name SendMail   -Scope Global -ErrorAction SilentlyContinue)) { $global:SendMail   = $false }

# Token budget globals (canonical + back-compat)
if (-not (Get-Variable -Name OpenAI_MaxTokensPerRequest -Scope Global -ErrorAction SilentlyContinue)) {
  $Global:OpenAI_MaxTokensPerRequest = 16384
}
if (-not (Get-Variable -Name AI_MaxTokensPerRequest -Scope Global -ErrorAction SilentlyContinue)) {
  $Global:AI_MaxTokensPerRequest = [int]$Global:OpenAI_MaxTokensPerRequest
}

# Bucketing globals (engine reads these too)
if (-not (Get-Variable -Name UseQueryBucketing -Scope Global -ErrorAction SilentlyContinue)) { $Global:UseQueryBucketing = $false }
if (-not (Get-Variable -Name DefaultBucketCount -Scope Global -ErrorAction SilentlyContinue)) { $Global:DefaultBucketCount = 2 }
if (-not (Get-Variable -Name BucketPlaceholderToken -Scope Global -ErrorAction SilentlyContinue)) { $Global:BucketPlaceholderToken = '__BUCKET_FILTER__' }

# Graph reconnect tuning defaults
if (-not (Get-Variable -Name GraphReconnectMaxAgeMinutes -Scope Global -ErrorAction SilentlyContinue)) { $Global:GraphReconnectMaxAgeMinutes = 45 }
if (-not (Get-Variable -Name GraphQueryMaxRetries -Scope Global -ErrorAction SilentlyContinue)) { $Global:GraphQueryMaxRetries = 4 }

#########################################################################################################
# Optional: show config right away
#########################################################################################################

Write-Host ('[LAUNCHER] AutomationFramework={0} Summary={1} Detailed={2} BuildSummaryByAI={3}' -f $global:AutomationFramework, $global:Summary, $global:Detailed, $global:BuildSummaryByAI)
Write-Host ('[LAUNCHER] AutoBucketCount={0} AutoBucketMax={1} AutoBucketCache={2}' -f $global:AutoBucketCount, $global:AutoBucketMax, $global:AutoBucketCache)
Write-Host ('[LAUNCHER] ResetCache={0}' -f $global:ResetCache)
Write-Host ('[LAUNCHER] DebugQueryHash={0}' -f $global:DebugQueryHash)
Write-Host ('[LAUNCHER] SettingsPath={0}' -f $global:SettingsPath)
Write-Host ('[LAUNCHER] ReportTemplate={0}' -f $global:ReportTemplate)
Write-Host ''

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

$ScriptPath = Join-Path $global:SettingsPath 'SecurityInsight_RiskAnalysis.ps1'
if (-not (Test-Path -LiteralPath $ScriptPath)) {
  throw ('Main script not found: {0}' -f $ScriptPath)
}

. $ScriptPath
