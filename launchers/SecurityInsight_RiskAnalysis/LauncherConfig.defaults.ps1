#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight_RiskAnalysis.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then dot-sources the customer's LauncherConfig.ps1 (which overrides
    only the values they care about), then applies CLI args (last word).

    LayerOrder:  defaults.ps1  ->  LauncherConfig.ps1  ->  CLI args

    Customer never edits this file. Anything they set in their own
    LauncherConfig.ps1 simply re-assigns the global below it. New globals
    introduced in future releases land here automatically with our
    defaults; the customer only touches their own file when they want to
    deviate.

    Every $global:* the engine reads in COMMUNITY mode lives here. AF-mode
    long-name aliases ($global:SecurityInsight_LOG_*) are populated by
    platform-defaults.ps1 in the internal launcher; they are not set here.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : SecurityInsight_RiskAnalysis
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

# ============================================================================
#  REPORT SELECTION
# ============================================================================
# Two templates ship in the Locked YAML:
#   RiskAnalysis_Summary_Bucket    (default; compact summary across all areas)
#   RiskAnalysis_Detailed_Bucket   (full per-row detail, larger Excel, slower)
$global:ReportTemplate = 'RiskAnalysis_Summary_Bucket'
$global:OverwriteXlsx  = $true
$global:ShowConfig     = $false


# ============================================================================
#  EMAIL DELIVERY
# ============================================================================
# Engine writes the .xlsx either way. SendMail attaches it to an HTML email
# (with the AI summary if BuildSummaryByAI=$true) and SMTP-relays it.
$global:SendMail           = $false
$global:MailTo             = @()                  # array of recipients
$global:SmtpServer         = $null
$global:SMTPPort           = 587
$global:SMTP_UseSSL        = $true
$global:Mail_SendAnonymous = $false
$global:SMTPUser           = $null                # also used as the From address
$global:SMTPPassword       = $null


# ============================================================================
#  AI SUMMARY (Azure OpenAI)
# ============================================================================
$global:BuildSummaryByAI           = $false
$global:OpenAI_endpoint            = $null
$global:OpenAI_deployment          = $null
$global:OpenAI_apiVersion          = '2024-08-01-preview'
$global:OpenAI_apiKey              = $null
$global:OpenAI_MaxTokensPerRequest = 16384


# ============================================================================
#  ADAPTIVE BUCKETING (handles Defender's 30k-row query ceiling)
# ============================================================================
$global:UseQueryBucketing      = $false
$global:DefaultBucketCount     = 2
$global:AutoBucketCount        = $false
$global:AutoBucketMax          = 64
$global:AutoBucketCache        = $true
$global:ResetCache             = $false
$global:BucketPlaceholderToken = '__BUCKET_FILTER__'


# ============================================================================
#  GRAPH TUNING
# ============================================================================
$global:GraphReconnectMaxAgeMinutes = 45
$global:GraphQueryMaxRetries        = 4


# ============================================================================
#  RUNTIME FLAGS  (all overridable via CLI parameters on the launcher)
# ============================================================================
$global:WhatIfMode     = $false
$global:Summary        = $false        # let Resolve-RunMode in the launcher decide
$global:Detailed       = $false
$global:DebugQueryHash = $false
$global:Scope          = @('PROD')     # or @('TEST')
