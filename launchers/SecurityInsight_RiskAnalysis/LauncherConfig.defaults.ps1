#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight_RiskAnalysis.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then dot-sources the customer's LauncherConfig.custom.ps1 (which overrides
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
    Developed by          : Morten Knudsen, Microsoft MVP
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

# JSON sibling of the XLSX. Same dataset, same dir, .json next to .xlsx.
# Default OFF -- the XLSX already covers reporting + Power BI ingestion; the JSON
# sibling exists only when the customer wants a machine-readable mirror for an
# external pipeline. Set to $true in your LauncherConfig.custom.ps1 if you need it.
$global:WriteJsonOutput = $false


# ============================================================================
#  LOG ANALYTICS INGEST (Phase 2)
# ============================================================================
# Send the in-memory dataset to a Log Analytics custom table after the Excel
# build. Routes to two tables based on Summary vs Detailed mode:
#   SI_RiskAnalysis_Summary_CL   (when $global:Summary  = $true)
#   SI_RiskAnalysis_Detailed_CL  (when $global:Detailed = $true)
# AzLogDcrIngestPS module auto-creates the table + DCR on first ingest.
$global:SendToLogAnalytics                    = $false

# Two DCRs (one per table) -- HARDCODED in the engine ('dcr-si-risk-analysis-summary'
# + 'dcr-si-risk-analysis-detailed'); customer doesn't pick the names.
#
# EVERYTHING AUTO-RESOLVES. The solution-wide shared defaults (Layer 0,
# SecurityInsight.shared-defaults.ps1 in _lib) set $global:WorkspaceName,
# $global:DceName, $global:DceResourceGroup, $global:DcrResourceGroup to the
# canonical SecurityInsight layout. The engine auto-creates anything missing
# (workspace, DCE, DCE RG, DCR RG) and assigns the SPN the roles it needs.
#
# SI_RiskAnalysis_* per-engine overrides win over the shared short names. Only
# set them if this engine needs to deviate from the solution baseline.
$global:SI_RiskAnalysis_DcrResourceGroup       = $null   # override: falls back to $global:DcrResourceGroup
$global:SI_RiskAnalysis_DceName                = $null   # override: falls back to $global:DceName
$global:SI_RiskAnalysis_DceIngestionUri        = $null   # auto-resolved from DceName -- rarely set explicitly
$global:SI_RiskAnalysis_WorkspaceName          = $null   # override: falls back to $global:WorkspaceName
$global:SI_RiskAnalysis_WorkspaceResourceId    = $null   # overrides WorkspaceName when set (cross-sub supported)
$global:SI_RiskAnalysis_WorkspaceResourceGroup = $null   # override: falls back to $global:WorkspaceResourceGroup

# Custom table base names (engine appends _CL when LA creates the table).
$global:SI_RiskAnalysis_TableName_Summary     = 'SI_RiskAnalysis_Summary'
$global:SI_RiskAnalysis_TableName_Detailed    = 'SI_RiskAnalysis_Detailed'


# ============================================================================
#  EXPORT UPLOAD (Phase 3)
# ============================================================================
# Optional. After the Excel + JSON are written, the engine also uploads BOTH
# files to a UNC share or an Azure Storage container. Set this global to
# enable; leave $null to skip.
#
# DESTINATION TYPE IS AUTO-DETECTED from the value's prefix -- one variable
# covers both, no separate "use UNC vs use Azure" toggle:
#   '\\...'                                             -> UNC      (Copy-Item)
#   'https://<acct>.blob.core.windows.net/<container>/' -> Azure    (Set-AzStorageBlobContent)
#   anything else                                       -> [WARN] + skip
#
# Backup-then-overwrite: if a file with the same name already exists at the
# destination, it is RENAMED to <name>.<yyyy-MM-dd_HHmmss>.<ext>.bak (UNC:
# Move-Item; Azure: Start-AzStorageBlobCopy) BEFORE the new file is written.
# Canonical path always holds the latest run.
#
# Auth (per detected type):
#   UNC   -- caller's Windows identity needs share write (pure SPN auth
#            doesn't help SMB; use a service account, OR Az Storage instead).
#   Azure -- SPN needs 'Storage Blob Data Contributor' on the destination
#            container or its parent storage account. Uses the existing Az
#            session via New-AzStorageContext -UseConnectedAccount.
$global:ExportDestination = $null


# ============================================================================
#  EMAIL DELIVERY
# ============================================================================
# Engine writes the .xlsx either way. SendMail attaches it to an HTML email
# (with the AI summary if BuildSummaryByAI=$true) and SMTP-relays it.
# DO NOT unconditionally assign $null here -- that would clobber whatever the
# customer set in Layer 3 (SecurityInsight.custom.ps1). Only set fallback values
# when the variable hasn't been populated by a higher-priority layer.
if (-not (Test-Path variable:global:SendMail))           { $global:SendMail           = $false }
if (-not (Test-Path variable:global:MailTo))             { $global:MailTo             = @() }
if (-not (Test-Path variable:global:SMTPPort))           { $global:SMTPPort           = 587 }
if (-not (Test-Path variable:global:SMTP_UseSSL))        { $global:SMTP_UseSSL        = $true }
if (-not (Test-Path variable:global:Mail_SendAnonymous)) { $global:Mail_SendAnonymous = $false }
# $global:SmtpServer / $global:SMTPUser / $global:SMTPPassword / $global:SMTPFrom
# have no sensible engine default -- customer provides them. Unset == $null, which
# is what the engine's fail-fast check expects.


# ============================================================================
#  AI SUMMARY (Azure OpenAI)
# ============================================================================
# Same rule: only set defaults that are actually safe to ship.
if (-not (Test-Path variable:global:BuildSummaryByAI))           { $global:BuildSummaryByAI           = $false }
if (-not $global:OpenAI_apiVersion)                              { $global:OpenAI_apiVersion          = '2024-08-01-preview' }
if (-not (Test-Path variable:global:OpenAI_MaxTokensPerRequest)) { $global:OpenAI_MaxTokensPerRequest = 16384 }
# $global:OpenAI_endpoint / _deployment / _apiKey: customer-supplied, no fallback.


# ============================================================================
#  ADAPTIVE BUCKETING (handles Defender's 30k-row query ceiling)
# ============================================================================
$global:UseQueryBucketing      = $false
$global:DefaultBucketCount     = 2
$global:AutoBucketCount        = $false
$global:AutoBucketMax          = 1024     # was 64 in earlier versions; large estates need
                                          # higher bucket counts to stay under the 30k-row
                                          # ceiling per query. AutoBucket only escalates as
                                          # needed -- a small tenant still runs at low counts.
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
