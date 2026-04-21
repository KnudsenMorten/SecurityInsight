#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for SecurityInsight_RiskAnalysis (community-vm).

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. The custom
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    LAYERED CONFIG MODEL  (each layer overrides the previous)

      0. SecurityInsight.shared-defaults.ps1  <- solution-wide canonical
                                                 names (Workspace / DCE /
                                                 DCR RG / Location).
      1. LauncherConfig.defaults.ps1          <- per-engine baseline; sets
                                                 table names, DCR names,
                                                 mode flags.
      2. platform-defaults.ps1                <- internal/AF mode only.
      3. <Solution>.custom.ps1                <- optional solution-wide overrides.
      4. LauncherConfig.custom.ps1            <- THIS FILE (your copy).
      5. CLI args on the launcher             <- last word per invocation.

    Everything auto-resolves. You can ship this file with just the AUTH
    block and SubscriptionId set; the engine will auto-create the workspace,
    DCE, DCR resource groups if missing and assign the SPN the roles it
    needs (requires Owner / UAA on the sub for the first run).

.NOTES
    LauncherConfigVersion : 2
    Solution              : SecurityInsight
    Engine                : SecurityInsight_RiskAnalysis
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1.  AUTHENTICATION  -- REQUIRED. Uncomment ONE method block, fill in values.
# ============================================================================

# ----- METHOD 1: Managed Identity (recommended for Azure VMs / Arc / Function) -
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'

# ----- METHOD 2: SPN + secret stored in Azure Key Vault ------------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'
# $global:SpnSecretName   = 'SecurityInsight-Secret'

# ----- METHOD 3: SPN + certificate (thumbprint in local cert store) ------------
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ----- METHOD 4: SPN + plaintext secret  *** TESTING ONLY *** ------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'


# ============================================================================
# 2.  COMMON OVERRIDES  (uncomment + edit ONLY what you want to change)
# ============================================================================

# ----- Infrastructure naming (overrides Layer 0 shared defaults) ---------------
# The standard SecurityInsight layout is defined in LAUNCHERS/_lib/
# SecurityInsight.shared-defaults.ps1:
#   $global:WorkspaceName          = 'log-platform-management-securityinsight'
#   $global:WorkspaceResourceGroup = 'rg-securityinsight'
#   $global:DceName                = 'dce-securityinsight'
#   $global:DceResourceGroup       = 'rg-dce-securityinsight'
#   $global:DcrResourceGroup       = 'rg-dcr-securityinsight'
#   $global:Location               = 'westeurope'
#
# Override here only if you deviate. Example (community/test layout):
# $global:WorkspaceName    = 'log-platform-management-si-community'
# $global:DceName          = 'dce-securityinsight-community'
# $global:DceResourceGroup = 'rg-dce-securityinsight-community'
# $global:DcrResourceGroup = 'rg-dcr-securityinsight-community'
# $global:SubscriptionId   = '<your-target-subscription-id-guid>'

# ----- Mail delivery (community mode) ------------------------------------------
# Community mode resolves recipients in this order:
#   1. $global:RiskAnalysis_Detailed_SendMail / _To   (when -Detailed)
#   2. $global:RiskAnalysis_Summary_SendMail  / _To   (when -Summary)
#   3. Flat $global:SendMail + $global:MailTo         (fallback)
# Flat pair (same recipients regardless of mode):
# $global:SendMail        = $true
# $global:MailTo          = @('soc@yourdomain.com')
# $global:SmtpServer      = 'smtp.yourdomain.com'
# $global:SmtpPort        = 587
# $global:SMTP_UseSSL     = $true
# $global:SMTPUser        = '<smtp-login-username>'       # relay login (e.g. Brevo/SendGrid API key user)
# $global:SMTPPassword    = '<smtp-login-password>'
# $global:SMTPFrom        = 'noreply@yourdomain.com'      # verified-sender address (From header).
#                                                         # Required by Brevo/SendGrid/Postmark/M365.
#                                                         # Omit to fall back to $SMTPUser (legacy).
#
# Per-template recipients (also works in AF mode; legacy $global:Mail_SecurityInsight_*
# names are still accepted as a fallback):
# $global:RiskAnalysis_Detailed_SendMail = $true
# $global:RiskAnalysis_Detailed_To       = @('soc@yourdomain.com')
# $global:RiskAnalysis_Summary_SendMail  = $true
# $global:RiskAnalysis_Summary_To        = @('exec-summary@yourdomain.com')
#
# ----- Per-template recipient override (YAML, wins over globals) ---------------
# In the *_Custom.yaml file you can override recipients PER template:
#   ReportTemplates:
#     - ReportName: RiskAnalysis_Detailed_Bucket
#       Mail_To:
#         - vuln-team@yourdomain.com
#       Mail_SendMail: true
# When present on a template, those values win over the globals above for
# that template's run.

# ----- AI summary (Azure OpenAI) -----------------------------------------------
# $global:BuildSummaryByAI          = $true
# $global:OpenAI_endpoint           = 'https://<your-aoai-account>.openai.azure.com'
# $global:OpenAI_deployment         = '<your-deployment-name>'
# $global:OpenAI_apiKey             = '<your-azure-openai-key>'
# $global:OpenAI_apiVersion         = '2025-01-01-preview'
# $global:OpenAI_MaxTokensPerRequest = 16384

# ----- Run mode --------------------------------------------------------------
# Two ways to pick Summary vs Detailed:
#   1. Set $global:ReportTemplate explicitly:
# $global:ReportTemplate = 'RiskAnalysis_Detailed_Bucket'   # or _Summary_Bucket
#
#   2. Leave $global:ReportTemplate unset and use the override switches below.
#      Useful in a launcher so testers can flip between modes with one line:
# $global:RiskAnalysis_Summary_Override                = $null
# $global:RiskAnalysis_Detailed_Override               = $true
# $global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
# $global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# ----- JSON sibling of the XLSX ----------------------------------------------
# A .json with the same dataset is written next to the .xlsx by default.
# Disable if you only want the Excel:
# $global:WriteJsonOutput = $false

# ----- Log Analytics ingest (Phase 2) ----------------------------------------
# Send the in-memory dataset to a custom LA table after the Excel build.
# Two tables, routed per Summary vs Detailed mode:
#   SI_RiskAnalysis_Summary_CL   /  SI_RiskAnalysis_Detailed_CL
# Requires the AzLogDcrIngestPS module. Table + DCR are auto-created on first
# ingest. Missing workspace / DCE / DCE RG / DCR RG are also auto-created.
# $global:SendToLogAnalytics = $true

# ----- Export upload (Phase 3) -----------------------------------------------
# Uploads BOTH the .xlsx and the .json to a destination after they are written
# locally. Existing files at the destination are RENAMED to
# <name>.<yyyy-MM-dd_HHmmss>.<ext>.bak before the new file is written, so the
# canonical path always holds the latest run.
#
# Destination type is AUTO-DETECTED from the value's prefix:
#   '\\server\share\path\'                              -> UNC share
#   'https://<acct>.blob.core.windows.net/<container>/' -> Azure Storage blob
#
# For Azure Storage the container is auto-created if missing AND the engine
# tries (best-effort) to grant the SPN 'Storage Blob Data Contributor' at the
# container scope (requires caller Owner / UAA on the storage account for the
# grant to succeed; container is still created either way).
#
# Examples (uncomment ONE):
# $global:ExportDestination = '\\fileserver\reports\SecurityInsight\'
# $global:ExportDestination = 'https://<storacct>.blob.core.windows.net/<container>/'
# $global:ExportDestination = 'https://<storacct>.blob.core.windows.net/<container>/<prefix>/'


# ============================================================================
# 3.  COMPLETE EXAMPLE  (community mode, copy/paste starting point)
# ============================================================================
# This is the full shape of a populated LauncherConfig.custom.ps1. Replace the
# '<your-*>' placeholders with your own values. Comment out any block you
# don't need. Sensitive values shown as '<...>' placeholders.

<#
# --- Auth: SPN + plaintext secret (TESTING ONLY) ---
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'

# --- Infrastructure (overrides Layer 0 shared defaults for this test tenant) ---
$global:DcrResourceGroup = 'rg-dcr-securityinsight-community'
$global:DceResourceGroup = 'rg-dce-securityinsight-community'
$global:DceName          = 'dce-securityinsight-community'
$global:WorkspaceName    = 'log-platform-management-si-community'
$global:SubscriptionId   = '<your-target-subscription-id-guid>'

# --- Ingest + reporting mode ---
$global:SendToLogAnalytics = $true
$global:ReportTemplate     = 'RiskAnalysis_Summary_Bucket'

# --- Mail: flat (fallback) + per-template (preferred) ---
# Brevo/SendGrid/Postmark/M365 all REJECT mail whose From header is not a verified sender,
# so $SMTPFrom must be a verified-sender address -- NOT the relay login username.
$global:SendMail        = $true
$global:MailTo          = @('fallback@yourdomain.com')
$global:SmtpServer      = 'smtp-relay.brevo.com'
$global:SmtpPort        = 587
$global:SMTP_UseSSL     = $true
$global:SMTPUser        = '<smtp-login-username>'       # e.g. 'NNNNN@smtp-brevo.com'
$global:SMTPPassword    = '<smtp-login-password>'
$global:SMTPFrom        = 'noreply@yourdomain.com'      # verified sender in your relay

$global:RiskAnalysis_Detailed_SendMail = $true
$global:RiskAnalysis_Detailed_To       = @('soc@yourdomain.com')
$global:RiskAnalysis_Summary_SendMail  = $true
$global:RiskAnalysis_Summary_To        = @('exec-summary@yourdomain.com')

# --- Output: JSON sibling + upload to blob (container auto-created) ---
$global:WriteJsonOutput    = $true
$global:ExportDestination  = 'https://<your-storacct>.blob.core.windows.net/riskanalysis-summary/'

# --- Launcher mode overrides (flip Summary/Detailed without editing ReportTemplate) ---
$global:RiskAnalysis_Summary_Override                = $null
$global:RiskAnalysis_Detailed_Override               = $true
$global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# --- Behaviour tuning ---
$global:TroubleshootingMode              = $true
$global:CsaAttributeSet                  = 'SecurityInsight'
$global:SubscriptionNameExcludePatterns  = @('*Azure for Students*')

# --- AI executive summary (Azure OpenAI) ---
$global:OpenAI_apiKey              = '<your-azure-openai-key>'
$global:OpenAI_endpoint            = 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_deployment          = '<your-deployment-name>'
$global:OpenAI_apiVersion          = '2025-01-01-preview'
$global:OpenAI_MaxTokensPerRequest = 16384
#>


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (bucketing tuning, Graph reconnect, retention, etc.),
# look at LauncherConfig.defaults.ps1 in this same folder. Copy any line out
# of there into THIS file to override that single value.
