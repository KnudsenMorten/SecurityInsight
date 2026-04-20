#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for SecurityInsight_RiskAnalysis (community-vm).

.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the SAME folder. LauncherConfig.ps1
    is gitignored, so the populated copy stays on your machine and is never
    overwritten by a release upgrade.

    LAYERED CONFIG MODEL

      1. LauncherConfig.defaults.ps1   <- ships with each release; baseline for
                                          every $global:* the engine reads.
      2. LauncherConfig.ps1            <- THIS FILE (your copy). Set ONLY the
                                          values you actually need to override.
      3. CLI args on the launcher      <- last word for that one invocation.

    You only need the AUTH block (section 1) at minimum. Everything else has
    a sensible default in LauncherConfig.defaults.ps1 -- copy a value from
    there into here only when you want to deviate.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : SecurityInsight_RiskAnalysis
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
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

# ----- Mail delivery (community mode) ------------------------------------------
# Community mode reads the SHORT names below. Same recipients regardless of
# Summary vs Detailed run.
# $global:SendMail        = $true
# $global:MailTo          = @('soc@yourdomain.com')
# $global:SmtpServer      = 'smtp.yourdomain.com'
# $global:SMTPUser        = 'no-reply@yourdomain.com'
# $global:SMTPPassword    = '<smtp-password>'
#
# ----- Mail delivery (internal / AutomationFramework mode) ---------------------
# When $global:AutomationFramework=$true the engine reads SEPARATE recipients
# per Summary vs Detailed run (Detailed is the noisier per-row report; Summary
# is the executive overview). Set these in your platform-defaults.ps1 (layer 2)
# or here if you only run one engine:
# $global:Mail_SecurityInsight_Detailed_SendMail = $true
# $global:Mail_SecurityInsight_Detailed_To       = @('IT-Alerts-Identity@yourdomain.com')
# $global:Mail_SecurityInsight_Summary_SendMail  = $true
# $global:Mail_SecurityInsight_Summary_To        = @('exec-summary@yourdomain.com')
#
# ----- Per-template recipient override (YAML) ----------------------------------
# In the *_Custom.yaml file you can override recipients PER template:
#   Reports:
#     - ReportName: RiskAnalysis_Detailed_Bucket
#       Mail_To:
#         - vuln-team@yourdomain.com
#       Mail_SendMail: true
# When set on a template, those values win over the globals above for that
# template's run. Useful for routing a specific report to specific stakeholders.

# ----- AI summary (Azure OpenAI) -----------------------------------------------
# $global:BuildSummaryByAI  = $true
# $global:OpenAI_endpoint   = 'https://<your-aoai-account>.openai.azure.com'
# $global:OpenAI_deployment = 'gpt-4o-mini'
# $global:OpenAI_apiKey     = '<your-azure-openai-key>'

# ----- Run-mode --------------------------------------------------------------
# $global:ReportTemplate = 'RiskAnalysis_Detailed_Bucket'   # or '_Summary_Bucket' (default)

# ----- JSON sibling of the XLSX ----------------------------------------------
# A .json with the same dataset is written next to the .xlsx by default.
# Disable if you only want the Excel:
# $global:WriteJsonOutput = $false

# ----- Log Analytics ingest (Phase 2) ----------------------------------------
# Send the in-memory dataset to a custom LA table after the Excel build.
# Two tables, routed per Summary vs Detailed mode:
#   SI_RiskAnalysis_Summary_CL   /  SI_RiskAnalysis_Detailed_CL
# Requires the AzLogDcrIngestPS module installed (Install-Module AzLogDcrIngestPS).
# Table + DCR are auto-created on first ingest by the module.
#
# Two DCRs (one per table) are HARDCODED in the engine:
#   dcr-si-risk-analysis-summary   ->  SI_RiskAnalysis_Summary_CL
#   dcr-si-risk-analysis-detailed  ->  SI_RiskAnalysis_Detailed_CL
# Customer never picks DCR names -- only the resource group that holds them.
#
# $global:SendToLogAnalytics              = $true
#
# EVERYTHING AUTO-RESOLVES. By default the engine targets:
#   Workspace : log-platform-management-securityinsight (in rg-securityinsight)
#   DCE       : dce-securityinsight                     (in rg-dce-securityinsight)
#   DCR RG    : rg-dcr-securityinsight
# All four RGs + the workspace + the DCE are auto-created if missing, and the
# ingestion SPN is granted the roles it needs. DceIngestionUri is looked up from
# the DCE name via Get-AzDceListAll -- you do NOT have to hardcode it anymore.
#
# Override only what differs from the defaults. Per-engine names
# (SI_RiskAnalysis_*) win over the short names the IAC launcher sets.
# $global:SI_RiskAnalysis_WorkspaceName        = 'log-platform-management-securityinsight'  # default; override if this engine uses a different workspace
# $global:SI_RiskAnalysis_WorkspaceResourceId  = '/subscriptions/.../workspaces/<ws>'       # overrides WorkspaceName when set (cross-sub supported)
# $global:SI_RiskAnalysis_WorkspaceResourceGroup = 'rg-securityinsight'                     # only used if the workspace is missing and must be created
# $global:SI_RiskAnalysis_DceName              = 'dce-securityinsight'                      # default; override if you have a pre-existing DCE with another name
# $global:SI_RiskAnalysis_DcrResourceGroup     = 'rg-dcr-securityinsight'                   # default; override only to consolidate with an existing DCR RG
# $global:SI_RiskAnalysis_DceIngestionUri      = 'https://...ingest.monitor.azure.com'     # rarely needed -- auto-resolved from DceName

# ----- Export upload (Phase 3) -----------------------------------------------
# Uploads BOTH the .xlsx and the .json to a destination after they are written
# locally. Existing files at the destination are RENAMED to
# <name>.<yyyy-MM-dd_HHmmss>.<ext>.bak before the new file is written, so the
# canonical path always holds the latest run.
#
# Destination type is AUTO-DETECTED from the value's prefix -- you don't pick
# UNC vs Azure separately, you just set one variable to one of these formats:
#
#   '\\server\share\path\'                              -> UNC share
#   'https://<acct>.blob.core.windows.net/<container>/' -> Azure Storage blob
#
# Auth requirements differ by detected type:
#   UNC    -- the calling Windows identity needs write to the share
#             (pure SPN auth doesn't help SMB; run the launcher under a
#             service account, OR use Azure Storage instead).
#   Azure  -- the SPN that ran the engine needs 'Storage Blob Data Contributor'
#             on the destination container or its parent storage account.
#             Uses the existing Az session -- no extra credentials.
#
# Examples (uncomment ONE):
# $global:ExportDestination = '\\fileserver\reports\SecurityInsight\'
# $global:ExportDestination = 'https://<storacct>.blob.core.windows.net/<container>/'
# $global:ExportDestination = 'https://<storacct>.blob.core.windows.net/<container>/<prefix>/'


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (bucketing tuning, Graph reconnect, retention, etc.),
# look at LauncherConfig.defaults.ps1 in this same folder. Copy any line out
# of there into THIS file to override that single value.
