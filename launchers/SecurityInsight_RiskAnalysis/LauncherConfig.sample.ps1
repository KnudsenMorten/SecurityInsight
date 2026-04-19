#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for SecurityInsight_RiskAnalysis.
.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the SAME folder and fill in the values
    for whichever authentication method you want to use. LauncherConfig.ps1 is
    .gitignore'd so the populated copy stays on your machine.

    AUTHENTICATION METHODS (pick ONE)

    The launcher resolves auth in this priority order (first match wins):

      1.  Managed Identity  (production, most secure)
      2.  SPN + Key Vault-stored secret  (production)
      3.  SPN + certificate  (production; cert must be installed in user's cert store)
      4.  SPN + plaintext secret  (TESTING ONLY - do NOT use in production)

    In every production case the app still needs the Entra API permissions and
    Azure RBAC described in the solution README, Step 2.

.NOTES
    Solution       : SecurityInsight
    File           : LauncherConfig.sample.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>

# ================================================================================
#  METHOD 1 -- Managed Identity  (RECOMMENDED for Azure VMs / Arc-enabled servers
#                                 / Function Apps / Hybrid Runbook Workers)
# ================================================================================
# System-assigned MI is assumed. For user-assigned MI, set $global:SpnClientId to
# the MI's client ID.
#
# $global:UseManagedIdentity = $true
# $global:SpnTenantId         = '<your-tenant-id-guid>'   # still required for Graph connect


# ================================================================================
#  METHOD 2 -- Service Principal + secret stored in Azure Key Vault
# ================================================================================
# Requires the VM / caller to have a Managed Identity with 'Key Vault Secrets User'
# on the target Key Vault. The launcher uses MI to fetch the SPN secret, then
# authenticates as the SPN.
#
# $global:SpnTenantId         = '<your-tenant-id-guid>'
# $global:SpnClientId         = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName     = '<kv-name>'               # short name, not full URI
# $global:SpnSecretName       = 'SecurityInsight-Secret'  # name of the secret holding the client secret


# ================================================================================
#  METHOD 3 -- Service Principal + certificate (thumbprint in local cert store)
# ================================================================================
# Upload the public key of the cert to the Entra app under Certificates & secrets.
# The private key must be installed on THIS machine (CurrentUser\My or
# LocalMachine\My). Certificate auth is silent and does not expire as fast as
# secrets.
#
# $global:SpnTenantId             = '<your-tenant-id-guid>'
# $global:SpnClientId             = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'


# ================================================================================
#  METHOD 4 -- Service Principal + plaintext secret  *** TESTING ONLY ***
# ================================================================================
# WARNING: storing a plaintext client secret in a .ps1 file is acceptable for a
# short-lived TEST / LAB environment ONLY. For production use Method 1, 2, or 3.
# LauncherConfig.ps1 is .gitignore'd, so it won't accidentally land in a git
# commit -- but the secret is still in cleartext on disk, and on backup media,
# and in any filesystem snapshot, and in whatever process the script runs under.
# Expect to rotate the secret frequently if you do leave it here.
#
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'


# ================================================================================
#  REPORT SELECTION
# ================================================================================
# The Locked YAML ships two templates -- pick one:
#   RiskAnalysis_Summary_Bucket    (default; compact summary, faster)
#   RiskAnalysis_Detailed_Bucket   (full per-row detail, larger Excel, slower)
$global:ReportTemplate    = 'RiskAnalysis_Summary_Bucket'
$global:OverwriteXlsx     = $true       # overwrite the previous .xlsx
$global:ShowConfig        = $false      # $true = dump resolved config and exit


# ================================================================================
#  EMAIL DELIVERY  (only needed if SendMail = $true)
# ================================================================================
# Engine writes the Excel either way. SendMail just attaches it to an HTML email
# (with the AI summary if BuildSummaryByAI = $true) and SMTP-relays it.
# $global:SendMail            = $false                              # toggle on
# $global:MailTo              = @('you@yourdomain.com')             # one or more
# $global:SmtpServer          = '<smtp.yourdomain.com>'
# $global:SMTPPort            = 587
# $global:SMTP_UseSSL         = $true
# $global:Mail_SendAnonymous  = $false                              # $true = no creds
# $global:SMTPUser            = '<smtp-username-or-from-address>'   # also used as From
# $global:SMTPPassword        = '<smtp-password>'                   # only if not anonymous


# ================================================================================
#  AI SUMMARY  (Azure OpenAI)  -- only needed if BuildSummaryByAI = $true
# ================================================================================
# Engine builds an executive summary of the risk analysis from the rows it
# generated and writes it as a 'Summary' tab in the Excel + the email body.
# The OpenAI URL is constructed as:
#   <endpoint>/openai/deployments/<deployment>/chat/completions?api-version=<apiVersion>
# $global:BuildSummaryByAI            = $false                       # toggle on
# $global:OpenAI_endpoint             = 'https://<your-aoai-account>.openai.azure.com'
# $global:OpenAI_deployment           = 'gpt-4o-mini'                # your model deployment name
# $global:OpenAI_apiVersion           = '2024-08-01-preview'
# $global:OpenAI_apiKey               = '<your-azure-openai-key>'
# $global:OpenAI_MaxTokensPerRequest  = 16384


# ================================================================================
#  ADAPTIVE BUCKETING  (handles Defender's 30k-row query ceiling)
# ================================================================================
# Defaults handle most tenants. Only touch if a query is being truncated.
# $global:UseQueryBucketing     = $false       # auto-on per query if needed
# $global:DefaultBucketCount    = 2
# $global:AutoBucketCount       = $false       # adaptive probe (1..AutoBucketMax)
# $global:AutoBucketMax         = 64
# $global:AutoBucketCache       = $true        # cache discovered counts to disk
# $global:ResetCache            = $true        # one-shot purge of the bucket cache


# ================================================================================
#  GRAPH TUNING  (rarely changed)
# ================================================================================
# $global:GraphReconnectMaxAgeMinutes = 45
# $global:GraphQueryMaxRetries        = 4


# ================================================================================
#  RUNTIME FLAGS  (also available on the launcher command line)
# ================================================================================
# $global:WhatIfMode    = $false   # $true = dry run, no Excel/mail writes
# $global:Summary       = $false   # force RiskAnalysis_Summary_Bucket
# $global:Detailed      = $false   # force RiskAnalysis_Detailed_Bucket
# $global:DebugQueryHash = $false  # log query hash + cache key per query
# $global:Scope         = @('PROD')   # or @('TEST')
