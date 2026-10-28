#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight v2.2 -- Community-flavour customer override template.

.DESCRIPTION
    Community customers DON'T have PlatformConfiguration / Connect-Platform.
    The SPN, SMTP server, OpenAI key, Shodan key etc. all live inline in this
    file (or in a customer-owned Key Vault that the Get-AzKeyVaultSecret block
    at the bottom pulls from at runtime).

    Copy this file to `SecurityInsight.custom.ps1` (gitignored) and edit the
    values marked with <...> placeholders. Leave the rest as-is or delete the
    sections you don't use.

    Layer precedence (closer wins):
      1. launcher/_lib/SecurityInsight.shared-defaults.ps1   (solution baseline)
      2. launcher/<engine>/LauncherConfig.defaults.ps1       (engine baseline)
      3. config/SecurityInsight.custom.ps1  -- THIS FILE     (customer-wide)
      4. launcher/<engine>/LauncherConfig.custom.ps1         (per-engine, wins)

    For the full list of every supported global (cadence, EG label overrides,
    Shodan tuning, AI prompt overrides, schema-discovery, etc.), see
    `SecurityInsight.custom.reference.ps1` in this folder.

    Internal customers (with Connect-Platform): start from
    `SecurityInsight.custom.sample.ps1` instead.

.NOTES
    Flavour : Community (standalone -- no PlatformConfig dependency)
    Layer   : 3 (solution-wide customer overrides)
    Author  : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1. AUTH  -- managed identity (DEFAULT) or a service principal (optional)
# ============================================================================
# Managed identity: no secret and no certificate to rotate. Works on an Azure VM
# and on an Azure Arc-enabled server (system-assigned identity), or with a
# user-assigned identity when you give its client id.
$global:SI_AuthMethod              = 'ManagedIdentity'    # ManagedIdentity | Certificate | Secret
# $global:SI_ManagedIdentityClientId = '<user-assigned-identity-client-id>'   # empty = system-assigned
$global:SI_SPN_TenantId  = '<your-tenant-id-guid>'

# Service principal instead: set SI_AuthMethod = 'Certificate' (recommended) or
# 'Secret', then fill in the app below.
# $global:SI_SPN_AppId     = '<your-spn-app-id-guid>'
# $global:SI_SPN_ObjectId  = '<your-spn-object-id-guid>'   # SP ObjectId, NOT AppId
# $global:SI_SPN_CertThumbprint    = '<cert-thumbprint>'
# $global:SI_SPN_CertStoreLocation = 'LocalMachine'   # or 'CurrentUser'
# $global:SI_SPN_Secret    = '<your-spn-client-secret>'   # Secret only; rotate via your Key Vault procedure

# ============================================================================
# 2. WORKSPACE + STORAGE
# ============================================================================
$global:SI_AzSubscriptionId    = '<sub-id-guid>'
$global:SI_WorkspaceResourceId = '/subscriptions/<sub-id>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<workspace-name>'
$global:SI_WorkspaceName       = '<workspace-name>'
$global:SI_DceName             = 'dce-securityinsight'
# DCE and DCR live in the SAME RG as the workspace by default (engine derives
# via Az lookup; explicit override only needed when you split resources across
# multiple RGs, which is unusual). Don't set these unless you've intentionally
# split -- stale value makes the engine print a wrong "ingest -> DCR" line.
# $global:SI_DceResourceGroup  = '<rg>'
# $global:SI_DcrResourceGroup  = '<rg>'
$global:SI_StorageAccount      = '<storage-account-name>'
$global:SI_Location            = '<azure-region>'              # REQUIRED. Examples: westeurope, northeurope, eastus, eastus2, westus2, southcentralus, uksouth, swedencentral, francecentral, germanywestcentral, switzerlandnorth, norwayeast, australiaeast, southeastasia, japaneast, canadacentral, brazilsouth

# ============================================================================
# 3. OUTPUT SINKS
# ============================================================================
$global:SI_Sinks_Endpoint  = @('LA','JSON','Excel')
$global:SI_Sinks_Identity  = @('LA','JSON','Excel')
$global:SI_Sinks_Azure     = @('LA','JSON','Excel')
$global:SI_Sinks_PublicIp  = @('LA','JSON','Excel')
$global:SendToLogAnalytics = $false   # optional copy of the Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL) -- off by default; SecurityInsight reads its database
# $global:ExportDestination  = 'https://<storage-account-name>.blob.core.windows.net/securityinsight/'   # optional: also copy the RA workbooks to blob storage

# ============================================================================
# 4. PER-ENGINE KNOBS
# ============================================================================
$global:SI_AssetLimit_Endpoint   = 0
$global:SI_AssetLimit_Identity   = 0
$global:SI_AssetLimit_Azure      = 0
$global:SI_AssetLimit_PublicIp   = 0
$global:SI_ForceFullRun_Endpoint = $false
$global:SI_ForceFullRun_Identity = $false
$global:SI_ForceFullRun_Azure    = $false
$global:SI_ForceFullRun_PublicIp = $false
$global:SI_AzureSubscriptionExcludePatterns = @('*Azure for Students*','*Visual Studio*')

# ============================================================================
# 5. SMTP  (inline -- Community has no platform-defaults to inherit from)
# ============================================================================
$global:SmtpServer  = '<smtp-host>'                  # your relay's host name
$global:SmtpPort    = 587                            # 25=plain/STARTTLS, 465=SMTPS, 587=submission
$global:SMTPUser    = '<svc-account@example.com>'
$global:SMTPPassword= '<app-password-or-OAuth-token>'
$global:SMTPFrom    = '<svc-account@example.com>'
$global:SMTP_UseSSL = $true

$global:RiskAnalysis_Detailed_SendMail = $true
$global:RiskAnalysis_Detailed_To       = @('<recipient-1@example.com>')
$global:RiskAnalysis_Summary_SendMail  = $true
$global:RiskAnalysis_Summary_To        = @('<recipient-1@example.com>')

# ============================================================================
# 6. RISK ANALYSIS
# ============================================================================
$global:RiskAnalysis_Summary_Override  = $true
$global:RiskAnalysis_Detailed_Override = $false
$global:AutoBucketCount                = $true
$global:AutoBucketMax                  = 131072   # the engine default; lower it only to cap a small estate
$global:AutoBucketCache                = $true
$global:OverwriteXlsx                  = $true

# --- Do the Summary and Detailed reports show the SAME figures? -------------
# The two reports count different things and always will: Summary counts distinct
# ASSETS ("142 machines affected"), Detailed counts individual ASSET FINDINGS
# ("those machines carry 9,410 findings between them"). Neither number is wrong --
# they answer different questions, and no setting can make them equal. Both mails
# carry a line under the Risk Score saying so.
#
#   'Consistent' (default) -- both mails show ONE set of figures, so management
#                             receiving BOTH reports sees the same numbers twice.
#   'PerReport'            -- each mail shows its own figures; nothing is borrowed.
#                             Right where management receives only ONE of them.
#
# Leave both unset to keep the behaviour SecurityInsight has always had.
# $global:SI_AISummary_Mode   = 'Consistent'   # or 'PerReport'
#
# In 'Consistent' mode, whose figures the other report adopts. A tie-breaker, NOT a
# claim that one report is more correct: once you ask for the two mails to agree,
# one of them has to be copied onto the other. Default 'Summary', because "142
# machines affected" is the sentence a board reads; set 'Detailed' if your
# management receives the Detailed report instead.
# 🪤 In 'Consistent' mode the follower's EMAIL HEADLINE shows the leader's figures
# while its ATTACHED WORKBOOK still contains its own rows -- so totalling the
# spreadsheet will not match the headline above it. That is what making the two
# mails agree costs. Choose 'PerReport' if that is not the trade you want.
# $global:SI_AISummary_Leader = 'Detailed'     # or 'Summary' (only with the Summary step switched on)

# ============================================================================
# 7. AZURE OPENAI  (inline -- or pull from KV in section 9)
# ============================================================================
$global:OpenAI_endpoint            = 'https://<aoai-account>.openai.azure.com'
$global:OpenAI_deployment          = '<deployment-name>'
$global:OpenAI_apiVersion          = '2025-01-01-preview'
$global:OpenAI_MaxTokensPerRequest = 16384
$global:OpenAI_apiKey              = '<aoai-api-key>'   # OR leave blank + use KV pull in section 9
$global:BuildSummaryByAI           = $true

# ============================================================================
# 8. PUBLICIP / SHODAN  (only if you run the publicip engine)
# ============================================================================
$global:SI_Shodan_ApiKey = '<shodan-api-key>'        # OR leave blank + use KV pull in section 9

# ============================================================================
# 9. KV PULLS  (optional -- replace inline secrets above by uncommenting)
# ============================================================================
# Read over REST with SecurityInsight's own sign-in -- no PowerShell module needed. The identity
# (managed identity or SPN certificate) needs 'Key Vault Secrets User' on the vault.
# . (Join-Path $PSScriptRoot '..\auth\Get-SIKvSecret.ps1')
# $kvName = '<your-kv-name>'
# if (-not $global:SI_SPN_Secret -and $global:SI_SPN_CertThumbprint -eq $null) {
#     $global:SI_SPN_Secret = Get-SIKvSecret -VaultName $kvName -SecretName 'SI-SPN-Secret'
# }
# if (-not $global:OpenAI_apiKey)    { $global:OpenAI_apiKey    = Get-SIKvSecret -VaultName $kvName -SecretName 'OpenAI-ApiKey' }
# if (-not $global:SI_Shodan_ApiKey) { $global:SI_Shodan_ApiKey = Get-SIKvSecret -VaultName $kvName -SecretName 'SI-Shodan-ApiKey' }
# if (-not $global:SMTPPassword)     { $global:SMTPPassword     = Get-SIKvSecret -VaultName $kvName -SecretName 'SI-SMTP-Password' }
