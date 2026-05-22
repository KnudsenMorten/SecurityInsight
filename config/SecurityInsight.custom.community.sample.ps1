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
# 1. AUTH  (standalone SPN -- pick ONE of secret OR cert below)
# ============================================================================
$global:SI_SPN_TenantId  = '<your-tenant-id-guid>'
$global:SI_SPN_AppId     = '<your-spn-app-id-guid>'
$global:SI_SPN_ObjectId  = '<your-spn-object-id-guid>'   # SP ObjectId, NOT AppId

# SPN secret (rotate via Setup Wizard or your KV procedure)
$global:SI_SPN_Secret    = '<your-spn-client-secret>'

# OR SPN cert (uncomment + remove the Secret line above to switch)
# $global:SI_SPN_CertThumbprint    = '<cert-thumbprint>'
# $global:SI_SPN_CertStoreLocation = 'LocalMachine'   # or 'CurrentUser'

# ============================================================================
# 2. WORKSPACE + STORAGE
# ============================================================================
$global:SI_AzSubscriptionId    = '<sub-id-guid>'
$global:SI_WorkspaceResourceId = '/subscriptions/<sub-id>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<workspace-name>'
$global:SI_WorkspaceName       = '<workspace-name>'
$global:SI_DceName             = 'dce-securityinsight'
$global:SI_DcrResourceGroup    = '<dcr-rg>'
$global:SI_StorageAccount      = '<storage-account-name>'
$global:SI_Location            = '<azure-region>'              # REQUIRED. Examples: westeurope, northeurope, eastus, eastus2, westus2, southcentralus, uksouth, swedencentral, francecentral, germanywestcentral, switzerlandnorth, norwayeast, australiaeast, southeastasia, japaneast, canadacentral, brazilsouth

# ============================================================================
# 3. OUTPUT SINKS
# ============================================================================
$global:SI_Sinks_Endpoint  = @('LA','JSON','Excel')
$global:SI_Sinks_Identity  = @('LA','JSON','Excel')
$global:SI_Sinks_Azure     = @('LA','JSON','Excel')
$global:SI_Sinks_PublicIp  = @('LA','JSON','Excel')
$global:SendToLogAnalytics = $true
$global:ExportDestination  = 'https://<storage-account-name>.blob.core.windows.net/securityinsight/'

# ============================================================================
# 4. PER-ENGINE KNOBS
# ============================================================================
$global:SI_AssetLimit_Endpoint   = 0
$global:SI_AssetLimit_Identity   = 0
$global:SI_AssetLimit_Azure      = 0
$global:SI_AssetLimit_PublicIp   = 0
$global:SI_ForceFullRun_Endpoint = $true
$global:SI_ForceFullRun_Identity = $true
$global:SI_ForceFullRun_Azure    = $true
$global:SI_ForceFullRun_PublicIp = $true
$global:SI_AzureSubscriptionExcludePatterns = @('*Azure for Students*','*Visual Studio*')

# ============================================================================
# 5. SMTP  (inline -- Community has no platform-defaults to inherit from)
# ============================================================================
$global:SmtpServer  = '<smtp-host>'                  # e.g. smtp.office365.com, smtp-relay.brevo.com
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
$global:AutoBucketMax                  = 1024
$global:AutoBucketCache                = $true
$global:OverwriteXlsx                  = $true

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
# Requires the SPN to have Get on the named Key Vault secrets + Az.KeyVault module.
# $kvName = '<your-kv-name>'
# if (-not $global:SI_SPN_Secret -and $global:SI_SPN_CertThumbprint -eq $null) {
#     $global:SI_SPN_Secret = (Get-AzKeyVaultSecret -VaultName $kvName -Name 'SI-SPN-Secret'    -AsPlainText -ErrorAction SilentlyContinue)
# }
# if (-not $global:OpenAI_apiKey)    { $global:OpenAI_apiKey    = (Get-AzKeyVaultSecret -VaultName $kvName -Name 'OpenAI-ApiKey'   -AsPlainText -ErrorAction SilentlyContinue) }
# if (-not $global:SI_Shodan_ApiKey) { $global:SI_Shodan_ApiKey = (Get-AzKeyVaultSecret -VaultName $kvName -Name 'SI-Shodan-ApiKey' -AsPlainText -ErrorAction SilentlyContinue) }
# if (-not $global:SMTPPassword)     { $global:SMTPPassword     = (Get-AzKeyVaultSecret -VaultName $kvName -Name 'SI-SMTP-Password' -AsPlainText -ErrorAction SilentlyContinue) }
