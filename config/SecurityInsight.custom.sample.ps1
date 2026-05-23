#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight v2.2 -- Internal-flavour customer override template.

.DESCRIPTION
    Internal customers use Connect-Platform (PlatformConfiguration repo) which
    auto-populates SPN cert, SMTP server/port/from, and Az subscription discovery
    from KV + platform-defaults.ps1 BEFORE this file loads. Result: a typical
    Internal customer file is short (~60 lines of active settings) -- mostly
    workspace IDs, recipient lists, engine knobs, and KV pulls.

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

    Community customers (no Connect-Platform): start from
    `SecurityInsight.custom.community.sample.ps1` instead.

.NOTES
    Flavour : Internal (Connect-Platform / platform-defaults inherited)
    Layer   : 3 (solution-wide customer overrides)
    Author  : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1. AUTH  (SPN + Cert via Connect-Platform / HighPriv_* globals)
# ============================================================================
$global:SpnTenantId              = $global:AzureTenantId
$global:SpnClientId              = $global:HighPriv_Modern_ApplicationID_Azure
$global:SpnCertificateThumbprint = $global:HighPriv_Modern_CertificateThumbprint_Azure
$global:SI_RebuildAuthBlock      = $true   # re-pull from KV on every run
$global:AutomationFramework      = $true   # use long-name HighPriv_* globals

# ============================================================================
# 2. WORKSPACE + STORAGE
# ============================================================================
$global:SI_WorkspaceResourceId = '/subscriptions/<sub-id>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<workspace-name>'
$global:SI_WorkspaceName       = '<workspace-name>'
$global:SI_DceName             = 'dce-securityinsight'
# DCE and DCR live in the SAME resource group as the workspace by default
# (engine derives via Az lookup; explicit override only needed when you split
# resources across multiple RGs, which is unusual). Don't set these unless
# you've intentionally placed the DCE/DCR in a different RG -- a stale value
# here makes the engine print a wrong "ingest -> DCR (rg=...)" line.
# $global:SI_DceResourceGroup  = '<rg>'
# $global:SI_DcrResourceGroup  = '<rg>'
$global:SI_StorageAccount      = '<storage-account-name>'
$global:SI_Location            = '<azure-region>'              # REQUIRED. Examples: westeurope, northeurope, eastus, eastus2, westus2, southcentralus, uksouth, swedencentral, francecentral, germanywestcentral, switzerlandnorth, norwayeast, australiaeast, southeastasia, japaneast, canadacentral, brazilsouth
# $global:SI_TableNamePattern  = 'SI_{0}_Profile'              # engine default
# $global:SI_DcrNamePattern    = 'dcr-si-{0}-profile'          # engine default

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
# 5. RA MAIL RECIPIENTS  (Server/Port/From inherited from platform-defaults.ps1)
# ============================================================================
$global:RiskAnalysis_Detailed_SendMail = $true
$global:RiskAnalysis_Detailed_To       = @('<recipient-1@example.com>','<recipient-2@example.com>')
$global:RiskAnalysis_Summary_SendMail  = $true
$global:RiskAnalysis_Summary_To        = @('<recipient-1@example.com>','<recipient-2@example.com>')

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
# 7. AZURE OPENAI  (API key pulled from KV at bottom of file)
# ============================================================================
$global:OpenAI_endpoint            = 'https://<aoai-account>.openai.azure.com'
$global:OpenAI_deployment          = '<deployment-name>'
$global:OpenAI_apiVersion          = '2025-01-01-preview'
$global:OpenAI_MaxTokensPerRequest = 16384
$global:BuildSummaryByAI           = $true

# ============================================================================
# 8. CMDB + ACTIVITY FRESHNESS
# ============================================================================
$global:SI_EnableCmdbProvider       = $true
$global:SI_CmdbRefreshIntervalHours = 24
$global:SI_ActiveStaleDays          = 30

# ============================================================================
# 9. CONTAINER APP JOB BOOTSTRAP  (uncomment when running Bootstrap-ContainerAppJob.ps1)
# ============================================================================
# $global:SI_Bootstrap_ResourceGroupName       = 'rg-securityinsight'
# $global:SI_Bootstrap_Location                = '<azure-region>'    # REQUIRED. Match $global:SI_Location above.
# $global:SI_Bootstrap_AcrName                 = 'acrsecurityinsight'
# $global:SI_Bootstrap_EnvName                 = 'cae-securityinsight'
# $global:SI_Bootstrap_ImageTag                = 'latest'
# $global:SI_Bootstrap_Engines                 = @('endpoint','identity','azure','schema-discovery','risk-analysis')
# $global:SI_Bootstrap_ScheduleEndpoint        = '0 4 * * *'
# $global:SI_Bootstrap_ScheduleIdentity        = '30 4 * * *'
# $global:SI_Bootstrap_ScheduleAzure           = '0 5 * * *'
# $global:SI_Bootstrap_ScheduleSchemaDiscovery = '0 3 * * 0'
# $global:SI_Bootstrap_ScheduleRiskAnalysis    = '0 6 * * *'
# $global:SI_Bootstrap_TriggerNowAfter         = $true
# $global:SI_Bootstrap_SkipImageBuild          = $true
# $global:SI_Bootstrap_UseManagedIdentity      = $true
# $global:SI_Bootstrap_UseKEDA                 = $true
# $global:SI_Bootstrap_KedaMaxReplicas         = 30
# $global:SI_RiskAnalysis_ExportContainer      = 'sistaging'
# $global:SI_RiskAnalysis_ExportPrefix         = 'risk-analysis'
# $global:SI_RiskAnalysis_SendToLogAnalytics   = $true
# $global:SI_RiskAnalysis_BuildSummaryByAI     = $true

# ============================================================================
# 10. KV PULLS  (late-binding -- runs after $global:Context is set)
# ============================================================================
if (-not $global:SI_StorageKey)    { $global:SI_StorageKey    = Get-PlatformSecret -Context $global:Context -Name 'SI-StorageKey'    -AsPlainText }
if (-not $global:SI_Shodan_ApiKey) { $global:SI_Shodan_ApiKey = Get-PlatformSecret -Context $global:Context -Name 'SI-Shodan-ApiKey' -AsPlainText }
if (-not $global:OpenAI_apiKey)    { $global:OpenAI_apiKey    = Get-PlatformSecret -Context $global:Context -Name 'OpenAI-ApiKey'    -AsPlainText }
