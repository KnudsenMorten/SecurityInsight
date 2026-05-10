#Requires -Version 5.1
<#
.SYNOPSIS
    Solution-wide overrides for SecurityInsight v2.2 (Layer 3 of the layered config).

.DESCRIPTION
    Copy this file to SecurityInsight.custom.ps1 in the SAME folder (the
    customer-owned copy is gitignored). Drop auth (SPN, OpenAI, SMTP) + workspace
    pointers here ONCE so every v2.2 engine inherits them; leave each engine's
    LauncherConfig.custom.ps1 empty (or limited to engine-specific tuning).

    LAYER PRECEDENCE  (each layer overrides the previous; closer wins):
      1. LAUNCHERS/_lib/SecurityInsight.shared-defaults.ps1                 Solution baseline
      2. LAUNCHERS/<engine>/LauncherConfig.defaults.ps1                     Engine baseline
      3. SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1        Solution-wide customer (THIS FILE)
      4. LAUNCHERS/<engine>/LauncherConfig.custom.ps1                       Per-engine customer (wins)

    v2.2 changes vs v2.1: asset profiling split into 4 engines (endpoint /
    identity / azure / publicip), each with its own SI_AssetLimit_<Engine>,
    SI_Sinks_<Engine>, SI_ForceFullRun_<Engine>, SI_EnableAI_<Engine>.
    Single-SPN model (SI_SPN_*) replaces the old Graph/LogIngest split
    (SI_Graph_* / SI_LogIngest_* still accepted as legacy aliases). Storage
    account is now load-bearing (sistaging container + cache JSON).

.NOTES
    LauncherConfigVersion : 2
    Solution              : SecurityInsight v2.2
    Layer                 : 3 (solution-wide customer overrides)
    Developed by          : Morten Knudsen, Microsoft MVP
#>


# ============================================================================
# 1.  AUTHENTICATION  --  single-SPN model (Graph + ARG + LA ingest, one SPN)
# ============================================================================
# v2.2 uses ONE SPN for everything: Defender Graph reads, ARG, and Log Analytics
# DCR ingest. SPN must hold ThreatHunting.Read.All, Device.Read.All,
# User.Read.All, Application.Read.All Graph app-roles + Reader on the sub +
# Monitoring Metrics Publisher on the DCR RG (+ Storage Blob/Table/Queue Data
# Contributor on the staging account when using SI_UseStorageOAuth).
#
# These four are REQUIRED. Bootstrap-Auth.ps1 pulls them from KV when blank.
$global:SI_SPN_TenantId = '<your-tenant-id-guid>'
$global:SI_SPN_AppId    = '<your-spn-app-id-guid>'
$global:SI_SPN_Secret   = '<your-spn-client-secret>'
$global:SI_SPN_ObjectId = '<your-spn-object-id-guid>'   # SP ObjectId, NOT AppId

# Legacy split-SPN aliases (still honoured as fallback by the engine; set
# only if you can't use the unified SI_SPN_* names above):
# $global:SI_Graph_AppId        = '<graph-spn-app-id>'
# $global:SI_Graph_Secret       = '<graph-spn-secret>'
# $global:SI_Graph_TenantId     = '<tenant-id>'
# $global:SI_LogIngest_AppId    = '<ingest-spn-app-id>'
# $global:SI_LogIngest_Secret   = '<ingest-spn-secret>'
# $global:SI_LogIngest_TenantId = '<tenant-id>'
# $global:SI_LogIngest_ObjectId = '<ingest-spn-object-id>'

# UAMI mode (opt-in). When $true, the engine asks IMDS for tokens. Otherwise
# it uses the SI_SPN_* secret above.
# $global:SI_PreferUami    = $true
# $global:SI_UAMI_ClientId = '<uami-client-id-guid>'

# --- Launcher auth surface (community-vm + internal-vm launcher dispatch) ---
# The launchers (NOT the engines) read $global:Spn* + $global:UseManagedIdentity
# to decide HOW to log in to Azure. Pick ONE method block. The launcher then
# also exports the resolved values into SI_SPN_* for engine consumption, so
# you don't usually need both blocks set.
#
#   Method 1 -- Managed Identity:
#     $global:UseManagedIdentity = $true
#     $global:SpnTenantId        = '<tenant-id-guid>'
#
#   Method 2 -- SPN + Key Vault secret:
#     $global:SpnTenantId     = '<tenant-id-guid>'
#     $global:SpnClientId     = '<spn-app-id-guid>'
#     $global:SpnKeyVaultName = '<kv-name>'
#     $global:SpnSecretName   = 'SecurityInsight-Secret'
#
#   Method 3 -- SPN + certificate (thumbprint in LocalMachine/CurrentUser store):
#     $global:SpnTenantId              = '<tenant-id-guid>'
#     $global:SpnClientId              = '<spn-app-id-guid>'
#     $global:SpnCertificateThumbprint = '<hex thumbprint, no spaces>'
#
#   Method 4 -- SPN + plaintext secret (TESTING ONLY):
#     $global:SpnTenantId     = '<tenant-id-guid>'
#     $global:SpnClientId     = '<spn-app-id-guid>'
#     $global:SpnClientSecret = '<spn-client-secret>'

# Force Bootstrap-Auth.ps1 to re-pull from KV even when SI_SPN_AppId is
# already present in this file (rotates a leaked secret from the vault).
# $global:SI_RebuildAuthBlock = $true

# Path to a non-default custom config file (only when this file lives outside
# the canonical config/ folder; very rare).
# $global:SI_CustomConfigPath = '\\fileshare\IT\SecurityInsight.custom.ps1'


# ============================================================================
# 2.  WORKSPACE + INGESTION  --  Log Analytics + DCR + DCE
# ============================================================================
# Canonical names live in LAUNCHERS/_lib/SecurityInsight.shared-defaults.ps1.
# Override here only if your tenant deviates from that layout.

# REQUIRED for v2.2: full /subscriptions/.../workspaces/<ws> ARM resource ID.
# Engines that ingest to LA need this (the v2.1 short name was deprecated).
$global:SI_WorkspaceResourceId = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>'

# REQUIRED for v2.2 collection engines: storage account + key for the
# 'sistaging' container (per-asset shards, cache JSONs, schema diffs).
# Bootstrap-Storage.ps1 prints a copy-paste line with both populated.
$global:SI_StorageAccount = '<storage-account-name>'
$global:SI_StorageKey     = '<storage-account-primary-key-base64>'

# DCE / DCR resource layout (auto-resolved when the canonical short names below
# match your tenant; override only when they don't).
# $global:SI_DceName              = 'dce-securityinsight'
# $global:SI_DcrResourceGroup     = 'rg-dcr-securityinsight'
# $global:SI_WorkspaceName        = 'log-platform-management-securityinsight'
# $global:SI_DefenderWorkspaceResourceId = '/subscriptions/.../workspaces/<defender-ws>'   # only when MDE/IdentityInfo lives in a DIFFERENT workspace
# $global:SI_HasExposureGraphInLA = $true   # set when ExposureGraph is mirrored to LA (Sentinel data lake); enables RA queries that need EG tables

# Legacy short aliases (still read by the launchers + Setup script + RA fallback):
# $global:WorkspaceName          = 'log-platform-management-securityinsight'
# $global:WorkspaceResourceGroup = 'rg-securityinsight'
# $global:WorkspaceResourceId    = '/subscriptions/.../workspaces/<ws>'   # RA falls back to this when SI_WorkspaceResourceId is unset
# $global:DceName                = 'dce-securityinsight'
# $global:DceResourceGroup       = 'rg-dce-securityinsight'
# $global:DcrResourceGroup       = 'rg-dcr-securityinsight'
# $global:Location               = 'westeurope'
# $global:SubscriptionId         = '<your-target-subscription-id-guid>'

# Optional: explicit DCE ingestion URI (auto-resolved from SI_DceName otherwise).
# $global:DceIngestionUri    = 'https://dce-securityinsight-xxxx.westeurope-1.ingest.monitor.azure.com'
# $global:SI_DceIngestionUri = 'https://dce-securityinsight-xxxx.westeurope-1.ingest.monitor.azure.com'   # canonical SI alias
# $global:SI_DceIngestUri    = 'https://dce-securityinsight-xxxx.westeurope-1.ingest.monitor.azure.com'   # legacy publicip-engine alias

# Subscription override for DCR merge diagnostics + ad-hoc setup helpers.
# $global:SI_AzSubscriptionId = '<sub-id-guid>'

# Region override (used during workspace/DCE/DCR creation when missing).
# $global:SI_Location = 'westeurope'

# v2.2 LA table + DCR naming patterns. {0} placeholder is filled with engine name.
# Defaults: 'SI_{0}_Profile' + 'dcr-si-{0}-profile'. Override only if you maintain
# a parallel naming scheme.
# $global:SI_TableNamePattern = 'SI_{0}_Profile'
# $global:SI_DcrNamePattern   = 'dcr-si-{0}-profile'

# Diagnostic: dump pre-/post-merge column diff for every DCR ingest call.
# Off by default; turn on briefly when investigating "column dropped" warnings.
# $global:SI_DcrMergeDiagnostic = $true

# Optional staging directory override (defaults under SI_StorageAccount sistaging).
# $global:SI_StagingPath = 'D:\SI-staging'


# ============================================================================
# 3.  OUTPUT SINKS  --  Excel / JSON / LA / PowerBI / Mail / Blob upload
# ============================================================================

# Per-engine sinks: any subset of @('LA','JSON','Excel'). Default = all three.
# $global:SI_Sinks_Endpoint = @('LA','JSON','Excel')
# $global:SI_Sinks_Identity = @('LA','JSON','Excel')
# $global:SI_Sinks_Azure    = @('LA','JSON','Excel')
# $global:SI_Sinks_PublicIp = @('LA','JSON','Excel')

# RiskAnalysis: master ingest toggle for SI_RiskAnalysis_Summary_CL /
# SI_RiskAnalysis_Detailed_CL. Default $false (XLSX/JSON only).
# $global:SendToLogAnalytics = $true

# RiskAnalysis: write a JSON sibling next to the .xlsx. Default $true since
# preview.196 (the engine's $global:WriteJsonOutput auto-defaults to $true
# when unset). Set $false to suppress.
# $global:WriteJsonOutput = $false

# RiskAnalysis: blob/UNC upload after Excel/JSON write. Type auto-detected
# from prefix: 'https://...' = Azure Blob, '\\server\share' = UNC.
# Backup-then-overwrite: existing files renamed <name>.<ts>.<ext>.bak.
# $global:ExportDestination = 'https://<storacct>.blob.core.windows.net/<container>/'

# Power BI dataset refresh (per-run trigger after LA ingest completes).
# $global:SendToPowerBI         = $true
# $global:PowerBI_WorkspaceName = 'SecurityInsight-Reports'
# $global:PowerBI_DatasetName   = 'SecurityInsight - Risk Analysis'
# $global:PowerBI_AuthTenantId    = '<tenant-id-guid>'
# $global:PowerBI_AuthClientId    = '<powerbi-spn-client-id>'
# $global:PowerBI_AuthClientSecret = '<powerbi-spn-secret>'

# --- SMTP (RiskAnalysis email delivery) ---
# Brevo/SendGrid/Postmark/M365 REJECT mail when From != verified sender, so
# $SMTPFrom must be a verified-sender address -- NOT the relay login.
# $global:SendMail        = $true
# $global:MailTo          = @('soc@yourdomain.com')
# $global:SmtpServer      = 'smtp-relay.brevo.com'
# $global:SMTPPort        = 587
# $global:SMTP_UseSSL     = $true
# $global:SMTPUser        = '<smtp-login-username>'
# $global:SMTPPassword    = '<smtp-login-password>'
# $global:SMTPFrom        = 'noreply@yourdomain.com'
# $global:Mail_SendAnonymous = $true     # anonymous relay (no creds; not common)

# Per-mode mail routing for RiskAnalysis (community short names).
# $global:RiskAnalysis_Summary_SendMail  = $true
# $global:RiskAnalysis_Summary_To        = @('exec-summary@yourdomain.com')
# $global:RiskAnalysis_Detailed_SendMail = $true
# $global:RiskAnalysis_Detailed_To       = @('soc@yourdomain.com')

# AF-prefixed equivalents (internal AutomationFramework reads these).
# $global:Mail_SecurityInsight_Summary_SendMail  = $true
# $global:Mail_SecurityInsight_Summary_To        = @('exec-summary@yourdomain.com')
# $global:Mail_SecurityInsight_Detailed_SendMail = $true
# $global:Mail_SecurityInsight_Detailed_To       = @('IT-Alerts@yourdomain.com')


# ============================================================================
# 4.  ENGINE: ENDPOINT  --  device asset profiling (MDE + EG + Entra + ARG)
# ============================================================================
# Read by: launcher/endpoint/* + engine/asset-profiling/* (when -Engine endpoint)

# Cap discovered assets (0 = unlimited). KEEP at 0 for production smoke tests.
# $global:SI_AssetLimit_Endpoint = 0

# Skip the per-asset cadence short-circuit; re-classify every asset this run.
# $global:SI_ForceFullRun_Endpoint = $true

# Per-engine AI opt-in (force-off via SI_DisableAI_endpoint = $true).
# $global:SI_EnableAI_endpoint = $true
# $global:SI_DisableAI_endpoint = $true

# AI system-prompt override for the Endpoint Classify call.
# $global:SI_SystemPrompt_endpoint = "<your full system prompt>"

# Suppress assets that exist ONLY in EG/MDE/ARG but not in Entra (default = include).
# $global:SI_RequireMasterPresence = $true

# Disable the EndpointAzureCorrelation cache (only after diagnosing a cache bug).
# $global:SI_DisableEndpointAzureCorrelation = $true


# ============================================================================
# 5.  ENGINE: IDENTITY  --  user + service-principal profiling (Entra + EG)
# ============================================================================
# Read by: launcher/identity/* + engine/asset-profiling/* (when -Engine identity)
# Note: Identity is catalog-driven; AI is HARD-DISABLED in Test-SIAIEnabled.ps1.

# $global:SI_AssetLimit_Identity = 0
# $global:SI_ForceFullRun_Identity = $true

# Include 1st-party Microsoft service principals in discovery. Default $true
# (preview.87+; was opt-in in earlier previews -- noisier but more complete).
# $global:SI_IncludeFirstPartySpns = $false

# Sign-in enrichment (per-identity SignInActivity reads from Graph).
# $global:SI_EnableSignInEnrich = $true
# $global:SI_SignInBatchSize    = 100
# $global:SI_SignInEnrichMax    = 10000
# $global:SI_SignInLookbackDays = 7
# ^ default 7d. Drives all 3 sign-in/logon queries: EntraIdSignInEvents (per-user
#   enrichment) + DeviceLogonEvents (per-user devices + per-device primary users).

# Switch from EG bucket-paging to single-pass when bucket count exceeds N.
# Default 30000 (matches Defender's per-query row ceiling).
# $global:SI_EgIdentityBucketThreshold = 30000

# Subscriptions to EXCLUDE from delegation enumeration (wildcard match).
# $global:SI_AzureSubscriptionExcludePatterns = @('*Azure for Students*','*Visual Studio*')

# Custom Security Attribute set name used by Entra tagging logic. Default
# 'SecurityInsight'.
# $global:CsaAttributeSet = 'SecurityInsight'

# AI system-prompt override -- engine HARD-DISABLES identity AI today, so this
# is read but currently no-op; here for forward-compat.
# $global:SI_SystemPrompt_identity = "<your full system prompt>"


# ============================================================================
# 6.  ENGINE: AZURE  --  Azure resource profiling (EG primary + ARG fallback)
# ============================================================================
# Read by: launcher/azure/* + engine/asset-profiling/* (when -Engine azure)

# $global:SI_AssetLimit_Azure = 0
# $global:SI_ForceFullRun_Azure = $true
# $global:SI_EnableAI_azure = $true
# $global:SI_SystemPrompt_azure = "<your full system prompt>"

# Hard cap on resources pulled from ARG in one run (0 = ARG's own 100k cap applies).
# Use a smaller value for first-runs in big tenants (limits AI metaprofile spend).
# $global:SI_AzureMaxResources = 5000

# Restrict discovery to a hand-picked allowlist (default = ALL ARG-readable types).
# $global:SI_AzureResourceTypes = @('microsoft.keyvault/vaults','microsoft.storage/storageaccounts','microsoft.sql/servers')

# Additional types to EXCLUDE on top of the engine's noisy-types list.
# $global:SI_AzureExcludeTypes = @('microsoft.network/publicipaddresses','microsoft.compute/disks')

# Restrict subscription scope (default = every subscription the SPN can read).
# $global:SI_AzureResourceSubscriptions = @('<sub-id-1>','<sub-id-2>')

# EG node-label allowlist for Azure types (default = enumerated weekly).
# $global:SI_AzureEgTypeAllowlist = @('microsoft.keyvault/vaults','microsoft.storage/storageaccounts')

# EG node + edge label overrides (only when XDR schema is non-standard).
# $global:SI_AzureExposureGraph_ResourceLabels   = @('storageaccount','keyvault')
# $global:SI_AzureExposureGraph_IdentityLabels   = @('user','serviceprincipal')
# $global:SI_AzureExposureGraph_AccessEdgeLabels = @('has access to','can authenticate as')

# Forward-compat stub for explicit discovery-mode override (not yet wired).
# $global:SI_DiscoveryMode_azure = 'EG'


# ============================================================================
# 7.  ENGINE: PUBLICIP  --  public-IP scanner (Shodan REST integration)
# ============================================================================
# Read by: launcher/publicip/* + engine/publicip/Invoke-PublicIpScanner.ps1

# $global:SI_AssetLimit_PublicIp = 0
# $global:SI_ForceFullRun_PublicIp = $true
# $global:SI_EnableAI_publicip = $true

# Shodan API key (required for the engine to do anything useful).
# $global:SHODAN_ApiKey = '<your-shodan-api-key>'
# $global:SI_Shodan_ApiKey = '<your-shodan-api-key>'    # canonical SI-prefixed alias

# Cache + spend guards.
# $global:SI_ShodanCacheAgeDays            = 7
# $global:SI_ShodanMonthlyCreditCap        = 4000
# $global:SI_Shodan_LookbackDays           = 30
# $global:SI_Shodan_FreshScanIntervalHours = 24
# $global:SI_Shodan_ForceFreshScan         = $true
# $global:SI_Shodan_TierMax                = 1     # tiers > TierMax skip Shodan (T0/T1 only by default)
# $global:SI_Shodan_AssetLimit             = 0
# $global:SI_Shodan_ThrottleMs             = 1100  # 1 req/sec (Shodan free-tier rate)
# $global:SI_Shodan_TimeoutSec             = 30
# $global:SI_Shodan_ScanWaitMaxSec         = 600
# $global:SI_Shodan_ScanPollIntervalSec    = 10
# $global:SI_Shodan_PendingScansPath       = '<staging-blob-path>'
# $global:SI_Shodan_LastFreshScanPath      = '<staging-blob-path>'
# $global:SI_Shodan_TableName              = 'SI_Shodan'
# $global:SI_Shodan_DcrName                = 'dcr-si-shodan'
# $global:SI_Shodan_SkipLA_Ingest          = $true

# Customer-supplied extra targets (partner / supply-chain IPs to monitor).
# $global:SI_PublicIP_ExtraTargets = @('203.0.113.10','198.51.100.42')
# $global:SI_Shodan_ExtraIPs       = @('203.0.113.10','198.51.100.42')   # alias


# ============================================================================
# 8.  ENGINE: RISK-ANALYSIS  --  cross-CL hunting reports + Excel/AI summary
# ============================================================================
# Read by: launcher/risk-analysis/* + engine/risk-analysis/Invoke-RiskAnalysis.ps1

# Mode override (per-run). Mutually exclusive: Summary (tier-rolled-up) vs
# Detailed (one row per affected identity/device).
# $global:RiskAnalysis_Summary_Override  = $true
# $global:RiskAnalysis_Detailed_Override = $false

# Per-mode ReportTemplate override (bucketed templates handle >30k rows).
# $global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
# $global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# RA-specific workspace + DCR overrides (override the shared values in section 2).
# $global:SI_RiskAnalysis_WorkspaceResourceId    = '/subscriptions/.../workspaces/<ra-ws>'
# $global:SI_RiskAnalysis_WorkspaceName          = '<ra-workspace-name>'
# $global:SI_RiskAnalysis_WorkspaceResourceGroup = '<ra-rg>'
# $global:SI_RiskAnalysis_DceName                = 'dce-securityinsight-ra'
# $global:SI_RiskAnalysis_DceIngestionUri        = 'https://dce-...ingest.monitor.azure.com'
# $global:SI_RiskAnalysis_DcrResourceGroup       = 'rg-dcr-securityinsight'
# $global:SI_RiskAnalysis_TableName_Summary      = 'SI_RiskAnalysis_Summary'
# $global:SI_RiskAnalysis_TableName_Detailed     = 'SI_RiskAnalysis_Detailed'
# $global:SI_RiskAnalysis_ExportDestination      = 'https://<storacct>.blob.core.windows.net/risk-reports/'

# Tune the risk-score model (deep-merged with the locked schema).
# $global:SI_RiskAnalysis_RiskScoreModelOverride = @{ ... }

# Append additional per-engine fields to the risk-factor projection.
# $global:SI_RiskAnalysis_RiskFactorFieldsExtra = @{ endpoint = @('IsCustomFlag') }

# Adaptive bucketing (handles Defender's 30k-row query ceiling).
# $global:AutoBucketCount = $true     # probe 1->2->4->...->AutoBucketMax
# $global:AutoBucketMax   = 1024
# $global:AutoBucketCache = $true     # reuse last-known-good bucket count
# $global:ResetCache      = $true     # force fresh bucket probe

# Graph reconnect / retry tuning.
# $global:GraphReconnectMaxAgeMinutes = 45
# $global:GraphQueryMaxRetries        = 4

# Run-mode + scope flags.
# $global:Summary  = $true            # community short-name (also set by launcher)
# $global:Detailed = $true
# $global:Scope          = @('PROD')  # or @('TEST')
# $global:DebugQueryHash = $true
# $global:ShowConfig     = $true
# $global:ReportTemplate = 'RiskAnalysis_Summary_Bucket'
# $global:OverwriteXlsx  = $true


# ============================================================================
# 9.  ENGINE: PRIVILEGE-TIER-CLASSIFIER  --  builds tier-definitions JSON via AI
# ============================================================================
# Read by: launcher/privilege-tier-classifier/* + engine/privilege-tier-classifier/

# Master switch. $true (default) runs all 4 AI categories; $false short-circuits
# to the static built-in tier map.
# $global:SI_PrivilegeTierClassifier_RunAI = $false


# ============================================================================
# 10. ENGINE: SCHEMA-DISCOVERY  --  weekly XDR schema sweep + AI rule proposals
# ============================================================================
# Read by: engine/asset-profiling/stages/Invoke-SchemaDiscover.ps1 + Invoke-SchemaPropose.ps1

# AI cost ceiling for one schema-discovery run (USD; per-finding ~$0.01).
# $global:SI_SchemaProposeAiCeiling = 5.0

# Override the curated hunting-table list (default = 16 high-signal tables).
# $global:SI_SchemaTables = @('DeviceInfo','IdentityInfo','AlertEvidence')

# Auto-load AI-proposed pending rules into the live engine. Default OFF
# (drafts must be reviewed + promoted via human PR first).
# $global:SI_LoadPendingRules = $true

# Optional: override the default schema-catalog DCR / table names.
# $global:SI_SchemaCatalogDcr   = 'dcr-si-schema-catalog'
# $global:SI_SchemaCatalogTable = 'SI_Schema_Catalog'

# Optional: override the asset-tagging audit DCR / table (Invoke-Tagging).
# $global:SI_AssetTagActivityDcr   = 'dcr-si-assettag-activity'
# $global:SI_AssetTagActivityTable = 'SI_AssetTagActivity'


# ============================================================================
# 11. AZURE OPENAI  --  shared by RiskAnalysis AI summary + asset-profile Classify
# ============================================================================
# These four values are required when ANY engine has AI enabled (SI_EnableAI,
# SI_EnableAI_<engine>, BuildSummaryByAI, or SI_PrivilegeTierClassifier_RunAI).
# $global:OpenAI_apiKey              = '<your-azure-openai-key>'
# $global:OpenAI_endpoint            = 'https://<your-aoai-account>.openai.azure.com'
# $global:OpenAI_deployment          = '<your-deployment-name>'
# $global:OpenAI_apiVersion          = '2024-08-01-preview'
# $global:OpenAI_MaxTokensPerRequest = 16384

# RiskAnalysis: master ON/OFF for the AI executive summary in the email body.
# $global:BuildSummaryByAI = $true

# Tenant-wide AI opt-in for asset-profiling Classify (turns AI on for endpoint+
# azure+publicip; identity is hard-disabled). Per-engine opt-in is preferred.
# $global:SI_EnableAI = $true

# Tenant-wide AI kill-switch (wins over every opt-in above).
# $global:SI_DisableAI = $true

# AI spend ceiling for one orchestrator run (USD). Stage Classify stops when
# reached; remaining rows tagged SI_Classify_Status='budget-capped'. Default 4.
# $global:MaxAiSpendPerRun = 4

# Per-call cost estimate (USD). Default 0.01. Tune after observing actuals.
# $global:SI_AI_CostPerCallEstimate = 0.012

# Dump AI request/response payloads to disk (debug only; verbose I/O).
# $global:SI_DumpAIPayload = $true

# Bump to invalidate the cached per-engine signal-map weights (forces re-AI).
# $global:SI_SignalMap_PromptVersion = 'v2'


# ============================================================================
# 12. ASSET-PROFILING BEHAVIOUR  --  tier cadence + CMDB + activity freshness
# ============================================================================

# Force a full re-run for ALL profile engines this invocation. Per-engine
# overrides (SI_ForceFullRun_<Engine>) win over this tenant-wide switch.
# $global:SI_ForceFullRun = $true

# --- Tier-driven cadence (asset-profiling Stage Collect skip gate) ---
# Strings: '12h', '24h', '3d', '7d', or combos like '1d12h'. Engine defaults:
#   T0='12h'  T1='24h'  T2='3d'  T3='7d'  Default='24h'
# $global:SI_TierCadence_T0      = '12h'    # DCs, breakglass, GA admins
# $global:SI_TierCadence_T1      = '24h'    # production servers, privileged users
# $global:SI_TierCadence_T2      = '3d'     # workstations, regular users
# $global:SI_TierCadence_T3      = '7d'     # test/dev, externals, guests, shadow IT
# $global:SI_TierCadence_Default = '24h'    # used when cached tier is null/unknown

# --- CMDB provider auto-refresh (preview.87+) ---
# When ENABLED, Stage Schedule auto-refreshes the CMDB cache at run start (gated
# by cache age). Reconcile then folds matched rows into Properties.collect.cmdb.
# $global:SI_EnableCmdbProvider       = $true
# $global:SI_CmdbRefreshIntervalHours = 24
# $global:SI_CmdbCsvPath              = '\\fileshare\IT\cmdb-export.csv'

# --- Active-asset freshness threshold (preview.87+) ---
# Asset is IsEnabledActive=$true when seen by a provider within N days.
# $global:SI_ActiveStaleDays = 30


# ============================================================================
# 13. CONTAINER APP JOB BOOTSTRAP  --  Bootstrap-ContainerAppJob.ps1 knobs
# ============================================================================
# Each value below is the parameter default; uncomment to override before running
# Bootstrap-ContainerAppJob.ps1. CLI -<ParamName> always wins over these globals.

# ARM resource naming.
# $global:SI_Bootstrap_ResourceGroupName = 'rg-securityinsight'
# $global:SI_Bootstrap_Location          = 'westeurope'
# $global:SI_Bootstrap_AcrName           = 'acrsecurityinsight'
# $global:SI_Bootstrap_EnvName           = 'cae-securityinsight'
# $global:SI_Bootstrap_ImageTag          = 'latest'
# $global:SI_Bootstrap_Engines           = @('endpoint','identity','azure','schema-discovery','risk-analysis')

# Cron schedules (UTC).
# $global:SI_Bootstrap_ScheduleEndpoint        = '0 4 * * *'
# $global:SI_Bootstrap_ScheduleIdentity        = '30 4 * * *'
# $global:SI_Bootstrap_ScheduleAzure           = '0 5 * * *'
# $global:SI_Bootstrap_ScheduleSchemaDiscovery = '0 3 * * 0'
# $global:SI_Bootstrap_ScheduleRiskAnalysis    = '0 6 * * *'

# Per-engine parallelism (collection only; RA never shards).
# $global:SI_Bootstrap_ParallelismEndpoint        = 1
# $global:SI_Bootstrap_ParallelismIdentity        = 1
# $global:SI_Bootstrap_ParallelismAzure           = 1
# $global:SI_Bootstrap_ParallelismSchemaDiscovery = 1

# Deployment behaviour switches.
# $global:SI_Bootstrap_TriggerNowAfter    = $true
# $global:SI_Bootstrap_SkipImageBuild     = $true
# $global:SI_Bootstrap_UseManagedIdentity = $true
# $global:SI_Bootstrap_UseKEDA            = $true
# $global:SI_Bootstrap_KedaMaxReplicas    = 30

# RiskAnalysis-in-container knobs.
# $global:SI_RiskAnalysis_ReportTemplate     = 'RiskAnalysis_Summary_Bucket'
# $global:SI_RiskAnalysis_Mode               = 'Summary'
# $global:SI_RiskAnalysis_ExportContainer    = 'sistaging'
# $global:SI_RiskAnalysis_ExportPrefix       = 'risk-analysis'
# $global:SI_RiskAnalysis_SendToLogAnalytics = $true
# $global:SI_RiskAnalysis_BuildSummaryByAI   = $true


# ============================================================================
# 14. HOST MODE + RUNTIME FLAGS  --  VM vs Container vs serverless routing
# ============================================================================

# Asset-profiling HostMode: 'vm' = local Invoke-SIEngineRun.ps1, 'container' =
# az containerapp job start. Default 'vm'.
# $global:SI_HostMode = 'container'

# Storage auth mode for VM HostMode. $true = Az context (no shared key needed).
# Auto-set to $true by the Setup Wizard (v2.2.134+) since the wizard grants
# Storage Blob/Table/Queue Data Contributor on the SPN but not listKeys; the
# OAuth path uses those data-plane roles directly.
# $global:SI_UseStorageOAuth = $true

# Single-process mode (no parallel runspaces; easier debugging, slower).
# $global:SI_SingleProcess = $true

# Force every engine through the new (2026-Q1) RuleSet evaluator path.
# $global:SI_UseNewRuleEngine = $true

# Verbose engine logging (writes Properties.run.debug into every profile row).
# $global:SI_Verbose = $true

# RiskAnalysis -WhatIf mode: build the report but skip mail + LA ingest.
# $global:WhatIfMode = $true

# Internal: when $true, AutomationFramework long-name globals win (set by
# Initialize-PlatformAutomationFramework). Customer doesn't usually set this.
# $global:AutomationFramework = $true


# ============================================================================
# 15. LOGGING + RETENTION
# ============================================================================

# Disable launcher transcript writing entirely (lab/CI use only).
# $global:SI_DisableTranscript = $true

# Days to keep launcher transcripts before pruning. Default 30.
# $global:SI_LogRetentionDays = 30

# Subscription pattern exclude list (used by both Identity discovery + Setup).
# $global:SubscriptionNameExcludePatterns = @( '*Azure for Students*', '*Visual Studio*' )

# Diagnostic / dev-loop helpers.
# $global:TroubleshootingMode = $true     # extra Write-Host context in some helpers
