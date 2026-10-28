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
# Monitoring Metrics Publisher on the DCR RG + Storage Blob/Table/Queue Data
# Contributor on the staging account (storage is reached only with this identity).
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

# THE sign-in choice. Managed identity is the default for a new install: an Azure VM
# or an Azure Arc-enabled server uses its system-assigned identity; give a client id
# to use a user-assigned one. When SI_AuthMethod is NOT set, an existing install keeps
# what it has: a configured SPN stays the SPN.
# $global:SI_AuthMethod              = 'ManagedIdentity'   # ManagedIdentity | Certificate | Secret
# $global:SI_ManagedIdentityClientId = '<uami-client-id-guid>'

# Older managed-identity switch, still honoured (SI_AuthMethod is the one to use).
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

# REQUIRED for v2.2 collection engines: the storage account for the 'sistaging'
# container (per-asset shards, cache JSONs, schema diffs). It is reached only with the
# signed-in identity, which needs Storage Blob/Table/Queue Data Contributor on it.
$global:SI_StorageAccount = '<storage-account-name>'

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
# 3.  OUTPUT SINKS  --  Excel / JSON / LA / Mail / Blob upload
# ============================================================================

# Per-engine sinks: any subset of @('LA','JSON','Excel'). Default = all three.
# $global:SI_Sinks_Endpoint = @('LA','JSON','Excel')
# $global:SI_Sinks_Identity = @('LA','JSON','Excel')
# $global:SI_Sinks_Azure    = @('LA','JSON','Excel')
# $global:SI_Sinks_PublicIp = @('LA','JSON','Excel')

# --- Copy Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL) -- optional, off by default ---
# After each Risk Analysis run, copies its report rows (SI_RiskAnalysis_Detailed_CL; SI_RiskAnalysis_Summary_CL for the
# Summary report; the day's trend row in SI_Trend_CL) into your Log Analytics workspace, for your own workbooks, Sentinel or
# KQL. SecurityInsight itself does not need it: its pages read the results from its database. Adds ingestion cost.
# $global:SendToLogAnalytics = $false

# RiskAnalysis: write a JSON copy of the report next to the .xlsx. Default OFF (the shipped
# risk-analysis defaults set it); set $true when a downstream tool or the viewer needs it.
# $global:WriteJsonOutput = $true

# RiskAnalysis: blob/UNC upload after Excel/JSON write. Type auto-detected
# from prefix: 'https://...' = Azure Blob, '\\server\share' = UNC.
# Backup-then-overwrite: existing files renamed <name>.<ts>.<ext>.bak.
# $global:ExportDestination = 'https://<storacct>.blob.core.windows.net/<container>/'


# --- MAIL: how SecurityInsight sends every mail (MAIL-1) ---
# sharedMailbox (recommended): an Office 365 shared mailbox, through Microsoft Graph as SecurityInsight's own
#   identity; Mail.Send is granted in Exchange only, scoped to that mailbox (setup\Set-SIMail.ps1 sets it up).
# smtp: your own SMTP relay (the settings below). none: no mail. Not set: smtp when SmtpServer is set, else none.
# $global:SI_Mail_Mode = 'sharedMailbox'
# The shared mailbox SecurityInsight sends as (also the From address for smtp).
# $global:SI_Mail_From = 'securityinsight@yourdomain.com'
# A mailbox OUTSIDE the scope: SecurityInsight checks that it may NOT send as it before it sends anything.
# $global:SI_Mail_ProbeMailbox = 'admin@yourdomain.com'
# When no such mailbox can be tested: who confirmed the restriction (Test-ServicePrincipalAuthorization), and when.
# $global:SI_Mail_RestrictionAttestation = '<name>, <date>'
# Your own SMTP relay is kept by choice: the hint to move to a shared mailbox is no longer shown. Default $false.
# $global:SI_Mail_SmtpKept = $true
# --- SMTP (RiskAnalysis email delivery) ---
# Hosted relays REJECT mail when From != verified sender, so
# $SMTPFrom must be a verified-sender address -- NOT the relay login.
# $global:SendMail        = $true
# $global:MailTo          = @('soc@yourdomain.com')
# $global:SmtpServer      = '<smtp-host>'
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
# $global:SI_SignInBatchSize    = 200      # default 200 user ids per sign-in query batch
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

# EG node-label allowlist for Azure types (default = enumerated weekly).
# $global:SI_AzureEgTypeAllowlist = @('microsoft.keyvault/vaults','microsoft.storage/storageaccounts')

# EG node + edge label overrides (only when XDR schema is non-standard).
# $global:SI_AzureExposureGraph_ResourceLabels   = @('storageaccount','keyvault')
# $global:SI_AzureExposureGraph_IdentityLabels   = @('user','serviceprincipal')
# $global:SI_AzureExposureGraph_AccessEdgeLabels = @('has access to','can authenticate as')


# ============================================================================
# 7.  ENGINE: PUBLICIP  --  public-IP scanner (Shodan REST integration)
# ============================================================================
# Read by: launcher/publicip/* + engine/asset-profiling/Invoke-SIEngineRun.ps1 -Engine publicip
# (v2.2.348: publicip folded into the shared pipeline -- same engine entry as endpoint/identity/azure.)

# $global:SI_AssetLimit_PublicIp = 0
# $global:SI_ForceFullRun_PublicIp = $true
# (There is no AI step for public IPs: SI_EnableAI_publicip is ignored, with one warning, if set.)

# Shodan API key (required for the engine to do anything useful).
# $global:SHODAN_ApiKey = '<your-shodan-api-key>'
# $global:SI_Shodan_ApiKey = '<your-shodan-api-key>'    # canonical SI-prefixed alias

# Cache + spend guards.
# $global:SI_ShodanCacheAgeDays            = 7
# $global:SI_ShodanMonthlyCreditCap        = 4000
# $global:SI_Shodan_LookbackDays           = 30
# $global:SI_Shodan_FreshScanIntervalHours = 24
# $global:SI_Shodan_ForceFreshScan         = $true
# $global:SI_Shodan_TierMax                = 3     # default 3 = scan all tiers (T0-T3). Lower to 1 for T0/T1 only (Shodan cost control).
# $global:SI_Shodan_AssetLimit             = 0
# $global:SI_Shodan_ThrottleMs             = 1100  # 1 req/sec (Shodan free-tier rate)
# $global:SI_Shodan_TimeoutSec             = 30
# $global:SI_Shodan_ScanWaitMaxSec         = 600
# $global:SI_Shodan_ScanPollIntervalSec    = 30      # default 30 seconds between scan-status checks
# $global:SI_Shodan_PendingScansPath       = '<local file path>'   # default: a file in the solution's data folder
# $global:SI_Shodan_LastFreshScanPath      = '<local file path>'   # default: a file in the solution's data folder
# (SI_Shodan_TableName / SI_Shodan_DcrName are no longer read since 3.0.0: public IPs publish to SI_PublicIP_Profile_CL.
#  Override with SI_PublicIp_TableName / SI_PublicIp_DcrName if you must.)

# Customer-supplied extra targets (partner / supply-chain IPs to monitor).
# $global:SI_PublicIP_ExtraTargets = @('203.0.113.10','198.51.100.42')


# ============================================================================
# 8.  ENGINE: RISK-ANALYSIS  --  cross-CL hunting reports + Excel/AI summary
# ============================================================================
# Read by: launcher/risk-analysis/* + engine/risk-analysis/Invoke-RiskAnalysis.ps1

# Mode override (per-run). Mutually exclusive: Summary (tier-rolled-up) vs
# Detailed (one row per affected identity/device).
# $global:RiskAnalysis_Summary_Override  = $true
# $global:RiskAnalysis_Detailed_Override = $false

# Per-mode ReportTemplate override (every template is auto-bucketed for large estates).
# $global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary'
# $global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed'

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

# Adaptive bucketing (handles Defender's 30k-row query ceiling).
# $global:AutoBucketCount = $true     # probe 1->2->4->...->AutoBucketMax
# $global:AutoBucketMax   = 1024
# $global:AutoBucketCache = $true     # reuse last-known-good bucket count
# $global:ResetCache      = $true     # force fresh bucket probe
# Re-test of a suspicious split count: a count this many times the median of the other reports is re-tested ...
# $global:AutoBucketChallenger_MedianMultiplier = 10
# ... once at least this many reports have a count to compare with ...
# $global:AutoBucketChallenger_MinEntries       = 10
# ... and at most once in this many days after a run decided the count.
# $global:AutoBucketChallenger_ConfirmDays      = 7

# Graph reconnect / retry tuning.
# $global:GraphReconnectMaxAgeMinutes = 45
# $global:GraphQueryMaxRetries        = 4

# Run-mode + scope flags.
# $global:Summary  = $true            # community short-name (also set by launcher)
# $global:Detailed = $true
# $global:Scope          = @('PROD')  # or @('TEST')
# $global:DebugQueryHash = $true
# $global:ShowConfig     = $true
# $global:ReportTemplate = 'RiskAnalysis_Summary'
# $global:OverwriteXlsx  = $true


# ============================================================================
# 9.  ENGINE: PRIVILEGE-TIER-CLASSIFIER  --  builds tier-definitions JSON via AI
# ============================================================================
# Read by: launcher/privilege-tier-classifier/* + engine/privilege-tier-classifier/

# Master switch. $true (default) runs all 4 AI categories; $false short-circuits
# to the static built-in tier map.
# $global:SI_PrivilegeTierClassifier_RunAI = $false

# Days a catalog is kept while its inputs are unchanged. Each run collects the role
# definitions and permission catalogs (seconds) and skips the AI pass when they, the
# engine and the AI settings are the same as for the last complete catalog and that
# catalog is younger than this. 0 = rebuild on every run.
# $global:SI_PrivilegeTierClassifier_RefreshDays = 7


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
# $global:SI_SchemaCatalogTable = 'SI_SchemaCatalog'   # default

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

# Disabled accounts and devices, one setting per stage.
# Disabled = the account is disabled in its own directory (Entra accountEnabled = false, AD userAccountControl
# disabled) -- users, service principals / managed identities and computers alike; never inferred from inactivity.
# Read on every run: an account that is enabled again is included again everywhere. A stage that leaves disabled
# assets out logs how many, and their open findings, actions and tickets are kept (never resolved or closed). The
# later stages only see what collection kept, so the last four need SI_DisabledAssets_Collect on.
# $global:SI_DisabledAssets_Collect      = $true    # collected from the sources
# $global:SI_DisabledAssets_Correlate    = $true    # take part in CI correlation
# $global:SI_DisabledAssets_RiskAnalysis = $false   # reach the Risk Analysis reports
# $global:SI_DisabledAssets_StateActions = $false   # finding / vulnerability lifecycle, close-loop, tickets
# $global:SI_DisabledAssets_Connectors   = $false   # sent out by connectors and exports

# --- Optional copy of the provider records to Log Analytics ---
# The records live in the database (correlation and the CI build run in SQL only). 'records' also posts them to
# SI_Record_CL (+ SI_RecordRaw_CL for raw data) for Azure Monitor or workbooks -- a one-way copy; it costs ingestion.
# $global:SI_LaExport = 'off'   # 'off' (default)|'records'

# --- Copy findings per CI to Log Analytics (SI_Finding_CL) -- optional, off by default ---
# After each Risk Analysis Detailed run, copies the de-duplicated findings (one row per CI and finding) into your Log
# Analytics workspace, for your own workbooks, Sentinel or KQL. SecurityInsight itself does not need it: its pages read the
# findings from its database. On a large estate the copy can take hours and adds ingestion cost. Not the report rows
# (SendToLogAnalytics, SI_RiskAnalysis_Detailed_CL).
# $global:SI_RA_Findings = $false

# --- Data out: the workbooks and ServiceNow Import Set hand-offs written after each data sync ---
# Which outputs are written (ids from config\data-out.locked.json, comma separated); not set = the outputs on by default.
# $global:SI_DataOut_Outputs = ''   # e.g. 'excel-ci,excel-findings-detailed,servicenow-ci'
# The Import Set tables of the two ServiceNow outputs (an output without its table is not written, and says so).
# $global:SI_DataOut_ServiceNowCiTable   = ''
# $global:SI_DataOut_ServiceNowVulnTable = ''   # the vulnerable item output's Import Set table (not set = that output is not written, and says so)
# The staging status table: one row when a push of an output starts (writing) and one when it ends (complete, failed or
# held), so your ServiceNow importer knows when a batch is complete. Every data row carries the batch id (u_si_batch_id).
# Not set = u_si_staging_status. '' = no staging status table: the rows are sent without it, with a warning.
# $global:SI_DataOut_ServiceNowStagingStatusTable = 'u_si_staging_status'
# A one-time request for the ServiceNow outputs, carried out on the next sync: 'resync:<token>' sends every record in scope again
# as new (one batch, mode resync); 'test:<token>' first sends at most 5 rows per output as a test batch the importer never imports.
# A token is carried out once. Set from Connectors > ServiceNow: one route.
# $global:SI_DataOut_ServiceNowRequest = ''

# --- Pro database: how long the CI history is kept (days; removed after each data sync) ---
# $global:SI_Pro_CiChangeRetentionDays     = 730   # each CI's change history
# $global:SI_Pro_CiDailyRetentionDays      = 400   # each CI's daily trend
# $global:SI_Pro_FindingStateRetentionDays = 365   # closed findings' lifecycle rows (open ones are never removed)

# --- Findings per CI: the days a finding has to be fixed, per severity (its due date; 0 = no due date) ---
# $global:SI_Pro_FindingSla_CriticalDays = 15
# $global:SI_Pro_FindingSla_HighDays     = 30    # the days a high finding has to be fixed (0 = no due date)
# $global:SI_Pro_FindingSla_MediumDays   = 90    # the days a medium finding has to be fixed (0 = no due date)
# $global:SI_Pro_FindingSla_LowDays      = 180   # the days a low finding has to be fixed (0 = no due date)

# --- ServiceNow CMDB connector (the asset-cmdb job) and the asset correlation ---
# $global:SI_Cmdb_Run         = 'plan'         # 'plan' (default: nothing written) | 'apply' (writes to ServiceNow)
# $global:SI_Cmdb_Mode        = 'match-only'   # 'match-only' | 'create-if-unmatched'
# $global:SI_Cmdb_AllowCreate = $false         # the second switch before a CI is created
# $global:SI_Cmdb_RowLimit    = 0              # 0 = every asset; a number = only that many (testing)
# $global:SI_Correlation_DryRun   = $false     # compute and report, publish nothing
# $global:SI_Correlation_RowLimit = 0          # 0 = every asset (troubleshooting only)
# Vulnerability connectors: 'plan' keeps every connector in plan mode whatever its own mode; not set = each connector's mode.
# $global:SI_VulnSync_Run = 'plan'


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
# Sign-in of the jobs: a managed identity by default. A client secret only when chosen (a supported choice):
# $global:SI_Bootstrap_UseClientSecret    = $true
# $global:SI_Bootstrap_UseKEDA            = $true
# $global:SI_Bootstrap_KedaMaxReplicas    = 30
# Risk Analysis Detailed reports on queue workers, several reports at once: ON by default wherever queue scaling and the
# managed identity let them run (setup and every update give them). $false switches them off: the reports run one after
# another in the Risk Analysis job. RaMaxWorkers = how many workers run at once (default 4).
# $global:SI_Bootstrap_RaScaleOut         = $true
# $global:SI_Bootstrap_RaMaxWorkers       = 4

# Sizes (Pro). Empty = the product's size, which setup and every update give: the web app 2 CPU / 4 GiB, the Pro database
# Standard S3. A size set here is kept by every update, also when it is SMALLER: the web app's CPU (0.5 to 4 in steps of
# 0.25; memory is 2 x CPU unless WebAppMemory says it), and the Pro database's service objective (S1, S2, S3, S4, S6, S7,
# S9, S12 -- never below S1). Support sets them per install in the Pro database (Settings page, setup\Set-SIProSetting.ps1).
# $global:SI_Bootstrap_WebAppCpu           = ''
# $global:SI_Bootstrap_WebAppMemory        = ''
# $global:SI_Bootstrap_SqlServiceObjective = ''

# Asset tagging (Community edition and Pro): its job runs under its OWN identity, never the read-only collection identity, after the profilers.
# Its write grants (Defender machine tags, Tag Contributor, Entra custom security attributes) are given only when
# GrantTaggingRoles is on; TaggingScopes is where Azure tags may be written (default: the collection scope).
# $global:SI_Bootstrap_ScheduleAssetTagging = '50 5 * * *'
# $global:SI_Bootstrap_TaggingIdentityName  = 'uami-securityinsight-tagging'   # asset tagging's own identity (never the collection one)
# $global:SI_Bootstrap_TaggingScopes        = @('/subscriptions/<id>')          # where Azure tags may be written (Tag Contributor)
# $global:SI_Bootstrap_GrantTaggingRoles    = $false                            # grant asset tagging's write permissions (opt-in)

# RiskAnalysis-in-container knobs.
# $global:SI_RiskAnalysis_ReportTemplate     = 'RiskAnalysis_Summary'
# $global:SI_RiskAnalysis_Mode               = 'Summary'
# $global:SI_RiskAnalysis_ExportContainer    = 'sistaging'
# $global:SI_RiskAnalysis_ExportPrefix       = 'risk-analysis'
# $global:SI_RiskAnalysis_SendToLogAnalytics = $true
# $global:SI_RiskAnalysis_BuildSummaryByAI   = $true

# The daily pipeline (Collect -> Correlate -> Deliver): when a NEW install's pipeline starts -- a time of day in its own
# time zone, the same local time all year (summer time included). A pipeline already stored (Operations > Jobs, or
# config\job-flow.custom.json) keeps its own time. The guided installer asks for the time zone.
# $global:SI_Pipeline_StartTime = '19:00'               # HH:mm, local time in SI_Pipeline_TimeZone
# $global:SI_Pipeline_TimeZone  = 'Europe/Copenhagen'   # an IANA id (Europe/Oslo, America/New_York) or a Windows id; unknown = UTC
# Risk Analysis writes the day's risk trend row itself at the end of a summary run (the trend job is then not needed).
# $global:SI_Trend_AtEndOfRiskAnalysis = $true
# The CI build (correlation) rebuilds only the CIs whose records, link states, time thresholds, identity anchors or manual
# overrides changed since their last build; every CI is rebuilt (a full reconcile) when the last full build is this many
# days old, when the data model, rules, mappings or CMDB change, and after a build that failed. 0 = a full build every run.
# $global:SI_CiBuild_FullReconcileDays = 7
# The seconds the rules of ONE asset may take in the CI build. An asset that takes longer is not fully evaluated in that
# run: it keeps what it had from its last complete evaluation (a new asset is left out), is named in the run log and is
# evaluated again in the next run -- one asset never holds the build. 0 = no limit.
# $global:SI_CiRulesBudgetSeconds = 60


# ============================================================================
# 14. HOST MODE + RUNTIME FLAGS  --  VM vs Container vs serverless routing
# ============================================================================

# Single-process mode (no parallel runspaces; easier debugging, slower).
# $global:SI_SingleProcess = $true

# Verbose engine logging (writes Properties.run.debug into every profile row).
# $global:SI_Verbose = $true

# Dry run. Here, in the configuration, only asset tagging reads it (report only, no tag changed). Every other
# engine ignores it here and publishes as normal; start that one run with -WhatIfMode for a dry run instead.
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

# Diagnostic / dev-loop helpers.


# ============================================================================
# 16. SETTINGS THE CODE READS THAT THIS FILE NEVER LISTED  (added 2026-08-20)
# ============================================================================
# An audit of every $global:SI_* the engines actually read found 47 with no
# mention in any config file, sample, or doc. Several of them CHANGE WHAT THE
# REPORTS SAY, so their absence here was the difference between a tunable and a
# hidden constant. Defaults below are transcribed from the code, not intended.
#
# Read by: engine/risk-analysis/*, engine/asset-profiling/stages/*.
# Every line stays COMMENTED OUT -- uncomment only what you intend to change.

# --- Risk scoring: domain weights (RA) -------------------------------------
# Relative weight of each domain in the cross-domain risk score. Defaults sum
# to 1.0. Raising one domain lowers the others' relative influence.
# $global:SI_RiskReport_GlobalWeight_Endpoint = 0.30
# $global:SI_RiskReport_GlobalWeight_Identity = 0.30
# $global:SI_RiskReport_GlobalWeight_Azure    = 0.20
# $global:SI_RiskReport_GlobalWeight_PublicIP = 0.20

# --- Risk scoring: severity weights (RA) -----------------------------------
# What each severity band contributes before tier multiplication.
# $global:SI_RiskReport_SeverityWeight_Critical = 10.0
# $global:SI_RiskReport_SeverityWeight_High     = 5.0
# $global:SI_RiskReport_SeverityWeight_Medium   = 2.0
# $global:SI_RiskReport_SeverityWeight_Low      = 1.0

# --- Risk scoring: tier multipliers (RA) -----------------------------------
# How much an asset's criticality tier amplifies its score. T0 = 4x a T2 asset.
# $global:SI_RiskReport_TierMultiplier_T0 = 4.0
# $global:SI_RiskReport_TierMultiplier_T1 = 2.0
# $global:SI_RiskReport_TierMultiplier_T2 = 1.0
# $global:SI_RiskReport_TierMultiplier_T3 = 0.5

# --- CVE report filters (RA) -----------------------------------------------
# All OFF by default -- every CVE is reported. Each one REMOVES findings.
# $global:SI_CVE_MinSeverity         = 'High'   # 'Critical'|'High'|'Medium'|$null
# $global:SI_CVE_MinCvssScore        = 7.0      # 0..10; 0 = off
# $global:SI_CVE_RequireExploit      = $true    # only CVEs with exploit signals
# $global:SI_CVE_MaxPublishedAgeDays = 365      # 0 = off

# --- Asset filters: these DROP ROWS from the output ------------------------
# The engine filters inactive/stale assets by default and reports how many it
# dropped. These change that decision.
# $global:SI_IncludeInactive_Endpoint  = $true   # keep inactive endpoints
# $global:SI_IncludeInactive_Identity  = $true   # also publish Microsoft apps granted nothing
# $global:SI_RequireMdeActive_Endpoint = $true   # TIGHTEN: MDE-active only
# $global:SI_RA_StaleDeviceFilter      = 'strict'  # 'off' (default)|'lenient'|'strict'

# --- Retries and query bucketing (RA) --------------------------------------
# $global:SI_LAQueryMaxRetries      = 3   # Log Analytics query retries
# $global:SI_BucketTransientRetries = 3   # retry a bucket on a transient error
# $global:SI_BucketOverflowRetries  = 1   # 1 = split a too-large slice at once
# $global:SI_AutoBucketSubFanOut    = 4   # sub-buckets created per split
# The most parts of one Risk Analysis report asked from Defender at a time (the next parts' answers are on their way
# while a part is processed). Adapts by itself: starts at 2, more while Defender answers quickly, fewer when it asks to
# slow down. 1 = one part at a time.
# $global:SI_RA_PartsInParallel_Max = 6

# --- AI executive summary (RA) ---------------------------------------------
# HOW THE SUMMARY AND DETAILED REPORTS RELATE TO EACH OTHER.
#
# The two reports count different things and always will: Summary counts distinct
# ASSETS, Detailed counts individual ASSET FINDINGS (one asset can carry many). The
# same estate therefore produces different totals and percentages in the two
# reports. What you choose here is whether the two reports are made to AGREE, or
# whether each simply reports its own grain. Either way both mails now carry a line
# under the KPI explaining why the figures differ.
#
#   'Consistent' (Community default) -- the leading report builds the AI
#                             narrative, the headline Risk Score KPI and the Top-50
#                             list, and the other report REUSES them verbatim, so
#                             both mails show identical figures. Choose this where
#                             management receives BOTH reports.
#   'PerReport' (Pro default) -- each report computes and shows its own numbers and
#                             never adopts the other's. Choose this where
#                             management receives ONE report, or where each report
#                             should be true to its own grain.
#
# Leave unset for the edition's default: 'Consistent' in Community -- what every
# install did before this setting existed, so upgrading changes nothing -- and
# 'PerReport' in SecurityInsight Pro, where the web app shows Summary and Detailed
# side by side. A value you set here wins in both editions.
# $global:SI_AISummary_Mode         = 'Consistent'   # or 'PerReport'
#
# WHICH REPORT IS THE SOURCE OF TRUTH in 'Consistent' mode. The leader always
# builds its own figures and never adopts anyone else's; the other report adopts
# the leader's. Default 'Summary', because that is the grain an executive audience
# usually reads -- set 'Detailed' if your management receives the Detailed report
# instead and the relationship inverts cleanly.
#
# There is deliberately NO time window deciding who wins. An earlier design said
# "the first report of the cycle wins", but a cycle cannot be identified from a
# clock: your two runs may legitimately fall on different UTC days (Summary late
# evening, Detailed early morning), and a long run can straddle midnight by itself.
# Naming a leader removes the question entirely -- the pairing survives any
# schedule, timezone or run duration, and the follower's figures can never appear
# in the leader's mail.
# $global:SI_AISummary_Leader       = 'Detailed'     # or 'Summary' (only with the Summary step switched on)
#
# How stale the leader's snapshot may be before the other report stops adopting it
# and builds its own instead. A BACKSTOP only -- it does not decide who leads. It
# exists so a snapshot left behind by a host that was offline for a week is not
# carried into today's mail. Ignored in 'PerReport' mode, which never adopts.
# $global:SI_AISummary_MaxAgeHours  = 24
# Where the shared Top-50 asset cache lives. Unused in 'PerReport' mode.
# $global:SI_RATop50_BlobContainer  = 'sistaging'
# $global:SI_RATop50_BlobName       = 'risk-analysis/RiskAnalysis_Top50_Shared.json'

# --- Delivery limits (added v2.2.441) --------------------------------------
# Excel holds 1,048,576 rows INCLUDING the header. Above this the workbook keeps
# the TOP N by the sort column (highest risk first) and says how many were left
# out; the .json sibling and the LA ingest still carry every row.
# $global:SI_ExcelMaxDataRows    = 1000000
# The Excel workbook of each Risk Analysis report, on or off: the summary workbook is written, the detailed one is not
# (every row is in the web app). Above the size a workbook holds the detailed workbook is not written even when on.
# $global:SI_RA_ExcelExport_Summary  = $true
# The detailed workbook is off by default: the detailed results can hold millions of rows, and every row is in the web app.
# $global:SI_RA_ExcelExport_Detailed = $false
# Mail attachment budget in MB of MESSAGE, measured base64-ENCODED (attachments
# inflate ~37%, so a 20 MB file is ~27 MB on the wire). Over budget, the report
# is sent WITHOUT the attachment rather than the relay rejecting the whole mail.
# $global:SI_MaxMailAttachmentMB = 24
# The schema-audit and tag-activity streams are always ingested in full. The old row caps
# (SI_SchemaAuditRowCap / SI_TagActivityRowCap) limit nothing; a run that still has one set says so once.

# --- Table / DCR name overrides --------------------------------------------
# Only set these if you renamed the destination objects. The engine resolves the
# shipped names when unset; there is no hard-coded fallback in this file.
# $global:SI_Endpoint_TableName = 'SI_Endpoint_Profile_CL'
# $global:SI_Identity_TableName = 'SI_Identity_Profile_CL'
# $global:SI_Azure_TableName    = 'SI_Azure_Profile_CL'
# $global:SI_Endpoint_DcrName   = 'dcr-si-endpoint'
# $global:SI_Identity_DcrName   = 'dcr-si-identity'
# $global:SI_Azure_DcrName      = 'dcr-si-azure'
# $global:SI_RiskAnalysis_DcrName_Summary  = 'dcr-si-risk-analysis-summary'
# $global:SI_RiskAnalysis_DcrName_Detailed = 'dcr-si-risk-analysis-detailed'

# --- Infrastructure + misc --------------------------------------------------
# Resource groups of the workspace and the storage account. Setup creates both there; a collection
# run creates no Azure resource and assigns no role -- it only checks that they are there.
# $global:SI_WorkspaceResourceGroup = 'rg-securityinsight'
# $global:SI_StorageResourceGroup   = 'rg-securityinsight'
# Fingerprint cache is OPT-IN (the gate is `-eq $true`); default is OFF.
# $global:SI_FingerprintCache_Enabled = $true
# Enable the ServiceNow CMDB source in the Reconcile stage.
# $global:SI_EnableServiceNowCmdb = $true
# Simulation only -- forces a synthetic CL row count for scale testing.
# $global:SI_SimulateCLRowCount = 15000

# ============================================================================
# 17.  SETTINGS NEW IN 3.0  --  and ones the code read that no config file listed
# ============================================================================

# --- Key Vault + licence -----------------------------------------------------
# The ONE Key Vault SecurityInsight reads secrets from (the SPN secret, integration credentials, a Pro licence).
# Setup writes it. $global:SpnKeyVaultName is still accepted on installs that predate this name.
# $global:SI_KeyVaultName = '<your-keyvault-name>'
# Key Vault reads by a user-assigned managed identity (default: the machine's system identity / the SPN).
# $global:SI_KvMiClientId = '<uami-client-id>'
# SecurityInsight Pro: the licence is read from the Key Vault secret 'SI-License' (setup\Set-SILicense.ps1 installs
# it). Without one the install runs the Community edition -- complete on its own; Pro components print one line.
# The Pro updater job asks Invardia for the licence itself, and renews it before it ends (setup\Request-SILicense.ps1
# does the same by hand). Where Invardia's licence service is (https only; default https://invardia.com).
# $global:SI_LicenseRequest_BaseUrl = 'https://invardia.com'
# Who Invardia may contact about a licence request. Sent only when set.
# $global:SI_LicenseRequest_ContactEmail = 'secops@contoso.com'
# The edition asked for in a licence request (optional; Invardia's owner decides). Sent only when set.
# $global:SI_LicenseRequest_Edition = 'pro'
# SecurityInsight Pro: the updater job asks Invardia for the licence by itself every night when there is none, it ends
# within 30 days or it is in its grace period, installs it and mails the result. On by default; $false never asks.
# $global:SI_LicenseRequest_Auto = $true
# SecurityInsight Pro: the updater job checks Invardia every night for a release approved for this install's ring and
# applies it (signed, verified, restored on failure). On by default; $false never checks or applies anything.
# $global:SI_InvardiaUpdate_Enabled = $true
# SecurityInsight Pro: template packs (new Microsoft content and template updates between releases) wait on Template
# releases for a manual Install instead of being installed automatically by the updater job. Off by default.
# $global:SI_InvardiaUpdate_HoldMicrosoftContent = $false
# SecurityInsight Pro: this install's update ring (0 dev, 1 internal, 2 early release, 3 broad), recorded with the
# install so the web app shows it before the updater has run. Not set = the ring in the resource-group name.
# $global:SI_UpdateRing = 3
# SecurityInsight Pro: the update gives this install's directory objects the names a new install gets -- the engine's
# application "SecurityInsight Engine", the web app's sign-in application "SecurityInsight", the SQL admin group shown as
# "SecurityInsight SQL admins" -- only from SecurityInsight's earlier names (a name you chose is kept), each once, read back
# and put back if it does not take. On by default; $false leaves the names as they are (the update only says what it would do).
# $global:SI_Update_RenameDisplayNames = $true

# ---- Status reports to Invardia (telemetry) -----------------------------------
# One status report a day and one short report per engine run (which engine, ok / warning / failed, how long, the
# stage and the kind of error). Community: anonymous -- a random install id, no tenant, no host name, no error text,
# counts only as ranges. Pro: identified by the install key, with the error text shortened and secrets removed.
# On by default; $false sends nothing at all.
# $global:SI_Telemetry_Enabled = $true
# Which controls the daily setup report to Invardia carries (Pro, with an install key): 'all' (default) = the framework's
# minimum control list and SecurityInsight's own controls (when Invardia does not take that report, it goes again once
# with only the minimum list); 'minimum' = only the framework's minimum list; 'off' = no setup report.
# $global:SI_Telemetry_SetupControls = 'all'   # 'all' (default)|'minimum'|'off'
# Whether the daily status report (Pro, with an install key) carries this install's own links -- the web app's and the
# MCP server's addresses -- so Invardia's mails about this environment can open it. On by default; switch it off to
# send no links.
# $global:SI_Telemetry_SendEndpoints = $true
# Where the reports go (https only). Default: Invardia's report address.
# $global:SI_Telemetry_Endpoint = 'https://invardia.com/api/uplink/v1/report'

# ---- Guard mails ------------------------------------------------------------------
# When SecurityInsight holds, refuses or stops a step to protect your data (for example the vulnerability connector
# refusing to close far more records than usual), it mails the people below -- at most once a day per guard while it
# keeps happening. On by default.
# $global:SI_GuardMail_Enabled = $true
# Who gets them. Default: the report recipients (MailTo), else the SecurityInsight Pro SuperAdmins.
# $global:SI_GuardMail_To = @('secops@contoso.com')

# ---- Data-quality warnings (Pro, #577) -------------------------------------------------------------
# Every pipeline run stores its key numbers (assets per source, rows per Risk Analysis report, fill of the key columns,
# CIs per tier, active CIs, CIs to retire) and compares each with the median of the last 3 runs. A number off its range
# is shown on the Data quality panel and in the run health -- it never blocks anything. ONE mail a day, only when a
# number is off. On by default.
# $global:SI_Pro_DataQuality_Mail_Enabled = $true
# Who gets the data-quality mail. Default: the safety-check mail recipients (SI_GuardMail_To), else MailTo, else the SuperAdmins.
# $global:SI_Pro_DataQuality_Mail_To = @('secops@contoso.com')
# Assets (per source, active CIs): warn when down this many percent or more from the median of the last 3 runs.
# $global:SI_Pro_DataQuality_AssetDropPercent = 30
# A Risk Analysis report: warn when it has 0 rows, or is down this many percent or more.
# $global:SI_Pro_DataQuality_ReportDropPercent = 50
# A key column's fill (risk factors, tier, owner, asset type, SQL tag): warn when down this many percentage points or more.
# $global:SI_Pro_DataQuality_FillDropPoints = 30
# A tier: warn when it moved by this share of all active CIs or more (up or down); also CIs to retire rising by it.
# $global:SI_Pro_DataQuality_TierShiftPercent = 20
# A source whose collection fails does not stop the run: the calculation goes on with that source's last good collection,
# and every run says how old it is. When a source has had no good collection for this many days or more, delivery waits
# (no mail, no ticket change) until it collects again; the calculation still goes on. 0 = delivery never waits for a source.
# $global:SI_Pro_SourceDropout_HoldDeliveryDays = 7
# DATA HEALTH (Pro): every day a random 10% of each source's records are looked up in the newest collection, and a random 10%
# of the devices with vulnerability findings are asked again from Defender. Read-only. Three anomalous days in a row make the
# data Unhealthy (nothing is sent out until one good day, or a SuperAdmin lets one channel through); one good day, Healthy.
# $global:SI_DataHealth_Enabled = $true
# Margins: how many of the checked records may differ, in percent of those checked, per source (never fewer than the minimum).
# $global:SI_DataHealth_Margin_EntraUsers = 1
# Data health margin, Entra apps and service principals: percent of those checked that may differ.
# $global:SI_DataHealth_Margin_EntraApps = 1
# Data health margin, Defender devices: percent of those checked that may differ.
# $global:SI_DataHealth_Margin_Devices = 2
# Data health margin, Azure resources: percent of those checked that may differ.
# $global:SI_DataHealth_Margin_Azure = 3
# Data health margin, Defender for Cloud recommendations: percent of those checked that may differ.
# $global:SI_DataHealth_Margin_DefenderForCloud = 5
# Data health margin, vulnerabilities: percent of Defender's vulnerabilities of the checked devices that may be missing.
# $global:SI_DataHealth_Margin_Vulnerabilities = 5
# Data health margin, each Risk Analysis report: percent of the checked findings that may differ from Defender.
# $global:SI_DataHealth_Margin_RiskAnalysis = 3
# Data health margins: the fewest differences any margin allows, whatever its percent.
# $global:SI_DataHealth_MarginMinimum = 5
# Send the daily data health result (counts only) to Invardia. On by default; switched off, nothing about data health is sent.
# $global:SI_Telemetry_SendHealth = $true
# One failed step does not cost the rest of the run: when the correlation or Risk Analysis fails after the collections
# completed, the data sync and the verification still run on what is stored, so the web app shows what was collected.
# Nothing is closed, no ticket is changed and no mail is sent from such a run, and it is marked as not complete.
# $false = every step after a failed one waits for the next good run, as before.
# $global:SI_Pro_Pipeline_GoOnAfterFailedStep = $true
# Every page shows ONE run: the last run that completed in full. A run in which a report could not be completed and fell
# back to its last complete result is not shown either, and the pages keep the last complete run. $true = show such a run,
# marked "a part of this run is from an earlier result".
# $global:SI_Pro_PublishPartialRun = $false
# A new install's first collection: a step that fails or is stopped is started again at once -- it carries on from what
# it finished -- this many times. After that the run ends with a warning that names the step and who must act. Only the
# steps that collect, correlate and load the web app are started again; never a step that writes to a CMDB, to
# ServiceNow or to a ticket, and never after the first complete collection. 0 = a failed step is not started again.
# $global:SI_Pro_Pipeline_FirstRunRestarts = 2
# A collection that COMPLETES with far fewer assets than the last good one (down by SI_Pro_DataQuality_AssetDropPercent
# or more): confirm = keep the last good collection and accept the drop by itself when the next complete collection
# shows the same level (a real clean-up costs one run); accept = take it as it comes, the safety check only reports.
# $global:SI_Pro_SourceDropout_AssetDropAction = 'confirm'
# REMOVE-ME once it has run everywhere: the one-time repair of finding lifecycle rows left open or mislabelled before the
# empty-CI-id fix. off = nothing (the default); count = read only, the data sync's log says how many rows it would change
# and what they would become; apply = once, after a complete collection: an empty CI id becomes none, and a finding still
# open under an old asset key that the newest collection reports open under its CI closes as rekeyed. Nothing is deleted.
# $global:SI_Pro_LifecycleStaleOpenRepair = 'off'

# ---- Guard switches (#414) --------------------------------------------------------------------------
# Every safety check can be turned on or off, and its mail turned off (Pro: Settings > Guards). Since the guard relief
# (2026-10-11) only the two brakes are ON by default: CIs retired by mistake (cmdb.sql.collapse, cmdb.handoff.mass-change)
# and duplicate vulnerability records (vuln.connector.target-incomplete); every other check is OFF until you switch it on
# (the examples below show the switch, not the default -- the glossary at the end says each default).
# Off = the check does not hold, refuse or stop: it says so once in the job log and the step goes on (config\guard-catalog
# .locked.json 'whenOff' says what that means per check). WARNING: SecurityInsight then acts on data that may be broken.
# All checks at once:
# $global:SI_Guards_Enabled = $true
# The vulnerability close limit: the share of the open records (default 10), an optional number (default 0 = no number
# limit -- a patch round closes hundreds), and the share that must still be reported (0 to 1, default 0.5).
# $global:SI_VulnSync_MaxClosePercent = 10
# The number limit: 0 = none (the default for vulnerabilities).
# $global:SI_VulnSync_MaxCloseAbsolute = 0
# The share of the open records that must still be reported (0 to 1).
# $global:SI_VulnSync_CollapseFloor = 0.5
# Vulnerability close limit (vuln.connector.close-ceiling). Off: the step goes on as if the check had not tripped -- the vulnerability connector closes every record the run would close, however many; nothing is held for release.
# $global:SI_Guard_VulnConnectorCloseCeiling_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorCloseCeiling_Mail = $true
# Vulnerabilities: empty result (vuln.connector.empty-snapshot). Off: the step goes on as if the check had not tripped -- an EMPTY result closes the open records it no longer reports, so a failed collection can close every open vulnerability.
# $global:SI_Guard_VulnConnectorEmptySnapshot_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorEmptySnapshot_Mail = $true
# Vulnerabilities: result far smaller than usual (vuln.connector.collapse). Off: the step goes on as if the check had not tripped -- a result that lost most of its findings closes the records it no longer reports.
# $global:SI_Guard_VulnConnectorCollapse_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorCollapse_Mail = $true
# Vulnerabilities: scope changed (vuln.connector.scope-changed). Off: the step goes on as if the check had not tripped -- records that dropped out of the collection scope are closed like any other absent record.
# $global:SI_Guard_VulnConnectorScopeChanged_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorScopeChanged_Mail = $true
# Vulnerabilities: Risk Analysis run not finished (vuln.connector.run-incomplete). Off: the step goes on as if the check had not tripped -- records are closed even when the Risk Analysis run behind the results did not finish cleanly.
# $global:SI_Guard_VulnConnectorRunIncomplete_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorRunIncomplete_Mail = $true
# Vulnerabilities: results not known to be complete (vuln.connector.snapshot-incomplete). Off: the step goes on as if the check had not tripped -- absences are counted and records closed even when the newest results are not known to be complete.
# $global:SI_Guard_VulnConnectorSnapshotIncomplete_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorSnapshotIncomplete_Mail = $true
# Vulnerabilities: target not read in full (vuln.connector.target-incomplete). Off: no event and no mail. The step itself still stops, because writing after a partial read of the target would open every record the read missed again as a duplicate.
# $global:SI_Guard_VulnConnectorTargetIncomplete_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorTargetIncomplete_Mail = $true
# Vulnerabilities: connector not set up (vuln.connector.refused). Off: no event and no mail. The step itself still stops, because the connector is not set up completely and cannot run.
# $global:SI_Guard_VulnConnectorRefused_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_VulnConnectorRefused_Mail = $true
# CMDB table: asset collection not complete (cmdb.sql.snapshot-incomplete). Off: no event and no mail. The step itself still stops, because a CI is never written from an asset collection that is not complete.
# $global:SI_Guard_CmdbSqlSnapshotIncomplete_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbSqlSnapshotIncomplete_Mail = $true
# CMDB table: far fewer assets than usual (cmdb.sql.collapse). Off: the step goes on as if the check had not tripped -- CIs are retired even when SecurityInsight sees far fewer assets than are active in the CMDB table.
# $global:SI_Guard_CmdbSqlCollapse_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbSqlCollapse_Mail = $true
# CMDB table: empty asset collection (cmdb.sql.empty-snapshot). Off: the step goes on as if the check had not tripped -- an empty asset collection is written too, which can retire every CI.
# $global:SI_Guard_CmdbSqlEmptySnapshot_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbSqlEmptySnapshot_Mail = $true
# CMDB table: no correlation results (cmdb.sql.no-correlation-map). Off: no event and no mail. The step itself still stops, because without the correlation results no asset can be matched to its CI.
# $global:SI_Guard_CmdbSqlNoCorrelationMap_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbSqlNoCorrelationMap_Mail = $true
# CMDB table: changed by another run (cmdb.sql.stale). Off: no event and no mail. The step itself still stops, because another run changed the CMDB table meanwhile; the next run plans again.
# $global:SI_Guard_CmdbSqlStale_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbSqlStale_Mail = $true
# CMDB hand-off: large change (cmdb.handoff.mass-change). Off: the step goes on as if the check had not tripped -- the batch is handed over to ServiceNow however many CIs changed or disappeared.
# $global:SI_Guard_CmdbHandoffMassChange_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbHandoffMassChange_Mail = $true
# ServiceNow: not reachable (cmdb.servicenow.unreachable). Off: no event and no mail. The step itself still stops, because ServiceNow cannot be reached.
# $global:SI_Guard_CmdbServicenowUnreachable_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbServicenowUnreachable_Mail = $true
# ServiceNow: create and match rules (cmdb.servicenow.create-gate). Off: no event and no mail. The step itself still stops, because those assets do not meet the connector's create and match rules (set in the connector).
# $global:SI_Guard_CmdbServicenowCreateGate_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbServicenowCreateGate_Mail = $true
# ServiceNow: service model errors (cmdb.servicenow.service-model). Off: no event and no mail. The step itself still stops, because the service model has errors.
# $global:SI_Guard_CmdbServicenowServiceModel_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CmdbServicenowServiceModel_Mail = $true
# Asset metadata: large change (asset.properties.collection-change). Off: the step goes on as if the check had not tripped -- a large change of the asset metadata is handed over like any other.
# $global:SI_Guard_AssetPropertiesCollectionChange_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_AssetPropertiesCollectionChange_Mail = $true
# Collection: far fewer assets from one source (collection.source.asset-drop). Off: a collection with far fewer assets is taken as it comes -- the assets the source no longer lists are marked not seen at once, and their CIs retire after the usual days.
# $global:SI_Guard_CollectionSourceAssetDrop_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CollectionSourceAssetDrop_Mail = $true
# CI build started while another was running (ci.build.concurrent). Off: no event. The second CI build still waits for the first one, because two builds never write the CIs at the same time.
# $global:SI_Guard_CiBuildConcurrent_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_CiBuildConcurrent_Mail = $true
# Data sync: collection of an unfinished run (datasync.collection.held). Off: the step goes on as if the check had not tripped -- a collection whose Risk Analysis run did not finish completely is loaded anyway and MARKED PARTIAL in the web app.
# $global:SI_Guard_DatasyncCollectionHeld_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_DatasyncCollectionHeld_Mail = $true
# Data sync: rows without their key (datasync.collection.refused). Off: no event and no mail. The step itself still stops, because rows without their finding id or collection time cannot be placed in a day.
# $global:SI_Guard_DatasyncCollectionRefused_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_DatasyncCollectionRefused_Mail = $true
# Data sync: findings an asset kind filter cannot show (datasync.asset.kind-dropped). Off: no event and no mail when a loaded collection has findings of an asset kind that no asset of that kind carries; the findings are loaded as before.
# $global:SI_Guard_DatasyncAssetKindDropped_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_DatasyncAssetKindDropped_Mail = $true
# Data sync: collection not read in full (datasync.collection.short-read). Off: no event and no mail. The step itself still stops, because a collection that could not be read or written in full is not loaded.
# $global:SI_Guard_DatasyncCollectionShortRead_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_DatasyncCollectionShortRead_Mail = $true
# Risk Analysis: far fewer findings (ra.output.row-drop). Off: the step goes on as if the check had not tripped -- a report with far fewer findings than the previous run no longer makes the run partial (a failed query or a missing result still does).
# $global:SI_Guard_RaOutputRowDrop_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_RaOutputRowDrop_Mail = $true
# Risk Analysis: far more buckets than usual (ra.bucket.count-jump). Off: no event when a report needs far more buckets than usual; the run itself is unchanged.
# $global:SI_Guard_RaBucketCountJump_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_RaBucketCountJump_Mail = $true
# Risk Analysis: column emptied (ra.output.column-emptied). Off: no event and no mail when a report column lost its content; the report itself is unchanged.
# $global:SI_Guard_RaOutputColumnEmptied_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_RaOutputColumnEmptied_Mail = $true
# Log Analytics: rows not accepted (ingest.rows.short-count). Off: no event and no mail. The step itself still stops, because the rows Log Analytics did not accept are not there.
# $global:SI_Guard_IngestRowsShortCount_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_IngestRowsShortCount_Mail = $true
# Database change that could remove data (schema.gate.refused). Off: no event and no mail. The step itself still stops, because a database change that could remove data is never applied automatically.
# $global:SI_Guard_SchemaGateRefused_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_SchemaGateRefused_Mail = $true
# Update: database update failed (update.schema.failed). Off: no event and no mail. The step itself still stops, because the database update failed.
# $global:SI_Guard_UpdateSchemaFailed_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_UpdateSchemaFailed_Mail = $true
# Licence not valid (licence.state.invalid). Off: no event and no mail. The step itself still stops, because the licence, not this switch, decides which Pro features run.
# $global:SI_Guard_LicenceStateInvalid_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_LicenceStateInvalid_Mail = $true
# Licence grace period (licence.state.grace). Off: no event and no mail during the licence grace period; everything keeps running.
# $global:SI_Guard_LicenceStateGrace_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_LicenceStateGrace_Mail = $true
# Audit trail retention setting (audit.retention.refused). Off: no event and no mail. The step itself still stops, because the retention setting is not valid.
# $global:SI_Guard_AuditRetentionRefused_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_AuditRetentionRefused_Mail = $true
# Bulk exemption limit (exemption.bulk.refused). Off: no event and no mail. The request itself is still refused, because a whole collection is never exempted in one go -- raise the limit instead (Settings > Exemptions: Most findings in one bulk exemption request, up to 2,000).
# $global:SI_Guard_ExemptionBulkRefused_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_ExemptionBulkRefused_Mail = $true
# Daily flow: start held for the previous run (flow.run.catch-up). Off: no event and no mail; the daily flow still waits for its previous run.
# $global:SI_Guard_FlowRunCatchUp_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_FlowRunCatchUp_Mail = $true
# Daily flow: jobs skipped (flow.step.skipped). Off: no event and no mail; jobs that need a failed job are still skipped.
# $global:SI_Guard_FlowStepSkipped_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_FlowStepSkipped_Mail = $true
# Daily flow: job did not start (flow.step.start-failed). Off: no event and no mail; a job that does not start is still not run.
# $global:SI_Guard_FlowStepStartFailed_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_FlowStepStartFailed_Mail = $true
# Daily flow: job interrupted (flow.step.interrupted). Off: no event and no mail; an interrupted job is still not started again.
# $global:SI_Guard_FlowStepInterrupted_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_FlowStepInterrupted_Mail = $true
# Job started while still running (job.execution.previous-running). Off: no event and no mail. The step itself still stops, because two runs of one job never run at the same time.
# $global:SI_Guard_JobExecutionPreviousRunning_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_JobExecutionPreviousRunning_Mail = $true
# Job stuck on throttling (job.run.throttled-stuck). Off: no event and no mail when a job is stuck on throttling. Throttled runs are still shown as throttled on the Jobs and Run health pages.
# $global:SI_Guard_JobRunThrottledStuck_Enabled = $true
# Its mail: off = the event is still shown on the Guards page, but not mailed.
# $global:SI_Guard_JobRunThrottledStuck_Mail = $true
# THROTTLE-IS-NORMAL: a run Microsoft only throttled is shown as throttled, is never mailed and runs again at its next
# scheduled time. The ONE alert ("stuck") goes out when a job has been throttled on every run for this many hours, or
# this many runs in a row -- whichever comes first, never on one run alone. The next run that completes clears it.
# $global:SI_Throttle_StuckHours = 6
# How many throttled runs in a row, without one that completes, send the one "stuck" alert (whichever comes first).
# $global:SI_Throttle_StuckRuns = 12

# --- azure engine: Defender for Cloud recommendations + CVEs -------------------
# Collected by default into their own table. Opt out, or rename the destination:
# $global:SI_CollectDefenderRecommendations = $false
# $global:SI_AzureRecommendation_TableName  = 'SI_AzureRecommendation'
# $global:SI_AzureRecommendation_DcrName    = 'dcr-si-azure-recommendation'
# Exposure Graph node types treated as NOT assets (extension resources). Default: role/policy assignments, locks,
# diagnostic settings.
# $global:SI_AzureEgNonAssetTypes = @('microsoft.authorization/roleassignments')

# --- identity engine ---------------------------------------------------------
# 3.0 includes identities whose sign-in history is unavailable. $true restores the 2.2 rule: a sign-in within
# SI_ActiveStaleDays is REQUIRED (fewer identities, and any without sign-in data are excluded).
# $global:SI_RequireRecentSignIn_Identity = $true

# --- profile payload ---------------------------------------------------------
# 'cmdb' (default) = every collected property; 'security' = only the schema-declared columns (default-deny, smaller).
# $global:SI_PayloadProfile = 'security'

# --- asset decisions (tier overrides, exceptions, exemptions) -----------------
# Default: config\asset-decisions.custom.yaml (copy the .sample.yaml next to it).
# $global:SI_AssetDecisionsPath = 'D:\SecurityInsight\asset-decisions.custom.yaml'

# --- public IP ---------------------------------------------------------------
# Destination overrides (defaults: SI_PublicIP_Profile_CL via dcr-si-publicip-profile).
# $global:SI_PublicIp_TableName = 'SI_PublicIP_Profile'
# $global:SI_PublicIp_DcrName   = 'dcr-si-publicip-profile'

# --- trend (asset-trend engine) ----------------------------------------------
# $global:SI_Trend_Grain   = 'Summary'   # 'Detailed' also rolls up per-asset rows
# $global:SI_Trend_Weeks   = 12          # weeks -ShowWeeklyRate looks back over
# $global:SI_Trend_DryRun  = $false
# $global:SI_Trend_DcrName = '<dcr-name>'

# --- risk analysis -----------------------------------------------------------
# Late retries of a bucket that failed transiently, after the main pass (default 3).
# $global:SI_BucketLateRetries = 3
# Default bucket count for the Detailed run before adaptive bucketing takes over (default 2).
# $global:SI_AutoBucketDefaultDetailed = 2
# Attempts for each AI call (default 4).
# $global:AI_MaxAttempts = 4
# Patch cycle: a finding whose fix was released (or, without one dated update, that was first detected) more than this many
# days before the collection is Catch-up, else In monthly cycle (default 30; exactly 30 is still in the cycle).
# $global:SI_PatchCycle_CatchUpDays = 30
# Patch cycle: read the release date of each Microsoft update (by its KB) from Microsoft's public Security Update Guide
# (https://api.msrc.microsoft.com, once a day, cached). Off: no call; the month the update's name says is used (default on).
# $global:SI_PatchCycle_MsrcDates = $true
# Send the report mail even when a run produced 0 rows (a heartbeat). Default: an empty report is not mailed.
# $global:RA_MailEvenIfEmpty = $true
# Tenant domain shown in the risk score links (default: the tenant id) and, with the tenant id, in the mail
# subjects (default: the tenant's onmicrosoft.com domain, read from Microsoft Graph).
# $global:SI_TenantDomain = 'contoso.com'
# Address ranges that are internet-facing by design (DMZ, online landing zones), as CIDRs or addresses: an asset with an
# address in them gets the 'Internet exposed' risk factor, whatever the providers say (added to the internet_exposed_ranges
# list of data-model\lists.locked.json; lists.custom.json works too). Default: none.
# $global:SI_InternetExposedRanges = @('203.0.113.0/24', '10.50.0.0/16')

# --- container hosting (written by setup; see Bootstrap-ContainerAppJob.ps1) ----
# Where the containers live -- setup saves these so every update can find them. An install made before 3.0.0
# records them once with: setup\Invoke-SIContainerUpdate.ps1 -ResourceGroupName <rg> -AcrName <acr> -Save
# $global:SI_Bootstrap_SubscriptionId    = '<subscription-id>'
# $global:SI_Bootstrap_ResourceGroupName = 'rg-securityinsight'
# $global:SI_Bootstrap_AcrName           = '<acr-name>'
# Every NON-SECRET setting in this file is passed to the container jobs automatically; secrets travel only as
# job secrets. Trend and (with Pro) the Pro engines get their own jobs; schedules can be changed with:
# $global:SI_Bootstrap_ScheduleTrend       = '0 9 * * *'   # LAST -- after Risk Analysis Detailed
# $global:SI_Bootstrap_ScheduleConfigBackup = '0 18 * * *'  # the daily configuration backup -- its own timer, outside the pipeline

# ============================================================================
# 18.  SECURITYINSIGHT PRO -- THE SQL DATA BACKEND (Pro only; kept in the Pro settings database)
# ============================================================================
# Days of run data the Pro database keeps (findings, assets, daily aggregates); older collections are purged. Default 90,
# at least 1. The vulnerability current state and the identity ledger are never purged.
# $global:SI_Pro_DataRetentionDays = 90
# The shipped named views hidden from the view picker of Security recommendations > Summary and Detailed, for everyone:
# critical-high, tier0, cve, exploited, mitre, compliance, cvss (summary:<view> / detailed:<view> = one page). Default none.
# $global:SI_Pro_HiddenViews = @()
# The protection score (the share of active assets in good standing, 0-100, higher is better; the Executive overview,
# report, management mail and wall board): the accepted lifecycle -- days a Very High / High finding may be open before it
# counts in the "within accepted lifecycle" view -- per asset type. Default 30 each; 0 = the view equals the technical one.
# $global:SI_ProtectionScore_GraceDays_Device = 30
# The protection score's accepted lifecycle for identities, in days (default 30).
# $global:SI_ProtectionScore_GraceDays_Identity = 30
# The protection score's accepted lifecycle for cloud resources (Azure), in days (default 30).
# $global:SI_ProtectionScore_GraceDays_CloudResource = 30
# The protection score's accepted lifecycle for public IP addresses, in days (default 30).
# $global:SI_ProtectionScore_GraceDays_PublicIp = 30
# (#860) The accepted lifecycle above is for PATCH findings only (a vulnerability with a vendor fix: a fix release date, a
# recommended update or a patch cycle). Every other finding -- configuration, identity, Azure, attack paths -- has its own
# grace per asset type, in days; default 0 = it counts as a risk from the day it is found.
# $global:SI_ProtectionScore_OtherGraceDays_Device = 0
# The protection score's grace for identity findings (not patches), in days (default 0).
# $global:SI_ProtectionScore_OtherGraceDays_Identity = 0
# The protection score's grace for findings on cloud resources (Azure) that are not patches, in days (default 0).
# $global:SI_ProtectionScore_OtherGraceDays_CloudResource = 0
# The protection score's grace for findings on public IPs that are not patches, in days (default 0).
# $global:SI_ProtectionScore_OtherGraceDays_PublicIp = 0
# The protection score's tier weights, Tier 0..3 (an unclassified asset weighs as Tier 3). Default '8,4,2,1'.
# $global:SI_ProtectionScore_TierWeights = '8,4,2,1'
# The severities that take an asset out of good standing. Default 'Very High,Critical,High'.
# $global:SI_ProtectionScore_Severities = 'Very High,Critical,High'
# The key figures' windows (the Executive overview, report and management mail; every window a figure counts over is a
# setting -- #859). "Vulnerabilities opened / fixed in the last N days", in days (default 30).
# $global:SI_KeyFigures_RecentDays = 30
# The key figures' mean time to fix is worked out over the vulnerabilities fixed in the last N days (default 90).
# $global:SI_KeyFigures_MeanTimeToFixDays = 90
# The key figures' "privileged accounts without a sign-in for N days", in days (default 90).
# $global:SI_KeyFigures_StaleAdminDays = 90
# The key figures' age bands of open CVE findings ("older than N days"), one band per number, comma-separated. Default '30,60,90'.
# $global:SI_KeyFigures_CveAgeBands = '30,60,90'
# Risk Analysis reads Defender's software vulnerabilities export once per run (Vulnerability.Read.All) for the first time each
# CVE was seen on each device (si_source_first_seen; the protection score's accepted-lifecycle view ages findings by it). on | off. Default on.
# $global:SI_RA_SourceFirstSeen = 'on'
# Months the Pro audit trail (cfg.AuditEvent: every action in the web app, the jobs and setup) keeps its rows. Not set =
# kept forever. At least 13; older rows are removed only by the data sync's retention step, which records itself.
# $global:SI_Pro_AuditRetentionMonths = 25
# Days the configuration backups are kept (the daily backup job and Back up now; Configuration > Backups (restore)). Default 90, at
# least 1. A pinned backup is kept until it is unpinned; removals are recorded on the audit trail.
# $global:SI_Pro_ConfigBackupRetentionDays = 90
# Days the change journal (every configuration change, record by record -- what undo and restore are built on) keeps its
# rows. Not set = kept forever (the default). Never shorter than the backup retention: a shorter value is refused and the
# journal is kept.
# $global:SI_Pro_ConfigJournalRetentionDays = 400
# Days of Log Analytics the data sync looks back for complete runs it has not copied yet.
# $global:SI_Pro_DataLookbackDays = 2
# DATABASE WRITE PACE: the large writers (Risk Analysis storing its findings, the data sync preparing the views, the removal
# of old collections) read how busy the database is before each batch. Above the high mark (the highest of log write, data
# reads and CPU, in percent of the tier) they pause and write smaller batches; below the low mark they go back to full pace.
# Nothing is left out -- only slower while the database is saturated. On by default; $false switches it off.
# $global:SI_SqlPacing_Enabled = $true
# The database load (percent) above which the writers slow down. Default 85.
# $global:SI_SqlPacing_HighPercent = 85
# The database load (percent) below which they go back to full pace. Default 70; must be below the high mark.
# $global:SI_SqlPacing_LowPercent = 70
# Asset properties, two levels. 'security' (the default) = what SecurityInsight needs for risk: the profilers read their
# sources exactly as always and nothing extra is stored. 'full' = each profiler reads each source ONCE with every
# property, builds the same security profile from it, and publishes the whole object (Defender, Entra, Intune, AD, Azure,
# Exposure Graph, VM extensions) to SI_AssetProperties_CL for the CMDB hand-off; (Pro) the data sync stores every
# snapshot for the web app's asset page, with its history.
# $global:SI_AssetProperties = 'security'
# Days the full asset metadata is kept -- in Log Analytics (the table's retention, set by the run; Log Analytics keeps a
# table at least 4 days, so a lower value is raised to 4) and in the Pro database (pruned by the data sync). Default 3.
# $global:SI_AssetProperties_RetentionDays = 3
# How much (in percent) the full asset metadata collected from one source may change from one run to the next before
# the run holds that source's hand-off and raises a guard event. Default 10.
# $global:SI_AssetProperties_ChangeGuardPercent = 10
# The SQL server the data sync writes to (default: SI_ProSqlServer, the Pro settings database's server).
# $global:SI_Pro_DataSqlServer = '<server>.database.windows.net'
# The SQL database the data sync writes to (default: SI_ProSqlDatabase).
# $global:SI_Pro_DataSqlDatabase = '<database>'
# Plan the data sync (what would be copied and purged) without writing to SQL.
# $global:SI_Pro_DataSync_DryRun = $false
# THE SQL CMDB CONNECTOR: writes every asset SecurityInsight knows (one row per asset, with its tier, department, owner,
# business services, identifiers and history) into the CI table of the Pro database (cmdbsync.ConfigurationItem, and the
# view cmdbsync.vConfigurationItem for Power BI). On by default when there is a Pro database; $false switches it off.
# $global:SI_Pro_CmdbSql_Enabled = $true
# How many complete runs in a row an asset must be missing before its CI is retired (kept, never deleted). Each new
# snapshot counts once; a run that reads the same snapshot again counts nothing. Default 2, at least 1.
# $global:SI_Pro_CmdbSql_RetireAfterRuns = 2
# The least number of days an asset must go unseen before its CI is retired (in the CI table and in the state handed to
# ServiceNow) -- a brake under every other rule (the grace period, the runs missing, an early retirement). Default 7, at least 1.
# $global:SI_Cmdb_RetireAfterDays = 7
# Which kinds of asset become CIs: 'endpoint' (devices), 'azure' (Azure resources) and, if you want them, 'publicip'.
# Identities are never written as CIs.
# $global:SI_Pro_CmdbSql_Kinds = @('endpoint', 'azure')
# An asset counts as present when its profile was published within this many days. Low tiers are re-profiled weekly,
# so keep it above the slowest tier's re-check interval. Default 8, at least 1.
# $global:SI_Pro_CmdbSql_SeenWithinDays = 8
# Plan the SQL CMDB connector (what it would create, update and retire) without writing to SQL.
# $global:SI_Pro_CmdbSql_DryRun = $false
# AN ASSET SECURITYINSIGHT NO LONGER SEES (#406): how many days an asset may go unseen before SecurityInsight retires it --
# its open vulnerabilities then close as AssetRetired (never as fixed), its CI is retired, and ServiceNow gets the state
# (u_si_state). Seen again = active again. Default for every category; each category below can override it. Default 30.
# $global:SI_Pro_AssetRetire_GraceDays = 30
# Grace period for client PCs: a device whose operating system is not a server (laptops, desktops). Empty = SI_Pro_AssetRetire_GraceDays.
# $global:SI_Pro_AssetRetire_GraceDays_ClientPc = 30
# Grace period for servers: a device with a server operating system, or an Arc-connected machine. Empty = SI_Pro_AssetRetire_GraceDays.
# $global:SI_Pro_AssetRetire_GraceDays_Server = 30
# Grace period for service principals: an Entra service principal or managed identity. Empty = SI_Pro_AssetRetire_GraceDays.
# $global:SI_Pro_AssetRetire_GraceDays_ServicePrincipal = 30
# Grace period for users: an Entra user account. Empty = SI_Pro_AssetRetire_GraceDays.
# $global:SI_Pro_AssetRetire_GraceDays_User = 30
# Grace period for Azure virtual machines: an Azure virtual machine or scale set, also when Defender reports it as a device. Empty = SI_Pro_AssetRetire_GraceDays.
# $global:SI_Pro_AssetRetire_GraceDays_AzureVm = 30
# Grace period for other Azure resources: any Azure resource that is not a virtual machine. Empty = SI_Pro_AssetRetire_GraceDays.
# $global:SI_Pro_AssetRetire_GraceDays_AzureResource = 30
# ASSET RESPONSIBILITY (departments): where the data sync looks, in order, to decide which department an asset belongs to.
# 'tags' = the platform tags named below (Azure resource tags, Defender device tags, Entra attributes); 'rules' = the
# department rules defined on the web app (asset name, group, CMDB service, kind). Leave one out to switch it off. Overrides
# set on the web app always win; an asset nothing matches goes to the default department, else Unassigned.
# $global:SI_Pro_Responsibility_Sources = @('tags', 'rules')
# The tag names that name a department, earliest first. A tag's value matches a department by its name or one of its
# "also matches" values (e.g. a cost centre number). Defender tags count as Name:Value or Name=Value.
# $global:SI_Pro_Responsibility_TagNames = @('Department', 'Owner', 'CostCenter')
# The department an asset goes to when no override, tag or rule places it. Empty = the Unassigned queue.
# $global:SI_Pro_Responsibility_DefaultDepartment = ''
# When an open vulnerability counts as OVERDUE in the business owners' monthly report: days since it was first seen, per severity.
# $global:SI_Pro_Responsibility_OverdueDays = @('Critical=15', 'High=30', 'Medium=90', 'Low=180')
# Send each department's business owners a monthly status mail (their assets and services, with a link to the department page).
# Off by default. Sent by the close-loop mail job through the same relay as the Risk Analysis mail.
# $global:SI_Pro_DepartmentReport_SendMail = $false
# The day of the month (1 to 28) from which the monthly report for the previous month is sent.
# $global:SI_Pro_DepartmentReport_DayOfMonth = 1
# GOVERNANCE (departments, phase 2): after each data sync, send each department's technical owners ONE digest of the findings
# that are new for the department. Off by default. Sent by the close-loop mail job through the same relay as the Risk Analysis mail.
# $global:SI_Pro_GovernanceNotify_SendMail = $false
# How the technical owners' digest lists the new findings: 'vulnerability' (one row per finding) or 'asset' (one row per asset).
# $global:SI_Pro_GovernanceNotify_Mode = 'vulnerability'
# The lowest severity the technical owners' digest announces: Critical, High, Medium or Low.
# $global:SI_Pro_GovernanceNotify_MinSeverity = 'High'
# Send each department's technical owners a monthly review (statuses, what is still seen after its window, what has no decision yet).
# Off by default. Sent by the close-loop mail job through the same relay as the Risk Analysis mail.
# $global:SI_Pro_TechnicalReview_SendMail = $false
# The day of the month (1 to 28) from which the technical owners' review of the previous month is sent.
# $global:SI_Pro_TechnicalReview_DayOfMonth = 1
# REMEDIATION FLOWS (departments, phase 3): let the daily mail job plan every finding without a status whose flow is "Auto in the
# maintenance window" for the department's next window. Off by default. It records a planned state; it never changes Defender,
# Intune, Entra or Azure.
# $global:SI_Pro_Remediation_AutoSchedule = $false
# FOLLOW-UP TASKS: once a day, send each person who has open tasks that are overdue, due soon or whose reminder day has come
# ONE digest of them, with a link to each task. Off by default. Sent by the close-loop mail job through the same relay as the
# Risk Analysis mail.
# $global:SI_Pro_TaskDigest_SendMail = $false
# How many days ahead the task digest counts an open task as due soon (0 to 60).
# $global:SI_Pro_TaskDigest_DueSoonDays = 7
#
# EXEMPTED FINDINGS: an approved exemption never removes a finding -- Risk Analysis keeps it, marked, in Log Analytics and the
# Pro database, and each report decides whether to count it. Count exempted findings in the management numbers: Risk
# Analysis's workbook, JSON, summary and mail, and the web app's dashboards, KPIs, trends, closure and Services view and the
# wall board. Off by default: exempted findings are left out, and every surface says how many.
# $global:SI_Exempted_CountInManagement = $false
# Count exempted findings in the department reports: the department pages, the business owners' monthly report and the
# technical owners' digest and review. Off by default: exempted findings are left out, and the report says how many.
# $global:SI_Exempted_InDepartmentReports = $false
# Asset tagging (#643). Off by default: the asset-tagging rules (e.g. Auto-CanBeOnboarded--Excluded--SI) set no tag anywhere --
# not on the CIs inside SecurityInsight, not in Defender, Azure or Entra -- and no report treats a device as excluded because
# of a tagging rule (a tag an earlier tagging run wrote is ignored). Your own exclusion tags keep working. On: the rules
# apply inside SecurityInsight; writing to your tenant is still the separate SI_Pro_AssetTagging_Apply / SI_AssetTagging_Apply.
# $global:SI_AssetTagging_Enabled = $false
# Let the asset-tagging job WRITE the tags its rules select (Defender machine tags, Azure resource tags, Entra custom security
# attributes). Off by default: the job then only reports what it would tag, and every planned tag is logged to the asset-tag
# activity table. Writing also needs the job's own identity to hold the write permissions (setup -GrantTaggingRoles).
# $global:SI_Pro_AssetTagging_Apply = $false
# How many complete runs in a row a vulnerability must be missing from an asset before the close-loop closes it as fixed.
# Each run only counts when the asset itself was seen in that run with its vulnerability data; a run in which the asset was
# not seen counts for nothing and keeps the vulnerability open. Default 2, at least 1. Raise it if devices report a
# vulnerability on and off.
# $global:SI_VulnSync_CloseAfterRuns = 2
#
# SERVICENOW -- ONE ROUTE (#914). SecurityInsight never writes ServiceNow configuration items or vulnerable items itself: it
# delivers to STAGING -- the hand-off database (SQL views ServiceNow imports through a JDBC data source) or the ServiceNow
# data-out connector (Import Set tables, the SI_DataOut_ServiceNow* settings above) -- and ServiceNow's own import / transform
# rules make every change. The older push and its settings (SI_ServiceNow_ImportSetTable, SI_ServiceNow_ImportSetMaxRows,
# SI_VulnSync_ServiceNowImportSetTable, SI_ServiceNow_DirectWrite, SI_VulnSync_ServiceNowDirectWrite) were removed.
# The vulnerability close-loop's DAILY MAIL (Pro; edited on the management GUI's e-mail settings page): the last 24 hours'
# opened, closed and reopened vulnerabilities by severity and asset tier, what is open now, and the mean time to fix, sent
# after the close-loop run through the same relay as the Risk Analysis mail. Off by default.
# $global:Mail_CloseLoop_Daily_SendMail = $false
# Who receives the close-loop daily mail.
# $global:Mail_CloseLoop_Daily_To = @('secops@yourdomain.com')
# The time of day (UTC, HH:mm) the daily mail job runs. Default 10:45, after the close-loop; a changed time takes effect
# when setup (Bootstrap-ContainerAppJob.ps1) is run again.
# $global:Mail_CloseLoop_Daily_SendTimeUtc = '10:45'

# >>> SETTINGS GLOSSARY -- generated by engine\pro-settings\Build-SISettingsCatalog.ps1; do not edit by hand >>>
# Every Community setting in plain words: what it is for, what applies when you do not set it, what changing it
# does, and when you would. Settings marked (advanced) are tuning and diagnostic knobs most installs never change.
# The SecurityInsight Pro Settings page shows the same text.
#
# ----------------------------------------------------------------------------------------------------
# Mail & notifications
# Who receives the report mails, when they are sent, and the mail server they go through.
# ----------------------------------------------------------------------------------------------------
#
# Default recipients  [MailTo]  (engine: risk-analysis)
#   What it is for:   The addresses that receive every Risk Analysis report that has no recipient list of its own.
#   Default:          Empty (no recipients)
#   If you change it: Reports go to these addresses unless a report-specific list exists. If mail is switched on and
#                     no recipient list is set anywhere, the run stops at start.
#   When to change:   Set it when one group should receive every Risk Analysis report.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it when one group should receive every Risk Analysis
#                     report.
#   More info:        https://invardia.com/docs/si/settings/MailTo/
#
# Detailed report recipients  [RiskAnalysis_Detailed_To]  (engine: risk-analysis)
#   What it is for:   The addresses that receive the Detailed Risk Analysis report.
#   Default:          Not set: the older name, else MailTo, is used
#   If you change it: Detailed reports go to these addresses instead of the default list. Blank entries are dropped
#                     with a warning. A report template's own recipients still win.
#   When to change:   Set it when the Detailed report should go to different people than the default list.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it when the Detailed report should go to different people
#                     than the default list.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_Detailed_To/
#
# Encrypted mail connection  [SMTP_UseSSL]  (engine: risk-analysis)
#   What it is for:   Whether report e-mails are sent to the mail server over an encrypted (SSL/TLS) connection.
#   Default:          Not set: Risk Analysis mail fails (run continues); the daily close-loop mail sends unencrypted
#   If you change it: On: the connection is encrypted, as most cloud relays require. Off: plain connection, typical
#                     for an internal relay on port 25. A mismatch with the server makes sending fail.
#   When to change:   Set it to match your mail server; setup asks for it.
#   Risk:             Report mails (with asset and finding details) travel unencrypted to the mail server: only
#                     acceptable on an internal relay. Reversible at once.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/SMTP_UseSSL/
#
# How mail is sent  [SI_Mail_Mode]
#   What it is for:   How SecurityInsight sends every mail: sharedMailbox = an Office 365 shared mailbox through
#                     Microsoft Graph as SecurityInsight's own identity (recommended); smtp = your own SMTP relay;
#                     none = no mail.
#   Choices:          'sharedMailbox' (Shared mailbox (Office 365) -- recommended); 'smtp' (SMTP relay (your own mail
#                     server)); 'none' (No mail)
#   Default:          Not set: your SMTP relay when a mail server is set, else no mail
#   If you change it: Every mail (reports, safety-check alerts, close-loop, exemption, governance and digest mails,
#                     licence notices) goes this way. With sharedMailbox SecurityInsight sends only once it has
#                     verified that Mail.Send is restricted to the shared mailbox.
#   When to change:   Set up with Settings > E-mail > Set up mail, or setup\Set-SIMail.ps1.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set up with Settings > E-mail > Set up mail, or
#                     setup\Set-SIMail.ps1.
#   More info:        https://invardia.com/docs/si/settings/SI_Mail_Mode/
#
# Largest mail attachment  [SI_MaxMailAttachmentMB]  (MB)
#   What it is for:   The largest Excel attachment, measured as encoded for mail, that a Risk Analysis mail carries;
#                     larger reports are mailed without the attachment.
#   Default:          24 MB (fits a 25 MB mail server limit)
#   If you change it: Raising it lets bigger workbooks be attached, but above your mail server's limit the whole mail
#                     is rejected and nothing arrives. Lowering it is always safe.
#   When to change:   Raise only if your mail server accepts larger messages; lower if mails are rejected.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Raise only if your mail server accepts larger messages; lower
#                     if mails are rejected.
#   More info:        https://invardia.com/docs/si/settings/SI_MaxMailAttachmentMB/
#
# Mail every report  [SendMail]  (engine: risk-analysis)
#   What it is for:   Mails each Risk Analysis report, unless a report's own switch says otherwise.
#   Default:          Off
#   If you change it: On: reports are mailed to MailTo (or the report-specific lists). The run stops at start if mail
#                     is on but no recipients or required mail server sign-in details are set.
#   When to change:   Turn on to mail every report; use the Summary/Detailed switches for finer control.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Turn on to mail every report; use the Summary/Detailed
#                     switches for finer control.
#   More info:        https://invardia.com/docs/si/settings/SendMail/
#
# Mail reports with no findings  [RA_MailEvenIfEmpty]
#   What it is for:   Sends the report mail even when a run found nothing, as a sign the job ran.
#   Default:          Off: a report with no rows is not mailed.
#   If you change it: When on, recipients get a mail after every run, including empty ones, confirming the job is
#                     alive. When off, an empty run sends nothing.
#   When to change:   Turn on if you want a daily confirmation mail even when there are no findings.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Turn on if you want a daily confirmation mail even when there
#                     are no findings.
#   More info:        https://invardia.com/docs/si/settings/RA_MailEvenIfEmpty/
#
# Mail sender address  [SMTPFrom]  (engine: risk-analysis)
#   What it is for:   The From address on every mail.
#   Default:          Falls back to MailFrom, then SMTPUser; with signed-in mail the run stops at start
#   If you change it: Sets who the mail appears to come from. A sender the relay has not verified gets the mail
#                     rejected. With no sender at all and anonymous mail, mail is skipped with a warning.
#   When to change:   Set it whenever mail is on; use an address your mail relay accepts as sender.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it whenever mail is on; use an address your mail relay
#                     accepts as sender.
#   More info:        https://invardia.com/docs/si/settings/SMTPFrom/
#
# Mail server  [SmtpServer]  (engine: risk-analysis)
#   What it is for:   Host name of the mail server (SMTP relay) every SecurityInsight mail is sent through.
#   Default:          Not set: no mail can be sent (reports are still written)
#   If you change it: All Risk Analysis and close-loop mail goes through this server. Without it, sending fails with
#                     an error but the run completes.
#   When to change:   Set it when you turn report mail on.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it when you turn report mail on.
#   More info:        https://invardia.com/docs/si/settings/SmtpServer/
#
# Mail server password  [SMTPPassword]  (engine: risk-analysis, secret)
#   What it is for:   Password (or app password) of the mail server account.
#   Default:          Not set: signed-in mail cannot start; containers read it from your Key Vault
#   If you change it: Needed whenever mail is sent with sign-in. Without it, a Risk Analysis run with mail on stops at
#                     start and the daily close-loop mail is not sent.
#   When to change:   Set it when you turn mail on with a relay that needs sign-in, and when the password changes.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Set it when you turn mail on with a relay that needs sign-in,
#                     and when the password changes.
#   More info:        https://invardia.com/docs/si/settings/SMTPPassword/
#
# Mail server port  [SMTPPort]  (engine: risk-analysis)
#   What it is for:   The network port of the mail server used for report e-mails, for example 25, 465 or 587.
#   Default:          No fallback for Risk Analysis mail; the daily close-loop mail uses 587 with encryption, else 25
#   If you change it: Must match the mail server and the encryption setting; a wrong port makes sending fail (the run
#                     itself continues).
#   When to change:   Set it to match your mail server; setup asks for it.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it to match your mail server; setup asks for it.
#   More info:        https://invardia.com/docs/si/settings/SMTPPort/
#
# Mail server user name  [SMTPUser]  (engine: risk-analysis)
#   What it is for:   User name of the mail server account that sends the mails.
#   Default:          Not set: signed-in mail cannot start; some installs read it from your Key Vault
#   If you change it: Needed with the password whenever mail is sent with sign-in. Without it, a Risk Analysis run
#                     with mail on stops at start, unless anonymous mail is on.
#   When to change:   Set it when you turn mail on with a relay that needs sign-in.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it when you turn mail on with a relay that needs sign-in.
#   More info:        https://invardia.com/docs/si/settings/SMTPUser/
#
# Mail the Detailed report  [RiskAnalysis_Detailed_SendMail]  (engine: risk-analysis)
#   What it is for:   Mails the Detailed Risk Analysis report after each run.
#   Default:          Not set: the older name, else SendMail (off) decides
#   If you change it: On: each Detailed run mails the full report to its recipients; this needs working mail server
#                     settings. A report template's own mail switch still wins.
#   When to change:   Turn on when the security team should receive the full Detailed report by mail.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Turn on when the security team should receive the full
#                     Detailed report by mail.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_Detailed_SendMail/
#
# Mail the Summary report  [RiskAnalysis_Summary_SendMail]  (engine: risk-analysis)
#   What it is for:   Mails the Summary Risk Analysis report after each run.
#   Default:          Not set: the older name, else SendMail (off) decides
#   If you change it: On: each Summary run mails the report to its recipients; this needs working mail server
#                     settings. A report template's own mail switch still wins. While the Summary step is off (the
#                     default since 2026-10), the management mail -- the Detailed report's mail, with its management
#                     summary -- goes to these recipients instead.
#   When to change:   Turn on when management or the security team should receive the Summary report by mail.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Turn on when management or the security team should receive
#                     the Summary report by mail.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_Summary_SendMail/
#
# Mail when a safety check stops a step  [SI_GuardMail_Enabled]
#   What it is for:   Mails a person when a safety check holds, refuses or stops a step to protect your data -- for
#                     example when far more vulnerabilities would close than usual.
#   Default:          On
#   If you change it: Off sends no such mail: the event is still recorded in run health, on the Guards page of the Pro
#                     web app and in the audit trail, and still reported to Invardia when status reports are on. While
#                     a check keeps tripping, at most one mail a day is sent, saying how many times it happened.
#   When to change:   Leave it on. Turn it off only if another system already watches these events for you.
#   Risk:             No check mails anyone any more: a held or stopped step is seen only on the Guards page, in run
#                     health and in the audit trail. Reversible at once.
#   Recommended:      Keep it on. Change it when: Leave it on. Turn it off only if another system already watches
#                     these events for you.
#   More info:        https://invardia.com/docs/si/settings/SI_GuardMail_Enabled/
#
# Safety-check mail recipients  [SI_GuardMail_To]
#   What it is for:   The addresses that receive the mail when a safety check holds, refuses or stops a step.
#   Default:          The report recipients (MailTo); without those, the SecurityInsight Pro SuperAdmins whose sign-in
#                     name is a mail address
#   If you change it: These addresses get the mails instead of the report recipients.
#   When to change:   Set it to the team that runs SecurityInsight day to day, when that is not the team that reads
#                     the reports.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it to the team that runs SecurityInsight day to day, when
#                     that is not the team that reads the reports.
#   More info:        https://invardia.com/docs/si/settings/SI_GuardMail_To/
#
# Send mail without sign-in  [Mail_SendAnonymous]  (engine: risk-analysis)
#   What it is for:   Sends mail through a relay that accepts mail without a user name and password.
#   Default:          Off: the mail server sign-in (user, password, sender) is required
#   If you change it: On: no SMTP credentials are needed or checked. Off with mail switched on: the run stops at start
#                     if the sender, user or password is missing. A relay that requires sign-in rejects anonymous
#                     mail.
#   When to change:   Only when your internal relay accepts unauthenticated mail from this host.
#   Risk:             Mail is sent without signing in to the mail server: only safe through an internal relay that
#                     accepts mail from this host alone. With an open relay, report mails can be spoofed or
#                     intercepted. Reversible at once.
#   Recommended:      Off (sign in to the mail server, or use the shared mailbox).
#   More info:        https://invardia.com/docs/si/settings/Mail_SendAnonymous/
#
# Shared mailbox (sender)  [SI_Mail_From]
#   What it is for:   The shared mailbox SecurityInsight sends as. With an SMTP relay it is the From address (and wins
#                     over the older sender settings).
#   Default:          Not set: with a shared mailbox nothing is sent; with SMTP the older sender setting is used
#   If you change it: Mail comes from this address. With a shared mailbox, Exchange must allow SecurityInsight's
#                     identity to send as it (and only as it).
#   When to change:   Set when you set up mail, or when the mailbox changes.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set when you set up mail, or when the mailbox changes.
#   More info:        https://invardia.com/docs/si/settings/SI_Mail_From/
#
# Summary report recipients  [RiskAnalysis_Summary_To]  (engine: risk-analysis)
#   What it is for:   The addresses that receive the Summary Risk Analysis report.
#   Default:          Not set: the older name, else MailTo, is used
#   If you change it: Summary reports go to these addresses instead of the default list. Blank entries are dropped
#                     with a warning. A report template's own recipients still win. While the Summary step is off (the
#                     default since 2026-10), these addresses receive the management mail -- the Detailed report's
#                     mail -- when Mail the Summary report is on.
#   When to change:   Set it when the Summary report should go to different people than the default list.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set it when the Summary report should go to different people
#                     than the default list.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_Summary_To/
#
# Keep the SMTP relay (by choice)  [SI_Mail_SmtpKept]  (advanced)
#   What it is for:   Says that your own SMTP relay is kept on purpose, so SecurityInsight stops suggesting the move
#                     to an Office 365 shared mailbox.
#   Default:          Off: SecurityInsight recommends moving to an Office 365 shared mailbox, and Home and Settings >
#                     E-mail show that hint
#   If you change it: On: the SMTP relay is kept by choice -- the amber "move to an Office 365 shared mailbox" hint is
#                     hidden on Home and on Settings > E-mail, and mail shows as set up. A failed test mail is still
#                     shown in red. Mail is sent exactly as before.
#   When to change:   When you decide to keep your own SMTP relay; Ignore on the Home banner sets it, Undo on Settings
#                     > E-mail clears it.
#   Risk:             Low: only the advice to move to a shared mailbox is hidden; how mail is sent does not change,
#                     and a failed test mail still shows in red. Reversible at once (Undo on Settings > E-mail).
#   Recommended:      Off, unless you keep your own SMTP relay on purpose.
#   More info:        https://invardia.com/docs/si/settings/SI_Mail_SmtpKept/
#
# Mailbox to prove the restriction  [SI_Mail_ProbeMailbox]  (advanced)
#   What it is for:   An ordinary mailbox OUTSIDE the shared mailbox's scope. Before it sends, SecurityInsight checks
#                     that it may NOT send as this mailbox -- which proves Mail.Send is restricted. Nothing is
#                     delivered by the check.
#   Default:          Not set: the restriction counts as verified only when an Exchange administrator confirmed it
#   If you change it: Without it (and without a confirmation) SecurityInsight does not send through the shared
#                     mailbox.
#   When to change:   Set once, to an administrator's own mailbox; setup fills it in.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set once, to an administrator's own mailbox; setup fills it
#                     in.
#   More info:        https://invardia.com/docs/si/settings/SI_Mail_ProbeMailbox/
#
# Restriction confirmed by  [SI_Mail_RestrictionAttestation]  (advanced)
#   What it is for:   Who confirmed that Mail.Send is restricted to the shared mailbox
#                     (Test-ServicePrincipalAuthorization), and when. Used only when no other mailbox can be tested.
#   Default:          Not set
#   If you change it: Counts as verified when the check against another mailbox cannot run.
#   When to change:   Set by the mail setup, or after your Exchange administrator ran the check.
#   Risk:             A wrong value can mean that alerts and reports go to the wrong people or to nobody, or that mail
#                     stops; no collected data is changed. Reversible at once: change it back.
#   Recommended:      Keep the default. Change it when: Set by the mail setup, or after your Exchange administrator
#                     ran the check.
#   More info:        https://invardia.com/docs/si/settings/SI_Mail_RestrictionAttestation/
#
# ----------------------------------------------------------------------------------------------------
# Guards (safety checks)
# The safety checks that hold, refuse or stop a step to protect your data: each can be turned off,
# its mail turned off, and its limits tuned.
# ----------------------------------------------------------------------------------------------------
#
# All guards (safety checks)  [SI_Guards_Enabled]
#   What it is for:   One switch for every safety check that holds, refuses or stops a step to protect your data (the
#                     list below and the Guards page).
#   Default:          On
#   If you change it: WARNING -- Off turns EVERY safety check off at once: SecurityInsight then closes vulnerability
#                     records, retires CIs, hands over batches and loads collections even when the data looks broken
#                     or incomplete, so a failed collection can close or retire everything it no longer sees. Nothing
#                     is held for release and no guard mail is sent; each check says once in its job log that it is
#                     off. The checks that only report a stop SecurityInsight cannot skip (the source failed, the
#                     licence) stop reporting it. On: every check works as set below.
#   When to change:   Leave it on. Turn it off only for a short time, when the checks stop work you know is right --
#                     and prefer turning off or tuning the one check that is in the way.
#   Risk:             Turning this off removes EVERY safety check at once: no step is held or stopped to protect your
#                     data, whatever happens. Reversible at once: switch it back on; it applies from the next run.
#   Recommended:      Keep it on. Change it when: Leave it on. Turn it off only for a short time, when the checks stop
#                     work you know is right -- and prefer turning off or tuning the one check that is in the way.
#   More info:        https://invardia.com/docs/si/settings/SI_Guards_Enabled/
#
# Asset metadata: large change  [SI_Guard_AssetPropertiesCollectionChange_Enabled]
#   What it is for:   The safety check that protects the asset metadata handed to your CMDB and vulnerability system:
#                     The full asset metadata collected from one source changed by more than the allowed share since
#                     the previous run, which looks like a broken collection rather than a real change, so the
#                     previous collection of that source was kept for the hand-off.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- a large change of the asset metadata is
#                     handed over like any other. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_AssetPropertiesCollectionChange_Enabled/
#
# Asset metadata: large change: mail  [SI_Guard_AssetPropertiesCollectionChange_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_AssetPropertiesCollectionChange_Mail/
#
# Audit trail retention setting  [SI_Guard_AuditRetentionRefused_Enabled]
#   What it is for:   The safety check that protects the audit trail: The audit trail retention setting
#                     (SI_Pro_AuditRetentionMonths) is not a whole number of at least 13 months, so nothing was
#                     removed.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because the retention setting is not
#                     valid. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_AuditRetentionRefused_Enabled/
#
# Audit trail retention setting: mail  [SI_Guard_AuditRetentionRefused_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_AuditRetentionRefused_Mail/
#
# Bulk exemption limit  [SI_Guard_ExemptionBulkRefused_Enabled]
#   What it is for:   The safety check that protects your findings from being exempted in bulk by mistake: A request
#                     to exempt or change many findings at once was refused (no narrowing filter, or more findings
#                     than the limit allows).
#   Default:          Off
#   If you change it: Off: no event and no mail. The request itself is still refused, because a whole collection is
#                     never exempted in one go -- raise the limit instead (Settings > Exemptions: Most findings in one
#                     bulk exemption request, up to 2,000). On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_ExemptionBulkRefused_Enabled/
#
# Bulk exemption limit: mail  [SI_Guard_ExemptionBulkRefused_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_ExemptionBulkRefused_Mail/
#
# CI build started while another was running  [SI_Guard_CiBuildConcurrent_Enabled]
#   What it is for:   The safety check that protects your configuration items (CIs) from being written by two builds
#                     at the same time: A CI build was started while another CI build was still running.
#   Default:          On
#   If you change it: Off: no event. The second CI build still waits for the first one, because two builds never write
#                     the CIs at the same time. On: the check works as described on the Guards page.
#   When to change:   Leave it on: it only reports, and nothing is stopped by it. Turn it off when you do not need to
#                     know that a CI build had to wait.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep it on. Change it when: Leave it on: it only reports, and nothing is stopped by it. Turn it
#                     off when you do not need to know that a CI build had to wait.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CiBuildConcurrent_Enabled/
#
# CI build started while another was running: mail  [SI_Guard_CiBuildConcurrent_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: This check only reports and stops nothing, so it sends no mail either way: the event is shown on
#                     the Guards page and kept in run health and the audit trail.
#   When to change:   Nothing to change: a check that only reports is not mailed.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Nothing to change: a check that only reports is not mailed.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CiBuildConcurrent_Mail/
#
# CMDB hand-off: large change  [SI_Guard_CmdbHandoffMassChange_Enabled]
#   What it is for:   The safety check that protects the CIs your ServiceNow imports from the CMDB hand-off database:
#                     Far more of the CIs handed to ServiceNow last time are missing from this run than the connector
#                     allows, which looks like a broken collection rather than assets gone, so this run's batch was
#                     held and ServiceNow keeps importing the previous one.
#   Default:          On
#   If you change it: Off: the step goes on as if the check had not tripped -- the batch is handed over to ServiceNow
#                     however many CIs changed or disappeared. On: the check works as described on the Guards page.
#   When to change:   Leave it on. Turn it off only when this check keeps stopping work you know is right -- read what
#                     Off means first.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep it on. Change it when: Leave it on. Turn it off only when this check keeps stopping work
#                     you know is right -- read what Off means first.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbHandoffMassChange_Enabled/
#
# CMDB hand-off: large change: mail  [SI_Guard_CmdbHandoffMassChange_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbHandoffMassChange_Mail/
#
# CMDB table: asset collection not complete  [SI_Guard_CmdbSqlSnapshotIncomplete_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in your SQL CMDB table: The newest
#                     asset collection is not known to be complete, so the CMDB table was not changed.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because a CI is never written from an
#                     asset collection that is not complete. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlSnapshotIncomplete_Enabled/
#
# CMDB table: asset collection not complete: mail  [SI_Guard_CmdbSqlSnapshotIncomplete_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlSnapshotIncomplete_Mail/
#
# CMDB table: changed by another run  [SI_Guard_CmdbSqlStale_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in your SQL CMDB table: Another run
#                     changed the CMDB table while this one was planning, so this run wrote nothing.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because another run changed the CMDB
#                     table meanwhile; the next run plans again. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlStale_Enabled/
#
# CMDB table: changed by another run: mail  [SI_Guard_CmdbSqlStale_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlStale_Mail/
#
# CMDB table: empty asset collection  [SI_Guard_CmdbSqlEmptySnapshot_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in your SQL CMDB table: The newest
#                     asset collection holds no assets at all, so nothing was written or retired.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- an empty asset collection is written
#                     too, which can retire every CI. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlEmptySnapshot_Enabled/
#
# CMDB table: empty asset collection: mail  [SI_Guard_CmdbSqlEmptySnapshot_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlEmptySnapshot_Mail/
#
# CMDB table: far fewer assets than usual  [SI_Guard_CmdbSqlCollapse_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in your SQL CMDB table:
#                     SecurityInsight sees far fewer assets than are active in the CMDB table, which looks like a
#                     broken collection rather than assets gone, so nothing was retired.
#   Default:          On
#   If you change it: Off: the step goes on as if the check had not tripped -- CIs are retired even when
#                     SecurityInsight sees far fewer assets than are active in the CMDB table. On: the check works as
#                     described on the Guards page.
#   When to change:   Leave it on. Turn it off only when this check keeps stopping work you know is right -- read what
#                     Off means first.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep it on. Change it when: Leave it on. Turn it off only when this check keeps stopping work
#                     you know is right -- read what Off means first.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlCollapse_Enabled/
#
# CMDB table: far fewer assets than usual: mail  [SI_Guard_CmdbSqlCollapse_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlCollapse_Mail/
#
# CMDB table: no correlation results  [SI_Guard_CmdbSqlNoCorrelationMap_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in your SQL CMDB table: The asset
#                     correlation results are missing, so assets could not be matched to their CIs and nothing was
#                     written.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because without the correlation results
#                     no asset can be matched to its CI. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlNoCorrelationMap_Enabled/
#
# CMDB table: no correlation results: mail  [SI_Guard_CmdbSqlNoCorrelationMap_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbSqlNoCorrelationMap_Mail/
#
# Collection: far fewer assets from one source  [SI_Guard_CollectionSourceAssetDrop_Enabled]
#   What it is for:   The safety check that protects your configuration items (CIs) and everything calculated from
#                     them: One source returned far fewer assets than in its last good collection, although the
#                     collection completed.
#   Default:          On
#   If you change it: Off: a collection with far fewer assets is taken as it comes -- the assets the source no longer
#                     lists are marked not seen at once, and their CIs retire after the usual days. On: the check
#                     works as described on the Guards page.
#   When to change:   Leave it on. Turn it off only when this check keeps stopping work you know is right -- read what
#                     Off means first.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep it on. Change it when: Leave it on. Turn it off only when this check keeps stopping work
#                     you know is right -- read what Off means first.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CollectionSourceAssetDrop_Enabled/
#
# Collection: far fewer assets from one source: mail  [SI_Guard_CollectionSourceAssetDrop_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CollectionSourceAssetDrop_Mail/
#
# Daily flow: job did not start  [SI_Guard_FlowStepStartFailed_Enabled]
#   What it is for:   The safety check that protects the jobs of the daily flow: A job in the daily flow could not
#                     start: its container stopped before SecurityInsight ran (an Azure platform problem).
#   Default:          Off
#   If you change it: Off: no event and no mail; a job that does not start is still not run. On: the check works as
#                     described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowStepStartFailed_Enabled/
#
# Daily flow: job did not start: mail  [SI_Guard_FlowStepStartFailed_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowStepStartFailed_Mail/
#
# Daily flow: job interrupted  [SI_Guard_FlowStepInterrupted_Enabled]
#   What it is for:   The safety check that protects the jobs that depend on an earlier job: A job in the daily flow
#                     was interrupted and was not started again automatically.
#   Default:          Off
#   If you change it: Off: no event and no mail; an interrupted job is still not started again. On: the check works as
#                     described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowStepInterrupted_Enabled/
#
# Daily flow: job interrupted: mail  [SI_Guard_FlowStepInterrupted_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowStepInterrupted_Mail/
#
# Daily flow: jobs skipped  [SI_Guard_FlowStepSkipped_Enabled]
#   What it is for:   The safety check that protects the jobs that depend on an earlier job: One or more jobs in the
#                     daily flow were skipped because a job they need did not succeed.
#   Default:          Off
#   If you change it: Off: no event and no mail; jobs that need a failed job are still skipped. On: the check works as
#                     described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowStepSkipped_Enabled/
#
# Daily flow: jobs skipped: mail  [SI_Guard_FlowStepSkipped_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowStepSkipped_Mail/
#
# Daily flow: start held for the previous run  [SI_Guard_FlowRunCatchUp_Enabled]
#   What it is for:   The safety check that protects the order of the daily jobs: A scheduled start of the daily job
#                     flow was held because the previous run was still running; it ran once as soon as that run
#                     finished.
#   Default:          Off
#   If you change it: Off: no event and no mail; the daily flow still waits for its previous run. On: the check works
#                     as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowRunCatchUp_Enabled/
#
# Daily flow: start held for the previous run: mail  [SI_Guard_FlowRunCatchUp_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_FlowRunCatchUp_Mail/
#
# Data sync: collection not read in full  [SI_Guard_DatasyncCollectionShortRead_Enabled]
#   What it is for:   The safety check that protects the collections shown in the Pro web app: A collection could not
#                     be read or written in full, so it was not loaded.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because a collection that could not be
#                     read or written in full is not loaded. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncCollectionShortRead_Enabled/
#
# Data sync: collection not read in full: mail  [SI_Guard_DatasyncCollectionShortRead_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncCollectionShortRead_Mail/
#
# Data sync: collection of an unfinished run  [SI_Guard_DatasyncCollectionHeld_Enabled]
#   What it is for:   The safety check that protects the collections shown in the Pro web app: Some Risk Analysis
#                     collections were not loaded into the Pro database because the run that produced them is not
#                     known to be complete.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- a collection whose Risk Analysis run
#                     did not finish completely is loaded anyway and MARKED PARTIAL in the web app. On: the check
#                     works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncCollectionHeld_Enabled/
#
# Data sync: collection of an unfinished run: mail  [SI_Guard_DatasyncCollectionHeld_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncCollectionHeld_Mail/
#
# Data sync: findings an asset kind filter cannot show  [SI_Guard_DatasyncAssetKindDropped_Enabled]
#   What it is for:   The safety check that protects the asset kind filters of the Pro web app: findings of an asset
#                     kind were loaded, but their assets were stored without that kind (or without any kind), so the
#                     asset kind filter cannot show them.
#   Default:          Off
#   If you change it: Off: no event and no mail when a loaded collection has findings of an asset kind that no asset
#                     of that kind carries; the findings are loaded as before. On: the check works as described on the
#                     Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncAssetKindDropped_Enabled/
#
# Data sync: findings an asset kind filter cannot show: mail  [SI_Guard_DatasyncAssetKindDropped_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncAssetKindDropped_Mail/
#
# Data sync: rows without their key  [SI_Guard_DatasyncCollectionRefused_Enabled]
#   What it is for:   The safety check that protects the days shown in the Pro web app and its trends: Risk Analysis
#                     data arrived without its key columns (its finding ids, or its collection time), so it was not
#                     loaded as a day.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because rows without their finding id or
#                     collection time cannot be placed in a day. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncCollectionRefused_Enabled/
#
# Data sync: rows without their key: mail  [SI_Guard_DatasyncCollectionRefused_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_DatasyncCollectionRefused_Mail/
#
# Database change that could remove data  [SI_Guard_SchemaGateRefused_Enabled]
#   What it is for:   The safety check that protects your SecurityInsight database: A database change was refused
#                     because it is not approved for this install, or because it could remove data.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because a database change that could
#                     remove data is never applied automatically. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_SchemaGateRefused_Enabled/
#
# Database change that could remove data: mail  [SI_Guard_SchemaGateRefused_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_SchemaGateRefused_Mail/
#
# Job started while still running  [SI_Guard_JobExecutionPreviousRunning_Enabled]
#   What it is for:   The safety check that protects a job from running twice at the same time: A job was started
#                     while its previous run was still running, so the new run did nothing.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because two runs of one job never run at
#                     the same time. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_JobExecutionPreviousRunning_Enabled/
#
# Job started while still running: mail  [SI_Guard_JobExecutionPreviousRunning_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_JobExecutionPreviousRunning_Mail/
#
# Job stuck on throttling  [SI_Guard_JobRunThrottledStuck_Enabled]
#   What it is for:   The safety check that protects the data of a job that Microsoft keeps throttling: A job has not
#                     completed for a long time, because Microsoft throttled every run of it.
#   Default:          Off
#   If you change it: Off: no event and no mail when a job is stuck on throttling. Throttled runs are still shown as
#                     throttled on the Jobs and Run health pages. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_JobRunThrottledStuck_Enabled/
#
# Job stuck on throttling: mail  [SI_Guard_JobRunThrottledStuck_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_JobRunThrottledStuck_Mail/
#
# Licence grace period  [SI_Guard_LicenceStateGrace_Enabled]
#   What it is for:   The safety check that protects the SecurityInsight Pro features: The SecurityInsight Pro licence
#                     is in its grace period.
#   Default:          Off
#   If you change it: Off: no event and no mail during the licence grace period; everything keeps running. On: the
#                     check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_LicenceStateGrace_Enabled/
#
# Licence grace period: mail  [SI_Guard_LicenceStateGrace_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_LicenceStateGrace_Mail/
#
# Licence not valid  [SI_Guard_LicenceStateInvalid_Enabled]
#   What it is for:   The safety check that protects the SecurityInsight Pro features: The SecurityInsight Pro licence
#                     does not verify (it has expired or is not valid for this install), so the Pro jobs did not run.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because the licence, not this switch,
#                     decides which Pro features run. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_LicenceStateInvalid_Enabled/
#
# Licence not valid: mail  [SI_Guard_LicenceStateInvalid_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_LicenceStateInvalid_Mail/
#
# Log Analytics: rows not accepted  [SI_Guard_IngestRowsShortCount_Enabled]
#   What it is for:   The safety check that protects the results written to your Log Analytics workspace: Not every
#                     row of a result was accepted by Log Analytics, so the run was stopped instead of reporting a
#                     partial result as complete.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because the rows Log Analytics did not
#                     accept are not there. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_IngestRowsShortCount_Enabled/
#
# Log Analytics: rows not accepted: mail  [SI_Guard_IngestRowsShortCount_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_IngestRowsShortCount_Mail/
#
# Risk Analysis: column emptied  [SI_Guard_RaOutputColumnEmptied_Enabled]
#   What it is for:   The safety check that protects the completeness of your Risk Analysis reports: One or more
#                     report columns are empty (or gone) while they had values in the previous run.
#   Default:          Off
#   If you change it: Off: no event and no mail when a report column lost its content; the report itself is unchanged.
#                     On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_RaOutputColumnEmptied_Enabled/
#
# Risk Analysis: column emptied: mail  [SI_Guard_RaOutputColumnEmptied_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_RaOutputColumnEmptied_Mail/
#
# Risk Analysis: far fewer findings  [SI_Guard_RaOutputRowDrop_Enabled]
#   What it is for:   The safety check that protects the completeness of your Risk Analysis reports: One or more
#                     reports produced far fewer findings than the previous run.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- a report with far fewer findings than
#                     the previous run no longer makes the run partial (a failed query or a missing result still
#                     does). On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_RaOutputRowDrop_Enabled/
#
# Risk Analysis: far fewer findings: mail  [SI_Guard_RaOutputRowDrop_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_RaOutputRowDrop_Mail/
#
# Risk Analysis: far more buckets than usual  [SI_Guard_RaBucketCountJump_Enabled]
#   What it is for:   The safety check that protects the speed and correctness of your Risk Analysis reports: One or
#                     more reports needed far more buckets (query slices) than usual.
#   Default:          On
#   If you change it: Off: no event when a report needs far more buckets than usual; the run itself is unchanged. On:
#                     the check works as described on the Guards page.
#   When to change:   On by default (owner-approved bucket sizing design): it only warns and never stops a run. Turn
#                     it off only if you do not want these warnings.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep it on. Change it when: On by default (owner-approved bucket sizing design): it only warns
#                     and never stops a run. Turn it off only if you do not want these warnings.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_RaBucketCountJump_Enabled/
#
# Risk Analysis: far more buckets than usual: mail  [SI_Guard_RaBucketCountJump_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_RaBucketCountJump_Mail/
#
# ServiceNow: create and match rules  [SI_Guard_CmdbServicenowCreateGate_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in ServiceNow: Some assets were not
#                     created or updated in ServiceNow because SecurityInsight could not match them safely (no stable
#                     asset id yet, or more than one matching CI).
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because those assets do not meet the
#                     connector's create and match rules (set in the connector). On: the check works as described on
#                     the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbServicenowCreateGate_Enabled/
#
# ServiceNow: create and match rules: mail  [SI_Guard_CmdbServicenowCreateGate_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbServicenowCreateGate_Mail/
#
# ServiceNow: not reachable  [SI_Guard_CmdbServicenowUnreachable_Enabled]
#   What it is for:   The safety check that protects the configuration items (CIs) in ServiceNow: The ServiceNow
#                     instance could not be reached, so nothing was sent.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because ServiceNow cannot be reached.
#                     On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbServicenowUnreachable_Enabled/
#
# ServiceNow: not reachable: mail  [SI_Guard_CmdbServicenowUnreachable_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbServicenowUnreachable_Mail/
#
# ServiceNow: service model errors  [SI_Guard_CmdbServicenowServiceModel_Enabled]
#   What it is for:   The safety check that protects the placement of assets in your business services: The service
#                     model has errors, so no asset was placed in a business service.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because the service model has errors.
#                     On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbServicenowServiceModel_Enabled/
#
# ServiceNow: service model errors: mail  [SI_Guard_CmdbServicenowServiceModel_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_CmdbServicenowServiceModel_Mail/
#
# Update: database update failed  [SI_Guard_UpdateSchemaFailed_Enabled]
#   What it is for:   The safety check that protects your SecurityInsight installation from running a new version on
#                     an old database: An update stopped before it changed anything, because the new version's
#                     database changes could not be applied.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because the database update failed. On:
#                     the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_UpdateSchemaFailed_Enabled/
#
# Update: database update failed: mail  [SI_Guard_UpdateSchemaFailed_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_UpdateSchemaFailed_Mail/
#
# Vulnerabilities: connector not set up  [SI_Guard_VulnConnectorRefused_Enabled]
#   What it is for:   The safety check that protects your vulnerability target: A vulnerability connector is not set
#                     up completely, so it did not run.
#   Default:          Off
#   If you change it: Off: no event and no mail. The step itself still stops, because the connector is not set up
#                     completely and cannot run. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorRefused_Enabled/
#
# Vulnerabilities: connector not set up: mail  [SI_Guard_VulnConnectorRefused_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorRefused_Mail/
#
# Vulnerabilities: empty result  [SI_Guard_VulnConnectorEmptySnapshot_Enabled]
#   What it is for:   The safety check that protects open vulnerability records: The newest Risk Analysis results held
#                     no vulnerabilities while records are still open, so nothing was closed.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- an EMPTY result closes the open records
#                     it no longer reports, so a failed collection can close every open vulnerability. On: the check
#                     works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorEmptySnapshot_Enabled/
#
# Vulnerabilities: empty result: mail  [SI_Guard_VulnConnectorEmptySnapshot_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorEmptySnapshot_Mail/
#
# Vulnerabilities: result far smaller than usual  [SI_Guard_VulnConnectorCollapse_Enabled]
#   What it is for:   The safety check that protects open vulnerability records: Far fewer of the open vulnerability
#                     records are still reported than usual, which looks like a partial collection rather than a real
#                     fix, so nothing was closed.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- a result that lost most of its findings
#                     closes the records it no longer reports. On: the check works as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorCollapse_Enabled/
#
# Vulnerabilities: result far smaller than usual: mail  [SI_Guard_VulnConnectorCollapse_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorCollapse_Mail/
#
# Vulnerabilities: results not known to be complete  [SI_Guard_VulnConnectorSnapshotIncomplete_Enabled]
#   What it is for:   The safety check that protects open vulnerability records: The newest Risk Analysis results are
#                     not known to be complete, so findings were opened and updated but nothing was closed.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- absences are counted and records closed
#                     even when the newest results are not known to be complete. On: the check works as described on
#                     the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorSnapshotIncomplete_Enabled/
#
# Vulnerabilities: results not known to be complete: mail  [SI_Guard_VulnConnectorSnapshotIncomplete_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorSnapshotIncomplete_Mail/
#
# Vulnerabilities: Risk Analysis run not finished  [SI_Guard_VulnConnectorRunIncomplete_Enabled]
#   What it is for:   The safety check that protects open vulnerability records: The Risk Analysis run behind these
#                     results did not finish cleanly, so nothing was closed.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- records are closed even when the Risk
#                     Analysis run behind the results did not finish cleanly. On: the check works as described on the
#                     Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorRunIncomplete_Enabled/
#
# Vulnerabilities: Risk Analysis run not finished: mail  [SI_Guard_VulnConnectorRunIncomplete_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorRunIncomplete_Mail/
#
# Vulnerabilities: scope changed  [SI_Guard_VulnConnectorScopeChanged_Enabled]
#   What it is for:   The safety check that protects open vulnerability records: The scope of the collection changed,
#                     so records that dropped out of it were not closed.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- records that dropped out of the
#                     collection scope are closed like any other absent record. On: the check works as described on
#                     the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorScopeChanged_Enabled/
#
# Vulnerabilities: scope changed: mail  [SI_Guard_VulnConnectorScopeChanged_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorScopeChanged_Mail/
#
# Vulnerabilities: target not read in full  [SI_Guard_VulnConnectorTargetIncomplete_Enabled]
#   What it is for:   The safety check that protects your vulnerability target from duplicate records: The
#                     vulnerability target (for example the ServiceNow table) could not be read in full, so nothing
#                     was written: every record the read missed would have been opened again as a duplicate.
#   Default:          On
#   If you change it: Off: no event and no mail. The step itself still stops, because writing after a partial read of
#                     the target would open every record the read missed again as a duplicate. On: the check works as
#                     described on the Guards page.
#   When to change:   Leave it on. Turn it off only when this check keeps stopping work you know is right -- read what
#                     Off means first.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep it on. Change it when: Leave it on. Turn it off only when this check keeps stopping work
#                     you know is right -- read what Off means first.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorTargetIncomplete_Enabled/
#
# Vulnerabilities: target not read in full: mail  [SI_Guard_VulnConnectorTargetIncomplete_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorTargetIncomplete_Mail/
#
# Vulnerability close limit  [SI_Guard_VulnConnectorCloseCeiling_Enabled]
#   What it is for:   The safety check that protects open vulnerability records: SecurityInsight would have closed far
#                     more vulnerability records in one run than it allows, so it closed none.
#   Default:          Off
#   If you change it: Off: the step goes on as if the check had not tripped -- the vulnerability connector closes
#                     every record the run would close, however many; nothing is held for release. On: the check works
#                     as described on the Guards page.
#   When to change:   Off by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   Risk:             Turning this check off removes a protection: when its condition happens, nothing holds or stops
#                     the step and no event is raised. Reversible at once: switch it back on; it applies from the next
#                     run.
#   Recommended:      Keep the default (off) unless you want this check to hold or stop the step. Change it when: Off
#                     by default: only the two brakes stay on (CIs retired by mistake, duplicate vulnerability
#                     records) -- this check is a warning you can switch on. Turn it on when you want it to hold or
#                     stop the step, and mail, again.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorCloseCeiling_Enabled/
#
# Vulnerability close limit: mail  [SI_Guard_VulnConnectorCloseCeiling_Mail]
#   What it is for:   Whether this safety check sends a mail when it trips.
#   Default:          On (follows the check: nothing is mailed while the check is off)
#   If you change it: Off: the event is still shown on the Guards page and kept in run health and the audit trail, but
#                     no mail is sent for it. The install-wide switch "Mail when a safety check stops a step" still
#                     applies to every check.
#   When to change:   Turn it off for a check whose mails you do not need, instead of turning the check off.
#   Risk:             Low: no data is changed and the check still works; only its mail stops, so a trip is seen only
#                     on the Guards page, in run health and in the audit trail. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off for a check whose mails you do not need, instead
#                     of turning the check off.
#   More info:        https://invardia.com/docs/si/settings/SI_Guard_VulnConnectorCloseCeiling_Mail/
#
# Data health check  [SI_DataHealth_Enabled]  (advanced)
#   What it is for:   Every day SecurityInsight checks its own data: a random 10% of each source's records (at least
#                     50) are read from the source and looked up in the newest collection, and a random 10% of the
#                     devices with vulnerability findings are asked again from Defender. It only reads. Three
#                     anomalous days in a row make the data Unhealthy, one good day makes it Healthy again; while
#                     Unhealthy nothing is sent out unless a SuperAdmin lets a channel through.
#   Default:          On
#   If you change it: Off: nothing is checked, the state is no longer updated and nothing is held because of data
#                     health. On: the check runs with the verification job every day.
#   When to change:   Keep it on. Switch it off only for a short time while Microsoft support confirms a problem in a
#                     source.
#   Risk:             Off: SecurityInsight no longer checks its own data, and nothing is held when the data goes wrong
#                     -- a short or wrong collection can reach tickets, the CMDB and the connectors. Reversible at
#                     once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Keep it on. Switch it off only for a short time while
#                     Microsoft support confirms a problem in a source.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Enabled/
#
# Data health margin: Azure resources  [SI_DataHealth_Margin_Azure]  (advanced, %)
#   What it is for:   How many of the checked Azure resources may be missing from the newest collection or differ from
#                     Azure before the day counts as anomalous, as a percent of the resources checked (never fewer
#                     than the minimum records below).
#   Default:          3 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it only when resources are created and deleted all day (for example short-lived test
#                     environments).
#   Risk:             Higher: more missing or different Azure resources are tolerated before data-out is held. Lower:
#                     data-out is held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it only when resources are created and deleted all day
#                     (for example short-lived test environments).
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_Azure/
#
# Data health margin: Defender devices  [SI_DataHealth_Margin_Devices]  (advanced, %)
#   What it is for:   How many of the checked Defender for Endpoint devices may be missing from the newest collection
#                     or differ from Defender before the day counts as anomalous, as a percent of the devices checked
#                     (never fewer than the minimum records below).
#   Default:          2 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it only when many devices are onboarded or removed every day.
#   Risk:             Higher: more missing or different devices are tolerated before data-out is held. Lower: data-out
#                     is held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it only when many devices are onboarded or removed every
#                     day.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_Devices/
#
# Data health margin: Defender for Cloud recommendations  [SI_DataHealth_Margin_DefenderForCloud]  (advanced, %)
#   What it is for:   How many of the checked resources with Defender for Cloud recommendations may be missing from
#                     the newest collection or have a different number of open recommendations before the day counts
#                     as anomalous, as a percent of those checked (never fewer than the minimum records below).
#   Default:          5 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it only when Defender for Cloud re-evaluates many resources between the collection and the
#                     check.
#   Risk:             Higher: more differences in Defender for Cloud recommendations are tolerated before data-out is
#                     held. Lower: data-out is held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it only when Defender for Cloud re-evaluates many
#                     resources between the collection and the check.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_DefenderForCloud/
#
# Data health margin: Entra apps and service principals  [SI_DataHealth_Margin_EntraApps]  (advanced, %)
#   What it is for:   How many of the checked Entra apps and service principals may be missing from the newest
#                     collection or differ from Entra before the day counts as anomalous, as a percent of those
#                     checked (never fewer than the minimum records below).
#   Default:          1 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it only when apps are added and removed so often that normal changes count as differences.
#   Risk:             Higher: more missing or different apps are tolerated before data-out is held. Lower: data-out is
#                     held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it only when apps are added and removed so often that
#                     normal changes count as differences.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_EntraApps/
#
# Data health margin: Entra users  [SI_DataHealth_Margin_EntraUsers]  (advanced, %)
#   What it is for:   How many of the checked Entra users may be missing from the newest collection or differ from
#                     Entra before the day counts as anomalous, as a percent of the users checked (never fewer than
#                     the minimum records below).
#   Default:          1 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it only when the users change so fast that the daily check sees normal changes as
#                     differences.
#   Risk:             Higher: more missing or different users are tolerated before data-out is held. Lower: data-out
#                     is held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it only when the users change so fast that the daily
#                     check sees normal changes as differences.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_EntraUsers/
#
# Data health margin: minimum records  [SI_DataHealth_MarginMinimum]  (advanced, records)
#   What it is for:   The fewest differences any data health margin allows, whatever its percent -- so a small source
#                     does not turn the data Unhealthy over one or two records.
#   Default:          5 records
#   If you change it: Higher tolerates more differences in small sources; lower makes small sources stricter.
#   When to change:   Keep the default.
#   Risk:             Higher: small sources tolerate more differences before data-out is held. Lower: small sources
#                     are stricter. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Keep the default.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_MarginMinimum/
#
# Data health margin: Risk Analysis reports  [SI_DataHealth_Margin_RiskAnalysis]  (advanced, %)
#   What it is for:   Per Risk Analysis report with vulnerability findings: how many of the checked findings may
#                     differ from what Defender reports now (missing, or no longer reported) before the day counts as
#                     anomalous, as a percent of those checked (never fewer than the minimum records below).
#   Default:          3 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it only when devices are patched so often that findings fixed since the run count as
#                     differences.
#   Risk:             Higher: more differences between a report and Defender are tolerated before data-out is held.
#                     Lower: data-out is held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it only when devices are patched so often that findings
#                     fixed since the run count as differences.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_RiskAnalysis/
#
# Data health margin: vulnerabilities  [SI_DataHealth_Margin_Vulnerabilities]  (advanced, %)
#   What it is for:   How many of the vulnerabilities Defender reports for the checked devices may be missing from
#                     SecurityInsight's findings before the day counts as anomalous, as a percent of those
#                     vulnerabilities (never fewer than the minimum records below).
#   Default:          5 %
#   If you change it: Higher tolerates more differences before the data turns Unhealthy; lower turns it Unhealthy
#                     sooner.
#   When to change:   Raise it when vulnerabilities are left out on purpose (excluded vulnerabilities, a minimum age)
#                     and the check counts them.
#   Risk:             Higher: more vulnerabilities missing from the findings are tolerated before data-out is held.
#                     Lower: data-out is held sooner. Reversible at once; it applies from the next daily check.
#   Recommended:      Keep the default. Change it when: Raise it when vulnerabilities are left out on purpose
#                     (excluded vulnerabilities, a minimum age) and the check counts them.
#   More info:        https://invardia.com/docs/si/settings/SI_DataHealth_Margin_Vulnerabilities/
#
# Stuck on throttling after (hours)  [SI_Throttle_StuckHours]  (advanced, hours)
#   What it is for:   How long a job may keep being throttled by Microsoft, without completing, before the one "stuck"
#                     alert is sent.
#   Default:          6
#   If you change it: A throttled run is normal: it is shown as throttled, it is not mailed, and the job runs again at
#                     its next scheduled time. When a job has been throttled on every run for this many hours (and at
#                     least two runs), one alert says it is stuck. Whichever comes first of this and the number of
#                     runs below. The next run that completes clears it.
#   When to change:   Raise it if you get the alert for jobs that catch up by themselves; lower it if you need to know
#                     sooner.
#   Risk:             A safety check protects your data from a broken run; changing it changes when a step is held or
#                     stopped. Reversible at once.
#   Recommended:      Keep the default. Change it when: Raise it if you get the alert for jobs that catch up by
#                     themselves; lower it if you need to know sooner.
#   More info:        https://invardia.com/docs/si/settings/SI_Throttle_StuckHours/
#
# Stuck on throttling after (runs)  [SI_Throttle_StuckRuns]  (advanced, runs)
#   What it is for:   How many throttled runs in a row, without one that completes, send the one "stuck" alert.
#   Default:          12
#   If you change it: When a job has been throttled this many runs in a row, one alert says it is stuck -- whichever
#                     comes first of this and the number of hours above. The next run that completes clears it.
#   When to change:   Raise it for jobs that run very often; lower it if you need to know sooner.
#   Risk:             A safety check protects your data from a broken run; changing it changes when a step is held or
#                     stopped. Reversible at once.
#   Recommended:      Keep the default. Change it when: Raise it for jobs that run very often; lower it if you need to
#                     know sooner.
#   More info:        https://invardia.com/docs/si/settings/SI_Throttle_StuckRuns/
#
# ----------------------------------------------------------------------------------------------------
# Schedules & what runs
# Which jobs run and when; how many run side by side.
# ----------------------------------------------------------------------------------------------------
#
# Asset tagging schedule  [SI_Bootstrap_ScheduleAssetTagging]
#   What it is for:   When the asset tagging container job runs, as a cron expression in UTC.
#   Default:          Daily at 05:50 UTC, after the collection jobs
#   If you change it: Sets when tagging rules are evaluated. Running before the collection jobs finish means rules see
#                     the previous day's assets.
#   When to change:   When you move the collection schedules, to keep tagging after them.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: When you move the collection schedules, to keep tagging after
#                     them.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleAssetTagging/
#
# Azure collection schedule  [SI_Bootstrap_ScheduleAzure]
#   What it is for:   When the Azure profiling container job runs, as a cron expression in UTC.
#   Default:          Daily at 05:00 UTC
#   If you change it: Sets when Azure assets are collected. Reports and later jobs read the result, so keep it before
#                     risk analysis.
#   When to change:   To fit your own maintenance window or time zone.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: To fit your own maintenance window or time zone.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleAzure/
#
# Container jobs to deploy  [SI_Bootstrap_Engines]
#   What it is for:   The list of engines container setup creates scheduled jobs for.
#   Default:          All standard engines, plus asset trend and the Pro engines where installed
#   If you change it: Only the listed engines get a job. When you set a list it is used exactly as given, so Pro and
#                     trend jobs are not added automatically. The role classifier is left out when Azure OpenAI is not
#                     configured.
#   When to change:   When you want fewer jobs, or an engine not deployed by default, such as schema discovery.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: When you want fewer jobs, or an engine not deployed by
#                     default, such as schema discovery.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_Engines/
#
# Daily pipeline start time  [SI_Pipeline_StartTime]
#   What it is for:   The time of day a new install's daily pipeline (Collect, Correlate, Deliver) starts, in the
#                     pipeline's time zone.
#   Default:          19:00 in the local time of the install's Azure region (Danish time when the region is not known)
#   If you change it: The pipeline starts at this local time every day; summer time moves the time in UTC, never the
#                     local time. A pipeline already stored on Operations > Jobs or in config\job-flow.custom.json
#                     keeps its own time -- change that one there.
#   When to change:   When the collection should run at another time of day, for example to finish before the working
#                     day starts.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: When the collection should run at another time of day, for
#                     example to finish before the working day starts.
#   More info:        https://invardia.com/docs/si/settings/SI_Pipeline_StartTime/
#
# Daily pipeline time zone  [SI_Pipeline_TimeZone]
#   What it is for:   The time zone the daily pipeline's start time is read in.
#   Default:          The time zone of the install's Azure region, written by the install (Europe/Copenhagen, Danish
#                     time, when the region is not known)
#   If you change it: An IANA id such as Europe/Oslo or America/New_York, or a Windows id. The start time stays the
#                     same local time all year. An id the machine does not know is read as UTC, with a warning in the
#                     run log.
#   When to change:   Set it to the time zone of the people who read the results; the guided installer asks for it.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Set it to the time zone of the people who read the results;
#                     the guided installer asks for it.
#   More info:        https://invardia.com/docs/si/settings/SI_Pipeline_TimeZone/
#
# Endpoint collection schedule  [SI_Bootstrap_ScheduleEndpoint]
#   What it is for:   When the endpoint profiling container job runs, as a cron expression in UTC; also used for jobs
#                     without a schedule of their own.
#   Default:          Daily at 04:00 UTC
#   If you change it: Sets when endpoints are collected. Reports and later jobs read the result, so keep it before
#                     risk analysis.
#   When to change:   To fit your own maintenance window or time zone.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: To fit your own maintenance window or time zone.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleEndpoint/
#
# Identity collection schedule  [SI_Bootstrap_ScheduleIdentity]
#   What it is for:   When the identity profiling container job runs, as a cron expression in UTC.
#   Default:          Daily at 04:30 UTC
#   If you change it: Sets when identities are collected. Reports and later jobs read the result, so keep it before
#                     risk analysis.
#   When to change:   To fit your own maintenance window or time zone.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: To fit your own maintenance window or time zone.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleIdentity/
#
# Summary report schedule  [SI_Bootstrap_ScheduleRiskAnalysis]
#   What it is for:   When the Summary risk-analysis container job runs, as a cron expression in UTC.
#   Default:          Daily at 06:00 UTC, after collection
#   If you change it: Sets when the Summary report is built. Running it before collection finishes reports on the
#                     previous day's data.
#   When to change:   When you move the collection schedules or want the report at another time.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: When you move the collection schedules or want the report at
#                     another time.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleRiskAnalysis/
#
# Asset trend job schedule  [SI_Bootstrap_ScheduleTrend]  (advanced)
#   What it is for:   Schedule (cron, UTC) of the container job that builds the asset trend; it should run after the
#                     Detailed report.
#   Default:          Daily at 09:00 UTC, moved with the start hour chosen in guided setup.
#   If you change it: Container setup gives the trend job this schedule on its next run (an explicit -ScheduleTrend on
#                     the setup command still wins). Running it before the Detailed report trends the previous day's
#                     data.
#   When to change:   Only if the trend job must run at another time, for example after you moved the Detailed report.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only if the trend job must run at another time, for example
#                     after you moved the Detailed report.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleTrend/
#
# Azure job containers in parallel  [SI_Bootstrap_ParallelismAzure]  (advanced, containers)
#   What it is for:   How many containers the Azure profiling job runs side by side in each run.
#   Default:          1 container
#   If you change it: More containers split the Azure collection and finish sooner, at higher compute cost per run and
#                     more parallel load on Azure APIs.
#   When to change:   Only for large Azure estates where the job runs too long.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only for large Azure estates where the job runs too long.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ParallelismAzure/
#
# CI build: days between full rebuilds  [SI_CiBuild_FullReconcileDays]  (advanced, days)
#   What it is for:   The CI build (correlation) rebuilds only the CIs whose input changed since their last build: a
#                     record new, changed, moved or gone, a link state, a time threshold, an identity anchor or a
#                     manual override. Every CI is rebuilt (a full reconcile) when the last full build is this many
#                     days old; also at once when the data model, rules, mappings or CMDB change, and after a build
#                     that failed.
#   Default:          7 days: every CI is rebuilt at least once a week; the days between build only what changed
#   If you change it: A lower value rebuilds every CI more often (a longer correlation run on those days); 0 rebuilds
#                     every CI on every run, as before. A full reconcile that finds a CI the daily builds should have
#                     changed says so in the run log.
#   When to change:   Set 0 while support investigates a CI that looks out of date; otherwise keep the default.
#   Risk:             None to the data: a change to what the CIs are built from always rebuilds every CI on the next
#                     run; the setting only decides how often an unchanged estate is rebuilt in full. Reversible at
#                     once.
#   Recommended:      Keep the default (7).
#   More info:        https://invardia.com/docs/si/settings/SI_CiBuild_FullReconcileDays/
#
# CI build: time limit for the rules of one asset  [SI_CiRulesBudgetSeconds]  (advanced, seconds)
#   What it is for:   How long the rules of one asset may take in the CI build (correlation) before the build goes on
#                     with the next asset. Applying the rules to one asset normally takes milliseconds; an asset with
#                     unusually large data could otherwise hold the whole build, and with it every step after it.
#   Default:          60 seconds per asset
#   If you change it: An asset that takes longer is not fully evaluated in that run. Nothing of the half evaluation is
#                     stored: Risk Analysis and the views keep what the asset had from its last complete evaluation,
#                     and a new asset is left out until it is fully evaluated. It is named in the run log, counted ("N
#                     asset(s) not fully evaluated in this run") and evaluated again in the next run. A higher value
#                     gives a slow asset more time; 0 removes the limit, and one asset can then hold the build for as
#                     long as its rules take.
#   When to change:   Raise it when the run log names the same assets as not fully evaluated run after run and they
#                     must be included before the cause is fixed; otherwise keep the default.
#   Risk:             None to the data either way: an asset that is not fully evaluated keeps its last complete
#                     result, and no tier or finding is based on part of the rules. A very high value, or 0, lets one
#                     asset hold the build and with it the steps after it. Reversible at once.
#   Recommended:      Keep the default (60).
#   More info:        https://invardia.com/docs/si/settings/SI_CiRulesBudgetSeconds/
#
# Configuration backup job schedule  [SI_Bootstrap_ScheduleConfigBackup]  (advanced)
#   What it is for:   Schedule (cron, UTC) of the container job that backs up your configuration once a day.
#   Default:          Daily at 18:00 UTC: after the working day, before the evening pipeline, never at the 23:00
#                     update.
#   If you change it: Container setup gives the configuration backup job this schedule on its next run. The job is
#                     never a step of the pipeline and never runs twice at the same time.
#   When to change:   Only if your configuration changes happen at another time of day, or the pipeline starts
#                     earlier.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only if your configuration changes happen at another time of
#                     day, or the pipeline starts earlier.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleConfigBackup/
#
# Endpoint job containers in parallel  [SI_Bootstrap_ParallelismEndpoint]  (advanced, containers)
#   What it is for:   How many containers the endpoint profiling job runs side by side; also used for jobs that have
#                     no parallel setting of their own.
#   Default:          1 container
#   If you change it: More containers split the collection and finish sooner, at higher compute cost per run. It also
#                     applies to other collection jobs without their own setting, such as public IP.
#   When to change:   Only for large estates where the endpoint job runs too long.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only for large estates where the endpoint job runs too long.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ParallelismEndpoint/
#
# Identity job containers in parallel  [SI_Bootstrap_ParallelismIdentity]  (advanced, containers)
#   What it is for:   How many containers the identity profiling job runs side by side in each run.
#   Default:          1 container
#   If you change it: More containers split the identity collection and finish sooner, at higher compute cost per run
#                     and more parallel load on Microsoft Graph.
#   When to change:   Only for large directories where the job runs too long.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only for large directories where the job runs too long.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ParallelismIdentity/
#
# Maximum queue-driven workers  [SI_Bootstrap_KedaMaxReplicas]  (advanced, containers)
#   What it is for:   The most worker containers that may run at the same time per engine when queue-driven scaling is
#                     on.
#   Default:          30 workers
#   If you change it: Higher finishes large collections faster but runs more containers at once, raising peak cost and
#                     load on the source APIs. Has no effect unless queue-driven scaling is on.
#   When to change:   Only with queue-driven scaling, to speed up very large tenants or cap cost.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only with queue-driven scaling, to speed up very large tenants
#                     or cap cost.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_KedaMaxReplicas/
#
# Queue-driven scaling  [SI_Bootstrap_UseKEDA]  (advanced)
#   What it is for:   Runs the collection engines as queue-driven workers that scale from zero with the amount of
#                     work, instead of one scheduled job each.
#   Default:          Off: one scheduled job per engine.
#   If you change it: When on, each collection engine gets a scheduler and a worker job that scales up to the worker
#                     maximum, speeding up large tenants. Risk analysis and asset tagging are not affected.
#   When to change:   Only for very large tenants where scheduled jobs run too long.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only for very large tenants where scheduled jobs run too long.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_UseKEDA/
#
# Risk Analysis on queue workers  [SI_Bootstrap_RaScaleOut]  (advanced)
#   What it is for:   Runs the Risk Analysis Detailed reports on queue workers, several reports at the same time,
#                     instead of one after another in one job.
#   Default:          On wherever queue scaling and the managed identity let it run; otherwise the reports run in
#                     their job.
#   If you change it: On: setup and every update give the install a worker job that scales from zero with the reports
#                     to run, and the Detailed run finishes sooner; the stored findings and what Log Analytics
#                     receives are the same. Off: the reports run one after another in the Risk Analysis job.
#   When to change:   Only switch it off if support asks you to.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only switch it off if support asks you to.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_RaScaleOut/
#
# Risk Analysis workers at once  [SI_Bootstrap_RaMaxWorkers]  (advanced, containers)
#   What it is for:   How many Risk Analysis queue workers may run Detailed reports at the same time.
#   Default:          4 workers
#   If you change it: More workers finish a long Risk Analysis sooner but run more containers at once. The workers
#                     share the parts one Risk Analysis job may ask Defender at a time (each at least one), so more
#                     workers do not multiply what Defender is asked at once. Has no effect when the Risk Analysis
#                     workers are off.
#   When to change:   Rarely; only when Risk Analysis Detailed runs too long on a very large tenant.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Rarely; only when Risk Analysis Detailed runs too long on a
#                     very large tenant.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_RaMaxWorkers/
#
# Schema discovery containers in parallel  [SI_Bootstrap_ParallelismSchemaDiscovery]  (advanced, containers)
#   What it is for:   How many containers the schema discovery job runs side by side in each run.
#   Default:          1 container
#   If you change it: More containers finish schema discovery sooner at higher compute cost. Only matters when schema
#                     discovery is in the list of container jobs, which it is not by default.
#   When to change:   Rarely; only when schema discovery is deployed and runs too long.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Rarely; only when schema discovery is deployed and runs too
#                     long.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ParallelismSchemaDiscovery/
#
# Schema discovery schedule  [SI_Bootstrap_ScheduleSchemaDiscovery]  (advanced)
#   What it is for:   When the schema discovery container job runs, as a cron expression in UTC.
#   Default:          Sundays at 03:00 UTC
#   If you change it: Sets how often schema discovery runs. Only used when schema discovery is in the list of
#                     container jobs, which it is not by default.
#   When to change:   Only when schema discovery is deployed and you want another day or time.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only when schema discovery is deployed and you want another
#                     day or time.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ScheduleSchemaDiscovery/
#
# Start jobs right after setup  [SI_Bootstrap_TriggerNowAfter]  (advanced)
#   What it is for:   Makes container setup start each job once immediately after creating or updating it.
#   Default:          Off: jobs wait for their schedule.
#   If you change it: When on, every deployed job runs at once, giving results straight away but running all engines
#                     at the same time, out of their normal order, with the compute and API load that brings.
#   When to change:   For a first test run after setup; leave off otherwise.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: For a first test run after setup; leave off otherwise.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_TriggerNowAfter/
#
# Write the risk trend at the end of Risk Analysis  [SI_Trend_AtEndOfRiskAnalysis]  (advanced)
#   What it is for:   Whether a Risk Analysis summary run writes the day's risk trend row itself, from the rows it has
#                     just published.
#   Default:          On
#   If you change it: On: one trend row per day, written by Risk Analysis -- the separate risk trend job is not needed
#                     and waits for a run by hand. Off: no trend row unless the risk trend job runs. A run that was
#                     partial writes no row (a gap, not a drop).
#   When to change:   Only when you run the risk trend job on its own schedule instead.
#   Risk:             Changes when or whether jobs run: a job that does not run leaves its data older until it runs
#                     again. Reversible at once; nothing already collected is changed.
#   Recommended:      Keep the default. Change it when: Only when you run the risk trend job on its own schedule
#                     instead.
#   More info:        https://invardia.com/docs/si/settings/SI_Trend_AtEndOfRiskAnalysis/
#
# ----------------------------------------------------------------------------------------------------
# Collection scope & limits
# What each collection includes or skips, and the limits that keep runs fast. Engine tags show which
# collection a setting belongs to.
# ----------------------------------------------------------------------------------------------------
#
# Active asset freshness window  [SI_ActiveStaleDays]  (days)
#   What it is for:   Sets how recently an asset must have been seen (or an identity signed in) to count as active.
#   Default:          30 days
#   If you change it: Lower values mark more assets inactive; inactive endpoints are left out of the profile output
#                     and identities without a recent sign-in are flagged inactive. Higher values keep older, possibly
#                     retired assets in reports.
#   When to change:   Most installs keep 30. Lower for tighter hygiene reporting; raise if devices are often offline
#                     for long periods.
#   Risk:             A shorter value marks more assets inactive: devices not seen within it leave the profiles and
#                     reports (a device offline for a week or two can drop out). Reversible: the next run includes
#                     them again.
#   Recommended:      30 days.
#   More info:        https://invardia.com/docs/si/settings/SI_ActiveStaleDays/
#
# Asset decisions file  [SI_AssetDecisionsPath]
#   What it is for:   Path to your file of asset decisions: tier overrides, exceptions and exemptions applied during
#                     profiling.
#   Default:          The asset decisions file in the config folder and in your enrichment data folder, if they exist.
#   If you change it: When set, only this file is read and the default locations are ignored. A path that does not
#                     exist is reported, and none of your decisions are applied.
#   When to change:   When you keep the decisions file outside the installation folder.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you keep the decisions file outside the installation
#                     folder.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetDecisionsPath/
#
# Defender for Cloud recommendations  [SI_CollectDefenderRecommendations]
#   What it is for:   Whether the Azure engine also collects every unhealthy Defender for Cloud recommendation into
#                     its own table for the Risk Analysis reports.
#   Default:          On: recommendations are collected on every Azure run
#   If you change it: Setting it to false skips the recommendations step: the Azure run is a little shorter and
#                     ingests less data, but reports have no Defender for Cloud recommendation findings.
#   When to change:   Turn off only if you do not use Defender for Cloud or do not want these findings.
#   Risk:             Defender for Cloud recommendations are no longer collected: those findings disappear from the
#                     reports (they are not fixed). Reversible: the next Azure run collects them again.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/SI_CollectDefenderRecommendations/
#
# Disabled accounts and devices: CI correlation  [SI_DisabledAssets_Correlate]
#   What it is for:   Whether disabled users, service principals, managed identities and computers take part in the
#                     correlation that builds configuration items (CIs).
#   Default:          On: disabled assets are correlated into CIs
#   If you change it: Off keeps disabled assets out of the CI build: no CI is built or changed from them, and the
#                     findings of an existing CI are kept as they are (never resolved or closed) until the account is
#                     enabled again. Has no effect while collection of disabled assets is off -- they are not
#                     collected then. Each run logs how many were left out.
#   When to change:   Turn it off when disabled assets should not appear as CIs or reach your CMDB.
#   Risk:             Disabled assets are not built into CIs from the next run; findings of existing CIs are kept
#                     (never closed). Reversible: the next run correlates them again.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/SI_DisabledAssets_Correlate/
#
# Disabled accounts and devices: collect them  [SI_DisabledAssets_Collect]
#   What it is for:   Whether disabled users, service principals and managed identities, and disabled computers are
#                     collected from the sources. Disabled means the account is disabled in its own directory (Entra
#                     accountEnabled false, AD account disabled); it is never guessed from inactivity.
#   Default:          On: disabled accounts and devices are collected
#   If you change it: Off leaves them out of the profiles, so no later stage can see them -- the correlation, Risk
#                     Analysis, finding actions and connector settings below then have no effect for disabled assets.
#                     Their open findings, actions and tickets are kept as they are (never resolved or closed). The
#                     state is read on every run: an account that is enabled again is collected again on the next run.
#                     Each run logs how many were left out.
#   When to change:   Turn it off only if you never want to see disabled accounts or devices anywhere in
#                     SecurityInsight.
#   Risk:             Disabled accounts and devices disappear from profiles, CIs, reports and connectors from the next
#                     run; their open findings and tickets are kept (never closed). Reversible: the next run collects
#                     them again.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/SI_DisabledAssets_Collect/
#
# Disabled accounts and devices: connectors and exports  [SI_DisabledAssets_Connectors]
#   What it is for:   Whether connectors and exports send disabled users, service principals, managed identities and
#                     computers out of SecurityInsight (ServiceNow, Jira, risk register, CMDB, data exports).
#   Default:          Off: connectors and exports leave disabled assets out
#   If you change it: Off leaves disabled assets out of what is sent; a ticket or record already sent for one is kept
#                     as it is (never resolved or closed because the asset was left out) and carries on when the
#                     account is enabled again. On sends them like any other. Has no effect while collection of
#                     disabled assets is off. Each run logs how many were left out.
#   When to change:   Turn it on when your CMDB or ticketing system should also hold disabled accounts and devices.
#   Risk:             On sends disabled accounts and devices to your CMDB, ticketing systems and exports. Reversible
#                     for future runs; records already written there stay.
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_DisabledAssets_Connectors/
#
# Disabled accounts and devices: finding actions  [SI_DisabledAssets_StateActions]
#   What it is for:   Whether the finding and vulnerability lifecycle acts on disabled assets: opening, resolving and
#                     closing findings, the close-loop mail and opening or closing tickets.
#   Default:          Off: findings of disabled assets are kept as they are
#   If you change it: Off freezes the findings of a disabled asset: they are shown as excluded (disabled), never
#                     resolved or closed, and a missing finding is not counted as fixed. When the account is enabled
#                     again, the same findings carry on. On treats disabled assets like any other. Has no effect while
#                     collection of disabled assets is off. Each run logs how many were left out.
#   When to change:   Turn it on when findings on disabled assets should be opened and closed like any other.
#   Risk:             On lets the lifecycle resolve and close findings and tickets of disabled assets like any other,
#                     and a finding that is missing for a disabled asset can then be closed. Reversible for future
#                     runs; what was closed stays closed.
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_DisabledAssets_StateActions/
#
# Disabled accounts and devices: Risk Analysis  [SI_DisabledAssets_RiskAnalysis]
#   What it is for:   Whether the Risk Analysis reports include disabled users, service principals, managed identities
#                     and computers.
#   Default:          Off: the reports leave disabled assets out, except the reports where the disabled state is the
#                     finding
#   If you change it: On lets every report see disabled assets. Two reports always see them, whatever this says,
#                     because the disabled state is the finding there: a disabled guest still holding a privileged
#                     role, and a disabled service principal still owning a publicly reachable resource. Reports that
#                     ask about usable accounts (for example accounts without MFA) keep their own enabled filter. Has
#                     no effect while collection of disabled assets is off.
#   When to change:   Turn it on when you also want findings for disabled accounts and devices in the reports, for
#                     example while cleaning them up.
#   Risk:             On adds findings for disabled accounts and devices to the reports: more rows to read. Off is the
#                     default; the two reports where the disabled state is the finding always include them. Reversible
#                     at once.
#   Recommended:      Off, unless you are cleaning up disabled accounts and devices.
#   More info:        https://invardia.com/docs/si/settings/SI_DisabledAssets_RiskAnalysis/
#
# Extra public IPs to scan  [SI_PublicIP_ExtraTargets]  (engine: publicip)
#   What it is for:   A list of additional public IP addresses to check every run, such as partner or supply-chain
#                     addresses.
#   Default:          Empty: only discovered addresses are checked.
#   If you change it: Listed addresses are always added to the candidate set and looked up in Shodan, adding a lookup
#                     per address. They carry no tier or CMDB details unless given in the public IP schema overlay
#                     file.
#   When to change:   When you want to watch external addresses you care about but that SecurityInsight cannot
#                     discover.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you want to watch external addresses you care about but
#                     that SecurityInsight cannot discover.
#   More info:        https://invardia.com/docs/si/settings/SI_PublicIP_ExtraTargets/
#
# Highest tier to check  [SI_Shodan_TierMax]  (engine: publicip)
#   What it is for:   Checks public IPs only for assets at or below this privilege tier (0 is most critical).
#   Default:          3: all tiers (0 to 3).
#   If you change it: Lowering it, for example to 1, checks only the most critical assets, cutting Shodan lookups and
#                     cost but leaving lower-tier exposure unchecked.
#   When to change:   To control Shodan cost on a small plan.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: To control Shodan cost on a small plan.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_TierMax/
#
# Identity sign-in details  [SI_EnableSignInEnrich]
#   What it is for:   Lets the identity engine add sign-in statistics per user, such as sign-in counts, apps, IP
#                     addresses and countries.
#   Default:          On.
#   If you change it: Turning it off skips the sign-in log queries, so runs are faster and cheaper, but sign-in
#                     counts, apps and locations stay empty. Last sign-in date still comes from Entra.
#   When to change:   Turn off if sign-in queries are too slow or costly in your tenant.
#   Risk:             Sign-in counts, apps and locations stay empty: findings that depend on sign-in activity lose
#                     that context. Reversible: the next run collects it again.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/SI_EnableSignInEnrich/
#
# Include inactive endpoints  [SI_IncludeInactive_Endpoint]
#   What it is for:   Turns off the filter that leaves out stale or offboarded devices, so every known device is
#                     published.
#   Default:          Off: devices not seen by any source within the stale-days window are left out
#   If you change it: On publishes every device, including stale registrations and offboarded machines: more rows,
#                     more ingested data, and more noise in reports. Useful when cleaning up stale devices.
#   When to change:   When you want to find and clean up stale or ghost devices.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you want to find and clean up stale or ghost devices.
#   More info:        https://invardia.com/docs/si/settings/SI_IncludeInactive_Endpoint/
#
# Include inactive identities  [SI_IncludeInactive_Identity]
#   What it is for:   Turns off the one identity filter left: Microsoft-published applications this tenant granted
#                     nothing. Every user (disabled accounts and guests too) and every service principal and managed
#                     identity the tenant owns is always published.
#   Default:          Off: only Microsoft apps this tenant granted nothing are left out
#   If you change it: On publishes the Microsoft-published applications too (hundreds in most tenants): more rows,
#                     more ingested data, and more noise in reports.
#   When to change:   When you need a complete identity inventory, for example for an audit.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you need a complete identity inventory, for example for
#                     an audit.
#   More info:        https://invardia.com/docs/si/settings/SI_IncludeInactive_Identity/
#
# Include Microsoft service principals  [SI_IncludeFirstPartySpns]
#   What it is for:   Whether the identity engine includes Microsoft's own built-in service principals in its
#                     inventory.
#   Default:          On: Microsoft service principals are included.
#   If you change it: Turning it off drops the hundreds of Microsoft-published service principals, giving a smaller,
#                     less noisy inventory, but privileged ones among them are no longer reported.
#   When to change:   Turn off if Microsoft service principals add noise you do not want in reports.
#   Risk:             Microsoft-published service principals are left out -- including privileged ones, whose exposure
#                     then disappears from the reports. Reversible: the next run includes them again.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/SI_IncludeFirstPartySpns/
#
# Only Defender-active endpoints  [SI_RequireMdeActive_Endpoint]
#   What it is for:   Narrows the endpoint inventory to devices that Defender for Endpoint reports as active or
#                     recently seen.
#   Default:          Off: a device seen recently by Defender, Exposure Management or Entra is kept
#   If you change it: On drops devices known only to Exposure Management or Entra, such as some Azure VMs, personal
#                     and IoT devices: fewer rows, but less coverage. Ignored when SI_IncludeInactive_Endpoint is on.
#   When to change:   Only if you want the inventory to match the Defender portal's active device list.
#   Risk:             Drops every device known only to Exposure Management or Entra (some Azure VMs, personal and IoT
#                     devices): those devices disappear from profiles and reports, and their exposure with them.
#                     Reversible: the next run includes them again.
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_RequireMdeActive_Endpoint/
#
# Public IP discovery source  [SI_PublicIP_DiscoverySource]  (engine: publicip)
#   What it is for:   Chooses where the engine finds public IP addresses to check: classified assets (profile-cl),
#                     Azure and Defender inventory (arg-eg), or both (union).
#   Choices:          'profile-cl' (Classified servers (and your extra addresses)); 'arg-eg' (Azure and Defender
#                     inventory); 'union' (Both)
#   Default:          profile-cl: public IPs of already classified servers, plus your extra targets.
#   If you change it: arg-eg covers every Azure public IP and Defender node but without tier or CMDB context; union
#                     checks everything. Broader modes mean more addresses, longer runs and more Shodan lookups.
#                     Unknown values fall back to profile-cl.
#   When to change:   When you want Azure public IPs that are not attached to a classified asset to be checked too.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you want Azure public IPs that are not attached to a
#                     classified asset to be checked too.
#   More info:        https://invardia.com/docs/si/settings/SI_PublicIP_DiscoverySource/
#
# Require recent identity sign-in  [SI_RequireRecentSignIn_Identity]
#   What it is for:   Restores the older, stricter rule that an identity must have signed in recently to be published.
#   Default:          Off: identities without recent or available sign-in data are still published
#   If you change it: On also drops every identity without a sign-in within SI_ActiveStaleDays, including ones whose
#                     sign-in history is unavailable: fewer rows, but real accounts may be missing.
#   When to change:   Only if you need the behaviour of the previous major version.
#   Risk:             Drops every identity without a recent or available sign-in, including privileged accounts that
#                     are rarely used: they disappear from profiles and reports. Reversible: the next run includes
#                     them again.
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_RequireRecentSignIn_Identity/
#
# Shodan API key  [SI_Shodan_ApiKey]  (engine: publicip, secret)
#   What it is for:   The Shodan API key used to look up what is exposed on your public IP addresses.
#   Default:          Not set: older SHODAN_ApiKey name or SHODAN_API_KEY environment variable is tried; else Shodan
#                     lookups are skipped.
#   If you change it: With a key, each address is enriched with open ports, services and vulnerabilities from Shodan,
#                     using your Shodan plan's quota. Without it the engine still writes rows, but every Shodan field
#                     is empty.
#   When to change:   Set it when you use the public IP engine; rotate it when you reset the key in Shodan.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Set it when you use the public IP engine; rotate it when you
#                     reset the key in Shodan.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_ApiKey/
#
# Shodan fresh scans  [SI_Shodan_ForceFreshScan]  (engine: publicip)
#   What it is for:   Asks Shodan to actively re-scan your addresses before reading results, instead of using only
#                     data Shodan already has.
#   Default:          Off: cached and existing Shodan data only, no scan credits spent.
#   If you change it: On, a batch scan is submitted (at most once per fresh scan interval) and the run waits for it;
#                     if it does not finish in time the run writes no rows and the next run picks it up. Spends Shodan
#                     scan credits.
#   When to change:   When you need current results and your Shodan plan has scan credits; schedule extra runs a few
#                     hours apart.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you need current results and your Shodan plan has scan
#                     credits; schedule extra runs a few hours apart.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_ForceFreshScan/
#
# Shodan monthly credit cap  [SI_ShodanMonthlyCreditCap]  (engine: publicip, credits)
#   What it is for:   A safety ceiling on the Shodan scan credits spent per month, by per-address on-demand scans and
#                     by the batch fresh scan.
#   Default:          4000 credits per month.
#   If you change it: A scan that would take the month past the cap is refused (the batch fresh scan counts one credit
#                     per address), and so is any scan while the month's count cannot be read. Normal host lookups are
#                     not limited.
#   When to change:   Match it to your Shodan plan's monthly scan credits.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Match it to your Shodan plan's monthly scan credits.
#   More info:        https://invardia.com/docs/si/settings/SI_ShodanMonthlyCreditCap/
#
# Subscriptions skipped for identity roles  [SI_AzureSubscriptionExcludePatterns]  (engine: identity)
#   What it is for:   Subscription names (wildcards allowed) skipped when the identity engine scans Azure role
#                     assignments.
#   Default:          No subscriptions skipped; every visible subscription is scanned.
#   If you change it: Role assignments in matching subscriptions are ignored, which speeds up the scan but hides
#                     privileges granted there, so identities may get a lower tier than they really hold.
#   When to change:   To skip personal, trial or lab subscriptions that do not matter for privilege.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: To skip personal, trial or lab subscriptions that do not
#                     matter for privilege.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureSubscriptionExcludePatterns/
#
# Asset fingerprint cache  [SI_FingerprintCache_Enabled]  (advanced)
#   What it is for:   Remembers each asset between runs so incremental runs can skip assets that are not yet due for
#                     re-processing.
#   Default:          Off: every asset is processed on every run
#   If you change it: On can shorten incremental runs, but adds storage writes, and it has no effect on full runs. Off
#                     is safe: every row is still produced.
#   When to change:   Only on installs that run incremental (not full) runs and want shorter run times.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only on installs that run incremental (not full) runs and want
#                     shorter run times.
#   More info:        https://invardia.com/docs/si/settings/SI_FingerprintCache_Enabled/
#
# Azure access identity types  [SI_AzureExposureGraph_IdentityLabels]  (advanced)
#   What it is for:   Which exposure graph node types are treated as identities when mapping who can access Azure
#                     resources.
#   Default:          User, service principal, managed identity and group.
#   If you change it: Changes which kinds of identity are counted as having access to Azure resources. Leaving a type
#                     out hides access held by that kind of identity.
#   When to change:   Only if your Defender exposure graph uses non-standard node names.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if your Defender exposure graph uses non-standard node
#                     names.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureExposureGraph_IdentityLabels/
#
# Azure access relationship types  [SI_AzureExposureGraph_AccessEdgeLabels]  (advanced)
#   What it is for:   Which exposure graph relationship types count as an identity having access to an Azure resource.
#   Default:          The shipped list of 6 relationship types, such as 'has access to' and 'has permissions to'.
#   If you change it: Changes which access paths are counted when the engine works out which privileged identities can
#                     reach each Azure resource. A list that misses real relationship names leaves those counts empty.
#   When to change:   Only if your Defender exposure graph uses non-standard relationship names.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if your Defender exposure graph uses non-standard
#                     relationship names.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureExposureGraph_AccessEdgeLabels/
#
# Azure asset limit  [SI_AssetLimit_Azure]  (engine: azure, advanced, assets)
#   What it is for:   Caps how many discovered Azure resources the Azure engine processes in one run, for testing.
#   Default:          No limit (every discovered resource).
#   If you change it: Keeps only the first N resources after discovery, so runs are faster but the inventory and every
#                     report built on it are incomplete. A command-line value wins over this.
#   When to change:   Never in production; only for quick local tests.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Never in production; only for quick local tests.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetLimit_Azure/
#
# Azure exposure graph resource types  [SI_AzureExposureGraph_ResourceLabels]  (advanced)
#   What it is for:   Which exposure graph node types are treated as Azure resources for extra exposure details and
#                     access mapping.
#   Default:          The shipped list of 16 resource types; access mapping also includes every other Azure resource
#                     type.
#   If you change it: Restricts exposure detail lookups and access mapping to the types you list. Once set, access
#                     mapping no longer covers every other Azure resource type, so access counts can shrink.
#   When to change:   Only if your Defender exposure graph uses non-standard node names.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if your Defender exposure graph uses non-standard node
#                     names.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureExposureGraph_ResourceLabels/
#
# Azure exposure graph type list  [SI_AzureEgTypeAllowlist]  (advanced)
#   What it is for:   Fixes which Azure resource types are read from the Defender exposure graph, the Azure engine's
#                     main source.
#   Default:          Every Azure type in the exposure graph, minus role/policy assignments, locks and diagnostic
#                     settings.
#   If you change it: Replaces the automatically discovered type list entirely, so only the types you list are
#                     collected from the exposure graph. New Azure types are no longer picked up automatically, and
#                     the built-in exclusion of non-asset types no longer applies.
#   When to change:   Only to narrow collection to specific types, for example in a very large estate.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only to narrow collection to specific types, for example in a
#                     very large estate.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureEgTypeAllowlist/
#
# Azure full re-run  [SI_ForceFullRun_Azure]  (engine: azure, advanced)
#   What it is for:   Makes the Azure engine reprocess every resource instead of skipping ones that have not changed
#                     since the last run.
#   Default:          Off: unchanged resources are skipped.
#   If you change it: Every resource is reclassified, so the run takes longer and, with AI on, costs more. Overrides
#                     the all-engine full re-run switch for this engine.
#   When to change:   Once after changing rules or the schema; then switch it back off.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Once after changing rules or the schema; then switch it back
#                     off.
#   More info:        https://invardia.com/docs/si/settings/SI_ForceFullRun_Azure/
#
# Azure Resource Graph row cap  [SI_AzureMaxResources]  (advanced, rows)
#   What it is for:   A safety cap on how many resources the Azure engine pulls from Azure Resource Graph in one run.
#   Default:          No cap of its own; Resource Graph's own limit still applies.
#   If you change it: Stops reading Resource Graph once the cap is reached, which shortens first runs in large estates
#                     and limits AI spend. Resources beyond the cap are missing unless the exposure graph returns
#                     them.
#   When to change:   For a first run in a very large estate; remove it afterwards.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: For a first run in a very large estate; remove it afterwards.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureMaxResources/
#
# Azure resource types to collect  [SI_AzureResourceTypes]  (advanced)
#   What it is for:   Restricts the Azure Resource Graph source to a hand-picked list of resource types.
#   Default:          Every resource type the sign-in identity can read.
#   If you change it: Only the listed types are read from Resource Graph, which lowers run time and data volume. Other
#                     types then come only from the exposure graph, so brand-new resources of those types may be
#                     missed.
#   When to change:   Only when you deliberately want a narrow Azure inventory.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only when you deliberately want a narrow Azure inventory.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureResourceTypes/
#
# Azure resource types to skip  [SI_AzureExcludeTypes]  (advanced)
#   What it is for:   Extra Azure resource types the Resource Graph source leaves out, on top of the built-in list of
#                     noisy types.
#   Default:          Only the built-in list of 7 noisy types (alerts, assessments, policy states and similar) is
#                     skipped.
#   If you change it: The types you list are added to the built-in skip list for the Resource Graph source, reducing
#                     data volume and run time. Resources of those types disappear from the Azure inventory unless the
#                     exposure graph also returns them.
#   When to change:   When a high-volume type adds noise to your Azure inventory.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When a high-volume type adds noise to your Azure inventory.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureExcludeTypes/
#
# Azure types not treated as assets  [SI_AzureEgNonAssetTypes]  (advanced)
#   What it is for:   Azure resource types from the exposure graph that are settings on other resources, not assets,
#                     and are left out of Azure collection.
#   Default:          Role and policy assignments and definitions, locks and diagnostic settings.
#   If you change it: Replaces the list. Removing a type brings those items back as Azure assets, which can greatly
#                     increase row counts and duplicates; adding a type removes it from collection.
#   When to change:   Only if you genuinely want one of these types profiled, or another type excluded.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if you genuinely want one of these types profiled, or
#                     another type excluded.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureEgNonAssetTypes/
#
# Azure VM to device tier linking off  [SI_DisableEndpointAzureCorrelation]  (advanced)
#   What it is for:   Stops the Azure engine from giving an Azure VM or Arc machine the same tier as its matching
#                     Defender device.
#   Default:          Off: an Azure VM takes the tier of the matching endpoint device.
#   If you change it: When on, Azure VMs and Arc machines keep their own Azure-side tier and lose the link to their
#                     endpoint record, so the same machine can show different tiers in the two views.
#   When to change:   Only while diagnosing a problem with this linking.
#   Risk:             Azure VMs and Arc machines lose the link to their endpoint record, so one machine can show two
#                     different tiers. Reversible at once (the next run links them again).
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_DisableEndpointAzureCorrelation/
#
# Endpoint asset limit  [SI_AssetLimit_Endpoint]  (engine: endpoint, advanced, assets)
#   What it is for:   Caps how many discovered devices the endpoint engine processes in one run, for testing.
#   Default:          No limit (every discovered device).
#   If you change it: Keeps only the first N devices after discovery, so runs are faster but the inventory and every
#                     report built on it are incomplete. A command-line value wins over this.
#   When to change:   Never in production; only for quick local tests.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Never in production; only for quick local tests.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetLimit_Endpoint/
#
# Endpoint full re-run  [SI_ForceFullRun_Endpoint]  (engine: endpoint, advanced)
#   What it is for:   Makes the endpoint engine reprocess every device instead of skipping ones that have not changed
#                     since the last run.
#   Default:          Off: unchanged devices are skipped.
#   If you change it: Every device is reclassified, so the run takes longer and, with AI on, costs more. Overrides the
#                     all-engine full re-run switch for this engine.
#   When to change:   Once after changing rules or the schema; then switch it back off.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Once after changing rules or the schema; then switch it back
#                     off.
#   More info:        https://invardia.com/docs/si/settings/SI_ForceFullRun_Endpoint/
#
# Full run for all profilers  [SI_ForceFullRun]  (advanced)
#   What it is for:   Makes every asset-profiling engine process all assets on the next run, ignoring the per-asset
#                     skip schedule and cached CMDB data.
#   Default:          Off
#   If you change it: Every asset is re-collected and re-classified, so runs take longer and use more AI calls when AI
#                     is on. A per-engine full-run setting that is on wins; a job's own SI_FORCE_FULL_RUN wins over
#                     both. Applies the same way on a VM and in container jobs.
#   When to change:   After changing rules or fixing bad cached data, when you want every asset refreshed at once.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: After changing rules or fixing bad cached data, when you want
#                     every asset refreshed at once.
#   More info:        https://invardia.com/docs/si/settings/SI_ForceFullRun/
#
# Identity asset limit  [SI_AssetLimit_Identity]  (engine: identity, advanced, assets)
#   What it is for:   Caps how many discovered users and service principals the identity engine processes in one run,
#                     for testing.
#   Default:          No limit (every discovered identity).
#   If you change it: Keeps only the first N identities after discovery, so runs are faster but the inventory and
#                     every report built on it are incomplete. A command-line value wins over this.
#   When to change:   Never in production; only for quick local tests.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Never in production; only for quick local tests.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetLimit_Identity/
#
# Identity exposure graph split size  [SI_EgIdentityBucketThreshold]  (advanced, rows)
#   What it is for:   Above this many identities of one kind, the identity engine reads the exposure graph in several
#                     smaller queries instead of one.
#   Default:          30000 identities.
#   If you change it: A lower value splits reads sooner: more queries, but each stays within response limits. A higher
#                     value risks a single oversized query failing in very large tenants.
#   When to change:   Only if exposure graph reads for identities fail or time out.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if exposure graph reads for identities fail or time out.
#   More info:        https://invardia.com/docs/si/settings/SI_EgIdentityBucketThreshold/
#
# Identity full re-run  [SI_ForceFullRun_Identity]  (engine: identity, advanced)
#   What it is for:   Makes the identity engine reprocess every identity instead of skipping ones that have not
#                     changed since the last run.
#   Default:          Off: unchanged identities are skipped.
#   If you change it: Every identity is reprocessed, so the run takes longer. Overrides the all-engine full re-run
#                     switch for this engine.
#   When to change:   Once after changing rules or the schema; then switch it back off.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Once after changing rules or the schema; then switch it back
#                     off.
#   More info:        https://invardia.com/docs/si/settings/SI_ForceFullRun_Identity/
#
# Public IP asset limit  [SI_AssetLimit_PublicIp]  (engine: publicip, advanced, assets)
#   What it is for:   Caps how many public IP addresses the public IP engine processes in one run, for testing.
#   Default:          No limit (every discovered public IP).
#   If you change it: Keeps only the first N addresses after discovery, so runs are faster and use fewer Shodan
#                     credits, but the inventory and reports are incomplete. A command-line value wins over this.
#   When to change:   Never in production; only for quick local tests.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Never in production; only for quick local tests.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetLimit_PublicIp/
#
# Public IP discovery lookback  [SI_Shodan_LookbackDays]  (engine: publicip, advanced, days)
#   What it is for:   How far back the engine looks in the endpoint and Azure profile tables to find classified assets
#                     with public IPs.
#   Default:          8 days.
#   If you change it: Each asset's latest snapshot within the window is used. A shorter window drops assets not seen
#                     recently; a longer one keeps retired assets in scope.
#   When to change:   When profiling runs less often than weekly.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When profiling runs less often than weekly.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_LookbackDays/
#
# Public IP force full run  [SI_ForceFullRun_PublicIp]  (engine: publicip, advanced)
#   What it is for:   Makes the public IP engine process every address, ignoring the per-tier re-check cadence, for
#                     this engine only.
#   Default:          Off; falls back to SI_ForceFullRun, which is also off.
#   If you change it: On, every address is re-processed on every run. It only changes anything when the fingerprint
#                     cache (SI_FingerprintCache_Enabled) is on; without it every address is processed anyway. More
#                     run time when it matters.
#   When to change:   Once after changing tier rules or the schema, then turn it off again.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Once after changing tier rules or the schema, then turn it off
#                     again.
#   More info:        https://invardia.com/docs/si/settings/SI_ForceFullRun_PublicIp/
#
# Re-check interval, tier 0  [SI_TierCadence_T0]  (advanced, hours)
#   What it is for:   How often tier 0 assets (domain controllers, break-glass and global admins) are re-processed
#                     when the per-asset skip schedule is in use.
#   Default:          12 hours
#   If you change it: A number is read as hours; text such as '3d' also works. Shorter keeps the most critical assets
#                     fresher but costs run time. Only applies with the fingerprint cache on and outside full runs.
#   When to change:   Rarely; only when you run incremental profiling with the fingerprint cache on.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Rarely; only when you run incremental profiling with the
#                     fingerprint cache on.
#   More info:        https://invardia.com/docs/si/settings/SI_TierCadence_T0/
#
# Re-check interval, tier 1  [SI_TierCadence_T1]  (advanced, hours)
#   What it is for:   How often tier 1 assets (production servers, privileged users) are re-processed when the
#                     per-asset skip schedule is in use.
#   Default:          24 hours
#   If you change it: A number is read as hours; text such as '3d' also works. Shorter means fresher data and longer
#                     runs. Only applies with the fingerprint cache on and outside full runs.
#   When to change:   Rarely; only when you run incremental profiling with the fingerprint cache on.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Rarely; only when you run incremental profiling with the
#                     fingerprint cache on.
#   More info:        https://invardia.com/docs/si/settings/SI_TierCadence_T1/
#
# Re-check interval, tier 2  [SI_TierCadence_T2]  (advanced, hours)
#   What it is for:   How often tier 2 assets (workstations, regular users) are re-processed when the per-asset skip
#                     schedule is in use.
#   Default:          3 days
#   If you change it: A number is read as hours; text such as '3d' also works. Shorter means fresher data and longer
#                     runs. Only applies with the fingerprint cache on and outside full runs.
#   When to change:   Rarely; only when you run incremental profiling with the fingerprint cache on.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Rarely; only when you run incremental profiling with the
#                     fingerprint cache on.
#   More info:        https://invardia.com/docs/si/settings/SI_TierCadence_T2/
#
# Re-check interval, tier 3  [SI_TierCadence_T3]  (advanced, hours)
#   What it is for:   How often tier 3 assets (test and development, externals, guests, unmanaged) are re-processed
#                     when the per-asset skip schedule is in use.
#   Default:          7 days
#   If you change it: A number is read as hours; text such as '7d' also works. Shorter means fresher data and longer
#                     runs. Only applies with the fingerprint cache on and outside full runs.
#   When to change:   Rarely; only when you run incremental profiling with the fingerprint cache on.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Rarely; only when you run incremental profiling with the
#                     fingerprint cache on.
#   More info:        https://invardia.com/docs/si/settings/SI_TierCadence_T3/
#
# Re-check interval, unknown tier  [SI_TierCadence_Default]  (advanced, hours)
#   What it is for:   How often an asset whose privilege tier is not yet known is re-processed when the per-asset skip
#                     schedule is in use.
#   Default:          24 hours
#   If you change it: Shorter intervals refresh such assets more often at the cost of run time; longer ones skip them
#                     more. Only applies when the fingerprint cache is turned on and the run is not a full run.
#   When to change:   Rarely; only when you run incremental profiling with the fingerprint cache on.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Rarely; only when you run incremental profiling with the
#                     fingerprint cache on.
#   More info:        https://invardia.com/docs/si/settings/SI_TierCadence_Default/
#
# Scan server IPs only  [SI_Shodan_ServerOnly]  (engine: publicip, advanced)
#   What it is for:   Limits endpoint-derived public IPs to servers, because a workstation's public IP is usually a
#                     home or mobile network you do not own.
#   Default:          On: only servers' public IPs are checked.
#   If you change it: Off adds workstation public IPs, which are mostly internet provider addresses: more lookups and
#                     results that do not describe your own exposure.
#   When to change:   Almost never.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Almost never.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_ServerOnly/
#
# Schema discovery hunting tables  [SI_SchemaTables]  (advanced)
#   What it is for:   List of Defender advanced-hunting tables whose columns schema discovery checks for new fields.
#   Default:          A shipped list of 17 high-signal tables (device, identity, alert, email, cloud app, exposure
#                     graph).
#   If you change it: Replaces the shipped list entirely. Fewer tables means a faster run but new fields elsewhere go
#                     unnoticed; tables you cannot query cause errors for that table.
#   When to change:   Only to add newly released tables or drop ones your licences do not include.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only to add newly released tables or drop ones your licences
#                     do not include.
#   More info:        https://invardia.com/docs/si/settings/SI_SchemaTables/
#
# Shodan cache age  [SI_ShodanCacheAgeDays]  (engine: publicip, advanced, days)
#   What it is for:   How long a stored Shodan result is reused before the address is looked up again.
#   Default:          7 days.
#   If you change it: Shorter means fresher data but more live Shodan calls and longer runs; longer saves calls but
#                     results can be out of date.
#   When to change:   When you need fresher exposure data or must save Shodan quota.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When you need fresher exposure data or must save Shodan quota.
#   More info:        https://invardia.com/docs/si/settings/SI_ShodanCacheAgeDays/
#
# Shodan call spacing  [SI_Shodan_ThrottleMs]  (engine: publicip, advanced, milliseconds)
#   What it is for:   Pause between live Shodan lookups so the engine stays within Shodan's rate limit.
#   Default:          1100 milliseconds (about one call per second).
#   If you change it: A lower value speeds up large runs but may hit Shodan's rate limit and cause failed lookups on
#                     lower plans. Cached lookups are not delayed.
#   When to change:   Lower it only if your Shodan plan allows faster calls.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Lower it only if your Shodan plan allows faster calls.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_ThrottleMs/
#
# Shodan call timeout  [SI_Shodan_TimeoutSec]  (engine: publicip, advanced, seconds)
#   What it is for:   How long each Shodan lookup or scan submission may take before it is abandoned.
#   Default:          15 seconds.
#   If you change it: Longer timeouts tolerate a slow service at the cost of longer runs; shorter ones fail faster,
#                     leaving that address without Shodan data for the run.
#   When to change:   Only if lookups time out on a slow network.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if lookups time out on a slow network.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_TimeoutSec/
#
# Shodan fresh scan interval  [SI_Shodan_FreshScanIntervalHours]  (engine: publicip, advanced, hours)
#   What it is for:   The minimum time between two fresh Shodan scans when fresh scans are on.
#   Default:          20 hours.
#   If you change it: Lower values submit new scans more often, spending more scan credits; higher values reuse the
#                     last scan longer. Only matters when SI_Shodan_ForceFreshScan is on.
#   When to change:   When your schedule or Shodan credit budget calls for more or fewer scans.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When your schedule or Shodan credit budget calls for more or
#                     fewer scans.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_FreshScanIntervalHours/
#
# Shodan last scan state file  [SI_Shodan_LastFreshScanPath]  (advanced)
#   What it is for:   Where the engine records when the last fresh Shodan scan finished.
#   Default:          A file in the solution's data folder.
#   If you change it: The interval check reads this file. Pointing it somewhere that is lost between runs means scans
#                     may be re-submitted early, spending extra credits.
#   When to change:   Only when the data folder is not kept between runs.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only when the data folder is not kept between runs.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_LastFreshScanPath/
#
# Shodan pending scan state file  [SI_Shodan_PendingScansPath]  (advanced)
#   What it is for:   Where the engine remembers a submitted Shodan scan that has not finished yet.
#   Default:          A file in the solution's data folder.
#   If you change it: The next run reads this file to collect the pending scan. If the file is lost between runs, the
#                     scan result is not picked up and a new scan may be submitted.
#   When to change:   Only when the data folder is not kept between runs.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only when the data folder is not kept between runs.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_PendingScansPath/
#
# Shodan scan poll interval  [SI_Shodan_ScanPollIntervalSec]  (engine: publicip, advanced, seconds)
#   What it is for:   How often the engine checks whether a submitted fresh Shodan scan has finished.
#   Default:          30 seconds.
#   If you change it: Shorter checks notice completion sooner but make more status calls; longer checks may wait past
#                     completion. Only used with fresh scans on.
#   When to change:   Rarely; the default suits most installs.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Rarely; the default suits most installs.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_ScanPollIntervalSec/
#
# Shodan scan wait limit  [SI_Shodan_ScanWaitMaxSec]  (engine: publicip, advanced, seconds)
#   What it is for:   How long one run waits for a submitted fresh Shodan scan to finish.
#   Default:          300 seconds (5 minutes).
#   If you change it: Longer waits make the run take longer but finish more scans in the same run; if the limit
#                     passes, the run writes no rows and the next run collects the scan.
#   When to change:   When scans routinely take longer than five minutes for your address count.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When scans routinely take longer than five minutes for your
#                     address count.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_ScanWaitMaxSec/
#
# Sign-in history window  [SI_SignInLookbackDays]  (advanced, days)
#   What it is for:   How many days of sign-in and device logon history the identity and endpoint enrichment look back
#                     over.
#   Default:          7 days.
#   If you change it: A longer window catches less frequent sign-ins and device users but makes the queries slower and
#                     costlier; a shorter one is cheaper but may miss occasional use.
#   When to change:   When weekly activity is too short a window for your users' patterns.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: When weekly activity is too short a window for your users'
#                     patterns.
#   More info:        https://invardia.com/docs/si/settings/SI_SignInLookbackDays/
#
# Sign-in query batch size  [SI_SignInBatchSize]  (advanced, users)
#   What it is for:   How many users are looked up in one sign-in log query during identity sign-in enrichment.
#   Default:          200 users per query.
#   If you change it: Larger batches mean fewer queries but each is heavier and may hit query size or memory limits;
#                     smaller batches are safer but slower.
#   When to change:   Only if sign-in queries fail on size limits or run too slowly.
#   Risk:             Changes what is collected from the next run: narrowing it means some assets or data are not
#                     collected, so they look absent in profiles, CIs and reports (absence is never read as fixed).
#                     Reversible: change it back; the next run collects again.
#   Recommended:      Keep the default. Change it when: Only if sign-in queries fail on size limits or run too slowly.
#   More info:        https://invardia.com/docs/si/settings/SI_SignInBatchSize/
#
# Use AI-proposed draft rules  [SI_LoadPendingRules]  (advanced)
#   What it is for:   Lets the profiling engines also load draft posture rules proposed by schema discovery, before
#                     anyone has reviewed them.
#   Default:          Off: only shipped and your own custom rules are used.
#   If you change it: When on, unreviewed AI-drafted rules also affect findings and tiers. This can add useful
#                     detections but also wrong or noisy results.
#   When to change:   Only for testing drafts in a lab; normally review and promote drafts instead.
#   Risk:             Unreviewed, AI-drafted rules change tiers and findings: wrong tiers or noisy findings can
#                     follow. Reversible: turn it off; the next run uses reviewed rules only.
#   Recommended:      Off; review pending rules and approve the good ones instead.
#   More info:        https://invardia.com/docs/si/settings/SI_LoadPendingRules/
#
# ----------------------------------------------------------------------------------------------------
# Risk Analysis reports
# What the Risk Analysis reports contain, how findings are filtered and scored, and where the
# reports go.
# ----------------------------------------------------------------------------------------------------
#
# Copy Risk Analysis report rows to Log Analytics (container jobs, at setup)  [SI_RiskAnalysis_SendToLogAnalytics]
#   What it is for:   Optional, at setup only: whether the Risk Analysis container jobs are made with the copy of
#                     their report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL) switched on. SecurityInsight
#                     itself does not need it: its pages read the results from its database. Off by default.
#   Default:          Not set: the jobs follow Copy Risk Analysis report rows to Log Analytics, which is off by
#                     default.
#   If you change it: On: the jobs are made with the copy on (see Copy Risk Analysis report rows to Log Analytics).
#                     Not set or off: the jobs follow that setting, off by default.
#   When to change:   Only when your own workbooks, Sentinel rules or KQL read the report rows in Log Analytics; leave
#                     it not set otherwise.
#   Risk:             Log Analytics ingestion cost for every report row, every run. SecurityInsight itself does not
#                     need the copy. Reversible: Copy Risk Analysis report rows to Log Analytics turns it off again.
#   Recommended:      Not set (off).
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_SendToLogAnalytics/
#
# Copy Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL)  [SendToLogAnalytics]  (engine: risk-analysis)
#   What it is for:   Optional. After each Risk Analysis run, copies its report rows into your Log Analytics workspace
#                     (SI_RiskAnalysis_Detailed_CL, and SI_RiskAnalysis_Summary_CL when the Summary report runs; the
#                     day's trend row in SI_Trend_CL), for your own workbooks, Sentinel or KQL. SecurityInsight itself
#                     does not need it: its pages, the data sync, the vulnerability connectors and the trends read the
#                     results from its database. On a large estate the copy takes a long time and adds Log Analytics
#                     ingestion cost. Off by default.
#   Default:          Off: the report rows are kept in the database only
#   If you change it: On: after every Risk Analysis run its report rows are also posted to SI_RiskAnalysis_Detailed_CL
#                     (SI_RiskAnalysis_Summary_CL for the Summary report), after the result is complete in the
#                     database, and the day's trend row to SI_Trend_CL. On a large estate that is close to an hour,
#                     and it costs ingestion for every row, every run. Off: nothing is copied; the Excel reports, the
#                     mail and everything SecurityInsight shows are unchanged. The Azure workbook in
#                     preview\AzureWorkbook reads the copy, so it needs it on.
#   When to change:   Only when your own workbooks, Sentinel rules or KQL queries read SI_RiskAnalysis_Detailed_CL,
#                     SI_RiskAnalysis_Summary_CL or SI_Trend_CL; leave off otherwise.
#   Risk:             Log Analytics ingestion cost for every report row, every run, and a longer run on a large
#                     estate. SecurityInsight itself does not need the copy: its pages, the data sync, the
#                     vulnerability connectors and the trends read the database. Reversible: turn it off and the next
#                     run copies nothing.
#   Recommended:      Off, unless your own workbooks, Sentinel rules or KQL read the report rows in Log Analytics.
#   More info:        https://invardia.com/docs/si/settings/SendToLogAnalytics/
#
# CVE maximum age  [SI_CVE_MaxPublishedAgeDays]  (days)
#   What it is for:   Limits the vulnerability (CVE) reports to vulnerabilities published within the last number of
#                     days.
#   Default:          Off: CVEs of every age are reported
#   If you change it: Any value above 0 removes older CVEs from the reports, making them shorter and faster, but old
#                     unpatched vulnerabilities are no longer shown.
#   When to change:   Only if you deliberately want to focus on recently published vulnerabilities.
#   Risk:             Any value above 0 hides older CVEs from the reports: old unpatched vulnerabilities -- often the
#                     most exploited -- become invisible to readers. Reversible at once.
#   Recommended:      0 (every CVE, whatever its age).
#   More info:        https://invardia.com/docs/si/settings/SI_CVE_MaxPublishedAgeDays/
#
# CVE minimum CVSS score  [SI_CVE_MinCvssScore]
#   What it is for:   Limits the vulnerability (CVE) reports to vulnerabilities at or above this CVSS score (0 to 10).
#   Default:          Off: CVEs of every score are reported
#   If you change it: A value above 0 removes lower-scored CVEs from the reports, making them shorter and faster but
#                     hiding those findings completely.
#   When to change:   Only if you want to focus on high-impact vulnerabilities, for example 7.0.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if you want to focus on high-impact vulnerabilities, for
#                     example 7.0.
#   More info:        https://invardia.com/docs/si/settings/SI_CVE_MinCvssScore/
#
# CVE minimum severity  [SI_CVE_MinSeverity]
#   What it is for:   Limits the vulnerability (CVE) reports to this severity and above: Critical, High or Medium.
#   Default:          Off: CVEs of every severity are reported
#   If you change it: Setting it removes all less severe CVEs from the reports. Shorter, faster reports, but those
#                     findings are not shown anywhere in the report. An unknown value is ignored.
#   When to change:   Only if you want the reports to focus on the most severe vulnerabilities.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if you want the reports to focus on the most severe
#                     vulnerabilities.
#   More info:        https://invardia.com/docs/si/settings/SI_CVE_MinSeverity/
#
# Default to Detailed mode  [RiskAnalysis_Detailed_Override]  (engine: risk-analysis)
#   What it is for:   Makes risk analysis run in Detailed mode unless Summary is asked for on the command line.
#   Default:          Off: runs default to Summary mode.
#   If you change it: On, scheduled runs produce one row per affected asset: larger Excel files, longer runs, more
#                     data ingested, and the Detailed mail recipients. Cannot be on together with
#                     RiskAnalysis_Summary_Override.
#   When to change:   When a host should produce Detailed reports by default.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: When a host should produce Detailed reports by default.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_Detailed_Override/
#
# Default to Summary mode  [RiskAnalysis_Summary_Override]  (engine: risk-analysis)
#   What it is for:   Makes risk analysis run in Summary mode unless Detailed is asked for on the command line.
#   Default:          Summary mode is already the launcher's default.
#   If you change it: On keeps runs in compact Summary mode with the Summary table and recipients. Cannot be on
#                     together with RiskAnalysis_Detailed_Override; set it off when you switch a host to Detailed.
#   When to change:   Rarely; only to make the Summary choice explicit.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; only to make the Summary choice explicit.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_Summary_Override/
#
# Excel workbook of the detailed report  [SI_RA_ExcelExport_Detailed]
#   What it is for:   Whether a Risk Analysis detailed run writes its results to an Excel workbook. The detailed
#                     results can hold millions of rows; they are in the web app.
#   Default:          Off
#   If you change it: On: the detailed run writes its workbook, as long as the results are not larger than a workbook
#                     can hold here -- above that no workbook is written and the Settings page shows the switch greyed
#                     out. Off: no workbook is written; the mail says the results are in the web app. Every row is in
#                     the web app and in Log Analytics either way.
#   When to change:   Switch it on only when someone needs the detailed results as a file.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Switch it on only when someone needs the detailed results as a
#                     file.
#   More info:        https://invardia.com/docs/si/settings/SI_RA_ExcelExport_Detailed/
#
# Excel workbook of the summary report  [SI_RA_ExcelExport_Summary]
#   What it is for:   Whether a Risk Analysis summary run writes its results to an Excel workbook (attached to the
#                     summary mail when it fits).
#   Default:          On
#   If you change it: On: the summary run writes its workbook. Off: no workbook is written; the mail says the results
#                     are in the web app. The results themselves are the same either way: every row is in the web app
#                     and in Log Analytics.
#   When to change:   Switch it off when nobody uses the summary workbook.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Switch it off when nobody uses the summary workbook.
#   More info:        https://invardia.com/docs/si/settings/SI_RA_ExcelExport_Summary/
#
# Exposure graph available in workspace  [SI_HasExposureGraphInLA]
#   What it is for:   Tells Risk Analysis that Defender exposure graph tables are mirrored into Log Analytics, so
#                     reports needing them can run.
#   Default:          Off: reports needing exposure graph tables are skipped
#   If you change it: On, Risk Analysis runs the reports that query exposure graph tables in the workspace. Turning it
#                     on without the tables present makes those reports fail.
#   When to change:   Turn on after enabling exposure graph table mirroring to Log Analytics.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Turn on after enabling exposure graph table mirroring to Log
#                     Analytics.
#   More info:        https://invardia.com/docs/si/settings/SI_HasExposureGraphInLA/
#
# Internet-exposed network ranges  [SI_InternetExposedRanges]
#   What it is for:   Address ranges that are reachable from the internet by design, such as a DMZ or an online
#                     landing zone. An asset with an address in them counts as internet exposed in the risk score.
#   Default:          None: only what Defender, Exposure Graph, Azure and Shodan report counts as exposure.
#   If you change it: Assets with an address in these ranges get the Internet exposed risk factor, which adds its
#                     impact (default 4) to the asset side of their findings' risk score.
#   When to change:   When you have network segments that face the internet that the providers do not flag, for
#                     example a DMZ behind a firewall NAT.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: When you have network segments that face the internet that the
#                     providers do not flag, for example a DMZ behind a firewall NAT.
#   More info:        https://invardia.com/docs/si/settings/SI_InternetExposedRanges/
#
# Only CVEs with known exploits  [SI_CVE_RequireExploit]
#   What it is for:   Limits the vulnerability (CVE) reports to vulnerabilities for which an exploit is known to
#                     exist.
#   Default:          Off: CVEs are reported whether or not an exploit is known
#   If you change it: When on, every CVE without a known exploit is removed from the reports. Much shorter reports,
#                     but unexploited vulnerabilities are hidden.
#   When to change:   Only if you want to prioritise vulnerabilities that are actively exploitable.
#   Risk:             Hides every vulnerability without a known exploit from the reports: real, patchable exposure
#                     becomes invisible to readers. Reversible at once (the next report shows them again).
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_CVE_RequireExploit/
#
# Patch cycle: catch-up after  [SI_PatchCycle_CatchUpDays]  (days)
#   What it is for:   When a finding counts as catch-up instead of being fixed in the monthly patch cycle: its fix was
#                     released (the month a "October 2026 Security Updates" text names -> that month's Patch Tuesday),
#                     or -- without one dated update -- the finding was first detected, more than this many days
#                     before the collection.
#   Default:          30 days.
#   If you change it: The Patch cycle column of every finding (In monthly cycle / Catch-up / No fix available /
#                     Unknown) and its filter use this number from the next Risk Analysis run; findings already stored
#                     keep the value they were given.
#   When to change:   Match your patch policy: e.g. 45 when monthly patches are allowed six weeks.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Match your patch policy: e.g. 45 when monthly patches are
#                     allowed six weeks.
#   More info:        https://invardia.com/docs/si/settings/SI_PatchCycle_CatchUpDays/
#
# Report upload destination  [ExportDestination]  (engine: risk-analysis)
#   What it is for:   Where Risk Analysis copies its Excel (and JSON) report after a run: an Azure Blob container URL
#                     or a Windows file share path.
#   Default:          On a server: no upload. In a container: the staging storage account's report folder
#   If you change it: Reports are also uploaded there; an existing file with the same name is first kept as a
#                     timestamped backup. The run's identity needs write access to that location.
#   When to change:   Set it when reports should land on a share or storage container people or tools read from.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Set it when reports should land on a share or storage
#                     container people or tools read from.
#   More info:        https://invardia.com/docs/si/settings/ExportDestination/
#
# Risk report JSON copy  [WriteJsonOutput]  (engine: risk-analysis)
#   What it is for:   Also writes the Risk Analysis report as a JSON file next to the Excel file, for tools that read
#                     machine-readable data.
#   Default:          Off (shipped default)
#   If you change it: On: an extra JSON file is written and uploaded with the Excel file; slightly more disk space and
#                     run time.
#   When to change:   Turn on when another tool or pipeline needs the report as JSON.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Turn on when another tool or pipeline needs the report as
#                     JSON.
#   More info:        https://invardia.com/docs/si/settings/WriteJsonOutput/
#
# Tenant domain in mails and links  [SI_TenantDomain]
#   What it is for:   Tenant domain shown in report mail subjects and used in the Azure portal links Risk Analysis
#                     adds to findings on Azure resources.
#   Default:          Read from Microsoft Graph for mail subjects; the tenant id is used in portal links
#   If you change it: Changes the domain in mail subjects and how Azure portal links are written; links work either
#                     way. A wrong domain mislabels the mails and opens links in the wrong directory.
#   When to change:   Optional; set it if the run cannot read the domain from Microsoft Graph, or you prefer another
#                     domain in subjects and links.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Optional; set it if the run cannot read the domain from
#                     Microsoft Graph, or you prefer another domain in subjects and links.
#   More info:        https://invardia.com/docs/si/settings/SI_TenantDomain/
#
# Automatic query splitting  [AutoBucketCount]  (engine: risk-analysis, advanced)
#   What it is for:   Splits large risk analysis queries into smaller parts automatically so results stay under
#                     Defender's row limit.
#   Default:          On.
#   If you change it: Off, large queries run at a fixed split and can exceed Defender's limit, giving incomplete or
#                     failed reports on big estates.
#   When to change:   Leave on; turn off only for troubleshooting.
#   Risk:             Large queries run at a fixed split and can exceed Defender's row limit: reports on big estates
#                     can be incomplete or fail. Reversible at once.
#   Recommended:      On.
#   More info:        https://invardia.com/docs/si/settings/AutoBucketCount/
#
# Azure share of overall score  [SI_RiskReport_GlobalWeight_Azure]  (advanced)
#   What it is for:   How much the Azure score counts in the overall risk score, relative to the other domains.
#   Default:          0.20
#   If you change it: A higher value makes Azure findings move the overall score more and the other domains less.
#                     Individual findings and their scores do not change.
#   When to change:   Only if Azure matters more or less to your organisation than the default balance.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if Azure matters more or less to your organisation than
#                     the default balance.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_GlobalWeight_Azure/
#
# Container report mode  [SI_RiskAnalysis_Mode]  (advanced)
#   What it is for:   Summary or Detailed, for the scheduled Summary report job; used only when the report template's
#                     name does not say which.
#   Default:          Summary
#   If you change it: Decides which report and Log Analytics table the job uses when a custom template does not name
#                     its mode. With the shipped templates the template decides and this has no effect; a separate job
#                     builds the Detailed report.
#   When to change:   Only with a custom report template whose name contains neither Summary nor Detailed.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only with a custom report template whose name contains neither
#                     Summary nor Detailed.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_Mode/
#
# Container summary report template  [SI_RiskAnalysis_ReportTemplate]  (advanced)
#   What it is for:   The report template the scheduled Summary risk-analysis container job uses.
#   Default:          Your default Summary template if set, otherwise the shipped Summary template
#   If you change it: The Summary job builds this template instead. A Detailed template here makes that job build a
#                     Detailed report.
#   When to change:   When the scheduled Summary job should use your own template.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: When the scheduled Summary job should use your own template.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_ReportTemplate/
#
# Critical finding weight  [SI_RiskReport_SeverityWeight_Critical]  (advanced)
#   What it is for:   How heavily a Critical finding lowers the score in the management risk score (on a 0 to 10
#                     scale, where 10 is the full penalty).
#   Default:          10
#   If you change it: A lower value makes Critical findings pull the domain and overall scores down less. Values above
#                     10 act as 10. The original per-finding risk score is not affected.
#   When to change:   Rarely; only to tune the management score to your own risk appetite.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; only to tune the management score to your own risk
#                     appetite.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_SeverityWeight_Critical/
#
# Defender query retries  [GraphQueryMaxRetries]  (engine: risk-analysis, advanced, attempts)
#   What it is for:   How many attempts risk analysis makes for a Defender advanced hunting query before giving up.
#   Default:          4 attempts.
#   If you change it: More attempts ride out longer outages but can make a failing run take much longer; fewer
#                     attempts fail sooner and risk missing report sections after a brief error.
#   When to change:   Raise it if transient Defender errors often break runs.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Raise it if transient Defender errors often break runs.
#   More info:        https://invardia.com/docs/si/settings/GraphQueryMaxRetries/
#
# Detailed report starting buckets  [SI_AutoBucketDefaultDetailed]  (advanced, buckets)
#   What it is for:   How many slices a Detailed Risk Analysis query is split into on the first try, before automatic
#                     splitting adapts.
#   Default:          2 slices.
#   If you change it: More slices avoid query timeouts on very large tenants but add overhead per slice, making small
#                     tenants slower. A per-report bucket count in the report template still wins.
#   When to change:   Only if Detailed reports repeatedly time out on a very large tenant.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if Detailed reports repeatedly time out on a very large
#                     tenant.
#   More info:        https://invardia.com/docs/si/settings/SI_AutoBucketDefaultDetailed/
#
# Detailed report template  [RiskAnalysis_ReportTemplate_Default_Detailed]  (engine: risk-analysis, advanced)
#   What it is for:   The report template used for Detailed runs when no template is named explicitly.
#   Default:          RiskAnalysis_Detailed.
#   If you change it: Detailed runs and the Detailed container job use the named template instead. A template name
#                     that does not exist makes the run fail.
#   When to change:   When you have created your own Detailed template.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: When you have created your own Detailed template.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_ReportTemplate_Default_Detailed/
#
# Detailed run mode  [Detailed]  (engine: risk-analysis, advanced)
#   What it is for:   Runs risk analysis in Detailed mode: one row per affected asset, with the Detailed template,
#                     table and mail recipients.
#   Default:          Off: Summary mode.
#   If you change it: Honoured when the engine is run directly. The launchers and containers decide the mode
#                     themselves (command-line switch, RiskAnalysis_Detailed_Override, or the template name) and
#                     replace this value.
#   When to change:   Use the -Detailed switch or RiskAnalysis_Detailed_Override instead.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Use the -Detailed switch or RiskAnalysis_Detailed_Override
#                     instead.
#   More info:        https://invardia.com/docs/si/settings/Detailed/
#
# Endpoint share of overall score  [SI_RiskReport_GlobalWeight_Endpoint]  (advanced)
#   What it is for:   How much the endpoint score counts in the overall risk score, relative to the other domains.
#   Default:          0.30
#   If you change it: A higher value makes endpoint findings move the overall score more and the other domains less.
#                     Individual findings and their scores do not change.
#   When to change:   Only if endpoints matter more or less to your organisation than the default balance.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if endpoints matter more or less to your organisation
#                     than the default balance.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_GlobalWeight_Endpoint/
#
# Excel report row limit  [SI_ExcelMaxDataRows]  (advanced, rows)
#   What it is for:   The most rows written to one worksheet of an Excel report; above it, the highest-risk rows are
#                     kept and the rest are left out of the workbook.
#   Default:          1,000,000 rows
#   If you change it: A lower value gives smaller, quicker workbooks but more rows are left out of the Excel file.
#                     Nothing is lost from the run: the JSON file and Log Analytics still hold every row.
#   When to change:   Most installs never should. Lower it if workbooks are too large to open or mail.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should. Lower it if workbooks are too
#                     large to open or mail.
#   More info:        https://invardia.com/docs/si/settings/SI_ExcelMaxDataRows/
#
# Graph reconnect interval  [GraphReconnectMaxAgeMinutes]  (engine: risk-analysis, advanced, minutes)
#   What it is for:   How old the Microsoft Graph sign-in may get before risk analysis signs in again before a query.
#   Default:          45 minutes.
#   If you change it: Shorter reconnects more often (small overhead); longer risks a sign-in expiring during long runs
#                     and queries failing.
#   When to change:   Only if long runs fail with expired sign-ins.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if long runs fail with expired sign-ins.
#   More info:        https://invardia.com/docs/si/settings/GraphReconnectMaxAgeMinutes/
#
# High severity weight  [SI_RiskReport_SeverityWeight_High]  (advanced)
#   What it is for:   Sets how heavily a High (or Medium-High) severity finding counts in the Risk Analysis score
#                     columns used for management reporting.
#   Default:          5 (Critical is 10, Medium 2, Low 1)
#   If you change it: A higher weight lowers the secure-score value of High findings and raises their share of the
#                     domain and overall scores. The original risk score columns are not affected.
#   When to change:   Most installs never should; change only to align the scores with your own risk model.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only to align the scores
#                     with your own risk model.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_SeverityWeight_High/
#
# Identity share of overall score  [SI_RiskReport_GlobalWeight_Identity]  (advanced)
#   What it is for:   How much the identity score counts in the overall risk score, relative to the other domains.
#   Default:          0.30
#   If you change it: A higher value makes identity findings move the overall score more and the other domains less.
#                     Individual findings and their scores do not change.
#   When to change:   Only if identities matter more or less to your organisation than the default balance.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if identities matter more or less to your organisation
#                     than the default balance.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_GlobalWeight_Identity/
#
# Low severity weight  [SI_RiskReport_SeverityWeight_Low]  (advanced)
#   What it is for:   Sets how heavily a Low severity finding counts in the Risk Analysis score columns used for
#                     management reporting.
#   Default:          1
#   If you change it: A higher weight lowers the secure-score value of Low findings and gives them more influence on
#                     the domain and overall scores. The original risk score columns are not affected.
#   When to change:   Most installs never should; change only to align the scores with your own risk model.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only to align the scores
#                     with your own risk model.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_SeverityWeight_Low/
#
# Medium severity weight  [SI_RiskReport_SeverityWeight_Medium]  (advanced)
#   What it is for:   Sets how heavily a Medium severity finding counts in the Risk Analysis score columns used for
#                     management reporting.
#   Default:          2
#   If you change it: A higher weight lowers the secure-score value of Medium findings and gives them more influence
#                     on the domain and overall scores. The original risk score columns are not affected.
#   When to change:   Most installs never should; change only to align the scores with your own risk model.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only to align the scores
#                     with your own risk model.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_SeverityWeight_Medium/
#
# Patch cycle: read Microsoft update release dates  [SI_PatchCycle_MsrcDates]  (advanced)
#   What it is for:   Reads the release date of each Microsoft update (by its KB number) from Microsoft's public
#                     Security Update Guide (api.msrc.microsoft.com, no sign-in), once a day, and keeps it in the
#                     install. Defender names the update and its KB but not when it was released.
#   Default:          On.
#   If you change it: On: a Microsoft fix's own release date decides In monthly cycle / Catch-up (an out-of-band
#                     update by its own date). Off: no call to api.msrc.microsoft.com; the month the update's name
#                     says (its Patch Tuesday) is used. A third-party fix uses the first detection either way.
#   When to change:   Turn off when the install must not call out to api.msrc.microsoft.com (a private network that
#                     does not allow it). A failed call is said once per run and the name rule is used.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Turn off when the install must not call out to
#                     api.msrc.microsoft.com (a private network that does not allow it). A failed call is said once
#                     per run and the name rule is used.
#   More info:        https://invardia.com/docs/si/settings/SI_PatchCycle_MsrcDates/
#
# Public IP share of overall score  [SI_RiskReport_GlobalWeight_PublicIP]  (advanced)
#   What it is for:   How much the public IP score counts in the overall risk score, relative to the other domains.
#   Default:          0.20
#   If you change it: A higher value makes public IP findings move the overall score more and the other domains less.
#                     Individual findings and their scores do not change.
#   When to change:   Only if internet exposure matters more or less to your organisation than the default balance.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if internet exposure matters more or less to your
#                     organisation than the default balance.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_GlobalWeight_PublicIP/
#
# Query split fan-out  [SI_AutoBucketSubFanOut]  (advanced, pieces)
#   What it is for:   How many smaller pieces a timed-out Risk Analysis query slice is split into each time.
#   Default:          4 pieces per split.
#   If you change it: More pieces shrink heavy slices faster but run more queries; fewer pieces mean more split
#                     rounds. No rows are lost either way.
#   When to change:   Rarely; only when tuning very large tenants with support.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; only when tuning very large tenants with support.
#   More info:        https://invardia.com/docs/si/settings/SI_AutoBucketSubFanOut/
#
# Query split upper limit  [AutoBucketMax]  (engine: risk-analysis, advanced, parts)
#   What it is for:   The most parts automatic query splitting may divide a risk analysis query into.
#   Default:          131072 parts (sized for very large estates).
#   If you change it: A lower limit stops probing sooner, so a query too large for that many parts can still fail or
#                     return incomplete rows; a higher limit is accepted but rarely needed.
#   When to change:   Almost never.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Almost never.
#   More info:        https://invardia.com/docs/si/settings/AutoBucketMax/
#
# Remember query split counts  [AutoBucketCache]  (engine: risk-analysis, advanced)
#   What it is for:   Saves how many parts each large risk analysis query had to be split into, so later runs start at
#                     the right number.
#   Default:          On: split counts are saved and reused.
#   If you change it: Off, every run probes again from one part upward, which makes large estates noticeably slower.
#                     On, a changed query is detected and re-probed automatically.
#   When to change:   Rarely; turn off only while troubleshooting query splitting.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; turn off only while troubleshooting query splitting.
#   More info:        https://invardia.com/docs/si/settings/AutoBucketCache/
#
# Replace Excel workbook each run  [OverwriteXlsx]  (engine: risk-analysis, advanced)
#   What it is for:   Deletes the previous risk analysis Excel workbook at the start of a run and writes a fresh one.
#   Default:          On: a fresh workbook every run.
#   If you change it: Off, the run writes into the existing workbook instead, so older content can remain alongside
#                     new results.
#   When to change:   Almost never.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Almost never.
#   More info:        https://invardia.com/docs/si/settings/OverwriteXlsx/
#
# Report storage container  [SI_RiskAnalysis_ExportContainer]  (advanced)
#   What it is for:   The storage container in your staging storage account where the risk-analysis container jobs
#                     save their reports.
#   Default:          sistaging
#   If you change it: Reports are saved to this container. It is ignored when a full export destination is set, or
#                     when no staging storage account is configured.
#   When to change:   Only if reports must be kept apart from the staging data.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if reports must be kept apart from the staging data.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_ExportContainer/
#
# Report storage folder  [SI_RiskAnalysis_ExportPrefix]  (advanced)
#   What it is for:   The folder inside the report storage container where the risk-analysis container jobs save their
#                     reports.
#   Default:          risk-analysis
#   If you change it: Reports are saved under this folder; empty saves them at the container's top level. Ignored when
#                     a full export destination is set.
#   When to change:   Only if your report readers expect another folder.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if your report readers expect another folder.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_ExportPrefix/
#
# Reset query split memory  [ResetCache]  (engine: risk-analysis, advanced)
#   What it is for:   Deletes the saved query split counts at the start of a run so they are probed again.
#   Default:          Off.
#   If you change it: On, the next run re-probes every large query from scratch, so it takes longer; the new counts
#                     are saved again afterwards.
#   When to change:   For one run when reports look incomplete or after a large estate change.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: For one run when reports look incomplete or after a large
#                     estate change.
#   More info:        https://invardia.com/docs/si/settings/ResetCache/
#
# Risk Analysis late bucket retries  [SI_BucketLateRetries]  (advanced, attempts)
#   What it is for:   How many extra attempts a query slice gets at the end of a Risk Analysis report when it failed
#                     earlier because the service was throttling or unavailable.
#   Default:          3 attempts
#   If you change it: More attempts recover more slices on a busy tenant but lengthen the run (each waits up to 10
#                     minutes). Fewer, or 0, ends sooner but the rows of a failed slice are missing from the report.
#   When to change:   Most installs never should. Raise it if reports often miss rows because of throttling.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should. Raise it if reports often miss
#                     rows because of throttling.
#   More info:        https://invardia.com/docs/si/settings/SI_BucketLateRetries/
#
# Risk Analysis parts asked at a time (most)  [SI_RA_PartsInParallel_Max]  (advanced, parts)
#   What it is for:   A large Risk Analysis report is asked from Microsoft Defender in parts. While one part is
#                     processed (risk scores, the database), the next parts are already asked, so Defender and
#                     SecurityInsight work at the same time. This is the most parts asked at a time.
#   Default:          6 (never more than 4 per processor core)
#   If you change it: The number adapts by itself: each report starts at 2, asks more while Defender answers quickly,
#                     and halves at once when Defender asks to slow down (it then waits as long as Defender says). A
#                     higher maximum lets a large report finish sooner when Defender keeps up; 1 asks one part at a
#                     time. The parts are processed in their order either way: the stored findings are the same.
#   When to change:   Most installs never should. Set 1 only if support asks you to; lower it if other tools in the
#                     tenant share Defender's advanced hunting limits.
#   Risk:             Only changes how many parts of a report are asked from Defender at a time, so how long Risk
#                     Analysis takes: 1 makes a large report take much longer; a higher number can make Defender ask
#                     SecurityInsight to slow down more often (it then does). The findings are the same either way.
#                     Reversible at once.
#   Recommended:      Keep 6 (the default).
#   More info:        https://invardia.com/docs/si/settings/SI_RA_PartsInParallel_Max/
#
# Risk Analysis report export location  [SI_RiskAnalysis_ExportDestination]  (advanced)
#   What it is for:   Storage URL where container-hosted Risk Analysis jobs save their report workbooks and data
#                     files.
#   Default:          Built at setup from the staging storage account, folder risk-analysis in the staging container.
#   If you change it: Read by container setup and passed to the Risk Analysis jobs. Reports are uploaded to this URL
#                     instead; the identity must be able to write there. On a server install the ExportDestination
#                     setting is used instead.
#   When to change:   When reports must land in a different storage account or container. Re-run setup for it to take
#                     effect.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: When reports must land in a different storage account or
#                     container. Re-run setup for it to take effect.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_ExportDestination/
#
# Risk analysis report template  [ReportTemplate]  (engine: risk-analysis, advanced)
#   What it is for:   Names the report template risk analysis runs: RiskAnalysis_Summary (compact) or
#                     RiskAnalysis_Detailed (one row per finding).
#   Default:          RiskAnalysis_Summary.
#   If you change it: The launchers and containers set this themselves from the command line or the per-mode template
#                     settings, so a value in the config file is only honoured when the engine is run directly.
#   When to change:   Use RiskAnalysis_ReportTemplate_Default_Summary or _Detailed, or -ReportTemplate, instead.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Use RiskAnalysis_ReportTemplate_Default_Summary or _Detailed,
#                     or -ReportTemplate, instead.
#   More info:        https://invardia.com/docs/si/settings/ReportTemplate/
#
# Risk Analysis stale device filter  [SI_RA_StaleDeviceFilter]  (advanced)
#   What it is for:   Optionally removes devices not seen recently from the heavy attack-path Risk Analysis reports:
#                     off, lenient or strict.
#   Default:          Off: no devices are filtered out
#   If you change it: lenient drops devices last seen longer ago than SI_ActiveStaleDays; strict also drops devices
#                     with no last-seen date. Smaller, faster reports, but findings on those devices are hidden.
#   When to change:   Only if attack-path reports are swamped by devices that no longer exist.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if attack-path reports are swamped by devices that no
#                     longer exist.
#   More info:        https://invardia.com/docs/si/settings/SI_RA_StaleDeviceFilter/
#
# Risk Analysis too-large slice retries  [SI_BucketOverflowRetries]  (advanced, attempts)
#   What it is for:   How many times a Risk Analysis query slice that the service answers as too large is sent at the
#                     same size before it is split into smaller slices. 1 splits it on the first too-large answer.
#   Default:          1 attempt (split at once)
#   If you change it: Higher sends the same too-large request again, after a 30 s and then a 60 s pause, before
#                     splitting it. The same request at the same size fails the same way, so this only adds time.
#                     Throttling, timeouts and service errors are retried separately (Risk Analysis transient error
#                     retries).
#   When to change:   Most installs never should. Keep 1.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should. Keep 1.
#   More info:        https://invardia.com/docs/si/settings/SI_BucketOverflowRetries/
#
# Risk Analysis transient error retries  [SI_BucketTransientRetries]  (advanced, attempts)
#   What it is for:   How many times a Risk Analysis query slice is retried, after signing in again, when it fails
#                     with a temporary error such as an expired token or a gateway timeout.
#   Default:          3 attempts
#   If you change it: More attempts make long reports more robust against brief outages, at the cost of a longer run
#                     when the service stays unavailable. Fewer gives up on a slice sooner.
#   When to change:   Most installs never should. Raise it on tenants with frequent temporary service errors.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should. Raise it on tenants with frequent
#                     temporary service errors.
#   More info:        https://invardia.com/docs/si/settings/SI_BucketTransientRetries/
#
# Run Summary report  [Summary]  (engine: risk-analysis, advanced)
#   What it is for:   Run-mode switch telling Risk Analysis to build the Summary report and use the Summary mail
#                     settings and table.
#   Default:          Off; with neither Summary nor Detailed set, the Summary report is still built by default.
#   If you change it: Selects the Summary report template, its mail recipients and its Log Analytics table. Setting it
#                     together with Detailed stops the run with an error.
#   When to change:   Normally set by the launcher or container job, not in the configuration file.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Normally set by the launcher or container job, not in the
#                     configuration file.
#   More info:        https://invardia.com/docs/si/settings/Summary/
#
# Split count re-test pause  [AutoBucketChallenger_ConfirmDays]  (advanced, days)
#   What it is for:   After a run decided a report's split count, how many days pass before a suspiciously high count
#                     is tested again.
#   Default:          7 days.
#   If you change it: Shorter re-tests a count that looks too high sooner, at the cost of extra queries; longer keeps
#                     a wrong count longer.
#   When to change:   Rarely; only with support while tuning query splitting.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; only with support while tuning query splitting.
#   More info:        https://invardia.com/docs/si/settings/AutoBucketChallenger_ConfirmDays/
#
# Split count re-test sample size  [AutoBucketChallenger_MinEntries]  (advanced, reports)
#   What it is for:   How many reports must have a split count before one count is compared with the others at all.
#   Default:          10 reports.
#   If you change it: Lower compares sooner on small installs; higher waits for more reports before re-testing
#                     anything.
#   When to change:   Rarely; only with support while tuning query splitting.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; only with support while tuning query splitting.
#   More info:        https://invardia.com/docs/si/settings/AutoBucketChallenger_MinEntries/
#
# Split count re-test threshold  [AutoBucketChallenger_MedianMultiplier]  (advanced, times)
#   What it is for:   A report's split count this many times the median of the other reports' counts is treated as
#                     suspicious and tested again.
#   Default:          10 times the median.
#   If you change it: Lower re-tests more reports (more queries); higher re-tests only extreme counts.
#   When to change:   Rarely; only with support while tuning query splitting.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; only with support while tuning query splitting.
#   More info:        https://invardia.com/docs/si/settings/AutoBucketChallenger_MedianMultiplier/
#
# Summary report template  [RiskAnalysis_ReportTemplate_Default_Summary]  (engine: risk-analysis, advanced)
#   What it is for:   The report template used for Summary runs when no template is named explicitly.
#   Default:          RiskAnalysis_Summary.
#   If you change it: Summary runs and the Summary container job use the named template instead. A template name that
#                     does not exist makes the run fail.
#   When to change:   When you have created your own Summary template.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: When you have created your own Summary template.
#   More info:        https://invardia.com/docs/si/settings/RiskAnalysis_ReportTemplate_Default_Summary/
#
# Tier 0 score multiplier  [SI_RiskReport_TierMultiplier_T0]  (advanced)
#   What it is for:   Sets how much more a finding on a Tier 0 (most critical) asset counts in the Risk Analysis
#                     domain and overall scores.
#   Default:          4 (four times a Tier 2 asset)
#   If you change it: A higher value makes Tier 0 findings dominate the domain and overall scores; a lower value
#                     spreads attention to less critical assets. The original risk score columns are not affected.
#   When to change:   Most installs never should; change only if your tier model weighs critical assets differently.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only if your tier model
#                     weighs critical assets differently.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_TierMultiplier_T0/
#
# Tier 1 score multiplier  [SI_RiskReport_TierMultiplier_T1]  (advanced)
#   What it is for:   Sets how much a finding on a Tier 1 asset counts in the Risk Analysis domain and overall scores.
#   Default:          2 (twice a Tier 2 asset)
#   If you change it: A higher value gives Tier 1 findings more influence on the domain and overall scores. The
#                     original risk score columns are not affected.
#   When to change:   Most installs never should; change only if your tier model weighs assets differently.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only if your tier model
#                     weighs assets differently.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_TierMultiplier_T1/
#
# Tier 2 score multiplier  [SI_RiskReport_TierMultiplier_T2]  (advanced)
#   What it is for:   Sets how much a finding on a Tier 2 asset counts in the Risk Analysis domain and overall scores;
#                     the baseline the other tiers compare to.
#   Default:          1 (the baseline); assets with no tier also count 1
#   If you change it: Changing it shifts the balance between Tier 2 assets and the other tiers in the domain and
#                     overall scores. The original risk score columns are not affected.
#   When to change:   Most installs never should; change only if your tier model weighs assets differently.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only if your tier model
#                     weighs assets differently.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_TierMultiplier_T2/
#
# Tier 3 score multiplier  [SI_RiskReport_TierMultiplier_T3]  (advanced)
#   What it is for:   Sets how much a finding on a Tier 3 (least critical) asset counts in the Risk Analysis domain
#                     and overall scores.
#   Default:          0.5 (half a Tier 2 asset)
#   If you change it: A higher value gives low-criticality assets more influence on the domain and overall scores; a
#                     lower value nearly ignores them. The original risk score columns are not affected.
#   When to change:   Most installs never should; change only if your tier model weighs assets differently.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Most installs never should; change only if your tier model
#                     weighs assets differently.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskReport_TierMultiplier_T3/
#
# Trend dry run  [SI_Trend_DryRun]  (engine: asset-trend, advanced)
#   What it is for:   Lets the trend engine compute and print its rollup without publishing anything.
#   Default:          Off: the rollup is published every run.
#   If you change it: When on, nothing is written to the trend table, so the trend line and weekly history get a gap
#                     for every dry-run day. A command-line switch on the run wins over this value.
#   When to change:   For a first trial run, or while checking numbers; switch it back off afterwards.
#   Risk:             No trend rows are written while it is on: the trend line and weekly history get a gap for every
#                     such day, which cannot be filled later. Reversible from the next day.
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_Trend_DryRun/
#
# Trend source detail level  [SI_Trend_Grain]  (engine: asset-trend, advanced)
#   What it is for:   Chooses whether the trend rollup is built from the Risk Analysis summary results or the detailed
#                     per-asset results.
#   Default:          Summary (the Risk Analysis summary results).
#   If you change it: 'Detailed' rolls up from the detailed Risk Analysis table instead, which only helps if your
#                     reports publish at that level. Any value other than Summary or Detailed falls back to Summary
#                     with a warning.
#   When to change:   Only if your Risk Analysis reports are published at the detailed level and you want the trend
#                     built from that.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Only if your Risk Analysis reports are published at the
#                     detailed level and you want the trend built from that.
#   More info:        https://invardia.com/docs/si/settings/SI_Trend_Grain/
#
# Weekly rate weeks shown  [SI_Trend_Weeks]  (engine: asset-trend, advanced, weeks)
#   What it is for:   How many weeks the printed weekly opened/closed view covers when the trend engine is run by hand
#                     with the weekly rate view.
#   Default:          12 weeks.
#   If you change it: Only changes how many weeks are printed when a person asks for the weekly rate view on a VM run.
#                     The weekly history that is stored is unaffected, and scheduled container runs do not print the
#                     view.
#   When to change:   Rarely; when you want a longer or shorter printed history during a manual run.
#   Risk:             Changes what the Risk Analysis reports show, how findings are filtered or scored, or where
#                     reports go, from the next run; earlier reports are unchanged. Hiding findings can make real
#                     exposure invisible to readers. Reversible: change it back.
#   Recommended:      Keep the default. Change it when: Rarely; when you want a longer or shorter printed history
#                     during a manual run.
#   More info:        https://invardia.com/docs/si/settings/SI_Trend_Weeks/
#
# ----------------------------------------------------------------------------------------------------
# Risk Analysis -- mails and executive view
# Whether the Summary and Detailed mails show the same headline figures, which report leads, and the
# matching executive view in the web app.
# ----------------------------------------------------------------------------------------------------
#
# Leading report for AI summary  [SI_AISummary_Leader]
#   What it is for:   In Consistent mode, chooses which report (Summary or Detailed) builds the AI summary, risk score
#                     and top list that the other report reuses.
#   Choices:          'Summary' (Summary report leads); 'Detailed' (Detailed report leads)
#   Default:          Detailed is the leading report.
#   If you change it: The leading report always computes its own figures; the other copies them so both mails agree.
#                     An unknown value falls back to Detailed with a warning. Ignored in PerReport mode. With the
#                     Summary step off (the default) only the Detailed report runs, so it always leads.
#   When to change:   Set to Summary only when the Summary step is switched on and management mainly receives the
#                     Summary report.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Set to Summary only when the Summary step is switched on and
#                     management mainly receives the Summary report.
#   More info:        https://invardia.com/docs/si/settings/SI_AISummary_Leader/
#
# Protection Score: accepted lifecycle for cloud resources (days)  [SI_ProtectionScore_GraceDays_CloudResource]
#   What it is for:   The protection score's accepted lifecycle for cloud resources (Azure): how many days a Very High
#                     or High finding may be open before it counts in the "within Accepted Lifecycle" view.
#   Default:          30 days
#   If you change it: Only a PATCH finding (a vulnerability with a vendor fix: a fix release date, a recommended
#                     update or a patch cycle) gets this grace; every other finding has its own
#                     (SI_ProtectionScore_OtherGraceDays_*, default 0). A cloud resource patch finding younger than
#                     this (its age: the fix's release date, else the source's first-seen, else SI's first detection)
#                     does not lower the "within Accepted Lifecycle" protection score; the Actual Risks view always
#                     counts it. A finding with no date always counts. 0 = both views count it at once.
#   When to change:   Your patching or remediation process gives cloud resources a different grace (for example 14
#                     days for identities).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your patching or remediation process gives cloud resources a
#                     different grace (for example 14 days for identities).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_GraceDays_CloudResource/
#
# Protection Score: accepted lifecycle for devices (days)  [SI_ProtectionScore_GraceDays_Device]
#   What it is for:   The protection score's accepted lifecycle for devices: how many days a Very High or High finding
#                     may be open before it counts in the "within Accepted Lifecycle" view.
#   Default:          30 days
#   If you change it: Only a PATCH finding (a vulnerability with a vendor fix: a fix release date, a recommended
#                     update or a patch cycle) gets this grace; every other finding has its own
#                     (SI_ProtectionScore_OtherGraceDays_*, default 0). A device patch finding younger than this (its
#                     age: the fix's release date, else the source's first-seen, else SI's first detection) does not
#                     lower the "within Accepted Lifecycle" protection score; the Actual Risks view always counts it.
#                     A finding with no date always counts. 0 = both views count it at once.
#   When to change:   Your patching or remediation process gives devices a different grace (for example 14 days for
#                     identities).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your patching or remediation process gives devices a different
#                     grace (for example 14 days for identities).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_GraceDays_Device/
#
# Protection Score: accepted lifecycle for identities (days)  [SI_ProtectionScore_GraceDays_Identity]
#   What it is for:   The protection score's accepted lifecycle for identities: how many days a Very High or High
#                     finding may be open before it counts in the "within Accepted Lifecycle" view.
#   Default:          30 days
#   If you change it: Only a PATCH finding (a vulnerability with a vendor fix: a fix release date, a recommended
#                     update or a patch cycle) gets this grace; every other finding has its own
#                     (SI_ProtectionScore_OtherGraceDays_*, default 0). A identity patch finding younger than this
#                     (its age: the fix's release date, else the source's first-seen, else SI's first detection) does
#                     not lower the "within Accepted Lifecycle" protection score; the Actual Risks view always counts
#                     it. A finding with no date always counts. 0 = both views count it at once.
#   When to change:   Your patching or remediation process gives identities a different grace (for example 14 days for
#                     identities).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your patching or remediation process gives identities a
#                     different grace (for example 14 days for identities).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_GraceDays_Identity/
#
# Protection Score: accepted lifecycle for public IPs (days)  [SI_ProtectionScore_GraceDays_PublicIp]
#   What it is for:   The protection score's accepted lifecycle for public IP addresses: how many days a Very High or
#                     High finding may be open before it counts in the "within Accepted Lifecycle" view.
#   Default:          30 days
#   If you change it: Only a PATCH finding (a vulnerability with a vendor fix: a fix release date, a recommended
#                     update or a patch cycle) gets this grace; every other finding has its own
#                     (SI_ProtectionScore_OtherGraceDays_*, default 0). A public IP patch finding younger than this
#                     (its age: the fix's release date, else the source's first-seen, else SI's first detection) does
#                     not lower the "within Accepted Lifecycle" protection score; the Actual Risks view always counts
#                     it. A finding with no date always counts. 0 = both views count it at once.
#   When to change:   Your patching or remediation process gives public IPs a different grace (for example 14 days for
#                     identities).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your patching or remediation process gives public IPs a
#                     different grace (for example 14 days for identities).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_GraceDays_PublicIp/
#
# Protection Score: grace for Azure findings (days)  [SI_ProtectionScore_OtherGraceDays_CloudResource]  (days)
#   What it is for:   How many days a Very High or High finding on a cloud resource that is not a patch (an Azure /
#                     Defender for Cloud recommendation, an attack path) may be open before it counts in the "within
#                     Accepted Lifecycle" view.
#   Default:          0 days: it counts from the day it is found
#   If you change it: 0: such a finding is a risk from day one in both views. A higher number gives it a grace (its
#                     age: the source's first-seen, else SI's first detection); a finding with no date always counts.
#   When to change:   Your cloud team has an agreed time to fix recommendations (for example 30 days).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your cloud team has an agreed time to fix recommendations (for
#                     example 30 days).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_OtherGraceDays_CloudResource/
#
# Protection Score: grace for identity findings (days)  [SI_ProtectionScore_OtherGraceDays_Identity]  (days)
#   What it is for:   How many days a Very High or High identity finding (MFA, roles, sign-ins, attack paths --
#                     anything that is not a patch) may be open before it counts in the "within Accepted Lifecycle"
#                     view.
#   Default:          0 days: it counts from the day it is found
#   If you change it: 0: such a finding is a risk from day one in both views. A higher number gives it a grace (its
#                     age: the source's first-seen, else SI's first detection); a finding with no date always counts.
#   When to change:   Your identity team has an agreed time to fix (for example 7 days).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your identity team has an agreed time to fix (for example 7
#                     days).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_OtherGraceDays_Identity/
#
# Protection Score: grace for other device findings (days)  [SI_ProtectionScore_OtherGraceDays_Device]  (days)
#   What it is for:   How many days a Very High or High device finding that is NOT a patch (a configuration, an attack
#                     path, a vulnerability with no vendor fix) may be open before it counts in the "within Accepted
#                     Lifecycle" view.
#   Default:          0 days: it counts from the day it is found
#   If you change it: 0: such a finding is a risk from day one in both views. A higher number gives it a grace like a
#                     patch's (its age: the source's first-seen, else SI's first detection); a finding with no date
#                     always counts.
#   When to change:   Your process accepts a time to fix configuration findings too (for example 14 days).
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your process accepts a time to fix configuration findings too
#                     (for example 14 days).
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_OtherGraceDays_Device/
#
# Protection Score: grace for other public IP findings (days)  [SI_ProtectionScore_OtherGraceDays_PublicIp]  (days)
#   What it is for:   How many days a Very High or High finding on a public IP that is not a patch (an open port, an
#                     exposed service) may be open before it counts in the "within Accepted Lifecycle" view.
#   Default:          0 days: it counts from the day it is found
#   If you change it: 0: such a finding is a risk from day one in both views. A higher number gives it a grace (its
#                     age: the source's first-seen, else SI's first detection); a finding with no date always counts.
#   When to change:   Your network team has an agreed time to close exposures.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your network team has an agreed time to close exposures.
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_OtherGraceDays_PublicIp/
#
# Protection score: severities that count  [SI_ProtectionScore_Severities]
#   What it is for:   The finding severities that take an asset out of good standing in the protection score.
#   Default:          Very High, Critical, High
#   If you change it: An asset with an open, non-exempted finding of one of these severities is not in good standing.
#                     Separate with commas.
#   When to change:   Also count Medium findings, for a stricter score.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Also count Medium findings, for a stricter score.
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_Severities/
#
# Protection score: tier weights  [SI_ProtectionScore_TierWeights]
#   What it is for:   How much an asset of each tier weighs in the protection score, Tier 0 to Tier 3, separated by
#                     commas.
#   Default:          8,4,2,1 (an unclassified asset weighs as Tier 3)
#   If you change it: A Tier 0 asset out of good standing lowers the score as much as eight Tier 3 assets with the
#                     default. Four numbers, 0 or more; anything else = the default.
#   When to change:   Your management weighs tiers differently.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Your management weighs tiers differently.
#   More info:        https://invardia.com/docs/si/settings/SI_ProtectionScore_TierWeights/
#
# Summary and Detailed agreement  [SI_AISummary_Mode]
#   What it is for:   Chooses whether the Summary and Detailed reports show identical AI summary, risk score and top
#                     list, or each shows its own figures.
#   Choices:          'Consistent' (Same figures in both reports, from the leading report); 'PerReport' (Each report
#                     shows its own figures)
#   Default:          Depends on the edition. SecurityInsight Pro: PerReport -- each report shows its own figures
#                     (Summary counts distinct assets, Detailed counts individual findings). Community: Consistent --
#                     both reports show the same figures. A value you set wins in both editions.
#   If you change it: Consistent makes one report reuse the other's figures, saving AI calls. PerReport makes each
#                     report compute its own, so totals differ. Unknown values fall back to the edition's default.
#   When to change:   Choose PerReport when each audience receives only one report, or (Pro) to compare Summary and
#                     Detailed in the web app. Choose Consistent when management receives both mails and they must
#                     show the same figures.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Choose PerReport when each audience receives only one report,
#                     or (Pro) to compare Summary and Detailed in the web app. Choose Consistent when management
#                     receives both mails and they must show the same figures.
#   More info:        https://invardia.com/docs/si/settings/SI_AISummary_Mode/
#
# AI summary reuse age limit  [SI_AISummary_MaxAgeHours]  (advanced, hours)
#   What it is for:   How old the leading report's saved summary may be before the other report stops reusing it and
#                     builds its own.
#   Default:          24 hours.
#   If you change it: Higher lets an older summary be reused, so figures can be stale after a missed run. Lower makes
#                     the follower build its own figures more often, costing more AI calls.
#   When to change:   Only if your two reports run more than a day apart.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only if your two reports run more than a day apart.
#   More info:        https://invardia.com/docs/si/settings/SI_AISummary_MaxAgeHours/
#
# Read Defender's first sighting of each vulnerability  [SI_RA_SourceFirstSeen]  (advanced)
#   What it is for:   Risk Analysis reads Defender for Endpoint's software vulnerabilities export once per run for the
#                     first time each CVE was seen on each device (si_source_first_seen).
#   Default:          On
#   If you change it: The protection score's "within Accepted Lifecycle" view ages a vulnerability by Defender's own
#                     first sighting instead of SecurityInsight's first detection. Off: the export is not read and the
#                     vulnerability findings carry no source first-seen.
#   When to change:   Turn it off only when the export takes too long or the permission Vulnerability.Read.All is not
#                     granted.
#   Risk:             Changes how the headline figures are presented in the mails and the executive view; the findings
#                     themselves are unchanged. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn it off only when the export takes too long or the
#                     permission Vulnerability.Read.All is not granted.
#   More info:        https://invardia.com/docs/si/settings/SI_RA_SourceFirstSeen/
#
# ----------------------------------------------------------------------------------------------------
# AI
# Azure OpenAI: whether AI is used, for what, and how much it may spend.
# ----------------------------------------------------------------------------------------------------
#
# AI integration  [SI_EnableAI]
#   What it is for:   ONE switch for AI: on = AI for every engine that has an AI step (the endpoint and Azure engines
#                     classify the assets their rules cannot place). It needs the Azure OpenAI endpoint, deployment
#                     and key.
#   Default:          Off: assets are classified by rules only.
#   If you change it: When on, and Azure OpenAI is configured, assets that rules cannot place are sent to Azure OpenAI
#                     for a tier and service type. This adds AI cost and run time. The identity and public IP engines
#                     never use AI.
#   When to change:   When you want AI help classifying assets -- in Get Started > AI integration, with the endpoint,
#                     deployment and key.
#   Risk:             Asset data (names, properties) of assets the rules cannot place is sent to YOUR Azure OpenAI
#                     deployment, and each call costs. Reversible at once; tiers already set by AI stay until the next
#                     full run.
#   Recommended:      Off unless rules leave many assets untiered.
#   More info:        https://invardia.com/docs/si/settings/SI_EnableAI/
#
# AI summary in the report mail  [BuildSummaryByAI]  (engine: risk-analysis)
#   What it is for:   Adds an AI-written executive summary of the Risk Analysis findings to the report email.
#   Default:          Off
#   If you change it: When on, each Risk Analysis run calls your Azure OpenAI deployment, adding run time and AI cost.
#                     If the AI settings are missing, a VM run stops with an error; a container run skips the summary.
#   When to change:   Turn on when you have Azure OpenAI set up and want a narrative summary in the mail.
#   Risk:             Report content is sent to YOUR Azure OpenAI deployment for a summary, and each run costs.
#                     Reversible at once.
#   Recommended:      As your organisation prefers; on gives readers a written summary.
#   More info:        https://invardia.com/docs/si/settings/BuildSummaryByAI/
#
# AI summary in the report mail (container jobs)  [SI_RiskAnalysis_BuildSummaryByAI]
#   What it is for:   Decides whether the risk-analysis container jobs ask Azure OpenAI to write a summary of the
#                     findings.
#   Default:          Not set: the jobs follow your general AI summary setting, otherwise off.
#   If you change it: When on, each report run makes AI calls, adding cost and run time; the run stops if Azure OpenAI
#                     details are missing. When off, reports have no AI summary.
#   When to change:   When you want AI-written summaries in scheduled container reports.
#   Risk:             Report content is sent to YOUR Azure OpenAI deployment for a summary, and each run costs; a run
#                     stops if Azure OpenAI is not configured. Reversible at once.
#   Recommended:      As your organisation prefers.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_BuildSummaryByAI/
#
# Azure OpenAI deployment  [OpenAI_deployment]  (engine: risk-analysis)
#   What it is for:   Name of the Azure OpenAI model deployment used for AI classification and AI summaries.
#   Default:          Not set: AI classification is skipped; an AI summary request fails
#   If you change it: Chooses which model answers; a larger model may give better text at higher cost. AI features
#                     stay off unless endpoint, key and deployment are all set.
#   When to change:   When turning on AI features or moving to another model deployment.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: When turning on AI features or moving to another model
#                     deployment.
#   More info:        https://invardia.com/docs/si/settings/OpenAI_deployment/
#
# Azure OpenAI endpoint  [OpenAI_endpoint]  (engine: risk-analysis)
#   What it is for:   The web address of your Azure OpenAI resource, used for AI classification, AI tiering of roles
#                     and AI report summaries.
#   Default:          Not set: AI classification is skipped and AI summaries cannot run.
#   If you change it: With endpoint, key and deployment all set, engines that have AI switched on call your Azure
#                     OpenAI. Missing it, profiling falls back to rule-based tiers, role tiering marks items for
#                     manual review, and an AI summary request stops the report run.
#   When to change:   Set it when you want AI features; change it only when you move to another Azure OpenAI resource.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Set it when you want AI features; change it only when you move
#                     to another Azure OpenAI resource.
#   More info:        https://invardia.com/docs/si/settings/OpenAI_endpoint/
#
# Azure OpenAI key (Key Vault secret name)  [OpenAI_apiKey]  (engine: risk-analysis, secret)
#   What it is for:   The NAME of the Key Vault secret that holds the key of your Azure OpenAI resource -- never the
#                     key itself. Get Started > AI integration stores the key in your Key Vault and fills this in.
#   Default:          Not set: AI classification is skipped; an AI summary request fails
#   If you change it: With endpoint and deployment set, AI features can run. Keep it in Key Vault rather than in a
#                     file.
#   When to change:   When turning on AI features or rotating the key.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: When turning on AI features or rotating the key.
#   More info:        https://invardia.com/docs/si/settings/OpenAI_apiKey/
#
# Schema discovery AI budget  [SI_SchemaProposeAiCeiling]  (USD)
#   What it is for:   Maximum estimated AI spend, in US dollars, for drafting rules from new findings in one
#                     schema-discovery run.
#   Default:          5 US dollars per run.
#   If you change it: Raising it lets more new findings get an AI-drafted rule per run, at higher AI cost. Findings
#                     beyond the budget wait for the next weekly run.
#   When to change:   Lower it to cap AI cost; raise it if many findings keep being deferred.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Lower it to cap AI cost; raise it if many findings keep being
#                     deferred.
#   More info:        https://invardia.com/docs/si/settings/SI_SchemaProposeAiCeiling/
#
# Turn off AI classification (all engines)  [SI_DisableAI]
#   What it is for:   A master switch that turns off AI asset classification for every collection engine, whatever
#                     else is switched on.
#   Default:          Off: AI runs where it has been switched on.
#   If you change it: When on, asset profiling, signal maps and schema proposals use rules only and send nothing to
#                     Azure OpenAI. It does not stop the role tiering classifier or the risk-analysis AI summary,
#                     which have their own switches.
#   When to change:   When AI must not be used, for example for a policy or cost reason.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: When AI must not be used, for example for a policy or cost
#                     reason.
#   More info:        https://invardia.com/docs/si/settings/SI_DisableAI/
#
# Turn off AI for the endpoint engine  [SI_DisableAI_endpoint]
#   What it is for:   Switches off AI classification for the endpoint engine only, even when AI is on for all engines.
#   Default:          Off: the endpoint engine follows the general AI switches.
#   If you change it: Devices are classified by rules only; any device without a rule-based tier gets the default
#                     tier. Removes AI cost for endpoints. Wins over every AI turn-on switch.
#   When to change:   When you use AI elsewhere but want rule-only tiering for devices.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: When you use AI elsewhere but want rule-only tiering for
#                     devices.
#   More info:        https://invardia.com/docs/si/settings/SI_DisableAI_endpoint/
#
# AI call attempts  [AI_MaxAttempts]  (advanced, attempts)
#   What it is for:   How many times Risk Analysis tries an AI request when the AI service times out, throttles or has
#                     a temporary failure.
#   Default:          4 attempts.
#   If you change it: More attempts make the AI summary more likely to succeed under load, but a failing service makes
#                     the run take longer. Other errors fail at once regardless.
#   When to change:   Raise if AI summaries often fail on throttling or timeouts.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Raise if AI summaries often fail on throttling or timeouts.
#   More info:        https://invardia.com/docs/si/settings/AI_MaxAttempts/
#
# AI cost per call estimate  [SI_AI_CostPerCallEstimate]  (engine: identity, advanced, USD)
#   What it is for:   The estimated price in US dollars of one AI call, used to keep each run within its AI spending
#                     budget.
#   Default:          0.01 USD per call
#   If you change it: The engines count this amount per AI call against the run's AI budget. A higher estimate stops
#                     AI calls sooner (more assets classified by rules only); a lower one allows more calls and higher
#                     real cost.
#   When to change:   After a few real runs, set it to your observed cost per call.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: After a few real runs, set it to your observed cost per call.
#   More info:        https://invardia.com/docs/si/settings/SI_AI_CostPerCallEstimate/
#
# AI for privilege tier catalog  [SI_PrivilegeTierClassifier_RunAI]  (engine: privilege-tier-classifier, advanced)
#   What it is for:   An override for ONE engine: whether the privilege tier classifier asks Azure OpenAI to tier new
#                     roles and permissions. It follows its own switch, not AI integration: it calls AI whenever the
#                     Azure OpenAI settings are set, unless this is off.
#   Default:          On.
#   If you change it: Turning it off sends nothing to Azure OpenAI: roles and permissions already in the catalog keep
#                     their tier, and new ones are left unresolved for manual review. Removes AI cost for this engine.
#   When to change:   Only to keep AI out of the privilege tier classifier while it is used elsewhere; or turn it off
#                     if you tier new roles yourself.
#   Risk:             With the Azure OpenAI settings set, new role and permission names are sent to YOUR Azure OpenAI
#                     deployment, and each call costs; off leaves new ones untiered for manual review. Reversible at
#                     once.
#   Recommended:      Keep the default; turn it off only to keep AI out of this engine.
#   More info:        https://invardia.com/docs/si/settings/SI_PrivilegeTierClassifier_RunAI/
#
# AI for the Azure engine  [SI_EnableAI_azure]  (engine: azure, advanced)
#   What it is for:   An override for ONE engine: turns on Azure OpenAI classification and application grouping for
#                     the Azure engine only, while AI integration is off. With AI integration on it changes nothing.
#   Default:          Off, unless AI is turned on for all engines.
#   If you change it: Resources without a rule-based tier are classified by AI, and resource groups are named as
#                     applications. Adds AI cost and run time. Needs the Azure OpenAI settings; without them AI stays
#                     off. A disable switch wins.
#   When to change:   Only to use AI in the Azure engine alone; normally use AI integration (on = on for all engines).
#   Risk:             Resource data of untiered Azure resources is sent to YOUR Azure OpenAI deployment, and each call
#                     costs. Reversible at once.
#   Recommended:      Leave it off and use AI integration (on = on for all engines); this only turns the Azure engine
#                     on alone.
#   More info:        https://invardia.com/docs/si/settings/SI_EnableAI_azure/
#
# AI for the endpoint engine  [SI_EnableAI_endpoint]  (engine: endpoint, advanced)
#   What it is for:   An override for ONE engine: turns on Azure OpenAI classification for the endpoint engine only,
#                     while AI integration is off. With AI integration on it changes nothing.
#   Default:          Off, unless AI is turned on for all engines.
#   If you change it: Devices without a rule-based tier are classified by AI instead of getting the default tier. Adds
#                     AI cost and run time. Needs the Azure OpenAI settings; SI_DisableAI_endpoint wins over it.
#   When to change:   Only to use AI in the endpoint engine alone; normally use AI integration (on = on for all
#                     engines).
#   Risk:             Device data of untiered devices is sent to YOUR Azure OpenAI deployment, and each call costs.
#                     Reversible at once.
#   Recommended:      Leave it off and use AI integration (on = on for all engines); this only turns the endpoint
#                     engine on alone.
#   More info:        https://invardia.com/docs/si/settings/SI_EnableAI_endpoint/
#
# AI for the identity engine  [SI_EnableAI_identity]  (engine: identity, advanced)
#   What it is for:   Per-engine AI switch for the identity engine.
#   Default:          Off; identity classification never uses AI.
#   If you change it: No effect today: identity tiers always come from the built-in role and permission catalog,
#                     whatever this is set to.
#   When to change:   Never at present; it is kept for consistency with the other engines.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Never at present; it is kept for consistency with the other
#                     engines.
#   More info:        https://invardia.com/docs/si/settings/SI_EnableAI_identity/
#
# AI signal map version  [SI_SignalMap_PromptVersion]  (advanced)
#   What it is for:   A version label for the stored AI signal weights per engine and asset type; changing it makes
#                     the engines ask the AI again.
#   Default:          v1
#   If you change it: A new value ignores the stored weights and rebuilds them with fresh AI calls on the next run,
#                     which adds AI cost once. Keeping the value reuses the stored weights.
#   When to change:   Only when you want the AI signal weights rebuilt, for example after a model change.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Only when you want the AI signal weights rebuilt, for example
#                     after a model change.
#   More info:        https://invardia.com/docs/si/settings/SI_SignalMap_PromptVersion/
#
# AI spend limit per run  [MaxAiSpendPerRun]  (advanced, USD)
#   What it is for:   Caps the estimated Azure OpenAI spend (in US dollars) of AI classification in one profiling run.
#   Default:          Container jobs: 4 US dollars. VM runs: no limit
#   If you change it: When the estimate reaches the cap, remaining assets are classified without AI and marked as
#                     budget-capped. Higher caps allow more AI classification at more cost.
#   When to change:   Raise for large estates using AI classification; lower to control cost.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Raise for large estates using AI classification; lower to
#                     control cost.
#   More info:        https://invardia.com/docs/si/settings/MaxAiSpendPerRun/
#
# AI summary answer length  [OpenAI_MaxTokensPerRequest]  (engine: risk-analysis, advanced, tokens)
#   What it is for:   The largest answer, in tokens, the AI may return for each risk-analysis summary request.
#   Default:          16384 tokens, unless the older AI_MaxTokensPerRequest is set
#   If you change it: Higher allows longer AI summaries but costs more per call and may exceed what your model
#                     deployment allows; lower gives shorter, cheaper summaries that may be cut off.
#   When to change:   Rarely; lower it if your model has a smaller limit, raise it if summaries are cut short.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Rarely; lower it if your model has a smaller limit, raise it
#                     if summaries are cut short.
#   More info:        https://invardia.com/docs/si/settings/OpenAI_MaxTokensPerRequest/
#
# Azure AI instructions  [SI_SystemPrompt_azure]  (engine: azure, advanced)
#   What it is for:   Replaces the built-in instructions sent to Azure OpenAI when it classifies Azure resources.
#   Default:          The built-in Azure classification instructions.
#   If you change it: Changes how AI decides tiers and service types for Azure resources. A poorly written prompt can
#                     produce wrong tiers or unreadable answers, which fall back to a default tier. Has no effect
#                     while AI is off for the Azure engine.
#   When to change:   Rarely; only to tune AI classification for your estate.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Rarely; only to tune AI classification for your estate.
#   More info:        https://invardia.com/docs/si/settings/SI_SystemPrompt_azure/
#
# Azure OpenAI API version  [OpenAI_apiVersion]  (advanced)
#   What it is for:   The Azure OpenAI API version used when calling your model deployment.
#   Default:          2024-08-01-preview (Risk Analysis, the tier classifier and the profiling engines alike)
#   If you change it: Must be a version your Azure OpenAI resource supports; an unsupported version makes AI calls
#                     fail.
#   When to change:   Rarely; when your deployment needs a newer API version.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Rarely; when your deployment needs a newer API version.
#   More info:        https://invardia.com/docs/si/settings/OpenAI_apiVersion/
#
# Endpoint AI instructions  [SI_SystemPrompt_endpoint]  (engine: endpoint, advanced)
#   What it is for:   Replaces the built-in instructions sent to Azure OpenAI when it classifies devices.
#   Default:          The built-in device classification instructions.
#   If you change it: Changes how AI decides tiers and service types for devices. A poorly written prompt can produce
#                     wrong tiers or unreadable answers, which fall back to a default tier. Has no effect while AI is
#                     off for endpoints.
#   When to change:   Rarely; only to tune AI classification for your estate.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Rarely; only to tune AI classification for your estate.
#   More info:        https://invardia.com/docs/si/settings/SI_SystemPrompt_endpoint/
#
# Identity AI instructions  [SI_SystemPrompt_identity]  (engine: identity, advanced)
#   What it is for:   Reserved for replacing the AI instructions for identity classification.
#   Default:          Not used; identity classification never uses AI.
#   If you change it: No effect today: the identity engine never calls AI, so this text is never sent.
#   When to change:   Never at present; it is kept for future use.
#   Risk:             Affects whether and how AI is used: when AI is used, asset data is sent to YOUR Azure OpenAI
#                     deployment, and it costs per call. Reversible at once; results already produced stay.
#   Recommended:      Keep the default. Change it when: Never at present; it is kept for future use.
#   More info:        https://invardia.com/docs/si/settings/SI_SystemPrompt_identity/
#
# Privilege tier catalog: days kept while unchanged  [SI_PrivilegeTierClassifier_RefreshDays]  (engine: privilege-tier-classifier, advanced, days)
#   What it is for:   How long the privilege tier classifier keeps its catalog while nothing it is made from changed.
#                     Every run reads the Entra role definitions, the API permission catalog and the Azure role
#                     definitions (seconds); when they, the engine and the AI settings are the same as for the last
#                     complete catalog and that catalog is younger than this, the AI pass is skipped and the catalog
#                     is kept.
#   Default:          7 days: the catalog is rebuilt as soon as a role or permission changes, and at least once a week
#   If you change it: A lower value rebuilds (and sends the AI requests) more often; 0 rebuilds on every run, as
#                     before. A catalog that left items untiered is always rebuilt on the next run.
#   When to change:   Set 0 to rebuild every run, for example while you test new tiering prompts; raise it to cut AI
#                     calls further.
#   Risk:             None to the data: a changed role or permission always rebuilds the catalog on the next run; the
#                     setting only decides how long an unchanged catalog is kept. Reversible at once.
#   Recommended:      Keep the default (7).
#   More info:        https://invardia.com/docs/si/settings/SI_PrivilegeTierClassifier_RefreshDays/
#
# ----------------------------------------------------------------------------------------------------
# Connectors & CMDB
# What SecurityInsight reads from and writes to other systems: the CMDB, ServiceNow and asset tags.
# ----------------------------------------------------------------------------------------------------
#
# Asset tagging  [SI_AssetTagging_Enabled]
#   What it is for:   Turns asset tagging on: the asset-tagging rules (for example Auto-CanBeOnboarded--Excluded--SI
#                     for the devices Defender can onboard) apply inside SecurityInsight, and the tagging job may run.
#   Default:          Off: no tagging rule sets a tag anywhere and no report treats a device as excluded because of
#                     one
#   If you change it: On, the asset-tagging rules you have switched on tag the CIs inside SecurityInsight, and a rule
#                     whose tag ends in --Excluded--SI takes the device out of every report. Writing the tags to
#                     Defender, Azure and Entra stays the separate 'Asset tagging writes tags' setting. Off, no
#                     tagging rule tags anything, the tagging job does not run, and a tag an earlier tagging run wrote
#                     is ignored; your own exclusion tags keep working.
#   When to change:   Turn it on when you want the automatic exclusion rules (devices Defender cannot onboard, name
#                     patterns) to take devices out of the reports -- and check the Excluded assets report afterwards.
#   Risk:             The tagging rules you have switched on take devices out of every report (a tag ending in
#                     --Excluded--SI). A wrong rule hides many devices at once. Reversible: turn it off and the next
#                     CI build puts them back.
#   Recommended:      Off until you have decided which automatic exclusions you want; then on, and check the Excluded
#                     assets report.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetTagging_Enabled/
#
# Asset tagging on a server writes tags  [SI_AssetTagging_Apply]  (engine: asset-tagging)
#   What it is for:   Lets the asset-tagging script on a server (launcher.community-vm.ps1) write the tags its rules
#                     select in Defender, Azure and Entra on every run, instead of only reporting them.
#   Default:          Off: report only, every planned tag is logged, nothing is changed
#   If you change it: On, every run changes Defender machine tags, Azure resource tags and Entra custom security
#                     attributes in your tenant; -WhatIfMode on a run still makes that run report only. The identity
#                     also needs the write grants. For one run only, use -Apply instead.
#   When to change:   Turn it on after reviewing the report-only results and granting the tagging write grants. An
#                     install that wrote tags before 3.0 sets it to keep writing.
#   Risk:             Writes to your tenant: every run changes Defender machine tags, Azure resource tags and Entra
#                     custom security attributes. A wrong rule tags or untags many objects at once. Reversible only by
#                     changing the rules and running again (or by hand); the audit trail records every change.
#   Recommended:      Off until the report-only output has been reviewed; then on.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetTagging_Apply/
#
# CMDB enrichment on  [SI_EnableCmdbProvider]
#   What it is for:   Turns on enrichment of assets with data from your CMDB export (CMDB id, name, criticality, data
#                     sensitivity).
#   Default:          Off: CMDB data is not used
#   If you change it: When on and a CMDB.csv is present, profiling runs refresh the CMDB cache and stamp CMDB fields
#                     onto matched assets; CMDB ids in custom rules take effect. When off, they are ignored. In
#                     SecurityInsight Pro the services come from the CMDB in the Pro database (the CMDB page) instead
#                     of a file; a v2.2 CMDB.csv is moved there once by setup, and a CMDB.csv left on disk is not read
#                     (the run warns when the Pro CMDB is empty and a CSV was never moved).
#   When to change:   Turn on when you have a CMDB export (or, in Pro, services on the CMDB page) you want reflected
#                     in reports.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Turn on when you have a CMDB export (or, in Pro, services on
#                     the CMDB page) you want reflected in reports.
#   More info:        https://invardia.com/docs/si/settings/SI_EnableCmdbProvider/
#
# Data out: outputs written  [SI_DataOut_Outputs]
#   What it is for:   Which data-out outputs SecurityInsight writes after each data sync: the Excel workbooks (CIs,
#                     findings, the findings summary, records) and the ServiceNow Import Set hand-offs. Each is a
#                     listed connector whose runs and items are recorded.
#   Default:          Not set: the outputs that are on by default are written
#   If you change it: A list of output ids (for example excel-ci, excel-findings-detailed, servicenow-ci) writes
#                     exactly those and no others; an id that is not an output is left out with a warning. Outputs of
#                     the other edition are never written.
#   When to change:   When you want a workbook or a ServiceNow hand-off that is off by default, or want to stop one
#                     that is on.
#   Risk:             Changes which workbooks and ServiceNow hand-offs are written from the next data sync; an output
#                     switched off stops being refreshed, what it wrote before stays where it is. Reversible: switch
#                     it on again.
#   Recommended:      Leave it empty for the default outputs; name the outputs you need.
#   More info:        https://invardia.com/docs/si/settings/SI_DataOut_Outputs/
#
# Grant asset tagging write rights  [SI_Bootstrap_GrantTaggingRoles]
#   What it is for:   Lets container setup give the asset tagging job's own identity the rights it needs, including
#                     writing tags.
#   Default:          Off: rights are only listed, and the job can only report.
#   If you change it: When on, setup grants the tagging identity its read rights plus write rights for Defender
#                     machine tags, Azure resource tags and Entra security attributes. Tags are written only when
#                     asset tagging is also set to apply.
#   When to change:   When you have decided SecurityInsight may write tags in your tenant.
#   Risk:             Gives the asset tagging identity WRITE rights in your tenant (Defender machine tags, Azure tags,
#                     Entra security attributes). Reversible: remove the role assignments; turning the setting off
#                     does not remove rights already granted.
#   Recommended:      Off unless asset tagging should write; then on for one setup run.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_GrantTaggingRoles/
#
# Where Azure tags may be written  [SI_Bootstrap_TaggingScopes]
#   What it is for:   The Azure scopes, such as subscriptions or resource groups, where the asset tagging identity may
#                     write resource tags.
#   Default:          The same scopes the jobs read from (the subscription by default)
#   If you change it: A narrower list limits where tags can ever be written; a wider list allows tagging in more
#                     places. Rights are granted only when tagging write rights are granted.
#   When to change:   When tags should only be written in part of your estate.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: When tags should only be written in part of your estate.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_TaggingScopes/
#
# Asset tagging identity name  [SI_Bootstrap_TaggingIdentityName]  (advanced)
#   What it is for:   Name of the separate managed identity the asset tagging job runs as, so the collection identity
#                     stays read-only.
#   Default:          uami-securityinsight-tagging
#   If you change it: Setup creates or reuses this identity for the tagging job. It must differ from the collection
#                     identity, or setup stops.
#   When to change:   Only to follow your naming rules before first deployment.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Only to follow your naming rules before first deployment.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_TaggingIdentityName/
#
# Asset tagging rule scope  [Scope]  (advanced)
#   What it is for:   Which asset tagging rules run, by the mode each rule is marked with: PROD, TEST, or both.
#   Default:          PROD: only production rules run.
#   If you change it: Adding TEST also runs rules marked as test rules, which can tag assets with untried logic. Rules
#                     whose mode is not listed are skipped. Risk analysis does not read this setting.
#   When to change:   To try new tagging rules marked TEST before promoting them.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: To try new tagging rules marked TEST before promoting them.
#   More info:        https://invardia.com/docs/si/settings/Scope/
#
# Asset tagging rules folder  [SettingsPath]  (engine: asset-tagging, advanced)
#   What it is for:   The folder the asset tagging engine reads its tagging rule files from.
#   Default:          The shipped rule files next to the endpoint enrichment rules.
#   If you change it: Point it at your own folder to tag with your own rule files instead of the shipped ones. A
#                     missing folder stops the run with a clear error. The Risk Analysis and privilege tier launchers
#                     set their own folder and ignore this value.
#   When to change:   Only when you keep your own tagging rule files outside the installation.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Only when you keep your own tagging rule files outside the
#                     installation.
#   More info:        https://invardia.com/docs/si/settings/SettingsPath/
#
# CMDB cache refresh interval  [SI_CmdbRefreshIntervalHours]  (advanced, hours)
#   What it is for:   How long the cached CMDB data is reused before it is reloaded from the CSV at the start of a
#                     profiling run.
#   Default:          24 hours
#   If you change it: Lower values pick up CMDB changes sooner but re-read the CSV more often; higher values save work
#                     but CMDB changes appear later. A full run always refreshes.
#   When to change:   Rarely. Lower it if your CMDB export changes several times a day.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Rarely. Lower it if your CMDB export changes several times a
#                     day.
#   More info:        https://invardia.com/docs/si/settings/SI_CmdbRefreshIntervalHours/
#
# CMDB export file location  [SI_CmdbCsvPath]  (advanced)
#   What it is for:   Points the CMDB provider at your CMDB export CSV when it is stored outside the SecurityInsight
#                     folder, for example on a file share.
#   Default:          The CMDB.csv in the CMDB provider folder is used
#   If you change it: The CMDB cache is loaded from this file instead of the provider folder. A wrong path means no
#                     CMDB data, so CMDB columns stay empty. In SecurityInsight Pro the file is read once, by setup,
#                     to move it into the CMDB in the Pro database; runs then read the Pro CMDB.
#   When to change:   Only when your CMDB export lives on a share or other folder; leave empty when you drop CMDB.csv
#                     in the provider folder.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Only when your CMDB export lives on a share or other folder;
#                     leave empty when you drop CMDB.csv in the provider folder.
#   More info:        https://invardia.com/docs/si/settings/SI_CmdbCsvPath/
#
# Custom security attribute set  [CsaAttributeSet]  (engine: asset-tagging, advanced)
#   What it is for:   The Entra custom security attribute set that identity tagging rules write their tags into.
#   Default:          SecurityInsight
#   If you change it: Identity tags are written into the named attribute set instead. The set must exist in Entra; a
#                     rule that names its own set still wins over this value.
#   When to change:   Only if your Entra tenant uses a different attribute set name for these tags.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Only if your Entra tenant uses a different attribute set name
#                     for these tags.
#   More info:        https://invardia.com/docs/si/settings/CsaAttributeSet/
#
# Data out: ServiceNow CI Import Set table  [SI_DataOut_ServiceNowCiTable]  (advanced)
#   What it is for:   The ServiceNow Import Set table the CI hand-off output (servicenow-ci) sends its rows to.
#   Default:          Not set: the ServiceNow CI hand-off output is not written, and its run says so
#   If you change it: Rows are sent to this Import Set table, where your transform map creates and updates CIs.
#                     Without it the output does nothing.
#   When to change:   When you switch the servicenow-ci output on.
#   Risk:             Rows go to the named ServiceNow Import Set table; a wrong table name means the rows land where
#                     no transform map reads them. Reversible at once.
#   Recommended:      Keep the default. Change it when: When you switch the servicenow-ci output on.
#   More info:        https://invardia.com/docs/si/settings/SI_DataOut_ServiceNowCiTable/
#
# Data out: ServiceNow resync or test batch  [SI_DataOut_ServiceNowRequest]  (advanced)
#   What it is for:   A one-time request for the ServiceNow outputs, carried out on the next sync: a full resync
#                     (every record in scope sent again as new, in one batch) or a test batch (at most 5 rows per
#                     output, which your importer never imports).
#   Default:          Empty: no request. Each request is carried out once.
#   If you change it: resync:<token> sends every record in scope as new in the next batch (mode resync, imported like
#                     a normal batch). test:<token> first sends a test batch of at most 5 rows per output (mode test,
#                     never imported), then the normal batch.
#   When to change:   After your ServiceNow team rebuilt or emptied its tables (resync), or while it builds and checks
#                     its importer (test batch). Use the buttons on Connectors > ServiceNow: one route.
#   Risk:             A resync sends every record in scope again in one batch; a test batch sends at most 5 rows per
#                     output that the importer never imports. Carried out once per token; nothing is deleted.
#   Recommended:      Keep the default. Change it when: After your ServiceNow team rebuilt or emptied its tables
#                     (resync), or while it builds and checks its importer (test batch). Use the buttons on Connectors
#                     > ServiceNow: one route.
#   More info:        https://invardia.com/docs/si/settings/SI_DataOut_ServiceNowRequest/
#
# Data out: ServiceNow staging status table  [SI_DataOut_ServiceNowStagingStatusTable]  (advanced)
#   What it is for:   The ServiceNow import set table where SecurityInsight says when each push of a ServiceNow output
#                     starts (writing) and ends (complete, failed or held). Every data row carries the same batch id,
#                     so your importer imports a batch only once it is complete.
#   Default:          u_si_staging_status. An install that sent to ServiceNow before the staging status table existed
#                     has it empty: the rows are sent without it, with a warning, until your ServiceNow team creates
#                     the table and you set its name here.
#   If you change it: Set: each push is one batch -- a writing row first, the batch id on every data row, then a
#                     complete, failed or held row. If the table is missing or lacks a column, nothing is sent. Empty:
#                     the rows are sent without a batch, and the ServiceNow check warns.
#   When to change:   After your ServiceNow team has created the staging status table (Connectors > the ServiceNow
#                     data-out connector > For your ServiceNow team), if it has another name than the default -- or,
#                     on an install that has it empty, to switch it on.
#   Risk:             Set to a table that does not exist on the instance, nothing is sent to ServiceNow until it is
#                     there (the ServiceNow check says why). Empty, your importer cannot tell a finished push from one
#                     that stopped halfway. Reversible at once.
#   Recommended:      Keep the default. Change it when: After your ServiceNow team has created the staging status
#                     table (Connectors > the ServiceNow data-out connector > For your ServiceNow team), if it has
#                     another name than the default -- or, on an install that has it empty, to switch it on.
#   More info:        https://invardia.com/docs/si/settings/SI_DataOut_ServiceNowStagingStatusTable/
#
# Data out: ServiceNow vulnerable item Import Set table  [SI_DataOut_ServiceNowVulnTable]  (advanced)
#   What it is for:   The ServiceNow Import Set table the vulnerable item output (servicenow-vulnerable-item) sends
#                     its rows to.
#   Default:          Not set: the ServiceNow vulnerable item output is not written, and its run says so
#   If you change it: Rows are sent to this Import Set table, where your transform map creates and updates vulnerable
#                     items. Without it the output does nothing.
#   When to change:   When you switch the servicenow-vulnerable-item output on.
#   Risk:             Rows go to the named ServiceNow Import Set table; a wrong table name means the rows land where
#                     no transform map reads them. Reversible at once.
#   Recommended:      Keep the default. Change it when: When you switch the servicenow-vulnerable-item output on.
#   More info:        https://invardia.com/docs/si/settings/SI_DataOut_ServiceNowVulnTable/
#
# Shipped asset tagging rules file  [LockedYamlFile]  (engine: asset-tagging, advanced)
#   What it is for:   File name of the shipped asset tagging rules in the rules folder.
#   Default:          AssetTagging.locked.yaml
#   If you change it: The engine loads the shipped rules from this file. A wrong name loses the shipped rules; with
#                     neither rules file present the run stops. Ignored when rules come from the Pro settings
#                     database.
#   When to change:   Practically never; the shipped name should be kept.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Practically never; the shipped name should be kept.
#   More info:        https://invardia.com/docs/si/settings/LockedYamlFile/
#
# Your asset tagging rules file  [CustomYamlFile]  (engine: asset-tagging, advanced)
#   What it is for:   File name of your own asset tagging rules, loaded from the rules folder on top of the shipped
#                     rules.
#   Default:          AssetTagging.custom.yaml
#   If you change it: Rules in this file are added to the shipped rules. If the file does not exist, only the shipped
#                     rules run. Ignored when rules come from the Pro settings database.
#   When to change:   Only if you keep your tagging rules under another file name.
#   Risk:             Affects what SecurityInsight writes to your CMDB or ticketing systems. Reversible for future
#                     runs, but changes already written there stay; the connector's own guards hold large or unsafe
#                     changes.
#   Recommended:      Keep the default. Change it when: Only if you keep your tagging rules under another file name.
#   More info:        https://invardia.com/docs/si/settings/CustomYamlFile/
#
# ----------------------------------------------------------------------------------------------------
# Data & retention
# Where collected data is written, how much detail it keeps, and how long it is kept.
# ----------------------------------------------------------------------------------------------------
#
# Azure collection outputs  [SI_Sinks_Azure]  (engine: azure)
#   What it is for:   Chooses where the Azure collection writes its results: Log Analytics (LA), JSON files and/or
#                     Excel files.
#   Default:          All three: Log Analytics, JSON and Excel
#   If you change it: Leaving out LA means no Azure data in your workspace, so Risk Analysis and workbooks miss it;
#                     the collected records still go to the database. Leaving out JSON or Excel only saves local files
#                     and time.
#   When to change:   Most installs never should; drop file outputs if nobody uses them.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Most installs never should; drop file outputs if nobody uses
#                     them.
#   More info:        https://invardia.com/docs/si/settings/SI_Sinks_Azure/
#
# Copy findings per CI to Log Analytics (SI_Finding_CL)  [SI_RA_Findings]
#   What it is for:   Optional. After each Risk Analysis Detailed run, copies the de-duplicated findings (one row per
#                     CI and finding) into your Log Analytics workspace, for your own workbooks, Sentinel or KQL.
#                     SecurityInsight itself does not need it: its pages read the findings from its database. On a
#                     large estate the copy can take hours and adds Log Analytics ingestion cost. Off by default.
#   Default:          Off: the findings per CI are kept in the database only
#   If you change it: On: at the end of every Risk Analysis Detailed run its findings per CI are also posted to
#                     SI_Finding_CL, and the run ends when the copy has ended. On a large estate that is hours, and it
#                     costs ingestion for every finding, every run. The data sync reads that copy back only when it is
#                     the newest and whole; otherwise it makes the findings per CI from the database, as it does with
#                     the copy off. Off: nothing is copied. This is not the Risk Analysis report rows
#                     (SI_RiskAnalysis_Detailed_CL): they are their own optional output, Copy Risk Analysis report
#                     rows to Log Analytics, off by default.
#   When to change:   Only when your own workbooks, Sentinel rules or KQL queries read SI_Finding_CL; leave off
#                     otherwise.
#   Risk:             Longer Risk Analysis Detailed runs and Log Analytics ingestion cost for every finding, every
#                     run. SecurityInsight itself does not need the copy. Reversible: turn it off and the next run
#                     copies nothing.
#   Recommended:      Off, unless your own workbooks, Sentinel rules or KQL read SI_Finding_CL.
#   More info:        https://invardia.com/docs/si/settings/SI_RA_Findings/
#
# Endpoint collection outputs  [SI_Sinks_Endpoint]  (engine: endpoint)
#   What it is for:   Chooses where the endpoint collection writes its results: Log Analytics (LA), JSON files and/or
#                     Excel files.
#   Default:          All three: Log Analytics, JSON and Excel
#   If you change it: Leaving out LA means no endpoint data in your workspace, so Risk Analysis and workbooks miss it;
#                     the collected records still go to the database. Leaving out JSON or Excel only saves local files
#                     and time.
#   When to change:   Most installs never should; drop file outputs if nobody uses them.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Most installs never should; drop file outputs if nobody uses
#                     them.
#   More info:        https://invardia.com/docs/si/settings/SI_Sinks_Endpoint/
#
# Identity collection outputs  [SI_Sinks_Identity]  (engine: identity)
#   What it is for:   Chooses where the identity collection writes its results: Log Analytics (LA), JSON files and/or
#                     Excel files.
#   Default:          All three: Log Analytics, JSON and Excel
#   If you change it: Leaving out LA means no identity data in your workspace, so Risk Analysis and workbooks miss it;
#                     the collected records still go to the database. Leaving out JSON or Excel only saves local files
#                     and time.
#   When to change:   Most installs never should; drop file outputs if nobody uses them.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Most installs never should; drop file outputs if nobody uses
#                     them.
#   More info:        https://invardia.com/docs/si/settings/SI_Sinks_Identity/
#
# Public IP collection outputs  [SI_Sinks_PublicIp]  (engine: publicip)
#   What it is for:   Chooses where the public IP collection writes its results: Log Analytics (LA), JSON files and/or
#                     Excel files.
#   Default:          All three: Log Analytics, JSON and Excel
#   If you change it: Leaving out LA means no public IP data in your workspace, so Risk Analysis and workbooks miss
#                     it; the collected records still go to the database. Leaving out JSON or Excel only saves local
#                     files and time.
#   When to change:   Most installs never should; drop file outputs if nobody uses them.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Most installs never should; drop file outputs if nobody uses
#                     them.
#   More info:        https://invardia.com/docs/si/settings/SI_Sinks_PublicIp/
#
# Run log retention  [SI_LogRetentionDays]  (days)
#   What it is for:   How many days run logs are kept, both on the local disk and in the storage account, before being
#                     deleted.
#   Default:          30 days.
#   If you change it: Longer keeps more history for investigating past runs, using more disk and storage space.
#                     Shorter frees space but older runs can no longer be checked.
#   When to change:   When your audit or troubleshooting needs require a longer or shorter history.
#   Risk:             A shorter value deletes older run logs: past runs can no longer be investigated. Cannot be
#                     undone.
#   Recommended:      30 days.
#   More info:        https://invardia.com/docs/si/settings/SI_LogRetentionDays/
#
# Status reports to Invardia  [SI_Telemetry_Enabled]
#   What it is for:   Whether the install sends Invardia one status report a day and one short report per engine run:
#                     which engine ran, whether it ended ok, with warnings or failed, how long it took, the stage and
#                     the kind of error. Community reports are anonymous (a random install id; no tenant, host name or
#                     error text; counts only as ranges). Pro reports are identified by the install key and carry the
#                     error text with secrets removed.
#   Default:          On
#   If you change it: Off sends nothing at all: no report is built, no file is written and Invardia is never contacted
#                     for this. For Pro, Invardia then cannot see failed or silent runs and warn you about them.
#   When to change:   Turn it off if your organisation does not allow status reports to leave the environment.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Turn it off if your organisation does not allow status reports
#                     to leave the environment.
#   More info:        https://invardia.com/docs/si/settings/SI_Telemetry_Enabled/
#
# Asset detail level  [SI_PayloadProfile]  (advanced)
#   What it is for:   Chooses how much detail is kept per asset: everything collected (cmdb) or only the columns the
#                     schema declares (security).
#   Default:          cmdb: every collected property is kept
#   If you change it: security gives smaller rows and lower ingest cost, but drops undeclared properties that queries
#                     or dashboards may use; dropped fields are listed in the run log. An unknown value falls back to
#                     cmdb.
#   When to change:   Consider security only if ingest volume matters more than a full asset inventory.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Consider security only if ingest volume matters more than a
#                     full asset inventory.
#   More info:        https://invardia.com/docs/si/settings/SI_PayloadProfile/
#
# Copy records to Log Analytics  [SI_LaExport]  (advanced)
#   What it is for:   Optionally copies the provider records (every object a collection reads, mapped to SI fields) to
#                     Log Analytics, for Azure Monitor or your own workbooks.
#   Choices:          'off' (Off: records in the database only); 'records' (Records: also copy them to Log Analytics)
#   Default:          off: the records are kept only in the database
#   If you change it: 'records' also posts every record to SI_Record_CL (and, for the providers raw data is on for,
#                     the whole object to SI_RecordRaw_CL) on every collection run. This costs Log Analytics ingestion
#                     for every record, every run. It is a one-way copy: correlation, the CI build and the data sync
#                     read the records from the database only and never read this copy back. The CIs (SI_CI_CL) are in
#                     Log Analytics in every install, because Risk Analysis reads them there, so they need no setting;
#                     the findings per CI are copied there only when Copy findings per CI to Log Analytics
#                     (SI_Finding_CL) is on.
#   When to change:   Only when you build your own Azure Monitor alerts or workbooks on the raw provider records;
#                     leave off otherwise.
#   Risk:             Changes how long data is kept or how quickly assets are treated as gone. Shortening a retention
#                     DELETES older data at the next clean-up and that cannot be undone; shortening a grace period
#                     retires assets (and closes their findings) sooner. Lengthening is safe but uses more storage.
#   Recommended:      Keep the default. Change it when: Only when you build your own Azure Monitor alerts or workbooks
#                     on the raw provider records; leave off otherwise.
#   More info:        https://invardia.com/docs/si/settings/SI_LaExport/
#
# Database busy above (percent)  [SI_SqlPacing_HighPercent]  (advanced, percent)
#   What it is for:   The database load (the highest of log write, data reads and CPU, in percent of what its tier
#                     allows) above which the large writers slow down.
#   Default:          85
#   If you change it: Lower: the writers make room for the web app sooner, and a full run takes longer on a busy
#                     database. Higher: the writers keep their pace until the database is closer to its limit. A value
#                     that is not a number from 1 to 100 uses 85.
#   When to change:   Lower it if the web app is slow during the daily run; raise it if the run must finish sooner and
#                     nobody uses the web app then.
#   Risk:             Only changes how soon the large writers slow down: a lower value gives the web app more room and
#                     makes a full run take longer on a busy database. No data is changed. Reversible at once.
#   Recommended:      Keep 85.
#   More info:        https://invardia.com/docs/si/settings/SI_SqlPacing_HighPercent/
#
# Database calm again below (percent)  [SI_SqlPacing_LowPercent]  (advanced, percent)
#   What it is for:   The database load below which the large writers go back to their full pace after they slowed
#                     down.
#   Default:          70
#   If you change it: Between this and the busy mark a writer keeps the pause it has. Must be below the busy mark; a
#                     value at or above it uses the busy mark minus 15.
#   When to change:   Rarely. Lower it if the writers speed up and slow down again and again.
#   Risk:             Only changes when the large writers go back to full pace. No data is changed. Reversible at
#                     once.
#   Recommended:      Keep 70.
#   More info:        https://invardia.com/docs/si/settings/SI_SqlPacing_LowPercent/
#
# Send the data health result to Invardia  [SI_Telemetry_SendHealth]  (advanced)
#   What it is for:   Pro installs with an install key send Invardia the daily data health result -- the state and,
#                     per source and report, how many records were checked, found, missing and different. Counts only:
#                     no names, ids or values.
#   Default:          On -- switch it off to send nothing about data health
#   If you change it: On: every daily check, and at once when the state changes, the counts go to Invardia, which uses
#                     them to hold an update ring from moving on. Off: nothing about data health is sent.
#   When to change:   Keep it on. Switch it off only if your organisation does not allow the data health counts to
#                     leave the environment.
#   Risk:             On: the daily data health counts go to Invardia (no names or ids); an Unhealthy install then
#                     holds the update ring from moving on. Off: Invardia does not know the data health of this
#                     install. Reversible at once.
#   Recommended:      Keep the default. Change it when: Keep it on. Switch it off only if your organisation does not
#                     allow the data health counts to leave the environment.
#   More info:        https://invardia.com/docs/si/settings/SI_Telemetry_SendHealth/
#
# Send this install's links to Invardia  [SI_Telemetry_SendEndpoints]  (advanced)
#   What it is for:   Pro installs with an install key can send Invardia this install's own links -- the web app's and
#                     the MCP server's addresses -- with the daily status report, so every mail Invardia sends about
#                     this environment carries an Open SecurityInsight button. Only the addresses are sent: no names,
#                     no secrets.
#   Default:          On -- switch it off to send no links
#   If you change it: On: the daily status report carries the web app's and the MCP server's addresses (read from the
#                     install's own hosting). Off: it carries no links. A failed run's report links to the run health
#                     page either way.
#   When to change:   Switch it off only if Invardia should not see this install's web app and MCP addresses.
#   Risk:             Changes only what Invardia sees: the web app's and the MCP server's addresses; nothing in your
#                     tenant changes. Reversible at once.
#   Recommended:      Keep the default (on).
#   More info:        https://invardia.com/docs/si/settings/SI_Telemetry_SendEndpoints/
#
# Setup report to Invardia  [SI_Telemetry_SetupControls]  (advanced)
#   What it is for:   Pro installs with an install key send Invardia one setup report a day: a list of critical
#                     settings (updater, update ring, install key, licence, mail, permissions, last run, backup) with
#                     ok / missing / wrong / unknown, so Invardia can see what is not set up and help you. No secrets,
#                     no names of people and no error text are sent.
#   Choices:          'minimum'; 'all'; 'off'
#   Default:          all: every control, SecurityInsight's own too (sent again with only the minimum list when
#                     Invardia does not take it)
#   If you change it: 'all' (the default) sends the minimum list every product shares and SecurityInsight's own
#                     controls (SQL database reachable, job layout, run limits, last daily run, data sources, last CI
#                     build, Log Analytics ingestion, licence edition); when Invardia does not take that report, it is
#                     sent again once with only the minimum list, and the run log says so. 'minimum' sends only the
#                     minimum list. 'off' sends no setup report; the daily status report and the run reports are not
#                     affected. Status reports to Invardia off (SI_Telemetry_Enabled) turns this off too.
#   When to change:   Keep 'all'. Choose 'minimum' to send only the shared list, or 'off' if your organisation does
#                     not allow the setup state to leave the environment.
#   Risk:             Changes only what Invardia sees about this install's setup; nothing in your tenant changes. When
#                     Invardia does not take the full list ('all'), the report goes again once with the minimum list;
#                     the daily status report and the run reports are not affected. 'off' means Invardia cannot see a
#                     missing setting and offer help.
#   Recommended:      Keep the default (all).
#   More info:        https://invardia.com/docs/si/settings/SI_Telemetry_SetupControls/
#
# Slow down large writes when the database is busy  [SI_SqlPacing_Enabled]  (advanced)
#   What it is for:   Whether the large database writers (Risk Analysis storing its findings, the data sync preparing
#                     the views, the removal of old collections) look at how busy the database is before each batch.
#   Default:          On
#   If you change it: On: while the database is at its limit (log write, data reads or CPU above the high mark), each
#                     writer pauses before its next batch and writes smaller batches, so the web app and the other
#                     jobs keep a share; below the low mark it writes at full pace again. Nothing is left out -- the
#                     same rows are written, only slower while the database is saturated. Off: the writers always
#                     write at full pace.
#   When to change:   Leave it on. Switch it off only if support asks you to.
#   Risk:             Off: on a busy database the large writers keep it at its limit for as long as the daily run
#                     writes, and the web app is slow meanwhile. No data is changed either way. Reversible at once.
#   Recommended:      On (the default).
#   More info:        https://invardia.com/docs/si/settings/SI_SqlPacing_Enabled/
#
# ----------------------------------------------------------------------------------------------------
# Sign-in & Azure resources
# Set at install and rarely changed: how SecurityInsight signs in, and the names of the Azure
# resources it uses.
# ----------------------------------------------------------------------------------------------------
#
# Azure region  [SI_Location]
#   What it is for:   The Azure region setup creates the workspace, endpoint, storage and container resources in. A
#                     collection run creates no Azure resource, so it does not need it.
#   Default:          Not set: setup asks for the region; a collection run does not use it
#   If you change it: Decides where setup creates new resources. Existing resources are not moved. Risk Analysis falls
#                     back to Location, then westeurope.
#   When to change:   Set once at install to your preferred region.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set once at install to your preferred region.
#   More info:        https://invardia.com/docs/si/settings/SI_Location/
#
# Container hosting region  [SI_Bootstrap_Location]
#   What it is for:   The Azure region where container setup creates the registry, environment and identities.
#   Default:          Uses SI_Location; setup stops if neither is set.
#   If you change it: All container resources are created in this region. It should match your other SecurityInsight
#                     resources; changing it later creates new resources in the new region.
#   When to change:   Set it once at setup if containers should live in a different region than SI_Location.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set it once at setup if containers should live in a different
#                     region than SI_Location.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_Location/
#
# Container resource group  [SI_Bootstrap_ResourceGroupName]
#   What it is for:   The Azure resource group where container setup creates the registry, environment, identities and
#                     jobs.
#   Default:          rg-securityinsight (new installs get a name chosen by setup)
#   If you change it: All container resources go into this group. Its presence also marks the install as
#                     container-hosted, so updates and checks treat it that way; a new name creates everything anew
#                     there.
#   When to change:   Set once at setup to follow your naming rules; remove it on a machine-only install.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set once at setup to follow your naming rules; remove it on a
#                     machine-only install.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ResourceGroupName/
#
# Data collection endpoint name  [SI_DceName]
#   What it is for:   Name of the data collection endpoint all engines send their data to Log Analytics through.
#   Default:          Not set: endpoint pinning is skipped; setup may create dce-si-securityinsight
#   If you change it: Tells the engines which endpoint to use. A wrong name stops ingestion or, during setup, creates
#                     a new endpoint. Run health rows are not sent without it.
#   When to change:   Set at install to the endpoint your setup created; change only if you rename or move it.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set at install to the endpoint your setup created; change only
#                     if you rename or move it.
#   More info:        https://invardia.com/docs/si/settings/SI_DceName/
#
# Data collection rules resource group  [SI_DcrResourceGroup]
#   What it is for:   Resource group holding the data collection rules (and, by default, the endpoint) used to send
#                     data to Log Analytics.
#   Default:          Not set: Risk Analysis uses DcrResourceGroup; setup uses rg-securityinsight
#   If you change it: Tells engines where to find and create rules. A wrong group creates duplicate rules or refuses
#                     to post. Run health rows are not sent without it.
#   When to change:   Set at install; change only if you move the rules.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set at install; change only if you move the rules.
#   More info:        https://invardia.com/docs/si/settings/SI_DcrResourceGroup/
#
# Defender data workspace  [SI_DefenderWorkspaceResourceId]  (engine: endpoint)
#   What it is for:   Full resource id of a separate Log Analytics workspace holding Defender data, when it is not the
#                     SecurityInsight workspace.
#   Default:          Not set: Defender data is read from the SecurityInsight workspace
#   If you change it: Identity discovery and Risk Analysis queries read Defender tables from this workspace. A wrong
#                     value makes those queries return nothing or fail.
#   When to change:   Only when your Defender data is in a different workspace than SecurityInsight's own.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when your Defender data is in a different workspace than
#                     SecurityInsight's own.
#   More info:        https://invardia.com/docs/si/settings/SI_DefenderWorkspaceResourceId/
#
# Jobs sign in with managed identity  [SI_Bootstrap_UseManagedIdentity]
#   What it is for:   Makes all container jobs sign in as one user-assigned managed identity, said explicitly.
#   Default:          Not set: the managed identity anyway, unless the configuration carries a client secret (an
#                     existing install keeps it).
#   If you change it: On, setup creates the identity and the jobs carry no secret; the image is also pulled as that
#                     identity. Its rights are listed, and granted only when setup is told to grant them; some
#                     database access is a one-time manual step.
#   When to change:   To move an existing install that signs in with a client secret to a managed identity; guided
#                     installs switch it on.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: To move an existing install that signs in with a client secret
#                     to a managed identity; guided installs switch it on.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_UseManagedIdentity/
#
# Key Vault name  [SI_KeyVaultName]
#   What it is for:   The one Key Vault SecurityInsight reads its secrets from: the sign-in secret, integration
#                     credentials and a Pro licence.
#   Default:          Falls back to SpnKeyVaultName; with neither set, secret reads stop with an error
#   If you change it: All secrets are read from the named vault. A wrong name means sign-in secrets, keys and the
#                     licence cannot be read and runs fail or run as Community.
#   When to change:   Setup writes it. Change only if you move secrets to another Key Vault.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Setup writes it. Change only if you move secrets to another
#                     Key Vault.
#   More info:        https://invardia.com/docs/si/settings/SI_KeyVaultName/
#
# Log Analytics workspace  [SI_WorkspaceResourceId]
#   What it is for:   Full Azure resource id of the Log Analytics workspace all engines write to and query.
#   Default:          Not set: correlation, CMDB and vulnerability engines stop; others fall back
#   If you change it: Decides where all SecurityInsight data lands and is read from; also gives the subscription for
#                     ingestion. Changing it starts a new data history in the new workspace.
#   When to change:   Set at install; change only when moving to another workspace.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set at install; change only when moving to another workspace.
#   More info:        https://invardia.com/docs/si/settings/SI_WorkspaceResourceId/
#
# Log Analytics workspace name  [SI_WorkspaceName]
#   What it is for:   Name of the Log Analytics workspace SecurityInsight writes its data to and reads from.
#   Default:          log-platform-management-securityinsight when the resource id gives none
#   If you change it: Used when creating a missing workspace and in run messages; Risk Analysis uses it when no
#                     workspace resource id is set. A wrong name can make setup create a new workspace.
#   When to change:   Set at install; the workspace resource id is the main setting.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set at install; the workspace resource id is the main setting.
#   More info:        https://invardia.com/docs/si/settings/SI_WorkspaceName/
#
# Service principal app id  [SI_SPN_AppId]
#   What it is for:   Application (client) id of the service principal the engines sign in as when not using managed
#                     identity.
#   Default:          Taken from SpnClientId or the platform; if none, managed identity
#   If you change it: Decides which app registration reads data and ingests results; that app needs the required
#                     Graph, Azure and Log Analytics permissions. Without it, no service principal sign-in happens.
#   When to change:   Set during setup when you use a service principal; change when moving to a different app.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set during setup when you use a service principal; change when
#                     moving to a different app.
#   More info:        https://invardia.com/docs/si/settings/SI_SPN_AppId/
#
# Service principal client secret  [SI_SPN_Secret]  (secret)
#   What it is for:   Client secret of the service principal when the sign-in method is Secret.
#   Default:          Not set: certificate or managed identity is used
#   If you change it: Enables secret-based sign-in. If a certificate thumbprint is also set, the certificate wins and
#                     the secret is ignored. Secrets expire and must be rotated.
#   When to change:   Only when you cannot use managed identity or a certificate; rotate via your Key Vault procedure.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Only when you cannot use managed identity or a certificate;
#                     rotate via your Key Vault procedure.
#   More info:        https://invardia.com/docs/si/settings/SI_SPN_Secret/
#
# Service principal tenant id  [SI_SPN_TenantId]
#   What it is for:   The Entra tenant the service principal signs in to, for data reads and Log Analytics ingestion.
#   Default:          Taken from SpnTenantId, the platform, or the managed identity's sign-in
#   If you change it: Decides which tenant is read. A wrong value makes sign-in fail or targets the wrong tenant.
#   When to change:   Set during setup when you use a service principal.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set during setup when you use a service principal.
#   More info:        https://invardia.com/docs/si/settings/SI_SPN_TenantId/
#
# Sign-in certificate thumbprint  [SI_SPN_CertThumbprint]
#   What it is for:   Thumbprint of the service principal's certificate, with its private key in the certificate
#                     store, used for certificate sign-in.
#   Default:          Taken from the platform's certificate setting if present; else no certificate sign-in
#   If you change it: Lets the engines, ingestion and SQL connections sign in with this certificate. A wrong or
#                     missing certificate makes certificate sign-in fail; with both certificate and secret set, the
#                     certificate is preferred.
#   When to change:   Set at install and when the certificate is renewed.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set at install and when the certificate is renewed.
#   More info:        https://invardia.com/docs/si/settings/SI_SPN_CertThumbprint/
#
# Sign-in method  [SI_AuthMethod]
#   What it is for:   Chooses how SecurityInsight signs in to Microsoft services: managed identity, service principal
#                     with certificate, or service principal with client secret.
#   Default:          Keeps a configured service principal; otherwise the host's managed identity
#   If you change it: Decides which identity every engine uses, and therefore which permissions must be granted. An
#                     unknown value stops the run with an error. Choosing a service principal switches
#                     managed-identity sign-in off.
#   When to change:   Set during setup. Change when moving between managed identity and a service principal.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set during setup. Change when moving between managed identity
#                     and a service principal.
#   More info:        https://invardia.com/docs/si/settings/SI_AuthMethod/
#
# Staging storage account  [SI_StorageAccount]
#   What it is for:   The storage account the collection engines use for staging data, caches, the shared catalog and
#                     the identity ledger.
#   Default:          Not set: collection engines stop with an error
#   If you change it: Required for endpoint, identity, Azure and public IP collection. It is reached only with the
#                     signed-in identity, which needs the Storage Blob, Queue and Table Data Contributor roles on it.
#                     Changing it starts staging and caches from empty.
#   When to change:   Set at install; change only when moving to a new storage account.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set at install; change only when moving to a new storage
#                     account.
#   More info:        https://invardia.com/docs/si/settings/SI_StorageAccount/
#
# Storage account resource group  [SI_StorageResourceGroup]
#   What it is for:   Names the Azure resource group that holds the SecurityInsight storage account. Setup creates the
#                     account and grants its permissions there; a collection run only checks that the account is
#                     there.
#   Default:          Same resource group as the workspace (or the data collection rules)
#   If you change it: Setup looks the storage account up, creates it and grants permissions in this resource group; a
#                     run that does not find it there says so in one line and creates nothing. A wrong value makes
#                     setup create a second account in the wrong place.
#   When to change:   Only when your storage account lives in a different resource group from the workspace; setup
#                     normally writes it.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when your storage account lives in a different resource
#                     group from the workspace; setup normally writes it.
#   More info:        https://invardia.com/docs/si/settings/SI_StorageResourceGroup/
#
# User-assigned managed identity  [SI_ManagedIdentityClientId]
#   What it is for:   Client id of a user-assigned managed identity to sign in with when the sign-in method is managed
#                     identity.
#   Default:          Empty: the host's system-assigned identity
#   If you change it: Selects which managed identity holds the permissions. A wrong client id makes sign-in fail;
#                     empty uses the Azure VM's or Arc server's own identity.
#   When to change:   Only when you sign in with a user-assigned identity instead of the host's system-assigned one.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when you sign in with a user-assigned identity instead of
#                     the host's system-assigned one.
#   More info:        https://invardia.com/docs/si/settings/SI_ManagedIdentityClientId/
#
# Workspace resource group  [SI_WorkspaceResourceGroup]
#   What it is for:   Names the Azure resource group of the Log Analytics workspace the engines write to.
#   Default:          Taken from the workspace resource id; otherwise 'rg-securityinsight'
#   If you change it: The workspace is looked up in this resource group (setup creates it there). A collection run
#                     creates nothing: a workspace it does not find is said in one line, and the send fails.
#   When to change:   Set once during setup to match your workspace; change only if the workspace moves.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Set once during setup to match your workspace; change only if
#                     the workspace moves.
#   More info:        https://invardia.com/docs/si/settings/SI_WorkspaceResourceGroup/
#
# Azure profile collection rule  [SI_Azure_DcrName]  (advanced)
#   What it is for:   Name of the data collection rule the Azure profiling engine sends its results through.
#   Default:          dcr-si-azure-profile (from the standard naming pattern).
#   If you change it: Azure profile rows are ingested through this rule instead. Useful to avoid picking up a
#                     same-named rule from an older install; a wrong name makes ingestion fail.
#   When to change:   Only when another rule with the standard name is visible to the identity.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when another rule with the standard name is visible to
#                     the identity.
#   More info:        https://invardia.com/docs/si/settings/SI_Azure_DcrName/
#
# Azure profile table name  [SI_Azure_TableName]  (advanced)
#   What it is for:   Log Analytics table the Azure profiling engine writes its asset profiles to.
#   Default:          SI_Azure_Profile (stored as SI_Azure_Profile_CL).
#   If you change it: Azure profiles go to this table instead. Risk Analysis and workbooks that read the standard
#                     table will no longer see new Azure data unless changed too.
#   When to change:   Almost never; only to avoid a clash with an existing table.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a clash with an existing table.
#   More info:        https://invardia.com/docs/si/settings/SI_Azure_TableName/
#
# Azure recommendations collection rule  [SI_AzureRecommendation_DcrName]  (advanced)
#   What it is for:   Name of the data collection rule used to send Defender for Cloud recommendations to Log
#                     Analytics.
#   Default:          dcr-si-azure-recommendation
#   If you change it: Recommendations are sent through this rule instead. A rule that does not match the
#                     recommendations table makes them stop arriving.
#   When to change:   Almost never; only to avoid a name clash with an existing rule.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a name clash with an existing
#                     rule.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureRecommendation_DcrName/
#
# Azure recommendations table name  [SI_AzureRecommendation_TableName]  (advanced)
#   What it is for:   Log Analytics table that receives Defender for Cloud recommendations collected with the Azure
#                     engine.
#   Default:          SI_AzureRecommendation (stored as SI_AzureRecommendation_CL).
#   If you change it: Recommendations go to this table instead. Queries reading the standard table will no longer see
#                     new rows.
#   When to change:   Almost never; only to avoid a clash with an existing table.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a clash with an existing table.
#   More info:        https://invardia.com/docs/si/settings/SI_AzureRecommendation_TableName/
#
# Azure subscription for ingestion  [SI_AzSubscriptionId]  (advanced)
#   What it is for:   The Azure subscription in which the engines look up and create the data collection endpoint and
#                     rules.
#   Default:          Taken from the workspace resource id, else SubscriptionId
#   If you change it: Scopes all endpoint and rule lookups and resource creation to this subscription. A wrong value
#                     makes ingestion refuse to post or create resources in the wrong subscription.
#   When to change:   Only when the ingestion resources live in a different subscription than the workspace.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when the ingestion resources live in a different
#                     subscription than the workspace.
#   More info:        https://invardia.com/docs/si/settings/SI_AzSubscriptionId/
#
# Certificate store location  [SI_SPN_CertStoreLocation]  (advanced)
#   What it is for:   Which Windows certificate store (LocalMachine or CurrentUser) holds the sign-in certificate of
#                     the service principal.
#   Default:          Detected: the store that holds the certificate with its key, else LocalMachine
#   If you change it: Forces the store used for certificate sign-in. A wrong store makes certificate sign-in fail.
#                     Containers always use CurrentUser.
#   When to change:   Rarely; only if automatic detection picks the wrong store on your host.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Rarely; only if automatic detection picks the wrong store on
#                     your host.
#   More info:        https://invardia.com/docs/si/settings/SI_SPN_CertStoreLocation/
#
# Container Apps environment name  [SI_Bootstrap_EnvName]  (advanced)
#   What it is for:   Name of the Azure Container Apps environment the SecurityInsight jobs run in; container setup
#                     creates it if it does not exist.
#   Default:          cae-securityinsight (new installs get a name chosen by setup)
#   If you change it: All jobs are created in this environment. A new name creates a new environment and new jobs
#                     there; the old ones are left in place.
#   When to change:   Only before the first container setup, to follow your naming rules.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only before the first container setup, to follow your naming
#                     rules.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_EnvName/
#
# Container hosting subscription  [SI_Bootstrap_SubscriptionId]  (advanced)
#   What it is for:   The Azure subscription the SecurityInsight containers are installed in, saved by setup so later
#                     updates and upgrades work in the same subscription.
#   Default:          Falls back to SI_AzSubscriptionId, then the workspace subscription, then the signed-in Azure
#                     context.
#   If you change it: Container setup, updates and upgrades create and look for the containers in this subscription. A
#                     wrong value points updates at a subscription where the containers do not exist.
#   When to change:   Setup writes it. Change only if the container hosting was moved to another subscription.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Setup writes it. Change only if the container hosting was
#                     moved to another subscription.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_SubscriptionId/
#
# Container image tag  [SI_Bootstrap_ImageTag]  (advanced)
#   What it is for:   The tag of the container image that setup builds and every scheduled job runs.
#   Default:          latest
#   If you change it: Jobs run the image with this tag. A different tag lets you keep or test a specific build; a tag
#                     that was never built makes the jobs fail to start.
#   When to change:   Only to pin or test a specific image build.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only to pin or test a specific image build.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_ImageTag/
#
# Container registry name  [SI_Bootstrap_AcrName]  (advanced)
#   What it is for:   Name of the Azure Container Registry that holds the SecurityInsight container image; container
#                     setup creates it if it does not exist.
#   Default:          acrsecurityinsight (new installs get a name chosen by setup)
#   If you change it: Setup builds and stores the image in this registry and the jobs pull from it. A new name creates
#                     a new registry and image; updates also use it to find a container install.
#   When to change:   Only before the first container setup, to follow your naming rules.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only before the first container setup, to follow your naming
#                     rules.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_AcrName/
#
# Data collection endpoint resource group  [SI_DceResourceGroup]  (advanced)
#   What it is for:   The resource group that holds the data collection endpoint used to send data to Log Analytics.
#   Default:          Same resource group as the data collection rules
#   If you change it: Tells the engines where to find the endpoint. A wrong value makes runs refuse to post when
#                     several endpoints share the name, or print misleading ingestion lines.
#   When to change:   Only when you have deliberately placed the endpoint in a different resource group than the
#                     rules.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when you have deliberately placed the endpoint in a
#                     different resource group than the rules.
#   More info:        https://invardia.com/docs/si/settings/SI_DceResourceGroup/
#
# Detailed report data collection rule  [SI_RiskAnalysis_DcrName_Detailed]  (advanced)
#   What it is for:   The name of the data collection rule the detailed Risk Analysis rows are sent through to Log
#                     Analytics.
#   Default:          dcr-si-risk-analysis-detailed
#   If you change it: Detailed rows are sent through the named rule. A wrong name makes the detailed report ingest
#                     fail.
#   When to change:   Only if you renamed the rule or must avoid a name clash with another install.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you renamed the rule or must avoid a name clash with
#                     another install.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_DcrName_Detailed/
#
# Detailed Risk Analysis table name  [SI_RiskAnalysis_TableName_Detailed]  (engine: risk-analysis, advanced)
#   What it is for:   Name of the Log Analytics table that receives rows from the Detailed Risk Analysis report.
#   Default:          SI_RiskAnalysis_Detailed (stored as SI_RiskAnalysis_Detailed_CL).
#   If you change it: Detailed results are written to a different table. Workbooks, queries and the trend engine that
#                     read the standard table will no longer see new data unless they are changed too.
#   When to change:   Almost never; only to avoid a clash with an existing table of the same name.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a clash with an existing table of
#                     the same name.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_TableName_Detailed/
#
# Endpoint data collection rule name  [SI_Endpoint_DcrName]  (advanced)
#   What it is for:   The name of the data collection rule the endpoint engine sends its asset rows through to Log
#                     Analytics.
#   Default:          The standard name, dcr-si-endpoint-profile (from the naming pattern)
#   If you change it: Rows are sent through the named rule. A name that does not match an existing or creatable rule
#                     makes the endpoint ingest fail.
#   When to change:   Only if you renamed the rule or must avoid a name clash with another install.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you renamed the rule or must avoid a name clash with
#                     another install.
#   More info:        https://invardia.com/docs/si/settings/SI_Endpoint_DcrName/
#
# Endpoint table name  [SI_Endpoint_TableName]  (advanced)
#   What it is for:   The Log Analytics table the endpoint engine writes its asset rows to.
#   Default:          The standard table, SI_Endpoint_Profile_CL
#   If you change it: Rows go to the named table instead. Reports, queries and dashboards that read the standard table
#                     then no longer see new endpoint data.
#   When to change:   Only if you renamed the destination table.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you renamed the destination table.
#   More info:        https://invardia.com/docs/si/settings/SI_Endpoint_TableName/
#
# Identity data collection rule name  [SI_Identity_DcrName]  (advanced)
#   What it is for:   The name of the data collection rule the identity engine sends its rows through to Log
#                     Analytics.
#   Default:          The standard name, dcr-si-identity-profile (from the naming pattern)
#   If you change it: Rows are sent through the named rule. A name that does not match an existing or creatable rule
#                     makes the identity ingest fail.
#   When to change:   Only if you renamed the rule or must avoid a name clash with another install.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you renamed the rule or must avoid a name clash with
#                     another install.
#   More info:        https://invardia.com/docs/si/settings/SI_Identity_DcrName/
#
# Identity table name  [SI_Identity_TableName]  (advanced)
#   What it is for:   The Log Analytics table the identity engine writes its rows to.
#   Default:          The standard table, SI_Identity_Profile_CL
#   If you change it: Rows go to the named table instead. Reports, queries and dashboards that read the standard table
#                     then no longer see new identity data.
#   When to change:   Only if you renamed the destination table.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you renamed the destination table.
#   More info:        https://invardia.com/docs/si/settings/SI_Identity_TableName/
#
# Ingestion endpoint address  [SI_DceIngestionUri]  (advanced)
#   What it is for:   The ingestion address of the data collection endpoint that Risk Analysis sends results to.
#   Default:          Not set: looked up from the endpoint name
#   If you change it: Used by Risk Analysis unless SI_RiskAnalysis_DceIngestionUri is set. A wrong address makes Risk
#                     Analysis ingestion fail; the collection engines do not read it.
#   When to change:   Rarely; only if automatic lookup of the endpoint cannot work in your environment.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Rarely; only if automatic lookup of the endpoint cannot work
#                     in your environment.
#   More info:        https://invardia.com/docs/si/settings/SI_DceIngestionUri/
#
# Jobs sign in with a client secret  [SI_Bootstrap_UseClientSecret]  (advanced, secret)
#   What it is for:   Makes all container jobs sign in as the app registration (service principal) with its client
#                     secret instead of a managed identity.
#   Default:          Off: the jobs sign in as a managed identity, unless the configuration already carries a client
#                     secret.
#   If you change it: On, every job carries the client secret as a job secret. Queue scaling is not available with it.
#                     A supported choice, never the default.
#   When to change:   Only when a managed identity or a certificate cannot be used.
#   Risk:             Every job carries the client secret: a secret to store, rotate and protect, and queue scaling is
#                     not available. A supported choice, but weaker than a managed identity. Reversible: run setup
#                     with the managed identity.
#   Recommended:      Off (the managed identity).
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_UseClientSecret/
#
# Key Vault secret name  [SpnSecretName]  (advanced, secret)
#   What it is for:   Name of the Key Vault secret that holds the service principal's client secret.
#   Default:          Not set: the secret is not read from Key Vault
#   If you change it: With a vault name and app id, the launchers fetch the client secret from Key Vault at each run,
#                     so no secret is stored on disk. A wrong name stops the run.
#   When to change:   When the service principal secret is kept in Key Vault rather than using a certificate or
#                     managed identity.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: When the service principal secret is kept in Key Vault rather
#                     than using a certificate or managed identity.
#   More info:        https://invardia.com/docs/si/settings/SpnSecretName/
#
# Profile table name pattern  [SI_TableNamePattern]  (advanced)
#   What it is for:   The pattern used to name each collection engine's Log Analytics table, where {0} is replaced by
#                     the engine name.
#   Default:          SI_{0}_Profile
#   If you change it: Changing it sends collection data to new tables; reports and workbooks expecting the standard
#                     names will not find the data.
#   When to change:   Only if you maintain a parallel naming scheme; most installs never should.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you maintain a parallel naming scheme; most installs
#                     never should.
#   More info:        https://invardia.com/docs/si/settings/SI_TableNamePattern/
#
# Public IP data collection rule  [SI_PublicIp_DcrName]  (engine: publicip, advanced)
#   What it is for:   Names the data collection rule the public IP engine sends its results through.
#   Default:          dcr-si-publicip-profile (the standard naming pattern).
#   If you change it: Results are ingested through the named rule instead. A name that does not exist, or matches a
#                     rule from another install, makes ingestion fail or land in the wrong place.
#   When to change:   Only when a same-named rule from another install collides, or you deployed a uniquely named
#                     rule.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when a same-named rule from another install collides, or
#                     you deployed a uniquely named rule.
#   More info:        https://invardia.com/docs/si/settings/SI_PublicIp_DcrName/
#
# Public IP table name  [SI_PublicIp_TableName]  (engine: publicip, advanced)
#   What it is for:   Names the Log Analytics table the public IP engine writes to.
#   Default:          SI_PublicIP_Profile (stored as SI_PublicIP_Profile_CL).
#   If you change it: Results go to the named table. Reports, risk analysis and the web app read the standard name, so
#                     a different name hides public IP data from them.
#   When to change:   Practically never; keep the standard name.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Practically never; keep the standard name.
#   More info:        https://invardia.com/docs/si/settings/SI_PublicIp_TableName/
#
# Re-pull sign-in from Key Vault  [SI_RebuildAuthBlock]  (advanced)
#   What it is for:   Makes the authentication setup script re-read service principal credentials from Key Vault and
#                     rewrite them, even when they are already in the configuration file.
#   Default:          Off: existing credentials are kept and only tested
#   If you change it: When on, the next setup run replaces the sign-in block in your configuration file with fresh
#                     values from Key Vault, for example after rotating a secret.
#   When to change:   Only after rotating or replacing the service principal credential in Key Vault.
#   Risk:             The next setup run REPLACES the sign-in block in your configuration file with fresh values from
#                     Key Vault. Wrong Key Vault values stop every run until corrected. Reversible from a
#                     configuration backup.
#   Recommended:      Off; on once after rotating a secret.
#   More info:        https://invardia.com/docs/si/settings/SI_RebuildAuthBlock/
#
# Risk analysis collection endpoint  [SI_RiskAnalysis_DceName]  (engine: risk-analysis, advanced)
#   What it is for:   Names the data collection endpoint risk analysis uses for its Log Analytics results.
#   Default:          Falls back to SI_DceName, then DceName, then the standard SecurityInsight endpoint name.
#   If you change it: Risk analysis ingests through the named endpoint instead of the shared one. A wrong name makes
#                     ingestion fail; local output is still written.
#   When to change:   Only when risk analysis must use a different endpoint than the other engines.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when risk analysis must use a different endpoint than the
#                     other engines.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_DceName/
#
# Risk analysis ingestion address  [SI_RiskAnalysis_DceIngestionUri]  (engine: risk-analysis, advanced)
#   What it is for:   The data collection endpoint address risk analysis sends its results to in Log Analytics.
#   Default:          Falls back to SI_DceIngestionUri, else found automatically from the endpoint name.
#   If you change it: Forces results to this address. A wrong address makes Log Analytics ingestion fail; the Excel
#                     and JSON output are still written.
#   When to change:   Rarely; only when the address cannot be found automatically.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Rarely; only when the address cannot be found automatically.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_DceIngestionUri/
#
# Risk Analysis rule resource group  [SI_RiskAnalysis_DcrResourceGroup]  (engine: risk-analysis, advanced)
#   What it is for:   Resource group holding the data collection rules Risk Analysis uses to send its results to Log
#                     Analytics, when it should differ from the solution-wide one.
#   Default:          Uses SI_DcrResourceGroup (then DcrResourceGroup); if none is set, the standard SecurityInsight
#                     rules group.
#   If you change it: Risk Analysis looks up, and creates if missing, its two collection rules in this resource group.
#                     A wrong group means new rules are created there, separate from the rest of the solution.
#   When to change:   Rarely; only when Risk Analysis must ingest through rules kept apart from the other engines.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Rarely; only when Risk Analysis must ingest through rules kept
#                     apart from the other engines.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_DcrResourceGroup/
#
# Risk Analysis workspace name  [SI_RiskAnalysis_WorkspaceName]  (engine: risk-analysis, advanced)
#   What it is for:   Name of the Log Analytics workspace Risk Analysis writes its results to, when it should differ
#                     from the solution-wide workspace.
#   Default:          Uses SI_WorkspaceName (then WorkspaceName); if none, the standard SecurityInsight workspace
#                     name.
#   If you change it: Risk Analysis results go to this workspace, which is created if it does not exist. Ignored when
#                     SI_RiskAnalysis_WorkspaceResourceId or a workspace resource id is set.
#   When to change:   Only when Risk Analysis results must go to a separate workspace from collection data.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when Risk Analysis results must go to a separate
#                     workspace from collection data.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_WorkspaceName/
#
# Risk Analysis workspace resource group  [SI_RiskAnalysis_WorkspaceResourceGroup]  (engine: risk-analysis, advanced)
#   What it is for:   Resource group used to find or create the Risk Analysis workspace when it is given by name.
#   Default:          Uses WorkspaceResourceGroup; if not set, the standard SecurityInsight resource group.
#   If you change it: Changes where Risk Analysis looks for, and creates, its workspace when only a workspace name is
#                     known. Has no effect when a full workspace resource id is set.
#   When to change:   Only with SI_RiskAnalysis_WorkspaceName, when that workspace lives in a different resource
#                     group.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only with SI_RiskAnalysis_WorkspaceName, when that workspace
#                     lives in a different resource group.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_WorkspaceResourceGroup/
#
# Risk Analysis workspace resource id  [SI_RiskAnalysis_WorkspaceResourceId]  (engine: risk-analysis, advanced)
#   What it is for:   Full resource id of the Log Analytics workspace Risk Analysis writes to and reads collected data
#                     from, overriding the shared workspace.
#   Default:          Uses SI_WorkspaceResourceId (then WorkspaceResourceId); otherwise the workspace is found by
#                     name.
#   If you change it: Risk Analysis ingests its results into, and reads the SecurityInsight tables from, this
#                     workspace, which may be in another subscription. A workspace without the collected data gives
#                     empty or partial reports.
#   When to change:   Only for split setups where Risk Analysis uses a different workspace than the rest of the
#                     solution.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only for split setups where Risk Analysis uses a different
#                     workspace than the rest of the solution.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_WorkspaceResourceId/
#
# Rule name pattern  [SI_DcrNamePattern]  (advanced)
#   What it is for:   The pattern used to name each collection engine's data collection rule, where {0} is replaced by
#                     the engine name.
#   Default:          dcr-si-{0}-profile
#   If you change it: Changing it makes engines create and use differently named rules; existing rules are left behind
#                     and new ones are made.
#   When to change:   Only if you maintain a parallel naming scheme; most installs never should.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you maintain a parallel naming scheme; most installs
#                     never should.
#   More info:        https://invardia.com/docs/si/settings/SI_DcrNamePattern/
#
# Schema catalog collection rule  [SI_SchemaCatalogDcr]  (advanced)
#   What it is for:   Name of the data collection rule schema discovery uses to send its catalog of found data fields
#                     to Log Analytics.
#   Default:          dcr-si-schema-catalog
#   If you change it: Schema catalog rows are sent through this rule instead. A rule that does not match the catalog
#                     table makes the catalog stop arriving.
#   When to change:   Almost never; only to avoid a name clash with an existing rule.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a name clash with an existing
#                     rule.
#   More info:        https://invardia.com/docs/si/settings/SI_SchemaCatalogDcr/
#
# Schema catalog table name  [SI_SchemaCatalogTable]  (advanced)
#   What it is for:   Log Analytics table receiving the schema catalog: new data fields, relationships and draft
#                     proposals found by schema discovery.
#   Default:          SI_SchemaCatalog (stored as SI_SchemaCatalog_CL).
#   If you change it: Schema discovery writes its catalog to this table. Queries reading the standard table will no
#                     longer see new rows.
#   When to change:   Almost never; only to avoid a clash with an existing table.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a clash with an existing table.
#   More info:        https://invardia.com/docs/si/settings/SI_SchemaCatalogTable/
#
# Service principal object id  [SI_SPN_ObjectId]  (advanced)
#   What it is for:   Object id (not app id) of the service principal, used to grant it rights on data collection
#                     rules and storage.
#   Default:          Looked up from the app id at run start
#   If you change it: If it cannot be found, infrastructure preparation is skipped and new data collection rules may
#                     lack the ingest permission. A wrong id grants rights to the wrong principal.
#   When to change:   Only when the automatic lookup fails because the signing-in identity cannot read service
#                     principals.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when the automatic lookup fails because the signing-in
#                     identity cannot read service principals.
#   More info:        https://invardia.com/docs/si/settings/SI_SPN_ObjectId/
#
# Shared top-50 cache container  [SI_RATop50_BlobContainer]  (advanced)
#   What it is for:   The storage container holding the shared top-50 risk summary, so several hosts or containers
#                     reuse one summary instead of each building it.
#   Default:          sistaging
#   If you change it: The shared summary is read from and written to this container in the staging storage account.
#                     Hosts pointing at different containers each build their own summary.
#   When to change:   Practically never; only if the staging container was renamed.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Practically never; only if the staging container was renamed.
#   More info:        https://invardia.com/docs/si/settings/SI_RATop50_BlobContainer/
#
# Shared top-50 cache file  [SI_RATop50_BlobName]  (advanced)
#   What it is for:   The file path, inside the container, of the shared top-50 risk summary that several hosts or
#                     containers reuse.
#   Default:          risk-analysis/RiskAnalysis_Top50_Shared.json
#   If you change it: The shared summary is stored under this path. Hosts using different paths each build their own
#                     summary, which costs extra time and AI calls.
#   When to change:   Practically never; only to keep separate installs from sharing one summary.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Practically never; only to keep separate installs from sharing
#                     one summary.
#   More info:        https://invardia.com/docs/si/settings/SI_RATop50_BlobName/
#
# Skip container image build  [SI_Bootstrap_SkipImageBuild]  (advanced)
#   What it is for:   Lets container setup reuse the image already in the registry instead of building a new one.
#   Default:          Off: setup builds the image each time.
#   If you change it: When on, setup is much faster but the jobs keep running the image already stored, so code
#                     changes are not picked up. If no image exists, the jobs fail to start.
#   When to change:   When re-running setup only to change settings and the image is already current.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: When re-running setup only to change settings and the image is
#                     already current.
#   More info:        https://invardia.com/docs/si/settings/SI_Bootstrap_SkipImageBuild/
#
# Summary report data collection rule  [SI_RiskAnalysis_DcrName_Summary]  (advanced)
#   What it is for:   The name of the data collection rule the summary Risk Analysis rows are sent through to Log
#                     Analytics.
#   Default:          dcr-si-risk-analysis-summary
#   If you change it: Summary rows are sent through the named rule. A wrong name makes the summary report ingest fail.
#   When to change:   Only if you renamed the rule or must avoid a name clash with another install.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only if you renamed the rule or must avoid a name clash with
#                     another install.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_DcrName_Summary/
#
# Summary Risk Analysis table name  [SI_RiskAnalysis_TableName_Summary]  (engine: risk-analysis, advanced)
#   What it is for:   Name of the Log Analytics table that receives rows from the Summary Risk Analysis report.
#   Default:          SI_RiskAnalysis_Summary (stored as SI_RiskAnalysis_Summary_CL).
#   If you change it: Summary results are written to a different table. Anything reading the standard table, such as
#                     workbooks, queries and trend, stops seeing new data unless changed too.
#   When to change:   Almost never; only to avoid a clash with an existing table of the same name.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a clash with an existing table of
#                     the same name.
#   More info:        https://invardia.com/docs/si/settings/SI_RiskAnalysis_TableName_Summary/
#
# Tag activity collection rule  [SI_AssetTagActivityDcr]  (advanced)
#   What it is for:   Name of the data collection rule used to send the asset-tagging activity log to Log Analytics.
#   Default:          dcr-si-assettag-activity
#   If you change it: Tagging activity rows are sent through this rule instead. A rule that does not match the
#                     activity table makes the activity log stop arriving.
#   When to change:   Almost never; only to avoid a name clash with an existing rule.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a name clash with an existing
#                     rule.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetTagActivityDcr/
#
# Tag activity table name  [SI_AssetTagActivityTable]  (advanced)
#   What it is for:   Log Analytics table receiving the asset-tagging activity log: which tags were or would be
#                     applied or removed.
#   Default:          SI_AssetTagActivity (stored as SI_AssetTagActivity_CL).
#   If you change it: Tagging activity from both the tagging engine and the profilers' read-only tagging check goes to
#                     this table. Queries reading the standard table will no longer see new rows.
#   When to change:   Almost never; only to avoid a clash with an existing table.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Almost never; only to avoid a clash with an existing table.
#   More info:        https://invardia.com/docs/si/settings/SI_AssetTagActivityTable/
#
# Trend data collection rule name  [SI_Trend_DcrName]  (engine: asset-trend, advanced)
#   What it is for:   The name of the data collection rule the trend engine publishes its daily rollup through.
#   Default:          The engine's own rule name for the trend table.
#   If you change it: Sends the trend rollup through a differently named data collection rule. A wrong name means the
#                     rollup is published through a rule you did not intend, or fails to publish.
#   When to change:   Only when the default rule name clashes with an existing one in your workspace.
#   Risk:             Affects how the jobs sign in or which Azure resources they use. A wrong value stops the affected
#                     jobs at their next run (nothing is changed or deleted); a broader identity or right gives the
#                     jobs more access than they need. Reversible: correct it and run again.
#   Recommended:      Keep the default. Change it when: Only when the default rule name clashes with an existing one
#                     in your workspace.
#   More info:        https://invardia.com/docs/si/settings/SI_Trend_DcrName/
#
# ----------------------------------------------------------------------------------------------------
# Advanced / diagnostics
# Diagnostic switches, older names kept for existing configuration files, and internal plumbing.
# Leave alone unless support asks.
# ----------------------------------------------------------------------------------------------------
#
# App id (launcher name)  [SpnClientId]  (advanced)
#   What it is for:   Application (client) id of the service principal the launchers sign in as; older name kept in
#                     step with SI_SPN_AppId.
#   Default:          Copied from SI_SPN_AppId
#   If you change it: Used by the launchers for certificate, Key Vault and secret sign-in; without it those methods
#                     stop with an error.
#   When to change:   Rarely; set SI_SPN_AppId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; set SI_SPN_AppId instead.
#   More info:        https://invardia.com/docs/si/settings/SpnClientId/
#
# App id (older Graph name)  [SI_Graph_AppId]  (advanced)
#   What it is for:   Older name for the service principal's application id; still read when SI_SPN_AppId is not set.
#   Default:          Not set: SI_SPN_AppId is used
#   If you change it: Only matters when SI_SPN_AppId is empty; then this app id is used for Microsoft Graph sign-in
#                     and setup copies it forward.
#   When to change:   Never on new installs; use SI_SPN_AppId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_SPN_AppId instead.
#   More info:        https://invardia.com/docs/si/settings/SI_Graph_AppId/
#
# Azure region (older name)  [Location]  (engine: risk-analysis, advanced)
#   What it is for:   Older name for the Azure region Risk Analysis uses when it has to create a missing workspace or
#                     ingestion resources.
#   Default:          westeurope; the workspace resource group's region wins when it exists
#   If you change it: Used only when SI_Location is not set, and only when Risk Analysis creates missing resources.
#                     Existing resources are not moved.
#   When to change:   Never on new installs; set SI_Location instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_Location instead.
#   More info:        https://invardia.com/docs/si/settings/Location/
#
# Azure subscription (older name)  [SubscriptionId]  (engine: risk-analysis, advanced)
#   What it is for:   Older name for the subscription Risk Analysis uses to find or create its workspace and ingestion
#                     resources.
#   Default:          Derived from the workspace resource id, else the signed-in subscription
#   If you change it: Risk Analysis uses it first when resolving the workspace; other engines use it only when
#                     SI_AzSubscriptionId and the workspace resource id give none. A wrong value points at the wrong
#                     subscription.
#   When to change:   Rarely; prefer setting the full workspace resource id.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; prefer setting the full workspace resource id.
#   More info:        https://invardia.com/docs/si/settings/SubscriptionId/
#
# Certificate thumbprint (launcher name)  [SpnCertificateThumbprint]  (advanced)
#   What it is for:   Thumbprint of the certificate in the local certificate store that the service principal signs in
#                     with; the recommended alternative to a client secret.
#   Default:          Copied from SI_SPN_CertThumbprint; empty means no certificate sign-in
#   If you change it: When set with an app id, the launchers sign in with the certificate. A thumbprint that is not in
#                     the store makes sign-in fail.
#   When to change:   When you sign in with a certificate and do not use the SI_SPN_ names.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: When you sign in with a certificate and do not use the SI_SPN_
#                     names.
#   More info:        https://invardia.com/docs/si/settings/SpnCertificateThumbprint/
#
# Client secret (launcher name)  [SpnClientSecret]  (advanced, secret)
#   What it is for:   Plain client secret the launchers sign in with when no managed identity, Key Vault secret or
#                     certificate is configured.
#   Default:          Copied from SI_SPN_Secret; not set means no secret sign-in
#   If you change it: Enables plain-secret sign-in, which the launcher warns is for testing only. Storing a secret in
#                     a file is a security risk.
#   When to change:   Only in labs; prefer managed identity, a certificate or a Key Vault secret.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Only in labs; prefer managed identity, a certificate or a Key
#                     Vault secret.
#   More info:        https://invardia.com/docs/si/settings/SpnClientSecret/
#
# Client secret (older Graph name)  [SI_Graph_Secret]  (advanced, secret)
#   What it is for:   Older name for the service principal's client secret; used only when SI_SPN_Secret is not set.
#   Default:          Not set: SI_SPN_Secret is used
#   If you change it: Only matters when SI_SPN_Secret is empty; then this secret is used for Microsoft Graph sign-in.
#   When to change:   Never on new installs; use SI_SPN_Secret, a certificate or managed identity.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_SPN_Secret, a certificate or
#                     managed identity.
#   More info:        https://invardia.com/docs/si/settings/SI_Graph_Secret/
#
# Custom configuration file path  [SI_CustomConfigPath]  (advanced)
#   What it is for:   Points the asset-profiling engine at a custom configuration file kept outside the standard
#                     config folder.
#   Default:          The standard custom configuration file in the config folder
#   If you change it: When set, the profiling engine loads this file at start, even when started by a launcher. A
#                     wrong path means your settings are not applied.
#   When to change:   Very rarely; only if your custom configuration file lives outside the config folder.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Very rarely; only if your custom configuration file lives
#                     outside the config folder.
#   More info:        https://invardia.com/docs/si/settings/SI_CustomConfigPath/
#
# Data collection endpoint name (older name)  [DceName]  (engine: risk-analysis, advanced)
#   What it is for:   Older name for the data collection endpoint that Risk Analysis sends its results through.
#   Default:          dce-securityinsight
#   If you change it: Used by Risk Analysis only when SI_RiskAnalysis_DceName and SI_DceName are not set; in a
#                     container it also fills SI_DceName. A wrong name stops Risk Analysis ingestion or creates a new
#                     endpoint.
#   When to change:   Never on new installs; set SI_DceName instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_DceName instead.
#   More info:        https://invardia.com/docs/si/settings/DceName/
#
# Detailed report mail on (older name)  [Mail_SecurityInsight_Detailed_SendMail]  (advanced)
#   What it is for:   Older name for switching e-mail of the Detailed Risk Analysis report on or off.
#   Default:          Not set: RiskAnalysis_Detailed_SendMail or SendMail decides
#   If you change it: Same as RiskAnalysis_Detailed_SendMail, which wins when both are set.
#   When to change:   Only kept for older configuration files; use RiskAnalysis_Detailed_SendMail instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only kept for older configuration files; use
#                     RiskAnalysis_Detailed_SendMail instead.
#   More info:        https://invardia.com/docs/si/settings/Mail_SecurityInsight_Detailed_SendMail/
#
# Detailed report recipients (older name)  [Mail_SecurityInsight_Detailed_To]  (advanced)
#   What it is for:   Older name for the recipient list of the Detailed Risk Analysis report.
#   Default:          Not set: RiskAnalysis_Detailed_To, else MailTo, is used
#   If you change it: Same as RiskAnalysis_Detailed_To, which wins when both are set.
#   When to change:   Only kept for older configuration files; use RiskAnalysis_Detailed_To instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only kept for older configuration files; use
#                     RiskAnalysis_Detailed_To instead.
#   More info:        https://invardia.com/docs/si/settings/Mail_SecurityInsight_Detailed_To/
#
# Dry run  [WhatIfMode]  (advanced)
#   What it is for:   Requests a run that shows what would change without changing anything.
#   Default:          Off: a normal run.
#   If you change it: In the configuration it is read only by asset tagging, which then only reports the tags it would
#                     apply or remove. Every other engine ignores it in the configuration (scheduled runs always
#                     publish, and each run says the value was ignored): a dry run of profiling, Risk Analysis or the
#                     tier classifier is asked for per run -- start the launcher with -WhatIfMode, or set SI_WHATIF=1
#                     on one container job execution. Such a run says so at its start and its end. Profiling and Risk
#                     Analysis then write their results to local files only -- nothing goes to Log Analytics, the
#                     mail, the export location or the caches; the run-health record says dry run. The tier classifier
#                     writes its result beside the catalog, never over it.
#   When to change:   In the configuration: only before the first real asset-tagging run. To preview any other engine,
#                     use -WhatIfMode on that one run.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: In the configuration: only before the first real asset-tagging
#                     run. To preview any other engine, use -WhatIfMode on that one run.
#   More info:        https://invardia.com/docs/si/settings/WhatIfMode/
#
# Endpoint resource group (older name)  [DceResourceGroup]  (engine: risk-analysis, advanced)
#   What it is for:   Older name for the resource group of the data collection endpoint used by Risk Analysis and
#                     setup checks.
#   Default:          rg-dce-securityinsight
#   If you change it: Used only when SI_DceResourceGroup (and, for other engines, SI_DcrResourceGroup) is not set. A
#                     wrong group makes the engine look in, or create resources in, the wrong place.
#   When to change:   Never on new installs; set SI_DceResourceGroup only if you split resource groups.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_DceResourceGroup only if you
#                     split resource groups.
#   More info:        https://invardia.com/docs/si/settings/DceResourceGroup/
#
# Ingestion app id (older name)  [SI_LogIngest_AppId]  (advanced)
#   What it is for:   Older name for the app id used to send data to Log Analytics; used only when SI_SPN_AppId is not
#                     set.
#   Default:          Not set: SI_SPN_AppId is used
#   If you change it: Only matters when SI_SPN_AppId is empty; then data ingestion signs in with this app.
#   When to change:   Never on new installs; use SI_SPN_AppId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_SPN_AppId instead.
#   More info:        https://invardia.com/docs/si/settings/SI_LogIngest_AppId/
#
# Ingestion endpoint address (older name)  [DceIngestionUri]  (advanced)
#   What it is for:   Older name for the data collection endpoint's ingestion address, used by Risk Analysis when
#                     sending results to Log Analytics.
#   Default:          Not set: looked up from the endpoint name
#   If you change it: Used only when SI_RiskAnalysis_DceIngestionUri and SI_DceIngestionUri are not set. A wrong
#                     address makes Risk Analysis ingestion fail.
#   When to change:   Never on new installs; use SI_DceIngestionUri or leave it to automatic lookup.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_DceIngestionUri or leave it to
#                     automatic lookup.
#   More info:        https://invardia.com/docs/si/settings/DceIngestionUri/
#
# Ingestion object id (older name)  [SI_LogIngest_ObjectId]  (advanced)
#   What it is for:   Older name for the object id of the ingesting service principal, used to grant it rights on data
#                     collection rules; used when SI_SPN_ObjectId is not set.
#   Default:          Not set: SI_SPN_ObjectId is used
#   If you change it: Used only when SI_SPN_ObjectId is empty: every output path that grants ingest rights on a data
#                     collection rule takes SI_SPN_ObjectId first and this name second.
#   When to change:   Never on new installs; set SI_SPN_ObjectId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_SPN_ObjectId instead.
#   More info:        https://invardia.com/docs/si/settings/SI_LogIngest_ObjectId/
#
# Ingestion secret (older name)  [SI_LogIngest_Secret]  (advanced, secret)
#   What it is for:   Older name for the client secret used to send data to Log Analytics; used only when
#                     SI_SPN_Secret is not set.
#   Default:          Not set: SI_SPN_Secret is used
#   If you change it: Only matters when SI_SPN_Secret is empty; then data ingestion signs in with this secret.
#   When to change:   Never on new installs; use SI_SPN_Secret, a certificate or managed identity.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_SPN_Secret, a certificate or
#                     managed identity.
#   More info:        https://invardia.com/docs/si/settings/SI_LogIngest_Secret/
#
# Ingestion tenant id (older name)  [SI_LogIngest_TenantId]  (advanced)
#   What it is for:   Older name for the Entra tenant id used to send data to Log Analytics; used only when
#                     SI_SPN_TenantId is not set.
#   Default:          Not set: SI_SPN_TenantId is used
#   If you change it: Only matters when SI_SPN_TenantId is empty; then data ingestion signs in to this tenant.
#   When to change:   Never on new installs; use SI_SPN_TenantId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_SPN_TenantId instead.
#   More info:        https://invardia.com/docs/si/settings/SI_LogIngest_TenantId/
#
# Internal platform sign-in mode  [AutomationFramework]  (advanced)
#   What it is for:   Marks a run as hosted on the vendor's internal automation platform, which provides the sign-in
#                     identity instead of SecurityInsight's own settings.
#   Default:          Off: SecurityInsight's own sign-in settings are used.
#   If you change it: When on, engines take their identity and connections from the internal platform and skip their
#                     own sign-in. On a normal install this breaks sign-in.
#   When to change:   Never on a customer install; it is set automatically by the internal platform.
#   Risk:             On a normal install this breaks sign-in: every engine takes its identity from an internal
#                     platform that is not there, and runs fail. Reversible at once.
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/AutomationFramework/
#
# Keep stage data in memory  [SI_SingleProcess]  (advanced)
#   What it is for:   Makes the profiling engines pass data between stages in memory instead of through the staging
#                     storage account.
#   Default:          Off: data between stages goes through staging storage.
#   If you change it: On a single server run this can be much faster. It must stay off for parallel container jobs,
#                     where each worker only sees its own memory.
#   When to change:   Only for single-server troubleshooting or speed tests; leave off otherwise.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only for single-server troubleshooting or speed tests; leave
#                     off otherwise.
#   More info:        https://invardia.com/docs/si/settings/SI_SingleProcess/
#
# Key Vault managed identity (older name)  [SI_KvMiClientId]  (advanced)
#   What it is for:   The client id of a user-assigned managed identity used to read Key Vault when no Azure sign-in
#                     exists yet. Older name for SI_ManagedIdentityClientId.
#   Default:          Uses SI_ManagedIdentityClientId; otherwise the machine's own system managed identity
#   If you change it: Key Vault reads sign in as this user-assigned identity. It is ignored when
#                     SI_ManagedIdentityClientId is set, or when an Azure sign-in already exists.
#   When to change:   Only on older configurations that use a user-assigned identity; new installs use
#                     SI_ManagedIdentityClientId.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only on older configurations that use a user-assigned
#                     identity; new installs use SI_ManagedIdentityClientId.
#   More info:        https://invardia.com/docs/si/settings/SI_KvMiClientId/
#
# Key Vault name (older name)  [SpnKeyVaultName]  (advanced)
#   What it is for:   Name of the Azure Key Vault holding the service principal secret and other credentials; older
#                     name accepted alongside SI_KeyVaultName.
#   Default:          Not set: SI_KeyVaultName is used; no vault means no vault reads
#   If you change it: With a secret name, the launchers read the client secret from this vault using the host's
#                     managed identity. SI_KeyVaultName wins when both are set.
#   When to change:   Rarely; set SI_KeyVaultName instead on new installs.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; set SI_KeyVaultName instead on new installs.
#   More info:        https://invardia.com/docs/si/settings/SpnKeyVaultName/
#
# Log Analytics query retries  [SI_LAQueryMaxRetries]  (advanced, attempts)
#   What it is for:   How many attempts the asset engines make for a Log Analytics query that fails with a temporary
#                     error.
#   Default:          3 attempts (1, 3 and 7 seconds apart)
#   If you change it: More attempts ride out brief workspace errors at the cost of a slightly longer run; fewer
#                     (minimum 1) fails faster and may drop the affected data from the run.
#   When to change:   Most installs never should. Raise it if runs log intermittent Log Analytics query failures.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Most installs never should. Raise it if runs log intermittent
#                     Log Analytics query failures.
#   More info:        https://invardia.com/docs/si/settings/SI_LAQueryMaxRetries/
#
# Managed identity client id (older name)  [SI_UAMI_ClientId]  (advanced)
#   What it is for:   Client id of a user-assigned managed identity; the older name for SI_ManagedIdentityClientId,
#                     and the one container jobs and ingestion read.
#   Default:          Copied from SI_ManagedIdentityClientId; empty means system-assigned
#   If you change it: Selects the user-assigned identity used for sign-in and ingestion. Several ingestion paths use
#                     managed identity only when this is set.
#   When to change:   Rarely; set SI_ManagedIdentityClientId instead, unless configuring a container job directly.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; set SI_ManagedIdentityClientId instead, unless
#                     configuring a container job directly.
#   More info:        https://invardia.com/docs/si/settings/SI_UAMI_ClientId/
#
# Managed identity on (launcher name)  [UseManagedIdentity]  (advanced)
#   What it is for:   Tells the launchers to sign in with the host's managed identity; set automatically by the
#                     sign-in method choice.
#   Default:          On when no service principal is configured; otherwise off
#   If you change it: When on, launchers sign in as the Azure VM's or Arc server's identity (or a user-assigned one),
#                     and that identity needs the permissions.
#   When to change:   Rarely; set SI_AuthMethod instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; set SI_AuthMethod instead.
#   More info:        https://invardia.com/docs/si/settings/UseManagedIdentity/
#
# Managed identity switch (older name)  [SI_PreferUami]  (advanced)
#   What it is for:   Older switch to sign in with a managed identity, still honoured; SI_AuthMethod is the setting to
#                     use.
#   Default:          Off, unless the sign-in choice selects managed identity
#   If you change it: When on and no service principal is configured, managed identity is used. For Log Analytics
#                     ingestion it takes effect only together with a user-assigned client id.
#   When to change:   Never on new installs; set SI_AuthMethod instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_AuthMethod instead.
#   More info:        https://invardia.com/docs/si/settings/SI_PreferUami/
#
# Query fingerprint debug output  [DebugQueryHash]  (engine: risk-analysis, advanced)
#   What it is for:   Logs each split query's fingerprint and saves the query to a debug folder for troubleshooting.
#   Default:          Off.
#   If you change it: On writes one query file per report to the output Debug folder and adds log lines; no effect on
#                     report content.
#   When to change:   Only when asked to diagnose query splitting.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only when asked to diagnose query splitting.
#   More info:        https://invardia.com/docs/si/settings/DebugQueryHash/
#
# Risk Analysis local staging folder  [SI_StagingPath]  (advanced)
#   What it is for:   A local folder where Risk Analysis writes its temporary query files and query error details.
#   Default:          A staging folder under the output path, else the temp folder
#   If you change it: Moves Risk Analysis's temporary query files to this folder. It does not change the staging
#                     storage account.
#   When to change:   Only if the default folder is not writable or too small on your host.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only if the default folder is not writable or too small on
#                     your host.
#   More info:        https://invardia.com/docs/si/settings/SI_StagingPath/
#
# Rule column diagnostic  [SI_DcrMergeDiagnostic]  (advanced)
#   What it is for:   Logs the difference between a data collection rule's columns and the data being sent, on every
#                     ingestion call.
#   Default:          Off
#   If you change it: On, each ingestion call logs added, removed and changed columns. Makes logs longer and runs
#                     slightly slower; never stops ingestion.
#   When to change:   Turn on briefly when investigating warnings about dropped columns.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Turn on briefly when investigating warnings about dropped
#                     columns.
#   More info:        https://invardia.com/docs/si/settings/SI_DcrMergeDiagnostic/
#
# Rules resource group (older name)  [DcrResourceGroup]  (engine: risk-analysis, advanced)
#   What it is for:   Older name for the resource group holding the data collection rules that Risk Analysis uses.
#   Default:          rg-dcr-securityinsight
#   If you change it: Used by Risk Analysis only when SI_RiskAnalysis_DcrResourceGroup and SI_DcrResourceGroup are not
#                     set; in a container it also fills SI_DcrResourceGroup. A wrong group puts rules in the wrong
#                     place.
#   When to change:   Never on new installs; set SI_DcrResourceGroup instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_DcrResourceGroup instead.
#   More info:        https://invardia.com/docs/si/settings/DcrResourceGroup/
#
# Save AI requests to disk  [SI_DumpAIPayload]  (advanced)
#   What it is for:   A troubleshooting switch that saves every AI classification request to a file in the machine's
#                     temp folder.
#   Default:          Off: nothing is saved.
#   If you change it: When on, each AI call writes one file holding the prompt and the asset data sent, so prompts can
#                     be inspected. This adds disk writes and leaves asset details on disk.
#   When to change:   Only while diagnosing AI results; switch it off again afterwards.
#   Risk:             Writes the prompts and the asset data sent to AI to files on disk, where they stay until
#                     removed. Reversible: turn it off and delete the files.
#   Recommended:      Off; on only briefly when support asks.
#   More info:        https://invardia.com/docs/si/settings/SI_DumpAIPayload/
#
# Shodan address limit (older name)  [SI_Shodan_AssetLimit]  (advanced, assets)
#   What it is for:   Caps how many public IP addresses are checked per run.
#   Default:          0: no limit (every candidate address).
#   If you change it: A positive number trims the candidate list to that many addresses, so the run is shorter and
#                     uses fewer Shodan lookups, but results are incomplete.
#   When to change:   Only for testing or a quick trial run.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only for testing or a quick trial run.
#   More info:        https://invardia.com/docs/si/settings/SI_Shodan_AssetLimit/
#
# Shodan API key (older name)  [SHODAN_ApiKey]  (advanced, secret)
#   What it is for:   Older name for the Shodan API key the public IP engine uses to look up your public IP addresses.
#   Default:          Not set: the key under its current name is used; without any key, Shodan details stay empty.
#   If you change it: Used only when SI_Shodan_ApiKey is not set. Without any key the public IP engine still runs, but
#                     every Shodan field (open ports, services, vulnerabilities) is empty.
#   When to change:   Prefer SI_Shodan_ApiKey; keep this only for older configuration files.
#   Risk:             A credential: kept only in the install's Key Vault, never shown again after it is saved. A wrong
#                     value stops the steps that use it until it is corrected; nothing else is changed.
#   Recommended:      Keep the default. Change it when: Prefer SI_Shodan_ApiKey; keep this only for older
#                     configuration files.
#   More info:        https://invardia.com/docs/si/settings/SHODAN_ApiKey/
#
# Show resolved configuration  [ShowConfig]  (engine: risk-analysis, advanced)
#   What it is for:   Prints the configuration risk analysis actually uses at start-up, so you can see which values
#                     are in effect.
#   Default:          Off.
#   If you change it: On adds a configuration listing to the run log, including identifiers from your setup; no effect
#                     on reports.
#   When to change:   When troubleshooting which value is in effect.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: When troubleshooting which value is in effect.
#   More info:        https://invardia.com/docs/si/settings/ShowConfig/
#
# Simulated table row count  [SI_SimulateCLRowCount]  (advanced, rows)
#   What it is for:   Test-only setting that pads the data Risk Analysis reads from your workspace with synthetic
#                     rows, to test behaviour at large scale on a small tenant.
#   Default:          Off (no simulation)
#   If you change it: Risk Analysis handles the extra synthetic rows, so runs get slower and heavier; the fake rows
#                     never match real assets and do not appear in the report. A warning is shown while active.
#   When to change:   Never in normal use; only for scale testing. Usually set by the launcher's asset-simulation
#                     option.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never in normal use; only for scale testing. Usually set by
#                     the launcher's asset-simulation option.
#   More info:        https://invardia.com/docs/si/settings/SI_SimulateCLRowCount/
#
# Status report address  [SI_Telemetry_Endpoint]  (advanced)
#   What it is for:   The https address the status reports are sent to.
#   Default:          Invardia's report address (https://invardia.com/api/uplink/v1/report)
#   If you change it: Reports go to this address instead. Only https addresses are used; anything else sends nothing.
#   When to change:   Practically never; only if Invardia tells you to use another address.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Practically never; only if Invardia tells you to use another
#                     address.
#   More info:        https://invardia.com/docs/si/settings/SI_Telemetry_Endpoint/
#
# Summary report mail on (older name)  [Mail_SecurityInsight_Summary_SendMail]  (advanced)
#   What it is for:   Older name for switching e-mail of the Summary Risk Analysis report on or off.
#   Default:          Not set: RiskAnalysis_Summary_SendMail or SendMail decides
#   If you change it: Same as RiskAnalysis_Summary_SendMail, which wins when both are set.
#   When to change:   Only kept for older configuration files; use RiskAnalysis_Summary_SendMail instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only kept for older configuration files; use
#                     RiskAnalysis_Summary_SendMail instead.
#   More info:        https://invardia.com/docs/si/settings/Mail_SecurityInsight_Summary_SendMail/
#
# Summary report recipients (older name)  [Mail_SecurityInsight_Summary_To]  (advanced)
#   What it is for:   Older name for the recipient list of the Summary Risk Analysis report.
#   Default:          Not set: RiskAnalysis_Summary_To, else MailTo, is used
#   If you change it: Same as RiskAnalysis_Summary_To, which wins when both are set.
#   When to change:   Only kept for older configuration files; use RiskAnalysis_Summary_To instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Only kept for older configuration files; use
#                     RiskAnalysis_Summary_To instead.
#   More info:        https://invardia.com/docs/si/settings/Mail_SecurityInsight_Summary_To/
#
# Tenant id (launcher name)  [SpnTenantId]  (advanced)
#   What it is for:   The Entra tenant id the launchers sign in to; older name kept in step with SI_SPN_TenantId.
#   Default:          Copied from SI_SPN_TenantId; with managed identity, read from the sign-in
#   If you change it: Required for service principal sign-in; without it and without managed identity the launcher
#                     stops with an error.
#   When to change:   Rarely; set SI_SPN_TenantId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; set SI_SPN_TenantId instead.
#   More info:        https://invardia.com/docs/si/settings/SpnTenantId/
#
# Tenant id (older Graph name)  [SI_Graph_TenantId]  (advanced)
#   What it is for:   Older name for the Entra tenant id the service principal signs in to; used only when
#                     SI_SPN_TenantId is not set.
#   Default:          Not set: SI_SPN_TenantId is used
#   If you change it: Only matters when SI_SPN_TenantId is empty; then this tenant is used for Microsoft Graph
#                     sign-in.
#   When to change:   Never on new installs; use SI_SPN_TenantId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; use SI_SPN_TenantId instead.
#   More info:        https://invardia.com/docs/si/settings/SI_Graph_TenantId/
#
# Turn off run logs  [SI_DisableTranscript]  (advanced)
#   What it is for:   Stops the launchers from writing a run log (transcript) to disk and uploading it to storage.
#   Default:          Off: every run writes and keeps a run log.
#   If you change it: No run log is kept, so failed runs cannot be investigated afterwards. Collection and reports are
#                     unaffected.
#   When to change:   Only in lab or test pipelines where logs are not wanted.
#   Risk:             No run log is kept: a failed run cannot be investigated afterwards and support has nothing to
#                     read. Reversible at once (from the next run).
#   Recommended:      Off.
#   More info:        https://invardia.com/docs/si/settings/SI_DisableTranscript/
#
# Verbose diagnostic logging  [SI_Verbose]  (advanced)
#   What it is for:   Adds detailed diagnostic lines (routing, timing, merge statistics, samples) to the run log.
#   Default:          Off: normal log detail.
#   If you change it: Run logs become much longer and more detailed, which helps support find problems. Collected data
#                     and reports are unchanged.
#   When to change:   When investigating a problem or when support asks for it; turn off again afterwards.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: When investigating a problem or when support asks for it; turn
#                     off again afterwards.
#   More info:        https://invardia.com/docs/si/settings/SI_Verbose/
#
# Workspace name (older name)  [WorkspaceName]  (engine: risk-analysis, advanced)
#   What it is for:   Older name for the Log Analytics workspace name, read by Risk Analysis and setup checks.
#   Default:          log-platform-management-securityinsight
#   If you change it: Used by Risk Analysis only when no workspace resource id and no SI_WorkspaceName is set; it may
#                     then find or create a workspace with this name.
#   When to change:   Never on new installs; set SI_WorkspaceResourceId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_WorkspaceResourceId instead.
#   More info:        https://invardia.com/docs/si/settings/WorkspaceName/
#
# Workspace resource group (older name)  [WorkspaceResourceGroup]  (engine: risk-analysis, advanced)
#   What it is for:   Resource group of the Log Analytics workspace, used by Risk Analysis when it must find or create
#                     the workspace.
#   Default:          rg-securityinsight
#   If you change it: Used when SI_RiskAnalysis_WorkspaceResourceGroup is not set; its region also decides where
#                     missing resources are created. A wrong group can create a new workspace.
#   When to change:   Rarely; prefer setting the full workspace resource id.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Rarely; prefer setting the full workspace resource id.
#   More info:        https://invardia.com/docs/si/settings/WorkspaceResourceGroup/
#
# Workspace resource id (older name)  [WorkspaceResourceId]  (advanced)
#   What it is for:   Older name for the full workspace resource id, read by Risk Analysis when the newer setting is
#                     not set.
#   Default:          Not set: SI_WorkspaceResourceId is used
#   If you change it: Used only when SI_RiskAnalysis_WorkspaceResourceId and SI_WorkspaceResourceId are not set. A
#                     wrong value sends Risk Analysis data and queries to another workspace.
#   When to change:   Never on new installs; set SI_WorkspaceResourceId instead.
#   Risk:             A tuning or diagnostic setting: it mostly changes run time, cost or log detail. Leave it at the
#                     default unless support asks. Reversible at once.
#   Recommended:      Keep the default. Change it when: Never on new installs; set SI_WorkspaceResourceId instead.
#   More info:        https://invardia.com/docs/si/settings/WorkspaceResourceId/
# <<< SETTINGS GLOSSARY <<<
