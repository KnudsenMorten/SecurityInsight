#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for IdentityAssetsCollectDefineTierIngestLog.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. LauncherConfig.custom.ps1
    is gitignored, so the populated copy stays on your machine and is never
    overwritten by a release upgrade.

    LAYERED CONFIG MODEL

      1. LauncherConfig.defaults.ps1   <- ships with each release; baseline.
      2. LauncherConfig.custom.ps1     <- THIS FILE (your copy). Set ONLY the
                                          values you actually need to override.
      3. CLI args on the launcher      <- last word for that one invocation.

    You need TWO sections at minimum: AUTH (1) and DCR INGESTION TARGETS (2).
    Everything else has a default in LauncherConfig.defaults.ps1.

    *** PRE-REQUISITE ***
    Before running this engine, the Workspace + DCE + DCR + SI_IdentityAssets_CL
    table must exist. Provision them by running the sibling onboarding launcher
    once per customer tenant:

        LAUNCHERS\Step2_OnboardValidate-SecurityInsight-LogAnalytics\launcher.community-vm.template.ps1

    Its end-of-run cheat-sheet prints the exact 6 globals to copy into section 2.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : IdentityAssetsCollectDefineTierIngestLog
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1.  AUTHENTICATION  -- REQUIRED. Uncomment ONE method block, fill in values.
# ============================================================================

# ----- METHOD 1: Managed Identity ---------------------------------------------
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'

# ----- METHOD 2: SPN + secret stored in Azure Key Vault -----------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'
# $global:SpnSecretName   = 'SecurityInsight-Secret'

# ----- METHOD 3: SPN + certificate (thumbprint in local cert store) -----------
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ----- METHOD 4: SPN + plaintext secret  *** TESTING ONLY *** -----------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'


# ============================================================================
# 2.  DCR INGESTION TARGETS  -- optional. Everything auto-resolves to sensible
#     defaults; override only what differs from the standard layout.
# ============================================================================
# Defaults (if you leave this block empty):
#   Workspace : log-platform-management-securityinsight  (in rg-securityinsight)
#   DCE       : dce-securityinsight                      (in rg-dce-securityinsight)
#   DCR       : dcr-si-identity-assets                   (in rg-dcr-securityinsight)
#   Table     : SI_IdentityAssets                        (_CL suffix added by LA)
# Missing workspace / DCE / RGs are auto-created and RBAC'd for the ingestion SPN.
# DceIngestionUri is auto-resolved from $DceName via Get-AzDceListAll -- no longer required.
#
# Workspace: set ResourceId to pin a specific cross-sub workspace; otherwise the
# engine resolves (and auto-creates) by name.
# $global:WorkspaceResourceId     = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws-name>'
# $global:WorkspaceName           = 'log-platform-management-securityinsight'
# $global:WorkspaceResourceGroup  = 'rg-securityinsight'
#
# DCE / DCR overrides (uncomment only if you deviate from the defaults):
# $global:DceName                 = 'dce-securityinsight'
# $global:DceResourceGroup        = 'rg-dce-securityinsight'
# $global:DcrResourceGroup        = 'rg-dcr-securityinsight'
# $global:DcrName                 = 'dcr-si-identity-assets'
# $global:DceIngestionUri         = 'https://...ingest.monitor.azure.com'   # rarely needed


# ============================================================================
# 3.  COMMON OVERRIDES  (uncomment only what you want to change)
# ============================================================================

# ----- Cross-workspace setup --------------------------------------------------
# Set this if Defender/Sentinel IdentityInfo lives in a DIFFERENT workspace
# than $global:WorkspaceResourceId above. Engine then issues cross-workspace KQL.
# Preferred name:  $global:Defender_WorkspaceNameResourceId
# Also accepted:   $global:DefenderWorkspaceResourceId / $global:SecurityInsight_Defender_WorkspaceResourceId
# $global:Defender_WorkspaceNameResourceId = $global:MainLogAnalyticsWorkspaceResourceId
# $global:Defender_WorkspaceNameResourceId = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<defender-ws>'

# ----- Subscription scope -----------------------------------------------------
# Skip subscriptions whose NAME matches any wildcard (e.g. sandbox / training)
# $global:SubscriptionNameExcludePatterns = @( '*Azure for Students*', '*Visual Studio*' )

# ----- Custom Security Attributes ---------------------------------------------
# $global:CsaAttributeSet = 'SecurityInsight'

# ----- Troubleshooting --------------------------------------------------------
# $global:TroubleshootingMode = $true     # process only first 10 rows for fast iteration

# ----- Export: JSON sibling + upload ------------------------------------------
# Writes a .json array next to the .jsonl collection file, then (optionally)
# uploads both to UNC or Azure Storage. Destination type is auto-detected.
# For Azure Storage the container is auto-created + the SPN is granted
# 'Storage Blob Data Contributor' on the container (best-effort).
# $global:WriteJsonOutput    = $true
# $global:ExportDestination  = 'https://<acct>.blob.core.windows.net/identityassets/'
# $global:ExportDestination  = '\\server\share\identityassets\'


# ============================================================================
# 4.  COMPLETE EXAMPLE  (community mode, copy/paste starting point)
# ============================================================================
# This is the full shape of a populated LauncherConfig.custom.ps1 for the
# Identity collection engine. Replace '<your-*>' placeholders with your values.
# Everything except section 1 (auth) is optional -- the engine auto-creates /
# auto-resolves anything that's missing.

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

# --- Behaviour tuning ---
$global:BatchSize                        = 200
$global:TroubleshootingMode              = $true
$global:CsaAttributeSet                  = 'SecurityInsight'
$global:SubscriptionNameExcludePatterns  = @('*Azure for Students*')

# --- Cross-workspace Defender/Sentinel IdentityInfo reads ---
# Set when Defender / Sentinel IdentityInfo lives in a DIFFERENT workspace
# than the identity-assets ingestion workspace. Engine then issues cross-
# workspace KQL. Accepts the canonical new name + the two legacy names.
$global:DefenderWorkspaceResourceId = '/subscriptions/<defender-sub-guid>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<defender-ws>'
#>


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (BatchSize, TableName, CsaAttributeSet, TenantDomain,
# etc.), look at LauncherConfig.defaults.ps1 in this same folder. Copy any
# line out of there into THIS file to override that single value.
