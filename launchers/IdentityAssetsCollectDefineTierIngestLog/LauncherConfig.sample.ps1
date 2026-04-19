#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for IdentityAssetsCollectDefineTierIngestLog.

.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the SAME folder. LauncherConfig.ps1
    is gitignored, so the populated copy stays on your machine and is never
    overwritten by a release upgrade.

    LAYERED CONFIG MODEL

      1. LauncherConfig.defaults.ps1   <- ships with each release; baseline.
      2. LauncherConfig.ps1            <- THIS FILE (your copy). Set ONLY the
                                          values you actually need to override.
      3. CLI args on the launcher      <- last word for that one invocation.

    You need TWO sections at minimum: AUTH (1) and DCR INGESTION TARGETS (2).
    Everything else has a default in LauncherConfig.defaults.ps1.

    *** PRE-REQUISITE ***
    Before running this engine, the Workspace + DCE + DCR + SI_IdentityAssets_CL
    table must exist. Provision them by running the sibling onboarding launcher
    once per customer tenant:

        LAUNCHERS\Onboarding_IdentityAssets_LogAnalytics\launcher.community-vm.template.ps1

    Its end-of-run cheat-sheet prints the exact 6 globals to copy into section 2.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : IdentityAssetsCollectDefineTierIngestLog
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
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
# 2.  DCR INGESTION TARGETS  -- REQUIRED. From the onboarding cheat-sheet.
# ============================================================================
$global:DceIngestionUri      = '<https://your-dce-name.<region>-1.ingest.monitor.azure.com>'
$global:WorkspaceResourceId  = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws-name>'
$global:DcrResourceGroup     = '<rg-holding-the-dcr>'
$global:DcrName              = '<dcr-name>'   # default: dcr-si-identity-assets
$global:DceName              = '<dce-name>'   # default: dce-si-identity


# ============================================================================
# 3.  COMMON OVERRIDES  (uncomment only what you want to change)
# ============================================================================

# ----- Cross-workspace setup --------------------------------------------------
# Set this if Defender/Sentinel IdentityInfo lives in a DIFFERENT workspace
# than $global:WorkspaceResourceId above. Engine then issues cross-workspace KQL.
# $global:DefenderWorkspaceResourceId = $global:MainLogAnalyticsWorkspaceResourceId
# $global:DefenderWorkspaceResourceId = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<defender-ws>'

# ----- Subscription scope -----------------------------------------------------
# Skip subscriptions whose NAME matches any wildcard (e.g. sandbox / training)
# $global:SubscriptionNameExcludePatterns = @( '*Azure for Students*', '*Visual Studio*' )

# ----- Troubleshooting --------------------------------------------------------
# $global:TroubleshootingMode = $true     # process only first 10 rows for fast iteration


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (BatchSize, TableName, CsaAttributeSet, TenantDomain,
# etc.), look at LauncherConfig.defaults.ps1 in this same folder. Copy any
# line out of there into THIS file to override that single value.
