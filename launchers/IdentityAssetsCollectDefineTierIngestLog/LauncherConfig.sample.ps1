#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for IdentityAssetsCollectDefineTierIngestLog.

.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the SAME folder and edit the values.
    LauncherConfig.ps1 is .gitignore'd so the populated copy stays on your machine.

    All sections are visible below. Sections you don't use can be left at their
    default values; only the ONE auth method you pick (section 1) and the DCR
    ingestion targets (section 2) need real values.

    AUTHENTICATION METHODS  --  pick exactly ONE block in section 1.

    The launcher resolves auth in this priority order (first match wins):

      1.  Managed Identity              (production, most secure)
      2.  SPN + Key Vault-stored secret (production)
      3.  SPN + certificate             (production; cert in user's cert store)
      4.  SPN + plaintext secret        (TESTING ONLY -- do NOT use in production)

    In every production case the app still needs the Entra API permissions and
    Azure RBAC described in the solution README, Step 2.

.NOTES
    Solution       : SecurityInsight
    File           : LauncherConfig.sample.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net   (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>

# ============================================================================
# 1.  AUTHENTICATION  -- uncomment ONE method block, fill in the values
# ============================================================================

# ----- METHOD 1: Managed Identity ----------------------------------------------
# RECOMMENDED for Azure VMs / Arc-enabled servers / Function Apps / Hybrid Runbook
# Workers. System-assigned MI is assumed; for user-assigned MI, set
# $global:SpnClientId to the MI's client ID.
#
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'   # required for Graph connect

# ----- METHOD 2: SPN + secret stored in Azure Key Vault ------------------------
# Requires the VM/caller to have a Managed Identity with 'Key Vault Secrets User'
# on the target Key Vault. The launcher uses MI to fetch the SPN secret, then
# authenticates as the SPN.
#
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'                # short name, not full URI
# $global:SpnSecretName   = 'SecurityInsight-Secret'   # name of the secret holding the client secret

# ----- METHOD 3: SPN + certificate (thumbprint in local cert store) ------------
# Upload the public key of the cert to the Entra app under Certificates & secrets.
# The private key must be installed on THIS machine (CurrentUser\My or
# LocalMachine\My). Certificate auth is silent and does not expire as fast as
# secrets.
#
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ----- METHOD 4: SPN + plaintext secret  *** TESTING ONLY *** ------------------
# WARNING: a plaintext client secret in a .ps1 file is acceptable for a
# short-lived TEST/LAB only. For production, use Method 1, 2, or 3.
# LauncherConfig.ps1 is .gitignore'd so it won't accidentally land in a commit
# -- but the secret is still cleartext on disk, on backups, in snapshots, and
# in whatever process the script runs under. Rotate frequently if you leave it
# here.
#
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'


# ============================================================================
# 2.  DCR INGESTION TARGETS  -- REQUIRED. Engine throws if any of these 3 are
#                               not set: DceIngestionUri, WorkspaceResourceId,
#                               DcrResourceGroup.
# ============================================================================
#
#   *** PRE-REQUISITE ***
#   Before this engine can run, the Log Analytics infrastructure
#   (Workspace + Data Collection Endpoint + Data Collection Rule + the
#   SI_IdentityAssets_CL custom table) must already exist. Run the sibling
#   onboarding launcher ONCE per customer tenant to provision everything:
#
#       LAUNCHERS\Onboarding_IdentityAssets_LogAnalytics\launcher.community-vm.template.ps1
#
#   Its output prints the exact DceIngestionUri / WorkspaceResourceId /
#   DcrResourceGroup values to copy-paste into the three globals below.
#
# These point at the Data Collection Endpoint + Data Collection Rule + Log
# Analytics workspace where the SI_IdentityAssets rows will land. If you
# already manage your own DCR pipeline (e.g. via AzLogDcrIngestPS), point the
# values below at that infra instead -- the onboarding script is optional in
# that case.

# Ingestion URI on the DCE (full URL, e.g. 'https://si-dce-xxx.westeurope-1.ingest.monitor.azure.com')
$global:DceIngestionUri      = '<https://your-dce-name.<region>-1.ingest.monitor.azure.com>'

# Full Log Analytics workspace resource ID
# (e.g. '/subscriptions/<sub-guid>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>')
$global:WorkspaceResourceId  = '/subscriptions/<sub-guid>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>'

# Resource group that holds the DCR (short name, not full path)
$global:DcrResourceGroup     = '<rg-holding-the-dcr>'

# Optional names -- only needed if your DCR/DCE creation script wrote them and
# the engine needs to look them up by name (rather than by URI/ResourceId above).
# $global:DcrName           = '<dcr-name>'
# $global:DceName           = '<dce-name>'

# Cross-workspace setup (Defender / Sentinel IdentityInfo lookups)
# ----------------------------------------------------------------
# The engine needs to read IdentityInfo (Entra ID daily snapshot) which lives
# in whichever workspace Defender/Sentinel is writing to. Pick the scenario
# that matches your environment:
#
#   A) SAME WORKSPACE -- you ingest SI_IdentityAssets INTO the same workspace
#      Defender/Sentinel already uses. Leave $global:DefenderWorkspaceResourceId
#      unset; the engine uses $global:WorkspaceResourceId for everything.
#
#   B) SEPARATE SI WORKSPACE, Defender/Sentinel elsewhere -- you ingest
#      SI_IdentityAssets to the workspace above, but IdentityInfo lives in a
#      different Defender/Sentinel workspace. Set the Defender workspace
#      resource ID below; the engine issues cross-workspace KQL.
#
#   C) SAME WORKSPACE AS A SHARED PLATFORM WORKSPACE -- you already have a
#      $global:MainLogAnalyticsWorkspaceResourceId on this host. Point
#      DefenderWorkspaceResourceId at it (literally one line).
#
# $global:DefenderWorkspaceResourceId = '/subscriptions/<sub-guid>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<defender-workspace-name>'
# $global:DefenderWorkspaceResourceId = $global:MainLogAnalyticsWorkspaceResourceId  # scenario C, if the platform global is set

# Tenant domain (used in some output column values; falls back to the
# authenticating SPN's tenant if not set)
# $global:TenantDomain = 'contoso.onmicrosoft.com'


# ============================================================================
# 3.  CUSTOM SECURITY ATTRIBUTES (CSA)
# ============================================================================
# Which CSA attribute set the engine reads/writes. Default is 'SecurityInsight'
# (matches the attribute set created by Setup-SecurityInsight-CustomSecurityAttributes.ps1).
$global:CsaAttributeSet = 'SecurityInsight'


# ============================================================================
# 4.  INGESTION TUNING  (rarely changed)
# ============================================================================
# Rows per POST to the DCE. Lower = more requests, easier on memory; higher =
# fewer requests, faster end-to-end. 300 is a safe default.
$global:BatchSize = 300

# Target Log Analytics table (without the _CL suffix; engine appends _CL if needed)
$global:TableName = 'SI_IdentityAssets'


# ============================================================================
# 5.  AZURE SUBSCRIPTION SCOPE  (optional)
# ============================================================================
# Wildcard patterns of subscription NAMES to skip during the Azure-side
# enumeration (Get-AzSubscription). Useful for excluding sandbox / training
# / personal-MSDN subs you never want SecurityInsight to touch.
# Patterns are PowerShell -like wildcards. Empty / unset = scan all enabled subs.
# $global:SubscriptionNameExcludePatterns = @(
#     '*Azure for Students*',
#     '*Visual Studio*'
# )


# ============================================================================
# 6.  TROUBLESHOOTING / WHATIF FLAGS  (optional)
# ============================================================================
# $global:TroubleshootingMode = $false      # $true = process only first 10 rows for fast iteration
# $global:WhatIfMode          = $false      # $true = dry run, no DCR ingestion
# $global:Scope               = @('PROD')   # or @('TEST')
