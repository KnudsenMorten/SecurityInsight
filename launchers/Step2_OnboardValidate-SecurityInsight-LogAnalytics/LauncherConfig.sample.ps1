#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for Step2_OnboardValidate-SecurityInsight-LogAnalytics.

.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the SAME folder and edit the values.
    LauncherConfig.ps1 is .gitignore'd so the populated copy stays on your machine.

    WHAT THIS LAUNCHER PROVISIONS (run once per customer tenant)

      - A Resource Group  (in the chosen subscription + region)
      - A Log Analytics workspace
      - A Data Collection Endpoint (DCE)
      - A Data Collection Rule (DCR)  with the SI_IdentityAssets_CL custom table
      - 'Monitoring Metrics Publisher' RBAC on the DCR for the SPN that will
         later run the IdentityAssetsCollectDefineTierIngestLog engine

    The engine prints, at the end of its run, the exact globals to copy
    into LauncherConfig.ps1 of the IdentityAssetsCollectDefineTierIngestLog
    launcher (WorkspaceResourceId / DcrResourceGroup / DcrName / DceName /
    TableName). DceIngestionUri is no longer needed -- the ingestion engine
    resolves it from the DCE name at run time via Get-AzDceListAll.

    AUTHENTICATION METHODS  --  pick exactly ONE block in section 1.

    The launcher resolves auth in this priority order (first match wins):

      1.  Managed Identity              (production, most secure)
      2.  SPN + Key Vault-stored secret (production)
      3.  SPN + certificate             (production; cert in user's cert store)
      4.  SPN + plaintext secret        (TESTING ONLY -- do NOT use in production)

    Whichever SPN / MI you authenticate as is ALSO granted 'Monitoring Metrics
    Publisher' on the new DCR -- so the same identity can later ingest rows.

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
# LocalMachine\My).
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
# 2.  AZURE PLACEMENT  --  where the new resources should land
# ============================================================================
# All values are OPTIONAL. The solution-wide shared defaults come from
#   SOLUTIONS/SecurityInsight/LAUNCHERS/_lib/SecurityInsight.shared-defaults.ps1
# (Layer 0 -- dot-sourced automatically by every SI launcher). Override here only
# what differs from the standard SecurityInsight layout:
#   WorkspaceName          = log-platform-management-securityinsight
#   WorkspaceResourceGroup = rg-securityinsight
#   DceName                = dce-securityinsight
#   DceResourceGroup       = rg-dce-securityinsight
#   DcrResourceGroup       = rg-dcr-securityinsight
#   Location               = westeurope

# Subscription (defaults to the Az context's current subscription, or
# $global:MainLogAnalyticsWorkspaceSubId if your platform sets it)
# $global:SubscriptionId = '<sub-guid>'

# Uncomment any of these only to DEVIATE from the shared defaults:
# $global:WorkspaceResourceGroup = 'rg-securityinsight'
# $global:DceResourceGroup       = 'rg-dce-securityinsight'
# $global:DcrResourceGroup       = 'rg-dcr-securityinsight'
# $global:Location               = 'westeurope'
# $global:WorkspaceName          = 'log-platform-management-securityinsight'
# $global:DceName                = 'dce-securityinsight'

# Data Collection Rule name (engine-specific -- Identity schema, not a shared default)
# $global:DcrName       = 'dcr-si-identity-assets'

# Custom table base name (engine-specific)
# $global:TableName     = 'SI_IdentityAssets'


# ============================================================================
# 4.  RETENTION  --  how long the workspace keeps the SI_IdentityAssets rows
# ============================================================================
# Set to your compliance / cost preference. 30 / 90 / 180 / 365 are common.
$global:WorkspaceRetentionDays = 90                    # default: 90


# ============================================================================
# 5.  RUNTIME FLAGS  (rarely changed)
# ============================================================================
# $global:Scope      = @('PROD')      # or @('TEST')
# $global:WhatIfMode = $false         # $true = dry run, no Azure writes


# ============================================================================
# 6.  MINIMUM COPY-PASTE EXAMPLE -- the absolute minimum to run Step2
# ============================================================================
# Uncomment this block, replace the three '<your-*>' placeholders, save as
# LauncherConfig.custom.ps1, and run:
#   .\launcher.community-vm.template.ps1
#
# Everything else (workspace name, DCE name, RG names, location) auto-resolves
# to the standard SecurityInsight layout from Layer 0 shared defaults.

<#
# --- Auth: SPN + plaintext secret (TESTING ONLY; use MI / KV / Cert in production) ---
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'

# --- Target subscription (optional if Az context is already on the right sub) ---
$global:SubscriptionId  = '<your-target-subscription-id-guid>'
#>
