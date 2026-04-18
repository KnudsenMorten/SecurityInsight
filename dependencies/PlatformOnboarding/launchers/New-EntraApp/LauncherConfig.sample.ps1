#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for New-EntraApp.
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
#  Optional engine-level settings (apply regardless of auth method)
# ================================================================================
# $global:Scope            = @('PROD')            # or @('TEST')
# $global:WhatIfMode        = $false               # $true = dry run, no changes
