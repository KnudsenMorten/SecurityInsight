#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for SecurityInsight privilege-tier-classifier engine.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. The custom
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    LAYERED CONFIG MODEL  (each layer overrides the previous)

      1. LauncherConfig.defaults.ps1            <- per-engine baseline
                                                 (this folder; ships with release)
      2. config\SecurityInsight.custom.ps1 <- optional solution-wide overrides
                                                 (covers EVERY SI engine in one place)
      3. LauncherConfig.custom.ps1            <- THIS FILE (your copy; per-engine,
                                                 wins over solution-wide)
      4. CLI args on the launcher             <- last word per invocation.

    Most customers put auth in the solution-wide config\SecurityInsight.custom.ps1
    so they only fill in once for all SI engines. Use THIS file only for per-engine
    deviations.

.NOTES
    Solution : SecurityInsight
    Engine   : PrivilegeTierClassifier
#>

# ---------------------------------------------------------------------------
# AUTHENTICATION (pick ONE block; comment out the others)
# ---------------------------------------------------------------------------

# Block 1 -- Managed Identity (preferred when running on Azure VM with system MI)
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-guid>'

# Block 2 -- SPN + Key Vault secret (preferred for non-MI scenarios)
# $global:SpnTenantId      = '<your-tenant-guid>'
# $global:SpnClientId      = '<your-app-registration-client-id>'
# $global:SpnKeyVaultName  = '<your-keyvault-name>'
# $global:SpnSecretName    = '<your-secret-name-in-keyvault>'

# Block 3 -- SPN + plaintext secret (TESTING ONLY -- never commit)
# $global:SpnTenantId     = '<your-tenant-guid>'
# $global:SpnClientId     = '<your-app-registration-client-id>'
# $global:SpnClientSecret = '<your-app-registration-client-secret>'

# ---------------------------------------------------------------------------
# OPTIONAL: AI behaviour overrides
# ---------------------------------------------------------------------------

# Disable the AI tiering call (engine falls back to its built-in static map)
# $global:SI_PrivilegeTierClassifier_RunAI = $false
