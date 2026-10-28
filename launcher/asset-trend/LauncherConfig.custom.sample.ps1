#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for the SecurityInsight asset-trend engine.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. The custom file is gitignored, so
    your copy stays on your machine and is never overwritten by an update.

    Most customers need NOTHING here: authentication and the workspace come from the solution-wide
    config\SecurityInsight.custom.ps1, which covers every SI engine. Use this file only for trend-only
    deviations.

    Trend reads the Risk Analysis results in your workspace and publishes SI_Trend_CL, so it needs the
    same workspace settings as Risk Analysis ($global:SI_WorkspaceResourceId, the DCE/DCR settings) and
    an identity that can query the workspace and ingest through the DCR.

.NOTES
    Solution : SecurityInsight
    Engine   : Trend
#>

# ---------------------------------------------------------------------------
# AUTHENTICATION -- only if you do NOT keep it in config\SecurityInsight.custom.ps1
# (pick ONE block; comment out the others)
# ---------------------------------------------------------------------------

# Block 1 -- Managed Identity (preferred when running on an Azure VM with a system MI)
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-guid>'

# Block 2 -- SPN + Key Vault secret
# $global:SpnTenantId      = '<your-tenant-guid>'
# $global:SpnClientId      = '<your-app-registration-client-id>'
# $global:SpnKeyVaultName  = '<your-keyvault-name>'
# $global:SpnSecretName    = '<your-secret-name-in-keyvault>'

# Block 3 -- SPN + certificate (certificate in the machine or user store)
# $global:SpnTenantId              = '<your-tenant-guid>'
# $global:SpnClientId              = '<your-app-registration-client-id>'
# $global:SpnCertificateThumbprint = '<certificate-thumbprint>'

# Block 4 -- SPN + plaintext secret (TESTING ONLY -- never commit)
# $global:SpnTenantId     = '<your-tenant-guid>'
# $global:SpnClientId     = '<your-app-registration-client-id>'
# $global:SpnClientSecret = '<your-app-registration-client-secret>'

# ---------------------------------------------------------------------------
# OPTIONAL: trend behaviour
# ---------------------------------------------------------------------------

# 'Summary' (default) = one point per report per day. 'Detailed' also rolls up per-asset rows.
# $global:SI_Trend_Grain = 'Detailed'

# Weeks that -ShowWeeklyRate looks back over (default 12).
# $global:SI_Trend_Weeks = 26

# Compute and print, but do not publish (default $false).
# $global:SI_Trend_DryRun = $true

# A different DCR name for SI_Trend_CL (default: the engine's own).
# $global:SI_Trend_DcrName = '<dcr-name>'
