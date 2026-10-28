#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for the SecurityInsight asset-tagging engine.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder (gitignored -- never overwritten by an
    update). Most customers need nothing here: authentication comes from config\SecurityInsight.custom.ps1.

    🔑 asset-tagging is REPORT ONLY by default: it logs every tag it would set and changes nothing. It writes
    only with -Apply on a run, or $global:SI_AssetTagging_Apply = $true (below, or in config\SecurityInsight.custom.ps1).
    Writing needs the write grants (setup\Grant-SIIdentity.ps1 -Tagging, or the Tag Contributor role setup grants
    only when asked: -IncludeTagContributor / the wizard checkbox).

.NOTES
    Solution : SecurityInsight
    Engine   : AssetTagging
#>

# ---------------------------------------------------------------------------
# AUTHENTICATION -- only if you do NOT keep it in config\SecurityInsight.custom.ps1
# (default: the host's managed identity, $global:SI_AuthMethod = 'ManagedIdentity'; an SPN as below when chosen)
# ---------------------------------------------------------------------------

# SPN + certificate (recommended)
# $global:SpnTenantId              = '<your-tenant-guid>'
# $global:SpnClientId              = '<your-app-registration-client-id>'
# $global:SpnCertificateThumbprint = '<certificate-thumbprint>'

# SPN + secret in Key Vault
# $global:SpnTenantId      = '<your-tenant-guid>'
# $global:SpnClientId      = '<your-app-registration-client-id>'
# $global:SpnKeyVaultName  = '<your-keyvault-name>'
# $global:SpnSecretName    = '<your-secret-name-in-keyvault>'

# ---------------------------------------------------------------------------
# OPTIONAL
# ---------------------------------------------------------------------------

# Write the tags on every run (default: report only -- every planned tag is logged, nothing is changed).
# $global:SI_AssetTagging_Apply = $true

# Report only, even when writing is switched on above (the default already reports only).
# $global:WhatIfMode = $true

# Which scope's rules to apply (default PROD).
# $global:Scope = @('PROD')

# Your own rules folder and file names (default: asset-profiling-enrichment\endpoint, AssetTagging.*.yaml).
# $global:SettingsPath   = 'C:\SecurityInsight\my-rules'
# $global:CustomYamlFile = 'AssetTagging.custom.yaml'

# The Entra custom security attribute set identity tags are written into (default SecurityInsight).
# $global:CsaAttributeSet = 'SecurityInsight'
