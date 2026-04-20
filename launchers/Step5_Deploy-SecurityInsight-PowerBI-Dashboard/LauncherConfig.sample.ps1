#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for Step5_Deploy-SecurityInsight-PowerBI-Dashboard.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. Customer
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    Defaults work for most lab installs -- you only MUST fill in:
      1. A Power BI SPN (tenant + client + secret) that has Workspace.ReadWrite.All
         permissions granted AND is allowed by the "Allow SPNs to use Power BI APIs"
         tenant setting. See DOCS/PowerBI-Prerequisites.md for the full setup.
      2. The customer's LA Workspace ID (GUID only, NOT the full Resource ID).

    Everything else has a sensible default from LauncherConfig.defaults.ps1.
#>

# ============================================================================
# 1.  POWER BI SPN  (REQUIRED)
# ============================================================================
$global:Step5_AuthMethod        = 'SpnSecret'
$global:Step5_AuthTenantId      = '<tenant-id-guid>'
$global:Step5_AuthClientId      = '<powerbi-spn-client-id>'
$global:Step5_AuthClientSecret  = '<powerbi-spn-secret>'

# Alternative: SPN + certificate
# $global:Step5_AuthMethod              = 'SpnCertificate'
# $global:Step5_AuthTenantId            = '<tenant-id-guid>'
# $global:Step5_AuthClientId            = '<powerbi-spn-client-id>'
# $global:Step5_AuthCertificateThumbprint = '<cert-thumbprint>'

# Alternative: Managed Identity (Azure host only; rare for Power BI APIs)
# $global:Step5_AuthMethod   = 'ManagedIdentity'
# $global:Step5_AuthClientId = '<user-assigned-mi-clientid>'   # omit for system-assigned

# Alternative: Interactive device code sign-in (ops laptop one-shot)
# $global:Step5_AuthMethod = 'Interactive'


# ============================================================================
# 2.  LOG ANALYTICS BINDING  (REQUIRED)
# ============================================================================
# Copy this from the LA portal:  Log Analytics -> Properties -> Workspace ID
# (the GUID, NOT the /subscriptions/.../workspaces/... resource id).
$global:Step5_LAWorkspaceId = '<la-workspace-guid>'
$global:Step5_LATenantId    = '<tenant-id-guid>'


# ============================================================================
# 3.  TARGET WORKSPACE / REPORT NAME  (optional; defaults kick in if omitted)
# ============================================================================
# $global:Step5_PowerBIWorkspaceName = 'SecurityInsight-Reports'
# $global:Step5_ReportName           = 'SecurityInsight - Risk Analysis'


# ============================================================================
# 4.  DASHBOARD PARAMETERS  (optional)
# ============================================================================
# $global:Step5_StalenessDays = 30    # days a TraceID must stay open to be "stale"
# $global:Step5_TopNFindings  = 25    # size of the "Top-N highest risk" tile


# ============================================================================
# 5.  AAD GROUP ACCESS  (optional; skip to manage access in the portal)
# ============================================================================
# $global:Step5_AccessGroupObjectId = '<aad-group-objectid-guid>'
# $global:Step5_AccessGroupRole     = 'Viewer'    # Viewer / Member / Contributor / Admin


# ============================================================================
# 6.  DRY-RUN
# ============================================================================
# $global:Step5_WhatIfMode = $true   # preview without creating/updating anything


# ============================================================================
# MINIMUM COPY-PASTE EXAMPLE  (lab, SPN + plaintext secret)
# ============================================================================
<#
$global:Step5_AuthMethod       = 'SpnSecret'
$global:Step5_AuthTenantId     = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'
$global:Step5_AuthClientId     = '11111111-2222-3333-4444-555555555555'
$global:Step5_AuthClientSecret = '<paste-secret-here>'
$global:Step5_LAWorkspaceId    = 'abc12345-6789-...-000000000000'
$global:Step5_LATenantId       = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'
#>
