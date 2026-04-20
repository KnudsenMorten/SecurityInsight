#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for Step4_Deploy-SecurityInsight-PowerBI-Dashboard.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this FIRST then the
    customer's LauncherConfig.custom.ps1 (gitignored). The customer NEVER
    edits this file -- it's replaced on every release.

    Maps 1:1 to Step4_Deploy-SecurityInsight-PowerBI-Dashboard.ps1 parameters.
    Override any of them in LauncherConfig.custom.ps1.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Step4_Deploy-SecurityInsight-PowerBI-Dashboard
#>

# ============================================================================
#  TARGET POWER BI WORKSPACE / REPORT
# ============================================================================
$global:Step4_PowerBIWorkspaceName = 'SecurityInsight-Reports'
$global:Step4_ReportName           = 'SecurityInsight - Risk Analysis'

# ============================================================================
#  .PBIX PATH  (leave $null to use TOOLS/PowerBI/SecurityInsight-RiskAnalysis.pbix)
# ============================================================================
$global:Step4_PbixPath             = $null

# ============================================================================
#  LOG ANALYTICS BINDING  (the dashboard queries this LA workspace)
# ============================================================================
# LA Workspace ID (GUID only -- NOT the full Resource ID). Leave $null to
# derive from $global:WorkspaceId if set by Layer 0 / Layer 3.
$global:Step4_LAWorkspaceId        = $null
$global:Step4_LATenantId           = $null

# ============================================================================
#  DASHBOARD PARAMETERS
# ============================================================================
$global:Step4_StalenessDays        = 30
$global:Step4_TopNFindings         = 25

# ============================================================================
#  AAD GROUP ACCESS  (optional)
# ============================================================================
# If set, the script adds this AAD group to the Power BI workspace with the
# role below so members can open the dashboard. Leave $null to manage access
# manually in the Power BI portal.
$global:Step4_AccessGroupObjectId  = $null
$global:Step4_AccessGroupRole      = 'Viewer'     # Viewer / Member / Contributor / Admin

# ============================================================================
#  REFRESH ON DEPLOY
# ============================================================================
# Queue an initial dataset refresh right after upload so the dashboard has
# data on first open.
$global:Step4_TriggerInitialRefresh = $true

# ============================================================================
#  AUTH METHOD  (how to auth to the Power BI REST API)
# ============================================================================
# Left $null so flavour-specific defaults apply:
#   community-vm     -> 'SpnSecret' (customer paste SPN creds in .custom)
#   community-azure  -> 'ManagedIdentity'
#   internal-vm / internal-azure -> taken from platform framework
$global:Step4_AuthMethod            = $null
$global:Step4_AuthTenantId          = $null
$global:Step4_AuthClientId          = $null
$global:Step4_AuthClientSecret      = $null
$global:Step4_AuthCertificateThumbprint = $null

# ============================================================================
#  RUNTIME FLAGS
# ============================================================================
$global:Step4_WhatIfMode           = $false
