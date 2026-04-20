#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for Step5_Deploy-SecurityInsight-PowerBI-Dashboard.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this FIRST then the
    customer's LauncherConfig.custom.ps1 (gitignored). The customer NEVER
    edits this file -- it's replaced on every release.

    Maps 1:1 to Step5_Deploy-SecurityInsight-PowerBI-Dashboard.ps1 parameters.
    Override any of them in LauncherConfig.custom.ps1.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Step5_Deploy-SecurityInsight-PowerBI-Dashboard
#>

# ============================================================================
#  TARGET POWER BI WORKSPACE / REPORT
# ============================================================================
$global:Step5_PowerBIWorkspaceName = 'SecurityInsight-Reports'
$global:Step5_ReportName           = 'SecurityInsight - Risk Analysis'

# ============================================================================
#  .PBIX PATH  (leave $null to use TOOLS/PowerBI/SecurityInsight-RiskAnalysis.pbix)
# ============================================================================
$global:Step5_PbixPath             = $null

# ============================================================================
#  LOG ANALYTICS BINDING  (the dashboard queries this LA workspace)
# ============================================================================
# LA Workspace ID (GUID only -- NOT the full Resource ID). Leave $null to
# derive from $global:WorkspaceId if set by Layer 0 / Layer 3.
$global:Step5_LAWorkspaceId        = $null
$global:Step5_LATenantId           = $null

# ============================================================================
#  DASHBOARD PARAMETERS
# ============================================================================
$global:Step5_StalenessDays        = 30
$global:Step5_TopNFindings         = 25

# ============================================================================
#  AAD GROUP ACCESS  (optional)
# ============================================================================
# If set, the script adds this AAD group to the Power BI workspace with the
# role below so members can open the dashboard. Leave $null to manage access
# manually in the Power BI portal.
$global:Step5_AccessGroupObjectId  = $null
$global:Step5_AccessGroupRole      = 'Viewer'     # Viewer / Member / Contributor / Admin

# ============================================================================
#  REFRESH ON DEPLOY
# ============================================================================
# Queue an initial dataset refresh right after upload so the dashboard has
# data on first open.
$global:Step5_TriggerInitialRefresh = $true

# ============================================================================
#  AUTH METHOD  (how to auth to the Power BI REST API)
# ============================================================================
# Left $null so flavour-specific defaults apply:
#   community-vm     -> 'SpnSecret' (customer paste SPN creds in .custom)
#   community-azure  -> 'ManagedIdentity'
#   internal-vm / internal-azure -> taken from platform framework
$global:Step5_AuthMethod            = $null
$global:Step5_AuthTenantId          = $null
$global:Step5_AuthClientId          = $null
$global:Step5_AuthClientSecret      = $null
$global:Step5_AuthCertificateThumbprint = $null

# ============================================================================
#  RUNTIME FLAGS
# ============================================================================
$global:Step5_WhatIfMode           = $false
