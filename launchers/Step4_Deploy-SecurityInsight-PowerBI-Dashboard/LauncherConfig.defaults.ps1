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
if (-not (Test-Path variable:global:Step4_PowerBIWorkspaceName)) { $global:Step4_PowerBIWorkspaceName = 'SecurityInsight-Reports' }
if (-not (Test-Path variable:global:Step4_ReportName)) { $global:Step4_ReportName = 'SecurityInsight - Risk Analysis' }

# ============================================================================
#  .PBIX PATH  (leave $null to use TOOLS/PowerBI/SecurityInsight-RiskAnalysis.pbix)
# ============================================================================
if (-not (Test-Path variable:global:Step4_PbixPath)) { $global:Step4_PbixPath = $null }

# ============================================================================
#  LOG ANALYTICS BINDING  (the dashboard queries this LA workspace)
# ============================================================================
# LA Workspace ID (GUID only -- NOT the full Resource ID). Leave $null to
# derive from $global:WorkspaceId if set by Layer 0 / Layer 3.
if (-not (Test-Path variable:global:Step4_LAWorkspaceId)) { $global:Step4_LAWorkspaceId = $null }
if (-not (Test-Path variable:global:Step4_LATenantId)) { $global:Step4_LATenantId = $null }

# ============================================================================
#  DASHBOARD PARAMETERS
# ============================================================================
if (-not (Test-Path variable:global:Step4_StalenessDays)) { $global:Step4_StalenessDays = 30 }
if (-not (Test-Path variable:global:Step4_TopNFindings)) { $global:Step4_TopNFindings = 25 }

# ============================================================================
#  AAD GROUP ACCESS  (optional)
# ============================================================================
# If set, the script adds this AAD group to the Power BI workspace with the
# role below so members can open the dashboard. Leave $null to manage access
# manually in the Power BI portal.
if (-not (Test-Path variable:global:Step4_AccessGroupObjectId)) { $global:Step4_AccessGroupObjectId = $null }
if (-not (Test-Path variable:global:Step4_AccessGroupRole)) { $global:Step4_AccessGroupRole = 'Viewer' }     # Viewer / Member / Contributor / Admin

# ============================================================================
#  REFRESH ON DEPLOY
# ============================================================================
# Queue an initial dataset refresh right after upload so the dashboard has
# data on first open.
if (-not (Test-Path variable:global:Step4_TriggerInitialRefresh)) { $global:Step4_TriggerInitialRefresh = $true }

# ============================================================================
#  AUTH METHOD  (how to auth to the Power BI REST API)
# ============================================================================
# Left $null so flavour-specific defaults apply:
#   community-vm     -> 'SpnSecret' (customer paste SPN creds in .custom)
#   community-azure  -> 'ManagedIdentity'
#   internal-vm / internal-azure -> taken from platform framework
if (-not (Test-Path variable:global:Step4_AuthMethod)) { $global:Step4_AuthMethod = $null }
if (-not (Test-Path variable:global:Step4_AuthTenantId)) { $global:Step4_AuthTenantId = $null }
if (-not (Test-Path variable:global:Step4_AuthClientId)) { $global:Step4_AuthClientId = $null }
if (-not (Test-Path variable:global:Step4_AuthClientSecret)) { $global:Step4_AuthClientSecret = $null }
if (-not (Test-Path variable:global:Step4_AuthCertificateThumbprint)) { $global:Step4_AuthCertificateThumbprint = $null }

# ============================================================================
#  RUNTIME FLAGS
# ============================================================================
if (-not (Test-Path variable:global:Step4_WhatIfMode)) { $global:Step4_WhatIfMode = $false }
