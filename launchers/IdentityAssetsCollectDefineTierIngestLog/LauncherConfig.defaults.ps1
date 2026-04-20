#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for IdentityAssetsCollectDefineTierIngestLog.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then dot-sources the customer's LauncherConfig.ps1 (which overrides
    only the values they care about), then applies CLI args (last word).

    Customer never edits this file.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : IdentityAssetsCollectDefineTierIngestLog
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

# ============================================================================
#  DCR INGESTION TARGETS
# ============================================================================
# EVERYTHING AUTO-RESOLVES. The engine auto-creates the workspace, DCE, DCE RG,
# and DCR RG if any are missing -- and assigns the ingestion SPN the roles it
# needs. The defaults below are the standard SecurityInsight layout; the
# customer only has to override values that differ.
#
# Workspace lookup hierarchy:
#   $global:WorkspaceResourceId  -- wins if set (cross-sub supported)
#   $global:WorkspaceName        -- looked up in current context; created if missing
$global:WorkspaceName             = 'log-platform-management-securityinsight'
$global:WorkspaceResourceId       = $null
$global:WorkspaceResourceGroup    = 'rg-securityinsight'       # used if workspace must be created

# DCE -- name is the only thing customers normally touch. Ingestion URI is
# auto-resolved from the name via Get-AzDceListAll.
$global:DceName                   = 'dce-securityinsight'
$global:DceResourceGroup          = 'rg-dce-securityinsight'   # auto-created if missing
$global:DceIngestionUri           = $null                      # auto-resolved from DceName

# DCR -- DCR name is engine-specific (SI_IdentityAssets schema)
$global:DcrResourceGroup          = 'rg-dcr-securityinsight'   # auto-created if missing
$global:DcrName                   = 'dcr-si-identity-assets'
$global:TableName                 = 'SI_IdentityAssets'


# ============================================================================
#  CROSS-WORKSPACE  (Defender / Sentinel IdentityInfo lookups)
# ============================================================================
# Leave $null to use $global:WorkspaceResourceId for both the SI ingestion
# and the IdentityInfo reads. Set this only when IdentityInfo lives in a
# different workspace -- the engine then issues cross-workspace KQL.
$global:DefenderWorkspaceResourceId = $null


# ============================================================================
#  CUSTOM SECURITY ATTRIBUTES + INGESTION TUNING
# ============================================================================
$global:CsaAttributeSet = 'SecurityInsight'
$global:BatchSize       = 300


# ============================================================================
#  AZURE SUBSCRIPTION SCOPE
# ============================================================================
# Wildcard patterns of subscription NAMES to skip during the Azure-side
# enumeration (Get-AzSubscription). Patterns are PowerShell -like wildcards.
# Empty / unset = scan all enabled subs.
$global:SubscriptionNameExcludePatterns = @()


# ============================================================================
#  TENANT INFO
# ============================================================================
# Tenant primary domain (used in some output column values; engine falls back
# to the authenticating SPN's tenant if not set)
$global:TenantDomain = $null


# ============================================================================
#  TROUBLESHOOTING / WHATIF
# ============================================================================
$global:TroubleshootingMode = $false      # $true = process only first 10 rows
$global:WhatIfMode          = $false      # $true = dry run, no DCR ingestion
$global:SuppressErrors      = $false
$global:SuppressWarnings    = $false
