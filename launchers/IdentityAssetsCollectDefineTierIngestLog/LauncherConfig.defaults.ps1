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
# The four shared infrastructure values ($global:WorkspaceName,
# $global:WorkspaceResourceGroup, $global:DceName, $global:DceResourceGroup,
# $global:DcrResourceGroup, $global:Location) are set by LAYER 0 --
# SecurityInsight.shared-defaults.ps1 in _lib -- so every SI engine uses the
# same canonical layout by default. To override: edit
# SOLUTIONS/SecurityInsight/CUSTOMDATA/SecurityInsight.custom.ps1
# (solution-wide) or LauncherConfig.custom.ps1 (this launcher only).
#
# Only engine-specific values belong in this file.
$global:WorkspaceResourceId       = $null                       # overrides WorkspaceName when set (cross-sub supported)
$global:DceIngestionUri           = $null                       # auto-resolved from DceName via Get-AzDceListAll

# DCR name + table name are engine-specific (SI_IdentityAssets schema)
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
