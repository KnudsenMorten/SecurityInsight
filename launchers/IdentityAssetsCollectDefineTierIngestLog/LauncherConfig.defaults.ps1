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
#  DCR INGESTION TARGETS  -- customer MUST set these in their LauncherConfig.ps1
# ============================================================================
# These come from the Onboarding_IdentityAssets_LogAnalytics run; the engine
# throws cleanly if any are missing. No sensible default exists.
$global:DceIngestionUri      = $null
$global:WorkspaceResourceId  = $null
$global:DcrResourceGroup     = $null
$global:DcrName              = $null
$global:DceName              = $null
$global:TableName            = 'SI_IdentityAssets'


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
