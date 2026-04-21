#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for Step2_OnboardValidate-SecurityInsight-LogAnalytics.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file BEFORE
    the customer's LauncherConfig.ps1, so any value here can be overridden
    by the customer copy.

    Customer never edits this file.

    LAYERING (every SI engine uses the same 5 layers -- see README § 3.6):
      0. _lib/SecurityInsight.shared-defaults.ps1   (solution-wide names)
      1. LauncherConfig.defaults.ps1                (THIS FILE -- engine baseline)
      2. platform-defaults.ps1                      (customer, internal only)
      3. SecurityInsight.custom.ps1                 (customer, solution-wide)
      4. LauncherConfig.custom.ps1 / LauncherConfig.ps1 (customer, per-engine)
      5. CLI args                                   (last word)

    The shared infrastructure values ($global:WorkspaceName,
    $global:WorkspaceResourceGroup, $global:DceName, $global:DceResourceGroup,
    $global:DcrResourceGroup, $global:Location) are set by LAYER 0. Only
    engine-specific values belong in this file.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Step2_OnboardValidate-SecurityInsight-LogAnalytics
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  ENGINE-SPECIFIC RESOURCE NAMES
# ============================================================================
# DCR + table are engine-specific (SI_IdentityAssets schema).
$global:DcrName       = 'dcr-si-identity-assets'
$global:TableName     = 'SI_IdentityAssets'


# ============================================================================
#  RETENTION
# ============================================================================
# How long the Log Analytics workspace keeps SI_IdentityAssets_CL rows.
# Common choices: 30 / 90 / 180 / 365. Compliance/cost tradeoff.
$global:WorkspaceRetentionDays = 90


# ============================================================================
#  AZURE PLACEMENT OVERRIDES (normally sourced from Layer 0)
# ============================================================================
# Leaving these as $null lets Layer 0 (SecurityInsight.shared-defaults.ps1)
# populate them. Set here to override for this engine only.
# $global:SubscriptionId         = $null
# $global:WorkspaceName          = $null
# $global:WorkspaceResourceGroup = $null
# $global:DceName                = $null
# $global:DceResourceGroup       = $null
# $global:DcrResourceGroup       = $null
# $global:Location               = $null


# ============================================================================
#  RUNTIME FLAGS
# ============================================================================
$global:WhatIfMode       = $false   # $true = dry run, no Azure writes
$global:SuppressErrors   = $false
$global:SuppressWarnings = $false
