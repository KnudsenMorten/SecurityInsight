#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for Step2_OnboardValidate-SecurityInsight-Permissions.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this FIRST then the
    customer's LauncherConfig.custom.ps1 (gitignored), then applies CLI args.

    These globals map 1:1 to the Step2_OnboardValidate-SecurityInsight-Permissions.ps1
    parameters. The launcher reads them at runtime and forwards each non-null
    value to the script via splatting.

    Customer never edits this file.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Step2_OnboardValidate-SecurityInsight-Permissions
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

# ============================================================================
#  TARGET SPN  (the one whose permissions we're onboarding/validating)
# ============================================================================
# Display name. The script looks up an existing SPN by this name; if none is
# found it creates a new app registration + service principal.
$global:OnboardValidate_SpnDisplayName = 'sp-securityinsight'

# OR existing SPN by AppId. When set, displayName lookup is skipped.
$global:OnboardValidate_SpnAppId = $null


# ============================================================================
#  AZURE RBAC SCOPE  (where the SPN gets Reader + Tag Contributor)
# ============================================================================
# TenantRoot      = default. ONE grant at the tenant root management group,
#                   cascades to every sub + RG + resource. Needs Owner / User
#                   Access Admin at tenant root on the onboarding identity.
# PerSubscription = legacy. Granted per sub in AzureSubscriptionIds (or every
#                   enabled sub the caller can see).
# If TenantRoot fails at runtime the engine auto-falls-back to PerSubscription.
$global:OnboardValidate_AzureRbacScope = 'TenantRoot'

# Only used when AzureRbacScope = 'PerSubscription'.
# Empty array = enumerate every enabled subscription the operator can see.
# Set to a specific list to limit blast radius.
$global:OnboardValidate_AzureSubscriptionIds = @()

# Optional. Full resource id of the Defender/Sentinel Log Analytics workspace.
# When set, the script grants 'Log Analytics Reader' to the SPN at this scope
# so cross-workspace IdentityInfo / SPN sign-in queries succeed.
$global:OnboardValidate_DefenderWorkspaceResourceId = $null

# Optional. Full resource id of the DCR that ingests SI_IdentityAssets_CL.
# When set, the script grants 'Monitoring Metrics Publisher' to the SPN here.
$global:OnboardValidate_DcrResourceId = $null


# ============================================================================
#  AUTH METHOD  (the operator running the onboarding)
# ============================================================================
# How the script authenticates to Microsoft Graph + Azure. Left $null here so
# each launcher flavor can apply its own sensible default after the customer's
# LauncherConfig.custom.ps1 runs:
#   community-vm    / internal-vm    -> 'Interactive'      (admin user runs it)
#   community-azure / internal-azure -> 'ManagedIdentity'  (host's MI)
# Override in LauncherConfig.custom.ps1 to force a different method on any
# flavor.
#
# Whichever identity you authenticate as MUST have:
#   Entra : Privileged Role Administrator OR Application Administrator
#   Azure : Owner or User Access Administrator at each subscription / scope
$global:OnboardValidate_AuthMethod = $null

# Required for non-interactive methods (filled in by the customer's
# LauncherConfig.custom.ps1, NOT here).
$global:OnboardValidate_AuthTenantId             = $null
$global:OnboardValidate_AuthClientId             = $null
$global:OnboardValidate_AuthClientSecret         = $null
$global:OnboardValidate_AuthCertificateThumbprint = $null


# ============================================================================
#  RUNTIME FLAGS
# ============================================================================
# Dry run -- script walks the catalog and prints what it WOULD do but
# does not create the SPN, grant any permission, or assign any RBAC role.
$global:OnboardValidate_WhatIfMode = $false
