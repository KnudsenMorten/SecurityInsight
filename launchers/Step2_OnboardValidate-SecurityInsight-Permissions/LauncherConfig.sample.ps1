#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for Step2_OnboardValidate-SecurityInsight-Permissions.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. Customer
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    LAYERED CONFIG MODEL

      1. LauncherConfig.defaults.ps1   <- ships with each release; baseline.
      2. LauncherConfig.custom.ps1     <- THIS FILE (your copy). Override only
                                          what you need.
      3. CLI args on the launcher      <- last word for that one invocation.

    Defaults work out-of-the-box for an interactive run (Privileged Role Admin
    + Owner). You only need to edit this file if you want to:
      - rename the target SPN
      - limit the Azure subscription scope
      - grant cross-workspace + DCR scopes too
      - run unattended via SPN/MI/cert auth

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Step2_OnboardValidate-SecurityInsight-Permissions
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

# ============================================================================
# 1.  TARGET SPN  (uncomment + edit only if you want a different name)
# ============================================================================
# $global:OnboardValidate_SpnDisplayName = 'sp-mysecurityinsight'
# $global:OnboardValidate_SpnAppId       = '<existing-app-client-id-guid>'   # alternative


# ============================================================================
# 2.  AZURE RBAC SCOPE  (where SPN gets Reader + Tag Contributor)
# ============================================================================
# Default is 'TenantRoot' -- ONE assignment at the tenant root management group,
# cascades to every sub + RG. Reader lets Resource Graph see everything;
# Tag Contributor is needed by CriticalAssetTagging to write tier tags on
# subs / RGs / resources.
#
# Switch to 'PerSubscription' if you can't elevate to tenant-root UAA, or to
# limit blast radius to specific subs.
# $global:OnboardValidate_AzureRbacScope = 'PerSubscription'

# Only used when AzureRbacScope = 'PerSubscription'.
# Uncomment to limit scope; leave commented for "all subs the caller can see".
# $global:OnboardValidate_AzureSubscriptionIds = @(
#     '<sub-guid-1>',
#     '<sub-guid-2>'
# )

# Set if Defender/Sentinel IdentityInfo lives in a workspace the SPN needs
# Log Analytics Reader on. Required for cross-workspace SI scenarios.
# $global:OnboardValidate_DefenderWorkspaceResourceId = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>'

# Set so the SPN gets 'Monitoring Metrics Publisher' on the SI DCR (required
# for the IdentityAssetsCollect engine to ingest rows).
# $global:OnboardValidate_DcrResourceId = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/dcr-si-identity-assets'


# ============================================================================
# 3.  UNATTENDED AUTH  (only if you don't want the interactive browser flow)
# ============================================================================
# Default is Interactive (browser sign-in). Switch to one of these for
# scheduled runs, CI/CD, or platform-managed hosts.

# ----- METHOD: Managed Identity ----------------------------------------------
# $global:OnboardValidate_AuthMethod   = 'ManagedIdentity'
# $global:OnboardValidate_AuthClientId = '<user-assigned-mi-clientid>'   # omit for system-assigned

# ----- METHOD: SPN + secret (testing / CI) ----------------------------------
# $global:OnboardValidate_AuthMethod       = 'SpnSecret'
# $global:OnboardValidate_AuthTenantId     = '<tenant-id-guid>'
# $global:OnboardValidate_AuthClientId     = '<onboarding-spn-clientid>'
# $global:OnboardValidate_AuthClientSecret = '<onboarding-spn-secret>'

# ----- METHOD: SPN + certificate --------------------------------------------
# $global:OnboardValidate_AuthMethod              = 'SpnCertificate'
# $global:OnboardValidate_AuthTenantId            = '<tenant-id-guid>'
# $global:OnboardValidate_AuthClientId            = '<onboarding-spn-clientid>'
# $global:OnboardValidate_AuthCertificateThumbprint = '<thumbprint>'


# ============================================================================
# 4.  WHATIF
# ============================================================================
# $global:OnboardValidate_WhatIfMode = $true


# ============================================================================
# 5.  MINIMUM COPY-PASTE EXAMPLES
# ============================================================================
# The absolute simplest way to get Step1 done is to NOT even create this file
# and just run the launcher. You'll get an interactive browser sign-in, and
# the engine creates 'sp-securityinsight' + grants all the right API perms +
# Azure Reader on every sub you can see. For 90% of labs this is enough.
#
#     .\launcher.community-vm.template.ps1
#
# If you want to run Step1 UNATTENDED (CI/CD or a scheduled task), uncomment
# and fill this block. The onboarding SPN needs 'Privileged Role Administrator'
# (or Global Admin) to create app registrations + grant admin consent.

<#
$global:OnboardValidate_AuthMethod       = 'SpnSecret'
$global:OnboardValidate_AuthTenantId     = '<tenant-id-guid>'
$global:OnboardValidate_AuthClientId     = '<onboarding-spn-clientid>'
$global:OnboardValidate_AuthClientSecret = '<onboarding-spn-secret>'
#>

# If your Defender/Sentinel IdentityInfo lives in a separate LA workspace, or
# you want to pre-grant the DCR RBAC for Step2's DCR, add these:
#
# $global:OnboardValidate_DefenderWorkspaceResourceId = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>'
# $global:OnboardValidate_DcrResourceId               = '/subscriptions/<sub>/resourceGroups/rg-dcr-securityinsight/providers/Microsoft.Insights/dataCollectionRules/dcr-si-identity-assets'
