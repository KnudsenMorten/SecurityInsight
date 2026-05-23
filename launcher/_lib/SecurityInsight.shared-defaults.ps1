#Requires -Version 5.1
<#
.SYNOPSIS
    Solution-wide shared defaults for SecurityInsight engines.

.DESCRIPTION
    Loaded by Initialize-LauncherConfig as Layer 0 -- BEFORE any per-engine
    defaults.ps1, platform-defaults, solution-custom or launcher-custom file.
    Customer overrides (any later layer) win.

    These four values define the canonical SecurityInsight infrastructure
    layout that ALL engines in the solution share by default:

        $global:WorkspaceName     = 'log-platform-management-securityinsight'
        $global:DceName           = 'dce-securityinsight'
        $global:DceResourceGroup  = 'rg-dce-securityinsight'
        $global:DcrResourceGroup  = 'rg-dcr-securityinsight'

    The ingestion engines (RiskAnalysis + IdentityAssetsCollectDefineTierIngestLog)
    auto-create the Workspace + DCE + RGs if any are missing, and assign the
    ingestion SPN the roles it needs. Customers only need to override when
    deviating from this standard layout.

    To override a value SOLUTION-WIDE (all SI engines):
      edit SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1

    To override for a SINGLE engine:
      edit LauncherConfig.custom.ps1 in that engine's launcher folder.

.NOTES
    File         : SecurityInsight.shared-defaults.ps1
    Solution     : SecurityInsight
    Developed by : Morten Knudsen, Microsoft MVP
#>

# --- Log Analytics workspace (shared by RiskAnalysis + Identity + Onboarding) ---
$global:WorkspaceName          = 'log-platform-management-securityinsight'
$global:WorkspaceResourceGroup = 'rg-securityinsight'

# --- Data Collection Endpoint (shared across all SI ingestion engines) ---
$global:DceName                = 'dce-securityinsight'
$global:DceResourceGroup       = 'rg-dce-securityinsight'

# --- Data Collection Rules (one RG holds ALL SI DCRs; DCR NAMES are engine-specific) ---
$global:DcrResourceGroup       = 'rg-dcr-securityinsight'

# --- Region (used when the engine has to create any missing infra) ---
$global:Location               = 'westeurope'

# --- Storage authentication mode (default = OAuth, NOT key) ---
# v2.2.284 -- pre-OAuth-default behaviour was: missing $global:SI_UseStorageOAuth
# fell through to $false, which then required SI_StorageKey to be present in
# the customer custom file. Fresh installs from Initialize-PlatformVm.ps1 don't
# set either, so the launcher halted at the first SI_StorageKey lookup.
# Defaulting to $true here means OAuth is the canonical staging-storage auth
# path -- the SPN's "Storage Blob Data Contributor" role on the staging
# account is sufficient and SI_StorageKey is never read or persisted.
# Customer can still opt out by setting $global:SI_UseStorageOAuth = $false
# in SecurityInsight.custom.ps1 (Layer 3, loads after this file).
$global:SI_UseStorageOAuth     = $true

# --- Subscription ---
# INTERNAL (AF) mode: the platform-defaults.ps1 layer sets
# $global:MainLogAnalyticsWorkspaceSubId; Initialize-LauncherConfig derives
# $global:SubscriptionId from it after all layers load (see the "derived
# defaults" step at the bottom of Initialize-LauncherConfig.ps1), so this
# eager assignment below is just a safety hint -- it's a no-op at Layer 0.
# COMMUNITY mode: customer sets $global:SubscriptionId directly in LauncherConfig.custom.ps1.
$global:SubscriptionId         = $global:MainLogAnalyticsWorkspaceSubId

# --- SPN bridge: v2.3 -> v2.2 SI engine contract -----------------------------
# 16 engine sites (Invoke-RiskAnalysis, Invoke-SIEngineRun, Send-SIRunHealthRow,
# Build-IdentityProfileRow, Invoke-Output) still read $global:SI_SPN_*. v2.3
# Connect-Platform sets $global:HighPriv_Modern_* + $global:AzureTenantId.
# Bridge here so customer custom files don't need to repeat the mapping. All
# four assignments are conditional ("if not already set") so a customer can
# still override any of them later in custom.ps1 if needed.
if (-not $global:SI_SPN_TenantId -and $global:AzureTenantId) {
    $global:SI_SPN_TenantId = $global:AzureTenantId
}
if (-not $global:SI_SPN_AppId -and $global:HighPriv_Modern_ApplicationID_Azure) {
    $global:SI_SPN_AppId = $global:HighPriv_Modern_ApplicationID_Azure
}
if (-not $global:SI_SPN_Secret -and $global:HighPriv_Modern_Secret_Azure) {
    $global:SI_SPN_Secret = $global:HighPriv_Modern_Secret_Azure
}
if (-not $global:SI_SPN_ObjectId -and $global:SI_SPN_AppId) {
    try {
        $global:SI_SPN_ObjectId = (Get-AzADServicePrincipal -ApplicationId $global:SI_SPN_AppId -ErrorAction Stop).Id
    } catch {
        Write-Verbose ("SI shared-defaults: SPN ObjectId lookup failed -- engines that need it will retry: $($_.Exception.Message)")
    }
}

# --- SMTP credential bridge + KV fallback ------------------------------------
# Why:
#   2linkit platform-defaults populates $global:HighPriv_SMTP_UserName +
#   $global:HighPriv_SMTP_Password (pulled from KV names 'SMTPuser' /
#   'SMTPpassword'). SI engines read $global:SMTPUser / $global:SMTPPassword.
#   Without a bridge, SMTP fails silently with "no creds, sending anonymous"
#   even though the secret is loaded under the HighPriv_* names.
#
#   Community-flavour customers don't have PlatformConfiguration at all -- for
#   them we fall back to a direct KV probe (case-insensitive, covers
#   'SMTPpassword' / 'SMTP-Password' variants).
# How:
#   1. Bridge HighPriv_SMTP_* -> SMTPUser/SMTPPassword (free, no KV call).
#   2. If still empty AND $global:Context exists, probe KV directly.
#   Same shape as the SPN bridge above. All assignments conditional so a
#   customer can override in layer 3 (custom.ps1) if needed.
if (-not $global:SMTPUser -and $global:HighPriv_SMTP_UserName) {
    $global:SMTPUser = $global:HighPriv_SMTP_UserName
}
if (-not $global:SMTPPassword -and $global:HighPriv_SMTP_Password) {
    $global:SMTPPassword = $global:HighPriv_SMTP_Password
}
if ($global:Context) {
    if (-not $global:SMTPPassword) {
        foreach ($_smtpKvName in @('SMTPpassword','SMTP-Password')) {
            try {
                $_val = Get-PlatformSecret -Context $global:Context -Name $_smtpKvName -AsPlainText -ErrorAction Stop
                if ($_val) {
                    $global:SMTPPassword = $_val
                    Write-Verbose ("SI shared-defaults: SMTPPassword resolved from KV name '$_smtpKvName' (community fallback)")
                    break
                }
            } catch {
                Write-Verbose ("SI shared-defaults: KV name '$_smtpKvName' not present -- trying next ($($_.Exception.Message))")
            }
        }
    }
    if (-not $global:SMTPUser) {
        foreach ($_smtpKvName in @('SMTPuser','SMTP-User')) {
            try {
                $_val = Get-PlatformSecret -Context $global:Context -Name $_smtpKvName -AsPlainText -ErrorAction Stop
                if ($_val) {
                    $global:SMTPUser = $_val
                    Write-Verbose ("SI shared-defaults: SMTPUser resolved from KV name '$_smtpKvName' (community fallback)")
                    break
                }
            } catch {
                Write-Verbose ("SI shared-defaults: KV name '$_smtpKvName' not present -- trying next ($($_.Exception.Message))")
            }
        }
    }
}
