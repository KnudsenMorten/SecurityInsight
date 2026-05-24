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

# --- Fingerprint cache (default = DISABLED, opt-in) ---
# The fingerprint cache (Azure Table 'sifingerprint') stores per-asset hash +
# computed SI_Tier verdict so the Collect stage can SKIP assets whose source
# signals haven't changed since the prior run (cadence-not-due short-circuit).
#
# Default is OFF because:
#   (a) tenants running ForceFullRun=true on every cron tick (the common case)
#       never read the cache -- the writes are pure overhead + 64KB property
#       limit collisions on identity rows with large role/permission JSON;
#   (b) the cache writes generate transcript noise (PS>TerminatingError(Invoke-
#       RestMethod) lines) that obscure real errors during operator review;
#   (c) when disabled, the Collect skip-gate degrades to "ForceFullRun-only" --
#       safe because the engine still emits every row, just without the
#       per-asset shortcut.
#
# Customers running incremental (ForceFullRun=$false) WHERE the cache actually
# saves classifier work opt in via:
#   $global:SI_FingerprintCache_Enabled = $true   # in SecurityInsight.custom.ps1
#
# Containers are unaffected either way -- the cache is a per-asset optimization,
# not a coordination mechanism. KEDA replicas don't share state through it.
$global:SI_FingerprintCache_Enabled = $false

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

# --- SMTP credential resolution ----------------------------------------------
# Convention (canonical, post-v2.2.366):
#   $global:SMTPUser     = SMTP relay LOGIN (auth username)
#   $global:SMTPPassword = SMTP relay PASSWORD
#   $global:SMTPFrom     = visible from-address header on outbound mail
#
# INTERNAL automation pattern (this is your case):
#   Platform-defaults sets $global:SMTPUser to the FROM ADDRESS (legacy 2linkit
#   convention -- the variable name is "SMTPUser" but its content is semantically
#   the from-address). The actual SMTP relay LOGIN + PASSWORD live in Key Vault
#   under secret names 'SMTPuser' + 'SMTPpassword'. When we have a platform
#   Context AND Mail_SendAnonymous is OFF, we:
#     1. Promote platform-defaults' $global:SMTPUser -> $global:SMTPFrom
#     2. Force-pull SMTPUser + SMTPPassword from KV (override the from-value)
#   Bridges from $global:HighPriv_SMTP_* (if your platform-defaults uses those)
#   are honored as a final fallback.
#
# COMMUNITY pattern (no platform Context):
#   Customer sets the actual login in $global:SMTPUser via custom.ps1 directly.
#   No promote, no KV pull (skipped silently). Customer sets SMTPFrom too if
#   different from SMTPUser.

# 1. INTERNAL automation: promote from-address + force-pull KV creds
if ($global:Context -and ($global:Mail_SendAnonymous -eq $false)) {
    # Promote platform-defaults' SMTPUser -> SMTPFrom (preserves the from address)
    if (-not $global:SMTPFrom -and $global:SMTPUser) {
        $global:SMTPFrom = $global:SMTPUser
        $global:SMTPUser = $null   # clear so KV pull below populates the actual login
        Write-Verbose "SI shared-defaults: promoted platform-defaults `$global:SMTPUser to `$global:SMTPFrom (legacy 2linkit convention); will pull actual SMTPUser+Password from KV below"
    }
    # Force-pull SMTPUser from KV (overrides any earlier value)
    if (-not $global:SMTPUser) {
        foreach ($_smtpKvName in @('SMTPuser','SMTP-User')) {
            try {
                $_val = Get-PlatformSecret -Context $global:Context -Name $_smtpKvName -AsPlainText -ErrorAction Stop
                if ($_val) {
                    $global:SMTPUser = $_val
                    Write-Verbose ("SI shared-defaults: SMTPUser resolved from KV name '$_smtpKvName' (internal automation, Anonymous=false)")
                    break
                }
            } catch {
                Write-Verbose ("SI shared-defaults: KV name '$_smtpKvName' not present -- trying next ($($_.Exception.Message))")
            }
        }
    }
    # Pull SMTPPassword from KV
    if (-not $global:SMTPPassword) {
        foreach ($_smtpKvName in @('SMTPpassword','SMTP-Password')) {
            try {
                $_val = Get-PlatformSecret -Context $global:Context -Name $_smtpKvName -AsPlainText -ErrorAction Stop
                if ($_val) {
                    $global:SMTPPassword = $_val
                    Write-Verbose ("SI shared-defaults: SMTPPassword resolved from KV name '$_smtpKvName' (internal automation, Anonymous=false)")
                    break
                }
            } catch {
                Write-Verbose ("SI shared-defaults: KV name '$_smtpKvName' not present -- trying next ($($_.Exception.Message))")
            }
        }
    }
}

# 2. Final fallback bridges from HighPriv_SMTP_* (fire only if still unset)
if (-not $global:SMTPUser     -and $global:HighPriv_SMTP_UserName) { $global:SMTPUser     = $global:HighPriv_SMTP_UserName }
if (-not $global:SMTPPassword -and $global:HighPriv_SMTP_Password) { $global:SMTPPassword = $global:HighPriv_SMTP_Password }
if (-not $global:SMTPFrom     -and $global:HighPriv_SMTP_From)     { $global:SMTPFrom     = $global:HighPriv_SMTP_From }

# 3. Log resolved values (length-only for password) so operators can verify at run start
Write-Host ("[shared-defaults] SMTP resolved: From={0} | User={1} | Password=[len={2}] | Anonymous={3} | Context={4}" -f `
    ($(if ($global:SMTPFrom) { $global:SMTPFrom } else { '<NULL>' })), `
    ($(if ($global:SMTPUser) { $global:SMTPUser } else { '<NULL>' })), `
    ($(if ($global:SMTPPassword) { ([string]$global:SMTPPassword).Length } else { 0 })), `
    ($(if ($null -ne $global:Mail_SendAnonymous) { $global:Mail_SendAnonymous } else { '<unset>' })), `
    ($(if ($global:Context) { 'present' } else { 'absent' })))
