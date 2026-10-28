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

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../engine/_shared/SI-AzRest.ps1') }

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

# --- Mail ---
# Your own SMTP relay kept by choice: the Pro web app then stops suggesting the move to an Office 365 shared mailbox.
# Mail is sent the same way either way.
$global:SI_Mail_SmtpKept = $false

# --- Copy findings per CI to Log Analytics (SI_Finding_CL) -- optional, OFF by default ---
# After each Risk Analysis Detailed run, copies the de-duplicated findings (one row per CI and finding) into the Log
# Analytics workspace, for your own workbooks, Sentinel or KQL. SecurityInsight itself does not need it: its pages read the
# findings from its database. On a large estate the copy can take hours and adds ingestion cost. Not the report rows
# (SendToLogAnalytics -> SI_RiskAnalysis_Detailed_CL: their own optional output, off by default -- #830). Read by Risk Analysis and the data sync
# (engine\risk-analysis\_shared\RA-Findings.ps1, Test-SIFindingsCopyOn): on only for $true / 'on'.
$global:SI_RA_Findings = $false

# --- Disabled accounts and devices: one setting per stage ---
# A disabled user, service principal / managed identity or computer = its account is disabled in its own directory
# (Entra accountEnabled = false, AD userAccountControl disabled), never inferred from inactivity. The state is read
# on every run, so an account that is enabled again is included again everywhere. A stage that leaves disabled
# assets out says how many in its log, and their open findings, actions and tickets are kept as they are (never
# resolved or closed) until the account is enabled again. Read by engine\_shared\SI-DisabledAssets.ps1.
$global:SI_DisabledAssets_Collect      = $true    # collected from the sources
$global:SI_DisabledAssets_Correlate    = $true    # take part in CI correlation (needs collection)
$global:SI_DisabledAssets_RiskAnalysis = $false   # reach the Risk Analysis reports (needs collection)
$global:SI_DisabledAssets_StateActions = $false   # finding / vulnerability lifecycle, close-loop, ticket open and close (needs collection)
$global:SI_DisabledAssets_Connectors   = $false   # sent out by connectors and exports (needs collection)

# --- CI build ---
# Every CI is rebuilt in full at least this often (days); the runs between build only the CIs whose input changed.
# 0 = a full build every run. Read by engine\data-model\SI-CiBuildSql.ps1 (Get-SICiFullReconcileDecision).
$global:SI_CiBuild_FullReconcileDays  = 7
# One asset never holds the CI build: the seconds the rules of ONE asset may take. An asset that takes longer is not fully
# evaluated in that run -- nothing of the half evaluation is stored: it keeps what it had from its last complete evaluation
# (a new asset is left out), is named in the run log and is evaluated again in the next run. 0 = no limit.
# Read by engine\data-model\SI-CiEnrich.ps1 (Get-SICiRulesBudgetSeconds).
$global:SI_CiRulesBudgetSeconds       = 60

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
# platform sign-in sets $global:HighPriv_Modern_* + $global:AzureTenantId.
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
        $global:SI_SPN_ObjectId = (Get-SIAzADServicePrincipal -ApplicationId $global:SI_SPN_AppId -ErrorAction Stop).Id
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
# v2.2.384 -- gate flipped from `-eq $false` to `-ne $true`. The previous gate
# only fired when SOMETHING upstream (Layer 1b or earlier) had explicitly set
# $global:Mail_SendAnonymous = $false. Most launchers set it via Layer 4
# (LauncherConfig.defaults), which runs AFTER this Layer 2 file -- so at gate
# evaluation time the variable was still $null, and `$null -eq $false` evaluates
# to $false in PowerShell, so the KV pull silently no-op'd. The new condition
# fires whenever Context is present UNLESS the customer has explicitly opted
# in to anonymous SMTP via $global:Mail_SendAnonymous = $true (which still
# correctly bypasses KV credential resolution).
if ($global:Context -and ($global:Mail_SendAnonymous -ne $true)) {
    # the platform Key Vault is read natively (auth\SI-PlatformConnect.ps1, plain REST -- no PowerShell module)
    if (-not (Get-Command -Name Get-SIPlatformSecret -ErrorAction SilentlyContinue)) {
        $_siPlatformConnect = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'auth', 'SI-PlatformConnect.ps1')
        if (Test-Path -LiteralPath $_siPlatformConnect) { . $_siPlatformConnect }
    }
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
                $_val = Get-SIPlatformSecret -Context $global:Context -Name $_smtpKvName -AsPlainText -ErrorAction Stop
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
                $_val = Get-SIPlatformSecret -Context $global:Context -Name $_smtpKvName -AsPlainText -ErrorAction Stop
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
