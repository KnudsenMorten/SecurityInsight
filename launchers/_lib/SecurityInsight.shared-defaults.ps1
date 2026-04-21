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
      edit SOLUTIONS/SecurityInsight/CUSTOMDATA/SecurityInsight.custom.ps1

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

# --- Subscription ---
# INTERNAL (AF) mode: the platform-defaults.ps1 layer sets
# $global:MainLogAnalyticsWorkspaceSubId; Initialize-LauncherConfig derives
# $global:SubscriptionId from it after all layers load (see the "derived
# defaults" step at the bottom of Initialize-LauncherConfig.ps1), so this
# eager assignment below is just a safety hint -- it's a no-op at Layer 0.
# COMMUNITY mode: customer sets $global:SubscriptionId directly in LauncherConfig.custom.ps1.
$global:SubscriptionId         = $global:MainLogAnalyticsWorkspaceSubId
