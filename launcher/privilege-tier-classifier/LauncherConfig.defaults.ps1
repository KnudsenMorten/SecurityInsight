#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight privilege-tier-classifier engine.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then the layered config helper picks up SecurityInsight.custom.ps1
    (Layer 3 -- config) and LauncherConfig.custom.ps1 (Layer 5 -- this
    same folder, gitignored). CLI args win last.

      LayerOrder:  LauncherConfig.defaults.ps1 (this file)  ->
                   SecurityInsight.custom.ps1 (config, optional)  ->
                   LauncherConfig.custom.ps1 (this folder, gitignored, optional)  ->
                   CLI args

    The Tiering engine takes no engine-specific knobs (no Sinks, no AssetLimit,
    no ForceFullRun) -- it always rebuilds the full tier-definitions JSON on
    each run. So this locked config only carries optional defaults for AI
    behaviour and the output location.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : PrivilegeTierClassifier
#>

# Authentication mode is resolved by the launcher (community) or by
# Initialize-PlatformAutomationFramework (internal-vm). No defaults here.

# AI behaviour: when $true, engine runs all 4 AI categories. Set to $false in
# config\SecurityInsight.custom.ps1 if you want to short-circuit the AI
# call (engine will fall back to a static built-in tier map).
if ($null -eq $global:SI_PrivilegeTierClassifier_RunAI) { $global:SI_PrivilegeTierClassifier_RunAI = $true }

# OpenAI API version default. Engine reads this to build the chat-completions
# URL. Setup-SecurityInsight's OpenAI phase will overwrite if it provisioned
# the AOAI deployment; this default protects ad-hoc classifier runs that
# never touched Setup. Carried over from v2.1 Build_Tier_Definitions defaults.
if (-not $global:OpenAI_ApiVersion) { $global:OpenAI_ApiVersion = '2024-08-01-preview' }
