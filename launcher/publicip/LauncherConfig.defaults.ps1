#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight asset-profiling PublicIP engine.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then the layered config helper picks up SecurityInsight.custom.ps1
    (Layer 3 -- config) and LauncherConfig.custom.ps1 (Layer 5 -- this
    same folder, gitignored). CLI args win last.

      LayerOrder:  LauncherConfig.defaults.ps1 (this file)  ->
                   SecurityInsight.custom.ps1 (config, optional)  ->
                   LauncherConfig.custom.ps1 (this folder, gitignored, optional)  ->
                   CLI args

    Customer never edits this file. Anything they set in their own
    LauncherConfig.custom.ps1 simply re-assigns the global below it.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : AssetProfiling_PublicIp
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  CORE RUN KNOBS  (per-run, but with sensible defaults)
# ============================================================================

# Asset limit -- 0 means no limit. Smoke tests on production tenants MUST keep
# this at 0; sliced samples hide pagination, throttling, and rare-type bugs.
$global:SI_AssetLimit_PublicIp = 0

# Sinks -- which destinations to write the engine's output to.
# Allowed entries: 'LA' (Log Analytics), 'JSON', 'Excel'.
$global:SI_Sinks_PublicIp = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit. Use after rule
# changes or schema updates. Default $false (cadence wins).
$global:SI_ForceFullRun_PublicIp = $false


# ============================================================================
#  PUBLICIP-SPECIFIC KNOBS  (Shodan integration)
# ============================================================================

# AI integration -- per-engine opt-in. Tenant-wide $global:SI_EnableAI also
# turns it on for ALL engines; this per-engine flag is the targeted opt-in.
$global:SI_EnableAI_publicip = $false

# Shodan API key -- REQUIRED, engine throws at startup if not set. Set in
# config/SecurityInsight.custom.ps1 (preferred -- one place, all engines see
# it) or this LauncherConfig.custom.ps1:
#   $global:SI_Shodan_ApiKey = '<your-shodan-api-key>'
# Legacy unprefixed $global:SHODAN_ApiKey is still accepted as a fallback.

# Shodan cache age -- a host's cached Shodan JSON is reused if its age is
# within this window. Reduces credit burn for stable IPs.
$global:SI_ShodanCacheAgeDays = 7

# Shodan monthly credit cap -- soft ceiling. The engine refuses new live calls
# when the rolling-month counter exceeds this. Default 4000 (matches a typical
# Small Business plan). Bump or lower based on your subscription tier.
$global:SI_ShodanMonthlyCreditCap = 4000


# ============================================================================
#  ACTIVITY / STALENESS
# ============================================================================
# Public IPs are flagged IsEnabledActive=$true when bound to an active Azure
# resource OR Shodan returned data within $global:SI_ActiveStaleDays. Default 30.
$global:SI_ActiveStaleDays = 30


# ============================================================================
#  CADENCE  (tier -> hours between full re-runs)
# ============================================================================
# Tier-driven cadence (Invoke-Schedule). Override per-tier via:
#   $global:SI_TierCadence_T0 = 24
#   $global:SI_TierCadence_T1 = 72
#   $global:SI_TierCadence_T2 = 168
#   $global:SI_TierCadence_T3 = 336


# ============================================================================
#  RUNTIME FLAGS  (overridable via launcher CLI)
# ============================================================================
$global:WhatIfMode = $false
