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

# No AI step for public IPs (Test-SIAIEnabled refuses the engine; an SI_EnableAI_publicip set in a
# config is ignored with one warning, and the tenant-wide SI_EnableAI does not apply here).

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

# ----------------------------------------------------------------------------
# TABLE / DCR NAME  --  ONE NAMING RULE FOR ALL FOUR PROFILE ENGINES
# ----------------------------------------------------------------------------
# publicip is a profile engine like the other three, so it publishes a profile
# table named like the other three:
#
#     SI_Endpoint_Profile_CL     SI_Identity_Profile_CL
#     SI_Azure_Profile_CL        SI_PublicIP_Profile_CL   <-- this engine
#
# HISTORY, so nobody restores the old name believing it was load-bearing: the
# standalone Invoke-PublicIpScanner.ps1 era hardcoded `SI_VulnerabilityPIP_CL`,
# and v2.2.349 carried that forward as a legacy override to preserve existing
# ingest history. That exception is REMOVED (operator ruling): it broke the one
# rule the other three keep, and consistency across the four profile tables
# matters more than continuity with the retired scanner. Every RA query, the
# correlation table map, the SIA table constants and the schema moved to the new
# name in the SAME change -- a table rename is only safe as one atomic edit.
#
# The name is set EXPLICITLY rather than left to the `SI_{0}_Profile` pattern,
# because the pattern title-cases the engine key and yields `SI_Publicip_Profile`
# -- lowercase `ip` -- which is not the name the rest of the product declares.
#
# WARNING: Log Analytics table names are CASE-SENSITIVE in KQL, and a custom
# table cannot be renamed once its DCR has created it. Change these two values
# only together, and only deliberately.
$global:SI_PublicIp_TableName = 'SI_PublicIP_Profile'    # module appends _CL on ingest
$global:SI_PublicIp_DcrName   = 'dcr-si-publicip-profile'


# ============================================================================
#  DISCOVERY SOURCE  (v2.2.348 -- pipeline-folded engine)
# ============================================================================
# How to find IPs to scan. Three modes:
#   'profile-cl' (DEFAULT) -- Tier 0-N servers from SI_Endpoint_Profile_CL +
#                              SI_Azure_Profile_CL + customer extras. Preserves
#                              the legacy "scan only IPs attached to assets we
#                              already classified" behaviour. Recommended.
#   'arg-eg'              -- ARG publicIPAddresses + EG NodeLabel + extras.
#                              Broader coverage; no per-IP tier or cmdb context.
#   'union'               -- All sources merged. Maximum coverage; Profile_CL
#                              metadata wins on same-IP collisions.
$global:SI_PublicIP_DiscoverySource = 'profile-cl'

# Tier cap for Profile_CL discovery. Only assets with Tier <= this value are
# considered. Default 3 = include Tier 0/1/2/3 (everything classified).
# Set to 1 if you only want Tier 0 (Critical) + Tier 1 (High) servers.
$global:SI_Shodan_TierMax = 3

# Server-only filter for Profile_CL discovery from SI_Endpoint_Profile_CL.
# Workstation PublicIp = user's home/cafe/cellular ISP NAT, not a scannable
# asset the customer owns. Default $true.
$global:SI_Shodan_ServerOnly = $true

# Lookback window for Profile_CL discovery (days). Latest snapshot per
# PrimaryEntityId within this window is used. Default 8 days.
$global:SI_Shodan_LookbackDays = 8


# ============================================================================
#  SHODAN RATE-LIMIT + TIMEOUT
# ============================================================================
# Throttle between per-IP /host calls (ms). Shodan free tier rate-limits at
# 1 call/sec; 1100ms gives a small safety margin. Cache hits skip the throttle.
$global:SI_Shodan_ThrottleMs = 1100

# Per-call timeout (seconds) for both /host and /scan submissions.
$global:SI_Shodan_TimeoutSec = 15


# ============================================================================
#  FRESH-SCAN FLOW  (POST /shodan/scan -> wait/defer state machine)
# ============================================================================
# Set ForceFreshScan = $true and schedule the launcher to run at 02:00 + 03:00
# (and optionally 04:00). First run submits + waits up to 5 min, persisting
# scan_id to data/shodan-pending-scans.json if it can't sync-complete. Later
# runs check pending state + a skip-if-recent guard
# (data/shodan-last-fresh-scan.json) so credits don't burn on duplicate submits.
# Defaults are OFF -- cache-only mode -- so passive enrichment doesn't burn
# scan credits. Turn ON in LauncherConfig.custom.ps1 when you want fresh data.
$global:SI_Shodan_ForceFreshScan         = $false
$global:SI_Shodan_ScanWaitMaxSec         = 300    # 5-min sync deadline per run
$global:SI_Shodan_ScanPollIntervalSec    = 30
$global:SI_Shodan_FreshScanIntervalHours = 20     # don't re-submit within this window


# ============================================================================
#  ACTIVITY / STALENESS
# ============================================================================
# Public IPs are flagged IsEnabledActive=$true when bound to an active Azure
# resource OR Shodan returned data within $global:SI_ActiveStaleDays. Default 30.
$global:SI_ActiveStaleDays = 30


# ============================================================================
#  CADENCE  (tier -> hours between full re-runs)
# ============================================================================
# Tier-driven cadence (Invoke-Schedule): how long an asset is skipped after it was processed.
# Applies ONLY with $global:SI_FingerprintCache_Enabled = $true (off by default -- then every run
# processes every asset) and never on a full run. A number is hours; '12h' / '3d' also work.
# Engine defaults (hours), override per tier via:
#   $global:SI_TierCadence_T0 = 12
#   $global:SI_TierCadence_T1 = 24
#   $global:SI_TierCadence_T2 = 72
#   $global:SI_TierCadence_T3 = 168


# ============================================================================
#  RUNTIME FLAGS  (overridable via launcher CLI)
# ============================================================================
$global:WhatIfMode = $false
