#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight asset-profiling Endpoint engine.

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
    Engine                : AssetProfiling_Endpoint
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  CORE RUN KNOBS  (per-run, but with sensible defaults)
# ============================================================================

# Asset limit -- 0 means no limit. Smoke tests on production tenants MUST keep
# this at 0; sliced samples hide pagination, throttling, and rare-type bugs.
$global:SI_AssetLimit_Endpoint = 0

# Sinks -- which destinations to write the engine's output to.
# Allowed entries: 'LA' (Log Analytics), 'JSON', 'Excel'.
$global:SI_Sinks_Endpoint = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit. Use after rule
# changes or schema updates. Default $false (cadence wins).
$global:SI_ForceFullRun_Endpoint = $false


# ============================================================================
#  ENDPOINT-SPECIFIC KNOBS
# ============================================================================

# AI integration -- per-engine opt-in. Tenant-wide $global:SI_EnableAI also
# turns it on for ALL engines; this per-engine flag is the targeted opt-in.
$global:SI_EnableAI_endpoint = $false

# System prompt override for the Endpoint AI Classify call. $null = ship default
# from engine/asset-profiling/stages/Invoke-Classify.ps1.
$global:SI_SystemPrompt_endpoint = $null

# Defender workspace separation -- when MDE / DefenderXDR Advanced Hunting
# tables (DeviceInfo, IdentityLogonEvents) live in a DIFFERENT workspace than
# the SI output workspace (common in mature tenants), set
# $global:SI_DefenderWorkspaceResourceId in custom.ps1 to that workspace's
# /subscriptions/.../workspaces/<name> resource ID. $null = same workspace.
$global:SI_DefenderWorkspaceResourceId = $null


# ============================================================================
#  ACTIVITY / STALENESS
# ============================================================================
# Endpoints are flagged IsEnabledActive=$true when MDE_LastSeen or EG.lastSeen
# is within $global:SI_ActiveStaleDays. Default 30.
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
