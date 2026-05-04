#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight asset-profiling Azure engine.

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
    Engine                : AssetProfiling_Azure
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  CORE RUN KNOBS  (per-run, but with sensible defaults)
# ============================================================================

# Asset limit -- 0 means no limit. Smoke tests on production tenants MUST keep
# this at 0; sliced samples hide pagination, throttling, and rare-type bugs.
$global:SI_AssetLimit_Azure = 0

# Sinks -- which destinations to write the engine's output to.
# Allowed entries: 'LA' (Log Analytics), 'JSON', 'Excel'.
$global:SI_Sinks_Azure = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit. Use after rule
# changes or schema updates. Default $false (cadence wins).
$global:SI_ForceFullRun_Azure = $false


# ============================================================================
#  AZURE-SPECIFIC KNOBS
# ============================================================================

# AI integration -- per-engine opt-in. Tenant-wide $global:SI_EnableAI also
# turns it on for ALL engines; this per-engine flag is the targeted opt-in.
$global:SI_EnableAI_azure = $false

# System prompt override for the Azure AI Classify call. $null = ship default
# from engine/asset-profiling/stages/Invoke-Classify.ps1.
$global:SI_SystemPrompt_azure = $null

# Discovery mode -- made Exposure Graph the source-of-truth. The
# engine has no separate $global:SI_DiscoveryMode_azure switch yet; the
# constant is hardcoded to 'EG-as-source'. Customer customisation lives in:
#   - asset-profiling-providers/_manifest.schema.locked.json (provider order)
#   - asset-profiling-schema/azure.schema.locked.json (per-source field map)
# This stub is here for forward-compat; the engine will read it once exposed.
# $global:SI_DiscoveryMode_azure = 'EG'


# ============================================================================
#  ACTIVITY / STALENESS
# ============================================================================
# Azure resources are flagged IsEnabledActive=$true when EG.lastSeen is within
# $global:SI_ActiveStaleDays. Default 30. Static existence in ARG (without an
# EG.lastSeen) also marks active -- so this knob is mostly harmless for Azure
# but is read for symmetry with the other engines.
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
