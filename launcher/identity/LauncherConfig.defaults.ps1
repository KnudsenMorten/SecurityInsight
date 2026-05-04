#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for SecurityInsight asset-profiling Identity engine.

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
    LauncherConfig.custom.ps1 simply re-assigns the global below it. New
    globals introduced in future releases land here automatically with our
    defaults; the customer only touches their own file when they want to
    deviate.

    Every $global:SI_* the engine reads in CLI / VM mode lives here. Container-
    mode env-var overrides ($env:SI_*) come in via Bootstrap-ContainerAppJob.ps1
    and are not set here.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : AssetProfiling_Identity
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  CORE RUN KNOBS  (per-run, but with sensible defaults)
# ============================================================================

# Asset limit -- 0 means no limit (process all discovered assets).
# Customer-side override: set $global:SI_AssetLimit_Identity in custom.ps1.
# Smoke tests on production tenants MUST keep this at 0; sliced samples hide
# scale-only bugs (pagination, throttling, large-array serialization, rare-type
# schema drift). Use only for local dev with mock data.
$global:SI_AssetLimit_Identity = 0

# Sinks -- which destinations to write the engine's output to.
# Allowed entries: 'LA' (Log Analytics), 'JSON', 'Excel'.
$global:SI_Sinks_Identity = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit; re-process every
# asset. Use after rule changes or schema updates. Default $false (cadence wins).
$global:SI_ForceFullRun_Identity = $false


# ============================================================================
#  IDENTITY-SPECIFIC KNOBS
# ============================================================================
# (engine reads $global:SI_* directly; values shown here are documented
#  defaults. Override in custom.ps1 to change behaviour.)

# AI integration -- per-engine opt-in. Tenant-wide $global:SI_EnableAI also
# turns it on for ALL engines; this per-engine flag is the targeted opt-in.
# Force-off: $global:SI_DisableAI_identity = $true.
$global:SI_EnableAI_identity = $false

# AI cost ceiling -- estimated USD per Classify call (used by cost-budget
# guardrail in Invoke-Classify). 0 disables the budget check. Tune after
# observing real GPT-4 invoice line items for your tenant.
# (Shared across all engines; lives in solution-wide custom.ps1 normally.)
$global:SI_AI_CostPerCallEstimate = 0.01

# System prompt override for the Identity AI Classify call. $null = ship default
# from engine/asset-profiling/stages/Invoke-Classify.ps1. Set to a multi-line
# string in custom.ps1 to override. Only takes effect when AI is enabled above.
$global:SI_SystemPrompt_identity = $null


# ============================================================================
#  ACTIVITY / STALENESS  (cross-engine, but identity is the most affected)
# ============================================================================
# Identities (users + SPs) are flagged IsEnabledActive=$true when they signed
# in within $global:SI_ActiveStaleDays. Default 30. Lower for tighter hygiene
# views; higher for slower-cadence environments.
$global:SI_ActiveStaleDays = 30


# ============================================================================
#  CADENCE  (tier -> hours between full re-runs)
# ============================================================================
# Tier-driven cadence (Invoke-Schedule). T0/T1/T2/T3 hours. The defaults are
# baked into the engine; override per-tier via:
#   $global:SI_TierCadence_T0 = 24    # rerun T0 assets every 24h
#   $global:SI_TierCadence_T1 = 72
#   $global:SI_TierCadence_T2 = 168
#   $global:SI_TierCadence_T3 = 336


# ============================================================================
#  RUNTIME FLAGS  (overridable via launcher CLI)
# ============================================================================
$global:WhatIfMode = $false
