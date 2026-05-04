#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for SecurityInsight asset-profiling Azure engine.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. The custom
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    LAYERED CONFIG MODEL  (each layer overrides the previous)

      1. LauncherConfig.defaults.ps1            <- per-engine baseline
                                                 (this folder; ships with release)
      2. config\SecurityInsight.custom.ps1 <- optional solution-wide overrides
                                                 (covers EVERY SI engine in one place)
      3. LauncherConfig.custom.ps1            <- THIS FILE (your copy; per-engine,
                                                 wins over solution-wide)
      4. CLI args on the launcher             <- last word per invocation.

    Most customers put auth + storage + workspace settings in the solution-wide
    config\SecurityInsight.custom.ps1 (so they only fill in once for all
    SI engines). Use THIS file for per-engine deviations only.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : AssetProfiling_Azure
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1.  AUTHENTICATION  -- REQUIRED. Uncomment ONE method block, fill in values.
#                       (Skip this section if you set auth in config\SecurityInsight.custom.ps1)
# ============================================================================

# ----- METHOD 1: Managed Identity (recommended for Azure VMs / Arc / Function) -
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'

# ----- METHOD 2: SPN + secret stored in Azure Key Vault ------------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'
# $global:SpnSecretName   = 'SecurityInsight-Secret'

# ----- METHOD 3: SPN + certificate (thumbprint in local cert store) ------------
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ----- METHOD 4: SPN + plaintext secret  *** TESTING ONLY *** ------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'


# ============================================================================
# 2.  STORAGE ACCOUNT  (used for shard coordination + fingerprint cache)
# ============================================================================
# Asset-profiling engines coordinate work across shards using an Azure Storage
# account (queues + tables + a staging container). Three ways to provide it:
#   1. CLI:    -StorageAccountName ... -StorageAccountKey ...   (per-run)
#   2. CLI:    -UseStorageOAuth                                  (per-run, AAD)
#   3. Globals here / in config:
# $global:SI_StorageAccount = '<storage-account-name>'
# $global:SI_StorageKey     = '<storage-account-key-base64>'


# ============================================================================
# 3.  ENGINE-SPECIFIC DEFAULTS  (override the locked baseline)
# ============================================================================
# Every value below has a default set in LauncherConfig.defaults.ps1. Uncomment
# only the lines you want to deviate from.

# Asset limit -- 0 means no limit. Smoke tests on production tenants MUST keep
# this at 0; sliced samples hide pagination, throttling, and rare-type bugs.
# $global:SI_AssetLimit_Azure = 0

# Sinks -- which destinations to write the engine's output to.
# $global:SI_Sinks_Azure = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit. Use after rule
# changes or schema updates.
# $global:SI_ForceFullRun_Azure = $false

# AI integration -- per-engine opt-in. AI default is OFF. Set to $true to enable
# GPT-4 Classify on this engine only. Tenant-wide opt-in lives in
# SecurityInsight.custom.ps1 as $global:SI_EnableAI = $true.
# $global:SI_EnableAI_azure = $true

# System prompt override for the Azure Classify call.
# $global:SI_SystemPrompt_azure = @'
# You are a security classifier...
# '@

# Activity / staleness window (days). Azure resources are flagged
# IsEnabledActive when EG.lastSeen is within this many days.
# $global:SI_ActiveStaleDays = 30

# Tier-driven cadence (hours between full re-runs per tier).
# $global:SI_TierCadence_T0 = 24
# $global:SI_TierCadence_T1 = 72
# $global:SI_TierCadence_T2 = 168
# $global:SI_TierCadence_T3 = 336


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (auth fallbacks, workspace IDs, DCR/DCE knobs), look at
# LauncherConfig.defaults.ps1 in this same folder OR config\SecurityInsight.custom.sample.ps1.
# Copy any line out of there into THIS file to override that single value.
