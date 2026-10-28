#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for SecurityInsight asset-profiling Identity engine.

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
    Engine                : AssetProfiling_Identity
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
# account (queues + tables + a staging container), reached only with the run's
# signed-in identity (Storage Blob/Table/Queue Data Contributor on the account).
# Name it on the CLI (-StorageAccountName ...) or here / in config:
# $global:SI_StorageAccount = '<storage-account-name>'


# ============================================================================
# 3.  ENGINE-SPECIFIC DEFAULTS  (override the locked baseline)
# ============================================================================
# Every value below has a default set in LauncherConfig.defaults.ps1. Uncomment
# only the lines you want to deviate from.

# Asset limit -- 0 means no limit. Smoke tests on production tenants MUST keep
# this at 0; sliced samples hide pagination, throttling, and rare-type bugs.
# $global:SI_AssetLimit_Identity = 0

# Sinks -- which destinations to write the engine's output to.
# $global:SI_Sinks_Identity = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit. Use after rule
# changes or schema updates.
# $global:SI_ForceFullRun_Identity = $false

# AI integration -- per-engine opt-in. AI default is OFF. Set to $true to enable
# GPT-4 Classify on this engine only. Tenant-wide opt-in lives in
# SecurityInsight.custom.ps1 as $global:SI_EnableAI = $true.
# $global:SI_EnableAI_identity = $true

# System prompt override for the Identity Classify call.
# $global:SI_SystemPrompt_identity = @'
# You are a security classifier...
# '@

# Activity / staleness window (days). Identities are flagged IsEnabledActive
# when they signed in within this many days.
# $global:SI_ActiveStaleDays = 30

# Tier-driven cadence -- how long an asset is skipped after it was processed. Applies ONLY with
# $global:SI_FingerprintCache_Enabled = $true (off by default: every run processes every asset) and
# never on a full run. A number is hours; '12h' / '3d' also work. The values below are the defaults.
# $global:SI_TierCadence_T0 = 12
# $global:SI_TierCadence_T1 = 24
# $global:SI_TierCadence_T2 = 72
# $global:SI_TierCadence_T3 = 168


# Subscriptions whose Azure role assignments the identity collection skips, by name (wildcards).
# $global:SI_AzureSubscriptionExcludePatterns = @('*Azure for Students*')

# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (auth fallbacks, workspace IDs, DCR/DCE knobs), look at
# LauncherConfig.defaults.ps1 in this same folder OR config\SecurityInsight.custom.sample.ps1.
# Copy any line out of there into THIS file to override that single value.
