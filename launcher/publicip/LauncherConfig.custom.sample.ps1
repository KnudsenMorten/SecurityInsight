#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for SecurityInsight asset-profiling PublicIp engine.

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
    Engine                : AssetProfiling_PublicIp
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
# $global:SI_AssetLimit_PublicIp = 0

# Sinks -- which destinations to write the engine's output to.
# $global:SI_Sinks_PublicIp = @('LA','JSON','Excel')

# Force-full-run -- skip the fingerprint cadence short-circuit. Use after rule
# changes or schema updates.
# $global:SI_ForceFullRun_PublicIp = $false

# AI integration -- per-engine opt-in. AI default is OFF. Set to $true to enable
# GPT-4 Classify on this engine only. Tenant-wide opt-in lives in
# SecurityInsight.custom.ps1 as $global:SI_EnableAI = $true.
# $global:SI_EnableAI_publicip = $true

# System prompt override for the PublicIp Classify call.
# $global:SI_SystemPrompt_publicip = @'
# You are a security classifier...
# '@

# Shodan API key (REQUIRED for Shodan-source columns to populate; engine still
# runs without it but those fields will be null). Note the unprefixed name --
# matches the v1 contract and the auth/Get-SIShodanKey.ps1 helper.
# $global:SHODAN_ApiKey = '<your-shodan-api-key>'

# Shodan cache age -- reuse a host's cached Shodan JSON when its age is within
# this window. Lower = fresher data, higher credit burn. Default 7 days.
# $global:SI_ShodanCacheAgeDays = 7

# Shodan monthly credit cap -- soft ceiling on live API calls per rolling
# month. Default 4000 (typical Small Business plan).
# $global:SI_ShodanMonthlyCreditCap = 4000

# Activity / staleness window (days). Public IPs are flagged IsEnabledActive
# when bound to an active Azure resource OR Shodan returned data within this window.
# $global:SI_ActiveStaleDays = 30

# Tier-driven cadence (hours between full re-runs per tier).
# $global:SI_TierCadence_T0 = 24
# $global:SI_TierCadence_T1 = 72
# $global:SI_TierCadence_T2 = 168
# $global:SI_TierCadence_T3 = 336

# ----- Extra IPs (manual list) -----
# Add public IPs that aren't in SI_Endpoint_Profile_CL or SI_Azure_Profile_CL --
# physical firewalls, branch-office gateways, partner endpoints, etc. Each entry
# is scanned by Shodan alongside the auto-discovered IPs and lands in
# SI_VulnerabilityPIP_CL with AssetEngine='extra'. Required: IpAddress, AssetName.
# Optional: Tier (default 99), cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity.
# Duplicates of auto-discovered IPs are silently ignored.
# $global:SI_Shodan_ExtraIPs = @(
#     @{ IpAddress = '203.0.113.10'; AssetName = 'HQ CheckPoint FW';      Tier = 0; cmdbId = 'CMDB-FW-001'; cmdbName = 'HQ Perimeter Firewall'; cmdbCriticality = 'Critical'; cmdbDataSensitivity = 'Restricted' }
#     @{ IpAddress = '203.0.113.11'; AssetName = 'HQ CheckPoint FW (HA)'; Tier = 0; cmdbId = 'CMDB-FW-002'; cmdbName = 'HQ Perimeter Firewall'; cmdbCriticality = 'Critical'; cmdbDataSensitivity = 'Restricted' }
#     @{ IpAddress = '198.51.100.5'; AssetName = 'Branch-Aarhus FortiGate'; Tier = 1; cmdbId = 'CMDB-FW-010'; cmdbName = 'Branch FW';            cmdbCriticality = 'High';     cmdbDataSensitivity = 'Confidential' }
# )


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface (auth fallbacks, workspace IDs, DCR/DCE knobs), look at
# LauncherConfig.defaults.ps1 in this same folder OR config\SecurityInsight.custom.sample.ps1.
# Copy any line out of there into THIS file to override that single value.
