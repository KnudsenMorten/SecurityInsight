#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for Build_Tier_Definitions_JSON_File.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. Customer
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    LAYERED CONFIG MODEL

      1. LauncherConfig.defaults.ps1   <- ships with each release; baseline.
      2. LauncherConfig.custom.ps1     <- THIS FILE (your copy). Set ONLY the
                                          values you actually need to override.
      3. CLI args on the launcher      <- last word for that one invocation.

    You need TWO sections at minimum: AUTH (1) and AZURE OPENAI (2).
    Everything else has a default in LauncherConfig.defaults.ps1.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Build_Tier_Definitions_JSON_File
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1.  AUTHENTICATION  -- REQUIRED. Uncomment ONE method block, fill in values.
# ============================================================================

# ----- METHOD 1: Managed Identity ---------------------------------------------
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'

# ----- METHOD 2: SPN + secret stored in Azure Key Vault -----------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'
# $global:SpnSecretName   = 'SecurityInsight-Secret'

# ----- METHOD 3: SPN + certificate (thumbprint in local cert store) -----------
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ----- METHOD 4: SPN + plaintext secret  *** TESTING ONLY *** -----------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'


# ============================================================================
# 2.  AZURE OPENAI  -- REQUIRED. The engine uses AI to assign tier values.
# ============================================================================
$global:OpenAI_Endpoint   = 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_Deployment = 'gpt-4o-mini'
$global:OpenAI_ApiKey     = '<your-azure-openai-key>'
# $global:OpenAI_ApiVersion = '2024-08-01-preview'   # default in defaults.ps1


# ============================================================================
# 3.  AI TUNING  (uncomment only if you need to deviate from defaults)
# ============================================================================
# Items per AI request. Reduce if hitting token / context limits.
# $global:AI_ChunkSize  = 50

# Per-response token cap (OpenAI max_tokens).
# $global:AI_MaxTokens  = 16384

# Retry attempts per chunk on transient failures.
# $global:AI_MaxRetries = 3


# ============================================================================
#  EVERYTHING ELSE
# ============================================================================
# For the full surface look at LauncherConfig.defaults.ps1 in this same folder.
# Copy any line out of there into THIS file to override that single value.
