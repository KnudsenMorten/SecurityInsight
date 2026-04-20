#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for Step4_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure.

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder and fill in
    the values. The custom file is gitignored so the populated copy stays on
    your machine and is never overwritten by a release upgrade.

    Step3 creates (or validates) an Azure OpenAI pay-as-you-go account + a model
    deployment so SecurityInsight_RiskAnalysis -BuildSummaryByAI works. All
    operations are idempotent. Re-run any time with -ValidateOnly for a drift
    check (non-zero exit code if any resource is missing).

    ABSOLUTE MINIMUM to run this step successfully (see section 5 for the full
    copy-paste block):
      - Auth block (one of sections 1-4)
      - SubscriptionId, ResourceGroupName, Location, AccountName, DeploymentName

.NOTES
    Solution       : SecurityInsight
    Engine         : Step4_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>

# ================================================================================
# 1.  AUTHENTICATION  -- pick ONE method block, uncomment, fill in values
# ================================================================================

# ----- METHOD 1: Managed Identity (recommended for Azure VMs / Function Apps) --
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'

# ----- METHOD 2: SPN + secret stored in Azure Key Vault -------------------------
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


# ================================================================================
# 2.  AZURE PLACEMENT -- REQUIRED. Where Step3 creates (or finds) the resources.
# ================================================================================
# $global:SubscriptionId     = '<your-target-subscription-id-guid>'
# $global:ResourceGroupName  = 'rg-securityinsight-openai'      # any name; created if missing
# $global:Location           = 'swedencentral'                  # any region where Azure OpenAI is available


# ================================================================================
# 3.  OPENAI ACCOUNT + DEPLOYMENT -- REQUIRED
# ================================================================================
# AccountName must be globally unique (DNS label for *.openai.azure.com)
# $global:AccountName        = 'oai-securityinsight-<unique-suffix>'
# DeploymentName is the logical name for the model deployment (you pass this
# as $global:OpenAI_deployment in the RiskAnalysis launcher config)
# $global:DeploymentName     = 'gpt-4o-mini'


# ================================================================================
# 4.  OPTIONAL TUNING (leave commented to accept safe defaults)
# ================================================================================
# Model preference -- if unset, the engine auto-selects the best available
# model in the region (typically gpt-4.1-mini, with fallback to gpt-4, gpt-35-turbo)
# $global:ModelName          = 'gpt-4.1-mini'
# $global:ModelVersion       = 'latest'
# $global:Capacity           = 100               # TPM capacity (thousands)
# $global:PublicNetworkAccess = 'Enabled'        # or 'Disabled' for private access only
# $global:DeploymentSkuOrder = @('GlobalStandard')  # try these deployment SKUs in order


# ================================================================================
# 5.  MINIMUM COPY-PASTE EXAMPLE -- community mode, bare minimum to provision
# ================================================================================
# Uncomment this whole block, replace the four '<your-*>' placeholders, save as
# LauncherConfig.custom.ps1, and run:
#   .\launcher.community-vm.template.ps1
# Re-run with -ValidateOnly any time to check the deployment is still healthy.

<#
# --- Auth: SPN + plaintext secret (TESTING ONLY; use Method 1-3 in production) ---
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'

# --- Azure placement ---
$global:SubscriptionId     = '<your-target-subscription-id-guid>'
$global:ResourceGroupName  = 'rg-securityinsight-openai'
$global:Location           = 'swedencentral'

# --- Account + deployment ---
$global:AccountName        = 'oai-securityinsight-<unique-suffix>'
$global:DeploymentName     = 'gpt-4o-mini'
#>
