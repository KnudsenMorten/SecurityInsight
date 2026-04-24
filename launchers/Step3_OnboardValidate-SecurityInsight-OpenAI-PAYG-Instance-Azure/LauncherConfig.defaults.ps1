#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for Step3_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure.

.DESCRIPTION
    Shipped with each release. Loaded as Layer 4 by Initialize-LauncherConfig
    AFTER the customer's Layer 3 (SecurityInsight.custom.ps1) and BEFORE the
    customer's Layer 5 (LauncherConfig.custom.ps1).

    Every assignment uses the conditional pattern
        if (-not (Test-Path variable:global:Foo)) { $global:Foo = <default> }
    so customer values from Layer 3 / Layer 5 always win over what we ship here.
    The role of THIS file is to guarantee every $global:* the engine reads is
    DEFINED -- otherwise Set-StrictMode in the engine throws
    'VariableIsUndefined' the moment it touches an unset name.

    Customer never edits this file.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Step3_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  AZURE PLACEMENT  -- REQUIRED. Customer MUST set in LauncherConfig.custom.ps1
#                                or CUSTOMDATA\SecurityInsight.custom.ps1.
# ============================================================================
# No safe engine default exists for these three -- they're tenant-specific.
# Pre-declare to $null so Set-StrictMode in the engine doesn't throw on the
# first read; the engine has its own fail-fast that surfaces a clear error
# when these end up empty.
if (-not (Test-Path variable:global:SubscriptionId))    { $global:SubscriptionId    = $null }
if (-not (Test-Path variable:global:ResourceGroupName)) { $global:ResourceGroupName = $null }
if (-not (Test-Path variable:global:Location))          { $global:Location          = $null }


# ============================================================================
#  OPENAI ACCOUNT + DEPLOYMENT  -- REQUIRED. Customer MUST set.
# ============================================================================
if (-not (Test-Path variable:global:AccountName))    { $global:AccountName    = $null }
if (-not (Test-Path variable:global:DeploymentName)) { $global:DeploymentName = $null }


# ============================================================================
#  MODEL TUNING  (safe defaults; engine auto-falls-back if model unavailable)
# ============================================================================
# Engine code uses 'if ($global:ModelName) { ... } else { 'gpt-4.1-mini' }'
# pattern, so these defaults are double-protected. Pre-declare here so
# Set-StrictMode doesn't trip the read.
if (-not (Test-Path variable:global:ModelName))    { $global:ModelName    = 'gpt-4.1-mini' }
if (-not (Test-Path variable:global:ModelVersion)) { $global:ModelVersion = 'latest' }


# ============================================================================
#  CAPACITY + NETWORK ACCESS  (safe defaults)
# ============================================================================
if (-not (Test-Path variable:global:Capacity))            { $global:Capacity            = 100 }       # TPM (thousands)
if (-not (Test-Path variable:global:PublicNetworkAccess)) { $global:PublicNetworkAccess = 'Enabled' } # 'Enabled' | 'Disabled'


# ============================================================================
#  DEPLOYMENT BEHAVIOUR  (safe defaults)
# ============================================================================
if (-not (Test-Path variable:global:WaitForAccountReady)) { $global:WaitForAccountReady = $true }
if (-not (Test-Path variable:global:DeploymentSkuOrder))  { $global:DeploymentSkuOrder  = @('GlobalStandard') }
if (-not (Test-Path variable:global:WriteModelDumps))     { $global:WriteModelDumps     = $true }
