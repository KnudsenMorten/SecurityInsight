#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for Build_Tier_Definitions_JSON_File.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then dot-sources the customer's LauncherConfig.custom.ps1 (which overrides
    only the values they care about), then applies CLI args (last word).

    Customer never edits this file.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : Build_Tier_Definitions_JSON_File
    Developed by          : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

# ============================================================================
#  AZURE OPENAI  -- REQUIRED. Customer MUST set these in LauncherConfig.custom.ps1
# ============================================================================
# The engine builds the chat-completions URI as:
#   <Endpoint>/openai/deployments/<Deployment>/chat/completions?api-version=<ApiVersion>
# No sensible default exists -- engine fails fast if any are blank.
$global:OpenAI_Endpoint   = $null     # 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_Deployment = $null     # e.g. 'gpt-4o-mini'
$global:OpenAI_ApiKey     = $null     # the AOAI API key
$global:OpenAI_ApiVersion = '2024-08-01-preview'


# ============================================================================
#  AI TUNING  (rarely changed)
# ============================================================================
# Items per AI request. Reduce if hitting token / context limits on the
# Entra-roles or API-permission catalog (a single chunk too big for the model).
$global:AI_ChunkSize  = 50

# Per-response token cap (mirrors the OpenAI 'max_tokens' field).
$global:AI_MaxTokens  = 16384

# Retry attempts per chunk on transient failures (HTTP 429, 5xx, transient
# socket errors). 3 is a reasonable starting point.
$global:AI_MaxRetries = 3
