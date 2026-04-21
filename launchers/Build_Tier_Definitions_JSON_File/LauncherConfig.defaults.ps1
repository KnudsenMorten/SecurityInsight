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
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  AZURE OPENAI  -- REQUIRED. Customer sets these in CUSTOMDATA\SecurityInsight.custom.ps1
#                              (solution-wide) OR LauncherConfig.custom.ps1 (per-engine).
# ============================================================================
# The engine builds the chat-completions URI as:
#   <Endpoint>/openai/deployments/<Deployment>/chat/completions?api-version=<ApiVersion>
# No sensible default exists -- engine fails fast if any are blank.
#
# DO NOT assign these to $null here. Unconditionally setting them would clobber
# whatever the customer set in Layer 3 (SecurityInsight.custom.ps1) since this
# defaults file is Layer 4. Left unassigned they default to $null anyway.
#
# Expected globals:
#   $global:OpenAI_Endpoint     # 'https://<your-aoai-account>.openai.azure.com'
#   $global:OpenAI_Deployment   # e.g. 'gpt-4o-mini'
#   $global:OpenAI_ApiKey       # the AOAI API key
#
# Only the API version has a safe engine default:
if (-not $global:OpenAI_ApiVersion) { $global:OpenAI_ApiVersion = '2024-08-01-preview' }


# ============================================================================
#  AI TUNING  (rarely changed)
# ============================================================================
# Items per AI request. Reduce if hitting token / context limits on the
# Entra-roles or API-permission catalog (a single chunk too big for the model).
# Conditional assignment so customer values in Layer 3 / 5 survive (see note above).
if (-not (Test-Path variable:global:AI_ChunkSize)) { $global:AI_ChunkSize = 50 }

# Per-response token cap (mirrors the OpenAI 'max_tokens' field).
if (-not (Test-Path variable:global:AI_MaxTokens)) { $global:AI_MaxTokens = 16384 }

# Retry attempts per chunk on transient failures (HTTP 429, 5xx, transient
# socket errors). 3 is a reasonable starting point.
if (-not (Test-Path variable:global:AI_MaxRetries)) { $global:AI_MaxRetries = 3 }
