#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for IdentityAssetsCollectDefineTierIngestLog.

.DESCRIPTION
    Shipped with each release. The launcher dot-sources this file FIRST,
    then dot-sources the customer's LauncherConfig.ps1 (which overrides
    only the values they care about), then applies CLI args (last word).

    Customer never edits this file.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : IdentityAssetsCollectDefineTierIngestLog
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
#  DCR INGESTION TARGETS
# ============================================================================
# The four shared infrastructure values ($global:WorkspaceName,
# $global:WorkspaceResourceGroup, $global:DceName, $global:DceResourceGroup,
# $global:DcrResourceGroup, $global:Location) are set by LAYER 0 --
# SecurityInsight.shared-defaults.ps1 in _lib -- so every SI engine uses the
# same canonical layout by default. To override: edit
# SOLUTIONS/SecurityInsight/CUSTOMDATA/SecurityInsight.custom.ps1
# (solution-wide) or LauncherConfig.custom.ps1 (this launcher only).
#
# Only engine-specific values belong in this file.
if (-not (Test-Path variable:global:WorkspaceResourceId)) { $global:WorkspaceResourceId = $null }                       # overrides WorkspaceName when set (cross-sub supported)
if (-not (Test-Path variable:global:DceIngestionUri)) { $global:DceIngestionUri = $null }                       # auto-resolved from DceName via Get-AzDceListAll

# DCR name + table name are engine-specific (SI_IdentityAssets schema)
if (-not (Test-Path variable:global:DcrName)) { $global:DcrName = 'dcr-si-identity-assets' }
if (-not (Test-Path variable:global:TableName)) { $global:TableName = 'SI_IdentityAssets' }


# ============================================================================
#  CROSS-WORKSPACE  (Defender / Sentinel IdentityInfo lookups)
# ============================================================================
# Leave $null to use $global:WorkspaceResourceId for both the SI ingestion
# and the IdentityInfo reads. Set this only when IdentityInfo lives in a
# different workspace -- the engine then issues cross-workspace KQL.
# Canonical name is $global:Defender_WorkspaceNameResourceId; the engine also
# accepts the legacy $global:DefenderWorkspaceResourceId and
# $global:SecurityInsight_Defender_WorkspaceResourceId.
if (-not (Test-Path variable:global:Defender_WorkspaceNameResourceId)) { $global:Defender_WorkspaceNameResourceId = $null }


# ============================================================================
#  EXPORT OUTPUT  (JSON sibling + optional upload)
# ============================================================================
# The engine already streams every collected record to
#   OUTPUT\IdentityAssets_Collection.jsonl
# during collection. When WriteJsonOutput is $true (default), a standard JSON
# array sibling (.json) is written next to the .jsonl. When ExportDestination
# is set, both files are uploaded to the destination.
#
# Destination type is AUTO-DETECTED from the value's prefix:
#   '\\server\share\path\'                              -> UNC share
#   'https://<acct>.blob.core.windows.net/<container>/' -> Azure Storage blob
if (-not (Test-Path variable:global:WriteJsonOutput)) { $global:WriteJsonOutput = $true }
if (-not (Test-Path variable:global:ExportDestination)) { $global:ExportDestination = $null }


# ============================================================================
#  CUSTOM SECURITY ATTRIBUTES + INGESTION TUNING
# ============================================================================
if (-not (Test-Path variable:global:CsaAttributeSet)) { $global:CsaAttributeSet = 'SecurityInsight' }
if (-not (Test-Path variable:global:BatchSize)) { $global:BatchSize = 300 }


# ============================================================================
#  AZURE SUBSCRIPTION SCOPE
# ============================================================================
# Wildcard patterns of subscription NAMES to skip during the Azure-side
# enumeration (Get-AzSubscription). Patterns are PowerShell -like wildcards.
# Empty / unset = scan all enabled subs.
if (-not (Test-Path variable:global:SubscriptionNameExcludePatterns)) { $global:SubscriptionNameExcludePatterns = @() }


# ============================================================================
#  TENANT INFO
# ============================================================================
# Tenant primary domain (used in some output column values; engine falls back
# to the authenticating SPN's tenant if not set)
if (-not (Test-Path variable:global:TenantDomain)) { $global:TenantDomain = $null }


# ============================================================================
#  TROUBLESHOOTING / WHATIF
# ============================================================================
if (-not (Test-Path variable:global:TroubleshootingMode)) { $global:TroubleshootingMode = $false }      # $true = process only first 10 rows
if (-not (Test-Path variable:global:WhatIfMode)) { $global:WhatIfMode = $false }      # $true = dry run, no DCR ingestion
if (-not (Test-Path variable:global:SuppressErrors)) { $global:SuppressErrors = $false }
if (-not (Test-Path variable:global:SuppressWarnings)) { $global:SuppressWarnings = $false }
