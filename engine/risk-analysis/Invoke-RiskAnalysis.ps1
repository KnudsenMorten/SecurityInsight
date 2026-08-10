<#
.SYNOPSIS
    SecurityInsight_RiskAnalysis - engine script in the SecurityInsight solution.

.NOTES
    Solution       : SecurityInsight
    File           : Invoke-RiskAnalysis.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------

# Disable StrictMode (script designed for non-StrictMode environments)
try {
    Set-StrictMode -Off
} catch {}

# ----------------------------------------------------------------------
# Windows PS 5.1 + PS 7 coexistence: scrub PS7 module paths from
# PSModulePath so Microsoft.PowerShell.Security loads cleanly. PS7's
# v7.x copy of that module otherwise wins on lookup but its TypeData
# clashes with the v5.1 host -> ConvertTo-SecureString refuses to load.
# ----------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = ($env:PSModulePath -split ';' |
                         Where-Object { $_ -and ($_ -notmatch '(?i)\\powershell\\7') }) -join ';'
}

# ----------------------------------------------------------------------
# v2.2.232 -- SPN name bridge (defensive copy of Initialize-LauncherConfig).
# The v2.3 Setup Wizard writes $global:SI_SPN_* (unified names). The
# Connect-AzAccount calls inside this engine (token refresh + reconnect
# paths) still read the legacy $global:Spn* names. Initialize-LauncherConfig
# already does this mirror -- but if the engine is invoked OUTSIDE the
# standard launcher path (direct call, custom orchestrator, AF bootstrap),
# the legacy names stay $null and SPN+cert auth in particular falls through
# every elseif branch. Mirror the names here so the engine is defensive.
# ----------------------------------------------------------------------
if ($global:SI_SPN_TenantId        -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:SI_SPN_TenantId }
if ($global:SI_SPN_AppId           -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:SI_SPN_AppId }
if ($global:SI_SPN_Secret          -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:SI_SPN_Secret }
if ($global:SI_SPN_ObjectId        -and -not $global:SpnObjectId)              { $global:SpnObjectId              = [string]$global:SI_SPN_ObjectId }
if ($global:SI_SPN_CertThumbprint  -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint }

# v2.2.278 -- ALSO bridge from the internal-AutomateIT framework's HighPriv_Modern_*_Azure
# globals, populated by Connect-Platform on internal/AutomateIT installs. Without
# this bridge, internal customers using SPN+cert auth would see Connect-GraphHighPriv
# fall through to the secret branch on every reconnect (`$global:SpnCertificateThumbprint`
# stays empty even though Connect-Platform set $global:HighPriv_Modern_CertificateThumbprint_Azure).
# Same pattern: only set $Spn* if it's not already populated, so SI_SPN_* > HighPriv_*
# precedence (community customer overrides win).
if ($global:HighPriv_Modern_TenantID                       -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:HighPriv_Modern_TenantID }
if ($global:HighPriv_Modern_ApplicationID_Azure            -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if ($global:HighPriv_Modern_ApplicationSecret_Azure        -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:HighPriv_Modern_ApplicationSecret_Azure }
if ($global:HighPriv_Modern_CertificateThumbprint_Azure    -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

# ----------------------------------------------------------------------
#  -WhatIfMode IS NOT IMPLEMENTED BY THIS ENGINE -- refuse rather than lie.
#
#  Every SecurityInsight launcher exposes -WhatIfMode and sets $global:WhatIfMode,
#  but only the asset-tagging engine actually reads it. Here the switch had NO effect
#  whatsoever: a "dry run" ingested to Log Analytics, refreshed the Power BI dataset,
#  uploaded the export file and SENT MAIL exactly like a real run. A switch that
#  silently does the opposite of what its name promises is more dangerous than no
#  switch at all, because it gets used precisely when someone is trying to be careful.
#
#  Found 2026-08-05 while verifying the audit #16 split on a live run.
#
#  This fails fast at the top, before any module load or connection. If real dry-run
#  support is ever implemented here, DELETE this block -- do not soften it to a warning.
# ----------------------------------------------------------------------
if ($global:WhatIfMode) {
    throw ("-WhatIfMode is NOT implemented by the Risk Analysis engine, so it would not have " +
           "prevented anything: Log Analytics ingest, Power BI refresh, export upload and mail all " +
           "still happen. Refusing to run rather than pretend this is a dry run. Re-run without " +
           "-WhatIfMode if you intended a real run.")
}

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared/Ensure-Module.ps1')   # forward slash works on both Win + Linux container
Ensure-SecurityInsightModules
# ===============================================================================================
# POWERSHELL 5.1 + STRICTMODE SAFE INITIALIZATION
# ===============================================================================================

# Ensure script-scope variables exist
if (-not (Get-Variable -Name AutoBucketMemo -Scope Script -ErrorAction SilentlyContinue)) {
    $script:AutoBucketMemo = @{}
}

if (-not (Get-Variable -Name _sheetWritten -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_sheetWritten = @{}
}

if (-not (Get-Variable -Name GraphLastConnectUtc -Scope Script -ErrorAction SilentlyContinue)) {
    $script:GraphLastConnectUtc = [datetime]::MinValue
}

# Ensure optional global variables exist (StrictMode safe)
$optionalGlobals = @(
    "DedupeKeyCandidates",
    "DedupePriorityRules",
    "DedupeCompletenessColumns",
    "EnableFilterAudit",
    "AutoBucketCount",
    "AutoBucketMax",
    "AutoBucketCache",
    "ResetCache",
    "GraphReconnectMaxAgeMinutes",
    "GraphQueryMaxRetries",
    "OpenAI_MaxTokensPerRequest",
    "AI_MaxTokensPerRequest",
    "DebugQueryHash"
)

foreach ($g in $optionalGlobals) {
    if (-not (Get-Variable -Name $g -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $g -Scope Global -Value $null
    }
}


# -------------------------------------------------------------------------------------------------
# GLOBAL-ONLY CONFIG (launcher is source of truth)
# -------------------------------------------------------------------------------------------------

# Optional safe defaults if someone runs the main script directly (without launcher)
if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
  $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:OverwriteXlsx)          { $global:OverwriteXlsx = $true  }
if ($null -eq $global:AutomationFramework)   { $global:AutomationFramework = $false }
if ($null -eq $global:Summary)               { $global:Summary = $false }
if ($null -eq $global:Detailed)              { $global:Detailed = $false }

# Mode override helpers -- lets a launcher flip between Summary/Detailed runs
# without editing $global:ReportTemplate directly. Explicit $global:Summary /
# $global:Detailed still win (set above or by the launcher). These only bump
# the mode to $true; they never force it to $false.
#
# CLI flag wins over config override: if the user passed -Detailed on the
# launcher (so $global:Detailed already true), don't let a config-side
# RiskAnalysis_Summary_Override also flip Summary on (and vice versa) -- that
# combination would trip the "use only one" guard later in the engine.
if ([bool]$global:RiskAnalysis_Detailed_Override -and -not [bool]$global:Summary)  { $global:Detailed = $true }
if ([bool]$global:RiskAnalysis_Summary_Override  -and -not [bool]$global:Detailed) { $global:Summary  = $true }

# Resolve $global:ReportTemplate. Precedence:
#   1. Explicit $global:ReportTemplate (launcher wins per-run)
#   2. $global:Detailed = $true -> $global:RiskAnalysis_ReportTemplate_Default_Detailed
#                                  (default: 'RiskAnalysis_Detailed_Bucket')
#   3. $global:Summary  = $true -> $global:RiskAnalysis_ReportTemplate_Default_Summary
#                                  (default: 'RiskAnalysis_Summary_Bucket')
#   4. Fallback: 'RiskAnalysis_Summary_Bucket'
if (-not $global:ReportTemplate -or [string]::IsNullOrWhiteSpace([string]$global:ReportTemplate)) {
    $__tmplDefaultDetailed = if (-not [string]::IsNullOrWhiteSpace([string]$global:RiskAnalysis_ReportTemplate_Default_Detailed)) {
        [string]$global:RiskAnalysis_ReportTemplate_Default_Detailed
    } else { 'RiskAnalysis_Detailed_Bucket' }
    $__tmplDefaultSummary  = if (-not [string]::IsNullOrWhiteSpace([string]$global:RiskAnalysis_ReportTemplate_Default_Summary)) {
        [string]$global:RiskAnalysis_ReportTemplate_Default_Summary
    } else { 'RiskAnalysis_Summary_Bucket' }
    if     ([bool]$global:Detailed) { $global:ReportTemplate = $__tmplDefaultDetailed }
    elseif ([bool]$global:Summary)  { $global:ReportTemplate = $__tmplDefaultSummary }
    else                            { $global:ReportTemplate = $__tmplDefaultSummary }
}
if ($null -eq $global:SendMail)              { $global:SendMail = $false }
if ($null -eq $global:BuildSummaryByAI)      { $global:BuildSummaryByAI = $false }
if ($null -eq $global:ShowConfig)            { $global:ShowConfig = $false }

# Diagnostic helper: dumps the most operationally-relevant resolved globals at
# a named pipeline stage. Triggered when the launcher passes -ShowConfig (which
# sets $global:ShowConfig = $true). Was referenced at line ~2213 but never
# defined; added here so the flag works without engine code change.
function Show-ResolvedConfig {
    [CmdletBinding()]
    param([string]$Stage = 'unspecified')

    Write-Host ''
    Write-Host ('=== Resolved config snapshot ({0}) ===' -f $Stage) -ForegroundColor Cyan
    $rows = @(
        # Identity / auth
        @{ Group = 'Auth';        Name = 'AzureTenantId';                    Value = $global:AzureTenantId }
        @{ Group = 'Auth';        Name = 'SpnClientId';                      Value = $global:SpnClientId }
        @{ Group = 'Auth';        Name = 'SpnTenantId';                      Value = $global:SpnTenantId }
        @{ Group = 'Auth';        Name = 'AutomationFramework';              Value = $global:AutomationFramework }
        # Workspaces
        @{ Group = 'Workspaces';  Name = 'LogAnalyticsWorkspaceId';          Value = $global:LogAnalyticsWorkspaceId }
        @{ Group = 'Workspaces';  Name = 'TenantId_DefenderXdr';             Value = $global:TenantId_DefenderXdr }
        @{ Group = 'Workspaces';  Name = 'AzureGraphScope';                  Value = $global:AzureGraphScope }
        # Settings + reports
        @{ Group = 'Settings';    Name = 'SettingsPath';                     Value = $global:SettingsPath }
        @{ Group = 'Settings';    Name = 'OutputDir';                        Value = $global:OutputDir }
        @{ Group = 'Reports';     Name = 'ReportSettingsFileLocked';         Value = $global:ReportSettingsFileLocked }
        @{ Group = 'Reports';     Name = 'ReportSettingsFileCustom';         Value = $global:ReportSettingsFileCustom }
        @{ Group = 'Reports';     Name = 'ReportTemplate';                   Value = $global:ReportTemplate }
        @{ Group = 'Reports';     Name = 'BuildSummaryByAI';                 Value = $global:BuildSummaryByAI }
        # Bucketing
        @{ Group = 'Bucketing';   Name = 'AutoBucketCount';                  Value = $global:AutoBucketCount }
        @{ Group = 'Bucketing';   Name = 'AutoBucketMax';                    Value = $global:AutoBucketMax }
        @{ Group = 'Bucketing';   Name = 'AutoBucketCache';                  Value = $global:AutoBucketCache }
        @{ Group = 'Bucketing';   Name = 'ResetCache';                       Value = $global:ResetCache }
        # Mail / output
        @{ Group = 'Mail';        Name = 'Report_SendMail';                  Value = $global:Report_SendMail }
        @{ Group = 'Mail';        Name = 'Report_To';                        Value = ($global:Report_To -join '; ') }
        @{ Group = 'Output';      Name = 'SendToPowerBI';                    Value = $global:SendToPowerBI }
    )
    $rows | ForEach-Object {
        $val = $_.Value
        if ($null -eq $val -or "$val" -eq '') { $val = '<unset>' }
        Write-Host ('  {0,-12} {1,-32} = {2}' -f $_.Group, $_.Name, $val)
    }
    Write-Host ''
}


# Adaptive bucketing -- on by default (was opt-in in earlier previews; flipped to on
# 2026-05-02 per user ask). Engine probes 1 -> 2 -> 4 -> 8 -> ... up to AutoBucketMax,
# caches the chosen count keyed on (ReportName, queryHash) in
# $SettingsPath/OUTPUT/AutoBucketCache.json. Re-runs with the same query hash skip
# probing entirely; query mutation -> hash change -> re-probe from 1. Operators no
# longer need to set UseQueryBucketing/DefaultBucketCount per ReportTemplate; those
# fields are vestigial -- the engine's hardcoded base + AutoBucket replaces them.
if ($null -eq $global:AutoBucketCount) { $global:AutoBucketCount = $true }    # adaptive on by default
if ($null -eq $global:AutoBucketMax)   { $global:AutoBucketMax = 131072 }     # safety cap for probing (1M+ asset tenants)
if ($null -eq $global:AutoBucketCache) { $global:AutoBucketCache = $true }    # persist chosen counts to disk

# Optional: force rebuild of AutoBucket cache file
# Supports:
#   - Launcher sets $global:ResetCache
#   - OR set $script:ResetCache_Override / $script:ResetCache when running this script directly
#   - OR set env var SECURITYINSIGHT_RESETCACHE=true|1
if ($null -eq $global:ResetCache) {
  $rc = $null
  try {
    if (Get-Variable -Name 'ResetCache_Override' -Scope Script -ErrorAction SilentlyContinue) { $rc = $script:ResetCache_Override }
    elseif (Get-Variable -Name 'ResetCache' -Scope Script -ErrorAction SilentlyContinue) { $rc = $script:ResetCache }
  } catch { }

  if ($null -eq $rc -and -not [string]::IsNullOrWhiteSpace($env:SECURITYINSIGHT_RESETCACHE)) {
    $v = $env:SECURITYINSIGHT_RESETCACHE.Trim().ToLowerInvariant()
    if ($v -in @('1','true','yes','y')) { $rc = $true }
    elseif ($v -in @('0','false','no','n')) { $rc = $false }
  }

  if ($null -ne $rc) { $global:ResetCache = [bool]$rc }
  else { $global:ResetCache = $false }
}


if ($null -eq $global:AI_MaxTokensPerRequest -or [int]$global:AI_MaxTokensPerRequest -lt 1) {
  $global:AI_MaxTokensPerRequest = 16384
}

# Bucketing constants (no longer configurable; engine always uses these values).

# Graph tuning defaults
if ($null -eq $global:GraphReconnectMaxAgeMinutes) { $global:GraphReconnectMaxAgeMinutes = 45 }
if ($null -eq $global:GraphQueryMaxRetries)        { $global:GraphQueryMaxRetries = 4 }

# Normalize SettingsPath
try {
  $global:SettingsPath = (Resolve-Path -LiteralPath $global:SettingsPath).Path
} catch {
  throw "SettingsPath does not exist or cannot be resolved: $($global:SettingsPath)"
}

# RunHealth heartbeat -> SI_RunHealth_CL. Same shape as the asset-profiling
# pipeline so a single KQL detects crashed runs across the whole stack.
# Failure detection contract: per the Send-SIRunHealthRow docstring, a
# Start row WITHOUT a matching End row IS the failure signal -- KQL
# `where Phase=='Start' | join kind=leftanti (... Phase=='End') on RunId`
# finds crashed runs. So we DO NOT need a script-scope `trap` to emit a
# 'failure' End row; the absence of an End row carries the same information.
# (Earlier attempt with `trap { Send-...End ...; continue }` aborted the
#  per-report foreach because PS resumes at the next TOP-LEVEL statement
#  after `continue` in a script-scope trap, skipping all remaining reports.)
# Per-report errors are now caught by the try/catch wrapper around the
# foreach body (see "MAIN LOOP" section), so they cannot propagate up to
# kill the run -- the End row will fire normally even if some reports fail.
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/shared/Send-SIRunHealthRow.ps1')
$script:_RunHealthCtx = [pscustomobject]@{
    RunId          = [guid]::NewGuid().ToString()
    Engine         = 'risk-analysis'
    ShardIndex     = 0
    ShardCount     = 1
    StartedAt      = [datetime]::UtcNow
    CollectionTime = ([datetime]::UtcNow).ToString('yyyy-MM-dd HH:mm:ss')
}
$script:_RunHealthEndSent = $false
function Send-RARunHealthEnd {
    param([string]$ExitReason = 'success', [string]$ErrorMessage = '', [int]$AssetCount = -1)
    if ($script:_RunHealthEndSent) { return }
    $script:_RunHealthEndSent = $true
    try {
        Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'End' `
                            -AssetCount $AssetCount -ExitReason $ExitReason -ErrorMessage $ErrorMessage
    } catch {}
}
try { Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'Start' } catch {}

# Validate required launcher-provided globals
if ([string]::IsNullOrWhiteSpace([string]$global:ReportTemplate)) {
  throw "Global:ReportTemplate is empty. Launcher must set it."
}

# If SendMail is enabled, at least one recipient source must be populated --
# either the flat $global:MailTo or a per-template _To (new or legacy names).
if ($global:SendMail -eq $true) {
  $__hasFlatMailTo = ($global:MailTo -and @($global:MailTo).Count -gt 0)
  $__hasPerTmplTo  = (
      ($global:RiskAnalysis_Detailed_To        -and @($global:RiskAnalysis_Detailed_To).Count        -gt 0) -or
      ($global:RiskAnalysis_Summary_To         -and @($global:RiskAnalysis_Summary_To).Count         -gt 0) -or
      ($global:Mail_SecurityInsight_Detailed_To -and @($global:Mail_SecurityInsight_Detailed_To).Count -gt 0) -or
      ($global:Mail_SecurityInsight_Summary_To  -and @($global:Mail_SecurityInsight_Summary_To).Count  -gt 0)
  )
  if (-not $__hasFlatMailTo -and -not $__hasPerTmplTo) {
    throw "Global:SendMail is true, but no recipients are set. Populate Global:MailTo, or a per-template `$global:RiskAnalysis_(Detailed|Summary)_To / `$global:Mail_SecurityInsight_(Detailed|Summary)_To."
  }
}

#######################################################################################################
# FUNCTIONS (begin)
#######################################################################################################

# ========== lightweight logging helpers ==========
function Write-Step   ($msg){ Write-Host (" [STEP] {0}" -f $msg) -ForegroundColor Cyan }
function Write-Info   ($msg){ Write-Host (" [INFO] {0}" -f $msg) -ForegroundColor White }
function Write-Ok     ($msg){ Write-Host (" [OK]   {0}" -f $msg) -ForegroundColor Green }
function Write-Warn2  ($msg){ Write-Host (" [WARN] {0}" -f $msg) -ForegroundColor Yellow }
function Write-Warn   ($msg){ Write-Host (" [WARN] {0}" -f $msg) -ForegroundColor Yellow }
# Diagnostic logger -- only emits when verbose mode is active
# ($global:SI_Verbose=$true OR -Verbose was passed). Used for routing/timing/
# bucketing internals that clutter the screen during demos but are useful when
# debugging. Convert any noisy Write-Info to Write-Diag to gate it.
function Write-Diag   ($msg){ if ($global:SI_Verbose -or $VerbosePreference -eq 'Continue') { Write-Host (" [DIAG] {0}" -f $msg) -ForegroundColor White } }
function Write-Err2   ($msg){ Write-Host (" [ERR]  {0}" -f $msg) -ForegroundColor Red }
function Write-Done   ($msg){ Write-Host (" [DONE] {0}" -f $msg) -ForegroundColor Green }

# ---------------------------------------------------------------------------
# Deferred / superseded multi-path logging (operator ask): when the engine
# tries several routes to the same data (Sentinel lake -> hybrid -> AH ->
# LA-direct) and a LATER route succeeds, the FAILED earlier attempts must NOT
# be logged as WARN/ERROR -- they were superseded by the success. We collect
# each failed attempt SILENTLY here (full detail preserved) and:
#   * on success via any later path  -> emit at most ONE [INFO] noting N
#     superseded fallback attempts (only if there were any).
#   * if EVERY path fails            -> flush a SINGLE [WARN] with all the
#     collected per-attempt detail (the dumped ra-laerr files still hold the
#     full HTTP bodies for the truly-failed final path).
# Scope is per logical query: Reset-SupersededAttempts is called at the top of
# Invoke-GraphHuntingQuery.
# ---------------------------------------------------------------------------
if (-not (Get-Variable -Name _SupersededAttempts -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SupersededAttempts = New-Object System.Collections.Generic.List[string]
}
# AUDIT #16 tranche 3: run-progress, the superseded-attempt ledger and the Excel/output-safety
# helpers. Moved to _shared/RA-RunProgress.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-RunProgress.ps1')   # forward slash works on both Win + Linux

# AUDIT #16: Microsoft Graph connection for the high-privilege SPN, and the reconnect guard. Moved to _shared/RA-GraphAuth.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-GraphAuth.ps1')   # forward slash works on both Win + Linux

# ===============================================================================================
# CL-TABLE ROUTING
#
# Advanced hunting (Microsoft Graph /security/runHuntingQuery) only sees XDR tables --
# custom SI_*_CL tables in Log Analytics are invisible unless Sentinel data lake mirroring is on.
# Engine recognizes any SI_*_CL reference (Profile + VulnerabilityPIP + future) and routes
# pure-LA queries directly to Log Analytics; mixed CL+XDR queries get a cross-workspace let.
# No data lake mirror required.
# ===============================================================================================

# AUDIT #16: Profile-CL augmentation: workspace resolution, CL snapshot shadows and the augment plan. Moved to _shared/RA-ProfileAugment.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-ProfileAugment.ps1')   # forward slash works on both Win + Linux

function Invoke-SISentinelLakeQuery {
    <# Sentinel data lake KQL endpoint. Wraps the Microsoft-published
       https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query API which
       (unlike Graph runHuntingQuery) takes an explicit `db` field naming the target
       workspace -- required when the tenant has multiple Sentinel workspaces. Uses
       the existing SPN auth via Get-SIGraphToken; needs Log Analytics Reader (Azure
       RBAC at workspace scope) on each workspace queried.
       Throws on failure so the retry/schema-classifier loop in the caller works. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1')

    if ($WorkspaceResourceId -notmatch '/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
        throw ('Invoke-SISentinelLakeQuery: invalid WorkspaceResourceId: {0}' -f $WorkspaceResourceId)
    }
    $wsName = $matches[1]
    $wsGuid = Resolve-WorkspaceCustomerId -WorkspaceResourceId $WorkspaceResourceId

    # Match the documented sample shape exactly -- just csl + db.
    # The properties.Options block is optional and was tripping the API for some tenants.
    $body = @{
        csl = $Query
        db  = ('{0}-{1}' -f $wsName, $wsGuid)
    } | ConvertTo-Json -Depth 4 -Compress

    $stage = 'token'
    try {
        $token = Get-SIGraphToken -Resource SentinelDataLake
        $stage = 'query'
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body $body -ErrorAction Stop
    } catch {
        # PS 5.1 WebException loses the response body; recover it from the
        # underlying HTTP response so the actual error reaches the retry loop
        # (which classifies on text like "Failed to resolve table..." / AADSTS*).
        $apiBody = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $apiBody = $_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            $stream = $null; $reader = $null
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream.CanSeek) { $stream.Position = 0 }
                $reader = New-Object System.IO.StreamReader($stream)
                $apiBody = $reader.ReadToEnd()
            } catch {} finally {
                if ($reader) { try { $reader.Dispose() } catch {} }
                if ($stream) { try { $stream.Dispose() } catch {} }
            }
        }
        $dbField = ('{0}-{1}' -f $wsName, $wsGuid)
        $msg = if ($apiBody) { ('lake-{0}: {1} | api-body: {2} | db: {3}' -f $stage, $_.Exception.Message, $apiBody, $dbField) }
               else          { ('lake-{0}: {1} | db: {2}' -f $stage, $_.Exception.Message, $dbField) }
        throw $msg
    }

    # ADX/KQL v2 response shape: Tables[0] = primary, .Columns[].ColumnName, .Rows[][]
    if (-not $resp -or -not $resp.Tables -or $resp.Tables.Count -eq 0) { return ,@() }
    $primary = $resp.Tables[0]
    $colNames = @($primary.Columns | ForEach-Object { $_.ColumnName })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in $primary.Rows) {
        $h = [ordered]@{}
        for ($i = 0; $i -lt $colNames.Count; $i++) { $h[$colNames[$i]] = $row[$i] }
        [void]$out.Add([pscustomobject]$h)
    }
    return ,$out.ToArray()
}

# AUDIT #16: Log Analytics / Advanced Hunting query execution and its literal-escaping helpers. Moved to _shared/RA-LogAnalyticsQuery.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-LogAnalyticsQuery.ps1')   # forward slash works on both Win + Linux

function Save-RARenderedQuery {
    # v2.2.270 -- dump the fully-rendered, about-to-submit KQL to staging\risk-analysis\
    # so a failing query can be pasted into the Sentinel / AH portal for the precise
    # parse-error line+column. Covers every submission path: Sentinel data lake, LA-direct
    # (with cross-workspace let-block), single-workspace LA fallback, and AH. De-duped by
    # body hash so multi-bucket runs don't spam.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$Tag = ''
    )
    try {
        if (-not $script:_RAStagingDir) {
            $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            $script:_RAStagingDir = Join-Path $siRoot 'staging\risk-analysis'
        }
        if (-not (Test-Path $script:_RAStagingDir)) { New-Item -ItemType Directory -Path $script:_RAStagingDir -Force | Out-Null }
        if (-not $script:_RADumpedHashes) { $script:_RADumpedHashes = New-Object 'System.Collections.Generic.HashSet[string]' }
        $hash = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Query))
        $hashStr = -join ($hash[0..3] | ForEach-Object { $_.ToString('x2') })
        $dumpPath = Join-Path $script:_RAStagingDir ("ra-rendered-{0}.kql" -f $hashStr)
        Set-Content -Path $dumpPath -Value $Query -Encoding UTF8 -ErrorAction Stop
        if ($script:_RADumpedHashes.Add($hashStr) -and $Tag) {
            Write-Diag ("[{0}] rendered query staged: {1}" -f $Tag, (Split-Path -Leaf $dumpPath))
        }
        return $dumpPath
    } catch {
        Write-Warn2 ("failed to stage rendered query: {0}" -f $_.Exception.Message)
        return $null
    }
}

# Known group-key columns that are sourced from a Profile_CL (or *PIP_CL) table and can
# arrive as KQL `dynamic` rather than `string`. LA refuses to `summarize ... by` a dynamic
# column (SEM0001 -- "Summarize group key 'X' is of a 'dynamic' type ... use tostring(X)").
# The CL-derived cmdb* fields are the offenders: they're projected with column_ifexists in
# the YAML/Build path (which yields dynamic when the column is absent) and the PublicIP RA
# queries surface cmdbName straight off SI_VulnerabilityPIP_CL. Keep this list to columns
# that are genuinely string-or-dynamic; NEVER add numeric columns (RiskScore*, *Tier, *Count)
# -- casting those to string would change ordering/scoring semantics.
$script:_DynamicGroupKeyCols = @(
    'cmdbName','cmdbId','cmdbCriticality','cmdbDataSensitivity'
)

function Add-DynamicGroupKeyCasts {
    <# Root-cause guard for SEM0001 ("Summarize group key 'cmdbName' is of a 'dynamic'
       type"). Scans every `| summarize ... by <keys>` clause in $Query and wraps any
       known-dynamic CL column (cmdb* -- see $script:_DynamicGroupKeyCols, plus any other
       column literally named `cmdb*`) that appears as a BARE group key in `tostring(...)`.

       Targeted, list-driven, idempotent:
         * Only the `by` portion of each summarize is rewritten (the aggregation list and
           downstream operators are untouched), so numeric aggregates stay numeric.
         * A key already wrapped (`tostring(cmdbName)`, `tolower(cmdbName)`, etc.) is left
           as-is -- the regex only matches a bare identifier not preceded by `(` or `.`.
         * An alias-assignment group key (`cmdbDataSensitivity = ""`) is left as-is -- the
           RHS is a literal string already; we only cast the standalone-identifier form.

       Mirrors Build-RiskAnalysis.ps1's _InjectCmdbDefensiveExtends / line ~142 cmdbName
       cast so the runtime summarize path can't regress relative to the built template.
       Covers the 6 cross-domain Attack_Paths Summary reports + the PublicIP open-port /
       vuln reports, all of which `summarize ... by ... cmdbName, cmdbCriticality, ...`. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)

    if ([string]::IsNullOrEmpty($Query)) { return $Query }
    if ($Query -notmatch '(?ims)\bsummarize\b') { return $Query }

    # Build the column list: the curated dynamic set, case-insensitively de-duped.
    $cols = @($script:_DynamicGroupKeyCols)
    if (-not $cols -or $cols.Count -eq 0) { return $Query }

    # Locate each `summarize ... by <byClause>` and rewrite ONLY the by-clause. A by-clause
    # runs from the `by` keyword to the next top-level pipe (`| project`, `| order`, etc.)
    # or end-of-query. KQL has no nested `summarize ... by` inside a by-clause, so a
    # non-greedy run-to-next-pipe capture is safe.
    $summByRx = New-Object System.Text.RegularExpressions.Regex(
        '(?is)(\bsummarize\b.*?\bby\b)(?<by>.*?)(?=(?:\r?\n\s*\|)|\z)',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)

    $evaluator = {
        param($m)
        $head = $m.Groups[1].Value
        $byClause = $m.Groups['by'].Value
        $newBy = $byClause
        foreach ($c in $cols) {
            # Bare identifier as a group key: not already inside tostring()/tolower()/etc
            # (negative look-behind for `(` or `.` or word char), and not the LHS of an
            # alias assignment (`cmdbName =` -- negative look-ahead for `=` that isn't `==`).
            $colRx = '(?<![\w.(])' + [regex]::Escape($c) + '\b(?!\s*=(?!=))(?!\s*\()'
            $newBy = [regex]::Replace($newBy, $colRx, ('tostring({0})' -f $c))
        }
        return $head + $newBy
    }
    return $summByRx.Replace($Query, $evaluator)
}

# AUDIT #16: Advanced Hunting query submission, retry policy and deterministic-failure classification. Moved to _shared/RA-GraphHunting.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-GraphHunting.ps1')   # forward slash works on both Win + Linux

function Export-AISummaryWorksheet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)][string]$SummaryText
  )

  # Normalize line endings and split into rows so itâ€™s readable in Excel
  $text = ($SummaryText -replace "`r`n", "`n" -replace "`r", "`n").Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { $text = "No AI summary output was produced." }

  $lines = @($text -split "`n")
  $rows = for ($i=0; $i -lt $lines.Count; $i++) {
    [pscustomobject]@{
      LineNo = ($i + 1)
      Text   = (ConvertTo-XlsxSafeString $lines[$i])   # v2.1.206 -- strip XML-illegal control chars / lone surrogates
    }
  }

  $safeSheet = $SheetName.Substring(0, [Math]::Min(31, $SheetName.Length)) -replace '[:\\/?*\[\]]','_'
  $tableName = ($safeSheet -replace '\W','_')

  $excel = $rows | Export-Excel -Path $Path -WorksheetName $safeSheet -TableStyle 'Medium9' `
    -TableName $tableName -AutoFilter -FreezeTopRow -BoldTopRow -ClearSheet -PassThru

  $ws = $excel.Workbook.Worksheets[$safeSheet]
  if (-not $IsLinux) { $ws.Cells.AutoFitColumns() }   # System.Drawing.Common unavailable on Linux containers
  for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
    if ($ws.Column($col).Width -gt 90) { $ws.Column($col).Width = 90 }
  }

  Close-ExcelPackage $excel
}

# =================================================================================================
# ASSETNAME-SAFE KQL HELPERS (FULL FIX)
# =================================================================================================

# AUDIT #16: KQL fragment builders: device keys, asset-name safety, and the bucket / sub-bucket filters. Moved to _shared/RA-BucketFilters.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-BucketFilters.ps1')   # forward slash works on both Win + Linux

# ----------------------------------------------------------------------------
# Per-report exclude-list mechanism.
#
# Reports can include literal placeholder tokens that get replaced at run-time
# with KQL array literals sourced from `<SettingsPath>/<ReportName>.exclude.json`.
#
# Supported tokens (extend the $script:_ExcludeTokenMap below to add more):
#   __EXCLUDED_CVES__                 -> JSON property `ExcludedCves`
#   __EXCLUDED_CONFIGURATION_IDS__    -> JSON property `ExcludedConfigurationIds`
#
# Single JSON file per report holds all the lists, e.g.:
#   {
#     "ExcludedCves":             ["CVE-2024-12345", "CVE-2023-99999"],
#     "ExcludedConfigurationIds": ["scid-2090", "scid-22"],
#     "Comment":                  "Operator-curated risk-accepted items"
#   }
# (A bare top-level array is also accepted for back-compat with single-list files;
#  it's then mapped to the FIRST token requested.)
#
# Substitution example:
#   `let _excludedCves = dynamic(__EXCLUDED_CVES__);`
#   ->
#   `let _excludedCves = dynamic(["CVE-2024-12345","CVE-2023-99999"]);`
#   or `dynamic([])` when the file is absent / property missing / list empty.
#
# So operators add/remove an excluded CVE / config ID by editing a small JSON
# next to the YAML -- no YAML edits, no engine restart.
# ----------------------------------------------------------------------------

# Token-to-JSON-property map. Extend here to add new exclude-lists.
$script:_ExcludeTokenMap = @{
    '__EXCLUDED_CVES__'              = @('ExcludedCves',             'Cves',           'Excluded')
    '__EXCLUDED_CONFIGURATION_IDS__' = @('ExcludedConfigurationIds', 'ConfigurationIds','ConfigIds')
    '__EXCLUDED_ASSET_TAGS__'        = @('ExcludedAssetTags',        'AssetTags',      'Tags')
}

# Tokens that should ALSO consult a single global fallback file when the per-report
# .exclude.custom.json doesn't carry the matching property. Useful for tenant-wide
# exclusions (e.g. a single list of "ignore these MDE asset tags" applied across
# every Endpoint RA report). Per-report file ALWAYS wins on the same property name.
$script:_GlobalExcludeTokens = @(
    '__EXCLUDED_ASSET_TAGS__'
)
$script:_GlobalExcludeFileName = 'RiskAnalysisGlobalExclusions.custom.json'

# AUDIT #16: Exclusion lists: per-report and global exclude JSON, and placeholder substitution. Moved to _shared/RA-ExcludeLists.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-ExcludeLists.ps1')   # forward slash works on both Win + Linux

# ----------------------------------------------------------------------------
# Scalar (number) placeholder substitution.
#
# Parallel to Resolve-ExcludePlaceholders but for SCALAR values (e.g. numeric
# thresholds) instead of arrays. Same block-marker contract:
#
#     //__CVE_MIN_AGE_DAYS_BEGIN__
#     let _cveMinAgeDays = 0;
#     //__CVE_MIN_AGE_DAYS_END__
#
# Engine reads the value from <ReportName>.exclude.custom.json (per-report only;
# no global fallback) and rewrites the let to the substituted scalar. Without
# engine substitution the inline default applies and the query parses fine.
# ----------------------------------------------------------------------------
$script:_ScalarTokenMap = @{
    '__CVE_MIN_AGE_DAYS__' = @{ JsonProps = @('CveMinAgeDays','CveMinDays'); Default = 0 }
}

function Get-ScalarValueForReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $ReportName,
        [Parameter(Mandatory)][string[]] $PropertyNames,
        [Parameter(Mandatory)]           $Default
    )
    $loaded = Get-ReportExcludeJson -ReportName $ReportName
    if ($null -ne $loaded -and $loaded.Body -isnot [System.Array]) {
        foreach ($p in $PropertyNames) {
            if ($loaded.Body.PSObject.Properties[$p] -and $null -ne $loaded.Body.$p) {
                return $loaded.Body.$p
            }
        }
    }
    return $Default
}

function Resolve-ScalarPlaceholders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName
    )
    foreach ($token in $script:_ScalarTokenMap.Keys) {
        $tokenName  = $token.Trim('_')
        $beginMark  = ('//__{0}_BEGIN__' -f $tokenName)
        $endMark    = ('//__{0}_END__'   -f $tokenName)

        $blockRx   = [regex]::Escape($beginMark) + '(?<body>.*?)' + [regex]::Escape($endMark)
        $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $bodyMatch.Success) { continue }

        $spec    = $script:_ScalarTokenMap[$token]
        $value   = Get-ScalarValueForReport -ReportName $ReportName -PropertyNames $spec.JsonProps -Default $spec.Default
        # Coerce to numeric KQL literal (int preferred, fallback to original)
        $kqlLit  = if ($value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal]) {
                       [string]$value
                   } elseif ([int]::TryParse([string]$value, [ref]([int]0))) {
                       [string]([int]$value)
                   } else {
                       [string]$value
                   }
        $varName = if ($bodyMatch.Groups['body'].Value -match 'let\s+(\w+)\s*=') { $matches[1] } else { '_scalarValue' }
        $newBlock = ($beginMark + [Environment]::NewLine +
                     ('let {0} = {1};' -f $varName, $kqlLit) + [Environment]::NewLine +
                     $endMark)
        $Query = $Query.Replace($bodyMatch.Value, $newBlock)
        Write-Info ("[scalar] {0}: substituted block {1} ({2}) = {3}" -f $ReportName, $tokenName, $varName, $kqlLit)
    }
    return $Query
}

# ----------------------------------------------------------------------------
# CVE source-side filter block. Portal-safe substitution like __BUCKET_FILTER__.
#
# YAML block:
#     //__CVE_FILTER_BEGIN__
#     | where 1 == 1
#     //__CVE_FILTER_END__
#
# Engine rewrites the body from these globals (all OFF by default):
#   $global:SI_CVE_MinSeverity         = 'Critical' | 'High' | 'Medium' | $null
#   $global:SI_CVE_MinCvssScore        = 0..10 (0 = off)
#   $global:SI_CVE_RequireExploit      = $true | $false (false = off)
#   $global:SI_CVE_MaxPublishedAgeDays = N (0 = off)
#
# When any are set, the block fills with WHERE clauses against
# NodeProperties.rawData fields (severity / cvssScore / hasExploit /
# publishedDate) so the CVE-finding set is cut at source BEFORE the
# expensive join with edges and assets.
# ----------------------------------------------------------------------------
$script:_CveFilterBeginMark = '//__CVE_FILTER_BEGIN__'
$script:_CveFilterEndMark   = '//__CVE_FILTER_END__'

function Resolve-CveFilterBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName
    )

    $blockRx   = [regex]::Escape($script:_CveFilterBeginMark) + '(?<body>.*?)' + [regex]::Escape($script:_CveFilterEndMark)
    $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $bodyMatch.Success) { return $Query }

    $clauses = New-Object System.Collections.Generic.List[string]
    $applied = New-Object System.Collections.Generic.List[string]
    $indent  = '              '   # match YAML let-body indent

    # MinSeverity: include this severity AND everything more severe.
    $sev = [string]$global:SI_CVE_MinSeverity
    if (-not [string]::IsNullOrWhiteSpace($sev)) {
        $sevSet = switch ($sev.Trim().ToLowerInvariant()) {
            'critical' { @('Critical') }
            'high'     { @('Critical','High') }
            'medium'   { @('Critical','High','Medium') }
            default    { @() }
        }
        if ($sevSet.Count -gt 0) {
            $sevList = ($sevSet | ForEach-Object { '"{0}"' -f $_ }) -join ', '
            [void]$clauses.Add(('{0}| where tostring(NodeProperties.rawData.severity) in~ ({1})' -f $indent, $sevList))
            [void]$applied.Add(("MinSeverity={0}" -f $sev))
        }
    }

    # MinCvssScore: 0 = no filter.
    $cvss = $global:SI_CVE_MinCvssScore
    if ($null -ne $cvss -and [double]$cvss -gt 0) {
        [void]$clauses.Add(('{0}| where toreal(NodeProperties.rawData.cvssScore) >= {1}' -f $indent, [double]$cvss))
        [void]$applied.Add(("MinCvssScore={0}" -f $cvss))
    }

    # RequireExploit: $true = only CVEs with a known exploit.
    if ([bool]$global:SI_CVE_RequireExploit) {
        [void]$clauses.Add(('{0}| where tobool(NodeProperties.rawData.hasExploit) == true' -f $indent))
        [void]$applied.Add('RequireExploit=true')
    }

    # MaxPublishedAgeDays: 0 = no filter.
    $days = $global:SI_CVE_MaxPublishedAgeDays
    if ($null -ne $days -and [int]$days -gt 0) {
        [void]$clauses.Add(('{0}| where todatetime(NodeProperties.rawData.publishedDate) > ago({1}d)' -f $indent, [int]$days))
        [void]$applied.Add(("MaxPublishedAgeDays={0}" -f $days))
    }

    if ($clauses.Count -eq 0) {
        # No filter requested -- leave the no-op `| where 1 == 1` block in place.
        return $Query
    }

    $newBody = ([Environment]::NewLine +
                ($clauses -join [Environment]::NewLine) +
                [Environment]::NewLine + $indent)
    $newBlock = ($script:_CveFilterBeginMark + $newBody + $script:_CveFilterEndMark)
    $result   = $Query.Replace($bodyMatch.Value, $newBlock)
    Write-Info ("[cve-filter] {0}: applied {1}" -f $ReportName, ($applied -join ', '))
    return $result
}

# ----------------------------------------------------------------------------
# Stale-device filter block helpers (v2.2.282) -- portal-safe substitution.
#
# Source query wraps a no-op `| where 1 == 1` default between begin/end
# line-comment markers, e.g.:
#
#     //__STALE_DEVICE_FILTER_BEGIN__
#     | where 1 == 1
#     //__STALE_DEVICE_FILTER_END__
#
# At engine run-time substituted from two globals:
#
#   $global:SI_RA_StaleDeviceFilter = 'off' | 'lenient' | 'strict'   (default 'off')
#       off      -- no-op (no filter), backwards compatible
#       lenient  -- drop devices whose LastSeen is OLDER than threshold;
#                   keep devices with NULL LastSeen (treat as live)
#       strict   -- also drop devices with NULL LastSeen (treat as stale)
#
#   $global:SI_ActiveStaleDays = N          (existing global, default 30)
#       Threshold in days. Reused from asset-profiling so one knob ties
#       freshness across the solution.
#
# Strict is the right pick when the tenant has lots of EG ghost nodes
# (devices Defender knows by ID but never enriched with lastSeen). Those
# ghosts otherwise pollute the cartesian on heavy attack-path queries
# without representing any real risk.
#
# Filter applies inside the EG DeviceNodes let, so it cuts the device set
# BEFORE the CVE / credential / identity / Azure-target hop chain expands.
# Without engine substitution (raw portal paste) the inline `| where 1 == 1`
# default applies -- entire device set is queried, no behaviour change.
# ----------------------------------------------------------------------------
$script:_StaleDeviceFilterBeginMark = '//__STALE_DEVICE_FILTER_BEGIN__'
$script:_StaleDeviceFilterEndMark   = '//__STALE_DEVICE_FILTER_END__'

function New-StaleDeviceFilterKql {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$MaxAgeDays,
        [Parameter()][string]$Mode = 'strict'   # 'lenient' | 'strict'
    )
    if ($MaxAgeDays -le 0) {
        return '              | where 1 == 1'
    }
    $indent = '              '
    # Portable filter: works in either ExposureGraphNodes scope (where the
    # column is NodeId) or ExposureGraphEdges scope after a CVE-affecting-
    # device join (where the device column is TargetNodeId). column_ifexists
    # picks whichever exists; coalesce takes the first non-empty result.
    if ($Mode -eq 'strict') {
        $lastSeenCheck = 'isnotnull(__ls) and __ls > ago({0}d)' -f $MaxAgeDays
    } else {
        $lastSeenCheck = 'isnull(__ls) or __ls > ago({0}d)' -f $MaxAgeDays
    }
    return @"
$indent| where coalesce(tostring(column_ifexists('TargetNodeId','')), tostring(column_ifexists('NodeId',''))) in ((
$indent    ExposureGraphNodes
$indent    | where NodeLabel in ("device","computer-account","microsoft.compute/virtualmachines")
$indent    | extend __ls = todatetime(coalesce(
$indent        todynamic(NodeProperties).rawData.lastSeen,
$indent        todynamic(NodeProperties).rawData.lastSeenTime,
$indent        todynamic(NodeProperties).rawData.lastActivityTime,
$indent        todynamic(NodeProperties).rawData.lastSeenDate,
$indent        todynamic(NodeProperties).lastSeen
$indent      ))
$indent    | where $lastSeenCheck
$indent    | project NodeId
$indent  ))
"@
}

function Resolve-StaleDeviceFilterBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName
    )

    # Mode: 'off' (DEFAULT, no-op) | 'lenient' | 'strict'.
    # v2.2.306 -- defaulted to 'off' globally. Stale-device filter was misanchoring
    # against graph-match query shapes (and arguably adds no value: EG itself only
    # snapshots recently-seen device nodes). Customer can opt back in by setting
    # `$global:SI_RA_StaleDeviceFilter = 'strict'` in custom.ps1 if they want it.
    $mode = 'off'
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RA_StaleDeviceFilter)) {
        $modeRaw = ([string]$global:SI_RA_StaleDeviceFilter).Trim().ToLowerInvariant()
        if ($modeRaw -in @('lenient','strict','off')) { $mode = $modeRaw }
    }
    if ($mode -eq 'off') { return $Query }

    # Threshold from existing solution-wide freshness global; default 30.
    $maxAge = 30
    if ($null -ne $global:SI_ActiveStaleDays) {
        try {
            $candidate = [int]$global:SI_ActiveStaleDays
            if ($candidate -gt 0) { $maxAge = $candidate }
        } catch { }
    }

    # Path 1 -- explicit placeholder block present (locked YAML carries it).
    $blockRx   = [regex]::Escape($script:_StaleDeviceFilterBeginMark) + '(?<body>.*?)' + [regex]::Escape($script:_StaleDeviceFilterEndMark)
    $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($bodyMatch.Success) {
        $newBody  = ([Environment]::NewLine +
                     (New-StaleDeviceFilterKql -MaxAgeDays $maxAge -Mode $mode) +
                     [Environment]::NewLine + '              ')
        $newBlock = ($script:_StaleDeviceFilterBeginMark + $newBody + $script:_StaleDeviceFilterEndMark)
        $result   = $Query.Replace($bodyMatch.Value, $newBlock)
        Write-Info ("[stale-device] {0}: applied MaxAgeDays={1} Mode={2}" -f $ReportName, $maxAge, $mode)
        return $result
    }

    # Path 2 -- v2.2.288 auto-injection. Customer custom YAML often overrides
    # a locked report body WITHOUT carrying the new __STALE_DEVICE_FILTER__
    # placeholder, so explicit substitution alone misses those overrides.
    # Auto-inject the filter ABOVE the first __BUCKET_FILTER_BEGIN__ line
    # when the query (a) has a bucket filter (i.e. it's a heavy report we
    # plan to bucket-partition) AND (b) actually touches ExposureGraph
    # device/computer-account/VM nodes (the cartesian-bomb shape).
    $bucketBeginMark = '//__BUCKET_FILTER_BEGIN__'
    $bucketIdx = $Query.IndexOf($bucketBeginMark)
    if ($bucketIdx -lt 0) { return $Query }   # nothing to anchor to

    $touchesEgDevice = ($Query -match 'ExposureGraph(Nodes|Edges)') -and
                       ($Query -match '"device"|"computer-account"|"microsoft\.compute/virtualmachines"')
    if (-not $touchesEgDevice) { return $Query }

    # v2.2.302 -- the auto-injected filter assumes the row at injection point has a
    # 'TargetNodeId' or 'NodeId' column (filter shape:
    # `coalesce(column_ifexists('TargetNodeId',''), column_ifexists('NodeId','')) in ((NodeIds))`).
    # If neither column reference appears in the query body, those column_ifexists
    # calls return "", coalesce returns "", and `"" in ((subquery))` is false for
    # every row -> 100% silent drop. Reports like Device_Recommendations_Summary
    # join EG only for IsCustomerFacing and don't carry TargetNodeId/NodeId at the
    # injection point -- the filter produced 0 rows on every run for those tenants.
    # Skip auto-injection when neither column is referenced; the placeholder-based
    # path 1 remains opt-in for reports that explicitly carry __STALE_DEVICE_FILTER__.
    $hasNodeKeyContract = ($Query -match '\bTargetNodeId\b') -or ($Query -match '\bNodeId\b')
    if (-not $hasNodeKeyContract) {
        Write-Info ("[stale-device] {0}: auto-injection skipped (query has no TargetNodeId/NodeId column at injection point; filter would drop every row)" -f $ReportName)
        return $Query
    }

    # Find start of the line that contains the bucket-begin mark + capture its indent.
    $lineStart = $Query.LastIndexOf("`n", $bucketIdx)
    if ($lineStart -lt 0) { $lineStart = 0 } else { $lineStart++ }
    $indent = ''
    $j = $lineStart
    while ($j -lt $Query.Length -and ($Query[$j] -eq ' ' -or $Query[$j] -eq "`t")) {
        $indent += $Query[$j]; $j++
    }

    $filterKql = New-StaleDeviceFilterKql -MaxAgeDays $maxAge -Mode $mode
    # Re-indent the filter to match the bucket-filter line's indent.
    $filterLines = $filterKql -split "(`r`n|`n)" | Where-Object { $_ -ne '' -and $_ -notmatch '^\r?\n$' }
    $rebuilt = New-Object System.Text.StringBuilder
    foreach ($ln in $filterLines) {
        $stripped = $ln.TrimStart()
        if ([string]::IsNullOrWhiteSpace($stripped)) { continue }
        [void]$rebuilt.Append($indent).Append($stripped).Append([Environment]::NewLine)
    }
    $reindented = $rebuilt.ToString()

    $injection = ($indent + $script:_StaleDeviceFilterBeginMark + [Environment]::NewLine +
                  $reindented +
                  $indent + $script:_StaleDeviceFilterEndMark + [Environment]::NewLine)

    $result = $Query.Insert($lineStart, $injection)
    Write-Info ("[stale-device] {0}: auto-injected (no placeholder in YAML) MaxAgeDays={1} Mode={2}" -f $ReportName, $maxAge, $mode)
    return $result
}

# ----------------------------------------------------------------------------
# Bucket-filter block helpers -- portal-safe substitution.
#
# Source query must wrap a no-op `| where 1 == 1` default between begin/end
# line-comment markers, e.g.:
#
#     //__BUCKET_FILTER_BEGIN__
#     | where 1 == 1
#     //__BUCKET_FILTER_END__
#
# When bucketing is enabled, engine replaces the entire block with the real
# bucket-filter KQL (extend __bucket_key, where isnotempty, extend __bucket =
# abs(hash(...)) % N, where __bucket == <bucketIndex>). Without engine
# substitution (raw portal paste) the inline `| where 1 == 1` default applies
# (no-op -- entire dataset is queried), so the query is portal-paste-safe.
# ----------------------------------------------------------------------------
$script:_BucketFilterBeginMark = '//__BUCKET_FILTER_BEGIN__'
$script:_BucketFilterEndMark   = '//__BUCKET_FILTER_END__'

function Test-QueryHasBucketFilterBlock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)
    return ($Query.IndexOf($script:_BucketFilterBeginMark) -ge 0 -and
            $Query.IndexOf($script:_BucketFilterEndMark)   -ge 0)
}

function Replace-BucketFilterBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$BucketFilterKql
    )
    # v2.2.334 -- cross-domain reports (Attack_Paths_*, Identity_Admin_LogonTo_*)
    # use projection-aliased CL bucket keys (Target_AzureResourceId_Guid, Source_AadDeviceId,
    # etc.) that aren't in the EG-side coalesce list (DeviceKey/NodeId/...). For these,
    # EG-side bucket filtering would partition EG rows by a column UNRELATED to the
    # CL join key, so the per-bucket join misses most matching rows (lossy). Skip
    # EG bucket substitution when Resolve-ProfileCLLetBlocks set this flag --
    # CL stays bucketed (body shrinks, fits 1MB cap), EG sees ALL rows per bucket
    # query (no partition loss), and across N buckets the union is lossless. Each
    # bucket query is more compute-heavy on EG, but lossless > 8x faster.
    if ([bool]$script:_SkipEGBucketForCrossDomain) {
        return $Query
    }
    $blockRx   = [regex]::Escape($script:_BucketFilterBeginMark) + '(?<body>.*?)' + [regex]::Escape($script:_BucketFilterEndMark)
    $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $bodyMatch.Success) { return $Query }
    $newBlock = ($script:_BucketFilterBeginMark + [Environment]::NewLine +
                 $BucketFilterKql.TrimEnd() + [Environment]::NewLine +
                 $script:_BucketFilterEndMark)
    return $Query.Replace($bodyMatch.Value, $newBlock)
}

function Add-DeviceKeyBeforeBucketBlock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)
    if ($Query -match '(?im)\bDeviceKey\b') { return $Query }
    if (-not (Test-QueryHasBucketFilterBlock -Query $Query)) { return $Query }
    $deviceKeyKql = (New-DeviceKeyKql).TrimEnd()
    return $Query.Replace($script:_BucketFilterBeginMark, ($deviceKeyKql + [Environment]::NewLine + $script:_BucketFilterBeginMark))
}

# ----------------------------------------------------------------------------
# Weighted risk-factor block helpers.
#
# The query wraps a no-op default (multiplier=1.0, no detail) between begin/end
# block markers:
#
#     //__WEIGHTED_FACTORS_BEGIN__
#     | extend RiskFactor_Weight_Multiplier    = 1.0
#     | extend RiskFactor_Weight_Detailed      = ""
#     | extend RiskFactor_Weight_DetailedScore = ""
#     //__WEIGHTED_FACTORS_END__
#
# At runtime the engine replaces the block with a generated KQL chain built
# from ALL rules in the customer JSON config (riskscore_weighted.schema.custom.json,
# weightedRiskFactors section). Engine has no hardcoded rule names / fields /
# values -- it just iterates whatever the JSON declares.
#
# JSON shape:
#   "weightedRiskFactors": {
#     "combine":       "product",   // or "max" | "sum-of-deltas"
#     "maxMultiplier": 5.0,         // optional clamp; omit for no cap
#     "rules": [
#       {
#         "name":       "CmdbCritical",
#         "field":      "cmdbCriticality",
#         "matchAny":   ["Critical","Very High","Mission","4"],
#         "multiplier": 2.0
#       }
#     ]
#   }
#
# Customer adds rules without touching KQL or engine code. With no rules (or
# missing JSON), the no-op default applies -- weighted score equals base score.
# ----------------------------------------------------------------------------
$script:_WeightedFactorsBeginMark = '//__WEIGHTED_FACTORS_BEGIN__'
$script:_WeightedFactorsEndMark   = '//__WEIGHTED_FACTORS_END__'

function Get-WeightedFactorsConfig {
    <# Loads weightedRiskFactors.<engine> section from per-report
       .weighted.custom.json (preferred) or the global
       riskscore_weighted.schema.custom.json (fallback).

       JSON is engine-keyed so each engine carries its own rule set
       (endpoint / identity / azure use different profile fields):

         "weightedRiskFactors": {
           "endpoint": { "combine":"product", "rules":[ {field:"...", ...} ] },
           "identity": { "combine":"product", "rules":[ ... ] },
           "azure":    { "combine":"product", "rules":[ ... ] }
         }

       $Engine matches the report's SecurityDomain lowercased
       (Endpoint -> endpoint, Identity -> identity, Azure -> azure).
       Returns $null when no config / no rules for this engine. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReportName,
        [Parameter(Mandatory)][string]$Engine
    )

    if ($null -eq $script:_WeightedFactorsCache) { $script:_WeightedFactorsCache = @{} }
    $cacheKey = ('{0}|{1}' -f $ReportName, $Engine.ToLowerInvariant())
    if ($script:_WeightedFactorsCache.ContainsKey($cacheKey)) { return $script:_WeightedFactorsCache[$cacheKey] }

    # v2.2.228 -- walk-up discovery, no longer requires $global:SettingsPath
    # being set by the launcher. Search order:
    #   1. $global:SettingsPath (when launcher set it; backward compat)
    #   2. walk-up from THIS file's $PSScriptRoot looking for a
    #      `risk-analysis-detection/` sibling at every level
    # First hit wins. Per-report `<ReportName>.weighted.custom.json` always
    # beats the solution-wide `riskscore_weighted.schema.custom.json`.
    $searchDirs = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($global:SettingsPath)) {
        [void]$searchDirs.Add([string]$global:SettingsPath)
    }
    $cur = $PSScriptRoot
    for ($depth = 0; $depth -lt 6; $depth++) {
        if ([string]::IsNullOrWhiteSpace($cur)) { break }
        $sibling = Join-Path $cur 'risk-analysis-detection'
        if (Test-Path -LiteralPath $sibling -PathType Container) {
            [void]$searchDirs.Add([string]$sibling)
        }
        $parent = Split-Path -Parent $cur
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cur) { break }
        $cur = $parent
    }

    $seenDirs  = @{}
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($d in $searchDirs) {
        if ([string]::IsNullOrWhiteSpace($d)) { continue }
        $dKey = $d.ToLowerInvariant()
        if ($seenDirs.ContainsKey($dKey)) { continue }
        $seenDirs[$dKey] = $true
        [void]$candidates.Add((Join-Path $d ('{0}.weighted.custom.json' -f $ReportName)))
        [void]$candidates.Add((Join-Path $d 'riskscore_weighted.schema.custom.json'))
    }

    $cfg       = $null
    $engineKey = $Engine.ToLowerInvariant()
    foreach ($path in $candidates) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $body = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Warn2 ("[weight] failed to parse {0}: {1}" -f $path, $_.Exception.Message)
            continue
        }
        $root = if ($body.PSObject.Properties['weightedRiskFactors']) { $body.weightedRiskFactors } else { $null }
        if ($null -eq $root) { continue }
        $section = if ($root.PSObject.Properties[$engineKey]) { $root.$engineKey } else { $null }
        if ($null -eq $section) { continue }
        # Accept either 'fields' (preferred new shape) or 'rules' (legacy alias)
        $fields = if     ($section.PSObject.Properties['fields']) { @($section.fields) }
                  elseif ($section.PSObject.Properties['rules'])  { @($section.rules)  }
                  else                                            { @() }
        if ($fields.Count -eq 0) { continue }
        $cfg = [pscustomobject]@{
            Path          = $path
            Engine        = $engineKey
            Combine       = if ($section.PSObject.Properties['combine']       -and $section.combine)       { [string]$section.combine } else { 'product' }
            MaxMultiplier = if ($section.PSObject.Properties['maxMultiplier'] -and $section.maxMultiplier) { [double]$section.maxMultiplier } else { 0.0 }
            Fields        = $fields
        }
        break
    }
    if ($null -ne $cfg) {
        Write-Info ("[weight] {0} (engine={1}): {2} field(s), combine={3}, source={4}" -f $ReportName, $cfg.Engine, @($cfg.Fields).Count, $cfg.Combine, $cfg.Path)
    } else {
        Write-Warn2 ("[weight] {0} (engine={1}): no riskscore_weighted.schema.custom.json found in [{2}] -- YAML stub will ship (Factor=100, Detailed='cmdbCriticality=...')" -f $ReportName, $engineKey, (@($searchDirs) -join '; '))
    }
    $script:_WeightedFactorsCache[$cacheKey] = $cfg
    return $cfg
}

# AUDIT #16: Weighted risk-factor KQL: building the substitution block and resolving it into a query. Moved to _shared/RA-WeightedFactors.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-WeightedFactors.ps1')   # forward slash works on both Win + Linux

# AUDIT #16: Row shaping: field lookup, normalisation, de-duplication and scope filtering. Moved to _shared/RA-RowShaping.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-RowShaping.ps1')   # forward slash works on both Win + Linux

# ===========================
# NEW: Supports mixed YAML for ReportsIncluded (string or object)
# ===========================
function Resolve-ReportInclude {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    if ($Item -is [string]) {
        return [pscustomobject]@{
            Name = $Item
        }
    }

    $name = $null
    if     ($Item.PSObject.Properties['Name'])       { $name = [string]$Item.Name }
    elseif ($Item.PSObject.Properties['ReportName']) { $name = [string]$Item.ReportName }

    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "ReportsIncluded item is missing 'Name'. Item: $($Item | ConvertTo-Json -Depth 8 -Compress)"
    }

    return [pscustomobject]@{
        Name = $name
    }
}

# AUDIT #16: The risk-scoring calculation. Moved to _shared/RA-RiskScore.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-RiskScore.ps1')   # forward slash works on both Win + Linux

function Filter-ObjectsByColumn {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowNull()]
    [object[]] $InputObject,

    [Parameter(Mandatory)]
    [string] $ColumnToFilter,

    [Parameter(Mandatory)][AllowNull()]
    [object[]] $InScopeData,

    [switch] $CaseInsensitive,

    # If true (default), blank/null values are treated as "in scope" and kept.
    [bool] $IncludeBlank = $true,

    # If set, return a PSCustomObject with Kept/Removed arrays (and mark removed with __FilterReason)
    [switch] $ReturnAudit,

    # Optional label used in __FilterReason
    [string] $FilterName = "Filter"
  )

  if ($null -eq $InputObject -or $InputObject.Count -eq 0) {
    if ($ReturnAudit) { return [pscustomobject]@{ Kept=@(); Removed=@() } }
    return @()
  }

  # If scope is empty, everything is in scope
  if ($null -eq $InScopeData -or $InScopeData.Count -eq 0) {
    if ($ReturnAudit) { return [pscustomobject]@{ Kept=@($InputObject); Removed=@() } }
    return @($InputObject)
  }

  function _Normalize([object] $val, [bool] $ci) {
    if ($null -eq $val) { return $null }
    $s = ([string]$val).Trim()
    if ($ci) { return $s.ToLowerInvariant() }
    return $s
  }

  # normalize scope (ignore blanks)
  $normalizedScope = @()
  foreach ($x in $InScopeData) {
    $nx = _Normalize -val $x -ci:$CaseInsensitive.IsPresent
    if ($null -ne $nx -and $nx -ne '') { $normalizedScope += $nx }
  }
  if ($normalizedScope.Count -eq 0) {
    if ($ReturnAudit) { return [pscustomobject]@{ Kept=@($InputObject); Removed=@() } }
    return @($InputObject)
  }

  $kept    = New-Object System.Collections.Generic.List[object]
  $removed = New-Object System.Collections.Generic.List[object]

  foreach ($obj in $InputObject) {
    if ($null -eq $obj) { continue }

    # Missing column => keep (generic safe default)
    if (-not ($obj.PSObject.Properties.Name -contains $ColumnToFilter)) {
      $kept.Add($obj) | Out-Null
      continue
    }

    $val = $obj.$ColumnToFilter

    # Null/blank => keep when IncludeBlank
    if ($null -eq $val) {
      if ($IncludeBlank) { $kept.Add($obj) | Out-Null }
      else {
        if ($ReturnAudit) {
          $obj | Add-Member -NotePropertyName "__FilterReason" -NotePropertyValue ("{0}:{1} is null" -f $FilterName,$ColumnToFilter) -Force
          $removed.Add($obj) | Out-Null
        }
      }
      continue
    }

    if ($val -is [string]) {
      if ($val.Trim() -eq "") {
        if ($IncludeBlank) { $kept.Add($obj) | Out-Null }
        else {
          if ($ReturnAudit) {
            $obj | Add-Member -NotePropertyName "__FilterReason" -NotePropertyValue ("{0}:{1} is blank" -f $FilterName,$ColumnToFilter) -Force
            $removed.Add($obj) | Out-Null
          }
        }
        continue
      }
    }

    # Build candidates (array, comma-separated string, or scalar)
    $candidates = @()
    if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
      foreach ($item in $val) { $candidates += $item }
    } else {
      $s = [string]$val
      if ($s -like "*,*") { $candidates = $s -split '\s*,\s*' }
      else { $candidates = @($s) }
    }

    # If candidates are effectively empty, treat as blank
    $hasNonEmptyCandidate = $false
    foreach ($cand in $candidates) {
      $ncTmp = _Normalize -val $cand -ci:$CaseInsensitive.IsPresent
      if ($null -ne $ncTmp -and $ncTmp -ne '') { $hasNonEmptyCandidate = $true; break }
    }
    if (-not $hasNonEmptyCandidate) {
      if ($IncludeBlank) { $kept.Add($obj) | Out-Null }
      else {
        if ($ReturnAudit) {
          $obj | Add-Member -NotePropertyName "__FilterReason" -NotePropertyValue ("{0}:{1} has no non-empty candidates" -f $FilterName,$ColumnToFilter) -Force
          $removed.Add($obj) | Out-Null
        }
      }
      continue
    }

    # Match if any candidate is in scope
    $match = $false
    foreach ($cand in $candidates) {
      $nc = _Normalize -val $cand -ci:$CaseInsensitive.IsPresent
      if ($null -ne $nc -and $nc -ne '' -and $normalizedScope -contains $nc) { $match = $true; break }
    }

    if ($match) {
      $kept.Add($obj) | Out-Null
    } else {
      if ($ReturnAudit) {
        $obj | Add-Member -NotePropertyName "__FilterReason" -NotePropertyValue ("{0}:{1} out-of-scope (value='{2}')" -f $FilterName,$ColumnToFilter,([string]$val)) -Force
        $removed.Add($obj) | Out-Null
      }
    }
  }

  if ($ReturnAudit) {
    return [pscustomobject]@{
      Kept    = @($kept.ToArray())
      Removed = @($removed.ToArray())
    }
  }

  return @($kept.ToArray())
}


# AUDIT #16: Excel workbook rendering: sheet sections, worksheet export and the risk index. Moved to _shared/RA-ExcelReport.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-ExcelReport.ps1')   # forward slash works on both Win + Linux

# AUDIT #16: SMTP delivery: the anonymous and authenticated send paths. Moved to _shared/RA-Mail.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-Mail.ps1')   # forward slash works on both Win + Linux

Write-Step "initializing"

# Wipe the rendered-query staging dir at startup so dumps from previous runs
# don't accumulate. Path is reused later by the hybrid path.
try {
    $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:_RAStagingDir = Join-Path $siRoot 'staging\risk-analysis'
    if (Test-Path $script:_RAStagingDir) {
        Get-ChildItem -Path $script:_RAStagingDir -Filter 'ra-rendered-*.kql' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Path $script:_RAStagingDir -Force | Out-Null
    }
} catch { Write-Warn2 ("staging dir init failed: {0}" -f $_.Exception.Message) }

#####################################################################################################
# CONNECTION
#####################################################################################################

# v2.2 SPN contract bridge: accept the unified $global:SI_SPN_* names
# AND the legacy $global:Spn{TenantId,ClientId,ClientSecret}
# names. SI_SPN_* wins when both are set, but only when present.
if ($global:SI_SPN_TenantId -and -not $global:SpnTenantId)     { $global:SpnTenantId     = [string]$global:SI_SPN_TenantId }
if ($global:SI_SPN_AppId    -and -not $global:SpnClientId)     { $global:SpnClientId     = [string]$global:SI_SPN_AppId }
if ($global:SI_SPN_Secret   -and -not $global:SpnClientSecret) { $global:SpnClientSecret = [string]$global:SI_SPN_Secret }

if ([bool]$global:AutomationFramework) {

    #----------------------
    # AUTOMATION FRAMEWORK
    #----------------------

    # v2 AutomationFramework bootstrap (replaces v1 Connect_Azure.ps1 chain).
    # Walks up to the AutomateITPS module, then one call to
    # Initialize-PlatformAutomationFramework does cert-based Connect-AzAccount,
    # fetches Modern secrets from KV, and populates the v1-contract
    # $global:HighPriv_* / $global:AzureTenantId names. Zero v1 module imports.
    $repoRoot = $PSScriptRoot
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$PSScriptRoot'."
    }
    $global:PathScripts = $repoRoot
    Write-Output ""
    Write-Output "Repo root          -> $($global:PathScripts)"

    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure

    if ([bool]$global:ShowConfig) { Show-ResolvedConfig -Stage "after AutomationFramework defaults loaded" }

    # v2.2.238 -- AutomationFramework branch accepts cert OR secret. AF cert-based
    # SPNs leave HighPriv_Modern_Secret_Azure empty and rely on a thumbprint mirror
    # populated by Initialize-PlatformAutomationFramework.
    $_afHasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $_afHasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        (-not $_afHasSecret -and -not $_afHasCert)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Provide them via wrapper globals or enable -AutomationFramework to load them."
    }

    # ==============================
    # Graph auth helpers
    # ==============================
    $script:GraphLastConnectUtc = [datetime]::MinValue

    #------------------------------------------------------------------------------------------------------------
    # Graph connect (initial)
    #------------------------------------------------------------------------------------------------------------
    Write-Step "connecting to Microsoft Graph (initial)"
    Tock
    try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
    Tick "graph connect"

    #------------------------------------------------------------------------------------------------------------
    # Output File -- write into the solution's <solutionRoot>/output/ folder so
    # operators don't have to dig through risk-analysis-detection/OUTPUT/. The
    # old path stays customizable via $global:SI_RiskAnalysis_OutputDir for
    # anyone who already had automation pointed at the deeper path.
    # $global:SettingsPath = <solutionRoot>/risk-analysis-detection (set by launcher).
    #------------------------------------------------------------------------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_OutputDir)) {
        $global:OutputDir = [string]$global:SI_RiskAnalysis_OutputDir
    } else {
        $solutionRoot      = Split-Path -Parent $global:SettingsPath
        $global:OutputDir  = Join-Path $solutionRoot 'output'
    }
    Ensure-Directory -Path $global:OutputDir
    $global:OutputXlsx = Join-Path $global:OutputDir ("{0}.xlsx" -f $global:ReportTemplate)

    #------------------------------------------------------------------------------------------------------------
    # Mail routing (Summary vs Detailed)
    #------------------------------------------------------------------------------------------------------------
    if ([bool]$global:Detailed -and [bool]$global:Summary) {
      throw "Invalid parameters: Use only one of -Detailed or -Summary."
    }

    # Mail globals support both NEW ($global:RiskAnalysis_*_SendMail / _To) and LEGACY
    # ($global:Mail_SecurityInsight_*_SendMail / _To) names. New name wins when both set.
    $__detailedSend = if ($null -ne $global:RiskAnalysis_Detailed_SendMail)                 { [bool]$global:RiskAnalysis_Detailed_SendMail }
                      elseif ($null -ne $global:Mail_SecurityInsight_Detailed_SendMail)     { [bool]$global:Mail_SecurityInsight_Detailed_SendMail }
                      else                                                                  { $false }
    $__detailedTo   = if ($global:RiskAnalysis_Detailed_To)                                 { @($global:RiskAnalysis_Detailed_To) }
                      elseif ($global:Mail_SecurityInsight_Detailed_To)                     { @($global:Mail_SecurityInsight_Detailed_To) }
                      else                                                                  { @() }
    $__summarySend  = if ($null -ne $global:RiskAnalysis_Summary_SendMail)                  { [bool]$global:RiskAnalysis_Summary_SendMail }
                      elseif ($null -ne $global:Mail_SecurityInsight_Summary_SendMail)      { [bool]$global:Mail_SecurityInsight_Summary_SendMail }
                      else                                                                  { $false }
    $__summaryTo    = if ($global:RiskAnalysis_Summary_To)                                  { @($global:RiskAnalysis_Summary_To) }
                      elseif ($global:Mail_SecurityInsight_Summary_To)                      { @($global:Mail_SecurityInsight_Summary_To) }
                      else                                                                  { @() }

    if ([bool]$global:Detailed) {
      Write-Info "Mail mode selected: Detailed"
      $global:Report_SendMail = $__detailedSend
      $global:Report_To       = $__detailedTo
    }
    elseif ([bool]$global:Summary) {
      Write-Info "Mail mode selected: Summary"
      $global:Report_SendMail = $__summarySend
      $global:Report_To       = $__summaryTo
    }
    else {
      Write-Info "Mail mode selected: Default (no -Detailed/-Summary provided)"
      $global:Report_SendMail = $__detailedSend
      $global:Report_To       = $__detailedTo
    }

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $global:Report_SendMail, ($global:Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # RiskAnalysis query settings
    #------------------------------------------------------------------------------------------------------------
    # The locked YAML is centrally maintained.
    # Customers can optionally add/override in the custom YAML.
    # Developers can stage experimental queries in the dev YAML (gitignored, not synced to customers).
    if ($null -eq $global:ReportSettingsFileLocked) { $global:ReportSettingsFileLocked = "RiskAnalysis_Queries_Locked.yaml" }
    if ($null -eq $global:ReportSettingsFileCustom) { $global:ReportSettingsFileCustom = "RiskAnalysis_Queries_Custom.yaml" }
    if ($null -eq $global:ReportSettingsFileDev)    { $global:ReportSettingsFileDev    = "RiskAnalysis_Queries_Dev.yaml" }
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "riskscore.index.custom.csv")

} else {

    #----------------------
    # Connect Custom Auth
    #----------------------

    # v2.2.234 -- accept either ClientSecret OR CertificateThumbprint. Previous
    # check demanded Secret and threw for SPN+cert customers (most common in
    # internal tenants using cert-based v1 SPNs the wizard re-uses).
    $__hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $__hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        (-not $__hasSecret -and -not $__hasCert)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Provide them via wrapper globals or enable -AutomationFramework to load them."
    }

    if ($__hasCert) { write-host "Connect using ServicePrincipal with AppId & Certificate" }
    else            { write-host "Connect using ServicePrincipal with AppId & Secret" }

    Write-Step "connecting to Azure"
    Tock
    try {
        if ($__hasCert) {
            Connect-AzAccount -ServicePrincipal `
                -Tenant              $global:SpnTenantId `
                -ApplicationId       $global:SpnClientId `
                -CertificateThumbprint $global:SpnCertificateThumbprint `
                -WarningAction SilentlyContinue | Out-Null
        } else {
            # Build SecureString without ConvertTo-SecureString -- avoids Microsoft.PowerShell.Security
            # autoload failures observed when Az/Graph have already loaded conflicting type data.
            $global:SecureSecret = New-Object System.Security.SecureString
            foreach ($__c in ([string]$global:SpnClientSecret).ToCharArray()) { $global:SecureSecret.AppendChar($__c) }
            $global:SecureSecret.MakeReadOnly()
            $global:Credential = New-Object System.Management.Automation.PSCredential (
                $global:SpnClientId,
                $global:SecureSecret
            )

            Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $global:Credential -WarningAction SilentlyContinue | Out-Null
        }
        Write-Ok "azure connection step done"
    } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
    Tick "azure connect"

    #------------------------------------------------------------------------------------------------------------
    # Graph auth helpers
    #------------------------------------------------------------------------------------------------------------
    $script:GraphLastConnectUtc = [datetime]::MinValue

    #------------------------------------------------------------------------------------------------------------
    # Graph connect (initial)
    #------------------------------------------------------------------------------------------------------------
    Write-Step "connecting to Microsoft Graph (initial)"
    Tock
    try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
    Tick "graph connect"

    #------------------------------------------------------------------------------------------------------------
    # Output File
    #------------------------------------------------------------------------------------------------------------
    Write-Info "Chosen ReportTemplate: $($global:ReportTemplate)"

    #------------------------------------------------------------------------------------------------------------
    # Mail routing (community) -- supports per-template Detailed/Summary splits with
    # new + legacy name fallback, and falls back to the flat $global:SendMail /
    # $global:MailTo when per-template vars aren't set.
    #------------------------------------------------------------------------------------------------------------
    $__detailedSend = if ($null -ne $global:RiskAnalysis_Detailed_SendMail)                 { [bool]$global:RiskAnalysis_Detailed_SendMail }
                      elseif ($null -ne $global:Mail_SecurityInsight_Detailed_SendMail)     { [bool]$global:Mail_SecurityInsight_Detailed_SendMail }
                      else                                                                  { $null }
    $__detailedTo   = if ($global:RiskAnalysis_Detailed_To)                                 { @($global:RiskAnalysis_Detailed_To) }
                      elseif ($global:Mail_SecurityInsight_Detailed_To)                     { @($global:Mail_SecurityInsight_Detailed_To) }
                      else                                                                  { @() }
    $__summarySend  = if ($null -ne $global:RiskAnalysis_Summary_SendMail)                  { [bool]$global:RiskAnalysis_Summary_SendMail }
                      elseif ($null -ne $global:Mail_SecurityInsight_Summary_SendMail)      { [bool]$global:Mail_SecurityInsight_Summary_SendMail }
                      else                                                                  { $null }
    $__summaryTo    = if ($global:RiskAnalysis_Summary_To)                                  { @($global:RiskAnalysis_Summary_To) }
                      elseif ($global:Mail_SecurityInsight_Summary_To)                      { @($global:Mail_SecurityInsight_Summary_To) }
                      else                                                                  { @() }

    if ([bool]$global:Detailed) {
        Write-Info "Mail mode selected: Detailed"
        $global:Report_SendMail = if ($null -ne $__detailedSend) { $__detailedSend } else { [bool]$global:SendMail }
        $global:Report_To       = if ($__detailedTo.Count -gt 0) { $__detailedTo }   else { @($global:MailTo) }
    } elseif ([bool]$global:Summary) {
        Write-Info "Mail mode selected: Summary"
        $global:Report_SendMail = if ($null -ne $__summarySend)  { $__summarySend } else { [bool]$global:SendMail }
        $global:Report_To       = if ($__summaryTo.Count -gt 0)  { $__summaryTo }   else { @($global:MailTo) }
    } else {
        Write-Info "Mail mode selected: Default (neither Detailed nor Summary set)"
        $global:Report_SendMail = [bool]$global:SendMail
        $global:Report_To       = @($global:MailTo)
    }

    if ($global:Report_SendMail -and (-not $global:Report_To -or @($global:Report_To).Count -eq 0)) {
        throw "SendMail was enabled, but no recipients were provided (MailTo empty and no matching per-template _To)."
    }

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $global:Report_SendMail, ($global:Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # ExposureInsight settings -- mirror the OutputDir resolution above (community-mode branch).
    #------------------------------------------------------------------------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_OutputDir)) {
        $global:OutputDir = [string]$global:SI_RiskAnalysis_OutputDir
    } else {
        $solutionRoot      = Split-Path -Parent $global:SettingsPath
        $global:OutputDir  = Join-Path $solutionRoot 'output'
    }
    Ensure-Directory -Path $global:OutputDir
    $global:OutputXlsx = Join-Path $global:OutputDir ("{0}.xlsx" -f $global:ReportTemplate)

    #------------------------------------------------------------------------------------------------------------
    # RiskAnalysis query settings
    #------------------------------------------------------------------------------------------------------------
    if ($null -eq $global:ReportSettingsFileLocked) { $global:ReportSettingsFileLocked = "RiskAnalysis_Queries_Locked.yaml" }
    if ($null -eq $global:ReportSettingsFileCustom) { $global:ReportSettingsFileCustom = "RiskAnalysis_Queries_Custom.yaml" }
    if ($null -eq $global:ReportSettingsFileDev)    { $global:ReportSettingsFileDev    = "RiskAnalysis_Queries_Dev.yaml" }
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "riskscore.index.custom.csv")
}

# v2.2.365 -- SMTP pre-flight validation at startup. If mail will be sent
# (Report_SendMail = true) AND anonymous mode is OFF (the default), require
# all three credentials -- SMTPFrom, SMTPUser, SMTPPassword -- to be non-empty.
# Throw early so the operator sees the misconfiguration at run start, not
# after a multi-hour Risk Analysis completes and only the mail-dispatch step
# at the very end discovers the missing credential.
if ([bool]$global:Report_SendMail -and ($global:Mail_SendAnonymous -eq $false)) {
    $_missing = @()
    if ([string]::IsNullOrWhiteSpace([string]$global:SMTPFrom))     { $_missing += 'SMTPFrom' }
    if ([string]::IsNullOrWhiteSpace([string]$global:SMTPUser))     { $_missing += 'SMTPUser' }
    if ([string]::IsNullOrWhiteSpace([string]$global:SMTPPassword)) { $_missing += 'SMTPPassword' }
    if ($_missing.Count -gt 0) {
        throw ("SMTP PRE-FLIGHT FAILED -- `$global:Report_SendMail is true and `$global:Mail_SendAnonymous is `$false (authenticated SMTP), but the following credential(s) are empty: {0}. Set them in your custom.ps1 (Layer 3) or platform-defaults.ps1, OR set `$global:Mail_SendAnonymous = `$true if your relay actually accepts anonymous submission. SMTPFrom = visible from-address; SMTPUser = SMTP relay login id; SMTPPassword = SMTP relay password (NOT an API key or Graph token)." -f ($_missing -join ', '))
    }
}

# Generic bucketing configuration (for large queries)
# (kept as GLOBALS only)
Write-Step "settings overview"
Write-Info ("OutputXlsx: {0}" -f $global:OutputXlsx)
Write-Info ("SettingsPath: {0}" -f $global:SettingsPath)
Write-Info ("Risk Analysis Settings Files: Locked='{0}', Custom='{1}'" -f $global:ReportSettingsFileLocked, $global:ReportSettingsFileCustom)
Write-Info ("Risk Index Csv Path: {0}" -f $global:RiskDefinitionsCsvPath)
Write-Info ("Chosen ReportTemplate: {0}" -f $global:ReportTemplate)
Write-Info "Query bucketing: enabled (count=2, token='__BUCKET_FILTER__')"
Write-Info ("Graph reconnect: MaxAgeMinutes={0}, MaxRetries={1}" -f $global:GraphReconnectMaxAgeMinutes, $global:GraphQueryMaxRetries)
# Token budget: canonical is $Global:OpenAI_MaxTokensPerRequest (back-compat alias: $Global:AI_MaxTokensPerRequest)
if (-not (Get-Variable -Name OpenAI_MaxTokensPerRequest -Scope Global -ErrorAction SilentlyContinue)) {
  if (Get-Variable -Name AI_MaxTokensPerRequest -Scope Global -ErrorAction SilentlyContinue) {
    $Global:OpenAI_MaxTokensPerRequest = [int]$Global:AI_MaxTokensPerRequest
  } else {
    $Global:OpenAI_MaxTokensPerRequest = 16384
  }
}
if (-not (Get-Variable -Name AI_MaxTokensPerRequest -Scope Global -ErrorAction SilentlyContinue)) {
  $Global:AI_MaxTokensPerRequest = [int]$Global:OpenAI_MaxTokensPerRequest
}

# Debug flag (optional)
if (-not (Get-Variable -Name DebugQueryHash -Scope Global -ErrorAction SilentlyContinue)) {
  $Global:DebugQueryHash = $false
}

Write-Info ("AI max_tokens (OpenAI_MaxTokensPerRequest): {0}" -f $Global:OpenAI_MaxTokensPerRequest)
Write-Info ("DebugQueryHash: {0}" -f [bool]$Global:DebugQueryHash)
Write-Info ("DebugQueryHash: {0}" -f [bool]$Global:DebugQueryHash)

#####################################################################################################
# INITIALIZATION
#####################################################################################################

Reset-ExcelOutput -Path $global:OutputXlsx -ForceRemove:([bool]$global:OverwriteXlsx)

# Optional: reset AutoBucket cache so it rebuilds
if ([bool]$global:ResetCache) {
  try {
    $cachePath = Join-Path $global:SettingsPath "OUTPUT\AutoBucketCache.json"
    if (Test-Path -LiteralPath $cachePath) {
      Remove-Item -LiteralPath $cachePath -Force -ErrorAction Stop
      Write-Info ("AutoBucket cache reset: deleted '{0}'" -f $cachePath)
    } else {
      Write-Info ("AutoBucket cache reset requested, but file did not exist: '{0}'" -f $cachePath)
    }
  } catch {
    Write-Warn ("AutoBucket cache reset requested, but delete failed: {0}" -f $_.Exception.Message)
  }
}

# track sheet first/append state per run (kept for compatibility; export is now single-write)
if (-not $script:_sheetWritten) { $script:_sheetWritten = @{} }

# Get data
Write-Step "loading report settings from YAML"
Tock
try {
  function Read-YamlFileOrNull {
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Yaml)
  }

  function Merge-ByReportName {
    param(
      [Parameter(Mandatory=$false)][object]$Locked,
      [Parameter(Mandatory=$false)][object]$Custom
    )

    function Convert-ToItemList {
      param([object]$InputObject)
      if ($null -eq $InputObject) { return @() }

      # If a dictionary (hashtable/ordered dictionary), merge its values
      if ($InputObject -is [System.Collections.IDictionary]) {
        return @($InputObject.Values)
      }

      # If it's an enumerable (array/list/arraylist), return items
      if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        return @($InputObject)
      }

      # Single object
      return @($InputObject)
    }

    function Get-ItemAndName {
      param([object]$Obj)

      $item = $Obj

      # If we got a DictionaryEntry, use its Value as the item
      if ($Obj -is [System.Collections.DictionaryEntry]) {
        $item = $Obj.Value
      }

      # Try property first
      $name = $null
      try { $name = $item.ReportName } catch {}

      # If it's a hashtable-like, try key lookup
      if ([string]::IsNullOrWhiteSpace([string]$name)) {
        if ($item -is [System.Collections.IDictionary]) {
          if ($item.Contains('ReportName')) { $name = $item['ReportName'] }
        }
      }

      return @($item, $name)
    }

    $lockedList = Convert-ToItemList $Locked
    $customList = Convert-ToItemList $Custom

    # Build a map of custom items by ReportName
    $customMap = @{}
    foreach ($c in $customList) {
      if ($null -eq $c) { continue }
      $pair = Get-ItemAndName $c
      $item = $pair[0]
      $name = $pair[1]
      if ([string]::IsNullOrWhiteSpace([string]$name)) { continue }
      $customMap[[string]$name] = $item
    }

    # Start with locked order; replace with custom on name-conflict
    $out = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($l in $lockedList) {
      if ($null -eq $l) { continue }
      $pair = Get-ItemAndName $l
      $item = $pair[0]
      $lname = $pair[1]
      if ([string]::IsNullOrWhiteSpace([string]$lname)) { continue }

      $key = [string]$lname
      if ($customMap.ContainsKey($key)) {
        [void]$out.Add($customMap[$key])
        $seen[$key] = $true
      } else {
        [void]$out.Add($item)
        $seen[$key] = $true
      }
    }

    # Append custom-only
    foreach ($c in $customList) {
      if ($null -eq $c) { continue }
      $pair = Get-ItemAndName $c
      $item = $pair[0]
      $cname = $pair[1]
      if ([string]::IsNullOrWhiteSpace([string]$cname)) { continue }
      $key = [string]$cname
      if (-not $seen.ContainsKey($key)) {
        [void]$out.Add($item)
        $seen[$key] = $true
      }
    }

    return $out
  }

function Merge-ReportSettings {
    param(
      [Parameter(Mandatory=$true)][object]$LockedSettings,
      [Parameter(Mandatory=$false)][object]$CustomSettings
    )

    if ($null -eq $LockedSettings) { throw "Locked settings is null" }

    # PS 5.1 quirk: powershell-yaml's ConvertFrom-Yaml returns [Hashtable], whose
    # .PSObject.Properties enumerates Hashtable metadata (Count/Keys/Values/...)
    # instead of the YAML keys -- so a naive PSObject.Properties copy ends up
    # with no Reports/Templates. Branch on IDictionary to iterate Keys instead.
    function _CopyTopLevelKeys([object]$Src, $Dst) {
      if ($null -eq $Src) { return }
      if ($Src -is [System.Collections.IDictionary]) {
        foreach ($k in $Src.Keys) { $Dst[[string]$k] = $Src[$k] }
      } else {
        foreach ($p in $Src.PSObject.Properties) { $Dst[$p.Name] = $p.Value }
      }
    }

    # Shallow copy locked root object
    $merged = [ordered]@{}
    _CopyTopLevelKeys $LockedSettings $merged

    if ($null -ne $CustomSettings) {
      $merged['Reports'] = Merge-ByReportName -Locked $LockedSettings.Reports -Custom $CustomSettings.Reports
      $merged['ReportTemplates'] = Merge-ByReportName -Locked $LockedSettings.ReportTemplates -Custom $CustomSettings.ReportTemplates

      # Copy any additional top-level keys from custom that don't exist in locked
      if ($CustomSettings -is [System.Collections.IDictionary]) {
        foreach ($k in $CustomSettings.Keys) { if (-not $merged.Contains([string]$k)) { $merged[[string]$k] = $CustomSettings[$k] } }
      } else {
        foreach ($p in $CustomSettings.PSObject.Properties) { if (-not $merged.Contains($p.Name)) { $merged[$p.Name] = $p.Value } }
      }
    } else {
      # Ensure keys exist
      if (-not $merged.Contains('Reports')) { $merged['Reports'] = @() }
      if (-not $merged.Contains('ReportTemplates')) { $merged['ReportTemplates'] = @() }
    }

    return [pscustomobject]$merged
  }

  # v2.2 layout puts the Locked yaml in <SettingsPath>/locked/ and
  # the Custom yaml in <SettingsPath>/custom/. v2.1 kept both at SettingsPath
  # root. Try the v2.2 subfolder first, fall back to the flat v2.1 location so
  # the engine boots cleanly against either layout.
  function _ResolveCatalogYaml([string]$relName, [string]$subfolder) {
    $sub = Join-Path (Join-Path $global:SettingsPath $subfolder) $relName
    if (Test-Path -LiteralPath $sub) { return $sub }
    return (Join-Path $global:SettingsPath $relName)
  }
  $lockedPath = _ResolveCatalogYaml $global:ReportSettingsFileLocked 'locked'
  $customPath = _ResolveCatalogYaml $global:ReportSettingsFileCustom 'custom'
  # v2.2.303 -- optional dev YAML for developer-only experimental queries.
  # Gitignored on purpose; not synced to customers via the publish workflow.
  # Merged BETWEEN locked and custom: locked -> dev -> custom (custom wins last).
  $devPath    = _ResolveCatalogYaml $global:ReportSettingsFileDev    'dev'

  if (-not (Test-Path -LiteralPath $lockedPath)) {
    throw "Locked YAML not found: $lockedPath"
  }

  $lockedYaml = Read-YamlFileOrNull -Path $lockedPath
  if ($null -eq $lockedYaml) {
    throw "Locked YAML was empty or could not be parsed: $lockedPath"
  }

  $devYaml    = Read-YamlFileOrNull -Path $devPath
  $customYaml = Read-YamlFileOrNull -Path $customPath

  # locked -> dev (dev overrides locked on name conflict)
  $afterDev = Merge-ReportSettings -LockedSettings $lockedYaml -CustomSettings $devYaml
  # afterDev -> custom (custom overrides anything below)
  $global:Report_Settings_raw = Merge-ReportSettings -LockedSettings $afterDev -CustomSettings $customYaml
  $global:Report_Settings     = ConvertTo-PSObjectDeep $global:Report_Settings_raw

  $lockedReportCount = @($lockedYaml.Reports).Count
  $lockedTplCount    = @($lockedYaml.ReportTemplates).Count
  $devReportCount    = if ($devYaml) { @($devYaml.Reports).Count } else { 0 }
  $devTplCount       = if ($devYaml) { @($devYaml.ReportTemplates).Count } else { 0 }
  $customReportCount = if ($customYaml) { @($customYaml.Reports).Count } else { 0 }
  $customTplCount    = if ($customYaml) { @($customYaml.ReportTemplates).Count } else { 0 }
  $mergedReportCount = @($global:Report_Settings_raw.Reports).Count
  $mergedTplCount    = @($global:Report_Settings_raw.ReportTemplates).Count

  Write-Info ("YAML merge: Locked Reports={0}/{1}, Dev Reports={2}/{3}, Custom Reports={4}/{5}, Merged Reports={6}/{7}" -f `
    $lockedReportCount, $lockedTplCount, $devReportCount, $devTplCount, $customReportCount, $customTplCount, $mergedReportCount, $mergedTplCount)

  $sources = @('locked')
  if ($devYaml)    { $sources += 'dev (developer-only, gitignored)' }
  if ($customYaml) { $sources += 'custom (customer override, wins last)' }
  Write-Ok ("report settings loaded ({0})" -f ($sources -join ' + '))
} catch { Write-Err2 "failed to read/parse report settings yaml: $($_.Exception.Message)"; throw }
Tick "yaml load"

$global:Exposure_Reports  = $global:Report_Settings.Reports
$global:Exposure_Template = $global:Report_Settings.ReportTemplates | Where-Object { $_.ReportName -eq $global:ReportTemplate }

if (-not $global:Exposure_Template) {
  throw "ReportTemplate '$($global:ReportTemplate)' not found in YAML under ReportTemplates."
}

$global:Exposure_Template_ReportsIncluded = $global:Exposure_Template.ReportsIncluded
if (-not $global:Exposure_Template_ReportsIncluded) {
  throw "ReportTemplate '$($global:ReportTemplate)' has no ReportsIncluded."
}

#------------------------------------------------------------------------------------------------------------
# Per-template mail override (optional fields in the template definition)
#------------------------------------------------------------------------------------------------------------
# Schema in the YAML (Locked or Custom):
#   - ReportName: RiskAnalysis_Detailed_Bucket
#     Mail_To:
#       - someone@yourdomain.com
#       - audit@yourdomain.com
#     Mail_SendMail: true       # optional; when present overrides the global toggle
#     ...
#
# When Mail_To / Mail_SendMail are present on the chosen template, they win over
# the globals resolved earlier (community $global:MailTo / AF $global:Mail_*_To).
# Useful when a particular template needs to be routed to different stakeholders.
$tplProps = @($global:Exposure_Template.PSObject.Properties | ForEach-Object { $_.Name })
if ('Mail_To' -in $tplProps -and $global:Exposure_Template.Mail_To) {
    $tplMailTo = @($global:Exposure_Template.Mail_To | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($tplMailTo.Count -gt 0) {
        $global:Report_To = $tplMailTo
        Write-Info ("Mail recipients overridden by template '{0}': {1}" -f $global:ReportTemplate, ($global:Report_To -join ', '))
    }
}
if ('Mail_SendMail' -in $tplProps -and $null -ne $global:Exposure_Template.Mail_SendMail) {
    $global:Report_SendMail = [bool]$global:Exposure_Template.Mail_SendMail
    Write-Info ("Mail send-flag overridden by template '{0}': SendMail={1}" -f $global:ReportTemplate, $global:Report_SendMail)
}

# Log resolved report names
$incNamesForLog = @()
foreach ($x in $global:Exposure_Template_ReportsIncluded) {
  $inc = Resolve-ReportInclude -Item $x
  $incNamesForLog += $inc.Name
}
Write-Info ("reports in template: {0}" -f ($incNamesForLog -join ', '))

# ---------- Risk Index --------------------------------------------------------------------
Write-Section "building risk index (CSV map)"

$global:CsvSecurityDomainColumnName        = 'SecurityDomain'
$global:CsvCategoryColumnName              = 'Category'
$global:CsvSubCategoryColumnName           = 'SubCategory'
$global:CsvConfigurationIdColumnName       = 'ConfigurationId'
$global:CsvSecuritySeverityColumnName      = 'SecuritySeverity'
$global:CsvCriticalityTierLevelColumnName  = 'CriticalityTierLevel'
$global:CsvConsequenceScoreColumnName      = 'RiskConsequenceScore_SecuritySeverity'
$global:CsvProbabilityScoreColumnName      = 'RiskProbablityScore_CriticialityTierLevel'

Tock
try {
  $global:RiskDefinitions = Import-Csv -Path $global:RiskDefinitionsCsvPath
  Write-Info ("risk rows: {0}" -f ($global:RiskDefinitions | Measure-Object | Select-Object -ExpandProperty Count))
} catch { Write-Err2 "cannot read risk definitions csv: $($_.Exception.Message)"; throw }

Tock
try {
  $global:RiskIndex = New-RiskIndex `
      -CsvRows $global:RiskDefinitions `
      -ColSecurityDomain       $global:CsvSecurityDomainColumnName `
      -ColCategory             $global:CsvCategoryColumnName `
      -ColSubCategory          $global:CsvSubCategoryColumnName `
      -ColConfigId             $global:CsvConfigurationIdColumnName `
      -ColSevValue             $global:CsvSecuritySeverityColumnName `
      -ColTierValue            $global:CsvCriticalityTierLevelColumnName `
      -ColConseqScore          $global:CsvConsequenceScoreColumnName `
      -ColProbScore            $global:CsvProbabilityScoreColumnName
  Write-Ok "risk index built"
} catch { Write-Err2 "failed to build risk index: $($_.Exception.Message)"; throw }
Tick "risk index build"

#######################################################################################################
# AUTO BUCKETING HELPERS (adaptive bucketing)
#######################################################################################################

# Per-run memo (StrictMode-safe)
if (-not (Get-Variable -Name AutoBucketMemo -Scope Script -ErrorAction SilentlyContinue)) {
    $script:AutoBucketMemo = @{}
}

# AUDIT #16: Adaptive bucketing: overflow/transient detection, the bucket-count cache and the challenger. Moved to _shared/RA-AutoBucketing.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-AutoBucketing.ps1')   # forward slash works on both Win + Linux

# AUDIT #57.1(a): run-over-run row-count regression guard. Loaded after AutoBucketing because it
# writes a sibling state file in the same OUTPUT folder. Moved to _shared/RA-RowCountGuard.ps1
. (Join-Path $PSScriptRoot '_shared/RA-RowCountGuard.ps1')   # forward slash works on both Win + Linux

# Per-report row counts for this run, filled in as each report finishes and compared against the
# previous run at the end. Absence is the thing SI keeps failing to notice (#48, v2.2.415, #57).
$global:RA_RowCountsThisRun = @{}

#####################################################################################################
# MAIN LOOP
#####################################################################################################

Write-Section "executing reports"

$global:AllShapedRows = New-Object System.Collections.Generic.List[object]
$global:FinalRiskScoreColumnName = $null
$global:FinalDesiredColumns = $null
# $global:final is read by JSON write, LA ingest, and AI summary AFTER the per-report
# loop. If a previous run left it populated and THIS run produces zero rows (every
# report failed -- e.g. KQL referencing a not-yet-provisioned table), the stale data
# would leak into JSON / LA / xlsx-AI-sheet, producing an xlsx whose only sheet is the
# AI summary rendered from yesterday's data. Reset to empty so the empty-result path
# is honest end-to-end.
$global:final = @()

# Collection timestamp + host identity -- same across every row in this run
# (every report, both Summary and Detailed) so the KQL filter
#   SI_RiskAnalysis_Summary_CL | where CollectionTime == toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime))
# returns exactly the most recent run's rows and nothing else.
# Mirrors IdentityAssetsCollectDefineTierIngestLog.ps1 line 1281.
[datetime]$global:RA_CollectionTime = ( Get-Date ([datetime]::Now.ToUniversalTime()) -Format "yyyy-MM-ddTHH:mm:ssK" )
try {
    $global:RA_DnsName = [System.Net.Dns]::GetHostEntry('').HostName
} catch {
    $global:RA_DnsName = $env:COMPUTERNAME
}

# SolutionVersion -- stamp which release of SecurityInsight produced this
# run's data. Lets Workbook / Power BI tiles show "dashboard powered by
# data ingested with v2.1.99" and lets ops answer "did my cron box update?"
# with a KQL `| distinct SolutionVersion` across the table.
$global:RA_SolutionVersion = '(dev)'
try {
    # v2.2.226 -- walk up from $PSScriptRoot FIRST. The walk naturally finds the
    # per-solution VERSION (e.g. SOLUTIONS/SecurityInsight/VERSION = "2.2.225")
    # before reaching the repo-root VERSION.txt -- which the bootstrap stamps
    # with a compound label like
    #   AutomateIT-internal-main-<sha> (solutions: PlatformConfiguration,
    #   PlatformMonitoring, SecurityInsight-v2.2.221) @ 2026-05-13T01:10:20
    # for sync tracking. That compound label was leaking into the engine's
    # SolutionVersion stamp (Excel header, email subject, LA row column) and
    # confusing operators -- they wanted just "2.2.225".
    # Old logic seeded $_candidateRoots with $global:RepoRoot/$global:InstallPath
    # FIRST, so the repo-root VERSION.txt was read before the walk-up reached
    # the per-solution file. Reordered: walk-up from $PSScriptRoot wins, root
    # VERSION.txt is the fallback only when no per-solution VERSION is found.
    $_cur = $PSScriptRoot
    while ($_cur) {
        foreach ($_name in @('VERSION','VERSION.txt')) {
            $_ver = Join-Path $_cur $_name
            if (Test-Path -LiteralPath $_ver) {
                $_raw = $null
                try { $_raw = (Get-Content -LiteralPath $_ver -Raw -ErrorAction Stop) } catch { }
                if ($_raw) { $_raw = $_raw.Trim() }
                if ($_raw) {
                    $global:RA_SolutionVersion = $_raw
                    break
                }
            }
        }
        if ($global:RA_SolutionVersion -ne '(dev)') { break }
        $_parent = Split-Path -Parent $_cur
        if (-not $_parent -or $_parent -eq $_cur) { break }
        $_cur = $_parent
    }
    # Fallback: explicit repo-root candidates if walk-up missed (e.g. engine
    # symlinked into an unusual layout). Same logic as before but only runs
    # when the per-solution VERSION wasn't discoverable.
    if ($global:RA_SolutionVersion -eq '(dev)') {
        $_candidateRoots = @()
        if ($global:RepoRoot)    { $_candidateRoots += [string]$global:RepoRoot }
        if ($global:InstallPath) { $_candidateRoots += [string]$global:InstallPath }
        foreach ($_r in $_candidateRoots) {
            foreach ($_name in @('VERSION','VERSION.txt')) {
                $_ver = Join-Path $_r $_name
                if (Test-Path -LiteralPath $_ver) {
                    $global:RA_SolutionVersion = (Get-Content -LiteralPath $_ver -Raw).Trim()
                    break
                }
            }
            if ($global:RA_SolutionVersion -ne '(dev)') { break }
        }
    }
} catch { }

# v2.2.363 -- announce the engine version at startup so operators can verify
# which release is actually running (not just which release the launcher loaded).
# Stamped values (Excel header, email subject, LA SolutionVersion column, etc.)
# all derive from $global:RA_SolutionVersion which was just populated above.
Write-Info ("SecurityInsight RiskAnalysis engine v{0} ({1})" -f $global:RA_SolutionVersion, $PSCommandPath)

foreach ($includeItem in $global:Exposure_Template_ReportsIncluded) {
  try {

    # v2.2.325 -- clear per-report bucket state at the TOP of every iteration
    # so non-bucketed reports never inherit (BucketCount, BucketIndex) leftover
    # from the previous report's last bucket. Without this, a non-bucketed
    # report following a 4-bucket report would silently re-inline only 1/4 of
    # its CL snapshot -- wrong results, no error.
    $script:_CurrentBucketCount      = 0
    $script:_CurrentBucketIndex      = 0
    $script:_CurrentReportIsDetailed = $false
    # v2.2.334 -- also reset the cross-domain EG-bucket-skip flag. Set by
    # Resolve-ProfileCLLetBlocks during the first probe of a cross-domain report;
    # if left set across reports, the next single-let report would incorrectly
    # leave EG unfiltered (wasted compute, correct results but slow).
    $script:_SkipEGBucketForCrossDomain = $false
    # AUDIT #24 -- per-report reset of the payload-bound signal the AutoBucket futility
    # check reads. Set by Resolve-ProfileCLLetBlocks on every call; cleared here so the
    # first probe of a report can never inherit the previous report's inline size.
    $script:_LastHybridInlineBytes = 0
    # v2.2.404 -- per-report crossDomainBucketCoalesce. Reset at the top of every
    # report so a coalesce declaration from a prior report never leaks. Populated
    # below from the report Entry; consumed by Resolve-ProfileCLLetBlocks /
    # New-BucketFilterKql to keep the EG-side bucket filter ACTIVE (bounded EG
    # work) for the 6 cross-domain Attack_Paths Summary reports whose CL bucket
    # key is DESIGNED-ALIGNED to an EG-native NodeId column (the CL value literally
    # equals the EG NodeId hex). Without it those reports fall back to the
    # conservative EG-filter-suppressed path (lossless but full-EG-scan per bucket
    # -> 900s HttpClient ceiling on large tenants). See the resolution block
    # in Resolve-ProfileCLLetBlocks (cross-domain detection).
    $script:_CrossDomainBucketCoalesce = @()

    $inc = Resolve-ReportInclude -Item $includeItem
    $ReportNameFromTemplate = $inc.Name

    $Entry = $global:Exposure_Reports | Where-Object { $_.ReportName -eq $ReportNameFromTemplate }

    if (-not $Entry) {
        Write-Warn2 ("report '{0}' defined in template but not found in report configurations" -f $ReportNameFromTemplate)
        continue
    }

    $ReportName                     = $Entry.ReportName
    $ReportPurpose                  = $Entry.ReportPurpose

    $SecurityDomain                 = $Entry.SecurityDomain
    $CategoryInputName              = $Entry.CategoryInputName
    $SubcategoryInputName           = $Entry.SubcategoryInputName
    $ConfigurationIdInputName       = $Entry.ConfigurationIdInputName

    $CriticalityTierLevelInputName  = $Entry.CriticalityTierLevelInputName
    $CriticalityTierLevelScope      = $Entry.CriticalityTierLevelScope

    $SecuritySeverityInputName      = $Entry.SecuritySeverityInputName
    $SecuritySeverityScope          = $Entry.SecuritySeverityScope

    $RiskConsequenceScoreOutputName = $Entry.RiskConsequenceScoreOutputName
    $RiskProbabilityScoreOutputName = $Entry.RiskProbabilityScoreOutputName
    $RiskScoreOutputName            = $Entry.RiskScoreOutputName

    $OutputPropertyOrder            = $Entry.OutputPropertyOrder
    $SortBy                         = $Entry.SortBy

    $Query                          = $Entry.ReportQuery

    # v2.2.404 -- read the per-report crossDomainBucketCoalesce declaration. Shape:
    #   crossDomainBucketCoalesce:
    #     - ClColumn: Target_AzureResourceId_Guid   # the CL-side projection-aliased bucket key
    #       EgNativeKey: NodeId                       # the EG-native column it equals (NodeId hex)
    # Each entry asserts the CL bucket-key value IS the EG NodeId for matched rows,
    # so the SHA256 partition is identical on both sides -> EG bucket filter can
    # stay active (bounded) AND per-bucket CL/EG subsets align (lossless). Missing
    # / empty = legacy behaviour (EG filter suppressed for cross-domain CL keys).
    if ($Entry.PSObject.Properties['crossDomainBucketCoalesce'] -and $Entry.crossDomainBucketCoalesce) {
        $script:_CrossDomainBucketCoalesce = @($Entry.crossDomainBucketCoalesce)
        $_cdcCols = @($script:_CrossDomainBucketCoalesce | ForEach-Object {
            if ($_ -is [System.Collections.IDictionary]) { [string]$_['ClColumn'] }
            elseif ($_.PSObject.Properties['ClColumn'])   { [string]$_.ClColumn }
            else { [string]$_ }
        }) | Where-Object { $_ }
        if ($_cdcCols.Count -gt 0) {
            Write-Info ("[crossdomain] report '{0}' declares EG-aligned CL bucket key(s): {1} -- EG-side bucket filter stays ACTIVE (bounded EG work)." -f $ReportName, ($_cdcCols -join ', '))
        }
    }

    # Bucketing resolution: bucketing parameters are now hardcoded constants.
    # Per-Report ReportTemplate.UseBucketFilter / BucketCount may still narrow
    # behaviour for a specific report; those legacy fields remain honoured.
    $effectiveUseBucket   = $true
    # v2.2.279 -- *_Detailed reports default to 32 (was 2). Detailed reports emit
    # one row per (asset, finding) tuple with no upstream dedup, so cartesian
    # blow-up is structural -- starting at 2 means 4-5 escalation rounds before
    # converging on most non-trivial tenants. Default 32 + sub-bucketing on
    # residual heavy buckets reaches a working count immediately on first run
    # for the vast majority of cases. Per-report YAML BucketCount still wins;
    # customer can also drop with $global:SI_AutoBucketDefaultDetailed.
    # v2.2.306 -- Detailed default lowered from 32 to 2. The 32 default was a blanket
    # assumption that all Detailed reports cartesian-explode (4-hop EG path expansion
    # historically did). Graph-match shape doesn't cartesian, so 32 buckets x ~55s
    # each just to return ~32 rows = 30 min of pure overhead. AutoBucket can still
    # escalate past 2 if the probe shows compute hitting AH's ceiling. Customer can
    # override via $global:SI_AutoBucketDefaultDetailed or per-report BucketCount.
    $effectiveBucketCount = if ($ReportNameFromTemplate -like '*_Detailed*' -or $ReportNameFromTemplate -like '*_Detailed_*') {
        if ($global:SI_AutoBucketDefaultDetailed) { [int]$global:SI_AutoBucketDefaultDetailed } else { 2 }
    } else { 2 }
    $effectivePlaceholder = '__BUCKET_FILTER__'

    if ($Entry.PSObject.Properties['UseBucketFilter'] -and $Entry.UseBucketFilter -ne $null) {
        $effectiveUseBucket = [bool]$Entry.UseBucketFilter
    }
    if ($Entry.PSObject.Properties['BucketCount'] -and $Entry.BucketCount) {
        $bc = [int]$Entry.BucketCount
        if ($bc -gt 0) { $effectiveBucketCount = $bc }
    }

    # Print the per-report header BEFORE placeholder/weighted-factor resolution so the
    # `[exclude]` and `[weight]` log lines emitted by those helpers visually attach to the
    # correct report instead of trailing under the previous report's section.
    Write-Phase -Title ("REPORT :: {0}" -f $ReportName) -Subtitle $ReportPurpose

    # -----------------------------------------------------------------------------------------
    # FULL FIX: make the KQL AssetName-safe BEFORE we decide bucketing and BEFORE execution
    # -----------------------------------------------------------------------------------------
    $Query = Ensure-QueryIsAssetNameSafe -Query $Query

    # substitute __EXCLUDED_CVES__ / __EXCLUDED_CONFIGURATION_IDS__ / __EXCLUDED_ASSET_TAGS__
    # placeholders from <ReportName>.exclude.json (if present). See helper block
    # near New-BucketFilterKql for accepted JSON shapes + token map.
    # __EXCLUDED_ASSET_TAGS__ ALSO falls through to <SettingsPath>/RiskAnalysisGlobalExclusions.custom.json
    # when the per-report file doesn't carry that property.
    $Query = Resolve-ExcludePlaceholders -Query $Query -ReportName $ReportName

    # substitute __CVE_MIN_AGE_DAYS__ scalar placeholder from <ReportName>.exclude.custom.json
    # (CveMinAgeDays property; default 0 = no age filter). See $script:_ScalarTokenMap.
    $Query = Resolve-ScalarPlaceholders -Query $Query -ReportName $ReportName

    # v2.2.203 -- substitute __CVE_FILTER__ block from $global:SI_CVE_* globals.
    # Cuts the CVE-finding set at source (severity / cvssScore / hasExploit /
    # publishedDate) BEFORE the EG join expands rows by edges and assets.
    $Query = Resolve-CveFilterBlock -Query $Query -ReportName $ReportName

    # v2.2.282 -- substitute __STALE_DEVICE_FILTER__ block from
    # $global:SI_RA_StaleDeviceFilter (off|lenient|strict) + $global:SI_ActiveStaleDays.
    # When a tenant has many EG ghost device nodes (Defender knows them by ID
    # but never enriched lastSeen), strict mode drops them at the DeviceNodes
    # let -- shrinks the cartesian on Attack_Paths_*_Device queries by 30-50%
    # without losing any real-risk signal. Default 'off' = backwards compatible.
    $Query = Resolve-StaleDeviceFilterBlock -Query $Query -ReportName $ReportName

    # substitute __WEIGHTED_FACTORS__ block from
    # riskscore_weighted.schema.custom.json -> weightedRiskFactors.<engine>.fields.
    # Engine determined from report's SecurityDomain. Engine code generates the
    # iff()+multiplier+detail KQL from JSON; query stays rule-agnostic. See
    # helper block near Add-DeviceKeyBeforeBucketBlock.
    # Read $Entry.SecurityDomain directly (the local $SecurityDomain isn't
    # assigned until the report-template block further down).
    $weightEngine = if ($Entry.PSObject.Properties['SecurityDomain'] -and $Entry.SecurityDomain) {
                        ([string]$Entry.SecurityDomain).ToLowerInvariant()
                    } else { 'endpoint' }
    $Query = Resolve-WeightedFactorsBlock -Query $Query -ReportName $ReportName -Engine $weightEngine

    # If bucketing is used and the query has the bucket-filter block, ensure
    # DeviceKey exists before the block (so the bucket filter can hash on it).
    $Query = Add-DeviceKeyBeforeBucketBlock -Query $Query
    $querySupportsBucket = Test-QueryHasBucketFilterBlock -Query $Query

    $ResultAll = @()

    if ($effectiveUseBucket -and $querySupportsBucket -and $effectiveBucketCount -gt 1) {

        # AutoBucket: try bucketCount=1 first, then increase until the query succeeds.
        # MaxBucketCount is allowed to grow beyond the configured BucketCount for this report,
        # up to AutoBucketMax (if set). This is required when BucketCount=2 still exceeds result size.
        $capBucket = [int]$effectiveBucketCount
        if ([int]$global:AutoBucketMax -gt 0) {
          $capBucket = [Math]::Max($capBucket, [int]$global:AutoBucketMax)
        }
        if ($capBucket -lt 1) { $capBucket = 1 }

        # v2.2.330 -- REMOVE-ME-IN-NEXT-RELEASE. Temporary opt-in debug knob.
        # OFF by default ($reportCap = 0) so production tenants never silently
        # cap. While the per-report join-key parser is being built, operators
        # can set `$global:AutoBucketReportCap = 256` to make cross-domain
        # reports (Attack_Paths_*_Github_to_Azure, _Public_IP_to_VM, etc. --
        # the ones whose EG-side bucket coalesce doesn't align with the CL-
        # side join key) bail at the cap instead of escalating 2->8->...->
        # 131072 forever. Delete this block (and the AutoBucketReportCap
        # global entirely) once the join-key parser lands and aligns the
        # bucket math properly for those reports.
        $reportCap = if ($null -ne $global:AutoBucketReportCap) {
            [int]$global:AutoBucketReportCap
        } else { 0 }
        if ($reportCap -gt 0 -and $capBucket -gt $reportCap) {
            $capBucket = $reportCap
            Write-Info ("AutoBucket report cap ACTIVE (debugging): '{0}' escalation capped at {1} buckets (set `$global:AutoBucketReportCap=0 to disable)." -f $ReportName, $reportCap)
        }

        $bucketCountToUse = $effectiveBucketCount

        if ([bool]$global:AutoBucketCount) {

          # Cache key: report name + STABLE hash of the PRE-BUCKET query.
          # NOTE:
          #  - We intentionally do NOT include MaxBucketCount/cap in the cache key.
          #  - We hash the query BEFORE bucket filter injection so the identity remains stable.
          #  - We do NOT use string.GetHashCode() for the primary identity because it is not
          #    stable across PowerShell sessions/processes.
          $queryForHash = $Query
          $queryForHashNorm = ($queryForHash -replace '\s+', ' ').Trim()
          $stableHash = Get-StableQueryHash32 -Text $queryForHashNorm
          $legacyHash = [Math]::Abs(($queryForHashNorm.GetHashCode()))

          $queryKey = ("{0}|{1}" -f $ReportName, $stableHash)
          $legacyKey = ("{0}|{1}" -f $ReportName, $legacyHash)

          if ([bool]$global:DebugQueryHash) {
            Write-Info ("AutoBucket hash identity for '{0}': stable={1}, legacy={2}" -f $ReportName, $stableHash, $legacyHash)
            try {
              $dbgDir = Join-Path (Join-Path $global:SettingsPath 'OUTPUT') 'Debug'
              if (-not (Test-Path -LiteralPath $dbgDir)) { New-Item -Path $dbgDir -ItemType Directory -Force | Out-Null }
              $safeName = ($ReportName -replace '[^a-zA-Z0-9_.-]', '_')
              $dbgPath = Join-Path $dbgDir ("QueryHash_{0}_{1}.kql" -f $safeName, $stableHash)
              Set-Content -LiteralPath $dbgPath -Value $queryForHash -Encoding UTF8
              Write-Info ("AutoBucket hash debug query written: {0}" -f $dbgPath)
            } catch { }
          }

          # v2.2.325 -- track whether this report is *_Detailed so the inner
          # CL-bucketing path in Invoke-GraphHuntingQuery / Resolve-ProfileCLLetBlocks
          # can skip Detailed (composite-key EG buckets don't align with single-
          # key CL row buckets, so CL filtering would drop join-matching rows).
          $script:_CurrentReportIsDetailed = ($ReportName -like '*_Detailed' -or $ReportName -like '*_Detailed_*')

          $probe = {
            param([int]$BucketCount)

            # v2.2.325 -- probe must see the SAME inline payload size that the
            # real per-bucket call will see; otherwise AutoBucket over-escalates
            # (a 2.4MB-per-bucket probe failure pushes counts to 122K+ while
            # actual per-bucket sends would be 60KB at N=40). Set script-scope
            # bucket state so Invoke-GraphHuntingQuery's CL-bucketing kicks in.
            $script:_CurrentBucketCount = $BucketCount
            $script:_CurrentBucketIndex = 0
            # AUDIT #24 -- clear the payload-bound signal so the futility check reads THIS
            # rung's inline size. Left set, a large body from an earlier rung would keep
            # the report looking payload-bound and the ramp would run on.
            $script:_LastHybridInlineBytes = 0
            try {
                # Probe only bucket 0. If this bucket still exceeds limits, smaller buckets are needed.
                $bucketFilter = New-BucketFilterKql -BucketCount $BucketCount -BucketIndex 0 -ReportName $ReportName
                $probeQuery   = Replace-BucketFilterBlock -Query $Query -BucketFilterKql $bucketFilter

                $null = Invoke-GraphHuntingQuery -Query $probeQuery `
                  -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes `
                  -MaxRetries 1
            } finally {
                $script:_CurrentBucketCount = 0
                $script:_CurrentBucketIndex = 0
            }
          }

          try {
            # v2.2.281 -- pass YAML BucketCount as the AutoBucket probe FLOOR. Without
            # this AutoBucket starts every probe at bucketCount=1 and doubles upward,
            # so an explicit `BucketCount: 64` in YAML still costs five wasted ~900s
            # probe attempts (1, 2, 4, 8, 16, 32) before reaching the configured count.
            # The floor lets a tenant operator say "you don't need to try less than 64"
            # while still allowing escalation past 64 when 64 itself overflows.
            # AUDIT #24 futility guard -- "splitting cannot help this report, stop ramping".
            # Passed as a scriptblock rather than a value because NEITHER input exists yet:
            # both are produced by Resolve-ProfileCLLetBlocks DURING a probe, so
            # Get-OptimalBucketCount evaluates this between rungs, which is the earliest
            # moment the answer exists. Cost is therefore one ceiling timeout -- what this
            # report class already paid before #24. Without it the ramp burned 16 rungs /
            # 242 min on one report and still failed.
            $bucketCountToUse = Get-OptimalBucketCount -QueryKey $queryKey -LegacyKeys @($legacyKey) -MaxBucketCount $capBucket -MinBucketCount $effectiveBucketCount -ProbeScript $probe `
              -FutilityCheck {
                # 1. EG-side bucket filter suppressed to keep a cross-domain join lossless:
                #    every sub-query still does the FULL Exposure-Graph work, so no bucket
                #    count can succeed. Same conclusion FUTILE-PRUNE reaches on the run side.
                if ([bool]$script:_SkipEGBucketForCrossDomain) {
                  return 'the EG-side bucket filter is suppressed to keep a cross-domain join lossless, so every sub-query still does the FULL Exposure-Graph work'
                }

                # 2. PAYLOAD-BOUND vs EG-BOUND. This is the case that actually produced the
                #    242-minute runaway -- and #24 mis-recorded it as case 1; the run log
                #    shows the EG filter STAYED ACTIVE for that report (it declares
                #    crossDomainBucketCoalesce). Its inline body was 25,996 bytes at rung 1
                #    and 868 by rung 6, yet every rung still hit the 900s ceiling. When the
                #    body is already a small fraction of the 1MB nginx cap, the body is not
                #    what timed out, so halving it again cannot help. A report that
                #    genuinely needs a higher count is still payload-bound here (large
                #    body), so it keeps escalating. 0 = no inline payload (2-phase path):
                #    signal absent, stay out of the way.
                $inlineBytes = [int]$script:_LastHybridInlineBytes
                $floor = if ($global:AutoBucketPayloadBoundFloorBytes) { [int]$global:AutoBucketPayloadBoundFloorBytes } else { 65536 }
                if ($inlineBytes -gt 0 -and $inlineBytes -lt $floor) {
                  return ("the inline payload was only {0} bytes (floor {1}), so this query is EG-BOUND, not payload-bound -- halving the body again cannot bring it under the query-time ceiling" -f $inlineBytes, $floor)
                }

                return $false
              }
          } catch {
            Write-Warn2 ("AutoBucket failed for report '{0}'. Falling back to configured BucketCount={1}. Error: {2}" -f `
              $ReportName, $effectiveBucketCount, $_.Exception.Message)
            $bucketCountToUse = $effectiveBucketCount
          }
        }

        if ($bucketCountToUse -lt 1) { $bucketCountToUse = 1 }

        
# -------------------------------------------------------------------------------------------------
# Buckets execution with escalation:
# If ANY bucket fails due to deterministic overflow/limits/timeout, re-run the WHOLE report with
# a higher bucket count (e.g., 4 -> 8) until success or cap is reached.
# -------------------------------------------------------------------------------------------------

$bucketRunSucceeded = $false
$lastBucketRunError = $null

# v2.2.198 -- per-report flag: once a bucket exhausts ALL inner+outer retries
# with TaskCanceledException only (deterministic 900s timeout), skip remaining
# buckets in this report rather than burn another 6 hours on each. Reset per
# report run so other reports start clean.
$script:_AutoBucketSkipRemainingBuckets = $false

# v2.2.370 -- DELETED per-report resets for the three hybrid measurement vars
# (_LastHybridSnapshotRowCount, _LastHybridBytesPerRow, _LastHybridQueryBodyOverheadBytes).
# Reasoning: resetting per-report meant each new report's first escalation had
# NO measurement data and fell back to bucketCount*4 growth (8 -> 32 -> 128 ...
# burning ~150s pre-group per attempt). Reports sharing a let-binding (e.g.
# Device_Missing_CVEs_Summary + Device_Recommendations_Summary both inline
# the _ep snapshot) should inherit prior measurements -- the snapshot is
# IDENTICAL across them via $script:_HybridSnapshotCache. The original
# v2.2.362 concern (narrow-row report polluting wide-row report) is moot:
# (a) we max-track within a run, so the inherited value is always >= what's
# needed, biasing toward MORE buckets, never fewer; (b) over-bucketing
# wastes a few buckets but never causes 413, which is the asymmetric cost
# that mattered. Vars are now run-scoped MAX trackers, set in
# Resolve-ProfileCLLetBlocks. First-report-of-run still falls back to the
# 170-byte/200KB defaults until the first inline lands a real measurement.

# v2.2.325 -- always start each report with bucket-state cleared so that
# non-bucketed report runs (and the first-iteration "is it Detailed" check)
# never inherit coordinates from the previous report's last bucket.
$script:_CurrentBucketCount = 0
$script:_CurrentBucketIndex = 0

# v2.2.380 -- adversarial fitting cache: per-report record of the actual
# rows-per-bucket value that the XDR backend rejected with nginx 413. Used by
# the escalation block as a hard ceiling on the next rows-per-bucket budget
# (cap = 0.7 x failed_value), so each escalation step learns from real
# overflow data instead of multiplying buckets blindly. Keyed by ReportName
# because per-row width + surrounding KQL body vary per report -- a failure
# in report A doesn't predict report B. Run-scoped (memoize across reports
# in the same run), report-scoped lookup.
if ($null -eq $script:_LastFailedRowsPerBucketByReport) {
    $script:_LastFailedRowsPerBucketByReport = @{}
}

while (-not $bucketRunSucceeded) {

  # Reset results on each (re)run so we don't keep partial data from a failing bucket count
  $ResultAll = @()

  Write-Info ("query contains placeholder '{0}' and bucketing is enabled. Using {1} bucket(s)." -f $effectivePlaceholder,$bucketCountToUse)

  $needEscalation = $false
  # v2.2.277 -- track buckets that timed out at 900s deterministically. Instead
  # of throwing away ALL successful buckets and restarting at higher bucket
  # count (the v2.2.272 escalation), record failed indices and sub-bucket only
  # those after the main loop. Lossless; preserves successful buckets' rows.
  $failedBucketIndices = New-Object System.Collections.Generic.List[int]

  for ($b = 0; $b -lt $bucketCountToUse; $b++) {

      if ($script:_AutoBucketSkipRemainingBuckets) {
          Write-Warn2 ("bucket {0}/{1}: skipping (prior bucket deterministically timed out at 900s on every attempt -- remaining buckets would do the same)." -f ($b + 1), $bucketCountToUse)
          continue
      }

      $bucketNo = $b + 1
      $bucketFilter = New-BucketFilterKql -BucketCount $bucketCountToUse -BucketIndex $b -ReportName $ReportName
      $thisQuery    = Replace-BucketFilterBlock -Query $Query -BucketFilterKql $bucketFilter

      # v2.2.325 -- publish current bucket coordinates so the CL-bucketing
      # branch inside Resolve-ProfileCLLetBlocks (called from Invoke-GraphHuntingQuery)
      # filters the inline _ep / _id / _az snapshot to only the rows whose
      # SHA256-bucket matches THIS EG bucket. Without these vars set the
      # legacy path reused the full snapshot per bucket, so escalation past
      # ~30 buckets accomplished nothing (CL body, not EG body, was the cap-buster).
      $script:_CurrentBucketCount = $bucketCountToUse
      $script:_CurrentBucketIndex = $b

      Write-Info ("bucket {0}/{1}: running query (auto-routed: LA-direct or XDR Advanced Hunting based on table mix)" -f $bucketNo, $bucketCountToUse)
      Tock

      # Per-bucket retry loop. Inner Invoke-GraphHuntingQuery already retries on
      # short transient errors (default 4 attempts via $global:GraphQueryMaxRetries);
      # this OUTER loop adds a longer-cycle retry+re-auth pass for the case where
      # the inner retry exhausted on a still-transient signal -- usually:
      #   - Az / Graph access token expired mid-run (long RA jobs commonly outlive 1h tokens)
      #   - Defender Graph backend hiccup (502/503/504, gateway timeout)
      #   - Throttle that the inner backoff didn't escape
      # Each outer attempt re-authenticates BOTH Graph AND Az before retrying the
      # same bucket; only escalate bucket count on TRUE overflow signals.
      $bucketTransientRetries = if ($null -ne $global:SI_BucketTransientRetries) {
          [int]$global:SI_BucketTransientRetries
      } else { 3 }
      # v2.2.199 -- the XDR backend's "Query execution has exceeded the allowed
      # limits ... preempted ... possibly due to high CPU and/or memory resource
      # consumption" error is OFTEN transient backend pressure, not real data
      # overflow. Treating the first occurrence as a hard "double the buckets
      # and restart" signal threw away already-successful buckets (e.g. on a
      # 63-bucket run, buckets 1-2 returned 30K rows before bucket 3 preempted
      # -- restarting at 126 buckets ran from scratch). Retry the SAME bucket
      # up to N times with backoff before escalating; if real overflow, all
      # retries will also overflow and escalation still happens.
      $bucketOverflowRetries  = if ($null -ne $global:SI_BucketOverflowRetries) {
          [int]$global:SI_BucketOverflowRetries
      } else { 3 }
      $bucketAttempt          = 0
      $bucketOverflowAttempt  = 0
      $bucketAttemptDone      = $false
      $resp                   = $null

      while (-not $bucketAttemptDone) {
          $bucketAttempt++
          try {
              $resp = Invoke-GraphHuntingQuery -Query $thisQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
              Tick ("hunting query bucket {0}/{1}" -f $bucketNo, $bucketCountToUse)
              $bucketAttemptDone = $true
          } catch {
              $errMsg = $_.Exception.Message

              # 1) Overflow -> retry SAME bucket N times before escalating. The XDR
              # backend's "preempted ... high CPU/memory" is often transient load,
              # not real data overflow. Only escalate when we've seen the overflow
              # repeatedly for THIS bucket.
              if (Test-IsBucketOverflowError $_) {
                  $bucketOverflowAttempt++
                  if ($bucketOverflowAttempt -lt $bucketOverflowRetries) {
                      $sleepSec = [Math]::Min(180, 30 * [Math]::Pow(2, ($bucketOverflowAttempt - 1)))   # 30s, 60s, 120s
                      # v2.2.324 -- reframed from "overflow/preempted" WARN to a
                      # neutral sizing-pass INFO. Engine is just calibrating; not
                      # a customer-actionable error.
                      Write-Info ("bucket {0}/{1}: re-probing with current shard size (attempt {2}/{3}, pausing {4}s)." -f `
                        $bucketNo, $bucketCountToUse, $bucketOverflowAttempt, $bucketOverflowRetries, $sleepSec)
                      Start-Sleep -Seconds $sleepSec
                      # Loop continues; same bucket retried at same bucketCountToUse.
                  } else {
                      $lastBucketRunError = $errMsg
                      # v2.2.380 -- record actual rows-per-bucket that failed,
                      # so the escalation block can size the NEXT attempt from
                      # real overflow data instead of guessing (option C).
                      $_snapshot = if ($script:_LastHybridSnapshotRowCount) { [int]$script:_LastHybridSnapshotRowCount } else { 0 }
                      if ($_snapshot -gt 0 -and $bucketCountToUse -gt 0) {
                          $_failedRpb = [int][Math]::Ceiling($_snapshot / [double]$bucketCountToUse)
                          $script:_LastFailedRowsPerBucketByReport[$ReportName] = $_failedRpb
                          Write-Info ("bucket {0}/{1}: shard too large after {2} probes (~{3} rows/bucket failed); recording for adversarial escalation -- increasing shard count and re-running report." -f `
                            $bucketNo, $bucketCountToUse, $bucketOverflowRetries, $_failedRpb)
                      } else {
                          Write-Info ("bucket {0}/{1}: shard too large after {2} probes -- increasing shard count and re-running report." -f `
                            $bucketNo, $bucketCountToUse, $bucketOverflowRetries)
                      }
                      $needEscalation    = $true
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
              }
              # 2) Transient platform error -> re-auth (Az + Graph) and retry SAME bucket.
              elseif (Test-IsTransientPlatformError $_) {
                  # v2.2.198 -- if the inner function reports every attempt timed out
                  # at the 900s HttpClient ceiling, this isn't transient -- the query
                  # genuinely can't run within Graph's deadline on this tenant.
                  # v2.2.272 -- BEFORE giving up, ESCALATE bucket count (smaller per-bucket
                  # workload). Only when escalation has already reached $capBucket do we
                  # fall back to the v2.2.198 skip-remaining behaviour. This unblocks heavy
                  # EG-path-expansion reports on large estates (Attack_Paths_*_
                  # Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure)
                  # that previously got stuck at cached BucketCount=2 forever.
                  if ($script:_LastGraphHuntingAllTimedOut) {
                      # v2.2.277 -- ADAPTIVE SUB-BUCKETING. The v2.2.272 behavior
                      # restarted the whole report at 4x bucket count when ANY
                      # bucket timed out, throwing away all already-completed
                      # buckets. Worse: at scale (e.g. 100K-edge tenants)
                      # the escalation never converges -- each level just shifts
                      # WHICH single bucket happens to be the heavy one, and the
                      # restart cost compounds (~30 min/level x many levels = days).
                      # New strategy: record this bucket index, continue with the
                      # next bucket, and after the main loop split JUST the failed
                      # buckets into K=4 sub-buckets via hash%(T*K) filtering.
                      # Sub-buckets that also time out get recursively split (depth
                      # cap 4, controllable via $global:SI_AutoBucketSubDepthMax).
                      # Lossless; preserves successful buckets' rows entirely.
                      Write-Warn2 ("bucket {0}/{1}: 900s deterministic timeout -- queueing for sub-bucket pass after main loop completes (won't restart whole report). Error: {2}" -f `
                        $bucketNo, $bucketCountToUse, $errMsg)
                      [void]$failedBucketIndices.Add($b)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
                  elseif ($bucketAttempt -ge $bucketTransientRetries) {
                      Write-Err2 ("bucket {0}/{1}: transient platform error after {2} retry attempt(s) -- skipping bucket and continuing. Error: {3}" -f `
                        $bucketNo, $bucketCountToUse, $bucketTransientRetries, $errMsg)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  } else {
                      $sleepSec = [Math]::Min(180, 30 * [Math]::Pow(2, ($bucketAttempt - 1)))   # 30s, 60s, 120s
                      Write-Warn2 ("bucket {0}/{1}: transient platform error (likely token expiry / 503 / throttle). Re-auth + retry attempt {2}/{3} after {4}s. Error: {5}" -f `
                        $bucketNo, $bucketCountToUse, $bucketAttempt, $bucketTransientRetries, $sleepSec, $errMsg)
                      Start-Sleep -Seconds $sleepSec
                      # Re-authenticate BOTH Graph and Az (the most common transient root cause).
                      try { Connect-GraphHighPriv } catch { Write-Warn2 ("Graph reconnect failed: {0}" -f $_.Exception.Message) }
                      try {
                          if (Get-Command -Name 'Connect-AzAccount' -ErrorAction SilentlyContinue) {
                              if ($global:SpnClientId -and $global:SpnClientSecret -and $global:SpnTenantId) {
                                  $secStr = ConvertTo-SecureString -String ([string]$global:SpnClientSecret) -AsPlainText -Force
                                  $cred   = New-Object System.Management.Automation.PSCredential ([string]$global:SpnClientId, $secStr)
                                  $null   = Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant ([string]$global:SpnTenantId) -ErrorAction Stop -WarningAction SilentlyContinue
                              } elseif ($global:SpnClientId -and $global:SpnCertificateThumbprint -and $global:SpnTenantId) {
                                  $null = Connect-AzAccount -ServicePrincipal -ApplicationId ([string]$global:SpnClientId) -CertificateThumbprint ([string]$global:SpnCertificateThumbprint) -Tenant ([string]$global:SpnTenantId) -ErrorAction Stop -WarningAction SilentlyContinue
                              }
                          }
                      } catch { Write-Warn2 ("Az reconnect failed (non-fatal -- the bucket may still complete on Graph creds): {0}" -f $_.Exception.Message) }
                      # Loop continues; bucketAttempt now incremented, retry same bucket.
                  }
              }
              # 3) Anything else -> log + skip bucket (existing behaviour).
              else {
                  Write-Err2 ("query failed for bucket {0}/{1}: {2}" -f $bucketNo, $bucketCountToUse, $errMsg)
                  $bucketAttemptDone = $true
                  $resp              = $null
              }
          }
      }

      if ($needEscalation) { break }
      if ($null -eq $resp) { continue }   # bucket skipped (transient exhausted or other error)

      # v2.1.202 LA-direct marker check (see matching block further down / Invoke-GraphHuntingQuery).
      if ($null -ne $resp -and $resp -is [pscustomobject] -and $resp.PSObject.Properties['_SIDirectRows']) {
          $bucketResult = @($resp._SIDirectRows)
          if (@($bucketResult).Count -eq 0) {
              Write-Info ("bucket {0}/{1}: no results" -f $bucketNo, $bucketCountToUse)
              continue
          }
      } else {
          $rawResults = $null
          if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }

          if ($null -eq $rawResults) {
              Write-Info ("bucket {0}/{1}: no results" -f $bucketNo, $bucketCountToUse)
              continue
          }

          Tock
          try {
              $bucketResult = ConvertTo-PSObjectDeep $rawResults -StripOData -CastPrimitiveArrays
          } catch {
              Write-Err2 ("result conversion failed for bucket {0}/{1}: {2}" -f $bucketNo, $bucketCountToUse, $_.Exception.Message)
              continue
          }
      }
      $bucketCount  = ($bucketResult | Measure-Object).Count
      Tick ("result conversion (bucket {0}/{1})" -f $bucketNo, $bucketCountToUse)

      Write-Info ("bucket {0}/{1}: {2} rows" -f $bucketNo, $bucketCountToUse, $bucketCount)
      foreach ($row in $bucketResult) { $ResultAll += ,$row }
  }

  if ($needEscalation) {

      if ($bucketCountToUse -ge $capBucket) {
          Write-Err2 ("bucket escalation reached cap {0}. Unable to complete report '{1}'. Last error: {2}" -f `
            $capBucket, $ReportName, $lastBucketRunError)
          break
      }

      # v2.2.273 -- 4x growth (was 2x), but ALSO consider the largest CL snapshot
      # row count seen during this report.
      # v2.2.361 -- size buckets empirically to a target fraction of the nginx 1MB
      # cap based on MEASURED bytes-per-row, instead of the hardcoded 500 rows/bucket
      # constant that was 8-10x too conservative for typical ~170 bytes/row payloads.
      # v2.2.362 -- per-report reset + MAX-tracking of bytesPerRow + 90% inline target.
      # v2.2.364 -- account for FULL request body, not just inline. v2.2.362 saw 931KB
      # inline (89%) + ~150KB surrounding KQL body still 413 at 91 buckets because the
      # 1MB cap is on the FULL request body (inline + KQL + URL params). Now budget:
      #     inline_budget = total_budget - measured_body_overhead
      # where measured_body_overhead is the surrounding-KQL bytes captured by
      # Resolve-ProfileCLLetBlocks (= modified.Length - totalInlineBytes). Both
      # bytesPerRow and bodyOverhead are tracked as MAX-seen-this-report.
      # v2.2.380 -- three changes:
      #   A1) budget target 95% -> 75% of 1MB. 95% left only ~52KB for HTTP
      #       headers, Bearer tokens, JSON-string-escape inflation of inline
      #       payload, per-bucket variance. Empirically the smart calc was
      #       under-budgeting and reports still 413'd on the first attempt;
      #       75% leaves a comfortable 256KB margin.
      #   A2) bytesPerRow x 1.15 to model JSON-escape inflation on the wire.
      #       Inline bytes measured by Resolve-ProfileCLLetBlocks are raw KQL
      #       string length; the HTTP POST body wraps that KQL as a JSON string
      #       field where every \" -> \\\", \\n -> \\\\n etc, typical 10-15%.
      #   B)  growth floor 4x -> 2x. The 4x floor used to bypass the smart calc
      #       entirely when current bucket count was small; now the smart calc
      #       (informed by A1+A2 + adversarial ceiling below) is allowed to win.
      #   C)  adversarial ceiling. If a prior escalation cycle THIS RUN already
      #       recorded a rows-per-bucket value that the XDR backend rejected
      #       for THIS report, cap the next rows-per-bucket at 0.7 x failed
      #       value -- i.e. the smart calc may say "1500 rows/bucket fits" but
      #       if reality just disproved 5877, we know 1500 is overly optimistic
      #       and clamp to floor(0.7 * 5877) = 4114 instead. Converges in 2 hops
      #       on average instead of the prior 4x leap that overshot drastically.
      $snapshotJump = 0
      if ($script:_LastHybridSnapshotRowCount -and [int]$script:_LastHybridSnapshotRowCount -gt 0) {
          # nginx Log Ingestion cap = 1MB total request body. Target 75% leaves
          # 25% (~256KB) for URL params, HTTP headers + Bearer token (8-16KB),
          # JSON-string-escape inflation of inline payload, per-bucket variance.
          $totalBudget      = [int](1MB * 0.75)
          # Measured overhead from prior inline calls; fallback to 200KB until first
          # measurement (conservative -- real overhead is typically 100-200KB).
          $bodyOverhead     = if ($script:_LastHybridQueryBodyOverheadBytes -gt 0) { [int]$script:_LastHybridQueryBodyOverheadBytes } else { 200KB }
          $inlineBudget     = [int][Math]::Max(64KB, $totalBudget - $bodyOverhead)
          # Inline bytes-per-row from prior inline calls (max-tracked). Fallback 170 (median observed).
          # JSON-escape multiplier 1.15 models the wire-bytes inflation of the
          # raw inline KQL when wrapped as a JSON string field in the HTTP POST.
          $bytesPerRowRaw   = if ($script:_LastHybridBytesPerRow -gt 0) { [double]$script:_LastHybridBytesPerRow } else { 170.0 }
          $bytesPerRow      = $bytesPerRowRaw * 1.15
          $rowsPerBucket    = [int][Math]::Max(1, [Math]::Floor($inlineBudget / $bytesPerRow))
          # Adversarial ceiling: if THIS report previously 413'd at a known
          # rows-per-bucket, cap rowsPerBucket at 0.7 x that value.
          if ($script:_LastFailedRowsPerBucketByReport.ContainsKey($ReportName)) {
              $_failedRpb = [int]$script:_LastFailedRowsPerBucketByReport[$ReportName]
              $_advCap    = [int][Math]::Floor(0.7 * [double]$_failedRpb)
              if ($_advCap -gt 0 -and $_advCap -lt $rowsPerBucket) {
                  $rowsPerBucket = $_advCap
              }
          }
          $snapshotJump     = [int][Math]::Ceiling([int]$script:_LastHybridSnapshotRowCount / [double]$rowsPerBucket)
      }
      $jumpCandidates = @(($bucketCountToUse * 2), ($bucketCountToUse + 1), $snapshotJump)
      $nextBucket = [Math]::Min($capBucket, ($jumpCandidates | Measure-Object -Maximum).Maximum)
      if ($snapshotJump -gt 0 -and $snapshotJump -ge ($bucketCountToUse * 2)) {
          $_bpr   = if ($script:_LastHybridBytesPerRow -gt 0) { [int]$script:_LastHybridBytesPerRow } else { 170 }
          $_bov   = if ($script:_LastHybridQueryBodyOverheadBytes -gt 0) { [int]$script:_LastHybridQueryBodyOverheadBytes } else { 200KB }
          $_ib    = [int][Math]::Max(64KB, [int](1MB * 0.75) - $_bov)
          $_rpb   = [int][Math]::Max(1, [Math]::Floor($_ib / ($_bpr * 1.15)))
          $_advTag = if ($script:_LastFailedRowsPerBucketByReport.ContainsKey($ReportName)) {
              (' [adversarial ceiling: prior failure {0} rows/bucket -> cap {1}]' -f $script:_LastFailedRowsPerBucketByReport[$ReportName], [int][Math]::Floor(0.7 * [double]$script:_LastFailedRowsPerBucketByReport[$ReportName]))
          } else { '' }
          Write-Info ("AutoBucket escalation jump informed by snapshot + measured row-width + JSON-escape x1.15 + body overhead ({0} rows / {1} rows-per-bucket; budget: {2}KB inline + {3}KB KQL-body = {4}KB total, 75% of nginx 1MB cap; row-width ~{5} bytes/row x 1.15 = {6} buckets){7}" -f $script:_LastHybridSnapshotRowCount, $_rpb, [int]($_ib/1KB), [int]($_bov/1KB), [int](([int](1MB * 0.75))/1KB), $_bpr, $snapshotJump, $_advTag)
      }

      Write-Info ("Shard sizing: '{0}' increasing shard count {1} -> {2} (auto-tuning for this report's payload)." -f `
        $ReportName, $bucketCountToUse, $nextBucket)

      $bucketCountToUse = [int]$nextBucket
      continue
  }

  # v2.2.277 -- ADAPTIVE SUB-BUCKETING PASS. After the main bucket loop has
  # attempted every bucket index, any indices that hit the deterministic 900s
  # timeout (TaskCanceled or 502) are queued in $failedBucketIndices. Split
  # each into K=4 sub-buckets via hash%(T*K) filter (= 1/K of the parent
  # bucket's rows per sub-query, lossless). Sub-buckets that ALSO time out
  # get recursively split up to depth $subDepthMax (default 4 = up to 256x
  # finer than the original BucketCount, so a 64-bucket start can shrink a
  # heavy slice to 1/16384 of total). This preserves the successful buckets'
  # results entirely; we never re-run them.
  if ($failedBucketIndices.Count -gt 0) {
      # v2.2.279 -- depth cap raised 4 -> 6 (modulus up to 4096 x original
      # BucketCount). Customer's the customer run hit the depth=4 cap with one
      # slice still timing out; deeper splits give the recursive partition
      # more room before giving up. Tunable via $global:SI_AutoBucketSubDepthMax.
      $subDepthMax = if ($null -ne $global:SI_AutoBucketSubDepthMax) { [int]$global:SI_AutoBucketSubDepthMax } else { 6 }
      $subFanOut   = if ($null -ne $global:SI_AutoBucketSubFanOut)   { [int]$global:SI_AutoBucketSubFanOut }   else { 4 }

      # v2.2.357 -- ADAPTIVE FUTILE-PARENT PRUNING. Some reports use cross-domain
      # join keys (e.g. Target_AzureResourceId_Guid) that aren't in the EG-side
      # bucket coalesce list. The hybrid path SUPPRESSES the EG-side bucket
      # filter for those (line ~1063, $script:_SkipEGBucketForCrossDomain) so
      # joins stay lossless -- but the consequence is that EACH sub-bucket
      # still does full EG work + slightly smaller CL inline. The work isn't
      # being split where it counts, so all children of an EG-suppressed parent
      # time out the SAME way as the parent.
      #
      # Pure logic fix (no arbitrary depth limit): when ALL $subFanOut children
      # of a parent time out at 900s, that's empirical proof that splitting
      # this slice further won't help -- the work isn't being distributed.
      # Don't enqueue any grandchildren from that parent. Sibling parents whose
      # children DID succeed continue normally.
      #
      # Effect on EG-suppressed reports: capped at depth=1 (one futile attempt
      # to learn it's futile). 2 original buckets * 4 sub-buckets * 900s = 2h
      # max instead of the depth-6 worst case of 113 days.
      # Effect on normal reports: unchanged -- futile-prune only fires when
      # 100% of children timeout, which doesn't happen when splitting actually
      # distributes work.
      $parentTimeoutCount = @{}     # key="$pN/$pT/$depth"  ->  int (count of timed-out children)
      $prunedSubtreeCount = 0

      # v2.2.363 -- EARLY-ABORT FUTILE SUB-BUCKET PASS. When EG-side bucket
      # filter is suppressed for this report (cross-domain key not in EG
      # coalesce list) AND 100% of the outer buckets timed out at 900s,
      # the sub-bucket pass is provably futile from the start: sub-bucketing
      # the CL inline doesn't reduce EG work (the actual bottleneck), and
      # the parent-level evidence already proves the EG side can't complete
      # within 900s for any partition of this snapshot. Skip the entire
      # sub-bucket pass instead of burning ~60min per parent (4 children *
      # 900s) to re-prove what we already know.
      #
      # Same logic family as v2.2.357 (empirical futile-prune of grandchildren),
      # one level earlier: instead of waiting for 4/4 children to timeout per
      # parent, use (EG-suppression flag) + (100% outer-bucket failure) as
      # combined proof.
      #
      # If only SOME outer buckets failed (e.g. 2/8), the EG work IS bounded
      # enough for some partitions -- still try sub-bucketing the failing ones
      # since they MIGHT split usefully; v2.2.357 futile-prune still catches
      # the per-parent futile cases at depth=1.
      $allOuterFailedWithEgSuppressed = ([bool]$script:_SkipEGBucketForCrossDomain -and $failedBucketIndices.Count -eq [int]$bucketCountToUse)
      if ($allOuterFailedWithEgSuppressed) {
          Write-Warn2 ("AutoBucket sub-bucketing pass SKIPPED for report '{0}' -- EG-side bucket filter is suppressed for this report (cross-domain join key) AND 100% of outer buckets ({1}/{1}) timed out at 900s. Sub-bucketing the CL inline cannot reduce EG-side work (the bottleneck), so attempting it would burn ~{2}min per parent (~{3}min total) to re-prove what we already know. Report ships with {4} row(s) from successful buckets (likely 0). To service this report at this customer's scale, the YAML query needs a per-report rewrite that moves `summarize by` from cmdb* columns to EG-native columns + post-augments CL data client-side." -f $ReportName, $failedBucketIndices.Count, ($subFanOut * 15), ($failedBucketIndices.Count * $subFanOut * 15), $ResultAll.Count)
          $failedBucketIndices.Clear()
          # Fall through past the BFS pass; report finishes immediately with whatever successful buckets produced.
      } else {

      $egSuppressedHint = if ([bool]$script:_SkipEGBucketForCrossDomain) {
          ' -- NOTE: EG-side bucket filter was suppressed for this report (cross-domain join key). Sub-bucketing may not distribute work; futile-prune will engage if all children timeout.'
      } else { '' }
      Write-Warn2 ("AutoBucket sub-bucketing pass: {0} bucket(s) timed out at BucketCount={1}; splitting each into {2} sub-buckets per pass (max depth {3}). Successful buckets retained ({4} rows so far).{5}" -f `
        $failedBucketIndices.Count, $bucketCountToUse, $subFanOut, $subDepthMax, $ResultAll.Count, $egSuppressedHint)

      # BFS queue: each item = @{ N = parent-index; T = parent-total; D = current-depth; PK = parentKey-from-grandparent }
      $subQueue = New-Object System.Collections.Generic.Queue[object]
      foreach ($idx in $failedBucketIndices) {
          $subQueue.Enqueue(@{ N = [int]$idx; T = [int]$bucketCountToUse; D = 1; PK = $null })
      }

      while ($subQueue.Count -gt 0) {
          $item    = $subQueue.Dequeue()
          $pN      = [int]$item.N
          $pT      = [int]$item.T
          $depth   = [int]$item.D
          $newT    = $pT * $subFanOut
          # parent-key identifies THIS parent across its own children below
          $thisParentKey = ('{0}/{1}/{2}' -f $pN, $pT, $depth)

          for ($j = 0; $j -lt $subFanOut; $j++) {
              $subN       = $pN + ($j * $pT)
              $subFilter  = New-SubBucketFilterKql -ParentBucketCount $pT -ParentBucketIndex $pN -SubBucketCount $subFanOut -SubBucketIndex $j -ReportName $ReportName
              $subQuery   = Replace-BucketFilterBlock -Query $Query -BucketFilterKql $subFilter

              Write-Info ("[sub-bucket] depth={0} parent={1}/{2}: running sub {3}/{4} (effective index {5}/{6})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subN, $newT)
              $script:_LastGraphHuntingAllTimedOut = $true   # reset; Invoke-GraphHuntingQuery flips it false on non-timeout failure or success
              try {
                  $subResp = Invoke-GraphHuntingQuery -Query $subQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries

                  $subRows = @()
                  if ($null -ne $subResp -and $subResp -is [pscustomobject] -and $subResp.PSObject.Properties['_SIDirectRows']) {
                      $subRows = @($subResp._SIDirectRows)
                  } elseif ($null -ne $subResp -and $null -ne $subResp.Results -and $null -ne $subResp.Results.AdditionalProperties) {
                      try {
                          $subRows = @(ConvertTo-PSObjectDeep $subResp.Results.AdditionalProperties -StripOData -CastPrimitiveArrays)
                      } catch {
                          Write-Err2 ("[sub-bucket] result conversion failed for sub {0}/{1} (parent={2}/{3} depth={4}): {5}" -f ($j + 1), $subFanOut, $pN, $pT, $depth, $_.Exception.Message)
                      }
                  }
                  Write-Info ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4}: {5} rows" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subRows.Count)
                  foreach ($row in $subRows) { $ResultAll += ,$row }
              } catch {
                  $subErr = $_.Exception.Message
                  if ($script:_LastGraphHuntingAllTimedOut) {
                      # Track timeout count for THIS parent. When all $subFanOut children
                      # have timed out, the parent is "futile" -- skip enqueueing grandchildren.
                      if (-not $parentTimeoutCount.ContainsKey($thisParentKey)) { $parentTimeoutCount[$thisParentKey] = 0 }
                      $parentTimeoutCount[$thisParentKey] = [int]$parentTimeoutCount[$thisParentKey] + 1
                  }
                  if ($script:_LastGraphHuntingAllTimedOut -and $depth -lt $subDepthMax) {
                      Write-Warn2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} timed out -- queueing for further split (depth {5})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, ($depth + 1))
                      $subQueue.Enqueue(@{ N = $subN; T = $newT; D = ($depth + 1); PK = $thisParentKey })
                  } elseif ($script:_LastGraphHuntingAllTimedOut) {
                      Write-Err2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} timed out at MAX DEPTH {5} -- giving up on this slice (rows in this sub-bucket NOT included). Error: {6}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $depth, $subErr)
                  } else {
                      Write-Err2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} failed (non-timeout): {5}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subErr)
                  }
              }
          }

          # v2.2.357 -- after all $subFanOut children of THIS parent have been
          # attempted, check the futile-prune trigger. If ALL children timed out,
          # purge any of this parent's grandchildren that were just enqueued.
          # Logic: splitting didn't help at this level, so splitting deeper
          # provably won't help either (the work isn't being distributed by
          # the bucket filter; usually because EG-side filter is suppressed).
          if ($parentTimeoutCount.ContainsKey($thisParentKey) -and [int]$parentTimeoutCount[$thisParentKey] -ge $subFanOut) {
              # Filter the queue: remove any grandchildren whose PK == thisParentKey.
              $purgedQueue = New-Object System.Collections.Generic.Queue[object]
              $purgedCount = 0
              while ($subQueue.Count -gt 0) {
                  $q = $subQueue.Dequeue()
                  if ([string]$q.PK -eq [string]$thisParentKey) { $purgedCount++ } else { $purgedQueue.Enqueue($q) }
              }
              while ($purgedQueue.Count -gt 0) { $subQueue.Enqueue($purgedQueue.Dequeue()) }
              if ($purgedCount -gt 0) {
                  $prunedSubtreeCount += $purgedCount
                  Write-Warn2 ("[sub-bucket] FUTILE-PRUNE: parent={0}/{1} depth={2} -- all {3}/{3} children timed out at 900s; splitting deeper won't help (bucket filter not distributing work). Pruned {4} grandchildren that would have produced 0 rows. Successful sibling-parent rows retained." -f $pN, $pT, $depth, $subFanOut, $purgedCount)
              }
          }
      }
      if ($prunedSubtreeCount -gt 0) {
          Write-Warn2 ("[sub-bucket] pass complete; total rows after sub-bucketing: {0}. Note: {1} futile sub-bucket attempts skipped (would have cost {2} minutes of additional 900s timeouts). Report has structural cardinality skew on the bucket key -- consider re-keying via the YAML's `crossDomainBucketCoalesce:` block if available." -f $ResultAll.Count, $prunedSubtreeCount, ($prunedSubtreeCount * 15))
      } else {
          Write-Info ("[sub-bucket] pass complete; total rows after sub-bucketing: {0}" -f $ResultAll.Count)
      }
      }   # v2.2.363 -- close `else` branch of $allOuterFailedWithEgSuppressed
  }

  # Success: all buckets executed (sub-bucketing pass handled any deterministic
  # timeouts). Even if some sub-bucket slices were given up at max depth, the
  # report is considered "as complete as possible" -- no point restarting.
  $bucketRunSucceeded = $true
}

# If we succeeded with a higher bucket count than the initial AutoBucket probe, update memo/cache so next run starts smarter.
if ($bucketRunSucceeded -and [bool]$global:AutoBucketCount) {
  try {
    $script:AutoBucketMemo[$queryKey] = [int]$bucketCountToUse
    if ([bool]$global:AutoBucketCache -and -not [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
      $cachePath2 = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
      $cache2 = Read-AutoBucketCache -Path $cachePath2
      if ($null -eq $cache2) { $cache2 = @{} }
      $cache2[$queryKey] = [int]$bucketCountToUse
      # v2.2.383 Layer 3 -- stamp confirmedAt for the end-of-run cascade write
      # too. This is the path where the engine escalated past the cached
      # value (e.g. cache said 62, run cascaded to 130). The new value is
      # battle-tested via an actual full report run, so the confirmation
      # is even stronger than the probe-path confirmation.
      $_cacheRefL3 = [ref]$cache2
      Set-AutoBucketConfirmed -Cache $_cacheRefL3 -QueryKey $queryKey
      $cache2 = $_cacheRefL3.Value
      Write-AutoBucketCache -Path $cachePath2 -CacheObject $cache2
    }
  } catch { }
}
        # $ResultAll = @(Deduplicate-Rows -Rows $ResultAll)
        $ResultAll = @($ResultAll)   # enforce array
        Write-Info ("total rows across all buckets: {0}" -f $ResultAll.Count)

    } else {

        if ($effectiveUseBucket -and -not $querySupportsBucket) {
            Write-Warn2 ("bucketing enabled but query does not contain placeholder '{0}'. Running single query." -f $effectivePlaceholder)
        }

        Tock
        try {
            Write-Info "running query (auto-routed: LA-direct or XDR Advanced Hunting based on table mix)"
            $resp = Invoke-GraphHuntingQuery -Query $Query -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
            Tick "hunting query"
        } catch {
            Write-Err2 "query failed: $($_.Exception.Message)"
            continue
        }

        # v2.1.202 -- the LA-direct routing in Invoke-GraphHuntingQuery ships rows in a marker
        # property (_SIDirectRows) because the Microsoft-Graph-shaped response shape
        # (.Results.AdditionalProperties broadcast + ConvertTo-PSObjectDeep) doesn't round-trip
        # cleanly for PSCustomObject rows coming from Invoke-AzOperationalInsightsQuery --
        # 1-row results ended up with the data nested in SyncRoot and only the first column
        # leaking through property broadcast. If the marker is present, use those rows directly.
        if ($null -ne $resp -and $resp -is [pscustomobject] -and $resp.PSObject.Properties['_SIDirectRows']) {
            $ResultSingle = @($resp._SIDirectRows)
            if (@($ResultSingle).Count -eq 0) {
                Write-Info "Query returned no results"
                continue
            }
            Tick "result conversion"
        } else {
            $rawResults = $null
            if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }
            if ($null -eq $rawResults) {
                Write-Info "Query returned no results"
                continue
            }

            Tock
            try {
                $ResultSingle = ConvertTo-PSObjectDeep $rawResults -StripOData -CastPrimitiveArrays
            } catch {
                Write-Err2 "result conversion failed: $($_.Exception.Message)"
                continue
            }
            Tick "result conversion"
        }

        foreach ($row in $ResultSingle) { $ResultAll += ,$row }
        Write-Info ("rows before filters: {0}" -f $ResultAll.Count)
    }

if ($ResultAll.Count -eq 0) {
        Write-Info "No rows returned from query"
        # AUDIT #57.1(a) -- RECORD THE ZERO **BEFORE** THIS `continue`.
        # 🪤 The first cut of this guard captured only at "rows after filters", below. This early
        # exit skips that entirely, so a report that produced NOTHING was the one case never
        # recorded -- i.e. the guard would have missed #57, the exact defect it was built for.
        # Caught by smoke-running it instead of trusting the unit tests. A zero is not the absence
        # of a measurement; it IS the measurement, and it is the one that matters most.
        if ($null -ne $global:RA_RowCountsThisRun) {
            $global:RA_RowCountsThisRun[[string]$ReportName] = 0
        }
        continue
    }

    # Filters
    $ResultFiltered = @($ResultAll)

    $EnableFilterAudit = $false
    if (Get-Variable -Name EnableFilterAudit -Scope Global -ErrorAction SilentlyContinue) {
        $EnableFilterAudit = [bool]$global:EnableFilterAudit
    }
    $FilteredOut = @()

    $filterSpecs = @(
      @{ Name="CriticalityTierLevel"; Column=$CriticalityTierLevelInputName; Scope=$CriticalityTierLevelScope },
      @{ Name="SecuritySeverity";     Column=$SecuritySeverityInputName;     Scope=$SecuritySeverityScope }
    )

    Tock
    # Skip filter step entirely when the upstream query returned 0 rows
    # (e.g. SI_VulnerabilityPIP_CL not yet populated, or any report whose
    # source table is missing/empty). Filter-ObjectsByColumn rejects empty
    # InputObject as a parameter binding error, which used to kill the
    # whole script when the per-report iteration had no try/catch wrapper.
    if ($null -eq $ResultFiltered -or @($ResultFiltered).Count -eq 0) {
        Write-Info "no rows from query; skipping filters + scoring for this report (continuing with next report)"
        continue
    }
    foreach ($fs in $filterSpecs) {
      if ($null -eq $fs.Column -or [string]::IsNullOrWhiteSpace([string]$fs.Column)) { continue }
      if ($null -eq $fs.Scope -or @($fs.Scope).Count -eq 0) { continue }
      # Guard each filter call -- a previous filter may have reduced the
      # result to zero rows, which Filter-ObjectsByColumn rejects as a
      # parameter-binding error (terminating). Bail out of the filter loop
      # cleanly; downstream code already handles the 0-row case.
      if (@($ResultFiltered).Count -eq 0) {
          Write-Info ("filter '{0}' skipped -- 0 rows remain after prior filters" -f $fs.Name)
          break
      }

      if ($EnableFilterAudit) {
        $r = Filter-ObjectsByColumn -InputObject @($ResultFiltered) -ColumnToFilter $fs.Column -InScopeData @($fs.Scope) -CaseInsensitive -IncludeBlank:$true -ReturnAudit -FilterName $fs.Name
        $ResultFiltered = @($r.Kept)
        $FilteredOut += @($r.Removed)
      } else {
        $ResultFiltered = @(Filter-ObjectsByColumn -InputObject @($ResultFiltered) -ColumnToFilter $fs.Column -InScopeData @($fs.Scope) -CaseInsensitive -IncludeBlank:$true -FilterName $fs.Name)
      }
    }

    $totalAfter = ($ResultFiltered | Measure-Object).Count
    Tick "apply filters"
    Write-Info ("rows after filters:  {0}" -f $totalAfter)

    # AUDIT #57.1(a) -- record the post-filter count for the run-over-run guard. Post-filter, not
    # raw, because that is the number that reaches the customer's export and Log Analytics.
    if ($null -ne $global:RA_RowCountsThisRun) {
        $global:RA_RowCountsThisRun[[string]$ReportName] = [int]$totalAfter
    }

    if ($EnableFilterAudit -and $FilteredOut.Count -gt 0) {
      Write-Info ("filtered away (out-of-scope only; blanks are kept): {0}" -f $FilteredOut.Count)

      $summary = $FilteredOut | Group-Object "__FilterReason" | Sort-Object Count -Descending | Select-Object Count, Name
      foreach ($s in $summary) { Write-Info ("  {0} - {1}" -f $s.Count, $s.Name) }

      try {
        $auditDir = Join-Path (Join-Path $global:SettingsPath 'OUTPUT') 'Debug'
        if (-not (Test-Path $auditDir)) { New-Item -ItemType Directory -Path $auditDir -Force | Out-Null }
        $safeReport = ($ReportName -replace '[^a-zA-Z0-9_.-]', '_')
        $auditPath = Join-Path $auditDir ("{0}_filtered_out.csv" -f $safeReport)
        $FilteredOut | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $auditPath
        Write-Info ("filter audit exported: {0}" -f $auditPath)
      } catch {
        Write-Warn2 ("failed to export filter audit: {0}" -f $_.Exception.Message)
      }
    }


    if ($totalAfter -eq 0) {
      Write-Info "No rows after filtering"
      continue
    }

    # Risk calc
    Tock
    Write-Info "calculating risk scores"
    $RiskScoreArray = Calculate-RiskScore `
      -Rows @($ResultFiltered) `
      -RiskIndex $global:RiskIndex `
      -SecurityDomain $SecurityDomain `
      -CategoryInputName $CategoryInputName `
      -SubCategoryInputName $SubcategoryInputName `
      -ConfigurationIdInputName $ConfigurationIdInputName `
      -SecuritySeverityInputName $SecuritySeverityInputName `
      -CriticalityTierLevelInputName $CriticalityTierLevelInputName `
      -SecurityDomainInputName 'SecurityDomain' `
      -OutputPropertyOrder $OutputPropertyOrder `
      -SortBy @($SortBy) -Descending `
      -RiskConsequenceScoreOutputName $RiskConsequenceScoreOutputName `
      -RiskProbabilityScoreOutputName $RiskProbabilityScoreOutputName `
      -RiskScoreOutputName $RiskScoreOutputName `
      -ReportName $ReportName
    Tick "risk scoring"

    # -------------------------------------------------------------------------
    # TraceName + TraceID -- applied IMMEDIATELY after risk scoring, BEFORE the
    # column-shaping / Select below, so the two columns are part of the base
    # row shape for everything downstream: excel, json, and (crucially) the
    # schema sample that CheckCreateUpdate-TableDcr-Structure uses to declare
    # the Log Analytics custom table's columns. If this block runs after
    # Select-Object, the LA schema never learns about the columns and the
    # module's Build-DataArrayToAlignWithSchema silently drops them at ingest.
    #
    # TraceName = "<ConfigurationName>--<SecuritySeverity>--<CriticalityTierLevel>--SI"
    #   Separator is '--' (double dash) so values that already contain a single
    #   dash (e.g. "Critical - tier 0", "Medium - tier 2") stay unambiguously
    #   readable when the four parts are joined. The trailing '--SI' tag marks
    #   the finding as produced by this SecurityInsight solution, matching the
    #   same suffix used on Defender asset tags (e.g. 'DomainControllerDNS--tier0--SI')
    #   so aggregators and downstream consumers can filter by source system.
    # TraceID   = first 16 hex chars of SHA256(TraceName_lowercased_utf8)
    # Deterministic -- same inputs always produce the same ID across runs, so
    # downstream consumers (management reports, ServiceNow, KQL history
    # queries) can group by TraceID to track a finding over time.
    # -------------------------------------------------------------------------
    $__sha = [System.Security.Cryptography.SHA256]::Create()
    # Detect Detailed reports by presence of an AssetName column â€” Detailed reports project
    # one row per asset, Summary reports aggregate above the asset level. Used below to
    # decide whether TraceName includes the AssetName segment.
    $isDetailedShape = $false
    if ($RiskScoreArray -and $RiskScoreArray.Count -gt 0) {
        $firstRow = $RiskScoreArray[0]
        if ($firstRow -and $firstRow.PSObject.Properties['AssetName']) { $isDetailedShape = $true }
    }
    try {
        foreach ($row in @($RiskScoreArray)) {
            $cfgName  = if ($row.PSObject.Properties['ConfigurationName']) { [string]$row.ConfigurationName } else { '' }
            $sev      = if ($row.PSObject.Properties['SecuritySeverity'])  { [string]$row.SecuritySeverity }  else { '' }
            $cmdbName = if ($row.PSObject.Properties['cmdbName'])          { [string]$row.cmdbName }          else { '' }
            $assetN   = if ($row.PSObject.Properties['AssetName'])         { [string]$row.AssetName }         else { '' }
            # TraceName composition (single-dash separator, only non-empty parts joined):
            #   Summary  + cmdb : <ConfigurationName>-<SecuritySeverity>-<cmdbName>-SI
            #   Detailed + cmdb : <ConfigurationName>-<SecuritySeverity>-<cmdbName>-<AssetName>-SI
            #   Summary  no cmdb: <ConfigurationName>-<SecuritySeverity>-SI
            #   Detailed no cmdb: <ConfigurationName>-<SecuritySeverity>-<AssetName>-SI
            $parts = @($cfgName, $sev)
            if (-not [string]::IsNullOrWhiteSpace($cmdbName)) { $parts += $cmdbName }
            if ($isDetailedShape -and -not [string]::IsNullOrWhiteSpace($assetN)) { $parts += $assetN }
            $parts += 'SI'
            $traceName = (($parts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '-')
            $traceId = ''
            if (-not [string]::IsNullOrWhiteSpace($traceName)) {
                $bytes   = [System.Text.Encoding]::UTF8.GetBytes($traceName.ToLowerInvariant())
                $hash    = $__sha.ComputeHash($bytes)
                $traceId = ([System.BitConverter]::ToString($hash) -replace '-','').Substring(0, 16).ToLowerInvariant()
            }
            Add-Member -InputObject $row -NotePropertyName 'CollectionTime'  -NotePropertyValue $global:RA_CollectionTime  -Force
            Add-Member -InputObject $row -NotePropertyName 'SolutionVersion' -NotePropertyValue $global:RA_SolutionVersion -Force
            Add-Member -InputObject $row -NotePropertyName 'TraceName'       -NotePropertyValue $traceName                 -Force
            Add-Member -InputObject $row -NotePropertyName 'TraceID'        -NotePropertyValue $traceId                  -Force
        }
    } finally { if ($__sha) { $__sha.Dispose() } }

    # Shape columns. ALL engine-set columns added to ComputedCols so they're
    # guaranteed in DesiredColumns regardless of what the first $RiskScoreArray
    # row happens to expose via Get-Member. Without this, reports whose first
    # row lacks (e.g.) RiskScoreTotal_Weighted as a note-property silently lose
    # the column for the WHOLE Excel sheet (the per-row write at _setScores
    # succeeds but the Select-Object filter drops it). AssetDetectedInReportName
    # is auto-added so every row carries the source ReportName (hunt-back).
    $ComputedCols = @(
        $RiskConsequenceScoreOutputName,
        $RiskProbabilityScoreOutputName,
        $RiskScoreOutputName,
        'RiskScoreTotal_Weighted',
        'RiskScore_Weight_Factor',
        'RiskScore_Weight_Detailed',
        'RiskFactor_Consequence',
        'RiskFactor_Consequence_Detailed',
        'RiskFactor_Probability',
        'RiskFactor_Probability_Detailed',
        'AssetDetectedInReportName'
    )
    $TraceCols    = @('CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID')    # always the LAST four columns -- not in any YAML OutputPropertyOrder on purpose

    $DesiredColumns = @()
    if ($OutputPropertyOrder) { $DesiredColumns += ($OutputPropertyOrder | Where-Object { $_ -notin $TraceCols }) }
    foreach ($c in $ComputedCols) { if ($DesiredColumns -notcontains $c -and $c -notin $TraceCols) { $DesiredColumns += $c } }

    # System.Array members that must never leak into the desired-columns list.
    # If any upstream stage ever lets a wrapped-array row reach here (v2.1.199 / v2.1.202
    # had a bug where pure-LA rows were stored as a System.Array containing the real rows),
    # Get-Member on that array could surface these as note properties via pipeline auto-
    # unwrap behavior. Blacklist guarantees they never end up in the Excel column list.
    $systemArrayProps = @('Count','IsFixedSize','IsReadOnly','IsSynchronized','Length','LongLength','Rank','SyncRoot')

    # AUDIT #26 -- discover the columns from the UNION of every row, not from row 1.
    #
    # Advanced-Hunting rows are rebuilt from the Graph additional-properties bag
    # (RA-GraphHunting.ps1:448, `foreach ($k in $r.AdditionalProperties.Keys)`), and that
    # bag OMITS null-valued columns. So a column that merely happens to be empty on the
    # first row was absent from $firstObj, never entered $DesiredColumns, and was then
    # dropped by the Select-Object below -- out of the xlsx, the JSON sibling AND the Log
    # Analytics ingest, for the whole report. A column declared in the YAML
    # OutputPropertyOrder is safe (added above regardless); RemediationOptions /
    # RecommendedAction were NOT declared when this was written, so they depended on
    # first-row luck. That is the "remediation data missing" symptom, and it explains why
    # it was intermittent rather than total.
    # ⚠️ HISTORICAL example only: #26 part 2 (5904f0f6) declared both, and a catalog sweep
    # on 2026-08-07 found no report emitting an undeclared remediation column. The union
    # still matters -- it covers every OTHER undeclared column.
    #
    # Cost is one pass over the rows -- see Get-RAColumnUnion (_shared/RA-ExcelReport.ps1)
    # for the measurements and for why it is deliberately not capped.
    $unionProps = Get-RAColumnUnion -Rows $RiskScoreArray

    $firstObj = $RiskScoreArray | Select-Object -First 1
    $firstRowProps = if ($firstObj) { @(($firstObj | Get-Member -MemberType NoteProperty).Name) } else { @() }
    $rescued = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $unionProps) {
      if ($DesiredColumns -notcontains $p -and $p -notin $TraceCols -and $p -notin $systemArrayProps) {
        $DesiredColumns += $p
        if ($p -notin $firstRowProps) { [void]$rescued.Add($p) }
      }
    }
    if ($rescued.Count -gt 0) {
      # Name them: these are exactly the columns the old row-1 discovery would have lost.
      Write-Info ("[columns] '{0}': {1} column(s) recovered that are absent from row 1 -- {2}" -f `
        $ReportName, $rescued.Count, (($rescued | Sort-Object) -join ', '))
    }

    # No engine post-hoc reorder of RiskFactor_Consequence_Detailed -- YAML's
    # OutputPropertyOrder is the single source of truth (canonical Detailed/
    # Summary shape standardized v2.2.175 places _Detailed BEFORE the count).

    # Re-position weight-score columns immediately AFTER RiskScoreTotal so the four
    # related columns sit together in this order:
    #   RiskScoreTotal
    #   RiskScore_Weight_Factor    -- the multiplier (KQL extend)
    #   RiskScore_Weight_Detailed  -- per-rule contribution string
    #   RiskScoreTotal_Weighted    -- RiskScoreTotal * RiskScore_Weight_Factor (sort key)
    # Same problem as Consequence_Detailed -- KQL extends append at the tail unless
    # explicitly relocated.
    $weightCols = @('RiskScore_Weight_Factor','RiskScore_Weight_Detailed','RiskScoreTotal_Weighted')
    if (($DesiredColumns -contains 'RiskScoreTotal') -and (@($weightCols | Where-Object { $DesiredColumns -contains $_ }).Count -gt 0)) {
        $rebuilt = New-Object System.Collections.Generic.List[string]
        foreach ($c in $DesiredColumns) {
            if ($weightCols -contains $c) { continue }
            [void]$rebuilt.Add($c)
            if ($c -eq 'RiskScoreTotal') {
                foreach ($wc in $weightCols) {
                    if ($DesiredColumns -contains $wc) { [void]$rebuilt.Add($wc) }
                }
            }
        }
        $DesiredColumns = $rebuilt.ToArray()
    }

    # Pin TraceName + TraceID as the last two columns -- stable identifier
    # pair, expected at the end of every report in xlsx / json / LA.
    foreach ($t in $TraceCols) { $DesiredColumns += $t }

    $Shaped = $RiskScoreArray | Select-Object -Property $DesiredColumns

    # Ensure RiskScore is numeric
    $Shaped = $Shaped | ForEach-Object {
      if ($_.$RiskScoreOutputName -isnot [double]) {
        $num = 0.0
        [void][double]::TryParse([string]($_.$RiskScoreOutputName), [ref]$num)
        $_.$RiskScoreOutputName = $num
      }
      $_
    }

    # TraceName + TraceID were already stamped on every row immediately after
    # Calculate-RiskScore (see the block above the "Shape columns" section).
    # Their names are carried in $OutputPropertyOrder via the YAML, so they've
    # landed in $DesiredColumns and survived the Select-Object above.

    if (-not $global:FinalRiskScoreColumnName -and -not [string]::IsNullOrWhiteSpace($RiskScoreOutputName)) {
        $global:FinalRiskScoreColumnName = $RiskScoreOutputName
    }
    # AUDIT #26, SECOND INSTANCE -- the finding named only the row-1 discovery above, but
    # the same mistake is made once more at the report level, and this one decides what the
    # operator actually opens. Every report's rows go into ONE 'Details' sheet, and
    # Export-Worksheet filters it with a STRICT `Select-Object -Property $DesiredColumns`
    # (RA-ExcelReport.ps1:124). Keeping only the FIRST report's list therefore dropped any
    # column unique to a later report from the workbook -- even after the row-1 fix above
    # put it safely in the row pool. Measured on the last real run
    # (OUTPUT/RiskAnalysis_Summary.json): the pool carried 48 distinct columns while row 1
    # had 46, so AssetName and AssetType were lost from the delivered xlsx.
    # Union across reports instead, in first-seen order.
    if (-not $global:FinalDesiredColumns) {
        $global:FinalDesiredColumns = @($DesiredColumns)
    } else {
        $mergedCols = New-Object 'System.Collections.Generic.List[string]'
        foreach ($c in $global:FinalDesiredColumns) { if (-not $mergedCols.Contains($c)) { [void]$mergedCols.Add($c) } }
        foreach ($c in $DesiredColumns)             { if (-not $mergedCols.Contains($c)) { [void]$mergedCols.Add($c) } }
        # Re-pin the trace columns last. They are appended per report (see $TraceCols
        # above, "always the LAST four columns"), so a plain union would leave report 1's
        # copies stranded mid-sheet with later reports' columns after them.
        foreach ($t in $TraceCols) { [void]$mergedCols.Remove($t) }
        foreach ($t in $TraceCols) { [void]$mergedCols.Add($t) }
        $global:FinalDesiredColumns = $mergedCols.ToArray()
    }

    foreach ($row in @($Shaped)) { $global:AllShapedRows.Add($row) | Out-Null }
    Write-Ok ("added {0} rows to export pool (total now {1})" -f (@($Shaped).Count), $global:AllShapedRows.Count)
  }
  catch {
    # Per-report iteration safety net. Without this, ANY terminating error in
    # one report (KQL parse fail, empty-array filter binding, KV secret miss,
    # etc.) kills the whole loop -- we'd lose the other 54 reports' output.
    # Log the error with the report name and continue with the next report.
    Write-Warn2 ("report failed -- skipping: {0}: {1}" -f $ReportName, $_.Exception.Message)
    continue
  }
}

# Final export
Write-Section "final excel export"

if ($global:AllShapedRows.Count -eq 0) {
    # Still produce an xlsx with a placeholder sheet so mail attachment works,
    # JSON sibling has a matching empty array, and the run looks "complete" to
    # downstream consumers. Export-Worksheet already handles empty -Rows by
    # writing a single 'Info: No rows returned' sheet (see line ~3490).
    Write-Warn2 "no rows collected across reports; writing placeholder xlsx + empty json sibling"
    Export-Worksheet -Path $global:OutputXlsx -SheetName 'Details' -Rows @() -TableStyle 'Medium9'
    $global:final = @()
} else {

    if ([string]::IsNullOrWhiteSpace($global:FinalRiskScoreColumnName)) {
        $global:FinalRiskScoreColumnName = 'RiskScore'
        Write-Warn2 "FinalRiskScoreColumnName not set; using default 'RiskScore'"
    }
    if (-not $global:FinalDesiredColumns) {
        # AUDIT #26, THIRD INSTANCE -- safety net for the case where no report set the list.
        # Same row-1 mistake, and worse here: $global:AllShapedRows holds EVERY report's
        # rows, so row 1 is one arbitrary report's shape imposed on all of them.
        $global:FinalDesiredColumns = Get-RAColumnUnion -Rows $global:AllShapedRows
    }

    # 2026-05-02: prefer RiskScoreTotal_Weighted over the YAML-declared
    # RiskScoreOutputName (typically RiskScoreTotal) for the final sort. The
    # weighted score is CMDB-amplified and represents the actual remediation
    # priority -- raw RiskScoreTotal puts a Weight=100 row above a Weight=225
    # row that scored slightly lower raw, which is wrong for asset triage.
    $sortCol = if ($global:AllShapedRows.Count -gt 0 -and
                   $global:AllShapedRows[0].PSObject.Properties['RiskScoreTotal_Weighted']) {
        'RiskScoreTotal_Weighted'
    } else { $global:FinalRiskScoreColumnName }
    Write-Step ("sorting rows by {0} (descending)" -f $sortCol)
    Tock

    $allRows = @()
    foreach ($r in $global:AllShapedRows) { $allRows += ,$r }

    $global:final = $allRows | Sort-Object -Descending -Property @{
        Expression = {
            $n = 0.0
            $v = $null
            if ($_.PSObject.Properties[$sortCol]) { $v = $_.$sortCol }
            [void][double]::TryParse([string]$v, [ref]$n)
            $n
        }
    }
    # Persist the actual sort column so downstream Excel-export label matches
    $global:FinalRiskScoreColumnName = $sortCol
    Tick "final sort"

    Write-Step "exporting to excel (single write)"
    Write-Info ("path: {0}" -f $global:OutputXlsx)
    Tock
    Export-Worksheet -Path $global:OutputXlsx -SheetName 'Details' `
      -Rows @($global:final) `
      -SortColumn $global:FinalRiskScoreColumnName -SortDescending `
      -DesiredColumns $global:FinalDesiredColumns `
      -ColumnsToFlatten @('ImpactedAssets','ImpactedAssetsList','IssueList','Logins','Benchmarks','EG_AssetProps','AssetProps','Properties') `
      -TableStyle 'Medium9'
    Tick "excel export"
    Write-Ok "report exported"
}

Write-Host ""
if (Test-Path -LiteralPath $global:OutputXlsx) {
    Write-Ok ("excel file ready: {0}" -f $global:OutputXlsx)
} else {
    Write-Warn2 ("excel skipped (no rows produced this run): {0}" -f $global:OutputXlsx)
}

#########################################################################################################
# JSON SIBLING  -- same dataset as the .xlsx, written next to it as .json
# Default: ON. Toggle off via $global:WriteJsonOutput = $false in LauncherConfig.
# Filename mirrors the XLSX (e.g. RiskAnalysis_Summary_Bucket.xlsx ->
# RiskAnalysis_Summary_Bucket.json) so the customer's downstream tools always
# find the matching pair.
#########################################################################################################

if ($null -eq $global:WriteJsonOutput) { $global:WriteJsonOutput = $true }

if ([bool]$global:WriteJsonOutput) {
    $global:OutputJson = [System.IO.Path]::ChangeExtension($global:OutputXlsx, 'json')
    Write-Step "exporting JSON sibling"
    Write-Info ("path: {0}" -f $global:OutputJson)
    try {
        @($global:final) | ConvertTo-Json -Depth 20 | Out-File -FilePath $global:OutputJson -Encoding UTF8 -Force
        Write-Ok ("json file ready: {0}" -f $global:OutputJson)
    } catch {
        Write-Warn "JSON export failed: $($_.Exception.Message) (continuing -- xlsx is still on disk)"
    }
}

#########################################################################################################
# LOG ANALYTICS INGEST  (Phase 2)
#
# Send the in-memory $global:final dataset to a Log Analytics custom table via
# the AzLogDcrIngestPS module (DCR + Log Ingestion API). Table is auto-created
# on first ingest by the module (CheckCreateUpdate-TableDcr-Structure handles
# table + DCR provisioning if missing).
#
# Routes to one of TWO tables based on the run mode:
#   $global:Summary  = $true  ->  $global:SI_RiskAnalysis_TableName_Summary
#   $global:Detailed = $true  ->  $global:SI_RiskAnalysis_TableName_Detailed
# (defaults: SI_RiskAnalysis_Summary / SI_RiskAnalysis_Detailed -- _CL added by LA)
#
# Default OFF. Set $global:SendToLogAnalytics = $true to enable.
#
# DCR is per-RiskAnalysis (separate from the IAC DCR -- different schema, own
# lifecycle). DCE + Workspace can be shared with IAC; the DCE / WorkspaceResourceId
# globals fall back to the IAC short names if not explicitly set.
#
# Two DCRs (one per table) are HARDCODED below by name; only the DcrResourceGroup
# is customer-configurable. Customer never has to invent DCR names.
#########################################################################################################

# DCR names default to 'dcr-si-risk-analysis-{summary|detailed}'. They're
# overridable via $global:SI_RiskAnalysis_DcrName_{Summary|Detailed} so
# customers running BOTH internal AND community demos with one cross-tenant
# SPN can disambiguate -- AzLogDcrIngestPS does name-based DCR lookup and
# picks the first match across all visible subscriptions, which silently
# routes ingest to the wrong DCR when names collide.
$RiskAnalysis_DcrName_Summary  = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DcrName_Summary))  { [string]$global:SI_RiskAnalysis_DcrName_Summary }  else { 'dcr-si-risk-analysis-summary' }
$RiskAnalysis_DcrName_Detailed = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DcrName_Detailed)) { [string]$global:SI_RiskAnalysis_DcrName_Detailed } else { 'dcr-si-risk-analysis-detailed' }

if ($null -eq $global:SendToLogAnalytics) { $global:SendToLogAnalytics = $false }

if ([bool]$global:SendToLogAnalytics -and (@($global:final).Count -eq 0)) {
    Write-Warn2 "SendToLogAnalytics=true but no rows produced this run -- skipping LA ingest (avoids 'empty collection' error from Az SDK)."
}
elseif ([bool]$global:SendToLogAnalytics) {
    Write-Sep

    # Resolve effective config (per-RiskAnalysis name wins; falls back to IAC short names).
    # Everything except Workspace (ResourceId OR Name) is optional -- sane defaults below.
    #
    # Lookup hierarchy (highest priority first):
    #   Workspace       : $SI_RiskAnalysis_WorkspaceResourceId > $SI_RiskAnalysis_WorkspaceName >
    #                     $WorkspaceResourceId > $WorkspaceName > default 'log-platform-management-securityinsight'
    #   DceIngestionUri : $SI_RiskAnalysis_DceIngestionUri > $DceIngestionUri > auto-resolved from DceName
    #   DceName         : $SI_RiskAnalysis_DceName > $DceName > default 'dce-securityinsight'
    #   DcrResourceGroup: $SI_RiskAnalysis_DcrResourceGroup > $DcrResourceGroup > default 'rg-dcr-securityinsight'
    # v2.2 unified naming uses $global:SI_*.
    # Resolution order: RA-specific (SI_RiskAnalysis_*) > v2.2 unified (SI_*) > legacy
    # bare names (DceIngestionUri, WorkspaceResourceId, ...). The customer's config
    # sets the SI_* family per the unified naming, so without the SI_* fallback the
    # LA-ingest path saw an empty WorkspaceResourceId and BadRequested every row.
    $laDce       = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DceIngestionUri))     { [string]$global:SI_RiskAnalysis_DceIngestionUri }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DceIngestionUri))               { [string]$global:SI_DceIngestionUri }
                   else { [string]$global:DceIngestionUri }
    $laWs        = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_WorkspaceResourceId)) { [string]$global:SI_RiskAnalysis_WorkspaceResourceId }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId))           { [string]$global:SI_WorkspaceResourceId }
                   else { [string]$global:WorkspaceResourceId }
    $laWsName    = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_WorkspaceName))       { [string]$global:SI_RiskAnalysis_WorkspaceName }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceName))                 { [string]$global:SI_WorkspaceName }
                   else { [string]$global:WorkspaceName }
    $laDceName   = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DceName))             { [string]$global:SI_RiskAnalysis_DceName }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DceName))                       { [string]$global:SI_DceName }
                   else { [string]$global:DceName }
    $laDcrRg     = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DcrResourceGroup))    { [string]$global:SI_RiskAnalysis_DcrResourceGroup }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DcrResourceGroup))              { [string]$global:SI_DcrResourceGroup }
                   else { [string]$global:DcrResourceGroup }
    $tblSummary  = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_TableName_Summary))   { [string]$global:SI_RiskAnalysis_TableName_Summary }   else { 'SI_RiskAnalysis_Summary' }
    $tblDetailed = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_TableName_Detailed))  { [string]$global:SI_RiskAnalysis_TableName_Detailed }  else { 'SI_RiskAnalysis_Detailed' }

    # SecurityInsight defaults -- if nothing is set, the standard layout is assumed.
    if ([string]::IsNullOrWhiteSpace($laDceName)) { $laDceName = 'dce-securityinsight' }
    if ([string]::IsNullOrWhiteSpace($laDcrRg))   { $laDcrRg   = 'rg-dcr-securityinsight' }
    if ([string]::IsNullOrWhiteSpace($laWs) -and [string]::IsNullOrWhiteSpace($laWsName)) {
        $laWsName = 'log-platform-management-securityinsight'
    }

    # Pick the DCR + table for this run (Summary catches the "neither set" fall-through)
    if ([bool]$global:Detailed) {
        $laTable   = $tblDetailed
        $laDcrName = $RiskAnalysis_DcrName_Detailed
    } else {
        $laTable   = $tblSummary
        $laDcrName = $RiskAnalysis_DcrName_Summary
    }

    # Validate required values. DceIngestionUri auto-resolves from DceName. Workspace
    # auto-resolves from name (and is auto-created if missing, along with the DCE/DCR RGs).
    $missing = @()
    if ([string]::IsNullOrWhiteSpace($laWs) -and [string]::IsNullOrWhiteSpace($laWsName)) {
        $missing += 'WorkspaceResourceId or WorkspaceName (or SI_RiskAnalysis_* variant)'
    }
    if ([string]::IsNullOrWhiteSpace($laDcrRg))   { $missing += 'DcrResourceGroup (or SI_RiskAnalysis_DcrResourceGroup)' }
    if ([string]::IsNullOrWhiteSpace($laDceName)) { $missing += 'DceName (or SI_RiskAnalysis_DceName)' }

    if ($missing.Count -gt 0) {
        Write-Warn ("SendToLogAnalytics=true but required globals are missing: {0}. Skipping LA ingest (xlsx + json still on disk)." -f ($missing -join ', '))
    } else {
        $modName = 'AzLogDcrIngestPS'
        try { Import-Module $modName -ErrorAction Stop -WarningAction SilentlyContinue } catch {
            Write-Warn ("Module '{0}' not available: {1}. Install with: Install-Module {0} -Scope CurrentUser. Skipping LA ingest." -f $modName, $_.Exception.Message)
            $modOk = $false
        }
        if ($null -eq $modOk) { $modOk = $true }

        if ($modOk) {
            # Build DCE/DCR cache + self-heal infra (creates workspace + DCE + DCR RG + RBAC if missing).
            # Shared logic mirrors Validate-SILogAnalytics.ps1.
            . (Join-Path $PSScriptRoot '_shared/Ensure-SecurityInsightInfra.ps1')   # forward slash works on both Win + Linux
            try {
                # Resolve SPN object ID for RBAC assignments
                $spnObj = Get-AzADServicePrincipal -ApplicationId $global:SpnClientId -ErrorAction SilentlyContinue
                $spnObjectId = if ($spnObj) { [string]$spnObj.Id } else { $null }

                # Resolve location (explicit override > workspace RG > default)
                $laLocation = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_Location)) { [string]$global:SI_Location }
                              elseif (-not [string]::IsNullOrWhiteSpace([string]$global:Location)) { [string]$global:Location }
                              else { 'westeurope' }

                # Resolve workspace: prefer ResourceId; else look up by name; else create
                $laWsRg = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_WorkspaceResourceGroup)) { [string]$global:SI_RiskAnalysis_WorkspaceResourceGroup }
                          elseif (-not [string]::IsNullOrWhiteSpace([string]$global:WorkspaceResourceGroup))            { [string]$global:WorkspaceResourceGroup }
                          else { 'rg-securityinsight' }

                # Subscription priority:
                #   1. Explicit $global:SubscriptionId (community customer sets it; AF derives it
                #      from $global:MainLogAnalyticsWorkspaceSubId in Initialize-LauncherConfig)
                #   2. Parsed from $laWs if it's a full ARM resource ID
                #   3. Current Az context (last resort)
                $laSubId = $null
                if (-not [string]::IsNullOrWhiteSpace([string]$global:SubscriptionId)) {
                    $laSubId = [string]$global:SubscriptionId
                } elseif ($laWs -match '/subscriptions/([^/]+)/') {
                    $laSubId = $Matches[1]
                } else {
                    try { $laSubId = (Get-AzContext -ErrorAction Stop).Subscription.Id } catch { }
                }
                if (-not $laSubId) { throw "Cannot determine subscription ID for workspace resolution -- set `$global:SubscriptionId or provide a full WorkspaceResourceId" }

                try { Set-AzContext -SubscriptionId $laSubId -TenantId $global:SpnTenantId -ErrorAction Stop | Out-Null } catch { }

                # If workspace RG exists, use its location (more accurate than the default)
                try { $__rgLoc = (Get-AzResourceGroup -Name $laWsRg -ErrorAction Stop).Location; if ($__rgLoc) { $laLocation = $__rgLoc } } catch { }

                $laWs = Ensure-SecurityInsightWorkspace `
                              -WorkspaceResourceId     $laWs `
                              -WorkspaceName           $laWsName `
                              -WorkspaceResourceGroup  $laWsRg `
                              -Location                $laLocation `
                              -SubscriptionId          $laSubId `
                              -IngestionSpnObjectId    $spnObjectId

                # Re-derive subscription from the resolved workspace (may differ if customer
                # set only a name and it resolved to a cross-sub workspace).
                if ($laWs -match '/subscriptions/([^/]+)/') { $laSubId = $Matches[1] }

                # Priority: SI_DceResourceGroup (canonical SI customer global, only set when
                # the customer overrides) BEFORE DceResourceGroup (legacy unprefixed name --
                # always populated by SecurityInsight.shared-defaults.ps1 Layer 0 to
                # 'rg-dce-securityinsight'). Reading the legacy name first masks the
                # customer's SI_* override and trips the DCE collision guard with the wrong RG.
                $laDceRg = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DceResourceGroup)) {
                                [string]$global:SI_DceResourceGroup
                            } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:DceResourceGroup)) {
                                [string]$global:DceResourceGroup
                            } else {
                                'rg-dce-securityinsight'
                            }

                # AzLogDcrIngestPS (1.6.2) reads tokens from the active Az session cache.
                # When v1 chain (Connect_Azure.ps1) leaves us in cert-SPN context, the
                # cached token won't satisfy the LA ingest endpoint -> AADSTS7000215.
                # Refresh the session here with the secret SPN so subsequent ingest calls
                # find a usable token. Idempotent. Skipped when secret is missing (UAMI / cert-only).
                if ($global:SpnClientId -and $global:SpnClientSecret -and $global:SpnTenantId) {
                    try {
                        $secCred = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force))
                        $null = Connect-AzAccount -ServicePrincipal `
                                                  -Tenant $global:SpnTenantId `
                                                  -Credential $secCred `
                                                  -ErrorAction Stop -WarningAction SilentlyContinue
                    } catch {
                        Write-Warning ("RA LA ingest: secret-SPN session refresh failed -- AzLogDcrIngestPS may 401: {0}" -f $_.Exception.Message)
                    }
                }

                # v2.2.271 -- cert OR secret auth. Build a splat once and reuse at all
                # 4 ingest call sites. Passing $global:SpnClientSecret='' to the module
                # under cert auth triggered ParameterBindingValidationException ("Cannot
                # bind argument to parameter 'AzAppSecret' because it is an empty string").
                $__ingestAuth = @{}
                if (-not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)) {
                    $__ingestAuth['AzAppCertificateThumbprint'] = [string]$global:SpnCertificateThumbprint
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
                    $__ingestAuth['AzAppSecret'] = [string]$global:SpnClientSecret
                }

                $null = Ensure-SecurityInsightDce `
                              -DceName              $laDceName `
                              -DceResourceGroup     $laDceRg `
                              -Location             $laLocation `
                              -SubscriptionId       $laSubId `
                              -TenantId             $global:SpnTenantId `
                              -AzAppId              $global:SpnClientId `
                              @__ingestAuth `
                              -IngestionSpnObjectId $spnObjectId

                $null = Ensure-SecurityInsightRg `
                              -ResourceGroup        $laDcrRg `
                              -Location             $laLocation `
                              -SubscriptionId       $laSubId `
                              -IngestionSpnObjectId $spnObjectId
            } catch {
                Write-Warn ("DCE/DCR/Workspace infra self-heal failed: {0} -- module will still attempt per-call resolution" -f $_.Exception.Message)
            }

            # Resolve DCE ingestion URI from name if not explicitly supplied (optional override).
            if ([string]::IsNullOrWhiteSpace($laDce)) {
                $__uri = Resolve-SecurityInsightDceIngestionUri -DceName $laDceName
                if ($__uri) {
                    $laDce = $__uri
                    Write-Info ("Resolved DCE ingestion URI from name '{0}': {1}" -f $laDceName, $laDce)
                }
            }

            Write-Step ("Ingesting to Log Analytics: {0}_CL" -f $laTable)
            Write-Info ("  DCR : {0} (rg={1})" -f $laDcrName, $laDcrRg)
            Write-Info ("  DCE : {0}" -f $laDceName)
            Write-Info ("  rows: {0}" -f (@($global:final)).Count)

            try {
                # UNCONDITIONAL silence of the AzLogDcrIngestPS / Az SDK
                # VERBOSE storm for the duration of the ingest block. Per-call
                # -Verbose:$false isn't enough -- the module reads
                # $global:VerbosePreference internally. The Az/DCR call traces are never
                # useful here (they don't help diagnose RA issues), so silence
                # regardless of operator -Verbose. Restored in the catch/finally.
                $_savedVerbosePreference = $global:VerbosePreference
                $global:VerbosePreference = 'SilentlyContinue'
                # Schema sample -- used by CheckCreateUpdate-TableDcr-Structure to DECLARE the
                # table + DCR columns. AUDIT #48: this was `Select-Object -First 100`, a POSITIONAL
                # sample, and the module declares the UNION of the property names across whatever it
                # is handed. Measured 2026-08-08 on the Detailed export: 2,216 rows carried 151
                # columns but the first 100 carried only 69 -- and the live DCR declared exactly
                # those 69, so 82 columns were silently dropped at ingest (57 of them holding real
                # data: RecommendedAction/RemediationOptions first appear on row 596, the whole
                # attack-path block on row 2215 of 2216). The rows posted, the run logged SUCCESS,
                # and the columns simply did not exist in Log Analytics. Same defect family as #26,
                # which fixed positional discovery in the EXPORT and left the INGEST path alone.
                # Get-RASchemaCoverageSample keeps the leading 100 rows and then adds only rows that
                # introduce a NOT-YET-SEEN column, so it can never declare fewer columns than before.
                $schemaSample = @(Get-RASchemaCoverageSample -Rows $global:final -BaseCount 100)

                # DROP COLUMNS LOG ANALYTICS CANNOT ACCEPT (2026-08-08).
                # The export carries 17 `<name>@odata.type` columns -- Graph/OData serialisation
                # metadata that leaked into the row shape. `@` is not legal in a Log Analytics
                # column name. This was HARMLESS only while the schema sample was the first 100
                # rows, because those columns appear further down; widening the sample to full
                # coverage exposed it at once and table creation failed with
                # `InvalidParameter: User provided schema is invalid`, leaving the table
                # NON-EXISTENT and every row unlanded -- while the run still printed
                # "Engine completed successfully".
                # ValidateFix-AzLogAnalyticsTableSchemaColumnNames is NOT sufficient here: measured
                # 2026-08-08, it strips the dot but keeps the '@' (`AllIdentities@odata.type` ->
                # `AllIdentities@odatatype`), so the name is still rejected. Run it first for the
                # normalisations it DOES handle, then drop whatever is still illegal.
                # Dropping them from the DECLARED schema is the correct outcome, not a workaround:
                # Build-DataArrayToAlignWithSchema drops undeclared columns from the posted rows
                # too, so declared and posted agree and only the 134 real columns land.
                # NOTE the artifact columns still reach the .xlsx/.json export -- that is a separate
                # defect (17 junk columns in a customer-facing workbook), recorded in REQUIREMENTS.
                $schemaSample = @(ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $schemaSample -Verbose:$false 4>$null)
                $__legalSample = foreach ($__row in $schemaSample) {
                    $__o = [ordered]@{}
                    foreach ($__p in $__row.PSObject.Properties) {
                        if ($__p.Name -match '^[A-Za-z][A-Za-z0-9_]*$') { $__o[$__p.Name] = $__p.Value }
                    }
                    [pscustomobject]$__o
                }
                $schemaSample = @($__legalSample)

                Write-Info ("  schema sample: {0} row(s) covering {1} column(s) (of {2} row(s))" -f `
                    $schemaSample.Count,
                    (@($schemaSample | ForEach-Object { $_.PSObject.Properties.Name } | Sort-Object -Unique)).Count,
                    (@($global:final)).Count)

                # v2.2.321 -- always print where data is being sent. Shared
                # Write-SIIngestTarget helper from Write-SIStyle.ps1 keeps the
                # 6-line format identical across publicip / profile / RA
                # engines. Fires once per RA report (Summary, Detailed each).
                # Lazy-load the helper because RA doesn't dot-source the asset-
                # profiling _shared scripts at startup; safe no-op when it's
                # already in scope or when the file moves.
                if (-not (Get-Command Write-SIIngestTarget -ErrorAction SilentlyContinue)) {
                    $__styleFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/_shared/Write-SIStyle.ps1'
                    if (Test-Path -LiteralPath $__styleFile) { . $__styleFile }
                }
                if (Get-Command Write-SIIngestTarget -ErrorAction SilentlyContinue) {
                    Write-SIIngestTarget -DcrName $laDcrName -TableName $laTable
                }

                # DCE collision guard (mirrors v2.2.59 in Invoke-Output.ps1). Strict
                # name + sub + RG match; if the cache contains multiple DCEs with
                # the same name across tenants/RGs the AzLogDcrIngestPS line 1575
                # name-only lookup picks both -> 'Array' bug on DCR PUT.
                if ($global:AzDceDetails -and $laDceName -and $global:SI_AzSubscriptionId -and $laDceRg) {
                    $_picked = @($global:AzDceDetails | Where-Object {
                        $_.name -eq $laDceName -and
                        $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$laDceRg/*"
                    }) | Select-Object -First 1
                    if ($_picked) {
                        $global:AzDceDetails = @($_picked)
                    } else {
                        Write-Warn ("DCE collision guard: '{0}' NOT in sub '{1}' / RG '{2}' -- module name-only lookup will pick wrong record." -f $laDceName, $global:SI_AzSubscriptionId, $laDceRg)
                    }
                }

                # append `4>$null` to redirect the verbose STREAM to
                # null. AzLogDcrIngestPS internally sets its own $script:VerbosePreference
                # which $global doesn't override; -Verbose:$false on the call only
                # affects the param binding, not the module's internal Write-Verbose
                # calls. Stream redirection is the only bulletproof silencer.
                $null = CheckCreateUpdate-TableDcr-Structure `
                            -AzLogWorkspaceResourceId                   $laWs `
                            -AzAppId                                    $global:SpnClientId `
                            @__ingestAuth `
                            -TenantId                                   $global:SpnTenantId `
                            -Verbose:$false `
                            -DceName                                    $laDceName `
                            -DcrName                                    $laDcrName `
                            -DcrResourceGroup                           $laDcrRg `
                            -TableName                                  $laTable `
                            -Data                                       $schemaSample `
                            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                            -AzLogDcrTableCreateFromAnyMachine          $true `
                            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

                # Re-sync the filtered DCE/DCR cache after DCR provisioning.
                # Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output resolves DcrName ->
                # immutableId via $global:AzDcrDetails; a newly created DCR isn't there
                # yet, and the module's fallback can send a bogus id (e.g. the DCE's
                # 'westeurope' location) causing a 404 at the Log Ingestion API.
                Start-Sleep -Seconds 15
                Ensure-SecurityInsightAzDceDcrCache `
                    -AzAppId           $global:SpnClientId `
                    @__ingestAuth `
                    -TenantId          $global:SpnTenantId `
                    -SubscriptionId    $laSubId `
                    -DceResourceGroup  $laDceRg `
                    -DcrResourceGroup  $laDcrRg `
                    -Force

                # Prepare + post the full dataset. Pipeline mirrors the
                # IdentityAssetsCollectDefineTierIngestLog ingest sequence so
                # both engines produce the same set of standard columns
                # (CollectionTime, Computer, ComputerFqdn, UserLoggedOn) and
                # behave identically under Build-DataArrayToAlignWithSchema.
                $DataVariable = @($global:final)

                # 1. CollectionTime  -- already stamped on every row upstream using
                #    the single $global:RA_CollectionTime so all rows share the same
                #    timestamp. Module call is kept as a safety net in case any
                #    row slipped through without it.
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable -Verbose:$false 4>$null

                # 2. Host identity (Computer / ComputerFqdn / UserLoggedOn)
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable `
                                    -Column1Name Computer     -Column1Data $env:ComputerName `
                                    -Column2Name ComputerFqdn -Column2Data $global:RA_DnsName `
                                    -Column3Name UserLoggedOn -Column3Data $env:USERNAME `
                                    -Verbose:$false 4>$null

                # 3. Validate + normalise column names (DCR schema requirements)
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable -Verbose:$false 4>$null

                # 4. Align data structure with the declared DCR schema
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable -Verbose:$false 4>$null

                $global:EnableCompressionDefault = $true
                $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                            -DceName     $laDceName `
                            -DcrName     $laDcrName `
                            -Data        $DataVariable `
                            -TableName   $laTable `
                            -AzAppId     $global:SpnClientId `
                            @__ingestAuth `
                            -TenantId    $global:SpnTenantId `
                            -Verbose:$false 4>$null

                Write-Ok ("ingested to {0}_CL" -f $laTable)
            } catch {
                # v2.2.358 -- surface the raw Azure error body, not just the
                # generic ".NET '(400) Bad Request'" string. ErrorDetails.Message
                # carries the JSON body from Invoke-RestMethod 4xx; the response
                # stream is the fallback when ErrorDetails wasn't populated.
                # Also dump the full target context so the operator can correlate
                # against the DCR / table / scope without re-reading the log header.
                $_azBody = $null
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    $_azBody = [string]$_.ErrorDetails.Message
                } else {
                    try {
                        $_respStream = $_.Exception.Response.GetResponseStream()
                        if ($_respStream) {
                            if ($_respStream.CanSeek) { $_respStream.Position = 0 }
                            $_reader = New-Object System.IO.StreamReader($_respStream)
                            try { $_body = $_reader.ReadToEnd(); if (-not [string]::IsNullOrWhiteSpace($_body)) { $_azBody = $_body } }
                            finally { $_reader.Close() }
                        }
                    } catch { }
                }
                # Try to extract the Azure error code from the JSON body for the
                # one-line summary (full body printed below).
                $_azCode = $null
                if ($_azBody) {
                    try {
                        $_azObj = $_azBody | ConvertFrom-Json -ErrorAction Stop
                        if ($_azObj -and $_azObj.error -and $_azObj.error.code) { $_azCode = [string]$_azObj.error.code }
                    } catch { }
                }
                $_codeSuffix = if ($_azCode) { " [code: $_azCode]" } else { '' }
                Write-Warn ("Log Analytics ingest failed: {0}{1} (continuing -- xlsx + json still on disk)" -f $_.Exception.Message, $_codeSuffix)
                Write-Warn '----- ingest target context -----'
                Write-Warn ("  DCR              : {0}  (rg={1})" -f $laDcrName, $global:SI_DcrResourceGroup)
                Write-Warn ("  DCE              : {0}" -f $laDceName)
                Write-Warn ("  Table            : {0}" -f $laTable)
                Write-Warn ("  Workspace        : {0}  (rg={1})" -f $global:SI_WorkspaceName, $global:SI_WorkspaceResourceGroup)
                Write-Warn ("  Subscription     : {0}" -f $global:SI_AzSubscriptionId)
                Write-Warn ("  SPN AppId        : {0}" -f $global:SpnClientId)
                Write-Warn ("  Rows attempted   : {0}" -f @($DataVariable).Count)
                Write-Warn '----- raw Azure error body -----'
                if ($_azBody) {
                    foreach ($_line in ($_azBody -split "`r?`n")) {
                        if (-not [string]::IsNullOrWhiteSpace($_line)) { Write-Warn ("  {0}" -f $_line.Trim()) }
                    }
                } else {
                    Write-Warn '  (no Azure response body captured; the SDK swallowed it -- run with -Verbose for the full HTTP trace)'
                }
                Write-Warn '----- common causes -----'
                Write-Warn "  - LinkedAuthorizationFailed 'Array' for dataCollectionEndpointId: the DCR has BOTH a stale + the current DCE attached (Azure portal -> DCR -> Properties shows both). Delete the stale entry, or re-create the DCR clean. Often follows a workspace/DCE move."
                Write-Warn "  - Schema drift: existing DCR/table column types differ from the engine's current row shape ('InvalidTransformOutput: <col> produced:X, output:Y'). Delete the DCR ('$laDcrName') AND the table ('$laTable') in workspace '$($global:SI_WorkspaceName)' -- engine will recreate with the correct shape."
                Write-Warn "  - SPN missing 'Monitoring Metrics Publisher' on DCR RG '$($global:SI_DcrResourceGroup)' in sub '$($global:SI_AzSubscriptionId)' -- the only role required for log ingest."
                Write-Warn "  - Body size > nginx 1 MB (rare for RA Summary outputs; common at >5000 rows of wide schema) -- re-run with smaller batch."
            } finally {
                # Restore caller's verbose preference even on exception path.
                if ($null -ne $_savedVerbosePreference) { $global:VerbosePreference = $_savedVerbosePreference }
            }
        }
    }
}

#########################################################################################################
# POWER BI DATASET REFRESH  (Phase 2b -- after LA ingest)
#
# Optional per-run trigger. When $global:SendToPowerBI = $true, after LA ingest
# completes, authenticate to the Power BI REST API using the same SPN creds
# already in globals and queue a refresh of the dashboard dataset. The
# dashboard reads live from LA so the data is already current -- this just
# forces the cached summary tiles / aggregations on the Power BI service to
# re-materialise from fresh KQL.
#
# The dashboard itself is deployed by Deploy-SIPowerBI_Deploy-SecurityInsight-PowerBI-Dashboard
# (run once per customer + when the dashboard design changes).
#
# Required globals when SendToPowerBI = $true:
#   $global:PowerBI_WorkspaceName   (default: 'SecurityInsight-Reports')
#   $global:PowerBI_DatasetName     (default: 'SecurityInsight - Risk Analysis')
#   $global:PowerBI_AuthTenantId    (default: $global:SpnTenantId)
#   $global:PowerBI_AuthClientId    (default: $global:SpnClientId)
#   $global:PowerBI_AuthClientSecret (default: $global:SpnClientSecret)
# Any of the above can be overridden per-engine in LauncherConfig.custom.ps1.
#########################################################################################################

if ($null -eq $global:SendToPowerBI) { $global:SendToPowerBI = $false }

if ([bool]$global:SendToPowerBI) {
    Write-Section "Power BI -- dataset refresh"

    $pbiWorkspace = if ($global:PowerBI_WorkspaceName) { [string]$global:PowerBI_WorkspaceName } else { 'SecurityInsight-Reports' }
    $pbiDataset   = if ($global:PowerBI_DatasetName)   { [string]$global:PowerBI_DatasetName }   else { 'SecurityInsight - Risk Analysis' }
    $pbiTenantId  = if ($global:PowerBI_AuthTenantId)  { [string]$global:PowerBI_AuthTenantId }  else { [string]$global:SpnTenantId }
    $pbiClientId  = if ($global:PowerBI_AuthClientId)  { [string]$global:PowerBI_AuthClientId }  else { [string]$global:SpnClientId }
    $pbiSecret    = if ($global:PowerBI_AuthClientSecret) { [string]$global:PowerBI_AuthClientSecret } else { [string]$global:SpnClientSecret }

    $pbiMissing = @()
    if (-not $pbiTenantId) { $pbiMissing += 'PowerBI_AuthTenantId (or SpnTenantId)' }
    if (-not $pbiClientId) { $pbiMissing += 'PowerBI_AuthClientId (or SpnClientId)' }
    if (-not $pbiSecret)   { $pbiMissing += 'PowerBI_AuthClientSecret (or SpnClientSecret)' }

    if ($pbiMissing.Count -gt 0) {
        Write-Warn ("SendToPowerBI=true but auth globals missing: {0}. Skipping refresh (LA + xlsx + json unaffected)." -f ($pbiMissing -join ', '))
    } else {
        try {
            Write-Step "Acquiring Power BI access token (SPN client credentials)"
            $tokResp = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$pbiTenantId/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{
                    grant_type    = 'client_credentials'
                    client_id     = $pbiClientId
                    client_secret = $pbiSecret
                    scope         = 'https://analysis.windows.net/powerbi/api/.default'
                }
            $pbiToken   = $tokResp.access_token
            $pbiHeaders = @{ Authorization = "Bearer $pbiToken"; 'Content-Type' = 'application/json' }
            $pbiBase    = 'https://api.powerbi.com/v1.0/myorg'

            # Resolve workspace -> dataset
            Write-Step ("Resolving workspace '{0}' + dataset '{1}'" -f $pbiWorkspace, $pbiDataset)
            $groups = Invoke-RestMethod -Method GET `
                -Uri "$pbiBase/groups?`$filter=name eq '$pbiWorkspace'" -Headers $pbiHeaders
            $group = $groups.value | Select-Object -First 1
            if (-not $group) { throw "Power BI workspace '$pbiWorkspace' not found. Run Step 4 first to deploy the dashboard." }

            $datasets = Invoke-RestMethod -Method GET `
                -Uri "$pbiBase/groups/$($group.id)/datasets" -Headers $pbiHeaders
            $ds = $datasets.value | Where-Object { $_.name -eq $pbiDataset } | Select-Object -First 1
            if (-not $ds) { throw "Power BI dataset '$pbiDataset' not found in workspace '$pbiWorkspace'. Run Step 4 to (re-)deploy the dashboard." }

            Write-Step "Triggering dataset refresh"
            $null = Invoke-RestMethod -Method POST `
                -Uri "$pbiBase/groups/$($group.id)/datasets/$($ds.id)/refreshes" `
                -Headers $pbiHeaders -Body '{"notifyOption":"NoNotification"}'
            Write-Ok ("refresh queued  workspace={0}  dataset={1}" -f $pbiWorkspace, $pbiDataset)
        } catch {
            Write-Warn ("Power BI refresh failed: {0} (continuing -- LA + xlsx + json unaffected)" -f $_.Exception.Message)
        }
    }
}

#########################################################################################################
# UPLOAD EXPORT FILES  (Phase 3)
#
# Optional. Sends the generated .xlsx + .json to either a UNC file share or an
# Azure Storage container. Enabled by setting $global:ExportDestination to:
#   \\server\share\subpath\                            -> UNC (uses caller's Windows identity)
#   https://<acct>.blob.core.windows.net/<container>/   -> Azure Storage blob (uses current Az SPN)
#   https://<acct>.blob.core.windows.net/<container>/<prefix>/   -> Azure Storage blob with prefix
#
# Behaviour: if the destination already has a file with the same name, the
# engine RENAMES the existing copy to <name>.<yyyy-MM-dd_HHmmss>.<ext>.bak
# (UNC: Move-Item, Storage: Start-AzStorageBlobCopy) BEFORE writing the new
# file. So the latest run's file always sits at the canonical path; older
# runs are timestamped backups next to it.
#
# Auth requirements:
#   UNC     -- caller's Windows identity needs write to the share. Pure SPN
#              auth doesn't help SMB; run the launcher under a service
#              account with share permissions, OR use Azure Storage.
#   Azure   -- the SPN that ran the engine needs 'Storage Blob Data Contributor'
#              on the destination container (or its parent storage account).
#########################################################################################################

# Shared helper: Send-ExportFile (+ _Unc / _AzStorage) defined in
# _shared\Send-SecurityInsightExportFile.ps1. Supports container auto-create +
# best-effort RBAC grant when the SPN's AppId/ObjectId is passed through.
. (Join-Path $PSScriptRoot '_shared/Send-SecurityInsightExportFile.ps1')   # forward slash works on both Win + Linux

if (-not [string]::IsNullOrWhiteSpace([string]$global:ExportDestination)) {
    Write-Sep
    Write-Step ("Uploading export files to: {0}" -f $global:ExportDestination)

    # Resolve SPN ObjectId once so Send-ExportFile can grant RBAC on auto-created containers
    $__raSpnObjectId = $null
    try {
        $__raSpn = Get-AzADServicePrincipal -ApplicationId $global:SpnClientId -ErrorAction SilentlyContinue
        if ($__raSpn) { $__raSpnObjectId = [string]$__raSpn.Id }
    } catch { }

    foreach ($localPath in @($global:OutputXlsx, $global:OutputJson)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$localPath)) {
            Send-ExportFile -LocalPath $localPath `
                -Destination          $global:ExportDestination `
                -IngestionSpnAppId    $global:SpnClientId `
                -IngestionSpnObjectId $__raSpnObjectId
        }
    }
}

#########################################################################################################
# BUILD AI SUMMARY CONTEXT
#########################################################################################################

if ([bool]$global:BuildSummaryByAI) {

    # Resolve AI config from GLOBAL OpenAI_* variables (single source of truth)
    if (-not [string]::IsNullOrWhiteSpace($global:OpenAI_apiKey)) {
        $global:AI_apiKey = $global:OpenAI_apiKey
    }
    if (-not [string]::IsNullOrWhiteSpace($global:OpenAI_deployment)) {
        $global:AI_deployment = $global:OpenAI_deployment
    }

    # Build URI from endpoint + deployment + apiVersion (unless caller passed AI_Uri explicitly)
    if ([string]::IsNullOrWhiteSpace($global:AI_Uri)) {

        $endpoint   = $global:OpenAI_endpoint
        $apiVersion = $global:OpenAI_apiVersion

        if ([string]::IsNullOrWhiteSpace($endpoint))        { throw "BuildSummaryByAI is enabled, but Global:OpenAI_endpoint is missing." }
        if ([string]::IsNullOrWhiteSpace($global:AI_deployment)) { throw "BuildSummaryByAI is enabled, but Global:OpenAI_deployment is missing." }
        if ([string]::IsNullOrWhiteSpace($apiVersion))      { throw "BuildSummaryByAI is enabled, but Global:OpenAI_apiVersion is missing." }

        $global:AI_Uri = "$($endpoint.TrimEnd('/'))/openai/deployments/$($global:AI_deployment)/chat/completions?api-version=$apiVersion"
    }

    # Max tokens
    if ($null -eq $global:AI_MaxTokensPerRequest -or [int]$global:AI_MaxTokensPerRequest -lt 1) {
        if ($null -ne $global:OpenAI_MaxTokensPerRequest -and [int]$global:OpenAI_MaxTokensPerRequest -gt 0) {
          $global:AI_MaxTokensPerRequest = [int]$global:OpenAI_MaxTokensPerRequest
        } else {
          $global:AI_MaxTokensPerRequest = 16384
        }
    }

    # Validation
    if ([string]::IsNullOrWhiteSpace($global:AI_apiKey))     { throw "BuildSummaryByAI is enabled, but Global:OpenAI_apiKey is missing." }
    if ([string]::IsNullOrWhiteSpace($global:AI_deployment)) { throw "BuildSummaryByAI is enabled, but Global:OpenAI_deployment is missing." }

    Write-Host "[AI] URI = $($global:AI_Uri)"
    Write-Host "[AI] Deployment = $($global:AI_deployment)"
    Write-Host "[AI] MaxTokensPerRequest = $($global:AI_MaxTokensPerRequest)"

    if ($global:AI_Uri -notmatch '^https?://') { throw "[AI] URI is not absolute: $($global:AI_Uri)" }

    # Always have a variable for mail body usage
    $global:AI_SummaryText = ""

    Write-Section "AI summary"

    # ---------------------------------------------------------------------
    # v2.2.346 -- LOCAL + BLOB lookup chain for the shared cache file. Local
    # works for single-host VMs; blob mirror lets multi-host / containerised
    # deployments share the cache (so two replicas don't both build the AI
    # summary the same hour). Storage account from $global:SI_StorageAccount
    # (the same account the asset-profiling pipeline already uses for staging).
    # Disabled gracefully when SI_StorageAccount isn't set OR Az.Storage isn't
    # importable -- local file remains the source of truth.
    $script:_RATop50Local       = Join-Path $global:OutputDir 'RiskAnalysis_Top50_Shared.json'
    $script:_RATop50Container   = if ($global:SI_RATop50_BlobContainer) { [string]$global:SI_RATop50_BlobContainer } else { 'sistaging' }
    $script:_RATop50BlobName    = if ($global:SI_RATop50_BlobName)      { [string]$global:SI_RATop50_BlobName }      else { 'risk-analysis/RiskAnalysis_Top50_Shared.json' }
    $script:_RATop50StorageAcct = [string]$global:SI_StorageAccount

    function Get-RATop50CachedFile {
        # Returns parsed JSON or $null. Local first (cheap), then blob.
        # On blob hit, saves a local copy so the next process on this host
        # is fast.
        if (Test-Path -LiteralPath $script:_RATop50Local) {
            try {
                $j = Get-Content -LiteralPath $script:_RATop50Local -Raw | ConvertFrom-Json
                return [pscustomobject]@{ Source = 'local'; Data = $j }
            } catch {
                Write-Warn2 ("[AISummaryCache] failed to parse local cache file: {0}" -f $_.Exception.Message)
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($script:_RATop50StorageAcct) -and (Get-Command -Name New-AzStorageContext -ErrorAction SilentlyContinue)) {
            try {
                $ctx = New-AzStorageContext -StorageAccountName $script:_RATop50StorageAcct -UseConnectedAccount -ErrorAction Stop
                $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + '.json')
                $prevProgress = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                try {
                    Get-AzStorageBlobContent -Container $script:_RATop50Container -Blob $script:_RATop50BlobName -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
                } finally { $ProgressPreference = $prevProgress }
                if (Test-Path -LiteralPath $tmp) {
                    $raw = Get-Content -LiteralPath $tmp -Raw
                    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                    $j = $raw | ConvertFrom-Json
                    # Save a local copy so subsequent processes on this host are fast.
                    try { Set-Content -LiteralPath $script:_RATop50Local -Value $raw -Encoding UTF8 -Force } catch { }
                    return [pscustomobject]@{ Source = 'blob'; Data = $j }
                }
            } catch {
                if ($_.Exception.Message -notmatch 'BlobNotFound|ResourceNotFound|404') {
                    Write-Warn2 ("[AISummaryCache] blob lookup failed: {0}" -f $_.Exception.Message)
                }
            }
        }
        return $null
    }

    function Save-RATop50CachedFile {
        param([Parameter(Mandatory)][string]$JsonContent)
        # Local write
        try {
            Set-Content -LiteralPath $script:_RATop50Local -Value $JsonContent -Encoding UTF8 -Force
        } catch {
            Write-Warn2 ("[AISummaryCache] failed to write local cache: {0}" -f $_.Exception.Message)
        }
        # Blob mirror (best-effort, single-host installs without SI_StorageAccount skip silently)
        if (-not [string]::IsNullOrWhiteSpace($script:_RATop50StorageAcct) -and (Get-Command -Name Set-AzStorageBlobContent -ErrorAction SilentlyContinue)) {
            try {
                $ctx = New-AzStorageContext -StorageAccountName $script:_RATop50StorageAcct -UseConnectedAccount -ErrorAction Stop
                # Auto-create container if missing.
                if (-not (Get-AzStorageContainer -Name $script:_RATop50Container -Context $ctx -ErrorAction SilentlyContinue)) {
                    New-AzStorageContainer -Name $script:_RATop50Container -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
                }
                $prevProgress = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                try {
                    Set-AzStorageBlobContent -Container $script:_RATop50Container -File $script:_RATop50Local -Blob $script:_RATop50BlobName -Context $ctx -Force -ErrorAction Stop | Out-Null
                } finally { $ProgressPreference = $prevProgress }
                Write-Info ("[AISummaryCache] mirrored to blob: {0}/{1}" -f $script:_RATop50Container, $script:_RATop50BlobName)
            } catch {
                Write-Warn2 ("[AISummaryCache] blob mirror failed (local file still authoritative): {0}" -f $_.Exception.Message)
            }
        }
    }

    # ---------------------------------------------------------------------
    # v2.2.345 -- FIRST-WIN AI SUMMARY CACHE (24h freshness)
    # Whichever RA run (Summary or Detailed) fires first after the cached
    # summary's age crosses $global:SI_AISummary_MaxAgeHours (default 24)
    # BUILDS a fresh AI summary and persists it to RiskAnalysis_Top50_Shared.json.
    # All other RA runs within the freshness window reuse that summary verbatim.
    #
    # Net effects:
    #   - Email/xlsx Top-50 + drilldown + quick-wins are IDENTICAL across all
    #     runs within a 24h window regardless of which template (Summary/Detailed)
    #     ran first.
    #   - AI is called at most once per 24h, not once per run (cost saving).
    #   - No "Summary is authority" asymmetry from v2.2.342 -- first-run wins.
    #
    # File payload (extends v2.2.342's shape with AISummaryText):
    #   { GeneratedAt, SolutionVersion, CollectionTime, SourceTemplate,
    #     TopAssets, TopFindings, AISummaryText }
    $sharedTopNPath        = $script:_RATop50Local   # back-compat with v2.2.345 var name; same path
    $aiSummaryMaxAgeHours  = if ([int]$global:SI_AISummary_MaxAgeHours -gt 0) {
        [int]$global:SI_AISummary_MaxAgeHours
    } else { 24 }
    $cachedSummaryUsed     = $false

    # v2.2.350 -- if the cached file ALSO carries the Risk Score KPI (GlobalScore,
    # DomainScore, SevByDomain, Band), capture it here. The KPI compute block at
    # the bottom of the engine will REPLACE the live-computed scores with these
    # cached values so the Summary + Detailed emails show the IDENTICAL overall
    # "63/100" number within the 24h freshness window. Customer ask: "the actual
    # score must be the same between summary and detailed".
    $script:_CachedRAKPI = $null

    $cached = Get-RATop50CachedFile
    if ($cached) {
        $shared = $cached.Data
        if ($shared.AISummaryText -and -not [string]::IsNullOrWhiteSpace([string]$shared.AISummaryText)) {
            # v2.2.369 -- handle BOTH [DateTime] (when ConvertFrom-Json auto-materialized ISO 8601)
            # AND [string] (when raw). Pure Parse fails on non-en-US boxes when the input is
            # already [DateTime] -- implicit ToString uses one culture, Parse uses another.
            $_gen = if ($shared.GeneratedAt -is [DateTime]) { [DateTime]$shared.GeneratedAt } else { [DateTime]::Parse([string]$shared.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
            $sharedAge = (Get-Date) - $_gen.ToLocalTime()
            if ($sharedAge.TotalHours -le $aiSummaryMaxAgeHours) {
                $global:AI_SummaryText = [string]$shared.AISummaryText
                Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText
                Write-Info ("[AISummaryCache] reusing cached AI summary from {0:N1}h ago (source={1}, template '{2}', collection {3}, max-age {4}h). AI not called this run." -f `
                    $sharedAge.TotalHours, $cached.Source, $shared.SourceTemplate, $shared.CollectionTime, $aiSummaryMaxAgeHours)
                $cachedSummaryUsed = $true
                # v2.2.350 -- capture cached KPI for downstream override.
                if ($shared.PSObject.Properties['GlobalScore'] -and $null -ne $shared.GlobalScore) {
                    $script:_CachedRAKPI = $shared
                } else {
                    # v2.2.351 -- cached AI text exists but cached KPI doesn't
                    # (cache was written by v2.2.345-349 before KPI persistence
                    # landed). This run skips the AI block entirely (AI text
                    # adopted), so the AI-write site's KPI-update flag would
                    # never fire. Set it here so the post-KPI-compute block at
                    # the bottom of the engine writes the just-computed KPI
                    # back into the existing cache file, populating it for
                    # subsequent runs without invalidating the cached AI text.
                    $script:_RACacheNeedsKPIUpdate = $true
                    Write-Info "[AISummaryCache] cached AI text adopted, but cached file has no GlobalScore (pre-v2.2.350 cache). Will backfill KPI into the cache from this run's live compute."
                }
            } else {
                Write-Info ("[AISummaryCache] cached AI summary is {0:N1}h old (source={1}, >{2}h max via `$global:SI_AISummary_MaxAgeHours); this run will REFRESH it." -f `
                    $sharedAge.TotalHours, $cached.Source, $aiSummaryMaxAgeHours)
            }
        } else {
            Write-Info ("[AISummaryCache] cache file exists (source={0}) but contains no AISummaryText; this run will build + persist." -f $cached.Source)
        }
    } else {
        Write-Info ("[AISummaryCache] no cached file (local or blob); this run will build + persist.")
    }
    # ---------------------------------------------------------------------

    if ($cachedSummaryUsed) {
        # Skip the entire rollup + AI call block -- nothing more to do here.
    }
    elseif ($null -eq $global:final -or @($global:final).Count -eq 0) {
        Write-Warn2 "BuildSummaryByAI requested, but there are no final rows to summarize."
    }
    else {

        # v2.2.224 -- AI rollup builds from ALL final rows (was top 50), so the
        # asset universe seen by the rollup is identical between Summary and
        # Detailed regardless of report shape. Detailed previously fed only top
        # 50 raw rows which often covered just 3-8 hot assets (one asset
        # dominates the top with many CVE rows); the AI then ranked the same
        # narrow set every run. Summary had broader coverage because each row
        # carried ImpactedAssetsList across many assets. Equalizing the input
        # window makes both reports converge on the same top assets.
        # $TopFindingsN is new in v2.2.224 -- parallel finding rollup so the AI
        # gets per-CVE/per-recommendation aggregation alongside the asset one.
        $TopN         = @($global:final).Count
        $TopAssetsN   = 50
        $TopFindingsN = 50

        function Test-LooksLikeHost {
            param([string]$s)
            if ([string]::IsNullOrWhiteSpace($s)) { return $false }
            $t = $s.Trim()
            if ($t -match '^[a-zA-Z0-9][a-zA-Z0-9\-]{1,63}$') { return $true }
            if ($t -match '^[a-zA-Z0-9][a-zA-Z0-9\-]{1,63}(\.[a-zA-Z0-9\-]{1,63}){1,10}$') { return $true }
            return $false
        }

        function Split-ImpactedAssets {
            param([AllowNull()][object]$AssetsText)

            if ($null -eq $AssetsText) { return @() }
            $t = if ($AssetsText -is [string]) { $AssetsText } else {
                try { $AssetsText | ConvertTo-Json -Compress -Depth 12 } catch { "" + $AssetsText }
            }
            if ([string]::IsNullOrWhiteSpace($t)) { return @() }

            $t = $t.Trim()

            if ($t.StartsWith('[') -and $t.EndsWith(']')) {
                try {
                    $j = $t | ConvertFrom-Json -ErrorAction Stop
                    $out = @()
                    foreach ($item in $j) {
                        if ($null -eq $item) { continue }
                        if ($item -is [string]) { $out += $item; continue }
                        $name = (Get-RowValue -Row $item -Names @("Name","name","DeviceName","deviceName","MachineName","machineName","DnsName","dnsName","Id","id"))
                        if ($name) { $out += $name }
                    }
                    return @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
                } catch { }
            }

            # Comma-parts are ATOMIC asset identifiers. Earlier preview tokenized each
            # part on whitespace and re-extracted any word matching the loose hostname
            # regex (Test-LooksLikeHost) -- which exploded identity descriptions like
            # "SPN with RoleManagement.ReadWrite.Directory - can grant Global Admin to any account"
            # into ~10 fake "assets" (account, with, SPN, can, Admin, ...). The AI prompt
            # then ranked single English words as top-risk assets. Treat each comma-part
            # as one asset name; trust the YAML author / engine's ImpactedAssets emitter
            # to format it correctly. .
            $parts = @($t -split '\s*,\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            return @($parts | Select-Object -Unique)
        }

        # AI rollup ranks on RiskScoreTotal_Weighted (CMDB-amplified)
        # so high-business-criticality assets surface even when their raw risk
        # is lower than a non-CMDB asset's. Falls back to RiskScoreTotal then
        # the legacy column for older data.
        $colRiskScore = if ($global:FinalRiskScoreColumnName) { $global:FinalRiskScoreColumnName } else { "RiskScoreTotal_Weighted" }

        # Pre-sort by weighted score so the top-N slice itself is biased toward
        # CMDB-prioritised rows, not just whichever rows happened to come first.
        $topRows = @($global:final |
            Sort-Object -Property @{
                Expression = {
                    $v = $_.PSObject.Properties[$colRiskScore]
                    if ($v) { [double](([string]$v.Value) -replace ',', '.') } else { 0.0 }
                }
                Descending = $true
            } |
            Select-Object -First $TopN)

        # v2.2.227 path B -- collapse pass for *_Detailed reports so the AI
        # rollup sees the same (asset x finding) shape as Summary does.
        # Detailed YAMLs emit one row per (asset, CVE): a host with 562 CVEs
        # contributes 562 rows. Summary YAMLs hard-code `extend ConfigurationId = "CVE"`
        # which collapses those 562 per-CVE rows into one "Update vulnerable
        # software [CVE]" row. Without engine-side parity the Detailed AI
        # over-weights hot assets (observed 24x sum on mgmt1: 562 rows ->
        # 24'024 weighted vs Summary's 25 rows -> 994), causing Summary and
        # Detailed to rank different top assets.
        #
        # Here we mirror Summary's collapse engine-side: for each
        # (asset, ConfigBucket) pair keep only the max-WeightedRisk row and
        # feed it to Add-AssetAgg / Add-FindingAgg once. ConfigBucket = "CVE"
        # when ConfigurationId looks like a CVE (CVE-YYYY-N+), otherwise the
        # raw ConfigurationId (scid-NNN etc. pass through unchanged so
        # recommendations stay 1:1). Other rows in the same pair are skipped
        # from AI rollup only -- the XLSX export remains untouched (the full
        # 562 rows still ship for forensic detail).
        $isDetailedTemplate = ($global:ReportTemplate -like '*_Detailed')
        $collapseBuckets    = $null
        if ($isDetailedTemplate -and $topRows.Count -gt 0) {
            $collapseBuckets = @{}
            foreach ($r in $topRows) {
                $cId = Get-RowValue -Row $r -Names @("ConfigurationId","RecommendationId","FindingId","Id")
                $bucket = if ([string]$cId -match '^CVE-\d{4}-\d+$') { 'CVE' } else { [string]$cId }
                $wTxt = Get-RowValue -Row $r -Names @("RiskScoreTotal_Weighted")
                [double]$w = 0; [void][double]::TryParse((([string]$wTxt) -replace ',', '.'), [ref]$w)
                $aTxt = Get-RowValue -Row $r -Names @("ImpactedAssetsList","ImpactedAssets","Assets","AffectedAssets","Machines")
                $aList = Resolve-AssetNamesForRow -Row $r -AssetsText $aTxt
                foreach ($a in $aList) {
                    if ([string]::IsNullOrWhiteSpace($a)) { continue }
                    $key = "{0}|{1}" -f ([string]$a).ToLowerInvariant(), $bucket
                    if (-not $collapseBuckets.ContainsKey($key)) {
                        $collapseBuckets[$key] = [pscustomobject]@{ MaxW = $w; RowRef = $r }
                    } elseif ($collapseBuckets[$key].MaxW -lt $w) {
                        $collapseBuckets[$key].MaxW   = $w
                        $collapseBuckets[$key].RowRef = $r
                    }
                }
            }
            Write-Info ("AI rollup collapse: {0} *_Detailed rows -> {1} (asset x ConfigBucket) buckets (max-weighted; XLSX unaffected)" -f $topRows.Count, $collapseBuckets.Count)
        }

        $findingLines = @()
        $assetAgg     = @{}

        # v2.2.224 -- parallel finding aggregator keyed by ConfigurationId. Lets the
        # AI prompt include a "top critical findings" rollup alongside the asset
        # rollup, so the operator sees BOTH "which assets to fix" AND "what to fix
        # on them" -- consistent across Summary + Detailed because both reports
        # share the same Add-FindingAgg logic on the same Final-rows pool.
        $findingAgg   = @{}

        function Add-FindingAgg {
            param(
                [string]$ConfId,
                [string]$ConfName,
                [string]$Category,
                [string]$Subcat,
                [string]$Severity,
                [string]$Domain,
                [string]$Asset,
                [double]$RiskScoreUnweighted = 0.0,
                [double]$RiskScoreWeighted   = 0.0,
                [string]$MoreDetails         = ''
            )

            if ([string]::IsNullOrWhiteSpace($ConfId)) { return }

            if (-not $findingAgg.ContainsKey($ConfId)) {
                $findingAgg[$ConfId] = [pscustomobject]@{
                    ConfId                  = $ConfId
                    ConfName                = $ConfName
                    Category                = $Category
                    Subcategory             = $Subcat
                    Severity                = $Severity
                    Domain                  = $Domain
                    TotalRiskScore          = 0.0
                    TotalRiskScore_Weighted = 0.0
                    AffectedAssetCount      = 0
                    AffectedAssets          = New-Object System.Collections.Generic.HashSet[string]
                    AssetRiskScores         = @{}   # asset -> weighted score sum (top-5 cross-ref)
                    Links                   = New-Object System.Collections.Generic.HashSet[string]
                }
            }

            $f = $findingAgg[$ConfId]
            $f.TotalRiskScore          += $RiskScoreUnweighted
            $f.TotalRiskScore_Weighted += $RiskScoreWeighted

            # Sticky: keep first-seen non-empty descriptive fields
            if (-not $f.ConfName -and $ConfName) { $f.ConfName = $ConfName }
            if (-not $f.Category -and $Category) { $f.Category = $Category }
            if (-not $f.Subcategory -and $Subcat) { $f.Subcategory = $Subcat }
            if (-not $f.Severity -and $Severity) { $f.Severity = $Severity }
            if (-not $f.Domain   -and $Domain)   { $f.Domain   = $Domain }

            if ($Asset -and -not [string]::IsNullOrWhiteSpace($Asset)) {
                $wasNew = $f.AffectedAssets.Add($Asset)
                if ($wasNew) { $f.AffectedAssetCount++ }
                # Track per-asset risk score sum so we can list top-5 hottest assets per finding
                if ($f.AssetRiskScores.ContainsKey($Asset)) {
                    $f.AssetRiskScores[$Asset] += $RiskScoreWeighted
                } else {
                    $f.AssetRiskScores[$Asset]  = $RiskScoreWeighted
                }
            }

            # Harvest reference URLs (cap 6 per finding)
            if (-not [string]::IsNullOrWhiteSpace($MoreDetails) -and $f.Links.Count -lt 6) {
                foreach ($urlMatch in ([regex]::Matches([string]$MoreDetails, 'https?://[^\s,;<>"`)\]]+'))) {
                    if ($f.Links.Count -ge 6) { break }
                    $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                    [void]$f.Links.Add($u)
                }
            }
        }

        function Add-AssetAgg {
            param(
                [string]$Asset,
                [double]$RiskScore,
                [string]$TierLevel,
                [string]$Severity,
                [string]$Domain,
                [string]$Category,
                [string]$Subcat,
                [string]$ConfName,
                [string]$ConfId,
                [string]$CmdbId,
                [string]$CmdbName,
                [string]$CmdbCriticality,
                [string]$CmdbDataSensitivity,
                [double]$RiskScoreUnweighted = 0.0,
                [double]$RiskScoreWeighted   = 0.0,
                [string]$MoreDetails         = ''
            )

            if ([string]::IsNullOrWhiteSpace($Asset)) { return }

            if (-not $assetAgg.ContainsKey($Asset)) {
                $assetAgg[$Asset] = [pscustomobject]@{
                    Asset               = $Asset
                    TierLevel           = $TierLevel
                    Findings            = 0
                    # v2.2.99: separated regular + weighted totals so the AI summary
                    # can show 'Total Risk Score' AND 'Weighted Risk Score' per asset
                    # (operators were confused by a single ambiguous 'RiskScoreTotal'
                    # column that summed whichever score was the active sort target).
                    TotalRiskScore           = 0.0
                    TotalRiskScore_Weighted  = 0.0
                    CmdbId              = $CmdbId
                    CmdbName            = $CmdbName
                    CmdbCriticality     = $CmdbCriticality
                    CmdbDataSensitivity = $CmdbDataSensitivity
                    Domains             = New-Object System.Collections.Generic.HashSet[string]
                    TopItems            = New-Object System.Collections.Generic.List[string]
                    Links               = New-Object System.Collections.Generic.HashSet[string]
                }
            }

            $o = $assetAgg[$Asset]
            $o.Findings++
            $o.TotalRiskScore          += $RiskScoreUnweighted
            $o.TotalRiskScore_Weighted += $RiskScoreWeighted
            # Sticky: keep first-seen non-empty cmdb fields (assets typically have one cmdb identity).
            if (-not $o.CmdbId              -and $CmdbId)              { $o.CmdbId              = $CmdbId }
            if (-not $o.CmdbName            -and $CmdbName)            { $o.CmdbName            = $CmdbName }
            if (-not $o.CmdbCriticality     -and $CmdbCriticality)     { $o.CmdbCriticality     = $CmdbCriticality }
            if (-not $o.CmdbDataSensitivity -and $CmdbDataSensitivity) { $o.CmdbDataSensitivity = $CmdbDataSensitivity }

            if ($Domain) { [void]$o.Domains.Add($Domain) }

            if ($o.TopItems.Count -lt 12) {
                $o.TopItems.Add(("{0} [{1}] ({2}/{3})" -f $ConfName, $ConfId, $Category, $Subcat))
            }

            # Harvest a few reference URLs from MoreDetails so the AI can hyperlink them
            # in the email summary. Cap at 6 unique URLs per asset to keep the prompt
            # bounded.
            if (-not [string]::IsNullOrWhiteSpace($MoreDetails) -and $o.Links.Count -lt 6) {
                foreach ($urlMatch in ([regex]::Matches([string]$MoreDetails, 'https?://[^\s,;<>"`)\]]+'))) {
                    if ($o.Links.Count -ge 6) { break }
                    $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                    [void]$o.Links.Add($u)
                }
            }
        }

        $i = 0
        foreach ($r in $topRows) {
            $i++

            $riskScoreText = Get-RowValue -Row $r -Names @($colRiskScore, "RiskScore")
            [double]$riskScore = 0
            [void][double]::TryParse(($riskScoreText -replace ',', '.'), [ref]$riskScore)

            # v2.2.99: pull BOTH risk-score variants per row so the AI summary
            # can show 'Total Risk Score' (unweighted) AND 'Weighted Risk Score'.
            $riskScoreUnText = Get-RowValue -Row $r -Names @("RiskScoreTotal", "RiskScore")
            [double]$riskScoreUn = 0
            [void][double]::TryParse(($riskScoreUnText -replace ',', '.'), [ref]$riskScoreUn)
            $riskScoreWtText = Get-RowValue -Row $r -Names @("RiskScoreTotal_Weighted")
            [double]$riskScoreWt = 0
            [void][double]::TryParse(($riskScoreWtText -replace ',', '.'), [ref]$riskScoreWt)
            $rowMoreDetails = Get-RowValue -Row $r -Names @("MoreDetails")

            $severity    = Get-RowValue -Row $r -Names @("SecuritySeverity", "Severity", "securityseverity")
            $tierLevel   = Get-RowValue -Row $r -Names @("CriticalityTierLevel", "CriticalityTier", "Tier", "criticalitytierlevel")
            $domain      = Get-RowValue -Row $r -Names @("SecurityDomain", "Domain", "securitydomain")
            $category    = Get-RowValue -Row $r -Names @("Category", "category")
            $subcat      = Get-RowValue -Row $r -Names @("Subcategory", "SubCategory", "subcategory")
            $confName    = Get-RowValue -Row $r -Names @("ConfigurationName", "RecommendationName", "FindingName", "Title", "Name")
            $confId      = Get-RowValue -Row $r -Names @("ConfigurationId", "RecommendationId", "FindingId", "Id")
            $devices     = Get-RowValue -Row $r -Names @("Devices", "DeviceCount", "ImpactedDevices")
            # 'ImpactedAssetsList' is the canonical column name since v2.2.72; legacy
            # 'ImpactedAssets' is now removed from Summary rows by the engine post-process,
            # so the AI rollup MUST look at the canonical name first or every Identity/Azure
            # Summary row falls through with empty $assetsText -> Add-AssetAgg returns early ->
            # AI summary collapses to whatever rows still happen to carry a per-row AssetName
            # (typically just one Endpoint asset).
            $assetsText  = Get-RowValue -Row $r -Names @("ImpactedAssetsList", "ImpactedAssets", "Assets", "AffectedAssets", "Machines")
            # CMDB context (engine stamps these from CMDB.csv via cmdbId lookup at Reconcile).
            $cmdbId       = Get-RowValue -Row $r -Names @("cmdbId", "CmdbId")
            $cmdbName     = Get-RowValue -Row $r -Names @("cmdbName", "CmdbName")
            $cmdbCrit     = Get-RowValue -Row $r -Names @("cmdbCriticality", "CmdbCriticality")
            $cmdbSens     = Get-RowValue -Row $r -Names @("cmdbDataSensitivity", "CmdbDataSensitivity")

            $findingLines += ("[{0}] RiskScore={1}; Tier={2}; Severity={3}; Domain={4}; Config={5} [{6}]; Category={7}/{8}; Devices={9}; CMDB={10} [{11}] (Criticality={12}, DataSensitivity={13}); ImpactedAssets={14}" -f `
                $i, $riskScoreText, $tierLevel, $severity, $domain, $confName, $confId, $category, $subcat, $devices, $cmdbName, $cmdbId, $cmdbCrit, $cmdbSens, $assetsText)

            $assetList = Resolve-AssetNamesForRow -Row $r -AssetsText $assetsText

            if ($assetList -and @($assetList).Count -gt 0) {
                foreach ($a in $assetList) {
                    # v2.2.227 path B -- in *_Detailed reports skip rows that
                    # aren't the max-weighted representative for their
                    # (asset, ConfigBucket) pair. Summary path is unaffected
                    # ($collapseBuckets stays $null when the template isn't *_Detailed).
                    if ($isDetailedTemplate -and $collapseBuckets) {
                        $bucket = if ([string]$confId -match '^CVE-\d{4}-\d+$') { 'CVE' } else { [string]$confId }
                        $key    = "{0}|{1}" -f ([string]$a).ToLowerInvariant(), $bucket
                        if ($collapseBuckets.ContainsKey($key) -and -not [object]::ReferenceEquals($collapseBuckets[$key].RowRef, $r)) {
                            continue
                        }
                    }

                    Add-AssetAgg -Asset $a -RiskScore $riskScore -TierLevel $tierLevel -Severity $severity -Domain $domain `
                        -Category $category -Subcat $subcat -ConfName $confName -ConfId $confId `
                        -CmdbId $cmdbId -CmdbName $cmdbName -CmdbCriticality $cmdbCrit -CmdbDataSensitivity $cmdbSens `
                        -RiskScoreUnweighted $riskScoreUn -RiskScoreWeighted $riskScoreWt -MoreDetails $rowMoreDetails

                    # v2.2.224 -- parallel finding rollup. Same row, same scoring,
                    # but keyed by ConfigurationId so AI gets per-finding aggregation
                    # alongside the per-asset one.
                    Add-FindingAgg -ConfId $confId -ConfName $confName -Category $category -Subcat $subcat `
                        -Severity $severity -Domain $domain -Asset $a `
                        -RiskScoreUnweighted $riskScoreUn -RiskScoreWeighted $riskScoreWt -MoreDetails $rowMoreDetails
                }
            } else {
                Write-Warn2 ("AI rollup: no asset resolved for row {0}. Config={1} [{2}]" -f $i, $confName, $confId)
            }
        }

        # v2.2.224 -- $findingsText replaced by aggregated per-finding rollup
        # built from $findingAgg below. Old raw-row dump ($findingLines) is no
        # longer fed to the AI; it produced inconsistent top-N across Summary
        # (50 aggregated rows = ~50 unique findings) vs Detailed (50 per-asset
        # rows = ~3-8 unique findings dominated by hot assets). Aggregating
        # first guarantees the same finding universe regardless of report shape.

        $assetRanked = @()
        if ($assetAgg.Count -gt 0) {
            # v2.2.381: surface CRITICALITY first. Operators were getting
            # Tier 3 (Low) assets at the top because sum-of-findings overran
            # weighting -- an asset with 361 low-severity findings beat a
            # Tier 0 asset with 50. Sort tier ASC (0 first), then weighted
            # risk score DESC inside the tier. Missing/unparseable tier
            # sorts last (99) so it doesn't pollute the top.
            $assetRanked = $assetAgg.Values |
                Sort-Object -Property `
                    @{Expression = {
                        $t = [string]$_.TierLevel
                        if ($t -match 'tier\s*(\d+)') { [int]$Matches[1] } else { 99 }
                    }; Ascending = $true}, `
                    @{Expression="TotalRiskScore_Weighted";Descending=$true}, `
                    @{Expression="TotalRiskScore";Descending=$true}, `
                    @{Expression="Findings";Descending=$true} |
                Select-Object -First $TopAssetsN
        }

        # v2.2.224 -- finding rollup (parallel to asset rollup)
        $findingRanked = @()
        if ($findingAgg.Count -gt 0) {
            $findingRanked = $findingAgg.Values |
                Sort-Object -Property @{Expression="TotalRiskScore_Weighted";Descending=$true}, @{Expression="TotalRiskScore";Descending=$true}, @{Expression="AffectedAssetCount";Descending=$true} |
                Select-Object -First $TopFindingsN
        }

        # v2.2.345 -- v2.2.342's Summary-writes / Detailed-reads Top-50 sharing
        # block was removed here. It's superseded by the cache-first-by-age
        # mechanism added near "Write-Section 'AI summary'" above: when the
        # cached AI summary is still fresh, we skip this whole rollup block
        # entirely; when it's stale, this run becomes the authoritative builder
        # and writes the result (AI text + Top-50 inputs) to the same shared
        # file in the post-AI-call persist step below.

        $findingLines2 = @()
        $rankF = 0
        foreach ($f in $findingRanked) {
            $rankF++
            # Top 5 affected assets per finding, ranked by per-asset weighted risk
            $topAssetsForFinding = @($f.AssetRiskScores.GetEnumerator() |
                Sort-Object -Property Value -Descending |
                Select-Object -First 5 |
                ForEach-Object { ("{0} ({1:N0})" -f $_.Key, $_.Value) }) -join '; '

            $finLinks = ""
            if ($f.Links.Count -gt 0) { $finLinks = (@($f.Links) | Select-Object -First 6) -join "; " }

            $findingLines2 += ("{0}. ConfigId={1}; Name={2}; Severity={3}; Domain={4}; Category={5}/{6}; AffectedAssetCount={7}; TotalRiskScore={8:N0}; WeightedRiskScore={9:N0}; TopAffectedAssets=[{10}]; Links={11}" -f `
                $rankF, $f.ConfId, $f.ConfName, $f.Severity, $f.Domain, $f.Category, $f.Subcategory, $f.AffectedAssetCount, $f.TotalRiskScore, $f.TotalRiskScore_Weighted, $topAssetsForFinding, $finLinks)
        }

        $findingsTextForAI = $findingLines2 -join "`n"

        $assetLines = @()
        $rank = 0
        foreach ($a in $assetRanked) {
            $rank++

            $domainSummary = ""
            if ($a.Domains.Count -gt 0) { $domainSummary = (@($a.Domains) | Sort-Object) -join ", " }

            $topItems = ""
            if ($a.TopItems.Count -gt 0) { $topItems = ($a.TopItems | Select-Object -First 8) -join "; " }

            $linkList = ""
            if ($a.Links.Count -gt 0) { $linkList = (@($a.Links) | Select-Object -First 6) -join "; " }

            $assetLines += ("{0}. Asset={1}; Tier={2}; CMDB={3} [{4}] (Criticality={5}, DataSensitivity={6}); Findings={7}; TotalRiskScore={8:N0}; WeightedRiskScore={9:N0}; Domains=[{10}]; TopItems={11}; Links={12}" -f `
                $rank, $a.Asset, $a.TierLevel, $a.CmdbName, $a.CmdbId, $a.CmdbCriticality, $a.CmdbDataSensitivity, $a.Findings, $a.TotalRiskScore, $a.TotalRiskScore_Weighted, $domainSummary, $topItems, $linkList)
        }

        $assetsTextForAI = $assetLines -join "`n"

        $runMeta = @"
ReportTemplate: $($global:ReportTemplate)
Final rows:     $(@($global:final).Count)
Included in AI: $(@($topRows).Count) (TopN findings)
Asset rollup:   $($assetAgg.Keys.Count) unique assets (TopAssetsN=$TopAssetsN included)
RiskScore col:  $colRiskScore
Output file:    $($global:OutputXlsx)
Generated:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

        $intro = @"
This summary is generated from Microsoft Defender data to answer one practical question:
what should we fix first, and on which assets, to reduce RiskScore the fastest.

Scope:
- This summary only covers the Top $TopAssetsN highest-risk assets for this run.
- Full evidence and the complete set of findings per asset is in the attached Excel report (Details sheet).
- A separate Summary sheet in the Excel contains the same AI text as this email.

Risk scoring is transparent: Consequence Ã— Probability = RiskScore, based on raw Kusto query outputs and a customizable risk index.
"@

        # v2.2.224 -- output the EXACT counts the engine produced so the AI
        # narrative header matches the bullet count. Previously the prompt
        # said "Top 25" as a literal, but $assetAgg often had fewer than 25
        # entries -- the AI would emit fewer bullets while the header still
        # claimed 25, confusing operators.
        $assetActualN   = [Math]::Min($TopAssetsN,   @($assetRanked).Count)
        $findingActualN = [Math]::Min($TopFindingsN, @($findingRanked).Count)
        $drilldownN     = [Math]::Min(10, $assetActualN)

        $userPrompt = @"
$intro

You are a security advisor AI.

You MUST focus on ASSETS and prioritize remediation by RiskScore.
You are given:
A) An asset rollup (top $assetActualN, ranked by Criticality Tier first (Tier 0 highest), then Weighted Risk Score within tier).
B) A finding rollup (top $findingActualN, already ranked by Weighted Risk Score).
   Each finding lists its TopAffectedAssets so you can pair "what to fix" with "where".

Both rollups are PRE-AGGREGATED from the SAME source data (engine-side, not by
you), so Summary and Detailed report variants converge on the same top entries.
Do not invent assets or findings outside this rollup.

$runMeta

A) Asset rollup:
$assetsTextForAI

B) Finding rollup:
$findingsTextForAI

Return format (STRICT MARKDOWN). Use the exact section headers, bold labels,
and bullet structure below. Every header MUST start at the beginning of a line.
Do not wrap in code fences. Do not add a preamble or closing remarks.

## Top $assetActualN risky assets

One bullet per asset, in rank order. Use ONLY the two score numbers provided
(TotalRiskScore = unweighted sum, WeightedRiskScore = weighted sum). Do NOT
invent a 'MaxRiskScore' field. Format numbers with thousands separators.
Output EXACTLY $assetActualN bullets (one per asset rollup entry).

- **<Rank>. <AssetName>** -- Tier **<Tier>** | Weighted Risk Score **<WeightedRiskScore>** | Total Risk Score **<TotalRiskScore>** | Findings **<Count>** | Domains: <Domains>

## Top $findingActualN critical findings

One bullet per finding, in rank order. Use the AffectedAssetCount and Weighted
Risk Score from the finding rollup. List up to 4 of the TopAffectedAssets per
bullet (the assets that contribute the most risk score to this finding).
Output EXACTLY $findingActualN bullets.

- **<Rank>. <ConfName>** [<ConfId>] -- Severity **<Severity>** | Affected assets **<AffectedAssetCount>** | Weighted Risk Score **<WeightedRiskScore>** | Top affected: <up to 4 asset names>

## Top $drilldownN asset drilldown

For each of the Top $drilldownN assets (same order as the asset rollup), output exactly this structure (separate each asset with a blank line):

### <Rank>. <AssetName>

- **Tier:** <Tier> | **Weighted Risk Score:** <WeightedRiskScore> | **Total Risk Score:** <TotalRiskScore>
- **Why it is high risk:** <one sentence citing the two top TopItems>
- **Top 5 actions to reduce risk FAST:**
  - **<Action>** -- <Why> | <Expected impact> | _References: <ConfigName> [<ConfigId>]_
  - **<Action>** -- <Why> | <Expected impact> | _References: <ConfigName> [<ConfigId>]_
  - **<Action>** -- <Why> | <Expected impact> | _References: <ConfigName> [<ConfigId>]_
  - **<Action>** -- <Why> | <Expected impact> | _References: <ConfigName> [<ConfigId>]_
  - **<Action>** -- <Why> | <Expected impact> | _References: <ConfigName> [<ConfigId>]_
- **Expected overall risk reduction:** High | Medium | Low
- **Reference links:** when the asset's ``Links=`` field includes URLs, render them as inline markdown anchors ``[label](url)``. Pick descriptive labels from the URL itself (e.g. ``[CVE-2026-33824](https://nvd.nist.gov/vuln/detail/CVE-2026-33824)``, ``[ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)``). Maximum 3 links per asset; omit this line if the asset has no links.

## Cross-asset quick wins

Use the finding rollup's AffectedAssetCount + TopAffectedAssets to pick remediation actions that fix the MOST assets per action. Max 8 bullets:

- **<Action>** [<ConfigId>] -- Affects <N> assets | Example: <up to 4 asset names from TopAffectedAssets>

Rules:
- Do NOT write generic advice. Every action must tie back to ConfigName [ConfigId] and concrete assets from the rollup.
- Do NOT merge multiple findings into one line.
- Do NOT invent or hallucinate assets / findings outside the rollups provided.
- Keep the output concise. No long paragraphs.
- Use **bold** for all labels and field values exactly as shown above.
- ONLY use the two score columns provided (Total Risk Score, Weighted Risk Score). Do NOT invent or carry over old field names like 'MaxRiskScore' or 'RiskScoreTotal' from prior outputs.
"@

        # v2.2.352 -- FINAL race re-check BEFORE the AI POST. The early cache
        # read at engine start may have shown empty cache for this run, but a
        # concurrent peer (Summary vs Detailed launched at ~same time) may have
        # finished its AI POST and written to the cache during our Top-50 prep.
        # Re-read here and adopt + skip the POST if so. Saves both AI API cost
        # AND prevents Summary/Detailed emails from showing divergent scores
        # when both start with empty cache. User ask: "don't read the cache
        # summary at the start of the script -- but just before you need it.
        # otherwise 2 starting same time, but finish at different time will
        # both fail, if first run."
        $skipAIPost = $false
        try {
            $preCallCheck = Get-RATop50CachedFile
            if ($preCallCheck -and $preCallCheck.Data -and $preCallCheck.Data.AISummaryText -and -not [string]::IsNullOrWhiteSpace([string]$preCallCheck.Data.AISummaryText)) {
                $_gen = if ($preCallCheck.Data.GeneratedAt -is [DateTime]) { [DateTime]$preCallCheck.Data.GeneratedAt } else { [DateTime]::Parse([string]$preCallCheck.Data.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
                $preCallAge = (Get-Date) - $_gen.ToLocalTime()
                if ($preCallAge.TotalHours -le $aiSummaryMaxAgeHours) {
                    Write-Info ("[AISummaryCache] pre-POST race re-check: peer run wrote cache {0:N1}h ago (template '{1}', source={2}). SKIPPING AI POST -- adopting peer's AI text + KPI." -f `
                        $preCallAge.TotalHours, $preCallCheck.Data.SourceTemplate, $preCallCheck.Source)
                    $global:AI_SummaryText = [string]$preCallCheck.Data.AISummaryText
                    try { Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText } catch {}
                    if ($preCallCheck.Data.PSObject.Properties['GlobalScore'] -and $null -ne $preCallCheck.Data.GlobalScore) {
                        $script:_CachedRAKPI = $preCallCheck.Data
                    } else {
                        # Peer cached AI but not KPI -- backfill KPI from our live compute.
                        $script:_RACacheNeedsKPIUpdate = $true
                    }
                    $skipAIPost = $true
                }
            }
        } catch { }

        if ($skipAIPost) {
            # Jump to end of try-block; the cache-write block below has its own
            # race guard that will skip when AI text wasn't built fresh.
        }
        else {

        Write-Host "`n[AI SUMMARY RESPONSE]`n" -ForegroundColor Cyan

        $sb = New-Object System.Text.StringBuilder

        $reader = $null
        $client = $null

        try {
            $body = @{
                model = $global:AI_deployment
                stream = $true
                # v2.2.342 -- temp 0 (was 0.2) so the AI rendering is byte-identical
                # across repeated calls with the same input. Combined with the new
                # shared Top-50 ($global:OutputDir/RiskAnalysis_Top50_Shared.json
                # written by Summary, read by Detailed), Summary and Detailed
                # email/xlsx top-N sections now agree.
                temperature = 0
                top_p = 1.0
                max_tokens = [int]$global:AI_MaxTokensPerRequest
                messages = @(
                    @{
                        role = "system"
                        content = "You are a helpful security advisor. You produce asset-focused prioritization and remediation guidance using the provided Defender-based risk data."
                    },
                    @{
                        role = "user"
                        content = $userPrompt
                    }
                )
            } | ConvertTo-Json -Depth 12 -Compress

            $handler = [System.Net.Http.HttpClientHandler]::new()
            $client  = [System.Net.Http.HttpClient]::new($handler)

            $request = [System.Net.Http.HttpRequestMessage]::new(
                [System.Net.Http.HttpMethod]::Post,
                $global:AI_Uri
            )

            $request.Headers.Add("api-key", $global:AI_apiKey)
            $request.Headers.Add("Accept", "text/event-stream")
            $request.Content = [System.Net.Http.StringContent]::new(
                $body,
                [System.Text.Encoding]::UTF8,
                "application/json"
            )

            $response = $client.SendAsync(
                $request,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).Result

            if (-not $response.IsSuccessStatusCode) {
                $err = $response.Content.ReadAsStringAsync().Result
                throw "Azure OpenAI returned HTTP $([int]$response.StatusCode): $err"
            }

            $stream = $response.Content.ReadAsStreamAsync().Result
            $reader = [System.IO.StreamReader]::new($stream)

            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($line -and $line.StartsWith("data: ")) {
                    $json = $line.Substring(6)
                    if ($json -eq "[DONE]") { break }

                    try {
                        $obj  = $json | ConvertFrom-Json
                        $text = $obj.choices[0].delta.content
                        if ($text) {
                            [void]$sb.Append($text)
                            Write-Host -NoNewline $text
                        }
                    } catch {
                        Write-Warning "Failed to parse AI chunk: $json"
                    }
                }
            }

            $global:AI_SummaryText = ($sb.ToString() -replace "`r`n","`n" -replace "`r","`n").Trim()

            # Write AI summary into Excel Summary sheet
            try {
              Write-Step "writing AI summary to excel sheet 'Summary'"
              Tock
              Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText
              Tick "excel summary export"
              Write-Ok "AI summary added to Excel (Summary sheet)"
            } catch {
              Write-Warn2 ("failed to write AI summary to excel: {0}" -f $_.Exception.Message)
            }

            # v2.2.345 -- PERSIST the AI summary + Top-50 inputs to the shared
            # file so the next RA run (Summary or Detailed) within the freshness
            # window reuses this exact text. First-writer-wins; subsequent runs
            # skip the entire rollup + AI call until the 24h cache expires.
            # v2.2.346 -- write goes through Save-RATop50CachedFile which mirrors
            # to the sistaging blob too when $global:SI_StorageAccount is set,
            # so multi-host / containerised installs share the cache.
            try {
                # v2.2.350 -- FIRST-WRITER-WINS race guard. Concurrent Summary +
                # Detailed runs both start with empty cache, both compute AI fresh.
                # Re-check the cache RIGHT BEFORE write: if a peer already wrote
                # within the freshness window, SKIP the write (and skip the KPI
                # update too -- peer's KPI also wins). Matches the same semantics
                # the user wants for the Risk Score KPI.
                $existing = Get-RATop50CachedFile
                $skipWrite = $false
                if ($existing -and $existing.Data -and $existing.Data.AISummaryText -and -not [string]::IsNullOrWhiteSpace([string]$existing.Data.AISummaryText)) {
                    try {
                        $_gen = if ($existing.Data.GeneratedAt -is [DateTime]) { [DateTime]$existing.Data.GeneratedAt } else { [DateTime]::Parse([string]$existing.Data.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
                        $existingAge = (Get-Date) - $_gen.ToLocalTime()
                        if ($existingAge.TotalHours -le $aiSummaryMaxAgeHours) {
                            $skipWrite = $true
                            Write-Info ("[AISummaryCache] race detected: peer run wrote cache {0:N1}h ago (template '{1}', source={2}). NOT overwriting -- first-writer-wins. This run's email will be regenerated to use peer's AI text + KPI." -f `
                                $existingAge.TotalHours, $existing.Data.SourceTemplate, $existing.Source)
                            # Adopt the peer's AI text + flag KPI override so the
                            # downstream KPI block + email use the cached values.
                            $global:AI_SummaryText = [string]$existing.Data.AISummaryText
                            try { Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText } catch {}
                            if ($existing.Data.PSObject.Properties['GlobalScore'] -and $null -ne $existing.Data.GlobalScore) {
                                $script:_CachedRAKPI = $existing.Data
                            }
                            $script:_RACacheNeedsKPIUpdate = $false
                        }
                    } catch {}
                }
                if (-not $skipWrite) {
                    $shared = [pscustomobject]@{
                        GeneratedAt     = (Get-Date).ToUniversalTime().ToString('o')
                        SolutionVersion = [string]$global:RA_SolutionVersion
                        CollectionTime  = ([datetime]$global:RA_CollectionTime).ToUniversalTime().ToString('o')
                        SourceTemplate  = [string]$global:ReportTemplate
                        MaxAgeHours     = $aiSummaryMaxAgeHours
                        TopAssets       = $assetRanked
                        TopFindings     = $findingRanked
                        AISummaryText   = $global:AI_SummaryText
                        # KPI fields populated by the post-KPI-compute updater.
                        GlobalScore     = $null
                        Band            = $null
                        RiskLevel       = $null
                        DomainScore     = $null
                        SevByDomain     = $null
                    }
                    $jsonContent = $shared | ConvertTo-Json -Depth 12 -Compress
                    Save-RATop50CachedFile -JsonContent $jsonContent
                    # Flag the post-KPI updater to fire when $global:RA_KPI is ready.
                    $script:_RACacheNeedsKPIUpdate = $true
                    Write-Info ("[AISummaryCache] persisted fresh AI summary + Top-{0} assets + {1} findings -> {2} (next run within {3}h will reuse it)." -f `
                        @($assetRanked).Count, @($findingRanked).Count, $script:_RATop50Local, $aiSummaryMaxAgeHours)
                }
            } catch {
                Write-Warn2 ("[AISummaryCache] failed to persist shared AI summary: {0}" -f $_.Exception.Message)
            }

        } catch {
            Write-Error "Azure OpenAI request failed: $($_.Exception.Message)"
            try {
              $global:AI_SummaryText = "AI summary failed: $($_.Exception.Message)"
              Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText
            } catch { }
        } finally {
            if ($reader) { try { $reader.Close() } catch {} }
            if ($client) { try { $client.Dispose() } catch {} }
        }
        }   # close v2.2.352 `else` (skipAIPost was $false; AI POST + cache-write block above)
    }
}

#####################################################################################################
# RISK SCORE KPI ROLLUP (v2.2.96 -- Microsoft-inspired, simple weighted avg)
#####################################################################################################
# Per-row KPI is a SECURE SCORE (HIGHER = BETTER, 0-100):
#   RiskScoreKPI       = round((1 - SeverityWeight/10) * 100)        (per row)
#   RiskScoreDomainKPI = round((1 - SeverityWeight/10) * TierFraction * 100)
#                        TierFraction = TierWeight / 4               (T0=1.00, T1=0.50, T2=0.25, T3=0.125)
#
# Run-end rollup is a tier-weighted average -- same shape as Microsoft's
# Cloud Secure Score (numerator weighted by criticality, denominator equal
# total criticality). Scale-independent: 10-machine lab and 150k-machine
# enterprise produce comparable scores.
#
#   DomainKPI  = sum(RiskScoreKPI x TierWeight) / sum(TierWeight)
#   GlobalKPI  = sum(DomainKPI    x DomainWeight) / sum(DomainWeight)
#
# Bands: At Risk 0-49 | Moderate 50-74 | Good 75-89 | Very Good 90-100.
#
# RiskScoreTotal / RiskScoreTotal_Weighted (the OG per-row Risk Score) are
# left untouched -- people are big fans of them, they keep working.
#####################################################################################################
$global:RA_KPI = $null
try {
    $rows = if ($null -ne $global:final) { @($global:final) } else { @() }
    $DomainSet = @('Endpoint','Identity','Azure','PublicIP')

    $sevCount    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0 }
    $sevByDomain = @{
        Endpoint = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
        Identity = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
        Azure    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
        PublicIP = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
    }

    # Per-domain weighted-avg accumulators (numerator = sum(rowKpi * tierWeight),
    # denominator = sum(tierWeight)). Plus a per-domain row counter.
    $domainAcc = @{
        Endpoint = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
        Identity = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
        Azure    = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
        PublicIP = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
    }

    function _TierWeight([int]$tier) {
        switch ($tier) {
            0       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T0) { [double]$global:SI_RiskReport_TierMultiplier_T0 } else { 4.0 } }
            1       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T1) { [double]$global:SI_RiskReport_TierMultiplier_T1 } else { 2.0 } }
            2       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T2) { [double]$global:SI_RiskReport_TierMultiplier_T2 } else { 1.0 } }
            3       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T3) { [double]$global:SI_RiskReport_TierMultiplier_T3 } else { 0.5 } }
            default { 1.0 }
        }
    }

    # v2.2.404 -- helper: derive SecurityDomain from report name when the per-row
    # field is empty. Most YAML reports don't declare a top-level SecurityDomain
    # (it's optional), so the per-row field ends up blank on the majority of
    # rows and the KPI table's Total cells stop matching the per-domain row
    # sums (the Total uses unfiltered counts, per-domain uses only canonical
    # SecurityDomain hits). Matching report-name prefixes back to one of the
    # 4 canonical domains restores arithmetic invariance.
    function _DomainFromReportName([string]$reportName) {
        if ([string]::IsNullOrWhiteSpace($reportName)) { return '' }
        $rn = $reportName.ToLowerInvariant()
        # Endpoint-specific Attack_Paths_* patterns FIRST (more specific than the
        # PublicIP family below). Public_IP_to_VM is a path from internet -> VM:
        # the VM is the target and classifies as Endpoint, not PublicIP.
        if ($rn -match 'public_ip_to_vm')                                  { return 'Endpoint' }
        if ($rn -match 'device_with_high_severity_vulnerabilities')        { return 'Endpoint' }
        # PublicIP family (anchored to prefix only -- avoids matching Public_IP_to_VM)
        if ($rn -match '^publicip_')                                       { return 'PublicIP' }
        # Endpoint family (prefix)
        if ($rn -match '^(device|endpoint)_')                              { return 'Endpoint' }
        # Identity family
        if ($rn -match '^identity_')                                       { return 'Identity' }
        if ($rn -match 'credential_based_lateral_movement')                { return 'Identity' }
        if ($rn -match 'identity_group_membership')                        { return 'Identity' }
        if ($rn -match 'data_sensitivity_to_exposed_credentials')          { return 'Identity' }
        # Azure family (catch-all for remaining Attack_Paths_* targeting Azure)
        if ($rn -match '^azure_')                                          { return 'Azure' }
        if ($rn -match 'github_to_azure')                                  { return 'Azure' }
        if ($rn -match 'to_azure_resources')                               { return 'Azure' }
        return ''
    }

    foreach ($r in $rows) {
        $dom = ''
        if ($r.PSObject.Properties['SecurityDomain']) { $dom = [string]$r.SecurityDomain }
        if ($dom -eq 'PublicIp') { $dom = 'PublicIP' }
        # v2.2.404 -- fallback derivation from report name when per-row field is empty.
        # Without this, rows from YAML reports that don't declare a top-level
        # SecurityDomain end up uncounted in the per-domain rows of the KPI
        # table, while the Total row counts them. Customer-reported bug:
        # Detailed-template Total cells showed 71,278 / 8218 crit while per-domain
        # rows summed to 1122 / 53 crit -- 98% of rows had blank SecurityDomain.
        if ([string]::IsNullOrWhiteSpace($dom) -and $r.PSObject.Properties['Report']) {
            $dom = _DomainFromReportName ([string]$r.Report)
        }

        # Severity tally (used by the email's Domain x Severity table)
        $sevText = ''
        if ($r.PSObject.Properties['SecuritySeverity']) { $sevText = [string]$r.SecuritySeverity }
        $sevBucket = switch -Regex ($sevText) {
            '^(?i)(critical|very high)$' { 'Critical'; break }
            '^(?i)high$'                 { 'High';     break }
            '^(?i)medium-?high$'         { 'High';     break }
            '^(?i)medium$'               { 'Medium';   break }
            '^(?i)low$'                  { 'Low';      break }
            default                      { 'Other' }
        }
        $sevCount[$sevBucket]++
        if ($sevByDomain.ContainsKey($dom)) {
            $sevByDomain[$dom][$sevBucket]++
            $sevByDomain[$dom]['Total']++
        }

        if (-not ($DomainSet -contains $dom)) { continue }

        # Pull the per-row RiskScoreKPI (already computed upstream)
        $rowKpi = 100.0
        if ($r.PSObject.Properties['RiskScoreKPI']) { [void][double]::TryParse([string]$r.RiskScoreKPI, [ref]$rowKpi) }

        # Tier weight for this row
        $tierVal = -1
        if ($r.PSObject.Properties['CriticalityTier']) { [void][int]::TryParse([string]$r.CriticalityTier, [ref]$tierVal) }
        $tw = _TierWeight $tierVal

        # v2.2.314 -- per-row population weight. Summary rows represent N
        # asset-findings collapsed into one row; Detailed rows are one-finding-per-asset
        # (weight = 1). Multiplying by population converges Summary KPI to Detailed KPI on the
        # same underlying data -- pre-v2.2.314 the two reports diverged by 1-9 points purely
        # from per-row vs per-asset-finding averaging. Customer ask: "my customers cannot
        # understand why the risk score is not same % between summary and detailed".
        #
        # AUDIT #52 -- the population is now ImpactedAssetCount. It was
        # TotalIssuesImpactedAssets, which has been removed as incorrect: it disagreed with
        # ImpactedAssetCount on 64 of 311 live rows, with ratios from 0.125 to 2048.5.
        # 🔴 THAT WAS NOT COSMETIC. This weight feeds the headline risk score, so a row whose
        # count was inflated 2048x dominated its domain's KPI, and rows whose count was too
        # low (ratio 0.125) were under-counted. The scores this converged were converging on a
        # distorted population.
        # ImpactedAssetCount is the honest population for a Summary row: array_length of the
        # asset list actually shown beside it, so the weight and the evidence agree. It is also
        # what the engine already substituted whenever the KQL supplied nothing -- so for the
        # 247 of 311 rows that were already consistent, the weighting is unchanged.
        $rowWeight = 1.0
        if ($r.PSObject.Properties['ImpactedAssetCount']) {
            $iac = 0
            if ([int]::TryParse([string]$r.ImpactedAssetCount, [ref]$iac) -and $iac -gt 0) {
                $rowWeight = [double]$iac
            }
        }

        $domainAcc[$dom].Numer += $rowKpi * $tw * $rowWeight
        $domainAcc[$dom].Denom += $tw * $rowWeight
        $domainAcc[$dom].Rows++
    }

    # ----- per-domain weighted average -----
    $domainScore = @{}
    foreach ($d in $DomainSet) {
        if ($domainAcc[$d].Denom -gt 0) {
            $domainScore[$d] = [int][Math]::Round($domainAcc[$d].Numer / $domainAcc[$d].Denom, 0)
        } else {
            $domainScore[$d] = 100   # no findings -> Very Good
        }
    }

    # ----- global = weighted average of domain scores by domain weight -----
    $domainWeights = @{
        Endpoint = if ($null -ne $global:SI_RiskReport_GlobalWeight_Endpoint) { [double]$global:SI_RiskReport_GlobalWeight_Endpoint } else { 0.30 }
        Identity = if ($null -ne $global:SI_RiskReport_GlobalWeight_Identity) { [double]$global:SI_RiskReport_GlobalWeight_Identity } else { 0.30 }
        Azure    = if ($null -ne $global:SI_RiskReport_GlobalWeight_Azure)    { [double]$global:SI_RiskReport_GlobalWeight_Azure }    else { 0.20 }
        PublicIP = if ($null -ne $global:SI_RiskReport_GlobalWeight_PublicIP) { [double]$global:SI_RiskReport_GlobalWeight_PublicIP } else { 0.20 }
    }
    $gNumer = 0.0; $gDenom = 0.0
    foreach ($d in $DomainSet) {
        $w = $domainWeights[$d]
        $gNumer += $domainScore[$d] * $w
        $gDenom += $w
    }
    $globalScore = if ($gDenom -gt 0) { [int][Math]::Round($gNumer / $gDenom, 0) } else { 100 }

    # ----- band (mirrors Microsoft Cloud Secure Score bands) -----
    $band = if     ($globalScore -ge 90) { 'Very Good' }
            elseif ($globalScore -ge 75) { 'Good' }
            elseif ($globalScore -ge 50) { 'Moderate' }
            else                         { 'At Risk' }

    # Back-compat alias for code that still reads RiskLevel from the old shape.
    $bcRiskLevel = if     ($band -eq 'Very Good') { 'Low' }
                   elseif ($band -eq 'Good')      { 'Moderate' }
                   elseif ($band -eq 'Moderate')  { 'Elevated' }
                   elseif ($band -eq 'At Risk')   { if ($globalScore -lt 25) { 'Critical' } else { 'High' } }
                   else                            { 'Unknown' }

    $global:RA_KPI = [pscustomobject]@{
        GlobalScore  = $globalScore
        Band         = $band
        RiskLevel    = $bcRiskLevel
        DomainScore  = $domainScore
        SevCount     = $sevCount
        SevByDomain  = $sevByDomain
        TotalRows    = $rows.Count
        Direction    = 'higher-is-better'
    }

    Write-Info ("[SCORE] Global={0} ({1}) Endpoint={2} Identity={3} Azure={4} PublicIP={5} | Sev: C={6} H={7} M={8} L={9} | Rows={10} | Direction: HIGHER = BETTER (Microsoft-inspired)" -f `
        $globalScore, $band, $domainScore['Endpoint'], $domainScore['Identity'], $domainScore['Azure'], $domainScore['PublicIP'], `
        $sevCount['Critical'], $sevCount['High'], $sevCount['Medium'], $sevCount['Low'], $rows.Count)

    # v2.2.350 -- FINAL re-read of the cache, late as possible. Catches the
    # race where THIS run started with empty cache + computed live, but a
    # concurrent peer wrote during our run. The peer's KPI now wins for our
    # email too -- both Summary and Detailed emails show the IDENTICAL
    # headline score regardless of order/timing.
    if (-not $script:_CachedRAKPI -or $null -eq $script:_CachedRAKPI.GlobalScore) {
        try {
            $finalCheck = Get-RATop50CachedFile
            if ($finalCheck -and $finalCheck.Data -and $finalCheck.Data.PSObject.Properties['GlobalScore'] -and $null -ne $finalCheck.Data.GlobalScore) {
                try {
                    $_gen = if ($finalCheck.Data.GeneratedAt -is [DateTime]) { [DateTime]$finalCheck.Data.GeneratedAt } else { [DateTime]::Parse([string]$finalCheck.Data.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
                    $finalAge = (Get-Date) - $_gen.ToLocalTime()
                    if ($finalAge.TotalHours -le $aiSummaryMaxAgeHours -and [string]$finalCheck.Data.SourceTemplate -ne [string]$global:ReportTemplate) {
                        $script:_CachedRAKPI = $finalCheck.Data
                        Write-Info ("[SCORE] final-pre-email re-check: peer run wrote cached KPI {0:N1}h ago (template '{1}', source={2}). Adopting peer's KPI for this run too." -f `
                            $finalAge.TotalHours, $finalCheck.Data.SourceTemplate, $finalCheck.Source)
                        # Suppress our own pending KPI write -- peer already populated.
                        $script:_RACacheNeedsKPIUpdate = $false
                    }
                } catch {}
            }
        } catch {}
    }

    # v2.2.350 -- if the AI summary cache carried a frozen KPI (either from
    # an earlier run's 24h-fresh write OR from a concurrent peer caught by
    # the final re-read above), OVERRIDE the just-computed scores. Per-domain
    # Total/Critical/High/Medium/Low row COUNTS in the dashboard table can
    # still differ (Summary aggregates, Detailed is per-row) -- that's
    # expected -- but the headline KPI is now coherent across templates.
    if ($script:_CachedRAKPI -and $null -ne $script:_CachedRAKPI.GlobalScore) {
        $c = $script:_CachedRAKPI
        $liveScore = $globalScore
        $cachedScore = [int]$c.GlobalScore
        # Rehydrate DomainScore / SevByDomain hashtables from the cached
        # PSCustomObject (ConvertFrom-Json returns objects, not hashtables).
        $cachedDomainScore = @{}
        if ($c.DomainScore) {
            foreach ($p in $c.DomainScore.PSObject.Properties) { $cachedDomainScore[$p.Name] = [int]$p.Value }
        }
        $cachedSevByDomain = @{}
        if ($c.SevByDomain) {
            foreach ($p in $c.SevByDomain.PSObject.Properties) {
                $bucket = @{}
                foreach ($sp in $p.Value.PSObject.Properties) { $bucket[$sp.Name] = [int]$sp.Value }
                $cachedSevByDomain[$p.Name] = $bucket
            }
        }
        # v2.2.386 -- derive SevCount + TotalRows from the cached SevByDomain so
        # the email KPI table's Total row equals the sum of its per-domain rows.
        # Pre-v2.2.386: per-domain rows used cached (from peer template), Total
        # row used live (this template's run-specific row count). Detailed's live
        # tally happened to match its per-domain sum (1:1 per row); Summary's
        # live tally collapsed many asset-findings into one row -- so Summary's
        # Total cell showed e.g. 248 while per-domain summed to 1107. Operators
        # saw "Total = sum of per-domain" violated for Summary template only.
        # Deriving from cached per-domain makes the invariant hold by construction
        # regardless of which template's tally the cache stored.
        $derivedSevCount  = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0 }
        $derivedTotalRows = 0
        if ($cachedSevByDomain.Count -gt 0) {
            foreach ($_dn in $cachedSevByDomain.Keys) {
                foreach ($_sk in @('Critical','High','Medium','Low','Other')) {
                    if ($cachedSevByDomain[$_dn].ContainsKey($_sk)) {
                        $derivedSevCount[$_sk] += [int]$cachedSevByDomain[$_dn][$_sk]
                    }
                }
                if ($cachedSevByDomain[$_dn].ContainsKey('Total')) {
                    $derivedTotalRows += [int]$cachedSevByDomain[$_dn]['Total']
                }
            }
        }
        $global:RA_KPI = [pscustomobject]@{
            GlobalScore  = $cachedScore
            Band         = if ($c.Band) { [string]$c.Band } else { $band }
            RiskLevel    = if ($c.RiskLevel) { [string]$c.RiskLevel } else { $bcRiskLevel }
            DomainScore  = if ($cachedDomainScore.Count -gt 0) { $cachedDomainScore } else { $domainScore }
            SevCount     = if ($cachedSevByDomain.Count -gt 0) { $derivedSevCount }  else { $sevCount }
            SevByDomain  = if ($cachedSevByDomain.Count -gt 0) { $cachedSevByDomain } else { $sevByDomain }
            TotalRows    = if ($cachedSevByDomain.Count -gt 0) { $derivedTotalRows } else { $rows.Count }
            Direction    = 'higher-is-better'
        }
        Write-Info ("[SCORE] OVERRIDE with cached values from AI summary cache: live={0} -> cached={1} (template '{2}' won the cache; ensures Summary + Detailed emails show identical headline KPI within {3}h window)." -f `
            $liveScore, $cachedScore, $c.SourceTemplate, $aiSummaryMaxAgeHours)
    }
    # When THIS run produced the cached AI summary, write the just-computed KPI
    # back into the cache file so the SECOND template (e.g. Detailed after Summary)
    # finds the GlobalScore on its next read. Same idempotent file path.
    elseif ($script:_RACacheNeedsKPIUpdate -and $global:RA_KPI) {
        try {
            $cachedNow = Get-RATop50CachedFile
            if (-not $cachedNow -or -not $cachedNow.Data) {
                Write-Warn2 "[AISummaryCache] cache file disappeared between AI-write and KPI-update; skipping KPI persist for this run."
            } elseif ($cachedNow.Data.PSObject.Properties['GlobalScore'] -and $null -ne $cachedNow.Data.GlobalScore) {
                # v2.2.352 -- another concurrent run already backfilled the KPI.
                # First-writer-wins -- DON'T overwrite. Adopt the peer's KPI for
                # this run's email too so both reports show the identical score.
                Write-Info ("[AISummaryCache] race detected on KPI backfill: peer already wrote GlobalScore={0}. Adopting peer's KPI for this run's email." -f $cachedNow.Data.GlobalScore)
                $script:_CachedRAKPI = $cachedNow.Data
                # Re-run the override block by rebuilding $global:RA_KPI with cached values.
                $cachedDomainScore = @{}
                if ($cachedNow.Data.DomainScore) { foreach ($p in $cachedNow.Data.DomainScore.PSObject.Properties) { $cachedDomainScore[$p.Name] = [int]$p.Value } }
                $cachedSevByDomain = @{}
                if ($cachedNow.Data.SevByDomain) {
                    foreach ($p in $cachedNow.Data.SevByDomain.PSObject.Properties) {
                        $bucket = @{}
                        foreach ($sp in $p.Value.PSObject.Properties) { $bucket[$sp.Name] = [int]$sp.Value }
                        $cachedSevByDomain[$p.Name] = $bucket
                    }
                }
                # v2.2.386 -- mirror the SevCount/TotalRows derivation from the primary
                # cache-rehydrate block so the email Total row equals sum of per-domain
                # rows for race-detected backfills too.
                $derivedSevCount2  = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0 }
                $derivedTotalRows2 = 0
                if ($cachedSevByDomain.Count -gt 0) {
                    foreach ($_dn in $cachedSevByDomain.Keys) {
                        foreach ($_sk in @('Critical','High','Medium','Low','Other')) {
                            if ($cachedSevByDomain[$_dn].ContainsKey($_sk)) {
                                $derivedSevCount2[$_sk] += [int]$cachedSevByDomain[$_dn][$_sk]
                            }
                        }
                        if ($cachedSevByDomain[$_dn].ContainsKey('Total')) {
                            $derivedTotalRows2 += [int]$cachedSevByDomain[$_dn]['Total']
                        }
                    }
                }
                $global:RA_KPI = [pscustomobject]@{
                    GlobalScore  = [int]$cachedNow.Data.GlobalScore
                    Band         = if ($cachedNow.Data.Band)      { [string]$cachedNow.Data.Band }      else { $global:RA_KPI.Band }
                    RiskLevel    = if ($cachedNow.Data.RiskLevel) { [string]$cachedNow.Data.RiskLevel } else { $global:RA_KPI.RiskLevel }
                    DomainScore  = if ($cachedDomainScore.Count -gt 0) { $cachedDomainScore } else { $global:RA_KPI.DomainScore }
                    SevCount     = if ($cachedSevByDomain.Count -gt 0) { $derivedSevCount2 }  else { $global:RA_KPI.SevCount }
                    SevByDomain  = if ($cachedSevByDomain.Count -gt 0) { $cachedSevByDomain } else { $global:RA_KPI.SevByDomain }
                    TotalRows    = if ($cachedSevByDomain.Count -gt 0) { $derivedTotalRows2 } else { $global:RA_KPI.TotalRows }
                    Direction    = 'higher-is-better'
                }
                $script:_RACacheNeedsKPIUpdate = $false
            } else {
                $shared = $cachedNow.Data
                $shared | Add-Member -NotePropertyName GlobalScore -NotePropertyValue ([int]$global:RA_KPI.GlobalScore)   -Force
                $shared | Add-Member -NotePropertyName Band        -NotePropertyValue ([string]$global:RA_KPI.Band)        -Force
                $shared | Add-Member -NotePropertyName RiskLevel   -NotePropertyValue ([string]$global:RA_KPI.RiskLevel)   -Force
                $shared | Add-Member -NotePropertyName DomainScore -NotePropertyValue $global:RA_KPI.DomainScore           -Force
                $shared | Add-Member -NotePropertyName SevByDomain -NotePropertyValue $global:RA_KPI.SevByDomain           -Force
                $jsonContent = $shared | ConvertTo-Json -Depth 12 -Compress
                Save-RATop50CachedFile -JsonContent $jsonContent
                Write-Info ("[AISummaryCache] persisted fresh Risk Score KPI (GlobalScore={0}, Band='{1}') to shared cache; next RA run (Summary or Detailed) within {2}h will reuse this score." -f `
                    $global:RA_KPI.GlobalScore, $global:RA_KPI.Band, $aiSummaryMaxAgeHours)
                $script:_RACacheNeedsKPIUpdate = $false
            }
        } catch {
            Write-Warn2 ("[AISummaryCache] failed to persist Risk Score KPI to shared cache: {0} (live KPI still shown in this run's email)." -f $_.Exception.Message)
        }
    }
} catch {
    Write-Warn2 ("KPI rollup failed: {0} (continuing -- mail will degrade gracefully)" -f $_.Exception.Message)
}

#####################################################################################################
# SEND OUTPUT VIA MAIL
#####################################################################################################

# Suppress the mail dispatch when zero rows were produced this run. A "0 findings"
# email creates noise that erodes trust in real findings emails (operators stop
# reading SI mail). Customer can force-send the empty report (e.g. as a heartbeat
# that "SI ran successfully today") via $global:RA_MailEvenIfEmpty = $true.
if ([bool]$global:Report_SendMail -and -not [bool]$global:RA_MailEvenIfEmpty) {
    $__rowCount = if ($null -ne $global:final) { @($global:final).Count } else { 0 }
    if ($__rowCount -eq 0) {
        Write-Warn2 "mail dispatch suppressed: 0 rows produced this run. Set `$global:RA_MailEvenIfEmpty=`$true to receive empty-report emails as a heartbeat."
        $global:Report_SendMail = $false
    }
}

Write-Section "mail dispatch decision"

if ([bool]$global:Report_SendMail -eq $true) {

    $to          = @($global:Report_To)
    # From address -- resolve in order:
    #   1) $global:SMTPFrom   (canonical; required when SMTP relay demands a verified sender,
    #      e.g. Brevo/SendGrid/Postmark reject mail whose From != verified sender)
    #   2) $global:MailFrom   (shorthand)
    #   3) $global:SMTPUser   (legacy fallback; works only when the relay accepts the
    #      SMTP-login-as-sender, which most modern relays do NOT)
    $from = $null
    foreach ($_c in 'SMTPFrom','MailFrom','SMTPUser') {
        $_v = (Get-Variable -Scope Global -Name $_c -ValueOnly -ErrorAction SilentlyContinue)
        if (-not [string]::IsNullOrWhiteSpace([string]$_v)) { $from = [string]$_v; break }
    }
    if ([string]::IsNullOrWhiteSpace($from)) {
        # degrade gracefully -- run produced xlsx + json + LA ingest already.
        # Skipping mail because no From is configured shouldn't kill the engine; log loudly
        # so the operator notices and either sets $global:SMTPFrom or flips SendMail off.
        Write-Warn2 "Mail enabled but no From address configured. Set `$global:SMTPFrom (preferred), `$global:MailFrom, or `$global:SMTPUser. Skipping mail dispatch -- xlsx + json artifacts are still on disk + ingested to LA."
        return
    }
    # Tenant tag for the subject -- lets a multi-tenant operator separate
    # incoming reports at a glance. Resolved in priority order:
    #   1) $global:TenantShort           e.g. "myfamilynetwork"   (cleanest)
    #   2) $global:TenantNameOrganization e.g. "contoso.onmicrosoft.com"
    #   3) $global:AzureTenantID / SpnTenantId -- GUID fallback
    # Skipped silently when none of these are populated (subject stays clean).
    $tenantTag = $null
    foreach ($_c in 'TenantShort','TenantNameOrganization','AzureTenantID','SpnTenantId') {
        $_v = (Get-Variable -Scope Global -Name $_c -ValueOnly -ErrorAction SilentlyContinue)
        if (-not [string]::IsNullOrWhiteSpace([string]$_v)) { $tenantTag = [string]$_v; break }
    }
    $subject     = if ([string]::IsNullOrWhiteSpace($tenantTag)) {
        "Security Insights | Risk Analysis | $($global:ReportTemplate)"
    } else {
        "Security Insights | Risk Analysis | $($global:ReportTemplate) | $tenantTag"
    }
    $attachments = @($global:OutputXlsx)

    $aiEnabled = [bool]$global:BuildSummaryByAI

    # ----- minimal markdown -> HTML for the AI section -----
    # Handles the subset the AI prompt produces:
    #   ## H2 / ### H3
    #   **bold** / _italic_
    #   - bullet (line-leading "- ")
    #   blank line -> paragraph break
    function _MdToHtml([string]$src) {
        if ([string]::IsNullOrWhiteSpace($src)) { return '' }
        # 1. HTML-escape, normalize newlines.
        $s = $src -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
        $s = $s -replace "`r`n","`n" -replace "`r","`n"
        # 2. Inline conversions (links + bold + italic). Links FIRST so the
        # bracket+paren form ([text](url)) doesn't get clobbered by later passes.
        # Note: at this point '<' / '>' are already &lt; / &gt;, so the pattern
        # works on the post-escape text -- the rendered <a> tag we emit is fine
        # because we use &gt; only inside text, never inside our own tags.
        $s = [regex]::Replace($s, '\[([^\]\n]+)\]\((https?://[^\s)]+)\)', {
            param($m)
            $label = $m.Groups[1].Value
            $url   = $m.Groups[2].Value -replace '"','&quot;'
            return ('<a href="' + $url + '" style="color:#2c5a8e;text-decoration:underline;" target="_blank" rel="noopener">' + $label + '</a>')
        })
        # Bare URLs not inside a markdown link -- auto-link them too so the AI
        # can drop a raw URL and it still renders as a click.
        $s = [regex]::Replace($s, '(?<![">])(https?://[^\s<>"`)\]]+)', '<a href="$1" style="color:#2c5a8e;text-decoration:underline;" target="_blank" rel="noopener">$1</a>')
        $s = [regex]::Replace($s, '\*\*([^\*\n]+?)\*\*', '<strong>$1</strong>')
        $s = [regex]::Replace($s, '(^|\s)_([^_\n]+?)_(\s|[\.,;:\)\]]|$)', '$1<em>$2</em>$3')
        # 3. Block conversions, line by line, with bullet group folding.
        $lines = $s -split "`n"
        $out   = New-Object System.Collections.Generic.List[string]
        $inUl  = $false
        $closeUl = { if ($inUl) { [void]$out.Add('</ul>'); $script:inUl = $false } }
        $script:inUl = $false
        for ($i = 0; $i -lt $lines.Length; $i++) {
            $ln  = $lines[$i]
            $raw = $ln.TrimEnd()
            # nested-bullet: "  - text" -> indented li
            if ($raw -match '^(\s{2,})-\s+(.+)$') {
                if (-not $script:inUl) { [void]$out.Add('<ul style="margin:4px 0 8px 22px;padding:0;">'); $script:inUl = $true }
                [void]$out.Add('<li style="margin:4px 0 4px 14px;color:#555;">' + $matches[2] + '</li>')
                continue
            }
            if ($raw -match '^-\s+(.+)$') {
                if (-not $script:inUl) { [void]$out.Add('<ul style="margin:4px 0 10px 18px;padding:0;">'); $script:inUl = $true }
                [void]$out.Add('<li style="margin:4px 0;">' + $matches[1] + '</li>')
                continue
            }
            if ($raw -match '^###\s+(.+)$') {
                if ($script:inUl) { [void]$out.Add('</ul>'); $script:inUl = $false }
                [void]$out.Add('<h4 style="margin:14px 0 4px 0;font-size:13px;color:#1a3a5e;">' + $matches[1] + '</h4>')
                continue
            }
            if ($raw -match '^##\s+(.+)$') {
                if ($script:inUl) { [void]$out.Add('</ul>'); $script:inUl = $false }
                [void]$out.Add('<h3 style="margin:18px 0 6px 0;font-size:15px;color:#1a3a5e;border-bottom:1px solid #e0e6ed;padding-bottom:4px;">' + $matches[1] + '</h3>')
                continue
            }
            if ([string]::IsNullOrWhiteSpace($raw)) {
                if ($script:inUl) { [void]$out.Add('</ul>'); $script:inUl = $false }
                continue
            }
            # plain paragraph
            if ($script:inUl) { [void]$out.Add('</ul>'); $script:inUl = $false }
            [void]$out.Add('<p style="margin:6px 0;">' + $raw + '</p>')
        }
        if ($script:inUl) { [void]$out.Add('</ul>'); $script:inUl = $false }
        return ($out -join "`n")
    }

    # ----- AI summary block (if enabled) -----
    # v2.2.404 -- compute snapshot-source attribution. The KPI banner, Top-50
    # risky assets list, and AI narrative are all snapshots from the first
    # template (Summary or Detailed) to complete in the current 24h window.
    # The second template's email silently reuses the cached snapshot without
    # surfacing that fact -- operators couldn't tell whether they were reading
    # live-from-this-report content or carried-over-from-a-peer content.
    # When the cache won (_CachedRAKPI populated), report source template +
    # age. When live (cache empty), report this run's template.
    $aiSourceLine = ''
    if ($script:_CachedRAKPI -and $null -ne $script:_CachedRAKPI.GlobalScore -and $script:_CachedRAKPI.SourceTemplate) {
        $_srcTpl = [string]$script:_CachedRAKPI.SourceTemplate
        $_ageHrs = -1.0
        try {
            $_gen = if ($script:_CachedRAKPI.GeneratedAt -is [DateTime]) { [DateTime]$script:_CachedRAKPI.GeneratedAt } else { [DateTime]::Parse([string]$script:_CachedRAKPI.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
            $_ageHrs = [Math]::Round(((Get-Date) - $_gen.ToLocalTime()).TotalHours, 1)
        } catch { }
        if ($_ageHrs -ge 0) {
            $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated by <strong>{0}</strong> {1}h ago (within 24h window -- this <strong>{2}</strong> run reused the snapshot). Re-runs of either template within 24h replay the same snapshot." -f $_srcTpl, $_ageHrs, $global:ReportTemplate)
        } else {
            $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated by <strong>{0}</strong> (within 24h window -- this <strong>{1}</strong> run reused the snapshot)." -f $_srcTpl, $global:ReportTemplate)
        }
    } else {
        $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated <strong>live by this run</strong> ({0}). Next template run within 24h will replay this snapshot." -f $global:ReportTemplate)
    }

    $aiSection = ''
    if ($aiEnabled) {
        $aiHtml = ''
        if (-not [string]::IsNullOrWhiteSpace($global:AI_SummaryText)) {
            $aiHtml = _MdToHtml ($global:AI_SummaryText.Trim())
        } else {
            $aiHtml = 'AI summary was enabled, but no AI summary output was produced.'
        }
        $aiSection = @"
        <h2 style="margin:28px 0 8px 0;font-family:Segoe UI,Arial,sans-serif;font-size:18px;color:#1a3a5e;border-bottom:2px solid #e0e6ed;padding-bottom:6px;">AI-generated analysis</h2>
        <div style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#333;line-height:1.55;">$aiHtml</div>
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#888;margin-top:10px;font-style:italic;">This narrative was generated by AI and may contain mistakes. Validate critical decisions against the detailed Excel findings.</p>
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#5a6a7a;margin-top:4px;">$aiSourceLine</p>
"@
    } else {
        $aiSection = @"
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#888;margin-top:18px;">AI narrative not included this run. Enable with <code>$global:BuildSummaryByAI=`$true</code> in the launcher.</p>
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#5a6a7a;margin-top:4px;">$aiSourceLine</p>
"@
    }

    # ----- KPI banner color per band (Microsoft Cloud Secure Score bands) -----
    $kpi = $global:RA_KPI
    if ($null -eq $kpi) {
        $kpi = [pscustomobject]@{
            GlobalScore = 100; Band = 'Very Good'; RiskLevel = 'Low';
            DomainScore = @{ Endpoint=100; Identity=100; Azure=100; PublicIP=100 };
            SevCount    = @{ Critical=0; High=0; Medium=0; Low=0; Other=0 };
            SevByDomain = @{
                Endpoint = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
                Identity = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
                Azure    = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
                PublicIP = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
            }
            TotalRows   = (@($global:final).Count)
        }
    }
    if (-not $kpi.PSObject.Properties['SevByDomain']) {
        $kpi | Add-Member -NotePropertyName SevByDomain -NotePropertyValue @{
            Endpoint = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
            Identity = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
            Azure    = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
            PublicIP = @{ Critical=0; High=0; Medium=0; Low=0; Total=0 }
        } -Force
    }
    if (-not $kpi.PSObject.Properties['Band']) {
        $kpi | Add-Member -NotePropertyName Band -NotePropertyValue 'Unknown' -Force
    }
    # Higher = better. Bands: At Risk 0-49 (red) | Moderate 50-74 (orange) |
    # Good 75-89 (light green) | Very Good 90-100 (dark green).
    $bandColor = switch ($kpi.Band) {
        'Very Good' { '#1b5e20' }
        'Good'      { '#2e7d32' }
        'Moderate'  { '#ef6c00' }
        'At Risk'   { '#c62828' }
        default     { '#546e7a' }
    }
    $levelColor = $bandColor   # back-compat alias for any remaining $levelColor refs

    # ----- Domain tile builder -----
    # New direction: HIGHER = BETTER. Color bands match Microsoft Cloud Secure Score:
    #   90-100 Very Good (dark green) | 75-89 Good (light green) |
    #   50-74 Moderate (orange)       | 0-49  At Risk (red)
    function _DomainTile([string]$name, [int]$score) {
        $bg  = if ($score -ge 90) { '#e8f5e9' } elseif ($score -ge 75) { '#f1f8f1' } elseif ($score -ge 50) { '#fff4e5' } else { '#fdecea' }
        $bar = if ($score -ge 90) { '#1b5e20' } elseif ($score -ge 75) { '#2e7d32' } elseif ($score -ge 50) { '#ef6c00' } else { '#c62828' }
        $w = [Math]::Max(2, [Math]::Min(100, $score))
        return @"
            <td width="25%" valign="top" style="padding:6px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background:$bg;border:1px solid #e0e6ed;border-radius:6px;">
                <tr><td style="padding:14px 14px 8px 14px;font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#5a6a7a;text-transform:uppercase;letter-spacing:.5px;">$name</td></tr>
                <tr><td style="padding:0 14px;font-family:Segoe UI,Arial,sans-serif;font-size:30px;font-weight:600;color:#1a3a5e;">$score<span style="font-size:14px;color:#8a99aa;font-weight:400;"> /100</span></td></tr>
                <tr><td style="padding:8px 14px 14px 14px;">
                  <div style="background:#ffffff;height:6px;border-radius:3px;overflow:hidden;">
                    <div style="background:$bar;width:$w%;height:6px;"></div>
                  </div>
                </td></tr>
              </table>
            </td>
"@
    }

    $tileEndpoint = _DomainTile 'Endpoint' ([int]$kpi.DomainScore['Endpoint'])
    $tileIdentity = _DomainTile 'Identity' ([int]$kpi.DomainScore['Identity'])
    $tileAzure    = _DomainTile 'Azure'    ([int]$kpi.DomainScore['Azure'])
    $tilePublicIP = _DomainTile 'Public IP' ([int]$kpi.DomainScore['PublicIP'])

    $genTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm zzz')
    $tenantLabel  = if ([string]::IsNullOrWhiteSpace($tenantTag)) { '&mdash;' } else { [System.Net.WebUtility]::HtmlEncode($tenantTag) }
    $reportLabel  = [System.Net.WebUtility]::HtmlEncode([string]$global:ReportTemplate)
    $solVer       = if ([string]::IsNullOrWhiteSpace([string]$global:RA_SolutionVersion)) { '(dev)' } else { [string]$global:RA_SolutionVersion }

    $sev = $kpi.SevCount
    $rowsTotal = [int]$kpi.TotalRows

    # ----- Severity x Domain breakdown table builder -----
    # Row order: per-domain rows first, then a bold Total row at the bottom
    # (spreadsheet-style subtotal). Columns: Domain | Total | Critical | High |
    # Medium | Low.
    #
    # Each severity cell uses BOTH a tinted background AND a saturated text color
    # so the semantic encoding survives clients that auto-invert colors in dark
    # mode (Outlook desktop dark, Yahoo dark) -- the cells stay visually distinct
    # even after inversion.
    function _SevCell([int]$value, [string]$bg, [string]$fg, [string]$weight, [string]$top) {
        $cellStyle = "padding:6px 10px;background-color:$bg;color:$fg;font-weight:$weight;$top"
        return "                  <td align=`"right`" style=`"$cellStyle`">$value</td>"
    }
    function _SevRow([string]$label, [hashtable]$d, [bool]$isTotalRow) {
        $rowBg  = if ($isTotalRow) { '#f3f5f8' } else { '#ffffff' }
        $weight = if ($isTotalRow) { '700' }     else { '500' }
        $top    = if ($isTotalRow) { 'border-top:2px solid #1a3a5e;' } else { 'border-top:1px solid #eef2f7;' }
        $cCrit = _SevCell ([int]$d['Critical']) '#fdecea' '#7a1414' $weight $top
        $cHigh = _SevCell ([int]$d['High'])     '#fff4e5' '#8a3d00' $weight $top
        $cMed  = _SevCell ([int]$d['Medium'])   '#fffde7' '#7a5d00' $weight $top
        $cLow  = _SevCell ([int]$d['Low'])      '#e8f5e9' '#1b5e20' $weight $top
        return @"
                <tr style="background-color:$rowBg;">
                  <td style="padding:6px 10px;background-color:$rowBg;color:#1a3a5e;font-weight:$weight;$top">$label</td>
                  <td align="right" style="padding:6px 10px;background-color:$rowBg;color:#1a3a5e;font-weight:$weight;$top">$($d['Total'])</td>
$cCrit
$cHigh
$cMed
$cLow
                </tr>
"@
    }
    $sbd = $kpi.SevByDomain
    $totalRow = @{
        Total = $rowsTotal
        Critical = [int]$sev['Critical']
        High     = [int]$sev['High']
        Medium   = [int]$sev['Medium']
        Low      = [int]$sev['Low']
    }
    $sevTableRows = (_SevRow 'Endpoint'  $sbd['Endpoint'] $false) +
                    (_SevRow 'Identity'  $sbd['Identity'] $false) +
                    (_SevRow 'Azure'     $sbd['Azure']    $false) +
                    (_SevRow 'Public IP' $sbd['PublicIP'] $false) +
                    (_SevRow 'Total'     $totalRow        $true)

    $bodyHtml = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- Pin to light rendering across clients that support color-scheme so we stay
     visually consistent in Apple Mail / iOS Mail / modern Outlook dark-mode
     setups. Most major clients honor at least one of these two hints. -->
<meta name="color-scheme" content="light only">
<meta name="supported-color-schemes" content="light only">
<!--[if mso]>
<style type="text/css">
  body, table, td, h1, h2, h3, h4, p, span, a { color-scheme: light only !important; }
</style>
<![endif]-->
</head>
<body style="margin:0;padding:0;background:#f3f5f8;color:#1a3a5e;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f5f8;padding:20px 0;">
  <tr><td align="center">
    <table width="720" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e0e6ed;border-radius:8px;max-width:720px;">

      <!-- Banner -->
      <tr><td style="background:linear-gradient(135deg,#1a3a5e 0%,#2c5a8e 100%);background-color:#1a3a5e;padding:22px 28px;border-radius:8px 8px 0 0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td valign="middle" style="font-family:Segoe UI,Arial,sans-serif;color:#ffffff;font-size:22px;font-weight:600;">SecurityInsight &middot; Risk Analysis</td>
            <td valign="middle" align="right" style="font-family:Segoe UI,Arial,sans-serif;color:#cfdce8;font-size:12px;">
              $reportLabel<br>
              <span style="color:#9bb4cd;">$tenantLabel &middot; $genTimestamp</span>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- Executive summary hero -->
      <tr><td style="padding:24px 28px 8px 28px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td width="32%" valign="middle" style="font-family:Segoe UI,Arial,sans-serif;">
              <div style="font-size:12px;color:#5a6a7a;text-transform:uppercase;letter-spacing:.5px;">Risk Score KPI</div>
              <div style="font-size:54px;font-weight:700;color:$bandColor;line-height:1;margin:6px 0 4px 0;">$($kpi.GlobalScore)<span style="font-size:22px;color:#8a99aa;font-weight:400;"> /100</span></div>
              <div style="display:inline-block;background:$bandColor;color:#ffffff;padding:4px 12px;border-radius:14px;font-size:12px;font-weight:600;letter-spacing:.5px;">$($kpi.Band.ToUpper())</div>
              <div style="font-size:10px;color:#8a99aa;margin-top:6px;">higher = better &middot; 90+ Very Good &middot; 75+ Good &middot; 50+ Moderate &middot; &lt;50 At Risk</div>
            </td>
            <td width="68%" valign="middle" style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#333;padding-left:18px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="font-size:12px;border-collapse:collapse;">
                <thead>
                  <tr style="background:#1a3a5e;color:#ffffff;">
                    <th align="left"  style="padding:8px 10px;text-transform:uppercase;letter-spacing:.5px;font-size:11px;font-weight:600;">Domain</th>
                    <th align="right" style="padding:8px 10px;text-transform:uppercase;letter-spacing:.5px;font-size:11px;font-weight:600;">Total</th>
                    <th align="right" style="padding:8px 10px;text-transform:uppercase;letter-spacing:.5px;font-size:11px;font-weight:600;">Critical</th>
                    <th align="right" style="padding:8px 10px;text-transform:uppercase;letter-spacing:.5px;font-size:11px;font-weight:600;">High</th>
                    <th align="right" style="padding:8px 10px;text-transform:uppercase;letter-spacing:.5px;font-size:11px;font-weight:600;">Medium</th>
                    <th align="right" style="padding:8px 10px;text-transform:uppercase;letter-spacing:.5px;font-size:11px;font-weight:600;">Low</th>
                  </tr>
                </thead>
                <tbody>
$sevTableRows
                </tbody>
              </table>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- Domain KPI tiles -->
      <tr><td style="padding:8px 22px 4px 22px;">
        <h3 style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#5a6a7a;text-transform:uppercase;letter-spacing:.5px;margin:0 6px 4px 6px;">Risk by domain</h3>
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
$tileEndpoint
$tileIdentity
$tileAzure
$tilePublicIP
          </tr>
        </table>
      </td></tr>

      <!-- Body copy -->
      <tr><td style="padding:18px 28px 4px 28px;font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#333;line-height:1.55;">
        <p style="margin:0 0 10px 0;">The attached Excel report contains the full prioritized list of findings ranked by RiskScore, with evidence and asset detail on the <em>Details</em> sheet.</p>
$aiSection
      </td></tr>

      <!-- Footer -->
      <tr><td style="padding:18px 28px 22px 28px;border-top:1px solid #e0e6ed;font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#8a99aa;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td>SecurityInsight &middot; Risk Analysis &middot; <a href="https://github.com/KnudsenMorten/SecurityInsight" style="color:#2c5a8e;text-decoration:none;">github.com/KnudsenMorten/SecurityInsight</a><br>
                Support: Morten Knudsen &lt;mok@mortenknudsen.net&gt;</td>
            <td align="right" style="white-space:nowrap;">Build <strong style="color:#1a3a5e;">v$solVer</strong></td>
          </tr>
        </table>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>
"@

    # Auto-assemble the SMTP PSCredential if the customer only provided
    # username + password strings. This avoids Send-MailMessage prompting
    # interactively for credentials when $global:SecureCredentialsSMTP is
    # $null.
    #
    # Fallback chain -- tries each (userVar, passwordVar) pair and uses the
    # first one where both are populated. Covers the canonical SI naming plus
    # common platform-defaults / AF-prefixed variants.
    if (-not [bool]$global:Mail_SendAnonymous -and -not $global:SecureCredentialsSMTP) {
        $credPairs = @(
            @{ User = 'SMTPUser';                 Password = 'SMTPPassword' }                # canonical SI
            @{ User = 'SmtpUser';                 Password = 'SmtpPassword' }                # camelCase variant
            @{ User = 'SmtpUsername';             Password = 'SmtpPassword' }                # -Username suffix
            @{ User = 'Mail_SmtpUser';            Password = 'Mail_SmtpPassword' }           # Mail_ prefix
            @{ User = 'Mail_SMTPUser';            Password = 'Mail_SMTPPassword' }           # Mail_ prefix + SMTP upper
            @{ User = 'Mail_Username';            Password = 'Mail_Password' }               # Mail_Username/Password
            @{ User = 'MailUser';                 Password = 'MailPassword' }                # bare MailUser
            @{ User = 'SMTP_User';                Password = 'SMTP_Password' }               # SMTP_User/SMTP_Password
            @{ User = 'Mail_SecurityInsight_Username'; Password = 'Mail_SecurityInsight_Password' }  # AF-style SI-scoped
        )
        $resolvedUser   = $null
        $resolvedPwd    = $null
        $resolvedLabel  = $null
        foreach ($pair in $credPairs) {
            $uVal = (Get-Variable -Scope Global -Name $pair.User     -ValueOnly -ErrorAction SilentlyContinue)
            $pVal = (Get-Variable -Scope Global -Name $pair.Password -ValueOnly -ErrorAction SilentlyContinue)
            if (-not [string]::IsNullOrWhiteSpace([string]$uVal) -and
                -not [string]::IsNullOrWhiteSpace([string]$pVal)) {
                $resolvedUser  = [string]$uVal
                $resolvedPwd   = [string]$pVal
                $resolvedLabel = ("`$global:{0} + `$global:{1}" -f $pair.User, $pair.Password)
                break
            }
        }

        if ($resolvedUser) {
            $__secPwd = ConvertTo-SecureString $resolvedPwd -AsPlainText -Force
            $global:SecureCredentialsSMTP = New-Object System.Management.Automation.PSCredential ($resolvedUser, $__secPwd)
            # Also fill the canonical $global:SMTPUser if it wasn't the pair that resolved,
            # so downstream code that reads it (e.g. the From address) still works.
            if ([string]::IsNullOrWhiteSpace([string]$global:SMTPUser)) { $global:SMTPUser = $resolvedUser }
            Write-Info ("SMTP credential assembled from {0}" -f $resolvedLabel)
        } else {
            # v2.2.222 -- INFER anonymous when no credentials resolved AND no explicit
            # toggle. Rationale: "no user + no password" can only mean anonymous relay;
            # forcing the operator to ALSO set $global:Mail_SendAnonymous = $true was
            # ceremony with no information value. If the relay actually requires auth,
            # the SMTP layer will reject with "530 Authentication required" -- the
            # error surfaces just as visibly, one layer later.
            # The diagnostic dump immediately below prints `Anonymous : 'True'` so the
            # operator can see what the engine is about to do; a Warn here makes it
            # impossible to miss in the log.
            $global:Mail_SendAnonymous = $true
            Write-Warn2 "No SMTP credentials found and no explicit `$global:Mail_SendAnonymous; INFERRING anonymous relay. If the SMTP server requires auth, expect a 530-style rejection. To silence this warning, set `$global:Mail_SendAnonymous = `$true explicitly in your LauncherConfig.custom.ps1 / platform-defaults.ps1 / <Solution>.custom.ps1, or provide a credential pair (e.g. `$global:SMTPUser + `$global:SMTPPassword)."
        }
    }

    # Diagnostic dump -- so the operator can see EXACTLY what the engine is
    # about to use for this send (helps when "OK" but no email arrives = the
    # From / Server / User the engine sees != the verified-sender at the relay).
    $__userLabel = if ($global:SecureCredentialsSMTP) { $global:SecureCredentialsSMTP.UserName } else { '<none -- anonymous>' }
    Write-Info ("MAIL DISPATCH PARAMS:")
    Write-Info ("   From       : '{0}'" -f $from)
    Write-Info ("   To         : '{0}'" -f ($to -join ', '))
    Write-Info ("   SmtpServer : '{0}'" -f $global:SmtpServer)
    Write-Info ("   SmtpPort   : '{0}'" -f $global:SMTPPort)
    Write-Info ("   UseSSL     : '{0}'" -f $global:SMTP_UseSSL)
    Write-Info ("   SmtpUser   : '{0}'" -f $__userLabel)
    Write-Info ("   Anonymous  : '{0}'" -f ([bool]$global:Mail_SendAnonymous))

    try {
        if ([bool]$global:Mail_SendAnonymous) {
            Write-Step ("sending mail anonymously to: {0}" -f ($to -join ', '))
            # v2.2.247 -- Send-MailAnonymous now returns [bool] (true=sent,
            # false=failed-with-details-printed-inline). Gate the [OK] line on
            # the return value so we never claim success when the relay
            # actually rejected. Script continues regardless ("no -stop").
            $mailOk = Send-MailAnonymous -SmtpServer $global:SmtpServer -Port $global:SMTPPort -UseSsl $global:SMTP_UseSSL `
                          -From $from -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments
            if ($mailOk) {
                Write-Ok "anonymous mail sent (NOTE: SMTP 250 OK only proves the relay accepted the message -- verify actual delivery in your SMTP provider's activity log + the recipient's junk folder)"
            } else {
                Write-Err2 "anonymous mail FAILED -- see TCP pre-flight / SMTP exception details immediately above. Engine continues (mail is non-fatal); fix the cause and re-run, or set credentials if the relay requires AUTH."
            }
        }
        else {
            Write-Step ("sending mail using secure credentials to: {0}" -f ($to -join ', '))
            Send-MailSecure -SmtpServer $global:SmtpServer -Port $global:SMTPPort -UseSsl $global:SMTP_UseSSL `
                -Credential $global:SecureCredentialsSMTP -From $from -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments
            Write-Ok "secure mail sent (NOTE: SMTP 250 OK only proves the relay accepted the message -- verify actual delivery in your SMTP provider's activity log + the recipient's junk folder)"
        }
    }
    catch {
        Write-Err2 ("mail failed: {0}" -f $_.Exception.Message)
        if ($_.Exception.InnerException) {
            Write-Err2 ("   inner    : {0}" -f $_.Exception.InnerException.Message)
        }
        if ($_.Exception.GetType().FullName) {
            Write-Err2 ("   type     : {0}" -f $_.Exception.GetType().FullName)
        }
        if ($_.ScriptStackTrace) {
            Write-Err2 ("   stack    :`n{0}" -f $_.ScriptStackTrace)
        }
    }
}
else {
    Write-Info "mail flag disabled; not sending"
}

# AUDIT #57.1(a) -- compare this run against the previous one and say so out loud. Runs only on a
# completed run, so a crashed/partial run never poisons the baseline with its truncated counts.
try {
    if ($null -ne $global:RA_RowCountsThisRun -and $global:RA_RowCountsThisRun.Count -gt 0) {
        Write-Section "row-count guard"
        $__tplName = [string]$global:ReportTemplate
        if ([string]::IsNullOrWhiteSpace($__tplName)) { $__tplName = 'UnknownTemplate' }
        $null = Invoke-RARowCountGuard -SettingsPath $global:SettingsPath `
                                       -TemplateName $__tplName `
                                       -Counts $global:RA_RowCountsThisRun
    }
} catch {
    # A guard must never be the reason a good run fails.
    Write-Warn2 ("[RowCountGuard] skipped: {0}" -f $_.Exception.Message)
}

Send-RARunHealthEnd -ExitReason 'success'
Write-Section "script completed"
