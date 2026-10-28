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

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }

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
#  -WhatIfMode = a DRY RUN (#257). It used to REFUSE (#22: the switch had been inert -- a "dry run"
#  ingested to Log Analytics, uploaded the export file and SENT MAIL). Now the queries run and the
#  report is built and saved to the local OUTPUT folder (xlsx + json) as usual. NOT done:
#    * the Log Analytics ingest (SendToLogAnalytics)      * the export upload (ExportDestination)
#    * the mail                                            * the run-health row
#    * the shared AI-summary snapshot (local file and blob) -- the next real report would adopt its figures
#  Each gate sits at its write and says "dry run" in the log.
# ----------------------------------------------------------------------
$script:SIWhatIf = [bool]$global:WhatIfMode
if ($script:SIWhatIf) {
    Write-Host '[dry run] -WhatIfMode: the report is built and saved locally; nothing is sent to Log Analytics, uploaded or mailed.' -ForegroundColor Yellow
}

# No PowerShell modules: Azure, Graph, Defender and Log Analytics ingestion are reached over plain REST.
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
#                                  (default: 'RiskAnalysis_Detailed')
#   3. $global:Summary  = $true -> $global:RiskAnalysis_ReportTemplate_Default_Summary
#                                  (default: 'RiskAnalysis_Summary')
#   4. Fallback: 'RiskAnalysis_Summary'
# (These defaults named '*_Bucket' templates that no shipped YAML defines; see Resolve-RALegacyTemplateName.)
if (-not $global:ReportTemplate -or [string]::IsNullOrWhiteSpace([string]$global:ReportTemplate)) {
    $__tmplDefaultDetailed = if (-not [string]::IsNullOrWhiteSpace([string]$global:RiskAnalysis_ReportTemplate_Default_Detailed)) {
        [string]$global:RiskAnalysis_ReportTemplate_Default_Detailed
    } else { 'RiskAnalysis_Detailed' }
    $__tmplDefaultSummary  = if (-not [string]::IsNullOrWhiteSpace([string]$global:RiskAnalysis_ReportTemplate_Default_Summary)) {
        [string]$global:RiskAnalysis_ReportTemplate_Default_Summary
    } else { 'RiskAnalysis_Summary' }
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
    # #709 / framework 8.16: every report that failed, did not apply or deviated rides on the run record as Reports[] (the
    # sender maps each to its code and cause). Built from what the run already knows; never fails the END record.
    try {
        if (Get-Command -Name Get-SIReportCauseFacts -ErrorAction SilentlyContinue) {
            $__lastGood = @{}
            $__facts = @(Get-SIReportCauseFacts -Notes $script:RAReportNotes -Failures @(if ($script:_RAReportFailures) { $script:_RAReportFailures.ToArray() }) `
                            -Incomplete @($script:_RAIncompleteReports) -Done $script:RAReportStatusDone -Retries $global:SI_UplinkRetryAnswers)
            if ($__facts.Count -and $script:RAStreamOn -and (Get-Command -Name Read-RAStreamLastGood -ErrorAction SilentlyContinue)) {
                try {
                    $__lastGood = Read-RAStreamLastGood -Stream $script:RAStream -Reports @($__facts | ForEach-Object { [string]$_.Report })
                    $__facts = @(Get-SIReportCauseFacts -Notes $script:RAReportNotes -Failures @(if ($script:_RAReportFailures) { $script:_RAReportFailures.ToArray() }) `
                                    -Incomplete @($script:_RAIncompleteReports) -Done $script:RAReportStatusDone -Retries $global:SI_UplinkRetryAnswers -LastGood $__lastGood)
                } catch { Write-Diag ("report causes: the last good run of the reports could not be read ({0})" -f $_.Exception.Message) }
            }
            # #709: the NotComplete reasons this collection already keeps in sidata.RaReportStatus -- a fact without a reason
            # takes its stored one, and a report only a queue worker judged is not left out of the run record
            if ($script:RAStreamOn -and $script:RAScaleRole -ne 'worker' -and (Get-Command -Name Add-SIReportCauseStoredReasons -ErrorAction SilentlyContinue) -and (Get-Command -Name Invoke-RAStreamSql -ErrorAction SilentlyContinue)) {
                try {
                    $__stored = @(Invoke-RAStreamSql -Stream $script:RAStream -Sql (Get-SIReportStatusReasonsSql) -Params @{ CollectionTime = $script:RAStream.TimeText; Grain = $script:RAStream.Grain } -Mode 'reader' -Attempts 1)
                    if ($__stored.Count) { $__facts = @(Add-SIReportCauseStoredReasons -Facts $__facts -Stored $__stored) }
                } catch { Write-Diag ("report causes: the stored reasons of the reports could not be read ({0})" -f $_.Exception.Message) }
            }
            # #902: a report held ON PURPOSE carries its hold (kind, runs in a row, escalated, the kept result and its age) -- the
            # uplink then sends it as held (si-ra-0911 / 0912, or 0913 / 0914 escalated), never as an unknown failure (si-ra-0900)
            if ($__facts.Count -and (Get-Command -Name Add-SIReportCauseHoldFacts -ErrorAction SilentlyContinue)) {
                try {
                    $__runUtc = $null
                    if ($null -ne $script:RAStream -and [string]$script:RAStream.TimeText) { $__runUtc = [datetime]::SpecifyKind([datetime]::Parse([string]$script:RAStream.TimeText, [Globalization.CultureInfo]::InvariantCulture), 'Utc') }
                    $__facts = @(Add-SIReportCauseHoldFacts -Facts $__facts -Held @((Get-RARunFailureSplit).Held) -RunUtc $__runUtc)
                } catch { Write-Diag ("report causes: the holds could not be added ({0})" -f $_.Exception.Message) }
            }
            if ($__facts.Count) { Add-Member -InputObject $script:_RunHealthCtx -NotePropertyName 'ReportCauses' -NotePropertyValue $__facts -Force }
        }
    } catch { Write-Diag ("report causes: not added to the run record ({0})" -f $_.Exception.Message) }
    # SUP-2026-00322: the reports held ON PURPOSE (#901) are named as information, not as incomplete, and a run whose ONLY
    # partial cause is such a hold reports 'success' to Invardia (no report-incomplete class, no fix request).
    # 🔒 THE EXIT REASON STAYS PARTIAL for them: the per-report freeze of the closes is reached ONLY through it.
    # Test-SIVulnSnapshotComplete (asset-cmdb\_shared\SI-VulnDesired.ps1) reads a 'success' run as complete, and then
    # Invoke-SIVulnLoop.ps1 and Test-SIDataFindingCollectionComplete (pro-data\_shared\SI-DataCiLifecycle.ps1) never read
    # sidata.RaReportStatus (Resolve-SIReportScopedComplete): FrozenReports would be empty and a held report's absent
    # findings could close. So only the presentation changes here; the run-health record keeps the exit as before.
    $__exitIn = $ExitReason
    $__otherPartial = $false
    $__split = $null
    try { $__split = Get-RARunFailureSplit } catch { $__split = $null }
    if ($null -eq $__split) { $__split = [pscustomobject]@{ Real = @(if ($null -ne $script:_RAReportFailures) { $script:_RAReportFailures.ToArray() }); Held = @() } }
    $__heldSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    # #902 (4): an ESCALATED hold (a Detailed hold of 3 runs in a row) is a real problem: named as incomplete, the run is not
    # 'held only' for it (the run record goes as report-incomplete -- a ticket and a fix request at Invardia)
    foreach ($__h in @($__split.Held)) { if ($__h -and [string]$__h.Report -and -not $__h.Escalated) { [void]$__heldSet.Add([string]$__h.Report) } }
    if (@($__split.Held | Where-Object { $_ -and $_.Escalated }).Count) { $__otherPartial = $true }
    # 🔴 AUDIT #62 -- A RUN THAT LOST BUCKETS MUST NOT REPORT A BARE 'success'.
    # The customer run that exposed this shipped ~1,100 findings short and recorded a clean success,
    # so nothing downstream -- workbook, mail, SI_RunHealth_CL -- could tell a partial run from a
    # whole one. This is the machine-readable half of the fix; the log verdicts are the human half.
    # 🔒 Crash detection is UNAFFECTED: per the contract above it keys on a Start row with NO End row,
    # never on this string. ⚠️ A dashboard filtering `ExitReason == 'success'` will stop counting
    # these runs -- which is the point, but worth knowing before you go looking for them.
    try {
        if ($null -ne $script:_RABucketLossRun -and $script:_RABucketLossRun.Count -gt 0) {
            $__otherPartial = $true
            if ($ExitReason -eq 'success') { $ExitReason = 'success-partial' }
            # #414: a lost bucket is a query that FAILED (timeout, error, a result that could not be read) -- never a bucket that
            # legitimately matched no data (that one is not recorded as lost). Said so, so nobody reads it as an empty result.
            $__bl = ("{0} bucket(s) could not be read (a query that timed out or failed, not an empty result) -- affected report(s) are partial" -f $script:_RABucketLossRun.Count)
            $ErrorMessage = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { $__bl } else { ($ErrorMessage + ' | ' + $__bl) }
        }
    } catch { }
    # A REPORT that did not deliver a whole result makes the run partial, and the message names every such report
    # (Get-RAIncompleteReports): the data sync then holds the collection and the close-loop closes nothing on it.
    try {
        $__inc = @($script:_RAIncompleteReports | Where-Object { $_ })
        if ($__inc.Count -eq 0 -and $null -ne $script:_RAReportFailures -and $script:_RAReportFailures.Count -gt 0) { $__inc = @(Get-RAIncompleteReports -Failures @($script:_RAReportFailures.ToArray())) }
        if ($__inc.Count -gt 0) {
            # unchanged for a report held on purpose too (see SUP-2026-00322 above: the closes' freeze needs it)
            if ($ExitReason -eq 'success') { $ExitReason = 'success-partial' }
            # the message names as INCOMPLETE only the reports that really are; a report held on purpose is a note of its own
            $__incReal = @($__inc | Where-Object { -not $__heldSet.Contains([string]$_.Report) })
            if ($__incReal.Count -gt 0) {
                $__otherPartial = $true
                $__im = Format-RAIncompleteReports -Incomplete $__incReal
                $ErrorMessage = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { $__im } else { ($ErrorMessage + ' | ' + $__im) }
            }
        }
        if (@($__split.Real).Count -gt 0) { $__otherPartial = $true }
        if (@($__split.Held).Count -gt 0) {
            $__hm = ('held on purpose: {0} -- each keeps its last complete result, nothing of it is closed' -f ((@($__split.Held) | ForEach-Object { '{0} ({1})' -f [string]$_.Report, [string]$_.Why }) -join '; '))
            $ErrorMessage = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { $__hm } else { ($ErrorMessage + ' | ' + $__hm) }
        }
    } catch { $__otherPartial = $true }
    # A PUBLISH that failed or is incomplete is a partial run too: a Log Analytics post that failed, new columns Azure
    # did not store yet, or a profile this run was built on whose own newest run was partial. The close-loop closes only
    # after a 'success' run, so a finding missing from a partial publish stays UNKNOWN instead of being closed as fixed.
    try {
        $__pub = New-Object System.Collections.Generic.List[string]
        if ($null -ne $script:_RAPublishFailures) { foreach ($__f in $script:_RAPublishFailures) { [void]$__pub.Add([string]$__f) } }
        # #414 (ring 1, 2026-10-06): NEW non-key columns Azure was not storing yet (propagation lag, Kind 'column-lag') are
        # not missing findings -- the rows and their key columns are there. Said as a warning; the run is NOT partial for it.
        if (Get-Command -Name Get-SILogIngestNotes -ErrorAction SilentlyContinue) {
            foreach ($__n in @(Get-SILogIngestNotes)) {
                if (-not $__n) { continue }
                if ($__n.PSObject.Properties['Kind'] -and [string]$__n.Kind -eq 'column-lag') { Write-Warning ('{0} (not a partial run: the rows are there)' -f [string]$__n.Message); continue }
                [void]$__pub.Add([string]$__n.Message)
            }
        }
        if ($null -ne $script:_RAUpstreamOutcome -and $script:_RAUpstreamOutcome.ExitReason -ne 'success') { [void]$__pub.Add([string]$script:_RAUpstreamOutcome.Message) }
        if ($__pub.Count -gt 0) {
            $__otherPartial = $true
            if ($ExitReason -eq 'success') { $ExitReason = 'success-partial' }
            $__pm = ($__pub -join ' | ')
            $ErrorMessage = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { $__pm } else { ($ErrorMessage + ' | ' + $__pm) }
        }
    } catch { }
    # THE WORKBOOK IS A CONVENIENCE OUTPUT: one that could not be written is noted on the run record and never changes the
    # exit -- the run's result is complete in the database (Invoke-RAWorkbookStep).
    if (-not [string]::IsNullOrWhiteSpace([string]$script:RAWorkbookRunNote)) {
        $ErrorMessage = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { [string]$script:RAWorkbookRunNote } else { ($ErrorMessage + ' | ' + [string]$script:RAWorkbookRunNote) }
    }
    # #774: a Detailed run that skipped its findings publish says so on the run record (Get-SIFindingsSkipNote); the exit stays
    if (-not [string]::IsNullOrWhiteSpace([string]$script:RAFindingsRunNote)) {
        $ErrorMessage = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { [string]$script:RAFindingsRunNote } else { ($ErrorMessage + ' | ' + [string]$script:RAFindingsRunNote) }
    }
    # #399: the launcher prints PARTIAL, not "completed successfully", over a partial run (as the profiling launchers do)
    $global:SI_LastRunExitReason = $ExitReason
    # SUP-2026-00322: partial ONLY by reports held on purpose -> the telemetry run report says 'success' (Outcome ok); the
    # run-health record (what the closes, the data sync and the heartbeat read) keeps 'success-partial'
    $__telHeldOnly = ($__exitIn -eq 'success' -and $ExitReason -eq 'success-partial' -and -not $__otherPartial -and @($__split.Held).Count -gt 0)
    $__rhTel = @{}; if ($__telHeldOnly) { $__rhTel = @{ NoTelemetry = $true } }
    try {
        Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'End' `
                            -AssetCount $AssetCount -ExitReason $ExitReason -ErrorMessage $ErrorMessage @__rhTel
    } catch {}
    if ($__telHeldOnly) {
        try {
            if (Get-Command -Name Send-SITelemetryRunEnd -ErrorAction SilentlyContinue) {
                $null = Send-SITelemetryRunEnd -RunContext $script:_RunHealthCtx -ExitReason 'success' -ErrorMessage $ErrorMessage -AssetCount $AssetCount
            }
        } catch { }
    }
}
# The run's publish failures and ingest notes (SI-LogIngest.ps1) start empty; SI-RunOutcome.ps1 judges the profile data.
$script:_RAPublishFailures = New-Object System.Collections.Generic.List[string]
# Reports that did not deliver a whole result this run (a failed query, a result that could not be read, findings left
# to a report that failed, or far fewer findings than the previous run). Their findings are UNKNOWN, not remediated:
# the run ends partial, so the data sync holds the collection and the close-loop closes nothing on it.
$script:_RAReportFailures = New-Object System.Collections.Generic.List[object]
$script:_RAIncompleteReports = @()
# #901: the reports SI holds ON PURPOSE at their last complete result (a silent source, an incomplete role read) -- report ->
# @{ Kind; Whys } (Add-RADeliberateHold); the row-count guard's flagged reports (a deliberate hold they are not)
$script:RADeliberateHolds = @{}
$script:_RARowCountFlagged = @()
# #902 (4): per report held on purpose, how many runs of this grain in a row it is held and its kept result's time
# (Read-RAStreamHoldStreak, read once at the end of the run) -- report -> @{ Kind; HeldRuns; KeptResultAt }
$script:RAHoldStreak = @{}
function Add-RAReportFailure {
    param([Parameter(Mandatory)][string]$ReportName, [Parameter(Mandatory)][string]$Reason)
    if ($null -eq $script:_RAReportFailures) { $script:_RAReportFailures = New-Object System.Collections.Generic.List[object] }
    [void]$script:_RAReportFailures.Add(@{ Report = $ReportName; Why = $Reason })
    Set-RAReportNote -ReportName $ReportName -Values @{ EndedUtc = [datetime]::UtcNow }
}
function Get-RARunFailureSplit {
    <# SUP-2026-00322: this run's report failures split into the REAL ones and the reports held ON PURPOSE (#901) --
       Split-RAReportFailures (RA-SilentSource.ps1), the rule the stored HoldKind uses, with the same inputs. Read by the
       mail (subject, summary, error codes, the held line) and the run record. Never throws: anything that cannot be judged
       is REAL (as before this change). #>
    $f = @(if ($null -ne $script:_RAReportFailures) { $script:_RAReportFailures.ToArray() })
    try {
        $hb = @()
        if ($null -ne $script:RAStream -and (Get-Command -Name Get-RAStreamHeldReports -ErrorAction SilentlyContinue)) { $hb = @(Get-RAStreamHeldReports -Stream $script:RAStream | Where-Object { $_ } | ForEach-Object { [string]$_.Report }) }
        Split-RAReportFailures -Failures $f -Holds $script:RADeliberateHolds -Flagged @($script:_RARowCountFlagged | Where-Object { $_ } | ForEach-Object { [string]$_ }) `
            -BucketLoss @($script:_RABucketLossRun | Where-Object { $_ } | ForEach-Object { [string]$_ }) -HeldBack $hb `
            -Streak $script:RAHoldStreak -Grain $(if ($null -ne $script:RAStream) { [string]$script:RAStream.Grain } else { '' })
    } catch { [pscustomobject]@{ Real = $f; Held = @() } }
}
function Set-RAReportRowsHeld {
    <#
        #877 (owner 2026-10-22: "Hold back that report"). The rows of a report that must not go out (it failed, or it is not
        in this run) could not be removed -- even in measured batches (-Cause). A Detailed run holds back ONLY THAT REPORT
        (RA-SqlStream.ps1 Add-RAStreamHeldReport): its rows of this run are never read as the report, it keeps its last
        complete result and closes nothing, every other report loads and the run ends partial. A Summary run keeps the
        strict rule (the stream is broken: the run fails). -ReportName / -Ordinal default to the report running now.
    #>
    param([string]$ReportName = '', [int]$Ordinal = 0, [Parameter(Mandatory)][string]$Cause)
    $st = $script:RAStream
    if ($null -eq $st) { return }
    if (-not $ReportName -and $null -ne $st.Current) { $ReportName = [string]$st.Current.Name }
    if ($Ordinal -le 0 -and $null -ne $st.Current) { $Ordinal = [int]$st.Current.Ordinal }
    if (Add-RAStreamHeldReport -Stream $st -ReportName $ReportName -Ordinal $Ordinal -Cause $Cause) {
        Write-Warn2 ("report '{0}' is HELD BACK: its rows of this run could not be removed ({1}). They are never read as the report: it keeps its last complete result and nothing of it is closed; every other report loads, and the data sync removes those rows before it delivers this run." -f $ReportName, $Cause)
    } else {
        Write-Warn2 ("the rows this report already wrote could not be removed -- the run's result is not complete: {0}" -f $Cause)
    }
}
function Add-RAHeldReportReasons {
    <# #877. Every report held back this run says so in its reason -- the log, the run record, the status report and the
       database all read the run's report failures: the held reason is added to the report's first failure (after it, so
       the kind of failure stays first), or is its failure when it has none. #>
    if ($null -eq $script:RAStream) { return }
    $heldList = @(Get-RAStreamHeldReports -Stream $script:RAStream)
    foreach ($h in $heldList) {
        $n = [string]$h.Report
        $w = [string]$h.Why
        $f = $null
        if ($null -ne $script:_RAReportFailures) {
            foreach ($x in $script:_RAReportFailures) { if ($null -ne $x -and [string]$x['Report'] -eq $n) { $f = $x; break } }
        }
        if ($null -eq $f) {
            Add-RAReportFailure -ReportName $n -Reason $w
        } elseif (-not ([string]$f['Why']).Contains([string]$script:RAStreamHeldShort)) {
            $f['Why'] = ('{0} -- {1}' -f [string]$f['Why'], $w)
        }
    }
}
# #709 / framework 8.16: what the run knows about each report for the run record's Reports[] -- when it started and ended,
# its verdict and reason, rows, what the source counted, buckets, the query fingerprint. Kept, never sent from here.
$script:RAReportNotes = @{}
function Set-RAReportNote {
    param([Parameter(Mandatory)][string]$ReportName, [hashtable]$Values = @{})
    try {
        if ($null -eq $script:RAReportNotes) { $script:RAReportNotes = @{} }
        if (-not $script:RAReportNotes.ContainsKey($ReportName)) { $script:RAReportNotes[$ReportName] = @{} }
        foreach ($k in @($Values.Keys)) { if ($k -ne 'EndedUtc' -or -not $script:RAReportNotes[$ReportName].ContainsKey('EndedUtc')) { $script:RAReportNotes[$ReportName][$k] = $Values[$k] } }
    } catch { }
}
# #294: posts that were REFUSED (a snapshot with its key columns empty, or a rule that would drop columns) -- the run ends 'error'
$script:_RAIngestRefused = New-Object System.Collections.Generic.List[string]
# The run's OWN result table (Summary or Detailed) that Log Analytics did not receive in full -- whatever the cause (out
# of memory while preparing the rows, a post that failed part way, a rule that could not be updated). The run then ends
# 'error' and the job ends failed: the web app, the data sync and the connectors read that table, and a run that did not
# deliver it must never look like a good one (a large install ran green for three days on the collection before it).
$script:_RAResultNotDelivered = New-Object System.Collections.Generic.List[string]
$script:_RALaRowsPosted = 0L
# #394: the rows this run actually posted to Log Analytics ($null = nothing was posted) -- the day's trend row is built from them
$script:_RAPublishedRows = $null
$script:_RAUpstreamOutcome = $null
$global:SI_LastRunExitReason = $null
try { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-RunOutcome.ps1') } catch { }
if (Get-Command -Name Reset-SILogIngestNotes -ErrorAction SilentlyContinue) { Reset-SILogIngestNotes }
# #450: on the INTERNAL launcher the run's identity is signed in later (the AutomationFramework branch below), so this
# Start row found no identity and was lost ("Run-health record not saved: no sign-in identity"). Then it is sent again
# right after that sign-in -- the warning flag says whether this one went out.
$global:SI_RunHealthFailWarned = $null
# #742: a QUEUE WORKER runs reports of its producer's run -- it is not a run of its own: no run-health record (the producer's
# START has no END from a worker; the producer ends the run). '' = the job runs as before (or as the producer).
$script:RAScaleRole = if (([string]$global:SI_RA_ScaleOutRole).Trim() -ieq 'worker') { 'worker' } else { '' }
if ($script:RAScaleRole -ne 'worker') { try { Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'Start' } catch {} }
$script:_RAStartPending = [bool]$global:SI_RunHealthFailWarned
if ($script:_RAStartPending) { $global:SI_RunHealthFailWarned = $null }

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

# AI summary mode + the snapshot-ownership decision (Consistent vs PerReport, and the
# UTC-day cycle key). Pure -- no globals, no disk, no clock of its own -- so every branch
# is reachable from a unit test. FOUR sites in this engine decide "is the cached snapshot
# still valid"; they all call the one function in here, because when they each had their
# own copy of the age test they did not agree.
. (Join-Path $PSScriptRoot '_shared/RA-AISummaryMode.ps1')   # forward slash works on both Win + Linux
# #288: the executive view snapshot (what each mail showed, one file per grain, for the Pro web app).
. (Join-Path $PSScriptRoot '_shared/RA-ExecView.ps1')
$script:_RAExecTopAssets = @(); $script:_RAExecTopFindings = @(); $script:_RAExecFiguresFrom = $null; $script:_RAExecFiguresAt = $null

# #113b: Graph is reached over PURE REST now -- no Microsoft.Graph SDK. Both files must load BEFORE
# RA-GraphAuth.ps1, which calls Get-SIGraphToken at connect time and whose hunting callers use
# Invoke-SIHuntingQueryRest. Dot-sourced at solution scope (not lazily inside the branch that uses
# them) for the same reason the container entrypoint loads its dependencies up front: a dependency
# that only loads on the write path is one that can be missing for weeks and then fail mid-run.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/Get-SIGraphToken.ps1')   # forward slash works on both Win + Linux
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-Yaml.ps1')                             # SecurityInsight's own YAML reader (no powershell-yaml module)
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-GraphRest.ps1')                         # engine/_shared, shared with the classifier
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-TenantDisplay.ps1')                     # the tenant in the mail: '<domain> (<tenant id>)' (#243)
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
# #212: every profile-table read keeps THIS install's rows (engine/_shared, shared with the profilers' readers).
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-InstallRows.ps1')
# #533: disabled accounts and devices -- SI_DisabledAssets_RiskAnalysis drives the reports' enabled filter (engine/_shared).
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-DisabledAssets.ps1')
# A failed query logs the service's error code and message, not only "BadRequest" (engine/_shared).
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-KqlError.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-UplinkCauses.ps1')   # #709: the report causes and error codes (run record Reports[], the mail's reference codes)

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

    # 🔑 v2.2.451 -- ASK FOR THE RESPONSE, NOT AN EXCEPTION.
    # The Sentinel data lake is NOT onboarded on most tenants, so a 400 InvalidDatabaseInQuery / 403 /
    # 404 here is the EXPECTED answer, and the caller already falls back to hybrid/AH silently. But a
    # PowerShell transcript records EVERY terminating error, so that expected answer printed a full
    # HTTP dump -- including the workspace GUID -- into the customer's log, twice per attempt:
    # once for Invoke-RestMethod and once for our own `throw`. Customers rang up asking what had
    # broken. Nothing had.
    # 🔒 Behaviour is unchanged -- same detection, same fallback, same deferred-warning policy. Only
    # the mechanism changes: a RETURNED failure instead of a THROWN one.
    # 🪤 PS 5.1 has no -SkipHttpErrorCheck, so there the catch still runs and the first transcript
    # entry remains. The second one is removed on BOTH hosts. Customer engines are pwsh 7.
    $stage = 'token'
    $lakeFail = $null
    try {
        $token = Get-SIGraphToken -Resource SentinelDataLake
        $stage = 'query'
        $irm = @{
            Method  = 'Post'
            Uri     = 'https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query'
            Headers = @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' }
            Body    = $body
        }
        $lakeHttpStatus = 0
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $irm['SkipHttpErrorCheck'] = $true
            $irm['StatusCodeVariable'] = 'lakeHttpStatus'
        } else {
            $irm['ErrorAction'] = 'Stop'
        }
        $resp = Invoke-RestMethod @irm
        if ($lakeHttpStatus -and ($lakeHttpStatus -lt 200 -or $lakeHttpStatus -ge 300)) {
            # Non-2xx WITHOUT an exception (PS7 path). Build the same message the catch would have,
            # so the caller's pattern matching is byte-for-byte unaffected.
            $bodyText = if ($null -ne $resp) { try { ($resp | ConvertTo-Json -Depth 6 -Compress) } catch { [string]$resp } } else { '' }
            $lakeFail = ('lake-{0}: HTTP {1} | api-body: {2} | db: {3}-{4}' -f $stage, $lakeHttpStatus, $bodyText, $wsName, $wsGuid)
        }
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
        $lakeFail = if ($apiBody) { ('lake-{0}: {1} | api-body: {2} | db: {3}' -f $stage, $_.Exception.Message, $apiBody, $dbField) }
                    else          { ('lake-{0}: {1} | db: {2}' -f $stage, $_.Exception.Message, $dbField) }
    }

    # 🔴 RETURN the failure, never THROW it. A re-thrown error is still a terminating error, and the
    # transcript would record exactly the block this change exists to remove -- the same mistake I
    # made once already in the advanced-hunting probe (v2.2.445) and caught before shipping.
    if ($lakeFail) { return [pscustomobject]@{ _SILakeError = $lakeFail } }

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
. (Join-Path $PSScriptRoot '_shared/RA-ColumnTypeAlign.ps1')     # every posted value matches its column's real type (#148)
. (Join-Path $PSScriptRoot '_shared/RA-IngestKeyColumns.ps1')    # a snapshot is never posted with its key columns empty (#294)
. (Join-Path $PSScriptRoot '_shared/RA-Delivery.ps1')             # Log Analytics in chunks, the JSON file row by row
. (Join-Path $PSScriptRoot '_shared/RA-SummaryBucketMerge.ps1')  # a Summary group split across buckets is ONE row again (#152)
# #638 the result goes to SQL a bucket at a time -- with the data sync's mappings (one mapping, never a second), the trend's
# and the findings' own rules (the same keys the in-memory path used)
. (Join-Path $PSScriptRoot '_shared/RA-SqlStream.ps1')
. ([System.IO.Path]::Combine($PSScriptRoot, '..', '_shared', 'SI-StepPhase.ps1'))   # #873 A: the [phases] times also go to cfg.StepPhaseTime
. (Join-Path $PSScriptRoot '_shared/RA-SilentSource.ps1')          # #900 a source that went silent holds the reports reading it
foreach ($__raSqlDep in @('../_shared/data-sql/SI-DataModel.ps1', '../_shared/data-sql/SI-DataSql.ps1', '../_shared/data-sql/SI-DataSummary.ps1', '../asset-trend/_shared/SI-TrendRollup.ps1', '_shared/RA-Findings.ps1')) {
    # core in both editions (owner 2026-10-13: "ra is part of core functionality"): engine/_shared/data-sql ships in both
    . ([System.IO.Path]::Combine($PSScriptRoot, $__raSqlDep))
}
# The ONE asset-identity resolver. Loaded after the LA query helper because it uses it.
# 84 reports resolve an identity across NINE hand-written chain variants in the catalog; this is the
# single implementation they all fall back to. See the file header for why it never reads
# ExposureGraph and never keys on a vendor id.
. (Join-Path $PSScriptRoot '_shared/RA-AssetIdentityMap.ps1')   # forward slash works on both Win + Linux
# v3 data model: every finding row tied to its CI and given the CI's tier, CMDB values, criticality and asset risk factors
# one risk factor counted once: tokens compared by their catalog factor (data-model/risk-factors.locked.json)
. (Join-Path $PSScriptRoot '_shared/RA-FactorKeys.ps1')
. (Join-Path $PSScriptRoot '_shared/RA-CiContext.ps1')
# rich context (Defender): the exploit details of a CVE from the Defender vulnerability API, on the vulnerability rows
. (Join-Path $PSScriptRoot '_shared/RA-DefenderCveContext.ps1')
# #636: the source's own first-seen on each finding row (Defender's software vulnerabilities export, Defender for Cloud, Shodan)
. (Join-Path $PSScriptRoot '_shared/RA-SourceFirstSeen.ps1')
. (Join-Path $PSScriptRoot '_shared/RA-DefenderRecommendationContext.ps1')
# #505: the CI blocks every report reads its assets through (SI_CI_CL, regenerated with SI_ActiveStaleDays).
. (Join-Path $PSScriptRoot '_shared/RA-CiKql.ps1')
. (Join-Path $PSScriptRoot '_shared/RA-OutBlock.ps1')   # #692 the generated data-out block of every report
# #541: the scope preamble -- the one reader of the customer's scope, the report's factor set, the typed KQL builders.
. (Join-Path $PSScriptRoot '_shared/RA-ScopePreamble.ps1')
# #546: unknown is never a finding -- the run log says, per report, how many assets could not be judged.
. (Join-Path $PSScriptRoot '_shared/RA-UnknownCount.ps1')
# #546: shipped default exclusion rules for Microsoft recommendations that are known false positives in a stated situation.
. (Join-Path $PSScriptRoot '_shared/RA-RecommendationExclusions.ps1')
# #561 / #562: the one classification mechanism -- every output row's finding dimensions (si_component: SQL, OS, ...).
. ([System.IO.Path]::Combine($PSScriptRoot, '..', 'data-model', 'SI-Classification.ps1'))
# #560: the generic SI finding fields of SI's own reports as data (WHAT / HOW / compliance / MITRE), and the inference rows.
. ([System.IO.Path]::Combine($PSScriptRoot, '..', 'data-model', 'SI-FindingTexts.ps1'))

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
# queries surface cmdbName straight off SI_PublicIP_Profile_CL. Keep this list to columns
# that are genuinely string-or-dynamic; NEVER add numeric columns (RiskScore*, *Tier, *Count)
# -- casting those to string would change ordering/scoring semantics.
$script:_DynamicGroupKeyCols = @(
    'cmdbName','cmdbId','cmdbCriticality','cmdbDataSensitivity',
    # #151 -- SI_Endpoint_Profile_CL.AssetName is `dynamic` (a type fixed at table creation), so a
    # customer's own report grouping by it would fail SEM0001. tostring() keeps the column name
    # (verified: `by tostring(AssetName)` yields `AssetName:string`) and is harmless on text.
    'AssetName'
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
  # No workbook this run (Invoke-RAWorkbookStep: switched off, too large, or not written): the summary goes to the mail
  # and the web app only -- a workbook holding nothing but the summary sheet is not made.
  if ($script:RAWorkbookSkipped -and -not (Test-Path -LiteralPath $Path)) { return }

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

  $safeSheet = Get-SIXlsxSafeSheetName $SheetName
  $tableName = ($safeSheet -replace '\W','_')

  # Same writer as the Details sheet (RA-XlsxWriter.ps1). Added to the workbook already on disk; a
  # 'Summary' sheet from an earlier write is replaced. Columns are sized to their content, capped at 90.
  $grid = New-Object 'System.Collections.Generic.List[object[]]'
  foreach ($r in @($rows)) { [void]$grid.Add([object[]]@($r.LineNo, $r.Text)) }
  Write-SIXlsxWorksheet -Path $Path -SheetName $safeSheet -Header @('LineNo', 'Text') -Rows $grid `
    -MaxColumnWidth 90 -TableName $tableName -TableStyle 'Medium9'
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
    # #541: excluded assets (CI ids or names) and excluded address ranges -- applied by the scope preamble
    '__EXCLUDED_ASSETS__'            = @('ExcludedAssets',           'Assets')
    '__EXCLUDED_IP_RANGES__'         = @('ExcludedIpRanges',         'IpRanges')
}

# Tokens that should ALSO consult a single global fallback file when the per-report
# .exclude.custom.json doesn't carry the matching property. Useful for tenant-wide
# exclusions (e.g. a single list of "ignore these MDE asset tags" applied across
# every Endpoint RA report). Per-report file ALWAYS wins on the same property name.
$script:_GlobalExcludeTokens = @(
    '__EXCLUDED_ASSET_TAGS__'
    '__EXCLUDED_ASSETS__'
    '__EXCLUDED_IP_RANGES__'
)
$script:_GlobalExcludeFileName = 'RiskAnalysisGlobalExclusions.custom.json'

# AUDIT #16: Exclusion lists: per-report and global exclude JSON, and placeholder substitution. Moved to _shared/RA-ExcludeLists.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-ExcludeLists.ps1')   # forward slash works on both Win + Linux
# #278: reports that hand their findings to another report -- the query side (Resolve-RADefenderHandoffBlock) and the run-over-run guards.
. (Join-Path $PSScriptRoot '_shared/RA-ReportHandoff.ps1')
# #673 plan B: the Defender de-duplication of the Azure recommendation reports done in the engine against the run's
# Defender list in SQL (SI_RA_DefenderFilterInEngine / SI_RA_DefenderFilterCompare, in-engine on by default since rc2, compare off -- REMOVE-ME)
. (Join-Path $PSScriptRoot '_shared/RA-DefenderFilter.ps1')
# #742: the reports on queue workers -- the plan, the manifest, the queue, the hand-over (RA-ScaleOut.ps1). A worker never
# loads the run's Defender list itself (the producer did, once).
. (Join-Path $PSScriptRoot '_shared/RA-ScaleOut.ps1')
$script:RAScaleProducerOn = $false
$script:RAScaleManifest = $null; $script:RAScaleFirst = $null; $script:RAScaleItem = $null; $script:RAWorkerTime = $null
if ($script:RAScaleRole -eq 'worker') {
    $script:RADfcWorker = $true
    # A worker takes its FIRST report before it prepares anything (an execution that finds nothing to do ends at once): the
    # report's run -- its manifest -- decides the collection time, the collection it writes to and the run's shared lookups.
    $__soAcct = [string]$global:SI_StorageAccount
    if (-not $__soAcct) { Write-Err2 '[scale-out] this worker has no storage account (SI_STORAGE_ACCOUNT) -- it cannot reach the work queue'; return }
    $script:RAScaleStore = New-RAScaleOutBlobStore -Account $__soAcct
    $script:RAScaleCtx = New-SIStorageContext -AccountName $__soAcct
    $script:RAScaleQueue = Get-RAScaleOutQueueName -Grain $(if ([bool]$global:Detailed) { 'Detailed' } else { 'Summary' })
    $script:RAScaleWorkerName = if ($env:CONTAINER_APP_JOB_EXECUTION_NAME) { [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME } else { [System.Net.Dns]::GetHostName() }
    $script:RAScaleFirst = Receive-RAScaleOutItem -Context $script:RAScaleCtx -QueueName $script:RAScaleQueue -Store $script:RAScaleStore -Worker $script:RAScaleWorkerName `
                               -SignInLibraries @($global:SI_RA_BeatSignIn | Where-Object { $_ }) -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } }
    if ($script:RAScaleFirst.Kind -ne 'item') { Write-Info ('[scale-out] no report waits for a worker ({0}) -- nothing to do' -f $script:RAScaleFirst.Why); return }
    $script:RAScaleManifest = $script:RAScaleFirst.Manifest
    $script:RAScaleRunId = [string]$script:RAScaleManifest['RunId']
    $script:RAScaleRunTime = [datetime]::Parse([string]$script:RAScaleManifest['RaCollectionTime'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
    $__soDfc = $script:RAScaleManifest['Defender']
    if ($__soDfc -and [string]$__soDfc['State'] -eq 'loaded') { $script:RADfcSet = @{ RunKey = [string]$script:RAScaleManifest['RunKey']; Keys = [long]$__soDfc['Keys']; Pages = [int]$__soDfc['Pages']; Verdict = $null } }
    elseif ($__soDfc -and [string]$__soDfc['State'] -eq 'failed') { $script:RADfcSetFailed = [string]$__soDfc['Error'] }
    $__soLockPath = Get-RAScaleOutPath -Engine ([string]$script:RAScaleManifest['Engine']) -RunId $script:RAScaleRunId -Kind lock
    $global:SI_RA_ScaleOutLockPath = $__soLockPath   # the entry point keeps this worker's bucket counts under the same lock
    $script:RAScaleLockPath = $__soLockPath
    # #831 A: how many items of the run are still open (one listing of the run's markers, at a report's start and every few
    # minutes) -- the last workers of a run share the Defender budget the others left free (RA-PartsInParallel.ps1)
    $script:RAPartsOpenProbe = { Get-RAScaleOutOpenItems -Store $script:RAScaleStore -Manifest $script:RAScaleManifest }
    # #882 -- A WORKER OF A RUN THAT IS OVER WRITES NOTHING (live 2026-10-22, internal: the pipeline closed the Detailed step
    # Interrupted at 09:40Z; this worker went on querying until 10:30 and wrote the remembered slice count the next run
    # used). Is this worker's run still the live one? (RA-ScaleOut.ps1 Test-RAScaleOutRunLive: not closed, its manifest there,
    # its collection still loading -- fail closed.) The bucket sizing asks it before it keeps anything; the report loop asks
    # it at every query slice and before the hand-over (Assert-RAScaleOutWorkerLive), and stops the worker when it is over.
    $script:RAScaleLive = {
        $cs = $null
        if ($script:RAStreamOn -and $null -ne $script:RAStream -and [int]$script:RAStream.CollectionId -gt 0) {
            $cs = { [string](Invoke-RAStreamSql -Stream $script:RAStream -Sql "SELECT Status FROM sidata.Collection WHERE CollectionId = CONVERT(int, @CollectionId) AND RaCompletedAt IS NULL;" -Params @{ CollectionId = [string]$script:RAStream.CollectionId } -Mode 'scalar') }
        }
        Test-RAScaleOutRunLive -Store $script:RAScaleStore -Engine ([string]$script:RAScaleManifest['Engine']) -RunId ([string]$script:RAScaleRunId) -CollectionState $cs
    }
    $script:AutoBucketWriteGate = $script:RAScaleLive
    Write-Info ('[scale-out] worker of run {0}: report {1} first' -f $script:RAScaleRunId, [string]$script:RAScaleFirst.Payload.Report)
}
function Assert-RAScaleOutWorkerLive {
    <# #882: a queue worker whose run is over (Test-RAScaleOutRunLive, fail closed) stops HERE and writes nothing more for it --
       no rows, no hand-over, no marker, no bucket counts. The report's message is left to the queue: the run is over, so the
       worker that takes it next discards it. The entry point sees $global:SI_RA_ScaleOutRunOver and keeps no counts either.
       -Where: what the worker was about to do (the line says it). A single job or a producer: nothing is asked. #>
    param([string]$Where = 'here')
    if ($script:RAScaleRole -ne 'worker' -or $null -eq $script:RAScaleLive) { return }
    $l = $null
    try { $l = & $script:RAScaleLive } catch { $l = [pscustomobject]@{ Live = $false; Why = [string]$_.Exception.Message } }
    if ($l -and [bool]$l.Live) { return }
    $why = if ($l) { [string]$l.Why } else { 'the check answered nothing' }
    $global:SI_RA_ScaleOutRunOver = $why
    Write-Warn2 ("[scale-out] this worker stops {0}: {1} -- it writes nothing more for that run (no rows, no hand-over, no bucket counts)" -f $Where, $why)
    foreach ($__soHeld in @($script:RAScaleItem, $script:RAScaleFirst)) { if ($__soHeld -and $__soHeld.Beat) { try { $null = Stop-SIWorkItemLeaseBeat -Beat $__soHeld.Beat } catch { } } }
    exit 0
}

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

# Get-ScalarValueForReport lives in _shared/RA-ExcludeLists.ps1 (moved verbatim 2026-10-15) so the data health check reads a report's
# CVE minimum age through the same function as this engine.

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
    $cvssNum = ConvertTo-RADouble -Value $cvss -Default 0.0
    if ($null -ne $cvss -and $cvssNum -gt 0) {
        # INVARIANT formatting: this number goes into KQL. `-f` uses the host culture, so on a da-DK host
        # a threshold of 7.5 rendered as `>= 7,5` -- a KQL syntax error (#121).
        [void]$clauses.Add([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}| where toreal(NodeProperties.rawData.cvssScore) >= {1}', $indent, $cvssNum))
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

    # #150 -- the vulnerability-management rows (DeviceTvmSoftwareVulnerabilities + KB) get the SAME rules on
    # their own columns, or a customer's CVE filter would stop applying to every CVE the graph lacks.
    $tvmRx = [regex]::Escape('//__CVE_FILTER_TVM_BEGIN__') + '(?<body>.*?)' + [regex]::Escape('//__CVE_FILTER_TVM_END__')
    $tvmMatch = [regex]::Match($result, $tvmRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($tvmMatch.Success) {
        $tc = New-Object System.Collections.Generic.List[string]
        if (-not [string]::IsNullOrWhiteSpace($sev) -and $sevSet.Count -gt 0) {
            [void]$tc.Add(('{0}| where tostring(TvmSeverity) in~ ({1})' -f $indent, (($sevSet | ForEach-Object { '"{0}"' -f $_ }) -join ', ')))
        }
        if ($null -ne $cvss -and $cvssNum -gt 0) {
            [void]$tc.Add([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}| where toreal(CvssScore) >= {1}', $indent, $cvssNum))
        }
        if ([bool]$global:SI_CVE_RequireExploit) { [void]$tc.Add(('{0}| where tobool(IsExploitAvailable) == true' -f $indent)) }
        if ($null -ne $days -and [int]$days -gt 0) { [void]$tc.Add(('{0}| where todatetime(PublishedDate) > ago({1}d)' -f $indent, [int]$days)) }
        if ($tc.Count -gt 0) {
            $tvmBlock = '//__CVE_FILTER_TVM_BEGIN__' + [Environment]::NewLine + ($tc -join [Environment]::NewLine) + [Environment]::NewLine + $indent + '//__CVE_FILTER_TVM_END__'
            $result = $result.Replace($tvmMatch.Value, $tvmBlock)
        }
    }
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
    # Pro (#211): the settings database's weights, materialised run-locally by Layer 5b, are the closest layer.
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath)) {
        [void]$searchDirs.Add([string]$global:SI_ProRaSettingsPath)
    }
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
        # No weights for this engine is a supported state, not a fault: the report's weighted score equals its base
        # score (factor 1.0x) and RiskScore_Weight_Detailed stays empty (Resolve-WeightedFactorsBlock). Said once per
        # engine per run, not once per report.
        if ($null -eq $script:_WeightedFactorsNoneSaid) { $script:_WeightedFactorsNoneSaid = @{} }
        if (-not $script:_WeightedFactorsNoneSaid.ContainsKey($engineKey)) {
            $script:_WeightedFactorsNoneSaid[$engineKey] = $true
            Write-Info ("risk weights: none set for {0} -- its reports' weighted score equals the base score (1.0x)" -f $engineKey)
        }
    }
    $script:_WeightedFactorsCache[$cacheKey] = $cfg
    return $cfg
}

# AUDIT #16: Weighted risk-factor KQL: building the substitution block and resolving it into a query. Moved to _shared/RA-WeightedFactors.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-WeightedFactors.ps1')   # forward slash works on both Win + Linux

# AUDIT #16: Row shaping: field lookup, normalisation, de-duplication and scope filtering. Moved to _shared/RA-RowShaping.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-RowShaping.ps1')   # forward slash works on both Win + Linux
# SecurityInsight Pro: per-asset finding exemptions (a no-op unless the Pro settings layer wrote them for this run).
. (Join-Path $PSScriptRoot '_shared/RA-Exemptions.ps1')   # forward slash works on both Win + Linux
# A finding on an asset no profiler has seen gets its tier from the tier rules (name rules, then the default tier rule).
. (Join-Path $PSScriptRoot '_shared/RA-UnprofiledTier.ps1')   # forward slash works on both Win + Linux
# SecurityInsight Pro (#274): the output scope per destination -- 'excel' narrows the workbook / JSON / AI summary / KPIs /
# mail (never Log Analytics). A no-op unless the Pro settings layer wrote config\output-scope.json for this run.
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-OutputScope.ps1')

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
# the risk scores of a large slice on several processor cores (SI_RA_ScoringThreads; 1 = one core)
. (Join-Path $PSScriptRoot '_shared/RA-ParallelScore.ps1')

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
  $normalizedScope = @(foreach ($x in $InScopeData) {
    $nx = _Normalize -val $x -ci:$CaseInsensitive.IsPresent
    if ($null -ne $nx -and $nx -ne '') { $nx }
  })
  if ($normalizedScope.Count -eq 0) {
    if ($ReturnAudit) { return [pscustomobject]@{ Kept=@($InputObject); Removed=@() } }
    return @($InputObject)
  }

  $kept    = New-Object System.Collections.Generic.List[object]
  $removed = New-Object System.Collections.Generic.List[object]

  foreach ($obj in $InputObject) {
    if ($null -eq $obj) { continue }

    # Missing column => keep (generic safe default). One case-insensitive lookup, never the row's whole name list.
    if ($null -eq $obj.PSObject.Properties[$ColumnToFilter]) {
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
      $candidates = @(foreach ($item in $val) { $item })
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
# The workbook step: on / off per grain, the size a workbook holds here, the streamed 'Details' sheet; never fails the run.
. (Join-Path $PSScriptRoot '_shared/RA-WorkbookExport.ps1')   # forward slash works on both Win + Linux
# The risk index rule (first match wins, in row order) and the v2.2 conversion New-RiskIndex uses.
. (Join-Path $PSScriptRoot '_shared/RA-RiskIndexOrder.ps1')   # forward slash works on both Win + Linux
# #559: the index keyed by the SI generic fields (asset base / vulnerability base) and the v2.2 -> SI key translation.
. (Join-Path $PSScriptRoot '_shared/RA-RiskIndexSi.ps1')   # forward slash works on both Win + Linux
# #398: which index files a run reads (the shipped locked index + the customer's own rows) and the one-time migration.
. (Join-Path $PSScriptRoot '_shared/RA-RiskIndexFiles.ps1')   # forward slash works on both Win + Linux

# AUDIT #16: SMTP delivery: the anonymous and authenticated send paths. Moved to _shared/RA-Mail.ps1; dot-sourced HERE to preserve load order.
. (Join-Path $PSScriptRoot '_shared/RA-Mail.ps1')   # forward slash works on both Win + Linux
# MAIL-1: the ONE mail transport every SecurityInsight mail uses (Send-SIMail; SI_Mail_Mode = sharedMailbox | smtp | none).
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-MailTransport.ps1')

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

    # The platform identity of an internal install, signed in by SecurityInsight itself over plain REST (no
    # PowerShell module): bootstrap\platform-config.json -> the platform Key Vault -> the platform identity, and the
    # framework's $global:HighPriv_* / $global:AzureTenantId names populated. The launcher normally did this already
    # (its configuration layer 1); then nothing is signed in twice.
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/SI-PlatformConnect.ps1')
    $__platformCfg = Find-SIPlatformConfigPath -Start $PSScriptRoot
    if ($__platformCfg) {
        $global:PathScripts = Split-Path -Parent (Split-Path -Parent $__platformCfg)
        Write-Output ""
        Write-Output "Repo root          -> $($global:PathScripts)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$global:HighPriv_Modern_ApplicationID_Azure)) {
        $null = Connect-SIPlatform -Start $PSScriptRoot
    }
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure
    if ($global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

    if ([bool]$global:ShowConfig) { Show-ResolvedConfig -Stage "after AutomationFramework defaults loaded" }

    # v2.2.238 -- AutomationFramework branch accepts cert OR secret. AF cert-based
    # SPNs leave HighPriv_Modern_Secret_Azure empty and rely on a thumbprint mirror
    # populated by the platform sign-in.
    $_afHasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $_afHasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        (-not $_afHasSecret -and -not $_afHasCert)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Provide them via wrapper globals or enable -AutomationFramework to load them."
    }
    # #450: the Start row that found no identity at the top of the run goes out now, signed in
    if ($script:_RAStartPending) {
        $script:_RAStartPending = $false
        try { Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'Start' } catch {}
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
    # #636: the Summary mail settings move to the management mail (this Detailed report's mail) while the Summary step is
    # not on (engine\_shared\SI-SummaryStep.ps1). Decided here from what is known without the database (the shipped default:
    # off) and again right before the send, with the stored pipeline (cfg.JobFlow) -- which can only narrow it.
    $script:RAMgmtMail = $null
    if (-not [bool]$global:Summary -and (Test-Path -LiteralPath ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-SummaryStep.ps1')))) {
      $__ssLib = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-SummaryStep.ps1'); if (-not (Get-Command -Name Resolve-SIManagementMailRouting -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $__ssLib)) { . $__ssLib }
      $script:RAMgmtMail = @{ DetailedSend = [bool]$global:Report_SendMail; DetailedTo = @($global:Report_To); SummarySend = [bool]$__summarySend; SummaryTo = @($__summaryTo) }
      $script:RAMgmtMailEarly = Get-SISummaryStepState
      $__mm = Resolve-SIManagementMailRouting @script:RAMgmtMail -SummaryStep $script:RAMgmtMailEarly
      $global:Report_SendMail = $__mm.Send; $global:Report_To = @($__mm.To)
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
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "riskscore.index.locked.csv")   # #398: the shipped index; the customer's own rows (riskscore.index.custom.csv) are read on top of it
    # SecurityInsight Pro (Phase C): the risk index materialised from the settings database (SI_ProRaSettingsPath) wins.
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath) -and (Test-Path -LiteralPath (Join-Path ([string]$global:SI_ProRaSettingsPath) "riskscore.index.custom.csv"))) { $global:RiskDefinitionsCsvPath = (Join-Path ([string]$global:SI_ProRaSettingsPath) "riskscore.index.custom.csv") }

} else {

    #----------------------
    # Connect Custom Auth
    #----------------------

    # v2.2.234 -- accept either ClientSecret OR CertificateThumbprint. Previous
    # check demanded Secret and threw for SPN+cert customers (most common in
    # internal tenants using cert-based v1 SPNs the wizard re-uses).
    $__hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $__hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    # #209: a container job signing in as its managed identity (the container entry point set the switch).
    $__hasMi     = [bool]((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity))
    if (-not $__hasMi -and (
        [string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        (-not $__hasSecret -and -not $__hasCert))) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Provide them via wrapper globals or enable -AutomationFramework to load them."
    }
    # #450: the Start row that found no identity at the top of the run goes out now, signed in
    if ($script:_RAStartPending) {
        $script:_RAStartPending = $false
        try { Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'Start' } catch {}
    }

    if ($__hasMi)       { write-host "Connect using the container job's managed identity" }
    elseif ($__hasCert) { write-host "Connect using ServicePrincipal with AppId & Certificate" }
    else                { write-host "Connect using ServicePrincipal with AppId & Secret" }

    Write-Step "connecting to Azure"
    Tock
    try {
        if ($__hasMi) {
            # The container entry point normally connected already; this keeps a direct run working too.
            if (-not (Get-SIAzContext -ErrorAction SilentlyContinue)) {
                Connect-SIAzAccount -Identity -AccountId ([string]$global:SI_UAMI_ClientId) -WarningAction SilentlyContinue | Out-Null
            }
        } elseif ($__hasCert) {
            Connect-SIAzAccount -ServicePrincipal `
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

            Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $global:Credential -WarningAction SilentlyContinue | Out-Null
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
    # #636: the Summary mail settings move to the management mail (this Detailed report's mail) while the Summary step is
    # not on (engine\_shared\SI-SummaryStep.ps1 -- config\job-flow.custom.json, else the shipped default: off)
    $script:RAMgmtMail = $null
    if ([bool]$global:Detailed -and (Test-Path -LiteralPath ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-SummaryStep.ps1')))) {
        $__ssLib = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-SummaryStep.ps1'); if (-not (Get-Command -Name Resolve-SIManagementMailRouting -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $__ssLib)) { . $__ssLib }
        $__sumSend = if ($null -ne $__summarySend) { [bool]$__summarySend } else { $false }
        $__sumTo = if ($__summaryTo.Count -gt 0) { $__summaryTo } else { @($global:MailTo) }
        $script:RAMgmtMail = @{ DetailedSend = [bool]$global:Report_SendMail; DetailedTo = @($global:Report_To); SummarySend = $__sumSend; SummaryTo = @($__sumTo) }
        $script:RAMgmtMailEarly = Get-SISummaryStepState
        $__mm = Resolve-SIManagementMailRouting @script:RAMgmtMail -SummaryStep $script:RAMgmtMailEarly
        $global:Report_SendMail = $__mm.Send; $global:Report_To = @($__mm.To)
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
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "riskscore.index.locked.csv")   # #398: the shipped index; the customer's own rows (riskscore.index.custom.csv) are read on top of it
    # SecurityInsight Pro (Phase C): the risk index materialised from the settings database (SI_ProRaSettingsPath) wins.
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath) -and (Test-Path -LiteralPath (Join-Path ([string]$global:SI_ProRaSettingsPath) "riskscore.index.custom.csv"))) { $global:RiskDefinitionsCsvPath = (Join-Path ([string]$global:SI_ProRaSettingsPath) "riskscore.index.custom.csv") }
}

# v2.2.365 -- SMTP pre-flight validation at startup. If mail will be sent
# (Report_SendMail = true) AND anonymous mode is OFF (the default), require
# all three credentials -- SMTPFrom, SMTPUser, SMTPPassword -- to be non-empty.
# Throw early so the operator sees the misconfiguration at run start, not
# after a multi-hour Risk Analysis completes and only the mail-dispatch step
# at the very end discovers the missing credential.
# MAIL-1: the mail mode decides what the pre-flight checks. sharedMailbox: the mailbox must be set (the restriction itself
# is checked by the transport right before the send -- a refusal there is printed, never a crashed run). none: mail is off.
$script:RAMailSettings = Get-SIMailSettings
if ([bool]$global:Report_SendMail -and $script:RAMailSettings.Off) {
    Write-Info 'mail: SI_Mail_Mode = none -- the report is not mailed (the xlsx and json are still written and ingested).'
    $global:Report_SendMail = $false
}
if ([bool]$global:Report_SendMail -and $script:RAMailSettings.Mode -eq 'sharedMailbox' -and @($script:RAMailSettings.Problems).Count) {
    throw ("MAIL PRE-FLIGHT FAILED -- `$global:Report_SendMail is true and SI_Mail_Mode is sharedMailbox, but: {0}." -f (@($script:RAMailSettings.Problems) -join '; '))
}
if ([bool]$global:Report_SendMail -and $script:RAMailSettings.Mode -eq 'smtp' -and ($global:Mail_SendAnonymous -eq $false)) {
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
    return ($raw | ConvertFrom-SIYaml -SourceName $Path)
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
    # SecurityInsight Pro (Phase C): when the settings layer materialised the report catalog from the database
    # (templates + the customer's overrides, already merged), it is the WHOLE catalog -- the installation's locked,
    # dev and custom files are not read. Unset (every Community / VM run) = no change.
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath) -and
        (Test-Path -LiteralPath (Join-Path ([string]$global:SI_ProRaSettingsPath) ([string]$global:ReportSettingsFileLocked)))) {
      return (Join-Path ([string]$global:SI_ProRaSettingsPath) $relName)
    }
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

# LEGACY TEMPLATE NAMES. 'RiskAnalysis_Summary_Bucket' / 'RiskAnalysis_Detailed_Bucket' were the names of
# an earlier catalog (bucketing is now automatic for every template) and are defined in no shipped YAML --
# yet this engine's own fallback defaults, the Detailed container job's provisioning and the config
# reference all still named them, so every such run threw "not found" below. Honoured ONLY when the name
# is not defined: a customer who defines a template with that name keeps it.
function Resolve-RALegacyTemplateName {
  param([string]$Requested, [string[]]$Available)
  if ($Available -contains $Requested) { return $Requested }
  if ($Requested -match '^(?i)(RiskAnalysis_(Summary|Detailed))_Bucket$') {
    $base = $Matches[1]
    $hit  = @($Available | Where-Object { $_ -ieq $base }) | Select-Object -First 1
    if ($hit) { return [string]$hit }
  }
  return $Requested
}
if (-not $global:Exposure_Template) {
  $__tplResolved = Resolve-RALegacyTemplateName -Requested ([string]$global:ReportTemplate) `
                     -Available @($global:Report_Settings.ReportTemplates | ForEach-Object { [string]$_.ReportName })
  if ($__tplResolved -ne [string]$global:ReportTemplate) {
    Write-Info ("Report template '{0}' is a name from an earlier version -- running '{1}'." -f $global:ReportTemplate, $__tplResolved)
    $global:ReportTemplate = $__tplResolved
    if ($global:OutputXlsx) { $global:OutputXlsx = Join-Path (Split-Path -Parent $global:OutputXlsx) ("{0}.xlsx" -f $global:ReportTemplate) }
    $global:Exposure_Template = $global:Report_Settings.ReportTemplates | Where-Object { $_.ReportName -eq $global:ReportTemplate }
  }
}

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
#   - ReportName: RiskAnalysis_Detailed
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
# (a list, never += on an array in a loop)
$__incList = New-Object 'System.Collections.Generic.List[object]'
foreach ($x in $global:Exposure_Template_ReportsIncluded) {
  $inc = Resolve-ReportInclude -Item $x
  $__incList.Add($inc.Name)
}
$incNamesForLog = $__incList.ToArray()
Write-Info ("reports in template: {0}" -f ($incNamesForLog -join ', '))
# #278 the reports of this run -- a report hands findings to another only when that one runs too.
$global:RA_TemplateReportNames = @($incNamesForLog)

# ---------- Asset-identity map ------------------------------------------------------------
# Built ONCE per run, from the profile tables, and shared by every report. This is the generic
# model: the catalog carries nine different hand-written identity chains across 84 reports, and
# keeping those in step across ~6,000 customer estates is not achievable -- they drift silently.
# The resolver is keyed on identity SOURCE PRIORITY (exact name -> short name -> ARM parent/child),
# never on resource type, so it holds for an estate this code has never seen.
# 🔒 Non-fatal by design: a customer may not run every engine, and a report that cannot resolve an
# id must still ship its findings. A failure here degrades to today's behaviour, it never stops a run.
if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) {
    try {
        $global:RA_CiIndex = $null   # v3: the CI index is read once per run (RA-CiContext.ps1)
        $global:RA_SourceFirstSeenIndex = $null; $global:RA_SourceFirstSeenSaid = $false   # #636: Defender's first sightings, read once per run
        $global:RA_DefenderCveIndex = $null; $global:RA_DefenderCveSaid = $false; $global:RA_DefenderRecIndex = $null; $global:RA_DefenderRecSaid = $false   # the Defender CVE details and the Defender recommendations are each read once per run (RA-DefenderCveContext.ps1, RA-DefenderRecommendationContext.ps1)
        Initialize-SIAssetIdentityMap -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId)
    } catch {
        Write-Warn2 ("[identity] asset-identity map unavailable ({0}) -- reports fall back to their own chains." -f $_.Exception.Message)
    }
} else {
    Write-Warn2 '[identity] no workspace configured -- asset-identity map skipped; reports fall back to their own chains.'
}

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
# #398 -- THE SHIPPED INDEX + THE CUSTOMER'S OWN ROWS. The shipped index is riskscore.index.locked.csv (updates replace
# it); riskscore.index.custom.csv is only ever the customer's, read FIRST. An unchanged copy of an earlier version's
# shipped index under the custom name is removed here, on whatever path the install was upgraded. SecurityInsight Pro
# materialises the WHOLE index from its database (SI_ProRaSettingsPath): that file is the index, nothing is laid over it.
$global:RiskDefinitionsOverlay = @()
$__riPro = (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath)) -and
           ([string]$global:RiskDefinitionsCsvPath).StartsWith(([string]$global:SI_ProRaSettingsPath), [System.StringComparison]::OrdinalIgnoreCase)
if (-not $__riPro) {
  try {
    $__riMarker = ''
    $__riLogs = Join-Path (Split-Path -Parent $global:SettingsPath) 'logs'
    if (Test-Path -LiteralPath $__riLogs -PathType Container) { $__riMarker = Join-Path $__riLogs 'state\riskindex-custom-noticed.txt' }
    $__ri = Resolve-SIRiskIndexFiles -Folder (Split-Path -Parent $global:RiskDefinitionsCsvPath) -NoticeMarker $__riMarker
    foreach ($__l in @($__ri.Lines)) { Write-Info $__l }
    if ($__ri.CustomPath) {
      $global:RiskDefinitionsOverlay = @(Import-Csv -Path $__ri.CustomPath)
      Write-Info ("your own risk rows: {0} ({1})" -f $global:RiskDefinitionsOverlay.Count, $__ri.CustomPath)
    }
  } catch { Write-Err2 "cannot read your own risk index rows (riskscore.index.custom.csv): $($_.Exception.Message)"; throw }
}
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
      -ColProbScore            $global:CsvProbabilityScoreColumnName `
      -OverlayRows             $global:RiskDefinitionsOverlay
  Write-Ok ("risk index built: {0} rows, first match wins{1}{2}" -f $global:RiskIndex.OrderedRowCount,
      $(if ($global:RiskIndex.OverlayRowCount -gt 0) { (' -- your {0} row(s) first, then the shipped index' -f $global:RiskIndex.OverlayRowCount) } else { '' }),
      ($(if ($global:RiskIndex.SourceForm -eq 'v2.2' -or $global:RiskIndex.OverlayForm -eq 'v2.2') { ' (an index without the Precedence column was put in precedence order; its scores are unchanged)' } else { '' }) +
       $(if ($global:RiskIndex.SourceForm -ne 'si' -or ($global:RiskIndex.OverlayForm -and $global:RiskIndex.OverlayForm -ne 'si')) { ' (rows written with the 2.2 columns were translated to the SI keys -- their base values are unchanged)' } else { '' })))
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
# #753: several parts of a report at a time (the next parts' requests on their way while a part is processed; SI_RA_PartsInParallel_Max)
. (Join-Path $PSScriptRoot '_shared/RA-PartsInParallel.ps1')
# #640: the bucket counts live in the Pro database -- its statements and the sizing rules (steps 2-4)
. (Join-Path $PSScriptRoot '_shared/RA-BucketStore.ps1')

# #640 (owner 2026-10-13: "config about sizing should of course be in sql only"): with the Pro database the remembered
# counts, the one-time resets and every report's history are read from and written to the database ONLY. The container
# entry point hands over the counts the install learned before ($global:SI_RaBucketImportCache, imported ONCE).
$script:AutoBucketSql = $null
$script:AutoBucketJumps = New-Object System.Collections.Generic.List[object]
if ([bool]$global:AutoBucketCount -and [bool]$global:AutoBucketCache -and $global:SI_ProSettingsStore -and $global:SI_ProSettingsStore.Invoke) {
  $__abRunId = if ($global:SI_RunId) { [string]$global:SI_RunId } else { [guid]::NewGuid().ToString('N').Substring(0, 16) }
  # #742: a queue worker reads the counts as its producer left them -- the one-time import and a reset are the producer's
  $__abInit = Initialize-AutoBucketSqlStore -Invoke $global:SI_ProSettingsStore.Invoke -Template ([string]$global:ReportTemplate) -RunId $__abRunId `
                -ImportCache $(if ($script:RAScaleRole -ne 'worker' -and $global:SI_RaBucketImportCache -is [hashtable]) { $global:SI_RaBucketImportCache } else { $null }) -ResetAll:([bool]$global:ResetCache -and $script:RAScaleRole -ne 'worker')
  if ($__abInit.Offline) {
    Write-Warn ("bucket sizing: the database could not be read ({0}) -- this run sizes every report again and keeps nothing" -f $__abInit.Problem)
  } else {
    Write-Info ("bucket sizing: {0} remembered count(s) for {1} read from the database" -f $__abInit.Entries, $global:ReportTemplate)
    if ($__abInit.Imported -ge 0) { Write-Info ("bucket sizing: {0} count(s) learned before this version imported into the database (once)" -f $__abInit.Imported) }
    if (@($__abInit.Resets).Count) { Write-Info ("bucket sizing: one-time reset consumed for {0} -- sized again on this run" -f ((@($__abInit.Resets) | ForEach-Object { if ($_ -eq '*') { 'every report' } else { $_ } }) -join ', ')) }
  }
}

# AUDIT #57.1(a): run-over-run row-count regression guard. Loaded after AutoBucketing because it
# writes a sibling state file in the same OUTPUT folder. Moved to _shared/RA-RowCountGuard.ps1
. (Join-Path $PSScriptRoot '_shared/RA-RowCountGuard.ps1')   # forward slash works on both Win + Linux

# ============================ AUDIT #62 -- BUCKET-LOSS ACCOUNTING ====================================
# 🔴 THE DEFECT: a bucket that fails is logged and SKIPPED, and the report then ships as if complete.
# Found in a customer run 2026-08-26. `Device_Recommendations_Detailed` lost buckets 10 and 11 of 26
# to HTTP 500 after all four retries; the engine printed two `[ERR] query failed for bucket N/26`
# lines and ran to completion normally. Measured against the previous night on the same estate:
# 162,495 -> 150,148 raw rows, 15,220 -> 14,084 after dedup -- roughly 1,100 findings absent from the
# workbook, from the Log Analytics table and from the email. The run looked clean.
#
# ⚠️ `RowCountGuard` CANNOT catch this and reported green. It asks "did any report lose ALL of its
# findings"; this report still produced 14,084 rows, so it passed. Same family as #58.5 (every row
# present, the columns blank): THE RUN LOOKS CLEAN AND THE DATA IS PARTIAL.
#
# 🔑 The bucket loop already knows the number it needs -- it simply never compared buckets ATTEMPTED
# with buckets that CONTRIBUTED. There are SIX distinct paths that drop a bucket's rows, and a fix
# that covered only the one in the customer's log would have left five silent:
#   1. every remaining bucket skipped after a deterministic 900s timeout
#   2. transient-retry budget exhausted
#   3. any other query error
#   4. result conversion threw
#   5. a sub-bucket still timing out at MAX DEPTH
#   6. a sub-bucket failing for a non-timeout reason
#
# 📌 A lost bucket does NOT fail the run. Partial data beats no data, and the report is still worth
# having -- but it must be IMPOSSIBLE to mistake for complete. Hence a loud per-report verdict, a
# run-level roll-up, and the count carried into SI_RunHealth_CL.
$script:_RABucketLoss    = New-Object System.Collections.Generic.List[string]   # current report
$script:_RABucketLossRun = New-Object System.Collections.Generic.List[string]   # whole run

function Reset-RABucketLoss {
    $script:_RABucketLoss = New-Object System.Collections.Generic.List[string]
}

function Add-RABucketLoss {
    param([Parameter(Mandatory)][string]$Reason)
    if ($null -eq $script:_RABucketLoss) { Reset-RABucketLoss }
    [void]$script:_RABucketLoss.Add($Reason)
}

function Invoke-RABucketReauth {
    # Re-authenticate BOTH Graph and Az -- the most common cause of a transient failure on a long run is
    # a token that outlived its hour. Shared by the main bucket loop, the late-retry pass and the
    # sub-bucket pass so all three recover the same way. Never throws: a failed reconnect is reported
    # and the retry still goes ahead (the bucket may complete on the credentials still held).
    try { Connect-GraphHighPriv } catch { Write-Warn2 ("Graph reconnect failed: {0}" -f $_.Exception.Message) }
    try {
        if ($global:SpnClientId -and $global:SpnClientSecret -and $global:SpnTenantId) {
            $secStr = ConvertTo-SecureString -String ([string]$global:SpnClientSecret) -AsPlainText -Force
            $cred   = New-Object System.Management.Automation.PSCredential ([string]$global:SpnClientId, $secStr)
            $null   = Connect-SIAzAccount -ServicePrincipal -Credential $cred -Tenant ([string]$global:SpnTenantId) -ErrorAction Stop -WarningAction SilentlyContinue
        } elseif ($global:SpnClientId -and $global:SpnCertificateThumbprint -and $global:SpnTenantId) {
            $null = Connect-SIAzAccount -ServicePrincipal -ApplicationId ([string]$global:SpnClientId) -CertificateThumbprint ([string]$global:SpnCertificateThumbprint) -Tenant ([string]$global:SpnTenantId) -ErrorAction Stop -WarningAction SilentlyContinue
        }
    } catch { Write-Warn2 ("Az reconnect failed (non-fatal -- the bucket may still complete on Graph creds): {0}" -f $_.Exception.Message) }
}

function Get-RABucketRows {
    # Turn one successful bucket response into rows. Returns @{ Ok; Rows; Error }: Ok=$false means the
    # query SUCCEEDED and conversion failed -- the caller must record that as lost, because nothing
    # upstream reports a failure at all.
    param($Resp)
    if ($null -eq $Resp) { return @{ Ok = $true; Rows = @(); Error = $null } }
    if ($Resp -is [pscustomobject] -and $Resp.PSObject.Properties['_SIDirectRows']) {
        return @{ Ok = $true; Rows = @($Resp._SIDirectRows); Error = $null }
    }
    if ($null -eq $Resp.Results -or $null -eq $Resp.Results.AdditionalProperties) {
        return @{ Ok = $true; Rows = @(); Error = $null }
    }
    try {
        $__phConvSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
        $rows = @(ConvertTo-PSObjectDeep $Resp.Results.AdditionalProperties -StripOData -CastPrimitiveArrays)
        if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'convert' -Seconds $__phConvSw.Elapsed.TotalSeconds }
        return @{ Ok = $true; Rows = $rows; Error = $null }
    } catch {
        # OutOfMemory: the worker had no memory to convert this answer -- the caller asks the same rows in smaller slices
        $oom = $false; try { $oom = [bool](Test-RABucketOutOfMemory -Err $_) } catch { }
        return @{ Ok = $false; Rows = @(); Error = [string]$_.Exception.Message; OutOfMemory = $oom }
    }
}

function Write-RABucketLossVerdict {
    # Called at the report footer, right after the row total, so the count and the caveat that
    # qualifies it are never separated in the log.
    param(
        [Parameter(Mandatory)][string]$ReportName,
        [int]$BucketCount = 0,
        [int]$RowsKept    = 0
    )
    if ($null -eq $script:_RABucketLoss -or $script:_RABucketLoss.Count -eq 0) { return }
    $lost = $script:_RABucketLoss.Count
    Write-Err2 ("INCOMPLETE REPORT -- '{0}': {1} of {2} bucket(s) contributed NO rows. The {3} row(s) above are a PARTIAL result and the findings from those bucket(s) are missing from the workbook, the Log Analytics table AND the email. This is NOT an empty-result report and NOT a row-count regression the guard can see -- it is data that was never retrieved." -f `
        $ReportName, $lost, $BucketCount, $RowsKept)
    foreach ($r in $script:_RABucketLoss) {
        Write-Err2 ("        lost bucket -- {0}" -f $r)
        [void]$script:_RABucketLossRun.Add(("{0} :: {1}" -f $ReportName, $r))
    }
    # 🔴 A LOST BUCKET IS NOT AUTOMATICALLY A PLATFORM PROBLEM, AND THE ADVICE MUST NOT PRETEND IT IS.
    # This used to say, unconditionally, "nothing here is a permanent data condition". A deterministic
    # KQL defect (a case() returning mixed types) reaches here looking identical to a 500, and the
    # operator was told to spend another full run re-running something that cannot succeed. Worse, the
    # findings are missing from the CL table too -- and any consumer that reads absence as remediation
    # (a ticketing sync, for one) will CLOSE those findings and reopen them on the next good run.
    # 🪤 AND THE SAME CANCELLATION HAS TO BE EXCLUDED HERE TOO -- this test reads the RECORDED
    # message, which carries both "Query cancelled on creation" and the service's generic "Fix
    # semantic errors" suffix, so `semantic` (and `BadRequest`) match it. Without the exclusion the
    # bucket is resized correctly by the hunting layer and then STILL reported to the operator as a
    # query defect that will "fail identically on every run" -- which is what sent a previous
    # session looking for a fault in a query that has none. See RA-GraphHunting.ps1's
    # $isCancelledOnCreation for the measurement that settled it.
    # 🔴 THE EXCLUSION IS NOW THE SHARED LIST, NOT A LOCAL COPY (audit #106). It used to name the two
    # #99 cancellation forms inline; a SECOND platform prefix then arrived ("Errors occurred while
    # resolving remote entities", 2026-09-03) and this site did not know about it, so a report that
    # lost 449 findings to a transient service-side failure was reported as a permanent query defect.
    # Both sites now read `Get-RAPlatformFailurePrefixPattern` from RA-GraphHunting.ps1 (dot-sourced at
    # line ~609), so a future prefix is added ONCE and cannot be fixed in one place and missed here.
    # 🪤 Guarded: if the helper is somehow unavailable, fall back to matching the known prefixes
    # literally rather than silently excluding NOTHING -- which would re-arm exactly this defect.
    $__platformPfx = if (Get-Command Get-RAPlatformFailurePrefixPattern -ErrorAction SilentlyContinue) {
        Get-RAPlatformFailurePrefixPattern
    } else {
        'Query cancelled on creation|ScalarEvaluator\.Evaluate failed|Errors occurred while resolving remote entities'
    }
    $__permanent = @($script:_RABucketLoss | Where-Object {
        ($_ -notmatch $__platformPfx) -and
        ($_ -match 'semantic|syntax|not compatible|BadRequest')
    })
    $__transient = $lost - $__permanent.Count
    if ($__permanent.Count -gt 0) {
        Write-Err2 ("        {0} of these failed on a QUERY DEFECT, not on the platform. RE-RUNNING WILL FAIL IDENTICALLY -- the query has to be fixed. This IS a permanent data condition, and it will recur on every run until it is." -f $__permanent.Count)
    }
    if ($__transient -gt 0) {
        Write-Err2 ("        {0} of these failed on the platform (timeout / 5xx / throttle) and were already retried in-run; those usually succeed on the next run, so re-run the affected report." -f $__transient)
    }
    Write-Err2 ("        Until the affected report is whole again, treat its findings as UNKNOWN rather than resolved -- they are absent from the workbook AND the Log Analytics table, and absence is not remediation.")
}

# Per-report row counts for this run, filled in as each report finishes and compared against the
# previous run at the end. Absence is the thing SI keeps failing to notice (#48, v2.2.415, #57).
$global:RA_RowCountsThisRun = @{}
# Every report this run ATTEMPTED, recorded before anything can fail. The guard compares it with the
# counts above: attempted-but-no-count means the report failed outright, which the counts alone could
# never show -- a report that throws never reaches the line that records its count.
$global:RA_ReportsAttemptedThisRun = New-Object System.Collections.Generic.List[string]

# AUDIT #57.1(d): run-over-run COLUMN-population guard -- the sibling of the row-count guard above.
# #58.5 proved the gap: CMDB enrichment was blank on every OAuth run since v2.2.314, and because
# every row was still present and correct in NUMBER, the row-count guard saw nothing and was right
# not to. Rows can be intact while their content drains away. Moved to _shared/RA-ColumnFillGuard.ps1
. (Join-Path $PSScriptRoot '_shared/RA-ColumnFillGuard.ps1')   # forward slash works on both Win + Linux

# Per-report column fill snapshots for this run: report -> { '__rows' = n; '<col>' = filled }.
$global:RA_ColumnFillThisRun = @{}

#####################################################################################################
# MAIN LOOP
#####################################################################################################

Write-Section "executing reports"

$global:AllShapedRows = New-Object System.Collections.Generic.List[object]
$global:FinalRiskScoreColumnName = $null
$global:FinalDesiredColumns = $null
# The KQL column types this run's queries declare -- the workbook's one-type-per-column decision (#242).
if (Get-Command -Name Reset-RAKqlColumnTypes -ErrorAction SilentlyContinue) { Reset-RAKqlColumnTypes }
# $global:final is read by JSON write, LA ingest, and AI summary AFTER the per-report
# loop. If a previous run left it populated and THIS run produces zero rows (every
# report failed -- e.g. KQL referencing a not-yet-provisioned table), the stale data
# would leak into JSON / LA / xlsx-AI-sheet, producing an xlsx whose only sheet is the
# AI summary rendered from yesterday's data. Reset to empty so the empty-result path
# is honest end-to-end.
$global:final = @()
$global:RA_ReportRows = @()
$global:RA_ExemptedNotCounted = 0

# Collection timestamp + host identity -- same across every row in this run
# (every report, both Summary and Detailed) so the KQL filter
#   SI_RiskAnalysis_Summary_CL | where CollectionTime == toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime))
# returns exactly the most recent run's rows and nothing else.
# Mirrors IdentityAssetsCollectDefineTierIngestLog.ps1 line 1281.
[datetime]$global:RA_CollectionTime = ( Get-Date ([datetime]::Now.ToUniversalTime()) -Format "yyyy-MM-ddTHH:mm:ssK" )
# #742: a queue worker's rows carry its PRODUCER's collection time (the same value, read back from the run's manifest)
if ($script:RAScaleRole -eq 'worker' -and $null -ne $script:RAScaleRunTime) { $global:RA_CollectionTime = $script:RAScaleRunTime }
try {
    $global:RA_DnsName = [System.Net.Dns]::GetHostEntry('').HostName
} catch {
    $global:RA_DnsName = $env:COMPUTERNAME
}

# SolutionVersion -- stamp which release of SecurityInsight produced this
# run's data. Lets Workbook tiles show "dashboard powered by
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
    # 🔒 THE EDITION MARKER (operator, 2026-08-31: *"this la has both v3 and v2.2 runs"* /
    # *"version is in rows"* / *"same scope always so we can track progress"*).
    #
    # 🔴 THE COLUMN MEANT TO SEPARATE THE EDITIONS COULD NOT DO IT. `SolutionVersion` is read from
    # the per-solution VERSION file, and the v3 branch deliberately keeps that at 2.2.x because the
    # customer sync pulls on a VERSION check -- so a v3 run and a v2.2 run BOTH stamped "2.2.460"
    # and nothing downstream could tell them apart. Measured on the shared workspace: every recent
    # snapshot reported a single SolutionVersion, and it was the same string for both editions.
    #
    # Why that matters beyond tidiness: the two editions run DIFFERENT report sets, so mixing them
    # silently changes the scope between one snapshot and the next. Anything that compares two
    # snapshots -- the trend rate, SnapshotDiff's new/closed, the exec score delta -- then measures
    # WHICH EDITION RAN rather than what changed in the estate (audit #93).
    #
    # 🔑 A SUFFIX, NOT A BUMP. The VERSION *file* is the sync contract and must not move for v3
    # work; the stamped *value* is data in an existing column, so marking it costs no schema change,
    # no ingest wait and no per-customer approval. It also stays useful after the migration: a
    # customer workspace holding both editions' history can always separate them.
    if ($global:RA_SolutionVersion -ne '(dev)' -and $global:RA_SolutionVersion -notmatch '\+v3$') {
        # The marker is a v3-ONLY file, so this cannot accidentally be true on a v2.2 install.
        $_v3Marker = Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-V3Snapshot.ps1'
        if (Test-Path -LiteralPath $_v3Marker) {
            $global:RA_SolutionVersion = '{0}+v3' -f $global:RA_SolutionVersion
        }
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

# =====================================================================================================================
# ONE REPORT'S ROWS -> SCORED, SHAPED ROWS (filters, exemptions, tiers, CI context, scoring, trace identity, columns).
# #638: a function, so it runs per BUCKET when the result goes to SQL (each bucket's rows are written and let go) and once
# per report otherwise (the rows join the export pool, as before). It reads the report's settings from the report loop.
# =====================================================================================================================
function Invoke-RAReportRows {
    param([AllowEmptyCollection()][object[]]$ResultAll = @(), [string]$RABucket = '')
    $ResultAll = @($ResultAll)
if ($ResultAll.Count -eq 0) {
        Write-Info "No rows returned from query"
        # AUDIT #57.1(a) -- RECORD THE ZERO **BEFORE** THIS `continue`.
        # 🪤 The first cut of this guard captured only at "rows after filters", below. This early
        # exit skips that entirely, so a report that produced NOTHING was the one case never
        # recorded -- i.e. the guard would have missed #57, the exact defect it was built for.
        # Caught by smoke-running it instead of trusting the unit tests. A zero is not the absence
        # of a measurement; it IS the measurement, and it is the one that matters most.
        if ($null -ne $global:RA_RowCountsThisRun) {
            if (-not $script:RAStreamOn) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 }
        }
        if (-not $script:RAStreamOn) { Write-RAZeroRowWarning -ReportName ([string]$ReportName) }
        return
    }

    # Filters
    $ResultFiltered = @($ResultAll)

    # SecurityInsight Pro: findings exempted in the management GUI (cfg.Exemption), materialised by the settings layer
    # into SI_ProRaSettingsPath, are MARKED, never dropped (#264): every row stays, the exempted ones carry SI_ExemptionId /
    # SI_ExemptedUntil / SI_ExemptionRequestId, and what is counted is decided at read time. No file = no change.
    $ResultFiltered = @(Set-RAExemptionMarks -Rows $ResultFiltered -ReportName $ReportName -FindingColumns @($ConfigurationIdInputName))

    # A finding on an asset NO PROFILER HAS SEEN (an Azure resource outside the profiled subscriptions, a subscription
    # node, ...) came back without a tier and was counted as Unclassified everywhere. Its tier now comes from the tier
    # rules -- the rules a name decides (a Tier board pin among them), else the default tier rule. Before the tier filter
    # and the scoring, so both see the tier. A row that has a tier is never touched.
    $__unprof = @{}
    $ResultFiltered = @(Set-RAUnprofiledTiers -Rows $ResultFiltered -ReportName $ReportName -LevelColumn $CriticalityTierLevelInputName -Stats $__unprof)
    if ($__unprof.Resolved -gt 0) {
        Write-Info ("{0} finding(s) on assets no profiler has seen were given a tier by the tier rules ({1} by a name rule, {2} by the default tier rule)" -f $__unprof.Resolved, $__unprof.ByRule, $__unprof.ByDefault)
    }
    if ($__unprof.Left -gt 0) {
        Write-Info ("{0} finding(s) have no tier: no profile, no matching name rule and no default tier rule for their asset kind -- they show as Unclassified" -f $__unprof.Left)
    }

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
    # (e.g. SI_PublicIP_Profile_CL not yet populated, or any report whose
    # source table is missing/empty). Filter-ObjectsByColumn rejects empty
    # InputObject as a parameter binding error, which used to kill the
    # whole script when the per-report iteration had no try/catch wrapper.
    if ($null -eq $ResultFiltered -or @($ResultFiltered).Count -eq 0) {
        Write-Info "no rows from query; skipping filters + scoring for this report (continuing with next report)"
        if ($null -ne $global:RA_RowCountsThisRun) { if (-not $script:RAStreamOn) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 } }
        return
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
        $FilteredOut = @($FilteredOut) + @($r.Removed)   # (one join per filter, not += in a loop)
      } else {
        $ResultFiltered = @(Filter-ObjectsByColumn -InputObject @($ResultFiltered) -ColumnToFilter $fs.Column -InScopeData @($fs.Scope) -CaseInsensitive -IncludeBlank:$true -FilterName $fs.Name)
      }
    }

    $totalAfter = ($ResultFiltered | Measure-Object).Count
    # #641 item 4: what this slice does with its rows is accounted for -- what is not stored must be named
    $__acLbl = $(if ($RABucket) { $RABucket } else { 'whole' })
    if ($script:RAStreamOn) { Set-RAStreamAccount -Stream $script:RAStream -Bucket $__acLbl -Values @{ In = $ResultAll.Count; Scope = ($ResultAll.Count - [int]$totalAfter); Excluded = 0; Duplicate = 0; Written = 0 } }
    Tick "apply filters"
    Write-Info ("rows after filters:  {0}" -f $totalAfter)
    if (-not $script:RAStreamOn -and [int]$totalAfter -eq 0 -and (Get-Command -Name Write-RAZeroRowWarning -ErrorAction SilentlyContinue)) { Write-RAZeroRowWarning -ReportName ([string]$ReportName) }

    # AUDIT #57.1(a) -- record the post-filter count for the run-over-run guard. Post-filter, not
    # raw, because that is the number that reaches the customer's export and Log Analytics.
    if ($null -ne $global:RA_RowCountsThisRun) {
        if ($script:RAStreamOn) { $global:RA_RowCountsThisRun[[string]$ReportName] = [int]$global:RA_RowCountsThisRun[[string]$ReportName] + [int]$totalAfter } else { $global:RA_RowCountsThisRun[[string]$ReportName] = [int]$totalAfter }
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
      return
    }

    # v3 data model: the CI context BEFORE scoring -- one asset, one tier / CMDB values / criticality / asset risk factors
    # #638 item 3: with the result in SQL, the CI context of THIS bucket's assets is looked up in sidata.Ci -- never every CI of the tenant
    $__ciIdx = $null
    if ($script:RAStreamOn -and -not ($global:SI_RA_CiContext -and ([string]$global:SI_RA_CiContext).Trim().ToLowerInvariant() -in 'off', 'false', '0')) {
        try { $__ciIdx = Get-RAStreamCiIndex -Invoke $script:RAStream.Invoke -Rows @($ResultFiltered) -StaleDays (Get-RAStaleDays) }
        catch { Write-Warn2 ("CI context: the CIs of this query slice could not be read from the database -- the findings are scored without them: {0}" -f $_.Exception.Message); $__ciIdx = New-RACiIndex -Cis @() }
    }
    try { $raFs = @(); if ($raScope -and $raScope.Active) { $raFs = @($raScope.Active.FactorSet) }; $ResultFiltered = Add-RACiContext -Rows @($ResultFiltered) -FactorSet $raFs -Index $__ciIdx } catch { Write-Warn2 ("CI context could not be added -- the findings are scored as before: {0}" -f $_.Exception.Message) }

    # rich context (Defender): the exploit details of each CVE row from the Defender vulnerability API -- OPT-IN
    # (SI_RA_DefenderCveApi = on; by default the CVE reports' own query carries them and no API call is made), context
    # columns only (no factor, no score), only the slice's own CVEs, and a refused or failed read is said once and changes nothing
    try { $ResultFiltered = Add-RADefenderCveContext -Rows @($ResultFiltered) -Log { param($m) Write-Warn2 $m } } catch { Write-Warn2 ("The exploit details of the vulnerabilities could not be added -- the findings are unchanged: {0}" -f $_.Exception.Message) }
    # #636 (owner 2026-10-19): the source's own first-seen (si_source_first_seen) -- the protection score ages a finding by it
    # before SI's own first detection; Defender's software vulnerabilities export is read once per run (SI_RA_SourceFirstSeen)
    try { $ResultFiltered = Add-RASourceFirstSeen -Rows @($ResultFiltered) -Log { param($m) Write-Warn2 $m } } catch { Write-Warn2 ("The source's first-seen dates could not be added -- the findings are unchanged: {0}" -f $_.Exception.Message) }
    # ... and what Defender says about the recommendation itself: its exposure impact and whether it has an active alert
    # (the Defender recommendations API) -- context columns only, one read per run, a refused read is said once
    try { $ResultFiltered = Add-RADefenderRecommendationContext -Rows @($ResultFiltered) -Log { param($m) Write-Warn2 $m } } catch { Write-Warn2 ("The exposure impact and active alert of the Defender recommendations could not be added -- the findings are unchanged: {0}" -f $_.Exception.Message) }

    # #546 (5) known false positives of a provider's recommendation in a stated situation: the data model's default
    # exclusion rules (customer-overridable) leave them out, counted per rule with its reason. No rule = unchanged.
    try {
        $raRecIdx = Get-RARecommendationExclusionIndex
        if ($raRecIdx -and $raRecIdx.Count -gt 0) {
            $raRecSel = Select-RARecommendationExclusions -Rows @($ResultFiltered) -ReportName $ReportName -ConfigurationColumn $ConfigurationIdInputName -Index $raRecIdx -CiIndex $(if ($null -ne $__ciIdx) { $__ciIdx } else { Get-RACiIndex })
            $ResultFiltered = @($raRecSel.Rows)
            foreach ($l in (Format-RARecommendationExclusionLines -ReportName $ReportName -Suppressed $raRecSel.Suppressed)) { Write-Info $l }
        }
    } catch { Write-Warn2 ("recommendation exclusion rules could not be applied -- no finding was left out: {0}" -f $_.Exception.Message) }
    if ($script:RAStreamOn) { Set-RAStreamAccount -Stream $script:RAStream -Bucket $__acLbl -Values @{ Excluded = ([int]$totalAfter - @($ResultFiltered).Count) } }
    if (@($ResultFiltered).Count -eq 0) { Write-Info "No rows after the default exclusion rules"; return }

    # Risk calc
    Tock
    Write-Info "calculating risk scores"
    $__phScoreSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
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
    if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'score' -Seconds $__phScoreSw.Elapsed.TotalSeconds }
    Tick "risk scoring"
    if ($script:RAStreamOn) { Set-RAStreamAccount -Stream $script:RAStream -Bucket $__acLbl -Values @{ Duplicate = (@($ResultFiltered).Count - @($RiskScoreArray).Count) } }

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
    # Detect Detailed reports by presence of an AssetName column â€” Detailed reports project
    # one row per asset, Summary reports aggregate above the asset level. Used below to
    # decide whether TraceName includes the AssetName segment.
    $isDetailedShape = $false
    if ($RiskScoreArray -and $RiskScoreArray.Count -gt 0) {
        $firstRow = $RiskScoreArray[0]
        if ($firstRow -and $firstRow.PSObject.Properties['AssetName']) { $isDetailedShape = $true }
    }
    foreach ($row in @($RiskScoreArray)) {
        Add-Member -InputObject $row -NotePropertyName 'CollectionTime'  -NotePropertyValue $global:RA_CollectionTime  -Force
        Add-Member -InputObject $row -NotePropertyName 'SolutionVersion' -NotePropertyValue $global:RA_SolutionVersion -Force
    }
    # TraceName composition (single-dash separator, only non-empty parts joined) -- _shared/RA-RowShaping.ps1:
    #   Summary : <ConfigurationName>-<SecuritySeverity>[-<cmdbName>]-SI
    #   Detailed: <ConfigurationName>-<SecuritySeverity>[-<cmdbName>]-<AssetName>[-<asset id> when another asset of this
    #             report shares the name]-SI
    Set-RATraceIdentity -Rows @($RiskScoreArray) -IsDetailed $isDetailedShape

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
        'AssetDetectedInReportName',
        # #910 the explained score (Calculate-RiskScore): each side's base and each counted factor's impact -- appended
        # LAST, so every column before them keeps its place
        'RiskConsequenceBase',
        'RiskProbabilityBase',
        'RiskFactor_Consequence_Impacts',
        'RiskFactor_Probability_Impacts'
    )
    # #264: the exemption mark travels on every row of a run that has exemptions (blank when not exempted), so the Log
    # Analytics schema learns its columns; a run without exemptions adds none.
    if ($null -ne (Get-RAExemptions)) { $ComputedCols += @(Get-RAExemptionMarkColumns) }
    $TraceCols   = @('CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID')    # always the LAST four columns -- not in any YAML OutputPropertyOrder on purpose

    # ============================================================================================
    # 🔒 AssetName / AssetId ARE NEVER BLANK -- FILLED FROM THE v3 SI_ COLUMNS, IN THE OLD NAMES.
    # ============================================================================================
    # Operator, 2026-08-28: "it must fill data from the si_ columns into thr old names",
    # "we keep old columns", "si_assetname and si_assetid must be 100% populated in excel moving
    # forward in the old columns", "remember 6000 customers".
    #
    # 🔴 WHY A FILL AND NOT A RENAME. SI_AssetName / SI_AssetId are the v3 identity columns, 100%
    # populated on all four profile tables, while the unprefixed AssetId measured 0% on all four
    # (declared "alias of PrimaryEntityId" in every schema, wired in none). Renaming the OUTPUT
    # column to the SI_ name would change the schema of SI_RiskAnalysis_Detailed_CL / _Summary_CL,
    # and every customer query, workbook and dashboard bound to AssetName/AssetId would silently
    # stop returning rows -- across ~6000 installs. So the NAME stays and only the VALUE is sourced
    # from the v3 column. Nothing downstream changes shape.
    #
    # 🪤 SCOPED TO REPORTS THAT ALREADY DECLARE THE COLUMN. Filling unconditionally would ADD
    # AssetName/AssetId to reports whose OutputPropertyOrder deliberately omits them -- the Summary
    # reports, which publish ImpactedAssetsList instead -- silently changing their shape. Declared-
    # only means this can add DATA and never a COLUMN.
    # 📌 Summary reports get the same v3 value by a different route: the ImpactedAssets resolver in
    # _shared/RA-RiskScore.ps1 carries SI_AssetName at the head of its own candidate list.
    #
    # 🪤 AND IT RUNS PER REPORT, NOT PER QUERY. A per-report YAML edit cannot reach the 105 reports
    # that derive their own AssetName/AssetId from EG/hunting sources, which is where the measured
    # 691-of-3,408 blank AssetId rows come from. One engine pass covers every report.
    if ($OutputPropertyOrder -and $RiskScoreArray -and @($RiskScoreArray).Count -gt 0) {
        # SI_ column first because it is the authored v3 value; the rest are the fallbacks these
        # reports already used, kept so behaviour only ever improves.
        $_fillPlan = @(
            @{ Target = 'AssetName'; Candidates = @('SI_AssetName','DisplayName','Hostname','Name','ConfigurationName') }
            # #193 -- never 'ConfigurationId': a recommendation or setting id is not an asset id, and a connector
            # keys on this column. Measured 2026-10-01: 178 of 15,614 Detailed rows published one. Blank is honest.
            @{ Target = 'AssetId';   Candidates = @('SI_AssetId','PrimaryEntityId','MdeDeviceId','AzureResourceId','EntraAccountObjectId') }
        )
        foreach ($_plan in $_fillPlan) {
            $_target = [string]$_plan.Target
            if ($OutputPropertyOrder -notcontains $_target) { continue }   # report does not publish it
            foreach ($_row in $RiskScoreArray) {
                if ($null -eq $_row) { continue }
                $_prop = $_row.PSObject.Properties[$_target]
                if ($_prop -and -not [string]::IsNullOrWhiteSpace([string]$_prop.Value)) { continue }  # already filled
                $_val = ''
                foreach ($_cand in $_plan.Candidates) {
                    $_cp = $_row.PSObject.Properties[$_cand]
                    if ($_cp -and -not [string]::IsNullOrWhiteSpace([string]$_cp.Value)) { $_val = [string]$_cp.Value; break }
                }
                if ([string]::IsNullOrWhiteSpace($_val)) { continue }      # nothing to fill from -- leave as-is
                if ($_prop) { $_row.$_target = $_val }
                else { Add-Member -InputObject $_row -MemberType NoteProperty -Name $_target -Value $_val -Force }
            }
        }

        # ONE ASSET, ONE IDENTITY (Detailed): the same canonicalisation as the Summary rows -- a row's id names its asset,
        # and an Azure VM id carried by a device becomes that device. Runs AFTER the TraceName/TraceID stamp above, so a
        # finding's trace stays the same over time; only the asset it is shown under is unified.
        if ((Get-Command Resolve-SICanonicalAsset -ErrorAction SilentlyContinue) -and $OutputPropertyOrder -contains 'AssetId') {
            foreach ($_row in $RiskScoreArray) {
                if ($null -eq $_row) { continue }
                $_ip = $_row.PSObject.Properties['AssetId']
                if (-not $_ip -or [string]::IsNullOrWhiteSpace([string]$_ip.Value)) { continue }
                $_np = $_row.PSObject.Properties['AssetName']
                $_c = Resolve-SICanonicalAsset -Name $(if ($_np) { [string]$_np.Value } else { '' }) -Id ([string]$_ip.Value)
                if (-not $_c.Changed) { continue }
                $_row.AssetId = $_c.Id
                if ($_np) { $_row.AssetName = $_c.Name } elseif ($OutputPropertyOrder -contains 'AssetName') { Add-Member -InputObject $_row -MemberType NoteProperty -Name 'AssetName' -Value $_c.Name -Force }
            }
        }
        # ========================================================================================
        # AssetIdSource -- WHERE the id came from (operator, 2026-09-01: "so i know where it came from")
        # ========================================================================================
        # 🔴 THE ID COLUMN CARRIES FOUR NAMESPACES AND ANNOUNCED NONE OF THEM. Measured over the
        # 1000 distinct impacted-asset ids on one live snapshot: 978 SI-authored asset ids, 19
        # ExposureGraph node ids (32 bare hex characters), 3 ARM resource ids and 3 raw IPv4
        # addresses. An SI asset id and an EG node id are both hex and resolve in DIFFERENT systems,
        # so the value alone cannot tell an operator -- or a CMDB connector -- where to look it up.
        #
        # 🪤 IT IS ONLY WORTH A COLUMN BECAUSE OF THE 2%. The answer is the same on ~98% of rows;
        # the ones that differ are precisely the ids nobody can currently resolve.
        #
        # 📌 ADDITIVE, AND ONLY WHERE THE ID IS. A new column changes nothing bound to the existing
        # ones -- the same property that made ImpactedAssetIds safe to ship to every install -- and
        # it is filled only on rows that actually carry an AssetId, so a report that publishes no
        # asset id gains no column.
        # 🔒 The classification is resolved against the run's identity map FIRST and only falls back
        # to shape; see Get-SIAssetIdSource. Reading the shape first would mis-file every SI asset
        # id whose value happens to look like something else.
        if ($OutputPropertyOrder -contains 'AssetId' -and (Get-Command Get-SIAssetIdSource -ErrorAction SilentlyContinue)) {
            foreach ($_row in $RiskScoreArray) {
                if ($null -eq $_row) { continue }
                $_idProp = $_row.PSObject.Properties['AssetId']
                if (-not $_idProp -or [string]::IsNullOrWhiteSpace([string]$_idProp.Value)) { continue }
                $_src = Get-SIAssetIdSource -AssetId ([string]$_idProp.Value)
                # the reports on SI_CI_CL publish the CI's id as AssetId: say so -- the findings are keyed on it (RA-Findings.ps1)
                $_ciProp = $_row.PSObject.Properties['si_ci_id']
                if ($_ciProp -and $_ciProp.Value -and [string]::Equals([string]$_ciProp.Value, [string]$_idProp.Value, [StringComparison]::OrdinalIgnoreCase)) { $_src = $script:SIAssetIdSourceCi }
                if ([string]::IsNullOrWhiteSpace($_src)) { continue }
                $_srcProp = $_row.PSObject.Properties['AssetIdSource']
                if ($_srcProp) { $_row.AssetIdSource = $_src }
                else { Add-Member -InputObject $_row -MemberType NoteProperty -Name 'AssetIdSource' -Value $_src -Force }
            }
        }
    }

    $DesiredColumns = @()
    if ($OutputPropertyOrder) { $DesiredColumns += ($OutputPropertyOrder | Where-Object { $_ -notin $TraceCols }) }
    # (a list while columns are added, never += on an array in a loop)
    $__dcList = New-Object 'System.Collections.Generic.List[object]'; foreach ($x in $DesiredColumns) { $__dcList.Add($x) }
    foreach ($c in $ComputedCols) { if ($__dcList -notcontains $c -and $c -notin $TraceCols) { $__dcList.Add($c) } }
    $DesiredColumns = $__dcList.ToArray()

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
    $__dcList = New-Object 'System.Collections.Generic.List[object]'; foreach ($x in $DesiredColumns) { $__dcList.Add($x) }
    foreach ($p in $unionProps) {
      if ($__dcList -notcontains $p -and $p -notin $TraceCols -and $p -notin $systemArrayProps) {
        $__dcList.Add($p)
        if ($p -notin $firstRowProps) { [void]$rescued.Add($p) }
      }
    }
    $DesiredColumns = $__dcList.ToArray()
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
    $DesiredColumns = @($DesiredColumns) + @($TraceCols)   # (one join, not += in a loop)
    # a column named twice (any case) makes Select-Object throw and the report fail -- never again (Get-RAUniqueColumns)
    $DesiredColumns = Get-RAUniqueColumns -Columns $DesiredColumns

    # A LONG STAGE IS NEVER SILENT (live 2026-10-16: 4.5 minutes per slice without a line from here to the database write).
    # Measured offline on 14,000 rows x 93 columns: this shaping + the column-fill count take seconds (Select-Object is
    # compiled and beats any script loop); the minutes were the database removing what the slice stored before
    # (Get-RAStreamDeleteBucketSql). Each now says how long it took.
    $__shapeSw = [System.Diagnostics.Stopwatch]::StartNew()
    $Shaped = $RiskScoreArray | Select-Object -Property $DesiredColumns

    # Ensure RiskScore is numeric
    $Shaped = $Shaped | ForEach-Object {
      if ($_.$RiskScoreOutputName -isnot [double]) {
        # Invariant: a culture-default TryParse reads "12.5" as 125 on a da-DK host (#121).
        $_.$RiskScoreOutputName = ConvertTo-RADouble -Value $_.$RiskScoreOutputName -Default 0.0
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
        # 🔴 THE UNION MUST BE CASE-INSENSITIVE, AND THIS LINE IS THE WHOLE FIX.
        # `List[string].Contains()` uses the ORDINAL comparer, so 'OsPlatform' (endpoint reports) and
        # 'OSPlatform' (the DI_OSPlatform coalesce in the locked YAML) were BOTH admitted to the union.
        # PSObject property names are case-INSENSITIVE, so the `Select-Object -Property $DesiredColumns`
        # in Export-Worksheet then threw:
        #     The property cannot be processed because the property "OSPlatform" already exists.
        # 🪤 WHAT HID IT: the per-report build above uses PowerShell's `-notcontains`, which IS
        # case-insensitive -- so no single report can ever collide with itself, and every report passes
        # its own Select-Object at line ~3308. Only the union ACROSS reports could collide, and only
        # when two reports spell one column differently. Switching from a PowerShell operator to a .NET
        # List silently changed the comparison semantics at exactly the point where it mattered.
        # 🔴 AND IT FAILED AT THE WORST POSSIBLE MOMENT: the Excel write is the LAST step and runs
        # BEFORE the JSON sibling, so a 26-minute run with every query already complete and 2600 rows
        # in the pool lost all of it. Reported from a real v2.2.438 customer run.
        # FIRST SPELLING WINS: the union is first-seen order and row values are looked up
        # case-insensitively anyway, so keeping the earlier spelling changes no cell value.
        $mergedCols = New-Object 'System.Collections.Generic.List[string]'
        $seenCols   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($c in $global:FinalDesiredColumns) { if ($seenCols.Add($c)) { [void]$mergedCols.Add($c) } }
        foreach ($c in $DesiredColumns)             { if ($seenCols.Add($c)) { [void]$mergedCols.Add($c) } }
        # Re-pin the trace columns last. They are appended per report (see $TraceCols
        # above, "always the LAST four columns"), so a plain union would leave report 1's
        # copies stranded mid-sheet with later reports' columns after them.
        # Removal is case-insensitive too -- an ordinal Remove() would leave a differently-cased
        # duplicate of a trace column stranded mid-sheet AND re-introduce the collision this fixes.
        foreach ($t in $TraceCols) {
            for ($i = $mergedCols.Count - 1; $i -ge 0; $i--) {
                if ([string]::Equals($mergedCols[$i], $t, [System.StringComparison]::OrdinalIgnoreCase)) { $mergedCols.RemoveAt($i) }
            }
        }
        foreach ($t in $TraceCols) { [void]$mergedCols.Add($t) }
        $global:FinalDesiredColumns = $mergedCols.ToArray()
    }

    # AUDIT #57.1(d) -- snapshot column fill from $Shaped, and ONLY from $Shaped.
    # 🪤 $Shaped is the correct site and the earlier candidates are all wrong in a way that would
    # make the guard miss the defect class it exists for:
    #   * $ResultFiltered (where #57.1(a) captures) is PRE-shaping, so a column dropped by the
    #     `Select-Object -Property $DesiredColumns` above -- audit #26, which really did lose
    #     AssetName and AssetType from a delivered workbook -- would still read as fully populated.
    #   * $RiskScoreArray is pre-shaping too, and additionally carries working columns that never
    #     reach the customer, so it would raise findings about data nobody receives.
    # $Shaped is what enters the export pool, and the export pool is what the customer opens.
    # 🔴 ITS OWN try/catch, AND THIS IS NOT DEFENSIVE BOILERPLATE. This capture sits INSIDE the
    # per-report try, whose catch does `Write-Warn2 "report failed -- skipping"` and moves to the
    # next report. So an exception thrown in here would not merely lose the guard's measurement --
    # it would DROP THE WHOLE REPORT FROM THE CUSTOMER'S EXPORT, silently, in the name of a feature
    # whose entire purpose is to prevent silent loss. A guard must never be the reason a good run
    # loses data.
    if ($null -ne $global:RA_ColumnFillThisRun) {
        try {
            $__snap = Get-RAColumnFillSnapshot -Rows @($Shaped); if ($script:RAStreamOn) { $__snap = Merge-RAColumnFillSnapshot -Into $global:RA_ColumnFillThisRun[[string]$ReportName] -Add $__snap }; $global:RA_ColumnFillThisRun[[string]$ReportName] = $__snap
        } catch {
            Write-Warn2 ("[ColumnFillGuard] snapshot skipped for {0}: {1}" -f $ReportName, $_.Exception.Message)
        }
    }
    Write-Info ("{0:N0} row(s) put in the report's {1} columns and their filled columns counted in {2:N1} s" -f @($Shaped).Count, @($DesiredColumns).Count, $__shapeSw.Elapsed.TotalSeconds)
    if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'shape' -Seconds $__shapeSw.Elapsed.TotalSeconds }   # #873 A

    if ($script:RAStreamOn) {
        # #638: this bucket's rows go to SQL now and are let go -- nothing of the report is gathered in memory
        $__w = Write-RAStreamBucketRows -Shaped @($Shaped) -Bucket $RABucket -IsDetailedShape $isDetailedShape -DesiredColumns $DesiredColumns
        Set-RAStreamAccount -Stream $script:RAStream -Bucket $__acLbl -Values @{ Written = [long](@($__w)[-1]) }
    } else {
        foreach ($row in @($Shaped)) { $global:AllShapedRows.Add($row) | Out-Null }
        Write-Ok ("added {0} rows to export pool (total now {1})" -f (@($Shaped).Count), $global:AllShapedRows.Count)
    }
}

# =====================================================================================================================
# #638 THE RESULT IN SQL -- the report loop's side of it (RA-SqlStream.ps1 holds the statements).
# =====================================================================================================================
$script:RAStreamOn = $false
$script:RAStream = $null
$script:RAStreamExemptedNotCounted = 0L
$script:RAEqIdx = $null
$script:RAExcelScope = $null
if ($null -eq $script:RAReportStatusDone) { $script:RAReportStatusDone = @{} }
# #690 (34): per report, the fingerprint of what it asks this run (Get-RAReportQueryFingerprint) -- stored with its verdict
if ($null -eq $script:RAReportQueryHash) { $script:RAReportQueryHash = @{} }
# #692: per report, the fingerprint(s) it had before a declared structure-only change (Get-RAReportQueryFingerprintCarry, ';')
if ($null -eq $script:RAReportQueryHashCarry) { $script:RAReportQueryHashCarry = @{} }

# #641 THE BUCKET PROOF (on demand: SI_RA_BucketProof = on): for every report small enough to run WHOLE (at most
# SI_RA_BucketProofMaxRows rows, default 20,000), the rows its buckets returned are compared with the rows the unbucketed
# query returns -- row by row, every column. The verdict is said and stored with the report's completeness.
$script:RAProof = $null
function Reset-RAProof {
    $on = ([string]$global:SI_RA_BucketProof).Trim().ToLowerInvariant() -in 'on', 'true', '1', 'yes'
    $max = 20000; if ([int]$global:SI_RA_BucketProofMaxRows -gt 0) { $max = [int]$global:SI_RA_BucketProofMaxRows }
    $script:RAProof = @{ On = $on; Max = $max; Sigs = (New-Object 'System.Collections.Generic.Dictionary[string,int]'); Rows = 0L; Over = $false }
}
function Get-RAProofSig {
    param($Row)
    $o = [ordered]@{}; foreach ($n in @($Row.PSObject.Properties.Name | Sort-Object)) { $o[$n] = $Row.$n }
    Get-RAStreamHash16 -Text ((ConvertTo-RAStreamJson -Row ([pscustomobject]$o)).Json)
}
function Add-RAProofRows {
    param([AllowEmptyCollection()][object[]]$Rows = @())
    if ($null -eq $script:RAProof -or -not $script:RAProof.On -or $script:RAProof.Over) { return }
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $script:RAProof.Rows++
        if ($script:RAProof.Rows -gt $script:RAProof.Max) { $script:RAProof.Over = $true; $script:RAProof.Sigs.Clear(); return }
        $s = Get-RAProofSig $r
        if ($script:RAProof.Sigs.ContainsKey($s)) { $script:RAProof.Sigs[$s]++ } else { $script:RAProof.Sigs[$s] = 1 }
    }
}
function Get-RAProofVerdict {
    <# The report's rows from its buckets against the unbucketed query's rows. '' when the proof is off. #>
    param([Parameter(Mandatory)][string]$Query)
    if ($null -eq $script:RAProof -or -not $script:RAProof.On) { return '' }
    if ($script:RAProof.Over) { return ('bucket proof: not run -- more than {0} rows, too large to run whole' -f $script:RAProof.Max) }
    $q = $Query
    if (Test-QueryHasBucketFilterBlock -Query $q) { $q = Replace-BucketFilterBlock -Query $q -BucketFilterKql (New-BucketFilterKql -BucketCount 1 -BucketIndex 0 -ReportName $ReportName) }
    $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
    try {
        $conv = Get-RABucketRows -Resp (Invoke-GraphHuntingQuery -Query $q -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries 1)
        if (-not $conv.Ok) { return ('bucket proof: the whole query''s result could not be read -- {0}' -f $conv.Error) }
    } catch { return ('bucket proof: the whole query could not run -- {0}' -f $_.Exception.Message) }
    $whole = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $n = 0L
    foreach ($r in @($conv.Rows)) { if ($null -eq $r) { continue }; $n++; $s = Get-RAProofSig $r; if ($whole.ContainsKey($s)) { $whole[$s]++ } else { $whole[$s] = 1 } }
    $missing = 0L; $extra = 0L
    foreach ($k in $whole.Keys) { $b = 0; if ($script:RAProof.Sigs.ContainsKey($k)) { $b = $script:RAProof.Sigs[$k] }; if ($whole[$k] -gt $b) { $missing += ($whole[$k] - $b) } }
    foreach ($k in $script:RAProof.Sigs.Keys) { $w = 0; if ($whole.ContainsKey($k)) { $w = $whole[$k] }; if ($script:RAProof.Sigs[$k] -gt $w) { $extra += ($script:RAProof.Sigs[$k] - $w) } }
    if ($missing -eq 0 -and $extra -eq 0) { return ('bucket proof: EQUAL -- the buckets returned the same {0} row(s) as the whole query' -f $n) }
    ('bucket proof: DIFFERENT -- the whole query returned {0} row(s); {1} of them were missing from the buckets, {2} bucket row(s) are not in it' -f $n, $missing, $extra)
}

function Test-RABucketRowCount {
    <#
        #641: one bucket's rows against the source's own count of the same query ('| count', the bucket's CL coordinates
        still set). @{ Short; Expected; Error } -- Short only when the count was had AND is larger than the rows; a count
        that could not be had is not a verdict (the report's whole count still is).
    #>
    param([Parameter(Mandatory)][string]$Query, [long]$Rows)
    try {
        $conv = Get-RABucketRows -Resp (Invoke-GraphHuntingQuery -Query ($Query.TrimEnd().TrimEnd(';') + "`n| count") -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries 1)
        if (-not $conv.Ok) { return @{ Short = $false; Expected = $null; Error = [string]$conv.Error } }
        $first = @($conv.Rows) | Select-Object -First 1
        $n = $null
        if ($null -ne $first) { foreach ($c in 'Count', 'count_', 'count') { $pp = $first.PSObject.Properties[$c]; if ($pp -and $null -ne $pp.Value) { $n = [long]$pp.Value; break } } } else { $n = 0L }
        if ($null -eq $n) { return @{ Short = $false; Expected = $null; Error = 'no Count column' } }
        @{ Short = ($n -gt $Rows); Expected = $n; Error = '' }
    } catch { @{ Short = $false; Expected = $null; Error = $_.Exception.Message } }
}

function Write-RAStreamBucketRows {
    <# One bucket's (or one staged page's) scored rows -> SQL, with which of them the workbook / mail view shows. #>
    param([AllowEmptyCollection()][object[]]$Shaped = @(), [string]$Bucket, [bool]$IsDetailedShape, [string[]]$DesiredColumns)
    Add-RAStreamColumns -Stream $script:RAStream -Columns @($DesiredColumns)
    $view = Select-RAReportRows -Rows @($Shaped) -IncludeExempted:([bool]$global:SI_Exempted_CountInManagement)
    $script:RAStreamExemptedNotCounted += [long]$view.Exempted
    $vr = @($view.Rows)
    if ($null -ne $script:RAExcelScope) { $vr = @((Select-SIOutputScopeRows -Rows $vr -Scope $script:RAExcelScope).Rows) }
    $set = New-Object 'System.Collections.Generic.HashSet[object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    foreach ($v in $vr) { if ($null -ne $v) { [void]$set.Add($v) } }
    $n = Write-RAStreamRows -Stream $script:RAStream -Rows @($Shaped) -Bucket $(if ($Bucket) { $Bucket } else { 'whole' }) -InView $set -IsDetailedShape $IsDetailedShape `
        -ConfigurationIdInputName $ConfigurationIdInputName -SortColumn 'RiskScoreTotal_Weighted' -FallbackSortColumn $(if ($RiskScoreOutputName) { $RiskScoreOutputName } else { 'RiskScoreTotal' }) `
        -Dedup (-not ([string]$ReportName -like '*_Summary*')) -Equivalence $script:RAEqIdx
    Write-Ok ("{0} row(s) written to the database (slice {1})" -f $n, $(if ($Bucket) { $Bucket } else { 'whole' }))
    [long]$n
}

function Add-RAStreamBucket {
    <#
        The query rows of ONE bucket of the current report, as they arrive. With the result in SQL: a Summary report's rows are
        staged (its groups are combined when every bucket is in); every other report's rows are scored and written now.
        Without: they join the report's rows in memory, as before. Returns nothing.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string]$Bucket, [switch]$Complete)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $script:RAStreamOn) { return }
    if ($Complete) { Clear-RAStreamReport -Stream $script:RAStream -Why 'one query slice returned the complete result'; Reset-RAProof }
    # #673 plan B: what this slice retrieved before the Defender filter and what the filter handed off (nothing when off)
    if (Get-Command -Name Add-RADfcAccount -ErrorAction SilentlyContinue) { Add-RADfcAccount -Bucket $Bucket }
    if ($rows.Count -eq 0) { return }
    if ($script:RAStream.Current.Staged) {
        $script:RAStream.Current.Retrieved += 0   # a Summary report is counted once its groups are combined
        $null = Add-RAStreamStage -Stream $script:RAStream -Rows $rows -Bucket $Bucket
    } else {
        $script:RAStream.Current.Retrieved += $rows.Count
        Add-RAProofRows -Rows $rows
        Invoke-RAReportRows -ResultAll $rows -RABucket $Bucket
    }
}

function Add-RAStreamBucketGuarded {
    <#
        Add-RAStreamBucket for ONE query slice, with the memory guard (live 2026-10-18, rc11, a small school's 4 GiB worker:
        Device_Missing_CVEs_Detailed failed "OutOfMemoryException" shaping a 32,757-row slice, three times in a row, and the
        report was lost each run): when processing the slice runs the process out of memory, what the slice stored is removed
        (Undo-RAStreamBucket), the memory is given back and $false is returned -- the caller asks the SAME rows again in
        smaller slices (the sub-bucket pass, lossless), and the finer count is kept for the next run as for a slice that was
        too large. The same method at every size: a slice is only ever made smaller, no row is dropped, no cap. Any other
        error is thrown as before. $true = the slice is in.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string]$Bucket, [switch]$Complete)
    $count = [long]@($Rows | Where-Object { $null -ne $_ }).Count
    try { Add-RAStreamBucket -Rows $Rows -Bucket $Bucket -Complete:$Complete; return $true }
    catch {
        $oom = $false
        if (Get-Command -Name Test-RAOutOfMemoryError -ErrorAction SilentlyContinue) { $oom = [bool](Test-RAOutOfMemoryError -Err $_) }
        else { $oom = [bool]("$($_.Exception.Message)" -match 'OutOfMemoryException') }
        if (-not $oom -or $Complete -or -not $script:RAStreamOn -or $count -le 1) { throw }
        $Rows = $null
        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
        $removed = [long](Undo-RAStreamBucket -Stream $script:RAStream -Bucket $Bucket -Retrieved $count)
        # the bucket proof (on demand) cannot prove a report whose slice was taken back: it says so instead of mis-counting
        if ($null -ne $script:RAProof -and $script:RAProof.On) { $script:RAProof.Over = $true; $script:RAProof.Sigs.Clear() }
        Write-Warn2 ("query slice {0}: not enough memory to process its {1:N0} row(s) at once -- nothing of it is kept ({2:N0} stored row(s) removed); the same rows are asked again in smaller slices" -f $Bucket, $count, $removed)
        return $false
    }
}

function Get-RAReportExpectedRows {
    <#
        #641: what the SOURCE says the report holds -- the report's query, unbucketed, counted ('| count'). A count is a
        single row, so it fits where the rows do not; the query itself may still be too large to run whole (then the count
        is not had and the report is 'Unverified', said). SI_RA_CompletenessCheck = off switches it off. @{ Count; Error }.
    #>
    # -BucketCount: the slices the report's rows were asked in ($script:RACountBuckets) -- the count is asked in the SAME
    # slices, each with its own bucket filter and its own per-slice lookup cut (Invoke-GraphHuntingQuery reads the slice
    # from _CurrentBucketCount/_Index), never as one unbucketed query that carries every lookup whole (live 2026-10-13:
    # "413 Request Entity Too Large"). -RowColumns: the columns the report's rows carry -- a Summary report is counted in
    # distinct groups only when the merge can group them (every group column on the rows).
    # -Retrieved: what the report's slices returned. When the whole count cannot be sent, the slices' rows ARE the count:
    # every slice that answered was below the row limit (an answer AT the limit is refused and the slice made smaller,
    # Invoke-GraphHuntingQuery), and a count asked in the same slices sees exactly what they saw -- asking it again doubled
    # every heavy report (live 2026-10-14: 29 slices counted and then fetched, 10-23 minutes per attack-path report).
    # -ExtraGroupKeys (#673 plan B): a Summary report whose groups were asked split by the Defender keys and the asset is
    # counted in those split groups (what its slices returned before the Defender filter)
    # -LostSlices (#741 (3)): slices of the report that could not be read -- then the slices' rows are NOT the count (a
    # slice that did not answer is not "below the row limit")
    # -WholeOnly (count timing, live 2026-10-26): only the query whole is counted -- the count taken right before the report's
    # first query slice and right after its last (Invoke-RAReadCount). Its fallbacks need what the read returned, so they
    # run at the verdict as before. -Whole: the whole count already asked right after the read (its answer or its error) --
    # not asked again; the fallbacks below run on it exactly as on a whole count asked here.
    param([Parameter(Mandatory)][string]$Query, [string]$ReportName, [int]$BucketCount = 1, [string[]]$RowColumns = @(), $Retrieved = $null, [string[]]$ExtraGroupKeys = @(), [int]$LostSlices = 0,
          [switch]$WholeOnly, $Whole = $null)
    $sw = ([string]$global:SI_RA_CompletenessCheck).Trim().ToLowerInvariant()
    if ($sw -in 'off', 'false', '0', 'no') { return @{ Count = $null; Error = 'the completeness check is switched off (SI_RA_CompletenessCheck)' } }
    $hasBlock = Test-QueryHasBucketFilterBlock -Query $Query
    $n = $(if ($hasBlock -and $BucketCount -gt 1) { $BucketCount } else { 1 })
    $keys = @()
    if ($n -gt 1 -and [string]$ReportName -like '*_Summary*') {
        $plan = $null; try { $plan = Get-RASummaryMergePlan -Query $Query } catch { $plan = $null }
        if ($plan -and @($plan.Keys).Count -gt 0 -and @($plan.Keys | Where-Object { @($RowColumns) -notcontains $_ }).Count -eq 0) { $keys = @($plan.Keys) }
        if ($keys.Count -gt 0 -and @($ExtraGroupKeys | Where-Object { $_ }).Count -gt 0) { $keys = @($keys) + @($ExtraGroupKeys | Where-Object { $_ }) }
    }
    # FIRST the query whole: only the whole query sees a row a slice's own lookup cut or filter leaves out (live
    # 2026-10-13: Device_Missing_CVEs_Detailed, 20,878 at the source, 16,943 from the slices -- each slice matched its own
    # count). Only when the whole count cannot be sent (413) is it asked slice by slice, said in the verdict -- a count per
    # slice cannot see a row that no slice returns.
    $slice = {
        param($i)
        $q = $Query
        if ($hasBlock) { $q = Replace-BucketFilterBlock -Query $q -BucketFilterKql (New-BucketFilterKql -BucketCount $script:__cntN -BucketIndex $i -ReportName $ReportName) }
        if ($script:__cntN -gt 1) { $script:_CurrentBucketCount = $script:__cntN; $script:_CurrentBucketIndex = $i } else { $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0 }
        Get-RABucketRows -Resp (Invoke-GraphHuntingQuery -Query (Get-RAReportCountKql -Query $q -GroupKeys $script:__cntKeys) -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries 1)
    }
    try {
        $script:__cntN = 1; $script:__cntKeys = @()
        $whole = $(if ($null -ne $Whole) { $Whole } else { Measure-RAReportExpectedRows -BucketCount 1 -RunSlice $slice })
        if ($null -ne $whole.Count) { return @{ Count = $whole.Count; Error = [string]$whole.Error; How = 'whole' } }
        if ($WholeOnly) { return @{ Count = $null; Error = [string]$whole.Error; How = 'whole' } }
        # The whole count could not be sent (413 at a report run in ONE slice since the bucket learning lets a report come
        # down to 1 -- live 2026-10-21: three attack-path reports "Unverified" with every row retrieved). The rule is the same
        # at one slice as at many: every slice that answered was below the row limit (an answer AT it is refused and the slice
        # made smaller), so when no slice was lost the slices' rows ARE the count. A slice made smaller (the sub-bucket pass)
        # is part of its slice.
        if ($null -ne $Retrieved -and -not $script:RALakeAnswered -and $LostSlices -le 0) {
            $__howN = if ($n -gt 1) { ('every one of the report''s {0} slices answered below the row limit' -f $n) } else { 'the report''s one query slice answered whole and below the row limit' }
            return @{ Count = [long]$Retrieved; Error = ''; How = ('{0}, so the source holds what they returned (the whole count could not be sent: {1})' -f $__howN, $whole.Error) }
        }
        # The whole count was refused for its SIZE (413) and the slices' rows cannot stand for it: the count is asked IN PARTS,
        # the way the read is split -- each part with its own slice filter and its own cut of the inlined lookups -- and in
        # twice as many parts while a part is still refused and the split still makes the request smaller (the read's own
        # rule, Test-RASplitCanStillFit; and the request must shrink from one split to the next -- measured, no fixed
        # depth). The parts' counts add up to the count (live 2026-10-21: an attack-path report "Unverified" at the largest
        # tenant, "could not count the report's rows in one query (413 Request Entity Too Large)").
        if ($hasBlock -and (Test-RACountRefusedForSize -Message ([string]$whole.Error))) {
            $__cpKeys = $keys
            if ($__cpKeys.Count -eq 0 -and [string]$ReportName -like '*_Summary*') {
                $plan = $null; try { $plan = Get-RASummaryMergePlan -Query $Query } catch { $plan = $null }
                if ($plan -and @($plan.Keys).Count -gt 0 -and @($plan.Keys | Where-Object { @($RowColumns) -notcontains $_ }).Count -eq 0) { $__cpKeys = @($plan.Keys) }
                if ($__cpKeys.Count -gt 0 -and @($ExtraGroupKeys | Where-Object { $_ }).Count -gt 0) { $__cpKeys = @($__cpKeys) + @($ExtraGroupKeys | Where-Object { $_ }) }
            }
            # a Summary report whose groups cannot be counted across parts is not counted in parts (a group spanning parts would count twice)
            if ($__cpKeys.Count -gt 0 -or [string]$ReportName -notlike '*_Summary*') {
                $__cpLast = @{ Inline = [long]::MaxValue }
                $__cpFiner = {
                    param($Err, $Parts)
                    $inl = [long]$script:_LastHybridInlineBytes
                    if ($inl -ge $__cpLast.Inline) { return $false }   # the split no longer makes the request smaller
                    $__cpLast.Inline = $inl
                    [bool](Test-RASplitCanStillFit -Err $Err -InlineBytes $inl -OverheadBytes ([long]$script:_LastHybridQueryBodyOverheadBytes))
                }
                $__cpSlice = { param($i, $parts) $script:__cntN = $parts; & $slice $i }
                $script:__cntKeys = $__cpKeys
                $inParts = Measure-RAReportExpectedRowsInParts -Start ([Math]::Max(2, $n)) -RunSlice $__cpSlice -GroupKeys $__cpKeys -CanSplitFiner $__cpFiner
                if ($null -ne $inParts.Count) {
                    return @{ Count = [long]$inParts.Count; Error = ''; How = ('counted in {0} parts, the way the report''s read is split (the whole count could not be sent: {1})' -f $inParts.Parts, $whole.Error) }
                }
                $__na = ('count not available ({0}); counted in {1} parts: {2}' -f $whole.Error, $inParts.Parts, $inParts.Error)
                if ($LostSlices -gt 0) { $__na = ('the whole count could not be sent ({0}); in {1} parts: {2}' -f $whole.Error, $inParts.Parts, $inParts.Error) }
                return @{ Count = $null; Error = $__na; How = 'parts' }
            }
        }
        if ($n -le 1) {
            # one slice: a count per slice is the same request -- the count is not available; said, never a failure
            $__na = [string]$whole.Error
            if ($LostSlices -le 0) { $__na = ('count not available ({0}); every slice of the report was read whole' -f $whole.Error) }
            return @{ Count = $null; Error = $__na; How = 'whole' }
        }
        $script:__cntN = $n; $script:__cntKeys = $keys
        $per = Measure-RAReportExpectedRows -BucketCount $n -GroupKeys $keys -RunSlice $slice
        if ($null -eq $per.Count) { return @{ Count = $null; Error = ('the whole count could not be sent ({0}); per slice: {1}' -f $whole.Error, $per.Error); How = 'slices' } }
        return @{ Count = $per.Count; Error = ''; How = ('counted in the report''s {0} slices (the whole count could not be sent: {1})' -f $n, $whole.Error) }
    } catch { return @{ Count = $null; Error = $_.Exception.Message; How = '' } }
    finally { $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0 }
}

# ---------------------------------------------------------------------------------------------------------------------
# COUNT TIMING (live 2026-10-26, a false NOT COMPLETE). A report's two slices were read at 09:23Z; the scoring and a slow
# insert (715 s) ran; only at 09:40Z was the source counted -- the live Defender data had moved (20,547 counted, 20,475
# read) and the run's publish was refused. The source is now counted right next to the read: once just BEFORE the
# report's first query slice (C1) and once just AFTER its last (C2), before that slice is scored and written. Both are
# the report's query whole ('| count', Get-RAReportExpectedRows -WholeOnly); the verdict is Get-RAReadCountVerdict.
# ---------------------------------------------------------------------------------------------------------------------
function Reset-RAReadCounts {
    <# The report's two counts of the source are not taken yet (a report's start, and each run of its slices again). #>
    $script:RAReadCounts = @{ Before = $null; After = $null }
}

function Invoke-RAReadCount {
    <#
        Counts the source for the report right next to its read: -When Before (C1, just before its first query slice) or
        After (C2, just after its last). @{ Count; Error; How; At } in $script:RAReadCounts. Its seconds are the report's
        'count' phase. Never throws; every engine variable a hunting request touches is put back (the slices are asked
        exactly as without it -- the slice coordinates, the request measures, the cross-domain flags, the key answers).
    #>
    param([Parameter(Mandatory)][ValidateSet('Before', 'After')][string]$When, [Parameter(Mandatory)][string]$Query, [string]$ReportName)
    if ($null -eq $script:RAReadCounts) { Reset-RAReadCounts }
    $s01 = $script:_CurrentBucketCount; $s02 = $script:_CurrentBucketIndex; $s03 = $script:_LastHybridInlineBytes
    $s04 = $script:_LastHybridQueryBodyOverheadBytes; $s05 = $script:_LastHybridSnapshotRowCount; $s06 = $script:_LastHybridBytesPerRow
    $s07 = $script:_RAHybridLastRequest; $s08 = $script:_RAHybridLookups; $s09 = $script:_RALookupNeededKeySets
    $s10 = $script:_RALookupKeyQueryBuilding; $s11 = $script:_LastGraphHuntingAllTimedOut; $s12 = $script:RADfcLast
    $s13 = $script:_SkipEGBucketForCrossDomain; $s14 = $script:_RACrossDomainReplicated; $s15 = $script:_SupersededAttempts
    $s16 = $script:_RALookupKeyAnswerMemo; $s17 = $script:RALakeAnswered
    $reduction = if ($script:_RALookupReductionOn -is [hashtable]) { $script:_RALookupReductionOn.Clone() } else { $script:_RALookupReductionOn }
    $at = [datetime]::UtcNow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = $null
    try { $r = Get-RAReportExpectedRows -Query $Query -ReportName $ReportName -BucketCount 1 -WholeOnly }
    catch { $r = @{ Count = $null; Error = [string]$_.Exception.Message; How = 'whole' } }
    finally {
        $script:_CurrentBucketCount = $s01; $script:_CurrentBucketIndex = $s02; $script:_LastHybridInlineBytes = $s03
        $script:_LastHybridQueryBodyOverheadBytes = $s04; $script:_LastHybridSnapshotRowCount = $s05; $script:_LastHybridBytesPerRow = $s06
        $script:_RAHybridLastRequest = $s07; $script:_RAHybridLookups = $s08; $script:_RALookupNeededKeySets = $s09
        $script:_RALookupKeyQueryBuilding = $s10; $script:_LastGraphHuntingAllTimedOut = $s11; $script:RADfcLast = $s12
        $script:_SkipEGBucketForCrossDomain = $s13; $script:_RACrossDomainReplicated = $s14; $script:_SupersededAttempts = $s15
        $script:_RALookupKeyAnswerMemo = $s16; $script:RALakeAnswered = $s17
        $script:_RALookupReductionOn = $reduction
    }
    $sw.Stop()
    if ($null -eq $r) { $r = @{ Count = $null; Error = 'no answer'; How = 'whole' } }
    $script:RAReadCounts[$When] = @{ Count = $r.Count; Error = [string]$r.Error; How = 'whole'; At = $at }
    if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'count' -Seconds $sw.Elapsed.TotalSeconds }
    $__w = $(if ($When -eq 'Before') { 'just before the read' } else { 'just after the read' })
    if ($null -ne $r.Count) { Write-Info ("completeness: the source's count {0}: {1} row(s) ({2:N1} s)" -f $__w, [long]$r.Count, $sw.Elapsed.TotalSeconds) }
    else { Write-Info ("completeness: the source's count {0} is not available ({1})" -f $__w, [string]$r.Error) }
}

function Complete-RAReportCompleteness {
    <#
        #641: the report's verdict for this run -- what the source said against what the buckets returned. NotComplete is a
        failed report (the run ends partial: nothing downstream closes on it, the report is named in the run record); the
        verdict is stored per report when the result is in SQL. Unverified is said, never a failure.
    #>
    param([Parameter(Mandatory)][string]$Query, [long]$Retrieved, $Stored = $null, [string[]]$RowColumns = @(), [long]$CrossSliceDuplicates = 0)
    # #673 plan B: the source is asked the query WITHOUT the Defender anti-joins, so it is compared with what the slices
    # retrieved BEFORE the Defender filter; the rows the filter removed are a named category ("handed to the Defender
    # recommendation report"). A Summary report's groups were asked split by the keys and the asset -- counted that way.
    $__dfcTot = $null; $__dfcOn = $false
    if ($script:RAStreamOn -and $null -ne $script:RAStream -and $null -ne $script:RAStream.Current) {
        $__dfcOn = Test-RADfcAccountActive -Account $script:RAStream.Current.Account
        if ($__dfcOn) { $__dfcTot = Get-RAStreamAccountTotal -Account $script:RAStream.Current.Account }
    }
    $__srcRetrieved = $Retrieved
    $__extraKeys = @()
    if ($__dfcOn) {
        $__srcRetrieved = [long]$__dfcTot.Pre
        if ([string]$ReportName -like '*_Summary*') { $__extraKeys = @('_dfcKey', '_dfcIdKey', '_dfcAkKey', '_dfcPart') }
    }
    # #741 (3): a slice of the report that could not be read makes it NOT complete here, at its own verdict -- the source is
    # not asked and the slices' rows are not taken as its count (they are not: a slice did not answer)
    $__lostV = Get-RALostSliceVerdict -Lost @($script:_RABucketLoss)
    $__c1Count = $null
    if ($__lostV) {
        $exp = @{ Count = $null; Error = [string]$__lostV.Reason; How = '' }
        $v = @{ State = 'NotComplete'; Reason = [string]$__lostV.Reason }
    } else {
        # COUNT TIMING: the source was counted right next to the read -- C1 just before its first slice, C2 just after its
        # last (Invoke-RAReadCount). C2's whole count is the report's count; when it could not be sent whole (or was not
        # taken), the count is had here as before -- its fallbacks on what the slices returned, the whole query not asked
        # again when C2 already asked it. A report with no count taken next to its read is counted here, as before.
        $__c1 = $null; $__c2 = $null
        if ($script:RAReadCounts -is [System.Collections.IDictionary]) { $__c1 = $script:RAReadCounts['Before']; $__c2 = $script:RAReadCounts['After'] }
        if ($null -ne $__c1) { $__c1Count = $__c1['Count'] }
        $__c2At = $(if ($null -ne $__c2) { $__c2['At'] } else { $null })
        if ($null -ne $__c2 -and $null -ne $__c2['Count']) { $exp = @{ Count = $__c2['Count']; Error = ''; How = 'whole' } }
        else {
            $exp = Get-RAReportExpectedRows -Query $Query -ReportName $ReportName -BucketCount ([int]$script:RACountBuckets) -RowColumns $RowColumns -Retrieved $__srcRetrieved -ExtraGroupKeys $__extraKeys -LostSlices @($script:_RABucketLoss | Where-Object { $_ }).Count -Whole $__c2
            $__c2At = [datetime]::UtcNow
        }
        $v = Get-RAReadCountVerdict -Before $__c1Count -After $exp.Count -Retrieved $__srcRetrieved -CountError ([string]$exp.Error) -BeforeUtc $(if ($null -ne $__c1) { $__c1['At'] } else { $null }) -AfterUtc $__c2At
    }
    if ($exp.How -and $exp.How -ne 'whole' -and $null -ne $exp.Count) { $v.Reason = (@([string]$v.Reason, [string]$exp.How) | Where-Object { $_ }) -join ' | ' }
    # #734: the expected count the report is SHOWN with (sidata.RaReportStatus.ExpectedRows, the report note's SourceCount ->
    # mails, heartbeat, run reports page) is the count AFTER the Defender de-duplication -- the source was asked without it,
    # so its count still holds the rows handed to the Defender recommendation report. The verdict above keeps comparing the
    # source's count with what the slices retrieved before the filter (like with like); the handed count is said, not hidden.
    # COUNT TIMING: the count shown is the one nearest the read -- C2 (just after it) when it was had, else C1
    $__expBase = $(if ($null -ne $exp.Count) { $exp.Count } else { $__c1Count })
    $__expShown = $__expBase
    if ($__dfcOn) {
        $__expShown = Get-RADfcReportedExpected -Expected $__expBase -Pre ([long]$__dfcTot.Pre) -Handed ([long]$__dfcTot.Handed) -Retrieved $Retrieved -Summary:([string]$ReportName -like '*_Summary*')
        $__ht = Get-RADfcHandedText -Total $__dfcTot
        $__dfcWhy = 'the Defender de-duplication ran in the engine: {0} row(s) retrieved before it' -f [long]$__dfcTot.Pre
        if ($null -ne $__expBase) { $__dfcWhy += (', the source''s count before it {0}, after it {1}' -f [long]$__expBase, [long]$__expShown) }
        if ($__ht) { $__dfcWhy += ', ' + $__ht }
        $v.Reason = (@([string]$v.Reason, $__dfcWhy) | Where-Object { $_ }) -join ' | '
    }
    # #641 item 4: retrieved is not stored -- what the run stored must be what it retrieved less what is NAMED (scope,
    # exclusion rules, duplicates); anything else is rows lost between the source and the database
    if ($script:RAStreamOn -and $null -ne $Stored -and $v.State -ne 'NotComplete') {
        # a Detailed report under plan B: retrieved before the filter, the filtered rows named; a Summary report's filter
        # ran before its groups were combined, so its stored rows are checked against the combined groups as before
        $__svRetrieved = $Retrieved; $__svHanded = 0L
        if ($__dfcOn -and [string]$ReportName -notlike '*_Summary*') { $__svRetrieved = [long]$__dfcTot.Pre; $__svHanded = [long]$__dfcTot.Handed }
        $sv = Get-RAStoredVerdict -Retrieved $__svRetrieved -Stored ([long]$Stored) -Total (Get-RAStreamAccountTotal -Account $script:RAStream.Current.Account) -CrossSliceDuplicates $CrossSliceDuplicates -Handed $__svHanded
        if ($sv.State -eq 'NotComplete') { $v = @{ State = 'NotComplete'; Reason = (@([string]$sv.Reason, [string]$v.Reason) | Where-Object { $_ }) -join ' | ' } }
        elseif ($sv.Reason) { $v.Reason = (@([string]$v.Reason, [string]$sv.Reason) | Where-Object { $_ }) -join ' | ' }
    }
    $proof = Get-RAProofVerdict -Query $Query
    if ($proof) {
        if ($proof -match 'DIFFERENT') { Write-Err2 ("{0}: {1}" -f $ReportName, $proof) } else { Write-Info $proof }
        $v.Reason = (@([string]$v.Reason, $proof) | Where-Object { $_ }) -join ' | '
    }
    switch ($v.State) {
        'Complete'    { Write-Info ("completeness: the source holds {0} row(s) for this report, the run retrieved {0}" -f $Retrieved) }
        'Unverified'  { Write-Warn2 ("completeness: not verified for this report -- {0}" -f $v.Reason) }
        'NotComplete' {
            Write-Err2 ("completeness: report '{0}' is NOT COMPLETE in this run -- {1}. The missing findings are unknown, not resolved." -f $ReportName, $v.Reason)
            Add-RAReportFailure -ReportName $ReportName -Reason ("not complete: {0}" -f $v.Reason)
        }
    }
    $script:RAReportStatusDone[[string]$ReportName] = $v.State
    $__naWhy = if ($Retrieved -eq 0 -and "$($script:RANotApplicableWhy)".Trim()) { [string]$script:RANotApplicableWhy } else { '' }
    Set-RAReportNote -ReportName ([string]$ReportName) -Values @{ EndedUtc = [datetime]::UtcNow; State = $(if ($__naWhy -and $v.State -ne 'NotComplete') { 'NotApplicable' } else { [string]$v.State }); Why = $(if ($__naWhy -and $v.State -ne 'NotComplete') { $__naWhy } else { [string]$v.Reason }); Rows = $Retrieved
                                                               SourceCount = $__expShown; Handed = $(if ($__dfcOn) { [long]$__dfcTot.Handed } else { $null }); Buckets = [int]$script:RACountBuckets; QueryHash = [string]$script:RAReportQueryHash[[string]$ReportName] }
    # #674: this report received findings from a report whose hand-off list read empty when it ran -- if THIS report found
    # rows, that report listed them too, so it is not complete (the end of the run stores its verdict as NotComplete)
    # (#742: on queue workers the giver and the receiver may run in different processes -- the producer decides this over
    # the whole run, in the same order: Get-RAScaleOutHandoffContradictions)
    if ($script:RAScaleRole -ne 'worker' -and $script:_RAHandoffEmptyGivers -and $script:_RAHandoffEmptyGivers.Count -gt 0) {
        foreach ($__hc in @(Get-RAHandoffContradiction -ReportName ([string]$ReportName) -Retrieved $Retrieved -EmptyGivers $script:_RAHandoffEmptyGivers)) {
            Write-Err2 ("completeness: report '{0}' is NOT COMPLETE in this run -- {1}" -f $__hc.Report, $__hc.Why)
            Add-RAReportFailure -ReportName $__hc.Report -Reason ("not complete: {0}" -f $__hc.Why)
            $script:_RAHandoffEmptyGivers.Remove($__hc.Report)
        }
    }
    if ($script:RAStreamOn) {
        try { Set-RAStreamReportStatus -Stream $script:RAStream -ReportName $ReportName -Expected $__expShown -Retrieved $Retrieved -Stored $Stored -State $v.State -Reason $v.Reason -QueryHash ([string]$script:RAReportQueryHash[[string]$ReportName]) -QueryHashCarry ([string]$script:RAReportQueryHashCarry[[string]$ReportName]) }
        catch { Write-Warn2 ("completeness: the verdict could not be stored -- {0}" -f $_.Exception.Message) }
    }
}

function Complete-RAReportInStream {
    <#
        The report's buckets are all in SQL. A Summary report's staged rows are combined group by group (the same rules as
        before) a page of whole groups at a time, scored and written; then the findings two slices both returned are kept
        once, the trace names two assets share get the asset id, the report is counted and checked against the source.
    #>
    param([Parameter(Mandatory)][string]$Query)
    $cur = $script:RAStream.Current
    if ($cur.Staged) {
        $script:__raMerged = 0L
        $null = Invoke-RAStreamStagePages -Stream $script:RAStream -OnPage {
            param($pageRows, $pageNo)
            $rowsP = @($pageRows)
            if ($rowsP.Count -gt 1) {
                $m = Merge-RASummaryBucketRows -Rows $rowsP -Query $Query
                if ($m.Applied -and $m.Merged -gt 0) { $rowsP = @($m.Rows); Write-Info ("combined {0} partial row(s) from different asset slices into their group -- {1} row(s), every asset kept" -f $m.Merged, $rowsP.Count) }
                if ($m.Applied -and [int]$m.Refused -gt 0) { Write-Info ("{0} group(s) kept as separate rows per asset slice -- a column could not be combined safely, so nothing was dropped" -f $m.Refused) }
            }
            $script:__raMerged += $rowsP.Count
            Add-RAProofRows -Rows $rowsP
            Invoke-RAReportRows -ResultAll $rowsP -RABucket ('page:{0}' -f $pageNo)
        }
        $cur.Retrieved = [long]$script:__raMerged
    }
    $fin = Complete-RAStreamReport -Stream $script:RAStream
    Write-Info ("this report: {0} row(s) retrieved from the source, {1} stored" -f $cur.Retrieved, $fin.Stored)
    Write-Info (Format-RAPhaseLine -Times $cur.Times -What ("report '{0}'{1}" -f $cur.Name, $(if ($script:RAScaleSplit) { ' (the part put together here, and its own slices)' } else { '' })))   # #873 A
    Write-RAPhaseTimesToSql -Stream $script:RAStream -Times $cur.Times -What $(if ($script:RAScaleSplit) { 'report {0} part {1} of {2} (put together here)' -f $cur.Name, ([int]$script:RAScaleSplit.Part + 1), $script:RAScaleSplit.Parts } else { 'report {0}' -f $cur.Name })
    if ($null -ne $global:RA_RowCountsThisRun -and [int]$global:RA_RowCountsThisRun[[string]$ReportName] -eq 0) { Write-RAZeroRowWarning -ReportName ([string]$ReportName) }
    Complete-RAReportCompleteness -Query $Query -Retrieved $cur.Retrieved -Stored $fin.Stored -CrossSliceDuplicates ([long]$fin.Duplicates) -RowColumns $(if ($cur.StageCols) { [string[]]$cur.StageCols.ToArray() } else { [string[]]@() })
}

# #638: the result goes to the Pro database a query slice at a time when the database is configured (SI_ProSqlServer /
# SI_ProSqlDatabase) and carries the tables (the updater's step). Otherwise -- or in a dry run -- the result is kept in
# memory as before, and that is said.
$script:RAStreamWanted = $false
if (Test-RAStreamWanted) {
    if ($script:SIWhatIf) { Write-Info 'dry run: the result is not written to the database' }
    else {
        # #882: this run has a database -- a result that cannot go there and reaches no other store ends the run failed
        # (Get-RARunEndVerdict: "nothing of this run could be stored")
        $script:RAStreamWanted = $true
        try {
            $__raG = @{}; foreach ($__n in 'SI_ProSqlServer', 'SI_ProSqlDatabase', 'SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase') { $__raG[$__n] = Get-Variable -Name $__n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
            $__raSet = Resolve-SIDataSettings -Globals $__raG
            $__raInv = New-SIDataSqlInvoke -Server $__raSet.Server -Database $__raSet.Database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
            $__raGrain = if ([bool]$global:Detailed) { 'Detailed' } else { 'Summary' }
            # #742: a queue worker JOINS the collection its producer began (never begins one of its own)
            $__raAttach = 0; if ($script:RAScaleRole -eq 'worker' -and $null -ne $script:RAScaleManifest) { $__raAttach = [int]$script:RAScaleManifest['CollectionId'] }
            $script:RAStream = New-RAStream -Invoke $__raInv -Grain $__raGrain -CollectionTime ([datetime]$global:RA_CollectionTime) -RunId ([string]$script:_RunHealthCtx.RunId) `
                -SolutionVersion ([string]$global:RA_SolutionVersion) -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } } -AttachCollectionId $__raAttach
            if ($__raAttach -gt 0 -and [string]$script:RAStream.TimeText -ne [string]$script:RAScaleManifest['TimeText']) { throw ("the run's collection time is {0} here and {1} in its manifest" -f $script:RAStream.TimeText, $script:RAScaleManifest['TimeText']) }
            $script:RAStreamOn = $true
            try {
                if (-not (Get-Command -Name Get-SIRecommendationEquivalence -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', 'data-model', 'SI-RecommendationEquivalence.ps1')) }
                $script:RAEqIdx = Get-SIRecommendationEquivalence
            } catch { $script:RAEqIdx = $null }
            $script:RAExcelScope = Get-SIOutputScope -Destination 'excel'
            # where THIS run builds the CIs (Community), they are built once now -- into the database the buckets read them from
            # (#742: by the producer, before it queues the reports -- never again by a worker)
            try {
                if ($script:RAScaleRole -ne 'worker' -and (Test-RACiBuildHere)) {
                    if (-not (Get-Command -Name Invoke-SICiBuild -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-CiBuildRun.ps1')) }
                    $null = Invoke-SICiBuild -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-Host $m } }
                }
            } catch { Write-Warn2 ("CI context: the CIs could not be built in this run ({0}) -- the stored ones are used" -f $_.Exception.Message) }
            Write-Info ("the result goes to the database a query slice at a time ({0} collection of {1} UTC) -- nothing of it is gathered in memory" -f $__raGrain, $script:RAStream.TimeText)
        } catch {
            $script:RAStreamOn = $false; $script:RAStream = $null
            $script:RAScaleAttachError = [string]$_.Exception.Message
            Write-Warn2 ("the result is kept in memory as before -- it cannot go to the database: {0}" -f $_.Exception.Message)
        }
    }
}

# #772 THE RELEASE DATES OF MICROSOFT'S UPDATES, for the patch cycle (owner 2026-10-19: "yes, read the fix release date from
# defender" -- Defender names the update and its KB, never when it was released): once per run from the install's cache
# (Pro: sidata.KbReleaseDate; Community: a file), the public Security Update Guide read at most once a day
# (engine\data-model\SI-KbReleaseDates.ps1). Off (SI_PatchCycle_MsrcDates) or no network: one line, the update names' month.
try {
    if (-not (Get-Command -Name Initialize-SIKbReleaseDates -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', 'data-model', 'SI-KbReleaseDates.ps1')) }
    $__kbStore = $null
    if ($script:RAStreamOn -and $null -ne $script:RAStream) { $__kbStore = New-SIKbDateSqlStore -Invoke $script:RAStream.Invoke }
    else { $__kbPath = ''; if ($global:SettingsPath) { $__kbPath = [System.IO.Path]::Combine([string]$global:SettingsPath, 'OUTPUT', 'msrc-kb-release-dates.json') }; $__kbStore = New-SIKbDateFileStore -Path $__kbPath }
    $null = Initialize-SIKbReleaseDates -Store $__kbStore -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } }
} catch { Write-Info ('patch cycle: the Microsoft update release dates are not used this run ({0}) -- the update names'' month is used' -f $_.Exception.Message) }

# #902 (5) A SOURCE THAT IS EMPTY FOR GOOD: the acceptances an Admin made per report (cfg.RaSourceAccept), read ONCE before the
# reports run -- the producer and a queue worker alike, so every report's fingerprint carries its acceptance (its findings
# then close as 'report changed', never as fixed) and the end of the run does not hold it for an accepted table. A database
# that cannot be read: no acceptance applies (the reports are held as before -- the safe direction).
$script:RASourceAcceptRows = @(); $script:RASourceAccepted = @{}
if ($global:SI_ProSettingsStore -and $global:SI_ProSettingsStore.Invoke) {
    try {
        $script:RASourceAcceptRows = @(& $global:SI_ProSettingsStore.Invoke (Get-RASourceAcceptSql 'Active') @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        $script:RASourceAccepted = ConvertTo-RASourceAcceptMap -Rows $script:RASourceAcceptRows
        foreach ($__l in @(Get-RASourceAcceptLines -Accepted $script:RASourceAccepted)) { Write-Info $__l }
    } catch {
        $script:RASourceAcceptRows = @(); $script:RASourceAccepted = @{}
        Write-Warn2 ("source acceptance: the acceptances could not be read this run ({0}) -- none applies, a report reading a silent source is held as usual" -f $_.Exception.Message)
    }
}

# #900 A SOURCE THAT WENT SILENT HOLDS THE REPORTS THAT READ IT (owner 2026-10-25): every source table the reports of this run
# read is counted ONCE, before the reports run -- one `summarize count()` per route (advanced hunting, Log Analytics), timed,
# with a phase row. The end of the run judges the counts (Invoke-RASilentSourceCheck). The producer only (a queue worker
# joins its producer's run); with the result in the database only. Never fails the run: a count that cannot be had is said,
# and the fallback judges its reports.
$script:RASourceMap = $null; $script:RASourceCounts = $null
if ($script:RAStreamOn -and $script:RAScaleRole -ne 'worker') {
    try {
        $script:RASourceMap = Get-RASourceTableMap -Reports @($global:Exposure_Reports) -Names @($global:RA_TemplateReportNames)
        if (@($script:RASourceMap.Routes.Keys).Count) {
            $__ssRun = {
                param($Route, $Kql)
                if ($Route -eq 'loganalytics') {
                    $__ssWs = [string]$global:SI_DefenderWorkspaceResourceId
                    if ([string]::IsNullOrWhiteSpace($__ssWs)) { $__ssWs = [string]$global:SI_RiskAnalysis_WorkspaceResourceId }
                    if ([string]::IsNullOrWhiteSpace($__ssWs)) { $__ssWs = [string]$global:SI_WorkspaceResourceId }
                    if ([string]::IsNullOrWhiteSpace($__ssWs)) { $__ssWs = [string]$global:WorkspaceResourceId }
                    if ([string]::IsNullOrWhiteSpace($__ssWs)) { throw 'no Log Analytics workspace is configured' }
                    $__ssRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $__ssWs -Query $Kql -TimeoutSec 300   # plain assignment: the function comma-protects its rows
                    return , @($__ssRows)
                }
                $__ssB = Get-RABucketRows -Resp (Invoke-GraphHuntingQuery -Query $Kql -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries 1)
                if (-not $__ssB.Ok) { throw ([string]$__ssB.Error) }
                , @($__ssB.Rows)
            }
            $__ssPhase = {
                param($Name, $Seconds, $Rows)
                Write-Info ('[phases] {0}: {1} s ({2} table(s))' -f $Name, ([double]$Seconds).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture), $(if ($Rows -ge 0) { $Rows } else { 'none counted' }))
                Write-RAStepPhaseRow -Stream $script:RAStream -Phase $Name -Seconds ([double]$Seconds) -Rows ([long]$Rows)
            }
            $script:RASourceCounts = Invoke-RASourceCounts -Routes $script:RASourceMap.Routes -RunQuery $__ssRun -Phase $__ssPhase -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } }
            Write-Info (Format-RASourceCountLine -Counts $script:RASourceCounts)
        }
    } catch {
        # the counts are not had: with the map known, every route is FAILED -- the fallback judges the reports (never "no source went silent")
        $__ssWhy = [string]$_.Exception.Message
        $script:RASourceCounts = $null
        if ($null -ne $script:RASourceMap) {
            $script:RASourceCounts = [pscustomobject]@{ Counts = @{}; Failed = @{}; Seconds = @{}; Routes = $script:RASourceMap.Routes; Queries = 0; At = [datetime]::UtcNow }
            foreach ($__ssR in @($script:RASourceMap.Routes.Values | Sort-Object -Unique)) { $script:RASourceCounts.Failed[[string]$__ssR] = $__ssWhy }
        }
        Write-Warn2 ("source count: the source tables could not be counted this run ({0}) -- the reports reading them are held only when their own source count went from rows to none" -f $__ssWhy)
    }
}

# =====================================================================================================================
#   * the PRODUCER (this job with SI_RA_ScaleOut on): plans one work item per report, queues them, waits for them and takes
#     the workers' hand-overs in; its report loop then runs NO report, and the end of the run goes on exactly as before --
#     the guards, the cross-report steps, the Log Analytics post (the whole run ONCE, from SQL, as the single job posts it),
#     the verdicts-final marker, the completion, the mail;
#   * a WORKER (SI_RA_ScaleOutRole = worker): its report loop runs the report of each item it takes from the queue, one item
#     per pass; after each it writes the hand-over and the marker (never a Log Analytics post: a worker that dies mid-report
#     and the retry of its report then cannot leave a row in Log Analytics twice), and it stops after the loop.
# =====================================================================================================================
function Get-RAScaleOutEngineState {
    <# The run's live collections the report loop fills -- what a hand-over is taken from and merged into. #>
    if ($null -eq $script:_RAHandoffEmptyGivers) { $script:_RAHandoffEmptyGivers = @{} }
    if ($null -eq $global:SI_UplinkRetryAnswers -or $global:SI_UplinkRetryAnswers -isnot [hashtable]) { $global:SI_UplinkRetryAnswers = @{} }
    if (-not ($global:SI_LogIngestNotes -is [System.Collections.Generic.List[object]])) { $global:SI_LogIngestNotes = New-Object System.Collections.Generic.List[object] }
    if ($null -eq $global:RA_KqlColumnTypes -and (Get-Command -Name Reset-RAKqlColumnTypes -ErrorAction SilentlyContinue)) { Reset-RAKqlColumnTypes }
    @{ RowCounts = $global:RA_RowCountsThisRun; ColumnFill = $global:RA_ColumnFillThisRun; StatusDone = $script:RAReportStatusDone; Notes = $script:RAReportNotes
       QueryHash = $script:RAReportQueryHash; Retries = $global:SI_UplinkRetryAnswers; EmptyGivers = $script:_RAHandoffEmptyGivers; DfcCompare = $script:RADfcCompare
       KqlTypes = $global:RA_KqlColumnTypes; Stream = $script:RAStream; Failures = $script:_RAReportFailures; BucketLossRun = $script:_RABucketLossRun
       Jumps = $script:AutoBucketJumps; Attempted = $global:RA_ReportsAttemptedThisRun; PublishFailures = $script:_RAPublishFailures
       IngestRefused = $script:_RAIngestRefused; NotDelivered = $script:_RAResultNotDelivered; IngestNotes = $global:SI_LogIngestNotes }
}
function Get-RAScaleOutEngineCounters {
    @{ ExemptedNotCounted = [double]$script:RAStreamExemptedNotCounted; DisabledFiltered = [double]$script:RA_DisabledFilteredReports
       Illegal = $(if ($null -ne $script:RAStream) { [double]$script:RAStream.Illegal } else { 0.0 }) }
}
function Clear-RAScaleOutReportRows {
    <# A report whose item did not deliver keeps no rows: a part of a report never goes out as the report. Never throws. #>
    # -ReportName (#877): the report's name -- a report whose rows cannot be removed is held back by it
    param([Parameter(Mandatory)][int]$Ordinal, [string]$ReportName = '')
    if (-not $script:RAStreamOn -or $null -eq $script:RAStream -or $Ordinal -le 0) { return }
    try {
        $p = @{ CollectionTime = $script:RAStream.TimeText; CollectionId = [string]$script:RAStream.CollectionId; Report = [string]$Ordinal; Bucket = '*'; RunKey = $script:RAStream.RunKey }
        # in batches, each its own short statement (a report that did not deliver may hold a million rows)
        $n = Remove-RAStreamRowsBatched -Stream $script:RAStream -Sql (Get-RAStreamDeleteReportBatchSql -Grain $script:RAStream.Grain) -Params $p -What 'removing the rows the report stored' -Kind ('remove|' + $script:RAStream.Grain)
        if ($n -gt 0) { Write-Info ("{0} row(s) its attempt stored are removed -- the report is not in this run" -f $n) }
        # every row of the report is gone: a report a worker held back is not held any more
        Remove-RAStreamHeldReport -Stream $script:RAStream -Ordinal $Ordinal
    } catch { Set-RAReportRowsHeld -ReportName $ReportName -Ordinal $Ordinal -Cause $_.Exception.Message }
}
function Get-RAScaleOutSplitOfItem {
    <# #831 B: the part of a split report this worker's item is -- its slices, its siblings, its write-number ranges, and
       whether it is already in (its partial written by an earlier attempt: the retry only finishes the report) -- or $null
       for an item that is a whole report. #>
    param($Received)
    $p = $Received.Payload
    if ($null -eq $p -or $null -eq $p.Parts -or [int]$p.Parts -le 1) { return $null }
    $eng = [string]$p.Engine; $run = [string]$p.RunId; $item = [int]$p.Item; $ord = [int]$p.Ordinal
    $sib = @(Get-RAScaleOutSiblings -Manifest $Received.Manifest -Report ([string]$p.Report) | ForEach-Object { [int]$_['Item'] })
    if (-not $sib.Count) { $sib = @($item) }
    $done = $null -ne (Read-RAScaleOutPartial -Store $script:RAScaleStore -Engine $eng -RunId $run -Item $item)
    @{ Item = $item; Part = [int]$p.Part; Parts = [int]$p.Parts; Buckets = [int]$p.Buckets; From = [int]$p.From; To = [int]$p.To; Ordinal = $ord; Report = [string]$p.Report
       Engine = $eng; RunId = $run; Siblings = $sib; Done = $done; PartialWritten = $false; Finisher = $false
       OwnSeq = @(Get-RAScaleOutSplitSeqRanges -Ordinal $ord -Part ([int]$p.Part) -Parts ([int]$p.Parts)) }
}
function Complete-RAScaleOutSplitPart {
    <#
        #831 B: this part's slices of the report are in (-Evidence: what the bucket learning needs of them and how they
        ended). Its partial is written, then the last part to finish puts the report together (Request-RAScaleOutFinish).
        Returns $null when THIS process does not finish the report (the caller ends the report here; its item hands over
        only its counters), else the merged parts (Merge-RAScaleOutPartials), already applied to this process's state: the
        stream entry (rows retrieved, the accounts, the columns), the row count, column fill, retry answers, lost slices,
        the report's start, the lists in part order -- the report then finishes exactly as the single job finishes it.
        Its removals from here on remove the WHOLE report. Parts whose rows another part's whole-result slice replaces
        (#401) are removed. Returns 'skip' when the parts do not add up to the report (it is NOT COMPLETE, no rows kept).
    #>
    param([Parameter(Mandatory)][hashtable]$Evidence, [Parameter(Mandatory)][string]$ReportName)
    $sp = $script:RAScaleSplit
    $state = Get-RAScaleOutEngineState
    if (-not $sp.Done) {
        $part = New-RAScaleOutPartial -State $state -Mark $script:RAScaleMark -Report $ReportName -Item ([int]$sp.Item) -Part ([int]$sp.Part) -Parts ([int]$sp.Parts) `
                    -Entry $script:RAStream.Current -BucketLoss @($script:_RABucketLoss | Where-Object { $_ }) -Evidence $Evidence -NotApplicableWhy ([string]$script:RANotApplicableWhy) -Worker ([string]$script:RAScaleWorkerName)
        Write-RAScaleOutPartial -Store $script:RAScaleStore -Engine ([string]$sp.Engine) -RunId ([string]$sp.RunId) -Partial $part
    }
    $sp.PartialWritten = $true
    $req = $null
    try { $req = Request-RAScaleOutFinish -Store $script:RAScaleStore -Engine ([string]$sp.Engine) -RunId ([string]$sp.RunId) -Ordinal ([int]$sp.Ordinal) -Item ([int]$sp.Item) -Siblings @($sp.Siblings) -Worker ([string]$script:RAScaleWorkerName) }
    catch { Write-Warn2 ("[scale-out] {0}: part {1} of {2} is in the database; whether it is the last part could not be read ({3}) -- another part puts the report together" -f $ReportName, ([int]$sp.Part + 1), $sp.Parts, $_.Exception.Message); return $null }
    if (-not $req.Finisher) {
        Write-Info ("[scale-out] {0}: part {1} of {2} (query slices {3}-{4} of {5}) is in the database -- {6}" -f $ReportName, ([int]$sp.Part + 1), $sp.Parts, ([int]$sp.From + 1), $sp.To, $sp.Buckets, $req.Why)
        Write-Info (Format-RAPhaseLine -Times $script:RAStream.Current.Times -What ("report '{0}', part {1} of {2}" -f $ReportName, ([int]$sp.Part + 1), $sp.Parts))   # #873 A
        Write-RAPhaseTimesToSql -Stream $script:RAStream -Times $script:RAStream.Current.Times -What ('report {0} part {1} of {2}' -f $ReportName, ([int]$sp.Part + 1), $sp.Parts)
        return $null
    }
    $sp.Finisher = $true
    Write-Info ("[scale-out] {0}: every one of its {1} parts is in -- the report is put together here" -f $ReportName, $sp.Parts)
    $m = Merge-RAScaleOutPartials -Partials $req.Partials
    if ($null -eq $script:_RAReportFailures) { $script:_RAReportFailures = New-Object System.Collections.Generic.List[object]; $state = Get-RAScaleOutEngineState }
    # this process's state becomes the report's: the lists in part order (this part's own entries replaced by all of them)
    foreach ($k in 'Failures', 'BucketLossRun', 'Jumps', 'Attempted', 'PublishFailures', 'IngestRefused', 'NotDelivered', 'IngestNotes') {
        $l = $state[$k]; $from = [int]$script:RAScaleMark[$k]
        if ($null -ne $l -and $l.Count -gt $from) { $l.RemoveRange($from, $l.Count - $from) }
    }
    $fake = @{ Reports = @(); PerReport = @{}; Lists = $m.Lists; Counters = @{}; FinalDesiredColumns = @(); KqlTypes = $null; Broken = '' }
    $null = Merge-RAScaleOutHandovers -State $state -Manifest @{ Items = @(@{ Item = 0; Ordinal = 1 }) } -Handovers @{ 0 = $fake }
    $cur = $script:RAStream.Current
    $cur.OwnSeq = $null
    $cur.Retrieved = [long]$m.Retrieved
    $acc = @{}; foreach ($k in @($m.Account.Keys)) { $a = @{}; $v = $m.Account[$k]; if ($v -is [System.Collections.IDictionary]) { foreach ($x in @($v.Keys)) { $a[[string]$x] = [long]$v[$x] } }; $acc[[string]$k] = $a }
    $cur.Account = $acc
    $cur.Columns.Clear(); $cur.ColSet.Clear(); foreach ($c in @($m.Columns)) { if ($c -and $cur.ColSet.Add([string]$c)) { $cur.Columns.Add([string]$c) } }
    $cur.DateCols.Clear(); foreach ($c in @($m.DateCols)) { if ($c) { [void]$cur.DateCols.Add([string]$c) } }
    if ($null -ne $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun[[string]$ReportName] = [int]$m.RowCount }
    if ($null -ne $global:RA_ColumnFillThisRun) { if ($null -ne $m.ColumnFill) { $cf = @{}; foreach ($k in @($m.ColumnFill.Keys)) { $cf[[string]$k] = [long]$m.ColumnFill[$k] }; $global:RA_ColumnFillThisRun[[string]$ReportName] = $cf } else { $global:RA_ColumnFillThisRun.Remove([string]$ReportName) } }
    if ($null -ne $m.Retries -and $global:SI_UplinkRetryAnswers -is [hashtable]) { $rt = @{}; foreach ($k in @($m.Retries.Keys)) { $rt[[string]$k] = [long]$m.Retries[$k] }; $global:SI_UplinkRetryAnswers[[string]$ReportName] = $rt }
    $script:_RABucketLoss = New-Object System.Collections.Generic.List[string]; foreach ($x in @($m.BucketLoss)) { if ($x) { [void]$script:_RABucketLoss.Add([string]$x) } }
    $script:RANotApplicableWhy = [string]$m.NotApplicableWhy
    # count timing: the report's two counts are the earliest any part took before its read and the latest any took after it
    $script:RAReadCounts = Merge-RAReadCounts -Counts @(foreach ($__rcP in @($req.Partials.Values)) { if ($null -ne $__rcP -and $__rcP['Evidence'] -is [System.Collections.IDictionary]) { $__rcP['Evidence']['ReadCounts'] } })
    if ($m.StartedUtc) { $t = [datetime]::MinValue; if ([datetime]::TryParse([string]$m.StartedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$t)) { if ($script:RAReportNotes[[string]$ReportName]) { $script:RAReportNotes[[string]$ReportName]['StartedUtc'] = $t.ToUniversalTime() } } }
    # #401: the first part returned the whole report in one slice -- the other parts' rows go (they would double it)
    foreach ($d in @($m.Drop)) {
        $dp = $req.Partials[[string]$d]
        if ($null -eq $dp) { continue }
        $n = Remove-RAStreamSeqRanges -Stream $script:RAStream -Ordinal ([int]$sp.Ordinal) -Ranges @(Get-RAScaleOutSplitSeqRanges -Ordinal ([int]$sp.Ordinal) -Part ([int]$dp['Part']) -Parts ([int]$sp.Parts))
        if ($n -gt 0) { Write-Info ("{0} row(s) of part {1} are removed -- one query slice of part 1 returned the complete result" -f $n, ([int]$dp['Part'] + 1)) }
    }
    if ($m.Problem -and -not $m.CannotFit) {
        Write-Err2 ("report '{0}' is NOT COMPLETE in this run: {1}. Its findings are unknown for this run, not resolved." -f $ReportName, $m.Problem)
        try { Clear-RAStreamReport -Stream $script:RAStream -Why 'the report is not in this run' } catch { Set-RAReportRowsHeld -Cause $_.Exception.Message }
        Add-RAReportFailure -ReportName $ReportName -Reason ("not complete: {0}" -f $m.Problem)
        return 'skip'
    }
    $m
}
function Receive-RAScaleOutWorkerItem {
    <# The next report of this worker's run (RA-ScaleOut.ps1 Receive-RAScaleOutItem), or $null (nothing left, or another run's). #>
    param([string]$ExpectedRunId = '')
    $r = Receive-RAScaleOutItem -Context $script:RAScaleCtx -QueueName $script:RAScaleQueue -Store $script:RAScaleStore -ExpectedRunId $ExpectedRunId `
            -Worker $script:RAScaleWorkerName -SignInLibraries @($global:SI_RA_BeatSignIn | Where-Object { $_ }) -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } }
    if ($r.Kind -eq 'item') { return $r }
    if ($r.Kind -eq 'other-run') { Write-Info ('[scale-out] {0} -- this worker stops here; a new worker takes it' -f $r.Why) }
    $null
}
function Invoke-RAScaleOutLocalWorker {
    <# A worker in THIS container (a child process of the entry point, as a queue worker would run): no worker job, or none
       started. Returns when it has drained the queue. #>
    $entry = [string]$global:SI_RA_ScaleOutEntryPoint
    if (-not $entry) { $entry = '/app/container/Start-RiskAnalysisInContainer.ps1' }
    if (-not (Test-Path -LiteralPath $entry)) { throw ('the worker''s entry point {0} is not in this container' -f $entry) }
    $old = [Environment]::GetEnvironmentVariable('SI_RA_SCALEOUT_ROLE')
    [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_ROLE', 'worker')
    [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', '1')
    try { & pwsh -NoProfile -File $entry | Out-Host; Write-Info ('[scale-out] the worker in this job ended (exit {0})' -f $LASTEXITCODE) }
    finally { [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_ROLE', $old); [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', $null) }
}
function Invoke-RAScaleOutProducerPass {
    <# The producer's part: plan, the run's shared lookups once, manifest, queue, wait, hand-overs in. Returns the items
       queued (0 = nothing was queued: the reports run in this job as before). #>
    $grain = if ([bool]$global:Detailed) { 'Detailed' } else { 'Summary' }
    $engine = Get-RAScaleOutEngine -Grain $grain
    $acct = [string]$global:SI_StorageAccount
    $store = New-RAScaleOutBlobStore -Account $acct
    $ctx = New-SIStorageContext -AccountName $acct
    $queue = Get-RAScaleOutQueueName -Grain $grain
    $entryOf = { param($n) $global:Exposure_Reports | Where-Object { $_.ReportName -eq $n } | Select-Object -First 1 }
    # #831 B: a report whose remembered slice count is large against the run is split into parts (Get-RAScaleOutSplitCount),
    # so every worker works on it to the end. The workers that may run at once: SI_RA_WORKERS (setup's default 4); without a
    # worker job the producer's own worker is the only one -- nothing is split.
    $__soWorkers = 0
    if ([string]::IsNullOrWhiteSpace([string]$global:SI_RA_WorkerJob)) { $__soWorkers = 1 }
    elseif (-not [int]::TryParse(([string][Environment]::GetEnvironmentVariable('SI_RA_WORKERS')).Trim(), [ref]$__soWorkers) -or $__soWorkers -lt 1) {
        $__soWorkers = 4; $__soBw = 0; if ([int]::TryParse(([string]$global:SI_Bootstrap_RaMaxWorkers).Trim(), [ref]$__soBw) -and $__soBw -gt 0) { $__soWorkers = $__soBw }
    }
    $__soCache = @{}
    if ([bool]$global:AutoBucketCount -and [bool]$global:AutoBucketCache -and -not [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
        try { $__soCache = Read-AutoBucketCache -Path (Get-AutoBucketCachePath -SettingsPath $global:SettingsPath) } catch { $__soCache = @{} }
        if ($__soCache -isnot [hashtable]) { $__soCache = @{} }
    }
    $__soProof = ([string]$global:SI_RA_BucketProof).Trim().ToLowerInvariant() -in 'on', 'true', '1', 'yes'
    # #873 B: the rows each report returned at its last run (the bucket history in the database) -- a report is split by
    # its share of the run's measured rows; a report never measured, by its slices as before
    $__soHist = @{}
    if ((Test-AutoBucketSqlActive) -and $script:AutoBucketSql.History -is [hashtable]) { $__soHist = $script:AutoBucketSql.History }
    $plan = @(New-RAScaleOutPlan -Workers $__soWorkers -Reports @(foreach ($n in @($global:RA_TemplateReportNames)) {
        $e = & $entryOf ([string]$n)
        $sp = $false; $nb = 0; $rw = 0L
        if ($e) {
            $ub = $null; if ($e.PSObject.Properties['UseBucketFilter']) { $ub = $e.UseBucketFilter }
            $bc = $null; if ($e.PSObject.Properties['BucketCount']) { $bc = $e.BucketCount }
            $sp = Test-RAScaleOutSplittable -Name ([string]$n) -Query ([string]$e.ReportQuery) -UseBucketFilter $ub -BucketCount $bc -AutoBucket ([bool]$global:AutoBucketCount) -Proof $__soProof
            # every report's remembered slices: the run's fair share, and the queue's largest-first order (#831)
            $nb = Get-RAScaleOutRememberedBuckets -Cache $__soCache -Report ([string]$n)
            $rw = Get-RAScaleOutMeasuredRows -History $__soHist -Report ([string]$n)
        }
        [pscustomobject]@{ Name = [string]$n; HasEntry = [bool]$e; Buckets = $nb; Splittable = $sp; Rows = $rw } }))
    $__soRunRows = 0L; foreach ($n in @($global:RA_TemplateReportNames)) { $__soRunRows += [long](Get-RAScaleOutMeasuredRows -History $__soHist -Report ([string]$n)) }
    foreach ($__soR in @($plan | Where-Object { [int]$_.Parts -gt 1 -and [int]$_.Part -eq 0 })) {
        $__soRw = Get-RAScaleOutMeasuredRows -History $__soHist -Report ([string]$__soR.Report)
        if ($__soRw -gt 0) { Write-Info ('[scale-out] {0}: {1} query slices remembered, {2} of the run''s {3} measured rows at its last run -- run in {4} parts for {5} workers' -f $__soR.Report, $__soR.Buckets, $__soRw, $__soRunRows, $__soR.Parts, $__soWorkers) }
        else { Write-Info ('[scale-out] {0}: {1} query slices remembered -- run in {2} parts, so every worker works on it' -f $__soR.Report, $__soR.Buckets, $__soR.Parts) }
    }
    if (-not $plan.Count) { Write-Info '[scale-out] no report of the template has a definition -- nothing to hand to the workers'; return 0 }
    # #673: the run's Defender recommendation list, ONCE, before any worker starts (a load clears the list: never two at once)
    $dfc = @{ State = 'none'; Error = ''; Keys = 0L; Pages = 0 }
    $queries = @($plan | ForEach-Object { [string](& $entryOf ([string]$_.Report)).ReportQuery })
    if (Test-RAScaleOutNeedsDefenderKeys -Queries $queries -InEngine (Test-RADefenderFilterInEngineOn $global:SI_RA_DefenderFilterInEngine) -Compare (Test-RADefenderFilterSetting $global:SI_RA_DefenderFilterCompare)) {
        try {
            $ws = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) { [string]$global:SI_WorkspaceResourceId } else { [string]$global:WorkspaceResourceId }
            $set = Sync-RADefenderKeySet -Stream $script:RAStream -WorkspaceResourceId $ws
            $dfc = @{ State = 'loaded'; Error = ''; Keys = [long]$set.Keys; Pages = [int]$set.Pages }
        } catch {
            $dfc = @{ State = 'failed'; Error = [string]$_.Exception.Message; Keys = 0L; Pages = 0 }
            Write-Warn2 ("[scale-out] the Defender recommendation list could not be loaded for this run -- the reports that need it are not complete: {0}" -f $_.Exception.Message)
        }
    }
    $hn = if ($env:COMPUTERNAME) { [string]$env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
    $hostInfo = @{ Name = $hn; Fqdn = $(if ($global:RA_DnsName) { [string]$global:RA_DnsName } else { $hn }); User = $(if ($env:USERNAME) { [string]$env:USERNAME } elseif ($env:USER) { [string]$env:USER } else { 'container' }) }
    $m = New-RAScaleOutManifest -Grain $grain -TimeText ([string]$script:RAStream.TimeText) -CollectionTime ([datetime]$global:RA_CollectionTime).ToUniversalTime() -CollectionId ([int]$script:RAStream.CollectionId) `
            -RunKey ([string]$script:RAStream.RunKey) -HealthRunId ([string]$script:_RunHealthCtx.RunId) -Template ([string]$global:ReportTemplate) -Items $plan -Defender $dfc -HostInfo $hostInfo `
            -ProducerExecution ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME)
    $m['RaCollectionTime'] = ([datetime]$global:RA_CollectionTime).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    $script:RAScaleManifest = $m
    $earlier = @(Close-RAScaleOutEarlierRuns -Store $store -Engine $engine -RunId ([string]$m.RunId))
    if ($earlier.Count) { Write-Info ('[scale-out] {0} earlier run(s) whose producer did not finish are closed -- their reports are not run again' -f $earlier.Count) }
    Write-RAScaleOutManifest -Store $store -Manifest $m
    $queued = Publish-RAScaleOutItems -Manifest $m -Context $ctx -QueueName $queue
    $script:RAScaleQueued = [int]$queued
    $useKeda = -not [string]::IsNullOrWhiteSpace([string]$global:SI_RA_WorkerJob)
    Write-Info ('[scale-out] {0} report(s) handed to queue workers ({1}{2}); this job waits for them and then finishes the run' -f $queued, $queue, $(if ($useKeda) { ', worker job ' + [string]$global:SI_RA_WorkerJob } else { ', run by a worker in this job' }))
    $w = Wait-RAScaleOutItems -Store $store -Manifest $m -UseKeda $useKeda -LocalWorker { Invoke-RAScaleOutLocalWorker } -Log { param($l, $t) if ($l -eq 'WARN') { Write-Warn2 $t } else { Write-Info $t } }
    $handovers = Read-RAScaleOutHandovers -Store $store -Manifest $m
    $state = Get-RAScaleOutEngineState
    $merged = Merge-RAScaleOutHandovers -State $state -Manifest $m -Handovers $handovers
    $script:RAStreamExemptedNotCounted = [long]$script:RAStreamExemptedNotCounted + [long]$merged.Counters['ExemptedNotCounted']
    $script:RA_DisabledFilteredReports = [int]$script:RA_DisabledFilteredReports + [int]$merged.Counters['DisabledFiltered']
    $script:RAStream.Illegal = [long]$script:RAStream.Illegal + [long]$merged.Counters['Illegal']
    $global:FinalDesiredColumns = $merged.FinalDesiredColumns
    if (@($merged.Broken).Count -and -not $script:RAStream.Broken) { $script:RAStream.Broken = [string]@($merged.Broken)[0] }
    # #877: the reports a worker held back are held back in the run (their rows are never read as the report)
    foreach ($__hd in @($merged.Held)) {
        if ($null -eq $__hd -or -not [string]$__hd.Report) { continue }
        $null = Add-RAStreamHeldReport -Stream $script:RAStream -ReportName ([string]$__hd.Report) -Ordinal ([int]$__hd.Ordinal) -Cause ([string]$__hd.Cause)
    }
    foreach ($n in @($merged.StreamReports.Keys)) {
        $e = $merged.StreamReports[$n]
        $script:RAStream.Reports[[string]$n] = New-RAStreamReportEntry -Name ([string]$n) -Ordinal ([int]$e['Ordinal']) -Staged ([bool]$e['Staged']) -Columns @($e['Columns']) -DateCols @($e['DateCols']) `
                                               -Retrieved ([long]$e['Retrieved']) -StageCols @($e['StageCols']) -Pages ([int]$e['Pages'])
        if ([int]$e['Ordinal'] -gt [int]$script:RAStream.Ordinal) { $script:RAStream.Ordinal = [int]$e['Ordinal'] }
    }
    # an item that did not deliver: its report is NOT COMPLETE with the cause, and keeps no rows
    foreach ($f in @(Get-RAScaleOutItemFailures -Manifest $m -Markers @($w.Markers) -Handovers $handovers)) {
        Write-Err2 ("completeness: report '{0}' is NOT COMPLETE in this run -- {1}. The missing findings are unknown, not resolved." -f $f.Report, $f.Why)
        # (#831 B: a part of a split report that failed already named its report's cause -- the report is named once)
        $__soHas = @(@($script:_RAReportFailures) | Where-Object { $null -ne $_ -and [string]$_['Report'] -eq [string]$f.Report }).Count -gt 0
        if (-not $__soHas) { Add-RAReportFailure -ReportName ([string]$f.Report) -Reason ("not complete: {0}" -f $f.Why) }
        if ($null -ne $global:RA_ReportsAttemptedThisRun -and -not $global:RA_ReportsAttemptedThisRun.Contains([string]$f.Report)) { [void]$global:RA_ReportsAttemptedThisRun.Add([string]$f.Report) }
        $o = @($plan | Where-Object { $_.Report -eq $f.Report } | Select-Object -First 1)
        if ($o.Count) { Clear-RAScaleOutReportRows -Ordinal ([int]$o[0].Ordinal) -ReportName ([string]$f.Report) }
    }
    # #674 over the whole run, in the single job's order
    $retrieved = @{}; $ords = @{}
    foreach ($p in $plan) { $ords[[string]$p.Report] = [int]$p.Ordinal }
    foreach ($n in @($merged.StreamReports.Keys)) { $retrieved[[string]$n] = [long]$merged.StreamReports[$n]['Retrieved'] }
    foreach ($c in @(Get-RAScaleOutHandoffContradictions -EmptyGivers $state['EmptyGivers'] -Retrieved $retrieved -Ordinals $ords)) {
        Write-Err2 ("completeness: report '{0}' is NOT COMPLETE in this run -- {1}" -f $c.Report, $c.Why)
        Add-RAReportFailure -ReportName ([string]$c.Report) -Reason ("not complete: {0}" -f $c.Why)
    }
    $null = Close-RAScaleOutRun -Store $store -Engine $engine -RunId ([string]$m.RunId) -Why 'every report is in'
    Write-Info ('[scale-out] {0} report(s) back from the workers ({1}); the run is finished here' -f @($merged.Reports).Count, [string]$w.Text)
    $global:SI_RA_ScaleOutRan = $true
    $queued
}
function Step-RALoopPass {
    <# One pass of the report loop: $true with the reports of this pass in $script:RALoopList, or $false (the loop is done). #>
    $script:RALoopPass++
    if ($script:RAScaleRole -eq 'worker') {
        $r = $null
        # #873 A: the worker's time on its items and waiting for the queue, said when it stops (log only)
        if ($null -eq $script:RAWorkerTime) { $script:RAWorkerTime = @{ Started = [datetime]::UtcNow; Clock = [System.Diagnostics.Stopwatch]::StartNew(); Wait = 0.0; Items = 0 } }
        $__phWaitSw = [System.Diagnostics.Stopwatch]::StartNew()
        if ($script:RALoopPass -eq 1 -and $null -ne $script:RAScaleFirst) { $r = $script:RAScaleFirst; $script:RAScaleFirst = $null }
        else { $r = Receive-RAScaleOutWorkerItem -ExpectedRunId ([string]$script:RAScaleRunId) }
        $script:RAWorkerTime.Wait += $__phWaitSw.Elapsed.TotalSeconds
        if ($null -eq $r) {
            try {
                $__wt = $script:RAWorkerTime; $__wtBusy = $__wt.Clock.Elapsed.TotalSeconds - $__wt.Wait
                Write-Info (Format-RAWorkerTimeLine -Items $__wt.Items -BusySeconds $__wtBusy -WaitSeconds $__wt.Wait -StartedUtc $__wt.Started -EndedUtc ([datetime]::UtcNow))
                Write-RAStepPhaseRow -Stream $script:RAStream -Phase 'worker: working on its items' -Seconds $__wtBusy -Rows ([long]$__wt.Items)
                Write-RAStepPhaseRow -Stream $script:RAStream -Phase 'worker: waiting for the queue' -Seconds $__wt.Wait
            } catch { }
            return $false
        }
        $script:RAWorkerTime.Items++
        $script:RAScaleItem = $r
        $script:RAScaleSplit = $null
        # (a part never runs as the whole report: if its part cannot be read, the worker stops and the item comes back)
        $script:RAScaleSplit = Get-RAScaleOutSplitOfItem -Received $r
        $rep = [string]$r.Payload.Report
        $script:RALoopList = @(@($script:RATemplateIncludes) | Where-Object { (Resolve-ReportInclude -Item $_).Name -eq $rep } | Select-Object -First 1)
        $global:FinalDesiredColumns = $null
        $script:RAScaleMark = Start-RAScaleOutItemState -State (Get-RAScaleOutEngineState) -Counters (Get-RAScaleOutEngineCounters)
        if (-not $script:RALoopList.Count) { Add-RAReportFailure -ReportName $rep -Reason 'it was not run: its definition is not in this worker''s template' }
        Write-Info ('[scale-out] report {0} (item {1} of {2}, attempt {3}){4}' -f $rep, ([int]$r.Payload.Item + 1), [int]$r.Payload.ShardCount, [int]$r.Message.DequeueCount,
            $(if ($script:RAScaleSplit) { ' -- part {0} of {1}: query slices {2}-{3} of {4}{5}' -f ([int]$script:RAScaleSplit.Part + 1), $script:RAScaleSplit.Parts, ([int]$script:RAScaleSplit.From + 1), $script:RAScaleSplit.To, $script:RAScaleSplit.Buckets, $(if ($script:RAScaleSplit.Done) { ' (already in the database: only the report''s end runs)' } else { '' }) } else { '' }))
        return $true
    }
    if ($script:RALoopPass -gt 1) { return $false }
    $script:RALoopList = @($script:RATemplateIncludes)
    if ($script:RAScaleProducerOn) {
        $q = 0; $script:RAScaleQueued = 0
        try { $q = [int](Invoke-RAScaleOutProducerPass) }
        catch {
            $why = [string]$_.Exception.Message
            if ([int]$script:RAScaleQueued -le 0) {
                # nothing reached a worker: the reports run in this job, as before
                Write-Warn2 ("[scale-out] the reports could not be handed to queue workers ({0}) -- they run in this job" -f $why)
                $script:RAScaleProducerOn = $false; $script:RAScaleManifest = $null
                return $true
            }
            # the reports are with the workers and this job could not follow them: every report of the plan without a
            # verdict is NOT COMPLETE with this cause (the end of the run names them), and the run is closed for the workers
            Write-Err2 ("[scale-out] the reports were handed to queue workers, and this job could not follow them: {0}" -f $why)
            foreach ($it in @($script:RAScaleManifest['Items'])) { Add-RAReportFailure -ReportName ([string]$it['Report']) -Reason ("not complete: this run could not collect it from its worker ({0})" -f $why) }
            try { $null = Close-RAScaleOutRun -Store (New-RAScaleOutBlobStore -Account ([string]$global:SI_StorageAccount)) -Engine ([string]$script:RAScaleManifest['Engine']) -RunId ([string]$script:RAScaleManifest['RunId']) -Why $why } catch { }
            $script:RALoopList = @()
            return $true
        }
        if ($q -gt 0) { $script:RALoopList = @() } else { $script:RAScaleProducerOn = $false }
    }
    return $true
}
function Complete-RALoopPass {
    <# A worker's item is done: the hand-over and the marker, then the message is removed. A hand-over that cannot be
       written leaves the message: a worker takes the report again. A worker NEVER posts to Log Analytics: the producer posts
       the whole run once, from SQL, after every report is in -- a worker that dies (or a retried report) can never leave
       rows in Log Analytics twice; Log Analytics gets exactly the rows a single job posts. #>
    if ($script:RAScaleRole -ne 'worker' -or $null -eq $script:RAScaleItem) { return }
    # #882: a hand-over for a run that is over is never written (the worker stops, its counts are not kept)
    Assert-RAScaleOutWorkerLive -Where ('before handing report {0} over' -f [string]$script:RAScaleItem.Payload.Report)
    $it = $script:RAScaleItem; $script:RAScaleItem = $null
    $rep = [string]$it.Payload.Report; $ord = [int]$it.Payload.Ordinal
    $stored = 0L
    if ($script:RAStreamOn -and $null -ne $script:RAStream) {
        try { $c = Get-RAStreamReportCounts -Stream $script:RAStream; if ($c.ContainsKey($ord)) { $stored = [long]$c[$ord] } } catch { Write-Warn2 ("[scale-out] the rows of {0} could not be counted: {1}" -f $rep, $_.Exception.Message) }
    }
    # #831 B: a part of a split report that did not put the report together hands over no report -- only its counters (not
    # the per-report one: the report is counted once), its columns and KQL types; its list entries went into its partial
    # (when it wrote none -- it failed -- they come here, so its cause is never lost)
    $__soSp = $script:RAScaleSplit; $script:RAScaleSplit = $null
    $__soRep = @($rep); $__soNoLists = $false; $__soNoCtr = @()
    if ($__soSp -and -not $__soSp.Finisher) { $__soRep = @(); $__soNoLists = [bool]$__soSp.PartialWritten; $__soNoCtr = @('DisabledFiltered') }
    $h = New-RAScaleOutHandover -State (Get-RAScaleOutEngineState) -Mark $script:RAScaleMark -Counters (Get-RAScaleOutEngineCounters) -Reports $__soRep -Item ([int]$it.Payload.Item) `
            -FinalDesiredColumns @($global:FinalDesiredColumns) -Worker ([string]$script:RAScaleWorkerName) -Broken $(if ($null -ne $script:RAStream) { [string]$script:RAStream.Broken } else { '' }) `
            -NoLists:$__soNoLists -NoCounters $__soNoCtr -Held @(Get-RAStreamHeldReports -Stream $script:RAStream)
    try {
        Write-RAScaleOutItemResult -Store $script:RAScaleStore -Engine ([string]$it.Payload.Engine) -RunId ([string]$it.Payload.RunId) -Item ([int]$it.Payload.Item) -Handover $h -State done -Rows $stored -Worker ([string]$script:RAScaleWorkerName)
        $null = Complete-RAScaleOutItem -Context $script:RAScaleCtx -QueueName $script:RAScaleQueue -Received $it
        $script:RAScaleDone++
        # (#831 B: only the part that put the report together keeps its bucket counts -- one coherent state per report)
        if ($global:SI_RA_ScaleOutReportsRun -is [System.Collections.Generic.List[string]] -and (-not $__soSp -or $__soSp.Finisher)) { [void]$global:SI_RA_ScaleOutReportsRun.Add($rep) }
        Write-Info ('[scale-out] report {0} handed to the producer: {1} row(s) in the database' -f $rep, $stored)
    } catch {
        Write-Err2 ("[scale-out] report {0}: its result could not be handed to the producer ({1}) -- a worker takes the report again" -f $rep, $_.Exception.Message)
        if ($it.Beat) { $null = Stop-SIWorkItemLeaseBeat -Beat $it.Beat }
    }
}

$script:RATemplateIncludes = $global:Exposure_Template_ReportsIncluded
$script:RALoopPass = 0; $script:RALoopList = @(); $script:RAScaleDone = 0
if ($script:RAScaleRole -eq 'worker' -and -not $script:RAStreamOn) {
    # a worker writes only to its run's collection: without it nothing is run here. A collection that is no longer loading
    # is a run that is over (its producer stopped): the run is closed for every worker and the message removed; anything
    # else (the database not reachable from here) puts the report back to the queue for another worker
    if ([string]$script:RAScaleAttachError -match 'not loading any more') {
        Write-Warn2 ('[scale-out] this report''s run is over ({0}) -- nothing is run; its remaining reports are not run either' -f $script:RAScaleAttachError)
        $null = Close-RAScaleOutRun -Store $script:RAScaleStore -Engine ([string]$script:RAScaleManifest['Engine']) -RunId $script:RAScaleRunId -Why $script:RAScaleAttachError
        if ($script:RAScaleFirst) { $null = Complete-RAScaleOutItem -Context $script:RAScaleCtx -QueueName $script:RAScaleQueue -Received $script:RAScaleFirst }
        return
    }
    Write-Err2 '[scale-out] this worker cannot reach its run''s result in the database -- it runs nothing; the report goes back to the queue'
    $__soRcpt = if ($script:RAScaleFirst) { [string]$script:RAScaleFirst.Message.PopReceipt } else { '' }
    if ($script:RAScaleFirst -and $script:RAScaleFirst.Beat) { $__soStop = Stop-SIWorkItemLeaseBeat -Beat $script:RAScaleFirst.Beat; if ($__soStop -and $__soStop.PopReceipt) { $__soRcpt = [string]$__soStop.PopReceipt } }
    if ($script:RAScaleFirst) { $null = Update-SIWorkItemLease -Context $script:RAScaleCtx -QueueName $script:RAScaleQueue -Id ([string]$script:RAScaleFirst.Message.Id) -PopReceipt $__soRcpt -VisibilityTimeoutSeconds 60 -RawText ([string]$script:RAScaleFirst.Message.RawText) }
    return
}
if ($script:RAScaleRole -ne 'worker') {
    $__soWant = Test-RAScaleOutWanted -Setting $global:SI_RA_ScaleOut -Grain $(if ([bool]$global:Detailed) { 'Detailed' } else { 'Summary' }) -StreamOn ([bool]$script:RAStreamOn) -WhatIf ([bool]$script:SIWhatIf) -StorageAccount ([string]$global:SI_StorageAccount)
    $script:RAScaleProducerOn = [bool]$__soWant.On
    if (([string]$global:SI_RA_ScaleOut).Trim()) { Write-Info ('[scale-out] {0}' -f $__soWant.Why) }
}

while (Step-RALoopPass) {
foreach ($includeItem in $script:RALoopList) {
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
    # #401 -- and its companion: "the CL lookups were replicated, so one bucket is the complete result".
    $script:_RACrossDomainReplicated = $false
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
    # Per-report LookupNeededKeys: how a lookup WITHOUT a per-asset key is cut to one slice when it does not fit whole
    # (RA-ProfileAugment.ps1, Get-RALookupNeededKeyDeclarations). Reset here so one report's declaration never reaches
    # the next report; filled below from the report's entry.
    $script:_RALookupNeededKeys = @()
    # #711: the lookups the previous report did not use are let go here -- they were kept for the whole run, and at a
    # large install every report's own CI lookup (~100,000 rows) stayed in memory until the run ran out of it.
    if (Get-Command -Name Start-RALookupCacheReport -ErrorAction SilentlyContinue) { $null = Start-RALookupCacheReport }

    $inc = Resolve-ReportInclude -Item $includeItem
    $ReportNameFromTemplate = $inc.Name

    $Entry = $global:Exposure_Reports | Where-Object { $_.ReportName -eq $ReportNameFromTemplate }

    if (-not $Entry) {
        Write-Warn2 ("report '{0}' defined in template but not found in report configurations" -f $ReportNameFromTemplate)
        continue
    }

    $ReportName                     = $Entry.ReportName
    if ($null -ne $global:RA_ReportsAttemptedThisRun) { [void]$global:RA_ReportsAttemptedThisRun.Add([string]$ReportName) }
    # #709: when this report started; the hunting calls count their 429 / 502 / 504 answers against it
    Set-RAReportNote -ReportName ([string]$ReportName) -Values @{ StartedUtc = [datetime]::UtcNow }
    $global:SI_UplinkCurrentReport = [string]$ReportName
    $script:RANotApplicableWhy = ''
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
    # #690 (34): what the report asks, as authored (before the run's substitutions below) -- a corrected query reads as a
    # changed report, so the findings it no longer lists close as 'report changed', never as 'remediated'
    # #902 (5): with the source tables an Admin accepted as empty for THIS report (none: the fingerprint is as before)
    try { $script:RAReportQueryHash[[string]$ReportName] = Get-RAReportQueryFingerprint -Query ([string]$Entry.ReportQuery) -TierScope $CriticalityTierLevelScope -SeverityScope $SecuritySeverityScope -AcceptedEmpty @($script:RASourceAccepted[[string]$ReportName]) } catch { }
    # #692: the fingerprint(s) the report had before a declared structure-only change (data-model/report-fingerprint-carry) -- a
    # report that only gained the generated output block or the bucket filter asks the same: its findings keep their history
    try { $script:RAReportQueryHashCarry[[string]$ReportName] = (@(Get-RAReportQueryFingerprintCarry -Query ([string]$Entry.ReportQuery) -ReportName ([string]$ReportName) -TierScope $CriticalityTierLevelScope -SeverityScope $SecuritySeverityScope) -join ';') } catch { }
    # #692: the generated output block is the report's declaration of its data out (comments only) -- it is not sent
    $Query = Remove-RAOutBlock -Query $Query

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

    if ($Entry.PSObject.Properties['LookupNeededKeys'] -and $Entry.LookupNeededKeys) {
        $script:_RALookupNeededKeys = @($Entry.LookupNeededKeys)
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
    $__abTemplateCount = 0   # #833: a count the report's template sets stays the floor of its learned size
    if ($Entry.PSObject.Properties['BucketCount'] -and $Entry.BucketCount) {
        $bc = [int]$Entry.BucketCount
        if ($bc -gt 0) { $effectiveBucketCount = $bc; $__abTemplateCount = $bc }
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

    # #278 the graph recommendation reports leave what Defender for Cloud carries to the Defender recommendation
    # report -- only correct when that report is part of this run. Otherwise the lookup is emptied and every
    # recommendation stays here (a template without the Defender report must never lose them).
    $Query = Resolve-RADefenderHandoffBlock -Query $Query -ReportName $ReportName -IncludedReports @($global:RA_TemplateReportNames)

    # substitute __CVE_MIN_AGE_DAYS__ scalar placeholder from <ReportName>.exclude.custom.json
    # (CveMinAgeDays property; default 0 = no age filter). See $script:_ScalarTokenMap.
    $Query = Resolve-ScalarPlaceholders -Query $Query -ReportName $ReportName

    # #505 / #541 the report's SCOPE (RA-ScopePreamble.ps1, the one reader of the customer's scope): the scope block at the
    # top of the query (exclusions, disabled assets, tier scope, the factor set, the lists and criteria the query names),
    # the CI blocks (_ciLink / _ciAsset, RA-CiKql.ps1) regenerated with this install's SI_ActiveStaleDays, the same scope
    # and the report's factor set, the excluded configuration ids appended -- and any legacy disabled-asset marker line
    # rewritten from SI_DisabledAssets_RiskAnalysis (#533 (c)). What applies to which report is data-model/report-scope.
    if (-not $script:RA_DisabledAssetPolicy) { $script:RA_DisabledAssetPolicy = Get-SIDisabledAssetPolicy }
    $raScope = Resolve-RAScopePreamble -Query $Query -ReportName $ReportName -TierLabels @($CriticalityTierLevelScope) -Policy $script:RA_DisabledAssetPolicy
    $Query = $raScope.Query
    if ($raScope.Active -and -not $raScope.Active.IncludeDisabled) { $script:RA_DisabledFilteredReports++ }
    # #546 unknown is never a finding: say how many in-scope assets this report could not judge (warn-free, never fails)
    $raUnknownLine = Get-RAUnknownLine -Query $Query -ReportName $ReportName
    if ($raUnknownLine) { Write-Info $raUnknownLine }

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

    # #464: a report that asks for the CI's factors (marker //__SI_CI_FACTORS__) gets the _SiCiFactors() helper -- one row per
    # CI with si_rf_<id> + si_rf_count (_shared/RA-FactorKeys.ps1). No shipped report uses it yet; no marker = unchanged.
    $Query = Resolve-RACiFactorsBlock -Query $Query

    # #212: every SI_*_Profile_CL read keeps THIS install's rows before its max / arg_max -- two installs can write
    # one workspace, and the newest snapshot can be the other one's (its tiers, its rules). Every route reads this
    # text (Log Analytics direct, advanced hunting, the let-blocks run in Log Analytics); a customer's single install
    # is unaffected. 8 days = the window the report queries read.
    $Query = Add-SIInstallRowsFilter -Query $Query -SolutionVersion $global:RA_SolutionVersion -LookbackDays 8

    # If bucketing is used and the query has the bucket-filter block, ensure
    # DeviceKey exists before the block (so the bucket filter can hash on it).
    $Query = Add-DeviceKeyBeforeBucketBlock -Query $Query
    $querySupportsBucket = Test-QueryHasBucketFilterBlock -Query $Query

    $ResultAll = @()
    Reset-RAProof
    # #697 (3): a key answer of the previous report is never used for this one
    if (Get-Command -Name Clear-RALookupKeyAnswerMemo -ErrorAction SilentlyContinue) { Clear-RALookupKeyAnswerMemo }
    # #641: the slices the report's rows are asked in -- its completeness count is asked in the same (set after the bucket loop)
    $script:RACountBuckets = 1
    # count timing: the report's two counts of the source (just before its first slice, just after its last) are not taken yet
    Reset-RAReadCounts
    # #638: the report's rows go to SQL bucket by bucket -- whatever an earlier attempt of it wrote is removed first
    if ($script:RAStreamOn) {
        # #742: a queue worker numbers the report as its producer planned it (the single job's ordinal and write order)
        $__soStart = @{}
        if ($script:RAScaleRole -eq 'worker' -and $null -ne $script:RAScaleItem) { $__soOrd = [int]$script:RAScaleItem.Payload.Ordinal; $__soStart = @{ Ordinal = $__soOrd; SeqBase = (Get-RAScaleOutSeqBase -Ordinal $__soOrd) } }
        # #831 B: ONE PART of a split report numbers its rows in its own bands and removes only its own rows (never another
        # part's); a part already in (an earlier attempt wrote its partial) keeps its rows -- its retry only finishes the report
        if ($null -ne $script:RAScaleSplit) {
            $__soSp = $script:RAScaleSplit
            $__soStart = @{ Ordinal = [int]$__soSp.Ordinal; SeqBase = (Get-RAScaleOutSplitSeqBase -Ordinal ([int]$__soSp.Ordinal) -Part ([int]$__soSp.Part) -Parts ([int]$__soSp.Parts) -Band main); OwnSeq = @($__soSp.OwnSeq) }
            if ($__soSp.Done) { $__soStart['KeepRows'] = $true }
        }
        $null = Start-RAStreamReport -Stream $script:RAStream -ReportName ([string]$ReportName) -Staged ([string]$ReportName -like '*_Summary*') -Query $Query @__soStart
        if ($null -ne $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 }
        if ($null -ne $global:RA_ColumnFillThisRun) { $global:RA_ColumnFillThisRun.Remove([string]$ReportName) }
    }

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
        # #833: the lowest count this report's learned size may come down to -- 1 with the Pro database (measured), unless
        # the report's template sets a count; without the database the configured count as before
        $__abLearnFloor = Get-AutoBucketLearnFloor -Configured ([int]$effectiveBucketCount) -TemplateCount ([int]$__abTemplateCount) -Measured:(Test-AutoBucketSqlActive)
        if ($__abLearnFloor -gt $capBucket) { $__abLearnFloor = [int]$capBucket }

        # Set (to the reason) the moment it is known that NO slice count can make this report's query fit in one
        # request: a lookup needed whole in every slice is larger than a request can carry. Decided once -- before
        # anything is sent when the sizes alone settle it, else on the first request the service refuses for its
        # size -- and then the report is failed as a whole and the run goes on with the next report.
        $reportCannotFit = $null

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

                try {
                    $null = Invoke-GraphHuntingQuery -Query $probeQuery `
                      -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes `
                      -MaxRetries 1
                } catch {
                    # The service refused this request for its size, and what more slices could still remove
                    # from it is a sliver: the ramp would build the same request at every rung. Say so once.
                    $__refused = Get-RARefusedRequestVerdict -Err $_
                    if ($__refused) { throw (New-RALookupTooLargeError -Message $__refused) }
                    throw
                }
            } finally {
                $script:_CurrentBucketCount = 0
                $script:_CurrentBucketIndex = 0
            }
          }

          # #831 B: ONE PART of a split report asks the slice count its producer planned for EVERY part (the remembered count) --
          # never sized again here: two parts with different counts would slice the report differently (rows twice, or none)
          if ($null -ne $script:RAScaleSplit) {
            $bucketCountToUse = [int]$script:RAScaleSplit.Buckets
            $script:AutoBucketMemo[$queryKey] = [int]$bucketCountToUse
            $script:_AutoBucketSource = 'cache'
            $script:_AutoBucketProbeFailed = $false
            $__abPlan = $null
            Write-Info ("bucket sizing: '{0}' runs in {1} part(s) over {2} remembered bucket(s) -- this part asks buckets {3}-{4}" -f $ReportName, $script:RAScaleSplit.Parts, $bucketCountToUse, ([int]$script:RAScaleSplit.From + 1), $script:RAScaleSplit.To)
          } else {
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
            # #640 STEP 4: no remembered count for this query (a reset, a changed query) but a measured earlier run --
            # start from the count that measurement needs, not from 1, 2, 4, 8.
            # A CHANGED QUERY (a new build, a new fingerprint) starts from the count the report used under its earlier query --
            # a remembered count, not a confirmed one -- instead of sizing again from scratch (Get-AutoBucketPreviousCount).
            # #833: ... but only when the report was never MEASURED: a changed query with a measured earlier run starts from
            # that measurement (rows, bytes, request and slice time against half of every limit, Get-AutoBucketStartPlan),
            # never from the earlier query's count (live 2026-10-20: 16 buckets for at most 80 rows a bucket, 372 s for 36 s).
            # The learned size may come down to 1 (Get-AutoBucketLearnFloor); a first run with nothing known starts from
            # the configured count as before.
            $__abHint = $null
            $__abPlan = Get-AutoBucketStartPlan -ReportName $ReportName -QueryKey $queryKey -Floor $__abLearnFloor -Cap $capBucket -Start $effectiveBucketCount
            if ($null -eq $__abPlan.Measured) { $__abHint = Get-AutoBucketPreviousCount -QueryKey $queryKey -Floor $effectiveBucketCount -Cap $capBucket }
            if ($null -ne $__abHint) {
              Write-Info ("bucket sizing: '{0}' starts from {1} bucket(s), the count it used before its query changed" -f $ReportName, $__abHint)
              $bucketCountToUse = [int]$__abHint
              $script:AutoBucketMemo[$queryKey] = [int]$__abHint
              $script:_AutoBucketSource = 'hint'
              $script:_AutoBucketProbeFailed = $false
            } else {
            if ($null -ne $__abPlan.Measured) { Write-Info ("bucket sizing: '{0}' sized from its last measured result: {1} bucket(s) (start {2})" -f $ReportName, $__abPlan.Measured, $__abPlan.MinCount) }
            $bucketCountToUse = Get-OptimalBucketCount -QueryKey $queryKey -LegacyKeys @($legacyKey) -MaxBucketCount $capBucket -MinBucketCount $__abPlan.MinCount -ProbeScript $probe `
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
            }
          } catch {
            if (Test-RAReportCannotRunError -Err $_) {
              # Not a sizing problem a fallback count can solve: the same request would be built at every count.
              $reportCannotFit = [string]$_.Exception.Message
            } else {
              # The service's code and message (e.g. SEM0100 ...), not just "BadRequest" -- that is what says what to fix.
              Write-Warn2 ("AutoBucket failed for report '{0}'. Falling back to configured BucketCount={1}. Error: {2}" -f `
                $ReportName, $effectiveBucketCount, (Get-SIKqlErrorSummary -ErrorRecord $_))
            }
            $bucketCountToUse = $effectiveBucketCount
            $script:_AutoBucketSource = 'configured'
          }
          # #697 (2): 'measured' only when the measured start held on its first rung; a probe that had to climb above it
          # stays 'probe' -- a count a failed query proved necessary, which the measured sizing never goes below
          if ([string]$script:_AutoBucketSource -eq 'probe' -and $__abPlan -and $null -ne $__abPlan.Measured -and -not [bool]$script:_AutoBucketProbeFailed) { $script:_AutoBucketSource = 'measured' }
          # #640 STEP 3: a remembered count whose last run stayed far below every limit -- try half this run (an overflow
          # doubles again as before; never halved right after a doubling).
          if ([string]$script:_AutoBucketSource -in @('cache', 'memo')) {
            $__abDown = Get-AutoBucketDownPlan -ReportName $ReportName -Count ([int]$bucketCountToUse) -Floor ([int]$__abLearnFloor) -ProbeFloor ([int]$effectiveBucketCount) -QueryKey $queryKey
            if ($__abDown.Down) {
              Write-Info ("bucket sizing: '{0}' tries {1} bucket(s) instead of {2} -- {3}" -f $ReportName, $__abDown.Count, $bucketCountToUse, $__abDown.Why)
              $bucketCountToUse = [int]$__abDown.Count
              $script:_AutoBucketSource = 'down'
            }
          }
          }   # #831 B: close the else of a part of a split report
        }

        if ($null -ne $script:RAScaleSplit) { $bucketCountToUse = [int]$script:RAScaleSplit.Buckets }   # every part: the same count
        if ($bucketCountToUse -lt 1) { $bucketCountToUse = 1 }
        # #640: where this report's count started and how it was decided (the end of the report records it)
        $__abStartCount = [int]$bucketCountToUse
        $__abStartSource = [string]$script:_AutoBucketSource

        
# -------------------------------------------------------------------------------------------------
# Buckets execution with escalation:
# If ANY bucket fails due to deterministic overflow/limits/timeout, re-run the WHOLE report with
# a higher bucket count (e.g., 4 -> 8) until success or cap is reached.
# -------------------------------------------------------------------------------------------------

$bucketRunSucceeded = $false
$lastBucketRunError = $null
$__abEarlySavedAt = 0   # the count this report's run has already kept early (Save-AutoBucketCountEarly)

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

while (-not $bucketRunSucceeded -and -not $reportCannotFit) {

  # Reset results on each (re)run so we don't keep partial data from a failing bucket count
  $ResultAll = @()
  Reset-AutoBucketMeasure   # #640: the measured result belongs to the count the report finally ran with
  $__abSplitUsed = $false   # #640: a bucket had to be split this run -> the next run starts from a higher count
  $__abSplitBuckets = 0     # #722: how many buckets of this count had to be split
  $__abSplitWorking = 0     # #722: the finest count a split slice SUCCEEDED at (the size that worked)
  # #737: THIS report's own evidence, never another's -- per split bucket whether the service SAID it was too large, then
  # the rows / bytes / seconds its sub-slices took together (Get-RACountAfterSplit sizes the next run from it); and how many
  # slices met a busy backend (retried / deferred) -- such a run is never taken as "far below" to size down from.
  $__abSplitCause = @{}
  $__abSplitSlices = @{}
  $__abBusySlices = 0
  $__abMemSplit = 0         # slices whose rows did not fit in memory at once -- asked again smaller (Add-RAStreamBucketGuarded)
  $__abMemRoots = @{}       # the buckets split because the worker had no memory for them (read or processing) -- sized from what it held
  Reset-RAProof
  # count timing: each run of the report's slices is framed by its own two counts (a run again with more slices counts again)
  Reset-RAReadCounts
  # (#831 B: a part already in keeps its rows -- it runs no slice again)
  if ($script:RAStreamOn -and -not ($null -ne $script:RAScaleSplit -and $script:RAScaleSplit.Done)) { Clear-RAStreamReport -Stream $script:RAStream -Why 'the report runs again with more query slices'; if ($null -ne $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 }; if ($null -ne $global:RA_ColumnFillThisRun) { $global:RA_ColumnFillThisRun.Remove([string]$ReportName) } }

  Write-Info ("query contains placeholder '{0}' and bucketing is enabled. Using {1} bucket(s)." -f $effectivePlaceholder,$bucketCountToUse)

  $needEscalation = $false
  # v2.2.277 -- track buckets that timed out at 900s deterministically. Instead
  # of throwing away ALL successful buckets and restarting at higher bucket
  # count (the v2.2.272 escalation), record failed indices and sub-bucket only
  # those after the main loop. Lossless; preserves successful buckets' rows.
  $failedBucketIndices = New-Object System.Collections.Generic.List[int]
  # Buckets whose failure was the API throttling / being unavailable, and which exhausted their in-loop
  # retries. They are retried again AFTER the other buckets, at the SAME size -- by then the throttle
  # window has usually passed. Never split: splitting multiplies calls against a throttling API.
  $deferredBucketIndices = New-Object System.Collections.Generic.List[int]
  Reset-RABucketLoss   # audit #62 -- per-report, so one report's losses never leak into the next

  # #401 -- set once a bucket returned the COMPLETE result (see $bucketIsComplete below).
  $completeBucketDone = $false
  # #753 SEVERAL PARTS AT A TIME: while a part is processed, the advanced-hunting requests of the next parts are already on
  # their way (RA-PartsInParallel.ps1). The parts are still processed here one by one, in order -- only the requests overlap.
  Reset-RAPartsInParallel -PartCount ([int]$bucketCountToUse)
  # #831 B: one part of a split report runs ITS slices [From, To) of the same count; a part already in runs none
  $__soFrom = 0; $__soTo = [int]$bucketCountToUse
  if ($null -ne $script:RAScaleSplit) {
      $__soFrom = [int]$script:RAScaleSplit.From; $__soTo = [int]$script:RAScaleSplit.To
      if ($script:RAScaleSplit.Done) { $__soTo = $__soFrom }
  }
  for ($b = $__soFrom; $b -lt $__soTo; $b++) {

      # #882: a queue worker whose run is over sends no further query (and writes nothing more)
      if ($script:RAScaleRole -eq 'worker') { Assert-RAScaleOutWorkerLive -Where ('before query slice {0} of {1}' -f ($b + 1), $ReportName) }

      # #401 -- ONE COMPLETE BUCKET IS THE WHOLE REPORT. With the EG-side bucket filter off AND every CL
      # binding replicated (Resolve-ProfileCLLetBlocks), each bucket query IS the unbucketed query: running
      # the other buckets returns the same rows again -- which a Summary merge would then ADD UP -- and
      # repeats the full Exposure-Graph work for nothing.
      if ($completeBucketDone) {
          Write-Info ("bucket {0}..{1}/{1}: skipped -- bucket {2} already returned the complete result (EG-side filter off, CL lookups replicated)" -f ($b + 1), $bucketCountToUse, $b)
          break
      }

      $bucketNo = $b + 1
      # count timing C1: the source's count just BEFORE the report's first query slice is read
      if ($null -eq $script:RAReadCounts['Before']) { Invoke-RAReadCount -When Before -Query $Query -ReportName $ReportName }
      $bucketFilter = New-BucketFilterKql -BucketCount $bucketCountToUse -BucketIndex $b -ReportName $ReportName
      # #401 -- whether THIS query was built without the EG-side filter. The flag is raised by
      # Resolve-ProfileCLLetBlocks INSIDE the call below, so on an AutoBucket cache hit (no probe) the first
      # bucket's query was already built WITH the filter: that bucket is a correct slice, not the whole.
      $egFilterOffAtBuild = [bool]$script:_SkipEGBucketForCrossDomain
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
      # #722 SPLIT AT ONCE: a slice the service answers as TOO LARGE is split on the FIRST such answer -- the same request
      # at the same size cannot succeed (live 2026-10-16: 8/8 buckets of two Detailed reports failed 3 probes each, ~12 min
      # of pauses per report, then every 4-way sub-slice succeeded). 1 = no re-probe; SI_BucketOverflowRetries still
      # overrides (Get-RABucketOverflowStep). Throttle / 5xx / timeout keep their retries below (working rule 4).
      $bucketOverflowRetries  = if ($null -ne $global:SI_BucketOverflowRetries) {
          [int]$global:SI_BucketOverflowRetries
      } else { 1 }
      $bucketAttempt          = 0
      $bucketOverflowAttempt  = 0
      $bucketAttemptDone      = $false
      $resp                   = $null

      while (-not $bucketAttemptDone) {
          $bucketAttempt++
          $__abSliceSw = [System.Diagnostics.Stopwatch]::StartNew()   # #737: the slice's time is measured like its rows
          try {
              $resp = Invoke-GraphHuntingQuery -Query $thisQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
              $__abSliceSw.Stop()
              if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'hunt' -Seconds $__abSliceSw.Elapsed.TotalSeconds }   # #873 A
              Tick ("hunting query bucket {0}/{1}" -f $bucketNo, $bucketCountToUse)
              $bucketAttemptDone = $true
          } catch {
              # The bare message first (classifiers below still see it), then the service's code and message.
              $errMsg = Get-SIKqlErrorSummary -ErrorRecord $_

              # 0) NO SLICE COUNT CAN MAKE THIS REPORT FIT -- decided once, here, before a single retry, escalation
              #    or sub-slice is spent on it. Either the hunting layer already knew from the sizes (nothing was
              #    sent), or the service has just refused this request for its size and what more slices could
              #    still remove from it is a sliver. Every other slice carries the same lookup, so each would end
              #    the same way: the report is failed as a whole below and the run goes on with the next report.
              $__cannotFit = if (Test-RAReportCannotRunError -Err $_) { [string]$_.Exception.Message } else { Get-RARefusedRequestVerdict -Err $_ }
              if ($__cannotFit) {
                  $reportCannotFit   = [string]$__cannotFit
                  # #638: a part of a report never goes out as the report -- what its earlier slices wrote is removed
                  if ($script:RAStreamOn) { try { Clear-RAStreamReport -Stream $script:RAStream -Why 'the report is not in this run' } catch { Set-RAReportRowsHeld -Cause $_.Exception.Message } }
                  $bucketAttemptDone = $true
                  $resp              = $null
              }
              # 1) Overflow -> retry SAME bucket N times before escalating. The XDR
              # backend's "preempted ... high CPU/memory" is often transient load,
              # not real data overflow. Only escalate when we've seen the overflow
              # repeatedly for THIS bucket.
              # #880: a busy answer ("preempted ... high CPU and/or memory") carries the overflow wording but is NOT a size
              # answer -- it goes to 2) below (Get-RABucketFailureAction -> Retry: backoff + re-auth, then the late retry), never split
              elseif ((Test-IsBucketOverflowError $_) -and -not (Test-RABucketBusyAnswer -Err $_)) {
                  $bucketOverflowAttempt++
                  # #737: "preempted ... high CPU and/or memory" is a busy backend -- sent once more at the same size first
                  $__ovBusy = Test-RABucketBusyAnswer -Err $_
                  if ($__ovBusy) { $__abBusySlices++ }
                  $__abSplitCause[[int]$b] = (-not $__ovBusy)
                  $__ovStep = Get-RABucketOverflowStep -OverflowAttempt $bucketOverflowAttempt -ProbeAttempts $bucketOverflowRetries -Busy:$__ovBusy
                  if ($__ovStep.Action -eq 'Probe') {
                      # Only when SI_BucketOverflowRetries asks for re-probes (default: none -- #722 splits at once)
                      Write-Info ("bucket {0}/{1}: re-probing with current shard size (attempt {2}/{3}, pausing {4}s)." -f `
                        $bucketNo, $bucketCountToUse, $bucketOverflowAttempt, $bucketOverflowRetries, $__ovStep.PauseSeconds)
                      Start-Sleep -Seconds $__ovStep.PauseSeconds
                      # Loop continues; same bucket retried at same bucketCountToUse.
                  } elseif ($bucketCountToUse -ge $capBucket) {
                      # 🔴 AT THE ESCALATION CAP, SPLIT THIS SLICE INSTEAD OF GIVING UP ON THE REPORT.
                      # Escalating here used to hit the cap check below and `break` -- keeping the buckets
                      # before this one and silently never running the rest. The sub-bucket pass is
                      # exactly the tool for a slice that is still too large: it splits only THIS bucket,
                      # finer, while every other bucket runs normally.
                      Write-Warn2 ("bucket {0}/{1}: too large at the escalation cap ({2}) -- queueing this bucket for the sub-bucket pass (finer slices) and continuing with the remaining buckets." -f `
                        $bucketNo, $bucketCountToUse, $capBucket)
                      [void]$failedBucketIndices.Add($b)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  } else {
                      $lastBucketRunError = $errMsg
                      # v2.2.380 -- record actual rows-per-bucket that failed,
                      # so the escalation block can size the NEXT attempt from
                      # real overflow data instead of guessing (option C).
                      $_snapshot = if ($script:_LastHybridSnapshotRowCount) { [int]$script:_LastHybridSnapshotRowCount } else { 0 }
                      if ($_snapshot -gt 0 -and $bucketCountToUse -gt 0) {
                          $_failedRpb = [int][Math]::Ceiling($_snapshot / [double]$bucketCountToUse)
                          $script:_LastFailedRowsPerBucketByReport[$ReportName] = $_failedRpb
                          Write-Info ("bucket {0}/{1}: too large for the service (~{2} rows/bucket) -- split into smaller slices at once (sub-bucket pass after the main loop; rows already retrieved are kept)." -f `
                            $bucketNo, $bucketCountToUse, $_failedRpb)
                      } else {
                          Write-Info ("bucket {0}/{1}: too large for the service -- split into smaller slices at once (sub-bucket pass after the main loop; rows already retrieved are kept)." -f `
                            $bucketNo, $bucketCountToUse)
                      }
                      # #640 SELF-HEALING (owner 2026-10-13: "better to small than too big so they breaks. self-healing,
                      # retries"): an overflow splits THAT bucket (the sub-bucket pass) and re-runs only it -- the other
                      # buckets' rows are kept; the report is no longer re-run from the start at a higher count. The run
                      # then remembers a higher count for the next run (below, $__abSplitUsed).
                      [void]$failedBucketIndices.Add($b)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
              }
              # 2) Everything else is routed by CAUSE (Get-RABucketFailureAction), so a bucket is never
              #    written off while a recovery is left:
              #      Split  -> too big / too slow: queue for the sub-bucket pass (smaller, lossless)
              #      Retry  -> API throttled / unavailable / token expiry: backoff + re-auth, same size;
              #                when the budget runs out, DEFER to a late retry after the other buckets
              #                (the throttle window has usually passed by then) -- never split, which
              #                would only multiply the calls against a throttling API
              #      Defect -> the query is wrong: fail now and say so (working rule 4)
              #      Fail   -> unrecognised: recorded as lost, loudly
              #    The #99/#106 platform cancellations used to fall through every classifier here
              #    ("cancelled" is not "canceled", and a 400 is not transient) and were recorded lost
              #    WITHOUT ever being resized, although the hunting layer had already flagged them as
              #    too large. The shared classifier is what makes that impossible now.
              else {
                  $bucketAction = Get-RABucketFailureAction -Err $_ -AllTimedOut ([bool]$script:_LastGraphHuntingAllTimedOut)
                  if ($bucketAction -ne 'Split' -and $bucketAction -ne 'Defect' -and $bucketAction -ne 'Absent') { $__abBusySlices++ }
                  if ($bucketAction -eq 'Split' -and (Test-RABucketOutOfMemory -Err $_)) {
                      # the worker could not hold this slice's answer: the same rows are asked again in smaller slices, split
                      # until they fit, and the next run starts finer (a split for size, as a slice the service called too large)
                      Write-Warn2 ("query slice {0}/{1}: its answer is too large for this worker's memory -- nothing of it is kept; the same rows are asked again in smaller slices after the other slices" -f $bucketNo, $bucketCountToUse)
                      $__abMemSplit++; if (Get-Command -Name Stop-RAPartsAheadForMemory -ErrorAction SilentlyContinue) { $null = Stop-RAPartsAheadForMemory }
                      $__abMemRoots[[int]$b] = $true
                      $__abSplitCause[[int]$b] = $true
                      [void]$failedBucketIndices.Add($b)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
                  elseif ($bucketAction -eq 'Split') {
                      Write-Warn2 ("bucket {0}/{1}: too large or too slow for the backend -- queueing for the sub-bucket pass after the main loop (smaller slices; rows already retrieved are kept). Error: {2}" -f `
                        $bucketNo, $bucketCountToUse, $errMsg)
                      # #737: a 502 / the 900 s ceiling does not say WHY -- the sub-slices' own answer decides the next count
                      $__abSplitCause[[int]$b] = (Test-RABucketExplicitTooLarge -Err $_)
                      [void]$failedBucketIndices.Add($b)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
                  elseif ($bucketAction -eq 'Retry') {
                      if ($bucketAttempt -ge $bucketTransientRetries) {
                          Write-Warn2 ("bucket {0}/{1}: the API is still throttling or unavailable after {2} retry attempt(s) -- deferring this bucket to a late retry after the remaining buckets (same size). Error: {3}" -f `
                            $bucketNo, $bucketCountToUse, $bucketTransientRetries, $errMsg)
                          [void]$deferredBucketIndices.Add($b)
                          $bucketAttemptDone = $true
                          $resp              = $null
                      } else {
                          $sleepSec = Get-RABucketRetryDelaySeconds -Attempt $bucketAttempt -Err $_
                          $__whyRetry = if (Test-RABucketBusyAnswer -Err $_) { 'Defender is busy (the query was preempted for its load, not refused for its size) -- asked again at the same size' } else { 'the API is throttling or had an issue (token expiry / 429 / 503 / 504)' }
                          Write-Warn2 ("bucket {0}/{1}: {6}. Re-auth + retry attempt {2}/{3} after {4}s. Error: {5}" -f `
                            $bucketNo, $bucketCountToUse, $bucketAttempt, $bucketTransientRetries, $sleepSec, $errMsg, $__whyRetry)
                          Start-Sleep -Seconds $sleepSec
                          Invoke-RABucketReauth
                          # Loop continues; bucketAttempt now incremented, retry same bucket.
                      }
                  }
                  elseif ($bucketAction -eq 'Absent') {
                      # No Microsoft Defender XDR in this tenant: this report has no data source here. Not a lost
                      # bucket -- nothing exists to retrieve (live 2026-10-06, Community rehearsal).
                      Write-Info ("bucket {0}/{1}: not applicable -- {2}" -f $bucketNo, $bucketCountToUse, $errMsg)
                      $script:RANotApplicableWhy = [string]$errMsg   # #709: kept for the report's cause (Complete-RAReportCompleteness)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
                  else {
                      $whyLost = if ($bucketAction -eq 'Defect') { 'query defect -- the query must be fixed, re-running fails identically' } else { 'query failed' }
                      Write-Err2 ("query failed for bucket {0}/{1}: {2}" -f $bucketNo, $bucketCountToUse, $errMsg)
                      # #62 LOSS PATH 3 -- only a DEFECT or an unrecognised failure reaches here now.
                      Add-RABucketLoss ("bucket {0}/{1}: {2} -- {3}" -f $bucketNo, $bucketCountToUse, $whyLost, $errMsg)
                      $bucketAttemptDone = $true
                      $resp              = $null
                  }
              }
          }
      }

      if ($needEscalation) { break }
      if ($reportCannotFit) { break }     # no slice count can fit: the remaining slices are not tried
      # count timing C2: the source's count just AFTER the report's last query slice is read -- before that slice is
      # converted, scored and written (a slice that returned the whole report, #401, is its last)
      if ($b -eq ($__soTo - 1) -or ($null -ne $resp -and $egFilterOffAtBuild -and [bool]$script:_RACrossDomainReplicated)) { Invoke-RAReadCount -When After -Query $Query -ReportName $ReportName }
      # #753: this part's request is answered -- the next parts are asked ahead while it is processed. Not for a part built
      # without the slice filter (#401: the next part would be the whole report again) nor once the lake answers.
      if (-not [bool]$script:_SkipEGBucketForCrossDomain -and -not [bool]$script:RALakeAnswered) {
          Invoke-RAPartsAhead -After $b -PartCount ([int]$bucketCountToUse) -Query $Query -ReportName $ReportName -End $__soTo
      }
      if ($null -eq $resp) { continue }   # bucket skipped (transient exhausted or other error)

      # #401 -- built without the EG-side filter AND with every CL lookup replicated = the complete result.
      $bucketIsComplete = ($egFilterOffAtBuild -and [bool]$script:_RACrossDomainReplicated)

      # v2.1.202 LA-direct marker check (see matching block further down / Invoke-GraphHuntingQuery).
      if ($null -ne $resp -and $resp -is [pscustomobject] -and $resp.PSObject.Properties['_SIDirectRows']) {
          $bucketResult = @($resp._SIDirectRows)
          if (@($bucketResult).Count -eq 0) {
              Write-Info ("bucket {0}/{1}: no results" -f $bucketNo, $bucketCountToUse)
              # #833: an empty slice is measured too (no rows, its time) -- a report that returns nothing can come down to 1
              Add-AutoBucketMeasure -Rows 0 -Seconds ([double]$__abSliceSw.Elapsed.TotalSeconds)
              if ($bucketIsComplete) { $ResultAll = @(); $completeBucketDone = $true; Add-RAStreamBucket -Rows @() -Bucket ('{0}/{1}' -f $bucketNo, $bucketCountToUse) -Complete }
              elseif ($script:RAStreamOn) { Add-RAStreamBucket -Rows @() -Bucket ('{0}/{1}' -f $bucketNo, $bucketCountToUse) }   # #673: a slice the Defender filter emptied is still booked
              continue
          }
      } else {
          $rawResults = $null
          if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }

          if ($null -eq $rawResults) {
              Write-Info ("bucket {0}/{1}: no results" -f $bucketNo, $bucketCountToUse)
              # #833: an empty slice is measured too (no rows, its request, its time)
              Add-AutoBucketMeasure -Rows 0 -RequestBytes $(if ([long]$script:_LastHybridInlineBytes -gt 0) { [long]$script:_LastHybridInlineBytes + [long]$script:_LastHybridQueryBodyOverheadBytes } else { 0 }) `
                -RequestShape $(if ([long]$script:_LastHybridInlineBytes -gt 0) { $script:_RAHybridLastRequest } else { $null }) -Seconds ([double]$__abSliceSw.Elapsed.TotalSeconds)
              if ($bucketIsComplete) { $ResultAll = @(); $completeBucketDone = $true; Add-RAStreamBucket -Rows @() -Bucket ('{0}/{1}' -f $bucketNo, $bucketCountToUse) -Complete }
              elseif ($script:RAStreamOn) { Add-RAStreamBucket -Rows @() -Bucket ('{0}/{1}' -f $bucketNo, $bucketCountToUse) }   # #673: a slice the Defender filter emptied is still booked
              continue
          }

          Tock
          try {
              $__phConvSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
              $bucketResult = ConvertTo-PSObjectDeep $rawResults -StripOData -CastPrimitiveArrays
              if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'convert' -Seconds $__phConvSw.Elapsed.TotalSeconds }
          } catch {
              if ((Test-RABucketOutOfMemory -Err $_) -and -not $bucketIsComplete) {
                  # no memory to convert this slice's answer: the same rows in smaller slices (as for a read the worker cannot hold)
                  $rawResults = $null; $resp = $null
                  [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                  Write-Warn2 ("query slice {0}/{1}: its answer is too large for this worker's memory -- nothing of it is kept; the same rows are asked again in smaller slices after the other slices" -f $bucketNo, $bucketCountToUse)
                  $__abMemSplit++; if (Get-Command -Name Stop-RAPartsAheadForMemory -ErrorAction SilentlyContinue) { $null = Stop-RAPartsAheadForMemory }
                  $__abMemRoots[[int]$b] = $true
                  $__abSplitCause[[int]$b] = $true
                  [void]$failedBucketIndices.Add($b)
                  continue
              }
              Write-Err2 ("result conversion failed for bucket {0}/{1}: {2}" -f $bucketNo, $bucketCountToUse, $_.Exception.Message)
              # #62 LOSS PATH 4 -- the query SUCCEEDED and the rows were still lost. Easily the most
              # deceptive of the six: nothing upstream reports a failure at all.
              Add-RABucketLoss ("bucket {0}/{1}: query succeeded but result conversion threw -- {2}" -f $bucketNo, $bucketCountToUse, $_.Exception.Message)
              continue
          }
      }
      $bucketCount  = ($bucketResult | Measure-Object).Count
      Tick ("result conversion (bucket {0}/{1})" -f $bucketNo, $bucketCountToUse)

      Write-Info ("bucket {0}/{1}: {2} rows" -f $bucketNo, $bucketCountToUse, $bucketCount)
      # #640: measure only (rows, estimated answer bytes, request bytes) -- the rows themselves are not touched here
      # #697 (2): the request is measured from what THIS bucket really sent (its shape: the split lookups and the rest)
      Add-AutoBucketMeasure -Rows $bucketCount -Sample @($bucketResult | Select-Object -First 20) -RequestBytes $(if ([long]$script:_LastHybridInlineBytes -gt 0) { [long]$script:_LastHybridInlineBytes + [long]$script:_LastHybridQueryBodyOverheadBytes } else { 0 }) `
        -RequestShape $(if ([long]$script:_LastHybridInlineBytes -gt 0) { $script:_RAHybridLastRequest } else { $null }) -Seconds ([double]$__abSliceSw.Elapsed.TotalSeconds)
      # #641: A SHORT BUCKET IS CAUGHT. The source can answer short with no error (measured at a large install: one report's
      # rows swung 935 -> 25,267 -> 1,330 on the same code). The bucket's own count (the same query, '| count') is asked;
      # fewer rows than it = the bucket is asked again once, and if it stays short its loss is recorded (the report is then
      # not complete -- never shipped as whole). SI_RA_BucketCountCheck = off switches it off.
      # #753: only a part near the source's row limit is counted on its own (Test-RABucketCountWanted; 'all' = every part);
      # the report's own count (Get-RAReportExpectedRows) still checks every report once.
      # #673 plan B: the source counts the rows BEFORE the Defender filter -- compared with what the slice retrieved before it
      $__bcRows = Get-RADfcCountedRows -Rows ([long]$bucketCount)
      if (Test-RABucketCountWanted -Rows $__bcRows) {
          $__bc = Test-RABucketRowCount -Query $thisQuery -Rows $__bcRows
          if ($__bc.Short) {
              Write-Warn2 ("bucket {0}/{1}: the source counts {2} row(s) but returned {3} -- asking it again" -f $bucketNo, $bucketCountToUse, $__bc.Expected, $__bcRows)
              $__dfcKeep = $script:RADfcLast
              # #697 (3): a part asked again because it came back short gets a FRESH key answer, never the remembered one
              if (Get-Command -Name Clear-RALookupKeyAnswerMemo -ErrorAction SilentlyContinue) { Clear-RALookupKeyAnswerMemo }
              try {
                  $__again = Get-RABucketRows -Resp (Invoke-GraphHuntingQuery -Query $thisQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries)
                  $__againRows = Get-RADfcCountedRows -Rows ([long]@($__again.Rows).Count)
                  if ($__again.Ok -and $__againRows -gt $__bcRows) { $bucketResult = @($__again.Rows); $bucketCount = $bucketResult.Count; $__bcRows = $__againRows }
                  else { $script:RADfcLast = $__dfcKeep }   # the first answer is kept -- and its numbers
              } catch { $script:RADfcLast = $__dfcKeep; Write-Warn2 ("bucket {0}/{1}: asking again failed -- {2}" -f $bucketNo, $bucketCountToUse, $_.Exception.Message) }
              if ($__bcRows -lt $__bc.Expected) {
                  Write-Err2 ("bucket {0}/{1}: still short -- {2} of {3} row(s). The missing findings are unknown for this run, not resolved." -f $bucketNo, $bucketCountToUse, $__bcRows, $__bc.Expected)
                  Add-RABucketLoss ("bucket {0}/{1}: the source returned {2} of the {3} row(s) it counts" -f $bucketNo, $bucketCountToUse, $__bcRows, $__bc.Expected)
              } else { Write-Info ("bucket {0}/{1}: complete on the second answer -- {2} rows" -f $bucketNo, $bucketCountToUse, $bucketCount) }
          }
      }
      if ($bucketIsComplete) {
          # #401 -- rows from an earlier bucket are a slice of these (built before the filter went off); keep one copy.
          if (@($ResultAll).Count -gt 0) { Write-Info ("bucket {0}/{1}: complete result -- replaces {2} row(s) from earlier bucket(s)" -f $bucketNo, $bucketCountToUse, @($ResultAll).Count) }
          $ResultAll = @()
          $completeBucketDone = $true
      }
      if ($script:RAStreamOn) {
          $__slIn = Add-RAStreamBucketGuarded -Rows $bucketResult -Bucket ('{0}/{1}' -f $bucketNo, $bucketCountToUse) -Complete:$bucketIsComplete
          $bucketResult = $null
          if (-not $__slIn) {
              # not enough memory for this slice's rows at once: the sub-bucket pass asks the same rows in smaller slices,
              # and the finer count is kept for the next run (a split for size, as a slice the service called too large)
              $__abMemSplit++; if (Get-Command -Name Stop-RAPartsAheadForMemory -ErrorAction SilentlyContinue) { $null = Stop-RAPartsAheadForMemory }
              $__abMemRoots[[int]$b] = $true
              $__abSplitCause[[int]$b] = $true
              [void]$failedBucketIndices.Add($b)
              continue
          }
      }
      else { $ResultAll = @($ResultAll) + @($bucketResult) }   # one join per bucket, never += per row
      # A slice succeeded at this count: keep the count now, so a run stopped part-way still leaves it for the next run
      # (only ever up, not confirmed -- the end of the report writes and confirms it as before)
      if ([bool]$global:AutoBucketCount -and $queryKey -and [int]$bucketCountToUse -gt [int]$__abEarlySavedAt) {
          $__abEarlySavedAt = [int]$bucketCountToUse
          try {
              # #833: said as what it is -- kept in case the run stops; the end of the report says the count kept for the next run
              if (Save-AutoBucketCountEarly -QueryKey $queryKey -Count ([int]$bucketCountToUse) -Incomplete:($null -ne $script:_RABucketLoss -and $script:_RABucketLoss.Count -gt 0)) { Write-Info ("bucket sizing: '{0}' -- {1} bucket(s) kept in case the run stops part-way" -f $ReportName, $bucketCountToUse) }
          } catch { Write-Warn2 ("bucket sizing: the count of '{0}' could not be kept yet ({1}); it is kept when the report is done" -f $ReportName, $_.Exception.Message) }
      }
  }
  # #753: the main pass is over -- what was asked ahead and not read is dropped (the late retry and the sub-slices run one at a time)
  Stop-RAPartsInParallel
  # count timing C2: a main pass whose last slice did not take it (it ended before its last slice) takes it here
  if (-not $needEscalation -and -not $reportCannotFit -and $null -ne $script:RAReadCounts['Before'] -and $null -eq $script:RAReadCounts['After']) { Invoke-RAReadCount -When After -Query $Query -ReportName $ReportName }

  # No slice count can fit: leave the escalation loop too -- no late retry, no sub-slices, no larger count.
  if ($reportCannotFit) { break }

  # #401 -- a complete bucket supersedes every earlier bucket, failed or deferred ones included.
  if ($completeBucketDone) {
      $failedBucketIndices.Clear()
      $deferredBucketIndices.Clear()
      Reset-RABucketLoss
  }

  if ($needEscalation) {

      if ($bucketCountToUse -ge $capBucket) {
          Write-Err2 ("bucket escalation reached cap {0}. Unable to complete report '{1}'. Last error: {2}" -f `
            $capBucket, $ReportName, $lastBucketRunError)
          # Safety net: an overflow AT the cap is now split rather than escalated, so this should not be
          # reached -- but if it is, every bucket from the failing one onward was never run, and the
          # report must not be mistaken for complete.
          for ($lb = [int]$b; $lb -lt [int]$bucketCountToUse; $lb++) {
              Add-RABucketLoss ("bucket {0}/{1}: never run -- escalation cap {2} reached on bucket {3}" -f ($lb + 1), $bucketCountToUse, $capBucket, ($b + 1))
          }
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

  # LATE-RETRY PASS -- the API was throttling or unavailable for these buckets and their in-loop
  # retries ran out. Every other bucket has run since, which is usually long enough for a throttle
  # window to pass, so each is retried at the SAME size with a longer backoff + re-auth. A bucket that
  # now proves too large moves to the sub-bucket pass below; only an exhausted late retry is lost.
  # #831 B: a part numbers its late retries and its sub-slices in their own bands, so the report's final order is the
  # single job's (every main slice, then every late retry, then the sub-slices)
  if ($null -ne $script:RAScaleSplit -and $script:RAStreamOn -and $deferredBucketIndices.Count -gt 0) { $script:RAStream.Seq = Get-RAScaleOutSplitSeqBase -Ordinal ([int]$script:RAScaleSplit.Ordinal) -Part ([int]$script:RAScaleSplit.Part) -Parts ([int]$script:RAScaleSplit.Parts) -Band late }
  if ($deferredBucketIndices.Count -gt 0) {
      $lateRetries =if ($null -ne $global:SI_BucketLateRetries) { [int]$global:SI_BucketLateRetries } else { 3 }
      Write-Warn2 ("late retry: {0} bucket(s) of '{1}' failed because the API was throttling or unavailable -- retrying each at the same size (up to {2} attempt(s) a pass, longer backoff, re-auth; another pass while a pass recovers a slice). Rows already retrieved are kept." -f `
        $deferredBucketIndices.Count, $ReportName, $lateRetries)
      # #882 PASSES WHILE THE RUN MAKES PROGRESS (Step-RALatePasses): pass 1 is the late retry as before; a slice still refused
      # is asked again in a next pass only while the pass before recovered a slice -- a pass that recovers nothing stops it
      $__lp = New-RALatePasses -Pending @($deferredBucketIndices.ToArray())
      $__lpErr = @{}; $__lpBusy = @{}
      while (Step-RALatePasses -State $__lp) {
      if ($__lp.Pass -gt 1) {
          Write-Warn2 ("late retry: pass {0} of '{1}' -- {2} slice(s) still refused; the pass before recovered {3}, so they are asked again (a pass that recovers nothing ends it)" -f `
            $__lp.Pass, $ReportName, @($__lp.Current).Count, $__lp.RecoveredLastPass)
      }
      foreach ($db in @($__lp.Current)) {
          if ($script:RAScaleRole -eq 'worker') { Assert-RAScaleOutWorkerLive -Where ('before the late retry of slice {0} of {1}' -f ($db + 1), $ReportName) }   # #882
          $dbNo = $db + 1
          $dbQuery = Replace-BucketFilterBlock -Query $Query -BucketFilterKql (New-BucketFilterKql -BucketCount $bucketCountToUse -BucketIndex $db -ReportName $ReportName)
          $dbDone = $false
          $dbResult = 'gone'
          for ($la = 1; $la -le $lateRetries -and -not $dbDone; $la++) {
              # Longer than the in-loop backoff on purpose: this bucket already failed its fast retries.
              $lateSleep = Get-RABucketRetryDelaySeconds -Attempt ($la + 1) -BaseSeconds 60 -MaxSeconds 600
              Write-Info ("late retry: bucket {0}/{1} attempt {2}/{3} after {4}s" -f $dbNo, $bucketCountToUse, $la, $lateRetries, $lateSleep)
              Start-Sleep -Seconds $lateSleep
              Invoke-RABucketReauth
              $script:_CurrentBucketCount = $bucketCountToUse
              $script:_CurrentBucketIndex = $db
              try {
                  $__abLateSw = [System.Diagnostics.Stopwatch]::StartNew()   # #880: a recovered slice is measured like every other
                  $dbResp = Invoke-GraphHuntingQuery -Query $dbQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
                  $__abLateSw.Stop()
                  if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'hunt' -Seconds $__abLateSw.Elapsed.TotalSeconds }   # #873 A
                  $conv = Get-RABucketRows -Resp $dbResp
                  $dbResp = $null
                  if (-not $conv.Ok -and $conv.ContainsKey('OutOfMemory') -and [bool]$conv.OutOfMemory) {
                      # no memory to convert it: the same rows in smaller slices (the sub-bucket pass)
                      $conv = $null; [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                      Write-Warn2 ("late retry: query slice {0}/{1}: its answer is too large for this worker's memory -- the same rows are asked again in smaller slices" -f $dbNo, $bucketCountToUse)
                      $__abSplitCause[[int]$db] = $true; $__abMemSplit++; $__abMemRoots[[int]$db] = $true
                      [void]$failedBucketIndices.Add($db)
                  } elseif (-not $conv.Ok) {
                      Write-Err2 ("late retry: result conversion failed for bucket {0}/{1}: {2}" -f $dbNo, $bucketCountToUse, $conv.Error)
                      Add-RABucketLoss ("bucket {0}/{1}: late retry succeeded but result conversion threw -- {2}" -f $dbNo, $bucketCountToUse, $conv.Error)
                  } else {
                      Write-Info ("late retry: bucket {0}/{1} recovered -- {2} rows" -f $dbNo, $bucketCountToUse, @($conv.Rows).Count)
                      # #880: measured as in the main pass, so a report whose busy slices were all answered at their own size is
                      # still measured whole (the count may then come down from it)
                      Add-AutoBucketMeasure -Rows ([long]@($conv.Rows).Count) -Sample @(@($conv.Rows) | Select-Object -First 20) -Seconds ([double]$__abLateSw.Elapsed.TotalSeconds) `
                        -RequestBytes $(if ([long]$script:_LastHybridInlineBytes -gt 0) { [long]$script:_LastHybridInlineBytes + [long]$script:_LastHybridQueryBodyOverheadBytes } else { 0 }) `
                        -RequestShape $(if ([long]$script:_LastHybridInlineBytes -gt 0) { $script:_RAHybridLastRequest } else { $null })
                      if ($script:RAStreamOn) {
                          # the memory guard as for every other slice: rows it cannot hold at once are asked again smaller
                          if (-not (Add-RAStreamBucketGuarded -Rows @($conv.Rows) -Bucket ('late:{0}/{1}' -f $dbNo, $bucketCountToUse))) {
                              $__abSplitCause[[int]$db] = $true; $__abMemSplit++; $__abMemRoots[[int]$db] = $true
                              [void]$failedBucketIndices.Add($db)
                          } else { $dbResult = 'ok' }
                      }
                      else { $ResultAll = @($ResultAll) + @($conv.Rows); $dbResult = 'ok' }   # one join per bucket, never += per row
                  }
                  $dbDone = $true
              } catch {
                  $dbErr = $_.Exception.Message
                  $dbAction = Get-RABucketFailureAction -Err $_ -AllTimedOut ([bool]$script:_LastGraphHuntingAllTimedOut)
                  if ($dbAction -eq 'Split') {
                      Write-Warn2 ("late retry: bucket {0}/{1} is now failing as too large -- moving it to the sub-bucket pass. Error: {2}" -f $dbNo, $bucketCountToUse, $dbErr)
                      $__abSplitCause[[int]$db] = (Test-RABucketExplicitTooLarge -Err $_)
                      if (Test-RABucketOutOfMemory -Err $_) { $__abMemSplit++; $__abMemRoots[[int]$db] = $true }
                      [void]$failedBucketIndices.Add($db)
                      $dbDone = $true
                  } elseif ($dbAction -eq 'Retry' -and $la -lt $lateRetries) {
                      Write-Warn2 ("late retry: bucket {0}/{1} attempt {2}/{3} -- API still throttling/unavailable: {4}" -f $dbNo, $bucketCountToUse, $la, $lateRetries, $dbErr)
                  } elseif ($dbAction -eq 'Retry') {
                      # #882: this pass's attempts ran out -- asked again in the next pass while the run makes progress; lost only
                      # when a whole pass recovers nothing (below)
                      Write-Warn2 ("late retry: bucket {0}/{1} still refused after pass {2} -- asked again in the next pass if this pass recovers a slice. Error: {3}" -f $dbNo, $bucketCountToUse, $__lp.Pass, $dbErr)
                      $__lpErr[[int]$db] = $dbErr; $__lpBusy[[int]$db] = [bool](Test-RABucketBusyAnswer -Err $_)
                      $dbResult = 'retry'
                      $dbDone = $true
                  } else {
                      Write-Err2 ("late retry: bucket {0}/{1} could not be retrieved: {2}" -f $dbNo, $bucketCountToUse, $dbErr)
                      Add-RABucketLoss ("bucket {0}/{1}: the late retry failed and cannot recover it -- {2}" -f $dbNo, $bucketCountToUse, $dbErr)
                      $dbDone = $true
                  }
              }
          }
          Set-RALatePassResult -State $__lp -Index ([int]$db) -Result $dbResult
      }
      }
      # #882: a whole pass recovered nothing -- what is still refused is a named loss (the report is NOT COMPLETE and keeps its
      # last complete result, #877); never fewer rows silently
      foreach ($db in @($__lp.Left)) {
          $__lateWhy = if ([bool]$__lpBusy[[int]$db]) { 'Defender kept refusing it as busy (preempted for its load) through' } else { 'API throttling/unavailable survived' }
          Write-Err2 ("late retry: bucket {0}/{1} could not be retrieved -- pass {2} recovered no slice: {3}" -f ($db + 1), $bucketCountToUse, $__lp.Pass, [string]$__lpErr[[int]$db])
          Add-RABucketLoss ("bucket {0}/{1}: {3} the in-loop AND late retries ({4} late pass(es); the last recovered no slice) -- {2}" -f ($db + 1), $bucketCountToUse, [string]$__lpErr[[int]$db], $__lateWhy, $__lp.Pass)
      }
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
  if ($null -ne $script:RAScaleSplit -and $script:RAStreamOn -and $failedBucketIndices.Count -gt 0) { $script:RAStream.Seq = Get-RAScaleOutSplitSeqBase -Ordinal ([int]$script:RAScaleSplit.Ordinal) -Part ([int]$script:RAScaleSplit.Part) -Parts ([int]$script:RAScaleSplit.Parts) -Band sub }
  if ($failedBucketIndices.Count -gt 0) {
      # v2.2.279 -- depth cap raised 4 -> 6 (modulus up to 4096 x original
      # BucketCount). Customer's the customer run hit the depth=4 cap with one
      # slice still timing out; deeper splits give the recursive partition
      # more room before giving up. Tunable via $global:SI_AutoBucketSubDepthMax.
      # (owner 2026-10-22: no fixed limits) the depth cap is gone -- the split goes deeper while it reduces the failure (#880)
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
      # (a slice split because its rows did not fit in memory is not a timeout: its smaller slices are always asked)
      # (#831 B: "every outer bucket" = every bucket THIS process ran -- a part of a split report runs its own range)
      $allOuterFailedWithEgSuppressed = ([bool]$script:_SkipEGBucketForCrossDomain -and $failedBucketIndices.Count -eq [int]($__soTo - $__soFrom) -and [int]$__abMemSplit -eq 0)
      if ($allOuterFailedWithEgSuppressed) {
          Write-Warn2 ("AutoBucket sub-bucketing pass SKIPPED for report '{0}' -- EG-side bucket filter is suppressed for this report (cross-domain join key) AND 100% of outer buckets ({1}/{1}) timed out at 900s. Sub-bucketing the CL inline cannot reduce EG-side work (the bottleneck), so attempting it would burn ~{2}min per parent (~{3}min total) to re-prove what we already know. Report ships with {4} row(s) from successful buckets (likely 0). To service this report at this customer's scale, the YAML query needs a per-report rewrite that moves `summarize by` from cmdb* columns to EG-native columns + post-augments CL data client-side." -f $ReportName, $failedBucketIndices.Count, ($subFanOut * 15), ($failedBucketIndices.Count * $subFanOut * 15), $ResultAll.Count)
          # Skipping is a judgement about COST, not a recovery -- every one of these buckets is data that
          # was never retrieved, and the report must say so rather than read as complete.
          foreach ($skippedIdx in $failedBucketIndices) {
              Add-RABucketLoss ("bucket {0}/{1}: sub-bucket pass skipped as futile (EG-side filter suppressed and every outer bucket timed out)" -f ([int]$skippedIdx + 1), $bucketCountToUse)
          }
          $failedBucketIndices.Clear()
          # Fall through past the BFS pass; report finishes immediately with whatever successful buckets produced.
      } else {

      $egSuppressedHint = if ([bool]$script:_SkipEGBucketForCrossDomain) {
          ' -- NOTE: EG-side bucket filter was suppressed for this report (cross-domain join key). Sub-bucketing may not distribute work; a split that does not reduce the failure stops there (a named loss).'
      } else { '' }
      $__abSplitUsed = $true
      $__abSplitBuckets = [int]$failedBucketIndices.Count
      Write-Warn2 ("AutoBucket sub-bucketing pass: {0} bucket(s) timed out at BucketCount={1}; splitting each into {2} sub-buckets per pass (deeper while it reduces the failure). Successful buckets retained ({4} rows so far).{5}" -f `
        $failedBucketIndices.Count, $bucketCountToUse, $subFanOut, $null, $ResultAll.Count, $egSuppressedHint)

      # BFS queue: each item = @{ N = parent-index; T = parent-total; D = current-depth; PK = parentKey-from-grandparent }
      $subQueue = New-Object System.Collections.Generic.Queue[object]
      foreach ($idx in $failedBucketIndices) {
          # #737: R = the bucket of THIS report the sub-slice belongs to; its sub-slices' answers are summed under it
          # How = 'key' (split by the bucket key, as always) | 'row' (split by the row: one key value alone is too large for the
          # worker's memory). RC / RI: the slice's own row split (1 / 0 = none). M: the slice is split because the worker had no
          # memory for it -- such a slice is split again until it fits (no depth cap; Get-RAMemorySplitNext).
          $subQueue.Enqueue(@{ N = [int]$idx; T = [int]$bucketCountToUse; D = 1; PK = $null; R = [int]$idx; How = 'key'; RC = 1L; RI = 0L; M = [bool]$__abMemRoots[[int]$idx] })
          # #880 Busy: busy answers its smaller slices met (retried, never split); SizeFails: smaller slices refused for their size
          # or time; LostBusy: a smaller slice lost because Defender kept refusing it as busy (never a size need)
          $__abSplitSlices[[int]$idx] = [pscustomobject]@{ Rows = 0L; Bytes = 0L; Seconds = 0.0; TooLarge = [bool]$__abSplitCause[[int]$idx]; Lost = $false
                                                          OutOfMemory = [bool]$__abMemRoots[[int]$idx]; MaxPartRows = 0L; Busy = 0; SizeFails = 0; LostBusy = $false }
      }
      # #880 THE SPLIT MUST REDUCE THE FAILURE, measured per bucket: how many of its smaller slices were asked and refused for their
      # size or time at each depth (Test-RASplitReducesFailure). A slice whose smaller slices are refused as often as it was is
      # not split deeper. And a smaller slice Defender keeps refusing as BUSY is asked again after its siblings (How = 'again',
      # the same slice, A = its rounds, as the late retry of the main pass) -- never split.
      $__subTried = @{}; $__subFailed = @{}
      $__subOk = 0L   # #882: smaller slices recovered so far (Test-RASubSliceAskAgain)
      $__subLateRounds = if ($null -ne $global:SI_BucketLateRetries) { [int]$global:SI_BucketLateRetries } else { 3 }
      $__subCount = {
          param([hashtable]$Stats, [int]$Root, [int]$Depth)
          if (-not $Stats.ContainsKey($Root)) { $Stats[$Root] = @{} }
          $Stats[$Root][$Depth] = [int]('0' + [string]$Stats[$Root][$Depth]) + 1
      }

      while ($subQueue.Count -gt 0) {
          if ($script:RAScaleRole -eq 'worker') { Assert-RAScaleOutWorkerLive -Where ('before a smaller slice of {0}' -f $ReportName) }   # #882
          $item    = $subQueue.Dequeue()
          $pN      = [int]$item.N
          $pT      = [int]$item.T
          $depth   = [int]$item.D
          $root    = [int]$item.R
          $pHow    = if ($item.ContainsKey('How') -and $item.How) { [string]$item.How } else { 'key' }
          $pRC     = if ($item.ContainsKey('RC')) { [long]$item.RC } else { 1L }
          $pRI     = if ($item.ContainsKey('RI')) { [long]$item.RI } else { 0L }
          $pAgain  = ($pHow -eq 'again')
          $pRounds = if ($item.ContainsKey('A')) { [int]$item.A } else { 0 }
          $newT    = if ($pHow -eq 'row' -or $pAgain) { $pT } else { $pT * $subFanOut }
          $kids    = if ($pAgain) { 1 } else { $subFanOut }
          # #880: a deeper key split runs only while the split reduced the failure of this bucket (measured, see above) -- a
          # memory split and a request that shrinks with every split (F) always make the next slice smaller and are not judged here
          if (-not $pAgain -and $pHow -in @('key', 'row') -and -not [bool]$item.M -and -not [bool]$item.F -and $depth -ge 2 -and
              -not (Test-RASplitReducesFailure -Tried $(if ($__subTried.ContainsKey($root)) { $__subTried[$root] } else { @{} }) -Failed $(if ($__subFailed.ContainsKey($root)) { $__subFailed[$root] } else { @{} }) -Depth $depth)) {
              $prunedSubtreeCount++
              Write-Warn2 ("[sub-bucket] slice {0}/{1} (depth {2}) of bucket {3}: not split further -- its smaller slices were refused for their size or time as often as their parents were, so a finer split does not reduce the failure; its rows are unknown, not resolved" -f $pN, $pT, $depth, ($root + 1))
              Add-RABucketLoss ("sub-bucket index {0}/{1} (depth {2}): not split further -- splitting did not reduce the failure of bucket {3}" -f $pN, $pT, $depth, ($root + 1))
              continue
          }
          if ($pAgain) {
              # the same slice once more, after its siblings and a longer pause (as the main pass's late retry)
              $__againSleep = Get-RABucketRetryDelaySeconds -Attempt ($pRounds + 1) -BaseSeconds 60 -MaxSeconds 600
              Write-Info ("[sub-bucket] slice {0}/{1}: asked again (round {2}/{3}) after {4}s -- it was refused as busy or throttled, never split for it" -f $pN, $pT, $pRounds, $__subLateRounds, $__againSleep)
              Start-Sleep -Seconds $__againSleep
              Invoke-RABucketReauth
          }
          # parent-key identifies THIS parent across its own children below
          $thisParentKey = if ($pRC -gt 1 -or $pHow -eq 'row') { ('{0}/{1}/{2}/r{3}/{4}' -f $pN, $pT, $depth, $pRI, $pRC) } else { ('{0}/{1}/{2}' -f $pN, $pT, $depth) }
          # this parent's children that ran out of the worker's memory (split again below, after the futile check, never pruned)
          # and how many answered with no row (all rows in ONE child of a key split = one key value carries them)
          $__memKids = New-Object System.Collections.Generic.List[object]
          $__emptyKids = 0

          for ($j = 0; $j -lt $kids; $j++) {
              if ($pAgain) {
                  # #880: the slice itself (its key slice and its own row part), asked again
                  $subN   = $pN
                  $subRC  = $pRC
                  $subRI  = $pRI
                  $subFilter  = New-BucketFilterKql -BucketCount $pT -BucketIndex $pN -ReportName $ReportName
              } elseif ($pHow -eq 'row') {
                  $subN   = $pN
                  $subRC  = [long]($pRC * $subFanOut)
                  $subRI  = [long]($pRI + ($j * $pRC))
                  $subFilter  = New-BucketFilterKql -BucketCount $pT -BucketIndex $pN -ReportName $ReportName
              } else {
                  $subN   = $pN + ($j * $pT)
                  $subRC  = 1L
                  $subRI  = 0L
                  $subFilter  = New-SubBucketFilterKql -ParentBucketCount $pT -ParentBucketIndex $pN -SubBucketCount $subFanOut -SubBucketIndex $j -ReportName $ReportName
              }
              $subQuery   = Add-RARowSplitFilter -Query (Replace-BucketFilterBlock -Query $Query -BucketFilterKql $subFilter) -RowCount $subRC -RowIndex $subRI
              $subLabel   = if ($subRC -gt 1) { ('sub:{0}/{1}/row:{2}/{3}' -f $subN, $newT, $subRI, $subRC) } else { ('sub:{0}/{1}' -f $subN, $newT) }
              # v2.2.428 -- narrow the CL side to the SAME partition as the EG filter above.
              # This pass rewrote only the EG-side __BUCKET_FILTER__ and left
              # $script:_CurrentBucketCount/_Index holding whatever the MAIN loop finished on, so
              # RA-GraphHunting.ps1 (~:149) re-inlined the SAME CL rows into every child. A customer
              # transcript shows all 8 children of a 2-bucket report printing the identical
              # "'_ep' bucket 2/2: 426/845 row(s) inlined" -- including the four under parent 0/2,
              # which should have carried bucket 1/2. Sub-bucketing therefore halved the EG side while
              # each child still dragged the full 54KB CL payload and its join work.
              # ALIGNMENT, which is what makes this safe rather than lossy: New-SubBucketFilterKql is
              # literally New-BucketFilterKql(count = pT*K, index = pN + j*pT), and the CL side hashes
              # with Get-SISha256Bucket -- documented as "identical math on KQL + PS", first 4 bytes of
              # SHA256 mod N. Same key, same hash, same modulus => the CL rows inlined here are exactly
              # the counterparts of the EG rows this filter selects. A mismatched pair would silently
              # drop real join matches, which is worse than the payload waste being fixed.
              $script:_CurrentBucketCount = $newT
              $script:_CurrentBucketIndex = $subN

              if ($subRC -gt 1) { Write-Info ("[sub-bucket] depth={0} parent={1}/{2}: running row part {3}/{4} (row split {5}/{6})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subRI, $subRC) }
              else { Write-Info ("[sub-bucket] depth={0} parent={1}/{2}: running sub {3}/{4} (effective index {5}/{6})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subN, $newT) }
              # One child, with its own recovery: a THROTTLED/unavailable API is retried at the same size
              # (backoff + re-auth) -- never split, which would multiply calls against a throttling API;
              # a slice that is still TOO LARGE is split deeper; only a defect or an exhausted recovery
              # is recorded lost. Same classifier as the main loop (Get-RABucketFailureAction).
              $subTransientRetries = if ($null -ne $global:SI_BucketTransientRetries) { [int]$global:SI_BucketTransientRetries } else { 3 }
              $subAttempt = 0
              $subDone    = $false
              while (-not $subDone) {
                  $subAttempt++
                  $__abSubSw = [System.Diagnostics.Stopwatch]::StartNew()   # #737
                  try {
                      $subResp = Invoke-GraphHuntingQuery -Query $subQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
                      $__abSubSw.Stop()
                      if ($script:RAStreamOn) { Add-RAStreamTime -Stream $script:RAStream -Phase 'hunt' -Seconds $__abSubSw.Elapsed.TotalSeconds }   # #873 A
                      $subConv = Get-RABucketRows -Resp $subResp
                      $subResp = $null
                      if (-not $subConv.Ok -and $subConv.ContainsKey('OutOfMemory') -and [bool]$subConv.OutOfMemory) {
                          # no memory to convert this smaller slice's answer either: split it again (below, after its siblings)
                          $__memErr = [string]$subConv.Error; $subConv = $null
                          [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                          $__memKids.Add(@{ N = $subN; T = $newT; RC = $subRC; RI = $subRI; Why = $__memErr })
                      }
                      elseif (-not $subConv.Ok) {
                          Write-Err2 ("[sub-bucket] result conversion failed for sub {0}/{1} (parent={2}/{3} depth={4}): {5}" -f ($j + 1), $subFanOut, $pN, $pT, $depth, $subConv.Error)
                          # The query SUCCEEDED and the rows were still dropped -- the most deceptive loss
                          # there is, so it is counted like every other one.
                          Add-RABucketLoss ("sub-bucket depth={0} parent={1}/{2} sub={3}/{4}: query succeeded but result conversion threw -- {5}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subConv.Error)
                      } else {
                          Write-Info ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4}: {5} rows" -f $depth, $pN, $pT, ($j + 1), $subFanOut, @($subConv.Rows).Count)
                          if (@($subConv.Rows).Count -eq 0) { $__emptyKids++ }
                          & $__subCount $__subTried $root $depth   # #880: asked and answered at this depth
                          # #737: the split bucket's own answer -- rows, estimated bytes and time of its sub-slices together
                          if ($__abSplitSlices.ContainsKey($root)) {
                              $__abEv = $__abSplitSlices[$root]
                              $__abEv.Rows += [long]@($subConv.Rows).Count
                              $__abEv.Bytes += [long](Get-AutoBucketRowBytes -Rows ([long]@($subConv.Rows).Count) -Sample @(@($subConv.Rows) | Select-Object -First 20))
                              $__abEv.Seconds += [double]$__abSubSw.Elapsed.TotalSeconds
                          }
                          # #641: a split bucket's own slice is checked against the source's count of THAT slice (the final split
                          # result decides): short = recorded as lost (the report is then not complete), never shipped as whole
                          $__sbcRows = Get-RADfcCountedRows -Rows ([long]@($subConv.Rows).Count)   # #673: before the Defender filter
                          if (Test-RABucketCountWanted -Rows $__sbcRows) {   # #753: near the source's row limit only
                              $__sbc = Test-RABucketRowCount -Query $subQuery -Rows $__sbcRows
                              if ($__sbc.Short) {
                                  Write-Err2 ("[sub-bucket] {0}/{1}: the source counts {2} row(s) but returned {3} -- the missing findings are unknown, not resolved" -f $subN, $newT, $__sbc.Expected, $__sbcRows)
                                  Add-RABucketLoss ("sub-bucket depth={0} parent={1}/{2} sub={3}/{4}: the source returned {5} of the {6} row(s) it counts" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $__sbcRows, $__sbc.Expected)
                              }
                          }
                          $__subIn = $true
                          if ($script:RAStreamOn) {
                              $__subRowsN = [long]@($subConv.Rows).Count
                              $__subIn = Add-RAStreamBucketGuarded -Rows @($subConv.Rows) -Bucket $subLabel
                              if (-not $__subIn) {
                                  # not enough memory for this sub-slice's rows at once: split it again until it fits (below, after
                                  # its siblings) -- a memory split always makes the next slice smaller, so it has no depth cap
                                  if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].Rows -= $__subRowsN; $__abSplitSlices[$root].OutOfMemory = $true }
                                  $subConv = $null
                                  $__memKids.Add(@{ N = $subN; T = $newT; RC = $subRC; RI = $subRI; Why = ('not enough memory to process its {0:N0} row(s) at once' -f $__subRowsN) })
                              } elseif ($__abSplitSlices.ContainsKey($root) -and $__subRowsN -gt [long]$__abSplitSlices[$root].MaxPartRows) {
                                  # the largest smaller slice this worker DID hold -- what the next run's count is sized from
                                  $__abSplitSlices[$root].MaxPartRows = $__subRowsN
                              }
                          }
                          else { $ResultAll = @($ResultAll) + @($subConv.Rows) }   # one join per bucket, never += per row
                          if ($__subIn) { $__subOk++ }   # #882: a smaller slice recovered -- the progress the 'again' rounds go on with
                          # #722: a split slice succeeded at $newT -- the count the next run starts from is kept NOW (only up, not
                          # confirmed), so a run stopped part-way through the sub-bucket pass does not leave the old count behind
                          # and the next run does not pay the too-large requests and the split again (the #713 early save covers
                          # only a slice that succeeded at the count itself, which none did when every bucket was too large)
                          if ($__subIn -and [int]$newT -gt [int]$__abSplitWorking) { $__abSplitWorking = [int]$newT }
                          if ($__subIn -and [bool]$global:AutoBucketCount -and $queryKey) {
                              # #737: sized from the answers measured so far (a partial sum only under-counts; the end of the
                              # report writes the full one) -- a busy-backend split whose answer is small keeps the count
                              # #880: only the slices whose SIZE is proven raise it here (-ProvenOnly), and nothing is kept once a
                              # slice of this report is lost (-Incomplete) -- a run stopped part-way never leaves a busy-raised count
                              $__abSplitNext = Get-RACountAfterSplit -BucketCount ([int]$bucketCountToUse) -Slices @($__abSplitSlices.Values) -WorkingCount $__abSplitWorking -FanOut $subFanOut -Cap ([int]$capBucket) -ProvenOnly
                              if ($__abSplitNext -gt [int]$__abEarlySavedAt) {
                                  $__abEarlySavedAt = [int]$__abSplitNext
                                  try {
                                      if (Save-AutoBucketCountEarly -QueryKey $queryKey -Count $__abSplitNext -Incomplete:($null -ne $script:_RABucketLoss -and $script:_RABucketLoss.Count -gt 0)) { Write-Info ("bucket sizing: '{0}' -- split slices worked at {1}; {2} bucket(s) kept in case the run stops part-way" -f $ReportName, $newT, $__abSplitNext) }
                                  } catch { Write-Warn2 ("bucket sizing: the count of '{0}' could not be kept yet ({1}); it is kept when the report is done" -f $ReportName, $_.Exception.Message) }
                              }
                          }
                      }
                      $subDone = $true
                  } catch {
                      $subErr    = $_.Exception.Message
                      $subAction = Get-RABucketFailureAction -Err $_ -AllTimedOut ([bool]$script:_LastGraphHuntingAllTimedOut)
                      $__abSubSw.Stop()
                      # #880: a busy answer is the backend's load -- counted as busy evidence for the bucket (never its size)
                      $__subBusy = ($subAction -eq 'Retry') -and (Test-RABucketBusyAnswer -Err $_)
                      if ($__subBusy) { $__abBusySlices++; if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].Busy = [int]$__abSplitSlices[$root].Busy + 1 } }
                      if ($subAction -eq 'Retry' -and $subAttempt -lt $subTransientRetries) {
                          $subSleep = Get-RABucketRetryDelaySeconds -Attempt $subAttempt -Err $_
                          $__subWhyRetry = if ($__subBusy) { 'Defender is busy (preempted for its load, not refused for its size)' } else { 'the API is throttling or had an issue' }
                          Write-Warn2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4}: {9} -- re-auth + retry {5}/{6} after {7}s (same size). Error: {8}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subAttempt, $subTransientRetries, $subSleep, $subErr, $__subWhyRetry)
                          Start-Sleep -Seconds $subSleep
                          Invoke-RABucketReauth
                          continue
                      }
                      $subDone = $true
                      # #882: after its first rounds a refused slice goes round again only while the pass recovered a slice since it was queued
                      $__subAtAsk = if ($item.ContainsKey('S')) { [long]$item.S } else { -1L }
                      if ($subAction -eq 'Retry' -and (Test-RASubSliceAskAgain -Rounds $pRounds -LateRounds $__subLateRounds -RecoveredNow $__subOk -RecoveredAtAsk $__subAtAsk)) {
                          # #880: its retries ran out -- the same slice is asked again after its siblings (How = 'again'), never split
                          Write-Warn2 ("[sub-bucket] slice {0}/{1}: still refused after {2} attempt(s) -- asked again at the same size after the other slices (round {3}/{4}). Error: {5}" -f $subN, $newT, $subTransientRetries, ($pRounds + 1), $__subLateRounds, $subErr)
                          $subQueue.Enqueue(@{ N = $subN; T = $newT; D = $depth; PK = $thisParentKey; R = $root; How = 'again'; RC = $subRC; RI = $subRI; M = $false; A = ($pRounds + 1); S = $__subOk })
                          continue
                      }
                      if ($subAction -eq 'Retry' -and $__subBusy -and $__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].LostBusy = $true }
                      if ($subAction -eq 'Split' -and (Test-RABucketOutOfMemory -Err $_)) {
                          # the worker had no memory for this smaller slice's answer either: split again until it fits (below,
                          # after its siblings) -- never counted towards the futile-prune, never capped by depth
                          [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                          if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].OutOfMemory = $true; $__abSplitSlices[$root].Seconds += [double]$__abSubSw.Elapsed.TotalSeconds }
                          $__memKids.Add(@{ N = $subN; T = $newT; RC = $subRC; RI = $subRI; Why = 'its answer is too large for this worker''s memory' })
                          continue
                      }
                      # a child refused for its REQUEST size whose inlined CL rows shrink with every split is not futile:
                      # a finer split makes it fit (Test-RASplitCanStillFit) -- it never counts towards the futile-prune
                      $__subCanFit = ($subAction -eq 'Split') -and (Test-RASplitCanStillFit -Err $_ -InlineBytes ([long]$script:_LastHybridInlineBytes) -OverheadBytes ([long]$script:_LastHybridQueryBodyOverheadBytes))
                      if ($subAction -eq 'Split' -and -not $__subCanFit) {
                          # #880: asked and refused for its size or time at this depth (Test-RASplitReducesFailure)
                          & $__subCount $__subTried $root $depth
                          & $__subCount $__subFailed $root $depth
                          if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].SizeFails = [int]$__abSplitSlices[$root].SizeFails + 1 }
                      }
                      # no depth cap (owner 2026-10-22, no fixed limits): a slice is split deeper while the split reduces the failure --
                      # the measured stop is Test-RASplitReducesFailure (#880, above); the only other end is a slice count past what
                      # the hash partition can address (2^31), where a finer split of the key does not exist
                      $__subFiner = Test-RASubSplitAddressable -SliceCount $newT -FanOut $subFanOut
                      if ($subAction -eq 'Split' -and $__subFiner) {
                          if ($__subCanFit) { Write-Info ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4}: the request is still over the service's size limit, and a finer split makes it smaller -- split again (depth {5})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, ($depth + 1)) }
                          else { Write-Warn2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} still too large or too slow -- queueing for further split (depth {5})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, ($depth + 1)) }
                          # a row part stays a row part (its children split its rows further, never the whole key slice again)
                          $subQueue.Enqueue(@{ N = $subN; T = $newT; D = ($depth + 1); PK = $thisParentKey; R = $root; How = $(if ($subRC -gt 1) { 'row' } else { 'key' }); RC = $subRC; RI = $subRI; M = $false; F = [bool]$__subCanFit })
                          # #737: a sub-slice that had to go deeper is itself evidence the bucket was large (or slow)
                          if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].Seconds += [double]$__abSubSw.Elapsed.TotalSeconds }
                      } elseif ($subAction -eq 'Split') {
                          Write-Err2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} still too large at {5} slices, the finest split the key partition can address -- giving up on this slice (rows in this sub-bucket NOT included). Error: {6}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $newT, $subErr)
                          if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].Lost = $true }   # #737
                          # #62 LOSS PATH 5 -- the message already says "NOT included"; now it is COUNTED too.
                          Add-RABucketLoss ("sub-bucket depth={0} parent={1}/{2} sub={3}/{4}: still too large or too slow at {5} slices -- the key partition cannot be split finer" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $newT)
                      } elseif ($subAction -eq 'Absent') {
                          Write-Info ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4}: not applicable -- {5}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subErr)
                      } else {
                          $subWhy = if ($subAction -eq 'Retry' -and $__subBusy) { ("Defender kept refusing it as busy through {0} retries and {1} later round(s)" -f $subTransientRetries, $pRounds) } elseif ($subAction -eq 'Retry') { ("API throttling/unavailable survived {0} retries and {1} later round(s)" -f $subTransientRetries, $pRounds) } elseif ($subAction -eq 'Defect') { 'query defect' } else { 'failed (non-timeout)' }
                          Write-Err2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} {5}: {6}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subWhy, $subErr)
                          # #62 LOSS PATH 6.
                          Add-RABucketLoss ("sub-bucket depth={0} parent={1}/{2} sub={3}/{4}: {5} -- {6}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subWhy, $subErr)
                      }
                  }
              }
          }

          # (owner 2026-10-22, one mechanism) the v2.2.357 futile-prune is gone: a parent whose children were all refused is judged
          # when its children are dequeued -- Test-RASplitReducesFailure (#880) then stops them as a NAMED loss (Add-RABucketLoss)

          # THE WORKER'S MEMORY: a smaller slice it still could not hold is split again -- by its key while that can split it,
          # by the row once one key value carries the slice (the parent's rows all came back in ONE child: every other child
          # answered with no row), until it fits. No depth cap: every split makes the next answer smaller; only a slice that
          # cannot be made smaller (a single row, Get-RAMemorySplitNext 'none') is left unknown -- never resolved.
          $__oneKey = ($pHow -ne 'row' -and $__memKids.Count -eq 1 -and $__emptyKids -eq ($subFanOut - 1))
          foreach ($__mk in $__memKids) {
              $__nx = Get-RAMemorySplitNext -KeyCount ([long]$__mk.T) -RowCount ([long]$__mk.RC) -FanOut $subFanOut -SingleKey:$__oneKey
              if ($__nx.Kind -eq 'none') {
                  if ($__abSplitSlices.ContainsKey($root)) { $__abSplitSlices[$root].Lost = $true }
                  Write-Err2 ("[sub-bucket] slice {0}/{1} (row part {2}/{3}): too large for this worker's memory and it cannot be made smaller -- its rows are unknown, not resolved ({4})" -f $__mk.N, $__mk.T, $__mk.RI, $__mk.RC, $__mk.Why)
                  Add-RABucketLoss ("sub-bucket {0}/{1} row part {2}/{3}: too large for this worker's memory at the finest split ({4})" -f $__mk.N, $__mk.T, $__mk.RI, $__mk.RC, $__mk.Why)
                  continue
              }
              if ($__nx.Kind -eq 'row') { Write-Warn2 ("[sub-bucket] slice {0}/{1}: still too large for this worker's memory ({2}) -- {3}; split by row into {4} parts" -f $__mk.N, $__mk.T, $__mk.Why, $(if ($__oneKey -and [long]$__mk.RC -le 1) { 'one key value carries its rows' } else { 'its rows are split further' }), $subFanOut) }
              else { Write-Warn2 ("[sub-bucket] slice {0}/{1}: still too large for this worker's memory ({2}) -- split into {3} smaller slices" -f $__mk.N, $__mk.T, $__mk.Why, $subFanOut) }
              $subQueue.Enqueue(@{ N = [int]$__mk.N; T = [int]$__mk.T; D = ($depth + 1); PK = $thisParentKey; R = $root; How = [string]$__nx.Kind; RC = [long]$__mk.RC; RI = [long]$__mk.RI; M = $true })
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

# #831 B -- ONE PART OF A SPLIT REPORT: its slices are in. Its partial is written; the LAST part to finish takes every part's
# partial into this process and the report goes on below EXACTLY as the single job's (the bucket learning, the lost-slice
# verdict, the report's end in the database, its completeness, its verdict). Any other part ends the report here.
if ($null -ne $script:RAScaleSplit) {
    $__soEv = @{ SplitUsed = [bool]$__abSplitUsed; SplitBuckets = [int]$__abSplitBuckets; SplitWorking = [int]$__abSplitWorking; SplitSlices = $__abSplitSlices
                 BusySlices = [int]$__abBusySlices; Deferred = [int]$deferredBucketIndices.Count; MemSplit = [int]$__abMemSplit; Complete = [bool]$completeBucketDone
                 CannotFit = [string]$reportCannotFit; Measure = $script:AutoBucketMeasure
                 ReadCounts = $script:RAReadCounts }   # count timing: this part's counts just before and just after its own slices
    $__soM = Complete-RAScaleOutSplitPart -Evidence $__soEv -ReportName ([string]$ReportName)
    if ($null -eq $__soM -or ($__soM -is [string] -and $__soM -eq 'skip')) { continue }
    # the report's evidence from here on is every part's
    $__abSplitUsed = [bool]$__soM.Evidence.SplitUsed
    $__abSplitBuckets = [int]$__soM.Evidence.SplitBuckets
    $__abSplitWorking = [int]$__soM.Evidence.SplitWorking
    $__abBusySlices = [int]$__soM.Evidence.BusySlices
    $__abMemSplit = [int]$__soM.Evidence.MemSplit
    $__abSplitSlices = @{}
    foreach ($__soK in @($__soM.Evidence.SplitSlices.Keys)) {
        $__soV = $__soM.Evidence.SplitSlices[$__soK]
        $__abSplitSlices[[int]$__soK] = [pscustomobject]@{ Rows = [long]$__soV['Rows']; Bytes = [long]$__soV['Bytes']; Seconds = [double]$__soV['Seconds']; TooLarge = [bool]$__soV['TooLarge']; Lost = [bool]$__soV['Lost']
                                                          OutOfMemory = [bool]$__soV['OutOfMemory']; MaxPartRows = [long]$__soV['MaxPartRows']
                                                          Busy = [int]('0' + [string]$__soV['Busy']); SizeFails = [int]('0' + [string]$__soV['SizeFails']); LostBusy = [bool]$__soV['LostBusy'] }
    }
    $deferredBucketIndices = New-Object System.Collections.Generic.List[int]
    for ($__soI = 0; $__soI -lt [int]$__soM.Evidence.Deferred; $__soI++) { [void]$deferredBucketIndices.Add($__soI) }
    $completeBucketDone = [bool]$__soM.Complete
    if ($__soM.CannotFit) {
        $reportCannotFit = [string]$__soM.CannotFit
        # a part of a report never goes out as the report: every part's rows are removed (as the single job removes its own)
        if ($script:RAStreamOn) { try { Clear-RAStreamReport -Stream $script:RAStream -Why 'the report is not in this run' } catch { Set-RAReportRowsHeld -Cause $_.Exception.Message } }
    }
    $script:AutoBucketMeasure = $__soM.Evidence.Measure
}

# 🔴 THE REPORT COULD NOT BE ASKED AT ALL IN THIS RUN. Nothing it would have found is known -- which is not the same
# as nothing being wrong. Rows already returned by earlier slices are dropped with it: a part of a report must never
# go out as the report. Recorded as a failed report (the run ends partial, so nothing downstream reads the missing
# findings as fixed), said in plain words, and the run goes on: one report never holds up the others.
if ($reportCannotFit) {
    $script:_CurrentBucketCount = 0
    $script:_CurrentBucketIndex = 0
    Reset-RABucketLoss
    Write-Err2 ("report '{0}' is NOT in this run: {1}. Its findings are unknown for this run, not resolved. The run continues with the next report." -f $ReportName, $reportCannotFit)
    # #674: a lookup it needs could not be read -- said as that, not as a query that could not be sent
    $__cannotWhy = if (Test-RALookupUnavailableError -Err $reportCannotFit) { 'it was not run: {0}' } else { 'its query could not be sent: {0}' }
    Add-RAReportFailure -ReportName $ReportName -Reason ($__cannotWhy -f $reportCannotFit)
    continue
}

# If we succeeded with a higher bucket count than the initial AutoBucket probe, update memo/cache so next run starts smarter.
if ($bucketRunSucceeded -and [bool]$global:AutoBucketCount) {
  # #640 SELF-HEALING: a bucket had to be split this run (too large / too slow) -- the next run starts from twice the
  # count, so it does not pay the split again ("better to small than too big"). The rows of THIS run are unchanged.
  $__abRemember = [int]$bucketCountToUse
  # #880: a report that ended NOT COMPLETE (a slice's rows are unknown) never changes its count -- its answers are partial
  $__abIncomplete = ($null -ne $script:_RABucketLoss -and $script:_RABucketLoss.Count -gt 0)
  if ($__abSplitUsed -and [int]$bucketCountToUse -lt [int]$capBucket) {
    # #737: sized to the answer -- each split bucket counts for the slices its own measured answer needed; a split caused
    # by a busy backend (small answer, quick sub-slices) adds nothing. Never the finest count for the whole report.
    $__abNext = Get-RACountAfterSplit -BucketCount ([int]$bucketCountToUse) -Slices @($__abSplitSlices.Values) -WorkingCount $__abSplitWorking -FanOut $subFanOut -Cap ([int]$capBucket) -Incomplete:$__abIncomplete
    if ($__abIncomplete) {
      Write-Info ("bucket sizing: '{0}' -- {1} of {2} bucket(s) had to be split, and the report is NOT COMPLETE: its answers are partial, so the count is not raised from them; the next run starts from {2} again" -f $ReportName, $__abSplitBuckets, $bucketCountToUse)
    } elseif ($__abNext -gt [int]$bucketCountToUse) {
      Write-Info ("bucket sizing: '{0}' -- {1} of {2} bucket(s) had to be split and their answers needed more slices; the next run starts from {3}" -f $ReportName, $__abSplitBuckets, $bucketCountToUse, $__abNext)
    } else {
      Write-Info ("bucket sizing: '{0}' -- {1} of {2} bucket(s) had to be split, but their answers were small (a busy backend, not a slice too large); the next run starts from {2} again" -f $ReportName, $__abSplitBuckets, $bucketCountToUse)
    }
    $__abRemember = $__abNext
  } elseif (-not $__abSplitUsed -and -not $__abIncomplete -and -not $completeBucketDone -and
            -not ([string]$__abStartSource -eq 'probe' -and [bool]$script:_AutoBucketProbeFailed)) {
    # #737: every slice came back far below every limit (rows, bytes, request and TIME) -- the next run tries half. Not right
    # after a probe proved this count by failing below it.
    # #880: a slice Defender refused as BUSY and then answered at its own size (in the main pass or the late retry) is measured
    # like every other -- busy answers no longer keep a count up (live 2026-10-22: a count raised 2 -> 28 by busy answers
    # could never come down, because every later run met a busy answer somewhere). And a report that ran COMPLETE at fewer
    # slices before, on the same query (Get-SIRaBucketCompleteLowerCount), comes back towards that count by halving even when
    # its slices are not far below every limit (each slice pays the same fixed reads however many there are).
    $__abFar = Test-RABucketRunFarBelow -Measure $script:AutoBucketMeasure
    $__abLower = 0
    if (-not $__abFar -and (Test-AutoBucketSqlActive) -and (Get-Command -Name Get-SIRaBucketCompleteLowerCount -ErrorAction SilentlyContinue)) {
      $__abFp = ''; $__abKp = Split-SIRaBucketKey -Key $queryKey; if ($__abKp) { $__abFp = [string]$__abKp.Fingerprint }
      $__abLower = Get-SIRaBucketCompleteLowerCount -Count ([int]$bucketCountToUse) -History @($script:AutoBucketSql.History[$ReportName] | Where-Object { $_ }) -Fingerprint $__abFp
    }
    if ($__abFar -or $__abLower -gt 0) {
      $__abHalfFloor = if ($__abFar) { [int]$__abLearnFloor } else { [int][Math]::Max([int]$__abLearnFloor, $__abLower) }
      $__abHalf = Get-RACountAfterSmallRun -BucketCount ([int]$bucketCountToUse) -Floor $__abHalfFloor
      if ($__abHalf -lt [int]$bucketCountToUse) {
        if ($__abFar) { Write-Info ("bucket sizing: '{0}' -- every slice of {1} came back far below every limit (largest {2} row(s), {3:N0} s); the next run tries {4}" -f $ReportName, $bucketCountToUse, [long]$script:AutoBucketMeasure.MaxBucketRows, [double]$script:AutoBucketMeasure.MaxBucketSeconds, $__abHalf) }
        else { Write-Info ("bucket sizing: '{0}' -- the report ran complete at {1} slice(s) before and this run of {2} was complete with no split; the next run tries {3}" -f $ReportName, $__abLower, $bucketCountToUse, $__abHalf) }
        $__abRemember = $__abHalf
      }
    }
  }
  try {
    $script:AutoBucketMemo[$queryKey] = [int]$__abRemember
    if ([bool]$global:AutoBucketCache -and -not [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
      $cachePath2 = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
      $cache2 = Read-AutoBucketCache -Path $cachePath2
      if ($null -eq $cache2) { $cache2 = @{} }
      $cache2[$queryKey] = [int]$__abRemember
      # #833: the report ran complete at its CURRENT query -- the counts kept for its earlier queries are removed now (they
      # can never be used again, and a changed query starts from its measurement, not from them)
      $_cacheRefStale = [ref]$cache2
      $__abStale = Remove-AutoBucketStaleSiblings -Cache $_cacheRefStale -QueryKey $queryKey
      $cache2 = $_cacheRefStale.Value
      if ($__abStale -gt 0) { Write-Info ("bucket sizing: '{0}' -- {1} count(s) kept for its earlier queries removed" -f $ReportName, $__abStale) }
      # v2.2.383 Layer 3 -- stamp confirmedAt for the end-of-run cascade write
      # too. This is the path where the engine escalated past the cached
      # value (e.g. cache said 62, run cascaded to 130). The new value is
      # battle-tested via an actual full report run, so the confirmation
      # is even stronger than the probe-path confirmation.
      # #640 DEFECT FIX: ONLY when this run decided the count (probed, sized, or had to raise it). A count used unchanged
      # from what was remembered is not re-confirmed -- stamping it every run kept the challenger's pause open forever.
      if (-not $__abIncomplete -and (Test-AutoBucketCountDecidedThisRun -Source $__abStartSource -StartCount $__abStartCount -FinalCount ([int]$__abRemember))) {
        $_cacheRefL3 = [ref]$cache2
        Set-AutoBucketConfirmed -Cache $_cacheRefL3 -QueryKey $queryKey
        $cache2 = $_cacheRefL3.Value
      }
      Write-AutoBucketCache -Path $cachePath2 -CacheObject $cache2
      # #833 THE LOG SAYS WHAT THE STATE HOLDS: the one line naming the count kept for the next run, written with it (the
      # early save during the run only keeps a count in case the run stops part-way)
      if (-not ((Test-AutoBucketSqlActive) -and [bool]$script:AutoBucketSql.Offline)) {
        Write-Info ("bucket sizing: '{0}' -- {1} bucket(s) kept for the next run (this run: {2})" -f $ReportName, $__abRemember, $bucketCountToUse)
      }
    }
  } catch { }
  # #640: the report's history row (count, how it was decided, the measured result) and STEP 2, the jump warning
  # #697 (2): the request numbers are THIS report's own (the lookups it split per bucket, and the part of its request no
  # bucket count shrinks) -- the run-wide largest snapshot, row width and query text sized three small reports to 16
  $__abReq = Get-AutoBucketRequestMeasure -Measure $script:AutoBucketMeasure
  $__abJump = Complete-AutoBucketReport -ReportName $ReportName -QueryKey $queryKey -StartCount $__abStartCount -FinalCount ([int]$__abRemember) -Source $__abStartSource `
                -RequestRows ([long]$__abReq.Rows) -RequestBytesPerRow ([int]$__abReq.BytesPerRow) -RequestOverheadBytes ([int]$__abReq.OverheadBytes) -RanCount ([int]$bucketCountToUse) -Incomplete:$__abIncomplete
  if ($__abJump) { Write-Warn2 ("bucket sizing: '{0}' -- {1}; the query or its data may be wrong (see Operations > Risk Analysis query splitting)" -f $ReportName, $__abJump) }
}
        # $ResultAll = @(Deduplicate-Rows -Rows $ResultAll)
        # #641: the completeness count is asked in the slices the rows were (one when a single slice returned the whole)
        $script:RACountBuckets = $(if ($completeBucketDone) { 1 } else { [int]$bucketCountToUse })
        $ResultAll = @($ResultAll)   # enforce array
        # #152 -- A SUMMARY GROUP THAT SPANS BUCKETS COMES BACK ONCE PER BUCKET, each row aggregated over only
        # that bucket's assets. They were concatenated and the risk-score de-duplication then kept the first
        # and DROPPED the rest with every asset they listed (measured: the two devices with the most CVEs in no
        # Summary row at all). Merged here, by the report's own summarize-by, before anything counts them.
        if ($ReportName -like '*_Summary*' -and $ResultAll.Count -gt 1) {
            $__merge = Merge-RASummaryBucketRows -Rows $ResultAll -Query $Query
            if ($__merge.Applied -and $__merge.Merged -gt 0) {
                $ResultAll = @($__merge.Rows)
                Write-Info ("combined {0} partial row(s) from different asset slices into their group -- {1} row(s), every asset kept" -f $__merge.Merged, $ResultAll.Count)
            } elseif (-not $__merge.Applied) {
                Write-Diag ("summary merge not applied: {0}" -f $__merge.Reason)
            }
            if ($__merge.Applied -and [int]$__merge.Refused -gt 0) {
                Write-Info ("{0} group(s) kept as separate rows per asset slice -- a column could not be combined safely, so nothing was dropped" -f $__merge.Refused)
            }
        }
        if (-not $script:RAStreamOn) { Write-Info ("total rows across all buckets: {0}" -f $ResultAll.Count) }
        # 🔴 AUDIT #62 -- the caveat goes HERE, immediately under the number it qualifies. Printed
        # anywhere else and an operator reads the total as complete. Buckets recovered by the
        # sub-bucket pass are NOT counted: the 900s path queues for splitting and only paths 5/6
        # record a loss if that split also fails.
        Write-RABucketLossVerdict -ReportName $ReportName -BucketCount $bucketCountToUse -RowsKept $(if ($script:RAStreamOn) { [int]$script:RAStream.Current.Retrieved } else { $ResultAll.Count })

    } else {

        # #831 B: a part of a split report whose query this worker cannot ask in slices would run the WHOLE report once per
        # part -- each part says so in its partial and the report is NOT COMPLETE (no rows kept), never doubled
        if ($null -ne $script:RAScaleSplit) {
            $__soWhy = 'it was planned in parts over its remembered query slices, and its query cannot be asked in slices here (slicing is off for it or its slice block is missing)'
            $__soM = Complete-RAScaleOutSplitPart -Evidence @{ Failed = $__soWhy } -ReportName ([string]$ReportName)
            if ($null -ne $__soM -and -not ($__soM -is [string])) {
                Write-Err2 ("report '{0}' is NOT COMPLETE in this run: {1}. Its findings are unknown for this run, not resolved." -f $ReportName, $__soWhy)
                try { Clear-RAStreamReport -Stream $script:RAStream -Why 'the report is not in this run' } catch { Set-RAReportRowsHeld -Cause $_.Exception.Message }
                Add-RAReportFailure -ReportName ([string]$ReportName) -Reason ("not complete: {0}" -f $__soWhy)
            }
            continue
        }

        if ($effectiveUseBucket -and -not $querySupportsBucket) {
            Write-Warn2 ("bucketing enabled but query does not contain placeholder '{0}'. Running single query." -f $effectivePlaceholder)
        }

        Tock
        try {
            Write-Info "running query (auto-routed: LA-direct or XDR Advanced Hunting based on table mix)"
            # count timing: the source's count just before the report's one query (C1) and just after it (C2)
            Invoke-RAReadCount -When Before -Query $Query -ReportName $ReportName
            $resp = Invoke-GraphHuntingQuery -Query $Query -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
            Tick "hunting query"
            Invoke-RAReadCount -When After -Query $Query -ReportName $ReportName
        } catch {
            if ((Get-Command Test-RANoDataSource -ErrorAction SilentlyContinue) -and (Test-RANoDataSource -Message $_.Exception.Message)) {
                # No data source in this tenant (no Defender XDR, or an SI profile table with no row yet): not a failed report
                # (live 2026-10-06, Community rehearsal; a tenant without Defender is a normal Community customer).
                Write-Info ("not applicable in this tenant: {0}" -f $_.Exception.Message)
                if ($null -ne $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 }
                $script:RAReportStatusDone[[string]$ReportName] = 'Complete'
                Set-RAReportNote -ReportName ([string]$ReportName) -Values @{ EndedUtc = [datetime]::UtcNow; State = 'NotApplicable'; Why = [string]$_.Exception.Message; Rows = 0; QueryHash = [string]$script:RAReportQueryHash[[string]$ReportName] }
                if ($script:RAStreamOn) { try { Set-RAStreamReportStatus -Stream $script:RAStream -ReportName $ReportName -Expected 0 -Retrieved 0 -Stored 0 -State Complete -Reason 'not applicable in this tenant (no data source)' -QueryHash ([string]$script:RAReportQueryHash[[string]$ReportName]) -QueryHashCarry ([string]$script:RAReportQueryHashCarry[[string]$ReportName]) } catch { } }
                continue
            }
            Write-Err2 "query failed: $($_.Exception.Message)"
            # The report produced NOTHING because its query failed -- not because nothing is wrong. Recorded, so the run
            # ends partial and nothing downstream reads the findings it would have reported as fixed.
            Add-RAReportFailure -ReportName $ReportName -Reason ("its query failed: {0}" -f $_.Exception.Message)
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
                if ($script:RAStreamOn) { Add-RAStreamBucket -Rows @() -Bucket 'whole' }   # #673: an answer the Defender filter emptied is still booked
                if ($null -ne $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 }
                if ($script:RAStreamOn) { Complete-RAReportInStream -Query $Query } else { Complete-RAReportCompleteness -Query $Query -Retrieved 0 }
                continue
            }
            Tick "result conversion"
        } else {
            $rawResults = $null
            if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }
            if ($null -eq $rawResults) {
                Write-Info "Query returned no results"
                if ($null -ne $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun[[string]$ReportName] = 0 }
                if ($script:RAStreamOn) { Complete-RAReportInStream -Query $Query } else { Complete-RAReportCompleteness -Query $Query -Retrieved 0 }
                continue
            }

            Tock
            try {
                $ResultSingle = ConvertTo-PSObjectDeep $rawResults -StripOData -CastPrimitiveArrays
            } catch {
                Write-Err2 "result conversion failed: $($_.Exception.Message)"
                Add-RAReportFailure -ReportName $ReportName -Reason ("its result could not be read: {0}" -f $_.Exception.Message)
                continue
            }
            Tick "result conversion"
        }

        if ($script:RAStreamOn) { Add-RAStreamBucket -Rows @($ResultSingle) -Bucket 'whole'; $ResultSingle = $null }
        else { $ResultAll = @($ResultAll) + @($ResultSingle) }   # one join, never += per row
        Write-Info ("rows before filters: {0}" -f $ResultAll.Count)
    }

    # #638: with the result in SQL every bucket was already scored and written (Write-RAStreamBucketRows); the report is
    # finished there -- a Summary report's staged groups, the findings two slices both returned, the shared trace names,
    # the counts and the completeness check (#641).
    if ($script:RAStreamOn) { Complete-RAReportInStream -Query $Query; continue }
    Add-RAProofRows -Rows @($ResultAll)
    Complete-RAReportCompleteness -Query $Query -Retrieved ([long]@($ResultAll).Count) -RowColumns $(if (@($ResultAll).Count -gt 0 -and $null -ne @($ResultAll)[0]) { [string[]]@(@($ResultAll)[0].PSObject.Properties.Name) } else { [string[]]@() })
    Invoke-RAReportRows -ResultAll $ResultAll
  }
  catch {
    # Per-report iteration safety net. Without this, ANY terminating error in
    # one report (KQL parse fail, empty-array filter binding, KV secret miss,
    # etc.) kills the whole loop -- we'd lose the other 54 reports' output.
    # Log the error with the report name and continue with the next report.
    Write-Warn2 ("report failed -- skipping: {0}: {1}" -f $ReportName, $_.Exception.Message)
    # #638: a part of a report never goes out as the report -- what its buckets already wrote is removed
    if ($script:RAStreamOn) { try { Clear-RAStreamReport -Stream $script:RAStream -Why 'the report failed' } catch { Set-RAReportRowsHeld -Cause $_.Exception.Message } }
    Add-RAReportFailure -ReportName ([string]$ReportName) -Reason ("it failed: {0}" -f $_.Exception.Message)
    continue
  }
}
Complete-RALoopPass
}

# #742: a QUEUE WORKER's part ends here -- every report it took is in the database, posted and handed over; the producer
# finishes the run (the guards, the completion, the mail). Nothing below runs in a worker.
if ($script:RAScaleRole -eq 'worker') {
    Write-Section ('worker finished: {0} report(s) run' -f [int]$script:RAScaleDone)
    return
}

# #673 plan B: every report has run -- the comparison of both paths is said and written (SI_RA_DefenderFilterCompare),
# and the run's Defender list is removed from SQL. Never fails the run.
try { $null = Complete-RADefenderFilterRun } catch { Write-Warn2 ("the Defender recommendation list of this run could not be removed from the database (the next run removes it): {0}" -f $_.Exception.Message) }

# Final result
Write-Section "final result"

$script:RAAllCount = 0L; $script:RAViewCount = 0L

if ($script:RAStreamOn) {
    # #638: every report's rows are in SQL, scored and shaped; nothing of the result is in memory. The order (score,
    # highest first, then the order the rows were written), the view the workbook and the mail show, and the counts come
    # from there; every step below reads the rows a page at a time.
    $global:final = @(); $global:RA_ReportRows = @()   # the export pool stays empty: every row went to SQL
    $ResultAll = $null; $ResultFiltered = $null; $RiskScoreArray = $null; $Shaped = $null; $resp = $null; $FilteredOut = $null
    $script:RAAllCount = Get-RAStreamCount -Stream $script:RAStream -Source All
    $script:RAViewCount = Get-RAStreamCount -Stream $script:RAStream -Source View
    $global:RA_ExemptedNotCounted = [int]$script:RAStreamExemptedNotCounted
    if ($global:RA_ExemptedNotCounted -gt 0) { Write-Info ("{0} exempted finding(s) are kept in Log Analytics and not counted in the workbook, the summary or the mail (SI_Exempted_CountInManagement is off)." -f $global:RA_ExemptedNotCounted) }
    if ($null -ne $script:RAExcelScope) { Write-Info ("Excel and mail show {0} of {1} row(s): the output scope for Excel + mail lets through {2}. Log Analytics keeps every row." -f $script:RAViewCount, ($script:RAAllCount - [long]$global:RA_ExemptedNotCounted), (Get-SIOutputScopeText $script:RAExcelScope)) }
    if ($script:RAStream.Illegal -gt 0) { Write-Diag ("[odata] {0} row(s) carried artefact properties -- left out of the stored rows" -f $script:RAStream.Illegal) }
    # the sort column the rows were ordered by (RA-SqlStream.ps1 Write-RAStreamRows: the weighted score, else the report's own)
    $global:FinalRiskScoreColumnName = 'RiskScoreTotal_Weighted'
    if ($global:FinalDesiredColumns) { $global:FinalDesiredColumns = @($global:FinalDesiredColumns | Where-Object { [string]$_ -match '^[A-Za-z][A-Za-z0-9_]*$' }) }
    Write-Info ("{0} row(s) in the database for this run, {1} shown in the workbook and the mail" -f $script:RAAllCount, $script:RAViewCount)
    # The workbook is written from the database AFTER the run's result is completed there (Invoke-RAWorkbookStep, below
    # the guards): it is a convenience output and never decides whether the collection is delivered.
}
elseif ($global:AllShapedRows.Count -eq 0) {
    # The workbook step (Invoke-RAWorkbookStep) still writes a placeholder sheet, so the mail attachment works, the
    # JSON sibling has a matching empty array, and the run looks "complete" to downstream consumers.
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

    # 🔴 v2.2.445 -- $global:AllShapedRows is ALREADY a List[object] (declared ~line 2033, filled
    # with .Add()). It used to be copied into a plain array one element at a time:
    #     $allRows = @(); foreach ($r in $global:AllShapedRows) { $allRows += ,$r }
    # `+=` REALLOCATES AND COPIES THE ENTIRE ARRAY on every iteration, so building N rows costs
    # O(N^2) element copies -- roughly 7.3 BILLION for the 121k-row Detailed run that exposed this.
    # Sort-Object buffers its input anyway, so the List pipes straight in: the copy is DELETED
    # rather than made faster.
    # 🪤 NOT `@($global:AllShapedRows)` -- wrapping a List[object] of PSCustomObjects in @() throws
    # ArgumentException on PS 5.1 (bit TenantManager v1.1.0 twice). Pipe it, or use .ToArray().
    $global:final = $global:AllShapedRows | Sort-Object -Descending -Property @{
        Expression = {
            $v = $null
            if ($_.PSObject.Properties[$sortCol]) { $v = $_.$sortCol }
            # Invariant -- the final sort order must not depend on the host's locale (#121).
            ConvertTo-RADouble -Value $v -Default 0.0
        }
    }
    # Persist the actual sort column so downstream Excel-export label matches
    $global:FinalRiskScoreColumnName = $sortCol
    Tick "final sort"

    #--------------------------------------------------------------------------------------------
    # v2.2.453 -- DROP OData SERIALISATION ARTEFACTS FROM THE CUSTOMER-FACING OUTPUTS.
    # Graph advanced hunting annotates each value with a sibling `<name>@odata.type` key
    # (`#Int64`, `#SByte`, `#Collection(String)`). Three AH call sites already remove them via
    # `ConvertTo-PSObjectDeep -StripOData` (:2792, :3016, :3150) -- but at least one path does not,
    # so they survive into the export pool.
    #
    # 🔑 THE DAMAGE IS WILDLY DISPROPORTIONATE, which is why this is worth a release:
    # measured 2026-08-26 on the internal estate, exactly **2 rows out of 6,339** (one report,
    # Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources) carried these
    # properties -- and because Export-Worksheet takes the UNION of column names, those 2 rows
    # added **17 junk columns to all 316** in every customer's workbook, and to the JSON sibling.
    #
    # Log Analytics was never affected: the schema sample is already filtered by this same regex
    # (see the ingest block below), and Build-DataArrayToAlignWithSchema drops undeclared columns
    # from the posted rows, so the CL table only ever held the legal names.
    #
    # 🔒 SAFETY -- verified before shipping, not assumed. Applying `^[A-Za-z][A-Za-z0-9_]*$` to all
    # 316 columns of a real Detailed workbook rejected **17, and all 17 were `*@odata.type`**; zero
    # legitimate columns failed (`TenantId` and `Type` pass -- they are renamed later BY THE INGEST
    # MODULE, which is correct and unrelated). Rows are rebuilt ONLY when they actually carry an
    # illegal property, so the normal case costs one property-name scan and allocates nothing.
    #--------------------------------------------------------------------------------------------
    $_RAIllegalColName = [regex]'^[A-Za-z][A-Za-z0-9_]*$'
    $_odataRowsFixed   = 0
    $_odataColsDropped = New-Object 'System.Collections.Generic.HashSet[string]'

    $_cleanFinal = New-Object 'System.Collections.Generic.List[object]'
    foreach ($_row in $global:final) {
        if ($null -eq $_row) { continue }

        $_hasIllegal = $false
        foreach ($_p in $_row.PSObject.Properties) {
            if (-not $_RAIllegalColName.IsMatch($_p.Name)) { $_hasIllegal = $true; break }
        }

        if (-not $_hasIllegal) { [void]$_cleanFinal.Add($_row); continue }

        $_kept = [ordered]@{}
        foreach ($_p in $_row.PSObject.Properties) {
            if ($_RAIllegalColName.IsMatch($_p.Name)) { $_kept[$_p.Name] = $_p.Value }
            else { [void]$_odataColsDropped.Add($_p.Name) }
        }
        [void]$_cleanFinal.Add([pscustomobject]$_kept)
        $_odataRowsFixed++
    }
    $global:final = $_cleanFinal.ToArray()
    # Delivery starts here: what only built the result is let go first -- the export pool (its rows live on in
    # $global:final) and the last report's own query result and working sets (a large install ran out of memory in delivery).
    $_cleanFinal = $null
    $global:AllShapedRows.Clear()
    $ResultAll = $null; $ResultFiltered = $null; $RiskScoreArray = $null; $Shaped = $null; $resp = $null; $FilteredOut = $null

    # #264 -- RISK ANALYSIS'S OWN READ-TIME VIEW. $global:final keeps EVERY row (exempted ones marked) and is what Log
    # Analytics receives: the raw data never loses an exempted finding. The workbook, the JSON sibling, the AI summary, the
    # KPIs and the mail are views of the run, and count exempted findings only when SI_Exempted_CountInManagement says so.
    $__raView = Select-RAReportRows -Rows @($global:final) -IncludeExempted:([bool]$global:SI_Exempted_CountInManagement)
    $global:RA_ReportRows = @($__raView.Rows)
    $global:RA_ExemptedNotCounted = [int]$__raView.Exempted
    if ($global:RA_ExemptedNotCounted -gt 0) { Write-Info ("{0} exempted finding(s) are kept in Log Analytics and not counted in the workbook, the summary or the mail (SI_Exempted_CountInManagement is off)." -f $global:RA_ExemptedNotCounted) }
    # #274 -- THE EXCEL + MAIL OUTPUT SCOPE (Pro): the same read-time view, narrowed to the reports / severities / tiers /
    # domains the operator chose for Excel and mail. Log Analytics (and so every connector) still receives every row.
    $__excelScope = Get-SIOutputScope -Destination 'excel'
    if ($null -ne $__excelScope) {
        $__scoped = Select-SIOutputScopeRows -Rows @($global:RA_ReportRows) -Scope $__excelScope
        $global:RA_ReportRows = @($__scoped.Rows)
        Write-Info ("Excel and mail show {0} of {1} row(s): the output scope for Excel + mail lets through {2}. Log Analytics keeps every row." -f @($global:RA_ReportRows).Count, (@($global:RA_ReportRows).Count + [int]$__scoped.Dropped), (Get-SIOutputScopeText $__excelScope))
    }

    # The workbook takes its columns from this list via a STRICT Select-Object, so it must be
    # filtered too -- otherwise the column survives as an empty column even with no row carrying it.
    if ($global:FinalDesiredColumns) {
        $_beforeCols = @($global:FinalDesiredColumns).Count
        $global:FinalDesiredColumns = @($global:FinalDesiredColumns | Where-Object { $_RAIllegalColName.IsMatch([string]$_) })
        $_droppedCols = $_beforeCols - @($global:FinalDesiredColumns).Count
        if ($_droppedCols -gt 0 -or $_odataRowsFixed -gt 0) {
            # 🔒 DIAGNOSTIC, NOT CUSTOMER-FACING. This used to be Write-Info and it reached every
            # customer log. "[odata] dropped 17 artefact column(s)" means nothing to an operator who
            # has never heard of OData annotations, and it reads like the export lost data -- it
            # generated support calls. Nothing was lost: these columns are Graph type annotations
            # that were never real findings, and the table never had them. Keep the detail for a
            # -Verbose run; say nothing on a normal one.
            Write-Diag ("[odata] dropped {0} artefact column(s) from the export; they were introduced by {1} row(s) of {2}. Log Analytics was already clean." -f `
                        $_droppedCols, $_odataRowsFixed, @($global:final).Count)
            if ($_odataColsDropped.Count -gt 0) {
                Write-Diag ("[odata] names: {0}" -f ((@($_odataColsDropped) | Sort-Object) -join ', '))
            }
        }
    }
    elseif ($_odataRowsFixed -gt 0) {
        Write-Info ("[odata] stripped artefact properties from {0} row(s)" -f $_odataRowsFixed)
    }
    # The workbook itself: Invoke-RAWorkbookStep (RA-WorkbookExport.ps1), just below -- the same step the database path takes.
}

if (-not $script:RAStreamOn) { $script:RAAllCount = [long]@($global:final).Count; $script:RAViewCount = [long]@($global:RA_ReportRows).Count }
# Without the database (the result in memory, as before) there is no collection to complete: the workbook is written here.
# With it, after the run's result is completed in the database (below the guards). Never fails the run either way.
if (-not $script:RAStreamOn) { Invoke-RAWorkbookStep }

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
    # #744 (a large customer 2026-10-17: 52 silent minutes uploading this file at the end): when the export destination is
    # Azure Storage, the file's bytes go up as blocks WHILE it is written (Send-SecurityInsightExportFile.ps1); the upload
    # step then only backs up the previous file and commits them. Never on a dry run (nothing is uploaded then).
    $script:RAJsonStaged = $null
    if (-not $script:SIWhatIf -and -not [string]::IsNullOrWhiteSpace([string]$global:ExportDestination)) {
        try {
            if (-not (Get-Command -Name New-SIExportStagedUpload -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_shared/Send-SecurityInsightExportFile.ps1') }
            $script:RAJsonStaged = New-SIExportStagedUpload -Destination ([string]$global:ExportDestination) -FileName ([System.IO.Path]::GetFileName($global:OutputJson))
        } catch { $script:RAJsonStaged = $null; Write-Diag ("the JSON file is uploaded from the disk at the upload step: {0}" -f $_.Exception.Message) }
    }
    try {
        # -InputObject, not the pipeline: piped, 0 rows wrote an EMPTY file and 1 row a bare object instead of
        # a one-element array -- a consumer reading the JSON as a list broke on exactly those two cases (#121).
        # Row by row to the file (RA-Delivery.ps1): the whole result as ONE string ran a large install out of memory.
        # #744: the next page read from the database while this one is written; the rows' text made on several cores.
        if ($script:RAStreamOn) {
            $__phJsonSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
            Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $script:RAStream -Source View -ReadAhead) -Path $global:OutputJson -Depth 20 -Upload $script:RAJsonStaged -Total $script:RAViewCount
            Write-Info (Format-RAAfterReportsLine -What 'the JSON file' -Seconds $__phJsonSw.Elapsed.TotalSeconds -Rows ([long]$script:RAViewCount))
            Write-RAStepPhaseRow -Stream $script:RAStream -Phase 'after the reports: the JSON file' -Seconds $__phJsonSw.Elapsed.TotalSeconds -Rows ([long]$script:RAViewCount)
        }
        else { Write-RAJsonArrayFile -Rows $global:RA_ReportRows -Path $global:OutputJson -Depth 20 -Upload $script:RAJsonStaged -Total $script:RAViewCount }
        if ($script:RAJsonStaged) { $null = Complete-SIExportStagedUpload -Upload $script:RAJsonStaged }
        Write-Ok ("json file ready: {0}" -f $global:OutputJson)
    } catch {
        if ($script:RAJsonStaged) { Stop-SIExportStagedUpload -Upload $script:RAJsonStaged -Why $_.Exception.Message }
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
# #743 (1), owner 2026-10-17: DELIVER FROM SQL FIRST, THE LOG ANALYTICS COPY AFTER. With the result in the database the
# collection is completed and delivered from SQL first (below, "THE END"); this Log Analytics copy is sent AFTER it, and a
# copy that fails makes the run PARTIAL, said plainly -- it no longer holds the delivery (Complete-RALaCopy). Without the
# database (the result in memory) the copy is sent here, as before. The block runs in this scope (dot-sourced).
$script:RALaPhase = {
$RiskAnalysis_DcrName_Summary  = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DcrName_Summary))  { [string]$global:SI_RiskAnalysis_DcrName_Summary }  else { 'dcr-si-risk-analysis-summary' }
$RiskAnalysis_DcrName_Detailed = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_DcrName_Detailed)) { [string]$global:SI_RiskAnalysis_DcrName_Detailed } else { 'dcr-si-risk-analysis-detailed' }

# #830 (owner 2026-10-20): "Copy Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL)" is an OPTIONAL
# output, OFF by default in every install: SecurityInsight reads the result from its database. ONE rule for its value
# (RA-Findings.ps1 Test-SIRaReportCopyOn: on only for an explicit true / 'on'); a text 'false' is never on.
if (-not (Get-Command -Name Test-SIRaReportCopyOn -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_shared/RA-Findings.ps1') }
$global:SendToLogAnalytics = [bool](Test-SIRaReportCopyOn -Value $global:SendToLogAnalytics)
if (-not [bool]$global:SendToLogAnalytics) {
    if ($script:RAStreamOn) { Write-Info 'report rows: the copy to Log Analytics (SI_RiskAnalysis_Detailed_CL) is off (the default) -- SecurityInsight reads the result from its database' }
    elseif (-not $script:SIWhatIf) { Write-Warn2 'report rows: the result of this run could not go to the database and the copy to Log Analytics (SI_RiskAnalysis_Detailed_CL) is off -- it is kept only in this run''s files and mail; SecurityInsight''s pages keep the last result the database holds until a run writes there again' }
}
if ($script:SIWhatIf -and [bool]$global:SendToLogAnalytics) {
    Write-Info ("[dry run] Log Analytics ingest skipped: {0} row(s) would have been sent." -f $script:RAAllCount)
    $global:SendToLogAnalytics = $false
}

if ([bool]$global:SendToLogAnalytics -and ($script:RAAllCount -eq 0)) {
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
        $modOk = $true   # the ingestion is plain REST (engine/_shared/SI-LogIngest.ps1) -- nothing to load

        if ($modOk) {
            # Build DCE/DCR cache + self-heal infra (creates workspace + DCE + DCR RG + RBAC if missing).
            # Shared logic mirrors Validate-SILogAnalytics.ps1.
            . (Join-Path $PSScriptRoot '_shared/Ensure-SecurityInsightInfra.ps1')   # forward slash works on both Win + Linux
            # #222: on a VM signing in as its managed identity there is no SPN app id ($global:SpnClientId is empty; a
            # container sets it to the identity's client id). The ingestion never uses the app id with -UseManagedIdentity,
            # but the parameters require a non-empty value: the client id when known, else a placeholder for the
            # system-assigned identity. The SPN object id lookup is for an SPN only -- an identity's grants come from setup.
            $__raMi = [bool]((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity))
            $__raIngestAppId = if (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientId)) { [string]$global:SpnClientId }
                               elseif ($__raMi -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_UAMI_ClientId)) { [string]$global:SI_UAMI_ClientId }
                               elseif ($__raMi) { '00000000-0000-0000-0000-000000000000' }
                               else { [string]$global:SpnClientId }
            try {
                # Resolve SPN object ID for RBAC assignments (an SPN only)
                $spnObj = if (-not $__raMi -and $global:SpnClientId) { Get-SIAzADServicePrincipal -ApplicationId $global:SpnClientId -ErrorAction SilentlyContinue } else { $null }
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
                    try { $laSubId = (Get-SIAzContext -ErrorAction Stop).Subscription.Id } catch { }
                }
                if (-not $laSubId) { throw "Cannot determine subscription ID for workspace resolution -- set `$global:SubscriptionId or provide a full WorkspaceResourceId" }

                try { Set-SIAzContext -SubscriptionId $laSubId -TenantId $global:SpnTenantId -ErrorAction Stop | Out-Null } catch { }

                # If workspace RG exists, use its location (more accurate than the default)
                try { $__rgLoc = (Get-SIAzResourceGroup -Name $laWsRg -ErrorAction Stop).Location; if ($__rgLoc) { $laLocation = $__rgLoc } } catch { }

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

                # The ingest calls below carry their own sign-in ($__ingestAuth) and mint their own tokens over REST.


                # v2.2.271 -- cert OR secret auth. Build a splat once and reuse at all
                # 4 ingest call sites. Passing $global:SpnClientSecret='' to the module
                # under cert auth triggered ParameterBindingValidationException ("Cannot
                # bind argument to parameter 'AzAppSecret' because it is an empty string").
                $__ingestAuth = @{}
                if ((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity)) {
                    # #209: the container job's managed identity ($global:SpnClientId is that identity's client id).
                    $__ingestAuth['UseManagedIdentity']      = $true
                    $__ingestAuth['ManagedIdentityClientId'] = [string]$global:SI_UAMI_ClientId
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)) {
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
                              -AzAppId              $__raIngestAppId `
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
            Write-Info ("  rows: {0}" -f $script:RAAllCount)
            # 🔑 v2.2.445 -- THE INGEST WAS THE ONLY EXPENSIVE PHASE WITH NO TIMING.
            # Graph connect, yaml load, each hunting query, result conversion, filters, risk scoring,
            # the final sort and the Excel export are all Tick'd -- so when an operator asked "is the
            # Log Analytics upload what's taking hours?" on a 121k-row run, the transcript could not
            # answer it. Every other candidate could be measured and this one could not, which is the
            # worst possible place for a blind spot. Now it reports like the rest.
            Tock

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
                # #638: one pass over the run's rows a page at a time (from SQL; or the result in memory as one page) -- the
                # schema sample, the columns that need a companion and the key columns empty on every row, all decided from
                # EVERY row as before, never by holding them all.
                $__keyCols = @(Get-RAIngestKeyColumns | Where-Object { $_ -ne 'CollectionTime' })
                $__laTypes = Get-RALaTableColumnTypes -WorkspaceResourceId $laWs -TableName $laTable
                $schemaSample = @(); $__decCols = @(); $__txtCols = @(); $__numCols = @(); $__keyGaps = @($__keyCols)
                $__pgS = if ($script:RAStreamOn) { New-RARowPager -Stream $script:RAStream -Source All } else { New-RARowPager -Rows $global:final }
                while ($null -ne ($__pgPage = $__pgS.Next())) {
                    $schemaSample = @(Get-RASchemaCoverageSample -Rows (@($schemaSample) + @($__pgPage)) -BaseCount 100)
                    if ($null -ne $__laTypes -and $__laTypes.Count -gt 0) {
                        $__decCols = @(@($__decCols) + @(Get-RALaDecimalCompanions -Rows @($__pgPage) -Types $__laTypes) | Select-Object -Unique)
                        $__txtCols = @(@($__txtCols) + @(Get-RALaTextCompanions -Rows @($__pgPage) -Types $__laTypes) | Select-Object -Unique)
                        $__numCols = @(@($__numCols) + @(Get-RALaNumberCompanions -Rows @($__pgPage) -Types $__laTypes) | Select-Object -Unique)
                    }
                    if ($__keyGaps.Count -gt 0) { $__keyGaps = @(Get-RAIngestKeyColumnGaps -Rows @($__pgPage) -Columns $__keyGaps) }
                    $__pgPage = $null
                }
                $__pgS = $null

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
                $schemaSample = @(Repair-SILogColumnName -Data $schemaSample -Verbose:$false 4>$null)
                $__legalSample = foreach ($__row in $schemaSample) {
                    $__o = [ordered]@{}
                    foreach ($__p in $__row.PSObject.Properties) {
                        if ($__p.Name -match '^[A-Za-z][A-Za-z0-9_]*$') { $__o[$__p.Name] = $__p.Value }
                    }
                    [pscustomobject]$__o
                }
                $schemaSample = @($__legalSample)

                # #148 -- A VALUE WHOSE TYPE DOES NOT MATCH THE EXISTING COLUMN IS DISCARDED BY LOG
                # ANALYTICS, SILENTLY. Column types are fixed at table creation and this ingest declares
                # them from a sample, so a column born `string` drops every later int (measured: the
                # Detailed table kept CriticalityTier on ~13% of rows). Read the REAL types and convert
                # the sample (so the DCR is declared to match the table) and, below, every posted row.
                if ($null -eq $__laTypes) {
                    Write-Warn ("  column types of {0} could not be read -- values are posted as built; a column whose type differs from the table's will lose them." -f $laTable)
                } elseif ($__laTypes.Count -gt 0) {
                    # A whole-number column that receives a FRACTIONAL value (a CVSS of 7.9 in `Impact`, born
                    # int) gets a `<column>_Exact` companion holding the exact value (as invariant text). Decided from EVERY row,
                    # not the sample, and declared through the sample so the DCR carries it.
                    # ... and one that receives TEXT (a sentence in `Impact`) gets `<column>_Text`; and a datetime column that
                    # receives a NUMBER (LastSignInDays, born datetime) gets `<column>_Number` -- all three from the pass above
                    $null = Set-RALaColumnTypes -Rows $schemaSample -Types $__laTypes -DecimalCompanions $__decCols -TextCompanions $__txtCols -NumberCompanions $__numCols -EnsureCompanionTyped
                }

                Write-Info ("  schema sample: {0} row(s) covering {1} column(s) (of {2} row(s))" -f `
                    $schemaSample.Count,
                    (@($schemaSample | ForEach-Object { $_.PSObject.Properties.Name } | Sort-Object -Unique)).Count,
                    $script:RAAllCount)

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
                $null = Update-SILogTableSchema `
                            -AzLogWorkspaceResourceId                   $laWs `
                            -AzAppId                                    $__raIngestAppId `
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
                    -AzAppId           $__raIngestAppId `
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
                # IN CHUNKS (RA-Delivery.ps1, a large install 2026-10-13: the whole result copied, then rebuilt, ran the
                # run out of memory before a single row was posted). Each chunk is prepared exactly as the whole set was --
                # COPIES (the type alignment ROUNDS in place, and nothing after ingest -- the AI summary, the mail -- may
                # see a rounded value), the run's collection time (stamped upstream; the call is a safety net), the host
                # columns, legal names, the chunk's columns on every row, every value to its column's REAL type (#148) --
                # and posted before the next chunk is built. Sized by measured bytes; the rows posted are counted.
                # A Linux container has no COMPUTERNAME / USERNAME, and an empty value fails the parameter binding,
                # so the upload never happened from a container (live 2026-10-03) -- same fallbacks as the profilers.
                $__raHost = if ($env:COMPUTERNAME) { [string]$env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
                $__raFqdn = if ($global:RA_DnsName) { [string]$global:RA_DnsName } else { $__raHost }
                $__raUser = if ($env:USERNAME) { [string]$env:USERNAME } elseif ($env:USER) { [string]$env:USER } else { 'container' }

                # #294 -- a snapshot whose KEY columns are empty on every row is never posted: it cannot be shown,
                # loaded as a day or trended, and posting it would look like a successful run. The run fails instead.
                # Checked on the result BEFORE the first chunk is posted (CollectionTime is stamped by the preparation, so
                # it is not judged here); the prepared chunks are checked again as they go (after the loop, below).
                if ($__keyGaps.Count -gt 0) {
                    throw (New-Object System.IO.InvalidDataException((Get-RAIngestKeyColumnMessage -Columns $__keyGaps -Rows $script:RAAllCount -TableName $laTable)))
                }

                $global:EnableCompressionDefault = $true
                $script:_RALaRowsPosted = 0L
                # #638: the rows a page at a time (from SQL, in the final order), each page posted in chunks before the next is
                # read -- or the result in memory as one page. The counts, the type report and the key check over every page.
                # #738: the pages are read ahead while a page is posted, and the posts are made by a sender for the table
                # (each filled close to the API's limit, up to 4 in flight, 429 / Retry-After honoured); the parts, the
                # prepared rows and their JSON are what they were. RowsPosted = the rows the service CONFIRMED.
                $__pgL = if ($script:RAStreamOn) { New-RARowPager -Stream $script:RAStream -Source All -ReadAhead } else { New-RARowPager -Rows $global:final }
                $__laDelivery = Invoke-RALaPagedPost -Pager $__pgL -KeyColumns @(Get-RAIngestKeyColumns) -TableName $laTable `
                    -Prepare {
                        param($__chunk)
                        ConvertTo-RALaPostRows -Rows $__chunk -HostName $__raHost -Fqdn $__raFqdn -User $__raUser `
                            -Types $__laTypes -DecimalCompanions $__decCols -TextCompanions $__txtCols -NumberCompanions $__numCols
                    } `
                    -Post {
                        param($__prepared)
                        Send-SILogData `
                            -DceName     $laDceName `
                            -DcrName     $laDcrName `
                            -Data        $__prepared `
                            -TableName   $laTable `
                            -AzAppId     $__raIngestAppId `
                            @__ingestAuth `
                            -TenantId    $global:SpnTenantId `
                            -Verbose:$false 4>$null
                    } `
                    -OnChunk {
                        param($__n, $__handed, $__confirmed)
                        $script:_RALaRowsPosted = [long]$__confirmed
                        Write-Info ("  Log Analytics: part {0} handed over -- {1} of {2} row(s) so far, {3} confirmed" -f $__n, $__handed, $script:RAAllCount, $__confirmed)
                    } `
                    -OnStopped { param($__confirmed) $script:_RALaRowsPosted = [long]$__confirmed }
                $__pgL = $null
                $script:_RALaRowsPosted = [long]$__laDelivery.RowsPosted
                if ($__laDelivery.Sender) { Write-Info ("  Log Analytics: {0} row(s) confirmed in {1} post(s)" -f $__laDelivery.RowsPosted, $__laDelivery.Posts) }
                if ([long]$__laDelivery.RowsPosted -ne $script:RAAllCount) { throw ("Posted {0} of {1} row(s) -- the other rows are UNKNOWN, not posted." -f $__laDelivery.RowsPosted, $script:RAAllCount) }

                # #148 -- what the type alignment did, over every chunk (see the sample step above).
                if ($__laTypes -and $__laTypes.Count -gt 0) {
                    $__align = $__laDelivery.Align
                    foreach ($__c in ($__align.MovedToNumber.Keys | Sort-Object)) {
                        Write-Info ("  column types: {0} number(s) in the datetime column '{1}' -- stored in '{1}_Number' (the column's type cannot change)." -f $__align.MovedToNumber[$__c], $__c)
                    }
                    foreach ($__c in ($__align.MovedToText.Keys | Sort-Object)) {
                        Write-Info ("  column types: {0} text value(s) in the number column '{1}' -- stored in '{1}_Text'." -f $__align.MovedToText[$__c], $__c)
                    }
                    foreach ($__c in ($__align.Rounded.Keys | Sort-Object)) {
                        Write-Info ("  column types: {0} decimal value(s) in '{1}' -- exact in '{1}_Exact' (as text, e.g. 7.9), rounded in '{1}' (a whole-number column)." -f $__align.Rounded[$__c], $__c)
                    }
                    $__conv  = @($__align.Converted.Keys | Sort-Object)
                    if ($__conv.Count) {
                        Write-Info ("  column types: {0} value(s) converted to the table's type in {1} column(s): {2}" -f `
                            (@($__align.Converted.Values) | Measure-Object -Sum).Sum, $__conv.Count, ($__conv -join ', '))
                    }
                    foreach ($__c in ($__align.Failed.Keys | Sort-Object)) {
                        Write-Warn ("  column types: {0} value(s) in '{1}' cannot be stored as {2} and will be EMPTY in Log Analytics (the export keeps them)." -f `
                            $__align.Failed[$__c], $__c, $__laTypes[$__c])
                    }
                }

                # #294 -- a key column the preparation left empty on every row (a value its column's type cannot hold):
                #    the rows went out, but the snapshot cannot be placed -- the run fails (not delivered in full), so
                #    nothing downstream reads this run as a complete one.
                if (@($__laDelivery.KeyGaps).Count -gt 0) {
                    throw ("the rows were posted, but the snapshot cannot be placed: {0}" -f (Get-RAIngestKeyColumnMessage -Columns @($__laDelivery.KeyGaps) -Rows ([long]$__laDelivery.RowsPosted) -TableName $laTable))
                }

                Tick "log analytics ingest"   # v2.2.445 -- see the Tock beside "Ingesting to..."
                Write-Ok ("ingested to {0}_CL ({1} row(s) in {2} part(s))" -f $laTable, $__laDelivery.RowsPosted, $__laDelivery.Chunks)
                # #394: the rows Log Analytics received -- for the trend row and the findings at the end of the run. The
                # result's OWN rows, not a kept copy of every posted part (that was a second full copy of the result):
                # a posted row differs from its source only by the host columns, legal names, empty columns of its part
                # and values its column's type converted -- none of which the trend or the findings read. Set only
                # once every part was posted and counted.
                # #638: from SQL, the trend and the findings read the stored rows. #774: assigned IN each branch -- an `if`
                # expression that yields @() assigns $null in PowerShell, and $null here means "nothing was published":
                # every SQL-published Detailed run then silently skipped the findings (SI_Finding_CL, sidata.CiFinding).
                if ($script:RAStreamOn) { $script:_RAPublishedRows = @() } else { $script:_RAPublishedRows = $global:final }
                $__laDelivery = $null
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
                # #294: a REFUSED post (key columns empty on every row, or a data collection rule that does not declare
                # a column of the data) fails the run -- see the end of this script. Said as an error, not a warning.
                if ($_.Exception -is [System.IO.InvalidDataException]) {
                    $__refusal = ("Log Analytics: {0}_CL was NOT written -- {1}" -f $laTable, $_.Exception.Message)
                    Write-Err2 $__refusal
                    try { [void]$script:_RAIngestRefused.Add($__refusal) } catch { }
                }
                Write-Warn ("Log Analytics ingest failed: {0}{1} (the workbook and the JSON file are still on disk; this run ends as failed)" -f $_.Exception.Message, $_codeSuffix)
                # The run's own result did not reach Log Analytics in full: recorded for run health (Send-RARunHealthEnd),
                # and the run ENDS FAILED at the end of this script (after the mail, the guards and the run-health record).
                try { [void]$script:_RAPublishFailures.Add(("Log Analytics: {0}_CL was not written in full ({1}{2})" -f $laTable, $_.Exception.Message, $_codeSuffix)) } catch { }
                if (-not ($_.Exception -is [System.IO.InvalidDataException])) {
                    try { [void]$script:_RAResultNotDelivered.Add(("{0}_CL did not receive this run's result in full: {1}{2}" -f $laTable, $_.Exception.Message, $_codeSuffix)) } catch { }
                }
                Write-Warn '----- ingest target context -----'
                Write-Warn ("  DCR              : {0}  (rg={1})" -f $laDcrName, $global:SI_DcrResourceGroup)
                Write-Warn ("  DCE              : {0}" -f $laDceName)
                Write-Warn ("  Table            : {0}" -f $laTable)
                Write-Warn ("  Workspace        : {0}  (rg={1})" -f $global:SI_WorkspaceName, $global:SI_WorkspaceResourceGroup)
                Write-Warn ("  Subscription     : {0}" -f $global:SI_AzSubscriptionId)
                Write-Warn ("  SPN AppId        : {0}" -f $global:SpnClientId)
                Write-Warn ("  Rows attempted   : {0}" -f $script:RAAllCount)
                Write-Warn ("  Rows posted      : {0} (before the failure)" -f [long]$script:_RALaRowsPosted)
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
}
if (-not $script:RAStreamOn) { . $script:RALaPhase }

#########################################################################################################
# THE COLLECTION IS COMPLETED HERE -- BEFORE THE WORKBOOK, THE UPLOAD, THE AI SUMMARY AND THE MAIL (live 2026-10-16: a
# Detailed run stored all 65 reports, 1,167,338 rows, then ran out of memory building the workbook; the collection was
# never marked, the replica was restarted and a whole new run began). The guards, the per-report verdicts and the
# completion of the run's result in the database run first; the workbook and the mail are convenience outputs read
# from the completed result and can never decide whether the collection is delivered.
# A run that must end failed (Log Analytics did not receive the result, the result could not be completed) is recorded
# here and ENDS FAILED at the end of the script, after the workbook and the mail, exactly as before.
#########################################################################################################
$script:_RAEndFailure = $null
# 🔴 AUDIT #62 -- THE RUN-LEVEL ROLL-UP, and it sits ABOVE the row-count guard on purpose.
# The guard is the thing an operator trusts to say "nothing went missing", and on the run that
# exposed this it printed "no report lost its findings" while ~1,100 findings were absent. So the
# roll-up has to be read FIRST, and it has to say plainly that the guard cannot see this class.
# 📌 Deliberately not fatal. Every report that survived is still correct and still worth having;
# what must not happen is a partial run reading as a clean one.
try {
    if ($null -ne $script:_RABucketLossRun -and $script:_RABucketLossRun.Count -gt 0) {
        Write-Section "INCOMPLETE DATA -- buckets lost this run"
        $__lossByReport = @{}
        foreach ($entry in $script:_RABucketLossRun) {
            $__rn = ($entry -split ' :: ', 2)[0]
            $__lossByReport[$__rn] = [int]$__lossByReport[$__rn] + 1
        }
        Write-Err2 ("{0} bucket(s) across {1} report(s) produced NO rows this run. Those findings are missing from the workbook, the Log Analytics table and the email." -f `
            $script:_RABucketLossRun.Count, $__lossByReport.Keys.Count)
        foreach ($k in ($__lossByReport.Keys | Sort-Object)) {
            Write-Err2 ("    {0}  --  {1} bucket(s) lost" -f $k, $__lossByReport[$k])
        }
        Write-Err2 ("The row-count guard below CANNOT detect this: it asks whether a report lost ALL of its findings, and these reports still produced rows. Re-run the affected reports -- a bucket lost to a 500 or a timeout usually succeeds next time.")
    } else {
        Write-Info ("[BucketLoss] every bucket in every report contributed -- no partial reports this run.")
    }
} catch { }

# owner 2026-10-17 (guards heal themselves): a guard of this run is CLEARED only when the run is complete -- every report
# delivered a whole result and no bucket was lost. A run that is not complete never clears a guard.
function Test-RAGuardRunComplete {
    $inc = 0; $lost = 0
    try { $inc = @($script:_RAIncompleteReports | Where-Object { $_ }).Count } catch { $inc = 1 }
    try { $lost = @($script:_RABucketLossRun | Where-Object { $_ }).Count } catch { $lost = 1 }
    ($inc -eq 0) -and ($lost -eq 0)
}

# #900 A SOURCE THAT WENT SILENT: every report reading a source table that had rows and now has none -- also as a lookup --
# is NOT COMPLETE this run (it keeps its last complete result and nothing of it closes; the per-report freeze below), said
# in a WARNING every run with the table's last non-zero count and date and what an Admin can do. Before the row-count
# guard, so the run's list of incomplete reports carries them. Never fails the run.
if ($script:RAStreamOn -and $null -ne $script:RASourceCounts -and $null -ne $script:RASourceMap) {
    try {
        $__ss = Invoke-RASilentSourceCheck -Invoke $script:RAStream.Invoke -TimeText ([string]$script:RAStream.TimeText) -Grain ([string]$script:RAStream.Grain) -Map $script:RASourceMap.Reports `
                    -Counts $script:RASourceCounts -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } } -Accepted $script:RASourceAccepted
        foreach ($__w in @($__ss.Warnings)) { Write-Warn2 $__w }
        foreach ($__h in @($__ss.Holds)) {
            $__hw = ('not complete: {0}' -f [string]$__h.Why)
            Add-RAReportFailure -ReportName ([string]$__h.Report) -Reason $__hw
            # #901 a silent source is a deliberate hold (the run still publishes); the fallback (the count could not be had) is not
            # #902: with the silent tables it is about (HoldNames: the uplink's MissingName, what an Admin may accept as empty)
            if (-not $__h.Fallback) { Add-RADeliberateHold -Store $script:RADeliberateHolds -Report ([string]$__h.Report) -Kind 'silent-source' -Why $__hw -Names @($__h.Tables) }
        }
        # #902 (5): an acceptance whose source has rows again, or whose report no longer reads the source, is cleared by this
        # run (cfg.RaSourceAccept + its cfg.ChangeLog row) -- the report is judged as usual from the next run
        if (@($script:RASourceAcceptRows).Count -and $global:SI_ProSettingsStore -and $global:SI_ProSettingsStore.Invoke) {
            try {
                $__acClears = @(Get-RASourceAcceptClears -Rows @($script:RASourceAcceptRows) -Counts $script:RASourceCounts.Counts -Map $script:RASourceMap.Reports -RunReports @($global:RA_TemplateReportNames))
                if ($__acClears.Count) {
                    $null = & $global:SI_ProSettingsStore.Invoke (Get-RASourceAcceptSql 'Clear') @{ clears = (ConvertTo-Json -InputObject @($__acClears | ForEach-Object { [ordered]@{ Id = $_.Id; How = $_.How } }) -Compress); runId = [string]$global:SI_RunId } 'scalar'
                    foreach ($__l in @(Get-RASourceAcceptLines -Clears $__acClears)) { Write-Info $__l }
                }
            } catch { Write-Warn2 ("source acceptance: the acceptances could not be cleared this run ({0}) -- the next run tries again" -f $_.Exception.Message) }
        }
        foreach ($__b in @($__ss.Back)) { Write-Info ("source {0} has rows again ({1}) -- the reports reading it are judged as usual" -f $__b, [long]$__ss.Tables[$__b].Rows) }
        if (@($__ss.Holds).Count) { Write-Warn2 ("{0} report(s) held for a source that went silent: {1}" -f @($__ss.Holds).Count, (@($__ss.Holds | ForEach-Object { $_.Report }) -join ', ')) }
    } catch { Write-Warn2 ("source count: the silent-source check could not be made this run ({0}) -- no report is held for it" -f $_.Exception.Message) }
}

# AUDIT #57.1(a) -- compare this run against the previous one and say so out loud. Runs only on a
# completed run, so a crashed/partial run never poisons the baseline with its truncated counts.
try {
    # Runs when ANY report was attempted -- not only when some produced a count. A run in which EVERY
    # report failed has no counts at all, and it is exactly the run this guard most needs to speak about.
    $__attempted = @()
    if ($null -ne $global:RA_ReportsAttemptedThisRun) { $__attempted = @($global:RA_ReportsAttemptedThisRun.ToArray()) }
    if (($null -ne $global:RA_RowCountsThisRun -and $global:RA_RowCountsThisRun.Count -gt 0) -or $__attempted.Count -gt 0) {
        if ($null -eq $global:RA_RowCountsThisRun) { $global:RA_RowCountsThisRun = @{} }
        Write-Section "row-count guard"
        $__tplName = [string]$global:ReportTemplate
        if ([string]::IsNullOrWhiteSpace($__tplName)) { $__tplName = 'UnknownTemplate' }
        $__rcFindings = Invoke-RARowCountGuard -SettingsPath $global:SettingsPath `
                                       -TemplateName $__tplName `
                                       -Counts $global:RA_RowCountsThisRun `
                                       -Attempted $__attempted
        # A report the guard flags (findings left to a report that failed, far fewer findings than last run, no result) is
        # INCOMPLETE this run -- with the reports whose query failed outright.
        # #414: the row-drop guard switched off (Settings > Guards) -- far fewer findings than last run (LARGE-DROP /
        # WENT-TO-ZERO) no longer makes a report incomplete; a failed query or a missing result still does.
        $__rcForInc = @($__rcFindings)
        if ((Get-Command -Name Test-SIGuardOn -ErrorAction SilentlyContinue) -and @($__rcFindings | Where-Object { $_ -and [string]$_.Kind -in @('LARGE-DROP', 'WENT-TO-ZERO') }).Count -and -not (Test-SIGuardOn -GuardId 'ra.output.row-drop')) {
            $__rcForInc = @($__rcFindings | Where-Object { $_ -and [string]$_.Kind -notin @('LARGE-DROP', 'WENT-TO-ZERO') })
        }
        # #901 a report with no result or a lost hand-off really failed (a drop to none / far fewer is what a deliberate hold explains)
        $script:_RARowCountFlagged = @($__rcForInc | Where-Object { $_ -and [string]$_.Kind -in @('HANDOFF-LOST', 'MISSING') } | ForEach-Object { [string]$_.Report })
        $script:_RAIncompleteReports = @(Get-RAIncompleteReports -Findings @($__rcForInc) -Attempted $__attempted -Counts $global:RA_RowCountsThisRun -Failures @($script:_RAReportFailures.ToArray()))
        if ($script:_RAIncompleteReports.Count -gt 0) {
            Write-Err2 ("{0} report(s) did not deliver a whole result this run. Their findings are UNKNOWN, not remediated, and this run is recorded as partial:" -f $script:_RAIncompleteReports.Count)
            foreach ($__ir in $script:_RAIncompleteReports) { Write-Err2 ("    {0} -- {1}" -f $__ir.Report, $__ir.Why) }
        }
        # #277: one guard event per run listing every report (mail + telemetry; never fails the run)
        if (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) { $null = Invoke-SIGuardCalls -Calls @(Get-SIGuardCallsForRowCount -Findings @($__rcFindings) -Template $__tplName) -Common @{ Engine = 'risk-analysis'; Job = (Resolve-SITelemetryJob -Engine 'risk-analysis' -ReportTemplate $__tplName) } -Checked @('ra.output.row-drop') -Subject $__tplName -Complete (Test-RAGuardRunComplete) }
    }
} catch {
    # A guard must never be the reason a good run fails.
    Write-Warn2 ("[RowCountGuard] skipped: {0}" -f $_.Exception.Message)
}

# AUDIT #57.1(d) -- the column-population half of the same question. Deliberately a SEPARATE try,
# so a fault in either guard cannot take the other one down with it.
try {
    if ($null -ne $global:RA_ColumnFillThisRun -and $global:RA_ColumnFillThisRun.Count -gt 0) {
        Write-Section "column-fill guard"
        $__tplNameC = [string]$global:ReportTemplate
        if ([string]::IsNullOrWhiteSpace($__tplNameC)) { $__tplNameC = 'UnknownTemplate' }
        $__cfFindings = Invoke-RAColumnFillGuard -SettingsPath $global:SettingsPath `
                                         -TemplateName $__tplNameC `
                                         -Snapshots $global:RA_ColumnFillThisRun
        # #277: one guard event per run listing every report and column
        if (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) { $null = Invoke-SIGuardCalls -Calls @(Get-SIGuardCallsForColumnFill -Findings @($__cfFindings) -Template $__tplNameC) -Common @{ Engine = 'risk-analysis'; Job = (Resolve-SITelemetryJob -Engine 'risk-analysis' -ReportTemplate $__tplNameC) } -Checked @('ra.output.column-emptied') -Subject $__tplNameC -Complete (Test-RAGuardRunComplete) }
    }
} catch {
    # A guard must never be the reason a good run fails.
    Write-Warn2 ("[ColumnFillGuard] skipped: {0}" -f $_.Exception.Message)
}

# #640 STEP 2 -- the bucket count jump warning: ONE warning event per run naming every report that needed 4 x its usual
# count or more than 256 (Guards page + the report to Invardia; the run completes).
try {
    # owner 2026-10-17: a run without a jump is checked too -- a complete one clears an earlier jump warning by itself
    if ($null -ne $script:AutoBucketJumps -and (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue)) {
        $__tplNameJ = [string]$global:ReportTemplate
        $null = Invoke-SIGuardCalls -Calls @(Get-SIRaBucketJumpGuardCalls -Jumps @($script:AutoBucketJumps.ToArray()) -Template $__tplNameJ) -Common @{ Engine = 'risk-analysis'; Job = (Resolve-SITelemetryJob -Engine 'risk-analysis' -ReportTemplate $__tplNameJ) } `
                    -Checked @('ra.bucket.count-jump') -Subject $__tplNameJ -Complete (Test-RAGuardRunComplete)
    }
} catch {
    Write-Warn2 ("[BucketJump] skipped: {0}" -f $_.Exception.Message)
}

# What this run was BUILT on: a profile whose own newest run was partial (a failed post, columns not yet stored) makes
# this run partial too -- see Get-SIUpstreamOutcome. Unknown (no record, or it cannot be read) changes nothing.
try {
    if ((Get-Command -Name Get-SIUpstreamRunHealthKql -ErrorAction SilentlyContinue) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId) -and -not $script:SIWhatIf) {
        $__up = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -Query (Get-SIUpstreamRunHealthKql) -TimeoutSec 120   # plain assignment: the function comma-protects its rows
        $script:_RAUpstreamOutcome = Get-SIUpstreamOutcome -Rows $__up
        # #899: partial ONLY because the identity run's role read was not complete -> the reports that read role lists or
        # shadow admin are NOT COMPLETE (named, so only they are frozen); the rest of the run is not held for it
        $__rr = Resolve-RARoleReadUpstream -Outcome $script:_RAUpstreamOutcome -Reports @($global:Exposure_Reports) -Names @($global:RA_TemplateReportNames)
        if ([string]$__rr.Why) {
            $script:_RAUpstreamOutcome = $__rr.Outcome
            foreach ($__rn in @($__rr.Reports)) {
                Add-RAReportFailure -ReportName ([string]$__rn) -Reason ('not complete: ' + [string]$__rr.Why)
                Add-RADeliberateHold -Store $script:RADeliberateHolds -Report ([string]$__rn) -Kind 'role-read' -Why ('not complete: ' + [string]$__rr.Why)   # #901
                $script:_RAIncompleteReports = @(@($script:_RAIncompleteReports) + @([pscustomobject]@{ Report = [string]$__rn; Why = [string]$__rr.Why }))
            }
            Write-Warn2 ("The Entra role read of the newest identity run was not complete: {0} report(s) that read role lists are NOT COMPLETE in this run and nothing of them is closed ({1}); every other report is complete" -f @($__rr.Reports).Count, (@($__rr.Reports) -join ', '))
        }
        if ($script:_RAUpstreamOutcome.ExitReason -ne 'success') { Write-Warn2 ("This run is partial: {0}" -f $script:_RAUpstreamOutcome.Message) }
    }
} catch { Write-Diag ("profile run-health check skipped: {0}" -f $_.Exception.Message) }

# #533 (c): the one line that says how many disabled accounts the reports left out (SI_DisabledAssets_RiskAnalysis off).
try {
    if ($script:RA_DisabledFilteredReports -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId) -and -not $script:SIWhatIf) {
        $__dis = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -Query (Get-SIDisabledIdentityCountKql) -TimeoutSec 120
        $__disN = 0; foreach ($__r in @($__dis)) { if ($null -ne $__r -and $__r.PSObject.Properties['Disabled']) { $__disN = [int]$__r.Disabled } }
        Write-Info (Format-SIDisabledStageLine -Stage RiskAnalysis -Count $__disN -Where ('Risk Analysis ({0} report(s) that keep enabled accounts only)' -f $script:RA_DisabledFilteredReports))
    }
} catch { Write-Diag ("disabled-account count skipped: {0}" -f $_.Exception.Message) }

# #294: a REFUSED Log Analytics post fails the run -- run health 'error', and the job ends failed. The workbook and the
# mail went out above; the snapshot did not, and nothing downstream may read this run as a complete one.
# The same for a result that was NOT DELIVERED IN FULL for any other reason ($script:_RAResultNotDelivered): the files on
# disk and the run-health record are written first, the last lines of the log say what it means, and the throw makes the
# job end failed -- which is what the pipeline reads (a step's exit, never run health), so the steps that need this
# run's result do not start on it.
# #641: EVERY report of the template has a verdict this run. A report with none did not run to the end (it failed, was not
# found, or its query could not be sent): it is NOT COMPLETE -- named in the run record (the run ends partial, nothing
# downstream closes on it) and stored with its reason.
# #877: a report HELD BACK (its rows of this run could not be removed) says so in its reason, wherever the run's report
# reasons go -- this log, the run record, the status report and the database.
if ($script:RAStreamOn) { try { Add-RAHeldReportReasons } catch { Write-Diag ("the held-back reports' reasons could not all be added: {0}" -f $_.Exception.Message) } }
try {
    foreach ($__tn in @($global:RA_TemplateReportNames | Where-Object { $_ })) {
        if ($script:RAReportStatusDone.ContainsKey([string]$__tn)) { continue }
        $__why = @($script:_RAReportFailures | Where-Object { $_ -and [string]$_.Report -eq [string]$__tn } | ForEach-Object { [string]$_.Why }) | Select-Object -First 1
        if (-not $__why) { $__why = 'it is not in this run'; Add-RAReportFailure -ReportName ([string]$__tn) -Reason $__why }
        Write-Warn2 ("completeness: report '{0}' is NOT COMPLETE in this run -- {1}" -f $__tn, $__why)
        $script:RAReportStatusDone[[string]$__tn] = 'NotComplete'
        if ($script:RAStreamOn) { try { Set-RAStreamReportStatus -Stream $script:RAStream -ReportName ([string]$__tn) -State NotComplete -Reason ([string]$__why) } catch { } }
    }
} catch { Write-Warn2 ("completeness: the reports not in this run could not all be recorded -- {0}" -f $_.Exception.Message) }
# #902 (4): each report held on purpose -- how many runs of this grain in a row it is held (its previous verdict row) and when
# its kept result is from. ONE read, before the counts, the mail and the run record use it. Never fails the run: not
# readable = 1 run, kept result not known (never an escalation by guess).
try {
    if ($script:RAStreamOn -and $null -ne $script:RAStream -and @($script:RADeliberateHolds.Keys).Count) {
        $__hsKinds = @{}; foreach ($__k in @($script:RADeliberateHolds.Keys)) { $__hsKinds[[string]$__k] = [string]$script:RADeliberateHolds[$__k].Kind }
        $script:RAHoldStreak = Read-RAStreamHoldStreak -Stream $script:RAStream -Holds $__hsKinds
        foreach ($__hs in @((Get-RARunFailureSplit).Held | Where-Object { $_ -and $_.Escalated })) {
            Write-Warn2 ("{0} has been held at its last complete result for {1} {2} runs in a row ({3}) -- a real problem now: SecurityInsight support is told ({4}); nothing of it is closed" -f $__hs.Report, $__hs.HeldRuns, $script:RAStream.Grain, $__hs.Kind, (Get-SIHoldKindCode -Kind $__hs.Kind -Escalated))
        }
    }
} catch { Write-Diag ("hold streak: not read ({0}) -- every hold counts as its first run" -f $_.Exception.Message) }
# #641: the run's report counts ride on its run record to Invardia (numbers only; the names are in this log and the
# database) -- with the web app page of the run's reports. Set on the run context the run-health END record reports from.
try {
    $__incAllNames = @($script:RAReportStatusDone.Keys | Where-Object { [string]$script:RAReportStatusDone[$_] -eq 'NotComplete' })
    # SUP-2026-00322: a report held ON PURPOSE (#901) is not counted as incomplete on the run record to Invardia (no
    # report-incomplete class for it); it is still NotComplete in sidata.RaReportStatus, and it is not counted as stored
    # #902 (4): an ESCALATED hold (a Detailed hold of 3 runs in a row) IS counted: it is a real problem now
    $__incHeld = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try { foreach ($__h in @((Get-RARunFailureSplit).Held)) { if ($__h -and [string]$__h.Report -and -not $__h.Escalated) { [void]$__incHeld.Add([string]$__h.Report) } } } catch { }
    $__incNames = @($__incAllNames | Where-Object { -not $__incHeld.Contains([string]$_) })
    if ($__incAllNames.Count -gt $__incNames.Count) { Write-Warn2 ("{0} report(s) held at their last complete result on purpose -- not counted as incomplete: {1}" -f ($__incAllNames.Count - $__incNames.Count), ((@($__incAllNames | Where-Object { $__incHeld.Contains([string]$_) }) | Sort-Object) -join ', ')) }
    if ($__incNames.Count -gt 0) {
        $__exp = [Math]::Max(@($global:RA_TemplateReportNames | Where-Object { $_ }).Count, $script:RAReportStatusDone.Count)
        $__link = ''
        try {
            if (Get-Command -Name Get-SITelemetryRunLink -ErrorAction SilentlyContinue) {
                $__eps = @(Get-SITelemetryInstallEndpoints)
                if ($__eps.Count) { $__base = Get-SITelemetryRunLink -Endpoints $__eps; if ($__base) { $__link = '{0}/Reports/{1}' -f $__base, [uri]::EscapeDataString([string]$script:_RunHealthCtx.RunId) } }   # a path, no query: the receiver takes no query string
            }
        } catch { $__link = '' }
        if ($__link.Length -gt 400) { $__link = '' }
        foreach ($__kv in @(@('ReportsExpected', [long]$__exp), @('ReportsStored', [long]($__exp - $__incAllNames.Count)), @('ReportsIncomplete', [long]$__incNames.Count), @('ReportsIncompleteLink', $__link))) {
            Add-Member -InputObject $script:_RunHealthCtx -NotePropertyName $__kv[0] -NotePropertyValue $__kv[1] -Force
        }
        Write-Warn2 ("{0} of {1} report(s) are NOT COMPLETE in this run: {2}" -f $__incNames.Count, $__exp, (($__incNames | Sort-Object) -join ', '))
    }
} catch { Write-Diag ("completeness: the report counts could not be set on the run record: {0}" -f $_.Exception.Message) }

$__raNotDelivered = @($script:_RAResultNotDelivered | Where-Object { $_ })
# #882 A REPORT THAT FAILS FAILS ALONE (Get-RARunEndVerdict, RA-Delivery.ps1): a report that threw, ended NOT COMPLETE or was
# held back is a warning (it keeps its last complete result, #877) and the job completes. The run ends FAILED only when
# nothing of it can be trusted as stored -- here: a run without a database whose Log Analytics post was refused or not
# delivered (Log Analytics is then its only store), or a run with a database whose result could not go there and reached
# no copy. (The other two -- rows that cannot be recorded as held, a collection that cannot be marked complete -- are judged
# where the collection is completed, below.) In a run WITH a database the Log Analytics copy is sent after the delivery from
# SQL and never fails the run (#743).
$__raEndVerdict = Get-RARunEndVerdict -StreamWanted ([bool]$script:RAStreamWanted) -StreamOn ([bool]$script:RAStreamOn) -WhatIf ([bool]$script:SIWhatIf) `
                      -LaRefused @($script:_RAIngestRefused | Where-Object { $_ }) -LaNotDelivered $__raNotDelivered -LaSent ($null -ne $script:_RAPublishedRows) -StreamWhy ([string]$script:RAScaleAttachError)
if ($__raEndVerdict.Fail -and -not $script:RAStreamOn -and -not ((@($script:_RAIngestRefused | Where-Object { $_ }).Count -gt 0) -or $__raNotDelivered.Count -gt 0)) {
    Write-Err2 $__raEndVerdict.Why
    $script:_RAEndFailure = [pscustomobject]@{ Health = $__raEndVerdict.Why; Lines = @($__raEndVerdict.Why, 'The web app keeps showing the earlier run; nothing downstream was given a partial result.'); Throw = ("Risk Analysis could not store its result: {0}" -f $__raEndVerdict.Why) }
}
if ($__raEndVerdict.Fail -and (($null -ne $script:_RAIngestRefused -and $script:_RAIngestRefused.Count -gt 0) -or $__raNotDelivered.Count -gt 0)) {
    # The run ENDS FAILED -- at the end of the script, after the workbook and the mail, as before -- and its collection is
    # NOT completed: the data sync holds it and the connectors close nothing on it.
    $__refusedMsg = ((@($script:_RAIngestRefused) + $__raNotDelivered | Where-Object { $_ }) -join ' | ')
    $__efLines = New-Object System.Collections.Generic.List[string]
    $__efLines.Add($__refusedMsg)
    if ($__raNotDelivered.Count -gt 0) {
        $__efLines.Add("The result of this run was NOT delivered to Log Analytics, so this run is recorded as failed.")
        $__efLines.Add("The web app keeps showing the earlier run. Nothing downstream was given a partial result: the data sync holds this collection and the connectors close nothing on it.")
        $__efLines.Add('@workbook')
    }
    $script:_RAEndFailure = [pscustomobject]@{ Health = $__refusedMsg; Lines = $__efLines.ToArray(); Throw = ("Risk Analysis did not publish its Log Analytics snapshot: {0}" -f $__refusedMsg) }
}
# #638: THE END -- every bucket of every report is in the database: the run's result is marked so, and only now (the data
# sync then completes the collection). A run that failed before this line leaves it 'Loading': nothing reads it.
if ($script:RAStreamOn -and $null -eq $script:_RAEndFailure) {
    $__raPartial = ''
    try { $__raInc = @(Get-RAIncompleteReports -Failures @($script:_RAReportFailures.ToArray())); if ($__raInc.Count) { $__raPartial = Format-RAIncompleteReports -Incomplete $__raInc } } catch { }
    # PER-REPORT LOADING: every report this run judged incomplete -- its query failed, the row-count guard flagged it, or a
    # bucket of it was lost -- carries the verdict NotComplete (sidata.RaReportStatus), and the run says whether ANYTHING
    # ELSE made it partial (a Log Analytics post, a profile it was built on): only when nothing else did may the data sync
    # and the closes act per report (Get-RAPartialScope). Never fails the run; unknown is 'run' (the whole run is held as before).
    $__raScope = 'run'
    try {
        $__incSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($__ir in @($script:_RAIncompleteReports) + @($__raInc)) { if ($__ir -and [string]$__ir.Report) { [void]$__incSet.Add([string]$__ir.Report) } }
        foreach ($__bl in @($script:_RABucketLossRun)) { if ($__bl) { $__bn = (([string]$__bl) -split ' :: ', 2)[0]; if ($__bn) { [void]$__incSet.Add($__bn) } } }
        # #877: a report held back is one of them (a named report: the others load)
        foreach ($__hr in @(Get-RAStreamHeldReports -Stream $script:RAStream)) { if ($__hr -and [string]$__hr.Report) { [void]$__incSet.Add([string]$__hr.Report) } }
        foreach ($__rn in @($__incSet)) {
            if ([string]$script:RAReportStatusDone[[string]$__rn] -eq 'NotComplete') { continue }
            $__w = @(@($script:_RAIncompleteReports) + @($__raInc) | Where-Object { $_ -and [string]$_.Report -eq $__rn } | ForEach-Object { [string]$_.Why }) | Select-Object -First 1
            if (-not $__w) { $__w = 'a query slice of the report could not be read this run' }
            $script:RAReportStatusDone[[string]$__rn] = 'NotComplete'
            # #901 a report held ON PURPOSE (and nothing else wrong with it) carries its kind: it does not make the run partial for the publish
            $__hk = ''
            try {
                $__hk = Get-RADeliberateHoldKind -Report ([string]$__rn) -Holds $script:RADeliberateHolds -Failures @($script:_RAReportFailures.ToArray()) -Flagged @($script:_RARowCountFlagged) `
                            -BucketLoss @($script:_RABucketLossRun | Where-Object { $_ } | ForEach-Object { [string]$_ }) -HeldBack @(Get-RAStreamHeldReports -Stream $script:RAStream | Where-Object { $_ } | ForEach-Object { [string]$_.Report })
            } catch { $__hk = '' }
            # #902 (4): with a kind, the hold's facts are stored with it (the uplink, the mail and the web app read them)
            $__hf = @{}
            if ($__hk) {
                $__hsr = $script:RAHoldStreak[[string]$__rn]
                $__hf = @{ HeldRuns = $(if ($__hsr -and $__hsr.HeldRuns) { [int]$__hsr.HeldRuns } else { 1 })
                           KeptResultAt = $(if ($__hsr -and $__hsr.KeptResultAt) { ([datetime]$__hsr.KeptResultAt).ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) } else { '' })
                           HoldNames = $(if ($script:RADeliberateHolds[[string]$__rn] -and $script:RADeliberateHolds[[string]$__rn].Names) { (@($script:RADeliberateHolds[[string]$__rn].Names.ToArray()) -join ';') } else { '' }) }
            }
            Set-RAStreamReportNotComplete -Stream $script:RAStream -ReportName ([string]$__rn) -Reason ([string]$__w) -HoldKind $__hk @__hf
        }
        $__dHeld = @($script:RADeliberateHolds.Keys | Sort-Object)
        if ($__dHeld.Count) { Write-Warn2 ("{0} report(s) held at their last complete result on purpose: {1} -- they do not hold the publish of this run" -f $__dHeld.Count, ($__dHeld -join ', ')) }
        $__runCauses = New-Object System.Collections.Generic.List[string]
        foreach ($__f in @($script:_RAPublishFailures)) { if ($__f) { $__runCauses.Add([string]$__f) } }
        if (Get-Command -Name Get-SILogIngestNotes -ErrorAction SilentlyContinue) {
            foreach ($__n in @(Get-SILogIngestNotes)) { if ($__n -and -not ($__n.PSObject.Properties['Kind'] -and [string]$__n.Kind -eq 'column-lag')) { $__runCauses.Add([string]$__n.Message) } }
        }
        if ($null -ne $script:_RAUpstreamOutcome -and $script:_RAUpstreamOutcome.ExitReason -ne 'success') { $__runCauses.Add([string]$script:_RAUpstreamOutcome.Message) }
        $__raScope = Get-RAPartialScope -Reports @($__incSet) -RunCauses $__runCauses.ToArray()
        if ($__raScope -eq 'reports') { Write-Warn2 ("{0} report(s) could not be completed in this run; every other report is complete and is loaded -- those reports keep their last complete result, and nothing of them is closed" -f $__incSet.Count) }
    } catch { $__raScope = 'run'; Write-Diag ("per-report scope not recorded (the run is treated as partial as a whole): {0}" -f $_.Exception.Message) }
    # #877 (owner 2026-10-22: "Hold back that report"): a report whose rows of this run could not be removed is HELD BACK
    # -- recorded in the database with the ordinal of its rows (the data sync removes them before it delivers this run, and
    # nothing reads them as the report); the run ends partial, never failed. Rows that cannot be recorded as held keep the
    # strict rule: the result is broken and the run fails.
    $__heldNow = @(Get-RAStreamHeldReports -Stream $script:RAStream)
    if ($__heldNow.Count -and -not $script:RAStream.Broken) {
        try {
            $null = Set-RAStreamHeldReports -Stream $script:RAStream
            foreach ($__hr in $__heldNow) { $script:RAReportStatusDone[[string]$__hr.Report] = 'NotComplete' }
            $__heldNames = (@($__heldNow | ForEach-Object { [string]$_.Report }) -join ', ')
            Write-Warn2 ("{0} report(s) HELD BACK in this run: {1}. Their rows of this run could not be removed; they are never read as the report -- those reports keep their last complete result and nothing of them is closed. Every other report is loaded, the run is partial (not failed), and the data sync removes those rows before it delivers this run." -f $__heldNow.Count, $__heldNames)
            $__heldText = ('held back (its rows of this run could not be removed): {0}' -f $__heldNames)
            if ($__raPartial.IndexOf($__heldText, [StringComparison]::Ordinal) -lt 0) { $__raPartial = (@($__raPartial, $__heldText) | Where-Object { "$_".Trim() }) -join '; ' }
        } catch {
            $script:RAStream.Broken = ("the rows of report(s) {0} could not be removed, and they could not be recorded as held back either ({1}) -- a part of a report never goes out as the report" -f (@($__heldNow | ForEach-Object { [string]$_.Report }) -join ', '), $_.Exception.Message)
            Write-Warn2 $script:RAStream.Broken
        }
    }
    if ($script:RAStream.Broken) {
        $script:_RAEndFailure = [pscustomobject]@{ Health = ("the result in the database is not complete: {0}" -f $script:RAStream.Broken); Lines = @()
                                                   Throw = ("Risk Analysis could not complete its result in the database: {0}" -f $script:RAStream.Broken) }
    } else {
        # #725: every verdict of the run is settled (the guards, the per-report verdicts, the Log Analytics post) and nothing
        # holds it: said on the collection with the partial reason and scope, BEFORE it is marked in -- the data sync may then
        # complete it if this run stops in between (a collection without it is never completed that way).
        try { Set-RAStreamVerdictsFinal -Stream $script:RAStream -Partial $__raPartial -Scope $__raScope } catch { Write-Diag ("the run's verdicts could not be recorded as final on its collection: {0}" -f $_.Exception.Message) }
        try {
            $__raRows = Complete-RAStream -Stream $script:RAStream -Partial $__raPartial -Scope $__raScope
            Write-Ok ("the run's result is complete in the database: {0} row(s)" -f $__raRows)
        } catch {
            $script:_RAEndFailure = [pscustomobject]@{ Health = ("the result could not be marked complete in the database: {0}" -f $_.Exception.Message); Lines = @()
                                                       Throw = ("Risk Analysis could not complete its result in the database: {0}" -f $_.Exception.Message) }
        }
    }
}

# #743 (1): THE LOG ANALYTICS COPY, AFTER THE DELIVERY FROM SQL. The collection above is complete and delivered (the web app,
# the mails and the connectors read the database); the copy goes to Log Analytics now. A copy that went out in full is
# marked on the collection (LaCopyAt); one that did not makes the run PARTIAL with one plain sentence -- never a failed run,
# and never a collection held back (Complete-RALaCopy, RA-SqlStream.ps1).
if ($script:RAStreamOn) {
    . $script:RALaPhase
    $__laCopy = Complete-RALaCopy -Stream $script:RAStream -Sent ([bool]$global:SendToLogAnalytics -and $script:RAAllCount -gt 0) `
                    -Refused @($script:_RAIngestRefused) -NotDelivered @($script:_RAResultNotDelivered) -Delivered ($null -eq $script:_RAEndFailure)
    if ($__laCopy.Level -eq 'WARN') { Write-Warn2 $__laCopy.Text } elseif ($__laCopy.Text) { Write-Info $__laCopy.Text }
    if ($__laCopy.Partial) { foreach ($__pf in @($__laCopy.Causes)) { if ($__pf -and -not $script:_RAPublishFailures.Contains([string]$__pf)) { [void]$script:_RAPublishFailures.Add([string]$__pf) } } }
    # the trend and the findings follow the delivery from the database, whatever became of the copy -- #830: and whether the
    # copy is on at all (the findings copy pages from the database; the trend row is written only when the copy is on)
    if ($null -eq $script:_RAPublishedRows -and $null -eq $script:_RAEndFailure) { $script:_RAPublishedRows = @() }
}

# THE WORKBOOK (RA-WorkbookExport.ps1) -- from the completed result in the database, a page at a time, when the setting
# for this grain is on and the result is not larger than a workbook holds here. It never fails the run.
if ($script:RAStreamOn) {
    $__phWbSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
    Invoke-RAWorkbookStep
    Write-Info (Format-RAAfterReportsLine -What 'the workbook step' -Seconds $__phWbSw.Elapsed.TotalSeconds)
    Write-RAStepPhaseRow -Stream $script:RAStream -Phase 'after the reports: the workbook step' -Seconds $__phWbSw.Elapsed.TotalSeconds
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

if ($script:SIWhatIf -and -not [string]::IsNullOrWhiteSpace([string]$global:ExportDestination)) {
    Write-Info ("[dry run] export upload skipped: the files stay in the local OUTPUT folder, not copied to {0}." -f $global:ExportDestination)
}
elseif (-not [string]::IsNullOrWhiteSpace([string]$global:ExportDestination)) {
    Write-Sep
    Write-Step ("Uploading export files to: {0}" -f $global:ExportDestination)

    # Resolve SPN ObjectId once so Send-ExportFile can grant RBAC on auto-created containers
    $__raSpnObjectId = $null
    try {
        $__raSpn = Get-SIAzADServicePrincipal -ApplicationId $global:SpnClientId -ErrorAction SilentlyContinue
        if ($__raSpn) { $__raSpnObjectId = [string]$__raSpn.Id }
    } catch { }

    foreach ($localPath in @($global:OutputXlsx, $global:OutputJson)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$localPath) -and (Test-Path -LiteralPath $localPath) -and -not ($script:RAWorkbookSkipped -and $localPath -eq $global:OutputXlsx)) {   # no workbook this run: nothing to upload for it
            # #744: the JSON file's blocks were sent while it was written -- committed after the backup (or, when that
            # did not complete, the file goes up from the disk as before)
            Send-ExportFile -LocalPath $localPath `
                -Destination          $global:ExportDestination `
                -IngestionSpnAppId    $global:SpnClientId `
                -IngestionSpnObjectId $__raSpnObjectId `
                -Staged               $(if ($localPath -eq $global:OutputJson) { $script:RAJsonStaged } else { $null })
        }
    }
}

#########################################################################################################
# BUILD AI SUMMARY CONTEXT
#########################################################################################################

# #863: THE TOP LISTS NEVER DEPEND ON THE AI SUMMARY (owner 2026-10-21: an install without the AI summary showed
# "Top 0 risky assets"). The Top-50 asset + finding rollup below is built on EVERY run with rows; the AI summary only adds
# its text on top. With the AI summary off ($_RATopListsOnly) the AI configuration, the shared AI snapshot (read and
# write) and the AI call are skipped -- the rollup runs alone and feeds the executive view (sidata.RiskExecView).
$script:_RATopListsOnly = -not [bool]$global:BuildSummaryByAI
$cachedSummaryUsed = $false
if ([bool]$global:BuildSummaryByAI -or [long]$script:RAViewCount -gt 0) {
    if (-not $script:_RATopListsOnly) {

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
    # AI SUMMARY MODE -- how the Summary and Detailed reports relate to each other.
    #
    # The two grains are not comparable: Summary counts distinct ASSETS, Detailed
    # counts ASSET-FINDINGS. The same estate therefore yields different totals and
    # percentages in the two reports, and it always will. What a customer gets to
    # choose is whether the two reports are made to AGREE (by one of them adopting
    # the other's snapshot) or whether each simply reports its own grain.
    #
    #   Consistent  (default) -- the first report of the UTC day builds the AI
    #                            narrative, the headline KPI and the Top-50, and the
    #                            other report REUSES them verbatim. Both mails carry
    #                            identical figures. For customers where management
    #                            receives BOTH reports.
    #   PerReport             -- neither report reads or writes the shared snapshot;
    #                            each computes and shows its own numbers. No
    #                            divergence to explain, because nothing is borrowed.
    #                            For customers where management receives ONE report.
    #
    # 🔒 DEFAULT IS 'Consistent' BECAUSE IT IS WHAT EVERY INSTALL ALREADY DOES.
    # This engine reaches ~30 subscription customers on their next nightly sync and
    # ~6,000 community installs, with no review step. Changing the default would
    # silently move the headline score an executive sees, with no announcement --
    # so the new mode ships opt-in and every existing install keeps today's numbers.
    #
    # 🪤 UNKNOWN VALUES WARN AND FALL BACK, they do not throw. This is customer
    # config consumed by an unattended scheduled job; a typo must not cost a
    # customer their nightly report.
    #
    # SecurityInsight Pro (a run whose settings came from the Pro settings database)
    # defaults to 'PerReport' instead (operator, 2026-10-05): in the web app Summary
    # and Detailed are one click apart, so each showing its own figures reads better.
    # Community keeps 'Consistent'. An explicitly set value wins in both editions.
    $script:_AISummaryEdition = Get-RAAISummaryEdition -ProSettingsVersion ([string]$global:SI_ProSettingsVersion)
    $__modeResolved = Resolve-RAAISummaryMode -Value ([string]$global:SI_AISummary_Mode) -Edition $script:_AISummaryEdition
    $script:_AISummaryMode = $__modeResolved.Mode
    if (-not $__modeResolved.Recognised) {
        Write-Warn2 ("[AISummaryCache] `$global:SI_AISummary_Mode = '{0}' is not a recognised mode (expected 'Consistent' or 'PerReport'). Using the default, '{1}'." -f [string]$global:SI_AISummary_Mode, $__modeResolved.Mode)
    } elseif (-not $__modeResolved.Supplied) {
        Write-Info ("[AISummaryCache] SI_AISummary_Mode is not set -- the {0} default applies: {1}." -f $__modeResolved.Edition, $__modeResolved.Mode)
    }

    # THE LEADER -- who is the source of truth. There is deliberately no cycle key and
    # no date arithmetic here; see _shared/RA-AISummaryMode.ps1 for why two attempts at
    # a clock-based "first run of the cycle wins" rule both failed. Short version:
    # rolling age drifts onto Detailed, and a UTC-day key breaks the moment a customer's
    # two runs land either side of midnight -- "Summary late evening, Detailed early
    # morning" is an ordinary schedule, and a long run can straddle it by itself.
    #
    #   the leader     -> always builds its own figures, adopts from nobody
    #   the follower   -> adopts the leader's snapshot within the backstop, else builds
    #
    # That is order-, timezone- and date-independent, and it gives the property the
    # complaint actually needs: the follower's figures can never reach the leader's mail.
    $__leaderResolved = Resolve-RAAISummaryLeader -Value ([string]$global:SI_AISummary_Leader)
    $script:_AISummaryLeader = $__leaderResolved.Leader
    if (-not $__leaderResolved.Recognised) {
        Write-Warn2 ("[AISummaryCache] `$global:SI_AISummary_Leader = '{0}' is not recognised (expected 'Summary' or 'Detailed'). Falling back to 'Detailed'." -f [string]$global:SI_AISummary_Leader)
    }

    # This run's grain, reduced from the template so the comparison never depends on a
    # customer's template string matching exactly.
    $script:_AISummaryMyGrain = Get-RAReportGrainLabel -ReportTemplate ([string]$global:ReportTemplate)
    if (-not $script:_AISummaryMyGrain -and $script:_AISummaryMode -eq 'Consistent') {
        # A template that classifies as neither cannot be placed in the leader/follower
        # relationship at all. Say so once and let it build its own figures -- silently
        # treating it as the follower would let it adopt numbers describing a different
        # grain entirely.
        Write-Warn2 ("[AISummaryCache] report template '{0}' is neither a Summary nor a Detailed report, so it cannot take part in Consistent mode. This run will build its own figures." -f [string]$global:ReportTemplate)
    }

    Write-Info ("[AISummaryCache] mode = {0}; leader = {1}; this run = {2}" -f `
        $script:_AISummaryMode, $script:_AISummaryLeader, $(if ($script:_AISummaryMyGrain) { $script:_AISummaryMyGrain } else { 'unclassified' }))
    if ($script:_AISummaryMode -eq 'PerReport') {
        Write-Info ("[AISummaryCache] PerReport: this '{0}' report computes and shows its OWN numbers. The shared snapshot is neither read nor written this run." -f $global:ReportTemplate)
    }

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
        #
        # 🔒 PerReport MODE IS ENFORCED HERE, NOT AT THE CALL SITES. There are five
        # readers and two writers of this cache -- the initial lookup, the pre-POST
        # race re-check, the post-build race check, the final pre-email re-read, and
        # the KPI backfill. Gating each one separately would mean seven chances to
        # miss one, and a single missed reader is enough for the other template's
        # numbers to leak back into a PerReport run. One gate in each function
        # cannot be partially applied.
        if ($script:_AISummaryMode -eq 'PerReport') { return $null }
        if (Test-Path -LiteralPath $script:_RATop50Local) {
            try {
                $j = Get-Content -LiteralPath $script:_RATop50Local -Raw | ConvertFrom-Json
                return [pscustomobject]@{ Source = 'local'; Data = $j }
            } catch {
                Write-Warn2 ("[AISummaryCache] failed to parse local cache file: {0}" -f $_.Exception.Message)
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($script:_RATop50StorageAcct)) {
            try {
                $ctx = New-SIAzStorageContext -StorageAccountName $script:_RATop50StorageAcct -UseConnectedAccount -ErrorAction Stop
                $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + '.json')
                $prevProgress = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                try {
                    Get-SIAzStorageBlobContent -Container $script:_RATop50Container -Blob $script:_RATop50BlobName -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
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
        # 🔒 PerReport writes nothing -- see the note in Get-RATop50CachedFile.
        # A PerReport run must not leave a snapshot behind either: if it did, a
        # customer switching modes (or running one report in each mode) would find
        # a stale file waiting, and the first Consistent run would adopt figures
        # from a report that was never meant to publish them.
        # 🪤 RETURNS WHETHER IT ACTUALLY WROTE, and the callers must narrate from that
        # rather than from having called it. The first live PerReport run logged
        # "persisted fresh AI summary ... (next run within 24h will reuse it)" having
        # written nothing at all, because the Write-Info sat unconditionally after the
        # call. A log line claiming work that did not happen is the same defect as one
        # hiding work that did.
        if ($script:_AISummaryMode -eq 'PerReport') { return $false }
        # A dry run (#257) leaves no snapshot either -- the next real report would adopt its figures.
        if ($script:SIWhatIf) { return $false }
        # Local write
        # Tracked, because the caller now narrates from the return value: a failed local
        # write that still reported "persisted" would be the same lie in the other
        # direction, and this is the file the other report depends on.
        $wroteLocal = $false
        try {
            Set-Content -LiteralPath $script:_RATop50Local -Value $JsonContent -Encoding UTF8 -Force
            $wroteLocal = $true
        } catch {
            Write-Warn2 ("[AISummaryCache] failed to write local cache: {0}" -f $_.Exception.Message)
        }
        # Blob mirror (best-effort, single-host installs without SI_StorageAccount skip silently)
        if (-not [string]::IsNullOrWhiteSpace($script:_RATop50StorageAcct)) {
            try {
                $ctx = New-SIAzStorageContext -StorageAccountName $script:_RATop50StorageAcct -UseConnectedAccount -ErrorAction Stop
                # Auto-create container if missing.
                if (-not (Get-SIAzStorageContainer -Name $script:_RATop50Container -Context $ctx -ErrorAction SilentlyContinue)) {
                    New-SIAzStorageContainer -Name $script:_RATop50Container -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
                }
                $prevProgress = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                try {
                    Set-SIAzStorageBlobContent -Container $script:_RATop50Container -File $script:_RATop50Local -Blob $script:_RATop50BlobName -Context $ctx -Force -ErrorAction Stop | Out-Null
                } finally { $ProgressPreference = $prevProgress }
                Write-Info ("[AISummaryCache] mirrored to blob: {0}/{1}" -f $script:_RATop50Container, $script:_RATop50BlobName)
            } catch {
                Write-Warn2 ("[AISummaryCache] blob mirror failed (local file still authoritative): {0}" -f $_.Exception.Message)
            }
        }
        return $wroteLocal
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
            $_verdict = Test-RAAISummaryShouldAdopt -Mode $script:_AISummaryMode `
                -LeaderGrain $script:_AISummaryLeader -MyGrain $script:_AISummaryMyGrain `
                -SnapshotGrain (Get-RAReportGrainLabel -ReportTemplate ([string]$shared.SourceTemplate)) `
                -GeneratedAtUtc $_gen.ToUniversalTime() -NowUtc ([datetime]::UtcNow) `
                -MaxAgeHours $aiSummaryMaxAgeHours -HasSnapshot
            if ($_verdict.Adopt) {
                $global:AI_SummaryText = [string]$shared.AISummaryText
                Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText
                Write-Info ("[AISummaryCache] reusing cached AI summary from {0:N1}h ago (source={1}, template '{2}', collection {3}, max-age {4}h). AI not called this run." -f `
                    $sharedAge.TotalHours, $cached.Source, $shared.SourceTemplate, $shared.CollectionTime, $aiSummaryMaxAgeHours)
                $cachedSummaryUsed = $true
                # #288: the executive view shows the Top-50 this mail carries -- the leader's.
                $script:_RAExecTopAssets = @($shared.TopAssets); $script:_RAExecTopFindings = @($shared.TopFindings)
                $script:_RAExecFiguresFrom = [string]$shared.SourceTemplate; $script:_RAExecFiguresAt = $shared.GeneratedAt
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
                # 🪤 THIS MESSAGE USED TO ASSERT AN AGE REASON UNCONDITIONALLY -- "cached AI
                # summary is 3,6h old (>24h max)", which is self-contradictory and was
                # printed on the first live run of the leader rule. Age is now only ONE of
                # the reasons a snapshot is declined (the leader always rebuilds; a snapshot
                # from a non-leader is never adopted), so the verdict states its own reason
                # and this line no longer invents one.
                Write-Info ("[AISummaryCache] building this run's own figures ({0:N1}h-old snapshot from '{1}', source={2}): {3}. This run will REFRESH it." -f `
                    $sharedAge.TotalHours, $shared.SourceTemplate, $cached.Source, $_verdict.Reason)
            }
        } else {
            Write-Info ("[AISummaryCache] cache file exists (source={0}) but contains no AISummaryText; this run will build + persist." -f $cached.Source)
        }
    } elseif ($script:_AISummaryMode -eq 'PerReport') {
        # NOT "no cached file" -- there may well be one; this mode simply never
        # consults it. Claiming "will build + persist" here would be wrong twice.
        Write-Info ("[AISummaryCache] PerReport: building this report's own AI summary and KPI. Nothing is persisted for another template to adopt.")
    } else {
        Write-Info ("[AISummaryCache] no cached file (local or blob); this run will build + persist.")
    }
    # ---------------------------------------------------------------------
    }   # close #863 `if (-not $script:_RATopListsOnly)` -- AI configuration + shared snapshot read
    else {
        Write-Section "Top 50 lists"
        Write-Info "The AI summary is off (BuildSummaryByAI): building the Top 50 risky assets and Top 50 critical findings without it."
    }

    if ($cachedSummaryUsed) {
        # Skip the entire rollup + AI call block -- nothing more to do here.
    }
    elseif ($script:RAViewCount -eq 0) {
        Write-Warn2 "BuildSummaryByAI requested, but there are no final rows to summarize."
    }
    else {
      # #863: never fatal -- the findings are exported already; a failed rollup leaves the top lists empty and says so.
      try {

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
        $TopN         = $script:RAViewCount
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
                    # a list, never += on an array in a loop (a group can list thousands of assets)
                    $out = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($item in $j) {
                        if ($null -eq $item) { continue }
                        if ($item -is [string]) { $out.Add($item); continue }
                        $name = (Get-RowValue -Row $item -Names @("Name","name","DeviceName","deviceName","MachineName","machineName","DnsName","dnsName","Id","id"))
                        if ($name) { foreach ($__n in @($name)) { $out.Add($__n) } }
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
        # #638: from SQL the rows come in the final order already (the same score, highest first), a page at a time;
        # in memory they are sorted here as before.
        $topRows = @()
        if (-not $script:RAStreamOn) {
        $topRows = @($global:RA_ReportRows |
                Sort-Object -Property @{
                    Expression = {
                        $v = $_.PSObject.Properties[$colRiskScore]
                        if ($v) { [double](([string]$v.Value) -replace ',', '.') } else { 0.0 }
                    }
                    Descending = $true
                } |
                Select-Object -First $TopN)
        }

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
        function Get-RARowAssetKeys {
            <# The aggregation key for each asset name in a row, aligned by position: 'id:<id>' from ImpactedAssetIds (or a
               Detailed row's AssetId), else 'name:<name>'. A list that does not line up falls back to names -- never a guess. #>
            param($Row, [object[]]$Names)
            $nm = @($Names)
            $raw = Get-RowValue -Row $Row -Names @('ImpactedAssetIds')
            $ids = @()
            if ($null -ne $raw -and [string]$raw -ne '') {
                if ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) { $ids = @($raw | ForEach-Object { [string]$_ }) }
                elseif (([string]$raw).TrimStart().StartsWith('[')) { try { $ids = @(ConvertFrom-Json -InputObject ([string]$raw) | ForEach-Object { [string]$_ }) } catch { $ids = @() } }
                else { $ids = @(([string]$raw) -split '\s*;\s*') }
            }
            if ($ids.Count -ne $nm.Count) {
                $one = Get-RowValue -Row $Row -Names @('AssetId')
                # @() OUTSIDE the if: a one-item array returned from an if unrolls to a bare string, and $ids[0] is then a CHAR
                $ids = @(if ($nm.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$one)) { [string]$one })
            }
            @(for ($q = 0; $q -lt $nm.Count; $q++) {
                $idq = if ($ids.Count -eq $nm.Count) { [string]$ids[$q] } else { '' }
                if ([string]::IsNullOrWhiteSpace($idq)) { 'name:' + ([string]$nm[$q]).ToLowerInvariant() } else { 'id:' + $idq.Trim().ToLowerInvariant() }
            })
        }

        $isDetailedTemplate = ($global:ReportTemplate -like '*_Detailed')
        # The (asset x ConfigBucket) collapse, WHILE the rows stream by: the rows arrive highest weighted score first, so the
        # first row seen for a pair IS its max-weighted row (ties: the first, as before) -- the same representative the
        # two-pass collapse picked, without holding every row first (#638).
        $collapseSeen = $null
        if ($isDetailedTemplate) { $collapseSeen = New-Object 'System.Collections.Generic.HashSet[string]' }

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
                [string]$MoreDetails         = '',
                # ONE ASSET, ONE ENTRY: the asset's id when the row carries one, else its name. Two machines that share a name stay
                # two entries; one machine named differently by two sources stays one.
                [string]$Key                 = ''
            )

            if ([string]::IsNullOrWhiteSpace($Asset)) { return }
            $aggKey = if ([string]::IsNullOrWhiteSpace($Key)) { 'name:' + $Asset.ToLowerInvariant() } else { $Key }

            if (-not $assetAgg.ContainsKey($aggKey)) {
                $assetAgg[$aggKey] = [pscustomobject]@{
                    Asset               = $Asset
                    # #288: the aggregation key ('id:<asset id>' or 'name:<name>'), so the web app can link the asset
                    AssetKey            = $aggKey
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

            $o = $assetAgg[$aggKey]
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
        $__aiPager = if ($script:RAStreamOn) { New-RARowPager -Stream $script:RAStream -Source View } else { New-RARowPager -Rows $topRows }
        $__aiRows = 0L
        $__phAiSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
        while ($null -ne ($__aiPage = $__aiPager.Next())) {
        foreach ($r in $__aiPage) {
            $i++
            $__aiRows++

            $riskScoreText = Get-RowValue -Row $r -Names @($colRiskScore, "RiskScore")
            [double]$riskScore = ConvertTo-RADouble -Value $riskScoreText -Default 0.0   # invariant, da-DK-safe (#121)

            # v2.2.99: pull BOTH risk-score variants per row so the AI summary
            # can show 'Total Risk Score' (unweighted) AND 'Weighted Risk Score'.
            $riskScoreUnText = Get-RowValue -Row $r -Names @("RiskScoreTotal", "RiskScore")
            [double]$riskScoreUn = ConvertTo-RADouble -Value $riskScoreUnText -Default 0.0
            $riskScoreWtText = Get-RowValue -Row $r -Names @("RiskScoreTotal_Weighted")
            [double]$riskScoreWt = ConvertTo-RADouble -Value $riskScoreWtText -Default 0.0
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


            $assetList = Resolve-AssetNamesForRow -Row $r -AssetsText $assetsText

            if ($assetList -and @($assetList).Count -gt 0) {
                $assetKeys = @(Get-RARowAssetKeys -Row $r -Names @($assetList))
                $ax = -1
                foreach ($a in $assetList) {
                    $ax++
                    $aKey = [string]$assetKeys[$ax]
                    # v2.2.227 path B -- in *_Detailed reports skip rows that
                    # aren't the max-weighted representative for their
                    # (asset, ConfigBucket) pair. Summary path is unaffected
                    # ($collapseBuckets stays $null when the template isn't *_Detailed).
                    if ($isDetailedTemplate -and $null -ne $collapseSeen) {
                        $bucket = if ([string]$confId -match '^CVE-\d{4}-\d+$') { 'CVE' } else { [string]$confId }
                        $key    = "{0}|{1}" -f $aKey, $bucket
                        if (-not $collapseSeen.Add($key)) { continue }
                    }

                    Add-AssetAgg -Asset $a -RiskScore $riskScore -TierLevel $tierLevel -Severity $severity -Domain $domain `
                        -Category $category -Subcat $subcat -ConfName $confName -ConfId $confId `
                        -CmdbId $cmdbId -CmdbName $cmdbName -CmdbCriticality $cmdbCrit -CmdbDataSensitivity $cmdbSens `
                        -RiskScoreUnweighted $riskScoreUn -RiskScoreWeighted $riskScoreWt -MoreDetails $rowMoreDetails -Key $aKey

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
        $__aiPage = $null
        }
        $__aiPager = $null
        if ($script:RAStreamOn) { Write-Info (Format-RAAfterReportsLine -What 'the AI summary''s read of the rows' -Seconds $__phAiSw.Elapsed.TotalSeconds -Rows $__aiRows); Write-RAStepPhaseRow -Stream $script:RAStream -Phase 'after the reports: the AI summary' -Seconds $__phAiSw.Elapsed.TotalSeconds -Rows $__aiRows }   # #873 A
        if ($isDetailedTemplate -and $null -ne $collapseSeen) { Write-Info ("AI rollup collapse: {0} *_Detailed rows -> {1} (asset x ConfigBucket) buckets (max-weighted; XLSX unaffected)" -f $__aiRows, $collapseSeen.Count) }

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
        # #288: the executive view shows this run's own Top-50 (until a peer's is adopted below).
        $script:_RAExecTopAssets = @($assetRanked); $script:_RAExecTopFindings = @($findingRanked)
        $script:_RAExecFiguresFrom = [string]$global:ReportTemplate; $script:_RAExecFiguresAt = $null
        if ($script:_RATopListsOnly) {
            Write-Info ("Top lists built without the AI summary: {0} asset(s), {1} finding(s)." -f @($assetRanked).Count, @($findingRanked).Count)
        } else {

        # v2.2.345 -- v2.2.342's Summary-writes / Detailed-reads Top-50 sharing
        # block was removed here. It's superseded by the cache-first-by-age
        # mechanism added near "Write-Section 'AI summary'" above: when the
        # cached AI summary is still fresh, we skip this whole rollup block
        # entirely; when it's stale, this run becomes the authoritative builder
        # and writes the result (AI text + Top-50 inputs) to the same shared
        # file in the post-AI-call persist step below.

        # 🔒 Numbers fed to the AI are culture-INVARIANT with no group separator. Formatted in the
        # host's culture, da-DK turned 4366 into "4.366"; the model read it as a decimal below 289
        # and re-ranked the Top-50 list it was told to copy (live, 2026-09-29).
        $script:_RAFmtInv = { param([string]$fmt, [object[]]$fmtArgs) [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, $fmt, $fmtArgs) }
        $findingLines2 = @()
        $rankF = 0
        foreach ($f in $findingRanked) {
            $rankF++
            # Top 5 affected assets per finding, ranked by per-asset weighted risk
            $topAssetsForFinding = @($f.AssetRiskScores.GetEnumerator() |
                Sort-Object -Property Value -Descending |
                Select-Object -First 5 |
                ForEach-Object { $script:_RAFmtInv.Invoke("{0} ({1:0})", @($_.Key, $_.Value)) }) -join '; '

            # 🔒 Say what was trimmed. These slices feed the AI prompt, so an undisclosed cut does not
            # just hide data -- it lets the model state "the affected assets are X, Y, Z" as if the
            # list were complete. The counts make the truncation visible to the model AND to anyone
            # reading the prompt back.
            if ($f.AssetRiskScores.Count -gt 5) {
                $topAssetsForFinding += ('; [+{0} more of {1} total]' -f ($f.AssetRiskScores.Count - 5), $f.AssetRiskScores.Count)
            }

            $finLinks = ""
            if ($f.Links.Count -gt 0) {
                $finLinks = (@($f.Links) | Select-Object -First 6) -join "; "
                if ($f.Links.Count -gt 6) { $finLinks += ('; [+{0} more]' -f ($f.Links.Count - 6)) }
            }

            $findingLines2 += $script:_RAFmtInv.Invoke("{0}. ConfigId={1}; Name={2}; Severity={3}; Domain={4}; Category={5}/{6}; AffectedAssetCount={7}; TotalRiskScore={8:0}; WeightedRiskScore={9:0}; TopAffectedAssets=[{10}]; Links={11}", @(
                $rankF, $f.ConfId, $f.ConfName, $f.Severity, $f.Domain, $f.Category, $f.Subcategory, $f.AffectedAssetCount, $f.TotalRiskScore, $f.TotalRiskScore_Weighted, $topAssetsForFinding, $finLinks))
        }

        $findingsTextForAI = $findingLines2 -join "`n"

        $assetLines = @()
        $rank = 0
        foreach ($a in $assetRanked) {
            $rank++

            $domainSummary = ""
            if ($a.Domains.Count -gt 0) { $domainSummary = (@($a.Domains) | Sort-Object) -join ", " }

            $topItems = ""
            if ($a.TopItems.Count -gt 0) {
                $topItems = ($a.TopItems | Select-Object -First 8) -join "; "
                if ($a.TopItems.Count -gt 8) { $topItems += ('; [+{0} more of {1} total]' -f ($a.TopItems.Count - 8), $a.TopItems.Count) }
            }

            $linkList = ""
            if ($a.Links.Count -gt 0) {
                $linkList = (@($a.Links) | Select-Object -First 6) -join "; "
                if ($a.Links.Count -gt 6) { $linkList += ('; [+{0} more]' -f ($a.Links.Count - 6)) }
            }

            $assetLines += $script:_RAFmtInv.Invoke("{0}. Asset={1}; Tier={2}; CMDB={3} [{4}] (Criticality={5}, DataSensitivity={6}); Findings={7}; TotalRiskScore={8:0}; WeightedRiskScore={9:0}; Domains=[{10}]; TopItems={11}; Links={12}", @(
                $rank, $a.Asset, $a.TierLevel, $a.CmdbName, $a.CmdbId, $a.CmdbCriticality, $a.CmdbDataSensitivity, $a.Findings, $a.TotalRiskScore, $a.TotalRiskScore_Weighted, $domainSummary, $topItems, $linkList))
        }

        $assetsTextForAI = $assetLines -join "`n"

        $runMeta = @"
ReportTemplate: $($global:ReportTemplate)
Final rows:     $($script:RAViewCount)
Included in AI: $($__aiRows) (TopN findings)
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
                # 🔴 THIS SITE MUST USE THE SAME RULE AS THE READ PATH, and until 2026-09-07
                # it did not. It tested age alone, so on the first run of a NEW day the read
                # path would correctly decline yesterday's snapshot -- and then this check,
                # a few hundred lines later, would find that same ~22h-old snapshot "fresh"
                # and adopt it anyway. The cycle fix would have been silently undone by the
                # race guard, and yesterday's owner would keep both reports for another day.
                $_preVerdict = Test-RAAISummaryShouldAdopt -Mode $script:_AISummaryMode `
                    -LeaderGrain $script:_AISummaryLeader -MyGrain $script:_AISummaryMyGrain `
                    -SnapshotGrain (Get-RAReportGrainLabel -ReportTemplate ([string]$preCallCheck.Data.SourceTemplate)) `
                    -GeneratedAtUtc $_gen.ToUniversalTime() -NowUtc ([datetime]::UtcNow) `
                    -MaxAgeHours $aiSummaryMaxAgeHours -HasSnapshot
                if ($_preVerdict.Adopt) {
                    Write-Info ("[AISummaryCache] pre-POST race re-check: peer run wrote cache {0:N1}h ago (template '{1}', source={2}). SKIPPING AI POST -- adopting peer's AI text + KPI." -f `
                        $preCallAge.TotalHours, $preCallCheck.Data.SourceTemplate, $preCallCheck.Source)
                    $global:AI_SummaryText = [string]$preCallCheck.Data.AISummaryText
                    $script:_RAExecTopAssets = @($preCallCheck.Data.TopAssets); $script:_RAExecTopFindings = @($preCallCheck.Data.TopFindings)   # #288
                    $script:_RAExecFiguresFrom = [string]$preCallCheck.Data.SourceTemplate; $script:_RAExecFiguresAt = $preCallCheck.Data.GeneratedAt
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
        $__aiChunks = 0

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

            # A PLATFORM failure (timeout 408, throttling 429, 5xx, no connection) is retried in-run with
            # backoff, honouring Retry-After. Measured 2026-09-29: one HTTP 408 from Azure OpenAI ended a
            # Summary run AFTER its data was ingested -- no mail, no row-count / column-fill guards. Any other
            # status is a request defect and fails at once. A request message cannot be re-sent, so each
            # attempt builds its own.
            $response = $null; $__aiErr = ''
            $__aiMax = if ($global:AI_MaxAttempts) { [int]$global:AI_MaxAttempts } else { 4 }
            for ($__aiAtt = 1; $__aiAtt -le $__aiMax; $__aiAtt++) {
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
                # GetAwaiter().GetResult(), never .Result: `.Result` is a property getter and PowerShell
                # swallows a getter's exception, so a timeout or connection failure came back as a $null
                # response and surfaced as a misleading null-reference error instead of its real cause.
                $response = $null
                try {
                    $response = $client.SendAsync(
                        $request,
                        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
                    ).GetAwaiter().GetResult()
                } catch {
                    $__aiErr = $_.Exception.Message
                }
                if ($response -and $response.IsSuccessStatusCode) { break }
                $__aiCode = if ($response) { [int]$response.StatusCode } else { 0 }
                if ($response) { $__aiErr = "HTTP ${__aiCode}: " + $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
                $__aiTransient = ($__aiCode -eq 0 -or $__aiCode -eq 408 -or $__aiCode -eq 429 -or $__aiCode -ge 500)
                if (-not $__aiTransient -or $__aiAtt -ge $__aiMax) { throw "Azure OpenAI returned $__aiErr" }
                $__aiWait = [Math]::Min(60, 10 * [Math]::Pow(2, $__aiAtt - 1))
                try { if ($response -and $response.Headers.RetryAfter -and $response.Headers.RetryAfter.Delta) { $__aiWait = [Math]::Min(120, [Math]::Max(1, $response.Headers.RetryAfter.Delta.Value.TotalSeconds)) } } catch { }
                Write-Info ("AI summary: Azure OpenAI did not answer ({0}); retrying in {1:N0}s (attempt {2} of {3})." -f $(if ($__aiCode) { "HTTP $__aiCode" } else { 'no connection' }), $__aiWait, ($__aiAtt + 1), $__aiMax)
                Start-Sleep -Seconds ([int]$__aiWait)
            }

            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
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
                            # 🪤 NO per-chunk Write-Host HERE, and -NoNewline does NOT save you.
                            # Start-Transcript records every Write-Host CALL as its own line and
                            # ignores -NoNewline, so a live typewriter effect that looks like one
                            # tidy paragraph on the console becomes THOUSANDS of one-token lines in
                            # the customer's transcript ("##" / " Top" / "50" / " risky"...). The
                            # summary is printed once, assembled, after the stream completes.
                            $__aiChunks++
                        }
                    } catch {
                        Write-Warning "Failed to parse AI chunk: $json"
                    }
                }
            }

            $global:AI_SummaryText = ($sb.ToString() -replace "`r`n","`n" -replace "`r","`n").Trim()

            # The whole summary, as ONE Write-Host call: the transcript records it as one block
            # instead of one line per token. This is what the operator actually reads.
            Write-Host $global:AI_SummaryText
            Write-Info ("[AI] summary assembled from {0} streamed chunk(s), {1} chars" -f $__aiChunks, $global:AI_SummaryText.Length)

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
                        # Same rule as the read path -- see the pre-POST note above. An
                        # age-only test here would refuse to overwrite YESTERDAY's snapshot
                        # and adopt it instead, which is the same defect wearing the
                        # first-writer-wins label.
                        $_exVerdict = Test-RAAISummaryShouldAdopt -Mode $script:_AISummaryMode `
                            -LeaderGrain $script:_AISummaryLeader -MyGrain $script:_AISummaryMyGrain `
                            -SnapshotGrain (Get-RAReportGrainLabel -ReportTemplate ([string]$existing.Data.SourceTemplate)) `
                            -GeneratedAtUtc $_gen.ToUniversalTime() -NowUtc ([datetime]::UtcNow) `
                            -MaxAgeHours $aiSummaryMaxAgeHours -HasSnapshot
                        if ($_exVerdict.Adopt) {
                            $skipWrite = $true
                            Write-Info ("[AISummaryCache] race detected: peer run wrote cache {0:N1}h ago (template '{1}', source={2}). NOT overwriting -- first-writer-wins. This run's email will be regenerated to use peer's AI text + KPI." -f `
                                $existingAge.TotalHours, $existing.Data.SourceTemplate, $existing.Source)
                            # Adopt the peer's AI text + flag KPI override so the
                            # downstream KPI block + email use the cached values.
                            $global:AI_SummaryText = [string]$existing.Data.AISummaryText
                            $script:_RAExecTopAssets = @($existing.Data.TopAssets); $script:_RAExecTopFindings = @($existing.Data.TopFindings)   # #288
                            $script:_RAExecFiguresFrom = [string]$existing.Data.SourceTemplate; $script:_RAExecFiguresAt = $existing.Data.GeneratedAt
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
                        # The grain that wrote this snapshot, and the leader in force when
                        # it was written. Adoption is decided from SourceTemplate + the
                        # reader's own leader setting, so these are diagnostic -- but they
                        # make a stale file self-explanatory when someone opens it.
                        SourceGrain     = $script:_AISummaryMyGrain
                        LeaderAtWrite   = $script:_AISummaryLeader
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
                    $_wrote = Save-RATop50CachedFile -JsonContent $jsonContent
                    if ($_wrote) {
                        # Only flag the post-KPI updater when there is actually a file for it to
                        # update. In PerReport nothing was written, so firing it would send it
                        # looking for a cache that was never meant to exist -- which is exactly
                        # how the first live PerReport run produced a spurious
                        # "cache file disappeared between AI-write and KPI-update" warning.
                        $script:_RACacheNeedsKPIUpdate = $true
                        Write-Info ("[AISummaryCache] persisted fresh AI summary + Top-{0} assets + {1} findings -> {2} (the other report will reuse it)." -f `
                            @($assetRanked).Count, @($findingRanked).Count, $script:_RATop50Local)
                    } else {
                        Write-Info ("[AISummaryCache] PerReport: built this report's own AI summary + Top-{0} assets + {1} findings. Nothing persisted -- the other report keeps its own figures." -f `
                            @($assetRanked).Count, @($findingRanked).Count)
                    }
                }
            } catch {
                Write-Warn2 ("[AISummaryCache] failed to persist shared AI summary: {0}" -f $_.Exception.Message)
            }

        } catch {
            # A WARNING, not Write-Error: the findings are already exported and ingested, and the mail and
            # the row-count / column-fill guards still have to run. Write-Error under the engine's Stop
            # preference ended the whole run here.
            Write-Warn2 ("AI summary could not be generated -- the report and its data are complete, only the AI-written summary is missing: {0}" -f $_.Exception.Message)
            try {
              $global:AI_SummaryText = "AI summary failed: $($_.Exception.Message)"
              Export-AISummaryWorksheet -Path $global:OutputXlsx -SheetName 'Summary' -SummaryText $global:AI_SummaryText
            } catch { }
        } finally {
            if ($reader) { try { $reader.Close() } catch {} }
            if ($client) { try { $client.Dispose() } catch {} }
        }
        }   # close v2.2.352 `else` (skipAIPost was $false; AI POST + cache-write block above)
        }   # close #863 `else` -- the AI prompt + call run only with the AI summary on
      } catch {
        Write-Warn2 ("Top 50 lists could not be built -- the report and its data are complete, only the top lists are missing: {0}" -f $_.Exception.Message)
      }
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
    # #638: the rows a page at a time (from SQL; or the result in memory as one page) -- the KPI is a running sum
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

    # #636 (owner 2026-10-19: "include both angles with gaps vs. monthly lifecycle"): the missing patches by PATCH CYCLE -- in the
    # monthly cycle, catch-up, no single update -- tallied in the same pass (engine\_shared\SI-PatchCycle.ps1); the mail shows
    # the three groups instead of a raw total
    if (-not (Get-Command -Name New-SIPatchCycleTally -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-PatchCycle.ps1')) }
    $__patchDays = 30; if ($global:SI_PatchCycle_CatchUpDays -and [int]$global:SI_PatchCycle_CatchUpDays -gt 0) { $__patchDays = [int]$global:SI_PatchCycle_CatchUpDays }
    $__patch = New-SIPatchCycleTally -CollectionTime ([datetime]::UtcNow) -CatchUpDays $__patchDays
    # #636 (owner 2026-10-19): the PROTECTION SCORE replaces the old 0-100 KPI in the mail, the kept view and the pages -- ONE
    # engine function for both editions (engine\_shared\SI-ProtectionScore.ps1), fed here by the Detailed run's findings and the
    # run's CI index; Pro also stores it per collection (the data sync, the same rules in SQL). A Summary run has no
    # per-asset findings: it takes the Detailed run's score from the shared cache, else its mail says (one plain line) that the
    # score is in the Detailed report. Without a score the mail always says WHY ($script:RAProtectionReason).
    if (-not (Get-Command -Name New-SIProtectionTally -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-ProtectionScore.ps1')) }
    $__prot = $null
    $script:RAProtectionReason = ''
    # PRO (owner 2026-10-22: "one computation, never two that can differ"): the score of a Detailed run that writes its result
    # to the Pro database is the STORED one -- the data sync's key figures of this collection, the number the web app shows.
    # This run does not count it at all (no walk over every CI); its mail waits for the stored figures in sidata.RaMailOutbox
    # and the data sync sends it with them (engine\_shared\data-sql\SI-RaMailOutbox.ps1). Community counts it here.
    $script:RAProtectionFromStore = $false
    try {
        $script:RAProtectionFromStore = (Get-RAReportGrainLabel -ReportTemplate ([string]$global:ReportTemplate)) -ne 'Summary' -and
            -not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSettingsVersion) -and [bool]$script:RAStreamOn -and $null -ne $script:RAStream -and
            $null -ne $script:RAStream.Invoke -and [int]$script:RAStream.CollectionId -gt 0 -and -not [bool]$script:SIWhatIf -and $script:RAScaleRole -ne 'worker'
    } catch { $script:RAProtectionFromStore = $false }
    try {
        if ($script:RAProtectionFromStore) {
            Write-Info '[SCORE] Protection Score: taken from this run''s stored figures once the data sync has computed them -- the mail waits for them (the numbers the web app shows)'
        } elseif ((Get-RAReportGrainLabel -ReportTemplate ([string]$global:ReportTemplate)) -eq 'Summary') {
            $script:RAProtectionReason = Get-SIProtectionReason 'summary'
        } else {
            $__ciIdxP = $global:RA_CiIndex
            if ($null -eq $__ciIdxP -and (Get-Command -Name Get-RACiIndex -ErrorAction SilentlyContinue)) { $__ciIdxP = Get-RACiIndex }
            if ($global:RA_CiIndexProblem) { $script:RAProtectionReason = 'the CIs could not be read: ' + ([string]$global:RA_CiIndexProblem) }
            elseif ($null -eq $__ciIdxP -or -not $__ciIdxP.ById -or $__ciIdxP.Count -le 0) { $script:RAProtectionReason = Get-SIProtectionReason 'no-cis' }
            if ($null -ne $__ciIdxP -and $__ciIdxP.ById -and $__ciIdxP.Count -gt 0) {
                $__prot = New-SIProtectionTally -CollectionTime ([datetime]::UtcNow)
                $__seenCi = @{}
                foreach ($__c in $__ciIdxP.ById.Values) {
                    $__cid = [string]$__c.si_ci_id
                    if (-not $__cid -or $__seenCi.ContainsKey($__cid)) { continue }
                    $__seenCi[$__cid] = $true
                    $__at = ''; if ($__c.PSObject.Properties['si_asset_type']) { $__at = [string]$__c.si_asset_type }
                    # the stale flag is TEXT from the database ('true' / 'false', ConvertFrom-RACiSqlRows) and a bool from Log
                    # Analytics -- read as text: [bool]'false' is $true, and every CI counted as inactive (live 2026-10-20..22:
                    # "0 assets in scope" on every Detailed run)
                    $__stale = $false; if ($__c.PSObject.Properties['si_stale_']) { $__stale = ([string]$__c.si_stale_).Trim() -in 'true', '1' }
                    Add-SIProtectionAsset -Tally $__prot -Id $__cid -Class ([string]$__c.si_class) -AssetType $__at -Tier $__c.si_tier -Active (-not $__stale)
                }
                $__seenCi = $null
            }
        }
    } catch { Write-Warn2 ("Protection score: not computed in this run -- {0}" -f $_.Exception.Message); $__prot = $null; $script:RAProtectionReason = ('it could not be computed: ' + $_.Exception.Message) }
    $__kpiPager = if ($script:RAStreamOn) { New-RARowPager -Stream $script:RAStream -Source View } else { New-RARowPager -Rows @($global:RA_ReportRows | Where-Object { $null -ne $_ }) }
    $__phKpiSw = [System.Diagnostics.Stopwatch]::StartNew()   # #873 A
    while ($null -ne ($__kpiPage = $__kpiPager.Next())) {
    foreach ($r in $__kpiPage) {
        Add-SIPatchCycleRow -Tally $__patch -Row $r
        if ($null -ne $__prot) { Add-SIProtectionRow -Tally $__prot -Row $r }
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
        if ($r.PSObject.Properties['RiskScoreKPI']) { $rowKpi = ConvertTo-RADouble -Value $r.RiskScoreKPI -Default 100.0 }

        # Tier weight for this row
        # Unknown stays -1 (the default weight). A failed [int]::TryParse wrote 0 here and weighted an
        # unclassified asset as Tier 0 -- 4x in the headline KPI (#121).
        $tierVal = -1
        if ($r.PSObject.Properties['CriticalityTier']) { $__t = ConvertTo-RATierOrNull $r.CriticalityTier; if ($null -ne $__t) { $tierVal = [int]$__t } }
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
    }
    $__kpiPager = $null; $__kpiPage = $null
    if ($script:RAStreamOn) { Write-Info (Format-RAAfterReportsLine -What 'the key figures'' read of the rows' -Seconds $__phKpiSw.Elapsed.TotalSeconds); Write-RAStepPhaseRow -Stream $script:RAStream -Phase 'after the reports: the key figures' -Seconds $__phKpiSw.Elapsed.TotalSeconds }   # #873 A

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
    # the bands are ONE definition (data-model\protection-score-bands.locked.json, also the web app's) -- built-in if it is not loaded
    $band = if (Get-Command -Name Get-SIProtectionBand -ErrorAction SilentlyContinue) { (Get-SIProtectionBand -Score $globalScore).Name }
            elseif ($globalScore -ge 90) { 'Very Good' }
            elseif ($globalScore -ge 75) { 'Good' }
            elseif ($globalScore -ge 50) { 'Moderate' }
            else                         { 'At Risk' }

    # Back-compat alias for code that still reads RiskLevel from the old shape.
    $bcRiskLevel = if     ($band -eq 'Very Good') { 'Low' }
                   elseif ($band -eq 'Good')      { 'Moderate' }
                   elseif ($band -eq 'Moderate')  { 'Elevated' }
                   elseif ($band -eq 'At Risk')   { if ($globalScore -lt 25) { 'Critical' } else { 'High' } }
                   else                            { 'Unknown' }

    # the rows the KPI counted: every page's rows went into one severity bucket each (Other included). #638 pages the rows,
    # so the old `$rows` of the in-memory loop no longer exists -- its .Count was 0 and every report mail said "Total: 0".
    $__kpiRows = [long](@($sevCount.Values) | Measure-Object -Sum).Sum
    $global:RA_KPI = [pscustomobject]@{
        GlobalScore  = $globalScore
        Band         = $band
        RiskLevel    = $bcRiskLevel
        DomainScore  = $domainScore
        SevCount     = $sevCount
        SevByDomain  = $sevByDomain
        TotalRows    = $__kpiRows
        Direction    = 'higher-is-better'
        PatchCycle   = (Complete-SIPatchCycleTally -Tally $__patch)
    }

    Write-Info ("[SCORE] Global={0} ({1}) Endpoint={2} Identity={3} Azure={4} PublicIP={5} | Sev: C={6} H={7} M={8} L={9} | Rows={10} | Direction: HIGHER = BETTER (Microsoft-inspired)" -f `
        $globalScore, $band, $domainScore['Endpoint'], $domainScore['Identity'], $domainScore['Azure'], $domainScore['PublicIP'], `
        $sevCount['Critical'], $sevCount['High'], $sevCount['Medium'], $sevCount['Low'], $__kpiRows)

    # v2.2.350 -- FINAL re-read of the cache, late as possible. Catches the
    # race where THIS run started with empty cache + computed live, but a
    # concurrent peer wrote during our run. The peer's KPI now wins for our
    # email too -- both Summary and Detailed emails show the IDENTICAL
    # headline score regardless of order/timing.
    # Bug B (2026-10-22): the shared cache is the Consistent mode's, and its readers exist only when the AI summary's block ran
    # (with the AI summary off there is no mode at all) -- "The term 'Get-RATop50CachedFile' is not recognized" was the warning
    # of every run with the AI summary off. Every late reader asks first.
    $script:RACacheReadable = ($script:_AISummaryMode -eq 'Consistent') -and [bool](Get-Command -Name Get-RATop50CachedFile -ErrorAction SilentlyContinue)
    if ($script:RACacheReadable -and (-not $script:_CachedRAKPI -or $null -eq $script:_CachedRAKPI.GlobalScore)) {
        try {
            $finalCheck = Get-RATop50CachedFile
            if ($finalCheck -and $finalCheck.Data -and $finalCheck.Data.PSObject.Properties['GlobalScore'] -and $null -ne $finalCheck.Data.GlobalScore) {
                try {
                    $_gen = if ($finalCheck.Data.GeneratedAt -is [DateTime]) { [DateTime]$finalCheck.Data.GeneratedAt } else { [DateTime]::Parse([string]$finalCheck.Data.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
                    $finalAge = (Get-Date) - $_gen.ToLocalTime()
                    # Fourth and last freshness decision -- same rule as the other three.
                    $_finVerdict = Test-RAAISummaryShouldAdopt -Mode $script:_AISummaryMode `
                        -LeaderGrain $script:_AISummaryLeader -MyGrain $script:_AISummaryMyGrain `
                        -SnapshotGrain (Get-RAReportGrainLabel -ReportTemplate ([string]$finalCheck.Data.SourceTemplate)) `
                        -GeneratedAtUtc $_gen.ToUniversalTime() -NowUtc ([datetime]::UtcNow) `
                        -MaxAgeHours $aiSummaryMaxAgeHours -HasSnapshot
                    if ($_finVerdict.Adopt -and [string]$finalCheck.Data.SourceTemplate -ne [string]$global:ReportTemplate) {
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
    # PerReport never takes another report's score (Test-RAAISummaryUseCachedKpi), whatever is in memory.
    if (Test-RAAISummaryUseCachedKpi -Mode $script:_AISummaryMode -CachedKpi $script:_CachedRAKPI) {
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
            TotalRows    = if ($cachedSevByDomain.Count -gt 0) { $derivedTotalRows } else { $__kpiRows }
            Direction    = 'higher-is-better'
        }
        Write-Info ("[SCORE] OVERRIDE with cached values from AI summary cache: live={0} -> cached={1} (template '{2}' won the cache; ensures Summary + Detailed emails show identical headline KPI within {3}h window)." -f `
            $liveScore, $cachedScore, $c.SourceTemplate, $aiSummaryMaxAgeHours)
    }
    # When THIS run produced the cached AI summary, write the just-computed KPI
    # back into the cache file so the SECOND template (e.g. Detailed after Summary)
    # finds the GlobalScore on its next read. Same idempotent file path.
    elseif ($script:_RACacheNeedsKPIUpdate -and $global:RA_KPI -and $script:RACacheReadable) {
        try {
            $cachedNow = Get-RATop50CachedFile
            if (-not $cachedNow -or -not $cachedNow.Data) {
                # 🪤 In PerReport this WARNING used to fire on every run: the reader is gated
                # off by design, so "the file disappeared" described a mode working correctly.
                # A warning that fires on correct behaviour is how operators learn to ignore
                # warnings. The mode is now excluded at the branch, so reaching this line
                # again means the file genuinely went missing mid-run.
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
                # Narrate from what the writer reports, not from having called it -- same rule
                # as the AI-summary persist above.
                if (Save-RATop50CachedFile -JsonContent $jsonContent) {
                    Write-Info ("[AISummaryCache] persisted fresh Risk Score KPI (GlobalScore={0}, Band='{1}') to shared cache; the other report will reuse this score." -f `
                        $global:RA_KPI.GlobalScore, $global:RA_KPI.Band)
                }
                $script:_RACacheNeedsKPIUpdate = $false
            }
        } catch {
            Write-Warn2 ("[AISummaryCache] failed to persist Risk Score KPI to shared cache: {0} (live KPI still shown in this run's email)." -f $_.Exception.Message)
        }
    }
    # #636: the protection score and the patch cycle on the KPI the mail and the kept view read -- AFTER the cache override above
    # (which rebuilds the object); a Summary run takes the Detailed run's protection score from the shared cache
    $__protScore = $null
    if ($null -ne $__prot) { $__protScore = Complete-SIProtectionTally -Tally $__prot }
    elseif (-not $script:RAProtectionFromStore -and $script:_CachedRAKPI -and $script:_CachedRAKPI.PSObject.Properties['Protection'] -and $null -ne $script:_CachedRAKPI.Protection) { $__protScore = $script:_CachedRAKPI.Protection }
    if ($global:RA_KPI) {
        $global:RA_KPI | Add-Member -NotePropertyName Protection -NotePropertyValue $__protScore -Force
        if (-not $global:RA_KPI.PSObject.Properties['PatchCycle']) { $global:RA_KPI | Add-Member -NotePropertyName PatchCycle -NotePropertyValue (Complete-SIPatchCycleTally -Tally $__patch) -Force }
    }
    if ($null -ne $__protScore -and $null -ne $__prot) {
        Write-Info ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '[SCORE] Protection Score, within Accepted Lifecycle {0:0.0} %, Actual Risks {1:0.0} % ({2} assets in scope; {3} of {4} counted findings without a date)', $__protScore.Lifecycle, $__protScore.Technical, $__protScore.Assets, $__protScore.NoDate, $__protScore.Findings))
        # the Summary run of the same day shows the Detailed run's score: kept in the shared cache beside the AI text
        if ($script:RACacheReadable) {
            try {
                $__cachedP = Get-RATop50CachedFile
                if ($__cachedP -and $__cachedP.Data) {
                    $__cachedP.Data | Add-Member -NotePropertyName Protection -NotePropertyValue $__protScore -Force
                    [void](Save-RATop50CachedFile -JsonContent ($__cachedP.Data | ConvertTo-Json -Depth 12 -Compress))
                }
            } catch { Write-Warn2 ("Protection score: not kept in the shared cache for the Summary run -- {0}" -f $_.Exception.Message) }
        }
    }
} catch {
    Write-Warn2 ("KPI rollup failed: {0} (continuing -- mail will degrade gracefully)" -f $_.Exception.Message)
}

#####################################################################################################
# #636: THE SUMMARY GROUPINGS OF THIS DETAILED RUN (owner 2026-10-19: "community must switch" / "same core functionality").
# Without the Pro database (Community) the groupings of data-model\summary-groupings.locked.json are computed HERE, from
# this run's findings, by THE engine function (engine\_shared\SI-SummaryGroupings.ps1 Invoke-SISummaryGrouping) -- the one
# Pro's data sync runs on the stored collection. They go into the management summary of the mail and next to the workbook
# (<workbook>.groupings.json). Pro reads them from the database (the data sync writes them), so a run streaming to SQL does
# not compute them twice. Never fatal.
#####################################################################################################
$script:RASummaryGroupings = $null
if ([bool]$global:Detailed -and -not $script:RAStreamOn -and -not $script:SIWhatIf) {
    try {
        if (-not (Get-Command -Name Invoke-SISummaryGrouping -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-SummaryGroupings.ps1')) }
        $__sgRows = if ($null -ne $global:final) { @($global:final) } else { @($global:RA_ReportRows) }
        $script:RASummaryGroupings = @(Invoke-SISummaryGrouping -Rows @($__sgRows | Where-Object { $null -ne $_ }))
        $__sgRows = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$global:OutputXlsx)) {
            $__sgFile = [System.IO.Path]::ChangeExtension([string]$global:OutputXlsx, '.groupings.json')
            [System.IO.File]::WriteAllText($__sgFile, (ConvertTo-Json -InputObject @($script:RASummaryGroupings) -Depth 4 -Compress), [System.Text.UTF8Encoding]::new($false))
            Write-Info ("summary groupings: {0} group row(s) from this run's findings (management summary of the mail; {1})" -f @($script:RASummaryGroupings).Count, $__sgFile)
        }
    } catch {
        Write-Warn2 ("summary groupings: not computed this run ({0}) -- the mail goes out without its management summary." -f $_.Exception.Message)
        $script:RASummaryGroupings = $null
    }
}

#####################################################################################################
# #288: THE EXECUTIVE VIEW -- what this run's mail shows, kept for the Pro web app (Overview > Executive report >
# Risk Analysis). One file per report grain, written in EVERY agreement mode, never read back by the engine, so it
# cannot change a mail. Skipped on a dry run and on a run with no rows (whose mail is suppressed too). Never fatal.
#####################################################################################################
try {
    $__evGrain = Get-RAReportGrainLabel -ReportTemplate ([string]$global:ReportTemplate)
    $__evRows  = [long]$script:RAViewCount
    if ($script:SIWhatIf) {
        Write-Info "[dry run] executive view not written."
    } elseif (-not $__evGrain) {
        Write-Info ("executive view: report '{0}' is neither a Summary nor a Detailed report -- not kept for the web app." -f [string]$global:ReportTemplate)
    } elseif ($__evRows -eq 0) {
        Write-Info "executive view: no rows this run -- the last kept view stays."
    } else {
        $__evMode   = if ($script:_AISummaryMode)   { [string]$script:_AISummaryMode }   else { (Resolve-RAAISummaryMode -Value ([string]$global:SI_AISummary_Mode) -Edition (Get-RAAISummaryEdition -ProSettingsVersion ([string]$global:SI_ProSettingsVersion))).Mode }
        $__evLeader = if ($script:_AISummaryLeader) { [string]$script:_AISummaryLeader } else { (Resolve-RAAISummaryLeader -Value ([string]$global:SI_AISummary_Leader)).Leader }
        $__evFrom = [string]$global:ReportTemplate; $__evFromAt = $null
        if ((Test-RAAISummaryUseCachedKpi -Mode $__evMode -CachedKpi $script:_CachedRAKPI) -and $script:_CachedRAKPI.SourceTemplate) {
            $__evFrom = [string]$script:_CachedRAKPI.SourceTemplate; $__evFromAt = $script:_CachedRAKPI.GeneratedAt
        } elseif ($script:_RAExecFiguresFrom) {
            $__evFrom = [string]$script:_RAExecFiguresFrom; $__evFromAt = $script:_RAExecFiguresAt
        }
        $__evTenant = $null
        try { $__evTenant = Get-SITenantDisplayName } catch { $__evTenant = $null }
        $__evMax = if ([int]$global:SI_AISummary_MaxAgeHours -gt 0) { [int]$global:SI_AISummary_MaxAgeHours } else { 24 }
        $__ev = New-RAExecViewSnapshot -Grain $__evGrain -ReportTemplate ([string]$global:ReportTemplate) -Tenant $__evTenant `
            -GeneratedAtUtc ([datetime]::UtcNow) -CollectionTime $global:RA_CollectionTime -SolutionVersion ([string]$global:RA_SolutionVersion) `
            -Mode $__evMode -Leader $__evLeader -MaxAgeHours $__evMax -FiguresFromTemplate $__evFrom -FiguresGeneratedAt $__evFromAt `
            -Kpi $global:RA_KPI -AISummaryEnabled ([bool]$global:BuildSummaryByAI) -AISummaryText ([string]$global:AI_SummaryText) `
            -TopAssets @($script:_RAExecTopAssets) -TopFindings @($script:_RAExecTopFindings)
        $__evJson = $__ev | ConvertTo-Json -Depth 8 -Compress
        $__evBlob = Get-RAExecViewBlobName -Grain $__evGrain -Top50BlobName ([string]$global:SI_RATop50_BlobName)
        $__evRes  = Save-RAExecViewFile -Json $__evJson -LocalPath (Join-Path $global:OutputDir ('RiskAnalysis_ExecView_{0}.json' -f $__evGrain)) `
            -StorageAccount ([string]$global:SI_StorageAccount) -Container $(if ($global:SI_RATop50_BlobContainer) { [string]$global:SI_RATop50_BlobContainer } else { 'sistaging' }) -BlobName $__evBlob
        if ($__evRes.Error) { Write-Warn2 ("executive view for the web app not fully saved ({0}); the report and the mail are not affected." -f $__evRes.Error) }
        else { Write-Info ("executive view kept for the web app ({0}{1})." -f $__evGrain, $(if ($__evRes.Blob) { ', ' + $__evBlob } else { ', local file only' })) }
        # #638: with the result in SQL the view goes straight into sidata.RiskExecView too (the data sync's mapping and its
        # "replace only when newer" statement) -- the web app does not wait for the data sync to copy the file
        if ($script:RAStreamOn) {
            try {
                if (-not (Get-Command -Name ConvertFrom-SIDataExecViewJson -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '_shared', 'data-sql', 'SI-DataExecView.ps1')) }
                $__evRow = ConvertFrom-SIDataExecViewJson -Json $__evJson -ExpectedGrain $__evGrain
                if (-not $__evRow.Problem) { $null = & $script:RAStream.Invoke (Get-SIDataExecViewUpsertSql) $__evRow.Row 'nonquery'; Write-Info ("executive view written to the database ({0})." -f $__evGrain) }
                else { Write-Warn2 ("executive view not written to the database: {0}" -f $__evRow.Problem) }
            } catch { Write-Warn2 ("executive view not written to the database ({0}); the data sync copies the file." -f $_.Exception.Message) }
        }
    }
} catch {
    Write-Warn2 ("executive view for the web app not saved: {0} (the report and the mail are not affected)." -f $_.Exception.Message)
}

#####################################################################################################
# SEND OUTPUT VIA MAIL
#####################################################################################################

# Suppress the mail dispatch when zero rows were produced this run. A "0 findings"
# email creates noise that erodes trust in real findings emails (operators stop
# reading SI mail). Customer can force-send the empty report (e.g. as a heartbeat
# that "SI ran successfully today") via $global:RA_MailEvenIfEmpty = $true.
if ([bool]$global:Report_SendMail -and -not [bool]$global:RA_MailEvenIfEmpty) {
    $__rowCount = [long]$script:RAViewCount
    if ($__rowCount -eq 0) {
        Write-Warn2 "mail dispatch suppressed: 0 rows produced this run. Set `$global:RA_MailEvenIfEmpty=`$true to receive empty-report emails as a heartbeat."
        $global:Report_SendMail = $false
    }
}

Write-Section "mail dispatch decision"

# ---- v2.2.444: SANITISE THE RECIPIENT LIST BEFORE THE SEND DECISION ----
# 🔴 ONE EMPTY STRING IN THE OPERATOR'S ARRAY KILLED THE ENTIRE DISPATCH. A config line like
#     $global:RiskAnalysis_Detailed_To = @("a@x.dk","b@y.dk","")
# -- which is what a trailing comma, or deleting an address and leaving its quotes, produces -- flowed
# straight into Send-MailMessage's -To. That parameter validates PER ELEMENT, so it threw
#     "Cannot bind argument to parameter 'To' because it is an empty string"
# and the whole run failed. Nothing between the config and the cmdlet ever looked at the values.
#
# 🪤 AND IT LANDED AT THE WORST POSSIBLE MOMENT: the report was built, the workbook written, every
# query run -- and the run died on the final dispatch. Same shape as v2.2.439, where a finished Risk
# Analysis run could be thrown away at the last write. The engine's own diagnostic dump even printed
# the trailing ", " in the To line, and nothing said why that mattered.
#
# Sanitised HERE, above the send decision, so both the anonymous and the secure branch are covered by
# one filter rather than two that can drift.
# #636: the management mail once more, now with the stored pipeline (the Pro database, when this run writes to it): while the
# Summary step is not on, its mail settings (RiskAnalysis_Summary_SendMail / _To) are this mail's -- said once. Only narrows
# what was decided at the start (a mail switched off since stays off); a state the same as at the start changes nothing.
if ($null -ne $script:RAMgmtMail -and [bool]$global:Report_SendMail -and $script:RAStreamOn -and $script:RAStream -and $script:RAStream.Invoke) {
    try {
        $__mmState = Get-SISummaryStepState -Invoke $script:RAStream.Invoke
        if ($__mmState -ne [string]$script:RAMgmtMailEarly) {
            $__mm = Resolve-SIManagementMailRouting @script:RAMgmtMail -SummaryStep $__mmState
            $global:Report_SendMail = $__mm.Send; $global:Report_To = @($__mm.To)
        } else { $__mm = Resolve-SIManagementMailRouting @script:RAMgmtMail -SummaryStep $__mmState }
        if (@($__mm.Moved).Count) { Write-Info ("management mail: the Risk Analysis Summary step is off, so the Summary report's recipients ({0}) receive this mail (RiskAnalysis_Summary_To)" -f (@($__mm.Moved) -join ', ')) }
    } catch { Write-Warn2 ("management mail: the Summary step's state was not read ({0}) -- the recipients decided at the start are used." -f $_.Exception.Message) }
}
$__toRaw     = @($global:Report_To)
$to          = @($__toRaw | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$__toDropped = $__toRaw.Count - $to.Count

# NAME what was dropped instead of silently tidying it. A config that quietly loses a recipient looks
# exactly like one that works, and the operator never learns an address was malformed -- which is how
# someone stops receiving a report and nobody notices for a month.
if ($__toDropped -gt 0) {
    Write-Warn2 ("mail recipients: dropped {0} empty/blank entr{1} from the configured recipient list ({2} valid recipient(s) remain). Check for a trailing comma or an empty string in your `$global:RiskAnalysis_*_To / `$global:MailTo array in config\SecurityInsight.custom.ps1." -f `
        $__toDropped, $(if ($__toDropped -eq 1) { 'y' } else { 'ies' }), $to.Count)
}

# Every recipient blank is a CONFIG error, not a transport error, and it must not present as one. Mail
# is non-fatal everywhere else in this engine ("Engine continues"), so it stays non-fatal here: the
# report and workbook are already complete on disk and are not worth discarding over an email.
if ([bool]$global:Report_SendMail -eq $true -and $to.Count -eq 0) {
    Write-Err2 ("mail dispatch SKIPPED -- every configured recipient was empty or blank ({0} entr{1} supplied, 0 usable). The report and workbook are COMPLETE and on disk; only the email was not sent. Fix the recipient array in config\SecurityInsight.custom.ps1 and re-run, or run with -SkipMail to silence this." -f `
        $__toRaw.Count, $(if ($__toRaw.Count -eq 1) { 'y' } else { 'ies' }))
    $global:Report_SendMail = $false
}

# From address -- resolve in order:
#   1) $global:SMTPFrom   (canonical; required when SMTP relay demands a verified sender,
#      e.g. Hosted relays reject mail whose From != verified sender)
#   2) $global:MailFrom   (shorthand)
#   3) $global:SMTPUser   (legacy fallback; works only when the relay accepts the
#      SMTP-login-as-sender, which most modern relays do NOT)
# 🔴 RESOLVED BEFORE THE SEND DECISION, AND A MISSING ONE TURNS MAIL OFF -- IT NEVER `return`s. This
# code is at SCRIPT scope: a `return` here ended the whole run, skipping the bucket-loss roll-up, the
# row-count and column-fill guards and the RunHealth END row -- so SI_RunHealth_CL showed a start with
# no end, which reads as a crash, on a run that had in fact completed (#120). Same pattern as the
# empty-recipient case just above: mail is non-fatal, the run carries on.
$from = $null
foreach ($_c in 'SI_Mail_From','SMTPFrom','MailFrom','SMTPUser') {
    $_v = (Get-Variable -Scope Global -Name $_c -ValueOnly -ErrorAction SilentlyContinue)
    if (-not [string]::IsNullOrWhiteSpace([string]$_v)) { $from = [string]$_v; break }
}
if ([bool]$global:Report_SendMail -eq $true -and [string]::IsNullOrWhiteSpace($from)) {
    Write-Warn2 "Mail enabled but no From address configured. Set `$global:SMTPFrom (preferred), `$global:MailFrom, or `$global:SMTPUser. Skipping mail dispatch -- xlsx + json artifacts are still on disk + ingested to LA."
    $global:Report_SendMail = $false
}

if ($script:SIWhatIf -and [bool]$global:Report_SendMail -eq $true) {
    Write-Info ("[dry run] mail NOT sent (would have gone to: {0})." -f ((@($to) | ForEach-Object { [string]$_ }) -join ', '))
    $global:Report_SendMail = $false
}

if ([bool]$global:Report_SendMail -eq $true) {
    # Tenant tag for the subject -- lets a multi-tenant operator separate
    # incoming reports at a glance: '<primary domain> (<tenant id>)' (#243). The domain comes from
    # $global:SI_TenantDomain, else the v2.2 globals (TenantNameOrganization / TenantShort), else
    # Microsoft Graph /organization as the run's identity -- engine/_shared/SI-TenantDisplay.ps1.
    # The id alone when the domain cannot be read; never fails the mail.
    # Skipped silently when nothing is known (subject stays clean).
    $tenantTag = $null
    try { $tenantTag = Get-SITenantDisplayName } catch { $tenantTag = $null }
    # SUP-2026-00322: 'Failed' only for a report that REALLY did not complete; a report held ON PURPOSE (#901, a silent
    # source / an incomplete role read) is its own line in the body (Get-RARunFailureSplit -- the stored HoldKind's rule)
    $__mailSplit = $null
    try { $__mailSplit = Get-RARunFailureSplit } catch { $__mailSplit = $null }
    if ($null -eq $__mailSplit) { $__mailSplit = [pscustomobject]@{ Real = @(if ($null -ne $script:_RAReportFailures) { $script:_RAReportFailures.ToArray() }); Held = @() } }
    $__mailReal = @($__mailSplit.Real | Where-Object { $_ })
    $__mailHeld = @($__mailSplit.Held | Where-Object { $_ })
    $subject     = Get-RAMailSubject -ReportTemplate ([string]$global:ReportTemplate) -TenantTag $tenantTag -NotComplete:([bool]($__mailReal.Count -gt 0))
    # 🔒 ATTACHMENT SIZE GUARD (v2.2.441). A workbook that exceeds the relay's limit does not
    # "arrive smaller" -- the whole MESSAGE is rejected, so the operator loses the AI summary and the
    # findings too, not just the spreadsheet. With the Excel cap now allowing up to 1,000,000 rows the
    # .xlsx can comfortably reach hundreds of MB, so this is reachable, not theoretical.
    # 🔑 The trade: DROP THE ATTACHMENT, SEND THE MAIL. The body carries the summary and the top
    # findings, which is the part people read; the workbook is recoverable from disk and from the
    # blob upload. Losing the mail to save the attachment would be the wrong way round.
    # ⚠️ Base64 inflates an attachment by ~37% on the wire, so the cap is compared against the ENCODED
    # size, not the size on disk. A 10 MB file is ~13.7 MB of message -- which is why a naive on-disk
    # check passes and the relay still rejects.
    # 24 MB is the MESSAGE budget, not the on-disk file size -- the limit relays actually enforce.
    # Because base64 inflates by ~37%, a 24 MB budget admits a workbook of roughly 17 MB on disk.
    # Both numbers are printed in the warning so there is never any doubt which one was measured.
    # 🪤 THE DEFAULT IS SIZED FOR THE RELAY, NOT FOR THE REPORT, AND THAT IS DELIBERATE.
    # Most relays cap a message at 25 MB (Exchange Online's default; on-prem is often lower), and
    # that cap covers the WHOLE message -- body and headers included, not just the attachment this
    # function measures. 24 leaves roughly 1.7 MB of headroom under a 25 MB relay.
    # A budget set ABOVE what the relay accepts is worse than one set below it: instead of the
    # graceful "summary sent, attachment dropped", the relay rejects the ENTIRE message and the
    # recipient gets nothing at all. v2.2.458 briefly shipped 34 here, which produces a ~33 MB
    # message and would do exactly that on a 25 MB relay; v2.2.459 corrected it.
    # Customers whose relay accepts more can raise $global:SI_MaxMailAttachmentMB in their own
    # config. Lowering it is always safe; raising it is only safe if you know the relay's limit.
    $_mailMaxMb    = if ($global:SI_MaxMailAttachmentMB -gt 0) { [double]$global:SI_MaxMailAttachmentMB } else { 24 }
    # MAIL-1: through the shared mailbox (Microsoft Graph) at most 3 MB can be attached inline; a larger workbook is left
    # out and the mail says where it is (an upload session would need Mail.ReadWrite -- more than Mail.Send).
    if ($script:RAMailSettings -and $script:RAMailSettings.Mode -eq 'sharedMailbox') { $_mailMaxMb = [Math]::Min($_mailMaxMb, [double]$script:RAMailSettings.MaxAttachmentMb) }
    $_attachNotice = ''
    $attachments   = @()
    if (-not $script:RAWorkbookSkipped -and (Test-Path -LiteralPath $global:OutputXlsx)) {
        # One implementation of the size rule, in RA-Mail.ps1, so the boundary the tests pin is the
        # boundary the engine applies.
        $_fit       = Test-SIMailAttachmentFits -SizeBytes ((Get-Item -LiteralPath $global:OutputXlsx).Length) -MaxMb $_mailMaxMb
        $_encodedMb = $_fit.EncodedMb
        $_diskMb    = $_fit.DiskMb
        if (-not $_fit.Fits) {
            Write-Warn2 ("mail: NOT attaching {0} -- {1} MB on disk (~{2} MB once base64-encoded) exceeds the {3} MB attachment limit. The mail is still sent WITH the summary; the workbook stays on disk{4}. Raise with `$global:SI_MaxMailAttachmentMB." -f `
                (Split-Path $global:OutputXlsx -Leaf), $_diskMb, $_encodedMb, $_mailMaxMb, $(if ($global:ExportDestination) { " and at $($global:ExportDestination)" } else { '' }))
            $_attachNotice = ('<p style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.5;margin:0 0 14px 0;padding:10px 12px;border-left:4px solid #c00;background:#fff4f4;">' +
                '<b>Workbook not attached:</b> the full report was too large to attach ({0} MB, ~{1} MB encoded; limit {2} MB).<br/>' +
                'This email still contains the complete summary below. The workbook is available at:<br/>' +
                '<code>{3}</code>{4}</p>') -f $_diskMb, $_encodedMb, $_mailMaxMb, $global:OutputXlsx,
                $(if ($global:ExportDestination) { '<br/><code>' + $global:ExportDestination + '</code>' } else { '' })
        } else {
            $attachments = @($global:OutputXlsx)
        }
    }
    # No workbook this run (switched off for this grain, larger than a workbook holds here, or it could not be written):
    # the mail says so, and that the results are in the web app (Invoke-RAWorkbookStep).
    if (-not [string]::IsNullOrWhiteSpace([string]$script:RAWorkbookMailNote)) { $_attachNotice = [string]$script:RAWorkbookMailNote + $_attachNotice }

    $aiEnabled = [bool]$global:BuildSummaryByAI

    # ----- minimal markdown -> HTML for the AI section -----
    # Handles the subset the AI prompt produces:
    #   ## H2 / ### H3
    #   **bold** / _italic_
    #   - bullet (line-leading "- ")
    #   blank line -> paragraph break
    function _MdToHtml([string]$src) {
        # MAIL-2 / #573: the ONE mail layout (engine\_shared\SI-MailLayout.ps1) -- a <p> per PARAGRAPH (a blank line
        # separates them, a single line break stays a <br>), an explicit paragraph margin, every value encoded. It
        # replaced a <p> per LINE with a 6 px gap, which ran the narrative's paragraphs together.
        if ([string]::IsNullOrWhiteSpace($src)) { return '' }
        if (-not (Get-Command -Name ConvertTo-SIMailParagraphHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-MailLayout.ps1')) }
        return (ConvertTo-SIMailParagraphHtml -Text $src -Markdown)
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
    # the mail names the report "Summary report" / "Detailed report" -- never the internal template id
    $__mailReportName = [System.Net.WebUtility]::HtmlEncode((Get-RAMailReportName -ReportTemplate ([string]$global:ReportTemplate)))
    if ((Test-RAAISummaryUseCachedKpi -Mode $script:_AISummaryMode -CachedKpi $script:_CachedRAKPI) -and $script:_CachedRAKPI.SourceTemplate) {
        $_srcTpl = [System.Net.WebUtility]::HtmlEncode((Get-RAMailReportName -ReportTemplate ([string]$script:_CachedRAKPI.SourceTemplate)))
        $_ageHrs = -1.0
        try {
            $_gen = if ($script:_CachedRAKPI.GeneratedAt -is [DateTime]) { [DateTime]$script:_CachedRAKPI.GeneratedAt } else { [DateTime]::Parse([string]$script:_CachedRAKPI.GeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture) }
            $_ageHrs = [Math]::Round(((Get-Date) - $_gen.ToLocalTime()).TotalHours, 1)
        } catch { }
        if ($_ageHrs -ge 0) {
            $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated by <strong>{0}</strong> {1}h ago (this <strong>{2}</strong> run reused today's snapshot, so both reports show the same figures). Re-runs of either report today replay the same snapshot." -f $_srcTpl, $_ageHrs, $__mailReportName)
        } else {
            $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated by <strong>{0}</strong> (this <strong>{1}</strong> run reused today's snapshot, so both reports show the same figures)." -f $_srcTpl, $__mailReportName)
        }
    } elseif ($script:_AISummaryMode -eq 'PerReport') {
        # PerReport never adopts a peer snapshot, so "next run will replay this" would
        # be false. Say what this mode actually guarantees instead.
        $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated <strong>live by this run</strong> (<strong>{0}</strong>). Each report shows its own figures; nothing is carried over from the other report." -f $__mailReportName)
    } else {
        $aiSourceLine = ("Headline KPI + Top-50 + this narrative: generated <strong>live by this run</strong> ({0}). The other report run today will replay this snapshot." -f $__mailReportName)
    }

    # The two grains are not comparable, and this sentence is the whole point of the
    # exercise: management receiving BOTH reports kept asking why the percentages
    # differ. Freezing one report's numbers onto the other made the mails agree, but
    # it never answered the question -- it hid it, and the answer is simply that the
    # two reports count different things. Shown in BOTH modes: in Consistent it
    # explains why the per-domain row counts still differ even though the headline
    # KPI matches; in PerReport it explains the whole divergence.
    # #636: the Detailed report is the default (the Summary step is optional): the note is said on a Summary report only
    $grainNote = if ([string]$global:ReportTemplate -notlike '*_Summary*') { '' } else { 'The <strong>Summary</strong> report counts distinct <strong>assets</strong>; the <strong>Detailed</strong> report counts individual <strong>asset findings</strong> (one asset can carry many). The two reports therefore show different totals and percentages for the same estate &mdash; that is expected, and neither figure is wrong.' }

    $aiSection = ''
    if ($aiEnabled) {
        $aiHtml = ''
        if (-not [string]::IsNullOrWhiteSpace($global:AI_SummaryText)) {
            $aiHtml = _MdToHtml ($global:AI_SummaryText.Trim())
        } else {
            $aiHtml = 'AI summary was enabled, but no AI summary output was produced.'
        }
        # #728: a section heading of the one layout; the narrative's own paragraphs, headings and bullets (_MdToHtml)
        if (-not (Get-Command -Name ConvertTo-SIMailHeadingHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-MailLayout.ps1')) }
        $aiHead = ConvertTo-SIMailHeadingHtml 'AI-generated analysis'
        $aiSection = @"
        $aiHead
        <div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#333;line-height:1.55;">$aiHtml</div>
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#888;margin:10px 0 6px 0;font-style:italic;">This narrative was generated by AI and may contain mistakes. Validate critical decisions against the detailed Excel findings.</p>
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#5a6a7a;margin:4px 0 14px 0;">$aiSourceLine</p>
"@
    } else {
        $aiSection = @"
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#888;margin:18px 0 6px 0;">AI narrative not included this run. Turn on the setting <a href="https://invardia.com/docs/si/settings/BuildSummaryByAI/" style="color:#2c5a8e;">AI summary in the report mail</a> (BuildSummaryByAI) to add it.</p>
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#5a6a7a;margin:4px 0 14px 0;">$aiSourceLine</p>
"@
    }

    # #709 / framework 8.16: a mail about a run that is NOT COMPLETE names the stable code of each failure, linked to its page
    # (https://invardia.com/docs/si/errors/<code>/) -- the same code the run record, the ticket and support carry
    $codeSection = ''
    try {
        if ($__mailReal.Count -gt 0 -and (Get-Command -Name ConvertTo-SIErrorCodeMailHtml -ErrorAction SilentlyContinue)) {
            # the real failures only: a report held on purpose has no error code in this mail (SUP-2026-00322)
            $__mailHeldNames = @($__mailHeld | ForEach-Object { [string]$_.Report })
            $__mailFacts = @(Get-SIReportCauseFacts -Notes $script:RAReportNotes -Failures $__mailReal -Done $script:RAReportStatusDone | Where-Object { [string]$_.State -in @('Failed', 'NotComplete') -and $__mailHeldNames -notcontains [string]$_.Report })
            $codeSection = ConvertTo-SIErrorCodeMailHtml -Codes @(Get-SIUplinkMailCodes -Facts $__mailFacts)
        }
    } catch { $codeSection = '' }

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
            TotalRows   = [long]$script:RAViewCount
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
    # ----- the mail body (#728: no tables -- readable on a phone) -----
    # engine\risk-analysis\_shared\RA-ReportMail.ps1 builds it in the one SI mail layout: the SUMMARY first (risk score +
    # band, the totals per severity, whether to act; the portal link line goes directly under it), the workbook notice,
    # "Findings by domain" and "Risk by domain" as ONE LINE PER DOMAIN, the grain note, the workbook sentence, the error
    # references, the AI analysis, the footer. Same content and numbers as the table layout it replaced.
    if (-not (Get-Command -Name ConvertTo-RAReportMailHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '_shared', 'RA-ReportMail.ps1')) }
    $genTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm zzz')
    $solVer       = if ([string]::IsNullOrWhiteSpace([string]$global:RA_SolutionVersion)) { '(dev)' } else { [string]$global:RA_SolutionVersion }
    # Prepended to the content, not appended: a missing attachment must be the first thing the reader sees after the
    # summary, or they scroll a complete-looking mail and never learn the workbook was omitted.
    # #636: the management summary of the Detailed findings (computed above, Community) -- the Summary report's mail content
    $__sgHtml = ''
    if ($null -ne $script:RASummaryGroupings) { try { $__sgHtml = ConvertTo-RAReportMailGroupingsHtml -Result @($script:RASummaryGroupings) -Counted (-not [bool]$global:SI_Exempted_CountInManagement) } catch { $__sgHtml = '' } }
    $__mailArgs = @{ ReportLabel = (Get-RAMailReportName -ReportTemplate ([string]$global:ReportTemplate)); TenantTag = ([string]$tenantTag); GeneratedAt = $genTimestamp
        SolutionVersion = $solVer; NoticeHtml = $_attachNotice; GrainNoteHtml = $grainNote; CodeSectionHtml = $codeSection; AiSectionHtml = $aiSection
        PatchHtml = $(if ($kpi.PSObject.Properties['PatchCycle'] -and (Get-Command -Name ConvertTo-SIPatchCycleMailHtml -ErrorAction SilentlyContinue)) { ConvertTo-SIPatchCycleMailHtml -Summary $kpi.PatchCycle } else { '' })
        NotComplete = ([bool]($__mailReal.Count -gt 0)); HeldReports = $__mailHeld }
    $bodyHtml = ConvertTo-RAReportMailHtml -Kpi $kpi @__mailArgs -GroupingsHtml $__sgHtml -ProtectionReason ([string]$script:RAProtectionReason)

    # Auto-assemble the SMTP PSCredential if the customer only provided
    # username + password strings. This avoids Send-MailMessage prompting
    # interactively for credentials when $global:SecureCredentialsSMTP is
    # $null.
    #
    # Fallback chain -- tries each (userVar, passwordVar) pair and uses the
    # first one where both are populated. Covers the canonical SI naming plus
    # common platform-defaults / AF-prefixed variants.
    $__raMode = if ($script:RAMailSettings) { [string]$script:RAMailSettings.Mode } else { 'smtp' }
    if ($__raMode -eq 'smtp' -and -not [bool]$global:Mail_SendAnonymous -and -not $global:SecureCredentialsSMTP) {
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

    # The workbook notice ($_attachNotice) is already in the body, directly under the summary (ConvertTo-RAReportMailHtml -NoticeHtml).

    # MAIL-1: ONE transport for every mail -- the shared mailbox (Microsoft Graph, this run's identity) or the SMTP relay.
    # Send-SIMail never throws: it prints its diagnostics and says Sent / Error; the run continues either way (mail is
    # non-fatal for Risk Analysis).
    $__mailSettings = Get-SIMailSettings
    $__mailSettings.From = $from
    $__sendNow = $true
    if ($script:RAProtectionFromStore) {
        # PRO: the mail WAITS for this collection's stored Protection Score (the data sync sends it right after its key figures
        # -- SI-RaMailOutbox.ps1). First, a mail of an EARLIER run that is still waiting (no data sync has run since) is sent
        # now, with its stored score or the one line why. A mail that cannot be kept is sent at once, saying why -- never lost.
        try {
            if (-not (Get-Command -Name Add-SIRaMailOutbox -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'data-sql', 'SI-RaMailOutbox.ps1')) }
            $__oInv = $script:RAStream.Invoke
            $__syncRunning = $false
            try { $__syncRunning = [int](@(& $__oInv "SET NOCOUNT ON; IF OBJECT_ID('sidata.ViewState') IS NULL SELECT 0; ELSE SELECT COUNT(*) FROM sidata.ViewState WHERE Name = N'sync' AND UpdatedAt > DATEADD(hour, -12, SYSUTCDATETIME());" @{} 'scalar') | Select-Object -Last 1) -gt 0 } catch { $__syncRunning = $true }
            $__oSend = { param($m) $s = Get-SIMailSettings; if ($m.From) { $s.From = $m.From }; $r = Send-SIMail -Settings $s -To @($m.To) -Subject $m.Subject -BodyHtml $m.BodyHtml -Attachments @($m.Attachments) -Priority $m.Priority; @{ Sent = [bool]$r.Sent; Error = [string]$r.Error } }
            $null = Invoke-SIRaMailOutbox -Invoke $__oInv -Role producer -Send $__oSend -OwnCollectionId ([int]$script:RAStream.CollectionId) -SyncRunning $__syncRunning `
                -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } elseif ($l -eq 'OK') { Write-Ok $m } else { Write-Info $m } }
            # review B1: kept only when the data sync recorded that it can send -- else this mail goes NOW, saying where the score is
            $__sender = Test-SIRaMailSender -Invoke $__oInv
            if (-not $__sender.Ready) {
                Write-Info ("mail: sent now, without waiting for the stored Protection Score -- {0}" -f $__sender.Why)
                $bodyHtml = ConvertTo-RAReportMailHtml -Kpi $kpi @__mailArgs -GroupingsHtml $__sgHtml -ProtectionReason (Get-SIProtectionReason 'mail-not-ready')
                throw [System.OperationCanceledException]::new('sender-not-ready')
            }
            $__pending = ConvertTo-RAReportMailHtml -Kpi $kpi @__mailArgs -GroupingsHtml $__sgHtml -ProtectionPending
            $__mid = Add-SIRaMailOutbox -Invoke $__oInv -CollectionId ([int]$script:RAStream.CollectionId) -CollectionTime ([datetime]$script:RAStream.CollectionTime) -Subject $subject `
                -BodyHtml $__pending -To @($to) -From $from -Priority 'High' -AttachmentPath $(if (@($attachments).Count) { [string]@($attachments)[0] } else { '' })
            Write-Ok ("mail kept for the data sync (#{0}): it goes to {1} once this run's Protection Score is stored -- the numbers the web app shows" -f $__mid, ($to -join ', '))
            $__sendNow = $false
        } catch [System.OperationCanceledException] {
            # (the data sync cannot send: the body with its line was built above -- sent below, now)
        } catch {
            Write-Warn2 ("mail: could not wait for this run's stored Protection Score ({0}) -- sent now, saying why the score is not in it" -f $_.Exception.Message)
            $bodyHtml = ConvertTo-RAReportMailHtml -Kpi $kpi @__mailArgs -GroupingsHtml $__sgHtml -ProtectionReason (Get-SIProtectionReason 'no-wait' $_.Exception.Message)
        }
    }
    if ($__sendNow) {
    Write-Step ("sending mail ({0}) to: {1}" -f $__mailSettings.Mode, ($to -join ', '))
    $__mailRes = Send-SIMail -Settings $__mailSettings -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments -Priority 'High'
    if ($__mailRes.Sent) {
        if ($__mailSettings.Mode -eq 'sharedMailbox') { Write-Ok ("mail sent from the shared mailbox {0} (Microsoft Graph accepted it)" -f $__mailSettings.SharedMailbox) }
        else { Write-Ok "mail sent (NOTE: SMTP 250 OK only proves the relay accepted the message -- verify actual delivery in your SMTP provider's activity log + the recipient's junk folder)" }
    } else {
        Write-Err2 ("mail FAILED: {0}. Engine continues (mail is non-fatal); fix the cause and re-run." -f $__mailRes.Error)
    }
    }
}
else {
    Write-Info "mail flag disabled; not sending"
}

# The run that must END FAILED (recorded where the collection is completed, above): now, after the workbook and the mail.
if ($null -ne $script:_RAEndFailure) {
    Send-RARunHealthEnd -ExitReason 'error' -ErrorMessage ([string]$script:_RAEndFailure.Health)
    Write-Section "script completed with an error"
    foreach ($__efl in @($script:_RAEndFailure.Lines)) {
        if ([string]$__efl -eq '@workbook') {
            if (-not [string]::IsNullOrWhiteSpace([string]$global:OutputXlsx) -and (Test-Path -LiteralPath $global:OutputXlsx)) { Write-Err2 ("The workbook of this run is on disk: {0}" -f $global:OutputXlsx) }
        } else { Write-Err2 ([string]$__efl) }
    }
    throw ([string]$script:_RAEndFailure.Throw)
}
# #774: a Detailed run that will skip its findings (SI_Finding_CL) says so loudly and on the run record -- a warning, never
# a changed exit (no blocking guard); the data sync fills the findings per CI from the database.
$script:RAFindingsRunNote = ''
try {
    . (Join-Path $PSScriptRoot '_shared/RA-Findings.ps1')
    $script:RAFindingsRunNote = [string](Get-SIFindingsSkipNote -Detailed ([bool]$global:Detailed) -Published ($null -ne $script:_RAPublishedRows) `
                                    -WhatIfRun ([bool]$script:SIWhatIf) -SentToLogAnalytics ([bool]$global:SendToLogAnalytics) -EndFailed ($null -ne $script:_RAEndFailure))
    if ($script:RAFindingsRunNote) { Write-Warn2 $script:RAFindingsRunNote }
} catch { Write-Warn2 ("the findings publish could not be judged: {0}" -f $_.Exception.Message) }
# v3 data model: the Detailed run's published rows de-duplicated per CI and finding key -> SI_Finding_CL (RA-Findings.ps1).
# #829 "Copy findings per CI to Log Analytics (SI_Finding_CL)" is an OPTIONAL output, OFF by default (SI_RA_Findings): the
# data sync makes the findings per CI from the database. When it is on, the copy runs BEFORE the run's END record, so a
# run that has ended is a copy that has ended -- the data sync never starts reading a collection still being written.
# Only rows Log Analytics received; never fails the run.
if ([bool]$global:Detailed -and $null -ne $script:_RAPublishedRows) {
    try {
        . (Join-Path $PSScriptRoot '_shared/RA-Findings.ps1')
        if (-not (Test-SIFindingsCopyOn)) {
            Write-Info 'findings per CI: the copy to Log Analytics (SI_Finding_CL) is off (the default) -- the data sync makes them from the database'
        } else {
            $__ct = [datetime]::UtcNow; $__r0 = @($script:_RAPublishedRows)[0]; if ($__r0 -and $__r0.PSObject.Properties['CollectionTime'] -and $__r0.CollectionTime) { try { $__ct = ([datetime]$__r0.CollectionTime).ToUniversalTime() } catch { } }
            $__nFind = 0L
            if ($script:RAStreamOn) { $__ct = ([datetime]$global:RA_CollectionTime).ToUniversalTime(); $__nFind = Publish-SIFindings -Pager (New-RARowPager -Stream $script:RAStream -Source FindingKey) -CollectionTime $__ct -WhatIfRun:([bool]$script:SIWhatIf) }
            else { $__nFind = Publish-SIFindings -Rows @($script:_RAPublishedRows) -CollectionTime $__ct -WhatIfRun:([bool]$script:SIWhatIf) }
            # #774: rows went out but no finding was posted (a failed post) -- loud, never silent; the data sync fills them from SQL
            if ([long](@($__nFind) | Select-Object -Last 1) -eq 0 -and $script:RAAllCount -gt 0 -and -not [bool]$script:SIWhatIf) {
                Write-Warn2 ("no findings were posted to SI_Finding_CL from {0} Detailed row(s) -- the data sync fills the findings per CI from the database" -f $script:RAAllCount)
            }
        }
    } catch { Write-Warn2 ("findings were not published: {0}" -f $_.Exception.Message) }
}
Send-RARunHealthEnd -ExitReason 'success'
# #306: the day's trend row (SI_Trend_CL), from the rows this run published -- the risk trend is no longer a job of the
# pipeline. #636: the DETAILED run writes it (the Summary step is optional and off by default; the trend counts findings).
# Never fails the run (RA-TrendAtEnd.ps1).
try {
    . (Join-Path $PSScriptRoot '_shared/RA-TrendAtEnd.ps1')
    # #394: the rows Log Analytics actually received -- not merely "SendToLogAnalytics was on" (a post that was skipped or
    # failed published nothing, and the day is then a gap rather than a rollup of rows that are not in the table).
    # #638: from SQL the day's rollup is computed there (the rows this run wrote = the rows it published), never the rows in memory
    $__trRollup = $null; $__trCount = -1L
    if ($script:RAStreamOn -and [bool]$global:Detailed -and $null -ne $script:_RAPublishedRows) { $__trRollup = @(Get-RAStreamTrendRollup -Stream $script:RAStream); $__trCount = $script:RAAllCount }
    $null = Invoke-SIRaTrendAtEnd -Rows @($script:_RAPublishedRows) -Rollup $__trRollup -RowCount $__trCount -Detailed ([bool]$global:Detailed) -Published ($null -ne $script:_RAPublishedRows) -WhatIfRun ([bool]$script:SIWhatIf) `
        -LostBuckets $(if ($null -ne $script:_RABucketLossRun) { @($script:_RABucketLossRun).Count } else { 0 }) `
        -UpstreamExit $(if ($script:_RAUpstreamOutcome) { [string]$script:_RAUpstreamOutcome.ExitReason } else { 'success' }) `
        -Setting $global:SI_Trend_AtEndOfRiskAnalysis -Copy ([bool](Test-SIRaReportCopyOn)) -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warn2 $m } else { Write-Info $m } }
} catch { Write-Warn2 ("the daily trend row was not written: {0}" -f $_.Exception.Message) }
# #689 WEEKLY CONTEXT DISCOVERY FOR RISK ANALYSIS (engine/data-model/SI-ContextDiscovery.ps1): at most once in six days, after
# a Detailed run, what the sources hold that the chain (source column -> mapping -> SI field -> output map) does not carry
# yet is saved as proposals (additions only, never a rename). Every install has this job, so a new and an existing install
# both get it with the code. Read only; never fails the run.
if ([bool]$global:Detailed -and $script:RAScaleRole -ne 'worker' -and -not [bool]$script:SIWhatIf) {
    try {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/SI-ContextDiscovery.ps1')
        $__cdHunt = $null
        if ((Get-Command -Name Invoke-SIHuntingQueryRest -ErrorAction SilentlyContinue) -and $script:GraphAccessToken) {
            $__cdHunt = { param($Kql) $__r = Invoke-SIHuntingQueryRest -Query $Kql -Token $script:GraphAccessToken -TimeoutSec 900; @(@($__r.Results) | ForEach-Object { $_.AdditionalProperties }) }
        }
        $null = Invoke-SIContextDiscoveryIfDue -SIRoot (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -Hunting $__cdHunt -Log { param($l, $m) Write-Info $m }
    } catch { Write-Info ("the weekly context discovery was not run: {0}" -f $_.Exception.Message) }
}
Write-Section "script completed"
