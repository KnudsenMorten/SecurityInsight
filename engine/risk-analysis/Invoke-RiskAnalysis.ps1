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

function Get-RowValue {
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter(Mandatory=$true)] [string[]] $Names
    )
    foreach ($n in $Names) {
        if ($Row.PSObject.Properties.Name -contains $n) {
            $v = $Row.$n
            if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
        }
    }
    return ""
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
function Write-Phase  {
    param([Parameter(Mandatory)][string]$Title, [string]$Subtitle = '')
    # flush-left (no 1-char indent). Subtitles are usually multi-line
    # report descriptions from YAML; with a leading-space the first line indents
    # but PowerShell's Write-Host doesn't propagate the indent to wrapped /
    # newline-split lines, so they end up flush-left while line 1 floats one char
    # right -- looked broken. All lines now start at column 0 for clean alignment.
    $line = '-' * 88
    Write-Host ''
    Write-Host $line -ForegroundColor White
    Write-Host $Title.ToUpper() -ForegroundColor Cyan
    if ($Subtitle) { Write-Host $Subtitle -ForegroundColor White }
    Write-Host $line -ForegroundColor White
}
function Write-Sep          { Write-Host ("-" * 80) -ForegroundColor DarkCyan }
function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Resolve-AssetNamesForRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter()][AllowNull()] [object] $AssetsText
    )

    function _ToText([AllowNull()][object]$v) {
        if ($null -eq $v) { return "" }

        # Already a string
        if ($v -is [string]) { return $v }

        # Arrays / IEnumerable (but not string) -> try JSON first, else join
        if (($v -is [System.Collections.IEnumerable]) -and -not ($v -is [string])) {
            try { return ($v | ConvertTo-Json -Compress -Depth 12) } catch {}
            try {
                $parts = @()
                foreach ($x in $v) { if ($null -ne $x) { $parts += ("" + $x) } }
                return ($parts -join ",")
            } catch {
                return ("" + $v)
            }
        }

        # PSCustomObject / Hashtable -> JSON
        if ($v -is [pscustomobject] -or $v -is [hashtable] -or $v -is [System.Collections.IDictionary]) {
            try { return ($v | ConvertTo-Json -Compress -Depth 12) } catch { return ("" + $v) }
        }

        return ("" + $v)
    }

    $assetsTextNorm = (_ToText $AssetsText).Trim()

    # 1) Summary mode: parse ImpactedAssets text (json array or comma list)
    if (-not [string]::IsNullOrWhiteSpace($assetsTextNorm)) {
        $list = Split-ImpactedAssets -AssetsText $assetsTextNorm
        if ($list -and @($list).Count -gt 0) { return @($list) }
    }

    # 2) Detailed mode: one asset per row in a dedicated column
    $fallback = Get-RowValue -Row $Row -Names @(
        "AssetName","DeviceName","Device","MachineName","Computer",
        "HostName","DnsName","FQDN","Endpoint","Asset"
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$fallback)) {
        $val = ([string]$fallback).Trim()
        if ($val -match '[,;]') {
            $parts = @($val -split '\s*[,;]\s*' | Where-Object { $_ -and $_.Trim() })
            return @($parts | ForEach-Object { $_.Trim() } | Select-Object -Unique)
        }
        return @($val)
    }

    return @()
}

# ===== reset helper (delete workbook at start when OverwriteXlsx is true) =====
function ConvertTo-XlsxSafeString {
    [CmdletBinding()]
    param([Parameter()][AllowEmptyString()][AllowNull()][string]$Value)

    # XLSX shared-strings safety. Excel's strict XML validator (per XML 1.0 spec) rejects
    # control characters 0x00-0x1F (except TAB/LF/CR), DEL 0x7F, and lone UTF-16 surrogate
    # halves. When such a char slips into a cell value -- typically via a KQL extract()
    # result, a CSA / TierSources JSON blob, or pasted-in text -- Excel still recovers
    # the workbook on open but pops the "Repaired Records: String properties from
    # /xl/sharedStrings.xml" warning. Stripping at the source kills the warning for
    # every customer. v2.1.206.
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    # Control chars 0x00-0x1F (except TAB/LF/CR) + DEL 0x7F.
    $Value = [regex]::Replace($Value, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
    # Lone UTF-16 surrogate halves (high without trailing low, or low without leading high).
    $Value = [regex]::Replace($Value, '[\uD800-\uDBFF](?![\uDC00-\uDFFF])', '')
    $Value = [regex]::Replace($Value, '(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]', '')
    # also strip Unicode non-characters (U+FFFE / U+FFFF) and the
    # rarely-seen line / paragraph separators (U+2028 / U+2029) -- EPPlus
    # sharedStrings.xml writer accepts them but Excel's stricter validator on
    # open triggers the "Repaired Records" warning.
    $Value = [regex]::Replace($Value, "[\uFFFE\uFFFF\u2028\u2029]", '')
    # Excel cell hard limit: 32,767 chars. Strings beyond that trigger the
    # "We found a problem with some content" repair dialog on open. Compose the
    # truncation marker first, then back off the substring length so the COMBINED
    # result is guaranteed <= 32767. v2.2 -- common source: MoreDetails
    # for reports with hundreds of CVEs.
    if ($Value.Length -gt 32767) {
        $clip   = $Value.Length - 32767  # provisional; recomputed after sizing
        $marker = '... [truncated {0} chars]' -f $clip
        # Re-derive marker after we know the actual cut so the suffix length is honest
        $cut    = 32767 - $marker.Length
        if ($cut -lt 0) { $cut = 0 }
        $clip   = $Value.Length - $cut
        $marker = '... [truncated {0} chars]' -f $clip
        # If new marker grew (e.g. clip count is now 5 digits), shrink cut once more
        $cut    = 32767 - $marker.Length
        if ($cut -lt 0) { $cut = 0 }
        $Value  = $Value.Substring(0, $cut) + $marker
    }
    return $Value
}

function Reset-ExcelOutput {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter()][switch]$ForceRemove = $true
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  if (Test-Path $Path) {
    if ($ForceRemove) {
      try { [System.IO.File]::SetAttributes($Path, 'Normal') } catch {}
      $deleted = $false
      for ($i = 1; $i -le 5 -and -not $deleted; $i++) {
        try {
          Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
          $deleted = $true
        } catch {
          Write-Warn2 ("excel file locked (attempt {0}/5); retrying..." -f $i)
          Start-Sleep -Milliseconds 500
        }
      }
      if (-not $deleted) { throw "Could not delete existing Excel file: $Path (locked)" }
    } else {
      Write-Warn2 "Overwrite disabled; keeping existing Excel file and appending sheets."
    }
  }
  $script:_sheetWritten = @{}
}

function Connect-GraphHighPriv {
    [CmdletBinding()]
    param()

    # v2.2.234 -- branch on cert vs secret. Connect-MicrosoftGraphPS only takes
    # AppSecret; for SPN+cert we fall through to Connect-MgGraph directly
    # (Microsoft.Graph.Authentication module ships with the rest of the SDK,
    # so no extra dependency).
    $hasCert = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ($hasCert) {
        Write-Info "Connecting to Microsoft Graph (app+certificate)..."
        Connect-MgGraph -TenantId $global:SpnTenantId `
                        -ClientId $global:SpnClientId `
                        -CertificateThumbprint $global:SpnCertificateThumbprint `
                        -NoWelcome -ErrorAction Stop
    } else {
        Write-Info "Connecting to Microsoft Graph (app+secret)..."
        Connect-MicrosoftGraphPS -AppId $global:SpnClientId `
                                 -AppSecret $global:SpnClientSecret `
                                 -TenantId $global:SpnTenantId
    }

    # increase Graph SDK HTTP timeout + tune retries
    Set-MgRequestContext -ClientTimeout 900 -MaxRetry 6 -RetryDelay 5 -RetriesTimeLimit 600

    $script:GraphLastConnectUtc = [datetime]::UtcNow
    Write-Ok ("Graph connected at {0:u}" -f $script:GraphLastConnectUtc)
    Write-Info "Graph request context: ClientTimeout=900s, MaxRetry=6, RetryDelay=5s, RetriesTimeLimit=600s"
}

function Ensure-GraphAuth {
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 45
    )

    $need = $false

    if ($script:GraphLastConnectUtc -eq [datetime]::MinValue) { $need = $true }
    else {
        $ageMin = ([datetime]::UtcNow - $script:GraphLastConnectUtc).TotalMinutes
        if ($ageMin -ge $MaxAgeMinutes) { $need = $true }
    }

    if ($need) {
        Connect-GraphHighPriv
    }
}

# ===============================================================================================
# CL-TABLE ROUTING
#
# Advanced hunting (Microsoft Graph /security/runHuntingQuery) only sees XDR tables --
# custom SI_*_CL tables in Log Analytics are invisible unless Sentinel data lake mirroring is on.
# Engine recognizes any SI_*_CL reference (Profile + VulnerabilityPIP + future) and routes
# pure-LA queries directly to Log Analytics; mixed CL+XDR queries get a cross-workspace let.
# No data lake mirror required.
# ===============================================================================================

function Resolve-WorkspaceCustomerId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)

    if (-not $script:_WorkspaceCustomerIdCache) { $script:_WorkspaceCustomerIdCache = @{} }
    if ($script:_WorkspaceCustomerIdCache.ContainsKey($WorkspaceResourceId)) {
        return $script:_WorkspaceCustomerIdCache[$WorkspaceResourceId]
    }

    if ($WorkspaceResourceId -notmatch '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
        throw "Invalid WorkspaceResourceId: $WorkspaceResourceId"
    }
    $subId  = $matches[1]
    $rgName = $matches[2]
    $wsName = $matches[3]

    $curSubId = $null
    try { $curSubId = (Get-AzContext).Subscription.Id } catch {}
    if ($curSubId -and $curSubId -ne $subId) {
        $null = Set-AzContext -Subscription $subId -ErrorAction Stop
    }

    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction Stop
    $custId = $ws.CustomerId.Guid

    if ($curSubId -and $curSubId -ne $subId) {
        try { $null = Set-AzContext -Subscription $curSubId -ErrorAction SilentlyContinue } catch {}
    }

    $script:_WorkspaceCustomerIdCache[$WorkspaceResourceId] = $custId
    return $custId
}

function Convert-RowsToKqlDatatable {
    <# Serializes an array of PSCustomObject rows into a KQL `datatable(<schema>) [ <values> ]` literal.
       Column types inferred from the first row's .NET types. Used by the hybrid CL-snapshot path. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LetVarName,
        [object[]]$Rows
    )
    if (-not $Rows -or $Rows.Count -eq 0) {
        return ('let {0} = datatable(__placeholder:string)[];' -f $LetVarName)
    }
    $first = $Rows[0]
    $colSpecs  = New-Object System.Collections.Generic.List[string]
    $colNames  = New-Object System.Collections.Generic.List[string]
    $colTypes  = New-Object System.Collections.Generic.List[string]
    foreach ($p in $first.PSObject.Properties) {
        # Az.OperationalInsightsQuery returns ALL values as strings regardless of
        # the underlying KQL column type. Inferring from .TypeNameOfValue is
        # therefore useless -- we need to scan VALUES across ALL rows and detect
        # the narrowest KQL type whose pattern matches every non-null value.
        $values = New-Object System.Collections.Generic.List[string]
        foreach ($r in $Rows) {
            $v = $r.PSObject.Properties[$p.Name].Value
            if ($null -ne $v -and -not ([string]::IsNullOrEmpty([string]$v))) {
                [void]$values.Add([string]$v)
            }
        }
        $kqlType = 'string'
        if ($values.Count -gt 0) {
            # Detect bool/long/real/datetime only. GUID promotion is INTENTIONALLY
            # disabled -- the source query body typically casts ID columns via
            # `tostring(...)` to ensure string-typed joins downstream; auto-promoting
            # GUID-shaped strings to `guid` breaks join-key compatibility with the
            # AH side which projects the same columns as `string`.
            $allBool = $true; $allLong = $true; $allReal = $true; $allDate = $true
            foreach ($s in $values) {
                if ($allBool -and $s -notmatch '^(?i:true|false)$') { $allBool = $false }
                if ($allLong -and $s -notmatch '^-?\d+$')           { $allLong = $false }
                if ($allReal -and $s -notmatch '^-?\d+(\.\d+)?([eE][-+]?\d+)?$') { $allReal = $false }
                if ($allDate -and $s -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $allDate = $false }
                if (-not ($allBool -or $allLong -or $allReal -or $allDate)) { break }
            }
            # Order matters: bool > long > real (long is subset of real).
            if     ($allBool) { $kqlType = 'bool' }
            elseif ($allLong) { $kqlType = 'long' }
            elseif ($allReal) { $kqlType = 'real' }
            elseif ($allDate) { $kqlType = 'datetime' }
        }
        [void]$colSpecs.Add(('{0}:{1}' -f $p.Name, $kqlType))
        [void]$colNames.Add($p.Name)
        [void]$colTypes.Add($kqlType)
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendFormat('let {0} = datatable({1}) [' + [Environment]::NewLine, $LetVarName, ($colSpecs -join ','))
    foreach ($r in $Rows) {
        $vals = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $colNames.Count; $i++) {
            $v = $r.PSObject.Properties[$colNames[$i]].Value
            $t = $colTypes[$i]
            if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrEmpty($v))) {
                # Untyped null literal isn't allowed inside datatable rows; cast per type.
                $lit = switch ($t) {
                    'string'   { '""' }
                    'bool'     { 'bool(null)' }
                    'long'     { 'long(null)' }
                    'real'     { 'real(null)' }
                    'datetime' { 'datetime(null)' }
                    'guid'     { 'guid(null)' }
                    default    { '""' }
                }
            } else {
                switch ($t) {
                    'string'   { $lit = '"' + (([string]$v) -replace '\\','\\' -replace '"','\"' -replace "`r",'\r' -replace "`n",'\n' -replace "`t",'\t') + '"' }
                    'bool'     {
                        # [bool]"false" returns $true in PowerShell (non-empty string).
                        # Compare the string value explicitly.
                        $sv = ([string]$v).ToLowerInvariant()
                        $lit = if ($sv -eq 'true' -or $sv -eq '1') { 'true' } else { 'false' }
                    }
                    'long'     { $lit = ([int64](([string]$v))).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
                    'real'     { $lit = ([double]::Parse(([string]$v), [System.Globalization.CultureInfo]::InvariantCulture)).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
                    'datetime' { $lit = 'datetime(' + ([datetime]$v).ToString('o') + ')' }
                    'guid'     { $lit = 'guid(' + ([guid]([string]$v)).ToString() + ')' }
                    default    { $lit = '"' + ([string]$v) + '"' }
                }
            }
            [void]$vals.Add($lit)
        }
        [void]$sb.AppendLine('  ' + ($vals -join ',') + ',')
    }
    # Trim trailing comma+newline.
    $out = $sb.ToString().TrimEnd(",`r`n".ToCharArray()) + [Environment]::NewLine + '];'
    return $out
}

function Add-CLSnapshotShadows {
    <# UNIVERSAL CL-snapshot shadowing (Pattern 2 / table-shadow).
       Generalizes Resolve-ProfileCLLetBlocks beyond the `let _x = SI_*_CL | ...`
       pattern to ANY reference of an SI_*_Profile_CL table -- joins, unions,
       direct table position, or wrapped in let blocks. KQL's `let TableName = ...`
       shadows the real table at parse time, so every downstream reference
       resolves to the inlined datatable. Snapshots are pre-fetched once per
       run per unique CL table and cached in $script:_CLSnapshotsKql. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    if (-not $script:_CLSnapshotsKql) { $script:_CLSnapshotsKql = @{} }

    # Strip strings/comments first so `where Category == "SI_Endpoint_Profile_CL"` doesn't false-match.
    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # Match ANY SI_*_CL custom Log Analytics table (Profile + VulnerabilityPIP + future).
    $clPattern = '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b'
    $tables = @([regex]::Matches($stripped, $clPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($tables.Count -eq 0) { return $Query }

    # Smart column projection: walk every `let <var> = <table> | ... | project ...`
    # block in the query and collect the source columns each block actually needs.
    # Pre-fetching only those columns shrinks the inlined datatable 5-20x and keeps
    # the AH body well under the 1MB nginx cap that bricked Azure_Recommendations +
    # all Attack_Paths reports on 2026-05-02. Falls back to `*` if no projection found.
    $kqlReserved = @('tostring','toint','tobool','todouble','todatetime','todynamic',
                     'column_ifexists','iif','iff','case','coalesce','isnotempty','isnull','isempty',
                     'int','long','real','bool','datetime','dynamic','null','true','false',
                     'parse_json','tolower','toupper','trim','strcat','strcat_array','split','extract',
                     'now','ago','make_set','make_list','make_bag','bag_pack','bag_merge','array_concat',
                     'datetime_diff','datetime_add','startofday','arg_max','arg_min','count','dcount','sum','min','max','any','avg')
    $colsByTable = @{}
    foreach ($tbl in $tables) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        # Always need these for the universal `where TimeGenerated > ago(...) | summarize arg_max(CollectionTime, *) by PrimaryEntityId` shape:
        [void]$set.Add('TimeGenerated'); [void]$set.Add('CollectionTime'); [void]$set.Add('PrimaryEntityId')
        $colsByTable[$tbl] = $set
    }
    # Match `let X = TBL | ... | project <body>` -- terminate <body> at next `;` or `| where isnotempty(`
    # which is the conventional tail after the project in our refactored YAML.
    $letProjectRx = '(?ms)\blet\s+\w+\s*=\s*(?<tbl>SI_[A-Za-z]+_Profile_CL)\b[^;]*?\|\s*project\s+(?<body>[^;]+?)(?=\s*\|\s*where\s+isnotempty|\s*;)'
    foreach ($pm in [regex]::Matches($stripped, $letProjectRx)) {
        $tbl = $pm.Groups['tbl'].Value
        if (-not $colsByTable.ContainsKey($tbl)) { continue }
        $body = $pm.Groups['body'].Value
        # 1. Extract column_ifexists("X", ...) first-arg string literals -- explicit source-col references.
        foreach ($cm in [regex]::Matches($body, 'column_ifexists\(\s*"([^"\r\n]+)"')) {
            [void]$colsByTable[$tbl].Add($cm.Groups[1].Value)
        }
        # 2. Extract bare identifier references in the project body (catches `tostring(PrimaryEntityId)`-style),
        # filter out KQL function names + literals.
        foreach ($idm in [regex]::Matches($body, '\b([A-Za-z_][A-Za-z0-9_]*)\b')) {
            $name = $idm.Groups[1].Value
            if ($name -in $kqlReserved) { continue }
            # Skip alias-LHS positions: `<Alias> = <expr>` -- the LHS is an output name not a source col.
            # Heuristic: if the next non-space char after this identifier is `=` (and not `==`), it's an alias.
            $idx = $idm.Index + $idm.Length
            while ($idx -lt $body.Length -and ($body[$idx] -eq ' ' -or $body[$idx] -eq "`t")) { $idx++ }
            if ($idx -lt $body.Length -and $body[$idx] -eq '=' -and ($idx + 1 -ge $body.Length -or $body[$idx+1] -ne '=')) { continue }
            [void]$colsByTable[$tbl].Add($name)
        }
    }

    $shadows = New-Object System.Collections.Generic.List[string]
    foreach ($tbl in $tables) {
        if (-not $script:_CLSnapshotsKql.ContainsKey($tbl)) {
            Write-Diag ("[shadow] pre-fetching {0} snapshot from LA workspace ..." -f $tbl)
            # Pre-summarize to latest-per-PrimaryEntityId so the shadow has one row per
            # asset. The original query's `| where TimeGenerated > ago(Nd) | summarize
            # arg_max(CollectionTime, *) by PrimaryEntityId` becomes a no-op against
            # the already-collapsed shadow. Smart projection narrows columns to only
            # those the query references.
            $cols = @($colsByTable[$tbl])
            if ($cols.Count -le 3) {
                # only the always-include trio -- no project found, fall back to all columns
                $projectClause = ''
                $colsLogTag = '*'
            } else {
                $projectClause = "`n| project " + (($cols | Sort-Object -Unique) -join ', ')
                $colsLogTag = ("{0} cols" -f ($cols | Sort-Object -Unique).Count)
            }
            $snapshotKql = ("{0}`n| where TimeGenerated > ago(8d){1}`n| summarize arg_max(CollectionTime, *) by PrimaryEntityId" -f $tbl, $projectClause)
            try {
                $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $snapshotKql
            } catch {
                Write-Err2 ("[shadow] {0} snapshot fetch failed: {1}" -f $tbl, $_.Exception.Message)
                throw
            }
            $rowArr = if ($rows) { @($rows) } else { @() }
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $tbl -Rows $rowArr
            $script:_CLSnapshotsKql[$tbl] = $datatableLet
            Write-Info ("caching {0} ({1} rows, {2}) to staging" -f $tbl, $rowArr.Count, $colsLogTag)
        }
        [void]$shadows.Add($script:_CLSnapshotsKql[$tbl])
    }
    return (($shadows -join [Environment]::NewLine) + [Environment]::NewLine + $Query)
}

function Resolve-ProfileCLLetBlocks {
    <# HYBRID CL-snapshot inlining. When a query references both
       SI_*_Profile_CL AND ExposureGraph*, the data-lake API is the only surface
       that sees both, but it doesn't accept SPN auth (Microsoft documented gap).
       Workaround: replace each `let <var> = SI_*_Profile_CL | ... ;` block with
       an inline `let <var> = datatable(...) [...];` literal pre-fetched from LA
       (where SPN works), then send the modified query through AH-via-Graph
       (where EG resolves natively). Same KQL semantics, different transport.

       2026-05-02: scoped pre-fetch attempt reverted -- regex-based KQL splitting
       produced bad discovery queries on real reports (zero IDs / syntax errors).
       Restoring the simple full-snapshot fetch; the proper fix is the 2-phase
       post-process model (run pure-EG query, augment with cmdb in PowerShell). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )
    # Strip strings/comments first to avoid false-positive `;` inside literals.
    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # let-binding pattern: `let <var> = ... SI_*_Profile_CL ... ;` -- multiline,
    # non-greedy, terminates at first `;` (already safe vs. string literals).
    $letRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+_Profile_CL\b[^;]*?);'
    $matches2 = [regex]::Matches($stripped, $letRx)
    if ($matches2.Count -eq 0) { return $Query }

    $modified = $Query
    foreach ($m in $matches2) {
        $varName = $m.Groups['var'].Value
        # Re-extract body from the ORIGINAL query (string-stripped version has placeholders)
        $origMatch = [regex]::Match($modified, $letRx)
        if (-not $origMatch.Success) { continue }
        $bodyKql = $origMatch.Groups['body'].Value
        $fullBlock = $origMatch.Value

        # Snapshot cache keyed on let-var name + hash of body KQL. v2.2.183 had
        # NO cache here -- a single report with 960 AutoBucket buckets fetched
        # the same 176KB _ep snapshot 960 times in a row (~3 hours of wasted LA
        # round-trips per report). The body never changes across buckets within
        # one report, AND most reports use the same _ep / _TargetCmdb let-binding
        # bodies, so a run-wide cache eliminates the duplication entirely.
        if (-not $script:_HybridSnapshotCache) { $script:_HybridSnapshotCache = @{} }
        $bodyHash = [BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash(
                        [System.Text.Encoding]::UTF8.GetBytes($bodyKql))).Replace('-','')
        $cacheKey = $varName + '|' + $bodyHash
        if ($script:_HybridSnapshotCache.ContainsKey($cacheKey)) {
            $datatableLet = $script:_HybridSnapshotCache[$cacheKey]
            Write-Info ("[hybrid] '{0}' snapshot reused from cache ({1} bytes)" -f $varName, $datatableLet.Length)
        } else {
            Write-Info ("[hybrid] pre-fetching CL snapshot for let-binding '{0}' from LA workspace ..." -f $varName)
            try {
                $clRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $bodyKql
            } catch {
                Write-Err2 ("[hybrid] CL snapshot fetch failed for '{0}': {1}" -f $varName, $_.Exception.Message)
                throw
            }
            $rowCount = if ($clRows) { @($clRows).Count } else { 0 }
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $varName -Rows @($clRows)
            Write-Info ("[hybrid] '{0}' snapshot: {1} row(s) inlined as datatable ({2} bytes)" -f $varName, $rowCount, $datatableLet.Length)
            $script:_HybridSnapshotCache[$cacheKey] = $datatableLet
            # v2.2.273 -- track the largest CL snapshot row count seen for this query
            # so AutoBucket can pre-bias initial bucket count for heavy reports
            # (avoids the 2 -> 4 -> 16 -> 64 escalation grind on first run when we
            # already know the snapshot is huge).
            if ($null -eq $script:_LastHybridSnapshotRowCount -or $rowCount -gt [int]$script:_LastHybridSnapshotRowCount) {
                $script:_LastHybridSnapshotRowCount = [int]$rowCount
            }
        }
        $modified = $modified.Replace($fullBlock, $datatableLet)
    }
    return $modified
}

function Resolve-ProfileAugmentPlan {
    <# 2026-05-02 -- 2-phase post-augmentation. Detects the canonical CL-enrichment
       pattern in a query:

           let <var> = SI_*_Profile_CL | ... | project <Projection> | where isnotempty(<RightKey>);
           // ... pure EG / per-row pipeline ...
           | join kind=<Kind> (<var>) on $left.<LeftKey> == $right.<RightKey>
           | extend <newCol> = <var-projected-col>, <newCol2> = <var-projected-col2>, ...

       When the post-extend alias columns are NOT referenced by a downstream
       `summarize ... by ...` clause (typical for Detailed reports — and Attack_Paths
       Detailed in particular), the join can be removed from the query entirely:
       the rows still have the alias columns, but populated post-hoc by Invoke-
       CmdbAugment from a single LA fetch + in-memory hashtable.

       Returns @{
           Query = <modified query, let+join+extend stripped>
           Plans = [@{ Var; TableName; ProjectionKql; LeftKey; RightKey;
                       ColumnAliases = @{ newCol = sourceCol; ... } }, ...]
       }

       If no augmentable plan was detected, returns @{ Query = $Query; Plans = @() }
       and the caller should keep the existing inline-datatable path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)

    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # 1. Find every `let <var> = SI_*_Profile_CL | ... | project <body> | where isnotempty(<RightKey>);` let block.
    $letRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<bodyAll>[^;]*?\bSI_(?<table>[A-Za-z]+_Profile)_CL\b[^;]*?\|\s*project\s+(?<proj>[^;]*?)\|\s*where\s+isnotempty\(\s*(?<rkey>\w+)\s*\)\s*);'

    $plans = New-Object System.Collections.Generic.List[hashtable]
    $modified = $Query
    $cumulativeMatches = [regex]::Matches($modified, $letRx)
    if ($cumulativeMatches.Count -eq 0) { return @{ Query = $Query; Plans = @() } }

    foreach ($m in $cumulativeMatches) {
        $varName  = $m.Groups['var'].Value
        $tableTag = $m.Groups['table'].Value      # e.g. "Azure_Profile" -> SI_Azure_Profile_CL
        $tableNm  = "SI_" + $tableTag + "_CL"
        $rkey     = $m.Groups['rkey'].Value
        # Re-extract projection body from the original query (avoids placeholder issues from the strip pass).
        $origMatch = [regex]::Match($modified, $letRx)
        if (-not $origMatch.Success) { continue }
        $projBody = $origMatch.Groups['proj'].Value
        $fullLetBlock = $origMatch.Value

        # 2. Find the corresponding `| join kind=<kind> (<var>) on $left.<lk> == $right.<rk>` line (operands either order).
        $joinRx = ('(?ms)\|\s*join\s+(?:kind\s*=\s*\w+\s+)?\(\s*' + [regex]::Escape($varName) + '\s*\)\s+on\s+(?:\$left\.(?<lk>\w+)\s*==\s*\$right\.' + [regex]::Escape($rkey) + '|\$right\.' + [regex]::Escape($rkey) + '\s*==\s*\$left\.(?<lk2>\w+))')
        $jm = [regex]::Match($modified, $joinRx)
        if (-not $jm.Success) { continue }
        $leftKey = if ($jm.Groups['lk'].Success -and $jm.Groups['lk'].Value) { $jm.Groups['lk'].Value } else { $jm.Groups['lk2'].Value }
        $fullJoinLine = $jm.Value

        # 3. Find the post-join `| extend <newCol> = <oldCol>, ...` block IMMEDIATELY after the join.
        # \A anchor + optional comment lines means the extend MUST be the first KQL operator after
        # the join (intervening `| where ...` or any non-comment pipe op disqualifies the match).
        # Without this anchor we'd false-match downstream extends -- like the engine-substituted
        # weighted-factors block `| extend RiskFactor_Weight = RiskScore_Weight_Factor` which has
        # the same `id = id` shape but is NOT a let-block alias rename.
        # Additionally, every alias's RHS must reference a column actually projected by the let-block;
        # otherwise the match isn't a join-projection rename. Both gates are needed because the engine
        # substitutes the weighted-factors block AFTER YAML load but BEFORE this regex runs.
        $afterJoinIdx = $modified.IndexOf($fullJoinLine) + $fullJoinLine.Length
        $tail = $modified.Substring($afterJoinIdx)
        $extendRx = '(?ms)\A(?:\s*//[^\r\n]*[\r\n]+)*\s*\|\s*extend(?<body>(?:\s+[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*,?)+)\s*(?=\||\s*$)'
        $em = [regex]::Match($tail, $extendRx)
        $columnAliases = @{}
        $fullExtendBlock = ''
        if ($em.Success) {
            # Build the set of column names the let-block actually projects (LHS of each `<name> = <expr>` in $projBody).
            $projectedCols = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($pm in [regex]::Matches($projBody, '(?ms)([A-Za-z_]\w*)\s*=')) {
                [void]$projectedCols.Add($pm.Groups[1].Value)
            }
            $body = $em.Groups['body'].Value
            $candidates = @{}
            $allRhsValid = $true
            foreach ($am in [regex]::Matches($body, '([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)')) {
                $rhs = $am.Groups[2].Value
                if (-not $projectedCols.Contains($rhs)) { $allRhsValid = $false; break }
                $candidates[$am.Groups[1].Value] = $rhs
            }
            if ($allRhsValid -and $candidates.Count -gt 0) {
                $fullExtendBlock = $em.Value
                $columnAliases = $candidates
            }
        }
        if ($columnAliases.Count -eq 0) { continue }

        # 4. SAFETY GATE: if any of the new cmdb columns are used in a downstream `summarize ... by ...`
        # clause, we CAN'T strip them -- the bucketing depends on having them in the data BEFORE summarize.
        # In that case skip this plan -- the inline-datatable path will handle it.
        $aliasNames = @($columnAliases.Keys)
        $summRx = '(?ms)\|\s*summarize\b[^|]*\bby\b[^|]*'
        $cmdbInSummarize = $false
        foreach ($sm in [regex]::Matches($stripped, $summRx)) {
            $byClause = $sm.Value
            foreach ($ali in $aliasNames) {
                if ($byClause -match ('\b' + [regex]::Escape($ali) + '\b')) { $cmdbInSummarize = $true; break }
            }
            if ($cmdbInSummarize) { break }
        }
        if ($cmdbInSummarize) {
            Write-Info ("[2phase] '{0}' SKIPPED -- alias cols ({1}) used in a downstream summarize-by; falling back to inline-datatable hybrid path" -f $varName, ($aliasNames -join ','))
            continue
        }

        # 5. Strip let-block + join-line + post-extend block from the query.
        # Replace the join with a PLACEHOLDER `| extend alias="", ...` line so
        # downstream `| project ... cmdbId, cmdbName, ...` references resolve
        # in the AH query. The post-AH augment then OVERWRITES these placeholder
        # values with the real CMDB lookups.
        $placeholderExtend = '| extend ' + (($aliasNames | ForEach-Object { '{0}=""' -f $_ }) -join ', ')
        $modified = $modified.Replace($fullLetBlock, '')
        $modified = $modified.Replace($fullJoinLine, $placeholderExtend)
        if ($fullExtendBlock) { $modified = $modified.Replace($fullExtendBlock, '') }

        # 6. Build the projection KQL the augment function will run against LA to fetch the CL snapshot.
        # Use the same project body the YAML author wrote, plus the raw RightKey if not in the alias set.
        $projectionKql = ("{0}`n| where TimeGenerated > ago(8d)`n| summarize arg_max(CollectionTime, *) by PrimaryEntityId`n| project {1}`n| where isnotempty({2})" -f $tableNm, $projBody.Trim(), $rkey)

        $plans.Add(@{
            Var            = $varName
            TableName      = $tableNm
            ProjectionKql  = $projectionKql
            LeftKey        = $leftKey
            RightKey       = $rkey
            ColumnAliases  = $columnAliases
        }) | Out-Null

        Write-Info ("[2phase] '{0}' plan: leftKey={1}, rightKey={2}, alias-cols=[{3}]" -f $varName, $leftKey, $rkey, ($aliasNames -join ','))
    }

    return @{ Query = $modified; Plans = @($plans.ToArray()) }
}

function Invoke-ProfileAugment {
    <# 2026-05-02 -- post-query in-memory augmentation. Given the rows the EG query
       returned + the plans Resolve-ProfileAugmentPlan extracted, fetch each plan's CL
       snapshot from LA once (cached), build a hashtable on the right-side join key,
       and stamp the aliased columns onto every row.

       Performance notes (32-64 GB VM, 100K rows):
         - Hashtable lookup is O(1)
         - Direct Add-Member is slow (~30-60s for 100K) -- AVOIDED
         - We mutate the existing PSCustomObject's NoteProperty values in place
           (or add via .Properties.Add) which is ~5x faster than Add-Member -Force #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Rows,
        [Parameter()][AllowNull()]$Plans,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return ,@($Rows) }
    if (-not $Plans -or @($Plans).Count -eq 0) { return ,@($Rows) }
    if (-not $script:_ProfileAugmentLookups) { $script:_ProfileAugmentLookups = @{} }

    foreach ($plan in $Plans) {
        $cacheKey = "{0}|{1}" -f $plan.TableName, $plan.RightKey
        if (-not $script:_ProfileAugmentLookups.ContainsKey($cacheKey)) {
            try {
                $clRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $plan.ProjectionKql
            } catch {
                Write-Warn2 ("[2phase] '{0}' CL fetch failed; augment cols will be empty: {1}" -f $plan.Var, $_.Exception.Message)
                $clRows = @()
            }
            $lookup = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($r in @($clRows)) {
                if ($null -eq $r) { continue }
                if ($r.PSObject.Properties[$plan.RightKey]) {
                    $k = [string]$r.PSObject.Properties[$plan.RightKey].Value
                    if (-not [string]::IsNullOrWhiteSpace($k) -and -not $lookup.ContainsKey($k)) {
                        $lookup[$k] = $r
                    }
                }
            }
            $script:_ProfileAugmentLookups[$cacheKey] = $lookup
            Write-Info ("[2phase] '{0}' lookup built: {1} CL rows -> hashtable on {2}" -f $plan.Var, @($clRows).Count, $plan.RightKey)
        }
        $lookup = $script:_ProfileAugmentLookups[$cacheKey]

        $hits = 0; $misses = 0
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            $lk = ''
            if ($row.PSObject.Properties[$plan.LeftKey]) { $lk = [string]$row.PSObject.Properties[$plan.LeftKey].Value }
            $clRow = $null
            if (-not [string]::IsNullOrWhiteSpace($lk) -and $lookup.TryGetValue($lk, [ref]$clRow)) {
                $hits++
            } else {
                $misses++
            }
            foreach ($alias in $plan.ColumnAliases.Keys) {
                $sourceCol = $plan.ColumnAliases[$alias]
                $val = ''
                if ($null -ne $clRow -and $clRow.PSObject.Properties[$sourceCol]) {
                    $val = $clRow.PSObject.Properties[$sourceCol].Value
                }
                if ($row.PSObject.Properties[$alias]) {
                    $row.PSObject.Properties[$alias].Value = $val
                } else {
                    $row | Add-Member -NotePropertyName $alias -NotePropertyValue $val -Force
                }
            }
        }
        Write-Info ("[2phase] '{0}' augmented {1} rows ({2} hits, {3} misses)" -f $plan.Var, $Rows.Count, $hits, $misses)
    }

    return ,@($Rows)
}

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

function Invoke-LogAnalyticsKqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 600
    )

    # Reuse the existing Connect-AzAccount session via Az.OperationalInsights -- no manual
    # token retrieval, no REST plumbing. Az.OperationalInsights ships with the Az meta-module,
    # which is in $script:SecurityInsight_RequiredModules (already ensured at engine startup).
    $custId = Resolve-WorkspaceCustomerId -WorkspaceResourceId $WorkspaceResourceId
    try {
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $custId -Query $Query -Wait $TimeoutSec -ErrorAction Stop
    } catch {
        # Diagnostic dump: when LA returns 400/BadRequest, Az.OperationalInsights surfaces only
        # the bare HTTP status -- the actual KQL parse error is in the inner exception's response
        # body. Persist query + full exception chain + body to staging so we can see exactly which
        # column / syntax LA rejected per failing report.
        # NOTE: missing-table errors ('Failed to resolve table or column expression named SI_*_CL')
        # are real REPORT-DESIGN bugs, not transient state. They mean a report's KQL declared a
        # source dependency the customer's environment hasn't satisfied (asset-profiling not yet
        # run, or that report shouldn't have been included in the template). v2.2.80's graceful-skip
        # was reverted in v2.2.82 -- per operator policy, surface the failure loudly so report
        # authors can either (a) fix the dependency declaration or (b) gate the report behind a
        # SourceTables manifest entry the engine can pre-flight before submitting the query.
        try {
            $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
            $stagingDir = if ($global:SI_StagingPath) { Join-Path $global:SI_StagingPath 'risk-analysis' }
                          elseif ($global:OutputPath) { Join-Path $global:OutputPath 'staging\risk-analysis' }
                          else { Join-Path $env:TEMP 'si-ra' }
            New-Item -Path $stagingDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            $errFile = Join-Path $stagingDir ("ra-laerr-{0}.txt" -f $stamp)
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("=== Workspace ===")
            [void]$sb.AppendLine($WorkspaceResourceId)
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== Outer exception ===")
            [void]$sb.AppendLine([string]$_.Exception.Message)
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== Exception type chain ===")
            $e = $_.Exception
            while ($null -ne $e) {
                [void]$sb.AppendLine([string]$e.GetType().FullName + " :: " + [string]$e.Message)
                $e = $e.InnerException
            }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== HTTP response body (LA's actual error) ===")
            # Az.OperationalInsights ErrorResponseException exposes the body via several paths
            # depending on SDK version. Try them all and dump whatever we find.
            $bodyCandidates = @()
            try {
                $ex = $_.Exception
                # Path 1: Azure SDK -- .Body is a deserialised ErrorResponse object with .Error.{Code,Message,Details}
                if ($ex.Body) {
                    $bodyCandidates += "[.Body]"
                    $bodyCandidates += try { $ex.Body | ConvertTo-Json -Depth 8 } catch { [string]$ex.Body }
                }
                # Path 2: .Response.Content -- HttpResponseMessage style
                if ($ex.Response -and $ex.Response.Content) {
                    $bodyCandidates += "[.Response.Content]"
                    $bodyCandidates += try { $ex.Response.Content | ConvertTo-Json -Depth 8 } catch { [string]$ex.Response.Content }
                }
                # Path 3: WebException-style stream
                $webResp = $null
                if ($ex.Response -and $ex.Response.GetType().Name -eq 'HttpWebResponse') { $webResp = $ex.Response }
                elseif ($ex.InnerException -and $ex.InnerException.Response -and $ex.InnerException.Response.GetType().Name -eq 'HttpWebResponse') { $webResp = $ex.InnerException.Response }
                if ($webResp) {
                    try {
                        $stream = $webResp.GetResponseStream()
                        if ($stream.CanSeek) { $stream.Position = 0 }
                        $reader = New-Object System.IO.StreamReader($stream)
                        $bodyCandidates += "[.Response stream]"
                        $bodyCandidates += $reader.ReadToEnd()
                    } catch { $bodyCandidates += "(stream read failed: " + $_.Exception.Message + ")" }
                }
                # Path 4: ErrorRecord's TargetObject
                if ($_.TargetObject) {
                    $bodyCandidates += "[.TargetObject]"
                    $bodyCandidates += try { $_.TargetObject | ConvertTo-Json -Depth 6 } catch { [string]$_.TargetObject }
                }
                # Path 5: ErrorDetails on the ErrorRecord
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    $bodyCandidates += "[.ErrorDetails.Message]"
                    $bodyCandidates += [string]$_.ErrorDetails.Message
                }
                # Path 6: dump every public property name of the exception so we know what's available
                $bodyCandidates += "[exception public properties]"
                $bodyCandidates += try { ($ex | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -join ', ' } catch { '(none)' }
            } catch { $bodyCandidates += "(body capture threw: " + $_.Exception.Message + ")" }
            if ($bodyCandidates.Count -eq 0) { $bodyCandidates += "(no response body found through any known path)" }
            foreach ($c in $bodyCandidates) { [void]$sb.AppendLine($c); [void]$sb.AppendLine('') }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== Query ===")
            [void]$sb.AppendLine($Query)
            Set-Content -LiteralPath $errFile -Value $sb.ToString() -Encoding UTF8
            Write-Warn2 ("LA query failed -- full detail dumped to {0}" -f $errFile)
        } catch { }
        throw
    }

    # Comma-protect so PowerShell emits the rows array as a SINGLE value to the
    # pipeline (preserving array shape across function-output unwrap). Caller
    # MUST use plain assignment, NOT @() wrap -- @(call) re-wraps the single
    # comma-protected value into [Object[1] of Object[N]], which broke the
    # downstream foreach in v2.1.199 / v2.1.202 / v2.1.203.
    if (-not $resp -or -not $resp.Results) { return ,@() }
    return ,@($resp.Results)
}

function ConvertTo-KqlStringLiteral {
    param($Value)
    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    $s = $s.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    return '"' + $s + '"'
}

function Get-DefenderTableOwner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TableName)

    # Map a missing-table name to a customer-friendly explanation of which Defender service
    # owns the table and what licence / onboarding is required to make it appear in advanced
    # hunting. Used by the schema-error short-circuit in Invoke-GraphHuntingQuery so the log
    # line tells the customer exactly what to fix instead of just 'table not found'.
    switch -Regex ($TableName) {
        '_CL$' {
            return ("Custom Log Analytics table -- ingestion engine has not yet written to it, " +
                    "or the workspace is wrong. Check `$global:WorkspaceResourceId and run the " +
                    "matching SI ingestion engine (e.g. AssetProfileEngine for SI_*_Profile_CL, " +
                    "PublicIpScanner for SI_VulnerabilityPIP_CL).")
        }
        '^Device(?!Tvm)' {
            return ("Owned by Microsoft Defender for Endpoint (MDE Plan 2 / M365 E5 Security / M365 E5). " +
                    "Devices may already be onboarded for inventory + risk + exposure (Defender for Business / " +
                    "MDE Plan 1 also support those), but the EDR advanced-hunting schema (Device*, DeviceInfo, " +
                    "DeviceProcessEvents, DeviceLogonEvents, etc.) requires Plan 2. Newly upgraded tenants " +
                    "typically see the tables appear within minutes to ~24h while the backend re-provisions.")
        }
        '^DeviceTvm' {
            return ("Owned by Microsoft Defender Vulnerability Management (MDVM standalone add-on, or bundled " +
                    "in MDE Plan 2 / M365 E5). DeviceTvm* tables require either license + device onboarding.")
        }
        '^Identity' {
            return ("Owned by Microsoft Defender for Identity (MDI / EMS E5 / M365 E5). Requires the MDI sensor " +
                    "deployed on AD domain controllers and / or AD FS / Entra Connect servers.")
        }
        '^(AADSignInEvents|EntraIdSignInEvents|AADSpnSignInEvents|EntraIdSpnSignInEvents|GraphAPIAuditEvents|IdentityAccountInfo)' {
            return ("Owned by Microsoft Entra (Defender XDR pulls Entra sign-in / audit logs into advanced hunting). " +
                    "Requires Entra ID P1 / P2 with diagnostic-settings forwarding enabled. " +
                    "ALTERNATIVE: forward Entra Sign-in + Audit logs to your Log Analytics workspace via " +
                    "Entra > Diagnostic settings (preferably routed through Microsoft Sentinel for retention + " +
                    "analytic-rule coverage). The engine can then run sign-in queries against the LA-side " +
                    "SigninLogs / AADNonInteractiveUserSignInLogs / AuditLogs tables instead of the XDR ones, " +
                    "which avoids the advanced-hunting body cap on big-tenant let-block bridges.")
        }
        '^ExposureGraph' {
            return ("Owned by Microsoft Security Exposure Management (MDEM -- bundled in M365 E5 Security / " +
                    "M365 E5 / standalone Exposure Management SKU).")
        }
        '^Email|^Message|^UrlClickEvents' {
            return ("Owned by Microsoft Defender for Office 365 Plan 2 (MDO P2 -- bundled in M365 E5 / E5 Security / " +
                    "MDO P2 standalone).")
        }
        '^CloudApp|^AppFile' {
            return ("Owned by Microsoft Defender for Cloud Apps (MDA -- bundled in M365 E5 / EMS E5 / MDA standalone).")
        }
        '^Cloud(Audit|Dns|Process|Storage)' {
            return ("Owned by Microsoft Defender for Cloud (workload protection plans for Servers / Storage / DNS).")
        }
        '^(Alert|Behavior)' {
            return ("Owned by Microsoft Defender XDR (alerts + behaviors aggregated across all Defender services). " +
                    "Requires at least one Defender plan generating alerts.")
        }
        default {
            return ("Owner unknown -- check the Defender XDR advanced-hunting schema browser for which service " +
                    "exposes this table and confirm the corresponding licence / onboarding is in place.")
        }
    }
}

function Test-AdvancedHuntingHasTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName
    )

    if ($null -eq $script:_TableInAdvHunting) { $script:_TableInAdvHunting = @{} }
    if ($script:_TableInAdvHunting.ContainsKey($TableName)) { return $script:_TableInAdvHunting[$TableName] }

    Write-Info ("Probing whether {0} is queryable from advanced hunting (unified Defender XDR portal / data-lake mirroring check) ..." -f $TableName)
    try {
        Ensure-GraphAuth
        $null = Start-MgBetaSecurityHuntingQuery -Query ("{0} | take 1" -f $TableName) -ErrorAction Stop
        $script:_TableInAdvHunting[$TableName] = $true
        Write-Ok ("{0} IS queryable from advanced hunting. Preferred path." -f $TableName)
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match ("Failed to resolve table or column expression named '{0}'" -f [regex]::Escape($TableName))) {
            $script:_TableInAdvHunting[$TableName] = $false
            Write-Info ("{0} is NOT queryable from advanced hunting -- will route to Log Analytics direct." -f $TableName)
        } else {
            # Some other error (auth, throttle). Don't cache; let the real call surface it.
            Write-Warn2 ("AdvancedHunting probe for {0} inconclusive ({1}). Will assume table is accessible and let the real call decide." -f $TableName, $msg)
            $script:_TableInAdvHunting[$TableName] = $true
        }
    }
    return $script:_TableInAdvHunting[$TableName]
}

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

function Invoke-GraphHuntingQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$ReconnectMaxAgeMinutes = 45,
        [int]$MaxRetries = 4
    )

    # 2026-05-02 -- 2-phase post-augment plan holder. Populated by Resolve-ProfileAugmentPlan
    # in the EG+CL hybrid block below, consumed after AH submission to attach alias cols
    # to returned rows from a single LA snapshot per (TableName, RightKey). Empty array
    # means no augment needed (LA-direct, EG-only, or hybrid-fallback path).
    $augmentPlans      = @()
    $augmentWsForCL    = $null

    # CL-table routing: any query that references SI_*_CL chooses between two paths --
    #   PURE-LA  (no Defender XDR tables) -> submit the whole query directly to Log Analytics.
    #            No let-block, no advanced-hunting round trip, no body-size limit.
    #   MIXED    (CL + Device* / Identity* / ExposureGraph* / ...) -> AH route IF the CL table
    #            is mirrored into AH; else LA-direct with cross-workspace let for the XDR side.
    $customClPattern = '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b'
    if ($Query -match $customClPattern) {
        # Probe AH first: if every referenced SI_*_CL table is visible in advanced hunting,
        # submit as-is (unified Defender XDR portal customers). Otherwise fall back to
        # LA-direct (the only path that works without Sentinel data lake mirroring).
        $clTableHits = @([regex]::Matches($Query, $customClPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique)
        $available = $true
        # EG-references force AH. ExposureGraphNodes/Edges ONLY exist in advanced
        # hunting (no LA mirroring path), so any query referencing them MUST route to AH. The
        # AH probe for SI_*_Profile_CL can return false-negative when the SPN's Graph token
        # can't see CL even though it IS mirrored to AH for interactive users -- that probe
        # failure mustn't push us to LA when EG is in the query (LA would then EG-skip and
        # we'd produce zero rows). Skip the probe in this case; if CL truly isn't in AH for
        # this tenant, AH returns a clear "Failed to resolve table" error which the retry/
        # schema-classifier downstream surfaces with the right remediation.
        $queryReferencesEG = ($Query -match '\bExposureGraph(?:Nodes|Edges)\b')
        if ($queryReferencesEG) {
            $wsForCL = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) { [string]$global:SI_WorkspaceResourceId } else { [string]$global:WorkspaceResourceId }

            # PRIMARY PATH: Sentinel data lake KQL API. Single query covers EG+CL natively.
            # Microsoft docs (sentinel/datalake/kql-queries-api) confirms SPN auth IS
            # supported; the only constraint is that Entra ID / Defender XDR Unified RBAC
            # roles can't be used to grant the SPN -- it must be granted via workspace
            # Azure RBAC. If the SPN doesn't have access yet, we get InvalidDatabaseInQuery
            # and automatically fall back to the hybrid pre-fetch+inline path below.
            # Cache the unavailability after first failure so we don't waste a lake-call
            # per report (100+ queries x ~1s each = noticeable latency).
            if (-not $script:_SentinelLakeUnavailable) {
                Write-Diag ("[lake] probing Sentinel data lake for {0} ..." -f (Split-Path -Leaf $wsForCL))
                [void](Save-RARenderedQuery -Query $Query -Tag 'lake')
                try {
                    $lakeRows = Invoke-SISentinelLakeQuery -Query $Query -WorkspaceResourceId $wsForCL -ErrorAction Stop
                    Write-Ok ("[lake] {0} row(s) returned -- single-query path active." -f (@($lakeRows).Count))
                    return [pscustomobject]@{ _SIDirectRows = @($lakeRows) }
                } catch {
                    $lakeMsg = $_.Exception.Message
                    # All known "lake just won't work for this run" patterns:
                    # - InvalidDatabaseInQuery / not available / 403 / 401  : RBAC not granted
                    # - TenantNotFound / 404 / "Tenant not registered"      : Sentinel data lake feature not enabled on this workspace
                    # All of these are PERMANENT within a single run, so flip the
                    # short-circuit flag and stop probing every subsequent query.
                    if ($lakeMsg -match 'InvalidDatabaseInQuery|not available for current user|Forbidden|403|Unauthorized|401|TenantNotFound|Tenant not registered|404|Not Found') {
                        Write-Diag ("[lake] unavailable for this run ({0}). Using hybrid fallback for ALL subsequent queries." -f ($lakeMsg -split "`n" | Select-Object -First 1))
                        $script:_SentinelLakeUnavailable = $true
                    } else {
                        # Unknown failure mode -- still log loudly + still flip the flag
                        # so we don't spam the same error on every query.
                        Write-Warn2 ("[lake] failed: {0}. Falling back to hybrid for this query and disabling lake for the rest of the run." -f ($lakeMsg -split "`n" | Select-Object -First 1))
                        $script:_SentinelLakeUnavailable = $true
                    }
                }
            }
            # Suppress per-query "lake skipped" chatter once we know it's unavailable.

            # 2026-05-02 -- 2-PHASE POST-AUGMENT (preferred). Detect the canonical
            # `let <var> = SI_*_Profile_CL | ... | project ... ; ... | join (<var>) on ... | extend <alias> = <var-col>`
            # pattern and STRIP it from the query. The remaining query is pure EG (or EG
            # joined with other AH tables) and submits cleanly through AH. After rows
            # return, Invoke-ProfileAugment fetches the CL snapshot ONCE per (TableName,
            # RightKey), builds an in-memory hashtable, and stamps the alias columns
            # post-hoc. Avoids both the 1MB nginx body cap (no inlined datatable) and the
            # malformed-KQL failures the inline path produced for Attack_Paths reports.
            #
            # FALLBACK: when the augment-plan regex doesn't match (e.g. cmdb cols used
            # in a downstream summarize-by, or non-canonical join shape), fall through to
            # the legacy hybrid path: pre-fetch + inline as datatable() + table-shadow.
            try {
                $planResult = Resolve-ProfileAugmentPlan -Query $Query
                if ($planResult.Plans -and @($planResult.Plans).Count -gt 0) {
                    $Query           = $planResult.Query
                    $augmentPlans    = @($planResult.Plans)
                    $augmentWsForCL  = $wsForCL
                    Write-Info ("[2phase] active: {0} plan(s); let+join+extend stripped from query, augment will run post-AH" -f $augmentPlans.Count)
                }
            } catch {
                Write-Warn2 ("[2phase] plan resolve failed; falling back to legacy hybrid. Reason: {0}" -f $_.Exception.Message)
            }

            if (-not $augmentPlans -or @($augmentPlans).Count -eq 0) {
                # Legacy hybrid: pre-fetch + inline as datatable() literal.
                try {
                    $Query = Resolve-ProfileCLLetBlocks -Query $Query -WorkspaceResourceId $wsForCL
                } catch {
                    Write-Warn2 ("[scope] failed; let-blocks left for table-shadow fallback. Reason: {0}" -f $_.Exception.Message)
                }
                try {
                    $Query = Add-CLSnapshotShadows -Query $Query -WorkspaceResourceId $wsForCL
                } catch {
                    Write-Warn2 ("[shadow] failed; routing query as-is. Reason: {0}" -f $_.Exception.Message)
                }
            }
            [void](Save-RARenderedQuery -Query $Query -Tag 'hybrid')
        } else {
            foreach ($clTbl in $clTableHits) {
                if (-not (Test-AdvancedHuntingHasTable -TableName $clTbl)) { $available = $false; break }
            }
        }
        # v2.2.272 -- diagnostic breadcrumb. Class 1 routing bug (Nordstern):
        # Endpoint_ActiveCompromise_Detected_Detailed had probe say "NOT in AH" yet
        # AH submission still happened. Log the routing decision so the next run
        # tells us which branch actually fired.
        Write-Diag ("[route] CL probe done: available={0} | clHits=[{1}] | hasEG={2}" -f $available, ($clTableHits -join ','), $queryReferencesEG)
        if (-not $available) {
            # same fallback as LA-ingest path. Resolution order:
            # RA-specific (SI_RiskAnalysis_*, for split-workspace setups) -> v2.2 unified
            # (SI_*) -> bare legacy. Customer config sets $global:SI_WorkspaceResourceId
            # per the unified contract; without the SI_* fallback every Profile_CL query
            # threw "Cannot bridge ... $global:WorkspaceResourceId is not set".
            $wsResId = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_WorkspaceResourceId)) { [string]$global:SI_RiskAnalysis_WorkspaceResourceId }
                       elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId))           { [string]$global:SI_WorkspaceResourceId }
                       else { [string]$global:WorkspaceResourceId }
            if ([string]::IsNullOrWhiteSpace($wsResId)) {
                throw "Cannot bridge SI_*_CL tables: no workspace configured. Set `$global:SI_WorkspaceResourceId (preferred), `$global:SI_RiskAnalysis_WorkspaceResourceId (split-workspace), or legacy `$global:WorkspaceResourceId. Or enable Sentinel data lake + table mirroring."
            }

            # XDR-table detection. \b on both sides means SI_IdentityAssets_CL doesn't trigger
            # the Identity* branch (no word boundary between '_' and 'I'). Negative lookaheads
            # exclude our custom tables explicitly (Identity(?!Assets)). DeviceTvm IS an XDR
            # table from MDVM (only exists in advanced hunting), so it gets its own branch.
            #
            # CRITICAL: strip KQL string literals + line comments BEFORE matching, otherwise
            # column-value strings like SecurityDomain == "Identity" or Category == "Email"
            # falsely trigger the regex and force pure-LA queries through the let-block bridge
            # (which then hits nginx 413 on big estates). v2.1.199 had this bug; v2.1.200 fixes.
            $queryForDetection = $Query
            $queryForDetection = [regex]::Replace($queryForDetection, '"[^"\r\n]*"', '""')   # double-quoted strings
            $queryForDetection = [regex]::Replace($queryForDetection, "'[^'\r\n]*'", "''")   # single-quoted strings
            $queryForDetection = [regex]::Replace($queryForDetection, "@'[^']*'", "''")      # @'...' verbatim single
            $queryForDetection = [regex]::Replace($queryForDetection, '@"[^"]*"', '""')      # @"..." verbatim double
            $queryForDetection = [regex]::Replace($queryForDetection, '//[^\r\n]*', '')      # // line comments

            # TABLE-POSITION ANCHOR (same fix Test-Smoke got in ).
            # Without anchoring, `\bDevice(?!Tvm)\w*\b` greedily matches column names
            # like DeviceKey / DeviceName -- which are NOT XDR tables. Result: false-
            # positive XDR detection forces the cross-workspace let-block, which then
            # injects invalid KQL like `let DeviceKey = workspace(...).DeviceKey;` and
            # the whole query 400s. Restrict to legal table-reference positions:
            # - start-of-line / start-of-statement (after newline+optional whitespace)
            # - after `|` (pipe operator: `... | DeviceInfo` would be illegal but
            #   `... | join (DeviceInfo | ...) on X` IS — the table follows `(` though)
            # - after `(` (start of parenthesized subquery: `union(DeviceInfo, ...)` `join (DeviceInfo)`)
            # - after `,` (table-arg lists: `union DeviceInfo, DeviceLogonEvents`)
            # - after `=` (let assignment: `let X = DeviceInfo | ...`)
            # - after the literal keywords `union` / `join` / `materialize` / `evaluate`
            #   (followed by a single space then the table name)
            # Tables that live in the Defender / Sentinel workspace -- NOT in the SI
            # workspace where SI_*_Profile_CL lives. These get cross-workspace let
            # blocks pointing at $global:SI_DefenderWorkspaceResourceId.
            #
            # Two families:
            #   (a) Defender XDR Advanced Hunting tables (Device* / Identity* / Email* etc.)
            #       These are queryable via /security/runHuntingQuery OR via the Sentinel
            #       LA workspace if mirroring/data-lake is enabled. Either way, NOT in the
            #       SI workspace.
            #   (b) Sentinel-side LA tables (SigninLogs / AuditLogs / AAD*SignInLogs)
            #       Standard Entra diagnostic-settings outputs. Live in the Defender /
            #       Sentinel workspace by convention. NOT in the SI workspace.
            #
            # Position anchor (assembled below) blocks DeviceKey (column) from matching --
            # bare `\bDevice\w*\b` was the rev2 false-positive regression.
            $xdrTableNames = '(' +
                # ---- (a) Defender XDR Advanced Hunting families ----
                'Device\w*' +                                       # MDE P2 + MDVM + MDB Baseline (all Device* tables)
                '|Identity(?!Assets|Type|Provider)\w*' +            # MDI: IdentityInfo, IdentityLogonEvents, IdentityAccountInfo
                '|ExposureGraph\w*' +                               # MDEM: ExposureGraphNodes, ExposureGraphEdges
                '|Email\w*' +                                       # MDO: EmailEvents, EmailUrlInfo, EmailAttachmentInfo
                '|Message(?:Events|PostDelivery|UrlInfo)\w*' +      # MDO: MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo
                '|UrlClickEvents' +                                 # MDO
                '|CloudApp\w*' +                                    # MDA: CloudAppEvents
                '|AppFileEvents' +                                  # MDA
                '|Cloud(?:Audit|Dns|Process|Storage)\w*' +          # Defender for Cloud
                '|Alert(?:Evidence|Info)' +                         # XDR
                '|Behavior(?:Entities|Info)' +                      # XDR
                '|AAD\w*SignIn\w*' +                                # Entra (XDR-side)
                '|EntraId\w*SignIn\w*' +                            # Entra (XDR-side)
                '|GraphAPIAuditEvents' +                            # Entra (XDR-side)
                # ---- (b) Sentinel-workspace LA tables (Entra diagnostic settings) ----
                '|SigninLogs' +                                     # Entra interactive sign-ins (LA-side)
                '|AADNonInteractiveUserSignInLogs' +                # Entra non-interactive (LA-side)
                '|AADServicePrincipalSignInLogs' +                  # Entra SPN sign-ins (LA-side)
                '|AADManagedIdentitySignInLogs' +                   # Entra MI sign-ins (LA-side)
                '|AADProvisioningLogs' +                            # Entra provisioning (LA-side)
                '|AuditLogs' +                                      # Entra audit (LA-side)
                '|IntuneAuditLogs' +                                # Intune (LA-side)
                '|MicrosoftGraphActivityLogs' +                     # Graph activity (LA-side)
                ')\b'

            # Anchor: TIGHT table-reference positions. Earlier draft used [|=(,] which
            # caught `ConfigurationName=DeviceName` as table-position (= anchor) and
            # `coalesce(DeviceName, ...)` (( anchor) and `project A, DeviceName` (, anchor).
            # Real KQL table refs only appear at:
            #   - start of statement (^ in multiline)
            #   - immediately after a `|` pipe (with optional whitespace)
            #   - after a keyword: union | join | materialize | evaluate
            # The `let X = TableName` case isn't supported -- rare in practice and the
            # let body usually ends with `|` so the next pipe catches it.
            $xdrTablePattern = '(?ms)(?:(?:^|\|)\s*|\b(?:union|join|materialize|evaluate)\s+(?:\(\s*)?)' + $xdrTableNames

            # Find every distinct table identifier at table-position; -AllMatches needed
            # so we can dedupe and emit one let per unique name.
            $xdrMatches = [regex]::Matches($queryForDetection, $xdrTablePattern)
            $xdrTableHits = @($xdrMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $hasXdrTables = $xdrTableHits.Count -gt 0

            # EG-only tables (ExposureGraphNodes /
            # ExposureGraphEdges) only exist in Defender XDR Advanced Hunting. They're
            # NOT exposed as tables in any LA workspace by default. The cross-workspace
            # let-block we'd inject (`workspace('xdr-ws').ExposureGraphNodes`) will fail
            # because the Defender LA workspace doesn't have EG either. Customer would
            # need to enable Sentinel data lake + table mirroring for EG to make these
            # queries work. Until the flag is on (`$global:SI_HasExposureGraphInLA = $true`),
            # SKIP the report cleanly rather than retry-fail-retry-fail.
            #
            # Detection: SUBSTRING check on the stripped query (NOT the position-anchor
            # XDR regex), because EG often appears in `let _x = ExposureGraphNodes`
            # let-bindings -- which my position-anchor regex correctly ignores (= isn't
            # a table-position anchor, would otherwise match column projections like
            # `ConfigurationName=DeviceName`). Substring check is safe here because no
            # legitimate KQL column would be named `ExposureGraphNodes` / `ExposureGraphEdges`.
            $egNeeded = @()
            if ($queryForDetection -match '\bExposureGraphNodes\b') { $egNeeded += 'ExposureGraphNodes' }
            if ($queryForDetection -match '\bExposureGraphEdges\b') { $egNeeded += 'ExposureGraphEdges' }
            if ($egNeeded.Count -gt 0 -and -not $global:SI_HasExposureGraphInLA) {
                Write-Warn2 ("Skipping report -- query needs ExposureGraph table(s) ({0}) which aren't exposed in any LA workspace. Enable Sentinel data lake + table mirroring for ExposureGraph in `$global:SI_DefenderWorkspaceResourceId, then set `$global:SI_HasExposureGraphInLA = `$true to opt in." -f ($egNeeded -join ', '))
                return [pscustomobject]@{ _SIDirectRows = @() }
            }

            # _CL tables ALWAYS require Log Analytics --
            # they don't exist in Defender XDR Advanced Hunting. The let-block-then-AH
            # Route SI_*_CL queries to LA-direct unconditionally. When the query also
            # references XDR tables (DeviceInfo, IdentityInfo, ExposureGraph*, AAD*
            # SignIn*, etc.), prepend a cross-workspace let-block resolving each XDR
            # table via `workspace("<defender-ws>").TableName`. Defender workspace
            # resolves from $global:SI_DefenderWorkspaceResourceId
            # and falls back to $wsResId if no separate Defender workspace is configured
            # (single-workspace tenants where Sentinel + XDR live alongside SI_*_CL).
            $crossWorkspaceLet = ''
            if ($hasXdrTables) {
                $defenderWs = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DefenderWorkspaceResourceId)) {
                    [string]$global:SI_DefenderWorkspaceResourceId
                } else { $wsResId }

                # Reuse the dedup'd hits captured during $hasXdrTables detection above.
                # The let SHADOWS the bare identifier downstream so the rest of the query
                # reads as written -- no in-place rewriting that might miss a reference
                # inside a join() or union() arg.
                $sb = New-Object System.Text.StringBuilder
                foreach ($t in $xdrTableHits) {
                    [void]$sb.AppendLine(("let {0} = workspace('{1}').{0};" -f $t, $defenderWs))
                }
                $crossWorkspaceLet = $sb.ToString()
                if ($defenderWs -eq $wsResId) {
                    Write-Info ("Query joins SI_*_CL with {0} XDR table(s) ({1}); routing to LA-direct with cross-table self-workspace let-block (single-workspace setup -- no separate `$global:SI_DefenderWorkspaceResourceId)." -f $xdrTableHits.Count, ($xdrTableHits -join ', '))
                } else {
                    Write-Info ("Query joins SI_*_CL with {0} XDR table(s) ({1}); routing to LA-direct with cross-workspace let-block bridging to `$global:SI_DefenderWorkspaceResourceId." -f $xdrTableHits.Count, ($xdrTableHits -join ', '))
                }
            } else {
                Write-Info "Query touches only Log Analytics tables (no Defender XDR tables); routing entire query directly to LA workspace -- no let-block, no advanced-hunting round trip, no body-size limit."
            }

            $finalQuery = if ($crossWorkspaceLet) { $crossWorkspaceLet + "`n" + $Query } else { $Query }
            [void](Save-RARenderedQuery -Query $finalQuery -Tag 'la-direct')
            # v2.2.272 -- diagnostic. Confirm we actually got HERE on routes that the
            # probe said should be LA-direct.
            Write-Diag ("[route] LA-direct submission entered. wsResId={0} hasXdr={1} crossLetLen={2}" -f $wsResId, $hasXdrTables, $crossWorkspaceLet.Length)

            # NO @() wrap on the call below. Invoke-LogAnalyticsKqlQuery returns the rows
            # array via `,@($resp.Results)` (comma-protected so PowerShell emits it as ONE
            # value). `@(call)` would re-wrap that single value into a [Object[1] of
            # Object[N]], then the foreach below iterated ONCE with $r = the inner array,
            # and Calculate-RiskScore later read $r.PSObject.Properties = System.Array's
            # native props (Count/Length/SyncRoot/...). Plain assignment captures the
            # inner rows array directly. v2.1.204 fix.
            #
            # fallback (per user request): if the cross-workspace XDR let
            # block resolves to a Defender workspace that doesn't have the table (mis-
            # configured `$global:SI_DefenderWorkspaceResourceId`, or the customer's
            # XDR tables actually live alongside SI_*_CL in the same workspace), retry
            # against the SI workspace alone -- raw query, no let. Cleaner than failing
            # the whole report when LA can resolve the table itself.
            try {
                # v2.2.280 -- visible heartbeat before the LA call. Same silent-gap
                # problem as the AH path: large LA-direct queries can sit for
                # minutes before returning, and operators saw the engine appear
                # to hang.
                Write-Info "submitting query to Log Analytics direct (may take several minutes for large workspaces)..."
                $_laSw = [System.Diagnostics.Stopwatch]::StartNew()
                $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $wsResId -Query $finalQuery
                $_laSw.Stop()
                Write-Info ("Log Analytics returned in {0:F1}s" -f $_laSw.Elapsed.TotalSeconds)
            } catch {
                # Cross-workspace failures surface as generic BadRequest (the inner
                # SemanticError isn't always propagated through the LA REST layer).
                # Auto-fallback only when WE prepended a cross-workspace let -- otherwise
                # the failure is in the user's query itself and re-running it changes
                # nothing. We retry against $wsResId alone (no let-block) so single-
                # workspace setups where XDR tables happen to live alongside SI_*_CL
                # still resolve. If that also fails, the original error surfaces below.
                $shouldFallback = $crossWorkspaceLet -and ($_.Exception.Message -match "BadRequest|Failed to resolve|SemanticError")
                if ($shouldFallback) {
                    Write-Warn2 ("Cross-workspace XDR lookup failed ({0}). Retrying as direct LA query against `$global:SI_WorkspaceResourceId (single-workspace fallback)." -f $_.Exception.Message)
                    $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $wsResId -Query $Query
                } else { throw }
            }
            if ($null -eq $rows) { $rows = @() }
            # Bypass the Microsoft Graph response shape entirely. v2.1.199 tried to mock
            # it by wrapping each row's data in an AdditionalProperties hashtable and
            # returning a 1-element Results array -- but PowerShell's property broadcast
            # on a 1-element PSCustomObject array returns the raw hashtable in a way
            # that downstream Calculate-RiskScore iterated as System.Array (Length/Rank/
            # SyncRoot appeared on the row, the real data ended up in SyncRoot, every
            # column except the first leaked as null). v2.1.202 fix: ship the clean rows
            # in a marker property `_SIDirectRows` and have the engine detect it and
            # use them directly, skipping the `.AdditionalProperties` + ConvertTo-PSObjectDeep
            # dance that only makes sense for Microsoft Graph SDK responses.
            $cleanRows = New-Object System.Collections.Generic.List[object]
            foreach ($r in $rows) {
                $h = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }
                [void]$cleanRows.Add([pscustomobject]$h)
            }
            return [pscustomobject]@{ _SIDirectRows = $cleanRows.ToArray() }
        }
    }

    # v2.2.198 -- track whether every retry attempt on this submission ended in
    # TaskCanceledException (= 900s HttpClient timeout). If so, outer AutoBucket
    # loop treats it as a DETERMINISTIC failure (the query genuinely can't run
    # within 900s on this tenant's Graph hunting backend) and skips remaining
    # buckets instead of paying another 5+ hours of identical timeouts. Reset
    # to true before each call; flipped false in the catch on ANY non-timeout
    # exception OR on success below.
    $script:_LastGraphHuntingAllTimedOut = $true

    [void](Save-RARenderedQuery -Query $Query -Tag 'ah')
    # v2.2.272 -- diagnostic. If a query that referenced SI_*_CL ends up here, log
    # how it got past the LA-direct branch (Class 1 routing-bug Nordstern paste).
    if ($Query -match '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b') {
        Write-Diag ("[route] AH submission entered for query containing SI_*_CL -- either EG-hybrid path resolved CL, or LA-direct branch was bypassed.")
    }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Ensure-GraphAuth -MaxAgeMinutes $ReconnectMaxAgeMinutes

        try {
            # v2.2.280 -- visible heartbeat BEFORE the AH submission. Without
            # this, operators saw the engine go silent for up to 15 min between
            # "snapshot inlined" and the next log line whenever a query took its
            # full HttpClient ceiling (TaskCanceled@900s pattern). Print start
            # + duration so progress is observable.
            Write-Info ("submitting query to advanced hunting (attempt {0}/{1}; may take up to 900s if too large)..." -f $attempt, $MaxRetries)
            $_ahSw = [System.Diagnostics.Stopwatch]::StartNew()
            $ahResp = Start-MgBetaSecurityHuntingQuery -Query $Query -ErrorAction Stop
            $_ahSw.Stop()
            Write-Info ("advanced hunting returned in {0:F1}s" -f $_ahSw.Elapsed.TotalSeconds)

            # 2-phase post-augment: when Resolve-ProfileAugmentPlan stripped cmdb let/join/
            # extend from the query, the AH rows lack those columns. Convert the Graph
            # response shape (Results[].AdditionalProperties hashtables) to clean
            # PSCustomObjects, augment in PowerShell from a single LA fetch per plan,
            # and ship as _SIDirectRows so the caller's existing marker-property branch
            # picks them up (same shape as the LA-direct + Sentinel-lake paths).
            if ($augmentPlans -and @($augmentPlans).Count -gt 0) {
                $cleanRows = New-Object System.Collections.Generic.List[object]
                if ($null -ne $ahResp -and $null -ne $ahResp.Results) {
                    foreach ($r in $ahResp.Results) {
                        $h = [ordered]@{}
                        if ($null -ne $r.AdditionalProperties) {
                            foreach ($k in $r.AdditionalProperties.Keys) { $h[[string]$k] = $r.AdditionalProperties[$k] }
                        } else {
                            foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }
                        }
                        [void]$cleanRows.Add([pscustomobject]$h)
                    }
                }
                $augmented = Invoke-ProfileAugment -Rows $cleanRows.ToArray() -Plans $augmentPlans -WorkspaceResourceId $augmentWsForCL
                return [pscustomobject]@{ _SIDirectRows = @($augmented) }
            }

            return $ahResp
        } catch {
            $msg = $_.Exception.Message

            $isTaskCanceled = ($_.Exception -is [System.Threading.Tasks.TaskCanceledException]) -or ($msg -match 'A task was canceled')
            # v2.2.276 -- 502 Bad Gateway from nginx (in front of /security/runHuntingQuery)
            # is the SAME deterministic "query too big" pattern as TaskCanceled. nginx
            # responds 502 when the upstream AH backend produces a response too large
            # for nginx to proxy. Retrying the identical query just burns 4 more
            # attempts (each up to 900s) on the same fail. Classify it like
            # TaskCanceled so the AutoBucket escalation kicks in immediately.
            $is502BadGateway = ($msg -match '502 Bad Gateway' -or $msg -match '\[UnknownError\][^<]*<html>')
            $isDeterministicTooLarge = $isTaskCanceled -or $is502BadGateway
            # v2.2.198 -- any non-timeout failure means this call is NOT a clean
            # deterministic-timeout pattern, so the outer AutoBucket loop should
            # treat subsequent buckets as still worth trying.
            if (-not $isDeterministicTooLarge) { $script:_LastGraphHuntingAllTimedOut = $false }
            $looksAuth      = ($msg -match 'InvalidAuthenticationToken|Access token|Authentication|Unauthorized|401')
            $looksThrottle  = ($msg -match 'Too Many Requests|429|throttl|temporar')


            $looksOverflow  = (Test-IsBucketOverflowError -Err $_) -or ($msg -match 'exceeded the allowed result size|exceeded the allowed limits|preempted')

            # 413 Request Entity Too Large -- the nginx in front of /security/runHuntingQuery
            # rejected the body size before it reached the hunting backend. This is hit by the
            # let-block bridge on big customer estates whenever a SI_*_(Profile|Assets)_CL
            # snapshot is inlined as datatable() and the row count + columns push the body
            # over the ~1 MB cap. The warning emitted below names the ACTUAL tables in the
            # current query (not a hardcoded SI_IdentityAssets_CL reference).
            $looksRequestTooLarge = ($msg -match '413 Request Entity Too Large')

            # Schema error: missing table or column. Deterministic -- retrying cannot help.
            # Capture the table name and classify it by Defender service so the log line tells
            # the customer WHICH service / SKU they're missing.
            $looksSchemaError = $false
            $missingTable     = $null
            if ($msg -match "Failed to resolve (?:table or column )?expression named '([^']+)'") {
                $looksSchemaError = $true
                $missingTable     = $matches[1]
            }

if ($looksAuth) {
                Write-Warn2 "Graph auth issue detected. Reconnecting and retrying..."
                try { Connect-GraphHighPriv } catch { Write-Err2 "Graph reconnect failed: $($_.Exception.Message)"; throw }
            }


            if ($looksRequestTooLarge) {
                # Inspect THIS query (with KQL string literals stripped to avoid false positives
                # like the Identity / Email regex trap from v2.1.199) to decide which fix to surface.
                $qStripped = $Query
                $qStripped = [regex]::Replace($qStripped, '"[^"\r\n]*"', '""')
                $qStripped = [regex]::Replace($qStripped, "'[^'\r\n]*'", "''")
                $qStripped = [regex]::Replace($qStripped, "@'[^']*'", "''")
                $qStripped = [regex]::Replace($qStripped, '@"[^"]*"', '""')
                $qStripped = [regex]::Replace($qStripped, '//[^\r\n]*', '')
                $referencesSignInTables = ($qStripped -match '\b(AAD\w*SignIn\w*|EntraId\w*SignIn\w*|GraphAPIAuditEvents)\b')

                # Identify the ACTUAL SI_*_(Profile|Assets)_CL tables this query inlines, so the
                # warning names them instead of the legacy hardcoded `SI_IdentityAssets_CL`.
                $actualClTables = @([regex]::Matches($qStripped, '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b') |
                                    ForEach-Object { $_.Value } | Sort-Object -Unique)
                $clTablesDisplay = if ($actualClTables.Count -gt 0) { ($actualClTables -join ', ') } else { 'SI_*_(Profile|Assets)_CL' }

                Write-Warn2 ("Query body exceeded the advanced-hunting nginx body cap (413 Request Entity Too Large). " +
                             "This is a hard Microsoft-side limit (~1 MB) on /security/runHuntingQuery; not retryable.")

                if ($referencesSignInTables) {
                    Write-Warn2 ("This query joins {0} with XDR sign-in tables (AADSignInEvents / " -f $clTablesDisplay +
                                 "EntraIdSignInEvents / GraphAPIAuditEvents), so it MUST go through advanced hunting with " +
                                 "an inline let-block of your asset table. Two fixes:")
                    Write-Warn2 ("  (1) PREFERRED FOR SIGN-IN REPORTS: forward Entra Sign-in + Audit logs to your Log " +
                                 "Analytics workspace via Entra > Diagnostic settings (preferably routed through Microsoft " +
                                 "Sentinel for retention + analytic-rule coverage). Once SigninLogs / " +
                                 "AADNonInteractiveUserSignInLogs / AuditLogs are in LA, the YAML query authors can switch " +
                                 "the join target to the LA-side table -- the report becomes pure-LA and bypasses the body cap.")
                    Write-Warn2 ("  (2) Enable Microsoft Sentinel data lake + table mirroring for {0}. The " -f $clTablesDisplay +
                                 "engine probe at startup detects this and queries submit DIRECTLY to advanced hunting with " +
                                 "no inline let-block -- the asset table is natively visible there.")
                } else {
                    Write-Warn2 ("Fix: enable Microsoft Sentinel data lake + table mirroring for {0}. The " -f $clTablesDisplay +
                                 "engine probe at startup detects this and queries submit DIRECTLY to advanced hunting with " +
                                 "no inline let-block -- the asset table is natively visible there. Alternatively, reduce " +
                                 "the per-row size of your custom asset table (drop wide columns from the Profile schema, " +
                                 "or use the engine's scoped pre-fetch so only the rows actually joined are inlined) to keep " +
                                 "the inline block under ~1 MB.")
                }
                throw
            }

            if ($looksOverflow) {
                Write-Warn2 "Query exceeded allowed limits/result size; not retrying (deterministic failure)."
                throw
            }

            if ($looksSchemaError) {
                $owner = Get-DefenderTableOwner -TableName $missingTable
                Write-Warn2 ("Table '{0}' not present in this tenant's advanced hunting schema. {1}" -f $missingTable, $owner)
                Write-Warn2 "Not retrying (deterministic schema failure -- retries cannot conjure a missing table)."
                throw
            }

            # Syntax errors are deterministic -- retrying produces the same parse error.
            # AH/Graph swallows the error body's line/column info, so dump the rendered
            # query path (already written in the staging block above) for portal paste.
            $looksSyntaxError = ($msg -match 'Fix syntax errors in your query|Expected:|SyntaxError')
            if ($looksSyntaxError) {
                Write-Warn2 ("Query failed with KQL syntax error -- not retryable: {0}" -f $msg)
                try {
                    if ($script:_RAStagingDir -and (Test-Path $script:_RAStagingDir)) {
                        $hashLast = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Query))
                        $hashLastStr = -join ($hashLast[0..3] | ForEach-Object { $_.ToString('x2') })
                        $renderedPath = Join-Path $script:_RAStagingDir ("ra-rendered-{0}.kql" -f $hashLastStr)
                        if (Test-Path $renderedPath) {
                            Write-Warn2 ("Paste rendered query into Sentinel/AH portal for the precise line+column: {0}" -f $renderedPath)
                        }
                    }
                } catch { }
                throw
            }

            # v2.2.273 / v2.2.276 -- fail-fast on deterministic "query too large"
            # patterns. The 4x900s retry pattern was useful when timeouts looked
            # transient, but in practice when AH hits the HttpClient ceiling (900s)
            # OR nginx returns 502 (upstream response too large for nginx to proxy),
            # the query is genuinely too big. Retrying burns hours on identical
            # fails. Bubble up after the FIRST occurrence so the AutoBucket
            # escalation in the outer loop can re-run with a higher bucket count
            # immediately. The script:_LastGraphHuntingAllTimedOut flag is the
            # signal the outer bucket loop reads.
            if ($isDeterministicTooLarge) {
                $reason = if ($isTaskCanceled) { 'TaskCanceled@900s (HttpClient ceiling)' } else { '502 Bad Gateway (nginx upstream-response-too-large)' }
                Write-Err2 ("Query failed deterministically ({0}) on attempt {1} -- bypassing retries. AutoBucket escalation will resize the report at higher bucket count." -f $reason, $attempt)
                $script:_LastGraphHuntingAllTimedOut = $true
                throw
            }

            if ($attempt -lt $MaxRetries) {
                $sleepSec = if ($looksThrottle) { [math]::Min(60, 5 * $attempt) }
                            else { [math]::Min(20, 2 * $attempt) }

                Write-Warn2 ("Query failed (attempt {0}/{1}). Waiting {2}s then retrying... {3}" -f $attempt, $MaxRetries, $sleepSec, $msg)
                Start-Sleep -Seconds $sleepSec
                # v2.2.276 -- visible "now retrying" line so operators can tell
                # the engine isn't hung when the next attempt takes its full 900s
                # before returning. Without this the log goes silent for up to
                # 15 min between "Waiting 2s" and the next attempt's outcome.
                Write-Info ("Retrying attempt {0}/{1} now (call may take up to 900s)..." -f ($attempt + 1), $MaxRetries)
                continue
            }

            Write-Err2 ("Query failed after {0} attempts: {1}" -f $MaxRetries, $msg)
            throw
        }
    }
}

function Export-AISummaryWorksheet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)][string]$SummaryText
  )

  # Normalize line endings and split into rows so it’s readable in Excel
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
  $ws.Cells.AutoFitColumns()
  for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
    if ($ws.Column($col).Width -gt 90) { $ws.Column($col).Width = 90 }
  }

  Close-ExcelPackage $excel
}

# =================================================================================================
# ASSETNAME-SAFE KQL HELPERS (FULL FIX)
# =================================================================================================

function New-DeviceKeyKql {
@"
| extend DeviceKey = coalesce(
    tostring(column_ifexists('AadDeviceId','')),
    tostring(column_ifexists('DeviceId','')),
    tostring(column_ifexists('MachineId','')),
    tostring(column_ifexists('AssetName','')),
    tostring(column_ifexists('DeviceName','')),
    tostring(column_ifexists('Computer','')),
    tostring(column_ifexists('DnsName','')),
    tostring(column_ifexists('HostName','')),
    tostring(column_ifexists('FQDN','')),
    tostring(column_ifexists('Id','')),
    'unknown'
)
"@
}

function Ensure-QueryIsAssetNameSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Query
    )

    $safeDeviceKeyBlock = (New-DeviceKeyKql).TrimEnd()

    # Replace only DeviceKey assignments that reference AssetName (the common failure)
    # Example (your YAML):
    # | extend DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, AssetName)
    $Query = $Query -replace '(?im)^\s*\|\s*extend\s+DeviceKey\s*=\s*iif\s*\(\s*isnotempty\s*\(\s*AadDeviceId\s*\)\s*,\s*AadDeviceId\s*,\s*AssetName\s*\)\s*$', $safeDeviceKeyBlock

    # Also cover minor formatting variations where AssetName is used on the DeviceKey line
    $Query = $Query -replace '(?im)^\s*\|\s*extend\s+DeviceKey\s*=.*\bAssetName\b.*$', $safeDeviceKeyBlock

    return $Query
}

function New-BucketFilterKql {
  param(
    [int]$BucketCount,
    [int]$BucketIndex,
    [string]$ReportName = ''
  )

  # v2.2.200 -- composite bucket key for *_Detailed reports.
  #
  # Default (Summary + everything else): hash on the FIRST non-empty device-
  # level identifier. All rows for the same device land in the same bucket,
  # so any downstream `summarize by <device>` rolls up correctly.
  #
  # *_Detailed reports emit one row per (asset, finding) tuple -- a hot device
  # with 10K findings dumps 10K join-explosion rows into a single bucket and
  # the XDR backend preempts no matter how high we escalate the bucket count
  # (the device is deterministic-bucketed; doubling N just moves the whole
  # device to a different bucket, never splits it). Composite key strcat's
  # the asset key AND the finding key, so the SAME asset's findings hash to
  # DIFFERENT buckets -- the hot device gets split across N buckets naturally.
  # Per-(asset, finding) rows are unique to a bucket, so the downstream
  # `summarize by AssetName, FindingName` still works -- each tuple lives in
  # one bucket only, and across-bucket concatenation gives the full result.
  $isDetailed = $ReportName -like '*_Detailed'

  if ($isDetailed) {
@"
| extend __bucket_key = strcat(
    coalesce(tostring(column_ifexists('DeviceKey','')),
             tostring(column_ifexists('NodeId','')),
             tostring(column_ifexists('DeviceNodeId','')),
             tostring(column_ifexists('AadDeviceId','')),
             tostring(column_ifexists('DeviceId','')),
             tostring(column_ifexists('MachineId','')),
             tostring(column_ifexists('Id','')),
             tostring(column_ifexists('SourceNodeId','')),
             tostring(column_ifexists('TargetNodeId',''))),
    '|',
    coalesce(tostring(column_ifexists('FindingNodeId','')),
             tostring(column_ifexists('FindingName','')),
             tostring(column_ifexists('CVE','')),
             tostring(column_ifexists('CveId','')),
             tostring(column_ifexists('ConfigurationId','')),
             tostring(column_ifexists('RecommendationId','')),
             '')
)
| where isnotempty(__bucket_key)
| extend __bucket = abs(hash(__bucket_key)) % $BucketCount
| where __bucket == $BucketIndex
"@
  } else {
@"
| extend __bucket_key = coalesce(
    tostring(column_ifexists('DeviceKey','')),
    tostring(column_ifexists('NodeId','')),
    tostring(column_ifexists('DeviceNodeId','')),
    tostring(column_ifexists('AadDeviceId','')),
    tostring(column_ifexists('DeviceId','')),
    tostring(column_ifexists('MachineId','')),
    tostring(column_ifexists('Id','')),
    tostring(column_ifexists('SourceNodeId','')),
    tostring(column_ifexists('TargetNodeId',''))
)
| where isnotempty(__bucket_key)
| extend __bucket = abs(hash(__bucket_key)) % $BucketCount
| where __bucket == $BucketIndex
"@
  }
}

function New-SubBucketFilterKql {
  # v2.2.277 -- emits a KQL filter for sub-bucket j of K within parent bucket N
  # at parent total T. Produces the same hash-modulo filter as New-BucketFilterKql
  # but at modulus T*K with index N + j*T. Math: a row in parent bucket N
  # satisfies hash%T == N, i.e. hash = T*q + N for some q. Then hash%(T*K) =
  # N + T*(q % K), so the K possible values are {N, N+T, N+2T, ..., N+(K-1)T}.
  # Picking sub-index j selects exactly 1/K of the parent-N rows. Lossless;
  # K sub-buckets together = the original parent bucket.
  param(
    [int]$ParentBucketCount,
    [int]$ParentBucketIndex,
    [int]$SubBucketCount,
    [int]$SubBucketIndex,
    [string]$ReportName = ''
  )
  $newCount = $ParentBucketCount * $SubBucketCount
  $newIndex = $ParentBucketIndex + ($SubBucketIndex * $ParentBucketCount)
  return (New-BucketFilterKql -BucketCount $newCount -BucketIndex $newIndex -ReportName $ReportName)
}

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

function Get-ReportExcludeJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReportName)

    if ($null -eq $script:_ReportExcludeJsonCache) { $script:_ReportExcludeJsonCache = @{} }
    if ($script:_ReportExcludeJsonCache.ContainsKey($ReportName)) {
        return $script:_ReportExcludeJsonCache[$ReportName]
    }
    $result = $null
    if (-not [string]::IsNullOrWhiteSpace($global:SettingsPath)) {
        # Customer .custom.json wins over repo-shipped .json (matches the
        # .locked.yaml / .custom.yaml convention used elsewhere in v2.2).
        $candidates = @(
            (Join-Path $global:SettingsPath ('{0}.exclude.custom.json' -f $ReportName)),
            (Join-Path $global:SettingsPath ('{0}.exclude.json'        -f $ReportName))
        )
        foreach ($path in $candidates) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            try {
                $result = [pscustomobject]@{
                    Path = $path
                    Body = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
                }
                break
            } catch {
                Write-Warn2 ("[exclude] failed to parse {0}: {1}" -f $path, $_.Exception.Message)
            }
        }
    }
    $script:_ReportExcludeJsonCache[$ReportName] = $result
    return $result
}

function Get-GlobalExcludeJson {
    [CmdletBinding()]
    param()
    if ($null -ne $script:_GlobalExcludeJsonCache) {
        if ($script:_GlobalExcludeJsonCache -is [string] -and $script:_GlobalExcludeJsonCache -eq '__none__') { return $null }
        return $script:_GlobalExcludeJsonCache
    }
    $script:_GlobalExcludeJsonCache = '__none__'
    if ([string]::IsNullOrWhiteSpace($global:SettingsPath)) { return $null }
    $path = Join-Path $global:SettingsPath $script:_GlobalExcludeFileName
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $obj = [pscustomobject]@{
            Path = $path
            Body = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        $script:_GlobalExcludeJsonCache = $obj
        Write-Info ("[exclude] global fallback loaded: {0}" -f $path)
        return $obj
    } catch {
        Write-Warn2 ("[exclude] failed to parse global file {0}: {1}" -f $path, $_.Exception.Message)
        return $null
    }
}

function Get-ExcludedListForReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]  $ReportName,
        [Parameter(Mandatory)][string[]]$PropertyNames,
        [string]                        $Token = ''
    )
    $loaded = Get-ReportExcludeJson -ReportName $ReportName
    $list   = @()
    $found  = $false
    if ($null -ne $loaded) {
        $body = $loaded.Body
        # Bare array file: maps to the first property name requested
        if ($body -is [System.Array]) {
            $list  = $body
            $found = $true
        } else {
            foreach ($p in $PropertyNames) {
                if ($body.PSObject.Properties[$p] -and $body.$p) {
                    $list  = $body.$p
                    $found = $true
                    break
                }
            }
        }
    }
    # Global fallback ONLY for whitelisted tokens (e.g. ExcludedAssetTags) when
    # per-report file didn't carry the property.
    if (-not $found -and -not [string]::IsNullOrWhiteSpace($Token) -and ($script:_GlobalExcludeTokens -contains $Token)) {
        $g = Get-GlobalExcludeJson
        if ($null -ne $g) {
            foreach ($p in $PropertyNames) {
                if ($g.Body.PSObject.Properties[$p] -and $g.Body.$p) {
                    $list = $g.Body.$p
                    break
                }
            }
        }
    }
    $clean = @($list | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ })
    return $clean
}

function Resolve-ExcludePlaceholders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName
    )
    # Block-marker form ONLY (portal-safe). Source query must wrap a default
    # `let _foo = dynamic([]);` between begin/end line-comment markers, e.g.:
    #
    #     //__EXCLUDED_CVES_BEGIN__
    #     let _excludedCves = dynamic([]);
    #     //__EXCLUDED_CVES_END__
    #
    # Engine replaces the ENTIRE block with a real let binding sourced from
    # <ReportName>.exclude.custom.json (or .exclude.json fallback). The let
    # variable name is recovered from the inline default so it doesn't have
    # to be hardcoded per token. Without engine substitution (raw portal
    # paste) the inline default applies and the query parses fine.

    foreach ($token in $script:_ExcludeTokenMap.Keys) {
        $tokenName  = $token.Trim('_')   # 'EXCLUDED_CVES'
        $beginMark  = ('//__{0}_BEGIN__' -f $tokenName)
        $endMark    = ('//__{0}_END__'   -f $tokenName)

        $blockRx   = [regex]::Escape($beginMark) + '(?<body>.*?)' + [regex]::Escape($endMark)
        $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $bodyMatch.Success) { continue }

        $items = @(Get-ExcludedListForReport -ReportName $ReportName -PropertyNames $script:_ExcludeTokenMap[$token] -Token $token)
        $kqlArray = if ($items.Count -gt 0) {
            '[' + (($items | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' }) -join ',') + ']'
        } else {
            '[]'
        }
        $varName = if ($bodyMatch.Groups['body'].Value -match 'let\s+(\w+)\s*=') { $matches[1] } else { '_excludedItems' }
        $newBlock = ($beginMark + [Environment]::NewLine +
                     ('let {0} = dynamic({1});' -f $varName, $kqlArray) + [Environment]::NewLine +
                     $endMark)
        $Query = $Query.Replace($bodyMatch.Value, $newBlock)
        Write-Info ("[exclude] {0}: substituted block {1} ({2}) with {3} item(s)" -f $ReportName, $tokenName, $varName, $items.Count)
    }
    return $Query
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
    $blockRx   = [regex]::Escape($script:_StaleDeviceFilterBeginMark) + '(?<body>.*?)' + [regex]::Escape($script:_StaleDeviceFilterEndMark)
    $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $bodyMatch.Success) { return $Query }

    # Mode: 'off' (default) | 'lenient' | 'strict'. 'off' means no-op (skip).
    $mode = 'off'
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RA_StaleDeviceFilter)) {
        $modeRaw = ([string]$global:SI_RA_StaleDeviceFilter).Trim().ToLowerInvariant()
        if ($modeRaw -in @('lenient','strict')) { $mode = $modeRaw }
    }
    if ($mode -eq 'off') {
        # Off -- leave no-op block. Don't log per-report; would spam.
        return $Query
    }

    # Threshold from the existing solution-wide freshness global. If unset
    # or non-positive, fall back to a sensible default of 30 days (matches
    # asset-profiling default).
    $maxAge = 30
    if ($null -ne $global:SI_ActiveStaleDays) {
        try {
            $candidate = [int]$global:SI_ActiveStaleDays
            if ($candidate -gt 0) { $maxAge = $candidate }
        } catch { }
    }

    $newBody  = ([Environment]::NewLine +
                 (New-StaleDeviceFilterKql -MaxAgeDays $maxAge -Mode $mode) +
                 [Environment]::NewLine + '              ')
    $newBlock = ($script:_StaleDeviceFilterBeginMark + $newBody + $script:_StaleDeviceFilterEndMark)
    $result   = $Query.Replace($bodyMatch.Value, $newBlock)
    Write-Info ("[stale-device] {0}: applied MaxAgeDays={1} Mode={2}" -f $ReportName, $maxAge, $mode)
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

function Build-WeightedFactorsKql {
    <# Generates the KQL chain that computes per-field multipliers (case() over
       a value->multiplier map), combines them per Combine mode, and emits the
       3 columns RiskScore_Weight_Factor + RiskScore_Weight_Detailed (and the
       intermediate RF_W_<field> per-field multiplier).
       Pure JSON->KQL transform -- no rule semantics hardcoded. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Config)

    $nl  = [Environment]::NewLine
    $sb  = New-Object System.Text.StringBuilder

    # Sanitize: keep only fields that have a non-empty valueMap
    $valid = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Config.Fields) {
        if (-not $f.field) { continue }
        if ($null -eq $f.valueMap) { continue }
        $mapProps = @($f.valueMap.PSObject.Properties)
        if ($mapProps.Count -eq 0) { continue }
        [void]$valid.Add($f)
    }

    # Per-field case() extends:
    #   RF_W_<safeFieldName> = case(
    #       tolower(trim(" ", tostring(column_ifexists("<field>", "")))) == "critical", 1.5,
    #       ... ,
    #       <default | 1.0>
    #   )
    foreach ($f in $valid) {
        $field      = [string]$f.field
        $safeName   = ($field -replace '[^A-Za-z0-9_]','_')
        $defaultMul = if ($f.PSObject.Properties['default'] -and ($null -ne $f.default)) {
                          [double]$f.default
                      } else { 1.0 }

        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        # BASIS-100 INTEGERS. JSON values are now integers (Critical=150
        # = 1.5x, Low=105 = 1.05x, default=100 = 1.0x). Engine post-query divides by
        # 100 to apply the weight. Integers eliminate the locale-decimal trap (1.5
        # parsing as 15 on da-DK).
        [void]$sb.AppendFormat($inv, '| extend RF_W_{0} = case({1}', $safeName, $nl)
        foreach ($prop in $f.valueMap.PSObject.Properties) {
            $matchValue = ([string]$prop.Name -replace '"','\"').ToLowerInvariant()
            $multInt    = [int]([double]$prop.Value)
            [void]$sb.AppendFormat($inv, '      tolower(trim(" ", tostring(column_ifexists("{0}", "")))) == "{1}", {2},{3}',
                $field, $matchValue, $multInt, $nl)
        }
        $defaultMulInt = [int]([double]$defaultMul)
        [void]$sb.AppendFormat($inv, '      {0}{1}){1}', $defaultMulInt, $nl)
    }

    # Combine per-field multipliers into RiskScore_Weight_Factor
    $multParts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $valid) {
        $safeName = ([string]$f.field -replace '[^A-Za-z0-9_]','_')
        [void]$multParts.Add(('RF_W_{0}' -f $safeName))
    }
    # BASIS-100 combine math. All factors are integers where 100 = 1.0x
    # baseline. Combine modes adapted accordingly:
    #   product:       (f1 * f2 * ... * fN) / 100^(N-1)
    #                  e.g. cmdbCriticality=Medium(110) * cmdbDataSensitivity=Confidential(150) / 100 = 165 (1.65x)
    #   max:           max_of(100, f1, f2, ...)
    #                  e.g. max(100, 110, 150) = 150 (1.50x) -- worst single signal wins
    #   sum-of-deltas: 100 + sum(fi - 100 for each field)
    #                  e.g. 100 + (110-100) + (150-100) = 160 (1.60x) -- additive lift
    switch ($Config.Combine) {
        'max' {
            $multExpr = if ($multParts.Count -gt 0) { 'max_of(100,' + ($multParts -join ',') + ')' } else { '100' }
        }
        'sum-of-deltas' {
            $deltaParts = New-Object System.Collections.Generic.List[string]
            foreach ($p in $multParts) { [void]$deltaParts.Add(('({0} - 100)' -f $p)) }
            $multExpr = if ($deltaParts.Count -gt 0) { '100 + ' + ($deltaParts -join ' + ') } else { '100' }
        }
        default {
            # product: chain multiplications then divide by 100^(N-1) to stay basis-100.
            if     ($multParts.Count -eq 0) { $multExpr = '100' }
            elseif ($multParts.Count -eq 1) { $multExpr = $multParts[0] }
            else {
                $divisor = [int][Math]::Pow(100, $multParts.Count - 1)
                $multExpr = '(' + ($multParts -join ' * ') + ") / $divisor"
            }
        }
    }
    if ($Config.MaxMultiplier -gt 0) {
        # integer cap (basis-100). 500 = 5x cap. All-integer min_of()
        # avoids any decimal/locale formatting concerns.
        $maxMul = [int]([double]$Config.MaxMultiplier)
        $multExpr = ('min_of({0}, {1})' -f $maxMul, $multExpr)
    }
    [void]$sb.AppendFormat('| extend RiskScore_Weight_Factor = {0}{1}', $multExpr, $nl)
    # Engine-compat alias -- existing post-query layer reads `RiskFactor_Weight`
    # to compute RiskScoreTotal_Weighted = RiskScoreTotal * RiskFactor_Weight.
    [void]$sb.Append('| extend RiskFactor_Weight = RiskScore_Weight_Factor' + $nl)

    # Detail string: ;-joined "<field>=<currentValue>" for fields whose
    # multiplier resolved to something other than 1.0 (i.e. the value
    # actually contributed to the weight). Reader sees WHY this row got weighted.
    $detailedParts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $valid) {
        $field    = [string]$f.field
        $safeName = ($field -replace '[^A-Za-z0-9_]','_')
        [void]$detailedParts.Add(
            ('iff(RF_W_{0} != 100, pack_array(strcat("{1}=", tostring(column_ifexists("{1}", "")))), dynamic([]))' -f $safeName, $field)
        )
    }
    if ($detailedParts.Count -gt 0) {
        [void]$sb.AppendFormat('| extend RiskScore_Weight_Detailed = strcat_array(array_concat({0}), ";"){1}',
            ($detailedParts -join ', '), $nl)
    } else {
        [void]$sb.Append('| extend RiskScore_Weight_Detailed = ""' + $nl)
    }

    return $sb.ToString().TrimEnd()
}

function Resolve-WeightedFactorsBlock {
    <# Replaces the //__WEIGHTED_FACTORS_BEGIN__ ... //__WEIGHTED_FACTORS_END__
       block with the engine-generated KQL chain (or leaves the no-op default
       in place when no JSON config is present for this engine). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName,
        [Parameter(Mandatory)][string]$Engine
    )
    $beginMark = $script:_WeightedFactorsBeginMark
    $endMark   = $script:_WeightedFactorsEndMark
    if ($Query.IndexOf($beginMark) -lt 0 -or $Query.IndexOf($endMark) -lt 0) { return $Query }

    $cfg = Get-WeightedFactorsConfig -ReportName $ReportName -Engine $Engine
    if ($null -eq $cfg -or @($cfg.Fields).Count -eq 0) { return $Query }   # leave no-op default

    $blockRx   = [regex]::Escape($beginMark) + '(?<body>.*?)' + [regex]::Escape($endMark)
    $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $bodyMatch.Success) { return $Query }

    $generatedKql = Build-WeightedFactorsKql -Config $cfg
    $newBlock = ($beginMark + [Environment]::NewLine + $generatedKql + [Environment]::NewLine + $endMark)
    $Query = $Query.Replace($bodyMatch.Value, $newBlock)
    Write-Verbose ("[weight] {0} (engine={1}): substituted {2} weighted-factor field(s) (combine={3}, source={4})" -f $ReportName, $cfg.Engine, @($cfg.Fields).Count, $cfg.Combine, (Split-Path -Leaf $cfg.Path))
    return $Query
}

function Get-RowValue {
  param(
    [Parameter(Mandatory=$true)] $Row,
    [Parameter(Mandatory=$true)] [string[]] $Names
  )
  foreach ($n in $Names) {
    if ($Row -and ($Row.PSObject.Properties.Name -contains $n)) {
      $v = $Row.$n
      if ($null -ne $v -and ("" + $v).Trim() -ne "") { return $v }
    }
  }
  return $null
}

function ConvertTo-NormalizedString {
  param([AllowNull()] $Value)

  if ($null -eq $Value) { return "" }

  # arrays / IEnumerable -> stable string
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($x in $Value) {
      if ($null -eq $x) { continue }
      $s = ("" + $x).Trim()
      if ($s -ne "") { [void]$items.Add($s) }
    }
    if ($items.Count -eq 0) { return "" }
    $arr = $items.ToArray()
    [array]::Sort($arr)
    return ($arr -join ";").ToLowerInvariant()
  }

  return (("" + $Value).Trim()).ToLowerInvariant()
}

function New-DedupeKey {
  <#
    Generic key builder.

    KeyCandidates is tried in order. Each candidate is an array of "field alternatives".
    Example:
      @(
        @(@("DeviceId","MachineId"), @("ConfigurationId","Id")),
        @(@("EventId","RecordId","Id"))
      )
    Meaning:
      - For the first candidate, we need one value from (DeviceId OR MachineId) AND one value from (ConfigurationId OR Id)
      - If any part is missing/blank, the candidate fails and we try next.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] $Row,
    [Parameter(Mandatory=$true)] [object[]] $KeyCandidates
  )

  foreach ($candidate in $KeyCandidates) {
    $parts = New-Object System.Collections.Generic.List[string]
    $ok = $true

    foreach ($fieldAlternatives in $candidate) {
      $v = Get-RowValue -Row $Row -Names @($fieldAlternatives)
      $s = ConvertTo-NormalizedString $v
      if ($s -eq "") { $ok = $false; break }
      [void]$parts.Add($s)
    }

    if ($ok -and $parts.Count -gt 0) {
      return ($parts.ToArray() -join "|")
    }
  }

  return ""
}

function Get-GenericCompletenessScore {
  param(
    [Parameter(Mandatory=$true)] $Row,
    [string[]] $ColumnsToConsider = @()
  )

  $props =
    if ($ColumnsToConsider.Count -gt 0) {
      $Row.PSObject.Properties | Where-Object { $ColumnsToConsider -contains $_.Name }
    } else {
      $Row.PSObject.Properties
    }

  $filled = 0
  $total = 0
  $stringLen = 0

  foreach ($p in $props) {
    $total++
    $v = $p.Value
    if ($null -eq $v) { continue }

    if ($v -is [string]) {
      $t = $v.Trim()
      if ($t -eq "") { continue }
      $filled++
      $stringLen += $t.Length
      continue
    }

    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
      $any = $false
      foreach ($x in $v) {
        if ($null -ne $x -and ("" + $x).Trim() -ne "") { $any = $true; break }
      }
      if (-not $any) { continue }
      $filled++
      continue
    }

    $filled++
  }

  return [pscustomobject]@{
    Filled    = $filled
    Total     = $total
    StringLen = $stringLen
  }
}

function Select-BestRow {
  <#
    Generic "best row" selector.

    PriorityRules (optional) are evaluated first (in order). If a rule can decide, it wins.
    If not, we fall back to generic completeness.

    PriorityRules examples:
      @{ Column="CriticalityTier"; Type="int"; Direction="asc"; MissingLast=$true }
      @{ Column="Impact"; Type="int"; Direction="desc"; MissingLast=$true }

    Supported Type: int | double | string
    Direction: asc | desc
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] [object[]] $Rows,
    [object[]] $PriorityRules = @(),
    [string[]] $CompletenessColumns = @()
  )

  if ($Rows.Count -eq 1) { return $Rows[0] }

  $best = $null
  foreach ($r in $Rows) {
    if ($null -eq $best) { $best = $r; continue }

    $picked = $false

    foreach ($rule in $PriorityRules) {
      if ($null -eq $rule) { continue }
      $col = $rule.Column
      if (-not $col) { continue }

      $hasA = ($r.PSObject.Properties.Name -contains $col)
      $hasB = ($best.PSObject.Properties.Name -contains $col)

      $a = if ($hasA) { $r.$col } else { $null }
      $b = if ($hasB) { $best.$col } else { $null }

      $aEmpty = ($null -eq $a -or ("" + $a).Trim() -eq "")
      $bEmpty = ($null -eq $b -or ("" + $b).Trim() -eq "")

      if ($aEmpty -and $bEmpty) { continue }

      $missingLast = $true
      if ($rule.ContainsKey("MissingLast")) { $missingLast = [bool]$rule.MissingLast }

      if ($aEmpty -ne $bEmpty) {
        if ($missingLast) {
          if (-not $aEmpty) { $best = $r }
        } else {
          if ($aEmpty) { $best = $r }
        }
        $picked = $true
        break
      }

      $type = ("" + $rule.Type).ToLowerInvariant()
      $dir  = ("" + $rule.Direction).ToLowerInvariant()

      $cmp = 0
      try {
        if ($type -eq "int") {
          $ai = [int]$a; $bi = [int]$b
          $cmp = $ai.CompareTo($bi)
        } elseif ($type -eq "double") {
          $ad = [double]$a; $bd = [double]$b
          $cmp = $ad.CompareTo($bd)
        } else {
          $as = ConvertTo-NormalizedString $a
          $bs = ConvertTo-NormalizedString $b
          $cmp = [string]::Compare($as, $bs, $true)
        }
      } catch { $cmp = 0 }

      if ($cmp -ne 0) {
        if ($dir -eq "asc") {
          if ($cmp -lt 0) { $best = $r }
        } else {
          if ($cmp -gt 0) { $best = $r }
        }
        $picked = $true
        break
      }
    }

    if ($picked) { continue }

    $sA = Get-GenericCompletenessScore -Row $r -ColumnsToConsider $CompletenessColumns
    $sB = Get-GenericCompletenessScore -Row $best -ColumnsToConsider $CompletenessColumns

    if ($sA.Filled -gt $sB.Filled) { $best = $r; continue }
    if ($sA.Filled -lt $sB.Filled) { continue }

    if ($sA.StringLen -gt $sB.StringLen) { $best = $r; continue }
    if ($sA.StringLen -lt $sB.StringLen) { continue }

    # stable final tie-breaker
    $sigA = ConvertTo-NormalizedString (($r.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "|")
    $sigB = ConvertTo-NormalizedString (($best.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "|")
    if ([string]::Compare($sigA, $sigB, $true) -lt 0) { $best = $r }
  }

  return $best
}

function Deduplicate-RowsGeneric {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] $Rows,
    [Parameter(Mandatory=$true)] [object[]] $KeyCandidates,
    [object[]] $PriorityRules = @(),
    [string[]] $CompletenessColumns = @(),
    [switch] $KeepUnkeyed
  )

  $rowsArr = @()
  foreach ($r in $Rows) { if ($null -ne $r) { $rowsArr += ,$r } }
  if ($rowsArr.Count -eq 0) { return @() }

  foreach ($r in $rowsArr) {
    $k = New-DedupeKey -Row $r -KeyCandidates $KeyCandidates
    $r | Add-Member -NotePropertyName "__DedupeKey" -NotePropertyValue $k -Force
  }

  $out = New-Object System.Collections.Generic.List[object]

  $groups = $rowsArr | Group-Object "__DedupeKey"
  foreach ($g in $groups) {
    $key = $g.Name

    if ($key -eq "" -and -not $KeepUnkeyed) {
      foreach ($r in $g.Group) { [void]$out.Add($r) }
      continue
    }

    if ($g.Count -eq 1) {
      [void]$out.Add($g.Group[0])
      continue
    }

    $best = Select-BestRow -Rows $g.Group -PriorityRules $PriorityRules -CompletenessColumns $CompletenessColumns
    [void]$out.Add($best)
  }

  return @($out.ToArray())
}

function Deduplicate-Rows {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] $Rows
  )

  # ----- StrictMode-safe global checks -----

  $KeyCandidates = $null
  if (Get-Variable -Name DedupeKeyCandidates -Scope Global -ErrorAction SilentlyContinue) {
      $KeyCandidates = $global:DedupeKeyCandidates
  }

  if (-not $KeyCandidates) {
      $KeyCandidates = @(
        @(@("DeviceId","DeviceGuid","MachineId","HostId"), @("ConfigurationId","ControlId","RuleId","RecommendationId","Id")),
        @(@("AadDeviceId","AzureAdDeviceId","DeviceKey"), @("ConfigurationId","ControlId","RuleId","RecommendationId","Id")),
        @(@("EventId","AlertId","IncidentId","RecordId","Id")),
        @(@("DeviceId","MachineId","AadDeviceId","DeviceKey","AssetName","DeviceName","Computer","HostName"), @("Title","Name","DisplayName"))
      )
  }

  $PriorityRules = $null
  if (Get-Variable -Name DedupePriorityRules -Scope Global -ErrorAction SilentlyContinue) {
      $PriorityRules = $global:DedupePriorityRules
  }

  if (-not $PriorityRules) {
      $PriorityRules = @(
        @{ Column="CriticalityTier"; Type="int"; Direction="asc"; MissingLast=$true },
        @{ Column="Impact";         Type="int"; Direction="desc"; MissingLast=$true }
      )
  }

  $CompletenessColumns = $null
  if (Get-Variable -Name DedupeCompletenessColumns -Scope Global -ErrorAction SilentlyContinue) {
      $CompletenessColumns = $global:DedupeCompletenessColumns
  }

  if (-not $CompletenessColumns) {
      $CompletenessColumns = @()
  }

  return Deduplicate-RowsGeneric `
    -Rows $Rows `
    -KeyCandidates $KeyCandidates `
    -PriorityRules $PriorityRules `
    -CompletenessColumns $CompletenessColumns `
    -KeepUnkeyed
}



function Apply-ScopeFilter {
  [CmdletBinding()]
  param(
    [Parameter()][AllowNull()]$Rows,
    [Parameter(Mandatory)][string]$ColumnName,
    [Parameter()][AllowNull()]$Scope
  )

  # Always return an array, never $null
  if ($null -eq $Rows) { return @() }

  # Normalize Rows to a plain array (works for List[object] too)
  $rowsArr = @()
  foreach ($r in $Rows) { $rowsArr += ,$r }

  # If no scope -> pass-through
  if ($null -eq $Scope -or ($Scope -is [string] -and [string]::IsNullOrWhiteSpace($Scope))) {
    return @($rowsArr)
  }

  # Normalize scope to array
  if ($Scope -is [string]) {
    $Scope = $Scope -split '\s*,\s*'
  }
  elseif ($Scope -isnot [System.Collections.IEnumerable]) {
    $Scope = @($Scope)
  }
  if (@($Scope).Count -eq 0) { return @($rowsArr) }

  # Filter (always return array)
  $filtered = @(Filter-ObjectsByColumn -InputObject $rowsArr -ColumnToFilter $ColumnName -InScopeData @($Scope) -CaseInsensitive)
  return @($filtered)
}

function ConvertTo-PSObjectDeep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $InputObject,
        [switch] $StripOData,
        [switch] $CastPrimitiveArrays,
        [switch] $ConvertArraysToString,
        [string] $ArrayJoinChar = ', ',
        [switch] $PreserveRootArray = $true
    )

    function _IsPrimitive([object]$x) {
        if ($null -eq $x) { return $true }
        $t = $x.GetType()
        return ($t.IsPrimitive -or $t.FullName -in @(
            'System.String','System.Decimal','System.DateTime','System.Guid','System.TimeSpan'
        ))
    }

    function _Convert([object]$obj, [bool]$isRoot = $false) {

        if ($null -eq $obj) { return $null }

        if ($obj -is [pscustomobject]) {
            $ordered = [ordered]@{}
            foreach ($p in $obj.PSObject.Properties) {
                if ($StripOData -and ($p.Name -like '*@odata*')) { continue }
                $ordered[$p.Name] = _Convert $p.Value $false
            }
            return [pscustomobject]$ordered
        }

        if ($obj -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($k in $obj.Keys) {
                if ($StripOData -and ($k -is [string]) -and ($k -like '*@odata*')) { continue }
                $ordered[$k] = _Convert $obj[$k] $false
            }
            return [pscustomobject]$ordered
        }

        if (($obj -is [System.Collections.IEnumerable]) -and -not ($obj -is [string])) {

            $items = @()
            foreach ($item in $obj) { $items += ,(_Convert $item $false) }

            if ($ConvertArraysToString -and -not ($isRoot -and $PreserveRootArray)) {
                $pieces = foreach ($e in $items) {
                    if (_IsPrimitive $e) { $e }
                    else {
                        try { ($e | ConvertTo-Json -Compress -Depth 12) }
                        catch { [string]$e }
                    }
                }
                return ($pieces -join $ArrayJoinChar)
            }

            if ($CastPrimitiveArrays -and -not $ConvertArraysToString -and $items.Count -gt 0) {

                # StrictMode-safe: always force arrays from pipelines
                $nonNull   = @($items | Where-Object { $_ -ne $null })
                $typeNames = @($nonNull | ForEach-Object { $_.GetType().FullName } | Select-Object -Unique)

                $allPrim = (@($nonNull | ForEach-Object { _IsPrimitive $_ } | Where-Object { -not $_ }).Count -eq 0)

                if ($allPrim -and $typeNames.Count -eq 1) {
                    switch ($typeNames[0]) {
                        'System.String'  { return [string[]] $items }
                        'System.Int32'   { return [int[]]    $items }
                        'System.Int64'   { return [long[]]   $items }
                        'System.Double'  { return [double[]] $items }
                        'System.Boolean' { return [bool[]]   $items }
                    }
                }
            }

            return @($items)
        }

        return $obj
    }

    $rootIsArray = (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]))

    if ($rootIsArray -and $PreserveRootArray) {
        $out = @()
        foreach ($i in $InputObject) { $out += ,(_Convert $i $false) }
        return @($out)
    }

    return (_Convert $InputObject $true)
}

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

function Calculate-RiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [object[]] $Rows,
        [Parameter(Mandatory=$true)] [psobject] $RiskIndex,
        [string] $SecurityDomain,
        [Parameter(Mandatory=$true)] [string] $CategoryInputName,
        [Parameter(Mandatory=$true)] [string] $SubCategoryInputName,
        [Parameter(Mandatory=$true)] [string] $ConfigurationIdInputName,
        [Parameter(Mandatory=$true)] [string] $SecuritySeverityInputName,
        [Parameter(Mandatory=$true)] [string] $CriticalityTierLevelInputName,
        [string] $SecurityDomainInputName,
        [string[]] $OutputPropertyOrder,
        [string[]] $SortBy,
        [switch]   $Descending,

        [string] $RiskConsequenceScoreOutputName  = 'RiskConsequenceScore_SecuritySeverity',
        [string] $RiskProbabilityScoreOutputName  = 'RiskProbablityScore_CriticialityTierLevel',
        [string] $RiskScoreOutputName             = 'RiskScore',

        # ReportName from the YAML -- stamped into every row as
        # AssetDetectedInReportName so operators can hunt back which report
        # produced which finding. Auto-added (no need to list in OutputPropertyOrder).
        [string] $ReportName,

        # Risk factor columns (KQL can output these; treat 0/1/true/false/yes/no)
        [string] $RiskFactorConsequenceInputName  = 'riskfactor_consequence',
        [string] $RiskFactorProbabilityInputName  = 'riskfactor_probability',

        [switch] $Trace
    )

    function _get([object]$o,[string]$n) {
        if ($null -eq $o -or [string]::IsNullOrWhiteSpace([string]$n)) { return $null }
        $p = $o.PSObject.Properties[$n]
        if ($null -eq $p) { return $null }
        $p.Value
    }

    function _mkKey([hashtable]$kv,[string[]]$pattern) {
        $vals = foreach ($c in $pattern) {
            $v = $kv[$c]
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    function _asBit([object]$v) {
        if ($null -eq $v) { return 0 }
        if ($v -is [bool]) { return [int]($v -eq $true) }
        $s = ([string]$v).Trim().ToLowerInvariant()
        if ($s -in @('1','true','yes','y')) { return 1 }
        0
    }

    # ---- ONE safe-math helper for ALL profilers ----------------------------
    # Single source of truth for: RiskConsequenceScore = consBase + rfCons,
    # RiskProbabilityScore = probBase + rfProb, RiskScoreTotal = product,
    # RiskScoreTotal_Weighted = product * weight/100. Defensive against null
    # inputs (cast via _toDouble or default 0). Sets ALL 4 stamps atomically
    # so rows can never be in a partial state. Called ONCE per row, after
    # token enrichment has updated rfCons/rfProb. NO other code path stamps
    # these columns.
    function _setScores {
        param(
            [Parameter(Mandatory)] $tmp,
            $ConsBase, $ProbBase, $RfCons, $RfProb, $WeightPct
        )
        # Normalize every input to a usable number. PS5.1 [double] cast on $null
        # returns 0; on a string parses InvariantCulture. Belt-and-suspenders.
        $cb = if ($null -eq $ConsBase) { 0.0 } elseif ($ConsBase -is [double]) { [double]$ConsBase } else { try { [double]$ConsBase } catch { 0.0 } }
        $pb = if ($null -eq $ProbBase) { 0.0 } elseif ($ProbBase -is [double]) { [double]$ProbBase } else { try { [double]$ProbBase } catch { 0.0 } }
        $rc = if ($null -eq $RfCons)   { 0.0 } else { try { [double]$RfCons } catch { 0.0 } }
        $rp = if ($null -eq $RfProb)   { 0.0 } else { try { [double]$RfProb } catch { 0.0 } }
        $wp = if ($null -eq $WeightPct -or [double]$WeightPct -le 0) { 100.0 } else { [double]$WeightPct }

        $consAdj  = $cb + $rc
        $probAdj  = $pb + $rp
        $risk     = $consAdj * $probAdj
        $weighted = $risk * $wp / 100.0

        # HARDCODED canonical column names. Per-report YAML override fields
        # (RiskConsequenceScoreOutputName etc.) are LEGACY -- always write to
        # the same canonical columns so every domain (Endpoint / Identity /
        # Azure / PublicIP) gets consistent column shape in Excel.
        $tmp['RiskConsequenceScore']    = [double]$consAdj
        $tmp['RiskProbabilityScore']    = [double]$probAdj
        $tmp['RiskScoreTotal']          = [double]$risk
        $tmp['RiskScoreTotal_Weighted'] = [int][math]::Floor([double]$weighted)
    }

    function _toDouble([object]$v) {
        if ($null -eq $v) { return 0.0 }
        if ($v -is [double]) { return [double]$v }
        if ($v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [single]) { return [double]$v }
        # CRITICAL: parse with InvariantCulture. On da-DK and other comma-decimal
        # locales, default TryParse reads "1.0" as 10 (period treated as thousands
        # separator). Backend KQL/JSON always emits invariant ("1.0" never "1,0"),
        # so we MUST parse invariant to round-trip correctly.
        $n = 0.0
        [void][double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)
        $n
    }

    function _findScore {
        param(
            [ValidateSet('Consequence','Probability')] [string] $Kind,
            [hashtable] $kv,
            [psobject]  $Index,
            [switch]    $TraceLocal
        )

        $hasDomain = -not [string]::IsNullOrWhiteSpace([string]$kv[$Index.SecurityDomainColumn])

        if ($Kind -eq 'Consequence') {
            $patWith  = $Index.Conseq_WithDomainPatterns
            $mapWith  = $Index.Conseq_WithDomainMaps
            $patNo    = $Index.Conseq_NoDomainPatterns
            $mapNo    = $Index.Conseq_NoDomainMaps
            $scoreCol = $Index.ConseqScoreColumn
            $valCol   = $Index.SevValueColumn
        } else {
            $patWith  = $Index.Prob_WithDomainPatterns
            $mapWith  = $Index.Prob_WithDomainMaps
            $patNo    = $Index.Prob_NoDomainPatterns
            $mapNo    = $Index.Prob_NoDomainMaps
            $scoreCol = $Index.ProbScoreColumn
            $valCol   = $Index.TierValueColumn
        }

        if ($hasDomain) {
            for ($i=0; $i -lt $patWith.Count; $i++) {
                $key = _mkKey -kv $kv -pattern $patWith[$i]
                if ($key -and $mapWith[$i].ContainsKey($key)) {
                    $row = $mapWith[$i][$key]
                    $num = _toDouble $row.$scoreCol
                    if ($TraceLocal) { Write-Host ("[{0}] matched WITH-domain #{1}: {2} -> {3}" -f $Kind, ($i+1), $key, $num) -ForegroundColor Yellow }
                    return @{ Score=$num; PatternIndex=($i+1); ValueColumnUsed=$valCol }
                }
                if ($TraceLocal -and $key) { Write-Host ("[{0}] tried WITH-domain #{1}: {2} -> no match" -f $Kind, ($i+1), $key) -ForegroundColor White }
            }
        }

        for ($j=0; $j -lt $patNo.Count; $j++) {
            $key = _mkKey -kv $kv -pattern $patNo[$j]
            if ($key -and $mapNo[$j].ContainsKey($key)) {
                $row = $mapNo[$j][$key]
                $num = _toDouble $row.$scoreCol
                if ($TraceLocal) { Write-Host ("[{0}] matched NO-domain #{1}: {2} -> {3}" -f $Kind, ($j+1), $key, $num) -ForegroundColor Yellow }
                return @{ Score=$num; PatternIndex=($j+1); ValueColumnUsed=$valCol }
            }
            if ($TraceLocal -and $key) { Write-Host ("[{0}] tried NO-domain #{1}: {2} -> no match" -f $Kind, ($j+1), $key) -ForegroundColor White }
        }

        if ($TraceLocal) { Write-Host ("[{0}] no match -> 0" -f $Kind) -ForegroundColor Red }
        @{ Score=0.0; PatternIndex=0; ValueColumnUsed=$valCol }
    }

    if ([string]::IsNullOrWhiteSpace($SecurityDomainInputName)) {
        $SecurityDomainInputName = $RiskIndex.SecurityDomainColumn
    }

    if ($null -eq $Rows) { return @() }
    $rowsArr = @()
    foreach ($r in $Rows) { if ($null -ne $r) { $rowsArr += ,$r } }
    if ($rowsArr.Count -eq 0) { return @() }

    # row dedup by FULL DIMENSIONAL KEY.
    # Original (.189) used (ConfigurationName, ConfigurationId) only -- too narrow:
    # collapsed legitimate tier x severity buckets (e.g. summary reports that
    # produce one row per (Name, Id, Tier, Severity) bucket lost N-1 of N rows).
    # Now dedups by every dimension column the report's `summarize ... by` clause
    # would emit: SecurityDomain, Category, Subcategory, ConfigurationName,
    # ConfigurationId, CriticalityTier, SecuritySeverity. mv-expand/join inflation
    # still collapses correctly because duplicated rows match on ALL these columns.
    $deduped = New-Object System.Collections.Generic.List[object]
    $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $cnInName = if ($PSBoundParameters.ContainsKey('ConfigurationIdInputName') -and $ConfigurationIdInputName) { $ConfigurationIdInputName } else { 'ConfigurationId' }
    # Bucket-level dimensions (Summary reports) PLUS optional per-row identity columns.
    # Detailed reports carry AssetName/AadDeviceId -- absent on Summary rows so they
    # contribute empty-string and don't change Summary dedup. cmdbCriticality / cmdbDataSensitivity
    # added so cmdb-bucketed Summary rows survive (previously collapsed because key omitted them).
    # ConfigurationId is already in the key via $cnInName -- when each Detailed row carries a
    # unique ConfigurationId (CVE id, scid-*, recommendation id, etc.) the Asset+ConfigurationId
    # pair is the per-row identity. No report-specific columns (CVE_ID, etc.) -- keep generic.
    $keyCols = @('SecurityDomain','Category','Subcategory','ConfigurationName',$cnInName,'CriticalityTier','SecuritySeverity','cmdbCriticality','cmdbDataSensitivity','AssetName','AadDeviceId')
    foreach ($r in $rowsArr) {
        $cn = if ($r.PSObject.Properties['ConfigurationName']) { [string]$r.ConfigurationName } else { '' }
        $ci = if ($r.PSObject.Properties[$cnInName])           { [string]$r.PSObject.Properties[$cnInName].Value } else { '' }
        if ([string]::IsNullOrWhiteSpace($cn) -and [string]::IsNullOrWhiteSpace($ci)) {
            [void]$deduped.Add($r)   # no name/id key -> keep all (defensive)
            continue
        }
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($col in $keyCols) {
            $v = if ($r.PSObject.Properties[$col]) { [string]$r.PSObject.Properties[$col].Value } else { '' }
            [void]$parts.Add($v)
        }
        $key = ($parts -join '|').ToLowerInvariant()
        if ($seenKeys.Add($key)) { [void]$deduped.Add($r) }
    }
    $dedupRemoved = $rowsArr.Count - $deduped.Count
    if ($dedupRemoved -gt 0) {
        Write-Info ("dedup'd {0} duplicate row(s) by ({1}) -- {2} unique row(s) remaining (mv-expand / join collapse)" -f $dedupRemoved, ($keyCols -join ', '), $deduped.Count)
        $rowsArr = @($deduped.ToArray())
    }

    $out   = New-Object System.Collections.Generic.List[object]
    $total = $rowsArr.Count
    $done  = 0

    foreach ($r in $rowsArr) {
        $done++
        Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Status "Row $done of $total" -PercentComplete ([math]::Floor(($done/[math]::Max($total,1))*100))

        $domainValue = if ([string]::IsNullOrWhiteSpace($SecurityDomain)) { _get $r $SecurityDomainInputName } else { $SecurityDomain }

        $kv = @{
            ($RiskIndex.SecurityDomainColumn) = $domainValue
            ($RiskIndex.CategoryColumn)       = _get $r $CategoryInputName
            ($RiskIndex.SubCategoryColumn)    = _get $r $SubCategoryInputName
            ($RiskIndex.ConfigIdColumn)       = _get $r $ConfigurationIdInputName
            ($RiskIndex.SevValueColumn)       = _get $r $SecuritySeverityInputName
            ($RiskIndex.TierValueColumn)      = _get $r $CriticalityTierLevelInputName
        }

        # RiskFactor_Consequence is derived dynamically from RiskFactor_Consequence_Detailed:
        # count of ;-separated non-empty entries. Mirrors the probability convention
        # ("each fired factor adds +1"). Defaults to 0 when Detailed is empty.
        # This count flows into both Layer 2 risk-scoring (consAdj = consBase + rfCons)
        # AND the displayed RiskFactor_Consequence column so they stay in lock-step.
        #
        # TIER 1 -- universal engine fallback: when YAML did NOT extend
        # RiskFactor_Consequence_Detailed, derive a baseline from generic asset signals
        # that genuinely describe IMPACT-IF-COMPROMISED (not likelihood). These signals
        # are universal across every report so a baseline always exists. YAML reports
        # can override with finding-specific factors via `| extend RiskFactor_Consequence_Detailed = "..."`.
        $rfConsDetailedRaw = [string](_get $r 'RiskFactor_Consequence_Detailed')
        if ([string]::IsNullOrWhiteSpace($rfConsDetailedRaw)) {
            $derivedFactors = New-Object System.Collections.Generic.List[string]
            $tierVal = _toDouble (_get $r 'CriticalityTier')
            if ($tierVal -ge 0 -and $tierVal -lt 1) { [void]$derivedFactors.Add('Tier0BlastRadius') }   # Tier 0 only
            $cmdbCrit = [string](_get $r 'cmdbCriticality')
            if ($cmdbCrit -ieq 'Critical') { [void]$derivedFactors.Add('BusinessCriticalAsset') }
            $cmdbSens = [string](_get $r 'cmdbDataSensitivity')
            if     ($cmdbSens -ieq 'Restricted')   { [void]$derivedFactors.Add('RestrictedDataAccess') }
            elseif ($cmdbSens -ieq 'Confidential') { [void]$derivedFactors.Add('ConfidentialDataAccess') }
            $rfConsDetailedRaw = ($derivedFactors -join ';')
        }
        if ([string]::IsNullOrWhiteSpace($rfConsDetailedRaw)) {
            $rfCons = 0
        } else {
            $rfCons = @($rfConsDetailedRaw -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
        }
        $rfProb = [int](_toDouble (_get $r $RiskFactorProbabilityInputName))

        $consBase = _findScore -Kind 'Consequence' -kv $kv -Index $RiskIndex -TraceLocal:$Trace
        $probBase = _findScore -Kind 'Probability' -kv $kv -Index $RiskIndex -TraceLocal:$Trace

        $consAdj = ([double]$consBase.Score) + ([double]$rfCons)
        $probAdj = ([double]$probBase.Score) + ([double]$rfProb)
        $risk    = $consAdj * $probAdj

        # Layer 3 -- business-criticality multiplier in BASIS-100.
        # RiskFactor_Weight is now an INTEGER on the basis-100 scale: Critical=150
        # (1.5x), High=125 (1.25x), Medium=110 (1.1x), Low=105 (1.05x cmdb-tracked
        # uplift), default=100 (1.0x = no amplification when CMDB is OFF or
        # cmdbCriticality is empty). Integer arithmetic dodges all locale-decimal
        # traps (1.5 -> "1,5" -> 15 on da-DK). Engine divides by 100 to apply.
        $rfWeightPct = 100
        if ($r.PSObject.Properties['RiskFactor_Weight']) {
            $w = _toDouble (_get $r 'RiskFactor_Weight')
            if ($w -gt 0) { $rfWeightPct = [int]$w }
        }
        $riskWeighted = [double]$risk * [double]$rfWeightPct / 100.0

        $tmp = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $tmp[$p.Name] = $p.Value }

        $tmp[$SecurityDomainInputName] = $domainValue
        # Score stamping deferred to ONE call to _setScores after token enrichment
        # below -- so per-report YAMLs that don't project RiskFactor_*_Detailed
        # inline (Identity reports etc.) still get the post-enrichment counts
        # reflected in the final score. NO other path stamps these columns.

        # Force-cast known numeric columns from string -> double using InvariantCulture.
        # Az.OperationalInsightsQuery returns every cell as string; Excel + ImportExcel
        # then re-parse using the OS locale. On da-DK that turns "7.8" into 78
        # (`.` interpreted as thousands separator). Pre-coercing to [double] makes Excel
        # store the value as a real numeric and respect locale only on display.
        $__numericCols = @('Impact','CvssScore','MaxImpact','AvgImpact','ConfigurationImpact','CredentialExpiryDays','LastSignInDays','DaysInactive')
        foreach ($__nc in $__numericCols) {
            if ($tmp.Contains($__nc) -and $null -ne $tmp[$__nc] -and -not ([string]::IsNullOrWhiteSpace([string]$tmp[$__nc]))) {
                $__v = $tmp[$__nc]
                if ($__v -isnot [double] -and $__v -isnot [int] -and $__v -isnot [long]) {
                    $__d = 0.0
                    if ([double]::TryParse([string]$__v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$__d)) {
                        $tmp[$__nc] = $__d
                    }
                }
            }
        }

        if (-not $tmp.Contains('RiskFactor_Probability'))          { $tmp['RiskFactor_Probability']          = [int]$rfProb }
        if (-not $tmp.Contains('RiskFactor_Weight'))               { $tmp['RiskFactor_Weight']               = [double]$rfWeight }
        # Guarantee the *Detailed companion columns exist on every row. YAML may
        # populate them (e.g. RiskFactor_Probability_Detailed = "ExploitSignals;Internet-Exposed");
        # when not, the column is still present (empty) so dashboards / mail templates
        # always find it. Consequence_Detailed documents what drives the Consequence
        # score (severity tier, business impact, blast radius) -- populated per-report
        # via `| extend RiskFactor_Consequence_Detailed = "..."`. Engine derives the
        # numeric count above (lock-step with the entry list).
        if (-not $tmp.Contains('RiskFactor_Consequence_Detailed')) { $tmp['RiskFactor_Consequence_Detailed'] = '' }
        if (-not $tmp.Contains('RiskFactor_Probability_Detailed')) { $tmp['RiskFactor_Probability_Detailed'] = '' }

        # Engine-level RiskFactor_*_Detailed token enrichment (audit Tier D).
        # Reads flat columns already in Profile_CL via row join (MDE_*, EG_*) and
        # appends standard tokens to the existing semicolon-list. Tokens are
        # ADD-only -- engine never removes YAML-emitted tokens. Idempotent: a
        # token only appears once even if the source column is set on multiple
        # joined sources.
        $rfProbExisting = [string]$tmp['RiskFactor_Probability_Detailed']
        $rfConsExisting = [string]$tmp['RiskFactor_Consequence_Detailed']
        $probTokens = [System.Collections.Generic.HashSet[string]]::new()
        $consTokens = [System.Collections.Generic.HashSet[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($rfProbExisting)) {
            foreach ($t in $rfProbExisting -split ';') { $tt = $t.Trim(); if ($tt) { [void]$probTokens.Add($tt) } }
        }
        if (-not [string]::IsNullOrWhiteSpace($rfConsExisting)) {
            foreach ($t in $rfConsExisting -split ';') { $tt = $t.Trim(); if ($tt) { [void]$consTokens.Add($tt) } }
        }
        function _rowHas { param($colNames) foreach ($c in $colNames) { if ($r.PSObject.Properties[$c]) { return $true } } return $false }
        function _rowVal { param($colNames) foreach ($c in $colNames) { if ($r.PSObject.Properties[$c]) { return $r.$c } } return $null }
        # ---- Probability tokens (likelihood amplifiers) ----
        $isCompromised = _rowVal @('IsCompromisedRecently','EG_IsCompromisedRecently')
        if ($isCompromised -eq $true -or $isCompromised -eq 1 -or [string]$isCompromised -eq 'true') { [void]$probTokens.Add('IsCompromisedRecently') }
        $machineRisk = [string](_rowVal @('MachineRiskState','EG_MachineRiskState'))
        if ($machineRisk -in 'High','high','High Risk') { [void]$probTokens.Add('HighMachineRisk') }
        $avStatus = [string](_rowVal @('DefenderAvStatus','MDE_DefenderAvStatus'))
        if ($avStatus -in 'Disabled','Off') { [void]$probTokens.Add('DefenderAvDisabled') }
        if ($avStatus -in 'OutOfDate','Expired') { [void]$probTokens.Add('DefenderAvOutOfDate') }
        $onboard = [string](_rowVal @('OnboardingStatus','MDE_OnboardingStatus'))
        if (-not [string]::IsNullOrWhiteSpace($onboard) -and $onboard -ne 'Onboarded') { [void]$probTokens.Add('Unonboarded') }
        $mgmtType = [string](_rowVal @('DeviceManagementType','MDE_DeviceManagementType'))
        if ($mgmtType -in 'Unknown','Unmanaged','None','MdmContainerOnly') { [void]$probTokens.Add('Unmanaged') }
        $isExcl = _rowVal @('IsExcluded','MDE_IsExcluded','EG_IsExcluded')
        if ($isExcl -eq $true -or $isExcl -eq 1 -or [string]$isExcl -eq 'true') { [void]$probTokens.Add('Excluded') }
        $hasInetSig = _rowVal @('HasInternetExposureSignal','EG_HasInternetExposureSignal')
        if ($hasInetSig -eq $true -or $hasInetSig -eq 1 -or [string]$hasInetSig -eq 'true') { [void]$probTokens.Add('InternetExposureSignal') }
        # ---- Consequence tokens (blast radius amplifiers) ----
        $msCrit = [string](_rowVal @('MsCriticalityLevel','EG_MsCriticalityLevel'))
        if ($msCrit -in 'High','VeryHigh','high','very_high') { [void]$consTokens.Add('MsCriticalityHigh') }
        $isProd = _rowVal @('IsProductionEnvironment','EG_IsProductionEnvironment')
        if ($isProd -eq $true -or $isProd -eq 1 -or [string]$isProd -eq 'true') { [void]$consTokens.Add('IsProductionEnvironment') }
        $isAdfs = _rowVal @('IsAdfsServer','EG_IsAdfsServer')
        if ($isAdfs -eq $true -or $isAdfs -eq 1 -or [string]$isAdfs -eq 'true') { [void]$consTokens.Add('IsAdfsServer') }
        $isExch = _rowVal @('IsExchangeServer','EG_IsExchangeServer')
        if ($isExch -eq $true -or $isExch -eq 1 -or [string]$isExch -eq 'true') { [void]$consTokens.Add('IsExchangeServer') }
        $isExo = _rowVal @('IsExchangeOnlineMailbox','EG_IsExchangeOnlineMailbox')
        if ($isExo -eq $true -or $isExo -eq 1 -or [string]$isExo -eq 'true') { [void]$consTokens.Add('IsExchangeOnlineMailbox') }
        # Re-stamp the *_Detailed columns + recount the numeric pair (lock-step).
        # CANONICAL RULE: RiskFactor_{Consequence,Probability} is ALWAYS the
        # count of ;-separated tokens in the *_Detailed column, otherwise 0.
        # The post-enrichment token block above merges YAML-emitted tokens with
        # engine-derived ones; we recount from that merged set so any legacy
        # YAML literal value is overridden. Final stamp into $tmp happens at
        # the canonical re-stamp block further down (single write site).
        if ($probTokens.Count -gt 0) {
            $tmp['RiskFactor_Probability_Detailed'] = ($probTokens -join ';')
            $rfProb = $probTokens.Count
        }
        if ($consTokens.Count -gt 0) {
            $tmp['RiskFactor_Consequence_Detailed'] = ($consTokens -join ';')
            $rfConsDetailedRaw = ($consTokens -join ';')
            $rfCons = $consTokens.Count
        }

        # ---- ONE safe-math call -- stamps all 4 score columns atomically ----
        # Uses post-enrichment rfCons/rfProb (lock-step with displayed
        # RiskFactor_Consequence/Probability counts). Replaces the v2.2 dual-write
        # path. Same call works for Endpoint / Identity / Azure / PublicIP --
        # there is NO other code path that stamps these columns.
        _setScores -tmp $tmp `
            -ConsBase     $consBase.Score `
            -ProbBase     $probBase.Score `
            -RfCons       $rfCons `
            -RfProb       $rfProb `
            -WeightPct    $rfWeightPct

        # Provenance: stamp ReportName into every row so operators can hunt back
        # which report produced which finding. Auto-added (no need to list in
        # OutputPropertyOrder; engine appends to the column set).
        if ($ReportName) {
            $tmp['AssetDetectedInReportName'] = [string]$ReportName
        }

        # CANONICAL re-stamp -- RiskFactor_{Consequence,Probability} = count of
        # tokens in *_Detailed (or 0). YAML-emitted literal values from KQL
        # `| extend RiskFactor_X = N` are overridden here with the derived count
        # so the displayed number ALWAYS matches the displayed token list.
        $tmp['RiskFactor_Consequence']          = [int]$rfCons
        $tmp['RiskFactor_Consequence_Detailed'] = $rfConsDetailedRaw
        $tmp['RiskFactor_Probability']          = [int]$rfProb
        # _Probability_Detailed already stamped above when probTokens fired;
        # otherwise the source row's value (or empty) survives.

        # MoreDetails: collect raw URLs (one per line, no labels) so the cell
        # renders as a stacked clickable list in Excel + a readable list in LA.
        # Three sources, accumulated in order:
        #   1) Auto-harvest -- scan every column on this row for http(s):// values
        #      (skipped when YAML pre-populated MoreDetails, e.g. Device_Missing_CVEs_*
        #      writes "CVE-XXX => URL" pairs that are more informative than raw URLs)
        #   2) Portal links -- Defender / Entra / Azure portal URLs computed from
        #      MdeDeviceId / EntraObjectId / AzureResourceId when present on the row
        #   3) MITRE links -- attack.mitre.org URLs derived from MITRE_Tactics /
        #      MITRE_Techniques semicolon-lists when present on the row
        # Final cap: 4000 chars / 25 URLs total (Excel-readable, LA-friendly).
        $sep = "`r`n"   # Excel renders this as a line-break inside a cell; LA accepts as-is
        $mdLines = New-Object System.Collections.Generic.List[string]

        # 1) Auto-harvest (skipped if YAML pre-populated MoreDetails)
        $existingMd = if ($tmp.Contains('MoreDetails')) { [string]$tmp['MoreDetails'] } else { '' }
        if ([string]::IsNullOrWhiteSpace($existingMd)) {
            $seen = New-Object System.Collections.Generic.HashSet[string]
            foreach ($p in $r.PSObject.Properties) {
                $v = $p.Value
                if ($null -eq $v) { continue }
                $items = if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { @($v) } else { @($v) }
                foreach ($item in $items) {
                    $s = [string]$item
                    if ([string]::IsNullOrWhiteSpace($s)) { continue }
                    if ($s.Length -gt 4096) { continue }   # cell guard: skip oversized blobs
                    if ($s -notmatch 'https?://') { continue }
                    # Pull out EVERY URL from the field. Prior version used $s -match '^https?://'
                    # which kept the WHOLE string as one entry -- if a YAML rollup had
                    # concatenated two URLs without a separator (e.g.
                    # 'https://nvd.nist.gov/vuln/detail/CVE-2016-9535https://nvd.nist.gov/...')
                    # the cell rendered as one un-clickable run-on. Iterate matches instead.
                    foreach ($urlMatch in ([regex]::Matches($s, 'https?://[^\s,;<>"`)\]]+'))) {
                        $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                        if ($seen.Add($u)) { [void]$mdLines.Add($u) }
                    }
                }
            }
        } else {
            # Preserve YAML-populated MoreDetails as line-per-URL. Some vuln reports
            # build entries like 'CVE-2026-33824 => https://nvd.nist.gov/vuln/detail/CVE-2026-33824'
            # in KQL via strcat. KQL strcat without an explicit separator can also produce
            # 'https://...CVE-X-Yhttps://...' run-ons -- iterate every URL match instead of
            # splitting on a single delimiter so concatenated pairs land as separate lines.
            $seenY = New-Object System.Collections.Generic.HashSet[string]
            foreach ($piece in ($existingMd -split '\s*;\s*')) {
                $pTrim = $piece.Trim()
                if ([string]::IsNullOrWhiteSpace($pTrim)) { continue }
                # Extract every URL embedded in the piece (handles 'label => URL' AND
                # 'URL1URL2URL3' run-ons). Falls back to the literal piece if no URL is
                # found (preserves rare non-URL labels for downstream consumers).
                $urlMatches = [regex]::Matches($pTrim, 'https?://[^\s,;<>"`)\]]+')
                if ($urlMatches.Count -eq 0) {
                    if ($seenY.Add($pTrim)) { [void]$mdLines.Add($pTrim) }
                    continue
                }
                foreach ($urlMatch in $urlMatches) {
                    $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                    if ($seenY.Add($u)) { [void]$mdLines.Add($u) }
                }
            }
        }

        # 2) Portal/security links removed by request -- MoreDetails now contains
        # ONLY harvested URLs (CVE / NVD / external references). Operators told us
        # the portal.azure.com and security.microsoft.com links were noise, not
        # navigation aids: the asset name + AssetType already tell you where to go,
        # and the portal blade URLs broke when assets moved tenants. Re-enable per
        # report by adding the URL into the YAML rollup directly.

        # 2b) CVE links -- harvest CVE-YYYY-NNNNN from any field on the row and append
        # NVD detail URLs. Mostly populates from IssueList / Issues / IssuesList /
        # Recommendations columns where the YAML KQL rolls up `mv-expand` CVEs.
        $cveSeen = New-Object System.Collections.Generic.HashSet[string]
        foreach ($p in $r.PSObject.Properties) {
            $v = $p.Value
            if ($null -eq $v) { continue }
            $items = if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { @($v) } else { @($v) }
            foreach ($item in $items) {
                $s = [string]$item
                if ([string]::IsNullOrWhiteSpace($s)) { continue }
                foreach ($cveMatch in ([regex]::Matches($s, 'CVE-\d{4}-\d{4,}'))) {
                    $cve = $cveMatch.Value.ToUpperInvariant()
                    if ($cveSeen.Add($cve)) {
                        [void]$mdLines.Add('https://nvd.nist.gov/vuln/detail/{0}' -f $cve)
                    }
                }
            }
        }

        # 3) MITRE links derived from MITRE_Tactics / MITRE_Techniques
        foreach ($mitreCol in 'MITRE_Tactics','MITRE_Techniques') {
            if (-not $r.PSObject.Properties[$mitreCol]) { continue }
            $raw = [string]$r.$mitreCol
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            foreach ($id in ($raw -split ';')) {
                $idTrim = $id.Trim()
                if ([string]::IsNullOrWhiteSpace($idTrim)) { continue }
                if ($idTrim -match '^TA\d+$')             { [void]$mdLines.Add('https://attack.mitre.org/tactics/{0}/'    -f $idTrim) }
                elseif ($idTrim -match '^T\d+(\.\d+)?$')  { [void]$mdLines.Add('https://attack.mitre.org/techniques/{0}/' -f ($idTrim -replace '\.','/')) }
            }
        }

        # 4) Portal links per asset (v2.2.235). Three sources, all gated on
        # $global:SI_SPN_TenantId being set (the {tid} parameter in every URL).
        # - MDE Endpoint   : requires MdeDeviceId
        # - MDE Identity   : requires AccountSID OR EntraAccountObjectId (3 shapes
        #                    based on which is present:
        #                      both     -> synced  (aad + sid)
        #                      AAD only -> cloud   (aad)
        #                      SID only -> AD-only (sid))
        # - Azure resource : requires AzureResourceId (uses $global:SI_TenantDomain
        #                    if set; falls back to TenantId in the #@<...> anchor)
        # Grace-skip per row when the identifier or tenant ID is missing -- the
        # cell stays focused on CVE / MITRE links instead of dumping useless
        # /overview?tid= placeholders.
        $tid = [string]$global:SI_SPN_TenantId
        if (-not [string]::IsNullOrWhiteSpace($tid)) {
            $mdeIdVal = if ($r.PSObject.Properties['MdeDeviceId']) { [string]$r.MdeDeviceId } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($mdeIdVal)) {
                [void]$mdLines.Add(('https://security.microsoft.com/machines/v2/{0}/overview?tid={1}' -f $mdeIdVal, $tid))
            }

            $aadIdVal = if ($r.PSObject.Properties['EntraAccountObjectId']) { [string]$r.EntraAccountObjectId } else { '' }
            $sidVal   = if ($r.PSObject.Properties['AccountSID'])           { [string]$r.AccountSID }           else { '' }
            $hasAad   = -not [string]::IsNullOrWhiteSpace($aadIdVal)
            $hasSid   = -not [string]::IsNullOrWhiteSpace($sidVal)
            if ($hasAad -and $hasSid) {
                # Synced (AD + Entra linked)
                [void]$mdLines.Add(('https://security.microsoft.com/user?aad={0}&sid={1}&tab=overview&tid={2}' -f $aadIdVal, $sidVal, $tid))
            } elseif ($hasAad) {
                # Cloud-only (Entra ID only)
                [void]$mdLines.Add(('https://security.microsoft.com/user?aad={0}&tab=overview&tid={1}' -f $aadIdVal, $tid))
            } elseif ($hasSid) {
                # AD-only (no Entra sync)
                [void]$mdLines.Add(('https://security.microsoft.com/user?sid={0}&tab=overview&tid={1}' -f $sidVal, $tid))
            }

            $azResIdVal = if ($r.PSObject.Properties['AzureResourceId']) { [string]$r.AzureResourceId } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($azResIdVal)) {
                $tdom = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_TenantDomain)) { [string]$global:SI_TenantDomain } else { $tid }
                [void]$mdLines.Add(('https://portal.azure.com/#@{0}/resource{1}/overview' -f $tdom, $azResIdVal))
            }
        }

        # Dedupe (preserves order), cap at 25 URLs, then join with line-break and cap at 4000 chars.
        if ($mdLines.Count -gt 0) {
            $deduped = [System.Collections.Generic.List[string]]::new()
            $seen2 = New-Object System.Collections.Generic.HashSet[string]
            foreach ($u in $mdLines) { if ($seen2.Add($u)) { [void]$deduped.Add($u) } }
            $arr = @($deduped | Select-Object -First 25)
            $joined = ($arr -join $sep)
            if ($joined.Length -gt 4000) { $joined = $joined.Substring(0, 3990) + '...' }
            $tmp['MoreDetails'] = $joined
        }

        if ($OutputPropertyOrder -and $OutputPropertyOrder.Count -gt 0) {
            $h = [ordered]@{}
            foreach ($name in $OutputPropertyOrder) {
                if ($tmp.Contains($name)) { $h[$name] = $tmp[$name] }
            }
            foreach ($k in $tmp.Keys) { if (-not $h.Contains($k)) { $h[$k] = $tmp[$k] } }
            # YAML's OutputPropertyOrder is the SINGLE source of truth for column
            # order (canonical Detailed/Summary shape standardized v2.2.175). No
            # engine post-hoc reorder -- it would override YAML curation.
            $out.Add([pscustomobject]$h) | Out-Null
        } else {
            $out.Add([pscustomobject]$tmp) | Out-Null
        }
    }

    Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Completed

    # per-report aggregates emitted under canonical OutputPropertyOrder names:
    #   ImpactedAssetCount        = distinct ConfigurationId in report           (int, scalar)
    #   UniqueIssues              = distinct ConfigurationName count             (int, scalar)
    #   TotalIssuesImpactedAssets = total finding rows in report                 (int, scalar)
    #   ImpactedAssetsList        = distinct AssetName(s) across all rows         (array of string)
    #   IssueList                 = distinct ConfigurationName(s) across all rows (array of string)
    # Per user spec:
    #   - LA sink: emit as dynamic (JSON array of names)
    #   - Excel sink: flatten to comma-joined string downstream
    # The engine emits a [string[]] -- AzLogDcrIngestPS serializes as dynamic for LA,
    # Excel writer joins with ', ' for the human-readable cell.
    # AssetName is standardized across SI_*_Profile_CL (set by every row builder); fall
    # back through DisplayName / Hostname / Name / ConfigurationName for legacy rows.
    # Re-apply OutputPropertyOrder so the new columns slot into the canonical position.
    if ($out.Count -gt 0) {
        $totalIssues = $out.Count
        $assetIds    = New-Object System.Collections.Generic.HashSet[string]
        $assetNames  = New-Object System.Collections.Generic.HashSet[string]
        $issueRefs   = New-Object System.Collections.Generic.HashSet[string]
        foreach ($row in $out) {
            $cid = $row.PSObject.Properties[$ConfigurationIdInputName]
            if ($cid -and -not [string]::IsNullOrWhiteSpace([string]$cid.Value)) {
                [void]$assetIds.Add([string]$cid.Value)
            }
            foreach ($candidate in @('AssetName','DisplayName','Hostname','Name','ConfigurationName')) {
                $prop = $row.PSObject.Properties[$candidate]
                if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                    [void]$assetNames.Add([string]$prop.Value)
                    break
                }
            }
            # Issues_Details collects per-row finding identifier so summary
            # rows can show which CVEs / which configuration items / which rules made up
            # the count. Try ConfigurationName first (human-readable like 'CVE-2025-49708'),
            # fall back to ConfigurationId if name absent.
            foreach ($candidate in @('ConfigurationName','ConfigurationId')) {
                $prop = $row.PSObject.Properties[$candidate]
                if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                    [void]$issueRefs.Add([string]$prop.Value)
                    break
                }
            }
        }
        $assetCount     = $assetIds.Count
        # Ordered, distinct array -- LA dynamic + Excel join both look stable across runs.
        $impactedAssets = @($assetNames | Sort-Object -Unique)
        $issuesDetails  = @($issueRefs  | Sort-Object -Unique)

        # Aggregate counters apply ONLY to Summary reports (whole-report scalars
        # don't make sense per-asset in Detailed reports). ReportName suffix
        # `_Summary` is the canonical signal. Detailed reports leave these
        # columns alone -- the YAML projects per-asset variants if needed.
        $isSummaryReport = $ReportName -and ($ReportName.EndsWith('_Summary', [StringComparison]::OrdinalIgnoreCase))
        $uniqueIssues   = $issueRefs.Count

        $reordered = New-Object System.Collections.Generic.List[object]
        foreach ($row in $out) {
            $tmp2 = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) { $tmp2[$p.Name] = $p.Value }
            # Preserve YAML-computed aggregates (Summary KQL often summarizes with the
            # correct DisplayName/UserPrincipalName coalesce that engine cannot
            # reconstruct from post-summarize columns). Only inject engine values when
            # the YAML did not provide them, and ONLY for Summary reports.
            if ($isSummaryReport) {
                if (-not $tmp2.Contains('ImpactedAssetCount') -or [string]::IsNullOrWhiteSpace([string]$tmp2['ImpactedAssetCount'])) {
                    $tmp2['ImpactedAssetCount'] = [int]$assetCount
                }
                if (-not $tmp2.Contains('UniqueIssues') -or [string]::IsNullOrWhiteSpace([string]$tmp2['UniqueIssues'])) {
                    $tmp2['UniqueIssues'] = [int]$uniqueIssues
                }
                if (-not $tmp2.Contains('TotalIssuesImpactedAssets') -or [string]::IsNullOrWhiteSpace([string]$tmp2['TotalIssuesImpactedAssets'])) {
                    $tmp2['TotalIssuesImpactedAssets'] = [int]$totalIssues
                }
            }
            # ImpactedAssetsList + IssueList: Summary-only aggregate lists. YAML
            # may project them already (per-summary-group); otherwise engine fills
            # with whole-report aggregates. For Detailed reports, leave alone --
            # YAML projects per-asset variants if applicable.
            if ($isSummaryReport) {
                $existingImpacted = $null
                if ($tmp2.Contains('ImpactedAssetsList'))   { $existingImpacted = $tmp2['ImpactedAssetsList'] }
                elseif ($tmp2.Contains('ImpactedAssets'))   { $existingImpacted = $tmp2['ImpactedAssets'] }
                $hasYamlImpacted = $false
                if ($existingImpacted -is [System.Collections.IEnumerable] -and -not ($existingImpacted -is [string])) {
                    foreach ($x in $existingImpacted) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$x)) { $hasYamlImpacted = $true; break }
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$existingImpacted)) {
                    $hasYamlImpacted = $true
                }
                if ($hasYamlImpacted) {
                    # YAML projects either semicolon-joined string (strcat_array) or
                    # dynamic array (make_set). Normalize to ordered/unique array.
                    if ($existingImpacted -is [string]) {
                        $existingImpacted = @($existingImpacted -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                    }
                } else {
                    $existingImpacted = $impactedAssets
                }
                $tmp2['ImpactedAssetsList'] = $existingImpacted
                if ($tmp2.Contains('ImpactedAssets')) { $tmp2.Remove('ImpactedAssets') }
                if (-not $tmp2.Contains('IssueList') -or $null -eq $tmp2['IssueList']) {
                    $tmp2['IssueList'] = $issuesDetails
                }
            } else {
                # Detailed report: IssueList = single ConfigurationName for THIS row's
                # asset. Per-asset list (one finding per row), not a whole-report
                # aggregate. Keeps the Detailed canonical OPO column populated
                # (operators expect to see WHICH issue this row represents).
                if (-not $tmp2.Contains('IssueList') -or $null -eq $tmp2['IssueList']) {
                    $cfgName = if ($tmp2.Contains('ConfigurationName')) { [string]$tmp2['ConfigurationName'] } else { '' }
                    if (-not [string]::IsNullOrWhiteSpace($cfgName)) {
                        $tmp2['IssueList'] = @($cfgName)
                    } else {
                        $cfgId = if ($tmp2.Contains('ConfigurationId')) { [string]$tmp2['ConfigurationId'] } else { '' }
                        $tmp2['IssueList'] = if ([string]::IsNullOrWhiteSpace($cfgId)) { @() } else { @($cfgId) }
                    }
                }
            }

            # Guarantee cross-cutting columns exist on every report (empty if the
            # per-report YAML didn't populate them) so downstream readers / dashboards
            # / mail-template consumers always find them with a stable schema.
            #   MoreDetails                       -- harvested URLs + portal links + MITRE links
            #   RiskFactor_Consequence_Detailed   -- engine-derived consequence breakdown
            #   MITRE_Tactics / Techniques        -- inferred from SecurityDomain + Subcategory
            #   ComplianceTags                    -- benchmark / framework tags (rare in YAML; usually empty)
            # STRICT-mode reorder below also force-injects all of these into the
            # output when YAML's OutputPropertyOrder doesn't list them explicitly.
            if (-not $tmp2.Contains('MoreDetails'))                     { $tmp2['MoreDetails']                     = '' }
            if (-not $tmp2.Contains('RiskFactor_Consequence_Detailed')) { $tmp2['RiskFactor_Consequence_Detailed'] = '' }

            # MITRE inference: priority order
            #   1. YAML-projected MITRE_Tactics + MITRE_Techniques  (already filled -- skip)
            #   2. Defender-native fields on the row:
            #        - 'Categories' / 'AlertCategories' (AlertInfo / AlertEvidence)  -> name->TA#### lookup
            #        - 'AttackTechniques' (AlertInfo / DeviceEvents / EG edges)      -> already T#### IDs
            #   3. Keyword regex over SecurityDomain + Subcategory + ConfigurationName.
            #   4. SecurityDomain-level fallback (broad TA-tactic).
            #
            # Categories -> Tactic ID lookup (MITRE ATT&CK 14 enterprise tactics).
            # Defender XDR's 'Categories' column carries human-readable tactic names
            # like "Credential Access", "Lateral Movement". Customers want TA#### IDs
            # for downstream tooling, so engine maps once.
            $mitreCategoryToTactic = @{
                'reconnaissance'         = 'TA0043'
                'resource development'   = 'TA0042'
                'initial access'         = 'TA0001'
                'execution'              = 'TA0002'
                'persistence'            = 'TA0003'
                'privilege escalation'   = 'TA0004'
                'defense evasion'        = 'TA0005'
                'credential access'      = 'TA0006'
                'discovery'              = 'TA0007'
                'lateral movement'       = 'TA0008'
                'collection'             = 'TA0009'
                'command and control'    = 'TA0011'
                'exfiltration'           = 'TA0010'
                'impact'                 = 'TA0040'
            }

            $mitreTactics    = if ($tmp2.Contains('MITRE_Tactics'))    { [string]$tmp2['MITRE_Tactics']    } else { '' }
            $mitreTechniques = if ($tmp2.Contains('MITRE_Techniques')) { [string]$tmp2['MITRE_Techniques'] } else { '' }

            # Step 2: Defender-native columns. Read regardless of MITRE_Tactics state --
            # if YAML projected RAW Categories/AttackTechniques but no MITRE_Tactics, we can
            # still translate. If YAML projected MITRE_Tactics directly, we honor that.
            if ([string]::IsNullOrWhiteSpace($mitreTactics)) {
                $catRaw = ''
                foreach ($colName in 'Categories','AlertCategories','MITRE_Categories') {
                    if ($tmp2.Contains($colName) -and -not [string]::IsNullOrWhiteSpace([string]$tmp2[$colName])) {
                        $catRaw = [string]$tmp2[$colName]; break
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($catRaw)) {
                    # Comma- or semicolon- separated tactic names. Map each to TA####.
                    $tids = @($catRaw -split '[,;]' | ForEach-Object {
                        $name = $_.Trim().ToLowerInvariant()
                        if ($mitreCategoryToTactic.ContainsKey($name)) { $mitreCategoryToTactic[$name] }
                    } | Where-Object { $_ } | Sort-Object -Unique)
                    if ($tids.Count -gt 0) { $mitreTactics = ($tids -join ';') }
                }
            }
            if ([string]::IsNullOrWhiteSpace($mitreTechniques)) {
                foreach ($colName in 'AttackTechniques','MITRE_AttackTechniques') {
                    if ($tmp2.Contains($colName) -and -not [string]::IsNullOrWhiteSpace([string]$tmp2[$colName])) {
                        # Already T#### IDs (Defender's shape). Normalize comma/space/semicolon to ';'.
                        $raw = [string]$tmp2[$colName]
                        $tlist = @($raw -split '[,;\s]+' | Where-Object { $_ -match '^T\d+(\.\d+)?$' } | Sort-Object -Unique)
                        if ($tlist.Count -gt 0) { $mitreTechniques = ($tlist -join ';'); break }
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($mitreTactics) -and [string]::IsNullOrWhiteSpace($mitreTechniques)) {
                $secDomain  = if ($tmp2.Contains('SecurityDomain'))  { [string]$tmp2['SecurityDomain']  } else { '' }
                $subcat     = if ($tmp2.Contains('Subcategory'))     { [string]$tmp2['Subcategory']     } else { '' }
                $cfgName    = if ($tmp2.Contains('ConfigurationName')){[string]$tmp2['ConfigurationName']} else { '' }
                $blob       = ($secDomain + ' ' + $subcat + ' ' + $cfgName).ToLowerInvariant()

                # Match most-specific keywords first, then broader domain defaults.
                $tactics    = $null
                $techniques = $null
                switch -Regex ($blob) {
                    'mfa|conditional access|multi.factor'                 { $tactics = 'TA0006';        $techniques = 'T1078;T1110';            break }
                    'brute.?force|password spray'                         { $tactics = 'TA0006';        $techniques = 'T1110;T1110.003';        break }
                    'impossible travel|nontrusted location|risky.sign'    { $tactics = 'TA0006;TA0001'; $techniques = 'T1078;T1078.004';        break }
                    'permanent.*role|privileged.*role|never.*expire'      { $tactics = 'TA0004;TA0003'; $techniques = 'T1078;T1098.003';        break }
                    'shadow admin|nested.*group|stale.*group'             { $tactics = 'TA0004';        $techniques = 'T1078;T1484.001';        break }
                    'guest|external user|departed|stale'                  { $tactics = 'TA0006';        $techniques = 'T1078;T1078.004';        break }
                    'spn|service principal|app registration|mailbox'      { $tactics = 'TA0004;TA0003'; $techniques = 'T1078.004;T1098.001';    break }
                    'cve|vulnerab|recommendation|patch'                   { $tactics = 'TA0001';        $techniques = 'T1190';                  break }
                    'public.*ip|exposed|open port|public.*facing'         { $tactics = 'TA0001;TA0007'; $techniques = 'T1190;T1133';            break }
                    'lateral|exploitable.*device|logon.*to'               { $tactics = 'TA0008';        $techniques = 'T1021;T1078';            break }
                    'attack path'                                          { $tactics = 'TA0008;TA0004'; $techniques = 'T1078;T1021';            break }
                    'data sensitivity|sensitive data|key vault'            { $tactics = 'TA0009;TA0010'; $techniques = 'T1213;T1530';            break }
                }
                # Domain-level fallback if no specific keyword hit.
                if ($null -eq $tactics) {
                    switch ($secDomain) {
                        'Identity'   { $tactics = 'TA0006';        $techniques = 'T1078'             }
                        'Endpoint'   { $tactics = 'TA0001;TA0008'; $techniques = 'T1190;T1021'      }
                        'Azure'      { $tactics = 'TA0004;TA0001'; $techniques = 'T1078.004;T1190'  }
                        'PublicIp'   { $tactics = 'TA0001;TA0007'; $techniques = 'T1190;T1133'      }
                        'AttackPath' { $tactics = 'TA0008;TA0004'; $techniques = 'T1078;T1021'      }
                        default      { $tactics = '';              $techniques = ''                 }
                    }
                }
                $tmp2['MITRE_Tactics']    = $tactics
                $tmp2['MITRE_Techniques'] = $techniques
            } else {
                # At least one of mitreTactics/mitreTechniques came from row data
                # (Step 2 Defender-native). Persist whatever we resolved; fill the
                # missing side with empty string so downstream readers can rely on
                # the column existing.
                $tmp2['MITRE_Tactics']    = if ($mitreTactics)    { $mitreTactics }    else { '' }
                $tmp2['MITRE_Techniques'] = if ($mitreTechniques) { $mitreTechniques } else { '' }
            }

            # ComplianceTags inference: when YAML didn't pre-populate, derive a sensible
            # default from the same SecurityDomain + Subcategory + ConfigurationName blob.
            # Lists the most common control framework anchors per finding type so customers
            # can map to their compliance evidence pack. YAML overrides win when set.
            $compTags = if ($tmp2.Contains('ComplianceTags')) { [string]$tmp2['ComplianceTags'] } else { '' }
            if ([string]::IsNullOrWhiteSpace($compTags)) {
                $secDomain  = if ($tmp2.Contains('SecurityDomain'))   { [string]$tmp2['SecurityDomain']   } else { '' }
                $subcat     = if ($tmp2.Contains('Subcategory'))      { [string]$tmp2['Subcategory']      } else { '' }
                $cfgName    = if ($tmp2.Contains('ConfigurationName')){ [string]$tmp2['ConfigurationName']} else { '' }
                $blob       = ($secDomain + ' ' + $subcat + ' ' + $cfgName).ToLowerInvariant()

                # Each keyword now anchors against:
                #   - NIST 800-53 (US federal)        - NIST CSF 2.0     (US framework)
                #   - ISO 27001 Annex A (international) - CIS Controls v8 (community)
                #   - PCI DSS 4.0 (payments)          - HIPAA Security Rule (US healthcare)
                #   - SOC 2 Trust Services Criteria   - NIS2 (EU) / DORA (EU finance)
                #   - GDPR (EU privacy, data sensitivity only)
                # Customers refine via per-report YAML; these defaults are best-fit anchors.
                $tags = $null
                switch -Regex ($blob) {
                    'mfa|conditional access|multi.factor' {
                        $tags = 'NIST 800-53 IA-2(1);NIST CSF PR.AA-3;ISO 27001 A.9.4.2;CIS 5.1;PCI DSS 8.4;HIPAA 164.312(a)(1);SOC 2 CC6.1;NIS2 Art.21(2)(d)'
                        break }
                    'brute.?force|password spray' {
                        $tags = 'NIST 800-53 AC-7;NIST CSF DE.CM-1;ISO 27001 A.9.4.2;CIS 5.2;HIPAA 164.308(a)(5)(ii)(D);SOC 2 CC6.6'
                        break }
                    'impossible travel|nontrusted location|risky.sign' {
                        $tags = 'NIST 800-53 AC-17,SI-4;NIST CSF DE.AE-3;ISO 27001 A.9.4.2;CIS 6.5;SOC 2 CC7.2'
                        break }
                    'permanent.*role|privileged.*role|never.*expire' {
                        $tags = 'NIST 800-53 AC-2,AC-5,AC-6;NIST CSF PR.AC-4;ISO 27001 A.9.2.3;CIS 5.4;SOC 2 CC6.2;NIS2 Art.21(2)(i);DORA Art.9'
                        break }
                    'shadow admin|nested.*group|stale.*group' {
                        $tags = 'NIST 800-53 AC-2;NIST CSF PR.AC-1;ISO 27001 A.9.2.5;CIS 5.4;SOC 2 CC6.2'
                        break }
                    'guest|external user|departed|stale.*user|stale.*account' {
                        $tags = 'NIST 800-53 AC-2(2),AC-2(3);NIST CSF PR.AC-1;ISO 27001 A.9.2.5,A.9.2.6;CIS 5.3;HIPAA 164.308(a)(3)(ii)(C);SOC 2 CC6.3'
                        break }
                    'spn|service principal|app registration|mailbox' {
                        $tags = 'NIST 800-53 IA-3,IA-9;NIST CSF PR.AA-1;ISO 27001 A.9.4.5;CIS 5.5;SOC 2 CC6.1'
                        break }
                    'cve|vulnerab|recommendation|patch' {
                        $tags = 'NIST 800-53 SI-2,RA-5;NIST CSF ID.RA-1,PR.IP-12;ISO 27001 A.12.6.1;CIS 7.1;PCI DSS 6.2;HIPAA 164.308(a)(1)(ii)(B);SOC 2 CC7.1;NIS2 Art.21(2)(e);DORA Art.10'
                        break }
                    'public.*ip|exposed|open port|public.*facing' {
                        $tags = 'NIST 800-53 SC-7,CA-3;NIST CSF PR.AC-5;ISO 27001 A.13.1;CIS 12.1;PCI DSS 1.1;HIPAA 164.312(e)(1);SOC 2 CC6.6;NIS2 Art.21(2)(c)'
                        break }
                    'lateral|exploitable.*device|logon.*to' {
                        $tags = 'NIST 800-53 SC-7(13),AC-4;NIST CSF PR.AC-5;ISO 27001 A.13.1.3;CIS 12.4;SOC 2 CC6.6'
                        break }
                    'attack path' {
                        $tags = 'NIST 800-53 RA-3,SC-7;NIST CSF ID.RA-3;ISO 27001 A.12.6.1;SOC 2 CC3.1;NIS2 Art.21(2)(b);DORA Art.8'
                        break }
                    'data sensitivity|sensitive data|key vault' {
                        $tags = 'NIST 800-53 SC-12,SC-13,MP-2;NIST CSF PR.DS-1,PR.DS-5;ISO 27001 A.8.2,A.10.1;GDPR Art.32;PCI DSS 3;HIPAA 164.312(a)(2)(iv);SOC 2 CC6.7;DORA Art.9'
                        break }
                    'firewall|defender' {
                        $tags = 'NIST 800-53 SC-7,SI-3;NIST CSF PR.PT-4,DE.CM-4;ISO 27001 A.13.1.1;CIS 9.2;PCI DSS 1;SOC 2 CC6.6'
                        break }
                    'tls|encryption|unencrypted' {
                        $tags = 'NIST 800-53 SC-8,SC-13;NIST CSF PR.DS-2;ISO 27001 A.10.1;PCI DSS 4;HIPAA 164.312(e)(2)(ii);SOC 2 CC6.7'
                        break }
                }
                if ($null -eq $tags) {
                    switch ($secDomain) {
                        'Identity'   { $tags = 'NIST 800-53 AC-2,IA-2;NIST CSF PR.AA-1;ISO 27001 A.9;SOC 2 CC6.1' }
                        'Endpoint'   { $tags = 'NIST 800-53 SI-2,SI-3;NIST CSF DE.CM-4;ISO 27001 A.12.6;SOC 2 CC7.1' }
                        'Azure'      { $tags = 'NIST 800-53 AC-3,AC-6;NIST CSF PR.AC-4;ISO 27001 A.9.4;SOC 2 CC6.1' }
                        'PublicIp'   { $tags = 'NIST 800-53 SC-7;NIST CSF PR.AC-5;ISO 27001 A.13.1;SOC 2 CC6.6' }
                        'AttackPath' { $tags = 'NIST 800-53 RA-3,SC-7;NIST CSF ID.RA-3;ISO 27001 A.12.6;SOC 2 CC3.1' }
                        default      { $tags = '' }
                    }
                }
                $tmp2['ComplianceTags'] = $tags
            } else {
                if (-not $tmp2.Contains('ComplianceTags')) { $tmp2['ComplianceTags'] = '' }
            }

            # =====================================================================
            # NEW (v2.2.89): RiskScoreDomainKPI + RiskScoreKPI
            # =====================================================================
            # Two new per-row columns that feed the management-facing reporting
            # rollups (global Risk Score KPI + per-domain breakdown). The existing
            # math model (RiskFactor_Consequence x RiskFactor_Probability x
            # RiskScore_Weight_Factor = RiskScoreTotal[_Weighted]) is left
            # untouched -- customer dashboards built on those columns keep
            # working. These two NEW columns are designed to be easy to explain
            # to management:
            #
            #   RiskScoreDomainKPI = SeverityWeight x AssetTierMultiplier
            #   RiskScoreKPI       = RiskScoreDomainKPI x GlobalWeight[<domain>]
            #
            # Sum RiskScoreDomainKPI by SecurityDomain -> domain raw score.
            # Sum RiskScoreKPI across all rows -> global raw score.
            # Both normalized to 0-100 in the run-end aggregation block (~line 6045).
            $sevName  = if ($tmp2.Contains('SecuritySeverity')) { [string]$tmp2['SecuritySeverity'] } else { '' }
            $tierVal  = $null
            if ($tmp2.Contains('CriticalityTier'))      { [void][int]::TryParse([string]$tmp2['CriticalityTier'], [ref]$tierVal) }
            $domName  = if ($tmp2.Contains('SecurityDomain')) { [string]$tmp2['SecurityDomain'] } else { '' }

            $sevWeight = switch -Regex ($sevName) {
                '^(?i)(critical|very high)$' { if ($null -ne $global:SI_RiskReport_SeverityWeight_Critical) { [double]$global:SI_RiskReport_SeverityWeight_Critical } else { 10.0 }; break }
                '^(?i)high$'                 { if ($null -ne $global:SI_RiskReport_SeverityWeight_High)     { [double]$global:SI_RiskReport_SeverityWeight_High }     else {  5.0 }; break }
                '^(?i)medium-?high$'         { if ($null -ne $global:SI_RiskReport_SeverityWeight_High)     { [double]$global:SI_RiskReport_SeverityWeight_High }     else {  5.0 }; break }
                '^(?i)medium$'               { if ($null -ne $global:SI_RiskReport_SeverityWeight_Medium)   { [double]$global:SI_RiskReport_SeverityWeight_Medium }   else {  2.0 }; break }
                '^(?i)low$'                  { if ($null -ne $global:SI_RiskReport_SeverityWeight_Low)      { [double]$global:SI_RiskReport_SeverityWeight_Low }      else {  1.0 }; break }
                default                      { 1.0 }
            }
            $tierMult = switch ($tierVal) {
                0       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T0) { [double]$global:SI_RiskReport_TierMultiplier_T0 } else { 4.0 } }
                1       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T1) { [double]$global:SI_RiskReport_TierMultiplier_T1 } else { 2.0 } }
                2       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T2) { [double]$global:SI_RiskReport_TierMultiplier_T2 } else { 1.0 } }
                3       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T3) { [double]$global:SI_RiskReport_TierMultiplier_T3 } else { 0.5 } }
                default { 1.0 }
            }
            $globalWeight = switch ($domName) {
                'Endpoint'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_Endpoint) { [double]$global:SI_RiskReport_GlobalWeight_Endpoint } else { 0.30 } }
                'Identity'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_Identity) { [double]$global:SI_RiskReport_GlobalWeight_Identity } else { 0.30 } }
                'Azure'      { if ($null -ne $global:SI_RiskReport_GlobalWeight_Azure)    { [double]$global:SI_RiskReport_GlobalWeight_Azure }    else { 0.20 } }
                'PublicIP'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_PublicIP) { [double]$global:SI_RiskReport_GlobalWeight_PublicIP } else { 0.20 } }
                'PublicIp'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_PublicIP) { [double]$global:SI_RiskReport_GlobalWeight_PublicIP } else { 0.20 } }
                'AttackPath' { 0.0 }   # attack-path rows already counted in their target domain
                default      { 0.20 }
            }
            # v2.2.96: per-row KPI is a SECURE SCORE (HIGHER = BETTER, 0-100),
            # inspired by Microsoft Cloud Secure Score. The original RiskScore
            # math (Severity x Probability x Weight = RiskScoreTotal) is left
            # untouched -- the OG number people are fans of stays on every row.
            #
            # Per-row formula:
            #   sevPenalty = SeverityWeight / 10        (0..1, 1.0 = critical)
            #   RiskScoreKPI = round((1 - sevPenalty) * 100)
            #     -> Critical 0 | High 50 | Medium 80 | Low 90 | Other 95
            #   RiskScoreDomainKPI = RiskScoreKPI x TierWeight / 4
            #     -> normalized 0..100 with T0 carrying full weight (4/4),
            #        T1 half weight (2/4), T2 quarter (1/4), T3 eighth (0.5/4)
            #     -> aggregator: DomainScore = sum(RiskScoreDomainKPI) / sum(TierWeight/4) -> mgmt KPI
            $sevPenalty   = [Math]::Min(1.0, $sevWeight / 10.0)
            $rowKpi       = [int][Math]::Round((1.0 - $sevPenalty) * 100.0, 0)
            $tierFraction = $tierMult / 4.0   # T0 1.00, T1 0.50, T2 0.25, T3 0.125
            $rowDomainKpi = [int][Math]::Round((1.0 - $sevPenalty) * $tierFraction * 100.0, 0)
            $tmp2['RiskScoreKPI']       = $rowKpi
            $tmp2['RiskScoreDomainKPI'] = $rowDomainKpi

            if ($OutputPropertyOrder -and $OutputPropertyOrder.Count -gt 0) {
                # STRICT mode -- when OutputPropertyOrder is declared, emit ONLY those
                # columns. The legacy engine-injected aggregates
                # (AssetCount/TotalIssues/ImpactedAssets/Issues_Details + the
                # RiskFactor_Weight engine-alias) are dropped because their data lives
                # in YAML-declared columns under the new names (ImpactedAssetCount /
                # TotalIssuesImpactedAssets / ImpactedAssetsList / IssueList /
                # RiskScore_Weight_Factor). MoreDetails + RiskFactor_Consequence_Detailed
                # + MITRE_* + ComplianceTags are force-included regardless of whether the
                # per-report YAML lists them, so the schema stays stable across reports.
                # RiskFactor_Consequence_Detailed is then re-positioned to sit right
                # after RiskFactor_Consequence.
                $h2 = [ordered]@{}
                foreach ($name in $OutputPropertyOrder) {
                    # Treat 'ImpactedAssets' and 'ImpactedAssetsList' as aliases. The engine
                    # canonicalizes on 'ImpactedAssetsList' a few lines above; YAMLs that
                    # still list the legacy 'ImpactedAssets' name in OutputPropertyOrder
                    # remap here so column-name parity is preserved for Excel + LA.
                    $effectiveName = if ($name -eq 'ImpactedAssets') { 'ImpactedAssetsList' } else { $name }
                    if ($tmp2.Contains($effectiveName)) { $h2[$effectiveName] = $tmp2[$effectiveName] }
                }
                foreach ($forceCol in 'RiskFactor_Consequence_Detailed','MITRE_Tactics','MITRE_Techniques','ComplianceTags','MoreDetails','RiskScoreDomainKPI','RiskScoreKPI') {
                    if (-not $h2.Contains($forceCol)) { $h2[$forceCol] = $tmp2[$forceCol] }
                }
                # v2.2.225 -- carry-through extra YAML-projected columns. Previously
                # OutputPropertyOrder was a strict whitelist: any column projected by
                # the YAML KQL but missing from OutputPropertyOrder got silently
                # dropped. That made CVE Detailed lose HasExploit / IsExploitVerified /
                # IsInExploitKit / IsZeroDay / CVELastModified / CVSSDesc / CveUrl
                # which the operator wants visible without inflating the canonical
                # OutputPropertyOrder. Now: OutputPropertyOrder defines the LEADING
                # canonical column block; any additional row-level columns from the
                # KQL get appended in row-natural order. Blacklist below skips legacy
                # engine-aliases + internal helpers.
                $extraColBlacklist = @{
                    'AssetCount'        = $true   # legacy alias -> ImpactedAssetCount
                    'TotalIssues'       = $true   # legacy alias -> TotalIssuesImpactedAssets
                    'ImpactedAssets'    = $true   # legacy alias -> ImpactedAssetsList
                    'Issues_Details'    = $true   # legacy alias -> MoreDetails
                    'RiskFactor_Weight' = $true   # legacy alias -> RiskScore_Weight_Factor
                    'DeviceKey'         = $true   # internal join key
                    'EpJoinKey'         = $true   # internal join key (v2.2.221)
                    'EdgeLabels'        = $true   # internal trace set (v2.2.215)
                    'FindingNodeId'     = $true   # internal join key
                    'FindingLabel'      = $true   # internal raw-EG label (kept inside Finding* scalars)
                    'FindingCategories' = $true   # internal raw-EG categories
                    'EG_IsCustomerFacing' = $true # internal raw flag (consumed by RF_P_InternetExposed)
                    'EG_IsExcluded'     = $true   # internal raw flag (filtered upstream)
                    'AadDeviceId1'      = $true   # leftouter-join right-side rename
                }
                foreach ($k in $tmp2.Keys) {
                    if ($h2.Contains($k))            { continue }   # already emitted in canonical block
                    if ($k.StartsWith('_'))          { continue }   # internal/temp columns (e.g. _AssetTagsLower, _AssetTierFilter)
                    if ($k.StartsWith('__'))         { continue }   # bucket-filter internals (__bucket_key, __bucket)
                    if ($extraColBlacklist.ContainsKey($k)) { continue }
                    if ($k -like '*_From_CL')        { continue }   # leftouter-side raw cols (consumed by AssetName/AssetId/AssetType extends)
                    $h2[$k] = $tmp2[$k]
                }
                # YAML OutputPropertyOrder is the LEADING column-order authority;
                # extras appended above sit AFTER the canonical block.
                [void]$reordered.Add([pscustomobject]$h2)
            } else {
                [void]$reordered.Add([pscustomobject]$tmp2)
            }
        }
        $out = $reordered
    }

    $finalOut = $null
    try {
        $finalOut = [object[]]$out.ToArray()
    } catch {
        $tmpList = New-Object System.Collections.Generic.List[object]
        foreach ($x in $out) { $tmpList.Add($x) | Out-Null }
        $finalOut = [object[]]$tmpList.ToArray()
    }

    if ($SortBy -and $SortBy.Count -gt 0) {
        if ($Descending) { $finalOut = @($finalOut | Sort-Object -Property $SortBy -Descending) }
        else             { $finalOut = @($finalOut | Sort-Object -Property $SortBy) }
    }

    return @($finalOut)
}

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


function Write-Section($text) {
  Write-Host ""
  Write-Host "==== $text ====" -ForegroundColor Cyan
}

# exporter (single-write workflow; still supports -ClearSheet)
function Export-Worksheet {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)]$Rows,
    [string]$SortColumn,
    [switch]$SortDescending,
    [string[]]$DesiredColumns,
    [string[]]$ColumnsToFlatten = @(),
    [string]$TableStyle = 'Medium9'
  )

  function Convert-CellValue {
    param(
      [Parameter()][AllowNull()]$Value,
      [string]$JoinChar = ', '
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [string] -or
        $Value -is [int] -or $Value -is [long] -or
        $Value -is [double] -or $Value -is [decimal] -or
        $Value -is [datetime] -or $Value -is [bool] -or
        $Value -is [guid]) {
      return $Value
    }

    if ($Value -is [pscustomobject] -or $Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
      try { return ($Value | ConvertTo-Json -Compress -Depth 12) } catch { return ($Value | Out-String).Trim() }
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
      $items = @()
      foreach ($i in $Value) {
        if ($null -eq $i) { continue }
        if ($i -is [string] -or $i.GetType().IsPrimitive) {
          $items += [string]$i
        } else {
          try { $items += ($i | ConvertTo-Json -Compress -Depth 12) }
          catch { $items += ([string]($i | Out-String).Trim()) }
        }
      }
      return ($items -join $JoinChar)
    }

    return [string]$Value
  }

  $safeSheet = $SheetName.Substring(0, [Math]::Min(31, $SheetName.Length)) -replace '[:\\/?*\[\]]','_'
  $tableName = ($safeSheet -replace '\W','_')

  if (-not $Rows -or $Rows.Count -eq 0) {
    $excel = ([pscustomobject]@{ Info = 'No rows returned' }) |
      Export-Excel -Path $Path -WorksheetName $safeSheet -TableName $tableName -TableStyle $TableStyle `
        -AutoSize -FreezeTopRow -BoldTopRow -ClearSheet -PassThru
    $ws = $excel.Workbook.Worksheets[$safeSheet]
    $ws.Cells.AutoFitColumns()
    # v2.2.226 -- enable WrapText on known multi-line columns so embedded
    # newlines (\r\n built by the MoreDetails post-process; IssueList /
    # RiskFactor_*_Detailed / ImpactedAssetsList aggregations) render as
    # line breaks in Excel. Without WrapText the cell shows one long
    # string and operators see "MoreDetails doesn't separate multiple
    # entries". Capping width at 50 (below) keeps cells readable when
    # wrap fires.
    $wrapTargets = @{
        'MoreDetails'                     = $true
        'IssueList'                       = $true
        'RiskFactor_Probability_Detailed' = $true
        'RiskFactor_Consequence_Detailed' = $true
        'ImpactedAssetsList'              = $true
        'AssetDetectedInReportName'       = $true
        'CVSSDesc'                        = $true
    }
    for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
      if ($ws.Column($col).Width -gt 50) { $ws.Column($col).Width = 50 }
      $headerVal = [string]$ws.Cells[1, $col].Value
      if ($headerVal -and $wrapTargets.ContainsKey($headerVal)) {
        try { $ws.Column($col).Style.WrapText = $true } catch { }
      }
    }
    Close-ExcelPackage $excel
    $script:_sheetWritten[$safeSheet] = $true
    return
  }

  $Data = $Rows
  if ($DesiredColumns) { $Data = $Data | Select-Object -Property $DesiredColumns }

  if ($ColumnsToFlatten.Count -gt 0) {
    $Data = $Data | ForEach-Object {
      $o = [ordered]@{}
      foreach ($p in $_.PSObject.Properties) {
        $v = $p.Value
        if ($ColumnsToFlatten -contains $p.Name) {
          $v = Convert-CellValue -Value $v
        }
        $o[$p.Name] = $v
      }
      [pscustomobject]$o
    }
  }

  if ($SortColumn) {
    $Data = $Data | Sort-Object -Property $SortColumn -Descending:$SortDescending.IsPresent
  }

  # ALSO flatten any [object[]] / IDictionary / IEnumerable cell into
  # a string -- without this, ImportExcel calls .ToString() on arrays and emits
  # "System.Object[]" into the cell. ColumnsToFlatten was only narrowly applied
  # for explicitly-listed columns; this catches everything.
  # XLSX shared-strings safety: scrub control chars + lone surrogates from every
  # string property of every row before Export-Excel. Without this, any KQL extract()
  # result / CSA blob / pasted-in text containing such a character makes Excel pop
  # the "Repaired Records: String properties from sharedStrings.xml" dialog on
  # file open. v2.1.206.
  $Data = $Data | ForEach-Object {
    $o = [ordered]@{}
    foreach ($p in $_.PSObject.Properties) {
      $v = $p.Value
      # Universal flatten: any non-scalar (array / hashtable / pscustomobject)
      # gets joined / JSON-serialized so it lands as a readable string in the cell.
      if ($null -ne $v -and -not ($v -is [string]) -and (
            $v -is [System.Collections.IDictionary] -or
            $v -is [pscustomobject] -or
            ($v -is [System.Collections.IEnumerable] -and -not ($v.GetType().IsValueType))
          )) {
        $v = Convert-CellValue -Value $v
      }
      if ($v -is [string] -and -not [string]::IsNullOrEmpty($v)) {
        $v = ConvertTo-XlsxSafeString $v
      }
      $o[$p.Name] = $v
    }
    [pscustomobject]$o
  }

  # locale-defensive Excel write. PowerShell + EPPlus auto-stringify
  # doubles using CurrentCulture; on da-DK / nl-NL / de-DE / fr-FR / etc. (comma
  # decimal locales) `9.8` becomes the string "9,8", which Excel then re-parses
  # as `9 thousand 8 -> 98` (comma = thousands separator under en-US-ish locale
  # detection during xlsx import). Swap the running thread to InvariantCulture
  # for the duration of the Export-Excel call so every double serializes with
  # period-decimal regardless of the host locale. Restore in finally so the rest
  # of the engine sees its original culture (logs / dates / etc.). Works on ANY
  # locale because Invariant is locale-agnostic.
  $_savedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
  try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
    $excel = $Data | Export-Excel -Path $Path -WorksheetName $safeSheet -TableStyle $TableStyle `
      -TableName $tableName -AutoFilter -FreezeTopRow -BoldTopRow -ClearSheet -PassThru

    $ws = $excel.Workbook.Worksheets[$safeSheet]
    $ws.Cells.AutoFitColumns()
    # v2.2.226 -- enable WrapText on known multi-line columns so embedded
    # newlines (\r\n built by the MoreDetails post-process; IssueList /
    # RiskFactor_*_Detailed / ImpactedAssetsList aggregations) render as
    # line breaks in Excel. Without WrapText the cell shows one long
    # string and operators see "MoreDetails doesn't separate multiple
    # entries". Capping width at 50 (below) keeps cells readable when
    # wrap fires.
    $wrapTargets = @{
        'MoreDetails'                     = $true
        'IssueList'                       = $true
        'RiskFactor_Probability_Detailed' = $true
        'RiskFactor_Consequence_Detailed' = $true
        'ImpactedAssetsList'              = $true
        'AssetDetectedInReportName'       = $true
        'CVSSDesc'                        = $true
    }
    for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
      if ($ws.Column($col).Width -gt 50) { $ws.Column($col).Width = 50 }
      $headerVal = [string]$ws.Cells[1, $col].Value
      if ($headerVal -and $wrapTargets.ContainsKey($headerVal)) {
        try { $ws.Column($col).Style.WrapText = $true } catch { }
      }
    }
    Close-ExcelPackage $excel
  } finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $_savedCulture
  }

  $script:_sheetWritten[$safeSheet] = $true
}

function New-RiskIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]] $CsvRows,
        [Parameter(Mandatory=$true)][string] $ColSecurityDomain,
        [Parameter(Mandatory=$true)][string] $ColCategory,
        [Parameter(Mandatory=$true)][string] $ColSubCategory,
        [Parameter(Mandatory=$true)][string] $ColConfigId,
        [Parameter(Mandatory=$true)][string] $ColSevValue,
        [Parameter(Mandatory=$true)][string] $ColTierValue,
        [Parameter(Mandatory=$true)][string] $ColConseqScore,
        [Parameter(Mandatory=$true)][string] $ColProbScore
    )

    # StrictMode-safe normalization
    $CsvRows = @($CsvRows)
    if ($CsvRows.Count -eq 0) { throw "Risk definitions CSV is empty." }

    $firstCols = @($CsvRows[0].PSObject.Properties.Name)

    # Validate required columns (StrictMode-safe even when only 1 is missing)
    $required = @(
        $ColCategory,
        $ColSubCategory,
        $ColConfigId,
        $ColSevValue,
        $ColTierValue,
        $ColConseqScore,
        $ColProbScore
    )

    $missing = @($required | Where-Object { $firstCols -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw "CSV missing required columns: $($missing -join ', ')"
    }

    function _MakeKey {
        param(
            [Parameter(Mandatory=$true)][object] $Row,
            [Parameter(Mandatory=$true)][string[]] $Pattern
        )

        $vals = foreach ($c in @($Pattern)) {
            $v = $Row.$c
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    # Matching sequences (ordered from most-specific to least-specific)
    $seqWithDomain_Conseq = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSevValue),
        @($ColSecurityDomain,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )

    $seqNoDomain_Conseq = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColCategory,$ColSubCategory,$ColSevValue),
        @($ColCategory,$ColSevValue),
        @($ColSevValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    $seqWithDomain_Prob = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColTierValue),
        @($ColSecurityDomain,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )

    $seqNoDomain_Prob = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColCategory,$ColSubCategory,$ColTierValue),
        @($ColCategory,$ColTierValue),
        @($ColTierValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    # Maps per pattern (StrictMode-safe creation)
    $mapsConseq_With = @()
    foreach ($pat in $seqWithDomain_Conseq) { $mapsConseq_With += ,@{} }

    $mapsConseq_No = @()
    foreach ($pat in $seqNoDomain_Conseq) { $mapsConseq_No += ,@{} }

    $mapsProb_With = @()
    foreach ($pat in $seqWithDomain_Prob) { $mapsProb_With += ,@{} }

    $mapsProb_No = @()
    foreach ($pat in $seqNoDomain_Prob) { $mapsProb_No += ,@{} }

    foreach ($row in $CsvRows) {

        for ($i = 0; $i -lt @($seqWithDomain_Conseq).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqWithDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_With[$i].ContainsKey($k)) { $mapsConseq_With[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqNoDomain_Conseq).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqNoDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_No[$i].ContainsKey($k)) { $mapsConseq_No[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqWithDomain_Prob).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqWithDomain_Prob[$i]
            if ($k -and -not $mapsProb_With[$i].ContainsKey($k)) { $mapsProb_With[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqNoDomain_Prob).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqNoDomain_Prob[$i]
            if ($k -and -not $mapsProb_No[$i].ContainsKey($k)) { $mapsProb_No[$i][$k] = $row }
        }
    }

    [pscustomobject]@{
        SecurityDomainColumn = $ColSecurityDomain
        CategoryColumn       = $ColCategory
        SubCategoryColumn    = $ColSubCategory
        ConfigIdColumn       = $ColConfigId
        SevValueColumn       = $ColSevValue
        TierValueColumn      = $ColTierValue
        ConseqScoreColumn    = $ColConseqScore
        ProbScoreColumn      = $ColProbScore

        Conseq_WithDomainPatterns = $seqWithDomain_Conseq
        Conseq_NoDomainPatterns   = $seqNoDomain_Conseq
        Prob_WithDomainPatterns   = $seqWithDomain_Prob
        Prob_NoDomainPatterns     = $seqNoDomain_Prob

        Conseq_WithDomainMaps = $mapsConseq_With
        Conseq_NoDomainMaps   = $mapsConseq_No
        Prob_WithDomainMaps   = $mapsProb_With
        Prob_NoDomainMaps     = $mapsProb_No
    }
}

function Send-MailAnonymous {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SmtpServer,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter()] [bool]$UseSsl = $false,

        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,

        [Parameter()] [string[]]$Attachments,
        [Parameter()] [ValidateSet('Normal','High','Low')] [string]$Priority = 'High'
    )

    # v2.2.247 -- diagnostic-rich anonymous send. NEVER throws (operator: "no
    # -stop as script must continue"). Returns $true on success, $false on
    # failure, with the relay's actual status code / .NET exception chain
    # printed inline so the operator can see WHY mail didn't arrive instead
    # of a green "[OK] anonymous mail sent" line that lied about success.
    #
    # Two phases:
    #   1. TCP pre-flight (5s, async with timeout). If we can't even open a
    #      socket -- DNS failure, firewall ACL, listener down, source-IP
    #      restriction -- skip the cmdlet call entirely and log the cause.
    #   2. Send-MailMessage with -ErrorAction SilentlyContinue + -ErrorVariable.
    #      Any non-terminating error from the cmdlet now lands in $smtpErr
    #      instead of getting swallowed; we walk the .NET exception chain
    #      (SmtpException -> SmtpStatusCode, InnerException) and print each
    #      level. Then return $false so the caller knows not to log [OK].

    Write-Output ("Sending mail (anonymous) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)

    # 1. TCP pre-flight
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($SmtpServer, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(5000, $false)) {
            $tcp.Close()
            Write-Output ("   TCP pre-flight FAILED (5s timeout) -- {0}:{1}" -f $SmtpServer, $Port)
            Write-Output  "   (likely cause: DNS resolution slow / wrong, firewall ACL silently dropping, listener not on this port)"
            return $false
        }
        $tcp.EndConnect($iar)
        $tcp.Close()
        Write-Output ("   TCP pre-flight OK -- {0}:{1} accepted connection" -f $SmtpServer, $Port)
    } catch {
        Write-Output ("   TCP pre-flight FAILED -- {0}:{1} :: {2}" -f $SmtpServer, $Port, $_.Exception.Message)
        Write-Output  "   (likely cause: DNS resolution, firewall ACL, listener down, or relay restricting source IP)"
        return $false
    }

    $params = @{
        SmtpServer  = $SmtpServer
        Port        = $Port
        From        = $From
        To          = $To
        Subject     = $Subject
        Body        = $BodyHtml
        BodyAsHtml  = $true
        Encoding    = 'UTF8'
        Priority    = $Priority
        ErrorAction = 'SilentlyContinue'
    }
    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    # 2. Send; capture any non-terminating error so we can surface details
    $smtpErr = $null
    Send-MailMessage @params -ErrorVariable smtpErr 2>$null

    if ($smtpErr -and $smtpErr.Count -gt 0) {
        Write-Output  "   SMTP send FAILED -- relay rejected or cmdlet hit a non-terminating error:"
        foreach ($er in $smtpErr) {
            $ex = $er.Exception
            if ($null -eq $ex) { continue }
            Write-Output ("   Exception type : {0}" -f $ex.GetType().FullName)
            Write-Output ("   Message        : {0}" -f $ex.Message)
            if ($ex.PSObject.Properties['StatusCode']) {
                Write-Output ("   SMTP StatusCode: {0}" -f $ex.StatusCode)
            }
            $inner = $ex.InnerException
            $depth = 0
            while ($inner -and $depth -lt 5) {
                Write-Output ("   InnerException : [{0}] {1}" -f $inner.GetType().FullName, $inner.Message)
                if ($inner.PSObject.Properties['StatusCode']) {
                    Write-Output ("   Inner StatusCode: {0}" -f $inner.StatusCode)
                }
                $inner = $inner.InnerException
                $depth++
            }
        }
        Write-Output  "   (common causes: relay requires AUTH, sender not whitelisted, RBL block, SPF/DMARC reject, TLS handshake mismatch)"
        return $false
    }

    return $true
}

function Send-MailSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SmtpServer,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter()] [bool]$UseSsl = $false,

        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,

        [Parameter()] [string[]]$Attachments,
        [Parameter()] [ValidateSet('Normal','High','Low')] [string]$Priority = 'High'
    )

    $params = @{
        SmtpServer  = $SmtpServer
        Port        = $Port
        Credential  = $Credential
        From        = $From
        To          = $To
        Subject     = $Subject
        Body        = $BodyHtml
        BodyAsHtml  = $true
        Encoding    = 'UTF8'
        Priority    = $Priority
    }

    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    Write-Output ("Sending mail (secure) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)
    Send-MailMessage @params
}

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
    if ($null -eq $global:ReportSettingsFileLocked) { $global:ReportSettingsFileLocked = "RiskAnalysis_Queries_Locked.yaml" }
    if ($null -eq $global:ReportSettingsFileCustom) { $global:ReportSettingsFileCustom = "RiskAnalysis_Queries_Custom.yaml" }
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
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "riskscore.index.custom.csv")
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

  if (-not (Test-Path -LiteralPath $lockedPath)) {
    throw "Locked YAML not found: $lockedPath"
  }

  $lockedYaml = Read-YamlFileOrNull -Path $lockedPath
  if ($null -eq $lockedYaml) {
    throw "Locked YAML was empty or could not be parsed: $lockedPath"
  }

  $customYaml = Read-YamlFileOrNull -Path $customPath

  $global:Report_Settings_raw = Merge-ReportSettings -LockedSettings $lockedYaml -CustomSettings $customYaml
  $global:Report_Settings     = ConvertTo-PSObjectDeep $global:Report_Settings_raw

  $lockedReportCount = @($lockedYaml.Reports).Count
  $lockedTplCount    = @($lockedYaml.ReportTemplates).Count
  $customReportCount = if ($customYaml) { @($customYaml.Reports).Count } else { 0 }
  $customTplCount    = if ($customYaml) { @($customYaml.ReportTemplates).Count } else { 0 }
  $mergedReportCount = @($global:Report_Settings_raw.Reports).Count
  $mergedTplCount    = @($global:Report_Settings_raw.ReportTemplates).Count

  Write-Info ("YAML merge: Locked Reports={0}, Locked Templates={1}, Custom Reports={2}, Custom Templates={3}, Merged Reports={4}, Merged Templates={5}" -f `
    $lockedReportCount, $lockedTplCount, $customReportCount, $customTplCount, $mergedReportCount, $mergedTplCount)

  if ($customYaml) { Write-Ok "report settings loaded (locked + custom merged; custom wins on name conflicts)" }
  else { Write-Ok "report settings loaded (locked only; custom file missing/empty)" }
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

function Test-IsBucketOverflowError {
  # ONLY true-overflow signals -- the kind that bucketing actually solves.
  # 'A task was canceled' / 'timeout' / 'TaskCanceledException' are TRANSIENT
  # (re-auth needed, Defender Graph backend hiccup, throttle); escalating bucket
  # count amplifies them (more buckets = more API calls = more throttle). They
  # are now classified separately via Test-IsTransientPlatformError below, which
  # the outer bucket loop reacts to with re-auth + same-bucket retry instead.
  param(
    [Parameter(Mandatory=$true)]
    [object] $Err
  )

  $msg = ""

  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $detailMsg = ""
    try { if ($Err.ErrorDetails) { $detailMsg = [string]$Err.ErrorDetails.Message } } catch {}
    $msg = [string]($Err.Exception.Message + " " + $detailMsg)
  } else {
    $msg = [string]$Err
  }

  $m = $msg.ToLowerInvariant()

  # Signatures for "too many rows / result limit / response too large"
  # (deterministic overflow -- bucketing is the right answer)
  if (
    $m -match "too many" -or
    $m -match "result.*limit" -or
    $m -match "response.*too large" -or
    $m -match "payload.*too large" -or
    $m -match "request entity too large" -or
    $m -match "exceeded the allowed result size" -or
    $m -match "exceeded the allowed limits" -or
    ($m -match "rows" -and $m -match "limit")
  ) { return $true }

  return $false
}

function Test-IsTransientPlatformError {
  # Re-auth needed / Defender Graph backend hiccup / throttle. NOT row-overflow.
  # Right response is reconnect + same-bucket retry, NOT bucket escalation.
  param([Parameter(Mandatory=$true)][object]$Err)

  $msg = ""
  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $detailMsg = ""
    try { if ($Err.ErrorDetails) { $detailMsg = [string]$Err.ErrorDetails.Message } } catch {}
    $msg = [string]($Err.Exception.Message + " " + $detailMsg)
  } else {
    $msg = [string]$Err
  }
  $m = $msg.ToLowerInvariant()

  if ($Err -is [System.Management.Automation.ErrorRecord] -and
      $Err.Exception -is [System.Threading.Tasks.TaskCanceledException]) { return $true }

  if (
    $m -match "a task was canceled" -or
    $m -match "taskcanceledexception" -or
    $m -match "timed out" -or
    $m -match "timeout" -or
    $m -match "too many requests" -or
    $m -match "\b429\b" -or
    $m -match "throttl" -or
    $m -match "\b503\b" -or
    $m -match "\b502\b" -or
    $m -match "\b504\b" -or
    $m -match "service unavailable" -or
    $m -match "bad gateway" -or
    $m -match "gateway timeout" -or
    $m -match "invalidauthenticationtoken" -or
    $m -match "access token" -or
    $m -match "\b401\b" -or
    $m -match "unauthorized" -or
    $m -match "forbidden temporarily"
  ) { return $true }

  return $false
}

function Get-AutoBucketCachePath {
  param([Parameter(Mandatory=$true)][string]$SettingsPath)
  Join-Path $SettingsPath "OUTPUT\AutoBucketCache.json"
}

function ConvertTo-HashtableDeep {
  param([Parameter(Mandatory=$true)]$InputObject)

  if ($null -eq $InputObject) { return $null }

  # Hashtable / IDictionary
  if ($InputObject -is [System.Collections.IDictionary]) {
    $out = @{}
    foreach ($k in $InputObject.Keys) {
      $out[[string]$k] = ConvertTo-HashtableDeep -InputObject $InputObject[$k]
    }
    return $out
  }

  # PSCustomObject
  if ($InputObject -is [pscustomobject]) {
    $out = @{}
    foreach ($p in $InputObject.PSObject.Properties) {
      $out[[string]$p.Name] = ConvertTo-HashtableDeep -InputObject $p.Value
    }
    return $out
  }

  # IEnumerable (but not string)
  if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
    $list = @()
    foreach ($i in $InputObject) {
      $list += ,(ConvertTo-HashtableDeep -InputObject $i)
    }
    return $list
  }

  return $InputObject
}

function Read-AutoBucketCache {
  param([Parameter(Mandatory=$true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { return @{} }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }

    $obj = ($raw | ConvertFrom-Json -ErrorAction Stop)
    if ($null -eq $obj) { return @{} }

    $ht = ConvertTo-HashtableDeep -InputObject $obj
    if ($null -eq $ht) { return @{} }

    # Support both flat and wrapped cache formats
    foreach ($wrapper in @('Entries','Cache','Data','AutoBucket')) {
      if (($ht -is [hashtable]) -and $ht.ContainsKey($wrapper) -and ($ht[$wrapper] -is [hashtable])) {
        return $ht[$wrapper]
      }
    }

    if ($ht -is [hashtable]) { return $ht }

    # If the root isn't a hashtable, treat it as empty (unexpected format)
    return @{}
  } catch {
    return @{}
  }
}

function Get-AutoBucketCacheFallbackValue {
  param(
    [Parameter(Mandatory=$true)][hashtable]$Cache,
    [Parameter(Mandatory=$true)][string]$QueryKey,
    [Parameter(Mandatory=$true)][int]$MaxBucketCount
  )

  # PowerShell 5.1 compatibility + cache format migration:
  # - New cache key format is: <ReportName>|<QueryHash>
  # - Older cache files may still contain keys like: <ReportName>|<QueryHash>|cap<Max>
  #
  # If the exact key is missing, try to reuse any legacy cap-key for the same base key.
  $base = [string]$QueryKey
  if ([string]::IsNullOrWhiteSpace($base)) { return $null }

  $legacyPrefix = ($base + '|cap')
  $candidates = New-Object System.Collections.Generic.List[int]

  foreach ($k in $Cache.Keys) {
    $ks = [string]$k
    if ($ks -eq $base -or $ks -like ($legacyPrefix + '*')) {
      $v = $Cache[$k]
      $vi = 0
      if ([int]::TryParse([string]$v, [ref]$vi)) {
        if ($vi -ge 1) { $candidates.Add($vi) }
      }
    }
  }

  if ($candidates.Count -eq 0) { return $null }

  # Use the largest cached "working" bucket count to avoid re-probing.
  $best = ($candidates | Measure-Object -Maximum).Maximum
  $best = [int]$best
  if ($best -lt 1) { return $null }
  if ($best -gt $MaxBucketCount) { $best = $MaxBucketCount }
  return $best
}

function Get-StableQueryHash32 {
  param(
    [Parameter(Mandatory=$true)][string]$Text
  )

  # NOTE: .NET string.GetHashCode() is not stable across processes.
  # We use SHA256 and take the first 4 bytes as an unsigned 32-bit integer.
  $norm = ($Text -replace '\s+', ' ').Trim()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($norm)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hashBytes = $sha.ComputeHash($bytes)
  } finally {
    if ($sha -and ($sha -is [System.IDisposable])) { $sha.Dispose() }
  }

  return [System.BitConverter]::ToUInt32($hashBytes, 0)
}

function Write-AutoBucketCache {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][object]$CacheObject
  )

  $dir = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $CacheObject | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-CacheValue {
  param([Parameter(Mandatory=$true)][object]$Cache,[Parameter(Mandatory=$true)][string]$Key)

  if ($Cache -is [hashtable]) {
    if ($Cache.ContainsKey($Key)) { return $Cache[$Key] }
    return $null
  }

  try {
    $p = $Cache.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
  } catch {}

  return $null
}

function Set-CacheValue {
  param([Parameter(Mandatory=$true)][ref]$Cache,[Parameter(Mandatory=$true)][string]$Key,[Parameter(Mandatory=$true)][int]$Value)

  if ($Cache.Value -is [hashtable]) {
    $Cache.Value[$Key] = $Value
    return
  }

  try {
    $Cache.Value | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force
  } catch {
    $ht = @{}
    foreach ($prop in $Cache.Value.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
    $ht[$Key] = $Value
    $Cache.Value = $ht
  }
}

function Get-OptimalBucketCount {
  param(
    [Parameter(Mandatory=$true)][string]$QueryKey,
    [Parameter(Mandatory=$false)][string[]]$LegacyKeys,
    [Parameter(Mandatory=$true)][int]$MaxBucketCount,
    [Parameter(Mandatory=$true)][scriptblock]$ProbeScript,
    [Parameter(Mandatory=$false)][int]$MinBucketCount = 1
  )

  if ($MaxBucketCount -lt 1) { return 1 }
  if ($MinBucketCount -lt 1) { $MinBucketCount = 1 }
  if ($MinBucketCount -gt $MaxBucketCount) { $MinBucketCount = $MaxBucketCount }

  # Memo. Honour only if >= floor; otherwise re-probe (user raised the floor
  # via YAML BucketCount, so a smaller cached value is stale).
  if ($script:AutoBucketMemo.ContainsKey($QueryKey)) {
    $memoVal = [int]$script:AutoBucketMemo[$QueryKey]
    if ($memoVal -ge $MinBucketCount) { return $memoVal }
  }
  if ($LegacyKeys) {
    foreach ($lk in $LegacyKeys) {
      if (-not [string]::IsNullOrWhiteSpace($lk) -and $script:AutoBucketMemo.ContainsKey($lk)) {
        $val = [int]$script:AutoBucketMemo[$lk]
        if ($val -ge $MinBucketCount) {
          $script:AutoBucketMemo[$QueryKey] = $val
          return $val
        }
      }
    }
  }

  # Cache on disk (optional)
  $cachePath = $null
  $cache = $null
  if ([bool]$global:AutoBucketCache -and -not [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $cachePath = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
    $cache = Read-AutoBucketCache -Path $cachePath
    # Read-AutoBucketCache returns a hashtable, but keep the older getter for safety
    $cached = Get-CacheValue -Cache $cache -Key $QueryKey
    if ($null -ne $cached) {
      $ci = [int]$cached
      if ($ci -ge $MinBucketCount -and $ci -le $MaxBucketCount) {
        Write-Info ("AutoBucket cache hit: '{0}' => {1}" -f $QueryKey, $ci)
        $script:AutoBucketMemo[$QueryKey] = $ci
        return $ci
      } elseif ($ci -lt $MinBucketCount) {
        Write-Info ("AutoBucket cache hit '{0}' => {1} ignored (below YAML floor {2}; re-probing from floor)" -f $QueryKey, $ci, $MinBucketCount)
      }
    }

    # Try legacy keys (e.g., old unstable GetHashCode-based identity)
    if ($LegacyKeys) {
      foreach ($lk in $LegacyKeys) {
        if ([string]::IsNullOrWhiteSpace($lk)) { continue }
        $cached2 = Get-CacheValue -Cache $cache -Key $lk
        if ($null -ne $cached2) {
          $ci2 = [int]$cached2
          if ($ci2 -ge $MinBucketCount -and $ci2 -le $MaxBucketCount) {
            Write-Info ("AutoBucket cache hit (legacy): '{0}' => {1}" -f $lk, $ci2)
            # Migrate in-memory to new key
            $script:AutoBucketMemo[$QueryKey] = $ci2
            # Persist migration best-effort
            if ($cachePath) {
              $cacheRef = [ref]$cache
              Set-CacheValue -Cache $cacheRef -Key $QueryKey -Value $ci2
              $cache = $cacheRef.Value
              try { Write-AutoBucketCache -Path $cachePath -CacheObject $cache } catch {}
            }
            return $ci2
          }
        }
      }
    }

    # Fallback for old cache formats (cap in key) and other key mismatches
    if ($cache -is [hashtable]) {
      $fallback = Get-AutoBucketCacheFallbackValue -Cache $cache -QueryKey $QueryKey -MaxBucketCount $MaxBucketCount
      if ($null -ne $fallback -and [int]$fallback -ge $MinBucketCount) {
        Write-Info ("AutoBucket cache fallback: '{0}' => {1}" -f $QueryKey, $fallback)
        $script:AutoBucketMemo[$QueryKey] = [int]$fallback
        return [int]$fallback
      }
    }
  }

  # Exponential probe: starts at MinBucketCount (configured YAML floor), then
  # doubles. Probing below the YAML-declared floor wastes one ~900s attempt
  # per ramp-up step and confuses operators ("why is it starting at 1 when I
  # said 64?"). The probe still ESCALATES (doubles) past the floor when the
  # configured count itself overflows.
  $try = $MinBucketCount
  $lastFail = $MinBucketCount - 1
  if ($lastFail -lt 0) { $lastFail = 0 }
  $firstOk = 0

  while ($try -le $MaxBucketCount) {
    try {
      Write-Info ("AutoBucket probing '{0}' with bucketCount={1}" -f $QueryKey, $try)
      & $ProbeScript -BucketCount $try | Out-Null
      $firstOk = $try
      break
    } catch {
      if (-not (Test-IsBucketOverflowError $_)) { throw }
      $lastFail = $try
      $try = $try * 2
    }
  }

  if ($firstOk -eq 0) {
    throw ("AutoBucket: query '{0}' did not succeed up to MaxBucketCount={1}" -f $QueryKey, $MaxBucketCount)
  }

  # Binary search: (lastFail, firstOk]
  $low = [Math]::Max($lastFail + 1, 1)
  $high = $firstOk

  while ($low -lt $high) {
    $mid = [int][Math]::Floor(($low + $high) / 2)
    try {
      Write-Info ("AutoBucket binary probe '{0}' with bucketCount={1}" -f $QueryKey, $mid)
      & $ProbeScript -BucketCount $mid | Out-Null
      $high = $mid
    } catch {
      if (-not (Test-IsBucketOverflowError $_)) { throw }
      $low = $mid + 1
    }
  }

  $optimal = $low
  Write-Info ("AutoBucket chosen for '{0}': {1}" -f $QueryKey, $optimal)

  $script:AutoBucketMemo[$QueryKey] = $optimal

  if ($cachePath) {
    $cacheRef = [ref]$cache
    Set-CacheValue -Cache $cacheRef -Key $QueryKey -Value $optimal
    $cache = $cacheRef.Value
    try { Write-AutoBucketCache -Path $cachePath -CacheObject $cache } catch {}
  }

  return $optimal
}

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

foreach ($includeItem in $global:Exposure_Template_ReportsIncluded) {
  try {

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
    $effectiveBucketCount = if ($ReportNameFromTemplate -like '*_Detailed*' -or $ReportNameFromTemplate -like '*_Detailed_*') {
        if ($global:SI_AutoBucketDefaultDetailed) { [int]$global:SI_AutoBucketDefaultDetailed } else { 32 }
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

          $probe = {
            param([int]$BucketCount)

            # Probe only bucket 0. If this bucket still exceeds limits, smaller buckets are needed.
            $bucketFilter = New-BucketFilterKql -BucketCount $BucketCount -BucketIndex 0 -ReportName $ReportName
            $probeQuery   = Replace-BucketFilterBlock -Query $Query -BucketFilterKql $bucketFilter

            $null = Invoke-GraphHuntingQuery -Query $probeQuery `
              -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes `
              -MaxRetries 1
          }

          try {
            # v2.2.281 -- pass YAML BucketCount as the AutoBucket probe FLOOR. Without
            # this AutoBucket starts every probe at bucketCount=1 and doubles upward,
            # so an explicit `BucketCount: 64` in YAML still costs five wasted ~900s
            # probe attempts (1, 2, 4, 8, 16, 32) before reaching the configured count.
            # The floor lets a tenant operator say "you don't need to try less than 64"
            # while still allowing escalation past 64 when 64 itself overflows.
            $bucketCountToUse = Get-OptimalBucketCount -QueryKey $queryKey -LegacyKeys @($legacyKey) -MaxBucketCount $capBucket -MinBucketCount $effectiveBucketCount -ProbeScript $probe
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

# v2.2.273 -- per-report snapshot row tracker, reset here so the AutoBucket
# escalation logic only sees CL snapshot sizes from THIS report (not a leak
# from a prior heavier report).
$script:_LastHybridSnapshotRowCount = 0

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
                      Write-Warn2 ("bucket {0}/{1}: overflow/preempted (often transient XDR backend load). Retry attempt {2}/{3} after {4}s before escalating. Error: {5}" -f `
                        $bucketNo, $bucketCountToUse, $bucketOverflowAttempt, $bucketOverflowRetries, $sleepSec, $errMsg)
                      Start-Sleep -Seconds $sleepSec
                      # Loop continues; same bucket retried at same bucketCountToUse.
                  } else {
                      $lastBucketRunError = $errMsg
                      Write-Warn2 ("bucket {0}/{1} overflowed on {2} consecutive attempts -- treating as genuine data overflow. Escalating bucket count and restarting this report. Error: {3}" -f `
                        $bucketNo, $bucketCountToUse, $bucketOverflowRetries, $errMsg)
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
                  # EG-path-expansion reports on large estates (Nordstern Attack_Paths_*_
                  # Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure)
                  # that previously got stuck at cached BucketCount=2 forever.
                  if ($script:_LastGraphHuntingAllTimedOut) {
                      # v2.2.277 -- ADAPTIVE SUB-BUCKETING. The v2.2.272 behavior
                      # restarted the whole report at 4x bucket count when ANY
                      # bucket timed out, throwing away all already-completed
                      # buckets. Worse: at scale (e.g. Nordstern 100K-edge tenants)
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
      # row count seen during this report. Heuristic: at ~500 rows per bucket the
      # AH backend completes within the 900s ceiling for typical EG-path-expansion
      # joins, so a 100K-row snapshot wants ~200 buckets immediately rather than
      # grinding through 8 -> 32 -> 128 -> 512.
      $snapshotJump = 0
      if ($script:_LastHybridSnapshotRowCount -and [int]$script:_LastHybridSnapshotRowCount -gt 0) {
          $snapshotJump = [int][Math]::Ceiling([int]$script:_LastHybridSnapshotRowCount / 500.0)
      }
      $jumpCandidates = @(($bucketCountToUse * 4), ($bucketCountToUse + 1), $snapshotJump)
      $nextBucket = [Math]::Min($capBucket, ($jumpCandidates | Measure-Object -Maximum).Maximum)
      if ($snapshotJump -gt 0 -and $snapshotJump -ge ($bucketCountToUse * 4)) {
          Write-Info ("AutoBucket escalation jump informed by snapshot size ({0} rows / 500 = {1} buckets)" -f $script:_LastHybridSnapshotRowCount, $snapshotJump)
      }

      Write-Warn2 ("AutoBucket escalation: rerunning report '{0}' with BucketCount {1} -> {2}" -f `
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
      # BucketCount). Customer's Nordstern run hit the depth=4 cap with one
      # slice still timing out; deeper splits give the recursive partition
      # more room before giving up. Tunable via $global:SI_AutoBucketSubDepthMax.
      $subDepthMax = if ($null -ne $global:SI_AutoBucketSubDepthMax) { [int]$global:SI_AutoBucketSubDepthMax } else { 6 }
      $subFanOut   = if ($null -ne $global:SI_AutoBucketSubFanOut)   { [int]$global:SI_AutoBucketSubFanOut }   else { 4 }
      Write-Warn2 ("AutoBucket sub-bucketing pass: {0} bucket(s) timed out at BucketCount={1}; splitting each into {2} sub-buckets per pass (max depth {3}). Successful buckets retained ({4} rows so far)." -f `
        $failedBucketIndices.Count, $bucketCountToUse, $subFanOut, $subDepthMax, $ResultAll.Count)

      # BFS queue: each item = @{ N = parent-index; T = parent-total; D = current-depth }
      $subQueue = New-Object System.Collections.Generic.Queue[object]
      foreach ($idx in $failedBucketIndices) {
          $subQueue.Enqueue(@{ N = [int]$idx; T = [int]$bucketCountToUse; D = 1 })
      }

      while ($subQueue.Count -gt 0) {
          $item    = $subQueue.Dequeue()
          $pN      = [int]$item.N
          $pT      = [int]$item.T
          $depth   = [int]$item.D
          $newT    = $pT * $subFanOut

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
                  if ($script:_LastGraphHuntingAllTimedOut -and $depth -lt $subDepthMax) {
                      Write-Warn2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} timed out -- queueing for further split (depth {5})" -f $depth, $pN, $pT, ($j + 1), $subFanOut, ($depth + 1))
                      $subQueue.Enqueue(@{ N = $subN; T = $newT; D = ($depth + 1) })
                  } elseif ($script:_LastGraphHuntingAllTimedOut) {
                      Write-Err2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} timed out at MAX DEPTH {5} -- giving up on this slice (rows in this sub-bucket NOT included). Error: {6}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $depth, $subErr)
                  } else {
                      Write-Err2 ("[sub-bucket] depth={0} parent={1}/{2} sub={3}/{4} failed (non-timeout): {5}" -f $depth, $pN, $pT, ($j + 1), $subFanOut, $subErr)
                  }
              }
          }
      }
      Write-Info ("[sub-bucket] pass complete; total rows after sub-bucketing: {0}" -f $ResultAll.Count)
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
    # Detect Detailed reports by presence of an AssetName column — Detailed reports project
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

    $firstObj = $RiskScoreArray | Select-Object -First 1
    if ($firstObj) {
      $allProps = ($firstObj | Get-Member -MemberType NoteProperty).Name
      foreach ($p in $allProps) {
        if ($DesiredColumns -notcontains $p -and $p -notin $TraceCols -and $p -notin $systemArrayProps) { $DesiredColumns += $p }
      }
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
    if (-not $global:FinalDesiredColumns) {
        $global:FinalDesiredColumns = $DesiredColumns
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
        $global:FinalDesiredColumns = ($global:AllShapedRows[0] | Get-Member -MemberType NoteProperty).Name
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
                # Schema sample (first 100 rows) -- used by CheckCreateUpdate to
                # infer the target table schema. Same pattern as IAC.
                $schemaSample = @($global:final | Select-Object -First 100)

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
                Write-Warn ("Log Analytics ingest failed: {0} (continuing -- xlsx + json still on disk)" -f $_.Exception.Message)
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

    if ($null -eq $global:final -or @($global:final).Count -eq 0) {
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
            $assetRanked = $assetAgg.Values |
                Sort-Object -Property @{Expression="TotalRiskScore_Weighted";Descending=$true}, @{Expression="TotalRiskScore";Descending=$true}, @{Expression="Findings";Descending=$true} |
                Select-Object -First $TopAssetsN
        }

        # v2.2.224 -- finding rollup (parallel to asset rollup)
        $findingRanked = @()
        if ($findingAgg.Count -gt 0) {
            $findingRanked = $findingAgg.Values |
                Sort-Object -Property @{Expression="TotalRiskScore_Weighted";Descending=$true}, @{Expression="TotalRiskScore";Descending=$true}, @{Expression="AffectedAssetCount";Descending=$true} |
                Select-Object -First $TopFindingsN
        }

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

Risk scoring is transparent: Consequence × Probability = RiskScore, based on raw Kusto query outputs and a customizable risk index.
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
A) An asset rollup (top $assetActualN, already ranked by Weighted Risk Score).
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

- **<Rank>. <AssetName>** -- Tier **<Tier>** | Total Risk Score **<TotalRiskScore>** | Weighted Risk Score **<WeightedRiskScore>** | Findings **<Count>** | Domains: <Domains>

## Top $findingActualN critical findings

One bullet per finding, in rank order. Use the AffectedAssetCount and Weighted
Risk Score from the finding rollup. List up to 4 of the TopAffectedAssets per
bullet (the assets that contribute the most risk score to this finding).
Output EXACTLY $findingActualN bullets.

- **<Rank>. <ConfName>** [<ConfId>] -- Severity **<Severity>** | Affected assets **<AffectedAssetCount>** | Weighted Risk Score **<WeightedRiskScore>** | Top affected: <up to 4 asset names>

## Top $drilldownN asset drilldown

For each of the Top $drilldownN assets (same order as the asset rollup), output exactly this structure (separate each asset with a blank line):

### <Rank>. <AssetName>

- **Tier:** <Tier> | **Total Risk Score:** <TotalRiskScore> | **Weighted Risk Score:** <WeightedRiskScore>
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

        Write-Host "`n[AI SUMMARY RESPONSE]`n" -ForegroundColor Cyan

        $sb = New-Object System.Text.StringBuilder

        $reader = $null
        $client = $null

        try {
            $body = @{
                model = $global:AI_deployment
                stream = $true
                temperature = 0.2
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

    foreach ($r in $rows) {
        $dom = ''
        if ($r.PSObject.Properties['SecurityDomain']) { $dom = [string]$r.SecurityDomain }
        if ($dom -eq 'PublicIp') { $dom = 'PublicIP' }

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

        $domainAcc[$dom].Numer += $rowKpi * $tw
        $domainAcc[$dom].Denom += $tw
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
"@
    } else {
        $aiSection = @"
        <p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#888;margin-top:18px;">AI narrative not included this run. Enable with <code>$global:BuildSummaryByAI=`$true</code> in the launcher.</p>
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

Send-RARunHealthEnd -ExitReason 'success'
Write-Section "script completed"
