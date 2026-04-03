#------------------------------------------------------------------------------------------------
Write-host "***********************************************************************************************"
Write-host "Risk-based Security Exposure Insight"
Write-host ""
write-host "Security Insight: Rethink Secure Score into a new risk-based security risk score, based on consequence, probability and risk factors. "
write-host "Solution includes critical asset tagging, ready-to-use reports (based on Defender Exposure Graph and Azure Resource Graphs),"
write-host "automation-scripts, risk index and more"
Write-host ""
Write-host "Support: mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight"
Write-host "***********************************************************************************************"

# Disable StrictMode (script designed for non-StrictMode environments)
try {
    Set-StrictMode -Off
} catch {}

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
    "UseQueryBucketing",
    "DefaultBucketCount",
    "BucketPlaceholderToken",
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
if (-not $global:ReportTemplate -or [string]::IsNullOrWhiteSpace([string]$global:ReportTemplate)) {
  $global:ReportTemplate = 'RiskAnalysis_Summary'
}
if ($null -eq $global:OverwriteXlsx)          { $global:OverwriteXlsx = $true  }
if ($null -eq $global:AutomationFramework)   { $global:AutomationFramework = $false }
if ($null -eq $global:Summary)               { $global:Summary = $false }
if ($null -eq $global:Detailed)              { $global:Detailed = $false }
if ($null -eq $global:SendMail)              { $global:SendMail = $false }
if ($null -eq $global:BuildSummaryByAI)      { $global:BuildSummaryByAI = $false }
if ($null -eq $global:ShowConfig)            { $global:ShowConfig = $false }

# NEW: AutoBucket defaults (adaptive bucketing)
if ($null -eq $global:AutoBucketCount) { $global:AutoBucketCount = $false }   # enable adaptive bucket selection (probe bucketCount=1..N)
if ($null -eq $global:AutoBucketMax)   { $global:AutoBucketMax = 64 }        # safety cap for probing
if ($null -eq $global:AutoBucketCache) { $global:AutoBucketCache = $true }   # cache discovered bucket counts to disk

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

# Defaults for bucketing (can be overridden via YAML or include-items)
if ($null -eq $global:UseQueryBucketing)      { $global:UseQueryBucketing = $false }
if ($null -eq $global:DefaultBucketCount)     { $global:DefaultBucketCount = 2 }
if (-not $global:BucketPlaceholderToken -or [string]::IsNullOrWhiteSpace([string]$global:BucketPlaceholderToken)) {
  $global:BucketPlaceholderToken = "__BUCKET_FILTER__"
}

# Graph tuning defaults
if ($null -eq $global:GraphReconnectMaxAgeMinutes) { $global:GraphReconnectMaxAgeMinutes = 45 }
if ($null -eq $global:GraphQueryMaxRetries)        { $global:GraphQueryMaxRetries = 4 }

# Normalize SettingsPath
try {
  $global:SettingsPath = (Resolve-Path -LiteralPath $global:SettingsPath).Path
} catch {
  throw "SettingsPath does not exist or cannot be resolved: $($global:SettingsPath)"
}

# Validate required launcher-provided globals
if ([string]::IsNullOrWhiteSpace([string]$global:ReportTemplate)) {
  throw "Global:ReportTemplate is empty. Launcher must set it."
}

# If SendMail is enabled, MailTo must exist (non-automation path uses this)
if ($global:SendMail -eq $true) {
  if (-not $global:MailTo -or @($global:MailTo).Count -eq 0) {
    throw "Global:SendMail is true, but Global:MailTo is empty."
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
function Write-Step   ($msg){ Write-Host ("[STEP] {0}" -f $msg) -ForegroundColor Cyan }
function Write-Info   ($msg){ Write-Host ("[INFO] {0}" -f $msg) -ForegroundColor Gray }
function Write-Ok     ($msg){ Write-Host ("[OK]   {0}" -f $msg) -ForegroundColor Green }
function Write-Warn2  ($msg){ Write-Host ("[WARN] {0}" -f $msg) -ForegroundColor Yellow }
function Write-Err2   ($msg){ Write-Host ("[ERR]  {0}" -f $msg) -ForegroundColor Red }
function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Step ("Installing module $($Name)...")
    Install-Module $Name -Scope AllUsers -Force -AllowClobber
  } else {
    Write-Step ("Validating module $($Name)...")
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

    Write-Info "Connecting to Microsoft Graph (app+secret)..."
    Connect-MicrosoftGraphPS -AppId $global:SpnClientId `
                             -AppSecret $global:SpnClientSecret `
                             -TenantId $global:SpnTenantId

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

function Invoke-GraphHuntingQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$ReconnectMaxAgeMinutes = 45,
        [int]$MaxRetries = 4
    )

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Ensure-GraphAuth -MaxAgeMinutes $ReconnectMaxAgeMinutes

        try {
            return Start-MgSecurityHuntingQuery -Query $Query -ErrorAction Stop
        } catch {
            $msg = $_.Exception.Message

            $isTaskCanceled = ($_.Exception -is [System.Threading.Tasks.TaskCanceledException]) -or ($msg -match 'A task was canceled')
            $looksAuth      = ($msg -match 'InvalidAuthenticationToken|Access token|Authentication|Unauthorized|401')
            $looksThrottle  = ($msg -match 'Too Many Requests|429|throttl|temporar')

            
            $looksOverflow  = (Test-IsBucketOverflowError -Err $_) -or ($msg -match 'exceeded the allowed result size|exceeded the allowed limits|preempted')
if ($looksAuth) {
                Write-Warn2 "Graph auth issue detected. Reconnecting and retrying..."
                try { Connect-GraphHighPriv } catch { Write-Err2 "Graph reconnect failed: $($_.Exception.Message)"; throw }
            }

            
            if ($looksOverflow) {
                Write-Warn2 "Query exceeded allowed limits/result size; not retrying (deterministic failure)."
                throw
            }

if ($attempt -lt $MaxRetries) {
                $sleepSec = if ($looksThrottle) { [math]::Min(60, 5 * $attempt) }
                            elseif ($isTaskCanceled) { [math]::Min(90, 15 * $attempt) }
                            else { [math]::Min(20, 2 * $attempt) }

                $reason = if ($isTaskCanceled) { "Likely Graph client timeout (TaskCanceledException)" } else { "Query failed" }
                Write-Warn2 ("{0} (attempt {1}/{2}). Waiting {3}s then retrying... {4}" -f $reason, $attempt, $MaxRetries, $sleepSec, $msg)
                Start-Sleep -Seconds $sleepSec
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
      Text   = $lines[$i]
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
  param([int]$BucketCount,[int]$BucketIndex)

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
            Name                   = $Item
            UseQueryBucketing      = $null
            DefaultBucketCount     = $null
            BucketPlaceholderToken = $null
        }
    }

    $name = $null
    if     ($Item.PSObject.Properties['Name'])       { $name = [string]$Item.Name }
    elseif ($Item.PSObject.Properties['ReportName']) { $name = [string]$Item.ReportName }

    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "ReportsIncluded item is missing 'Name'. Item: $($Item | ConvertTo-Json -Depth 8 -Compress)"
    }

    $useBucketing = $null
    if ($Item.PSObject.Properties['UseQueryBucketing']) { $useBucketing = [bool]$Item.UseQueryBucketing }

    $bucketCount = $null
    if ($Item.PSObject.Properties['DefaultBucketCount']) { $bucketCount = [int]$Item.DefaultBucketCount }

    $token = $null
    if ($Item.PSObject.Properties['BucketPlaceholderToken']) { $token = [string]$Item.BucketPlaceholderToken }

    return [pscustomobject]@{
        Name                   = $name
        UseQueryBucketing      = $useBucketing
        DefaultBucketCount     = $bucketCount
        BucketPlaceholderToken = $token
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

    function _toDouble([object]$v) {
        if ($null -eq $v) { return 0.0 }
        if ($v -is [double]) { return [double]$v }
        if ($v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [single]) { return [double]$v }
        $n = 0.0
        [void][double]::TryParse([string]$v, [ref]$n)
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
                if ($TraceLocal -and $key) { Write-Host ("[{0}] tried WITH-domain #{1}: {2} -> no match" -f $Kind, ($i+1), $key) -ForegroundColor DarkGray }
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
            if ($TraceLocal -and $key) { Write-Host ("[{0}] tried NO-domain #{1}: {2} -> no match" -f $Kind, ($j+1), $key) -ForegroundColor DarkGray }
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

        $rfCons = _asBit (_get $r $RiskFactorConsequenceInputName)
        $rfProb = _asBit (_get $r $RiskFactorProbabilityInputName)

        $consBase = _findScore -Kind 'Consequence' -kv $kv -Index $RiskIndex -TraceLocal:$Trace
        $probBase = _findScore -Kind 'Probability' -kv $kv -Index $RiskIndex -TraceLocal:$Trace

        $consAdj = ([double]$consBase.Score) + ([double]$rfCons)
        $probAdj = ([double]$probBase.Score) + ([double]$rfProb)
        $risk    = $consAdj * $probAdj

        $tmp = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $tmp[$p.Name] = $p.Value }

        $tmp[$SecurityDomainInputName]        = $domainValue
        $tmp[$RiskConsequenceScoreOutputName] = [double]$consAdj
        $tmp[$RiskProbabilityScoreOutputName] = [double]$probAdj
        $tmp[$RiskScoreOutputName]            = [double]$risk

        if (-not $tmp.Contains('RiskFactor_Consequence')) { $tmp['RiskFactor_Consequence'] = [int]$rfCons }
        if (-not $tmp.Contains('RiskFactor_Probability')) { $tmp['RiskFactor_Probability'] = [int]$rfProb }

        if ($OutputPropertyOrder -and $OutputPropertyOrder.Count -gt 0) {
            $h = [ordered]@{}
            foreach ($name in $OutputPropertyOrder) { if ($tmp.Contains($name)) { $h[$name] = $tmp[$name] } }
            foreach ($k in $tmp.Keys) { if (-not $h.Contains($k)) { $h[$k] = $tmp[$k] } }
            $out.Add([pscustomobject]$h) | Out-Null
        } else {
            $out.Add([pscustomobject]$tmp) | Out-Null
        }
    }

    Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Completed

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
    for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
      if ($ws.Column($col).Width -gt 50) { $ws.Column($col).Width = 50 }
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

  $excel = $Data | Export-Excel -Path $Path -WorksheetName $safeSheet -TableStyle $TableStyle `
    -TableName $tableName -AutoFilter -FreezeTopRow -BoldTopRow -ClearSheet -PassThru

  $ws = $excel.Workbook.Worksheets[$safeSheet]
  $ws.Cells.AutoFitColumns()
  for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
    if ($ws.Column($col).Width -gt 50) { $ws.Column($col).Width = 50 }
  }
  Close-ExcelPackage $excel

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

    $params = @{
        SmtpServer = $SmtpServer
        Port       = $Port
        From       = $From
        To         = $To
        Subject    = $Subject
        Body       = $BodyHtml
        BodyAsHtml = $true
        Encoding   = 'UTF8'
        Priority   = $Priority
    }

    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    Write-Output ("Sending mail (anonymous) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)
    Send-MailMessage @params
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

function Test-AzModuleInstalled {
    Write-Step "Validating Az modules"
    return $null -ne (Get-Module -ListAvailable -Name 'Az.Accounts' -ErrorAction SilentlyContinue)
}

function Test-MicrosoftGraphInstalled {
    Write-Step "Validating Microsoft Graph modules"
    return $null -ne (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue)
}

#####################################################################################################
# POWERSHELL MODULE VALIDATION
#####################################################################################################

Write-Step "initializing"

if (-not (Test-AzModuleInstalled)) {
    Write-Step "Installing Az modules ... Please Wait !"
    Install-Module Az -Scope AllUsers -Force -AllowClobber
}

if (-not (Test-MicrosoftGraphInstalled)) {
    Write-Step "Installing Microsoft Graph modules ... Please Wait !"
    Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber
}

Ensure-Module Az.Accounts
Ensure-Module Az.Resources
Ensure-Module Az.ResourceGraph
Ensure-Module Microsoft.Graph.Security
Ensure-Module MicrosoftGraphPS
Ensure-Module ImportExcel
Ensure-Module powershell-yaml

#####################################################################################################
# CONNECTION
#####################################################################################################

if ([bool]$global:AutomationFramework) {

    #----------------------
    # AUTOMATION FRAMEWORK
    #----------------------

    $global:ScriptDirectory = $PSScriptRoot
    $global:PathScripts     = Split-Path -parent $global:ScriptDirectory
    Write-Output ""
    Write-Output "Script Directory -> $($global:PathScripts)"

    # Loading function modules (2LINKIT)
    Write-Step "importing function modules"
    Tock
    try {
      Import-Module "$($global:PathScripts)\FUNCTIONS\2LINKIT-Functions.psm1" -Global -Force -WarningAction SilentlyContinue
      Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-ConnectDetails.psm1" -Global -Force -WarningAction SilentlyContinue
      Write-Ok "modules imported"
    } catch { Write-Err2 "failed to import one or more modules: $($_.Exception.Message)"; throw }
    Tick "module import"

    Write-Step "loading connect details and defaults"
    Tock
    try {
      ConnectDetails
      Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-DefaultVariables.psm1" -Global -Force -WarningAction SilentlyContinue
      Default_Variables
      Write-Ok "connect details and defaults loaded"
    } catch { Write-Err2 "failed while loading connect details/defaults: $($_.Exception.Message)"; throw }
    Tick "connect details + defaults"

    Write-Step "connecting to Azure (helper Connect_Azure.ps1)"
    Tock
    try {
      & "$($global:PathScripts)\FUNCTIONS\Connect_Azure.ps1"
      Write-Ok "azure connection step done"
    } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }

    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure

    if ([bool]$global:ShowConfig) { Show-ResolvedConfig -Stage "after AutomationFramework defaults loaded" }

    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientSecret)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). Provide them via wrapper globals or enable -AutomationFramework to load them."
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
    # Output File
    #------------------------------------------------------------------------------------------------------------
    $global:OutputDir  = Join-Path $global:PathScripts 'OUTPUT'
    Ensure-Directory -Path $global:OutputDir
    $global:OutputXlsx = Join-Path $global:OutputDir ("{0}.xlsx" -f $global:ReportTemplate)

    #------------------------------------------------------------------------------------------------------------
    # Mail routing (Summary vs Detailed)
    #------------------------------------------------------------------------------------------------------------
    if ([bool]$global:Detailed -and [bool]$global:Summary) {
      throw "Invalid parameters: Use only one of -Detailed or -Summary."
    }

    if ([bool]$global:Detailed) {
      Write-Info "Mail mode selected: Detailed"
      $global:Report_SendMail = [bool]$global:Mail_SecurityInsight_Detailed_SendMail
      $global:Report_To       = @($global:Mail_SecurityInsight_Detailed_To)
    }
    elseif ([bool]$global:Summary) {
      Write-Info "Mail mode selected: Summary"
      $global:Report_SendMail = [bool]$global:Mail_SecurityInsight_Summary_SendMail
      $global:Report_To       = @($global:Mail_SecurityInsight_Summary_To)
    }
    else {
      Write-Info "Mail mode selected: Default (no -Detailed/-Summary provided)"
      $global:Report_SendMail = [bool]$global:Mail_SecurityInsight_Detailed_SendMail
      $global:Report_To       = @($global:Mail_SecurityInsight_Detailed_To)
    }

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $global:Report_SendMail, ($global:Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # RiskAnalysis query settings
    #------------------------------------------------------------------------------------------------------------
    # The locked YAML is centrally maintained.
    # Customers can optionally add/override in the custom YAML.
    if ($null -eq $global:ReportSettingsFileLocked) { $global:ReportSettingsFileLocked = "SecurityInsight_RiskAnalysis_Queries_Locked.yaml" }
    if ($null -eq $global:ReportSettingsFileCustom) { $global:ReportSettingsFileCustom = "SecurityInsight_RiskAnalysis_Queries_Custom.yaml" }
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "SecurityInsight_RiskIndex.csv")

} else {

    #----------------------
    # Connect Custom Auth
    #----------------------

    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientSecret)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). Provide them via wrapper globals or enable -AutomationFramework to load them."
    }

    write-host "Connect using ServicePrincipal with AppId & Secret"

    Write-Step "connecting to Azure"
    Tock
    try {
        $global:SecureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $global:Credential = New-Object System.Management.Automation.PSCredential (
            $global:SpnClientId,
            $global:SecureSecret
        )

        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $global:Credential -WarningAction SilentlyContinue
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
    # Mail routing
    #------------------------------------------------------------------------------------------------------------
    $global:Report_SendMail = [bool]$global:SendMail
    $global:Report_To       = @($global:MailTo)

    if ($global:Report_SendMail -and (-not $global:Report_To -or $global:Report_To.Count -eq 0)) {
        throw "SendMail was enabled, but no recipients were provided (MailTo is empty)."
    }

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $global:Report_SendMail, ($global:Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # ExposureInsight settings
    #------------------------------------------------------------------------------------------------------------
    $global:OutputDir  = Join-Path $global:SettingsPath 'OUTPUT'
    Ensure-Directory -Path $global:OutputDir
    $global:OutputXlsx = Join-Path $global:OutputDir ("{0}.xlsx" -f $global:ReportTemplate)

    #------------------------------------------------------------------------------------------------------------
    # RiskAnalysis query settings
    #------------------------------------------------------------------------------------------------------------
    if ($null -eq $global:ReportSettingsFileLocked) { $global:ReportSettingsFileLocked = "SecurityInsight_RiskAnalysis_Queries_Locked.yaml" }
    if ($null -eq $global:ReportSettingsFileCustom) { $global:ReportSettingsFileCustom = "SecurityInsight_RiskAnalysis_Queries_Custom.yaml" }
    $global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "SecurityInsight_RiskIndex.csv")
}

# Generic bucketing configuration (for large queries)
# (kept as GLOBALS only)
Write-Step "settings overview"
Write-Info ("OutputXlsx: {0}" -f $global:OutputXlsx)
Write-Info ("SettingsPath: {0}" -f $global:SettingsPath)
Write-Info ("Risk Analysis Settings Files: Locked='{0}', Custom='{1}'" -f $global:ReportSettingsFileLocked, $global:ReportSettingsFileCustom)
Write-Info ("Risk Index Csv Path: {0}" -f $global:RiskDefinitionsCsvPath)
Write-Info ("Chosen ReportTemplate: {0}" -f $global:ReportTemplate)
Write-Info ("Query bucketing: UseQueryBucketing={0}, DefaultBucketCount={1}, Placeholder='{2}'" -f `
  $global:UseQueryBucketing, $global:DefaultBucketCount, $global:BucketPlaceholderToken)
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

    # Shallow copy locked root object
    $merged = [ordered]@{}
    foreach ($p in $LockedSettings.PSObject.Properties) {
      $merged[$p.Name] = $p.Value
    }

    if ($null -ne $CustomSettings) {
      $merged['Reports'] = Merge-ByReportName -Locked $LockedSettings.Reports -Custom $CustomSettings.Reports
      $merged['ReportTemplates'] = Merge-ByReportName -Locked $LockedSettings.ReportTemplates -Custom $CustomSettings.ReportTemplates

      # Copy any additional top-level keys from custom that don't exist in locked
      foreach ($p in $CustomSettings.PSObject.Properties) {
        if (-not $merged.Contains($p.Name)) {
          $merged[$p.Name] = $p.Value
        }
      }
    } else {
      # Ensure keys exist
      if (-not $merged.Contains('Reports')) { $merged['Reports'] = @() }
      if (-not $merged.Contains('ReportTemplates')) { $merged['ReportTemplates'] = @() }
    }

    return [pscustomobject]$merged
  }

  $lockedPath = Join-Path $global:SettingsPath $global:ReportSettingsFileLocked
  $customPath = Join-Path $global:SettingsPath $global:ReportSettingsFileCustom

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
  if (
    $m -match "too many" -or
    $m -match "result.*limit" -or
    $m -match "exceed" -or
    $m -match "response.*too large" -or
    $m -match "a task was canceled" -or
    $m -match "taskcanceledexception" -or
    $m -match "timed out" -or
    $m -match "timeout" -or
    $m -match "payload.*too large" -or
    $m -match "request entity too large" -or
    ($m -match "rows" -and $m -match "limit")
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
    [Parameter(Mandatory=$true)][scriptblock]$ProbeScript
  )

  if ($MaxBucketCount -lt 1) { return 1 }

  # Memo
  if ($script:AutoBucketMemo.ContainsKey($QueryKey)) {
    return [int]$script:AutoBucketMemo[$QueryKey]
  }
  if ($LegacyKeys) {
    foreach ($lk in $LegacyKeys) {
      if (-not [string]::IsNullOrWhiteSpace($lk) -and $script:AutoBucketMemo.ContainsKey($lk)) {
        $val = [int]$script:AutoBucketMemo[$lk]
        $script:AutoBucketMemo[$QueryKey] = $val
        return $val
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
      if ($ci -ge 1 -and $ci -le $MaxBucketCount) {
        Write-Info ("AutoBucket cache hit: '{0}' => {1}" -f $QueryKey, $ci)
        $script:AutoBucketMemo[$QueryKey] = $ci
        return $ci
      }
    }

    # Try legacy keys (e.g., old unstable GetHashCode-based identity)
    if ($LegacyKeys) {
      foreach ($lk in $LegacyKeys) {
        if ([string]::IsNullOrWhiteSpace($lk)) { continue }
        $cached2 = Get-CacheValue -Cache $cache -Key $lk
        if ($null -ne $cached2) {
          $ci2 = [int]$cached2
          if ($ci2 -ge 1 -and $ci2 -le $MaxBucketCount) {
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
      if ($null -ne $fallback) {
        Write-Info ("AutoBucket cache fallback: '{0}' => {1}" -f $QueryKey, $fallback)
        $script:AutoBucketMemo[$QueryKey] = [int]$fallback
        return [int]$fallback
      }
    }
  }

  # Exponential probe: 1,2,4,8...
  $try = 1
  $lastFail = 0
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

foreach ($includeItem in $global:Exposure_Template_ReportsIncluded) {

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

    # Bucketing resolution: include item > report entry > script defaults (GLOBALS)
    $effectiveUseBucket   = [bool]$global:UseQueryBucketing
    $effectiveBucketCount = [int]$global:DefaultBucketCount
    $effectivePlaceholder = [string]$global:BucketPlaceholderToken

    if ($Entry.PSObject.Properties['UseBucketFilter'] -and $Entry.UseBucketFilter -ne $null) {
        $effectiveUseBucket = [bool]$Entry.UseBucketFilter
    }
    if ($Entry.PSObject.Properties['BucketCount'] -and $Entry.BucketCount) {
        $bc = [int]$Entry.BucketCount
        if ($bc -gt 0) { $effectiveBucketCount = $bc }
    }

    if ($inc.UseQueryBucketing -ne $null) {
        $effectiveUseBucket = [bool]$inc.UseQueryBucketing
    }
    if ($inc.DefaultBucketCount -ne $null) {
        $bc2 = [int]$inc.DefaultBucketCount
        if ($bc2 -gt 0) { $effectiveBucketCount = $bc2 }
    }
    if (-not [string]::IsNullOrWhiteSpace($inc.BucketPlaceholderToken)) {
        $effectivePlaceholder = [string]$inc.BucketPlaceholderToken
    }

    # -----------------------------------------------------------------------------------------
    # FULL FIX: make the KQL AssetName-safe BEFORE we decide bucketing and BEFORE execution
    # -----------------------------------------------------------------------------------------
    $Query = Ensure-QueryIsAssetNameSafe -Query $Query

    # If bucketing is used and the query has the placeholder token, ensure DeviceKey exists
    # before the token (so bucket filter can use it).
    if ($Query -like "*$effectivePlaceholder*" -and $Query -notmatch '(?im)\bDeviceKey\b') {
        $Query = $Query.Replace($effectivePlaceholder, ("`n" + (New-DeviceKeyKql) + "`n" + $effectivePlaceholder))
    }

    $querySupportsBucket = ($Query -like "*$effectivePlaceholder*")

    Write-Step ("report '{0}' - {1}" -f $ReportName,$ReportPurpose)
    Write-Info ("domain='{0}', category='{1}', sub='{2}', configId='{3}', sevCol='{4}', tierCol='{5}'" -f `
      $SecurityDomain,$CategoryInputName,$SubcategoryInputName,$ConfigurationIdInputName,$SecuritySeverityInputName,$CriticalityTierLevelInputName)
    Write-Info ("bucketing: UseQueryBucketing={0}, BucketCount={1}, Token='{2}', QueryHasToken={3}" -f `
      $effectiveUseBucket, $effectiveBucketCount, $effectivePlaceholder, $querySupportsBucket)

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
            $bucketFilter = New-BucketFilterKql -BucketCount $BucketCount -BucketIndex 0
            $probeQuery   = $Query.Replace($effectivePlaceholder, $bucketFilter)

            $null = Invoke-GraphHuntingQuery -Query $probeQuery `
              -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes `
              -MaxRetries 1
          }

          try {
            $bucketCountToUse = Get-OptimalBucketCount -QueryKey $queryKey -LegacyKeys @($legacyKey) -MaxBucketCount $capBucket -ProbeScript $probe
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

while (-not $bucketRunSucceeded) {

  # Reset results on each (re)run so we don't keep partial data from a failing bucket count
  $ResultAll = @()

  Write-Info ("query contains placeholder '{0}' and bucketing is enabled. Using {1} bucket(s)." -f $effectivePlaceholder,$bucketCountToUse)

  $needEscalation = $false

  for ($b = 0; $b -lt $bucketCountToUse; $b++) {

      $bucketNo = $b + 1
      $bucketFilter = New-BucketFilterKql -BucketCount $bucketCountToUse -BucketIndex $b
      $thisQuery    = $Query.Replace($effectivePlaceholder, $bucketFilter)

      Write-Info ("bucket {0}/{1}: running advanced hunting query against Defender Exposure Management Graph ... Please wait !" -f $bucketNo, $bucketCountToUse)
      Tock
      try {
          $resp = Invoke-GraphHuntingQuery -Query $thisQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
          Tick ("hunting query bucket {0}/{1}" -f $bucketNo, $bucketCountToUse)
      } catch {

          # If a single bucket exceeds limits/timeouts, the current bucket count is not safe.
          # Escalate and restart the WHOLE run with more buckets.
          if (Test-IsBucketOverflowError $_) {
              $lastBucketRunError = $_.Exception.Message
              Write-Warn2 ("bucket {0}/{1} exceeded limits/timeout. Escalating bucket count and restarting this report. Error: {2}" -f `
                $bucketNo, $bucketCountToUse, $lastBucketRunError)

              $needEscalation = $true
              break
          }

          Write-Err2 ("advanced hunting query failed for bucket {0}/{1}: {2}" -f $bucketNo, $bucketCountToUse, $_.Exception.Message)
          continue
      }

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

      # Growth strategy: prefer doubling (4->8) but ensure it increases at least +1.
      $nextBucket = [Math]::Min($capBucket, [Math]::Max(($bucketCountToUse * 2), ($bucketCountToUse + 1)))

      Write-Warn2 ("AutoBucket escalation: rerunning report '{0}' with BucketCount {1} -> {2}" -f `
        $ReportName, $bucketCountToUse, $nextBucket)

      $bucketCountToUse = [int]$nextBucket
      continue
  }

  # Success: all buckets executed without deterministic overflow/timeout
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
            Write-Info "running advanced hunting query against Defender Exposure Management Graph ... Please wait !"
            $resp = Invoke-GraphHuntingQuery -Query $Query -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries
            Tick "hunting query"
        } catch {
            Write-Err2 "advanced hunting query failed: $($_.Exception.Message)"
            continue
        }

        $rawResults = $null
        if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }
        if ($null -eq $rawResults) {
            Write-Warn2 "query returned no results"
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

        foreach ($row in $ResultSingle) { $ResultAll += ,$row }
        Write-Info ("rows before filters: {0}" -f $ResultAll.Count)
    }

if ($ResultAll.Count -eq 0) {
        Write-Warn2 "no rows returned from query; skipping this report"
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
    foreach ($fs in $filterSpecs) {
      if ($null -eq $fs.Column -or [string]::IsNullOrWhiteSpace([string]$fs.Column)) { continue }
      if ($null -eq $fs.Scope -or @($fs.Scope).Count -eq 0) { continue }

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
      Write-Warn2 "no rows after filtering; skipping risk calculation for this report"
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
      -RiskScoreOutputName $RiskScoreOutputName
    Tick "risk scoring"

    # Shape columns
    $ComputedCols = @($RiskConsequenceScoreOutputName, $RiskProbabilityScoreOutputName, $RiskScoreOutputName)
    $DesiredColumns = @()
    if ($OutputPropertyOrder) { $DesiredColumns += $OutputPropertyOrder }
    foreach ($c in $ComputedCols) { if ($DesiredColumns -notcontains $c) { $DesiredColumns += $c } }

    $firstObj = $RiskScoreArray | Select-Object -First 1
    if ($firstObj) {
      $allProps = ($firstObj | Get-Member -MemberType NoteProperty).Name
      foreach ($p in $allProps) { if ($DesiredColumns -notcontains $p) { $DesiredColumns += $p } }
    }

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

    if (-not $global:FinalRiskScoreColumnName -and -not [string]::IsNullOrWhiteSpace($RiskScoreOutputName)) {
        $global:FinalRiskScoreColumnName = $RiskScoreOutputName
    }
    if (-not $global:FinalDesiredColumns) {
        $global:FinalDesiredColumns = $DesiredColumns
    }

    foreach ($row in @($Shaped)) { $global:AllShapedRows.Add($row) | Out-Null }
    Write-Ok ("added {0} rows to export pool (total now {1})" -f (@($Shaped).Count), $global:AllShapedRows.Count)
}

# Final export
Write-Section "final excel export"

if ($global:AllShapedRows.Count -eq 0) {
    Write-Warn2 "no rows collected across reports; nothing to export"
} else {

    if ([string]::IsNullOrWhiteSpace($global:FinalRiskScoreColumnName)) {
        $global:FinalRiskScoreColumnName = 'RiskScore'
        Write-Warn2 "FinalRiskScoreColumnName not set; using default 'RiskScore'"
    }
    if (-not $global:FinalDesiredColumns) {
        $global:FinalDesiredColumns = ($global:AllShapedRows[0] | Get-Member -MemberType NoteProperty).Name
    }

    Write-Step "sorting rows by risk score (descending)"
    Tock

    $allRows = @()
    foreach ($r in $global:AllShapedRows) { $allRows += ,$r }

    $global:final = $allRows | Sort-Object -Descending -Property @{
        Expression = {
            $n = 0.0
            $v = $null
            if ($_.PSObject.Properties[$global:FinalRiskScoreColumnName]) { $v = $_.$($global:FinalRiskScoreColumnName) }
            [void][double]::TryParse([string]$v, [ref]$n)
            $n
        }
    }
    Tick "final sort"

    Write-Step "exporting to excel (single write)"
    Write-Info ("path: {0}" -f $global:OutputXlsx)
    Tock
    Export-Worksheet -Path $global:OutputXlsx -SheetName 'Details' `
      -Rows @($global:final) `
      -SortColumn $global:FinalRiskScoreColumnName -SortDescending `
      -DesiredColumns $global:FinalDesiredColumns `
      -ColumnsToFlatten @('ImpactedAssets','Logins','Benchmarks','EG_AssetProps','AssetProps','Properties') `
      -TableStyle 'Medium9'
    Tick "excel export"
    Write-Ok "report exported"
}

Write-Host ""
Write-Ok ("excel file ready: {0}" -f $global:OutputXlsx)

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

        $TopN = 50
        $TopAssetsN = 25

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

            $parts = @($t -split '\s*,\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

            $expanded = New-Object System.Collections.Generic.List[string]
            foreach ($p in $parts) {
                if (Test-LooksLikeHost $p) {
                    $expanded.Add($p) | Out-Null
                    continue
                }

                $tokens = @($p -split '\s+' | Where-Object { $_ })
                $hostTokens = @($tokens | Where-Object { Test-LooksLikeHost $_ })

                if ($hostTokens.Count -ge 2) {
                    foreach ($ht in $hostTokens) { $expanded.Add($ht.Trim()) | Out-Null }
                } elseif ($tokens.Count -eq 1) {
                    $expanded.Add($tokens[0].Trim()) | Out-Null
                } else {
                    $expanded.Add($p) | Out-Null
                }
            }

            return @($expanded | Where-Object { $_ } | Select-Object -Unique)
        }

        $colRiskScore = if ($global:FinalRiskScoreColumnName) { $global:FinalRiskScoreColumnName } else { "RiskScore" }

        $topRows = @($global:final | Select-Object -First $TopN)

        $findingLines = @()
        $assetAgg = @{}

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
                [string]$ConfId
            )

            if ([string]::IsNullOrWhiteSpace($Asset)) { return }

            if (-not $assetAgg.ContainsKey($Asset)) {
                $assetAgg[$Asset] = [pscustomobject]@{
                    Asset          = $Asset
                    TierLevel      = $TierLevel
                    Findings       = 0
                    RiskScoreTotal = 0.0
                    MaxRiskScore   = 0.0
                    Domains        = New-Object System.Collections.Generic.HashSet[string]
                    TopItems       = New-Object System.Collections.Generic.List[string]
                }
            }

            $o = $assetAgg[$Asset]
            $o.Findings++
            $o.RiskScoreTotal += $RiskScore
            if ($RiskScore -gt $o.MaxRiskScore) { $o.MaxRiskScore = $RiskScore }

            if ($Domain) { [void]$o.Domains.Add($Domain) }

            if ($o.TopItems.Count -lt 12) {
                $o.TopItems.Add(("{0} [{1}] ({2}/{3})" -f $ConfName, $ConfId, $Category, $Subcat))
            }
        }

        $i = 0
        foreach ($r in $topRows) {
            $i++

            $riskScoreText = Get-RowValue -Row $r -Names @($colRiskScore, "RiskScore")
            [double]$riskScore = 0
            [void][double]::TryParse(($riskScoreText -replace ',', '.'), [ref]$riskScore)

            $severity    = Get-RowValue -Row $r -Names @("SecuritySeverity", "Severity", "securityseverity")
            $tierLevel   = Get-RowValue -Row $r -Names @("CriticalityTierLevel", "CriticalityTier", "Tier", "criticalitytierlevel")
            $domain      = Get-RowValue -Row $r -Names @("SecurityDomain", "Domain", "securitydomain")
            $category    = Get-RowValue -Row $r -Names @("Category", "category")
            $subcat      = Get-RowValue -Row $r -Names @("Subcategory", "SubCategory", "subcategory")
            $confName    = Get-RowValue -Row $r -Names @("ConfigurationName", "RecommendationName", "FindingName", "Title", "Name")
            $confId      = Get-RowValue -Row $r -Names @("ConfigurationId", "RecommendationId", "FindingId", "Id")
            $devices     = Get-RowValue -Row $r -Names @("Devices", "DeviceCount", "ImpactedDevices")
            $assetsText  = Get-RowValue -Row $r -Names @("ImpactedAssets", "Assets", "AffectedAssets", "Machines")

            $findingLines += ("[{0}] RiskScore={1}; Tier={2}; Severity={3}; Domain={4}; Config={5} [{6}]; Category={7}/{8}; Devices={9}; ImpactedAssets={10}" -f `
                $i, $riskScoreText, $tierLevel, $severity, $domain, $confName, $confId, $category, $subcat, $devices, $assetsText)

            $assetList = Resolve-AssetNamesForRow -Row $r -AssetsText $assetsText

            if ($assetList -and @($assetList).Count -gt 0) {
                foreach ($a in $assetList) {
                    Add-AssetAgg -Asset $a -RiskScore $riskScore -TierLevel $tierLevel -Severity $severity -Domain $domain `
                        -Category $category -Subcat $subcat -ConfName $confName -ConfId $confId
                }
            } else {
                Write-Warn2 ("AI rollup: no asset resolved for row {0}. Config={1} [{2}]" -f $i, $confName, $confId)
            }
        }

        $findingsText = $findingLines -join "`n"

        $assetRanked = @()
        if ($assetAgg.Count -gt 0) {
            $assetRanked = $assetAgg.Values |
                Sort-Object -Property @{Expression="MaxRiskScore";Descending=$true}, @{Expression="RiskScoreTotal";Descending=$true}, @{Expression="Findings";Descending=$true} |
                Select-Object -First $TopAssetsN
        }

        $assetLines = @()
        $rank = 0
        foreach ($a in $assetRanked) {
            $rank++

            $domainSummary = ""
            if ($a.Domains.Count -gt 0) { $domainSummary = (@($a.Domains) | Sort-Object) -join ", " }

            $topItems = ""
            if ($a.TopItems.Count -gt 0) { $topItems = ($a.TopItems | Select-Object -First 8) -join "; " }

            $assetLines += ("{0}. Asset={1}; Tier={2}; Findings={3}; MaxRiskScore={4:N2}; RiskScoreTotal={5:N2}; Domains=[{6}]; TopItems={7}" -f `
                $rank, $a.Asset, $a.TierLevel, $a.Findings, $a.MaxRiskScore, $a.RiskScoreTotal, $domainSummary, $topItems)
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

        $userPrompt = @"
$intro

You are a security advisor AI.

You MUST focus on ASSETS and prioritize remediation by RiskScore.
You are given:
A) An asset rollup (already ranked).
B) The top findings (highest RiskScore first) for traceability.

$runMeta

A) Asset rollup:
$assetsTextForAI

B) Top findings:
$findingsText

Return format (STRICT):
1) Top 25 risky assets (one line per asset):
   - <Rank>. <AssetName> | Tier=<Tier> | MaxRiskScore=<Max> | RiskScoreTotal=<Total> | Findings=<Count> | Domains=<Domains>

2) For the Top 10 assets only, include per asset:
   - Asset: <AssetName>
     - Why it is high risk (cite MaxRiskScore + 2-3 TopItems)
     - Top 5 actions to reduce RiskScore FAST (each action MUST reference ConfigName [ConfigId])
       Format each action line as:
       - <Action> | <Why> | <Expected impact> | <References: ConfigName [ConfigId]>
     - Expected overall risk reduction (High/Medium/Low)

3) Cross-asset quick wins (max 8):
   - <Action> [ConfigId] | Affects <N> assets | Example assets: <up to 4>

Rules:
- Do NOT write generic advice. Every action must tie back to ConfigName [ConfigId] and assets.
- Do NOT merge multiple assets into one line. Each line must be one asset.
- Keep the output concise and structured. No long paragraphs.
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
# SEND OUTPUT VIA MAIL
#####################################################################################################

Write-Section "mail dispatch decision"

if ([bool]$global:Report_SendMail -eq $true) {

    $to          = @($global:Report_To)
    $from        = $global:SMTPUser
    $subject     = "Security Insights | Risk Analysis | $($global:ReportTemplate)"
    $attachments = @($global:OutputXlsx)

    $aiEnabled = [bool]$global:BuildSummaryByAI

    if ($aiEnabled) {

        $aiHtml = ""
        if (-not [string]::IsNullOrWhiteSpace($global:AI_SummaryText)) {
          $aiHtml = ($global:AI_SummaryText.Trim() -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;")
          $aiHtml = $aiHtml -replace "`r`n","`n" -replace "`r","`n"
          $aiHtml = $aiHtml -replace "`n","<br>"
        } else {
          $aiHtml = "AI summary was enabled, but no AI summary output was produced."
        }

        $bodyHtml = @"
Risk Analysis<br>
<br>
Attached you will find prioritized security risks, ranked by RiskScore.<br>
The Excel file contains full evidence, raw data, and detailed findings per asset (Details sheet).<br>
<br>
AI summary (also included in the Excel Summary sheet):<br>
<br>
$aiHtml
<br>
<br>
---## ---<br>
Security Insight | Risk Analysis | support: Morten Knudsen | mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight.<br>
This summary was generated using AI and may contain mistakes or incomplete conclusions. Please validate critical decisions using the detailed findings and raw data in the attached Excel report.
"@

    } else {

        $bodyHtml = @"
Risk Analysis<br>
<br>
Attached you will find prioritized security risks, ranked by RiskScore.<br>
The Excel file contains full evidence, raw data, and detailed findings per asset (Details sheet).<br>
<br>
AI summary was not included for this run (BuildSummaryByAI was not enabled).<br>
If you want an AI-based prioritization summary in both the email and the Excel (Summary sheet), set Global:BuildSummaryByAI = `$true in the launcher script and run again.<br>
<br>
Security Insight | Risk Analysis | support: Morten Knudsen | mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight.<br>
"@
    }

    try {
        if ([bool]$global:Mail_SendAnonymous) {
            Write-Step ("sending mail anonymously to: {0}" -f ($to -join ', '))
            Send-MailAnonymous -SmtpServer $global:SmtpServer -Port $global:SMTPPort -UseSsl $global:SMTP_UseSSL `
                -From $from -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments
            Write-Ok "anonymous mail sent"
        }
        else {
            Write-Step ("sending mail using secure credentials to: {0}" -f ($to -join ', '))
            Send-MailSecure -SmtpServer $global:SmtpServer -Port $global:SMTPPort -UseSsl $global:SMTP_UseSSL `
                -Credential $global:SecureCredentialsSMTP -From $from -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments
            Write-Ok "secure mail sent"
        }
    }
    catch {
        Write-Err2 ("mail failed: {0}" -f $_.Exception.Message)
    }
}
else {
    Write-Info "mail flag disabled; not sending"
}

Write-Section "script completed"