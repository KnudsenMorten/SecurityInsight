<#
.SYNOPSIS
    CriticalAssetTaggingMaintenance - engine script in the SecurityInsight solution.

.NOTES
    Solution       : SecurityInsight
    File           : CriticalAssetTaggingMaintenance.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
Write-host "***********************************************************************************************"
Write-host "Critical Asset Tagging Maintenance"
Write-host ""
Write-host "Diagnostic + maintenance sample queries for SecurityInsight asset tagging."
Write-host ""
Write-host "What this script does when run as-is:"
Write-host "  1. Connects to Microsoft Graph and the Defender Security Center API using your SPN."
Write-host "  2. Runs a read-only inventory query that lists every tag currently applied to"
Write-host "     Defender devices (no changes made -- purely diagnostic)."
Write-host ""
Write-host "What else is in this file:"
Write-host "  A library of SAMPLE maintenance operations at the bottom, each wrapped in a block"
Write-host "  comment (<# ... #>) so nothing runs by default. Each sample is a self-contained"
Write-host "  script you can copy into a separate file, or uncomment inline, to perform a specific"
Write-host "  maintenance task. The samples are:"
Write-host ""
Write-host "    SAMPLE A : Remove ONE specific SI tier tag (e.g. 'ADCertificateService--tier1--SI')"
Write-host "               from every Defender device that currently carries it."
Write-host ""
Write-host "    SAMPLE B : Remove ALL SI tier tags (--tier0--SI .. --tier3--SI) from every Defender"
Write-host "               device. Use this for a full reset before re-running CriticalAssetTagging.ps1"
Write-host "               from scratch. (Replaces the previous ResetDefenderTagsSecurityInsight.ps1.)"
Write-host ""
Write-host "    SAMPLE C : Remove a specific tag KEY (e.g. 'createdBy') from every Azure subscription"
Write-host "               that carries it."
Write-host ""
Write-host "    SAMPLE D : Remove a specific tag KEY (e.g. 'AssetTagName') from every Azure resource"
Write-host "               that carries it."
Write-host ""
Write-host "IMPORTANT:"
Write-host "  - The samples DO make changes. Review the KQL / Azure query, edit the target"
Write-host "    tag name, optionally set `$global:WhatIfMode = `$true for a dry run, then uncomment"
Write-host "    the specific sample block before running."
Write-host "  - The diagnostic at the top is always safe; only the SAMPLE sections mutate state."
Write-host ""
Write-host "Support: mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight"
Write-host "***********************************************************************************************"

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-SecurityInsightModules
# -------------------------------------------------------------------------------------------------
# GLOBAL-ONLY CONFIG (launcher is source of truth)
# -------------------------------------------------------------------------------------------------

# Optional safe defaults if someone runs the main script directly (without launcher)
if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
  $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }
if ($null -eq $global:WhatIfMode) { $global:WhatIfMode = $false }

# Normalize SettingsPath
try {
  $global:SettingsPath = (Resolve-Path -LiteralPath $global:SettingsPath).Path
} catch {
  throw "SettingsPath does not exist or cannot be resolved: $($global:SettingsPath)"
}

# If NOT AutomationFramework, require SPN globals (launcher should set these)
if (-not [bool]$global:AutomationFramework) {
  if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
      [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
      [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
    throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). Launcher must set them or enable AutomationFramework."
  }
}

# Map globals into locals
$SettingsPath        = $global:SettingsPath
$AutomationFramework = [bool]$global:AutomationFramework
$Scope               = @($global:Scope)
$WhatIfMode          = [bool]$global:WhatIfMode

#######################################################################################################
# FUNCTIONS (begin)
#######################################################################################################

# ================= Logging helpers =================
function Write-Step  ($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Info  ($m){ Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-Ok    ($m){ Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn2 ($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err2  ($m){ Write-Host "[ERR]  $m" -ForegroundColor Red }

function Write-Sep {
  param([string]$Char = '-', [int]$Width = 110)
  Write-Host ($Char * $Width) -ForegroundColor DarkGray
}

function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Connect-GraphHighPriv {
  [CmdletBinding()]
  param()

  Write-Info "Connecting to Microsoft Graph (app+secret)..."
  Connect-MicrosoftGraphPS -AppId $global:SpnClientId `
                           -AppSecret $global:SpnClientSecret `
                           -TenantId $global:SpnTenantId

  Set-MgRequestContext -ClientTimeout 900 -MaxRetry 6 -RetryDelay 5 -RetriesTimeLimit 600

  $script:GraphLastConnectUtc = [datetime]::UtcNow
  Write-Ok ("Graph connected at {0:u}" -f $script:GraphLastConnectUtc)
  Write-Info "Graph request context: ClientTimeout=900s, MaxRetry=6, RetryDelay=5s, RetriesTimeLimit=600s"
}

function Ensure-GraphAuth {
  if ($script:GraphLastConnectUtc -eq [datetime]::MinValue -or
      (([datetime]::UtcNow - $script:GraphLastConnectUtc).TotalMinutes -ge 45)) {
    Connect-GraphHighPriv
  }
}

function Invoke-DefenderGraphQuery {
  param([Parameter(Mandatory)][string]$Query)
  Ensure-GraphAuth
  Start-MgSecurityHuntingQuery -Query $Query
}

function Invoke-AzureResourceGraphQuery {
  param([Parameter(Mandatory)][string]$Query)

  $pageSize = 1000
  $skip     = 0
  $allRows  = @()

  while ($true) {
    if ($skip -eq 0) { $res = Search-AzGraph -Query $Query -First $pageSize }
    else            { $res = Search-AzGraph -Query $Query -First $pageSize -Skip $skip }

    $rows = @()
    if ($res) {
      if ($res.PSObject.Properties.Name -contains 'Data') { $rows = @($res.Data) }
      else                                               { $rows = @($res) }
    }

    if (-not $rows -or $rows.Count -eq 0) { break }
    $allRows += $rows
    if ($rows.Count -lt $pageSize) { break }
    $skip += $pageSize
  }

  [pscustomobject]@{
    Data  = $allRows
    Count = $allRows.Count
  }
}

function Get-DefenderAccessHeaders {
  $ConnectAuth = Connect-MicrosoftRestApiEndpointPS -AppId $global:SpnClientId `
                                                    -AppSecret $global:SpnClientSecret `
                                                    -TenantId $global:SpnTenantId `
                                                    -Uri "https://api.securitycenter.microsoft.com"
  return $ConnectAuth[1]
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
    return ($t.IsPrimitive -or $t.FullName -in @('System.String','System.Decimal','System.DateTime','System.Guid','System.TimeSpan'))
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
        $pieces = foreach ($e in $items) { if (_IsPrimitive $e) { $e } else { ($e | ConvertTo-Json -Compress -Depth 12) } }
        return ($pieces -join $ArrayJoinChar)
      }
      if ($CastPrimitiveArrays -and -not $ConvertArraysToString -and $items.Count -gt 0) {
        $nonNull   = $items | Where-Object { $_ -ne $null }
        $typeNames = $nonNull | ForEach-Object { $_.GetType().FullName } | Select-Object -Unique
        $allPrim   = ($nonNull | ForEach-Object { _IsPrimitive $_ } | Where-Object { -not $_ } | Measure-Object).Count -eq 0
        if ($allPrim -and $typeNames.Count -eq 1) {
          switch ($typeNames[0]) {
            'System.String'  { return [string[]]  $items }
            'System.Int32'   { return [int[]]     $items }
            'System.Int64'   { return [long[]]    $items }
            'System.Double'  { return [double[]]  $items }
            'System.Boolean' { return [bool[]]    $items }
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

# ── Throttle-aware REST invoker for Defender API ────────────────────────────
$script:DefenderMinDelayMs = 750
$script:DefenderLastCall   = [datetime]::MinValue

function Invoke-DefenderRest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH','PUT','DELETE')]
    [string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][hashtable]$Headers,
    [object]$BodyObj    = $null,
    [int]$MaxAttempts   = 8
  )

  $attempt      = 0
  $delaySeconds = 2

  while ($true) {
    $attempt++

    if ($script:DefenderLastCall -ne [datetime]::MinValue) {
      $elapsedMs = ([datetime]::UtcNow - $script:DefenderLastCall).TotalMilliseconds
      if ($elapsedMs -lt $script:DefenderMinDelayMs) {
        Start-Sleep -Milliseconds ([int]($script:DefenderMinDelayMs - $elapsedMs))
      }
    }

    try {
      $script:DefenderLastCall = [datetime]::UtcNow
      if ($null -ne $BodyObj) {
        $json = $BodyObj | ConvertTo-Json -Depth 6
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $json
      } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers
      }
    }
    catch {
      $ex         = $_.Exception
      $resp       = $ex.Response
      $statusCode = $null
      $retryAfter = $null

      if ($resp) {
        try { $statusCode = [int]$resp.StatusCode } catch {}
        try { $retryAfter = $resp.Headers['Retry-After'] } catch {}
      }

      if ($statusCode -eq 429) {
        $sleep = $null
        if ($retryAfter -and ($retryAfter -match '^\d+$')) { $sleep = [int]$retryAfter }
        if (-not $sleep) { $sleep = $delaySeconds }
        Write-Info ("429 throttled. Sleeping {0}s (attempt {1}/{2})" -f $sleep, $attempt, $MaxAttempts)
        Start-Sleep -Seconds $sleep
        $delaySeconds = [math]::Min($delaySeconds * 2, 60)
        if ($attempt -lt $MaxAttempts) { continue }
      }

      if ($statusCode -ge 500 -and $statusCode -le 599 -and $attempt -lt $MaxAttempts) {
        Write-Info ("{0} server error. Sleeping {1}s (attempt {2}/{3})" -f $statusCode, $delaySeconds, $attempt, $MaxAttempts)
        Start-Sleep -Seconds $delaySeconds
        $delaySeconds = [math]::Min($delaySeconds * 2, 60)
        continue
      }

      throw
    }
  }
}

function AddTagForMultipleMachines {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string[]]$DeviceInventoryIds,
    [Parameter(Mandatory)][string]$Tag
  )
  $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
  $bodyObj = @{ Value = $Tag; Action = "Add"; MachineIds = @($DeviceInventoryIds) }
  Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj
}

function Add-DefenderTag {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$DeviceInventoryId,
    [Parameter(Mandatory)][string]$Tag
  )
  $uri  = "https://api.securitycenter.microsoft.com/api/machines/$DeviceInventoryId/tags"
  $bodyObj = @{ Value = $Tag; Action = "Add" }
  Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj
}

function RemoveTagForMultipleMachines {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string[]]$DeviceInventoryIds,
    [Parameter(Mandatory)][string]$Tag
  )
  $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
  $bodyObj = @{ Value = $Tag; Action = "Remove"; MachineIds = @($DeviceInventoryIds) }
  Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj
}

function Remove-DefenderTag {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$DeviceInventoryId,
    [Parameter(Mandatory)][string]$Tag
  )
  $uri  = "https://api.securitycenter.microsoft.com/api/machines/$DeviceInventoryId/tags"
  $bodyObj = @{ Value = $Tag; Action = "Remove" }
  Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj
}

function Test-AzModuleInstalled {
  Write-Step "Validating Az modules"
  return $null -ne (Get-Module -ListAvailable -Name 'Az.Accounts' -ErrorAction SilentlyContinue)
}

function Test-MicrosoftGraphInstalled {
  Write-Step "Validating Microsoft Graph modules"
  return $null -ne (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue)
}

#######################################################################################################
# POWERSHELL MODULE VALIDATION
#######################################################################################################

Write-Step "initializing"
Write-Info ("WhatIfMode: {0}" -f $WhatIfMode)

if (-not (Test-AzModuleInstalled)) {
  Write-Step "Installing Az modules ... Please Wait !"
  Install-Module Az -Scope AllUsers -Force -AllowClobber
}

if (-not (Test-MicrosoftGraphInstalled)) {
  Write-Step "Installing Microsoft Graph modules ... Please Wait !"
  Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber
}

#######################################################################################################
# CONNECTION
#######################################################################################################

if ($AutomationFramework) {

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

  $script:GraphLastConnectUtc = [datetime]::MinValue

  Write-Step "connecting to Microsoft Graph (initial)"
  Tock
  try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
  Tick "graph connect"

  Write-Step "acquiring Defender API auth headers"
  $AccessHeaders = Get-DefenderAccessHeaders

} else {

  Write-Host "Connect using ServicePrincipal with AppId & Secret"

  Write-Step "connecting to Azure"
  Tock
  try {
    $SecureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $SecureSecret)
    Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $Credential -WarningAction SilentlyContinue
    Write-Ok "azure connection step done"
  } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
  Tick "azure connect"

  $script:GraphLastConnectUtc = [datetime]::MinValue

  Write-Step "connecting to Microsoft Graph (initial)"
  Tock
  try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
  Tick "graph connect"

  Write-Step "acquiring Defender API auth headers"
  $AccessHeaders = Get-DefenderAccessHeaders
}

#######################################################################################################
# DIAGNOSTIC (ACTIVE, READ-ONLY) -- show every tag currently applied to Defender devices
#######################################################################################################

Write-Sep -Char '*'
Write-Step "Diagnostic: inventory of all tags currently applied to Defender devices"
Write-Sep -Char '*'

$DiagnosticQuery = @'
ExposureGraphNodes
    | where NodeLabel has "device"
        or NodeLabel has "microsoft.compute/virtualmachines"
        or NodeLabel has "microsoft.hybridcompute/machines"
    | extend rawData = todynamic(NodeProperties).rawData
    | where tobool(rawData.isExcluded) == false
    | extend manual = iif(isnull(rawData.deviceManualTags), dynamic([]), todynamic(rawData.deviceManualTags))
    | extend AllTags = array_concat(manual)
    | mv-expand Tag = AllTags
    | extend Tag = trim(@" ", tostring(Tag))
    | where isnotempty(Tag)
    | summarize Nodes=count() by Tag
    | order by Tag asc
'@

Write-Info "Running hunting query against Defender Exposure Graph... Please wait!"
$resp = Invoke-DefenderGraphQuery -Query $DiagnosticQuery
if (-not $resp -or -not $resp.Results) {
  Write-Info "No tags found on any device."
} else {
  $tagRows = @(ConvertTo-PSObjectDeep $resp.Results.AdditionalProperties -StripOData)
  if (-not $tagRows -or $tagRows.Count -eq 0) {
    Write-Info "No tags found on any device."
  } else {
    Write-Info ("{0} distinct tag(s) found on Defender devices:" -f $tagRows.Count)
    $tagRows | Format-Table -AutoSize
  }
}

Write-Sep -Char '*'
Write-Info "Done. If you need to remove / reset tags, review the SAMPLE blocks in the"
Write-Info "lower half of this file, copy the one you need, edit the target tag name,"
Write-Info "and run it separately. Nothing further runs automatically."
Write-Sep -Char '*'

return   # <-- hard stop: nothing past this line executes unless you remove this 'return' on purpose.


#######################################################################################################
# SAMPLES -- NOT ACTIVE. Each block is a self-contained snippet you can copy into a
#            fresh script (or uncomment inline) when you need to perform that maintenance
#            operation. All samples assume auth is already established above.
#
#            Set   $global:WhatIfMode = $true   to do a dry run.
#######################################################################################################


<# =======================================================================================
   SAMPLE A -- Remove ONE specific SI tier tag from every Defender device that carries it.
   =======================================================================================

   Purpose: a targeted clean-up (e.g. a tag was applied in error, or a tier re-classification
   means a specific tag is no longer valid). Only the named tag is removed; other SI tier
   tags and non-SI tags on the same device are untouched.

   EDIT BEFORE RUNNING:
     $TagToDelete = '<tag name, e.g. ADCertificateService--tier1--SI>'

$TagToDelete = 'ADCertificateService--tier1--SI'

$Query = @'
ExposureGraphNodes
| where NodeLabel has "device"
    or NodeLabel has "microsoft.compute/virtualmachines"
    or NodeLabel has "microsoft.hybridcompute/machines"
| extend rawData = todynamic(NodeProperties).rawData
| where tobool(rawData.isExcluded) == false
| project NodeId, NodeName, NodeLabel, rawData, EntityIds
| extend
    deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
    deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
    tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
| extend AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
| extend entityIds_dyn = todynamic(EntityIds)
| mv-apply e = entityIds_dyn on (
    summarize
        DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
        SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
        AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
)
| extend AzureResourceId = strcat_array(AzureResourceId, ";")
| where AssetTags contains "{0}"
'@ -f $TagToDelete.Replace('"','\"')

Write-Info "Running hunting query against Defender Exposure Graph .... Please wait !"
$resp = Invoke-DefenderGraphQuery -Query $Query
if (-not $resp.Results) { Write-Info "no results"; return }

$rows = @(ConvertTo-PSObjectDeep $resp.Results.AdditionalProperties -StripOData)
if (-not $rows -or $rows.Count -eq 0) { Write-Info "no results"; return }

$deviceInventoryIds = @(
    $rows | ForEach-Object { [string]$_.DeviceInventoryId } |
            Where-Object   { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object  -Unique
)
if ($deviceInventoryIds.Count -eq 0) { Write-Warn2 "no DeviceInventoryId values found; skipping"; return }

if ($WhatIfMode) {
    Write-Warn2 ("[WHATIF] Would remove '{0}' from {1} device(s)." -f $TagToDelete, $deviceInventoryIds.Count)
    return
}

$chunkSize   = 500
$totalChunks = [math]::Ceiling($deviceInventoryIds.Count / $chunkSize)
for ($i = 0; $i -lt $deviceInventoryIds.Count; $i += $chunkSize) {
    $currentChunk = [math]::Floor($i / $chunkSize) + 1
    $endIndex     = [math]::Min($i + $chunkSize - 1, $deviceInventoryIds.Count - 1)
    $chunk        = $deviceInventoryIds[$i..$endIndex]
    try {
        RemoveTagForMultipleMachines -AccessHeaders $AccessHeaders -DeviceInventoryIds $chunk -Tag $TagToDelete | Out-Null
        Write-Ok ("tag '{0}' removed from {1} machines (chunk {2}/{3})" -f $TagToDelete, $chunk.Count, $currentChunk, $totalChunks)
    }
    catch {
        Write-Err2 ("bulk removal failed (chunk {0}/{1}): {2}" -f $currentChunk, $totalChunks, $_.Exception.Message)
        foreach ($id in $chunk) {
            try { Remove-DefenderTag -AccessHeaders $AccessHeaders -DeviceInventoryId $id -Tag $TagToDelete | Out-Null }
            catch { Write-Err2 ("failed removing from {0}: {1}" -f $id, $_.Exception.Message) }
        }
    }
}

#> # end SAMPLE A


<# =======================================================================================
   SAMPLE B -- Remove ALL SI tier tags (--tier0--SI .. --tier3--SI) from every device.
   =======================================================================================

   Purpose: full reset of SecurityInsight tier tagging across the Defender estate. Use
   before re-running CriticalAssetTagging.ps1 against a fresh tag model, or when
   decommissioning the SecurityInsight tagging scheme. Non-SI tags and the --excluded--
   sentinel are NOT touched. Processes one (device x tag) pair per 500-item batch.

   (This sample replaces the standalone ResetDefenderTagsSecurityInsight.ps1 that used
   to live in this folder.)

   EDIT BEFORE RUNNING: nothing mandatory. Optionally set $global:WhatIfMode = $true first.

Write-Sep -Char '*'
Write-Step "Scanning Defender Exposure Graph for all --tierN--SI tags"
Write-Sep -Char '*'

$Query = @'
ExposureGraphNodes
| where NodeLabel has "device"
    or NodeLabel has "microsoft.compute/virtualmachines"
    or NodeLabel has "microsoft.hybridcompute/machines"
| extend rawData = todynamic(NodeProperties).rawData
| where tobool(rawData.isExcluded) == false
| project NodeId, NodeName, NodeLabel, rawData, EntityIds
| extend
    deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
    deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags))
| extend
    AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
| extend entityIds_dyn = todynamic(EntityIds)
| mv-apply e = entityIds_dyn on (
    summarize
        DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
        SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
        AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
)
| extend AzureResourceId = strcat_array(AzureResourceId, ";")
| where AssetTags has "--tier0--SI"
    or AssetTags has "--tier1--SI"
    or AssetTags has "--tier2--SI"
    or AssetTags has "--tier3--SI"
| extend AssetTagsArray = split(AssetTags, ";")
| mv-apply tag = AssetTagsArray to typeof(string) on (
    summarize SITierTags = make_list_if(
        tag,
        tag matches regex @"--tier[0-3]--SI"
    )
)
| where array_length(SITierTags) > 0
| mv-expand TagToRemove = SITierTags to typeof(string)
| project NodeId, NodeName, NodeLabel, DeviceInventoryId, SenseDeviceId, AzureResourceId,
          TagToRemove, AllSITierTags = strcat_array(SITierTags, ";")
| order by TagToRemove asc, NodeName asc
'@

$resp = Invoke-DefenderGraphQuery -Query $Query
if (-not $resp -or -not $resp.Results) { Write-Step "Reset complete -- nothing to remove"; return }

$rows = @(ConvertTo-PSObjectDeep $resp.Results.AdditionalProperties -StripOData)
if (-not $rows -or $rows.Count -eq 0) { Write-Step "Reset complete -- nothing to remove"; return }

$uniqueDevices = @($rows | Select-Object -ExpandProperty NodeName -Unique)
$uniqueTags    = @($rows | Select-Object -ExpandProperty TagToRemove -Unique | Sort-Object)

Write-Sep
Write-Info ("Devices with SI tier tags : {0}" -f $uniqueDevices.Count)
Write-Info ("Distinct tags to remove   : {0}" -f $uniqueTags.Count)
Write-Info ("Total (device x tag) ops  : {0}" -f $rows.Count)
Write-Sep
foreach ($t in $uniqueTags) { Write-Info ("  {0}" -f $t) }
Write-Sep

if ($WhatIfMode) { Write-Warn2 "WhatIfMode is ON -- no tags will actually be removed"; Write-Sep }

$tagGroups = $rows |
  Where-Object { -not [string]::IsNullOrWhiteSpace($_.TagToRemove) } |
  Group-Object -Property TagToRemove

$totalRemoved = 0; $totalSkipped = 0; $totalFailed = 0
foreach ($group in $tagGroups) {
  $TagToDelete = $group.Name
  Write-Sep; Write-Info ("Processing tag : '{0}'" -f $TagToDelete)

  $deviceInventoryIds = @(
    $group.Group | ForEach-Object { [string]$_.DeviceInventoryId } |
                   Where-Object   { -not [string]::IsNullOrWhiteSpace($_) } |
                   Select-Object  -Unique
  )
  if ($deviceInventoryIds.Count -eq 0) {
    Write-Warn2 ("No valid DeviceInventoryId found for tag '{0}' -- skipping" -f $TagToDelete)
    $totalSkipped += $group.Group.Count; continue
  }

  $rowsById = @{}
  foreach ($r in $group.Group) {
    $id = [string]$r.DeviceInventoryId
    if (-not [string]::IsNullOrWhiteSpace($id) -and -not $rowsById.ContainsKey($id)) { $rowsById[$id] = $r }
  }

  Write-Info ("  Devices affected : {0}" -f $deviceInventoryIds.Count)
  $chunkSize   = 500
  $totalChunks = [math]::Ceiling($deviceInventoryIds.Count / $chunkSize)

  for ($i = 0; $i -lt $deviceInventoryIds.Count; $i += $chunkSize) {
    $currentChunk = [math]::Floor($i / $chunkSize) + 1
    $endIndex     = [math]::Min($i + $chunkSize - 1, $deviceInventoryIds.Count - 1)
    $chunk        = @($deviceInventoryIds[$i..$endIndex])

    if ($WhatIfMode) {
      Write-Warn2 ("[WHATIF] Would remove '{0}' from {1} devices (chunk {2}/{3})" -f $TagToDelete, $chunk.Count, $currentChunk, $totalChunks)
      $totalRemoved += $chunk.Count; continue
    }

    try {
      RemoveTagForMultipleMachines -AccessHeaders $AccessHeaders -DeviceInventoryIds $chunk -Tag $TagToDelete | Out-Null
      Write-Ok ("Tag '{0}' removed from {1} devices (chunk {2}/{3})" -f $TagToDelete, $chunk.Count, $currentChunk, $totalChunks)
      $totalRemoved += $chunk.Count
    }
    catch {
      Write-Err2 ("Bulk removal failed for '{0}' (chunk {1}/{2}): {3}" -f $TagToDelete, $currentChunk, $totalChunks, $_.Exception.Message)
      foreach ($id in $chunk) {
        try { Remove-DefenderTag -AccessHeaders $AccessHeaders -DeviceInventoryId $id -Tag $TagToDelete | Out-Null; $totalRemoved++ }
        catch { Write-Err2 ("  Failed removing '{0}' from {1}: {2}" -f $TagToDelete, $id, $_.Exception.Message); $totalFailed++ }
      }
    }
  }
}

Write-Sep -Char '*'
Write-Info ("Devices removed   : {0}" -f $totalRemoved)
Write-Info ("Devices skipped   : {0}" -f $totalSkipped)
Write-Info ("Devices failed    : {0}" -f $totalFailed)
Write-Sep -Char '*'

#> # end SAMPLE B


<# =======================================================================================
   SAMPLE C -- Remove a specific tag KEY from every Azure subscription that carries it.
   =======================================================================================

   Purpose: clean up orphan or deprecated subscription-level tag keys. Removes the entire
   tag key (name + value) from the subscription's resource tags.

   EDIT BEFORE RUNNING:
     $TagToDelete = '<tag key, e.g. createdBy>'

$TagToDelete = 'createdBy'

$Query = @'
resourcecontainers
| where type == "microsoft.resources/subscriptions"
| where isnotnull(tags["{0}"])
| project subscriptionId, subscriptionName = name
| order by subscriptionName asc
'@ -f $TagToDelete

Write-Info ("Querying subscriptions with tag '{0}'..." -f $TagToDelete)
$subsWithTag = Search-AzGraph -Query $Query -First 1000

foreach ($sub in $subsWithTag) {
    Write-Info ("Processing subscription: {0} [{1}]" -f $sub.subscriptionName, $sub.subscriptionId)
    if ($WhatIfMode) { Write-Warn2 ("[WHATIF] Would remove tag '{0}' from subscription {1}" -f $TagToDelete, $sub.subscriptionId); continue }
    try {
        Set-AzContext -SubscriptionId $sub.subscriptionId -ErrorAction Stop | Out-Null
        Update-AzTag `
            -ResourceId "/subscriptions/$($sub.subscriptionId)" `
            -Tag @{ $TagToDelete = "" } `
            -Operation Delete `
            -ErrorAction Stop | Out-Null
        Write-Ok ("Removed tag '{0}' from {1}" -f $TagToDelete, $sub.subscriptionId)
    }
    catch {
        Write-Err2 ("Failed on subscription {0}: {1}" -f $sub.subscriptionId, $_.Exception.Message)
    }
}

#> # end SAMPLE C


<# =======================================================================================
   SAMPLE D -- Remove a specific tag KEY from every Azure resource that carries it.
   =======================================================================================

   Purpose: clean up resource-level tag keys across the entire estate (e.g. deprecated
   AssetTagName or similar). Only the named key is deleted; the resource's other tags
   are preserved.

   EDIT BEFORE RUNNING:
     $TagToDelete = '<tag key, e.g. AssetTagName>'

$TagToDelete = 'AssetTagName'
$PageSize    = 1000

$Query = @'
Resources
| where isnotnull(tags["{0}"])
| project
    id, name, type, resourceGroup, subscriptionId, location,
    TagValue = tostring(tags["{0}"])
| order by subscriptionId asc
'@ -f $TagToDelete

Write-Info ("Querying all resources with tag '{0}'..." -f $TagToDelete)
$all = New-Object System.Collections.Generic.List[object]
$skipToken = $null
do {
    $result = Search-AzGraph -Query $Query -First $PageSize -SkipToken $skipToken
    if ($result -and $result.Data) { [void]$all.AddRange($result.Data) }
    $skipToken = $result.SkipToken
} while ($skipToken)

Write-Info ("Found {0} resources with tag '{1}'" -f $all.Count, $TagToDelete)

foreach ($r in $all) {
    Write-Info ("Processing: {0} [{1}]" -f $r.name, $r.type)
    Write-Info ("  ResourceId: {0}" -f $r.id)
    Write-Info ("  Current {0}: {1}" -f $TagToDelete, $r.TagValue)
    if ($WhatIfMode) { Write-Warn2 ("[WHATIF] Would remove tag '{0}' from {1}" -f $TagToDelete, $r.id); continue }
    try {
        Update-AzTag -ResourceId $r.id -Tag @{ $TagToDelete = "" } -Operation Delete -ErrorAction Stop | Out-Null
        Write-Ok ("  Removed tag '{0}'" -f $TagToDelete)
    }
    catch {
        Write-Err2 ("  FAILED: {0}" -f $_.Exception.Message)
    }
}

#> # end SAMPLE D
