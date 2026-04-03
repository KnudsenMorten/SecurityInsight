Write-host "***********************************************************************************************"
Write-host "Critical Asset Tagging using YAML-file"
Write-host ""
Write-host "Support: mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight"
Write-host "***********************************************************************************************"

# -------------------------------------------------------------------------------------------------
# GLOBAL-ONLY CONFIG (launcher is source of truth)
# -------------------------------------------------------------------------------------------------

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
  $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }

try {
  $global:SettingsPath = (Resolve-Path -LiteralPath $global:SettingsPath).Path
} catch {
  throw "SettingsPath does not exist or cannot be resolved: $($global:SettingsPath)"
}

if (-not [bool]$global:AutomationFramework) {
  if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
      [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
      [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
    throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). Launcher must set them or enable AutomationFramework."
  }
}

$SettingsPath        = $global:SettingsPath
$AutomationFramework = [bool]$global:AutomationFramework
$Scope               = @($global:Scope)

if ($null -eq $global:WhatIfMode) { $global:WhatIfMode = $false }
$WhatIfMode = [bool]$global:WhatIfMode

if ($null -eq $global:SuppressErrors) { $global:SuppressErrors = $false }
$SuppressErrors = [bool]$global:SuppressErrors

if ($null -eq $global:SuppressWarnings) { $global:SuppressWarnings = $false }
$SuppressWarnings = [bool]$global:SuppressWarnings

$script:SuppressErrors   = $SuppressErrors
$script:SuppressWarnings = $SuppressWarnings
$script:WhatIfMode       = $WhatIfMode

#######################################################################################################
# FUNCTIONS
#######################################################################################################

function Write-Step  ($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Info  ($m){ Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-Ok    ($m){ Write-Host "[OK]   $m" -ForegroundColor Green }

function Write-Warn2 {
  param($m)
  if (-not $script:SuppressWarnings) {
    Write-Host "[WARN] $m" -ForegroundColor Yellow
  }
}

function Write-Err2 {
  param($m)
  if (-not $script:SuppressErrors) {
    Write-Host "[ERR]  $m" -ForegroundColor Red
  }
}

function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Step ("Installing module $($Name)...")
    Install-Module $Name -Scope AllUsers -Force -AllowClobber
  } else {
    Write-Step ("Validating module $($Name)...")
  }
}

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

function Get-RuleMode {
  param([AllowNull()][object]$Mode)
  if ($null -eq $Mode) { return 'PROD' }
  $m = ([string]$Mode).Trim()
  if ([string]::IsNullOrWhiteSpace($m)) { return 'PROD' }
  $m.ToUpperInvariant()
}

function Get-QueryEngine {
  param([AllowNull()][object]$QueryEngine)
  if ($null -eq $QueryEngine) { return 'DEFENDERGRAPH' }
  $qe = ([string]$QueryEngine).Trim()
  if ([string]::IsNullOrWhiteSpace($qe)) { return 'DEFENDERGRAPH' }
  $qe.ToUpperInvariant()
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

# ==========================================================================================
# DEFENDER REST INVOKER WITH THROTTLING + RETRY
# ==========================================================================================
$script:DefenderMinDelayMs = 750
$script:DefenderLastCall   = [datetime]::MinValue

function Invoke-DefenderRest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH','PUT','DELETE')]
    [string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][hashtable]$Headers,
    [object]$BodyObj = $null,
    [int]$MaxAttempts = 8
  )

  $attempt = 0
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
      $ex = $_.Exception
      $resp = $ex.Response

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

# ==========================================================================================
# Helpers: name + SenseDeviceId extraction (NO DNS RESOLUTION)
# ==========================================================================================
function Get-FirstNonEmptyPropertyValue {
  param(
    [Parameter(Mandatory)][psobject]$Row,
    [Parameter(Mandatory)][string[]]$Names
  )
  foreach ($n in $Names) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
  }
  return $null
}

function Get-DeviceNameFromRow {
  param([Parameter(Mandatory)][psobject]$Row)

  $n = Get-FirstNonEmptyPropertyValue -Row $Row -Names @(
    'DeviceName','deviceName',
    'ComputerDnsName','computerDnsName',
    'HostName','hostName',
    'Name','name'
  )
  if ([string]::IsNullOrWhiteSpace($n)) { return "<unknown>" }
  return $n.Trim()
}

function Get-SenseDeviceIdFromRow {
  param([Parameter(Mandatory)][psobject]$Row)

  $id = Get-FirstNonEmptyPropertyValue -Row $Row -Names @('SenseDeviceId','senseDeviceId')
  if ([string]::IsNullOrWhiteSpace($id)) { return $null }
  return $id.Trim()
}

function Test-DefenderMachineExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$MachineId,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  if ([string]::IsNullOrWhiteSpace($MachineId)) { return $false }

  $uri = "https://api.securitycenter.microsoft.com/api/machines/$MachineId"
  try {
    Invoke-DefenderRest -Method GET -Uri $uri -Headers $AccessHeaders -BodyObj $null -MaxAttempts 3 | Out-Null
    return $true
  }
  catch {
    $ex = $_.Exception
    $resp = $ex.Response
    $statusCode = $null
    if ($resp) { try { $statusCode = [int]$resp.StatusCode } catch {} }
    if ($statusCode -eq 404) { return $false }

    if ($SuppressErrors) {
      Write-Warn2 ("Suppressed Defender machine existence check error: MachineId={0} | Error={1}" -f $MachineId, $_.Exception.Message)
      return $false
    }

    throw
  }
}

# ==========================================================================================
# DEFENDER TAGGING FUNCTIONS
# ==========================================================================================
function AddTagForMultipleMachines {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string[]]$MachineIds,
    [Parameter(Mandatory)][string]$Tag,
    [bool]$WhatIfMode = $script:WhatIfMode,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
  $bodyObj = @{
    Value      = $Tag
    Action     = "Add"
    MachineIds = @($MachineIds)
  }

  $result = [pscustomobject]@{
    Success      = $false
    Suppressed   = $false
    WhatIf       = $false
    ErrorMessage = $null
    Count        = @($MachineIds).Count
    Tag          = $Tag
    Uri          = $uri
  }

  if ($WhatIfMode) {
    Write-Warn2 ("[WHATIF] Would bulk-tag {0} machines with '{1}'" -f $MachineIds.Count, $Tag)
    Write-Info  ("[WHATIF] POST {0}" -f $uri)
    $result.Success = $true
    $result.WhatIf  = $true
    return $result
  }

  try {
    Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj | Out-Null
    $result.Success = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message
    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }
    throw
  }
}

function Add-DefenderTag {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$MachineId,
    [Parameter(Mandatory)][string]$Tag,
    [string]$DeviceName = "<unknown>",
    [bool]$WhatIfMode = $script:WhatIfMode,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  $uri  = "https://api.securitycenter.microsoft.com/api/machines/$MachineId/tags"
  $bodyObj = @{
    Value  = $Tag
    Action = "Add"
  }

  $result = [pscustomobject]@{
    Success      = $false
    Suppressed   = $false
    WhatIf       = $false
    ErrorMessage = $null
    MachineId    = $MachineId
    DeviceName   = $DeviceName
    Tag          = $Tag
    Uri          = $uri
  }

  if ($WhatIfMode) {
    Write-Warn2 ("[WHATIF] Would tag machine {0} ({1}) with '{2}'" -f $DeviceName, $MachineId, $Tag)
    Write-Info  ("[WHATIF] POST {0}" -f $uri)
    $result.Success = $true
    $result.WhatIf  = $true
    return $result
  }

  try {
    Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj | Out-Null
    $result.Success = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message
    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }
    throw
  }
}

# ==========================================================================================
# BULK APPLY WITH SPLIT-AND-RETRY + NAME LOGGING
# ==========================================================================================
function Apply-TagBulkWithSplit {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][pscustomobject[]]$Devices,
    [Parameter(Mandatory)][string]$Tag,
    [int]$MaxSplitDepth = 10,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  if (-not $Devices -or $Devices.Count -eq 0) { return }

  $stack = New-Object System.Collections.Stack
  $stack.Push([pscustomobject]@{ Items = @($Devices); Depth = 0 })

  while ($stack.Count -gt 0) {
    $work  = $stack.Pop()
    $items = @($work.Items)
    $depth = [int]$work.Depth

    $ids = @($items | ForEach-Object { $_.Id })

    try {
      $bulkResult = AddTagForMultipleMachines -AccessHeaders $AccessHeaders -MachineIds $ids -Tag $Tag -SuppressErrors $SuppressErrors

      if ($bulkResult.Suppressed) {
        Write-Warn2 ("Suppressed Defender bulk tagging error for {0} machines (depth {1}) | Tag='{2}' | Error={3}" -f $ids.Count, $depth, $Tag, $bulkResult.ErrorMessage)
      }
      else {
        Write-Ok ("bulk tag applied to {0} machines" -f $ids.Count)
      }

      continue
    }
    catch {
      Write-Err2 ("bulk tagging failed for {0} machines (depth {1}): {2}" -f $ids.Count, $depth, $_.Exception.Message)

      if ($items.Count -le 1 -or $depth -ge $MaxSplitDepth) {
        $one = $items[0]
        try {
          $singleResult = Add-DefenderTag -AccessHeaders $AccessHeaders -MachineId $one.Id -Tag $Tag -DeviceName $one.Name -SuppressErrors $SuppressErrors
          if ($singleResult.Suppressed) {
            Write-Warn2 ("Suppressed Defender single-machine tagging error: {0} ({1}) | Tag='{2}' | Error={3}" -f $one.Name, $one.Id, $Tag, $singleResult.ErrorMessage)
          }
          else {
            Write-Ok ("tag '{0}' added (single): {1} ({2})" -f $Tag, $one.Name, $one.Id)
          }
        }
        catch {
          if ($SuppressErrors) {
            Write-Warn2 ("Suppressed unprocessable machine error: {0} ({1}) | Error={2}" -f $one.Name, $one.Id, $_.Exception.Message)
          }
          else {
            Write-Err2 ("unprocessable machine: {0} ({1}): {2}" -f $one.Name, $one.Id, $_.Exception.Message)
          }
        }
        continue
      }

      $mid = [math]::Floor($items.Count / 2)
      if ($mid -lt 1) { $mid = 1 }

      $left  = @($items[0..($mid-1)])
      $right = @($items[$mid..($items.Count-1)])

      $stack.Push([pscustomobject]@{ Items = $right; Depth = ($depth + 1) })
      $stack.Push([pscustomobject]@{ Items = $left;  Depth = ($depth + 1) })
    }
  }
}

# ==========================================================================================
# Azure tagging helpers
# ==========================================================================================
function Get-ArgResourceIdFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($name in @('ResourceId','resourceId','id','Id')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
  }
  return $null
}

function Get-ArgResourceNameFromRow {
  param([Parameter(Mandatory)][psobject]$Row)

  foreach ($name in @('name','Name','resourceName','ResourceName','displayName','DisplayName')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
  }

  $rid = Get-ArgResourceIdFromRow -Row $Row
  if (-not [string]::IsNullOrWhiteSpace($rid)) {
    if ($rid -match '^/subscriptions/([0-9a-fA-F-]{36})$') {
      return $matches[1]
    }
    if ($rid -match '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/([^/]+)$') {
      return $matches[1]
    }

    $segments = @($rid.Trim('/') -split '/')
    if ($segments.Count -gt 0) {
      return $segments[-1]
    }
  }

  return $null
}

function Get-ArgAssetTagTypeFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($name in @('AssetTagType','assettagtype','TagKey','tagKey')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return $null
}

function Get-TagValueFromRow {
  param(
    [Parameter(Mandatory)][psobject]$Row,
    [Parameter(Mandatory)][string]$ColumnName
  )
  if ([string]::IsNullOrWhiteSpace($ColumnName)) { return $null }
  $p = $Row.PSObject.Properties[$ColumnName]
  if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  return $null
}

function Get-SubscriptionIdFromResourceId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }

  if ($ResourceId -match '^/subscriptions/([0-9a-fA-F-]{36})(/|$)') {
    return $matches[1].ToLowerInvariant()
  }

  return $null
}

function Test-SubscriptionScopeId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }

  return ($ResourceId -match '^/subscriptions/[0-9a-fA-F-]{36}$')
}

function Test-ResourceGroupScopeId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }

  return ($ResourceId -match '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+$')
}

function Get-ResourceTypeFromResourceId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }

  if (Test-SubscriptionScopeId -ResourceId $ResourceId) {
    return 'microsoft.resources/subscriptions'
  }

  if (Test-ResourceGroupScopeId -ResourceId $ResourceId) {
    return 'microsoft.resources/resourcegroups'
  }

  $m = [regex]::Match($ResourceId, '/providers/([^/]+/[^/]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }

  return $null
}

function Test-ArmResourceId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }

  if (Test-SubscriptionScopeId -ResourceId $ResourceId) { return $true }
  if (Test-ResourceGroupScopeId -ResourceId $ResourceId) { return $true }

  return ($ResourceId -match '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/[^/]+/.+')
}

function Set-AzContextFromResourceId {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ResourceId)

  $subId = Get-SubscriptionIdFromResourceId -ResourceId $ResourceId
  if ([string]::IsNullOrWhiteSpace($subId)) {
    throw "Could not extract subscription id from ResourceId: $ResourceId"
  }

  $ctx = Get-AzContext -ErrorAction SilentlyContinue
  $currentSub = $null
  if ($ctx -and $ctx.Subscription) { $currentSub = [string]$ctx.Subscription.Id }

  if ($currentSub -ne $subId) {
    Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
  }

  return $subId
}

function Test-SkipAzureTaggingForType {
  param([Parameter(Mandatory)][string]$ResourceType)

  $skipTypes = @(
    'microsoft.insights/scheduledqueryrules'
  )

  return ($skipTypes -contains $ResourceType.ToLowerInvariant())
}

function Add-AzureResourceTag {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ResourceId,
    [Parameter(Mandatory)][string]$AssetTagName,
    [Parameter(Mandatory)][string]$TagKey,
    [bool]$WhatIfMode = $script:WhatIfMode,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  $rid = if ($null -ne $ResourceId) { $ResourceId.Trim() } else { $null }

  $result = [pscustomobject]@{
    Success          = $false
    Suppressed       = $false
    Changed          = $false
    AlreadyPresent   = $false
    Skipped          = $false
    SkipReason       = $null
    WhatIf           = $false
    ResourceId       = $rid
    ResourceType     = $null
    SubscriptionId   = $null
    TagKey           = $TagKey
    TagValue         = $AssetTagName
    ErrorMessage     = $null
  }

  try {
    if ([string]::IsNullOrWhiteSpace($rid))          { throw "ResourceId is empty" }
    if ([string]::IsNullOrWhiteSpace($TagKey))       { throw "TagKey is empty" }
    if ([string]::IsNullOrWhiteSpace($AssetTagName)) { throw "AssetTagName is empty" }
    if (-not (Test-ArmResourceId -ResourceId $rid))  { throw "Invalid ARM ResourceId: $rid" }

    $resourceType        = Get-ResourceTypeFromResourceId -ResourceId $rid
    $subId               = Get-SubscriptionIdFromResourceId -ResourceId $rid
    $isSubscriptionScope = Test-SubscriptionScopeId -ResourceId $rid
    $isResourceGroup     = Test-ResourceGroupScopeId -ResourceId $rid

    $result.ResourceType   = $resourceType
    $result.SubscriptionId = $subId

    if (-not [string]::IsNullOrWhiteSpace($resourceType) -and
        -not $isSubscriptionScope -and
        -not $isResourceGroup -and
        (Test-SkipAzureTaggingForType -ResourceType $resourceType)) {
      $result.Skipped    = $true
      $result.SkipReason = "Tagging skipped for resource type: $resourceType"
      return $result
    }

    Set-AzContextFromResourceId -ResourceId $rid | Out-Null

    $existing = $null
    try {
      $existing = (Get-AzTag -ResourceId $rid -ErrorAction Stop).Properties.TagsProperty
    }
    catch {
      $existing = $null
    }

    $already = $false
    if ($existing -and $existing.ContainsKey($TagKey) -and ([string]$existing[$TagKey]) -eq $AssetTagName) {
      $already = $true
    }

    if ($already) {
      $result.Success        = $true
      $result.AlreadyPresent = $true
      $result.Changed        = $false
      if ($WhatIfMode) { $result.WhatIf = $true }
      return $result
    }

    if ($WhatIfMode) {
      $result.Success = $true
      $result.WhatIf  = $true
      $result.Changed = $true
      return $result
    }

    Update-AzTag -ResourceId $rid -Tag @{ $TagKey = $AssetTagName } -Operation Merge -ErrorAction Stop | Out-Null

    $result.Success = $true
    $result.Changed = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message

    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }

    throw
  }
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
Write-Info ("WhatIfMode: {0}" -f $WhatIfMode)
Write-Info ("SuppressErrors: {0}" -f $SuppressErrors)
Write-Info ("SuppressWarnings: {0}" -f $SuppressWarnings)

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

if ($AutomationFramework) {

  $ScriptDirectory = $PSScriptRoot
  $global:PathScripts = Split-Path -parent $ScriptDirectory
  Write-Output ""
  Write-Output "Script Directory -> $($global:PathScripts)"

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

#####################################################################################################
# INITIALIZATION
#####################################################################################################

$Scope = @(
  $Scope |
  ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } |
  Where-Object { $_ } |
  Select-Object -Unique
)

if ($null -eq $Scope -or @($Scope).Count -eq 0) { $Scope = @('PROD') }

Write-Step "execution scope initialized"
Write-Info ("Active Scope(s): {0}" -f ($Scope -join ', '))

# -------------------------------------------------------------------------------------------------
# YAML SOURCES (Locked + Custom)
# -------------------------------------------------------------------------------------------------

function Import-AssetTaggingYaml {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return @()
  }

  $y = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Yaml
  if (-not $y -or -not $y.AssetTagging) {
    throw "YAML file is missing AssetTagging root: $Path"
  }

  return @($y.AssetTagging)
}

$LockedYamlFile = if ($global:LockedYamlFile -and -not [string]::IsNullOrWhiteSpace([string]$global:LockedYamlFile)) { [string]$global:LockedYamlFile } else { 'SecurityInsight_CriticalAssetTagging_Locked.yaml' }
$CustomYamlFile = if ($global:CustomYamlFile -and -not [string]::IsNullOrWhiteSpace([string]$global:CustomYamlFile)) { [string]$global:CustomYamlFile } else { 'SecurityInsight_CriticalAssetTagging_Custom.yaml' }
$LegacyYamlFile = if ($global:LegacyYamlFile -and -not [string]::IsNullOrWhiteSpace([string]$global:LegacyYamlFile)) { [string]$global:LegacyYamlFile } else { 'CriticalAssetTagging.yaml' }

$lockedPath = Join-Path $SettingsPath $LockedYamlFile
$customPath = Join-Path $SettingsPath $CustomYamlFile
$legacyPath = Join-Path $SettingsPath $LegacyYamlFile

$lockedExists = Test-Path -LiteralPath $lockedPath
$customExists = Test-Path -LiteralPath $customPath
$legacyExists = Test-Path -LiteralPath $legacyPath

$rulesLocked = @()
$rulesCustom = @()

if ($lockedExists -or $customExists) {

  Write-Step ("loading Locked YAML: {0}" -f $LockedYamlFile)
  $rulesLocked = Import-AssetTaggingYaml -Path $lockedPath

  Write-Step ("loading Custom YAML: {0}" -f $CustomYamlFile)
  $rulesCustom = Import-AssetTaggingYaml -Path $customPath

} elseif ($legacyExists) {

  Write-Warn2 ("Locked/Custom YAML not found. Falling back to legacy YAML: {0}" -f $LegacyYamlFile)
  $rulesLocked = Import-AssetTaggingYaml -Path $legacyPath

} else {

  throw "No YAML found. Expected either Locked+Custom or legacy file in SettingsPath: $SettingsPath"

}

# Merge: Custom wins on duplicate AssetTagName (case-insensitive)
$ruleMap = [ordered]@{}
foreach ($r in @($rulesLocked)) {
  $k = ([string]$r.AssetTagName).Trim().ToUpperInvariant()
  if ([string]::IsNullOrWhiteSpace($k)) { continue }
  $ruleMap[$k] = $r
}
foreach ($r in @($rulesCustom)) {
  $k = ([string]$r.AssetTagName).Trim().ToUpperInvariant()
  if ([string]::IsNullOrWhiteSpace($k)) { continue }
  $ruleMap[$k] = $r
}

$mergedRules = @($ruleMap.Values)

$Yaml = [pscustomobject]@{ AssetTagging = $mergedRules }

Write-Info ("AssetTagging rules loaded: Locked={0}, Custom={1}, Effective={2}" -f (@($rulesLocked).Count), (@($rulesCustom).Count), (@($mergedRules).Count))

#####################################################################################################
# MAIN LOOP
#####################################################################################################

Write-Step "starting asset tag enforcement"

foreach ($rule in @($Yaml.AssetTagging)) {

  $ruleMode    = Get-RuleMode $rule.Mode
  $queryEngine = Get-QueryEngine $rule.QueryEngine

  if ($Scope -notcontains $ruleMode) {
    Write-Info ("Skipping rule '{0}' (Mode={1}) due to Scope filter" -f $rule.AssetTagName, $ruleMode)
    continue
  }

  if (-not $rule.Query) { continue }

  foreach ($queryItem in @($rule.Query)) {

    $query = [string]$queryItem
    if ([string]::IsNullOrWhiteSpace($query)) { continue }

    Write-Info ""
    Write-Info ("Processing: {0} (Mode={1}, Engine={2})" -f $rule.AssetTagName, $ruleMode, $queryEngine)

    if ($queryEngine -eq 'DEFENDERGRAPH') {

      Write-Info "running hunting query against engine: $queryEngine .... Please wait !"
      $resp = Invoke-DefenderGraphQuery -Query $query

      if (-not $resp.Results) { Write-Info "no results"; continue }

      $rows = @(ConvertTo-PSObjectDeep $resp.Results.AdditionalProperties -StripOData)
      if (-not $rows -or $rows.Count -eq 0) { Write-Info "no results"; continue }

      $assetTagName = [string]($rows | Select-Object -First 1).AssetTagName
      if ([string]::IsNullOrWhiteSpace($assetTagName)) { Write-Warn2 "query returned rows but AssetTagName is empty; skipping"; continue }

      $devices = @()
      $skippedNoSenseId = 0
      $skippedNotFound  = 0

      foreach ($r in $rows) {
        $name = Get-DeviceNameFromRow -Row $r
        $id   = Get-SenseDeviceIdFromRow -Row $r

        if ([string]::IsNullOrWhiteSpace($id)) {
          $skippedNoSenseId++
          Write-Warn2 ("Skipping row: missing SenseDeviceId for {0}" -f $name)
          continue
        }

        $exists = $true
        try {
          $exists = Test-DefenderMachineExists -AccessHeaders $AccessHeaders -MachineId $id -SuppressErrors $SuppressErrors
        }
        catch {
          if ($SuppressErrors) {
            Write-Warn2 ("Suppressed Defender existence check error for {0} ({1}) | Error={2}" -f $name, $id, $_.Exception.Message)
            $exists = $false
          }
          else {
            throw
          }
        }

        if (-not $exists) {
          $skippedNotFound++
          Write-Warn2 ("Skipping device: not found in Defender (404 or inaccessible): {0} ({1})" -f $name, $id)
          continue
        }

        $devices += [pscustomobject]@{ Id = $id; Name = $name }
      }

      if ($skippedNoSenseId -gt 0) { Write-Warn2 ("Skipped {0} row(s): missing SenseDeviceId" -f $skippedNoSenseId) }
      if ($skippedNotFound  -gt 0) { Write-Warn2 ("Skipped {0} row(s): SenseDeviceId not found in Defender or inaccessible" -f $skippedNotFound) }

      $devices = @($devices | Group-Object Id | ForEach-Object { $_.Group | Select-Object -First 1 })

      if (-not $devices -or $devices.Count -eq 0) { Write-Warn2 "no taggable devices found; skipping"; continue }

      $chunkSize   = 500
      $totalChunks = [math]::Ceiling($devices.Count / $chunkSize)

      for ($i = 0; $i -lt $devices.Count; $i += $chunkSize) {

        $currentChunk = [math]::Floor($i / $chunkSize) + 1
        $endIndex     = [math]::Min($i + $chunkSize - 1, $devices.Count - 1)
        $chunk        = @($devices[$i..$endIndex])

        $namesPreview = @($chunk | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
        if ($chunk.Count -gt 5) { $namesPreview = "$namesPreview, ..." }

        Write-Info ("tagging {0} machines with '{1}' (chunk {2}/{3}) -> {4}" -f $chunk.Count, $assetTagName, $currentChunk, $totalChunks, $namesPreview)

        try {
          Apply-TagBulkWithSplit -AccessHeaders $AccessHeaders -Devices $chunk -Tag $assetTagName -SuppressErrors $SuppressErrors
        }
        catch {
          if ($SuppressErrors) {
            Write-Warn2 ("Suppressed Defender chunk tagging error: Tag='{0}' | Chunk={1}/{2} | Error={3}" -f $assetTagName, $currentChunk, $totalChunks, $_.Exception.Message)
          }
          else {
            throw
          }
        }
      }
    }
    elseif ($queryEngine -eq 'AZURERESOURCEGRAPH') {

      Write-Info "running hunting query against engine: $queryEngine .... Please wait !"
      $arg = Invoke-AzureResourceGraphQuery -Query $query

      $rows = @()
      if ($arg -and ($arg.PSObject.Properties.Name -contains 'Data')) {
        $rows = @($arg.Data)
      } elseif ($arg) {
        $rows = @($arg)
      }
      $rows = @($rows)

      if (-not $rows -or $rows.Count -eq 0) { Write-Info "no results"; continue }

      $fallbackTagValue = $null
      if ($rule.PSObject.Properties.Name -contains 'AssetTagName' -and -not [string]::IsNullOrWhiteSpace([string]$rule.AssetTagName)) {
        $fallbackTagValue = [string]$rule.AssetTagName
      }

      $resourceIds = @(
        foreach ($r in $rows) {
          $rid = Get-ArgResourceIdFromRow -Row $r
          if (-not [string]::IsNullOrWhiteSpace($rid)) { $rid }
        }
      )
      $resourceIds = @($resourceIds | Select-Object -Unique)

      if (-not $resourceIds -or $resourceIds.Count -eq 0) {
        Write-Warn2 "ARG results did not include a resource id column (expected id/Id/ResourceId); skipping"
        continue
      }

      Write-Info ("tagging {0} Azure scope(s)/resources (individual tagging)" -f $resourceIds.Count)

      foreach ($rid in $resourceIds) {

        $match = $rows | Where-Object {
          ($_.PSObject.Properties.Name -contains 'id' -and ([string]$_.id) -eq $rid) -or
          ($_.PSObject.Properties.Name -contains 'Id' -and ([string]$_.Id) -eq $rid) -or
          ($_.PSObject.Properties.Name -contains 'ResourceId' -and ([string]$_.ResourceId) -eq $rid)
        } | Select-Object -First 1

        $nameHint = if ($match) { Get-ArgResourceNameFromRow -Row $match } else { $null }
        if ([string]::IsNullOrWhiteSpace($nameHint)) { $nameHint = "<resource>" }

        $tagKey = $null
        if ($match) { $tagKey = Get-ArgAssetTagTypeFromRow -Row $match }
        if ([string]::IsNullOrWhiteSpace($tagKey)) {
          Write-Warn2 ("Skipping Azure tag: missing AssetTagType for {0} ({1})" -f $nameHint, $rid)
          continue
        }

        $tagValue = $null
        if ($match) { $tagValue = Get-TagValueFromRow -Row $match -ColumnName 'AssetTagName' }
        if ([string]::IsNullOrWhiteSpace($tagValue)) { $tagValue = $fallbackTagValue }

        if ([string]::IsNullOrWhiteSpace($tagValue)) {
          Write-Warn2 ("Skipping Azure tag: missing AssetTagName for {0} ({1})" -f $nameHint, $rid)
          continue
        }

        $resourceType = $null
        $targetSub    = $null
        try {
          if (-not [string]::IsNullOrWhiteSpace($rid)) {
            $resourceType = Get-ResourceTypeFromResourceId -ResourceId $rid
            $targetSub    = Get-SubscriptionIdFromResourceId -ResourceId $rid
          }
        } catch {}

        try {
          $result = Add-AzureResourceTag `
            -ResourceId $rid `
            -AssetTagName $tagValue `
            -TagKey $tagKey `
            -WhatIfMode $WhatIfMode `
            -SuppressErrors $SuppressErrors

          if ($result.Skipped) {
            Write-Warn2 ("Skipping Azure tag: {0} | Type={1} | ResourceId={2} | Reason={3}" -f `
              $nameHint, $result.ResourceType, $rid, $result.SkipReason)
          }
          elseif ($result.Suppressed) {
            Write-Warn2 ("Suppressed Azure tagging error: {0} | Type={1} | TargetSub={2} | ResourceId={3} | Error={4}" -f `
              $nameHint, $resourceType, $targetSub, $rid, $result.ErrorMessage)
          }
          elseif ($result.WhatIf -and $result.Changed) {
            Write-Warn2 ("[WHATIF] Would set Azure tag: {0} -> {1}='{2}' | Type={3} | ResourceId={4}" -f `
              $nameHint, $tagKey, $tagValue, $result.ResourceType, $rid)
          }
          elseif ($result.AlreadyPresent) {
            Write-Info ("Azure tag already present: {0} -> {1}='{2}' | Type={3}" -f `
              $nameHint, $tagKey, $tagValue, $result.ResourceType)
          }
          elseif ($result.Changed) {
            Write-Ok ("Azure tag set: {0} -> {1}='{2}' | Type={3}" -f `
              $nameHint, $tagKey, $tagValue, $result.ResourceType)
          }
          else {
            Write-Warn2 ("Azure tag returned no-change/unknown state: {0} | Type={1} | ResourceId={2}" -f `
              $nameHint, $resourceType, $rid)
          }
        }
        catch {
          $currentSub = $null
          try { $currentSub = (Get-AzContext).Subscription.Id } catch {}

          if ($SuppressErrors) {
            Write-Warn2 ("Suppressed Azure tagging failure: {0} | Type={1} | TargetSub={2} | ContextSub={3} | ResourceId={4} | Error={5}" -f `
              $nameHint, $resourceType, $targetSub, $currentSub, $rid, $_.Exception.Message)
          }
          else {
            Write-Err2 ("Azure tagging failed: {0} | Type={1} | TargetSub={2} | ContextSub={3} | ResourceId={4} | Error={5}" -f `
              $nameHint, $resourceType, $targetSub, $currentSub, $rid, $_.Exception.Message)
          }
        }
      }
    }
    else {
      Write-Warn2 ("Unknown QueryEngine '{0}' for rule '{1}'. Use DefenderGraph or AzureResourceGraph." -f $queryEngine, $rule.AssetTagName)
      continue
    }
  }
}

Write-Step "asset tag enforcement completed"
