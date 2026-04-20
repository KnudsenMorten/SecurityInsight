<#
.SYNOPSIS
    CriticalAssetTagging - engine script in the SecurityInsight solution.

.NOTES
    Solution       : SecurityInsight
    File           : CriticalAssetTagging.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
Write-host "***********************************************************************************************"
Write-host "Critical Asset Tagging using YAML-file"
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

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
  $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }

# KustoCL engine globals (set by launcher, optional - only required when KustoCL rules exist)
if ($null -eq $global:KustoWorkspaceId)  { $global:KustoWorkspaceId  = $null }
if ($null -eq $global:KustoTable)        { $global:KustoTable         = 'SI_IdentityAssets_CL' }
if ($null -eq $global:CsaAttributeSet)   { $global:CsaAttributeSet   = 'SecurityInsight' }

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

function Write-Sep {
  param(
    [string]$Char = '-',
    [int]$Width = 110
  )
  Write-Host ($Char * $Width) -ForegroundColor DarkGray
}

function Write-BlockFields {
  param(
    [hashtable]$Fields,
    [ValidateSet('Info','Ok','Warn','Err')]
    [string]$Level = 'Info',
    [string]$Indent = ""
  )

  if (-not $Fields -or $Fields.Count -eq 0) { return }

  $color = switch ($Level) {
    'Ok'   { 'Green' }
    'Warn' { 'Yellow' }
    'Err'  { 'Red' }
    default { 'Gray' }
  }

  $keys = @($Fields.Keys)

  $preferredOrder = @(
    'Rule','Engine','Mode','Chunk','Count','Machines',
    'Name','Type','Tag','TagKey','TagValue',
    'Reason','TargetSub','ContextSub','Id',
    'ResourceId','Error'
  )

  $orderedKeys = @()
  foreach ($k in $preferredOrder) {
    if ($keys -contains $k) { $orderedKeys += $k }
  }
  foreach ($k in $keys) {
    if ($orderedKeys -notcontains $k) { $orderedKeys += $k }
  }

  foreach ($k in $orderedKeys) {
    $v = if ($null -eq $Fields[$k]) { "" } else { [string]$Fields[$k] }

    if ($k -in @('ResourceId','Error')) {
      Write-Host ("{0}{1,-12}:" -f $Indent, $k) -ForegroundColor $color
      foreach ($line in ($v -split "`r?`n")) {
        Write-Host $line -ForegroundColor $color
      }
    }
    else {
      Write-Host ("{0}{1,-12}: {2}" -f $Indent, $k, $v) -ForegroundColor $color
    }
  }
}

function Write-InfoBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($SeparatorBefore) { Write-Sep }
  Write-Info $Title
  Write-BlockFields -Fields $Fields -Level Info
  if ($SeparatorAfter) { Write-Sep }
}

function Write-OkBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($SeparatorBefore) { Write-Sep }
  Write-Ok $Title
  Write-BlockFields -Fields $Fields -Level Ok
  if ($SeparatorAfter) { Write-Sep }
}

function Write-WarnBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($script:SuppressWarnings) { return }

  if ($SeparatorBefore) { Write-Sep }
  Write-Warn2 $Title
  Write-BlockFields -Fields $Fields -Level Warn
  if ($SeparatorAfter) { Write-Sep }
}

function Write-ErrBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($script:SuppressErrors) { return }

  if ($SeparatorBefore) { Write-Sep }
  Write-Err2 $Title
  Write-BlockFields -Fields $Fields -Level Err
  if ($SeparatorAfter) { Write-Sep }
}

function Tick {
  param([string]$Label="")
  if($script:_sw){
    $script:_sw.Stop()
    Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds)
    $script:_sw=$null
  }
}

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

# ==========================================================================================
# KUSTOCL ENGINE - Log Analytics query + Entra CSA write-back
# ==========================================================================================

function Invoke-KustoCLQuery {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WorkspaceId,
    [Parameter(Mandatory)][string]$Query
  )

  # Requires Az.OperationalInsights
  $result = Invoke-AzOperationalInsightsQuery `
    -WorkspaceId $WorkspaceId `
    -Query       $Query `
    -ErrorAction Stop

  if (-not $result -or -not $result.Results) {
    return [pscustomobject]@{ Data = @(); Count = 0 }
  }

  $rows = @($result.Results)
  return [pscustomobject]@{ Data = $rows; Count = $rows.Count }
}

function Get-EntraObjectIdFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($n in @('ObjectId','objectId','ObjectId_s','objectId_s')) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return $null
}

function Get-EntraObjectTypeFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($n in @('ObjectType','objectType','ObjectType_s','objectType_s')) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return $null
}

function Get-EntraDisplayNameFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($n in @('DisplayName','displayName','DisplayName_s','displayName_s')) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return '<unknown>'
}

function Get-EntraEndpointFromObjectType {
  param([Parameter(Mandatory)][string]$ObjectType)
  switch ($ObjectType.ToLowerInvariant()) {
    'user'              { return 'users' }
    'serviceprincipal'  { return 'servicePrincipals' }
    'managedidentity'   { return 'servicePrincipals' }
    default             { return $null }
  }
}

function Get-EntraCurrentCSATags {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Endpoint,
    [Parameter(Mandatory)][string]$ObjectId,
    [Parameter(Mandatory)][string]$AttributeSet
  )

  try {
    $resp = Invoke-MgGraphRequest `
      -Method  GET `
      -Uri     "https://graph.microsoft.com/v1.0/$Endpoint/$ObjectId`?`$select=customSecurityAttributes" `
      -Headers @{ 'Content-Type' = 'application/json' }

    $csaBlock = $resp.customSecurityAttributes
    if (-not $csaBlock) { return @() }

    $setBlock = $csaBlock.$AttributeSet
    if (-not $setBlock) { return @() }

    $raw = $setBlock.AssetTags
    if (-not $raw) { return @() }

    # AssetTags is a string collection - may come back as array or single string
    if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
      return @($raw | ForEach-Object { [string]$_ } | Where-Object { $_ })
    }
    return @([string]$raw)
  }
  catch {
    # Object may not have CSA yet - treat as empty
    return @()
  }
}

function Set-EntraCSATag {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Endpoint,
    [Parameter(Mandatory)][string]$ObjectId,
    [Parameter(Mandatory)][string]$AttributeSet,
    [Parameter(Mandatory)][string]$AssetTagName,
    [Parameter(Mandatory)][string[]]$CurrentTags,
    [string]$DisplayName    = '<unknown>',
    [bool]$WhatIfMode       = $script:WhatIfMode,
    [bool]$SuppressErrors   = $script:SuppressErrors
  )

  $result = [pscustomobject]@{
    Success        = $false
    Suppressed     = $false
    AlreadyPresent = $false
    WhatIf         = $false
    Changed        = $false
    ErrorMessage   = $null
    ObjectId       = $ObjectId
    DisplayName    = $DisplayName
    AssetTagName   = $AssetTagName
  }

  # Skip if already tagged
  if ($CurrentTags -contains $AssetTagName) {
    $result.Success        = $true
    $result.AlreadyPresent = $true
    return $result
  }

  if ($WhatIfMode) {
    $result.Success = $true
    $result.WhatIf  = $true
    $result.Changed = $true
    return $result
  }

  # Merge new tag into existing collection
  $newTags = @($CurrentTags) + @($AssetTagName) | Select-Object -Unique

  $body = @{
    customSecurityAttributes = @{
      $AttributeSet = @{
        '@odata.type' = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue'
        'AssetTags@odata.type' = '#Collection(String)'
        AssetTags     = @($newTags)
      }
    }
  }

  try {
    Invoke-MgGraphRequest `
      -Method  PATCH `
      -Uri     "https://graph.microsoft.com/v1.0/$Endpoint/$ObjectId" `
      -Headers @{ 'Content-Type' = 'application/json' } `
      -Body    ($body | ConvertTo-Json -Depth 6) | Out-Null

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
    'NodeName','nodeName',
    'ComputerDnsName','computerDnsName',
    'HostName','hostName',
    'DnsName','dnsName',
    'NetBiosName','netBiosName',
    'AadDeviceName','aadDeviceName',
    'MachineName','machineName',
    'Name','name'
  )

  if (-not [string]::IsNullOrWhiteSpace($n)) {
    return $n.Trim()
  }

  $id = Get-SenseDeviceIdFromRow -Row $Row
  if (-not [string]::IsNullOrWhiteSpace($id)) {
    return "<unknown:$id>"
  }

  return "<unknown>"
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
      Write-WarnBlock -Title "Suppressed Defender machine existence check error" -Fields ([ordered]@{
        MachineId = $MachineId
        Error     = $_.Exception.Message
      }) -SeparatorBefore
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
    Write-WarnBlock -Title "[WHATIF] Would bulk-tag Defender machines" -Fields ([ordered]@{
      Count = $MachineIds.Count
      Tag   = $Tag
      Uri   = $uri
    }) -SeparatorBefore
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
    Write-WarnBlock -Title "[WHATIF] Would tag Defender machine" -Fields ([ordered]@{
      DeviceName = $DeviceName
      MachineId  = $MachineId
      Tag        = $Tag
      Uri        = $uri
    }) -SeparatorBefore
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
        Write-WarnBlock -Title "Suppressed Defender bulk tagging error" -Fields ([ordered]@{
          Count = $ids.Count
          Depth = $depth
          Tag   = $Tag
          Error = $bulkResult.ErrorMessage
        }) -SeparatorBefore
      }
      else {
        Write-OkBlock -Title "Defender bulk tag applied" -Fields ([ordered]@{
          Count = $ids.Count
          Tag   = $Tag
          Depth = $depth
        }) -SeparatorBefore
      }

      continue
    }
    catch {
      Write-ErrBlock -Title "Defender bulk tagging failed" -Fields ([ordered]@{
        Count = $ids.Count
        Depth = $depth
        Error = $_.Exception.Message
      }) -SeparatorBefore

      if ($items.Count -le 1 -or $depth -ge $MaxSplitDepth) {
        $one = $items[0]
        try {
          $singleResult = Add-DefenderTag -AccessHeaders $AccessHeaders -MachineId $one.Id -Tag $Tag -DeviceName $one.Name -SuppressErrors $SuppressErrors
          if ($singleResult.Suppressed) {
            Write-WarnBlock -Title "Suppressed Defender single-machine tagging error" -Fields ([ordered]@{
              Name  = $one.Name
              Id    = $one.Id
              Tag   = $Tag
              Error = $singleResult.ErrorMessage
            }) -SeparatorBefore
          }
          else {
            Write-OkBlock -Title "Defender single-machine tag applied" -Fields ([ordered]@{
              Name = $one.Name
              Id   = $one.Id
              Tag  = $Tag
            }) -SeparatorBefore
          }
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed unprocessable Defender machine error" -Fields ([ordered]@{
              Name  = $one.Name
              Id    = $one.Id
              Error = $_.Exception.Message
            }) -SeparatorBefore
          }
          else {
            Write-ErrBlock -Title "Unprocessable Defender machine" -Fields ([ordered]@{
              Name  = $one.Name
              Id    = $one.Id
              Error = $_.Exception.Message
            }) -SeparatorBefore
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

  # Types that cannot be tagged via Update-AzTag / PATCH on the resource id.
  # These are either provider-scope-only resources (no /tags endpoint on ARM),
  # internal Microsoft service objects, or types where PATCH is not supported.
  $skipTypes = @(
    # Already skipped - query rules have no tags endpoint
    'microsoft.insights/scheduledqueryrules',

    # Role assignments - PATCH not supported at any roleAssignment scope
    # (neither subscription-provider, resourceGroup, nor MG scope)
    'microsoft.authorization/roleassignments',

    # Policy assignments at subscription-provider scope have no tags endpoint.
    # (RG-scoped assignments are taggable, but ARG queries should already
    # filter to isnotempty(resourceGroup) so provider-scope ones never appear)
    'microsoft.authorization/policyassignments',

    # Defender for Cloud / security pricing plans - subscription-provider scope,
    # no /tags endpoint (microsoft.security/pricings/{PlanName})
    'microsoft.security/pricings',

    # Internal Microsoft Sentinel platform service - not a customer-manageable resource
    'microsoft.sentinelplatformservices/sentinelplatformservices'
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
    # Provider-scope resources (e.g. /subscriptions/{id}/providers/...) are not taggable
    # via ARM tags � they have no /tags endpoint. Detect them before the strict ARM id check
    # and return a clean skip rather than throwing.
    if (-not [string]::IsNullOrWhiteSpace($rid)) {
      $rt = Get-ResourceTypeFromResourceId -ResourceId $rid
      if (-not [string]::IsNullOrWhiteSpace($rt) -and
          (Test-SkipAzureTaggingForType -ResourceType $rt)) {
        $result.Skipped    = $true
        $result.SkipReason = "Tagging skipped for resource type: $rt"
        return $result
      }
    }

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

#####################################################################################################
# CONNECTION
#####################################################################################################

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
  if (-not $y) { return @() }
  if (-not $y.ContainsKey('AssetTagging')) {
    throw "YAML file is missing AssetTagging root: $Path"
  }
  if ($null -eq $y.AssetTagging) { return @() }

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

    Write-Sep
    Write-Info ("Processing: {0} (Mode={1}, Engine={2})" -f $rule.AssetTagName, $ruleMode, $queryEngine)

    if ($queryEngine -eq 'DEFENDERGRAPH') {

      Write-Info "running hunting query against engine: DEFENDERGRAPH .... Please wait !"
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
          Write-WarnBlock -Title "Skipping Defender row" -Fields ([ordered]@{
            Reason = "Missing SenseDeviceId"
            Name   = $name
          }) -SeparatorBefore
          continue
        }

        $exists = $true
        try {
          $exists = Test-DefenderMachineExists -AccessHeaders $AccessHeaders -MachineId $id -SuppressErrors $SuppressErrors
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed Defender existence check error" -Fields ([ordered]@{
              Name  = $name
              Id    = $id
              Error = $_.Exception.Message
            }) -SeparatorBefore
            $exists = $false
          }
          else {
            throw
          }
        }

        if (-not $exists) {
          $skippedNotFound++
          Write-WarnBlock -Title "Skipping Defender device" -Fields ([ordered]@{
            Reason = "Not found in Defender (404 or inaccessible)"
            Name   = $name
            Id     = $id
          }) -SeparatorBefore
          continue
        }

        $devices += [pscustomobject]@{ Id = $id; Name = $name }
      }

      if ($skippedNoSenseId -gt 0) {
        Write-WarnBlock -Title "Skipped Defender rows" -Fields ([ordered]@{
          Reason = "Missing SenseDeviceId"
          Count  = $skippedNoSenseId
        }) -SeparatorBefore
      }

      if ($skippedNotFound -gt 0) {
        Write-WarnBlock -Title "Skipped Defender rows" -Fields ([ordered]@{
          Reason = "SenseDeviceId not found in Defender or inaccessible"
          Count  = $skippedNotFound
        }) -SeparatorBefore
      }

      $devices = @($devices | Group-Object Id | ForEach-Object { $_.Group | Select-Object -First 1 })

      if (-not $devices -or $devices.Count -eq 0) {
        Write-Warn2 "no taggable devices found; skipping"
        continue
      }

      $chunkSize   = 500
      $totalChunks = [math]::Ceiling($devices.Count / $chunkSize)

      for ($i = 0; $i -lt $devices.Count; $i += $chunkSize) {

        $currentChunk = [math]::Floor($i / $chunkSize) + 1
        $endIndex     = [math]::Min($i + $chunkSize - 1, $devices.Count - 1)
        $chunk        = @($devices[$i..$endIndex])

        $namesPreview = @(
          $chunk | Select-Object -First 5 | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_.Name) -or $_.Name -like '<unknown*') {
              $_.Id
            }
            else {
              "{0} ({1})" -f $_.Name, $_.Id
            }
          }
        ) -join ', '

        if ($chunk.Count -gt 5) { $namesPreview = "$namesPreview, ..." }

        Write-InfoBlock -Title "Defender tagging batch" -Fields ([ordered]@{
          Rule     = $rule.AssetTagName
          Tag      = $assetTagName
          Chunk    = "$currentChunk/$totalChunks"
          Count    = $chunk.Count
          Machines = $namesPreview
        }) -SeparatorBefore

        try {
          Apply-TagBulkWithSplit -AccessHeaders $AccessHeaders -Devices $chunk -Tag $assetTagName -SuppressErrors $SuppressErrors
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed Defender chunk tagging error" -Fields ([ordered]@{
              Tag   = $assetTagName
              Chunk = "$currentChunk/$totalChunks"
              Error = $_.Exception.Message
            }) -SeparatorBefore
          }
          else {
            throw
          }
        }
      }
    }
    elseif ($queryEngine -eq 'AZURERESOURCEGRAPH') {

      Write-Info "running hunting query against engine: AZURERESOURCEGRAPH .... Please wait !"
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

      Write-InfoBlock -Title "Azure tagging batch" -Fields ([ordered]@{
        Rule   = $rule.AssetTagName
        Engine = $queryEngine
        Mode   = $ruleMode
        Count  = $resourceIds.Count
      }) -SeparatorBefore

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
          Write-WarnBlock -Title "Skipping Azure tag" -Fields ([ordered]@{
            Name       = $nameHint
            Reason     = "Missing AssetTagType"
            ResourceId = $rid
          }) -SeparatorBefore
          continue
        }

        $tagValue = $null
        if ($match) { $tagValue = Get-TagValueFromRow -Row $match -ColumnName 'AssetTagName' }
        if ([string]::IsNullOrWhiteSpace($tagValue)) { $tagValue = $fallbackTagValue }

        if ([string]::IsNullOrWhiteSpace($tagValue)) {
          Write-WarnBlock -Title "Skipping Azure tag" -Fields ([ordered]@{
            Name       = $nameHint
            Reason     = "Missing AssetTagName"
            ResourceId = $rid
          }) -SeparatorBefore
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
            Write-WarnBlock -Title "Skipping Azure tag" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $result.ResourceType
              Reason     = $result.SkipReason
              ResourceId = $rid
            }) -SeparatorBefore
          }
          elseif ($result.Suppressed) {
            Write-WarnBlock -Title "Suppressed Azure tagging error" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              TargetSub  = $targetSub
              ResourceId = $rid
              Error      = $result.ErrorMessage
            }) -SeparatorBefore
          }
          elseif ($result.WhatIf -and $result.Changed) {
            Write-WarnBlock -Title "[WHATIF] Would set Azure tag" -Fields ([ordered]@{
              Name       = $nameHint
              TagKey     = $tagKey
              TagValue   = $tagValue
              Type       = $result.ResourceType
              ResourceId = $rid
            }) -SeparatorBefore
          }
          elseif ($result.AlreadyPresent) {
            Write-InfoBlock -Title "Azure tag already present" -Fields ([ordered]@{
              Name     = $nameHint
              TagKey   = $tagKey
              TagValue = $tagValue
              Type     = $result.ResourceType
            }) -SeparatorBefore
          }
          elseif ($result.Changed) {
            Write-OkBlock -Title "Azure tag set" -Fields ([ordered]@{
              Name     = $nameHint
              TagKey   = $tagKey
              TagValue = $tagValue
              Type     = $result.ResourceType
            }) -SeparatorBefore
          }
          else {
            Write-WarnBlock -Title "Azure tag returned no-change/unknown state" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              ResourceId = $rid
            }) -SeparatorBefore
          }
        }
        catch {
          $currentSub = $null
          try { $currentSub = (Get-AzContext).Subscription.Id } catch {}

          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed Azure tagging failure" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              TargetSub  = $targetSub
              ContextSub = $currentSub
              ResourceId = $rid
              Error      = $_.Exception.Message
            }) -SeparatorBefore
          }
          else {
            Write-ErrBlock -Title "Azure tagging failed" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              TargetSub  = $targetSub
              ContextSub = $currentSub
              ResourceId = $rid
              Error      = $_.Exception.Message
            }) -SeparatorBefore
          }
        }
      }
    }
    elseif ($queryEngine -eq 'KUSTOCL') {

      # -----------------------------------------------------------------------
      # KustoCL engine - query Log Analytics custom table, write CSA on Entra
      # -----------------------------------------------------------------------

      if ([string]::IsNullOrWhiteSpace([string]$global:KustoWorkspaceId)) {
        Write-WarnBlock -Title "Skipping KustoCL rule" -Fields ([ordered]@{
          Rule   = $rule.AssetTagName
          Reason = "KustoWorkspaceId global is not set - add it to your launcher"
        }) -SeparatorBefore
        continue
      }

      # Substitute {{TABLE}} placeholder with the configured table name
      $kustoTable = if (-not [string]::IsNullOrWhiteSpace([string]$global:KustoTable)) {
        [string]$global:KustoTable
      } else { 'SI_IdentityAssets_CL' }

      $resolvedQuery = $query -replace '\{\{TABLE\}\}', $kustoTable

      Write-Info "running hunting query against engine: KUSTOCL .... Please wait !"

      $kResult = $null
      try {
        $kResult = Invoke-KustoCLQuery -WorkspaceId $global:KustoWorkspaceId -Query $resolvedQuery
      }
      catch {
        if ($SuppressErrors) {
          Write-WarnBlock -Title "Suppressed KustoCL query error" -Fields ([ordered]@{
            Rule  = $rule.AssetTagName
            Error = $_.Exception.Message
          }) -SeparatorBefore
          continue
        }
        throw
      }

      if (-not $kResult -or $kResult.Count -eq 0) { Write-Info "no results"; continue }

      $rows = @($kResult.Data)

      # Read AssetTagName from first row (same contract as DefenderGraph)
      $assetTagName = [string]($rows | Select-Object -First 1).AssetTagName
      if ([string]::IsNullOrWhiteSpace($assetTagName)) {
        Write-Warn2 "KustoCL query returned rows but AssetTagName column is empty; skipping"
        continue
      }

      # Resolve AttributeSet - from rule property, then global, then default
      $attributeSet = if ($rule.PSObject.Properties.Name -contains 'AttributeSet' -and
                          -not [string]::IsNullOrWhiteSpace([string]$rule.AttributeSet)) {
        [string]$rule.AttributeSet
      } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:CsaAttributeSet)) {
        [string]$global:CsaAttributeSet
      } else { 'SecurityInsight' }

      Write-InfoBlock -Title "KustoCL identity tagging batch" -Fields ([ordered]@{
        Rule         = $rule.AssetTagName
        Engine       = $queryEngine
        Mode         = $ruleMode
        Count        = $rows.Count
        AttributeSet = $attributeSet
      }) -SeparatorBefore

      $tagged   = 0
      $skipped  = 0
      $alreadyP = 0
      $failed   = 0

      foreach ($r in $rows) {

        $objectId   = Get-EntraObjectIdFromRow   -Row $r
        $objectType = Get-EntraObjectTypeFromRow  -Row $r
        $displayName= Get-EntraDisplayNameFromRow -Row $r

        if ([string]::IsNullOrWhiteSpace($objectId)) {
          Write-WarnBlock -Title "Skipping KustoCL row" -Fields ([ordered]@{
            Reason      = "Missing ObjectId column"
            DisplayName = $displayName
          }) -SeparatorBefore
          $skipped++
          continue
        }

        if ([string]::IsNullOrWhiteSpace($objectType)) {
          Write-WarnBlock -Title "Skipping KustoCL row" -Fields ([ordered]@{
            Reason      = "Missing ObjectType column"
            DisplayName = $displayName
            ObjectId    = $objectId
          }) -SeparatorBefore
          $skipped++
          continue
        }

        $endpoint = Get-EntraEndpointFromObjectType -ObjectType $objectType
        if ([string]::IsNullOrWhiteSpace($endpoint)) {
          Write-WarnBlock -Title "Skipping KustoCL row" -Fields ([ordered]@{
            Reason      = "Unrecognised ObjectType: $objectType"
            DisplayName = $displayName
            ObjectId    = $objectId
          }) -SeparatorBefore
          $skipped++
          continue
        }

        # Read current CSA tags - used for skip/already-present check
        $currentTags = @()
        try {
          $currentTags = Get-EntraCurrentCSATags `
            -Endpoint     $endpoint `
            -ObjectId     $objectId `
            -AttributeSet $attributeSet
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed CSA read error" -Fields ([ordered]@{
              DisplayName = $displayName
              ObjectId    = $objectId
              Error       = $_.Exception.Message
            }) -SeparatorBefore
            $skipped++
            continue
          }
          throw
        }

        try {
          $result = Set-EntraCSATag `
            -Endpoint     $endpoint `
            -ObjectId     $objectId `
            -AttributeSet $attributeSet `
            -AssetTagName $assetTagName `
            -CurrentTags  $currentTags `
            -DisplayName  $displayName `
            -WhatIfMode   $WhatIfMode `
            -SuppressErrors $SuppressErrors

          if ($result.Suppressed) {
            Write-WarnBlock -Title "Suppressed CSA tagging error" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              AssetTagName = $assetTagName
              Error        = $result.ErrorMessage
            }) -SeparatorBefore
            $failed++
          }
          elseif ($result.WhatIf -and $result.Changed) {
            Write-WarnBlock -Title "[WHATIF] Would set CSA tag" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              ObjectType   = $objectType
              AttributeSet = $attributeSet
              AssetTagName = $assetTagName
            }) -SeparatorBefore
            $tagged++
          }
          elseif ($result.AlreadyPresent) {
            Write-InfoBlock -Title "CSA tag already present" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              AssetTagName = $assetTagName
            }) -SeparatorBefore
            $alreadyP++
          }
          elseif ($result.Changed) {
            Write-OkBlock -Title "CSA tag set" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              ObjectType   = $objectType
              AttributeSet = $attributeSet
              AssetTagName = $assetTagName
            }) -SeparatorBefore
            $tagged++
          }
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed CSA tagging failure" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              Error        = $_.Exception.Message
            }) -SeparatorBefore
            $failed++
          }
          else {
            Write-ErrBlock -Title "CSA tagging failed" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              Error        = $_.Exception.Message
            }) -SeparatorBefore
          }
        }
      }

      Write-InfoBlock -Title "KustoCL batch complete" -Fields ([ordered]@{
        Rule      = $rule.AssetTagName
        Tagged    = $tagged
        AlreadyOk = $alreadyP
        Skipped   = $skipped
        Failed    = $failed
      }) -SeparatorBefore
    }
    else {
      Write-Warn2 ("Unknown QueryEngine '{0}' for rule '{1}'. Use DefenderGraph, AzureResourceGraph or KustoCL." -f $queryEngine, $rule.AssetTagName)
      continue
    }
  }
}

Write-Step "asset tag enforcement completed"
