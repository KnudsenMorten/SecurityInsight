Write-host "***********************************************************************************************"
Write-host "Critical Asset Tagging using YAML-file"
Write-host ""
Write-host "Support: mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight"
Write-host "***********************************************************************************************"

# -------------------------------------------------------------------------------------------------
# GLOBAL-ONLY CONFIG (launcher is source of truth)
# -------------------------------------------------------------------------------------------------

# Optional safe defaults if someone runs the main script directly (without launcher)
if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
  $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }

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

# Map globals into locals (rest of file can keep using $SettingsPath etc.)
$SettingsPath        = $global:SettingsPath
$AutomationFramework = [bool]$global:AutomationFramework
$Scope               = @($global:Scope)

# Optional safe defaults if someone runs the main script directly (without launcher)
if ($null -eq $global:WhatIfMode) { $global:WhatIfMode = $false }

$WhatIfMode = [bool]$global:WhatIfMode
Write-Info ("WhatIfMode: {0}" -f $WhatIfMode)

#######################################################################################################
# FUNCTIONS (begin)
#######################################################################################################

# ================= Logging helpers =================
function Write-Step  ($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Info  ($m){ Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-Ok    ($m){ Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn2 ($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err2  ($m){ Write-Host "[ERR]  $m" -ForegroundColor Red }
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

function AddTagForMultipleMachines {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string[]]$DeviceInventoryIds,
    [Parameter(Mandatory)][string]$Tag,
    [bool]$WhatIfMode = $script:WhatIfMode
  )

  $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
  $bodyObj = @{
    Value      = $Tag
    Action     = "Add"
    MachineIds = @($DeviceInventoryIds)
  }

  if ($WhatIfMode) {
    Write-Warn2 ("[WHATIF] Would bulk-tag {0} machines with '{1}'" -f $DeviceInventoryIds.Count, $Tag)
    Write-Info  ("[WHATIF] POST {0}" -f $uri)
    return [pscustomobject]@{
      WhatIf   = $true
      Uri      = $uri
      Body     = $bodyObj
      Count    = $DeviceInventoryIds.Count
      Tag      = $Tag
    }
  }

  $body = $bodyObj | ConvertTo-Json -Depth 4
  Invoke-RestMethod -Method POST -Uri $uri -Headers $AccessHeaders -ContentType "application/json" -Body $body
}

function Add-DefenderTag {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$DeviceInventoryId,
    [Parameter(Mandatory)][string]$Tag,
    [bool]$WhatIfMode = $script:WhatIfMode
  )

  $uri  = "https://api.securitycenter.microsoft.com/api/machines/$DeviceInventoryId/tags"
  $bodyObj = @{
    Value  = $Tag
    Action = "Add"
  }

  if ($WhatIfMode) {
    Write-Warn2 ("[WHATIF] Would tag machine {0} with '{1}'" -f $DeviceInventoryId, $Tag)
    Write-Info  ("[WHATIF] POST {0}" -f $uri)
    return [pscustomobject]@{
      WhatIf = $true
      Uri    = $uri
      Body   = $bodyObj
      Id     = $DeviceInventoryId
      Tag    = $Tag
    }
  }

  $body = $bodyObj | ConvertTo-Json -Depth 4
  Invoke-RestMethod -Method POST -Uri $uri -Headers $AccessHeaders -ContentType "application/json" -Body $body
}

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
  foreach ($name in @('name','Name','resourceName','ResourceName')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
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

function Add-AzureResourceTag {
  param(
    [Parameter(Mandatory)][string]$ResourceId,
    [Parameter(Mandatory)][string]$AssetTagName,
    [Parameter(Mandatory)][string]$TagKey,
    [bool]$WhatIfMode = $script:WhatIfMode
  )

  if ([string]::IsNullOrWhiteSpace($ResourceId))   { throw "ResourceId is empty" }
  if ([string]::IsNullOrWhiteSpace($TagKey))       { throw "TagKey is empty" }
  if ([string]::IsNullOrWhiteSpace($AssetTagName)) { throw "AssetTagName is empty" }

  $rid = $ResourceId.Trim()

  $existing = $null
  try { $existing = (Get-AzTag -ResourceId $rid -ErrorAction Stop).Properties.TagsProperty } catch { $existing = $null }

  $already = $false
  if ($existing -and $existing.ContainsKey($TagKey) -and ([string]$existing[$TagKey]) -eq $AssetTagName) {
    $already = $true
  }

  if ($WhatIfMode) {
    if ($already) {
      Write-Info ("[WHATIF] Azure tag already present: {0} -> {1}='{2}'" -f $rid, $TagKey, $AssetTagName)
    } else {
      Write-Warn2 ("[WHATIF] Would set Azure tag: {0} -> {1}='{2}' (Merge)" -f $rid, $TagKey, $AssetTagName)
    }

    return [pscustomobject]@{
      WhatIf     = $true
      Changed    = (-not $already)
      ResourceId = $rid
      TagKey     = $TagKey
      TagValue   = $AssetTagName
    }
  }

  Update-AzTag -ResourceId $rid -Tag @{ $TagKey = $AssetTagName } -Operation Merge -ErrorAction Stop | Out-Null

  [pscustomobject]@{
    Changed    = (-not $already)
    ResourceId = $rid
    TagKey     = $TagKey
    TagValue   = $AssetTagName
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

  #----------------------
  # AUTOMATION FRAMEWORK
  #----------------------

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

  #----------------------
  # Connect Custom Auth
  #----------------------

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

# ================= Scope handling ==================

$Scope = @(
  $Scope |
  ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } |
  Where-Object { $_ } |
  Select-Object -Unique
)

if ($null -eq $Scope -or @($Scope).Count -eq 0) { $Scope = @('PROD') }

Write-Step "execution scope initialized"
Write-Info ("Active Scope(s): {0}" -f ($Scope -join ', '))

# ================= Load YAML ========================

$TaggingYaml = "CriticalAssetTagging.yaml"

Write-Step "loading $TaggingYaml"
$Yaml = Get-Content -Raw "$SettingsPath\$TaggingYaml" | ConvertFrom-Yaml
if (-not $Yaml.AssetTagging) {
  throw "CriticalAssetTagging.yaml missing AssetTagging root"
}

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

      $deviceInventoryIds = @(
        $rows |
        ForEach-Object { [string]$_.DeviceInventoryId } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
      )

      if ($deviceInventoryIds.Count -eq 0) { Write-Warn2 "no DeviceInventoryId values found; skipping"; continue }

      $chunkSize   = 500
      $totalChunks = [math]::Ceiling($deviceInventoryIds.Count / $chunkSize)

      for ($i = 0; $i -lt $deviceInventoryIds.Count; $i += $chunkSize) {

        $currentChunk = [math]::Floor($i / $chunkSize) + 1
        $endIndex     = [math]::Min($i + $chunkSize - 1, $deviceInventoryIds.Count - 1)
        $chunk        = $deviceInventoryIds[$i..$endIndex]

        Write-Info ("tagging {0} machines with '{1}' (chunk {2}/{3})" -f $chunk.Count, $assetTagName, $currentChunk, $totalChunks)

        try {
          AddTagForMultipleMachines -AccessHeaders $AccessHeaders -DeviceInventoryIds $chunk -Tag $assetTagName | Out-Null
          Write-Ok ("bulk tag applied to {0} machines" -f $chunk.Count)
        }
        catch {
          Write-Err2 ("bulk tagging failed (chunk {0}/{1}): {2}" -f $currentChunk, $totalChunks, $_.Exception.Message)
          Write-Host ""
          Write-Info "Fall-back to add tag individually"

          foreach ($id in $chunk) {
            try {
              Add-DefenderTag -AccessHeaders $AccessHeaders -DeviceInventoryId $id -Tag $assetTagName | Out-Null
              Write-Ok ("tag '{0}' added: {1}" -f $assetTagName, $id)
            }
            catch {
              Write-Err2 ("failed tagging {0}: {1}" -f $id, $_.Exception.Message)
            }
          }
        }
      }
    }
    elseif ($queryEngine -eq 'AZURERESOURCEGRAPH') {

      Write-Info "running hunting query against engine: $queryEngine .... Please wait !"
      $arg = Invoke-AzureResourceGraphQuery -Query $query

      # Force array behavior (prevents scalar string/object issues in PS 5.1)
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

      # IMPORTANT: Select-Object -Unique can output a scalar when only 1 item -> force array again
      $resourceIds = @($resourceIds | Select-Object -Unique)

      if (-not $resourceIds -or $resourceIds.Count -eq 0) {
        Write-Warn2 "ARG results did not include a resource id column (expected id/Id/ResourceId); skipping"
        continue
      }

      Write-Info ("tagging {0} Azure resources (individual tagging)" -f $resourceIds.Count)

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

        try {
          $result = Add-AzureResourceTag -ResourceId $rid -AssetTagName $tagValue -TagKey $tagKey
          if ($result.Changed) { Write-Ok ("Azure tag set: {0} -> {1}='{2}'" -f $nameHint, $tagKey, $tagValue) }
          else                 { Write-Info ("Azure tag already present: {0} -> {1}='{2}'" -f $nameHint, $tagKey, $tagValue) }
        }
        catch {
          Write-Err2 ("Azure tagging failed: {0} ({1})" -f $nameHint, $_.Exception.Message)
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
