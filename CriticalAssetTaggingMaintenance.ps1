param(
    # Which YAML rule Modes to run (PROD, TEST, or both)
  [Parameter(Mandatory=$false)]
    [ValidateSet('PROD','TEST')]
    [string[]] $Scope,
  [Parameter(Mandatory=$false)]
    [switch] $AutomationFramework
)

Write-host "***********************************************************************************************"
Write-host "Critical Asset Tagging using YAML-file"
Write-host ""
Write-host "Support: mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight"
Write-host "***********************************************************************************************"


If (!($AutomationFramework)) {

    <# PRE-REQ: ONBOARDING OF SERVICE PRINCIPAL IN ENTRA
        # SPN Privilege (API permissions) - found under 'APIs my organization uses'. Remember: Grant Admin Control
            Microsoft Threat Protection
                AdvancedHunting.Read.All   (to run queries against Exposure Graph)

            Microsoft Graph
                ThreatHunting.Read.All     (to run queries against Exposure Graph)

            WindowsDefenderATP
                Machine.ReadWrite.All      (to set tag info on device)
    #>

    $SettingsPath               = "c:\scripts\securityinsights"

    $global:SpnTenantId         = "<Your TenantId>"     # override per your SPN tenant if different
    $global:SpnClientId         = "<APP/CLIENT ID GUID>"
    $global:SpnClientSecret     = "<CLIENT SECRET VALUE>"
}

# Script-default scope (used ONLY when -Scope is not provided)
# Keep ONE definition only (you had two). Set what you want as default:
$ScriptDefaultScope = @('PROD','TEST')  # change to @('PROD','TEST') to run both by default


#######################################################################################################
# FUNCTIONS (begin)
#######################################################################################################

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Step ("Installing module $($Name)...")
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    Write-Done ("Installed module $($Name).")
  }
  Import-Module $Name -ErrorAction Stop
  Write-Info ("Imported module $($Name).")
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

# ================= Logging helpers =================
function Write-Step  ($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Info  ($m){ Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-Ok    ($m){ Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn2 ($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err2  ($m){ Write-Host "[ERR]  $m" -ForegroundColor Red }
function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Get-RuleMode {
    param([AllowNull()][object]$Mode)

    if ($null -eq $Mode) { return 'PROD' } # default
    $m = ([string]$Mode).Trim()
    if ([string]::IsNullOrWhiteSpace($m)) { return 'PROD' }
    $m.ToUpperInvariant()
}

function Get-QueryEngine {
    param([AllowNull()][object]$QueryEngine)

    if ($null -eq $QueryEngine) { return 'DEFENDERGRAPH' } # default
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
    param(
        [Parameter(Mandatory)][string]$Query
    )

    $pageSize = 1000
    $skip     = 0
    $allRows  = @()

    while ($true) {

        if ($skip -eq 0) {
            # First page – DO NOT pass -Skip
            $res = Search-AzGraph -Query $Query -First $pageSize
        }
        else {
            # Subsequent pages – Skip must be >= 1
            $res = Search-AzGraph -Query $Query -First $pageSize -Skip $skip
        }

        # Normalize output
        $rows = @()
        if ($res) {
            if ($res.PSObject.Properties.Name -contains 'Data') {
                $rows = @($res.Data)
            } else {
                $rows = @($res)
            }
        }

        if (-not $rows -or $rows.Count -eq 0) { break }

        $allRows += $rows

        # Stop if we received less than a full page
        if ($rows.Count -lt $pageSize) { break }

        # Next page (Skip must now be >= 1)
        $skip += $pageSize
    }

    return [pscustomobject]@{
        Data  = $allRows
        Count = $allRows.Count
    }
}

# ================= Defender API =====================
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
        [Parameter(Mandatory)][string]$Tag
    )

    $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
    $body = @{
        Value      = $Tag
        Action     = "Add"
        MachineIds = @($DeviceInventoryIds)
    } | ConvertTo-Json -Depth 4

    Invoke-RestMethod -Method POST -Uri $uri -Headers $AccessHeaders -ContentType "application/json" -Body $body
}

function RemoveTagForMultipleMachines {
    param(
        [Parameter(Mandatory)][hashtable]$AccessHeaders,
        [Parameter(Mandatory)][string[]]$DeviceInventoryIds,
        [Parameter(Mandatory)][string]$Tag
    )

    $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
    $body = @{
        Value      = $Tag
        Action     = "Remove"
        MachineIds = @($DeviceInventoryIds)
    } | ConvertTo-Json -Depth 4

    Invoke-RestMethod -Method POST -Uri $uri -Headers $AccessHeaders -ContentType "application/json" -Body $body
}

function Add-DefenderTag {
    param(
        [Parameter(Mandatory)][hashtable]$AccessHeaders,
        [Parameter(Mandatory)][string]$DeviceInventoryId,
        [Parameter(Mandatory)][string]$Tag
    )

    $uri  = "https://api.securitycenter.microsoft.com/api/machines/$DeviceInventoryId/tags"
    $body = @{
        Value  = $Tag
        Action = "Add"
    } | ConvertTo-Json -Depth 4

    Invoke-RestMethod -Method POST -Uri $uri -Headers $AccessHeaders -ContentType "application/json" -Body $body
}

function Remove-DefenderTag {
    param(
        [Parameter(Mandatory)][hashtable]$AccessHeaders,
        [Parameter(Mandatory)][string]$DeviceInventoryId,
        [Parameter(Mandatory)][string]$Tag
    )

    $uri  = "https://api.securitycenter.microsoft.com/api/machines/$DeviceInventoryId/tags"
    $body = @{
        Value  = $Tag
        Action = "Remove"
    } | ConvertTo-Json -Depth 4

    Invoke-RestMethod -Method POST -Uri $uri -Headers $AccessHeaders -ContentType "application/json" -Body $body
}

# ================= Azure resource tagging (ARG engine) =====================
function Get-ArgResourceIdFromRow {
    param([Parameter(Mandatory)][psobject]$Row)

    foreach ($name in @('ResourceId','resourceId','id','Id')) {
        $p = $Row.PSObject.Properties[$name]
        if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
            return [string]$p.Value
        }
    }
    return $null
}

function Get-ArgResourceNameFromRow {
    param([Parameter(Mandatory)][psobject]$Row)

    foreach ($name in @('name','Name','resourceName','ResourceName')) {
        $p = $Row.PSObject.Properties[$name]
        if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
            return [string]$p.Value
        }
    }
    return $null
}

function Get-ArgAssetTagTypeFromRow {
    param([Parameter(Mandatory)][psobject]$Row)

    foreach ($name in @('AssetTagType','assettagtype','TagKey','tagKey')) {
        $p = $Row.PSObject.Properties[$name]
        if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
            return ([string]$p.Value).Trim()
        }
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
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
        return ([string]$p.Value).Trim()
    }
    return $null
}

function Add-AzureResourceTag {
    param(
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$AssetTagName,
        [Parameter(Mandatory)][string]$TagKey
    )

    if ([string]::IsNullOrWhiteSpace($ResourceId))   { throw "ResourceId is empty" }
    if ([string]::IsNullOrWhiteSpace($TagKey))       { throw "TagKey is empty" }
    if ([string]::IsNullOrWhiteSpace($AssetTagName)) { throw "AssetTagName is empty" }

    $rid = $ResourceId.Trim()

    # Detect "already present"
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

    # Merge tag (works for subscription and resource IDs)
    Update-AzTag -ResourceId $rid -Tag @{ $TagKey = $AssetTagName } -Operation Merge -ErrorAction Stop | Out-Null

    return [pscustomobject]@{
        Changed   = (-not $already)
        ResourceId = $rid
        TagKey    = $TagKey
        TagValue  = $AssetTagName
    }
}


#####################################################################################################
# POWERSHEL MODULE VALIDATION
#####################################################################################################

Write-Step "initializing"

Ensure-Module Az.Accounts
Ensure-Module Az.ResourceGraph
Ensure-Module Az.Resources
Ensure-Module Microsoft.Graph.Authentication
Ensure-Module Microsoft.Graph.Security
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

    $global:SpnTenantId         = $global:AzureTenantId
    $global:SpnClientId         = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret     = $global:HighPriv_Modern_Secret_Azure

    # ==============================
    # Graph auth helpers (app+cert)
    # ==============================
    $script:GraphLastConnectUtc = [datetime]::MinValue

    # Graph re-auth settings
    $GraphReconnectMaxAgeMinutes = 45               # proactive reconnect interval during long bucket loops
    $GraphQueryMaxRetries        = 4                # retries per bucket/single query

    #------------------------------------------------------------------------------------------------------------
    # Graph connect (initial)
    #------------------------------------------------------------------------------------------------------------
    Write-Step "connecting to Microsoft Graph (initial)"
    Tock
    try {
      Connect-GraphHighPriv
    } catch {
      Write-Err2 "initial graph connect failed: $($_.Exception.Message)"
      throw
    }
    Tick "graph connect"

    # ================= Defender Headers =================
    Write-Step "acquiring Defender API auth headers"
    $AccessHeaders = Get-DefenderAccessHeaders

    $SettingsPath           = "$($global:PathScripts)\SecurityInsights"

} Else {

    #----------------------
    # Connect Custom Auth
    #----------------------

    write-host "Connect using ServicePrincipal with AppId & Secret"

    Write-Step "connecting to Azure"
    Tock
    try {

        $SecureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force

        $Credential = New-Object System.Management.Automation.PSCredential (
            $global:SpnClientId,
            $SecureSecret
        )

        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $Credential -WarningAction SilentlyContinue

        Write-Ok "azure connection step done"
    } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
    Tick "azure connect"

    #------------------------------------------------------------------------------------------------------------
    # Graph auth helpers (app+cert)
    #------------------------------------------------------------------------------------------------------------
    $script:GraphLastConnectUtc = [datetime]::MinValue

    # Graph re-auth settings
    $GraphReconnectMaxAgeMinutes = 45               # proactive reconnect interval during long bucket loops
    $GraphQueryMaxRetries        = 4                # retries per bucket/single query

    #------------------------------------------------------------------------------------------------------------
    # Graph connect (initial)
    #------------------------------------------------------------------------------------------------------------
    Write-Step "connecting to Microsoft Graph (initial)"
    Tock
    try {
      Connect-GraphHighPriv
    } catch {
      Write-Err2 "initial graph connect failed: $($_.Exception.Message)"
      throw
    }
    Tick "graph connect"

    # ================= Defender Headers =================
    Write-Step "acquiring Defender API auth headers"
    $AccessHeaders = Get-DefenderAccessHeaders
}

#####################################################################################################
# MAIN PROGRAM
#####################################################################################################

Write-host "SHOW ALL TAGS IN DEFENDER"

$query = @'
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

Write-Info "running hunting query against Defender Exposure Graph .... Please wait !"
$resp = Invoke-DefenderGraphQuery -Query $query
if (-not $resp.Results) {
    Write-Info "no results"
    continue
}

$rows = @(ConvertTo-PSObjectDeep $resp.Results.AdditionalProperties -StripOData)
if (-not $rows -or $rows.Count -eq 0) {
    Write-Info "no results"
    continue
}

$rows

#>

<# DELETE SPECIFIC TAG from all devices (Defender)

$TagToDelete = 'SecurityManagementServer--tier0--SI'

$Query = @'
ExposureGraphNodes
| where NodeLabel has "device"
    or NodeLabel has "microsoft.compute/virtualmachines"
    or NodeLabel has "microsoft.hybridcompute/machines"
| extend rawData = todynamic(NodeProperties).rawData
| where tobool(rawData.isExcluded) == false
| project NodeId, NodeName, NodeLabel, rawData, EntityIds

// Output Required Columns
| extend
    deviceManualTags = iff(isnull(rawData.deviceManualTags), dynamic([]), todynamic(rawData.deviceManualTags)),
    deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
    tags = iff(isnull(rawData.tags.tags), dynamic([]), todynamic(rawData.tags.tags))
| extend
    AssetTags  = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
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

Write-Info "running hunting query against Defender Exposure Graph .... Please wait !"
$resp = Invoke-DefenderGraphQuery -Query $query

if (-not $resp.Results) {
    Write-Info "no results"
    continue
}

$rows = @(ConvertTo-PSObjectDeep $resp.Results.AdditionalProperties -StripOData)
if (-not $rows -or $rows.Count -eq 0) {
    Write-Info "no results"
    continue
}

$deviceInventoryIds = @(
    $rows |
    ForEach-Object { [string]$_.DeviceInventoryId } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -Unique
)

if ($deviceInventoryIds.Count -eq 0) {
    Write-Warn2 "no DeviceInventoryId values found; skipping"
    continue
}

$chunkSize   = 500
$totalChunks = [math]::Ceiling($deviceInventoryIds.Count / $chunkSize)

# Lookup for NodeName logging
$rowsById = @{}
foreach ($r in $rows) {
    $id = [string]$r.DeviceInventoryId
    if ([string]::IsNullOrWhiteSpace($id)) { continue }
    if (-not $rowsById.ContainsKey($id)) { $rowsById[$id] = $r }
}

for ($i = 0; $i -lt $deviceInventoryIds.Count; $i += $chunkSize) {

    $currentChunk = [math]::Floor($i / $chunkSize) + 1
    $endIndex     = [math]::Min($i + $chunkSize - 1, $deviceInventoryIds.Count - 1)
    $chunk        = $deviceInventoryIds[$i..$endIndex]

    try {
        RemoveTagForMultipleMachines -AccessHeaders $AccessHeaders -DeviceInventoryIds $chunk -Tag $TagToDelete | Out-Null
        Write-Ok ("tag '$($TagToDelete)' removed from {0} machines" -f $chunk.Count)
    }
    catch {
        Write-Err2 ("bulk tagging failed (chunk {0}/{1}): {2}" -f $currentChunk, $totalChunks, $_.Exception.Message)
        Write-Host ""
        Write-Info "Fall-back to add tag individually"

        foreach ($id in $chunk) {
            try {
                Remove-DefenderTag -AccessHeaders $AccessHeaders -DeviceInventoryId $id -Tag $TagToDelete | Out-Null
                Write-Ok ("tag '{0}' added: {1}" -f $assetTagName, $id)
            }
            catch {
                Write-Err2 ("failed tagging {0}: {1}" -f $id, $_.Exception.Message)
            }
        }
    }
}


#>