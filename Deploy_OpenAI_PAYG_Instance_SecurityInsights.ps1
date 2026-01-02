<#
================================================================================
Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1
================================================================================
PURPOSE
  Deploy (or reuse) an Azure OpenAI account (PAYG) and a model deployment using
  ON-DEMAND / PAY-PER-USE where possible (NO PTU).


USAGE
  Run defaults (edit $ScriptDefaults):
    .\Deploy_OpenAI_PAYG_Instance.ps1

  Override params:
    .\Deploy_OpenAI_PAYG_Instance.ps1 -AccountName "security-insight-02" -DeploymentName "chat" -Verbose

  Force a model (still tries SKUs if needed):
    .\Deploy_OpenAI_PAYG_Instance.ps1 -ModelName "gpt-4" -ModelVersion "latest" -Verbose

================================================================================
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$Location,
    [string]$AccountName,
    [string]$DeploymentName,

    # Optional: if not passed, script auto-selects a supported model for the account + region
    [string]$ModelName,
    [string]$ModelVersion,

    # If omitted, PS 5.1 may treat it as 0 => we treat 0 as "not provided"
    [int]$Capacity,

    [ValidateSet("Enabled","Disabled")]
    [string]$PublicNetworkAccess,

    [switch]$WaitForAccountReady,
    [ValidateRange(2,120)]
    [int]$WaitIntervalSeconds = 5,
    [ValidateRange(30,1800)]
    [int]$WaitTimeoutSeconds = 300,

    # Which deployment SKUs to try, in order.
    # Keep Standard first to prefer on-demand / pay-per-use.
    [string[]]$DeploymentSkuOrder,

    # If set, writes model dumps to disk when selection/deploy fails
    [switch]$WriteModelDumps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ================= USER-EDITABLE DEFAULTS =================
$ScriptDefaults = @{
    SubscriptionId      = "xxxxxxxx"
    ResourceGroupName   = "rg-security-insight"
    Location            = "swedencentral"
    AccountName         = "security-insight"
    DeploymentName      = "security-insight"

    # Preferred default (may not be supported; script will try others)
    ModelName           = "gpt-4o-mini"
    ModelVersion        = "latest"

    Capacity            = 100   # capacity = 1 → 1,000 TPM and 10 RPM, capacity = 100 → 100,000 TPM and 1,000 RPM
    PublicNetworkAccess = "Enabled"
    WaitForAccountReady = $true

    DeploymentSkuOrder  = @("GlobalStandard")

    WriteModelDumps     = $true
}

$AlwaysVerbose = $true
#endregion =======================================================

#region ================= LOGGING HELPERS =========================
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("INFO","WARN","ERROR","DEBUG")][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    switch ($Level) {
        "INFO"  { Write-Host "[$ts] [INFO ] $Message" }
        "WARN"  { Write-Host "[$ts] [WARN ] $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[$ts] [ERROR] $Message" -ForegroundColor Red }
        "DEBUG" {
            if ($AlwaysVerbose -or $PSBoundParameters.ContainsKey('Verbose')) {
                Write-Host "[$ts] [DEBUG] $Message" -ForegroundColor DarkGray
            }
        }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host $Title
    Write-Host ("-" * $Title.Length)
}

#endregion =======================================================

#region ================= DEFAULT RESOLUTION ======================
function Use-DefaultIfEmpty {
    param([string]$Name, $Value)
    if ($null -eq $Value) { return $ScriptDefaults[$Name] }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $ScriptDefaults[$Name] }
    return $Value
}
function Use-DefaultIfNullOrZero {
    param([string]$Name, $Value)
    if ($null -eq $Value) { return $ScriptDefaults[$Name] }
    if ($Value -is [ValueType] -and $Value -eq 0) { return $ScriptDefaults[$Name] }
    return $Value
}

Write-Section "1) Parameter Resolution"

$SubscriptionId      = Use-DefaultIfEmpty            "SubscriptionId"      $SubscriptionId
$ResourceGroupName   = Use-DefaultIfEmpty            "ResourceGroupName"   $ResourceGroupName
$Location            = Use-DefaultIfEmpty            "Location"            $Location
$AccountName         = Use-DefaultIfEmpty            "AccountName"         $AccountName
$DeploymentName      = Use-DefaultIfEmpty            "DeploymentName"      $DeploymentName
$ModelName           = Use-DefaultIfEmpty            "ModelName"           $ModelName
$ModelVersion        = Use-DefaultIfEmpty            "ModelVersion"        $ModelVersion
$Capacity            = [int](Use-DefaultIfNullOrZero "Capacity"            $Capacity)
$PublicNetworkAccess = Use-DefaultIfEmpty            "PublicNetworkAccess" $PublicNetworkAccess

if (-not $PSBoundParameters.ContainsKey("WaitForAccountReady")) {
    $WaitForAccountReady = [bool]$ScriptDefaults.WaitForAccountReady
}

if (-not $PSBoundParameters.ContainsKey("DeploymentSkuOrder") -or -not $DeploymentSkuOrder -or $DeploymentSkuOrder.Count -eq 0) {
    $DeploymentSkuOrder = [string[]]$ScriptDefaults.DeploymentSkuOrder
}

if (-not $PSBoundParameters.ContainsKey("WriteModelDumps")) {
    $WriteModelDumps = [bool]$ScriptDefaults.WriteModelDumps
}

Write-Log INFO  "SubscriptionId      : $SubscriptionId"
Write-Log INFO  "ResourceGroupName   : $ResourceGroupName"
Write-Log INFO  "Location            : $Location"
Write-Log INFO  "AccountName         : $AccountName"
Write-Log INFO  "DeploymentName      : $DeploymentName"
Write-Log INFO  "Requested Model     : $ModelName ($ModelVersion)"
Write-Log INFO  "Capacity            : $Capacity"
Write-Log INFO  "PublicNetworkAccess : $PublicNetworkAccess"
Write-Log INFO  "WaitForAccountReady : $WaitForAccountReady"
Write-Log INFO  "SKU order           : $($DeploymentSkuOrder -join ', ')"
Write-Log INFO  "WriteModelDumps     : $WriteModelDumps"
Write-Log DEBUG "ApiVersion          : $ApiVersion"
#endregion =======================================================

#region ================= SANITY CHECKS ===========================
Write-Section "2) Sanity Checks"

if ([string]::IsNullOrWhiteSpace($SubscriptionId))     { throw "SubscriptionId is empty." }
if ([string]::IsNullOrWhiteSpace($ResourceGroupName))  { throw "ResourceGroupName is empty." }
if ([string]::IsNullOrWhiteSpace($Location))           { throw "Location is empty." }
if ([string]::IsNullOrWhiteSpace($AccountName))        { throw "AccountName is empty." }
if ([string]::IsNullOrWhiteSpace($DeploymentName))     { throw "DeploymentName is empty." }
if ($Capacity -lt 1)                                  { throw "Capacity must be >= 1." }
if ($AccountName -notmatch '^[a-z0-9-]{2,63}$') {
    throw "AccountName '$AccountName' is invalid. Use 2-63 chars: lowercase letters, numbers, hyphen."
}
Write-Log INFO "Sanity checks passed."
#endregion =======================================================

#region ================= AZURE HELPERS ===========================
function Ensure-AzModules {
    foreach ($m in @("Az.Accounts","Az.Resources")) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            throw "Missing module '$m'. Install with: Install-Module $m -Scope CurrentUser"
        }
    }
}

function Ensure-AzContext {
    if (-not (Get-AzContext)) {
        Write-Log INFO "No Azure context detected. Running Connect-AzAccount..."
        Connect-AzAccount | Out-Null
    }
    Write-Log INFO "Selecting subscription: $SubscriptionId"
    Select-AzSubscription -SubscriptionId $SubscriptionId | Out-Null
}

function Ensure-ResourceGroup {
    $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $rg) {
        Write-Log INFO "Resource group '$ResourceGroupName' not found. Creating in '$Location'..."
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    } else {
        Write-Log INFO "Resource group '$ResourceGroupName' already exists (location: $($rg.Location))."
    }
}

# Use ${ResourceId} when appending ?api-version to avoid "$ResourceId?api" parsing
function Invoke-Get {
    param([string]$ResourceId, [string]$ApiVersion)
    $path = "${ResourceId}?api-version=${ApiVersion}"
    Write-Log DEBUG "GET  $path"
    $res = Invoke-AzRestMethod -Method GET -Path $path -ErrorAction SilentlyContinue
    if ($res.StatusCode -eq 404) { return $null }
    if ($res.Content) { return ($res.Content | ConvertFrom-Json) }
}

function Invoke-Put {
    param([string]$ResourceId, [string]$ApiVersion, $Body)
    $json = $Body | ConvertTo-Json -Depth 80 -Compress
    $path = "${ResourceId}?api-version=${ApiVersion}"
    Write-Log DEBUG "PUT  $path"
    Write-Log DEBUG "Body $json"
    $res = Invoke-AzRestMethod -Method PUT -Path $path -Payload $json
    Write-Log DEBUG "StatusCode: $($res.StatusCode)"
    if ($res.StatusCode -notin 200,201) {
        throw "PUT failed ($($res.StatusCode)): $($res.Content)"
    }
    if ($res.Content) { return ($res.Content | ConvertFrom-Json) }
}

function Invoke-Post {
    param([string]$Path, [string]$Payload)
    Write-Log DEBUG "POST $Path"
    $res = Invoke-AzRestMethod -Method POST -Path $Path -Payload $Payload
    Write-Log DEBUG "StatusCode: $($res.StatusCode)"
    return $res
}

function Wait-ForProvisioningState {
    param(
        [string]$ResourceId,
        [string]$ApiVersion,
        [string]$DesiredState,
        [int]$IntervalSeconds,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $obj = Invoke-Get -ResourceId $ResourceId -ApiVersion $ApiVersion
        $state = $null
        if ($obj -and $obj.properties -and $obj.properties.provisioningState) {
            $state = [string]$obj.properties.provisioningState
        }
        Write-Log INFO "ProvisioningState: $state (waiting for '$DesiredState')"
        if ($state -eq $DesiredState) { return $obj }
        if ((Get-Date) -ge $deadline) {
            throw "Timeout waiting for provisioningState='$DesiredState' (last state: '$state')."
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Get-AccountKeys {
    param([string]$AccountId, [string]$ApiVersion)
    $path = "${AccountId}/listKeys?api-version=${ApiVersion}"
    $res = Invoke-Post -Path $path -Payload "{}"
    if ($res.StatusCode -notin 200,201) {
        throw "listKeys failed ($($res.StatusCode)): $($res.Content)"
    }
    return ($res.Content | ConvertFrom-Json)
}

function Try-ParseAzureErrorMessage {
    param([string]$ExceptionMessage)

    # The thrown message usually contains the JSON body. Try to extract "message":"..."
    if ($ExceptionMessage -match '"message"\s*:\s*"([^"]+)"') { return $matches[1] }
    return $ExceptionMessage
}
#endregion =======================================================

#region ================= ACCOUNT MODEL DISCOVERY =================
function Get-AccountModels {
    param([string]$AccountId, [string]$ApiVersion)

    $rid = "${AccountId}/models"
    Write-Log INFO "Querying supported models for this Azure OpenAI account..."
    $result = Invoke-Get -ResourceId $rid -ApiVersion $ApiVersion

    $models = @()
    if ($result -and $result.value) { $models = @($result.value) }

    Write-Log INFO ("Account models returned: " + $models.Count)

    if (($AlwaysVerbose -or $PSBoundParameters.ContainsKey('Verbose')) -and $models.Count -gt 0) {
        Write-Log DEBUG ("Sample account model item: " + (($models | Select-Object -First 1) | ConvertTo-Json -Depth 18))
    }

    return $models
}

function Normalize-AccountModelsToCandidates {
    param([object[]]$AccountModels)

    function Get-PropValue { param($Obj,[string]$PropName)
        $p = $Obj.PSObject.Properties[$PropName]
        if ($null -eq $p) { return $null }
        return $p.Value
    }

    $norm = @()
    foreach ($m in $AccountModels) {
        $name = Get-PropValue $m "name"
        $ver  = Get-PropValue $m "version"
        $fmt  = Get-PropValue $m "format"

        if ($name) {
            $norm += [pscustomobject]@{
                Name    = [string]$name
                Version = if ($ver) { [string]$ver } else { $null }
                Format  = if ($fmt) { [string]$fmt } else { $null }
                Raw     = $m
            }
        }
    }

    return $norm
}

function Build-OrderedCandidates {
    param(
        [Parameter(Mandatory=$true)][object[]]$Candidates,
        [Parameter(Mandatory=$true)][string[]]$PreferenceNames
    )

    # Prefer OpenAI format if present
    $c = $Candidates
    $openAiFmt = $Candidates | Where-Object { $_.Format -and $_.Format -ieq "OpenAI" }
    if ($openAiFmt -and $openAiFmt.Count -gt 0) { $c = $openAiFmt }

    $ordered = @()

    foreach ($p in $PreferenceNames) {
        $hit = $c | Where-Object { $_.Name -ieq $p } | Select-Object -First 1
        if ($hit) { $ordered += $hit }
    }

    $restGpt = $c | Where-Object { $_.Name -match '^gpt' } | Where-Object { $ordered.Name -notcontains $_.Name }
    $ordered += $restGpt

    $restOther = $c | Where-Object { $ordered.Name -notcontains $_.Name }
    $ordered += $restOther

    return $ordered
}
#endregion =======================================================

#region ================= DEPLOYMENT WITH FALLBACK =================
function New-DeploymentWithSkuAndModelFallback {
    param(
        [Parameter(Mandatory=$true)][string]$DeploymentId,
        [Parameter(Mandatory=$true)][string]$ApiVersion,
        [Parameter(Mandatory=$true)][int]$Capacity,
        [Parameter(Mandatory=$true)][object[]]$CandidateModels,
        [Parameter(Mandatory=$true)][string[]]$SkuOrder
    )

    foreach ($skuName in $SkuOrder) {
        foreach ($c in $CandidateModels) {

            $mn = $c.Name
            $mv = $c.Version
            if ([string]::IsNullOrWhiteSpace($mv)) { $mv = "latest" }

            Write-Log INFO "Attempting deployment: sku=$skuName, model=$mn ($mv), capacity=$Capacity"

            try {
                Invoke-Put -ResourceId $DeploymentId -ApiVersion $ApiVersion -Body @{
                    properties = @{
                        model = @{
                            format  = "OpenAI"
                            name    = $mn
                            version = $mv
                        }
                    }
                    sku = @{
                        name     = $skuName
                        capacity = $Capacity
                    }
                } | Out-Null

                return [pscustomobject]@{
                    Sku     = $skuName
                    Name    = $mn
                    Version = $mv
                    Status  = "Succeeded"
                }
            }
            catch {
                $azMsg = Try-ParseAzureErrorMessage -ExceptionMessage $_.Exception.Message

                # Continue for known "try next" errors
                if ($azMsg -match "SKU '.*'.*not supported" -or
                    $azMsg -match "not supported in this region" -or
                    $azMsg -match "DeploymentModelNotSupported" -or
                    $azMsg -match "InvalidResourceProperties") {

                    Write-Log WARN "Rejected (will try next): sku=$skuName, model=$mn ($mv)"
                    Write-Log WARN "Azure says: $azMsg"
                    continue
                }

                # Unknown/critical error: stop immediately
                Write-Log ERROR "Deployment failed with non-retryable error."
                Write-Log ERROR "sku=$skuName, model=$mn ($mv)"
                Write-Log ERROR "Azure says: $azMsg"
                throw
            }
        }
    }

    throw "No candidate model could be deployed with the configured SKU order ($($SkuOrder -join ', ')) in region '$Location'."
}
#endregion =======================================================

#region ================= MAIN ===============================
Write-Section "3) Azure Auth + Subscription"
Ensure-AzModules
Ensure-AzContext

Write-Section "4) Resource Group"
Ensure-ResourceGroup

$AccountId    = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.CognitiveServices/accounts/$AccountName"
$DeploymentId = "${AccountId}/deployments/${DeploymentName}"

Write-Section "5) Azure OpenAI Account (PAYG)"
Write-Log INFO "Account ResourceId: $AccountId"
Write-Log INFO "Creating/reusing account: kind=OpenAI, sku=S0 (PAYG)"

$account = Invoke-Get -ResourceId $AccountId -ApiVersion $ApiVersion
if (-not $account) {
    Write-Log INFO "Account does not exist -> creating..."
    Invoke-Put -ResourceId $AccountId -ApiVersion $ApiVersion -Body @{
        location = $Location
        kind     = "OpenAI"
        sku      = @{ name = "S0" }
        properties = @{
            customSubDomainName = $AccountName
            publicNetworkAccess = $PublicNetworkAccess
            networkAcls = @{
                defaultAction       = "Allow"
                ipRules             = @()
                virtualNetworkRules = @()
            }
        }
        tags = @{}
    } | Out-Null
    Write-Log INFO "Account create request sent."
} else {
    Write-Log INFO "Account already exists -> skipping create."
}

if ($WaitForAccountReady) {
    Write-Section "5b) Wait for Account Ready"
    $account = Wait-ForProvisioningState -ResourceId $AccountId -ApiVersion $ApiVersion -DesiredState "Succeeded" `
        -IntervalSeconds $WaitIntervalSeconds -TimeoutSeconds $WaitTimeoutSeconds
} else {
    $account = Invoke-Get -ResourceId $AccountId -ApiVersion $ApiVersion
}

Write-Section "6) Model Discovery (Account Scoped)"
$acctModels = Get-AccountModels -AccountId $AccountId -ApiVersion $ApiVersion

if ($WriteModelDumps) {
    $dumpRaw = Join-Path -Path $PSScriptRoot -ChildPath ("account-models-raw-" + $AccountName + ".json")
    $acctModels | ConvertTo-Json -Depth 30 | Out-File -FilePath $dumpRaw -Encoding utf8
    Write-Log INFO "Wrote raw account models to: $dumpRaw"
}

$candidatesAll = Normalize-AccountModelsToCandidates -AccountModels $acctModels
Write-Log INFO ("Normalized candidates: " + $candidatesAll.Count)

Write-Section "7) Model Selection + Deployment (Fallback by SKU & Model)"

$UserForcedModel = $false
if ($PSBoundParameters.ContainsKey("ModelName") -or $PSBoundParameters.ContainsKey("ModelVersion")) {
    $UserForcedModel = $true
    Write-Log INFO "Model was provided via runtime parameters -> will deploy using that model (but still try SKU fallbacks)."
}

if ($UserForcedModel) {
    $ordered = @([pscustomobject]@{ Name=$ModelName; Version=$ModelVersion; Format="OpenAI"; Raw=$null })
} else {
    # Preference list (edit freely)
    $preference = @(
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-4.1-mini",
        "gpt-4.1",
        "gpt-4",
        "gpt-35-turbo"
    )

    $ordered = Build-OrderedCandidates -Candidates $candidatesAll -PreferenceNames $preference
    $preview = $ordered | Select-Object -First 12
    $previewText = ($preview | ForEach-Object {
        if ($_.Version) { "$($_.Name) ($($_.Version))" } else { "$($_.Name) (latest)" }
    }) -join ", "
    Write-Log INFO ("Top candidates to try: " + $previewText)

    if ($WriteModelDumps) {
        $dumpNorm = Join-Path -Path $PSScriptRoot -ChildPath ("account-models-normalized-" + $AccountName + ".json")
        $ordered | Select-Object Name,Version,Format | ConvertTo-Json -Depth 5 | Out-File -FilePath $dumpNorm -Encoding utf8
        Write-Log INFO "Wrote normalized candidate list to: $dumpNorm"
    }
}

$DeploymentExists = Invoke-Get -ResourceId $DeploymentId -ApiVersion $ApiVersion
if ($DeploymentExists) {
    Write-Log INFO "Deployment already exists -> skipping create."
} else {
    Write-Log INFO "Deployment does not exist -> creating..."
    $result = New-DeploymentWithSkuAndModelFallback -DeploymentId $DeploymentId -ApiVersion $ApiVersion -Capacity $Capacity `
        -CandidateModels $ordered -SkuOrder $DeploymentSkuOrder

    Write-Log INFO "Deployment succeeded!"
    Write-Log INFO "Chosen SKU   : $($result.Sku)"
    Write-Log INFO "Chosen Model : $($result.Name) ($($result.Version))"

    # Update output variables to reflect what actually worked
    $ModelName    = $result.Name
    $ModelVersion = $result.Version
}

Write-Section "8) Output (Endpoint + Keys)"
$account = Invoke-Get -ResourceId $AccountId -ApiVersion $ApiVersion
$keys    = Get-AccountKeys -AccountId $AccountId -ApiVersion $ApiVersion

Write-Host ""
Write-Host "==================== RESULT ===================="
Write-Host "AccountName : $AccountName"
Write-Host "ResourceId  : $AccountId"
Write-Host "Endpoint    : $($account.properties.endpoint)"
Write-Host "Deployment  : $DeploymentName"
Write-Host "Model       : $ModelName ($ModelVersion)"
Write-Host "Account SKU : S0 (PAYG)"
Write-Host "Deploy SKUs : Tried => $($DeploymentSkuOrder -join ', ')"
Write-Host "Key1        : $($keys.key1)"
Write-Host "Key2        : $($keys.key2)"
Write-Host "================================================"
Write-Host ""

Write-Host "Example API call:"
Write-Host "POST $($account.properties.endpoint)openai/responses?api-version=$ApiVersion"
Write-Host "Header: api-key: <key>"
Write-Host "Body: { `"model`": `"$DeploymentName`", `"input`": `"hello`" }"
Write-Host ""
#endregion =======================================================

Write-Section "9) PowerShell Variable Output (SecurityInsight - Copy/Paste Ready)"

$AI_apiKey     = $keys.key1
$AI_endpoint   = $account.properties.endpoint.TrimEnd('/')
$AI_deployment = $DeploymentName
$AI_apiVersion = "2025-01-01-preview"   # specific API for Chat Completions, used by REST api

Write-Host "`$AI_apiKey     = `"$AI_apiKey`""
Write-Host "`$AI_endpoint   = `"$AI_endpoint`""
Write-Host "`$AI_deployment = `"$AI_deployment`""
Write-Host "`$AI_apiVersion = `"$AI_apiVersion`""
