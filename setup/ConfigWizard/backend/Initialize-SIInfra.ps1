<#
.SYNOPSIS
    Provisions Log Analytics workspace + DCE + per-engine DCRs + Storage Account
    for SecurityInsight, and grants the SPN the RBAC it needs to operate.

.DESCRIPTION
    Idempotent. Run after New-SISpn (the SPN must exist). Creates / re-uses:
      * Resource Group  (SI workspace + DCE/DCR + storage live here)
      * Log Analytics workspace
      * Data Collection Endpoint (DCE)
      * Data Collection Rules (per-engine)   -- created by AzLogDcrIngestPS at first ingest
                                              by default; this script DOES NOT pre-create
                                              them, but ensures the RG + DCE exist so
                                              first ingest succeeds.
      * Storage account
        - Tables / queues / blobs are created by the engine on first run.
        - This script grants Storage Blob/Table/Queue Data Contributor on the SPN
          at storage-account scope, so the engine reaches storage via OAuth -- NO
          shared key written to config\SecurityInsight.custom.ps1.
      * (Optional) Key Vault    if -CreateKeyVault
      * RBAC for SPN at: workspace, DCR RG (Monitoring Metrics Publisher),
        storage account (Blob/Table/Queue Data Contributor)

    Required modules: Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Monitor, Az.Storage, Az.KeyVault

.PARAMETER SpnObjectId
    Service principal Object ID (NOT App ID). Returned by New-SISpn as 'ObjectId'.

.PARAMETER TenantId
.PARAMETER SubscriptionId
.PARAMETER ResourceGroupName
.PARAMETER Location

.PARAMETER WorkspaceName
.PARAMETER DceName
.PARAMETER DcrResourceGroupName
    Defaults to ResourceGroupName.

.PARAMETER StorageAccountName
    Must be globally unique, 3-24 lowercase alphanumeric.

.PARAMETER CreateKeyVault
    Optional KV. Useful when New-SISpn was run with -CredStorage KeyVault and the
    KV doesn't exist yet.

.PARAMETER KeyVaultName
.PARAMETER KvAccessSpnObjectIds
    Additional object IDs (besides the SPN) that need Get/Set permission on KV
    secrets / certificates. Default: only the caller's user.

.OUTPUTS
    pscustomobject with all provisioned resource IDs / names / DCE ingestion URI
    so the Write-SICustomConfig step can drop them into the customer's
    SecurityInsight.custom.ps1.

.NOTES
    Status: v2.2.105 -- ships with New-SISpn + Write-SICustomConfig + /api/apply.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$SpnObjectId,
    [Parameter(Mandatory)] [string]$TenantId,
    [Parameter(Mandatory)] [string]$SubscriptionId,
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)] [string]$Location,
    [Parameter(Mandatory)] [string]$WorkspaceName,
    [Parameter(Mandatory)] [string]$DceName,
    [Parameter()]          [string]$DcrResourceGroupName,
    [Parameter(Mandatory)] [string]$StorageAccountName,
    [Parameter()]          [string]$StorageResourceGroupName,
    [Parameter()]          [switch]$CreateKeyVault,
    [Parameter()]          [string]$KeyVaultName,
    [Parameter()]          [string[]]$KvAccessSpnObjectIds
)

$ErrorActionPreference = 'Stop'

if (-not $DcrResourceGroupName)     { $DcrResourceGroupName     = $ResourceGroupName }
if (-not $StorageResourceGroupName) { $StorageResourceGroupName = $ResourceGroupName }
if ($CreateKeyVault -and -not $KeyVaultName) { throw 'CreateKeyVault is set but -KeyVaultName is missing.' }

function _Step([string]$msg) { Write-Host "  [STEP] $msg" -ForegroundColor Cyan }
function _Ok  ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Info([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function _Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "=== Initialize-SIInfra ===" -ForegroundColor Cyan
_Info "subscription : $SubscriptionId"
_Info "RG (LA/DCE)  : $ResourceGroupName"
_Info "DCR RG       : $DcrResourceGroupName"
_Info "Storage RG   : $StorageResourceGroupName"
_Info "Location     : $Location"
_Info "Workspace    : $WorkspaceName"
_Info "DCE          : $DceName"
_Info "Storage      : $StorageAccountName"
if ($CreateKeyVault) { _Info "Key Vault    : $KeyVaultName" }
Write-Host ""

# ----- 1. Connect Az -----
_Step "connect Az PowerShell"
Import-Module Az.Accounts -ErrorAction Stop
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx -or $ctx.Tenant.Id -ne $TenantId -or $ctx.Subscription.Id -ne $SubscriptionId) {
    Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
}
_Ok ("Az context: {0} / {1}" -f (Get-AzContext).Account, (Get-AzContext).Subscription.Name)

# ----- 1b. Auto-register required Azure resource providers --------------
# Brand-new subs often have only a handful of RPs registered. Without these,
# resource creation calls fail with "[InvalidResource] : Invalid resource
# payload: 'properties' are missing" -- a misleading wrapper for "the RP
# this resource lives under isn't registered". Auto-registering up-front
# turns a confusing mid-Phase-2 failure into a clean prereq + wait.
$requiredRps = @(
    'Microsoft.Resources',
    'Microsoft.OperationalInsights',   # Log Analytics workspace
    'Microsoft.Insights',              # Diagnostic Settings + classic metrics
    'Microsoft.Monitor',               # Data Collection Endpoints + Rules (newer namespace)
    'Microsoft.Storage',               # Storage account
    'Microsoft.Authorization',         # Role assignments
    'Microsoft.AlertsManagement'       # Alerts + Smart Detection (used by RA reports)
)
if ($CreateKeyVault -or $KeyVaultName) { $requiredRps += 'Microsoft.KeyVault' }
_Step "verify Azure resource providers"
$rpStates = Get-AzResourceProvider -ListAvailable -ErrorAction SilentlyContinue |
    Where-Object { $requiredRps -contains $_.ProviderNamespace } |
    Select-Object ProviderNamespace, RegistrationState
$missing = @($requiredRps | Where-Object {
    $rp = $rpStates | Where-Object ProviderNamespace -ieq $_
    -not $rp -or $rp.RegistrationState -ne 'Registered'
})
if ($missing.Count -eq 0) {
    _Ok "all required resource providers are Registered"
} else {
    _Warn ("registering {0} missing resource provider(s): {1}" -f $missing.Count, ($missing -join ', '))
    foreach ($rp in $missing) {
        try {
            $null = Register-AzResourceProvider -ProviderNamespace $rp -ErrorAction Stop
            _Info ("  Register-AzResourceProvider {0} kicked off" -f $rp)
        } catch {
            _Warn ("  Register-AzResourceProvider {0} failed: {1}" -f $rp, $_.Exception.Message)
        }
    }
    _Step "waiting for resource providers to finish registering (up to 4 min)"
    $deadline = (Get-Date).AddSeconds(240)
    while ((Get-Date) -lt $deadline) {
        $rpStates = Get-AzResourceProvider -ProviderNamespace $missing -ErrorAction SilentlyContinue |
            Group-Object -Property ProviderNamespace
        $stillPending = @()
        foreach ($g in $rpStates) {
            $registered = ($g.Group | Where-Object RegistrationState -eq 'Registered').Count
            if ($registered -ne $g.Count) { $stillPending += $g.Name }
        }
        if ($stillPending.Count -eq 0) { _Ok "all providers Registered"; break }
        _Info ("  still registering: {0}" -f ($stillPending -join ', '))
        Start-Sleep -Seconds 12
    }
    # Final check -- any provider still pending is logged but not a hard fail
    # (resource creation will surface the real error if it actually matters).
    $rpStatesFinal = Get-AzResourceProvider -ProviderNamespace $missing -ErrorAction SilentlyContinue |
        Group-Object -Property ProviderNamespace
    $stillBad = @()
    foreach ($g in $rpStatesFinal) {
        $registered = ($g.Group | Where-Object RegistrationState -eq 'Registered').Count
        if ($registered -ne $g.Count) { $stillBad += $g.Name }
    }
    if ($stillBad.Count -gt 0) {
        _Warn ("provider(s) still not fully Registered after wait: {0}. Continuing -- resource creation may still work for already-Registered child types." -f ($stillBad -join ', '))
    }
}

# ----- 2. Resource group(s) -----
foreach ($rg in @($ResourceGroupName, $DcrResourceGroupName, $StorageResourceGroupName) | Sort-Object -Unique) {
    if (-not (Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue)) {
        _Step "create resource group $rg"
        $null = New-AzResourceGroup -Name $rg -Location $Location -ErrorAction Stop
        _Ok "created"
    } else {
        _Info "RG '$rg' already exists"
    }
}

# ----- 3. Log Analytics workspace -----
Import-Module Az.OperationalInsights -ErrorAction Stop
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $ws) {
    _Step "create Log Analytics workspace"
    $ws = New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName `
        -Name $WorkspaceName -Location $Location -Sku 'PerGB2018' -RetentionInDays 90 -ErrorAction Stop
    _Ok ("workspace created: {0}" -f $ws.ResourceId)
} else {
    _Info ("workspace already exists: {0}" -f $ws.ResourceId)
}
$workspaceResourceId = $ws.ResourceId

# ----- 4. Data Collection Endpoint -----
Import-Module Az.Monitor -ErrorAction Stop
$dceCmd = Get-Command New-AzDataCollectionEndpoint -ErrorAction SilentlyContinue
$dce = $null
if ($dceCmd) {
    $dce = Get-AzDataCollectionEndpoint -ResourceGroupName $ResourceGroupName -Name $DceName -ErrorAction SilentlyContinue
    if (-not $dce) {
        _Step "create Data Collection Endpoint"
        $dce = New-AzDataCollectionEndpoint -ResourceGroupName $ResourceGroupName -Name $DceName -Location $Location -ErrorAction Stop
        _Ok ("DCE created: {0}" -f $dce.LogIngestion.Endpoint)
    } else {
        _Info ("DCE already exists: {0}" -f $dce.LogIngestion.Endpoint)
    }
} else {
    _Warn 'Az.Monitor lacks New-AzDataCollectionEndpoint -- falling back to REST.'
    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/').Token
    $dceUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$($DceName)?api-version=2023-03-11"
    $body = @{ location = $Location; properties = @{ networkAcls = @{ publicNetworkAccess = 'Enabled' } } } | ConvertTo-Json -Depth 5
    $resp = Invoke-RestMethod -Uri $dceUri -Method Put -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } -Body $body
    $dce = [pscustomobject]@{
        LogIngestion = [pscustomobject]@{ Endpoint = $resp.properties.logsIngestion.endpoint }
        Id           = $resp.id
    }
    _Ok ("DCE provisioned via REST: {0}" -f $dce.LogIngestion.Endpoint)
}
$dceIngestionUri = $dce.LogIngestion.Endpoint

# ----- 5. Storage account -----
Import-Module Az.Storage -ErrorAction Stop
$sa = Get-AzStorageAccount -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $sa) {
    _Step "create Storage account"
    $sa = New-AzStorageAccount `
        -ResourceGroupName $StorageResourceGroupName `
        -Name $StorageAccountName -Location $Location `
        -SkuName 'Standard_LRS' -Kind 'StorageV2' `
        -AccessTier 'Hot' -MinimumTlsVersion 'TLS1_2' `
        -AllowBlobPublicAccess $false -ErrorAction Stop
    _Ok ("storage account created: {0}" -f $sa.PrimaryEndpoints.Blob)
} else {
    _Info ("storage account already exists: {0}" -f $sa.PrimaryEndpoints.Blob)
}

# ----- 6. RBAC for the SPN -----
Import-Module Az.Resources -ErrorAction Stop
$rbacScopes = @()
function _GrantRbac {
    param([string]$RoleId, [string]$RoleName, [string]$Scope)
    $existing = Get-AzRoleAssignment -ObjectId $SpnObjectId -Scope $Scope -RoleDefinitionId $RoleId -ErrorAction SilentlyContinue
    if ($existing) { _Info ("RBAC '{0}' already in place at {1}" -f $RoleName, $Scope); return }
    try {
        $null = New-AzRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionId $RoleId -Scope $Scope -ErrorAction Stop
        _Ok ("RBAC '{0}' granted at {1}" -f $RoleName, $Scope)
        $script:rbacScopes += ("{0}|{1}" -f $Scope, $RoleName)
    } catch {
        _Warn ("RBAC '{0}' grant failed at {1}: {2}" -f $RoleName, $Scope, $_.Exception.Message)
    }
}
$rbacGrants = @(
    # Workspace: Log Analytics Contributor (lets engine create DCRs against this workspace)
    @{ RoleId = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'; Name = 'Log Analytics Contributor'; Scope = $workspaceResourceId }
    # DCR RG: Monitoring Metrics Publisher (required for ingest)
    @{ RoleId = '3913510d-42f4-4e42-8a64-420c390055eb'; Name = 'Monitoring Metrics Publisher'; Scope = "/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroupName" }
    # Storage account: RBAC-only -- engine reads via OAuth, no shared key in custom.ps1
    @{ RoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'; Name = 'Storage Blob Data Contributor'; Scope = $sa.Id }
    @{ RoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'; Name = 'Storage Table Data Contributor'; Scope = $sa.Id }
    @{ RoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'; Name = 'Storage Queue Data Contributor'; Scope = $sa.Id }
)
foreach ($g in $rbacGrants) { _GrantRbac -RoleId $g.RoleId -RoleName $g.Name -Scope $g.Scope }

# ----- 7. (Optional) Key Vault -----
$kvUri = $null
if ($CreateKeyVault) {
    Import-Module Az.KeyVault -ErrorAction Stop
    $kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
    if (-not $kv) {
        _Step "create Key Vault"
        $callerUserOid = (Get-AzContext).Account.ExtendedProperties['HomeAccountId'] -split '\.' | Select-Object -First 1
        $kv = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName `
            -Location $Location -EnableRbacAuthorization -ErrorAction Stop
        _Ok ("KV created: {0}" -f $kv.VaultUri)
    } else {
        _Info ("KV already exists: {0}" -f $kv.VaultUri)
    }
    # Grant SPN: Key Vault Secrets User (read), Key Vault Certificate User (read cert)
    _GrantRbac -RoleId '4633458b-17de-408a-b874-0445c86b69e6' -RoleName 'Key Vault Secrets User' -Scope $kv.ResourceId
    _GrantRbac -RoleId 'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba' -RoleName 'Key Vault Certificate User' -Scope $kv.ResourceId
    $kvUri = $kv.VaultUri
}

Write-Host ""
[pscustomobject]@{
    SubscriptionId            = $SubscriptionId
    Location                  = $Location
    ResourceGroupName         = $ResourceGroupName
    DcrResourceGroupName      = $DcrResourceGroupName
    StorageResourceGroupName  = $StorageResourceGroupName
    WorkspaceName             = $WorkspaceName
    WorkspaceResourceId       = $workspaceResourceId
    DceName                   = $DceName
    DceIngestionUri           = $dceIngestionUri
    StorageAccountName        = $StorageAccountName
    StorageAccountResourceId  = $sa.Id
    KeyVaultName              = if ($CreateKeyVault) { $KeyVaultName } else { $null }
    KeyVaultUri               = $kvUri
    RbacScopes                = $rbacScopes
    StorageMode               = 'RBAC-only'  # signal to writer: do NOT emit SI_StorageKey
}
