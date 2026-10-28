<#
.SYNOPSIS
    Provisions Log Analytics workspace + DCE + per-engine DCRs + Storage Account
    for SecurityInsight, and grants the SPN the RBAC it needs to operate.

.DESCRIPTION
    Idempotent. Run after New-SISpn (the SPN must exist). Creates / re-uses:
      * Resource Group  (SI workspace + DCE/DCR + storage live here)
      * Log Analytics workspace
      * Data Collection Endpoint (DCE)
      * Data Collection Rules (per-engine)   -- created by the engine at first ingest
                                              by default; this script DOES NOT pre-create
                                              them, but ensures the RG + DCE exist so
                                              first ingest succeeds.
      * Storage account
        - Tables / queues / blobs are created by the engine on first run.
        - This script grants Storage Blob/Table/Queue Data Contributor on the SPN
          at storage-account scope: the engine reaches storage only with its identity.
      * (Optional) Key Vault    if -CreateKeyVault
      * RBAC for SPN at: workspace, DCR RG (Monitoring Metrics Publisher),
        storage account (Blob/Table/Queue Data Contributor)

    No PowerShell modules: native REST and ARM (setup\_shared\SI-SetupAzure.ps1).

.PARAMETER SpnObjectId
    Service principal Object ID (NOT App ID). Returned by New-SISpn as 'ObjectId'. Empty (with no
    -ManagedIdentityName) = no RBAC here: the container setup grants the jobs' managed identity itself.

.PARAMETER ManagedIdentityName
    Sign-in by a USER-ASSIGNED MANAGED IDENTITY (the wizard's default on an Azure VM): the identity is created (or
    re-used) in -ResourceGroupName right after the resource group, and the RBAC below is granted to it.

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

.PARAMETER Ring
.PARAMETER Edition
.PARAMETER Hosting
.PARAMETER Owner
    The tags a resource group gets when this script CREATES it: product, ring, edition, hosting, tenant, owner,
    purpose. Ring defaults to prod; Edition to the licence (a licence file in config\ = pro, else community);
    Hosting to vm (the container setup passes ca); Owner is empty unless given. An existing resource group is
    never re-tagged.

.OUTPUTS
    pscustomobject with all provisioned resource IDs / names / DCE ingestion URI
    so the Write-SICustomConfig step can drop them into the customer's
    SecurityInsight.custom.ps1.

.NOTES
    Status: v2.2.105 -- ships with New-SISpn + Write-SICustomConfig + /api/apply.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]          [string]$SpnObjectId,
    [Parameter()]          [string]$ManagedIdentityName,
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
    [Parameter()]          [string[]]$KvAccessSpnObjectIds,
    [Parameter()]          [ValidateSet('r0','r1','r2','prod')] [string]$Ring = 'prod',
    [Parameter()]          [ValidateSet('','community','pro')] [string]$Edition = '',
    [Parameter()]          [ValidateSet('ca','vm')] [string]$Hosting = 'vm',
    [Parameter()]          [string]$Owner = '',
    # #866 (a private install; owner: "we will not allow fw option or exceptions"): the storage account and the Key Vault
    # are CREATED with no public access -- setup makes their private endpoints right after this, before any read or write
    [Parameter()]          [switch]$PrivateNetwork
)

$ErrorActionPreference = 'Stop'

# The seven tags of a resource group this script creates (setup\_shared\SI-SetupNaming.ps1).
$siRootForTags = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $siRootForTags 'setup\_shared\SI-SetupNaming.ps1')
$rgTagEdition = Resolve-SISetupEdition -Edition $Edition -SIRoot $siRootForTags -LicenceValue ([string]$global:SI_License)

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

# ----- 1. Sign in to Azure (no PowerShell modules) -----
# The wizard host signs in once and runs this script in its own process, so this normally reuses that sign-in.
# Run on its own, it signs a person in (Azure Cloud Shell: automatically; a workstation: in the browser).
_Step "sign in to Azure"
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . (Join-Path $siRootForTags 'setup\_shared\SI-SetupAzure.ps1') }
$ctx = Get-SISetupAzureContext
if ($ctx -and $ctx.Tenant.Id -and $ctx.Tenant.Id -ne $TenantId) {
    # never start a second sign-in here: inside the wizard's listener nobody watches for a browser prompt
    throw ("This PowerShell session is signed in to tenant {0}, but the setup targets tenant {1}. Start the wizard again and sign in to tenant {1}: .\Start-SetupWizard.ps1 -TenantId {1}" -f $ctx.Tenant.Id, $TenantId)
}
$ctx = Connect-SISetupAzure -TenantId $TenantId -SubscriptionId $SubscriptionId
_Ok ("Azure sign-in: {0} / {1}" -f $ctx.Account.Id, $(if ($ctx.Subscription) { $ctx.Subscription.Name } else { $SubscriptionId }))

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
function _RpPending {
    param([string[]]$Namespaces)
    @($Namespaces | Where-Object {
        $rp = Get-SIResourceProvider -ProviderNamespace $_ -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        -not $rp -or $rp.RegistrationState -ne 'Registered'
    })
}
_Step "verify Azure resource providers"
$missing = @(_RpPending -Namespaces $requiredRps)
if ($missing.Count -eq 0) {
    _Ok "all required resource providers are Registered"
} else {
    _Warn ("registering {0} missing resource provider(s): {1}" -f $missing.Count, ($missing -join ', '))
    foreach ($rp in $missing) {
        try {
            $null = Register-SIResourceProvider -ProviderNamespace $rp -SubscriptionId $SubscriptionId
            _Info ("  registration of {0} started" -f $rp)
        } catch {
            _Warn ("  registering {0} failed: {1}" -f $rp, $_.Exception.Message)
        }
    }
    _Step "waiting for resource providers to finish registering (up to 4 min)"
    $deadline = (Get-Date).AddSeconds(240)
    while ((Get-Date) -lt $deadline) {
        $stillPending = @(_RpPending -Namespaces $missing)
        if ($stillPending.Count -eq 0) { _Ok "all providers Registered"; break }
        _Info ("  still registering: {0}" -f ($stillPending -join ', '))
        Start-Sleep -Seconds 12
    }
    # Final check -- any provider still pending is logged but not a hard fail
    # (resource creation will surface the real error if it actually matters).
    $stillBad = @(_RpPending -Namespaces $missing)
    if ($stillBad.Count -gt 0) {
        _Warn ("provider(s) still not fully Registered after wait: {0}. Continuing -- resource creation may still work for already-Registered child types." -f ($stillBad -join ', '))
    }
}

# ----- 2. Resource group(s) -----
foreach ($rg in @($ResourceGroupName, $DcrResourceGroupName, $StorageResourceGroupName) | Sort-Object -Unique) {
    if (-not (Get-SIAzResourceGroup -Name $rg -ErrorAction SilentlyContinue)) {
        _Step "create resource group $rg"
        $rgTags = Get-SIResourceGroupTags -Ring $Ring -Edition $rgTagEdition -Hosting $Hosting -Tenant (Resolve-SITenantTag -TenantId $TenantId) -Owner $Owner
        try { $null = New-SIAzResourceGroup -Name $rg -Location $Location -Tag (ConvertTo-SIAzTagHashtable -Tags $rgTags) -ErrorAction Stop }
        catch {
            # #223: setup may hold rights on a PRE-CREATED resource group only (the Invardia Support app). Creating one
            # is a subscription action -- say what the customer does once, instead of a bare authorization error.
            if ($_.Exception.Message -match '(?i)AuthorizationFailed|does not have authorization|Forbidden|403') {
                throw ("Resource group '{0}' does not exist and this identity cannot create it (a subscription action). CUSTOMER TASK, once: an Owner of subscription {2} creates it in {1} (Azure portal: Resource groups > Create) and gives this identity Contributor + Role Based Access Control Administrator on it (the resource group > Access control (IAM) > Add role assignment); then run the same command again." -f $rg, $Location, $SubscriptionId)
            }
            throw
        }
        _Ok "created"
    } else {
        _Info "RG '$rg' already exists"
    }
}

# ----- 2b. The user-assigned managed identity (sign-in by managed identity) -----
$miOut = $null
if ($ManagedIdentityName) {
    _Step "user-assigned managed identity $ManagedIdentityName"
    $miOut = New-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $ManagedIdentityName -Location $Location -SubscriptionId $SubscriptionId
    if (-not $miOut -or -not $miOut.PrincipalId) { throw ("The managed identity '{0}' could not be created in resource group '{1}'." -f $ManagedIdentityName, $ResourceGroupName) }
    _Ok ("identity: client id {0}, principal id {1}" -f $miOut.ClientId, $miOut.PrincipalId)
    $SpnObjectId = [string]$miOut.PrincipalId
}

# ----- 3. Log Analytics workspace -----
$ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $ws) {
    _Step "create Log Analytics workspace"
    $ws = New-SIAzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName `
        -Name $WorkspaceName -Location $Location -Sku 'PerGB2018' -RetentionInDays 90 -ErrorAction Stop
    _Ok ("workspace created: {0}" -f $ws.ResourceId)
} else {
    _Info ("workspace already exists: {0}" -f $ws.ResourceId)
}
$workspaceResourceId = $ws.ResourceId

# ----- 4. Data Collection Endpoint -----
# ARM PUT with the 'properties' wrapper (an older cmdlet sent a body without it and failed with "[InvalidResource] :
# Invalid resource payload: 'properties' are missing."). Read first, so an existing DCE is re-used.
$dce = Get-SIAzDataCollectionEndpoint -ResourceGroupName $ResourceGroupName -Name $DceName -ErrorAction SilentlyContinue
if (-not $dce) {
    _Step "create Data Collection Endpoint"
    $dcePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$DceName"
    $body = @{
        location   = $Location
        properties = @{
            networkAcls = @{ publicNetworkAccess = 'Enabled' }
        }
    }
    try {
        $resp = Invoke-SIArm -Method PUT -Path $dcePath -ApiVersion '2023-03-11' -Body $body
    } catch {
        # Surface the actual ARM error body so the operator sees more than a wrapped message.
        throw "DCE REST PUT failed for $DceName : $($_.Exception.Message)"
    }
    $dce = [pscustomobject]@{ LogIngestionEndpoint = [string]$resp.properties.logsIngestion.endpoint; Id = [string]$resp.id }
    _Ok ("DCE created: {0}" -f $dce.LogIngestionEndpoint)
} else {
    _Info ("DCE already exists: {0}" -f $dce.LogIngestionEndpoint)
}
$dceIngestionUri = $dce.LogIngestionEndpoint

# ----- 5. Storage account -----
$sa = Get-SIAzStorageAccount -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $sa) {
    _Step "create Storage account"
    # StorageV2 accounts are created with the Hot access tier by default -- and with shared-key access OFF, Entra ID
    # by default (New-SIAzStorageAccount): the engines reach storage with their own identity only.
    $sa = New-SIAzStorageAccount `
        -ResourceGroupName $StorageResourceGroupName `
        -Name $StorageAccountName -Location $Location `
        -SkuName 'Standard_LRS' -Kind 'StorageV2' `
        -MinimumTlsVersion 'TLS1_2' `
        -AllowBlobPublicAccess $false -PublicNetworkAccess $(if ($PrivateNetwork) { 'Disabled' } else { '' }) -ErrorAction Stop
    _Ok ("storage account created: {0}" -f $sa.PrimaryEndpoints.blob)
} else {
    _Info ("storage account already exists: {0}" -f $sa.PrimaryEndpoints.blob)
}

# ----- 6. RBAC for the SPN -----
$rbacScopes = @()
function _GrantRbac {
    param([string]$RoleName, [string]$Scope)
    if (-not $SpnObjectId) { _Info ("RBAC '{0}' at {1}: granted by the container setup to the jobs' managed identity" -f $RoleName, $Scope); return }
    # Assignments are read for this principal at -Scope; ARM also returns inherited ones from a parent scope, which
    # would false-positive the existence check and skip the EXPLICIT assignment the engine needs at this scope.
    # Filter on .Scope -ieq $Scope to require a direct assignment.
    $existing = @(Get-SIAzRoleAssignment -ObjectId $SpnObjectId -Scope $Scope -RoleDefinitionName $RoleName -ErrorAction SilentlyContinue |
        Where-Object { $_.Scope -ieq $Scope })
    if ($existing.Count) { _Info ("RBAC '{0}' already in place at {1}" -f $RoleName, $Scope); return }
    try {
        $null = New-SIRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionName $RoleName -Scope $Scope -PrincipalType ServicePrincipal
        _Ok ("RBAC '{0}' granted at {1}" -f $RoleName, $Scope)
        $script:rbacScopes += ("{0}|{1}" -f $Scope, $RoleName)
    } catch {
        _Warn ("RBAC '{0}' grant failed at {1}: {2}" -f $RoleName, $Scope, $_.Exception.Message)
    }
}
$rbacGrants = @(
    # The narrow roles a run needs -- the same ones setup\Grant-SIIdentity.ps1 -AllowSchemaCreate gives a managed
    # identity. No plain Contributor: a run creates no resource and assigns no role (it only checks, and says in one
    # line what is missing), so nothing asks for it any more.
    # Workspace: Log Analytics Contributor -- a run creates its tables and adds new columns.
    @{ Name = 'Log Analytics Contributor';      Scope = $workspaceResourceId }
    # DCR RG: Monitoring Metrics Publisher (send rows) + Monitoring Contributor (a run creates and extends its rules).
    @{ Name = 'Monitoring Metrics Publisher';   Scope = "/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroupName" }
    @{ Name = 'Monitoring Contributor';         Scope = "/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroupName" }
    # Storage account: RBAC-only -- the engine reaches it only with its identity
    @{ Name = 'Storage Blob Data Contributor';  Scope = $sa.Id }
    @{ Name = 'Storage Table Data Contributor'; Scope = $sa.Id }
    @{ Name = 'Storage Queue Data Contributor'; Scope = $sa.Id }
)
# A new rule is linked to the endpoint: when the endpoint is in another resource group than the rules, the identity
# needs Monitoring Contributor there too.
if ($DcrResourceGroupName -ne $ResourceGroupName) {
    $rbacGrants += @{ Name = 'Monitoring Contributor'; Scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" }
}
foreach ($g in $rbacGrants) { _GrantRbac -RoleName $g.Name -Scope $g.Scope }

# ----- 7. (Optional) Key Vault -----
$kvUri = $null
if ($CreateKeyVault) {
    $kv = Get-SIKeyVault -VaultName $KeyVaultName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if (-not $kv) {
        _Step "create Key Vault"
        # Azure RBAC authorization (not access policies): the SI role grants below apply to it.
        # Purge protection (a deleted vault and its secrets cannot be purged before their retention ends; ONE-WAY) only
        # while the security baseline switch is on for new installs (setup\_shared\SI-SecurityBaseline.ps1, default OFF).
        . (Join-Path $siRootForTags 'setup\_shared\SI-SecurityBaseline.ps1')
        $kvPurgeProtect = Test-SISecurityBaselineNewInstall
        $kv = New-SIKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $Location -SubscriptionId $SubscriptionId -TenantId $TenantId -EnableRbacAuthorization $true -EnablePurgeProtection:$kvPurgeProtect -PublicNetworkAccess $(if ($PrivateNetwork) { 'Disabled' } else { '' })
        if ($kvPurgeProtect) { _Info ("KV purge protection: {0}" -f $(if ($kv.EnablePurgeProtection) { 'on' } else { 'NOT on -- set it with setup\Set-SISecurityBaseline.ps1' })) }
        if (-not $kv.EnableRbacAuthorization) { throw ("Key Vault {0} was created WITHOUT RBAC authorization -- the SI role grants below would not apply." -f $KeyVaultName) }
        _Ok ("KV created: {0}" -f $kv.VaultUri)
    } else {
        _Info ("KV already exists: {0}" -f $kv.VaultUri)
    }
    # Grant SPN: Key Vault Secrets User (read), Key Vault Certificate User (read cert)
    _GrantRbac -RoleName 'Key Vault Secrets User' -Scope $kv.ResourceId
    _GrantRbac -RoleName 'Key Vault Certificate User' -Scope $kv.ResourceId
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
    StorageMode               = 'RBAC-only'  # storage is reached with the identity's data roles
    ManagedIdentityName       = if ($miOut) { [string]$miOut.Name } else { $null }
    ManagedIdentityClientId   = if ($miOut) { [string]$miOut.ClientId } else { $null }
    ManagedIdentityPrincipalId = if ($miOut) { [string]$miOut.PrincipalId } else { $null }
    ManagedIdentityResourceId = if ($miOut) { [string]$miOut.Id } else { $null }
}
