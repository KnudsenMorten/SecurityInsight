#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Microsoft.Graph.Authentication'; ModuleVersion='2.0.0' }
<#
.SYNOPSIS
    Onboard or validate the SecurityInsight SPN's API permissions and Azure RBAC.

.DESCRIPTION
    One-shot, idempotent setup + validation utility:

      1. Finds the SecurityInsight SPN by display name (or -SpnAppId). Creates
         the Entra app registration + service principal if missing.

      2. Iterates a data-driven catalog of REQUIRED API PERMISSIONS
         (Microsoft Graph + Microsoft Threat Protection + WindowsDefenderATP)
         and for each missing permission: grants the appRoleAssignment on the
         target SPN (which is the admin-consent equivalent).

      3. Iterates a data-driven catalog of REQUIRED AZURE RBAC roles and grants
         each at the chosen scope (default: every subscription the caller can
         see, plus optional Log Analytics + DCR scopes via parameters).

      4. Prints a one-line-per-item status table:
            [OK]      already in place
            [GRANTED] missing -> created now
            [FAIL]    missing and could not be created (with reason)
            [SKIP]    skipped (WhatIfMode, or scope not provided)

    Re-running this script is the validation pass: every line that prints [OK]
    is a confirmation. Adding more permissions later is a 1-line edit to the
    $RequiredApiPermissions or $RequiredAzureRoles tables; re-run to apply.

.PARAMETER SpnDisplayName
    Display name of the Entra app registration / SPN. Default: 'sp-securityinsight'.
    Used to look up the SPN by name. Ignored if -SpnAppId is provided.

.PARAMETER SpnAppId
    Existing SPN's AppId (clientId guid). When provided, skips the lookup-by-name
    and uses this SPN directly.

.PARAMETER AzureSubscriptionIds
    Subscription GUIDs to grant the Azure RBAC roles on. Default: all enabled
    subscriptions the caller can see. Pass a subset to limit blast radius.

.PARAMETER DefenderWorkspaceResourceId
    Optional. Full resource ID of the Defender/Sentinel Log Analytics workspace.
    When provided, grants 'Log Analytics Reader' to the SPN on this workspace
    so IdentityInfo and SPN sign-in cross-workspace queries succeed.

.PARAMETER DcrResourceId
    Optional. Full resource ID of the Data Collection Rule that ingests
    SI_IdentityAssets_CL. When provided, grants 'Monitoring Metrics Publisher'
    to the SPN so the IdentityAssetsCollect engine can POST rows.

.PARAMETER WhatIfMode
    Dry run. Walks the catalog, prints status, but does NOT create the SPN,
    grant any permission, or assign any RBAC role. Use this first to preview.

.PARAMETER AuthMethod
    How the script authenticates to Microsoft Graph + Azure. Default 'Interactive'
    (browser sign-in). Same 4 methods as every SI launcher; pick the one that
    matches your operator workflow.

      Interactive       - browser sign-in. Simplest. Use for ad-hoc onboarding.
      ManagedIdentity   - the host's MI. For Azure VMs / Function / Hybrid Worker
                          with the MI granted Privileged Role Admin + Owner.
      SpnSecret         - Service Principal + plaintext secret (testing / CI).
      SpnCertificate    - Service Principal + cert thumbprint in local store.

    Whichever identity you authenticate as MUST have:
      Entra : Privileged Role Administrator OR Application Administrator
              (to grant app permissions to the target SPN).
      Azure : Owner or User Access Administrator at each subscription you want
              RBAC granted on (or at the chosen DCR / workspace scope).

.PARAMETER AuthTenantId
    Tenant id (GUID). Required for ManagedIdentity (Graph), SpnSecret, SpnCertificate.

.PARAMETER AuthClientId
    AppId/ClientId. Required for SpnSecret + SpnCertificate. Optional for
    ManagedIdentity (set to a user-assigned MI's clientId; omit for system-assigned).

.PARAMETER AuthClientSecret
    Plaintext SPN secret. Required for SpnSecret only.

.PARAMETER AuthCertificateThumbprint
    Cert thumbprint installed in CurrentUser\My or LocalMachine\My. Required for
    SpnCertificate only.

.NOTES
    Solution     : SecurityInsight
    File         : Step2_OnboardValidate-SecurityInsight-Permissions.ps1

    Adding a new permission later:
      - For an API permission: add a line under the matching $RequiredApiPermissions
        entry (Graph / Defender / ATP).
      - For an Azure RBAC role: add a hashtable to $RequiredAzureRoles.

    Developed by : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

[CmdletBinding()]
param(
    [string]$SpnDisplayName = 'sp-securityinsight',
    [string]$SpnAppId,
    [string[]]$AzureSubscriptionIds,
    [string]$DefenderWorkspaceResourceId,
    [string]$DcrResourceId,
    [switch]$WhatIfMode,

    # ---- Auth selection ----
    [ValidateSet('Interactive','ManagedIdentity','SpnSecret','SpnCertificate')]
    [string]$AuthMethod = 'Interactive',
    [string]$AuthTenantId,
    [string]$AuthClientId,
    [string]$AuthClientSecret,
    [string]$AuthCertificateThumbprint
)

$ErrorActionPreference = 'Stop'

#region Logging helpers
function Write-Step ([string]$m) { Write-Host "[STEP]    $m" -ForegroundColor Cyan }
function Write-Info ([string]$m) { Write-Host "[INFO]    $m" -ForegroundColor Gray }
function Write-Ok   ([string]$m) { Write-Host "[OK]      $m" -ForegroundColor Green }
function Write-Add  ([string]$m) { Write-Host "[GRANTED] $m" -ForegroundColor Yellow }
function Write-Skip ([string]$m) { Write-Host "[SKIP]    $m" -ForegroundColor DarkYellow }
function Write-Err2 ([string]$m) { Write-Host "[FAIL]    $m" -ForegroundColor Red }
function Write-Sep         { Write-Host ("-" * 88) -ForegroundColor DarkGray }
#endregion


# ============================================================================
# 1.  REQUIRED API PERMISSIONS  (data-driven; extend by adding lines below)
# ============================================================================
# Each entry: ResourceDisplayName + ResourceAppId (well-known) + array of
# permission VALUES (the AppRole.Value, e.g. 'User.Read.All') -- NOT the GUIDs.
# The script resolves each value to the AppRole id at runtime.
#
# To add a permission later: just append to the Permissions array.
# ============================================================================

$RequiredApiPermissions = @(
    @{
        ResourceDisplayName = 'Microsoft Graph'
        ResourceAppId       = '00000003-0000-0000-c000-000000000000'
        Permissions         = @(
            'User.Read.All'
            'Group.Read.All'
            'Directory.Read.All'
            'Application.Read.All'
            'AuditLog.Read.All'
            'Policy.Read.All'
            'RoleManagement.Read.All'
            'RoleManagement.Read.Directory'
            'RoleManagementPolicy.Read.Directory'
            'RoleEligibilitySchedule.Read.Directory'
            'RoleAssignmentSchedule.Read.Directory'
            'IdentityRiskyUser.Read.All'
            'IdentityRiskEvent.Read.All'
            'IdentityRiskyServicePrincipal.Read.All'
            'ThreatHunting.Read.All'
        )
    }
    @{
        ResourceDisplayName = 'Microsoft Threat Protection'
        ResourceAppId       = '8ee8fdad-f234-4243-8f3b-15c294843740'
        Permissions         = @(
            'AdvancedHunting.Read.All'
        )
    }
    @{
        ResourceDisplayName = 'WindowsDefenderATP'
        ResourceAppId       = 'fc780465-2017-40d4-a0c5-307022471b92'
        Permissions         = @(
            'Machine.ReadWrite.All'
        )
    }
)


# ============================================================================
# 2.  REQUIRED AZURE RBAC ROLES  (data-driven)
# ============================================================================
# SubscriptionRoles: granted on every entry of $AzureSubscriptionIds.
# Other roles: granted on optional scopes only when those parameters are set.
# ============================================================================

$RequiredAzureRoles = @{
    SubscriptionRoles      = @('Reader')                            # per subscription scope
    DefenderWorkspaceRoles = @('Log Analytics Reader')              # only if -DefenderWorkspaceResourceId
    DcrRoles               = @('Monitoring Metrics Publisher')      # only if -DcrResourceId
}


# ============================================================================
#   I M P L E M E N T A T I O N
# ============================================================================

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Category, [string]$Item, [string]$Status, [string]$Detail = '')
    $results.Add([pscustomobject]@{
        Category = $Category
        Item     = $Item
        Status   = $Status
        Detail   = $Detail
    }) | Out-Null
}

# ----------------------------------------------------------------------------
# Connect to Microsoft Graph (admin scopes for SPN + permission management)
# ----------------------------------------------------------------------------
Write-Sep
Write-Step ("Connecting to Microsoft Graph  (AuthMethod={0})" -f $AuthMethod)
$graphScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'Directory.ReadWrite.All'
    'RoleManagement.ReadWrite.Directory'
)
try {
    switch ($AuthMethod) {
        'Interactive' {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop | Out-Null
        }
        'ManagedIdentity' {
            if ($AuthClientId) {
                Connect-MgGraph -Identity -ClientId $AuthClientId -NoWelcome -ErrorAction Stop | Out-Null
            } else {
                Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
            }
        }
        'SpnSecret' {
            if (-not $AuthTenantId -or -not $AuthClientId -or -not $AuthClientSecret) {
                throw "AuthMethod=SpnSecret requires -AuthTenantId, -AuthClientId, and -AuthClientSecret."
            }
            $sec  = ConvertTo-SecureString $AuthClientSecret -AsPlainText -Force
            $cred = [pscredential]::new($AuthClientId, $sec)
            Connect-MgGraph -TenantId $AuthTenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop | Out-Null
        }
        'SpnCertificate' {
            if (-not $AuthTenantId -or -not $AuthClientId -or -not $AuthCertificateThumbprint) {
                throw "AuthMethod=SpnCertificate requires -AuthTenantId, -AuthClientId, and -AuthCertificateThumbprint."
            }
            Connect-MgGraph -TenantId $AuthTenantId -ClientId $AuthClientId -CertificateThumbprint $AuthCertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
        }
    }
    $ctx = Get-MgContext
    Write-Ok ("connected as '{0}' (tenant {1})" -f $ctx.Account, $ctx.TenantId)
} catch {
    Write-Err2 ("Connect-MgGraph failed: {0}" -f $_.Exception.Message)
    throw
}

# ----------------------------------------------------------------------------
# Find or create the SPN
# ----------------------------------------------------------------------------
Write-Sep
Write-Step "Resolving SecurityInsight SPN"

$targetSp = $null
if ($SpnAppId) {
    Write-Info "looking up by AppId: $SpnAppId"
    $resp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=appId eq '{0}'" -f $SpnAppId) -ErrorAction SilentlyContinue
    $targetSp = $resp.value | Select-Object -First 1
} else {
    Write-Info "looking up by displayName: $SpnDisplayName"
    $resp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=displayName eq '{0}'" -f $SpnDisplayName) -ErrorAction SilentlyContinue
    $targetSp = $resp.value | Select-Object -First 1
}

if ($targetSp) {
    Write-Ok ("found SPN: '{0}' (objectId={1}, appId={2})" -f $targetSp.displayName, $targetSp.id, $targetSp.appId)
    Add-Result -Category 'SPN' -Item $targetSp.displayName -Status 'OK' -Detail $targetSp.appId
} elseif ($WhatIfMode) {
    Write-Skip "SPN '$SpnDisplayName' not found. WhatIfMode -- would create it."
    Add-Result -Category 'SPN' -Item $SpnDisplayName -Status 'SKIP' -Detail 'WhatIfMode'
} else {
    Write-Step "SPN not found -- creating app registration + servicePrincipal"
    try {
        $appBody = @{ displayName = $SpnDisplayName; signInAudience = 'AzureADMyOrg' } | ConvertTo-Json
        $newApp  = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/applications' -Body $appBody -ContentType 'application/json' -ErrorAction Stop
        Start-Sleep -Seconds 5     # let Entra propagate the new app
        $spBody  = @{ appId = $newApp.appId } | ConvertTo-Json
        $newSp   = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/servicePrincipals' -Body $spBody -ContentType 'application/json' -ErrorAction Stop
        $targetSp = $newSp
        Write-Add ("created SPN: '{0}' (objectId={1}, appId={2})" -f $targetSp.displayName, $targetSp.id, $targetSp.appId)
        Add-Result -Category 'SPN' -Item $SpnDisplayName -Status 'GRANTED' -Detail $targetSp.appId
    } catch {
        Write-Err2 ("could not create SPN: {0}" -f $_.Exception.Message)
        Add-Result -Category 'SPN' -Item $SpnDisplayName -Status 'FAIL' -Detail $_.Exception.Message
        throw
    }
}

if (-not $targetSp -and -not $WhatIfMode) { throw "Failed to resolve target SPN. Cannot continue." }

# ----------------------------------------------------------------------------
# API PERMISSIONS  (granted as appRoleAssignedTo on the resource SP)
# ----------------------------------------------------------------------------
Write-Sep
Write-Step "Reconciling API permissions"

foreach ($apiBlock in $RequiredApiPermissions) {

    Write-Info ("resource: {0}" -f $apiBlock.ResourceDisplayName)

    # Look up the resource SP (e.g. Microsoft Graph) by its well-known appId
    $resp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=appId eq '{0}'" -f $apiBlock.ResourceAppId) -ErrorAction SilentlyContinue
    $resourceSp = $resp.value | Select-Object -First 1
    if (-not $resourceSp) {
        Write-Err2 ("resource SP for '{0}' (appId={1}) not found in this tenant -- skipping its permissions" -f $apiBlock.ResourceDisplayName, $apiBlock.ResourceAppId)
        foreach ($perm in $apiBlock.Permissions) {
            Add-Result -Category 'API Permission' -Item ("{0} / {1}" -f $apiBlock.ResourceDisplayName, $perm) -Status 'FAIL' -Detail 'resource SP not in tenant'
        }
        continue
    }

    # Build a name->id lookup for this resource's appRoles, and a current grants set for our target SPN
    $appRoleIdByValue = @{}
    foreach ($ar in $resourceSp.appRoles) {
        if ($ar.value) { $appRoleIdByValue[$ar.value] = $ar.id }
    }

    $currentGrants = @{}
    if ($targetSp) {
        $grantsResp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $targetSp.id) -ErrorAction SilentlyContinue
        foreach ($g in $grantsResp.value) {
            if ($g.resourceId -eq $resourceSp.id) { $currentGrants[$g.appRoleId] = $true }
        }
    }

    foreach ($permValue in $apiBlock.Permissions) {
        $permKey = "{0} / {1}" -f $apiBlock.ResourceDisplayName, $permValue
        $appRoleId = $appRoleIdByValue[$permValue]
        if (-not $appRoleId) {
            Write-Err2 ("  {0} -- appRole value not found on resource SP" -f $permValue)
            Add-Result -Category 'API Permission' -Item $permKey -Status 'FAIL' -Detail 'appRole value not defined by resource'
            continue
        }
        if ($currentGrants[$appRoleId]) {
            Write-Ok ("  {0}" -f $permValue)
            Add-Result -Category 'API Permission' -Item $permKey -Status 'OK'
            continue
        }
        if ($WhatIfMode) {
            Write-Skip ("  {0} -- would grant" -f $permValue)
            Add-Result -Category 'API Permission' -Item $permKey -Status 'SKIP' -Detail 'WhatIfMode'
            continue
        }
        try {
            $body = @{
                principalId = $targetSp.id
                resourceId  = $resourceSp.id
                appRoleId   = $appRoleId
            } | ConvertTo-Json
            Invoke-MgGraphRequest -Method POST -Uri ("/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $targetSp.id) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            Write-Add ("  {0}" -f $permValue)
            Add-Result -Category 'API Permission' -Item $permKey -Status 'GRANTED'
        } catch {
            Write-Err2 ("  {0} -- {1}" -f $permValue, $_.Exception.Message)
            Add-Result -Category 'API Permission' -Item $permKey -Status 'FAIL' -Detail $_.Exception.Message
        }
    }
}

# ----------------------------------------------------------------------------
# AZURE RBAC
# ----------------------------------------------------------------------------
Write-Sep
Write-Step ("Connecting to Azure  (AuthMethod={0})" -f $AuthMethod)
try {
    Import-Module Az.Accounts  -ErrorAction Stop -WarningAction SilentlyContinue
    Import-Module Az.Resources -ErrorAction Stop -WarningAction SilentlyContinue
    switch ($AuthMethod) {
        'Interactive' {
            Connect-AzAccount -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
        'ManagedIdentity' {
            if ($AuthClientId) {
                Connect-AzAccount -Identity -AccountId $AuthClientId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            } else {
                Connect-AzAccount -Identity -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
        }
        'SpnSecret' {
            $sec  = ConvertTo-SecureString $AuthClientSecret -AsPlainText -Force
            $cred = [pscredential]::new($AuthClientId, $sec)
            Connect-AzAccount -ServicePrincipal -Tenant $AuthTenantId -Credential $cred -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
        'SpnCertificate' {
            Connect-AzAccount -ServicePrincipal -Tenant $AuthTenantId -ApplicationId $AuthClientId -CertificateThumbprint $AuthCertificateThumbprint -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
    }
    Write-Ok "Az connected"
} catch {
    Write-Err2 ("Connect-AzAccount failed: {0}" -f $_.Exception.Message)
    Add-Result -Category 'Azure RBAC' -Item 'Connect-AzAccount' -Status 'FAIL' -Detail $_.Exception.Message
    throw
}

# Subscription scopes
if (-not $AzureSubscriptionIds -or $AzureSubscriptionIds.Count -eq 0) {
    Write-Info "no -AzureSubscriptionIds provided -- enumerating all enabled subs the caller can see"
    $AzureSubscriptionIds = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' } | Select-Object -ExpandProperty Id)
    Write-Info ("found {0} enabled subscription(s)" -f $AzureSubscriptionIds.Count)
}

function Grant-Role {
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$RoleName,
        [Parameter(Mandatory)][string]$Scope,
        [string]$ItemLabel
    )
    if (-not $ItemLabel) { $ItemLabel = "{0} @ {1}" -f $RoleName, $Scope }
    try {
        $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Ok ("  {0}" -f $ItemLabel)
            Add-Result -Category 'Azure RBAC' -Item $ItemLabel -Status 'OK'
            return
        }
        if ($WhatIfMode) {
            Write-Skip ("  {0} -- would assign" -f $ItemLabel)
            Add-Result -Category 'Azure RBAC' -Item $ItemLabel -Status 'SKIP' -Detail 'WhatIfMode'
            return
        }
        New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop | Out-Null
        Write-Add ("  {0}" -f $ItemLabel)
        Add-Result -Category 'Azure RBAC' -Item $ItemLabel -Status 'GRANTED'
    } catch {
        Write-Err2 ("  {0} -- {1}" -f $ItemLabel, $_.Exception.Message)
        Add-Result -Category 'Azure RBAC' -Item $ItemLabel -Status 'FAIL' -Detail $_.Exception.Message
    }
}

if (-not $targetSp) {
    Write-Skip "SPN not yet created (WhatIfMode) -- skipping Azure RBAC reconciliation"
} else {
    Write-Sep
    Write-Step ("Reconciling Azure RBAC for SPN objectId {0}" -f $targetSp.id)

    foreach ($subId in $AzureSubscriptionIds) {
        $subScope = "/subscriptions/$subId"
        foreach ($role in $RequiredAzureRoles.SubscriptionRoles) {
            Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $subScope -ItemLabel ("{0} @ /subscriptions/{1}" -f $role, $subId)
        }
    }

    if ($DefenderWorkspaceResourceId) {
        foreach ($role in $RequiredAzureRoles.DefenderWorkspaceRoles) {
            Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $DefenderWorkspaceResourceId -ItemLabel ("{0} @ DefenderWorkspace" -f $role)
        }
    } else {
        Write-Skip "no -DefenderWorkspaceResourceId provided -- skipping Log Analytics Reader grant on Defender workspace"
        Add-Result -Category 'Azure RBAC' -Item 'Log Analytics Reader @ Defender workspace' -Status 'SKIP' -Detail 'DefenderWorkspaceResourceId not provided'
    }

    if ($DcrResourceId) {
        foreach ($role in $RequiredAzureRoles.DcrRoles) {
            Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $DcrResourceId -ItemLabel ("{0} @ DCR" -f $role)
        }
    } else {
        Write-Skip "no -DcrResourceId provided -- skipping Monitoring Metrics Publisher grant on DCR"
        Add-Result -Category 'Azure RBAC' -Item 'Monitoring Metrics Publisher @ DCR' -Status 'SKIP' -Detail 'DcrResourceId not provided'
    }
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
Write-Sep
Write-Step "Summary"
$grouped = $results | Group-Object Status
foreach ($g in ($grouped | Sort-Object Name)) {
    $color = switch ($g.Name) {
        'OK'      { 'Green' }
        'GRANTED' { 'Yellow' }
        'SKIP'    { 'DarkYellow' }
        'FAIL'    { 'Red' }
        default   { 'Gray' }
    }
    Write-Host ("  {0,-9} {1}" -f $g.Name, $g.Count) -ForegroundColor $color
}
Write-Sep
$results | Format-Table -AutoSize -Property Category, Item, Status, Detail
Write-Sep

# ----------------------------------------------------------------------------
# SPN provisioning summary -- final report with copy-paste-ready SPN details
# for LauncherConfig.custom.ps1 + verification next steps.
# ----------------------------------------------------------------------------
$apiCount        = @($results | Where-Object Category -eq 'API Permission'  | Where-Object Status -eq 'GRANTED').Count
$rbacGranted     = @($results | Where-Object Category -eq 'Azure RBAC'      | Where-Object Status -eq 'GRANTED').Count
$rbacFailed      = @($results | Where-Object Category -eq 'Azure RBAC'      | Where-Object Status -eq 'FAIL').Count
$rbacSkipped     = @($results | Where-Object Category -eq 'Azure RBAC'      | Where-Object Status -eq 'SKIP').Count
$defenderStatus  = @($results | Where-Object Item -like 'Log Analytics Reader*')      | Select-Object -First 1
$dcrStatus       = @($results | Where-Object Item -like 'Monitoring Metrics Publisher*') | Select-Object -First 1
$tenantIdForSpn  = if ($AuthTenantId) { $AuthTenantId } elseif ($targetSp.appOwnerOrganizationId) { [string]$targetSp.appOwnerOrganizationId } else { '' }

Write-Host ""
Write-Host "  ========= SecurityInsight SPN -- provisioning summary =========" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  App display name       : {0}" -f $targetSp.displayName)   -ForegroundColor White
Write-Host ("  App (client) ID        : {0}" -f $targetSp.appId)         -ForegroundColor White
Write-Host ("  Service Principal ID   : {0}" -f $targetSp.id)            -ForegroundColor White
if ($tenantIdForSpn) {
    Write-Host ("  Tenant ID              : {0}" -f $tenantIdForSpn)     -ForegroundColor White
}
Write-Host ""
Write-Host "  Counts" -ForegroundColor Gray
Write-Host ("    API permissions      : {0} granted" -f $apiCount)                                        -ForegroundColor Gray
Write-Host ("    Azure RBAC (subs)    : {0} granted / {1} failed / {2} skipped" -f $rbacGranted, $rbacFailed, $rbacSkipped) -ForegroundColor Gray
if ($defenderStatus) { Write-Host ("    Defender workspace   : {0}  ({1})" -f $defenderStatus.Status, $defenderStatus.Detail) -ForegroundColor Gray }
else                 { Write-Host ("    Defender workspace   : SKIP  (DefenderWorkspaceResourceId not provided)")            -ForegroundColor Gray }
if ($dcrStatus)      { Write-Host ("    DCR grant            : {0}  ({1})" -f $dcrStatus.Status, $dcrStatus.Detail)           -ForegroundColor Gray }
else                 { Write-Host ("    DCR grant            : SKIP  (DcrResourceId not provided)")                          -ForegroundColor Gray }

Write-Host ""
Write-Host "  Copy into LauncherConfig.custom.ps1 (community mode):" -ForegroundColor Yellow
Write-Host ""
if ($tenantIdForSpn) {
    Write-Host ("    `$global:SpnTenantId     = '{0}'" -f $tenantIdForSpn) -ForegroundColor White
}
Write-Host ("    `$global:SpnClientId     = '{0}'" -f $targetSp.appId)      -ForegroundColor White
Write-Host  "    `$global:SpnClientSecret = '<create a client secret in Entra -> App registrations -> Certificates & secrets>'" -ForegroundColor White
Write-Host ""
Write-Host "  Verification next steps:" -ForegroundColor Yellow
Write-Host ("    1. Re-run this script with -SpnAppId {0} to confirm no drift." -f $targetSp.appId) -ForegroundColor Gray
Write-Host  "    2. Run any SecurityInsight engine once (IAC, RiskAnalysis, ...) to ingest test data."                    -ForegroundColor Gray
Write-Host  "    3. Verify in Log Analytics:"                                                                             -ForegroundColor Gray
Write-Host  "         SI_IdentityAssets_CL | summarize Count=count() by ObjectType"                                       -ForegroundColor Gray
Write-Host  "         SI_RiskAnalysis_Summary_CL | top 10 by RiskScoreTotal desc"                                         -ForegroundColor Gray
Write-Host ""
Write-Sep

$failCount = ($results | Where-Object Status -eq 'FAIL').Count
if ($failCount -gt 0) {
    Write-Err2 "$failCount item(s) failed -- review above and re-run after fixing."
    exit 1
}
Write-Ok "All required permissions and RBAC roles are in place."
