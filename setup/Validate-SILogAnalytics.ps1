<#
.SYNOPSIS
    Provisions Log Analytics workspace, DCE, DCR, and custom table for SI_IdentityAssets ingestion.
.DESCRIPTION
    Idempotent setup script. Safe to re-run.
    Requires no PowerShell module: Azure Resource Manager, Log Analytics and the Logs Ingestion API are called over
    plain REST (setup\_shared\SI-SetupAzure.ps1, engine\_shared\SI-LogIngest.ps1).

.NOTES
    Solution       : SecurityInsight
    File           : Step2_OnboardValidate-SecurityInsight-LogAnalytics.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.


.LINK
    https://invardia.com/docs/si/scripts/Validate-SILogAnalytics/
#>
[CmdletBinding(SupportsShouldProcess)]
param()

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Validate-SILogAnalytics' -Quiet:($false)
try {

# ----------------------------------------------------------------------
#  Azure over plain REST -- no PowerShell modules (#305)
# ----------------------------------------------------------------------
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1'))
# A resource group this script creates gets the setup tags (product, ring, edition, hosting, tenant, owner, purpose).
# The NAMES below are not setup defaults: they find an existing install and keep the values earlier releases used.
. (Join-Path $PSScriptRoot '_shared\SI-SetupNaming.ps1')
function Get-SISetupRgTag {
    $ring    = if (@('r0', 'r1', 'r2', 'prod') -contains "$($global:SI_Ring)".Trim()) { "$($global:SI_Ring)".Trim() } else { 'prod' }
    $hosting = if ("$($global:SI_Bootstrap_ResourceGroupName)".Trim()) { 'ca' } else { 'vm' }
    $edition = Resolve-SISetupEdition -SIRoot (Split-Path -Parent $PSScriptRoot) -LicenceValue ([string]$global:SI_License)
    ConvertTo-SIAzTagHashtable -Tags (Get-SIResourceGroupTags -Ring $ring -Edition $edition -Hosting $hosting -Tenant (Resolve-SITenantTag) -Owner ([string]$global:SI_Owner))
}
#------------------------------------------------------------------------------------------------------------
# CONFIGURATION (v2: launcher is source of truth)
#------------------------------------------------------------------------------------------------------------

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $global:SettingsPath = $PSScriptRoot
}
# #524: one sign-in -- SecurityInsight's own REST client as the ingestion app named by the SPN globals. The retired
# AutomationFramework branch (the AutomateIT platform module's sign-in and its platform globals) is gone.
if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
    [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
    [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
    throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). The launcher must set them: the ingestion app SecurityInsight signs in as."
}

# Sign in over plain REST as the ingestion app (no PowerShell module). A sign-in already made in this PowerShell
# session is reused, as before.
$__siState = Get-SIAzRestState
if (-not ($__siState.Connection -is [hashtable])) {
    $__siSignIn = @{ TenantId = [string]$global:SpnTenantId; ApplicationId = [string]$global:SpnClientId }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) { $__siSignIn['ClientSecret'] = [string]$global:SpnClientSecret }
    $null = Connect-SISetupAzure @__siSignIn
}

#########################################################################################################
# VARIABLES -- customer-tunable. Override via launcher ($global:*) or edit here.
#########################################################################################################

$TenantId                = $global:SpnTenantId
$SubscriptionId          = if ($global:SubscriptionId)       { $global:SubscriptionId }       elseif ($global:MainLogAnalyticsWorkspaceSubId) { $global:MainLogAnalyticsWorkspaceSubId } else { [string](Get-SISetupAzureContext).Subscription.Id }

# The four shared infra values ($global:WorkspaceName, $global:DceName, $global:DceResourceGroup,
# $global:DcrResourceGroup, $global:WorkspaceResourceGroup, $global:Location) are set by
# SecurityInsight.shared-defaults.ps1 (Layer 0). Customer overrides anywhere on top.
# $global:ResourceGroup kept as a backwards-compat alias for $global:WorkspaceResourceGroup.
$ResourceGroup           = if ($global:WorkspaceResourceGroup) { $global:WorkspaceResourceGroup }
                           elseif ($global:ResourceGroup)      { $global:ResourceGroup }
                           else { "rg-securityinsight" }              # Log Analytics workspace RG
$DceResourceGroup        = if ($global:DceResourceGroup)     { $global:DceResourceGroup }     else { "rg-dce-securityinsight" }          # DCE RG
$DcrResourceGroup        = if ($global:DcrResourceGroup)     { $global:DcrResourceGroup }     else { "rg-dcr-securityinsight" }          # DCR RG
$Location                = if ($global:Location)             { $global:Location }             else { "westeurope" }
$WorkspaceName           = if ($global:WorkspaceName)        { $global:WorkspaceName }        else { "log-platform-management-securityinsight" }
$DceName                 = if ($global:DceName)              { $global:DceName }              else { "dce-securityinsight" }
$DcrName                 = if ($global:DcrName)              { $global:DcrName }              else { "dcr-si-identity-assets" }
$TableName               = if ($global:TableName)            { $global:TableName }            else { "SI_IdentityAssets" }
$WorkspaceRetentionDays  = if ($global:WorkspaceRetentionDays){$global:WorkspaceRetentionDays}else { 90 }
$IngestionSpnClientId    = $global:SpnClientId

#########################################################################################################
# HELPERS
#########################################################################################################

function Write-Step { param($m) Write-Host "[STEP] $m" -ForegroundColor Cyan  }
function Write-Info { param($m) Write-Host "[INFO] $m" -ForegroundColor White  }
function Write-Ok   { param($m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERR]  $m" -ForegroundColor Red   }
function Write-Sep  { Write-Host ("-" * 80) -ForegroundColor White }

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [int] $MaxAttempts = 5,
        [int] $InitialDelaySec = 3,
        [string] $OperationName = "operation"
    )
    # -WhatIf: what would be created or assigned is printed, never done (reads still run)
    if ($WhatIfPreference -and $OperationName -match '^(Create|Assign)\b') { Write-Host ("[WHATIF] would {0} -- not done" -f $OperationName) -ForegroundColor Yellow; return $null }
    $attempt = 0
    $delay = $InitialDelaySec
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            if ($attempt -ge $MaxAttempts) {
                Write-Err "$OperationName failed after $attempt attempts: $($_.Exception.Message)"
                throw
            }
            Write-Warn "$OperationName attempt $attempt failed: $($_.Exception.Message) - retrying in ${delay}s"
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 30)
        }
    }
}

function Ensure-RoleAssignment {
    param(
        [Parameter(Mandatory)] [string] $ObjectId,
        [Parameter(Mandatory)] [string] $RoleDefinitionName,
        [Parameter(Mandatory)] [string] $Scope
    )
    $existing = Get-SIAzRoleAssignment -ObjectId $ObjectId -Scope $Scope -ErrorAction SilentlyContinue |
        Where-Object { $_.RoleDefinitionName -eq $RoleDefinitionName -and $_.Scope -eq $Scope }

    if ($existing) {
        Write-Info "Role '$RoleDefinitionName' already assigned at $Scope"
        return $false
    }

    Invoke-WithRetry -OperationName "Assign $RoleDefinitionName" -ScriptBlock {
        New-SIAzRoleAssignment `
            -ObjectId           $ObjectId `
            -RoleDefinitionName $RoleDefinitionName `
            -Scope              $Scope `
            -ErrorAction        Stop | Out-Null
    }
    Write-Ok "Assigned '$RoleDefinitionName' at $Scope"
    return $true
}

#########################################################################################################
# PREFLIGHT -- no PowerShell module to check: SI's log-ingest wrappers (Get-SIDceList, Update-SILogTableSchema, ...)
# run over plain REST (SI-SetupAzure.ps1 above switches this process to it and loads them).
#########################################################################################################

if (-not (Get-Command -Name Send-SILogData -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\SI-LogIngest.ps1') }

#########################################################################################################
# VALIDATE INPUT VARIABLES
#########################################################################################################

Write-Sep
Write-Step "Validating input variables"

if ([string]::IsNullOrWhiteSpace($IngestionSpnClientId)) {
    throw "IngestionSpnClientId is empty - check that `$global:SpnClientId is set"
}
if ([string]::IsNullOrWhiteSpace($TenantId))       { throw "TenantId is empty" }
if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { throw "SubscriptionId is empty" }
Write-Ok "Variables validated"

#########################################################################################################
# CONTEXT
#########################################################################################################

Write-Sep
Write-Step "Setting Azure context"

try {
    $currentCtx = Get-SISetupAzureContext
    if (-not $currentCtx -or $currentCtx.Subscription.Id -ne $SubscriptionId -or $currentCtx.Tenant.Id -ne $TenantId) {
        Set-SIAzContext -Subscription $SubscriptionId -Tenant $TenantId -ErrorAction Stop | Out-Null
    }
    $ctx = Get-SISetupAzureContext
    if (-not $ctx) { throw "Not signed in to Azure - run the same command again; it signs in with the SecurityInsight app" }
    Write-Ok "Context: $($ctx.Account.Id) | Sub: $($ctx.Subscription.Name)"
} catch {
    throw "Failed to set Azure context: $($_.Exception.Message)"
}

#########################################################################################################
# RESOLVE SecurityInsight SPN
#########################################################################################################

Write-Sep
Write-Step "Resolving ingestion service principal"

$spn = Invoke-WithRetry -OperationName "Get SecurityInsight SPN" -ScriptBlock {
    Get-SIAzADServicePrincipal -ApplicationId $IngestionSpnClientId -ErrorAction Stop
}
if (-not $spn) {
    throw "Service principal with AppId '$IngestionSpnClientId' not found in tenant $TenantId"
}
$spnObjectId = $spn.Id
Write-Ok "SPN ObjectId: $spnObjectId ($($spn.DisplayName))"

#########################################################################################################
# RESOURCE GROUPS (idempotent) - one for Log Analytics workspace, one for DCE, one for DCR
#########################################################################################################

Write-Sep
Write-Step "Ensuring resource groups (workspace / DCE / DCR)"

function Ensure-Rg {
    param([string]$Name, [string]$DesiredLocation)
    $rg = Get-SIAzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    if (-not $rg) {
        Invoke-WithRetry -OperationName "Create RG $Name" -ScriptBlock {
            New-SIAzResourceGroup -Name $Name -Location $DesiredLocation -Tag (Get-SISetupRgTag) -ErrorAction Stop | Out-Null
        }
        Write-Ok "Created resource group: $Name ($DesiredLocation)"
        return $DesiredLocation
    } else {
        if ($rg.Location -ne $DesiredLocation) {
            Write-Warn "RG '$Name' exists in '$($rg.Location)' but requested '$DesiredLocation' - using existing location"
            return $rg.Location
        }
        Write-Info "RG exists: $Name ($($rg.Location))"
        return $rg.Location
    }
}

# Workspace RG drives $Location for the workspace itself (kept authoritative)
$Location = Ensure-Rg -Name $ResourceGroup    -DesiredLocation $Location
$null     = Ensure-Rg -Name $DceResourceGroup -DesiredLocation $Location
$null     = Ensure-Rg -Name $DcrResourceGroup -DesiredLocation $Location

#########################################################################################################
# LOG ANALYTICS WORKSPACE (idempotent)
#########################################################################################################

Write-Sep
Write-Step "Ensuring Log Analytics workspace: $WorkspaceName"

$workspace = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $workspace) {
    Invoke-WithRetry -OperationName "Create workspace" -ScriptBlock {
        New-SIAzOperationalInsightsWorkspace `
            -ResourceGroupName $ResourceGroup `
            -Name              $WorkspaceName `
            -Location          $Location `
            -Sku               "PerGB2018" `
            -RetentionInDays   $WorkspaceRetentionDays `
            -ErrorAction       Stop | Out-Null
    }
    $workspace = Invoke-WithRetry -OperationName "Get workspace" -ScriptBlock {
        $w = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceName -ErrorAction Stop
        if (-not $w -or -not $w.CustomerId -or -not $w.ResourceId) { throw "Workspace not fully provisioned yet" }
        $w
    }
    Write-Ok "Created workspace: $WorkspaceName"
} else {
    Write-Info "Workspace exists: $WorkspaceName"
}

$WorkspaceResourceId = $workspace.ResourceId
$WorkspaceCustomerId = $workspace.CustomerId
$WorkspaceLocation   = $workspace.Location

if (-not $WorkspaceResourceId) { throw "Could not resolve workspace ResourceId" }

Write-Ok "ResourceId : $WorkspaceResourceId"
Write-Ok "CustomerId : $WorkspaceCustomerId"
Write-Ok "Location   : $WorkspaceLocation"

#########################################################################################################
# BUILD DCE/DCR CACHE
#
# Filter to $SubscriptionId so duplicate-named DCEs/DCRs in other subs don't
# poison the module's internal name lookup (would cause a 403 "DCE FQDN not
# associated with DCR immutable Id" error on ingest).
#########################################################################################################

Write-Sep
Write-Step "Building DCE/DCR global cache (filtered to sub: $SubscriptionId)"

$global:AzDceDetails = Invoke-WithRetry -OperationName "List DCEs" -ScriptBlock {
    Get-SIDceList -TenantId $TenantId -Verbose:$false
}
$global:AzDcrDetails = Invoke-WithRetry -OperationName "List DCRs" -ScriptBlock {
    Get-SIDcrList -TenantId $TenantId -Verbose:$false
}

# Filter both caches to the target subscription (matches the DCE/DCR objects'
# subscriptionId property, or parses from .id when the property is absent).
$__filterToSub = {
    param($item, [string]$sub)
    $s = [string]$item.subscriptionId
    if ([string]::IsNullOrWhiteSpace($s) -and $item.id -match '/subscriptions/([^/]+)/') { $s = $Matches[1] }
    return ($s -eq $sub)
}
if ($global:AzDceDetails) { $global:AzDceDetails = @($global:AzDceDetails | Where-Object { & $__filterToSub $_ $SubscriptionId }) }
if ($global:AzDcrDetails) { $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { & $__filterToSub $_ $SubscriptionId }) }

Write-Ok "DCE cache: $(($global:AzDceDetails | Measure-Object).Count) | DCR cache: $(($global:AzDcrDetails | Measure-Object).Count)"

#########################################################################################################
# DATA COLLECTION ENDPOINT (idempotent)
#########################################################################################################

Write-Sep
Write-Step "Ensuring Data Collection Endpoint: $DceName (rg=$DceResourceGroup)"

$dce = Get-SIAzDataCollectionEndpoint -ResourceGroupName $DceResourceGroup -Name $DceName -ErrorAction SilentlyContinue
if (-not $dce) {
    $dce = Invoke-WithRetry -OperationName "Create DCE" -ScriptBlock {
        New-SIAzDataCollectionEndpoint `
            -ResourceGroupName              $DceResourceGroup `
            -Name                           $DceName `
            -Location                       $Location `
            -NetworkAclsPublicNetworkAccess "Enabled" `
            -ErrorAction                    Stop
    }
    Write-Ok "Created DCE: $DceName"
} else {
    Write-Info "DCE exists: $DceName"
}

if (-not $dce.LogIngestionEndpoint) {
    throw "DCE exists but has no LogIngestionEndpoint - check provisioning state: $($dce.ProvisioningState)"
}

$DceResourceId   = $dce.Id
$DceIngestionUri = $dce.LogIngestionEndpoint
Write-Ok "DCE ResourceId    : $DceResourceId"
Write-Ok "DCE Ingestion URI : $DceIngestionUri"

#########################################################################################################
# BUILD SAMPLE DATA + SANITISE SCHEMA
#########################################################################################################

Write-Sep
Write-Step "Building sample data + sanitising schema"

$sampleObject = [PSCustomObject]@{
    # Identity core
    ObjectId = "00000000-0000-0000-0000-000000000000"; ObjectType = "User"
    DisplayName = "Sample Identity"; UPN = "sample@domain.com"
    AppId = ""; SPType = ""; AccountEnabled = $true
    # External / guest
    IsExternal = $false; ExternalDomain = ""; IsB2BCollaborator = $false
    # On-prem sync
    OnPremSynced = $false; OnPremSamAccountName = ""; OnPremDistinguishedName = ""
    # Profile
    Department = ""; JobTitle = ""; Manager = ""
    # Extension attributes
    ExtensionAttribute1 = ""; ExtensionAttribute2 = ""; ExtensionAttribute3 = ""
    ExtensionAttribute4 = ""; ExtensionAttribute5 = ""; ExtensionAttribute6 = ""
    ExtensionAttribute7 = ""; ExtensionAttribute8 = ""; ExtensionAttribute9 = ""
    ExtensionAttribute10 = ""; ExtensionAttribute11 = ""; ExtensionAttribute12 = ""
    ExtensionAttribute13 = ""; ExtensionAttribute14 = ""; ExtensionAttribute15 = ""
    # Lifecycle
    CreatedDateTime = [datetime]::UtcNow.ToString("o"); CreatedDays = 0
    LastSignInDateTime = ""; LastSignInDays = -1; LastNonInteractiveSignInDays = -1
    IsStale = $false; PasswordLastChangedDays = -1; IsPasswordNeverExpires = $false
    # MFA
    MFARegistered = $false; MFAMethodCount = 0; MFAMethods = ""; IsPasswordlessOnly = $false
    # Roles
    AssignedEntraRoles = ""; EligibleEntraRoles = ""
    IsPrivileged = $false; IsPrivilegedEligible = $false
    HasPermanentPrivilegedRole = $false; RequiresPIMReview = $false
    # Risk
    IsSensitive = $false; IsHighValueTarget = $false; IsBreakGlass = $false
    IsShadowAdmin = $false; IsOrphan = $false
    # API permissions
    ApplicationPermissions = ""; DelegatedPermissions = ""; HighestRiskPermission = ""
    HasWritePermissions = $false; HasDirectoryWriteAccess = $false
    HasRoleWriteAccess = $false; HasMailboxAccess = $false
    TargetAPICount = 0; DerivedTierFromPermissions = -1
    # Credentials
    HasClientSecret = $false; HasCertificate = $false; HasExpiredCredential = $false
    CredentialExpiryDays = -1; HasNoOwner = $false; OwnersCount = 0; Owners = ""
    # MI
    IsManagedIdentity = $false; IsManagedIdentityUserAssigned = $false; ManagedIdentityResourceId = ""
    # Multi-tenant
    IsMultiTenant = $false; PublisherVerified = $false; IsExternal_SPN = $false
    # Tagging
    AssetTags = ""; AssetTier = ""; AssetTagType = ""; EffectiveTier = -1
    # Metadata
    CollectionTime = [datetime]::UtcNow.ToString("o")
}

$dataArray = @($sampleObject)
$dataArray = Add-SICollectionTime            -Data $dataArray -Verbose:$false
$dataArray = Repair-SILogColumnName -Data $dataArray -Verbose:$false
$dataArray = Format-SILogRowsToSchema                 -Data $dataArray -Verbose:$false

$colCount = ($dataArray[0].PSObject.Properties | Measure-Object).Count
Write-Ok "Schema prepared: $colCount columns"

#########################################################################################################
# CREATE / UPDATE TABLE + DCR
#########################################################################################################

Write-Sep
Write-Step "Creating/updating table + DCR"

if ($WhatIfPreference) { Write-Host ("[WHATIF] would create or update the table {0}_CL and its data collection rule {1} -- not done" -f $TableName, $DcrName) -ForegroundColor Yellow }
else { try {
    Update-SILogTableSchema `
        -AzLogWorkspaceResourceId                   $WorkspaceResourceId `
        -TenantId                                   $TenantId `
        -DceName                                    $DceName `
        -DcrName                                    $DcrName `
        -DcrResourceGroup                           $DcrResourceGroup `
        -TableName                                  $TableName `
        -Data                                       $dataArray `
        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
        -AzLogDcrTableCreateFromAnyMachine          $true `
        -AzLogDcrTableCreateFromReferenceMachine    @() `
        -Verbose:$false | Out-Null
    Write-Ok "Table + DCR provisioned: ${TableName}_CL (rg=$DcrResourceGroup)"
} catch {
    Write-Err "Table/DCR provisioning failed: $($_.Exception.Message)"
    throw
} }

#########################################################################################################
# RBAC - SecurityInsight SPN -- the narrow roles a run needs, never plain Contributor:
#   - Monitoring Metrics Publisher on the DCE and DCR resource groups (send data through the rules)
#   - Monitoring Contributor on the DCR resource group (a run creates and extends its own rules), and on the
#     DCE resource group when it is another one (a new rule is linked to the endpoint)
#   - Log Analytics Contributor on the workspace (a run creates its tables and adds new columns)
# A collection run creates no resource and assigns no role itself -- it only checks, and says what is missing.
#########################################################################################################

Write-Sep
Write-Step "Assigning RBAC roles to SecurityInsight SPN"

$rgDceScope       = "/subscriptions/$SubscriptionId/resourceGroups/$DceResourceGroup"
$rgDcrScope       = "/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroup"

$roleChanges = @(
    # Workspace: Log Analytics Contributor (so the SPN can create/update tables in the workspace)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Log Analytics Contributor"    -Scope $WorkspaceResourceId)
    # DCE RG: Monitoring Metrics Publisher (send data)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Monitoring Metrics Publisher" -Scope $rgDceScope)
    # DCR RG: Monitoring Metrics Publisher (send data via DCR) + Monitoring Contributor (manage DCR)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Monitoring Metrics Publisher" -Scope $rgDcrScope)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Monitoring Contributor"       -Scope $rgDcrScope)
)

# A new rule is linked to the endpoint: Monitoring Contributor on the DCE RG too when it is another one
if ($DceResourceGroup -ne $DcrResourceGroup) {
    $roleChanges += (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Monitoring Contributor" -Scope $rgDceScope)
}

if ($roleChanges -contains $true) {
    Write-Ok "New role assignments made - waiting 60s for propagation..."
    Start-Sleep -Seconds 60
}

#########################################################################################################
# SUMMARY
#########################################################################################################

Write-Sep
Write-Sep

Write-Host ""
Write-Host "  [ADMIN] Paste the block below into LauncherConfig.custom.ps1 of the IdentityAssetsCollect" -ForegroundColor Yellow
Write-Host "          launcher (gitignored, sits next to LauncherConfig.sample.ps1):"             -ForegroundColor Yellow
Write-Host ""
Write-Host "          LAUNCHERS\IdentityAssetsCollectDefineTierIngestLog\LauncherConfig.custom.ps1"      -ForegroundColor Yellow
Write-Host ""
Write-Sep
Write-Host ""

Write-Host "    #############################################################################" -ForegroundColor White
Write-Host "    # SecurityInsight | LogAnalytics Integration"                                  -ForegroundColor White
Write-Host "    #############################################################################" -ForegroundColor White

    # Community mode: short global names that LauncherConfig.custom.ps1 sets directly
    Write-Host ("    `$global:BatchSize                       = 300")                                                                   -ForegroundColor White
    Write-Host ("    `$global:TableName                       = `"{0}`""   -f $TableName)                                               -ForegroundColor White
    Write-Host ("    `$global:WorkspaceResourceId             = `"{0}`""   -f $WorkspaceResourceId.ToLower())                           -ForegroundColor White
    Write-Host ("    `$global:DcrResourceGroup                = `"{0}`""   -f $DcrResourceGroup.ToLower())                              -ForegroundColor White
    Write-Host ("    `$global:DcrName                         = `"{0}`""   -f $DcrName.ToLower())                                       -ForegroundColor White
    Write-Host ("    `$global:DceResourceGroup                = `"{0}`""   -f $DceResourceGroup.ToLower())                              -ForegroundColor White
    Write-Host ("    `$global:DceName                         = `"{0}`""   -f $DceName.ToLower())                                       -ForegroundColor White
    # DCE ingestion URI is auto-resolved from the DCE name -- no longer required.
    # Uncomment the line below only if you want to pin a specific URI:
    # Write-Host ("    # `$global:DceIngestionUri               = `"{0}`""   -f $DceIngestionUri.TrimEnd('/'))                          -ForegroundColor White
    Write-Host ("    `$global:CsaAttributeSet                 = `"SecurityInsight`"")                                                   -ForegroundColor White
    Write-Host ("    # Optional -- set if Defender/Sentinel IdentityInfo lives in a different workspace:")                              -ForegroundColor White
    Write-Host ("    # `$global:DefenderWorkspaceResourceId    = `"<defender-workspace-resource-id>`"")                                  -ForegroundColor White
    Write-Host ("    # Optional -- skip subscriptions whose NAME matches any of these wildcards:")                                      -ForegroundColor White
    Write-Host ("    # `$global:SI_AzureSubscriptionExcludePatterns = @( '*Azure for Students*' )")                                          -ForegroundColor White

Write-Host ""
Write-Sep
Write-Host ""
} finally { Stop-SIScriptRun -Run $siRun }
