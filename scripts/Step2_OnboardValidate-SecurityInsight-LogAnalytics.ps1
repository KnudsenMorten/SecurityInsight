<#
.SYNOPSIS
    Provisions Log Analytics workspace, DCE, DCR, and custom table for SI_IdentityAssets ingestion.
.DESCRIPTION
    Idempotent setup script. Safe to re-run.
    Requires: Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Monitor, AzLogDcrIngestPS.

.NOTES
    Solution       : SecurityInsight
    File           : Step2_OnboardValidate-SecurityInsight-LogAnalytics.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-SecurityInsightModules
#------------------------------------------------------------------------------------------------------------
# CONFIGURATION (v2: launcher is source of truth)
#------------------------------------------------------------------------------------------------------------

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }

if (-not [bool]$global:AutomationFramework) {
    if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
        [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). Launcher must set them or enable AutomationFramework."
    }
}

if ([bool]$global:AutomationFramework) {
    # --- Automation Framework branch (internal 2LINKIT infra) ---
    $ScriptDirectory = $PSScriptRoot

    # v2 bootstrap: walk up to find the AutomateITPS module (= repo root),
    # then one call to Initialize-PlatformAutomationFramework takes care of
    # cert-based Connect-AzAccount, fetching Modern secrets from KV, and
    # populating the v1-contract $global:HighPriv_* / $global:AzureTenantId
    # names. Zero v1 module imports.
    $repoRoot = $ScriptDirectory
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$ScriptDirectory'."
    }
    $global:PathScripts = $repoRoot
    Write-Output ""
    Write-Output "Repo root          -> $($global:PathScripts)"

    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure

} else {
    # --- Community / standalone branch (SPN globals set by launcher) ---
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $credential   = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $credential -WarningAction SilentlyContinue | Out-Null
    }
}

#########################################################################################################
# VARIABLES -- customer-tunable. Override via launcher ($global:*) or edit here.
#########################################################################################################

$TenantId                = if ($global:AutomationFramework) { $Global:TenantID } else { $global:SpnTenantId }
$SubscriptionId          = if ($global:SubscriptionId)       { $global:SubscriptionId }       elseif ($global:MainLogAnalyticsWorkspaceSubId) { $global:MainLogAnalyticsWorkspaceSubId } else { (Get-AzContext).Subscription.Id }

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
$IngestionSpnClientId    = if ($global:AutomationFramework)  { $global:HighPriv_Modern_ApplicationID_Azure } else { $global:SpnClientId }

#########################################################################################################
# HELPERS
#########################################################################################################

function Write-Step { param($m) Write-Host "[STEP] $m" -ForegroundColor Cyan  }
function Write-Info { param($m) Write-Host "[INFO] $m" -ForegroundColor Gray  }
function Write-Ok   { param($m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERR]  $m" -ForegroundColor Red   }
function Write-Sep  { Write-Host ("-" * 80) -ForegroundColor DarkGray }

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [int] $MaxAttempts = 5,
        [int] $InitialDelaySec = 3,
        [string] $OperationName = "operation"
    )
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
    $existing = Get-AzRoleAssignment -ObjectId $ObjectId -Scope $Scope -ErrorAction SilentlyContinue |
        Where-Object { $_.RoleDefinitionName -eq $RoleDefinitionName -and $_.Scope -eq $Scope }

    if ($existing) {
        Write-Info "Role '$RoleDefinitionName' already assigned at $Scope"
        return $false
    }

    Invoke-WithRetry -OperationName "Assign $RoleDefinitionName" -ScriptBlock {
        New-AzRoleAssignment `
            -ObjectId           $ObjectId `
            -RoleDefinitionName $RoleDefinitionName `
            -Scope              $Scope `
            -ErrorAction        Stop | Out-Null
    }
    Write-Ok "Assigned '$RoleDefinitionName' at $Scope"
    return $true
}

#########################################################################################################
# PREFLIGHT -- modules already verified by Ensure-SecurityInsightModules at top of file.
# AzLogDcrIngestPS needs an explicit -Global import so its exported functions are visible
# to dot-sourced engine code that PowerShell's auto-loader places in a child scope.
#########################################################################################################

Import-Module AzLogDcrIngestPS -Global -Force -DisableNameChecking -WarningAction SilentlyContinue

#########################################################################################################
# VALIDATE INPUT VARIABLES
#########################################################################################################

Write-Sep
Write-Step "Validating input variables"

if ([string]::IsNullOrWhiteSpace($IngestionSpnClientId)) {
    throw "IngestionSpnClientId is empty - check that `$global:HighPriv_Modern_ApplicationID_Azure is set"
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
    $currentCtx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentCtx -or $currentCtx.Subscription.Id -ne $SubscriptionId -or $currentCtx.Tenant.Id -ne $TenantId) {
        Set-AzContext -SubscriptionId $SubscriptionId -TenantId $TenantId -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    if (-not $ctx) { throw "No Azure context - run Connect-AzAccount first" }
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
    Get-AzADServicePrincipal -ApplicationId $IngestionSpnClientId -ErrorAction Stop
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
    $rg = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    if (-not $rg) {
        Invoke-WithRetry -OperationName "Create RG $Name" -ScriptBlock {
            New-AzResourceGroup -Name $Name -Location $DesiredLocation -ErrorAction Stop | Out-Null
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

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $workspace) {
    Invoke-WithRetry -OperationName "Create workspace" -ScriptBlock {
        New-AzOperationalInsightsWorkspace `
            -ResourceGroupName $ResourceGroup `
            -Name              $WorkspaceName `
            -Location          $Location `
            -Sku               "PerGB2018" `
            -RetentionInDays   $WorkspaceRetentionDays `
            -ErrorAction       Stop | Out-Null
    }
    $workspace = Invoke-WithRetry -OperationName "Get workspace" -ScriptBlock {
        $w = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceName -ErrorAction Stop
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
    Get-AzDceListAll -TenantId $TenantId -Verbose:$false
}
$global:AzDcrDetails = Invoke-WithRetry -OperationName "List DCRs" -ScriptBlock {
    Get-AzDcrListAll -TenantId $TenantId -Verbose:$false
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

$dce = Get-AzDataCollectionEndpoint -ResourceGroupName $DceResourceGroup -Name $DceName -ErrorAction SilentlyContinue
if (-not $dce) {
    $dce = Invoke-WithRetry -OperationName "Create DCE" -ScriptBlock {
        New-AzDataCollectionEndpoint `
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
$dataArray = Add-CollectionTimeToAllEntriesInArray            -Data $dataArray -Verbose:$false
$dataArray = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $dataArray -Verbose:$false
$dataArray = Build-DataArrayToAlignWithSchema                 -Data $dataArray -Verbose:$false

$colCount = ($dataArray[0].PSObject.Properties | Measure-Object).Count
Write-Ok "Schema prepared: $colCount columns"

#########################################################################################################
# CREATE / UPDATE TABLE + DCR
#########################################################################################################

Write-Sep
Write-Step "Creating/updating table + DCR"

try {
    CheckCreateUpdate-TableDcr-Structure `
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
}

#########################################################################################################
# RBAC - SecurityInsight SPN
#   - Monitoring Metrics Publisher on RG (send data to DCRs)
#   - Contributor on RG (manage DCE/DCR resources)
#   - Contributor on the Log Analytics workspace
#########################################################################################################

Write-Sep
Write-Step "Assigning RBAC roles to SecurityInsight SPN"

$rgWorkspaceScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
$rgDceScope       = "/subscriptions/$SubscriptionId/resourceGroups/$DceResourceGroup"
$rgDcrScope       = "/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroup"

$roleChanges = @(
    # Workspace: Contributor (so the SPN can create/update tables in the workspace)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Contributor"                  -Scope $WorkspaceResourceId)
    # DCE RG: Monitoring Metrics Publisher (send data) + Contributor (manage DCE)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Monitoring Metrics Publisher" -Scope $rgDceScope)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Contributor"                  -Scope $rgDceScope)
    # DCR RG: Monitoring Metrics Publisher (send data via DCR) + Contributor (manage DCR)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Monitoring Metrics Publisher" -Scope $rgDcrScope)
    (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Contributor"                  -Scope $rgDcrScope)
)

# Also assign Contributor on workspace RG if it's different from the DCE/DCR RGs
if ($ResourceGroup -ne $DceResourceGroup -and $ResourceGroup -ne $DcrResourceGroup) {
    $roleChanges += (Ensure-RoleAssignment -ObjectId $spnObjectId -RoleDefinitionName "Contributor" -Scope $rgWorkspaceScope)
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
if ([bool]$global:AutomationFramework) {
    Write-Host "  [ADMIN] Paste the block below into your platform's Automation-DefaultVariables.psm1" -ForegroundColor Yellow
    Write-Host "          (under the SecurityInsight section). The IdentityAssetsCollect engine"      -ForegroundColor Yellow
    Write-Host "          reads these globals when running with `$global:AutomationFramework=`$true."   -ForegroundColor Yellow
} else {
    Write-Host "  [ADMIN] Paste the block below into LauncherConfig.custom.ps1 of the IdentityAssetsCollect" -ForegroundColor Yellow
    Write-Host "          launcher (gitignored, sits next to LauncherConfig.sample.ps1):"             -ForegroundColor Yellow
    Write-Host ""
    Write-Host "          LAUNCHERS\IdentityAssetsCollectDefineTierIngestLog\LauncherConfig.custom.ps1"      -ForegroundColor Yellow
}
Write-Host ""
Write-Sep
Write-Host ""

Write-Host "    #############################################################################" -ForegroundColor DarkGray
Write-Host "    # SecurityInsight | LogAnalytics Integration"                                  -ForegroundColor DarkGray
Write-Host "    #############################################################################" -ForegroundColor DarkGray
if ([bool]$global:AutomationFramework) {
    # AF mode: SecurityInsight_LOG_* / SecurityInsight_Identity_* / SecurityInsight_Defender_* prefixes
    Write-Host ("    `$global:SecurityInsight_LOG_BatchSize                = 300")                                                      -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_LOG_TableName                = `"{0}`""   -f $TableName)                                  -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_LOG_WorkspaceResourceId      = `"{0}`""   -f $WorkspaceResourceId.ToLower())              -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_LOG_DcrResourceGroup         = `"{0}`""   -f $DcrResourceGroup.ToLower())                 -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_LOG_DcrName                  = `"{0}`""   -f $DcrName.ToLower())                          -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_LOG_DceName                  = `"{0}`""   -f $DceName.ToLower())                          -ForegroundColor White
    # DCE ingestion URI is auto-resolved from the DCE name -- no longer required.
    # Uncomment the line below only if you want to pin a specific URI:
    # Write-Host ("    # `$global:SecurityInsight_LOG_DceIngestionUri        = `"{0}`""   -f $DceIngestionUri.TrimEnd('/'))             -ForegroundColor DarkGray
    Write-Host ("    `$global:SecurityInsight_Identity_TroubleshootingMode = `$false")                                                  -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_Identity_CsaAttributeSet     = `"SecurityInsight`"")                                      -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_Defender_WorkspaceResourceId = `$global:MainLogAnalyticsWorkspaceResourceId")             -ForegroundColor White
    Write-Host ("    `$global:SecurityInsight_Identity_SubscriptionNameExcludePatterns = @(")                                           -ForegroundColor White
    Write-Host ("        '*Azure for Students*'")                                                                                       -ForegroundColor White
    Write-Host ("    )")                                                                                                                 -ForegroundColor White
} else {
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
    # Write-Host ("    # `$global:DceIngestionUri               = `"{0}`""   -f $DceIngestionUri.TrimEnd('/'))                          -ForegroundColor DarkGray
    Write-Host ("    `$global:TroubleshootingMode             = `$false")                                                               -ForegroundColor White
    Write-Host ("    `$global:CsaAttributeSet                 = `"SecurityInsight`"")                                                   -ForegroundColor White
    Write-Host ("    # Optional -- set if Defender/Sentinel IdentityInfo lives in a different workspace:")                              -ForegroundColor DarkGray
    Write-Host ("    # `$global:DefenderWorkspaceResourceId    = `"<defender-workspace-resource-id>`"")                                  -ForegroundColor DarkGray
    Write-Host ("    # Optional -- skip subscriptions whose NAME matches any of these wildcards:")                                      -ForegroundColor DarkGray
    Write-Host ("    # `$global:SubscriptionNameExcludePatterns = @( '*Azure for Students*' )")                                          -ForegroundColor DarkGray
}

Write-Host ""
Write-Sep
Write-Host ""
