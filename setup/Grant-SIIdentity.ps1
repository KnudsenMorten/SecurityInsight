<#
.SYNOPSIS
    Grants a VM's or an Azure Arc server's MANAGED IDENTITY everything SecurityInsight needs (#222).

.DESCRIPTION
    Managed identity is the default sign-in (SI_AuthMethod = 'ManagedIdentity'). Container setup grants the job
    identity itself (Bootstrap-ContainerAppJob.ps1 -GrantIdentityRoles); this script does the same for the identity a
    VM or an Arc server runs as -- the SAME plan (container\_shared\SI-ContainerConfig.ps1, Get-SIContainerIdentityGrantPlan):
      * Reader on the collection scope(s) (default: the SI subscription)
      * Monitoring Metrics Publisher on the DCR resource group, Log Analytics Reader on the workspace(s)
      * the storage data roles on SI's own storage account
      * Key Vault Secrets User on the vault holding the Azure OpenAI / Shodan / SMTP secrets (-KeyVaultName)
      * the read-only application permissions (Microsoft Graph, Defender XDR, Defender for Endpoint)
    -AllowSchemaCreate also grants Monitoring Contributor on the DCR resource group and Log Analytics Contributor on
    the workspace, so the first run can create its own tables and data collection rules.

    -Tagging (#236) grants the ASSET-TAGGING plan instead (container\_shared\SI-ContainerConfig.ps1,
    Get-SIAssetTaggingIdentityGrantPlan) -- the one SecurityInsight engine that WRITES. Use it on asset tagging's OWN
    identity, never on the collection identity (which stays read only): Defender for Endpoint Machine.ReadWrite.All,
    Tag Contributor at -TaggingScopes (default the reader scopes), Entra custom security attribute assignment, plus the
    reads its rules need and SI's own workspace and storage for its activity log. Opt-in: nothing writes until the
    identity holds these AND the Pro setting SI_Pro_AssetTagging_Apply (or, on a server, -Apply / SI_AssetTagging_Apply = $true) asks.

    Which identity:
      -PrincipalId <object id>                              any managed identity, by its object (principal) id
      -IdentityName <name> -IdentityResourceGroup <rg>      a USER-assigned identity
      -VmName <name> -VmResourceGroup <rg>                  an Azure VM's SYSTEM-assigned identity
      -ArcMachineName <name> -ArcResourceGroup <rg>         an Azure Arc server's identity
      -AppId <client id>                                    an app registration that signs in with a certificate, by its
                                                            application (client) id -- never looked up by its name

    Prints the plan with what is present / missing; changes nothing without -Apply. Signs in with no PowerShell module (Azure Cloud Shell, the browser, or the sign-in already open in this session)
    with rights to assign roles at those scopes and to grant application permissions (AppRoleAssignment.ReadWrite.All,
    or an Entra admin). A grant it cannot make is printed as a ready-to-run task for someone who can.

    Only part of the plan:
      -OnlyAppPermissions          only the application permissions (Microsoft Graph, Defender): no Azure role is read
                                   or granted and no install configuration is needed
      -Only <name>[,<name>...]     only these application permissions of the plan, by name; a name that is not in the
                                   plan stops the run (nothing outside the plan is ever granted)
    With -Apply the plan is printed first (per permission: present / missing -- will be granted), then the result per
    permission. Only what is missing is granted.

    Support staff run it inside an Invardia Support session opened for the environment: it then works through that
    session (no sign-in of its own), in a subscription the session names, and every change is recorded in the
    environment's audit log.

.EXAMPLE
    .\Grant-SIIdentity.ps1 -VmName vm-si -VmResourceGroup rg-si -KeyVaultName kv-si -AllowSchemaCreate -Apply
.EXAMPLE
    .\Grant-SIIdentity.ps1 -AppId <application (client) id> -SubscriptionId <subscription id> -WorkspaceResourceId <workspace resource id> -AllowSchemaCreate -Apply
.EXAMPLE
    .\Grant-SIIdentity.ps1 -IdentityName uami-securityinsight-tagging -IdentityResourceGroup rg-si -Tagging -Apply
.EXAMPLE
    .\Grant-SIIdentity.ps1 -IdentityName uami-securityinsight -IdentityResourceGroup rg-si -SubscriptionId <subscription id> -Only SecurityAlert.Read.All,AccessReview.Read.All -Apply

.LINK
    https://invardia.com/docs/si/scripts/Grant-SIIdentity/
#>
[CmdletBinding(DefaultParameterSetName = 'Principal', SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'Principal', Mandatory)][string]$PrincipalId,
    [Parameter(ParameterSetName = 'Uami', Mandatory)][string]$IdentityName,
    [Parameter(ParameterSetName = 'Uami', Mandatory)][string]$IdentityResourceGroup,
    [Parameter(ParameterSetName = 'Vm', Mandatory)][string]$VmName,
    [Parameter(ParameterSetName = 'Vm', Mandatory)][string]$VmResourceGroup,
    [Parameter(ParameterSetName = 'Arc', Mandatory)][string]$ArcMachineName,
    [Parameter(ParameterSetName = 'Arc', Mandatory)][string]$ArcResourceGroup,
    # an app registration (certificate sign-in): its application (client) id; its service principal is found by that id
    [Parameter(ParameterSetName = 'AppId', Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$AppId,
    [string]$ConfigPath,
    # the subscription to work in; given, it wins over the config (the guided install passes its own answer)
    [string]$SubscriptionId,
    [string[]]$ReaderScopes,
    [string]$KeyVaultName,
    [switch]$AllowSchemaCreate,
    # #236: the asset-tagging plan (writes) instead of the read-only collection plan -- for asset tagging's own identity
    [switch]$Tagging,
    # #446: the Pro web app's own identity (uami-si-management): read-only Microsoft Graph for names, the people picker and
    # the enterprise application's role holders. Needs no config file; give -SubscriptionId with -IdentityName.
    [switch]$WebApp,
    [string[]]$TaggingScopes,
    # With -Tagging: only what the job needs to RUN and report (its licence -- give -KeyVaultName --, the rules' reads, its
    # activity rows, its run log) -- never the writes. What setup now grants every install; fix request 85bd728f.
    [switch]$ReportOnly,
    # A container install has no config file on the machine running this: give its values instead (each wins over the config).
    [string]$WorkspaceResourceId,
    [string]$StorageAccountName,
    [string]$StorageResourceGroup,
    [string]$DcrResourceGroup,
    # With -Tagging: the install's container registry (resource id) -- the job pulls its image as its own identity (AcrPull)
    [string]$AcrRegistryId,
    # Only the application permissions of the plan (Microsoft Graph, Defender): no Azure role is read or granted, and no
    # install configuration is needed -- for a change that was approved as exactly that.
    [switch]$OnlyAppPermissions,
    # Only these application permissions of the plan, by name (e.g. SecurityAlert.Read.All). Implies -OnlyAppPermissions.
    # A name that is not in the plan stops the run: nothing outside the plan is ever granted.
    [string[]]$Only,
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Grant-SIIdentity' -Quiet:($false)
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the plan: nothing is granted
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'container\_shared\SI-ContainerConfig.ps1')
# Azure over native REST, no PowerShell module (#305). An existing sign-in in this process (the guided install) is reused;
# otherwise a person signs in here (Azure Cloud Shell, or the browser) -- an account that may assign roles and
# application permissions.
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
if (-not (Get-Command -Name Invoke-SIGraphRequest -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-GraphRest.ps1')) }
# ALWAYS loaded (its API versions are script values of THIS script's scope): Invoke-SIRetryNotThereYet, used for a grant
# to an identity that is minutes old
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1'))
# Inside an Invardia Support session this signs in to nothing: the session is the sign-in and every change is recorded
# there (setup\_shared\SI-SetupAzure.ps1). A subscription the session does not name is refused before anything is read.
if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure }
if ($SubscriptionId -and (Get-Command -Name Assert-SISupportSubscription -ErrorAction SilentlyContinue)) { Assert-SISupportSubscription -SubscriptionId $SubscriptionId }
if (@($Only | Where-Object { $_ }).Count) { $OnlyAppPermissions = $true }

function Get-SIGrantShortError {
    <# The first line of a failure, without the request path, short enough for one result line. #>
    param($ErrorRecord)
    $m = ([string]$ErrorRecord.Exception.Message -split "`r?`n")[0]
    if ($m -match 'failed:\s*(.+)$') { $m = $Matches[1] }
    if ($m.Length -gt 240) { $m = $m.Substring(0, 240) }
    return $m.Trim()
}

# ---- the install's settings (workspace, DCR resource group, storage) -- not for the web app's identity ----
if ($WebApp) { $sub = if ($SubscriptionId) { $SubscriptionId } else { [string](Get-SISetupAzureContext).Subscription.Id } }
elseif ($OnlyAppPermissions) {
    # only application permissions: no install configuration is read, no Azure scope is needed
    $sub = if ($SubscriptionId) { $SubscriptionId } else { [string](Get-SISetupAzureContext).Subscription.Id }
    $ws = ''; $dcrRgId = ''; $stgId = ''; $kvId = ''
}
else {
if (-not $ConfigPath) { $ConfigPath = Join-Path $siRoot 'config\SecurityInsight.custom.ps1' }
if (Test-Path -LiteralPath $ConfigPath) { . $ConfigPath }
elseif (-not $WorkspaceResourceId) { throw "config not found: $ConfigPath (or give -WorkspaceResourceId and the other install values)" }
if ($WorkspaceResourceId) { $global:SI_WorkspaceResourceId = $WorkspaceResourceId }
if ($StorageAccountName) { $global:SI_StorageAccount = $StorageAccountName }
if ($StorageResourceGroup) { $global:SI_StorageResourceGroup = $StorageResourceGroup }
if ($DcrResourceGroup) { $global:SI_DcrResourceGroup = $DcrResourceGroup }
$ws = [string]$global:SI_WorkspaceResourceId
if (-not $ws) { throw 'SI_WorkspaceResourceId is not set in the config.' }
$sub = if ($SubscriptionId) { $SubscriptionId } elseif ($global:SI_AzSubscriptionId) { [string]$global:SI_AzSubscriptionId } else { ($ws -split '/')[2] }
$dcrRg = if ($global:SI_DcrResourceGroup) { [string]$global:SI_DcrResourceGroup } else { ($ws -split '/')[4] }
$dcrRgId = '/subscriptions/{0}/resourceGroups/{1}' -f $sub, $dcrRg
$stgId = ''
if ($global:SI_StorageAccount) {
    $stgRg = if ($global:SI_StorageResourceGroup) { [string]$global:SI_StorageResourceGroup } else { $dcrRg }
    $stgId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}' -f $sub, $stgRg, [string]$global:SI_StorageAccount
}
$kvId = ''
if ($KeyVaultName) {
    $kv = Get-SIKeyVault -VaultName $KeyVaultName -SubscriptionId $sub -ErrorAction SilentlyContinue
    if (-not $kv) { throw "Key Vault '$KeyVaultName' was not found (or is not readable from here)." }
    $kvId = [string]$kv.ResourceId
}
if (-not $ReaderScopes) { $ReaderScopes = @("/subscriptions/$sub") }
}

# ---- the identity ----
$principal = switch ($PSCmdlet.ParameterSetName) {
    'Principal' { $PrincipalId }
    'Uami'      { (Get-SIUserAssignedIdentity -ResourceGroupName $IdentityResourceGroup -Name $IdentityName -SubscriptionId $sub).PrincipalId }
    'Vm'        { $vm = Get-SIVirtualMachine -ResourceGroupName $VmResourceGroup -Name $VmName -SubscriptionId $sub
                  if (-not $vm.Identity -or -not $vm.Identity.principalId) { throw "VM '$VmName' has no system-assigned identity -- turn it on first (Azure portal: the VM -> Identity), or use -IdentityName for a user-assigned one." }
                  [string]$vm.Identity.principalId }
    'Arc'       { $m = Get-SIArmResource -ResourceId ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.HybridCompute/machines/{2}' -f $sub, $ArcResourceGroup, $ArcMachineName) -ApiVersion '2022-12-27'
                  [string]$m.Identity.principalId }
    'AppId'     { $sp = Find-SIGraphServicePrincipal -AppId $AppId
                  if (-not $sp -or -not $sp.id) { throw "No enterprise application (service principal) with the application id $AppId was found in this tenant." }
                  [string]$sp.id }
}
if ([string]::IsNullOrWhiteSpace($principal)) { throw 'The identity''s object (principal) id could not be resolved.' }
Write-Host ("SecurityInsight -- grants for the {2} {0} ({1})" -f $principal, $(if ($Apply) { 'applying' } else { 'checking only -- pass -Apply to grant' }), $(if ($PSCmdlet.ParameterSetName -eq 'AppId') { "app registration $AppId, service principal" } else { 'managed identity' }))

$plan = if ($WebApp) {
    Write-Host '  Plan: the PRO WEB APP (read-only Microsoft Graph: names, the people picker, the enterprise application''s role holders).'
    @(Get-SIWebAppIdentityGrantPlan)
} elseif ($Tagging) {
    # #236: asset tagging's OWN identity -- the write plan. Never the collection identity's plan widened.
    $tp = @(Get-SIAssetTaggingIdentityGrantPlan -ReaderScopes $ReaderScopes -TaggingScopes @($TaggingScopes | Where-Object { $_ }) `
        -DcrResourceGroupId $dcrRgId -WorkspaceResourceId $ws -StorageAccountId $stgId -LicenceKeyVaultId $kvId -AcrRegistryId $AcrRegistryId)
    if ($ReportOnly) {
        Write-Host '  Plan: ASSET TAGGING, REPORT ONLY (its licence, the rules'' reads, its activity rows and run log -- no writes) -- asset tagging''s own identity.' -ForegroundColor Yellow
        @($tp | Where-Object { -not $_.Write })
    } else {
        Write-Host '  Plan: ASSET TAGGING (writes Defender machine tags, Azure tags and Entra custom security attributes) -- use this only on asset tagging''s own identity.' -ForegroundColor Yellow
        $tp
    }
} else {
    @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ReaderScopes $ReaderScopes -DcrResourceGroupId $dcrRgId `
        -WorkspaceResourceId $ws -DefenderWorkspaceResourceId ([string]$global:SI_DefenderWorkspaceResourceId) -StorageAccountId $stgId `
        -OpenAIKeyVaultId $kvId)
}
if ($AllowSchemaCreate) {
    $plan += [pscustomobject]@{ Kind = 'AzureRole'; Role = 'Monitoring Contributor'; Scope = $dcrRgId; Why = 'the first run creates its data collection rules' }
    $plan += [pscustomobject]@{ Kind = 'AzureRole'; Role = 'Log Analytics Contributor'; Scope = $ws; Why = 'the first run creates its tables' }
}
if ($OnlyAppPermissions) {
    $plan = @($plan | Where-Object { $_.Kind -eq 'AppRole' })
    $names = @($Only | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if ($names.Count) {
        $known = @($plan | ForEach-Object { [string]$_.Role })
        $unknown = @($names | Where-Object { $known -notcontains $_ })
        if ($unknown.Count) {
            throw ('Not an application permission of this plan: {0}. Nothing was changed. The plan holds: {1}.' -f ($unknown -join ', '), (($known | Select-Object -Unique) -join ', '))
        }
        $plan = @($plan | Where-Object { $names -contains [string]$_.Role })
        Write-Host ('  Only these application permissions: {0}. Nothing else is read or granted.' -f ($names -join ', '))
    } else {
        Write-Host '  Only the application permissions of the plan. No Azure role is read or granted.'
    }
}

$tasks = New-Object System.Collections.Generic.List[string]
$missing = 0
foreach ($g in @($plan | Where-Object { $_.Kind -eq 'AzureRole' })) {
    $have = @(Get-SIAzRoleAssignment -ObjectId $principal -Scope $g.Scope -RoleDefinitionName $g.Role -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $g.Scope })
    $state = if ($have.Count) { 'present' } elseif ($Apply) {
        try { New-SIRoleAssignment -ObjectId $principal -Scope $g.Scope -RoleDefinitionName $g.Role -PrincipalType ServicePrincipal -ErrorAction Stop | Out-Null; 'granted' }
        catch { if ($_.Exception.Message -match 'Conflict|already exists') { 'present' } else { $missing++; 'FAILED' } }
    } else { $missing++; 'MISSING' }
    Write-Host ('  [{0,-7}] {1,-34} on {2}' -f $state, $g.Role, $g.Scope)
    if ($state -in 'FAILED', 'MISSING') {
        $tasks.Add(('# {0}' -f $g.Why))
        # #564: a portal path, never an az command (a customer has no az CLI); the guided install reads this line format
        $tasks.Add(('# Azure role "{1}" on "{2}" for the managed identity {0} -- Azure portal: open the scope > Access control (IAM) > Add > Add role assignment > {1} > Managed identity' -f $principal, $g.Role, $g.Scope))
    }
}

$appRoles = @($plan | Where-Object { $_.Kind -eq 'AppRole' })
if ($appRoles.Count) {
    # Microsoft Graph over REST as the signed-in account (setup\_shared\SI-GraphRest.ps1)
    $assigned = @()
    try { $assigned = @(Get-SIGraphAppRoleAssignments -ServicePrincipalId $principal) }
    catch { Write-Warning ('The application permissions the identity holds now could not be read ({0}) -- each one below is treated as missing.' -f (Get-SIGrantShortError $_)) }
    # 1. what is there now, read only: per permission present / missing / not in this tenant
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($grp in ($appRoles | Group-Object ResourceAppId)) {
        $res = $null; $looked = $false
        try { $res = Find-SIGraphServicePrincipal -AppId $grp.Name; $looked = $true } catch { }
        foreach ($g in $grp.Group) {
            $role = if ($res) { @($res.appRoles | Where-Object { $_.value -eq $g.Role })[0] } else { $null }
            # The API is not in this tenant at all (live 2026-10-06, Community rehearsal: no Defender for Endpoint, so no
            # WindowsDefenderATP service principal): there is nothing to grant and nothing to read -- not a missing grant,
            # which would hold the first run back for ever with a command that cannot work.
            $before = if ($looked -and -not $res) { 'ABSENT' }
                      elseif (-not $role) { 'UNKNOWN' }
                      elseif ($assigned | Where-Object { $_.appRoleId -eq $role.id -and $_.resourceId -eq $res.id }) { 'present' }
                      else { 'MISSING' }
            $rows.Add([pscustomobject]@{ Grant = $g; Resource = $res; Role = $role; Before = $before })
        }
    }
    if ($Apply) {
        Write-Host '  Application permissions -- the plan:'
        foreach ($r in $rows) {
            $what = switch ($r.Before) {
                'present' { 'present' }
                'MISSING' { 'missing -- will be granted' }
                'ABSENT'  { 'not in this tenant -- nothing to grant' }
                default   { 'not found on the API -- cannot be granted' }
            }
            Write-Host ('    {0,-40} {1}: {2}' -f $r.Grant.Role, $r.Grant.Resource, $what)
        }
        Write-Host '  Application permissions -- the result:'
    }
    # 2. the result per permission; only what is missing is granted, and only with -Apply
    foreach ($r in $rows) {
        $g = $r.Grant; $why = ''
        $state = if ($r.Before -eq 'ABSENT') { 'ABSENT' }
                 elseif ($r.Before -eq 'UNKNOWN') { $missing++; 'UNKNOWN' }
                 elseif ($r.Before -eq 'present') { 'present' }
                 elseif ($Apply) {
                     try {
                         $__siGrant = $r
                         Invoke-SIRetryNotThereYet -Waits @(10, 20, 30, 45, 60, 75) -Action { New-SIGraphAppRoleAssignment -ServicePrincipalId $principal -ResourceId $__siGrant.Resource.id -AppRoleId $__siGrant.Role.id } | Out-Null
                         # (the retry above: an identity made minutes ago is not known to every part of the directory yet --
                         # "not found" on ITS id is "not there yet" and is tried again, about 4 minutes; a refusal stops at
                         # once and is the reason shown. The grant itself stays right under -Apply.)
                         'granted'
                     }
                     catch {
                         $why = Get-SIGrantShortError $_
                         # it was there already (its read was refused, or someone granted it meanwhile): present, not a failure
                         if ($why -match '(?i)already exists') { $why = ''; 'present' } else { $missing++; 'FAILED' }
                     }
                 } else { $missing++; 'MISSING' }
        $tail = ''
        if ($state -eq 'ABSENT') { $tail = ' -- not in this tenant: nothing to grant, SecurityInsight reads nothing from it' }
        elseif ($state -eq 'FAILED' -and $why) { $tail = ' -- not granted: ' + $why }
        Write-Host ('  [{0,-7}] {1,-40} ({2}){3}' -f $state, $g.Role, $g.Resource, $tail)
        if ($state -in 'FAILED', 'MISSING', 'UNKNOWN') {
            $tasks.Add(('# API permission {0} on {1} (an Entra admin: Enterprise applications -> the identity -> Permissions, or AppRoleAssignment.ReadWrite.All)' -f $g.Role, $g.Resource))
        }
    }
}

if ($missing) {
    Write-Warning ('{0} grant(s) missing. SecurityInsight fails on what is missing -- re-run with -Apply, or hand these to someone with rights there:' -f $missing)
    foreach ($t in $tasks) { Write-Host ('  ' + $t) -ForegroundColor Yellow }
} else { Write-Host '  All grants present.' -ForegroundColor Green }
Write-Host ''
if ($PSCmdlet.ParameterSetName -ne 'AppId') { Write-Host '  In config\SecurityInsight.custom.ps1:  $global:SI_AuthMethod = ''ManagedIdentity''  (and $global:SI_ManagedIdentityClientId for a user-assigned identity)' }
exit [int]($missing -gt 0)
} finally { Stop-SIScriptRun -Run $siRun }
