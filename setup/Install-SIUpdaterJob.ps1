<#
.SYNOPSIS
    Create or update caj-si-updater: the nightly job that keeps a CONTAINER-hosted SecurityInsight on the
    version its update ring approves (#160, operator ruling 2026-09-29: "Updater job").

.DESCRIPTION
    Shows what it would do by default; -Apply makes the changes. Idempotent -- re-running updates in place.

      1. builds the updater image (container/updater) in the customer's registry: si-updater:v<VERSION>;
      2. ensures a user-assigned identity (uami-si-updater) that Container Apps uses ONLY to resolve the two
         Key Vault-referenced secrets and to pull the image -- every Azure action the updater takes is done
         as the SPN, by certificate;
      3. creates or updates the job: scheduled, one replica, the SPN's certificate as a Key Vault REFERENCE (or none
         with -UseManagedIdentity; this script never reads or passes a secret value), the customer's own hosting values
         and the update ring (-UpdateRing -> SI_UPDATER_RING) as environment.

    ONE SOURCE: Invardia's platform (operator 2026-10-06: "one solution: invardia"; framework UPDATE-1.7). SecurityInsight's
    own update feed (a storage container + read-only link, channel.json) is RETIRED: -Source feed and -SourceUrlSecretName
    are refused, and a job that still carries the feed link (SI_UPDATER_SOURCE_URL + secret src-url) has both removed.

    The SPN needs rights to build in the registry and to update the SI jobs. -GrantSpnRoles assigns
    Contributor on the registry and on the resource group; without it the script prints what is required.
    The job also requests and renews the install's licence from Invardia (#239): SI_UPDATER_KEY_VAULT names the vault
    that holds SI-License, the pull token and the request state, and -GrantSpnRoles gives the SPN Key Vault Secrets
    Officer there. The image is built with the SecurityInsight folder as its context (it carries the licence client).

    Pro database (#352): an update applies the release's database schema and the grants its code needs BEFORE it rolls any
    code, so the updater's identity needs db_datareader, db_datawriter, db_ddladmin and db_securityadmin on the Pro database.
    -GrantSql gives them (setup\Grant-SIUpdaterDatabase.ps1 -Apply, run as YOU -- the SQL server's Entra admin); without it
    the script prints the exact command. Until the identity has them, an update stops before rolling anything and says why.

    The job takes code and template packs from Invardia's signed manifests for ITS ring (#240, UPDATE-1.7); the install key
    (claimed automatically when missing) and the update state live in -KeyVaultName, which the identity reads and writes
    (-GrantSpnRoles: Key Vault Secrets Officer).

    The secret hand-over: the Pro web app never writes a secret -- it hands a pasted secret to the updater encrypted, and the
    updater stores it. -GrantSpnRoles therefore also gives the identity Key Vault Crypto Officer on the vault (its hand-over
    key is created and used there, never exported), and removes the web app's Key Vault Secrets Officer at exactly the vault
    (the grant SecurityInsight's Get Started once asked for) -- no other assignment is touched.

.EXAMPLE
    .\Install-SIUpdaterJob.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> -AcrName <acr> -EnvName <cae> `
        -KeyVaultName <kv> -TenantId <tenant> -UseManagedIdentity -UpdateRing 2 -ProSqlServer <server> -ProSqlDatabase <db> -Apply
.EXAMPLE
    .\Install-SIUpdaterJob.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> -AcrName <acr> -EnvName <cae> `
        -KeyVaultName <kv> -CertSecretName <kv secret holding the SPN PFX> -SpnClientId <appId> -TenantId <tenant> -UpdateRing 3 -Apply

.LINK
    https://invardia.com/docs/si/scripts/Install-SIUpdaterJob/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$AcrName,
    [Parameter(Mandatory)][string]$EnvName,
    [Parameter(Mandatory)][string]$KeyVaultName,
    [string]$CertSecretName,                                   # KV secret holding the SPN PFX (not with -UseManagedIdentity)
    # RETIRED (2026-10-06): SI's own update feed. Kept only to refuse it clearly -- Pro updates come only from Invardia.
    [string]$SourceUrlSecretName,
    # #240: where releases come from -- invardia (Pro) or community (#750 (b): the signed Community channel; the Community
    # edition's default, chosen by itself when this copy has no Invardia client). 'feed' is refused: the feed is retired.
    [ValidateSet('invardia', 'community', 'feed')][string]$Source = 'invardia',
    [string]$SpnClientId,                                      # the SPN's app id (not with -UseManagedIdentity)
    [Parameter(Mandatory)][string]$TenantId,
    # 18:30 in the LOCAL time of the install's Azure region (owner 2026-10-21), as the zone's UTC ticks -- e.g. westeurope
    # '30 16,17 * * *' (summer + winter), westus '30 1,2 * * *'; the updater ends the tick that is not 18:30 there
    # (setup/_shared/SI-NightlySchedule.ps1). Not given: computed from -Region, else from the location of the Container Apps
    # environment (-EnvName), else of the resource group; a region not known = Danish time, said in one line. The job records
    # the zone (tags si-nightly-schedule + si-nightly-region + si-nightly-1900), so the update's one-time steps have nothing to move. A -Schedule
    # given is a timer of your own (no tags). The daily pipeline starts after it, 19:00 in the same zone.
    [string]$Schedule   = '',
    [string]$Region     = '',
    # #350 / UPDATE-1.7: the update ring this environment pulls for (SI_UPDATER_RING, 0-3) -- daily, like every ring.
    # -1 = not set: the updater uses the ring recorded for the install (cfg.InstallState 'Ring'); none = no pull.
    [ValidateRange(-1, 9)][int]$UpdateRing = -1,
    # Pro: the settings database the updater reads the customer's switches from and records its state in (the header shows it)
    [string]$ProSqlServer,
    [string]$ProSqlDatabase,
    [string]$Block      = '',                    # capabilities this customer blocks, e.g. 'engine-image'
    [string]$JobName    = 'caj-si-updater',
    [string]$IdentityName = 'uami-si-updater',
    # the Pro web app (its old Key Vault right is removed with -GrantSpnRoles: it hands secrets to the updater now)
    [string]$WebAppName = 'ca-si-management',
    # the Pro MCP server (CR5 step 1: recorded on the job with the web app's and the job's own name, SI_UPDATER_MCP_APP)
    [string]$McpAppName = 'ca-si-mcp',
    # #350 / #222: the job signs in as its own user-assigned identity (uami-si-updater) -- no certificate in the vault, as PIM's
    # ca-pim-update. -GrantSpnRoles then grants the IDENTITY what the SPN would get.
    [switch]$UseManagedIdentity,
    [switch]$GrantSpnRoles,
    # #352: give the updater's identity its database rights on the Pro database (as the caller -- the server's Entra admin)
    [switch]$GrantSql,
    # an EXISTING job keeps the image it runs (it rolls itself to the version its ring approves); -Image sets one on purpose
    # (a full reference, or a tag of si-updater in the registry). A new job gets the image this setup builds.
    [string]$Image,
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Install-SIUpdaterJob' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: no image, identity, role or job is created
try {

$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent $PSScriptRoot
$sub = $SubscriptionId

function Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "    $m" }

# #521: Azure over ARM REST only -- no az CLI. setup's own sign-in (an existing one in this process is reused; else a person
# signs in -- Cloud Shell or the browser; an Invardia support session gives its tokens). Loaded only when -Apply needs it.
function Initialize-SIUpdaterJobRest {
    if (-not (Get-Command -Name Connect-SISetupAzure -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
    # ALWAYS loaded (#616): its API versions are script values, and this script has its own script scope even when the
    # guided install that started it has the functions already
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1'))
    if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure -TenantId $TenantId -SubscriptionId $sub }
}
function Grant-SIUpdaterJobRole {
    <# One role assignment, made only when missing. A failure does not stop the rest of the setup (the job is still made),
       but it is COUNTED ($script:SIUpdaterGrantsFailed): the run says at its end which rights are missing and ends in an
       error -- an updater without them fails at night, so "installed" would be untrue. #>
    param([Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][string]$Scope)
    try {
        if (Test-SIRoleAssignmentPresent -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $Role) { return 'present' }
        $null = New-SIRoleAssignment -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $Role -PrincipalType ServicePrincipal
        'granted'
    } catch {
        # granted by someone else in the meantime (or the read missed it): there, not a failure
        if ("$($_.Exception.Message)" -match '(?i)RoleAssignmentExists|already exists') { return 'present' }
        Write-Warning ("{0} on {1} for {2} was not granted: {3}" -f $Role, $Scope, $ObjectId, $_.Exception.Message)
        $script:SIUpdaterGrantsFailed.Add(('{0} on {1}' -f $Role, ($Scope -split '/')[-1]))
        'FAILED'
    }
}
$script:SIUpdaterGrantsFailed = New-Object System.Collections.Generic.List[string]

function Invoke-SIUpdaterDirectoryRead {
    <# The updater identity's read access to the directory (Microsoft Graph Directory.Read.All) through Grant-SIIdentity -Only
       (its plan, only what is missing, read back). NEVER throws, never counted as a missing right of the updater: one plain
       line. -Grant: the test seam { param($PrincipalId, $SubscriptionId) } -> the grant script's exit code. #>
    param([Parameter(Mandatory)][string]$PrincipalId, [string]$SubscriptionId, [scriptblock]$Grant)
    $ok = 'directory read (Directory.Read.All) for the tenant size -- present'
    $no = 'directory read (Directory.Read.All) could NOT be given from this sign-in -- the updater then sizes the jobs for a large tenant. An Entra administrator can give it: .\setup\Grant-SIIdentity.ps1 -PrincipalId {0} -Only Directory.Read.All -Apply'
    try {
        if (-not $Grant) {
            $Grant = {
                param($p, $s)
                $a = @{ PrincipalId = $p; Only = @('Directory.Read.All'); Apply = $true }
                if ($s) { $a.SubscriptionId = $s }
                $null = & ([IO.Path]::Combine($PSScriptRoot, 'Grant-SIIdentity.ps1')) @a *>&1
                $LASTEXITCODE
            }
        }
        $code = & $Grant $PrincipalId $SubscriptionId
        if ([int]$code -eq 0) { return $ok }
        return ($no -f $PrincipalId)
    } catch { return (($no -f $PrincipalId) + (' ({0})' -f $_.Exception.Message)) }
}

function Remove-SIUpdaterJobWebSecretGrant {
    <#
        The secret hand-over: the Pro web app never writes a secret any more (it hands it to the updater), so the ONE grant
        SecurityInsight's own Get Started asked a customer to make -- "Key Vault Secrets Officer" for the web app's identity at
        EXACTLY the vault -- is removed (container/updater/_shared/SI-UpdaterSecretHandover.ps1 Select-SIWebSecretGrant: no
        inherited assignment, no other scope, role or identity). A failure is a line, never the end of the run.
    #>
    param([Parameter(Mandatory)][string]$VaultId)
    $ho = [IO.Path]::Combine($solRoot, 'container', 'updater', '_shared', 'SI-UpdaterSecretHandover.ps1')
    if (-not (Test-Path -LiteralPath $ho)) { return }
    try {
        if (-not (Get-Command -Name Select-SIWebSecretGrant -ErrorAction SilentlyContinue)) { . $ho }
        $app = Get-SIContainerApp -ResourceGroupName $ResourceGroupName -Name $WebAppName -SubscriptionId $sub
        if (-not $app -or -not $app.identity) { return }
        $ids = @()
        if ($app.identity.PSObject.Properties['principalId'] -and $app.identity.principalId) { $ids += [string]$app.identity.principalId }
        if ($app.identity.PSObject.Properties['userAssignedIdentities'] -and $app.identity.userAssignedIdentities) {
            foreach ($p in @($app.identity.userAssignedIdentities.PSObject.Properties)) { if ($p.Value -and $p.Value.principalId) { $ids += [string]$p.Value.principalId } }
        }
        foreach ($principal in @($ids | Select-Object -Unique)) {
            $list = @(Invoke-SIArm -Path ($VaultId.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments?$filter=' + [uri]::EscapeDataString(("principalId eq '{0}'" -f $principal))) -ApiVersion '2022-04-01' -List)
            foreach ($a in @(Select-SIWebSecretGrant -Assignments $list -PrincipalId $principal -VaultId $VaultId)) {
                $null = Invoke-SIArm -Method DELETE -Path ([string]$a.id) -ApiVersion '2022-04-01' -AllowNotFound
                Info ("{0}: Key Vault Secrets Officer on {1} removed -- the web app hands secrets to the updater and needs no Key Vault right" -f $WebAppName, $KeyVaultName)
            }
        }
    } catch { Write-Warning ("the web app's old Key Vault right could not be checked or removed: {0}" -f $_.Exception.Message) }
}

$version = (Get-Content -LiteralPath (Join-Path $solRoot 'VERSION') -Raw).Trim()
# SI's own update feed is RETIRED (2026-10-06: "one solution: invardia"): Pro updates come only from Invardia.
if ($Source -eq 'feed' -or "$SourceUrlSecretName".Trim()) {
    throw 'SecurityInsight''s own update feed is retired -- Pro updates come only from Invardia''s platform. Run this without -Source feed / -SourceUrlSecretName (the default is Invardia); a job that still has the feed link gets it removed.'
}
if (-not $UseManagedIdentity -and (-not "$CertSecretName".Trim() -or -not "$SpnClientId".Trim())) { throw 'Sign-in by certificate needs -CertSecretName and -SpnClientId (or pass -UseManagedIdentity).' }
# #750 (b): WHICH UPDATE PATH this copy carries -- the Invardia client (SecurityInsight Pro), else the signed Community channel.
# A Pro copy is never set up on the community channel (it would replace Pro with the Community edition).
$hasInvardia = Test-Path -LiteralPath (Join-Path $solRoot 'container/updater/_shared/SI-UpdaterInvardia.ps1')
$hasCommunity = (Test-Path -LiteralPath (Join-Path $solRoot 'container/updater/_shared/SI-UpdaterCommunity.ps1')) -and (Test-Path -LiteralPath (Join-Path $solRoot 'engine/_shared/SI-CommunityUpdate.ps1'))
if ($hasInvardia -and $Source -eq 'community') { throw 'this copy is SecurityInsight Pro: its updater takes its releases from Invardia, never from the public Community channel. Run this without -Source community.' }
if (-not $hasInvardia) {
    if (-not $hasCommunity) { throw 'this copy carries no update client (neither the Invardia client of SecurityInsight Pro nor the signed Community client) -- use a newer release.' }
    $Source = 'community'
}
if ($UpdateRing -gt 3) { throw "-UpdateRing $UpdateRing is not an update ring (0-3)." }
# the Community channel has rings 2 (early release) and 3 (broad); none given = 3
if ($Source -eq 'community') {
    if ($UpdateRing -lt 0) { $UpdateRing = 3 }
    elseif ($UpdateRing -lt 2) { throw "-UpdateRing $UpdateRing is not a Community ring (2 = early release, 3 = broad)." }
}
# -Image is kept apart: PowerShell names are case-blind, and $image below is the image this setup builds
$explicitImage = [string]$Image
# the nightly schedule: 18:30 in the local time of the install's Azure region (SI-NightlySchedule.ps1, pure)
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-NightlySchedule.ps1'))
$ownSchedule = [bool]"$Schedule".Trim()
$nightly = $null; $nightlyTags = @()
if (-not $ownSchedule -and "$Region".Trim()) { $nightly = Get-SINightlyNewInstallSchedule -Region $Region; $Schedule = $nightly.UpdaterCron; $nightlyTags = @($nightly.UpdaterTagArgs) }
Step 'Plan'
if ($ownSchedule) { Info ("job {0} in {1} (environment {2}), schedule '{3}' UTC (-Schedule: a timer of your own)" -f $JobName, $ResourceGroupName, $EnvName, $Schedule) }
elseif ($nightly) { Info ("job {0} in {1} (environment {2}), daily at {3} -- '{4}' UTC" -f $JobName, $ResourceGroupName, $EnvName, (Get-SINightlyScheduleText -Zone $nightly.Zone -Known $nightly.Known), $Schedule) }
else { Info ("job {0} in {1} (environment {2}), daily at 23:00 in the local time of the install's Azure region (read from the environment when applied)" -f $JobName, $ResourceGroupName, $EnvName) }
Info ("image: {0} -- pulled with identity {1}" -f $(if ("$Image".Trim()) { "$Image (-Image)" } else { ('a NEW job gets {0}.azurecr.io/si-updater:v{1}; an EXISTING job keeps the image it runs (never moved back to this version)' -f $AcrName, $version) }), $IdentityName)
if ($UseManagedIdentity) { Info ("sign-in: the job's managed identity {0} -- no certificate" -f $IdentityName) }
else { Info ("secret by Key Vault reference: {0}/{1} (SPN certificate)" -f $KeyVaultName, $CertSecretName) }
if ($Source -eq 'community') { Info 'update source: Invardia''s signed Community channel (GET https://invardia.com/api/updates/securityinsight/community/<ring>, anonymous; the release zip checked by size and SHA-256) -- no install key, no licence request' }
else { Info ("update source: Invardia -- the install key (SI-Invardia-InstallKey, claimed automatically when missing) and the update state are read from {0} at run time" -f $KeyVaultName) }
if ($Block) { Info "customer blocks: $Block" }
if ($UpdateRing -ge 0) { Info ("update ring {0} (SI_UPDATER_RING): every run asks Invardia for what SecurityInsight released to ring {0}; the signed manifest must name ring {0} (UPDATE-1.7)" -f $UpdateRing) }
else { Info 'no -UpdateRing: the updater uses the ring recorded for the install (cfg.InstallState ''Ring'', or Update ring on the Settings page); with none recorded it asks Invardia for NOTHING (UPDATE-1.7: SecurityInsight decides the ring)' }
if ($ProSqlServer -and $ProSqlDatabase) { Info ("Pro database: {0}/{1} -- every update applies the release's schema and grants there first; the updater's identity needs db_datareader, db_datawriter, db_ddladmin and db_securityadmin ({2})" -f $ProSqlServer, $ProSqlDatabase, $(if ($GrantSql) { 'given by -GrantSql' } else { 'pass -GrantSql, or run setup\Grant-SIUpdaterDatabase.ps1 -Apply once' })) }
if (-not $Apply) {
    Info 'Nothing changed. Re-run with -Apply to create or update the job.'
    if (-not $GrantSpnRoles -and $UseManagedIdentity) { Info ("The identity {0} needs Contributor on registry {1} and resource group {2}, and Key Vault Secrets Officer and Key Vault Crypto Officer on {3} (or pass -GrantSpnRoles)." -f $IdentityName, $AcrName, $ResourceGroupName, $KeyVaultName) }
    elseif (-not $GrantSpnRoles) { Info ("The SPN {0} needs Contributor on registry {1} and on resource group {2} (or pass -GrantSpnRoles)." -f $SpnClientId, $AcrName, $ResourceGroupName) }
    exit 0
}

. Initialize-SIUpdaterJobRest
if (-not $ownSchedule -and -not $nightly) {
    # the install's Azure region: the Container Apps environment's location, else the resource group's
    $loc = ''
    try { $e0 = Get-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $EnvName -SubscriptionId $sub; if ($e0 -and $e0.PSObject.Properties['location']) { $loc = [string]$e0.location } } catch { }
    if (-not $loc.Trim()) { try { $g0 = Get-SIResourceGroupArm -Name $ResourceGroupName -SubscriptionId $sub; if ($g0 -and $g0.PSObject.Properties['location']) { $loc = [string]$g0.location } } catch { } }
    $nightly = Get-SINightlyNewInstallSchedule -Region $loc; $Schedule = $nightly.UpdaterCron; $nightlyTags = @($nightly.UpdaterTagArgs)
}
if ($nightly) {
    if ($nightly.Line) { Info $nightly.Line }
    Info ("nightly update: daily at {0} -- '{1}' UTC" -f (Get-SINightlyScheduleText -Zone $nightly.Zone -Known $nightly.Known), $Schedule)
}
Step '1. Build the updater image'
$acr = Get-SIContainerRegistry -ResourceGroupName $ResourceGroupName -Name $AcrName -SubscriptionId $sub
if (-not $acr) { throw ("the registry '{0}' was not found in resource group '{1}' (subscription {2})." -f $AcrName, $ResourceGroupName, $sub) }
$image = '{0}/si-updater:v{1}' -f $acr.loginServer, $version
# an existing job keeps the image it runs (a re-run for the role grants must never downgrade a self-rolled updater)
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterJobPlan.ps1')
$existing = Get-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $JobName -SubscriptionId $sub
$imgPlan = Resolve-SIUpdaterJobImage -Existing $existing -Default $image -Explicit $explicitImage -LoginServer ([string]$acr.loginServer)
Info $imgPlan.Why
if (-not $imgPlan.Build) { $image = [string]$imgPlan.Image; Info 'no build: the job keeps its image' } else {
# The SecurityInsight folder is the context: the licence request step (#239) carries its client from engine/ and setup/.
# The registry builds it (ACR Tasks over ARM REST: pack + upload + scheduleRun + poll; the .dockerignore honoured); .NET reads
# long paths, so a deep install path needs no short copy any more. The image name is relative to the registry.
$build = Invoke-SIAcrRestBuild -SubscriptionId $sub -ResourceGroup $ResourceGroupName -RegistryName $AcrName -SourcePath $solRoot `
            -ImageNames @("si-updater:v$version") -DockerFilePath 'container/updater/Dockerfile' -OnPoll { param($s) Info ("build: {0}" -f $s) }
if (-not $build.Ok) { throw ("the updater image build did not succeed (run {0}: {1})." -f $build.RunId, $build.Status) }
Info "built $image"
$image = [string]$imgPlan.Image
}

Step '2. Identity for secret references and image pull'
$uami = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -SubscriptionId $sub -ErrorAction SilentlyContinue
if (-not $uami) {
    $uami = New-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -Location ([string]$acr.location) -SubscriptionId $sub
    Info "created $IdentityName"
}
$kv = Get-SIKeyVaultArm -Name $KeyVaultName -SubscriptionId $sub
if (-not $kv) { throw ("the Key Vault '{0}' was not found in subscription {1} (or is not readable from here)." -f $KeyVaultName, $sub) }
foreach ($ra in @(@('Key Vault Secrets User', [string]$kv.id), @('AcrPull', [string]$acr.id))) {
    $state = Grant-SIUpdaterJobRole -ObjectId ([string]$uami.PrincipalId) -Role $ra[0] -Scope $ra[1]
    Info ("{0}: {1} ({2})" -f $IdentityName, $ra[0], $state)
}
if ($UseManagedIdentity) { $SpnClientId = [string]$uami.ClientId }
if ($GrantSpnRoles -and $UseManagedIdentity) {
    $rgId = [string](Get-SIResourceGroupArm -Name $ResourceGroupName -SubscriptionId $sub).id
    # Key Vault Crypto Officer: the secret hand-over key (created, read, decrypt inside the vault -- the web app writes no secret)
    foreach ($ra in @(@('Contributor', [string]$acr.id), @('Contributor', $rgId), @('Key Vault Secrets Officer', [string]$kv.id), @('Key Vault Crypto Officer', [string]$kv.id))) {
        $null = Grant-SIUpdaterJobRole -ObjectId ([string]$uami.PrincipalId) -Role $ra[0] -Scope $ra[1]
    }
    if (-not $script:SIUpdaterGrantsFailed.Count) { Info "$IdentityName`: Contributor on the registry and the resource group, Key Vault Secrets Officer and Key Vault Crypto Officer on $KeyVaultName" }
    else { Info ("{0}: NOT every right could be given -- missing: {1}" -f $IdentityName, ($script:SIUpdaterGrantsFailed.ToArray() -join '; ')) }
    Remove-SIUpdaterJobWebSecretGrant -VaultId ([string]$kv.id)
    # Owner 2026-10-17: the updater reads the tenant's size (users, groups, devices, service principals) to size the jobs.
    # Its identity gets READ access to the directory here -- one read-only Microsoft Graph permission, Directory.Read.All,
    # through the same grant step as the jobs' identity (Grant-SIIdentity -Only: nothing outside its plan, read back, only
    # what is missing). Without it the update sizes the jobs for a large tenant, so this never stops the setup.
    $dirRead = Invoke-SIUpdaterDirectoryRead -PrincipalId ([string]$uami.PrincipalId) -SubscriptionId $sub
    Info ("{0}: {1}" -f $IdentityName, $dirRead)
} elseif ($GrantSpnRoles) {
    $rgId = [string](Get-SIResourceGroupArm -Name $ResourceGroupName -SubscriptionId $sub).id
    # the SPN is named by its app (client) id: its service principal's object id is what a role assignment names
    $spnOid = Resolve-SIPrincipalObjectId -Id $SpnClientId
    foreach ($scope in @([string]$acr.id, $rgId)) { $null = Grant-SIUpdaterJobRole -ObjectId $spnOid -Role 'Contributor' -Scope $scope }
    Info "SPN $SpnClientId`: Contributor on the registry and the resource group"
    # #239: the licence request step keeps its pull token and state in the vault and installs SI-License there.
    $null = Grant-SIUpdaterJobRole -ObjectId $spnOid -Role 'Key Vault Secrets Officer' -Scope ([string]$kv.id)
    Info "SPN $SpnClientId`: Key Vault Secrets Officer on $KeyVaultName (licence requests)"
    # the secret hand-over key: created, read and used (decrypt) inside the vault by the updater
    $null = Grant-SIUpdaterJobRole -ObjectId $spnOid -Role 'Key Vault Crypto Officer' -Scope ([string]$kv.id)
    Info "SPN $SpnClientId`: Key Vault Crypto Officer on $KeyVaultName (the secret hand-over key)"
    Remove-SIUpdaterJobWebSecretGrant -VaultId ([string]$kv.id)
}

Step '3. Create or update the job'
$secretArgs = @()
if (-not $UseManagedIdentity) { $secretArgs += ("cert-pfx=keyvaultref:{0}secrets/{1},identityref:{2}" -f $kv.properties.vaultUri, $CertSecretName, $uami.id) }
$envArgs = @(
    "SI_UPDATER_TENANT_ID=$TenantId", "SI_UPDATER_CLIENT_ID=$SpnClientId", "SI_UPDATER_SUBSCRIPTION_ID=$sub",
    "SI_UPDATER_RESOURCE_GROUP=$ResourceGroupName", "SI_UPDATER_ACR=$AcrName", "SI_UPDATER_BLOCK=$Block",
    "SI_UPDATER_KEY_VAULT=$KeyVaultName", "SI_UPDATER_SOURCE=$Source"
)
if ($UseManagedIdentity) { $envArgs += 'SI_UPDATER_AUTH=ManagedIdentity' } else { $envArgs += 'SI_UPDATER_CERT_PFX_B64=secretref:cert-pfx' }
if ($UpdateRing -ge 0) { $envArgs += "SI_UPDATER_RING=$UpdateRing" }
if ($ProSqlServer -and $ProSqlDatabase) { $envArgs += @("SI_UPDATER_PRO_SQL_SERVER=$ProSqlServer", "SI_UPDATER_PRO_SQL_DATABASE=$ProSqlDatabase") }
# CR5 step 1 (framework section 12.11c item 6, #655): the names of the install's own web app, MCP server and this job, on the job --
# the updater records them in the install record (cfg.InstallState 'InstallNames') and every lookup reads them from there,
# never a literal. Today's names by default: an existing install records exactly what it runs with.
$envArgs += @("SI_UPDATER_WEB_APP=$WebAppName", "SI_UPDATER_MCP_APP=$McpAppName", "SI_UPDATER_JOB_NAME=$JobName")
if (-not $existing) {
    # the job definition as `az containerapp job create` arguments, translated to the ARM resource and PUT whole
    # (New-SIContainerAppJobFromArgs -> ConvertFrom-SIJobCreateArgs: an unknown flag is refused, never dropped)
    $cae = Get-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $EnvName -SubscriptionId $sub
    if (-not $cae) { throw ("the Container Apps environment '{0}' was not found in resource group '{1}'." -f $EnvName, $ResourceGroupName) }
    $createArgs = @('containerapp', 'job', 'create', '--name', $JobName, '--resource-group', $ResourceGroupName,
        '--environment', [string]$cae.id, '--trigger-type', 'Schedule', '--cron-expression', $Schedule, '--replica-timeout', '86400',
        '--replica-retry-limit', '0', '--parallelism', '1', '--replica-completion-count', '1',
        '--image', $image, '--registry-server', $acr.loginServer, '--registry-identity', [string]$uami.Id, '--mi-user-assigned', [string]$uami.Id,
    # the updater's size: 4 CPU / 8 GiB (owner 2026-10-10 -- the registry build ran out of memory on 0.5 CPU / 1 GiB)
        '--cpu', '4.0', '--memory', '8Gi') + $(if ($nightlyTags.Count) { @('--tags') + $nightlyTags } else { @() }) + $(if ($secretArgs.Count) { @('--secrets') + $secretArgs } else { @() }) + @('--env-vars') + $envArgs
    $null = New-SIContainerAppJobFromArgs -CreateArgs $createArgs -Location ([string]$cae.location) -EnvironmentId ([string]$cae.id) -SubscriptionId $sub
    Info "created $JobName"
} else {
    # UPDATE-1.6: the updater runs on its OWN daily schedule. An earlier switch to the pipeline could turn it to manual (it
    # was a pipeline step then) -- it gets its timer back here: a PATCH of only the trigger + tags (the remembered-timer tag
    # removed), never the secrets, BEFORE the update below (which sets a cron only on a Schedule job).
    if ($existing.PSObject.Properties['properties'] -and $existing.properties.configuration -and [string]$existing.properties.configuration.triggerType -eq 'Manual') {
        . (Join-Path $solRoot 'engine/_shared/SI-JobFlow.ps1')
        $body = ConvertTo-SIArmJobTrigger -Job $existing -Action 'to-schedule' -Cron $Schedule
        $null = Invoke-SIArm -Method PATCH -Path ([string]$existing.id) -ApiVersion '2025-07-01' -Body $body
        Info ("{0} had no timer ({1}) -- it runs on its own daily schedule again: '{2}' UTC" -f $JobName, [string]$existing.properties.configuration.triggerType, $Schedule)
    }
    # #171: an updater installed before 3.0.0 carried a GitHub token; #240 / feed retired 2026-10-06: a job that still carries
    # the feed link. Their env vars and secrets go -- in the SAME whole-job write as the update (READ-MODIFY-WRITE: the job is
    # read, its secret values read back, the changes applied, ONE PUT), so no secret is ever left referenced. Absent = nothing.
    $legacyEnv = @('SI_UPDATER_GITHUB_TOKEN', 'SI_UPDATER_REPO', 'SI_UPDATER_SOURCE_REF', 'SI_UPDATER_SOURCE_URL')
    $haveEnv = @()
    $containers = @($existing.properties.template.containers | Where-Object { $_ })
    if ($containers.Count) { $haveEnv = @($containers[0].env | Where-Object { $_ } | ForEach-Object { [string]$_.name }) }
    $dropEnv = @($legacyEnv | Where-Object { $haveEnv -contains $_ })
    $haveSecrets = @($existing.properties.configuration.secrets | Where-Object { $_ } | ForEach-Object { [string]$_.name })
    $dropSecrets = @(@('gh-token', 'src-url') | Where-Object { $haveSecrets -contains $_ })
    # its size: kept when at least 4 CPU / 8 GiB, else raised to that -- never lowered
    $size = Resolve-SIUpdaterJobSize -Existing $existing
    Info ("{0}: {1}" -f $JobName, $size.Why)
    $sizeArgs = @{}; if ($size.Change) { $sizeArgs.Cpu = $size.Cpu; $sizeArgs.Memory = $size.Memory }
    # the zone the timer is set for, recorded on the job (the update's one-time step then has nothing to move)
    if ($nightlyTags.Count) { $sizeArgs.Tags = $nightlyTags }
    $null = Update-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $JobName -SubscriptionId $sub @sizeArgs `
                -Cron $Schedule -Image $image -SetEnv $envArgs -RemoveEnv $dropEnv -SetSecrets $secretArgs -RemoveSecrets $dropSecrets
    if ($dropEnv.Count) { Info ("removed the legacy repository settings: {0}" -f ($dropEnv -join ', ')) }
    if ($dropSecrets -contains 'gh-token') { Info 'removed the legacy GitHub token secret (gh-token) from the job' }
    if ($dropSecrets -contains 'src-url') { Info 'removed the update feed link (src-url) from the job -- it now takes releases from Invardia' }
    Info "updated $JobName"
}
# #352: the updater applies the release's database schema + grants before it rolls code -- its identity needs the rights
if ($ProSqlServer -and $ProSqlDatabase) {
    Step '4. The updater''s rights on the Pro database'
    $grantDb = Join-Path $solRoot 'setup/Grant-SIUpdaterDatabase.ps1'
    $gArgs = @{ SubscriptionId = $sub; SqlServer = $ProSqlServer; SqlDatabase = $ProSqlDatabase }
    if ($UseManagedIdentity) { $gArgs.ResourceGroupName = $ResourceGroupName; $gArgs.IdentityName = $IdentityName }
    else { $gArgs.ClientId = $SpnClientId; $gArgs.UserName = ('si-updater-' + $SpnClientId) }
    if (-not (Test-Path -LiteralPath $grantDb)) { Info 'this copy has no Pro database step (SecurityInsight Pro only) -- nothing to grant' }
    elseif ($GrantSql) { & $grantDb @gArgs -Apply }
    else {
        Info ("NOT granted yet -- until it is, an update stops before rolling anything. Run once, as the SQL server's Entra admin:")
        Info ("  .\setup\Grant-SIUpdaterDatabase.ps1 {0} -Apply" -f (($gArgs.GetEnumerator() | Sort-Object Name | ForEach-Object { '-{0} {1}' -f $_.Name, $_.Value }) -join ' '))
    }
}
Info ("{0} runs '{1}' UTC{3}; start it now from the Azure portal (Container Apps job {0} in resource group {2} -> Run now)" -f $JobName, $Schedule, $ResourceGroupName, $(if ($nightly) { ' = daily at ' + (Get-SINightlyScheduleText -Zone $nightly.Zone -Known $nightly.Known) } else { '' }))
# The job is there, but an updater whose identity lacks a right fails at night: said, with what is missing, and the run
# ends in an error (safe to run again once someone who may assign roles there has made the grants).
if ($script:SIUpdaterGrantsFailed.Count) {
    $missingRights = @($script:SIUpdaterGrantsFailed.ToArray() | Select-Object -Unique)
    throw ("The updater job {0} is installed, but {1} right(s) could not be given to its identity {2}: {3}. Until they are given the updater cannot update this install. Someone who may assign roles in resource group {4} grants them (Azure portal: the scope > Access control (IAM) > Add role assignment > the role > Managed identity > {2}), or runs this command again." -f $JobName, $missingRights.Count, $IdentityName, ($missingRights -join '; '), $ResourceGroupName)
}
exit 0
} finally { Stop-SIScriptRun -Run $siRun }
