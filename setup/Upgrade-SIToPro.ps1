<#
.SYNOPSIS
    Upgrade a container installation to PRO updates: install the updater job, so the containers receive what
    SecurityInsight releases to your update ring -- from Invardia's update platform -- by themselves from now on.

.DESCRIPTION
    The same step as PIM4EntraPS's Upgrade-PimToPro.ps1. Both editions run the same containers; they differ in the
    licence (which features run) and in HOW an install is updated:

      * Community: you update when you choose -- .\Update-SecurityInsight.ps1 -Apply takes the release from GitHub
        and rebuilds + rolls the containers from it (verify, roll back on failure).
      * Pro: the nightly updater job in your own subscription takes what SecurityInsight released to your update ring
        from Invardia's update platform (signed manifests, checked against the keys this release carries) and rolls the
        containers to it. SecurityInsight's own update feed is retired (2026-10-06) -- there is no link to receive.

    This is the switch from the first to the second. RUN IT FROM THE PRO PACKAGE (the guided install on invardia.com, or
    the package your licence gives you): the updater job's Invardia client ships only with Pro. It reads the container
    hosting your setup SAVED in config\SecurityInsight.custom.ps1 and your engine identity, and runs
    setup\Install-SIUpdaterJob.ps1 with them. On success it records the updater job in the saved hosting block; from
    then on setup\Invoke-SIContainerUpdate.ps1 (and so Update-SecurityInsight.ps1) leaves the containers to the job.

    Without -Apply nothing changes: the plan is printed, including anything missing.

.PARAMETER UpdateRing
    The update ring this environment takes (0-3; your licence or Invardia support tells you which -- design partners 2,
    everyone else 3). Without it the ring recorded for the install is used; with none, the job asks for nothing.
.PARAMETER UseManagedIdentity
    The job signs in as its own managed identity (recommended) -- no certificate.
.PARAMETER CertSecretName
    Without -UseManagedIdentity: the Key Vault secret holding the SPN certificate (PFX) the updater signs in with.
.PARAMETER KeyVaultName
    Your Key Vault. Default: SI_KeyVaultName from your config.
.PARAMETER EnvName
    The Container Apps environment, when your saved hosting predates SI_Bootstrap_EnvName.
.PARAMETER GrantSpnRoles
    Passed to Install-SIUpdaterJob.ps1: grant the identity what the updater needs on the registry, resource group and vault.
.PARAMETER Apply
    Install the updater job. Without it, only the plan is printed.

.EXAMPLE
    .\setup\Upgrade-SIToPro.ps1 -UseManagedIdentity -UpdateRing 3            # the plan
    .\setup\Upgrade-SIToPro.ps1 -UseManagedIdentity -UpdateRing 3 -Apply     # upgrade

.LINK
    https://invardia.com/docs/si/scripts/Upgrade-SIToPro/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(-1, 3)][int]$UpdateRing = -1,
    [switch]$UseManagedIdentity,
    [string]$CertSecretName,
    [string]$KeyVaultName,
    [string]$EnvName,
    [string]$JobName = 'caj-si-updater',
    [switch]$GrantSpnRoles,
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Upgrade-SIToPro' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: the updater job is not installed
try {
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared/SI-ContainerUpdate.ps1')

$customFile = Join-Path $solRoot 'config/SecurityInsight.custom.ps1'
if (-not (Test-Path -LiteralPath $customFile)) { throw 'config\SecurityInsight.custom.ps1 not found -- run setup first; it saves the container hosting this upgrade reuses.' }
# Read the customer's values in a child scope and keep only the names needed (the same way Invoke-SIContainerUpdate.ps1 does).
try { & { . $customFile } 3>$null } catch { Write-Host ("config\SecurityInsight.custom.ps1 did not load completely here ({0}) -- continuing with what it set." -f $_.Exception.Message) -ForegroundColor Yellow }
$globals = @{}
foreach ($n in 'SI_Bootstrap_SubscriptionId', 'SI_Bootstrap_ResourceGroupName', 'SI_Bootstrap_AcrName', 'SI_Bootstrap_EnvName', 'SI_Bootstrap_Location',
               'SI_Bootstrap_UpdaterJob', 'SI_WorkspaceResourceId', 'SI_KeyVaultName', 'SpnKeyVaultName', 'SI_SPN_AppId', 'SI_SPN_TenantId') {
    $v = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction Ignore
    if ($null -ne $v) { $globals[$n] = $v }
}
if (-not (Resolve-SIContainerUpdateTarget -Globals $globals)) {
    throw 'This install has no container hosting saved -- the updater job updates CONTAINERS. A VM install keeps updating with .\Update-SecurityInsight.ps1 -Apply. (An install made before 3.0.0 records its containers once with: .\setup\Invoke-SIContainerUpdate.ps1 -ResourceGroupName <rg> -AcrName <acr> -Save)'
}
$plan = Get-SIProUpgradePlan -Globals $globals -CertSecretName $CertSecretName -KeyVaultName $KeyVaultName -EnvName $EnvName -UseManagedIdentity:$UseManagedIdentity

Write-Host '==> Upgrade to SecurityInsight Pro updates' -ForegroundColor Cyan
foreach ($k in $plan.Args.Keys) { Write-Host ("    {0,-20} {1}" -f $k, $(if ($plan.Args[$k]) { $plan.Args[$k] } else { '(missing)' })) }
$already = Get-SIUpdaterManagedJob -Globals $globals
if ($already) { Write-Host ("    already upgraded: '{0}' owns the rollout -- re-running refreshes it in place." -f $already) }
if (@($plan.Missing).Count) {
    throw ('Missing: {0}. Pass them as parameters (-KeyVaultName, -EnvName), or set SI_SPN_AppId / SI_SPN_TenantId in config\SecurityInsight.custom.ps1.' -f (@($plan.Missing) -join ', '))
}
if (-not $Apply) {
    Write-Host '    nothing changed -- re-run with -Apply to install the updater job.'
    Write-Host '    From then on the job updates the containers; .\Update-SecurityInsight.ps1 still updates this folder but leaves the containers to the job.'
    return
}

$install = @{} + $plan.Args
$install['JobName'] = $JobName
if ($UseManagedIdentity) { $install['UseManagedIdentity'] = $true }
if ($UpdateRing -ge 0) { $install['UpdateRing'] = $UpdateRing }
if ($GrantSpnRoles) { $install['GrantSpnRoles'] = $true }
& (Join-Path $PSScriptRoot 'Install-SIUpdaterJob.ps1') @install -Apply
# Only after the job exists: record it, so the Community update stops rolling these containers.
$saved = Save-SIContainerHostingConfig -ConfigPath $customFile -SubscriptionId $plan.Args.SubscriptionId -ResourceGroupName $plan.Args.ResourceGroupName `
    -AcrName $plan.Args.AcrName -EnvName $plan.Args.EnvName -Location ([string]$globals['SI_Bootstrap_Location']) -UpdaterJob $JobName
Write-Host ("[OK]   upgraded: '{0}' now updates these containers on your ring ({1})." -f $JobName, $(if ($saved.Changed) { 'recorded in config\SecurityInsight.custom.ps1' } else { 'already recorded' })) -ForegroundColor Green
} finally { Stop-SIScriptRun -Run $siRun }
