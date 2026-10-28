<#
.SYNOPSIS
    SecurityInsight Pro -- record this install's update ring in the Pro database, so the web app shows it.

.DESCRIPTION
    The update ring is a property of the install, known when it is installed. This records it in the Pro database
    (cfg.InstallState 'Ring'); the web app's header shows it (UPDATE RING) from then on, also before the updater job has
    ever run. The guided install and Bootstrap-ContainerAppJob.ps1 run this for you; run it yourself for an install built
    another way, or to correct the ring.

    Which ring is recorded:
      -Ring                    when given (0 dev, 1 internal, 2 early release, 3 broad; r1 / prod also work)
      else SI_UpdateRing       the setting (Settings page, or $global:SI_UpdateRing in config\SecurityInsight.custom.ps1)
      else the resource group  the ring in its name (rg-si-r1-pro-ca = 1, rg-si-prod-pro-ca = 3) -- this one never
                               replaces a ring that is already recorded
    Once the updater job runs it records the ring it actually updates by, and the header shows that.

    The database comes from SI_ProSqlServer / SI_ProSqlDatabase (load config\SecurityInsight.custom.ps1 first, or give
    -Server / -Database) and is reached as the engine identity, like the other setup\*.ps1 Pro tools.

.EXAMPLE
    . .\config\SecurityInsight.custom.ps1; .\setup\Set-SIInstallRing.ps1 -Ring 1 -Channel internal
.EXAMPLE
    .\setup\Set-SIInstallRing.ps1 -ResourceGroupName rg-si-r1-pro-ca      # the ring from the setting, else from the name

.LINK
    https://invardia.com/docs/si/scripts/Set-SIInstallRing/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Ring,
    # Where updates come from: invardia (Pro), internal (the internal update feed), community (GitHub). Shown with the ring.
    [ValidateSet('', 'invardia', 'internal', 'community')][string]$Channel = '',
    [string]$ResourceGroupName = [string]$global:SI_Bootstrap_ResourceGroupName,
    # Who records it (shown in the web app's tooltip).
    [string]$SetBy = 'setup',
    [string]$Server = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # The database, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    [switch]$PassThru
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SIInstallRing' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-InstallRing.ps1'))

if ($Ring -and $null -eq (ConvertTo-SIUpdateRing $Ring)) { throw ("'{0}' is not an update ring: give 0, 1, 2 or 3 (0 dev, 1 internal, 2 early release, 3 broad)" -f $Ring) }
if ($WhatIfPreference) {
    # -WhatIf: the Pro database is not opened -- recording the ring is its only action, so the preview says it and stops
    Write-Host ('-WhatIf: would record update ring {0} (channel {1}, resource group {2}, set by {3}) in the Pro database {4}/{5}. Nothing was written.' -f `
        $(if ($Ring) { $Ring } else { '(from the configuration)' }), $(if ($Channel) { $Channel } else { '(default)' }), $(if ($ResourceGroupName) { $ResourceGroupName } else { '(default)' }), $(if ($SetBy) { $SetBy } else { '(this account)' }), $Server, $Database) -ForegroundColor Yellow
    return
}
if (-not $Store) {
    if (-not $Server -or -not $Database) { throw 'the Pro database is not configured: load config\SecurityInsight.custom.ps1 first (SI_ProSqlServer / SI_ProSqlDatabase), or give -Server and -Database' }
    . ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
    $Store = New-SIProSettingsStore -Server $Server -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
}
$cfgSetting = $(if (Test-Path -Path 'variable:global:SI_UpdateRing') { $global:SI_UpdateRing } else { $null })
$res = Invoke-SIRecordInstallRing -Store $Store -Ring $(if ($Ring) { $Ring } else { $null }) -RingSource parameter -ConfigSetting $cfgSetting `
            -ResourceGroupName $ResourceGroupName -Channel $Channel -SetBy $SetBy
foreach ($p in @($res.Problems)) { Write-Host ('[WARN] {0}' -f $p) -ForegroundColor Yellow }
if ($res.Written) { Write-Host ('[OK]   {0}' -f $res.Reason) -ForegroundColor Green }
elseif ($null -eq $res.Ring -or $res.Reason -like 'the update ring could not be recorded*' -or $res.Reason -like '*no cfg.InstallState*') { Write-Host ('[WARN] {0}' -f $res.Reason) -ForegroundColor Yellow }
else { Write-Host ('[INFO] {0}' -f $res.Reason) }
if ($PassThru) { $res }
} finally { Stop-SIScriptRun -Run $siRun }
