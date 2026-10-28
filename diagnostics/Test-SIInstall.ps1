<#
.SYNOPSIS
    Is this SecurityInsight install healthy, and is it isolated? Read-only.

.DESCRIPTION
    Reads the install's config (config/SecurityInsight.custom.ps1, without running it) and reports:
      1. rows and the last time per SI table in the install's workspace (Log Analytics data plane)
      2. run health per engine: the latest start and end, and how the last run ended (ExitReason)
      3. the data collection rules in its resource group
      4. ISOLATION -- the install's managed identity holds NO write role (Owner / Contributor / Monitoring Metrics
         Publisher / User Access Administrator / ...) outside its own resource group, except the grants SecurityInsight
         documents for it; and its data collection rule names are unique in the subscription (an engine that resolves a
         rule by name could otherwise send this install's data into another one)
      5. the licence request (when the config names its Key Vault): none / requested / pending / approved / rejected,
         valid-to and the last check, from the state the updater keeps (SI-LicenceRequest-State; never the pull token).
      6. updates (Pro, when the config names its Key Vault): the update source, the last manifest per kind (version,
         sequence, ring), the last check and any HOLD, from the state the updater keeps (SI-Update-State; never the
         install key). A refused manifest or an install key that could not be claimed is a finding; a hold is a note.
         A REJECTED request is wrong; a request's last problem is a note
      6. a summary. Exit code 1 when anything is wrong, 0 otherwise.

    Needs no PowerShell module: Azure is reached over plain REST. Signs in as the install's own identity from its config
    (its managed identity, or its service principal certificate from the machine's certificate store), or as the
    service principal certificate named in SI_DIAGNOSTICS_APPID / SI_DIAGNOSTICS_TENANTID / SI_DIAGNOSTICS_CERTTHUMBPRINT
    (-SignIn). The identity needs Reader on the install's resource group and subscription, and Log Analytics Reader on the workspace.

.PARAMETER ConfigPath
    The install's config file. Default: config/SecurityInsight.custom.ps1 of this copy.
.PARAMETER SinceHours
    How far back to look for data and runs (default 26: one daily run plus margin).
.PARAMETER RunningGraceHours
    A run that started longer ago than this and never ended is reported (default 4).
.PARAMETER IdentityName
    The install's user-assigned identity, when the config does not name it and its resource group holds more than one.
.PARAMETER PrincipalId
    The identity's object (principal) id -- any identity, also a VM's system-assigned one.
.PARAMETER AllowedGrant
    Extra write grants that are allowed on purpose, as 'Role@/scope'.
.PARAMETER SignIn
    Auto (default: the SI_DIAGNOSTICS_* service principal when set, otherwise Config) | Config (the install's own
    identity). AzContext is no longer supported: SecurityInsight v3 uses no Az PowerShell session.

.EXAMPLE
    ./diagnostics/Test-SIInstall.ps1
.EXAMPLE
    ./diagnostics/Test-SIInstall.ps1 -ConfigPath ./config/SecurityInsight.custom.ps1 -SinceHours 48 -PassThru

.LINK
    https://invardia.com/docs/si/scripts/Test-SIInstall/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath,
    [double]$SinceHours = 26,
    [double]$RunningGraceHours = 4,
    [string]$IdentityName,
    [string]$PrincipalId,
    [string[]]$AllowedGrant = @(),
    [ValidateSet('Auto', 'AzContext', 'Config')][string]$SignIn = 'Auto',
    [switch]$PassThru,
    # Tests only: replacements for the calls that leave this process (Arm, LaQuery, Graph, Now, Sleep, Print).
    [Parameter(DontShow)][System.Collections.IDictionary]$Seams
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'setup', '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Test-SIInstall' -Quiet:([bool]$PSBoundParameters.ContainsKey('Seams'))
try {
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_SIInstallDiagnostics.ps1'))
if (-not $ConfigPath) { $ConfigPath = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'config', 'SecurityInsight.custom.ps1') }

$values = Read-SIInstallConfigValues -Path $ConfigPath
$target = Get-SIInstallTargetFromConfig -Values $values
if (-not $Seams) { $null = Initialize-SIDiagnosticsSignIn -SignIn $SignIn -Values $values }
$s = Merge-SIDiagnosticsSeams -Seams $Seams
$r = Invoke-SIInstallCheck -Target $target -Seams $s -SinceHours $SinceHours -RunningGraceHours $RunningGraceHours `
        -IdentityName $IdentityName -PrincipalId $PrincipalId -AllowedGrant $AllowedGrant
if ($PassThru) { $r }
exit $(if ($r.Ok) { 0 } else { 1 })
} finally { Stop-SIScriptRun -Run $siRun }
