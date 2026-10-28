<#
.SYNOPSIS
    Runs every SecurityInsight Container Apps job of an install ONCE, in schedule order, and reports each run.

.DESCRIPTION
    Reads the install's config (config/SecurityInsight.custom.ps1, without running it) for its subscription and resource
    group, lists the Container Apps jobs there and runs them the way the daily schedule would: jobs that start at the
    same time of day run together (in parallel), and each group waits for the one before it -- profilers before Risk
    Analysis, Risk Analysis before the trend. Each execution's outcome and duration is reported; exit code 1 when any
    run did not succeed (or did not finish within -TimeoutMinutes), 0 otherwise.

    Left out: the updater job (it changes the install; -IncludeUpdater runs it) and event-triggered jobs (they run when
    work arrives). -PlanOnly prints the order and starts nothing.

    Changes nothing but starting the jobs. Needs no PowerShell module (plain REST); signs in as the install's own
    identity from its config, or as the service principal certificate named in SI_DIAGNOSTICS_APPID /
    SI_DIAGNOSTICS_TENANTID / SI_DIAGNOSTICS_CERTTHUMBPRINT (-SignIn). The identity needs to start jobs in the
    resource group (Contributor there).

.EXAMPLE
    ./diagnostics/Invoke-SIJobsOnce.ps1 -PlanOnly
.EXAMPLE
    ./diagnostics/Invoke-SIJobsOnce.ps1 -TimeoutMinutes 180

.LINK
    https://invardia.com/docs/si/scripts/Invoke-SIJobsOnce/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath,
    [string]$ResourceGroup,
    [string]$SubscriptionId,
    [string[]]$Only = @(),
    [string[]]$Exclude = @(),
    [switch]$IncludeUpdater,
    [switch]$PlanOnly,
    [int]$TimeoutMinutes = 120,
    [int]$PollSeconds = 30,
    [ValidateSet('Auto', 'AzContext', 'Config')][string]$SignIn = 'Auto',
    [switch]$PassThru,
    # Tests only: replacements for the calls that leave this process (Arm, LaQuery, Graph, Now, Sleep, Print).
    [Parameter(DontShow)][System.Collections.IDictionary]$Seams
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'setup', '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Invoke-SIJobsOnce' -Quiet:([bool]$PSBoundParameters.ContainsKey('Seams'))
if ($WhatIfPreference) { $PlanOnly = $true }   # -WhatIf = the plan: no job is started
try {
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_SIInstallDiagnostics.ps1'))
if (-not $ConfigPath) { $ConfigPath = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'config', 'SecurityInsight.custom.ps1') }

$values = @{}
if ((-not $ResourceGroup -or -not $SubscriptionId) -or (Test-Path -LiteralPath $ConfigPath)) { $values = Read-SIInstallConfigValues -Path $ConfigPath }
$target = Get-SIInstallTargetFromConfig -Values $values
if ($SubscriptionId) { $target.SubscriptionId = $SubscriptionId }
if ($ResourceGroup) { $target.ResourceGroup = $ResourceGroup }
if (-not $target.SubscriptionId -or -not $target.ResourceGroup) { throw 'The subscription and resource group of the install are not known: give -ConfigPath, or -SubscriptionId and -ResourceGroup.' }
$rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $target.SubscriptionId, $target.ResourceGroup

if (-not $Seams) { $null = Initialize-SIDiagnosticsSignIn -SignIn $SignIn -Values $values }
$s = Merge-SIDiagnosticsSeams -Seams $Seams
$jobs = @(& $s.Arm 'GET' ($rgId + '/providers/Microsoft.App/jobs') $script:SIDiagJobApi -List:$true $null | Where-Object { $_ })
$plan = Get-SIJobRunPlan -Jobs $jobs -IncludeUpdater:$IncludeUpdater -Only $Only -Exclude $Exclude

& $s.Print ('== SecurityInsight jobs in {0}: {1} to run in {2} group(s)' -f $target.ResourceGroup, @($plan.Groups | ForEach-Object { $_.Jobs }).Count, @($plan.Groups).Count) 'Cyan'
$i = 0
foreach ($g in @($plan.Groups)) { $i++; & $s.Print ('  {0,2}. {1,-6} {2}' -f $i, $g.At, (@($g.Jobs | ForEach-Object Name) -join ', ')) '' }
foreach ($k in @($plan.Skipped)) { & $s.Print ('  left out: {0} ({1})' -f $k.Name, $k.Why) 'DarkGray' }
if (-not @($plan.Groups).Count) { & $s.Print '  no job to run.' 'Red'; exit 1 }
if ($PlanOnly) { if ($PassThru) { $plan }; exit 0 }

$r = Invoke-SIJobRunOnce -Plan $plan -Seams $s -PollSeconds $PollSeconds -TimeoutMinutes $TimeoutMinutes
if ($PassThru) { $r }
exit $(if ($r.Ok) { 0 } else { 1 })
} finally { Stop-SIScriptRun -Run $siRun }
