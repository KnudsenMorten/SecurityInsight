<#
.SYNOPSIS
    Switch a CONTAINER install between the daily job flow and per-job schedules (#269). Previewed; reversible.

.DESCRIPTION
    -Mode flow       the jobs of the flow lose their own timer (Manual; the timer is remembered in the si-disabled-cron
                     tag) and caj-si-flow gets the flow's start time: ONE start, each job when the one before it ended.
    -Mode schedules  every job of the flow gets its timer back (the remembered one, or the shipped default in dependency
                     order) and caj-si-flow waits (Manual, its time remembered).
    Without -Apply it only PRINTS what it would do. Switching back restores every remembered timer. A job outside the
    flow, an event-triggered (KEDA) job and the template job are never touched. A Pro install does the same from
    Operations > Jobs (the switch at the top), which also records the mode in the Pro database.

    The flow's steps: config\job-flow.custom.json when present, else the default flow over the jobs that exist
    (config\job-flow.locked.json). Signs in with setup's own REST sign-in (Azure Cloud Shell, the browser, or the Invardia
    support session) -- no az CLI. Pass -SubscriptionId.

.EXAMPLE
    .\setup\Switch-SIJobOrchestration.ps1 -Mode flow -ResourceGroupName rg-si-prod-community-ca -SubscriptionId <id>
    .\setup\Switch-SIJobOrchestration.ps1 -Mode flow -ResourceGroupName rg-si-prod-community-ca -SubscriptionId <id> -Apply

.LINK
    https://invardia.com/docs/si/scripts/Switch-SIJobOrchestration/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('flow', 'schedules')][string]$Mode,
    [string]$ResourceGroupName = $(if ($global:SI_Bootstrap_ResourceGroupName) { [string]$global:SI_Bootstrap_ResourceGroupName } else { '' }),
    [string]$SubscriptionId = $(if ($global:SI_Bootstrap_SubscriptionId) { [string]$global:SI_Bootstrap_SubscriptionId } else { [string]$global:SI_AzSubscriptionId }),
    [string]$ApiVersion = '2025-07-01',   # not 2024-03-01: that version drops a queue scale rule's identity when a job is read and written back (#616)
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Switch-SIJobOrchestration' -Quiet:($false)
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the plan: no job is changed
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'engine/_shared/SI-JobFlow.ps1')
if (-not $ResourceGroupName -or -not $SubscriptionId) { throw 'pass -ResourceGroupName and -SubscriptionId (the resource group of the caj-si-* jobs)' }

# #521: setup's own REST sign-in (an existing one in this process is reused; else a person signs in -- Cloud Shell or the
# browser; an Invardia support session gives its tokens). ARM directly, never the az CLI.
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure -SubscriptionId $SubscriptionId }

$base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroupName
$armRest = {
    param([string]$Method, [string]$Path, $Body)
    # Azure's refusal (e.g. ContainerAppSecretInvalid) is the only explanation a failed change has: its code and message
    # are kept in the error (Get-SIAzErrorMessage reads the ARM error body).
    try {
        if ($null -ne $Body) { Invoke-SIArm -Method $Method -Path $Path -ApiVersion $ApiVersion -Body $Body }
        else { Invoke-SIArm -Method $Method -Path $Path -ApiVersion $ApiVersion }
    } catch {
        $resp = $_.Exception.PSObject.Properties['Response']
        $txt = if ($resp -and $resp.Value) { [string]$resp.Value.Content } else { [string]$_.Exception.Message }
        throw ('{0} {1} failed: {2}' -f $Method, ($Path -split '/')[-1], (Get-SIAzErrorMessage -Lines @($txt)))
    }
}

$listed = @((& $armRest 'GET' $base $null).value | Where-Object { $_ -and [string]$_.name -like 'caj-si-*' })
$jobs = @($listed | ForEach-Object {
    $c = $_.properties.configuration
    [pscustomobject]@{ Name = [string]$_.name; TriggerType = [string]$c.triggerType
                       Cron = $(if ($c.scheduleTriggerConfig) { [string]$c.scheduleTriggerConfig.cronExpression } else { '' })
                       RememberedCron = $(if ($_.tags -and $_.tags.PSObject.Properties['si-disabled-cron']) { [string]$_.tags.'si-disabled-cron' } else { '' }) }
})
$custom = Join-Path $siRoot 'config/job-flow.custom.json'
$definition = if (Test-Path -LiteralPath $custom) { ConvertFrom-SIJobFlowJson -Json ([IO.File]::ReadAllText($custom)) } else { New-SIDefaultJobFlow -Installed @($jobs.Name) }
$plan = Get-SIJobOrchestrationSwitchPlan -Jobs $jobs -Mode $Mode -Definition $definition

Write-Host ('Switching {0} to: {1}{2}' -f $ResourceGroupName, $(if ($Mode -eq 'flow') { ('ONE FLOW, {0} at {1} UTC' -f $definition.Cadence, $definition.StartTime) } else { 'per-job schedules' }), $(if ($Apply) { '' } else { '  (preview -- nothing changes without -Apply)' }))
foreach ($p in $plan) { Write-Host ('  {0,-34} {1,-12} {2,-14} {3}' -f $p.Job, $p.Action, $p.Cron, $p.Why) }
if (-not $Apply) { return $plan }

$failed = New-Object System.Collections.Generic.List[object]
# TIMERS ON FIRST, then off (ring 2, 2026-10-10): a switch to the pipeline that turned the jobs' timers off and then failed
# on caj-si-flow left NOTHING scheduled ("neither mode"). Stopped half-way, it now leaves both on -- never neither.
foreach ($p in @(@($plan | Where-Object { $_.Action -eq 'to-schedule' }) + @($plan | Where-Object { $_.Action -eq 'to-manual' }))) {
    try {
        $job = & $armRest 'GET' ('{0}/{1}' -f $base, $p.Job) $null
        # PATCH with only the trigger + tags: a PUT of the GET'd job is refused for a job with a secret (ARM returns
        # secrets without their values) -- that silently left the Pro jobs on their own timers.
        $body = ConvertTo-SIArmJobTrigger -Job $job -Action $p.Action -Cron $(if ($p.Action -eq 'to-schedule') { $p.Cron } else { '' })
        $null = & $armRest 'PATCH' ('{0}/{1}' -f $base, $p.Job) $body
        Write-Host ('  {0,-34} done' -f $p.Job) -ForegroundColor Green
    } catch {
        $failed.Add([pscustomobject]@{ Job = $p.Job; Action = $p.Action; Error = $_.Exception.Message })
        Write-Host ('  {0,-34} FAILED: {1}' -f $p.Job, $_.Exception.Message) -ForegroundColor Red
        Write-Warning ('{0}: {1}' -f $p.Job, $_.Exception.Message)
    }
}
if ($failed.Count) {
    # Never silent: printed whatever the caller's $WarningPreference is, and the run ends in an error.
    $back = $(if ($Mode -eq 'flow') { 'schedules' } else { 'flow' })
    Write-Host ''
    Write-Host ('{0} job(s) were NOT switched:' -f $failed.Count) -ForegroundColor Red
    foreach ($f in $failed) { Write-Host ('  {0,-34} {1,-12} {2}' -f $f.Job, $f.Action, $f.Error) -ForegroundColor Red }
    Write-Host ('Run it again (it is idempotent), or switch back with -Mode {0}.' -f $back) -ForegroundColor Red
    Write-Warning ('{0} job(s) were not switched: {1}' -f $failed.Count, (($failed | ForEach-Object { $_.Job }) -join ', '))
    throw ('{0} of {1} job(s) were not switched to {2}: {3}' -f $failed.Count, @($plan | Where-Object { $_.Action -ne 'keep' }).Count, $Mode, (($failed | ForEach-Object { '{0} ({1})' -f $_.Job, $_.Error }) -join '; '))
}
$plan
} finally { Stop-SIScriptRun -Run $siRun }
