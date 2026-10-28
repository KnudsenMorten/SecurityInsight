<#
.SYNOPSIS
    VM install (Task Scheduler): run the engines as ONE daily flow instead of one scheduled task per engine (#269).
    Previewed; idempotent; reversible.

.DESCRIPTION
    -Apply    registers the scheduled task "\SecurityInsight\SecurityInsight (flow)" -- it WAKES every 5 minutes (one
              instance at a time: MultipleInstances IgnoreNew) and runs engine\flow\Invoke-SIJobFlowRun.ps1 -HostKind Vm,
              which starts the flow only when it is DUE (SCHED-1.1): at the flow's start time (config\job-flow.custom.json,
              default 01:00 UTC; never while the previous run is still running -- a blocked start runs once when it
              finishes), or every N after the previous run FINISHED. Each step's launcher runs in its own PowerShell process, one
              after the other (or together with the step above, where the definition says so), with the run record in
              data\flow\flow-run.json and one run-health row per step in Log Analytics.
              The per-engine tasks that ran a launcher of a step of the flow are DISABLED (not deleted) and recorded in
              data\flow\replaced-tasks.json.
    -Remove   the reverse: enables exactly the recorded tasks again and unregisters the flow task.
    Neither   prints what -Apply would do (the default).
    Running it again changes nothing that is already in place. Run as an administrator (the tasks run as SYSTEM, like
    the per-engine tasks the README describes).

    The flow's steps: config\job-flow.custom.json when present (the same shape the web app writes; "mode": "schedules"
    makes the flow task do nothing), else the default flow over the launchers present (config\job-flow.locked.json).

.EXAMPLE
    .\setup\Install-SIFlowTask.ps1                 # preview
    .\setup\Install-SIFlowTask.ps1 -Apply          # flow on, per-engine tasks disabled
    .\setup\Install-SIFlowTask.ps1 -Remove         # back to the per-engine tasks

.LINK
    https://invardia.com/docs/si/scripts/Install-SIFlowTask/
#>
[CmdletBinding(DefaultParameterSetName = 'Preview', SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Remove')][switch]$Remove,
    # (the start time / cadence is the flow definition's -- the task only wakes the runner)
    [ValidateSet('community-vm', 'internal-vm')][string]$Flavour = 'community-vm',
    [string]$TaskPath = '\SecurityInsight\',
    [string]$TaskName = 'SecurityInsight (flow)',
    [string]$RunAs = 'SYSTEM'
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Install-SIFlowTask' -Quiet:($false)
if ($WhatIfPreference) { if ($Remove) { Write-Host '-WhatIf: would enable the recorded per-engine tasks again and remove the flow task. Nothing was changed.' -ForegroundColor Yellow; return }; $Apply = [switch]$false }   # -WhatIf = the preview
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'engine\_shared\SI-JobFlow.ps1')
$record = Join-Path $siRoot 'data\flow\replaced-tasks.json'
$custom = Join-Path $siRoot 'config\job-flow.custom.json'
$definition = if (Test-Path -LiteralPath $custom) { ConvertFrom-SIJobFlowJson -Json ([IO.File]::ReadAllText($custom)) } else { New-SIDefaultJobFlow -Installed (Get-SIJobFlowVmInstalled -Root $siRoot -Flavour $Flavour) }
# the task WAKES the runner; the flow's cadence lives in the definition (SCHED-1.1)
$runner = Join-Path $siRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'
$arg = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -HostKind Vm -Flavour {1}' -f $runner, $Flavour

$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $a = @($_.Actions)[0]
    [pscustomobject]@{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = [string]$_.State; Execute = $(if ($a) { [string]$a.Execute } else { '' }); Arguments = $(if ($a) { [string]$a.Arguments } else { '' }) }
})
$replace = @(Get-SIFlowTaskReplacePlan -Tasks $tasks -Definition $definition)
$flowTask = @($tasks | Where-Object { $_.TaskPath -eq $TaskPath -and $_.TaskName -eq $TaskName })[0]

if ($Remove) {
    $recorded = if (Test-Path -LiteralPath $record) { @([IO.File]::ReadAllText($record) | ConvertFrom-Json) } else { @() }
    foreach ($t in $recorded) {
        try { Enable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName | Out-Null; Write-Host ('  enabled again   {0}{1}' -f $t.TaskPath, $t.TaskName) }
        catch { Write-Warning ('{0}{1}: {2}' -f $t.TaskPath, $t.TaskName, $_.Exception.Message) }
    }
    if ($flowTask) { Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false; Write-Host ('  removed         {0}{1}' -f $TaskPath, $TaskName) }
    if (Test-Path -LiteralPath $record) { Remove-Item -LiteralPath $record -Force }
    Write-Host 'Back to one scheduled task per engine.'
    return
}

Write-Host ('The flow: {0} step(s), {1} -- {2}' -f @($definition.Steps).Count, (Get-SIJobFlowCadenceText -Definition $definition), (@($definition.Steps | ForEach-Object Job) -join ' > '))
Write-Host ('  flow task       {0}{1} {2}' -f $TaskPath, $TaskName, $(if ($flowTask) { '(present -- updated)' } else { '(new)' }))
foreach ($t in $replace) { Write-Host ('  disable         {0,-60} ({1}; now {2})' -f $t.Task, $t.Job, $t.State.ToLowerInvariant()) }
if (-not @($replace).Count) { Write-Host '  no per-engine task runs a step of the flow' }
if (-not $Apply) { Write-Host 'Preview only -- run with -Apply to make it so (and -Remove to undo).' -ForegroundColor Yellow; return }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg -WorkingDirectory $siRoot
# SCHED-1.1: the task only WAKES the runner (every 5 minutes); the runner starts the flow when it is due -- at the
# flow's start time, never while the previous run is still running, or every N after the previous run FINISHED.
$trigger = New-ScheduledTaskTrigger -Once -At ([datetime]::Today) -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 23) -MultipleInstances IgnoreNew -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $RunAs -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
# record BEFORE disabling, and keep what an earlier run recorded (a task disabled then shows Disabled now)
$known = @(); if (Test-Path -LiteralPath $record) { $known = @([IO.File]::ReadAllText($record) | ConvertFrom-Json) }
# UPDATE-1.6: the updater runs on its own daily schedule, never in the pipeline -- its task, disabled by an earlier setup
# when the updater was a step, is enabled again and no longer recorded
foreach ($t in @($known | Where-Object { $_ -and (Test-SIJobFlowOwnSchedule -Job ([string]$_.Job)) })) {
    try { Enable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName | Out-Null; Write-Host ('  enabled again   {0}{1} (the updater runs on its own daily schedule)' -f $t.TaskPath, $t.TaskName) }
    catch { Write-Warning ('{0}{1}: {2}' -f $t.TaskPath, $t.TaskName, $_.Exception.Message) }
}
$known = @($known | Where-Object { $_ -and -not (Test-SIJobFlowOwnSchedule -Job ([string]$_.Job)) })
$all = @($known) + @($replace | Where-Object { $_.State -ne 'Disabled' } | Where-Object { $n = $_; -not (@($known) | Where-Object { $_.TaskPath -eq $n.TaskPath -and $_.TaskName -eq $n.TaskName }) } | ForEach-Object { [pscustomobject]@{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; Job = $_.Job } })
New-Item -ItemType Directory -Path (Split-Path -Parent $record) -Force | Out-Null
[IO.File]::WriteAllText($record, (ConvertTo-Json -InputObject @($all) -Depth 4))
foreach ($t in @($replace | Where-Object { $_.State -ne 'Disabled' })) { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName | Out-Null; Write-Host ('  disabled        {0}' -f $t.Task) }
Write-Host ('The flow task is registered; {0} per-engine task(s) are disabled (recorded in data\flow\replaced-tasks.json -- -Remove enables them again).' -f @($all).Count) -ForegroundColor Green
} finally { Stop-SIScriptRun -Run $siRun }
