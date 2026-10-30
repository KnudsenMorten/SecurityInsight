#Requires -Version 5.1
<#
    caj-si-updater -- A BOUND ON THE WAIT (owner 2026-10-29: "why is it it is so hard to get them updated" / "kill all running
    and get them to latest version NOW"). The run gate (SI-UpdaterRunGate.ps1) never installs while a pipeline run is going,
    and it never cancels one itself. On a busy install a new run starts as soon as one ends, so a waiting update could wait
    for ever. Here: an update that has waited MaxWaitHours (6) for a run that STARTED ON AN OLDER VERSION cancels that run
    (the #700 cancel, engine/_shared/SI-Pipeline.ps1 Invoke-SIPipelineCancelRun -OtherVersionThan) and installs; the next
    run starts on the new version. A run that started on the version being installed is never cancelled. The pipeline runner
    starts the updater for such a wait from every wake-up, also a busy one, at most once an hour
    (engine/_shared/SI-Pipeline.ps1 Get-SIPipelineUpdateOverdueStart). REST / .NET only, no PowerShell module.
#>

$script:SIUpdaterWaitBound = @{
    MaxWaitHours      = 6
    # after the cancel: the gate is asked again this often, this far apart, until the install is free
    CancelGateTries   = 10
    CancelGateSeconds = 30
}

function Test-SIUpdaterWaitOverdue {
    <#
        PURE. Has this update waited long enough for a running pipeline run to cancel it? -Gate: the run gate's answer
        (Invoke-SIUpdaterRunGate); -SinceUtc: since when the update waits (the wait mark's SinceUtc, kept across update runs).
        Only a WAIT of kind 'run' that names the run (RunId), with a version to install (-TargetVersion), after -MaxHours
        (6). An unreadable state ('store'), a wait without a run (a step of an ended run, a held lock) or a shorter wait: $false.
    #>
    param($Gate, $SinceUtc, [Parameter(Mandatory)][datetime]$NowUtc, [AllowEmptyString()][string]$TargetVersion = '', [int]$MaxHours = $script:SIUpdaterWaitBound.MaxWaitHours)
    if (-not $Gate -or [string]$Gate.Verdict -ne 'Wait' -or [string]$Gate.Kind -ne 'run' -or -not "$($Gate.RunId)".Trim()) { return $false }
    if (-not "$TargetVersion".Trim() -or $null -eq $SinceUtc -or $MaxHours -le 0) { return $false }
    [bool](($NowUtc.ToUniversalTime() - ([datetime]$SinceUtc).ToUniversalTime()).TotalHours -ge $MaxHours)
}

function Invoke-SIUpdaterOverdueCancel {
    <#
        The update has waited -MaxHours for run <Gate.RunId>: that run is cancelled when it STARTED ON ANOTHER VERSION than
        -TargetVersion (a run of the version being installed, or one whose version the database cannot keep, is left alone),
        then the gate is asked again until the install is free. Seams: -Cancel { param($RunId, $TargetVersion, $Reason) } ->
        @{ Outcome; Text } (Cancelled | SameVersion | NothingRunning | NotThatRun); -GateAgain { } -> a fresh gate answer;
        -Sleep; -Log { param($Message) }. Returns the gate answer to go on with (the original WAIT when nothing was cancelled
        or the install never became free). Never throws.
    #>
    param([Parameter(Mandatory)]$Gate, $SinceUtc, [Parameter(Mandatory)][datetime]$NowUtc, [AllowEmptyString()][string]$TargetVersion = '',
          [Parameter(Mandatory)][scriptblock]$Cancel, [Parameter(Mandatory)][scriptblock]$GateAgain,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Log = { param($m) Write-Host $m },
          [int]$MaxHours = $script:SIUpdaterWaitBound.MaxWaitHours, [int]$Tries = $script:SIUpdaterWaitBound.CancelGateTries, [int]$TrySeconds = $script:SIUpdaterWaitBound.CancelGateSeconds)
    if (-not (Test-SIUpdaterWaitOverdue -Gate $Gate -SinceUtc $SinceUtc -NowUtc $NowUtc -TargetVersion $TargetVersion -MaxHours $MaxHours)) { return $Gate }
    $hours = [int][Math]::Floor(($NowUtc.ToUniversalTime() - ([datetime]$SinceUtc).ToUniversalTime()).TotalHours)
    $why = 'an update to {0} waited {1} hours for this run, which started on an older version -- the run is cancelled so the update can be installed; the next run starts on the new version' -f $TargetVersion, $hours
    $cx = $null
    try { $cx = & $Cancel ([string]$Gate.RunId) $TargetVersion $why } catch { $cx = [pscustomobject]@{ Outcome = 'Error'; Text = [string]$_.Exception.Message } }
    $outcome = if ($cx -and $cx.PSObject.Properties['Outcome']) { [string]$cx.Outcome } else { 'Error' }
    $text = if ($cx -and $cx.PSObject.Properties['Text']) { [string]$cx.Text } else { '' }
    if ($outcome -ne 'Cancelled') {
        & $Log ('the update has waited {0} hours for run {1}; it was not cancelled ({2}: {3}) -- the update keeps waiting' -f $hours, $Gate.RunId, $outcome, $text)
        return $Gate
    }
    & $Log ('the update had waited {0} hours for run {1}: {2}' -f $hours, $Gate.RunId, $text)
    $last = $Gate
    for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) {
        $g = $null
        try { $g = & $GateAgain } catch { $g = $null }
        if ($g) { $last = $g }
        if ($g -and $g.Go) { return $g }
        if ($i -lt $Tries) { & $Sleep $TrySeconds }
    }
    & $Log ('run {0} is cancelled, but the install was not free yet ({1}) -- the update is installed at its next start' -f $Gate.RunId, $(if ($last) { [string]$last.Reason } else { 'no answer' }))
    $last
}

function Invoke-SIUpdaterCancelOldRun {
    <#
        The REAL cancel the update makes -- the #700 cancel (engine/_shared/SI-Pipeline.ps1 Invoke-SIPipelineCancelRun) over
        the install's state store, run by the updater itself (an older pipeline image could not take a cancel beside its
        running runner): the run's runner execution is stopped first, the run is marked Cancelled, its running executions and
        their queue workers are stopped, the lock is freed. Only run -RunId, and only when it started on another version than
        -TargetVersion. -SIRoot: the code this updater image carries (/si). Returns the cancel's result.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$TargetVersion, [string]$Reason = '',
          [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId, [string]$Holder = '', [string]$SIRoot = '')
    $root = $SIRoot
    if (-not $root) { foreach ($c in @('/si', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..'))) { if ($c -and (Test-Path -LiteralPath ([IO.Path]::Combine($c, 'engine', '_shared', 'SI-JobFlow.ps1')))) { $root = [IO.Path]::GetFullPath($c); break } } }
    if (-not $root -or -not (Test-Path -LiteralPath ([IO.Path]::Combine($root, 'engine', '_shared', 'SI-JobFlow.ps1')))) { throw 'this updater image does not carry the pipeline code -- the run is not cancelled' }
    . ([IO.Path]::Combine($root, 'engine', '_shared', 'SI-JobFlow.ps1'))
    $jobs = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/jobs'
    $installed = @()
    try { $installed = @(Invoke-SIUpdaterArm -Path $jobs -List | ForEach-Object { [string]$_.name } | Where-Object { $_ -like 'caj-si-*' }) } catch { $installed = @() }
    $stopExec = {
        param($JobName, $Execution)
        try { $null = Invoke-SIUpdaterArm -Method POST -Path ('{0}/{1}/stop/{2}' -f $jobs, $JobName, $Execution) -Body @{} }
        catch { if (-not (Test-SIJobFlowStopAlreadyEnded -Message ([string]$_.Exception.Message))) { throw } }
    }
    # a step's execution: its own job, or the producer of a collection in parts
    $stop = { param($Job, $Execution)
        $k = Get-SIJobFlowKey $Job
        $name = if ($installed -contains ('caj-si-{0}-producer' -f $k) -and $installed -notcontains ('caj-si-{0}' -f $k)) { 'caj-si-{0}-producer' -f $k } else { 'caj-si-{0}' -f $k }
        & $stopExec $name $Execution }
    # the step's queue workers that started since the step did (their queue runs end with the run)
    $stopWorkers = { param($Job, $SinceUtc, $Execution)
        foreach ($w in @(Get-SIJobFlowWorkerJobs -Job $Job -Installed $installed)) {
            $wk = [string]$w.Job; if (-not $wk) { continue }
            $list = @(Invoke-SIUpdaterArm -Path ('{0}/{1}/executions' -f $jobs, $wk) -List)
            foreach ($e in @($list | Where-Object { $_ -and $_.properties -and [string]$_.properties.status -in @('Running', 'Processing') })) {
                if ($SinceUtc -and $e.properties.startTime -and ([datetime]$e.properties.startTime).ToUniversalTime() -lt ([datetime]$SinceUtc).ToUniversalTime().AddMinutes(-5)) { continue }
                & $stopExec $wk ([string]$e.name)
            }
        } }
    $stopRunner = { param($RunnerHolder) if ([string]$RunnerHolder -match '^caj-si-flow-[a-z0-9\-]+$') { & $stopExec 'caj-si-flow' ([string]$RunnerHolder) } else { throw ("'{0}' is not an execution of the pipeline job" -f $RunnerHolder) } }
    Invoke-SIPipelineCancelRun -Store (New-SIJobFlowSqlStore -Invoke $Store.Invoke) -Control (New-SIPipelineSqlControl -Invoke $Store.Invoke) -FlowRunId $RunId -OtherVersionThan $TargetVersion `
        -By ('the update to {0}' -f $TargetVersion) -Reason $Reason -Self $Holder -Stop $stop -StopWorkers $stopWorkers -StopRunner $stopRunner -Log { param($l, $m) Write-UpdLog $m }
}
