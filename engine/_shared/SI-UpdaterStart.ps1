#Requires -Version 5.1
<#
    SecurityInsight -- STARTING THE UPDATER JOB (every edition). PURE helpers, no I/O:
      * Test-SIUpdateNowUpdaterRunning: is an execution of the updater running now (ARM executions shape);
      * New-SIUpdateNowStartTemplate:   the start body for the updater job with SI_UPDATER_MODE set;
      * New-SIJobStartTemplate:         the same body for any job, with any values (the one builder both use).
    Used by the heartbeat's "update now" (SI-UpdateNowSignal.ps1, Pro), by the pipeline runner when an update waits for a
    run (Invoke-SIJobFlowRun.ps1, #897) and by the updater's second update (Start-SIUpdater.ps1, #897). They live here, not
    in SI-UpdateNowSignal.ps1, because the runner and the updater are in every edition and must not load a Pro file.
#>

function Test-SIUpdateNowUpdaterRunning {
    <# PURE. Is an execution of the updater running now? Running / Processing, started within the job's run limit (+15
       minutes; a Running one older than that is a leftover). A Failed / Succeeded / Stopped one -- also a Failed one without
       an endTime -- has ended. Returns the running execution's name, or ''. #>
    param([object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$NowUtc, [int]$RunLimitSeconds = 0)
    $limit = if ($RunLimitSeconds -gt 0) { $RunLimitSeconds + 900 } else { 6 * 3600 }
    foreach ($e in @($Executions)) {
        if ($null -eq $e) { continue }
        $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
        $st = [string]$p.status
        if ($st -notin @('Running', 'Processing')) { continue }
        if ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim()) { continue }
        $start = $null; try { if ($p.PSObject.Properties['startTime'] -and "$($p.startTime)".Trim()) { $start = [datetime]::Parse([string]$p.startTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } } catch { $start = $null }
        if ($start -and ($NowUtc.ToUniversalTime() - $start).TotalSeconds -gt $limit) { continue }
        return $(if ($e.PSObject.Properties['name'] -and $e.name) { [string]$e.name } else { 'an execution' })
    }
    ''
}

function New-SIJobStartTemplate {
    <# PURE. The start body (a JobExecutionTemplate) for ONE execution of a Container Apps job (ARM shape): its own
       container -- name, image, resources, command, args, every env entry (secret references included) -- with -Env
       added, each replacing a variable of the same name (an execution template REPLACES the container's environment, so
       every other variable is kept). The same rule as the web app's start with env (JobRules.StartTemplate). Used for the
       updater (New-SIUpdateNowStartTemplate) and for a support start of the pipeline runner that cancels the running run
       (setup\_shared\SI-StopRunAndUpdate.ps1). #>
    param([Parameter(Mandatory)]$Job, [System.Collections.IDictionary]$Env = @{}, [string]$What = 'the job')
    $c = @($Job.properties.template.containers | Where-Object { $_ })[0]
    if (-not $c) { throw ('{0} has no container to start' -f $What) }
    $vars = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($c.env)) {
        if ($null -eq $e -or $Env.Contains([string]$e.name)) { continue }
        $x = [ordered]@{ name = [string]$e.name }
        if ($e.PSObject.Properties['secretRef'] -and "$($e.secretRef)".Trim()) { $x.secretRef = [string]$e.secretRef } else { $x.value = $(if ($e.PSObject.Properties['value']) { [string]$e.value } else { '' }) }
        $vars.Add([pscustomobject]$x)
    }
    foreach ($k in @($Env.Keys)) { $vars.Add([pscustomobject][ordered]@{ name = [string]$k; value = [string]$Env[$k] }) }
    $out = [ordered]@{ name = [string]$c.name; image = [string]$c.image; env = $vars.ToArray() }
    foreach ($k in 'resources', 'command', 'args') { if ($c.PSObject.Properties[$k] -and $null -ne $c.$k) { $out[$k] = $c.$k } }
    [ordered]@{ containers = @([pscustomobject]$out) }
}

function New-SIUpdateNowStartTemplate {
    <# PURE. The start body for the updater job with SI_UPDATER_MODE = -Mode (default update-now): New-SIJobStartTemplate. #>
    param([Parameter(Mandatory)]$Job, [string]$Mode = 'update-now')
    New-SIJobStartTemplate -Job $Job -Env ([ordered]@{ SI_UPDATER_MODE = $Mode }) -What 'the updater job'
}
