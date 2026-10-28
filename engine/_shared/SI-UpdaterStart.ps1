#Requires -Version 5.1
<#
    SecurityInsight -- STARTING THE UPDATER JOB (every edition). PURE helpers, no I/O:
      * Test-SIUpdateNowUpdaterRunning: is an execution of the updater running now (ARM executions shape);
      * New-SIUpdateNowStartTemplate:   the start body for the updater job with SI_UPDATER_MODE set.
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

function New-SIUpdateNowStartTemplate {
    <# PURE. The start body (a JobExecutionTemplate) for the updater job (ARM shape): its own container -- name, image,
       resources, command, args, every env entry (secret references included) -- with SI_UPDATER_MODE = -Mode (default
       update-now). The same rule as the web app's start with env (JobRules.StartTemplate). #>
    param([Parameter(Mandatory)]$Job, [string]$Mode = 'update-now')
    $c = @($Job.properties.template.containers | Where-Object { $_ })[0]
    if (-not $c) { throw 'the updater job has no container to start' }
    $env = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($c.env)) {
        if ($null -eq $e -or [string]$e.name -eq 'SI_UPDATER_MODE') { continue }
        $x = [ordered]@{ name = [string]$e.name }
        if ($e.PSObject.Properties['secretRef'] -and "$($e.secretRef)".Trim()) { $x.secretRef = [string]$e.secretRef } else { $x.value = $(if ($e.PSObject.Properties['value']) { [string]$e.value } else { '' }) }
        $env.Add([pscustomobject]$x)
    }
    $env.Add([pscustomobject][ordered]@{ name = 'SI_UPDATER_MODE'; value = $Mode })
    $out = [ordered]@{ name = [string]$c.name; image = [string]$c.image; env = $env.ToArray() }
    foreach ($k in 'resources', 'command', 'args') { if ($c.PSObject.Properties[$k] -and $null -ne $c.$k) { $out[$k] = $c.$k } }
    [ordered]@{ containers = @([pscustomobject]$out) }
}
