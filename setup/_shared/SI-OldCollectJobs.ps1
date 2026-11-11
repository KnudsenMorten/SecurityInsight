#Requires -Version 5.1
<#
    SecurityInsight -- THE OLD COLLECTION JOBS FROM BEFORE THE SPLIT ARE REMOVED ON UPDATE.

    The move to queue scaling (setup\_shared\SI-KedaConvert.ps1) gives identity, endpoint and Azure a producer and
    queue-scaled workers and takes the old single job's timer -- the old job is KEPT on purpose (its schedule remembered),
    so a failed move leaves the collection running. Nothing removed it afterwards: installs that moved still carried
    caj-si-azure, caj-si-endpoint and caj-si-identity, which a standard-names check reports as unknown jobs.

    Every update (setup\Invoke-SIContainerUpdate.ps1, step 9r) removes such an old job ONLY when ALL of these hold, each
    read LIVE from Azure in this run:
      (f) its name is one of the three above (never any other job) and SI's setup made it (its si-build tag);
      (a) its producer caj-si-<engine>-producer AND worker caj-si-<engine>-worker exist and read back;
      (b) it has no timer of its own (trigger Manual) -- one that still has a timer is kept and named;
      (e) the pipeline does not start it: each step resolves to its job by the runner's own rule (a step whose producer
          exists starts the producer, else caj-si-<step>) -- the stored pipeline, else the default one over the installed
          jobs; a stored pipeline that cannot be read keeps it;
      (c) no execution of it is Running or Processing;
      (d) no execution of it started after the split: later than one hour after the producer was created (an execution
          in that first hour belongs to the move itself -- the old job loses its timer only after its producer is made).
          Rule (d) holds only for a fixed time: until 14 days after the producer was created. After that, a run started
          by hand after the split no longer keeps the job and the other conditions decide (a run going on now is still
          kept by (c), always);
      (h) the producer has completed at least one collection (an execution that Succeeded) -- which also keeps the old
          job through the very update that made the split.
    Then ONE ARM DELETE of the job (the updater's own rights in its resource group), read back until it answers 404, and
    one plain line. Nothing else is touched -- no identity, no registry, no role: deleting the job is enough.
    Idempotent (a job that is gone is not mentioned). NEVER throws; a failure is one line, and the next update tries
    again. -WhatIf: the plan (live reads only, no DELETE).

    NO az CLI, no PowerShell module: every call goes through ONE seam,
    -Rest { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body }.
#>

$script:SIOldCollectLibRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Test-SIBootstrapJobIsSI -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIOldCollectLibRoot, 'container', '_shared', 'SI-ContainerConfig.ps1')) }
if (-not (Get-Command New-SIDefaultJobFlow -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIOldCollectLibRoot, 'engine', '_shared', 'SI-JobFlow.ps1')) }

# the ONLY names this step ever removes
$script:SIOldCollectJobNames = @('caj-si-azure', 'caj-si-endpoint', 'caj-si-identity')
$script:SIOldCollectArmApi = '2025-07-01'
# an execution of the old job that started within this long after the producer was created belongs to the move itself
$script:SIOldCollectAllowanceMinutes = 60
# rule (d) -- a run after the split keeps the old job -- holds only this long after the producer was created
$script:SIOldCollectAfterSplitHoldDays = 14

function Get-SIOldCollectProp {
    <# PURE. A property of a parsed ARM object, $null when absent. #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($p)) { $o = $o[$p] } else { return $null }; continue }
        $pp = $o.PSObject.Properties[$p]; if (-not $pp) { return $null }; $o = $pp.Value
    }
    $o
}

function ConvertTo-SIOldCollectUtc {
    <# PURE. An ARM time (an ISO string, or what ConvertFrom-Json made of it) as a UTC DateTime; $null when unreadable. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $o = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$o)) { return $o.UtcDateTime }
    $null
}

function Get-SIOldCollectPipelineJobs {
    <#
        PURE. The job each step of the pipeline starts, by the runner's own rule (Add-SIJobFlowCollectParts): a step whose
        producer caj-si-<step>-producer is installed starts the producer, every other step starts caj-si-<step>.
        -Definition: the stored pipeline; $null = the default pipeline over the installed jobs (as the runner has it).
        -Names: the installed job names. Returns the job names (lower case).
    #>
    param([AllowEmptyCollection()][string[]]$Names = @(), $Definition, $Map)
    $have = @($Names | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    if (-not $Definition) {
        if (-not $Map) { $Map = Get-SIJobFlowMap }
        $Definition = New-SIDefaultJobFlow -Installed @($have | ForEach-Object { Get-SIJobFlowStepKey $_ } | Select-Object -Unique) -Map $Map
    }
    @(@($Definition.Steps) | Where-Object { $_ -and "$($_.Job)".Trim() } | ForEach-Object {
        $k = Get-SIJobFlowStepKey ([string]$_.Job)
        if ($have -contains "caj-si-$k-producer") { "caj-si-$k-producer" } else { "caj-si-$k" }
    } | Select-Object -Unique)
}

function Invoke-SIOldCollectJobRemoval {
    <#
        Removes the old single collection jobs that the split left behind (the conditions: this file's header).
        -Jobs: the job list (ARM shape) -- only to know which of the three are there; every condition is read again live.
        -Definition: the stored pipeline ($null = the default); -DefinitionUnreadable: the install keeps a stored pipeline
        that could not be read (then no old job is removed).
        Returns @{ Results = @(@{ Job; Action = removed | would-remove | keep | failed; Line }); Lines }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [AllowEmptyCollection()][object[]]$Jobs = @(), $Definition, [switch]$DefinitionUnreadable, $Map, [switch]$WhatIf,
          [int]$PollSeconds = 5, [int]$PollMax = 24, $Now)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $add = { param($j, $a, $l) $results.Add([pscustomobject]@{ Job = $j; Action = $a; Line = $l }); if ($l) { $lines.Add($l) } }
    try {
        # -Now: the clock (tests); default the real UTC time
        $nowUtc = $null; if ($null -ne $Now) { $nowUtc = ConvertTo-SIOldCollectUtc $Now }; if (-not $nowUtc) { $nowUtc = [datetime]::UtcNow }
        $arm = 'https://management.azure.com/'
        $call = {
            param([string]$Method, [string]$Uri)
            $r = $null
            try { $r = & $Rest $Method $Uri $null $arm @{} } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
            if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }
            $r
        }
        $isOk = { param($r) $r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) if (-not $r -or -not "$($r.Body)".Trim()) { return $null }; $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; $o }
        $why = { param($r) $t = ("$(if ($r) { $r.Body })" -replace '\s+', ' ').Trim(); if ($t.Length -gt 200) { $t = $t.Substring(0, 197) + '...' }; ('HTTP {0}{1}' -f $(if ($r) { [int]$r.Status } else { 0 }), $(if ($t) { ": $t" } else { '' })) }
        $jobUri = { param($n, [string]$Tail) 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}{3}?api-version={4}' -f $SubscriptionId, $ResourceGroup, $n, $Tail, $script:SIOldCollectArmApi }
        # the executions of a job, every page (at most 5; Azure lists the newest first); $null when they cannot be read
        $execs = {
            param([string]$n)
            $all = New-Object System.Collections.Generic.List[object]; $u = & $jobUri $n '/executions'; $pg = 0
            while ($u -and $pg -lt 5) {
                $r = & $call 'GET' $u; $pg++
                if (-not (& $isOk $r)) { return $null }
                $b = & $parse $r
                foreach ($v in @(Get-SIOldCollectProp $b @('value'))) { if ($v) { $all.Add($v) } }
                $u = [string](Get-SIOldCollectProp $b @('nextLink'))
            }
            , $all.ToArray()
        }
        $names = @(@($Jobs) | Where-Object { $_ } | ForEach-Object { [string](Get-SIOldCollectProp $_ @('name')) } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
        $pipelineJobs = $null
        foreach ($old in $script:SIOldCollectJobNames) {
            if ($names -notcontains $old) { continue }
            $e = $old.Substring(7); $pName = "caj-si-$e-producer"; $wName = "caj-si-$e-worker"
            $keep = { param([string]$Why) & $add $old 'keep' ('old collection job {0} is kept -- {1}' -f $old, $Why) }
            try {
                # the old job itself, read live
                $r = & $call 'GET' (& $jobUri $old '')
                if ([int]$r.Status -eq 404) { continue }   # already gone: nothing to say
                if (-not (& $isOk $r)) { & $keep ('it could not be read ({0}); the next update looks again' -f (& $why $r)); continue }
                $job = & $parse $r
                # (f) SI's own job
                if (-not (Test-SIBootstrapJobIsSI -Job $job)) { & $keep 'SecurityInsight''s setup did not create it (no si-build tag), so the update never removes it'; continue }
                # (a) the producer and the worker exist and read back
                $pr = & $call 'GET' (& $jobUri $pName ''); $wr = & $call 'GET' (& $jobUri $wName '')
                $prod = $(if (& $isOk $pr) { & $parse $pr } else { $null }); $work = $(if (& $isOk $wr) { & $parse $wr } else { $null })
                if (-not $prod -or -not $work) {
                    $miss = @(); if (-not $prod) { $miss += $pName }; if (-not $work) { $miss += $wName }
                    & $keep ('the collection has not been split in parts here: {0} {1} not there' -f ($miss -join ' and '), $(if ($miss.Count -gt 1) { 'are' } else { 'is' })); continue
                }
                $bad = @(@(@{ N = $pName; J = $prod }, @{ N = $wName; J = $work }) | Where-Object { $ps = [string](Get-SIOldCollectProp $_.J @('properties', 'provisioningState')); $ps -and $ps -ne 'Succeeded' })
                if ($bad.Count) { & $keep ('{0} is not ready (provisioning {1})' -f $bad[0].N, [string](Get-SIOldCollectProp $bad[0].J @('properties', 'provisioningState'))); continue }
                # (b) no timer of its own
                $trigger = [string](Get-SIOldCollectProp $job @('properties', 'configuration', 'triggerType'))
                if ($trigger -eq 'Schedule') { & $keep ('it still has its own timer ({0}) -- a job on a timer is never removed' -f [string](Get-SIOldCollectProp $job @('properties', 'configuration', 'scheduleTriggerConfig', 'cronExpression'))); continue }
                if ($trigger -ne 'Manual') { & $keep ('its trigger is {0}, not manual' -f $(if ($trigger) { $trigger } else { 'unknown' })); continue }
                # (e) the pipeline does not start it
                if ($DefinitionUnreadable) { & $keep 'the stored pipeline could not be read, so it is not known that the pipeline no longer starts it'; continue }
                if ($null -eq $pipelineJobs) { $pipelineJobs = @(Get-SIOldCollectPipelineJobs -Names $names -Definition $Definition -Map $Map) }
                if ($pipelineJobs -contains $old) { & $keep 'the pipeline still starts it'; continue }
                # (c) nothing of it running, (d) nothing of it started after the split
                $ox = & $execs $old
                if ($null -eq $ox) { & $keep 'its runs could not be read; the next update looks again'; continue }
                $running = @($ox | Where-Object { [string](Get-SIOldCollectProp $_ @('properties', 'status')) -in @('Running', 'Processing') })
                if ($running.Count) { & $keep ('a run of it is going on now ({0})' -f [string](Get-SIOldCollectProp $running[0] @('name'))); continue }
                $created = ConvertTo-SIOldCollectUtc (Get-SIOldCollectProp $prod @('systemData', 'createdAt'))
                if (-not $created) { & $keep ('when {0} was created could not be read, so it is not known that the old job has not run since' -f $pName); continue }
                $cut = $created.AddMinutes($script:SIOldCollectAllowanceMinutes)
                $after = @($ox | Where-Object { $t = ConvertTo-SIOldCollectUtc (Get-SIOldCollectProp $_ @('properties', 'startTime')); $t -and $t -gt $cut })
                # (d) holds only until 14 days after the producer was created; after that the other conditions decide
                if ($after.Count -and $nowUtc -le $created.AddDays($script:SIOldCollectAfterSplitHoldDays)) { & $keep ('it has run since the collection was split in parts ({0}, started {1:yyyy-MM-dd HH:mm} UTC)' -f [string](Get-SIOldCollectProp $after[0] @('name')), (ConvertTo-SIOldCollectUtc (Get-SIOldCollectProp $after[0] @('properties', 'startTime')))); continue }
                # (h) the producer has completed a collection
                $px = & $execs $pName
                if ($null -eq $px) { & $keep ('the runs of {0} could not be read; the next update looks again' -f $pName); continue }
                if (-not @($px | Where-Object { [string](Get-SIOldCollectProp $_ @('properties', 'status')) -eq 'Succeeded' }).Count) { & $keep ('{0} has not completed a collection yet' -f $pName); continue }
                if ($WhatIf) { & $add $old 'would-remove' ('an old collection job from before the collection was split in parts would be removed: {0} (re-run with -Apply)' -f $old); continue }
                # the delete, read back until it answers 404
                $d = & $call 'DELETE' (& $jobUri $old '')
                if (-not ((& $isOk $d) -or [int]$d.Status -eq 404)) { & $add $old 'failed' ('old collection job {0} was NOT removed ({1}) -- the update goes on; the next update tries again' -f $old, (& $why $d)); continue }
                $gone = $false
                for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
                    $g = & $call 'GET' (& $jobUri $old '')
                    if ([int]$g.Status -eq 404) { $gone = $true; break }
                    if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
                }
                if (-not $gone) { & $add $old 'failed' ('old collection job {0} was NOT removed (it is still there after the delete) -- the update goes on; the next update tries again' -f $old); continue }
                & $add $old 'removed' ('an old collection job from before the collection was split in parts is removed: {0}' -f $old)
            } catch { & $add $old 'failed' ('old collection job {0} was NOT removed ({1}) -- the update goes on; the next update tries again' -f $old, $_.Exception.Message) }
        }
    } catch {
        $lines.Add(('old collection jobs: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray() }
}
