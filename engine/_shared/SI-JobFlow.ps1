#Requires -Version 5.1
<#
    SecurityInsight -- the daily job FLOW (#269).

    Operator 2026-10-04: "define it as a flow and NOT timer based, so it starts job run and then job 2 start when 1
    completes" / "i prefer the job flow queue, where i define an order and start time for the flow and then not control
    it per schedule" / "make both options, but flow is default/preferred".

    ONE flow per install: one start time + cadence, and an ORDERED list of steps (jobs). A step starts when the step
    before it has ENDED; a step marked "start together with the step above" (WithPrevious) joins that step's group, and
    the group waits for all of its members. Per step: Enabled, OnFailure (stop | continue | skip-dependents -- the
    default skips only the steps that NEED the failed one, transitively, from config\job-flow.locked.json) and a timeout.

    This file is the ENGINE-SIDE half and is host-neutral:
      * the definition (JSON, the same shape the web app writes to cfg.JobFlow and a VM keeps in
        config\job-flow.custom.json) -- read, validated, defaulted;
      * the RUNNER (Invoke-SIJobFlow) -- pure over its seams: -Start / -Poll / -Stop (ARM in a container job, local
        processes on a VM, a fake in tests), -Save (the run record), -Now / -Sleep (the clock);
      * the adapters: ARM (container), local process (VM), and three run-record stores (file, blob, Pro SQL).

    🔒 A STEP NEVER RUNS TWICE. The run record is saved BEFORE a step is started (state Starting) and again with the
    execution name once it has. A runner that crashes and is started again RESUMES the record: a Running step is polled
    (not started), a Starting step -- unknown whether it started -- is reported Interrupted and never started again, a
    finished day is reported, not repeated. A record whose heartbeat is fresh belongs to a runner that is still alive:
    the second runner refuses. PS 5.1 and 7.
#>

$script:SIJobFlow = @{
    SIRoot      = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    OnFailure   = @('skip-dependents', 'stop', 'continue')
    # 'interval' = every IntervalMinutes AFTER the previous run FINISHED (SCHED-1.1); the others are a time of day
    Cadences    = @('daily', 'weekdays', 'weekly', 'interval')
    # the flow job's cron only WAKES the runner (SCHED-1.1: a clock trigger never stands in for the cadence)
    TickCron    = '*/5 * * * *'
    Final       = @('Success', 'Failed', 'TimedOut', 'Interrupted', 'Skipped', 'Disabled')
    Failures    = @('Failed', 'TimedOut', 'Interrupted')
    # a RUN that has ended (#700: Cancelled = ended on purpose by a person or by the updater; never resumed)
    RunFinished = @('Succeeded', 'Failed', 'Stopped', 'Cancelled')
    ArmApi      = '2025-07-01'
    # Working rule 4 -- only the PLATFORM gets re-run (live 2026-10-05: a step's container died before the engine ran).
    # A step whose container never started the engine is started again this many times, after this pause; a run longer
    # than NeverStartedMaxSeconds is never called "never started".
    StartRetries           = 1
    StartRetryBackoff      = 60
    NeverStartedMaxSeconds = 120
    # A RUNNING step that shows no sign of progress is REPORTED, never stopped (owner 2026-10-12: "Warn only"): no new log
    # line and no run-health record for SilentAfterMinutes -> ONE warning for that step in that run. Asked for at most
    # every ProgressCheckMinutes, and only once the step has run that long.
    SilentAfterMinutes     = 120
    ProgressCheckMinutes   = 30
    # the shipped default LAYOUT (CONVERGE-DEFAULTS, framework 12.16): 1 = every step one after the other; 2 = the steps of a
    # stage that read nothing of each other's same-day output start together (the map's defaultPipeline 'withPrevious');
    # 3 (#754) = Risk Analysis Summary and Detailed start together too (the stage's 'withPreviousSince' names the level each
    # one came with). A stored pipeline below this level that still has the default layout of ITS level is brought to it as
    # it is read (Update-SIJobFlowDefaultLayout) and by the update (setup/_shared/SI-PipelineLayout.ps1); one a person
    # changed is only marked, never re-laid.
    # 4 (#636) = Risk Analysis Summary is off by default (the map's 'defaultEnabled': false): a stored pipeline still the
    # default of its level with every step on gets the step switched off; one a person changed keeps it (said once).
    DefaultsLevel          = 4
    SummaryOffSince        = 4
}
# #306: pipelines and stages (schema 2, the stage gate, the install's run lock and queue) -- one dot-source for every caller
. (Join-Path $PSScriptRoot 'SI-Pipeline.ps1')
# #532: THROTTLE-IS-NORMAL -- a step whose engine was only throttled is 'throttled', not a failure (framework §12.18)
if (-not (Get-Command -Name Get-SIThrottleText -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Throttle.ps1') }
# the failed step's class + first error lines for the pipeline's report (Get-SIJobFlowStepFailure)
if (-not (Get-Command -Name Get-SIErrorLines -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-ErrorClass.ps1') }

# =====================================================================================================================
#  The map (config\job-flow.locked.json) and the definition
# =====================================================================================================================
function Get-SIJobFlowMap {
    <# The dependency map + default flow. PURE over -Path (default: config\job-flow.locked.json of this solution). #>
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path (Join-Path $script:SIJobFlow.SIRoot 'config') 'job-flow.locked.json' }
    $raw = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $jobs = [ordered]@{}
    foreach ($j in @($raw.jobs)) {
        $t = 0; if ($j.PSObject.Properties['timeoutMinutes']) { $t = [int]$j.timeoutMinutes }
        $never = $false; if ($j.PSObject.Properties['neverInFlow']) { $never = [bool]$j.neverInFlow }
        $cron = ''; if ($j.PSObject.Properties['defaultCron']) { $cron = [string]$j.defaultCron }
        $stage = ''; if ($j.PSObject.Properties['stage']) { $stage = [string]$j.stage }
        $manual = $false; if ($j.PSObject.Properties['manualInFlowMode']) { $manual = [bool]$j.manualInFlowMode }
        $own = $false; if ($j.PSObject.Properties['ownSchedule']) { $own = [bool]$j.ownSchedule }
        $retired = $false; if ($j.PSObject.Properties['retired']) { $retired = [bool]$j.retired }
        # 'reads': jobs whose output of the SAME day this job reads when it is there, and does without (the previous run's)
        # when it is not -- not a need (a failure skips nothing), but a step started together with one reads the run before
        $reads = @(); if ($j.PSObject.Properties['reads']) { $reads = @(@($j.reads) | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
        # 'runsOnStored': the step holds back by itself whatever is not complete, so when a step it needs did not succeed in
        # this run it still runs, on what is stored (Get-SIPipelineStoredDataRun). Not set = it needs THIS run's output.
        $stored = $false; if ($j.PSObject.Properties['runsOnStored']) { $stored = [bool]$j.runsOnStored }
        $jobs[[string]$j.key] = [pscustomobject]@{ Key = [string]$j.key; Engine = [string]$j.engine; Needs = @(@($j.needs) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                                                   TimeoutMinutes = $t; NeverInFlow = ($never -or $own -or $retired); DefaultCron = $cron; Stage = $stage; ManualInFlowMode = $manual; OwnSchedule = $own
                                                   Retired = $retired; Reads = $reads; RunsOnStored = $stored
                                                   # 'brings': what the job would have brought, in plain words; 'assetBuild': the build of the merged assets
                                                   Brings = $(if ($j.PSObject.Properties['brings']) { [string]$j.brings } else { '' })
                                                   AssetBuild = $(if ($j.PSObject.Properties['assetBuild']) { [bool]$j.assetBuild } else { $false })
                                                   # 'niceToHave': the step's failure holds only the steps that need it (Risk Analysis Summary);
                                                   # 'runsWithoutNiceToHave': the step runs in full when only nice-to-have steps failed
                                                   NiceToHave = $(if ($j.PSObject.Properties['niceToHave']) { [bool]$j.niceToHave } else { $false })
                                                   RunsWithoutNiceToHave = $(if ($j.PSObject.Properties['runsWithoutNiceToHave']) { [bool]$j.runsWithoutNiceToHave } else { $false })
                                                   # #754 'startsWhenReady': in a run of the whole pipeline the step starts as soon as the steps it reads
                                                   # have ended (Get-SIJobFlowAwaited), not after every step above it
                                                   StartsWhenReady = $(if ($j.PSObject.Properties['startsWhenReady']) { [bool]$j.startsWhenReady } else { $false })
                                                   # #754 'heldBy': steps it does not read but waits for by the owner's rule (a failed Detailed holds every connector)
                                                   HeldBy = @($(if ($j.PSObject.Properties['heldBy']) { @($j.heldBy) | Where-Object { $_ } | ForEach-Object { [string]$_ } }))
                                                   # #748 'required': the update adds the step to a stored pipeline without it (where its job is installed)
                                                   Required = $(if ($j.PSObject.Properties['required']) { [bool]$j.required } else { $false })
                                                   # #636 'defaultEnabled': false = a new pipeline has the step switched off (Risk Analysis Summary)
                                                   DefaultEnabled = $(if ($j.PSObject.Properties['defaultEnabled']) { [bool]$j.defaultEnabled } else { $true }) }
    }
    # #306: the default PIPELINE (stages in order, each with its steps); a map without one gets it from defaultFlow by stage.
    # A stage's 'withPrevious' names the steps that start together with the step above them (DefaultsLevel 2), and its
    # 'withPreviousSince' the layout level each of them came with (#754; none named = level 2, the first such level).
    $pipe = $null
    if ($raw.PSObject.Properties['defaultPipeline'] -and $raw.defaultPipeline) {
        $pipe = [pscustomobject]@{ Id = [string]$raw.defaultPipeline.id; Name = [string]$raw.defaultPipeline.name
                                   Stages = @(@($raw.defaultPipeline.stages) | Where-Object { $_ } | ForEach-Object {
                                       $since = @{}
                                       if ($_.PSObject.Properties['withPreviousSince'] -and $_.withPreviousSince) { foreach ($sp in @($_.withPreviousSince.PSObject.Properties)) { $since[[string]$sp.Name] = [int]$sp.Value } }
                                       [pscustomobject]@{ Id = [string]$_.id; Name = [string]$_.name; Steps = @(@($_.steps) | ForEach-Object { [string]$_ })
                                                          WithPrevious = @($(if ($_.PSObject.Properties['withPrevious']) { @($_.withPrevious) | Where-Object { $_ } | ForEach-Object { [string]$_ } }))
                                                          WithPreviousSince = $since } }) }
    } else {
        $pipe = [pscustomobject]@{ Id = 'daily'; Name = 'Daily pipeline'; Stages = @(foreach ($sid in @('collect', 'correlate', 'deliver')) {
            [pscustomobject]@{ Id = $sid; Name = (Get-Culture).TextInfo.ToTitleCase($sid); Steps = @(@($raw.defaultFlow) | ForEach-Object { [string]$_ } | Where-Object { $jobs.Contains($_) -and $jobs[$_].Stage -eq $sid }); WithPrevious = @(); WithPreviousSince = @{} } }) }
    }
    [pscustomobject]@{
        Jobs = $jobs; DefaultFlow = @(@($raw.defaultFlow) | ForEach-Object { [string]$_ })
        DefaultPipeline = $pipe
        DefaultStartTime = [string]$raw.defaultStartTime; DefaultCadence = [string]$raw.defaultCadence
        DefaultTimeZone = $(if ($raw.PSObject.Properties['defaultTimeZone'] -and $raw.defaultTimeZone) { [string]$raw.defaultTimeZone } else { 'UTC' })
        DefaultTimeoutMinutes = [int]$raw.defaultTimeoutMinutes
    }
}

function Get-SIJobFlowKey {
    <# PURE. 'caj-si-endpoint' -> 'endpoint' (the key the map and the definition use). #>
    param([AllowEmptyString()][AllowNull()][string]$Name)
    $k = ([string]$Name).Trim().ToLowerInvariant()
    if ($k.StartsWith('caj-si-')) { $k = $k.Substring(7) }
    $k
}

function Get-SIJobFlowJobName { param([Parameter(Mandatory)][string]$Key) 'caj-si-' + $Key }

function Get-SIJobFlowWorkerJobs {
    <#
        PURE. #882: the jobs whose executions work FOR a step's job -- what must stop when the pipeline ends, interrupts or
        cancels that step (live 2026-10-22, internal: the Detailed Risk Analysis step was closed Interrupted and its queue
        worker went on for 50 minutes and wrote state the next run used):
          * a collection in parts: caj-si-<key>-worker (the producer caj-si-<key>-producer is the step's own execution);
          * Risk Analysis on queue workers: caj-si-raworker-<grain> (RA-ScaleOut.ps1), whose runs live under
            collect/ra-<grain>/ in the state store -- RunsFolder, where the pipeline marks the step's run closed.
        -Installed: the install's job names; only a worker job that exists is returned (none known = every candidate).
        Returns @(@{ Job (the worker job's name); RunsFolder ('' = none to close) }).
    #>
    param([AllowEmptyString()][string]$Job, [string[]]$Installed = $null)
    $k = Get-SIJobFlowKey $Job
    if (-not $k) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $cand = New-Object System.Collections.Generic.List[object]
    $cand.Add([pscustomobject]@{ Job = ('caj-si-{0}-worker' -f $k); RunsFolder = '' })
    if ($k -eq 'risk-analysis-detailed') { $cand.Add([pscustomobject]@{ Job = 'caj-si-raworker-detailed'; RunsFolder = 'ra-detailed' }) }
    elseif ($k -eq 'risk-analysis') { $cand.Add([pscustomobject]@{ Job = 'caj-si-raworker-summary'; RunsFolder = 'ra-summary' }) }
    foreach ($c in $cand) {
        if ($null -ne $Installed -and @($Installed).Count -and -not (@($Installed) -contains [string]$c.Job)) {
            # the queue workers' runs are closed even where their job is not listed: a worker inside the producer's own
            # container (no worker job) reads the same mark
            if ([string]$c.RunsFolder) { $out.Add([pscustomobject]@{ Job = ''; RunsFolder = [string]$c.RunsFolder }) }
            continue
        }
        $out.Add($c)
    }
    $out.ToArray()
}

function Test-SIJobFlowOwnSchedule {
    <#
        PURE. $true for a job that runs on its OWN daily timer in every mode and is never a step of any pipeline: the
        updater (framework UPDATE-1.6 (a): one updater per environment, daily at 03:00 UTC on its own schedule, plus started
        on a release -- never inside the product's daily pipeline). The map marks it 'ownSchedule'; the updater is one
        whatever the map says, so an older map cannot put it back into a pipeline. Why: the updater waits while any SI job
        runs, and a running pipeline is an SI job -- as a step it waited for itself and never updated (found live, ring 1).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Job, $Map)
    $k = Get-SIJobFlowKey $Job
    if ($k -eq 'updater') { return $true }
    [bool]($Map -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['OwnSchedule'] -and $Map.Jobs[$k].OwnSchedule)
}

function Test-SIJobFlowRetired {
    <#
        PURE. $true for a job that does nothing any more and is never a step: asset-properties (#412, operator 2026-10-06:
        "we dont pull in the same data twice" -- the endpoint, identity and azure profilers publish the full asset metadata
        themselves). The map marks it 'retired'; asset-properties is one whatever the map says, so an older map cannot put
        it back into a pipeline.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Job, $Map)
    $k = Get-SIJobFlowKey $Job
    if ($k -eq 'asset-properties') { return $true }
    [bool]($Map -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['Retired'] -and $Map.Jobs[$k].Retired)
}

function Remove-SIJobFlowOwnScheduleStep {
    <#
        PURE. A stored pipeline (schema 1 or 2) without the steps that are never steps (Test-SIJobFlowOwnSchedule: the
        updater; Test-SIJobFlowRetired: a retired job -- asset-properties, #412). Each dropped step is said in
        .MigrationNotes and the definition is marked .Migrated, so the runner logs it and the web app shows it; saving the
        pipeline stores it without the step. A step that started together with the dropped one starts on its own when it
        is now the first of its stage. The input is not changed.
    #>
    param([Parameter(Mandatory)]$Definition, $Map)
    $isDropped = { param($j) (Test-SIJobFlowOwnSchedule -Job $j -Map $Map) -or (Test-SIJobFlowRetired -Job $j -Map $Map) }
    $drop = @(@($Definition.Steps) | Where-Object { $_ -and (& $isDropped ([string]$_.Job)) })
    if (-not $drop.Count) { return $Definition }
    $keep = New-Object System.Collections.Generic.List[object]
    $prevStage = $null
    foreach ($s in @($Definition.Steps)) {
        if ($null -eq $s -or (& $isDropped ([string]$s.Job))) { continue }
        $c = $s.PSObject.Copy()
        $st = Get-SIPipelineStepStage $c
        if ([bool]$c.WithPrevious -and ($keep.Count -eq 0 -or $prevStage -ne $st)) { $c.WithPrevious = $false }
        $keep.Add($c); $prevStage = $st
    }
    $d = $Definition.PSObject.Copy()
    $d.Steps = $keep.ToArray()
    $notes = New-Object System.Collections.Generic.List[string]
    if ($Definition.PSObject.Properties['MigrationNotes']) { foreach ($n in @($Definition.MigrationNotes)) { if ($n) { $notes.Add([string]$n) } } }
    foreach ($x in $drop) {
        if (Test-SIJobFlowRetired -Job ([string]$x.Job) -Map $Map) { $notes.Add(('{0} was a step of the stored pipeline and is taken out: it is retired -- the endpoint, identity and azure profilers read each source once and publish the full asset metadata themselves' -f $x.Job)) }
        else { $notes.Add(('{0} was a step of the stored pipeline and is taken out: the updater runs on its own daily schedule (18:30 in the local time of the install''s Azure region), never inside the pipeline -- it waits while the pipeline runs, so as a step it waited for itself' -f $x.Job)) }
    }
    $d | Add-Member -NotePropertyName Migrated -NotePropertyValue $true -Force
    $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force
    $d
}

function Move-SIJobFlowStepAfterNeeds {
    <#
        PURE. A step runs after every step it NEEDS (the map's 'needs') when that step is in a later STAGE. v3 data model (V3-DATA-MODEL part 2, P4): Risk
        Analysis now needs the CI build, so a pipeline stored when Risk Analysis ran in Collect -- before the job it now
        reads -- gets that step moved to right after the last step it needs, into that step's stage, and says so in
        .MigrationNotes (.Migrated); saving the pipeline stores the new order. A need that is not a step of the pipeline is
        ignored (as everywhere in the flow), so nothing moves where that job is not installed. The input is not changed.
    #>
    param([Parameter(Mandatory)]$Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Definition.Steps)) { if ($s) { $steps.Add($s.PSObject.Copy()) } }
    $moved = New-Object System.Collections.Generic.List[string]
    $why = @{}
    $changed = $true; $guard = 0
    while ($changed -and $guard -lt 50) {
        $changed = $false; $guard++
        for ($i = 0; $i -lt $steps.Count; $i++) {
            $k = [string]$steps[$i].Job
            if (-not $Map.Jobs.Contains($k)) { continue }
            $last = -1
            # only a need in a LATER STAGE moves the step (a stored stage layout that predates the dependency); a misorder
            # inside one stage stays as it is and is warned about by Test-SIJobFlowDefinition, as before
            $myStage = Get-SIPipelineStepStage $steps[$i]
            $later = New-Object System.Collections.Generic.List[string]
            foreach ($n in @($Map.Jobs[$k].Needs)) { for ($j = $i + 1; $j -lt $steps.Count; $j++) { if ([string]$steps[$j].Job -eq $n -and (Get-SIPipelineStepStage $steps[$j]) -ne $myStage) { if ($j -gt $last) { $last = $j }; if (-not $later.Contains($n)) { $later.Add($n) } } } }
            if ($last -lt 0) { continue }
            $m = $steps[$i]; $steps.RemoveAt($i)
            $at = $last                                   # the needed step slid one place up: insert right after it ...
            while ($at -lt $steps.Count -and $moved.Contains([string]$steps[$at].Job)) { $at++ }   # ... and after the steps moved there before (their order is kept)
            $m.Stage = Get-SIPipelineStepStage $steps[$last - 1]
            $m.WithPrevious = $false
            $steps.Insert($at, $m)
            if (-not $moved.Contains($k)) { $moved.Add($k) }
            $why[$k] = $later.ToArray()
            $changed = $true
            break
        }
    }
    if ($moved.Count -eq 0) { return $Definition }
    # a step that started together with a moved one starts on its own when it is now the first of its stage
    $prevStage = $null
    for ($i = 0; $i -lt $steps.Count; $i++) {
        $st = Get-SIPipelineStepStage $steps[$i]
        if ([bool]$steps[$i].WithPrevious -and ($i -eq 0 -or $prevStage -ne $st)) { $steps[$i].WithPrevious = $false }
        $prevStage = $st
    }
    $d = $Definition.PSObject.Copy()
    $d.Steps = $steps.ToArray()
    $notes = New-Object System.Collections.Generic.List[string]
    if ($Definition.PSObject.Properties['MigrationNotes']) { foreach ($n in @($Definition.MigrationNotes)) { if ($n) { $notes.Add([string]$n) } } }
    foreach ($k in $moved) { $notes.Add(('{0} now runs after {1}: it reads its output' -f $k, (@($why[$k]) -join ', '))) }
    $d | Add-Member -NotePropertyName Migrated -NotePropertyValue $true -Force
    $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force
    $d
}
function New-SIJobFlowStep {
    param([Parameter(Mandatory)][string]$Job, [bool]$Enabled = $true, [bool]$WithPrevious = $false, [string]$OnFailure = 'skip-dependents', [int]$TimeoutMinutes = 240, [string]$Stage = '')
    [pscustomobject]@{ Job = $Job; Enabled = $Enabled; WithPrevious = $WithPrevious; OnFailure = $OnFailure; TimeoutMinutes = $TimeoutMinutes; Stage = $Stage }
}

function New-SIDefaultJobFlow {
    <#
        PURE. The default PIPELINE (#306, schema 2) for the jobs that are installed (-Installed: keys or caj-si-* names):
        the map's defaultPipeline -- Collect -> Correlate -> Deliver -- each stage one step after the other, except a step the
        stage names in 'withPrevious' (it reads nothing of the step above it from the same day): it starts together with
        the step above it when that step is installed. Each step with the map's timeout and its stage's on-failure default
        (Deliver: continue -- the targets are independent). Mode 'flow', the map's start time, daily, DefaultsLevel = the
        current layout. The three stages are always there (a stage with no installed job is empty).
    #>
    param([AllowEmptyCollection()][string[]]$Installed = @(), $Map,
          # the start time (HH:mm) and its time zone: the settings SI_Pipeline_StartTime / SI_Pipeline_TimeZone, else the
          # map's defaults: 19:00 Danish time (Europe/Copenhagen) when no region is known, after the 18:30 update (owner 2026-10-21).
          # The zone is read for a start time that is SET; with no start time the default time keeps its default zone.
          [string]$StartTime = [string]$global:SI_Pipeline_StartTime, [string]$TimeZone = [string]$global:SI_Pipeline_TimeZone)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    if ($StartTime -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { $StartTime = $Map.DefaultStartTime; $TimeZone = $Map.DefaultTimeZone }
    if (-not $TimeZone.Trim()) { $TimeZone = $Map.DefaultTimeZone }
    $have = @($Installed | ForEach-Object { Get-SIJobFlowKey $_ })
    $steps = New-Object System.Collections.Generic.List[object]
    $stages = New-Object System.Collections.Generic.List[object]
    foreach ($st in @($Map.DefaultPipeline.Stages)) {
        $stages.Add((New-SIPipelineStage -Id $st.Id -Name $st.Name))
        foreach ($k in @($st.Steps)) {
            if ($have -notcontains $k) { continue }
            $t = $Map.DefaultTimeoutMinutes
            if ($Map.Jobs.Contains($k) -and $Map.Jobs[$k].TimeoutMinutes -gt 0) { $t = $Map.Jobs[$k].TimeoutMinutes }
            $with = Test-SIJobFlowTogetherWithShippedAbove -Stage $st.Id -Job $k -Present $have -Map $Map
            # #636: a step the map ships switched off (Risk Analysis Summary: 'defaultEnabled': false) is there, off
            $on = -not ($Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['DefaultEnabled'] -and -not [bool]$Map.Jobs[$k].DefaultEnabled)
            $steps.Add((New-SIJobFlowStep -Job $k -Enabled $on -TimeoutMinutes $t -OnFailure (Get-SIPipelineStageOnFailure $st.Id) -Stage $st.Id -WithPrevious $with))
        }
    }
    New-SIPipelineDefinition -Id $Map.DefaultPipeline.Id -Name $Map.DefaultPipeline.Name -Mode 'flow' -StartTime $StartTime -Cadence $Map.DefaultCadence `
        -Weekday 1 -IntervalMinutes 1440 -Stages $stages.ToArray() -Steps $steps.ToArray() -TimeZone $TimeZone -DefaultsLevel $script:SIJobFlow.DefaultsLevel
}

function Test-SIJobFlowTogetherWithShippedAbove {
    <# PURE. Does -Job start together with the step SHIPPED right above it in -Stage? Only when the stage names it in
       'withPrevious' AND that step is in -Present: with it missing the job starts on its own (it would otherwise join a
       step whose same-day output it reads -- endpoint after identity when azure is not installed).
       -Level (#754): the default layout of THAT level -- a step that came with a later level ('withPreviousSince') is not
       together there (default: the current level). #>
    param([Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][string]$Job, [AllowEmptyCollection()][string[]]$Present = @(), $Map,
          [int]$Level = $script:SIJobFlow.DefaultsLevel)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $st = @(@($Map.DefaultPipeline.Stages) | Where-Object { [string]$_.Id -eq $Stage })[0]
    if (-not $st -or -not $st.PSObject.Properties['WithPrevious'] -or @($st.WithPrevious) -notcontains $Job) { return $false }
    $since = 2
    if ($st.PSObject.Properties['WithPreviousSince'] -and $st.WithPreviousSince -and $st.WithPreviousSince.ContainsKey($Job)) { $since = [int]$st.WithPreviousSince[$Job] }
    if ($since -gt $Level) { return $false }
    $i = [array]::IndexOf(@($st.Steps), $Job)
    ($i -gt 0) -and (@($Present) -contains [string]@($st.Steps)[$i - 1])
}

function Update-SIJobFlowDefaultLayout {
    <#
        PURE. CONVERGE-DEFAULTS (framework 12.16) for the pipeline's LAYOUT. A stored pipeline below the current DefaultsLevel
        that still has the default layout OF ITS OWN LEVEL -- each step starts together with the step above it exactly where
        that level's default says (level 1: nowhere, every step one after the other; level 2: endpoint with azure), and each
        stage's steps exactly the shipped default's steps in the shipped order (a job not installed is simply absent) --
        gets the current layout: each step a stage names in the map's 'withPrevious' starts together with the step above it
        (level 3, #754: Risk Analysis Detailed with Risk Analysis Summary). Nothing else of a step changes (on/off, on
        failure, timeout stay as they are). A pipeline a person changed (a group of their own, another order, a step moved
        to another stage, a custom step) is NOT re-laid. Either way the result carries the current DefaultsLevel, so once
        it is saved the decision is never made again -- a person who then runs those steps one after the other keeps that.
        Changed: .Migrated + one line in .MigrationNotes per step (the runner logs it, the web app shows it; saving stores
        it -- and the update stores it, setup/_shared/SI-PipelineLayout.ps1). Idempotent; the input is not changed.
        Level 4 (#636): on such a default pipeline with every step on, a step the map ships switched off ('defaultEnabled':
        false -- Risk Analysis Summary) is switched off, with its line; a pipeline a person changed keeps the step as it is,
        and one line says so.
    #>
    param([Parameter(Mandatory)]$Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $level = if ($Definition.PSObject.Properties['DefaultsLevel'] -and [int]$Definition.DefaultsLevel -ge 1) { [int]$Definition.DefaultsLevel } else { 1 }
    $now = [int]$script:SIJobFlow.DefaultsLevel
    if ($level -ge $now) { return $Definition }
    $d = $Definition.PSObject.Copy()
    $d | Add-Member -NotePropertyName DefaultsLevel -NotePropertyValue $now -Force
    $steps = @(@($Definition.Steps) | Where-Object { $_ })
    # the default of the stored level: each stage is the shipped stage's steps in the shipped order, and a step starts
    # together with the one above it exactly where that level's default put it
    $want = New-Object System.Collections.Generic.List[string]
    $present = @($steps | ForEach-Object { [string]$_.Job })
    foreach ($st in @($Map.DefaultPipeline.Stages)) { foreach ($k in @($st.Steps)) { if ($present -contains $k) { $want.Add(('{0}|{1}' -f $st.Id, $k)) } } }
    $got = @($steps | ForEach-Object { '{0}|{1}' -f (Get-SIPipelineStepStage $_), [string]$_.Job })
    $isOld = ($got.Count -eq $want.Count) -and (($got -join ';') -eq (($want.ToArray()) -join ';'))
    if ($isOld) {
        for ($i = 0; $i -lt $steps.Count; $i++) {
            $sid = Get-SIPipelineStepStage $steps[$i]
            $was = ($i -gt 0) -and (Get-SIPipelineStepStage $steps[$i - 1]) -eq $sid -and (Test-SIJobFlowTogetherWithShippedAbove -Stage $sid -Job ([string]$steps[$i].Job) -Present @([string]$steps[$i - 1].Job) -Map $Map -Level $level)
            if ([bool]$steps[$i].WithPrevious -ne [bool]$was) { $isOld = $false; break }
        }
    }
    $notes = New-Object System.Collections.Generic.List[string]
    if ($Definition.PSObject.Properties['MigrationNotes']) { foreach ($n in @($Definition.MigrationNotes)) { if ($n) { $notes.Add([string]$n) } } }
    # level 4 (#636): the steps the map ships switched off (Risk Analysis Summary) -- switched off on a pipeline that is still
    # the default of its level with every step on; a pipeline a person changed keeps the step as it is (one line says so)
    $summaryOff = ($level -lt [int]$script:SIJobFlow.SummaryOffSince)
    $offJobs = @($Map.Jobs.Keys | Where-Object { $Map.Jobs[$_].PSObject.Properties['DefaultEnabled'] -and -not [bool]$Map.Jobs[$_].DefaultEnabled })
    $keptNote = { param($k) '{0} stays switched on: the pipeline was changed by a person -- the Summary report is optional now (every Summary view is a grouping of the Detailed findings); switch the step off on the Jobs page when nobody reads its mail' -f $k }
    if (-not $isOld) {
        if ($summaryOff) {
            $kept = @($steps | Where-Object { $offJobs -contains [string]$_.Job -and [bool]$_.Enabled })
            if ($kept.Count) {
                foreach ($s in $kept) { $notes.Add((& $keptNote ([string]$s.Job))) }
                $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force
            }
        }
        return $d
    }
    $out = New-Object System.Collections.Generic.List[object]
    $prev = $null; $changed = $false
    foreach ($s in $steps) {
        $c = $s.PSObject.Copy()
        $sid = Get-SIPipelineStepStage $c
        if (-not [bool]$c.WithPrevious -and $prev -and (Get-SIPipelineStepStage $prev) -eq $sid -and (Test-SIJobFlowTogetherWithShippedAbove -Stage $sid -Job ([string]$c.Job) -Present @([string]$prev.Job) -Map $Map)) {
            $c.WithPrevious = $true; $changed = $true
            $notes.Add(('{0} now starts together with {1} (the new default: neither reads the other''s output of the same day) -- to run them one after the other again, untick "start together" and save' -f $c.Job, $prev.Job))
        }
        $out.Add($c); $prev = $c
    }
    if ($summaryOff) {
        $allOn = -not @($steps | Where-Object { -not [bool]$_.Enabled }).Count
        foreach ($c in $out) {
            if ($offJobs -notcontains [string]$c.Job -or -not [bool]$c.Enabled) { continue }
            if ($allOn) {
                $c.Enabled = $false; $changed = $true
                $notes.Add(('{0} is now switched off (the new default: the Summary report is optional -- every Summary view is a grouping of the Detailed findings) -- to run it again, switch the step on and save' -f $c.Job))
            } else { $notes.Add((& $keptNote ([string]$c.Job))) }
        }
        if (-not $changed -and $notes.Count) { $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force }
    }
    $d.Steps = $out.ToArray()
    if ($changed) {
        $d | Add-Member -NotePropertyName Migrated -NotePropertyValue $true -Force
        $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force
    }
    $d
}

function ConvertFrom-SIJobFlowJson {
    <#
        PURE. A definition from its JSON (camelCase, as the web app and config\job-flow.custom.json write it). Missing
        fields take their defaults; nothing is validated here (Test-SIJobFlowDefinition does).
        #306: schema 2 (stages[], each with its steps) is read as it is; a schema-1 flow (one steps[] list) is MIGRATED
        in memory (ConvertFrom-SIPipelineSchema1: lossless, .Migrated + .MigrationNotes) -- every reader reads both.
        Either schema: a step that is never a step (the updater -- it runs on its own daily schedule) is dropped, in the notes.
    #>
    param([Parameter(Mandatory)][string]$Json, $Map)
    $o = $Json | ConvertFrom-Json
    $p = { param($obj, $n, $d) if ($obj.PSObject.Properties[$n] -and $null -ne $obj.$n -and "$($obj.$n)" -ne '') { $obj.$n } else { $d } }
    $readStep = { param($s, $stage, $defOf) New-SIJobFlowStep -Job (Get-SIJobFlowKey ([string](& $p $s 'job' ''))) -Enabled ([bool](& $p $s 'enabled' $true)) -WithPrevious ([bool](& $p $s 'withPrevious' $false)) `
                    -OnFailure ([string](& $p $s 'onFailure' $defOf)).ToLowerInvariant() -TimeoutMinutes ([int](& $p $s 'timeoutMinutes' 240)) -Stage $stage }
    $schema = [int](& $p $o 'schema' 1)
    $mode = ([string](& $p $o 'mode' 'flow')).ToLowerInvariant()
    $start = [string](& $p $o 'startTime' '01:00'); $cad = ([string](& $p $o 'cadence' 'daily')).ToLowerInvariant()
    $wd = [int](& $p $o 'weekday' 1); $iv = [int](& $p $o 'intervalMinutes' 1440)
    # a schedule stored before time zones has none: its time was UTC, and stays UTC
    $tzId = [string](& $p $o 'timeZone' 'UTC')
    if ($schema -ge 2 -and $o.PSObject.Properties['stages'] -and $null -ne $o.stages) {
        $stages = New-Object System.Collections.Generic.List[object]
        $steps = New-Object System.Collections.Generic.List[object]
        foreach ($st in @($o.stages)) {
            if ($null -eq $st) { continue }
            $sid = ([string](& $p $st 'id' 'custom')).ToLowerInvariant()
            $stages.Add((New-SIPipelineStage -Id $sid -Name ([string](& $p $st 'name' (Get-SIPipelineStageName $sid))) -RunIfPreviousFailed ([bool](& $p $st 'runIfPreviousFailed' $false))))
            foreach ($s in @($st.steps)) { if ($null -ne $s) { $steps.Add((& $readStep $s $sid (Get-SIPipelineStageOnFailure $sid))) } }
        }
        $d2 = New-SIPipelineDefinition -Id ([string](& $p $o 'id' 'daily')) -Name ([string](& $p $o 'name' 'Daily pipeline')) -Mode $mode -StartTime $start -Cadence $cad -Weekday $wd -IntervalMinutes $iv `
                    -Stages $stages.ToArray() -Steps $steps.ToArray() -TimeZone $tzId -DefaultsLevel ([int](& $p $o 'defaults' 1))
        # the updater is never a step (UPDATE-1.6): a pipeline stored before that loses the step, and says so; a pipeline
        # still on the old default layout gets the current one (CONVERGE-DEFAULTS)
        return (Update-SIJobFlowDefaultLayout -Definition (Move-SIJobFlowStepAfterNeeds -Definition (Remove-SIJobFlowOwnScheduleStep -Definition $d2 -Map $Map) -Map $Map) -Map $Map)
    }
    $steps1 = foreach ($s in @($o.steps)) {
        if ($null -eq $s) { continue }
        & $readStep $s '' 'skip-dependents'
    }
    $v1 = [pscustomobject]@{ Schema = 1; Mode = $mode; StartTime = $start; TimeZone = $tzId; Cadence = $cad; Weekday = $wd; IntervalMinutes = $iv; Steps = @($steps1) }
    Update-SIJobFlowDefaultLayout -Definition (Move-SIJobFlowStepAfterNeeds -Definition (Remove-SIJobFlowOwnScheduleStep -Definition (ConvertFrom-SIPipelineSchema1 -Definition $v1 -Map $Map) -Map $Map) -Map $Map) -Map $Map
}

function ConvertTo-SIJobFlowJson {
    <#
        PURE. The definition as JSON (camelCase, schema 2) -- the shape ConvertFrom-SIJobFlowJson and the web app read:
        stages[] (id, name, runIfPreviousFailed, steps[]) AND the same steps flattened in steps[] (each with its stage),
        so a reader of schema 1 (an older runner or web app during the update) still sees the whole flow in its order.
    #>
    param([Parameter(Mandatory)]$Definition)
    $iv = $(if ($Definition.PSObject.Properties['IntervalMinutes'] -and $Definition.IntervalMinutes) { [int]$Definition.IntervalMinutes } else { 1440 })
    $id = if ($Definition.PSObject.Properties['Id'] -and $Definition.Id) { [string]$Definition.Id } else { 'daily' }
    $name = if ($Definition.PSObject.Properties['Name'] -and $Definition.Name) { [string]$Definition.Name } else { 'Daily pipeline' }
    $stepJson = { param($s) ConvertTo-Json -Compress -InputObject ([ordered]@{ job = [string]$s.Job; stage = (Get-SIPipelineStepStage $s); enabled = [bool]$s.Enabled; withPrevious = [bool]$s.WithPrevious; onFailure = [string]$s.OnFailure; timeoutMinutes = [int]$s.TimeoutMinutes }) }
    $stageJson = foreach ($st in @(Get-SIPipelineStages -Definition $Definition)) {
        $mine = @(@($Definition.Steps) | Where-Object { (Get-SIPipelineStepStage $_) -eq [string]$st.Id })
        $head = ConvertTo-Json -Compress -InputObject ([ordered]@{ id = [string]$st.Id; name = [string]$st.Name; runIfPreviousFailed = [bool]$st.RunIfPreviousFailed })
        $head.Substring(0, $head.Length - 1) + ',"steps":[' + ((@($mine | ForEach-Object { & $stepJson $_ })) -join ',') + ']}'
    }
    $lvl = if ($Definition.PSObject.Properties['DefaultsLevel'] -and [int]$Definition.DefaultsLevel -ge 1) { [int]$Definition.DefaultsLevel } else { 1 }
    $head = ConvertTo-Json -Compress -InputObject ([ordered]@{ schema = 2; id = $id; name = $name; mode = [string]$Definition.Mode; startTime = [string]$Definition.StartTime; timeZone = (Get-SIPipelineTimeZoneId $Definition); cadence = [string]$Definition.Cadence; weekday = [int]$Definition.Weekday; intervalMinutes = $iv; defaults = $lvl })
    # built by hand: PS 5.1 collapses a one-element array to an object, and nesting stages in steps would need it twice
    $head.Substring(0, $head.Length - 1) + ',"stages":[' + (@($stageJson) -join ',') + '],"steps":[' + ((@(@($Definition.Steps) | ForEach-Object { & $stepJson $_ })) -join ',') + ']}'
}

function Test-SIJobFlowDefinition {
    <#
        PURE. @{ Problems; Warnings } -- Problems refuse the definition (the runner does not start), Warnings are said and
        the flow runs: an unknown / duplicate / never-in-flow job, an unknown OnFailure, a timeout outside 5-4320 min, a
        start time that is not HH:mm, an unknown cadence (problems); a step placed before a job it needs, a job not
        installed (warnings). -Installed (keys or names) enables the "not installed" check.
    #>
    param([Parameter(Mandatory)]$Definition, $Map, [string[]]$Installed)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $problems = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    if ([string]$Definition.StartTime -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { $problems.Add(("the start time '{0}' is not HH:mm (UTC)" -f $Definition.StartTime)) }
    if ($script:SIJobFlow.Cadences -notcontains [string]$Definition.Cadence) { $problems.Add(("the cadence '{0}' is not one of {1}" -f $Definition.Cadence, ($script:SIJobFlow.Cadences -join ', '))) }
    if ([string]$Definition.Cadence -eq 'weekly' -and ([int]$Definition.Weekday -lt 0 -or [int]$Definition.Weekday -gt 6)) { $problems.Add('the weekday must be 0 (Sunday) to 6') }
    if ([string]$Definition.Cadence -eq 'interval' -and ([int]$Definition.IntervalMinutes -lt 5 -or [int]$Definition.IntervalMinutes -gt 10080)) { $problems.Add('the interval must be 5 minutes to 7 days (the rest between the end of one run and the start of the next)') }
    $seen = @{}
    $pos = @{}
    $i = 0
    $have = if ($null -ne $Installed) { @($Installed | ForEach-Object { Get-SIJobFlowKey $_ }) } else { $null }
    foreach ($s in @($Definition.Steps)) {
        $i++
        $k = [string]$s.Job
        if (-not $k -or $k -notmatch '^[a-z0-9][a-z0-9\-]{0,24}$') { $problems.Add(("step {0}: '{1}' is not a job" -f $i, $k)); continue }
        if ($seen.ContainsKey($k)) { $problems.Add(("step {0}: {1} is already step {2}" -f $i, $k, $seen[$k])); continue }
        $seen[$k] = $i
        if (Test-SIJobFlowOwnSchedule -Job $k -Map $Map) { $problems.Add(("step {0}: {1} is never part of the pipeline -- the updater runs on its own daily schedule" -f $i, $k)) }
        elseif (Test-SIJobFlowRetired -Job $k -Map $Map) { $problems.Add(("step {0}: {1} is retired -- the profilers publish the full asset metadata themselves" -f $i, $k)) }
        elseif ($Map.Jobs.Contains($k) -and $Map.Jobs[$k].NeverInFlow) { $problems.Add(("step {0}: {1} is never part of the flow (it is started on demand)" -f $i, $k)) }
        if ($script:SIJobFlow.OnFailure -notcontains [string]$s.OnFailure) { $problems.Add(("step {0} ({1}): on failure '{2}' is not one of {3}" -f $i, $k, $s.OnFailure, ($script:SIJobFlow.OnFailure -join ', '))) }
        if ([int]$s.TimeoutMinutes -lt 5 -or [int]$s.TimeoutMinutes -gt 4320) { $problems.Add(("step {0} ({1}): the timeout must be 5-4320 minutes" -f $i, $k)) }
        if ($null -ne $have -and $have -notcontains $k) { $warnings.Add(("step {0}: {1} is not installed -- it is reported as failed when the flow reaches it" -f $i, $k)) }
        if ($i -eq 1 -and [bool]$s.WithPrevious) { $warnings.Add(("step 1 ({0}) has no step above to start together with" -f $k)) }
    }
    # a step before a job it needs reads yesterday's output
    $groups = Get-SIJobFlowGroups -Definition $Definition
    foreach ($g in $groups) { foreach ($s in $g.Steps) { $pos[[string]$s.Job] = $g.Index } }
    foreach ($g in $groups) {
        foreach ($s in $g.Steps) {
            if (-not $Map.Jobs.Contains([string]$s.Job)) { continue }
            foreach ($n in $Map.Jobs[[string]$s.Job].Needs) {
                if ($pos.ContainsKey($n) -and $pos[$n] -ge $g.Index) {
                    $warnings.Add(("{0} runs {1} {2}, which it needs -- it reads {2}'s output from the run before" -f $s.Job, $(if ($pos[$n] -eq $g.Index) { 'together with' } else { 'before' }), $n))
                }
            }
            # a soft same-day read (the map's 'reads'): nothing is skipped when it fails, but run before / together with it the
            # job uses its previous run's output
            foreach ($n in @($(if ($Map.Jobs[[string]$s.Job].PSObject.Properties['Reads']) { $Map.Jobs[[string]$s.Job].Reads }))) {
                if ($n -and $pos.ContainsKey($n) -and $pos[$n] -ge $g.Index) {
                    $warnings.Add(("{0} runs {1} {2}, whose output of the same day it reads -- it uses {2}'s previous run instead" -f $s.Job, $(if ($pos[$n] -eq $g.Index) { 'together with' } else { 'before' }), $n))
                }
            }
        }
    }
    # #306: the stages (known ids, each once, Deliver after Collect, the steps in stage order)
    $sc = Test-SIPipelineStages -Definition $Definition
    foreach ($x in @($sc.Problems)) { $problems.Add($x) }
    foreach ($x in @($sc.Warnings)) { $warnings.Add($x) }
    [pscustomobject]@{ Problems = $problems.ToArray(); Warnings = $warnings.ToArray() }
}

function Get-SIJobFlowCron {
    <# PURE. The schedule as a cron (UTC) from the start time + cadence -- for display only: the runner wakes every 5
       minutes and decides with Get-SIJobFlowLatestSlot, so a time zone's daylight saving needs no cron change. In a time
       zone other than UTC the hour is today's (-NowUtc). #>
    param([Parameter(Mandatory)]$Definition, [datetime]$NowUtc = [datetime]::UtcNow)
    $h, $m = ([string]$Definition.StartTime) -split ':'
    $h = [int]$h; $m = [int]$m
    if ((Get-SIPipelineTimeZoneId $Definition) -ne 'UTC') {
        $z = (Resolve-SIPipelineTimeZone (Get-SIPipelineTimeZoneId $Definition)).Zone
        $u = ConvertTo-SIPipelineUtc -Local ([TimeZoneInfo]::ConvertTimeFromUtc([datetime]::SpecifyKind($NowUtc.ToUniversalTime(), 'Utc'), $z).Date.AddHours($h).AddMinutes($m)) -Zone $z
        $h = $u.Hour; $m = $u.Minute
    }
    switch ([string]$Definition.Cadence) {
        'weekdays' { '{0} {1} * * 1-5' -f $m, $h }
        'weekly'   { '{0} {1} * * {2}' -f $m, $h, [int]$Definition.Weekday }
        default    { '{0} {1} * * *' -f $m, $h }
    }
}

function Get-SIJobFlowCadenceText {
    <# PURE. The cadence in words: "daily at 01:00 UTC" / "every 6 h after the previous run finished". #>
    param([Parameter(Mandatory)]$Definition)
    $at = Get-SIPipelineScheduleText -Definition $Definition
    switch ([string]$Definition.Cadence) {
        'interval' { $iv = [int]$Definition.IntervalMinutes; if ($iv % 60 -eq 0) { 'every {0} h after the previous run finished' -f ($iv / 60) } else { 'every {0} min after the previous run finished' -f $iv } }
        'weekdays' { 'weekdays at {0}' -f $at }
        'weekly'   { '{0}s at {1}' -f ([DayOfWeek]([int]$Definition.Weekday % 7)), $at }
        default    { 'daily at {0}' -f $at }
    }
}

function Get-SIJobFlowGroups {
    <# PURE. The steps as groups in order: a step with WithPrevious joins the group above it -- never across a stage
       (#306: the first step of a stage always starts a group). @(@{ Index; Stage; Steps }). #>
    param([Parameter(Mandatory)]$Definition)
    $groups = New-Object System.Collections.Generic.List[object]
    $cur = $null
    foreach ($s in @($Definition.Steps)) {
        $sid = Get-SIPipelineStepStage $s
        if ($null -eq $cur -or -not [bool]$s.WithPrevious -or $cur.Stage -ne $sid) {
            $cur = [pscustomobject]@{ Index = $groups.Count + 1; Stage = $sid; Steps = (New-Object System.Collections.Generic.List[object]) }
            $groups.Add($cur)
        }
        $cur.Steps.Add($s)
    }
    , $groups.ToArray()
}

function Get-SIJobFlowDependents {
    <# PURE. The flow's steps that need -Job, directly or through another step (transitively), by the map. #>
    param([Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)]$Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $inFlow = @(@($Definition.Steps) | ForEach-Object { [string]$_.Job })
    $out = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Generic.Queue[string]
    $queue.Enqueue($Job)
    while ($queue.Count) {
        $x = $queue.Dequeue()
        foreach ($k in $inFlow) {
            if ($out.Contains($k) -or $k -eq $Job) { continue }
            if ($Map.Jobs.Contains($k) -and $Map.Jobs[$k].Needs -contains $x) { $out.Add($k); $queue.Enqueue($k) }
        }
    }
    , $out.ToArray()
}

function Get-SIJobFlowAwaited {
    <#
        PURE. #754 -- WHAT A STEP OF A RUN WAITS FOR before it may start: @{ Early; Jobs; Reads }.
          * Every step: the steps of the groups above it (-State: the run record, its steps in order with their Group) --
            the group-by-group order (a group starts when every step above it has ended). Early = $false.
          * A Deliver step the map marks 'startsWhenReady', in a run of the WHOLE pipeline (Scope 'pipeline'; a re-run
            from a step too): only the steps above it that it READS -- its 'needs' and 'reads', followed through the jobs
            those read in turn (a job not in this run is followed too, never waited for) -- and every step above it that is
            not in Correlate or Deliver (Collect, a custom stage) -- plus its 'heldBy' (steps it does not read but that hold
            it by the owner's rule: the CMDB connectors read only the CIs, and wait for Risk Analysis Detailed because a
            failed Detailed holds every connector). Early = $true; Reads = the steps of Correlate / Deliver it waits for.
            Risk Analysis Detailed is enough for the vulnerability connector and the CMDB connectors -- none of them waits for
            the Summary; the data sync reads both Risk Analysis reports and the vulnerability connector.
        -NoEarly: an install's first collection -- every step waits for the steps above it.
        A step never waits for a step placed below it (it reads that one's previous run, as Test-SIJobFlowDefinition warns),
        so the first waiting step of a run can always start.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Step, $Map,
          # an install's first collection: every step waits for the steps above it (nothing is written to the customer's
          # systems before one run is complete)
          [switch]$NoEarly)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $k = Get-SIJobFlowKey ([string]$Step.Job)
    $above = @(@($State.Steps) | Where-Object { $_ -and [int]$_.Group -lt [int]$Step.Group })
    $scope = if ($State.PSObject.Properties['Scope'] -and $State.Scope) { [string]$State.Scope } else { 'pipeline' }
    $early = -not $NoEarly -and $scope -eq 'pipeline' -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['StartsWhenReady'] -and [bool]$Map.Jobs[$k].StartsWhenReady -and
             (Get-SIPipelineStepStage $Step) -eq 'deliver'
    if (-not $early) { return [pscustomobject]@{ Early = $false; Jobs = @($above | ForEach-Object { [string]$_.Job }); Reads = @() } }
    # what it reads, followed through what those read
    $reads = @{}
    $queue = New-Object System.Collections.Generic.Queue[string]
    $queue.Enqueue($k)
    # ... and what holds it by rule without being read ('heldBy': the CMDB connectors wait for Risk Analysis Detailed)
    foreach ($h in @($(if ($Map.Jobs[$k].PSObject.Properties['HeldBy']) { $Map.Jobs[$k].HeldBy }))) { if ($h -and -not $reads.ContainsKey([string]$h)) { $reads[[string]$h] = $true; $queue.Enqueue([string]$h) } }
    while ($queue.Count) {
        $x = $queue.Dequeue()
        if (-not $Map.Jobs.Contains($x)) { continue }
        $r = @(@($Map.Jobs[$x].Needs) + @($(if ($Map.Jobs[$x].PSObject.Properties['Reads']) { $Map.Jobs[$x].Reads })) | Where-Object { $_ })
        foreach ($n in $r) { if (-not $reads.ContainsKey([string]$n)) { $reads[[string]$n] = $true; $queue.Enqueue([string]$n) } }
    }
    $jobs = New-Object System.Collections.Generic.List[string]
    $readJobs = New-Object System.Collections.Generic.List[string]
    foreach ($a in $above) {
        $j = [string]$a.Job
        if ((Get-SIPipelineStepStage $a) -notin @('correlate', 'deliver')) { $jobs.Add($j); continue }
        if ($reads.ContainsKey($j)) { $jobs.Add($j); $readJobs.Add($j) }
    }
    [pscustomobject]@{ Early = $true; Jobs = $jobs.ToArray(); Reads = $readJobs.ToArray() }
}

function Add-SIJobFlowRequiredStep {
    <#
        PURE. #748 -- a stored pipeline WITHOUT a step the map marks 'required' (the verification service: it runs the daily
        data health check, CR2) gets it, where its job is installed (-Installed: keys or caj-si-* names): in its stage, at
        its place in the default order (after the last step that comes before it there), else last in that stage -- the
        same place the web app's "include" gives it -- with the map's timeout and its stage's on-failure default. Said in
        .MigrationNotes (.Migrated); the update stores it (setup/_shared/SI-PipelineLayout.ps1). A step that is there,
        switched on or off, is left as it is. Idempotent; the input is not changed.
    #>
    param([Parameter(Mandatory)]$Definition, [AllowEmptyCollection()][string[]]$Installed = @(), $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $have = @($Installed | ForEach-Object { Get-SIJobFlowKey $_ })
    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Definition.Steps)) { if ($s) { $steps.Add($s.PSObject.Copy()) } }
    $stageIds = @(Get-SIPipelineStages -Definition $Definition | ForEach-Object { [string]$_.Id })
    $order = @($Map.DefaultFlow)
    $added = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Map.Jobs.Keys)) {
        $j = $Map.Jobs[$k]
        if (-not ($j.PSObject.Properties['Required'] -and [bool]$j.Required) -or $j.NeverInFlow) { continue }
        if ($have -notcontains $k) { continue }
        if (@($steps | Where-Object { [string]$_.Job -eq $k }).Count) { continue }
        $stage = if ($j.Stage -and $stageIds -contains [string]$j.Stage) { [string]$j.Stage } elseif ($stageIds.Count) { [string]$stageIds[-1] } else { 'deliver' }
        $rank = [array]::IndexOf($order, $k)
        $inStage = @(for ($i = 0; $i -lt $steps.Count; $i++) { if ((Get-SIPipelineStepStage $steps[$i]) -eq $stage) { $i } })
        if ($rank -ge 0 -and $inStage.Count) {
            $before = @($inStage | Where-Object { $r = [array]::IndexOf($order, [string]$steps[$_].Job); $r -ge 0 -and $r -lt $rank })
            $at = if ($before.Count) { [int]$before[-1] + 1 } else { [int]$inStage[0] }
        } elseif ($inStage.Count) { $at = [int]$inStage[-1] + 1 }
        else {
            $si = [array]::IndexOf($stageIds, $stage)
            $next = @(for ($i = 0; $i -lt $steps.Count; $i++) { if ([array]::IndexOf($stageIds, [string](Get-SIPipelineStepStage $steps[$i])) -gt $si) { $i } })
            $at = if ($next.Count) { [int]$next[0] } else { $steps.Count }
        }
        $t = $Map.DefaultTimeoutMinutes; if ($j.TimeoutMinutes -gt 0) { $t = $j.TimeoutMinutes }
        $steps.Insert($at, (New-SIJobFlowStep -Job $k -TimeoutMinutes $t -OnFailure (Get-SIPipelineStageOnFailure $stage) -Stage $stage))
        $added.Add($k)
    }
    if (-not $added.Count) { return $Definition }
    $d = $Definition.PSObject.Copy()
    $d.Steps = $steps.ToArray()
    $notes = New-Object System.Collections.Generic.List[string]
    if ($Definition.PSObject.Properties['MigrationNotes']) { foreach ($n in @($Definition.MigrationNotes)) { if ($n) { $notes.Add([string]$n) } } }
    foreach ($k in $added) { $notes.Add(('{0} is now a step of the pipeline: every pipeline has it -- it runs the daily data health check (its off switch is the setting SI_DataHealth_Enabled)' -f $k)) }
    $d | Add-Member -NotePropertyName Migrated -NotePropertyValue $true -Force
    $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force
    $d
}

# =====================================================================================================================
#  The run record
# =====================================================================================================================
function New-SIJobFlowRunState {
    <# PURE. A new run record: every step Waiting (a disabled step Disabled), in definition order. #>
    param([Parameter(Mandatory)]$Definition, [Parameter(Mandatory)][datetime]$NowUtc, [string]$FlowRunId, [string]$Trigger = 'schedule', [string]$FromStep,
          # SCHED-1.1: the time-of-day slot this run is for (none for a manual / interval run), the last slot any run was
          # for (carried forward, so a manual run never makes the next slot run twice), and a note (a blocked start)
          $SlotUtc, $LastSlotUtc, [string]$Note = '',
          # #306: what is run -- the pipeline, one stage (-Target = its id) or one step (-Target = the job) -- and who asked
          [ValidateSet('pipeline', 'stage', 'step', 'from-step')][string]$Scope = 'pipeline', [string]$Target = '', [string]$RequestedBy = '', [long]$RequestId = 0,
          # #700: the SecurityInsight version the run STARTED on (the updater cancels a run of another version); who cancelled it
          [string]$Version = '')
    if (-not $FlowRunId) { $FlowRunId = [guid]::NewGuid().ToString() }
    if ($FromStep -and $Scope -eq 'pipeline') { $Scope = 'from-step'; $Target = $FromStep }
    $steps = New-Object System.Collections.Generic.List[object]
    $order = 0
    foreach ($g in (Get-SIJobFlowGroups -Definition $Definition)) {
        foreach ($s in $g.Steps) {
            if ($Scope -eq 'stage' -and $g.Stage -ne $Target) { continue }
            if ($Scope -eq 'step' -and [string]$s.Job -ne $Target) { continue }
            $order++
            # a step run now on its own runs even when it is switched off in the pipeline (the operator asked for it)
            $on = [bool]$s.Enabled -or $Scope -eq 'step'
            $steps.Add([pscustomobject]@{ Order = $order; Group = $g.Index; Job = [string]$s.Job; Stage = $g.Stage; State = $(if ($on) { 'Waiting' } else { 'Disabled' })
                                          Execution = ''; StartedUtc = $null; EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 0; RetryReason = '' })
        }
    }
    [pscustomobject]@{ FlowRunId = $FlowRunId; Day = $NowUtc.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
                       Trigger = $Trigger; FromStep = [string]$FromStep; State = 'Running'; StartedUtc = $NowUtc; EndedUtc = $null; HeartbeatUtc = $NowUtc
                       StopReason = ''; SlotUtc = $SlotUtc; LastSlotUtc = $(if ($SlotUtc) { $SlotUtc } else { $LastSlotUtc }); Note = $Note
                       Scope = $Scope; Target = [string]$Target; RequestedBy = [string]$RequestedBy; RequestId = $RequestId
                       Version = [string]$Version; CancelledBy = ''; Steps = $steps.ToArray() }
}

function Get-SIJobFlowAttempts {
    <# PURE. How many times a step record's job was started: its Attempts, else (a record written before attempts were
       kept) 1 when it has an execution, 0 when not. #>
    param($Step)
    if ($null -eq $Step) { return 0 }
    if ($Step.PSObject.Properties['Attempts'] -and $null -ne $Step.Attempts -and -not ($Step.Attempts -is [DBNull]) -and "$($Step.Attempts)" -ne '') { return [int]$Step.Attempts }
    if ($Step.PSObject.Properties['Execution'] -and -not ($Step.Execution -is [DBNull]) -and "$($Step.Execution)" -ne '') { return 1 }
    0
}

function ConvertFrom-SIJobFlowRunJson {
    <# PURE. A run record from its JSON (the file / blob store). Times as UTC [datetime] or $null. #>
    param([Parameter(Mandatory)][string]$Json)
    $o = $Json | ConvertFrom-Json
    $t = { param($v) if ($null -eq $v -or "$v" -eq '') { $null } else { ([datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } }
    $steps = foreach ($s in @($o.Steps)) {
        if ($null -eq $s) { continue }
        [pscustomobject]@{ Order = [int]$s.Order; Group = [int]$s.Group; Job = [string]$s.Job; Stage = $(if ($s.PSObject.Properties['Stage'] -and $s.Stage) { [string]$s.Stage } else { '' }); State = [string]$s.State; Execution = [string]$s.Execution
                           StartedUtc = (& $t $s.StartedUtc); EndedUtc = (& $t $s.EndedUtc); ErrorClass = [string]$s.ErrorClass; Error = [string]$s.Error
                           Attempts = (Get-SIJobFlowAttempts $s); RetryReason = $(if ($s.PSObject.Properties['RetryReason']) { [string]$s.RetryReason } else { '' }) }
    }
    $f = { param($n, $d) if ($o.PSObject.Properties[$n] -and $null -ne $o.$n -and "$($o.$n)" -ne '') { $o.$n } else { $d } }
    [pscustomobject]@{ FlowRunId = [string]$o.FlowRunId; Day = [string]$o.Day; Trigger = [string]$o.Trigger; FromStep = [string]$o.FromStep; State = [string]$o.State
                       StartedUtc = (& $t $o.StartedUtc); EndedUtc = (& $t $o.EndedUtc); HeartbeatUtc = (& $t $o.HeartbeatUtc); StopReason = [string]$o.StopReason
                       SlotUtc = (& $t $o.SlotUtc); LastSlotUtc = (& $t $o.LastSlotUtc); Note = [string]$o.Note
                       Scope = [string](& $f 'Scope' 'pipeline'); Target = [string](& $f 'Target' ''); RequestedBy = [string](& $f 'RequestedBy' ''); RequestId = [long](& $f 'RequestId' 0)
                       Version = [string](& $f 'Version' ''); CancelledBy = [string](& $f 'CancelledBy' ''); Steps = @($steps) }
}

function ConvertTo-SIJobFlowRunJson {
    param([Parameter(Mandatory)]$State)
    $iso = { param($v) if ($null -eq $v) { $null } else { ([datetime]$v).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) } }
    $g = { param($n, $d) if ($State.PSObject.Properties[$n] -and $null -ne $State.$n) { $State.$n } else { $d } }
    $o = [ordered]@{ FlowRunId = $State.FlowRunId; Day = $State.Day; Trigger = $State.Trigger; FromStep = $State.FromStep; State = $State.State
                     StartedUtc = (& $iso $State.StartedUtc); EndedUtc = (& $iso $State.EndedUtc); HeartbeatUtc = (& $iso $State.HeartbeatUtc); StopReason = $State.StopReason
                     SlotUtc = (& $iso $State.SlotUtc); LastSlotUtc = (& $iso $State.LastSlotUtc); Note = [string]$State.Note
                     Scope = [string](& $g 'Scope' 'pipeline'); Target = [string](& $g 'Target' ''); RequestedBy = [string](& $g 'RequestedBy' ''); RequestId = [long](& $g 'RequestId' 0)
                     Version = [string](& $g 'Version' ''); CancelledBy = [string](& $g 'CancelledBy' '')
                     Steps =@(@($State.Steps) | ForEach-Object { [ordered]@{ Order = $_.Order; Group = $_.Group; Job = $_.Job; Stage = $(if ($_.PSObject.Properties['Stage']) { [string]$_.Stage } else { '' }); State = $_.State; Execution = $_.Execution
                                                                             StartedUtc = (& $iso $_.StartedUtc); EndedUtc = (& $iso $_.EndedUtc); ErrorClass = $_.ErrorClass; Error = $_.Error
                                                                             Attempts = (Get-SIJobFlowAttempts $_); RetryReason = $(if ($_.PSObject.Properties['RetryReason']) { [string]$_.RetryReason } else { '' }) } }) }
    $o | ConvertTo-Json -Depth 6
}

function Get-SIJobFlowLatestSlot {
    <#
        PURE. The latest time-of-day slot at or before -NowUtc for a daily / weekdays / weekly flow, as UTC; $null for
        interval. #306: the start time is a wall-clock time in the pipeline's time zone (TimeZone; none = UTC) -- 22:00
        Europe/Copenhagen is 20:00 UTC in summer and 21:00 UTC in winter, every day computed from that day's local date
        (the weekday too is the local one).
    #>
    param([Parameter(Mandatory)]$Definition, [Parameter(Mandatory)][datetime]$NowUtc)
    if ([string]$Definition.Cadence -eq 'interval') { return $null }
    $h, $m = ([string]$Definition.StartTime) -split ':'
    $n = [datetime]::SpecifyKind($NowUtc.ToUniversalTime(), 'Utc')
    $zone = (Resolve-SIPipelineTimeZone (Get-SIPipelineTimeZoneId $Definition)).Zone
    $localDay = [TimeZoneInfo]::ConvertTimeFromUtc($n, $zone).Date
    for ($i = 0; $i -lt 9; $i++) {
        $local = $localDay.AddDays(-$i).AddHours([int]$h).AddMinutes([int]$m)
        $t = ConvertTo-SIPipelineUtc -Local $local -Zone $zone
        if ($t -gt $n) { continue }
        $ok = switch ([string]$Definition.Cadence) {
            'weekdays' { $local.DayOfWeek -notin @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday) }
            'weekly'   { [int]$local.DayOfWeek -eq ([int]$Definition.Weekday % 7) }
            default    { $true }
        }
        if ($ok) { return $t }
    }
    $null
}

function Get-SIJobFlowCoveredSlot {
    <#
        PURE. (2026-10-24, seen on internal: a manual run still going at the daily time, then a catch-up -- a second full run
        back to back, and its load raised tickets.) The time-of-day slot -Previous COVERED: the latest slot S with
        StartedUtc < S <= EndedUtc -- the run was RUNNING at that time -- when it ended Succeeded (every step: a run with a
        failed step is Failed) AND it was a run of the WHOLE pipeline (Scope pipeline, no FromStep: one step, one stage or a
        re-run from a step does not collect everything) AND it had NO SLOT OF ITS OWN (a manual or queued run -- SlotUtc
        empty): a scheduled or catch-up run is already its own slot's run, and one that takes longer than the schedule's
        interval keeps "start when the last one ends" (the next slot runs once at its end -- a large install's data stays
        refreshed every run, not every second day). $null otherwise -- a failed, cancelled or stopped run, a run with its
        own slot, an interval cadence, no run -- and the catch-up stays as it was.
    #>
    param([Parameter(Mandatory)]$Definition, $Previous)
    if (-not $Previous -or [string]$Definition.Cadence -eq 'interval') { return $null }
    if ([string]$Previous.State -ne 'Succeeded') { return $null }
    if ($Previous.PSObject.Properties['SlotUtc'] -and $Previous.SlotUtc) { return $null }
    $scope = if ($Previous.PSObject.Properties['Scope'] -and [string]$Previous.Scope) { [string]$Previous.Scope } else { 'pipeline' }
    if ($scope -ne 'pipeline') { return $null }
    if ($Previous.PSObject.Properties['FromStep'] -and [string]$Previous.FromStep) { return $null }
    if (-not $Previous.StartedUtc -or -not $Previous.EndedUtc) { return $null }
    $start = ([datetime]$Previous.StartedUtc).ToUniversalTime(); $end = ([datetime]$Previous.EndedUtc).ToUniversalTime()
    $s = Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $end
    if ($s -and $s -gt $start) { return $s }
    $null
}

function Get-SIJobFlowSlotRun {
    <# PURE. The latest slot that HAS RUN after -Previous: its LastSlotUtc, or the slot it covered (Get-SIJobFlowCoveredSlot) when
       that is later; $null when neither. What a new run carries forward and what the schedule reads as "this slot has run". #>
    param([Parameter(Mandatory)]$Definition, $Previous)
    if (-not $Previous) { return $null }
    $last = if ($Previous.LastSlotUtc) { ([datetime]$Previous.LastSlotUtc).ToUniversalTime() } else { $null }
    $cov = Get-SIJobFlowCoveredSlot -Definition $Definition -Previous $Previous
    if ($cov -and (-not $last -or $cov -gt $last)) { return $cov }
    $last
}

function Get-SIJobFlowDue {
    <#
        PURE. SCHED-1.1 (framework): is a flow run due at this wake-up (the flow job's cron / the VM task only WAKE the
        runner -- they never stand in for the cadence)? Returns @{ Action; SlotUtc; Trigger; Note; NextUtc; Reason }:
          Busy    -- the previous run is still running (fresh heartbeat): nothing starts -- never two runs at once;
          Resume  -- the previous run is unfinished and its runner died (stale heartbeat): continue it;
          Start   -- a run is due now;
          Wait    -- not due; NextUtc says when.
        INTERVAL ("every N minutes / hours"): next = the previous run's FINISH + the interval -- an 8-minute run every
        5 minutes started at T finishes at T+8 and is next due at T+13. A failed run counts as finished. A cadence change
        is re-derived from the finish on the next wake-up (nothing is stored but the finish).
        TIME OF DAY (daily / weekdays / weekly at HH:mm): the slot keeps its clock time. A slot whose start was BLOCKED
        because the previous run was still running runs ONCE as soon as that run finishes (Trigger 'catch-up', Note says
        which run blocked it); several missed slots run once, never queued. With no slotted run in the history, only a
        slot within -FirstRunWindowMinutes starts (a new install does not start hours late).
    #>
    param([Parameter(Mandatory)]$Definition, $Previous, [Parameter(Mandatory)][datetime]$NowUtc, [int]$StaleAfterMinutes = 15, [int]$FirstRunWindowMinutes = 15)
    $now = $NowUtc.ToUniversalTime()
    $mk = { param($a, $slot, $trg, $note, $next, $why) [pscustomobject]@{ Action = $a; SlotUtc = $slot; Trigger = $trg; Note = $note; NextUtc = $next; Reason = $why } }
    # #700: a CANCELLED run is finished -- it is never resumed (a person or the updater ended it on purpose)
    $running = $Previous -and ([string]$Previous.State -notin $script:SIJobFlow.RunFinished)
    if ($running) {
        $hb = $Previous.HeartbeatUtc
        if ($hb -and ($now - ([datetime]$hb).ToUniversalTime()).TotalMinutes -lt $StaleAfterMinutes) {
            return (& $mk 'Busy' $null '' '' $null ('skipped: the previous flow run ({0}) is still running' -f $Previous.FlowRunId))
        }
        return (& $mk 'Resume' $null '' '' $null ('the previous flow run ({0}) stopped without finishing -- it is resumed' -f $Previous.FlowRunId))
    }
    if ([string]$Definition.Cadence -eq 'interval') {
        $iv = [int]$Definition.IntervalMinutes; if ($iv -lt 1) { $iv = 1440 }
        if (-not $Previous -or -not $Previous.EndedUtc) { return (& $mk 'Start' $null 'interval' '' $null 'no earlier run') }
        $next = ([datetime]$Previous.EndedUtc).ToUniversalTime().AddMinutes($iv)
        if ($now -ge $next) { return (& $mk 'Start' $null 'interval' '' $null ('the previous run finished {0:u}; every {1} min after the finish' -f $Previous.EndedUtc, $iv)) }
        return (& $mk 'Wait' $null '' '' $next ('next run {0:u}: the previous run finished {1:u} + {2} min' -f $next, $Previous.EndedUtc, $iv))
    }
    $slot = Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $now
    $nextSlot = Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $now.AddDays(8)
    for ($d = 7; $d -ge 0; $d--) { $c = Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $now.AddDays($d); if ($c -and $c -gt $now) { $nextSlot = $c } }
    # 2026-10-24: a whole run that was running at the slot and succeeded IS that slot's run (Get-SIJobFlowCoveredSlot)
    $last = Get-SIJobFlowSlotRun -Definition $Definition -Previous $Previous
    if ($last -and $slot -and ([datetime]$last).ToUniversalTime() -ge $slot) {
        $own = if ($Previous -and $Previous.LastSlotUtc) { ([datetime]$Previous.LastSlotUtc).ToUniversalTime() } else { $null }
        if (-not $own -or $own -lt $slot) {
            return (& $mk 'Wait' $null '' '' $nextSlot ('the {0:u} slot was covered by flow run {1}: it was running at that time and succeeded; next slot {2:u}' -f $slot, $Previous.FlowRunId, $nextSlot))
        }
        return (& $mk 'Wait' $null '' '' $nextSlot ('the {0:u} slot has run; next slot {1:u}' -f $slot, $nextSlot))
    }
    if (-not $slot) { return (& $mk 'Wait' $null '' '' $nextSlot 'no slot yet') }
    if (-not $last) {
        if (($now - $slot).TotalMinutes -le $FirstRunWindowMinutes) { return (& $mk 'Start' $slot 'schedule' '' $null ('the {0:u} slot' -f $slot)) }
        return (& $mk 'Wait' $null '' '' $nextSlot ('first run: the {0:u} slot has passed; next slot {1:u}' -f $slot, $nextSlot))
    }
    # the slot has not run: on time, or blocked by a run that was still running at the slot and has finished since
    $blocked = $Previous -and $Previous.StartedUtc -and $Previous.EndedUtc -and ([datetime]$Previous.StartedUtc).ToUniversalTime() -lt $slot -and ([datetime]$Previous.EndedUtc).ToUniversalTime() -gt $slot
    if ($blocked) {
        return (& $mk 'Start' $slot 'catch-up' ('the {0:u} start was blocked: flow run {1} was still running; it ran once when that run finished ({2:u})' -f $slot, $Previous.FlowRunId, $Previous.EndedUtc) $null 'a blocked start runs once when the previous run finishes')
    }
    $late = ($now - $slot).TotalMinutes
    $note = if ($late -gt $FirstRunWindowMinutes) { ('the {0:u} slot started {1:N0} min late (the runner was not woken earlier)' -f $slot, $late) } else { '' }
    & $mk 'Start' $slot 'schedule' $note $null ('the {0:u} slot' -f $slot)
}

function Get-SIJobFlowLateStart {
    <#
        PURE. WHY A SCHEDULED START IS LATE (owner 2026-10-12: "Quiet when runs are just long"), decided when the run
        STARTS and written into its note, so the run's own record says it (and a resumed run still knows it):
          on-time      -- it started within -LateAfterMinutes of its scheduled time (or it is not a scheduled start);
          previous-run -- it was owed ONLY because the previous run was still going at its scheduled time, and it started
                          as soon as that run ended (within -LateAfterMinutes of its end). Normal on an install whose run
                          takes longer than the schedule's interval: said in the note, NOT a guard event;
          missed       -- anything else: no run was going at its scheduled time and it still started late (the pipeline was
                          not woken, its job was switched off, an update held it), or the previous run was going but this
                          run did not start when that one ended. The guard 'flow.run.catch-up' reports it.
        -Trigger: schedule | catch-up (anything else is not a scheduled start); -SlotUtc: the scheduled time the run is
        for; -Previous: the last run record. @{ Kind; LateMinutes; Note } -- Note '' for on-time.
        The two sentences are what Get-SIGuardCallsForFlow (SI-Guard.ps1) reads: 'started late because the previous run was
        still going' = quiet, 'scheduled start was missed' = reported.
    #>
    param([string]$Trigger = 'schedule', $SlotUtc, $Previous, [Parameter(Mandatory)][datetime]$NowUtc, [int]$LateAfterMinutes = 15)
    $none = [pscustomobject]@{ Kind = 'on-time'; LateMinutes = 0; Note = '' }
    if (-not $SlotUtc -or $Trigger -notin @('schedule', 'catch-up')) { return $none }
    $now = $NowUtc.ToUniversalTime(); $slot = ([datetime]$SlotUtc).ToUniversalTime()
    $late = [int][Math]::Floor(($now - $slot).TotalMinutes)
    $pStart = if ($Previous -and $Previous.StartedUtc) { ([datetime]$Previous.StartedUtc).ToUniversalTime() } else { $null }
    $pEnd = if ($Previous -and $Previous.EndedUtc) { ([datetime]$Previous.EndedUtc).ToUniversalTime() } else { $null }
    if ($pStart -and $pEnd -and $pStart -lt $slot -and $pEnd -gt $slot) {
        # a run was going at the scheduled time
        $after = [int][Math]::Floor(($now - $pEnd).TotalMinutes)
        if ($after -le $LateAfterMinutes) {
            return [pscustomobject]@{ Kind = 'previous-run'; LateMinutes = $late
                Note = ('This run started late because the previous run ({0}) was still going at its scheduled time ({1:u}); it started as soon as that run ended ({2:u}).' -f $Previous.FlowRunId, $slot, $pEnd) }
        }
        return [pscustomobject]@{ Kind = 'missed'; LateMinutes = $late
            Note = ('This scheduled start was missed: the previous run ({0}) was still going at its time ({1:u}) and ended {2:u}, but this run started {3} minutes after that.' -f $Previous.FlowRunId, $slot, $pEnd, $after) }
    }
    if ($late -gt $LateAfterMinutes) {
        return [pscustomobject]@{ Kind = 'missed'; LateMinutes = $late
            Note = ('This scheduled start was missed: its time was {0:u} and no run was going then, but it started {1} minutes late.' -f $slot, $late) }
    }
    $none
}

function Resolve-SIJobFlowStart {
    <#
        PURE. What a runner does with the last run record it finds (crash recovery and double-start protection):
          New      -- no record, or the last one is finished and this is a new start (a forced / manual run, a re-run from
                      a step, or a scheduled run on a later day);
          Resume   -- the last record is unfinished and its heartbeat is stale (its runner died): continue THAT run;
          Busy     -- the last record is unfinished and its heartbeat is fresh: another runner is alive -- refuse;
          Done     -- a scheduled start finds today's run already finished: report it, run nothing again.
        -StaleAfterMinutes: a heartbeat older than this is a dead runner (the runner beats every poll).
    #>
    param($Previous, [Parameter(Mandatory)][datetime]$NowUtc, [switch]$Force, [string]$FromStep, [int]$StaleAfterMinutes = 15)
    if ($null -eq $Previous) { return 'New' }
    $finished = ([string]$Previous.State -in $script:SIJobFlow.RunFinished)
    if (-not $finished) {
        $hb = $Previous.HeartbeatUtc
        if ($hb -and ($NowUtc - ([datetime]$hb).ToUniversalTime()).TotalMinutes -lt $StaleAfterMinutes) { return 'Busy' }
        return 'Resume'
    }
    if ($Force -or $FromStep) { return 'New' }
    $today = $NowUtc.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    if ([string]$Previous.Day -eq $today) { return 'Done' }
    return 'New'
}

# =====================================================================================================================
#  The runner
# =====================================================================================================================
function Get-SIJobFlowBlocked {
    <#
        PURE. From the steps that have ended so far: whether the flow is stopped (a failed step with OnFailure 'stop') and
        which steps are skipped because a step they need failed (OnFailure 'skip-dependents'). @{ Stopped; StopReason; Skip = @{ job = failedJob } }.
        A SOURCE DROPOUT skips nothing: a failed collection step (identity / azure / endpoint / publicip) whose run has
        another collection that SUCCEEDED leaves the steps that need it running -- they read that source's last good
        collection. With no collection succeeded there is nothing new to calculate, and its dependents are skipped as before.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Definition, $Map)
    $stopped = $false; $why = ''
    $skip = @{}
    $anySource = (Get-SIPipelineCollectVerdict -State $State -Definition $Definition).AnySource
    foreach ($st in @($State.Steps)) {
        if ($script:SIJobFlow.Failures -notcontains [string]$st.State) { continue }
        # #700: a step whose execution was STOPPED from outside the pipeline stops the run there, whatever its own failure
        # rule says: a stop is on purpose, so the run does not go on by itself (and a run that ended Stopped is never resumed)
        if ([string]$st.ErrorClass -eq 'stopped') {
            if (-not $stopped) { $stopped = $true; $why = Get-SIJobFlowStoppedText -Job ([string]$st.Job) -Run }
            continue
        }
        $def = @(@($Definition.Steps) | Where-Object { $_.Job -eq $st.Job })[0]
        $mode = if ($def) { [string]$def.OnFailure } else { 'skip-dependents' }
        if ($mode -eq 'stop' -and -not $stopped) { $stopped = $true; $why = ('{0} {1} -- the flow stops there (on failure: stop)' -f $st.Job, $st.State.ToLowerInvariant()) }
        elseif ($mode -eq 'skip-dependents' -and $anySource -and (Get-SIPipelineStepStage $st) -eq 'collect' -and (Test-SIPipelineSourceJob ([string]$st.Job))) { continue }
        elseif ($mode -eq 'skip-dependents') { foreach ($d in (Get-SIJobFlowDependents -Job $st.Job -Definition $Definition -Map $Map)) { if (-not $skip.ContainsKey($d)) { $skip[$d] = $st.Job } } }
    }
    [pscustomobject]@{ Stopped = $stopped; StopReason = $why; Skip = $skip }
}

function Get-SIJobFlowStoppedText {
    <#
        PURE. #700: the plain words for a step whose execution was STOPPED from outside the pipeline (in Azure, by a person,
        by a release tool). -Run: the run's stop reason (the run does not go on). A stop on purpose is not a platform error:
        the step is never started again as one (working rule 4 retries only a container that never started the engine).
        Nor is it a failure of the engine (2026-10-23: "failed -- the execution ended stopped" + "who must act: the vendor"
        for executions an update / roll or a person stopped opened misleading fix requests): the step is recorded
        Interrupted (class 'stopped') with these words, and a run whose only failures are such steps is 'interrupted'
        (Get-SIJobFlowRunExitReason) -- never reported as a failure.
    #>
    param([Parameter(Mandatory)][string]$Job, [switch]$Run)
    if ($Run) { return ('{0} was stopped from outside the pipeline -- the run does not go on by itself (a stop is on purpose, not a platform error). Start the pipeline again when it should run.' -f $Job) }
    'stopped from outside the pipeline (an update, a roll or a person stopped its execution) -- not a failure of the step; nothing has to be fixed'
}

function Test-SIJobFlowStoppedOnly {
    <# PURE. The run did not succeed, and EVERY step that failed (Failed / TimedOut / Interrupted) was stopped from outside
       the pipeline (class 'stopped') or cancelled on purpose (class 'cancelled'): nothing failed by itself. #>
    param([Parameter(Mandatory)]$State)
    if ([string]$State.State -notin @('Failed', 'Stopped')) { return $false }
    $bad = @(@($State.Steps) | Where-Object { $script:SIJobFlow.Failures -contains [string]$_.State })
    if ($bad.Count -eq 0) { return $false }
    foreach ($s in $bad) { if ([string]$s.ErrorClass -notin @('stopped', 'cancelled')) { return $false } }
    $true
}

function Get-SIJobFlowFailureClass {
    <#
        PURE. Working rule 4 -- "only the PLATFORM gets re-run": did a failed step's container ever run the engine?
        Found live 2026-10-05 (ring 1): a step's execution ended Failed 31 s after it was started, with no console line,
        no run transcript and no run-health record -- the container died before PowerShell ran. That is an Azure
        platform failure, and it is started again; a failure of the engine itself is never started again (it would fail
        the same way and burn another run).
          -ErrorClass       the step's. Only 'job-failed' (the execution ended Failed / Stopped) is considered: a start ARM
                            refused, a timeout or an interruption is never retried here.
          -HasStartRecord   the engine's START run-health row for THIS execution exists ($true), does not ($false), or the
                            store cannot tell ($null: no workspace, the query failed, or the store holds no stamped row of
                            THIS engine in the last 7 days -- measured on ring 1 2026-10-05: container runs were not saving
                            run health at all, so an empty store proves nothing).
          -HasTranscript    a run transcript published inside the execution's window ($true / $false / $null = unknown).
          -DurationSeconds  from the start to the end the runner saw. -MaxSeconds (default 120): used only when the
                            store cannot tell (-HasStartRecord $null) -- longer is then never "never started".
          -Attempts / -Retries: the starts made so far and the retries allowed.
        A START row or a transcript = the engine ran: a real failure (engine-failed), never retried.
        never-started needs a POSITIVE signal, never the run-health store alone: NO run transcript in the window (known,
        not unknown) AND either a START row known absent (any duration -- live 2026-10-23 a platform outage held pods
        unstarted for 314 s / 377 s) or, when the store cannot tell, a run of at most -MaxSeconds. A transcript that
        cannot be checked is 'unknown' -- never retried, whatever the store says.
        Returns @{ Class = never-started | engine-failed | unknown | not-applicable; Retry; Signal; Why }.
    #>
    param([AllowEmptyString()][string]$ErrorClass, $HasStartRecord, $HasTranscript, [double]$DurationSeconds,
          [int]$MaxSeconds = $script:SIJobFlow.NeverStartedMaxSeconds, [int]$Attempts = 1, [int]$Retries = $script:SIJobFlow.StartRetries)
    $mk = { param($c, $r, $sig, $why) [pscustomobject]@{ Class = $c; Retry = [bool]$r; Signal = $sig; Why = $why } }
    if ($ErrorClass -ne 'job-failed') { return (& $mk 'not-applicable' $false '' ('a step that {0} is not a start failure' -f $(if ($ErrorClass) { "ended '$ErrorClass'" } else { 'did not fail' }))) }
    if ($HasStartRecord -eq $true) { return (& $mk 'engine-failed' $false 'run-health' 'the engine recorded its start, so the job itself failed -- it is not started again') }
    if ($HasTranscript -eq $true) { return (& $mk 'engine-failed' $false 'transcript' 'the engine wrote a run log, so the job itself failed -- it is not started again') }
    if ($HasTranscript -ne $false) { return (& $mk 'unknown' $false '' 'whether the job started could not be told (its run logs could not be read) -- it is not started again') }
    # Live 2026-10-23: Azure could not start any container for 13 minutes -- two executions ran 314 s and 377 s (pods
    # created, never started, BackoffLimitExceeded) with no run log and no START row. Both signals known absent is the
    # evidence that the engine never ran, whatever the duration: no fixed time bound decides it then.
    if ($HasStartRecord -eq $false) {
        return (& $mk 'never-started' ($Attempts -le $Retries) 'transcript+duration+run-health' ('the execution ended after {0:N0} s without a run log and without recording its start' -f $DurationSeconds))
    }
    $sig = 'transcript+duration'
    if ($DurationSeconds -gt $MaxSeconds) { return (& $mk 'unknown' $false $sig ('the execution ran {0:N0} s (over {1} s) without a run log -- not a start failure, it is not started again' -f $DurationSeconds, $MaxSeconds)) }
    & $mk 'never-started' ($Attempts -le $Retries) $sig ('the execution ended after {0:N0} s without a run log{1}' -f $DurationSeconds, $(if ($HasStartRecord -eq $false) { ' and without recording its start' } else { '' }))
}

function Get-SIJobFlowStartRecordQuery {
    <#
        PURE. The KQL that tells whether the engine of -Execution recorded its START (SI_RunHealth_CL, column Execution --
        every engine stamps CONTAINER_APP_JOB_EXECUTION_NAME there since #269). Mine = the execution's START rows (the
        flow's own step rows excluded); Stamped = rows of -Engine in the last 7 days that carry an execution -- 0 means
        this engine's runs are not in the store (an older image, or run health not being saved), so "no row" proves
        nothing and the answer is "cannot tell". $null for a name that is not an execution / engine name (never put
        into a query).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Execution, [Parameter(Mandatory)][datetime]$StartedUtc, [Parameter(Mandatory)][AllowEmptyString()][string]$Engine)
    if ($Execution -notmatch '^[a-z0-9][a-z0-9\-]{0,126}$') { return $null }
    if ($Engine -notmatch '^[a-z0-9][a-z0-9\-]{0,63}$') { return $null }
    $from = $StartedUtc.ToUniversalTime().AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    ("SI_RunHealth_CL | where TimeGenerated > ago(7d) | extend Execution = tostring(column_ifexists('Execution', '')) " +
     "| summarize Mine = countif(TimeGenerated > datetime({0}) and Phase == 'Start' and Execution == '{1}' and not(Engine startswith 'flow')), " +
     "Stamped = countif(Engine == '{2}' and isnotempty(Execution)), " +
     "Throttled = countif(TimeGenerated > datetime({0}) and Phase == 'End' and Execution == '{1}' and not(Engine startswith 'flow') and tostring(ExitReason) == 'throttled'), " +
     "EndOther = countif(TimeGenerated > datetime({0}) and Phase == 'End' and Execution == '{1}' and not(Engine startswith 'flow') and tostring(ExitReason) !in ('throttled', 'success'))") -f $from, $Execution, $Engine
}

function Test-SIJobFlowTranscriptInWindow {
    <#
        PURE. Is there a run transcript (run-logs/<engine>/<engine>_<flavour>_<yyyyMMddTHHmmssZ>.log) stamped inside
        [-StartedUtc - 60 s, -EndedUtc + 60 s]? Every engine's, on purpose: a transcript of another job in the window only
        makes the answer "it ran" -- never retried -- which is the safe side.
    #>
    param([AllowEmptyCollection()][string[]]$Names = @(), [Parameter(Mandatory)][datetime]$StartedUtc, [Parameter(Mandatory)][datetime]$EndedUtc)
    $a = $StartedUtc.ToUniversalTime().AddSeconds(-60); $b = $EndedUtc.ToUniversalTime().AddSeconds(60)
    foreach ($n in @($Names)) {
        if ([string]$n -notmatch '_(\d{8}T\d{6}Z)\.log$') { continue }
        $t = [datetime]::MinValue
        if ([datetime]::TryParseExact($Matches[1], 'yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) {
            if ($t -ge $a -and $t -le $b) { return $true }
        }
    }
    $false
}

function New-SIJobFlowStartEvidence {
    <#
        The container flow's "did the engine start?" probe: Probe($Job, $Execution, $StartedUtc, $EndedUtc) ->
        @{ HasStartRecord; HasTranscript; EndReason } -- each $true / $false, or $null when it cannot be told (never throws).
        EndReason (#532): 'throttled' when the engine of THIS execution recorded END 'throttled' and nothing else, 'failed'
        when it recorded another failure, $null when no END record of it was found (yet).
        Seams (tests): -Query { param($Kql) } -> rows with Mine / Stamped; -ListBlobs { param($Prefix) } -> blob names.
        Default: Log Analytics as the job's identity (Invoke-SILogLaQuery, -WorkspaceResourceId) and the install's
        storage (Get-SIBlobList, -StorageAccount, container sistaging, prefix run-logs/).
    #>
    param([string]$WorkspaceResourceId, [string]$StorageAccount, [scriptblock]$Query, [scriptblock]$ListBlobs, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $engines = @{}; foreach ($k in @($Map.Jobs.Keys)) { if ($Map.Jobs[$k].Engine) { $engines[[string]$k] = [string]$Map.Jobs[$k].Engine } }
    New-SIJobFlowSeams -Fields @{ Workspace = $WorkspaceResourceId; Account = $StorageAccount; Query = $Query; ListBlobs = $ListBlobs; Engines = $engines } -Methods @{
        Probe = {
            param($Job, $Execution, $StartedUtc, $EndedUtc)
            $row = $null; $tr = $null; $endReason = $null
            if (($this.Query -or $this.Workspace) -and $StartedUtc) {
                try {
                    $eng = if ($this.Engines.ContainsKey([string]$Job)) { $this.Engines[[string]$Job] } else { [string]$Job }
                    $kql = Get-SIJobFlowStartRecordQuery -Execution ([string]$Execution) -StartedUtc ([datetime]$StartedUtc) -Engine $eng
                    if ($kql) {
                        # @( ) around the whole if: one row out of an if is unrolled, and PS 5.1 gives a [pscustomobject] no .Count
                        $r = @(if ($this.Query) { & $this.Query $kql } else { Invoke-SILogLaQuery -WorkspaceResourceId $this.Workspace -Query $kql }) | Where-Object { $_ }
                        $r = @($r)
                        if ($r.Count -and [long]$r[0].Stamped -gt 0) { $row = ([long]$r[0].Mine -gt 0) }
                        elseif ($r.Count -and [long]$r[0].Mine -gt 0) { $row = $true }
                        # #532: the engine of this execution recorded END 'throttled' and no other failure -- throttled
                        if ($r.Count -and $r[0].PSObject.Properties['Throttled']) {
                            $other = if ($r[0].PSObject.Properties['EndOther']) { [long]$r[0].EndOther } else { 0 }
                            $endReason = if ([long]$r[0].Throttled -gt 0 -and $other -eq 0) { 'throttled' } elseif ($other -gt 0) { 'failed' } else { $null }
                        }
                    }
                } catch { $row = $null; $endReason = $null }
            }
            if (($this.ListBlobs -or $this.Account) -and $StartedUtc -and $EndedUtc) {
                try {
                    $names = if ($this.ListBlobs) { @(& $this.ListBlobs 'run-logs/') } else { @(Get-SIBlobList -Account $this.Account -Container 'sistaging' -Prefix 'run-logs/' | ForEach-Object { [string]$_.Name }) }
                    # #966 THIS STEP'S OWN run log (its engine, or its key; a producer / worker of it counts), never any
                    # engine's: in a pipeline the step before and the half-hourly heartbeat publish theirs inside the window,
                    # so "any transcript" answered "it ran" and a container that died before the engine started was never
                    # started again (live 2026-10-30: the verification step, pod created and BackoffLimitExceeded 65 s later,
                    # no line of its own -- the close-loop mail's run log 4 s before it decided "it ran", the run failed).
                    # No run log at all = this install keeps none; no run log of THIS engine ever = its logs are named
                    # otherwise: either way the signal does not exist ($null -- never retried on it).
                    $key = Get-SIJobFlowKey ([string]$Job)
                    $teng = if ($this.Engines.ContainsKey($key)) { $this.Engines[$key] } elseif ($this.Engines.ContainsKey([string]$Job)) { $this.Engines[[string]$Job] } else { $key }
                    $ever = if (@($names).Count) { Select-SIJobFlowStepLog -Names $names -Engine $teng -Key $key -StartedUtc ([datetime]::new(2000, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) -EndedUtc ([datetime]::new(2100, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) } else { '' }
                    $tr = if ($ever) { [bool](Select-SIJobFlowStepLog -Names $names -Engine $teng -Key $key -StartedUtc ([datetime]$StartedUtc) -EndedUtc ([datetime]$EndedUtc)) } else { $null }
                } catch { $tr = $null }
            }
            [pscustomobject]@{ HasStartRecord = $row; HasTranscript = $tr; EndReason = $endReason }
        }
    }
}

function Get-SIJobFlowSilentText {
    <#
        PURE. The plain words for a running step that shows no sign of progress (the log, the run-health record, the step).
        -NoticedUtc: when the pipeline noticed it. THE STEP RECORD CARRIES THIS SENTENCE (RetryReason), and the web app's
        pipeline page reads two things out of it to show the warning on the running step -- "no sign of progress for N
        hours" and "(noticed yyyy-MM-dd HH:mm UTC" (JobFlow.SilentStep in pro-management). Keep the two in step.
    #>
    param([Parameter(Mandatory)][string]$Job, [int]$SilentMinutes, $LastSeenUtc, $NoticedUtc)
    $h = ([double]$SilentMinutes / 60).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $bits = @()
    if ($NoticedUtc) { $bits += ('noticed {0} UTC' -f ([datetime]$NoticedUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', $inv)) }
    if ($LastSeenUtc) { $bits += ('its last log line or record was at {0} UTC' -f ([datetime]$LastSeenUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', $inv)) }
    $at = if ($bits.Count) { ' ({0})' -f ($bits -join '; ') } else { '' }
    '{0} has shown no sign of progress for {1} hours{2}. It is still running and nothing is stopped -- if it does not move on, look at the job''s log' -f $Job, $h, $at
}

function Get-SIJobFlowProgressQuery {
    <#
        PURE. The KQL that tells when a running step's job LAST SAID ANYTHING: its console log lines (Container Apps writes
        them to the workspace: ContainerAppConsoleLogs, or the classic ContainerAppConsoleLogs_CL -- whichever exists) and
        its run-health records, since the step started. -Execution: the step's execution (its replica's log name starts
        with it); -WorkerJob: for a collection in parts, the worker job whose replicas do the work after the producer.
        One row: Last (the newest of them), Console (how many LOG lines -- 0 means this install's console logs are not in
        the workspace, so silence proves nothing). $null for a name that is not an execution / job name (never put into a query).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Execution, [Parameter(Mandatory)][datetime]$StartedUtc, [AllowEmptyString()][string]$WorkerJob = '')
    if ($Execution -notmatch '^[a-z0-9][a-z0-9\-]{0,126}$') { return $null }
    if ($WorkerJob -and $WorkerJob -notmatch '^[a-z0-9][a-z0-9\-]{0,63}$') { return $null }
    $from = $StartedUtc.ToUniversalTime().AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $mine = if ($WorkerJob) { "(N startswith '{0}' or N startswith '{1}')" -f $Execution, $WorkerJob } else { "N startswith '{0}'" -f $Execution }
    ("union isfuzzy=true " +
     "(ContainerAppConsoleLogs | where TimeGenerated > datetime({0}) | extend N = tostring(column_ifexists('ContainerGroupName', '')) | where {1} | project TimeGenerated, K = 'log'), " +
     "(ContainerAppConsoleLogs_CL | where TimeGenerated > datetime({0}) | extend N = tostring(column_ifexists('ContainerGroupName_s', '')) | where {1} | project TimeGenerated, K = 'log'), " +
     "(SI_RunHealth_CL | where TimeGenerated > datetime({0}) | extend N = tostring(column_ifexists('Execution', '')) | where {1} and not(Engine startswith 'flow') | project TimeGenerated, K = 'health') " +
     "| summarize Last = max(TimeGenerated), Console = countif(K == 'log')") -f $from, $mine
}

function New-SIJobFlowProgressProbe {
    <#
        The container flow's "is this step still doing anything?" probe: Probe($Job, $Execution, $StartedUtc) ->
        @{ LastSeenUtc; Console } -- LastSeenUtc is when the step's job last wrote a console log line or a run-health record,
        or $null when it CANNOT BE TOLD: no console log line of this execution is in the workspace at all (this install's
        console logs do not go there, or they have not arrived yet), the query failed, or there is no workspace. Never
        throws, never guesses: silence is only reported for a job that was heard before.
        -PartsJobs: the engines collected in parts (their workers' log lines count for the step).
        Seam (tests): -Query { param($Kql) } -> rows with Last / Console. Default: Log Analytics as the job's identity.
    #>
    param([string]$WorkspaceResourceId, [scriptblock]$Query, [string[]]$PartsJobs = @())
    $parts = @{}; foreach ($p in @($PartsJobs)) { if ($p) { $parts[(Get-SIJobFlowKey (([string]$p) -replace '-(producer|worker)$', ''))] = $true } }
    New-SIJobFlowSeams -Fields @{ Workspace = $WorkspaceResourceId; Query = $Query; Parts = $parts } -Methods @{
        Probe = {
            param($Job, $Execution, $StartedUtc)
            $none = [pscustomobject]@{ LastSeenUtc = $null; Console = 0 }
            if (-not ($this.Query -or $this.Workspace) -or -not $StartedUtc -or -not $Execution) { return $none }
            try {
                $k = Get-SIJobFlowKey ([string]$Job)
                $worker = if ($this.Parts.ContainsKey($k)) { 'caj-si-{0}-worker' -f $k } else { '' }
                $kql = Get-SIJobFlowProgressQuery -Execution ([string]$Execution) -StartedUtc ([datetime]$StartedUtc) -WorkerJob $worker
                if (-not $kql) { return $none }
                $r = @(if ($this.Query) { & $this.Query $kql } else { Invoke-SILogLaQuery -WorkspaceResourceId $this.Workspace -Query $kql }) | Where-Object { $_ }
                $r = @($r)
                if (-not $r.Count) { return $none }
                $console = 0L; try { $console = [long]$r[0].Console } catch { $console = 0L }
                if ($console -le 0 -or -not $r[0].Last) { return $none }
                $last = if ($r[0].Last -is [datetime]) { $r[0].Last.ToUniversalTime() } else { [datetime]::Parse([string]$r[0].Last, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
                [pscustomobject]@{ LastSeenUtc = $last; Console = $console }
            } catch { $none }
        }
    }
}

function Select-SIJobFlowStepLog {
    <#
        PURE. The run log of ONE failed step: of the transcript names (run-logs/<engine>/<engine>_<flavour>..._<stamp>.log, or
        a VM's <engine>_<flavour>..._<stamp>.log), the LATEST one of that step's engine (-Engine, or the step key -Key; a
        producer / worker log of it counts) stamped inside [-StartedUtc - 60 s, -EndedUtc + 60 s]. '' when there is none.
    #>
    param([AllowEmptyCollection()][string[]]$Names = @(), [string]$Engine, [string]$Key, [Parameter(Mandatory)][datetime]$StartedUtc, [Parameter(Mandatory)][datetime]$EndedUtc)
    $a = $StartedUtc.ToUniversalTime().AddSeconds(-60); $b = $EndedUtc.ToUniversalTime().AddSeconds(60)
    $want = @(@($Engine, $Key) | Where-Object { "$_".Trim() } | ForEach-Object { ([regex]::Replace("$_", '[^A-Za-z0-9\-]', '')).ToLowerInvariant() } | Select-Object -Unique)
    $best = ''; $bestT = [datetime]::MinValue
    foreach ($n in @($Names)) {
        $leaf = ([string]$n -split '[\\/]')[-1]
        if ($leaf -notmatch '_(\d{8}T\d{6}Z)\.log$') { continue }
        $stamp = $Matches[1]
        $eng = ($leaf -split '_')[0].ToLowerInvariant()
        $ok = $false
        foreach ($w in $want) { if ($eng -eq $w -or $eng -like "$w-producer" -or $eng -like "$w-worker") { $ok = $true } }
        if (-not $ok) { continue }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($stamp, 'yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) { continue }
        if ($t -lt $a -or $t -gt $b) { continue }
        if ($t -ge $bestT) { $best = [string]$n; $bestT = $t }
    }
    $best
}

function New-SIJobFlowStepLogReader {
    <#
        The failed step's own run log, for the pipeline's report (telemetry quality, owner 2026-10-10): Read($Job, $StartedUtc,
        $EndedUtc) -> @{ Name; Lines } or $null. Container: the transcript the step's engine published to the install's
        storage (sistaging/run-logs/<engine>/, -StorageAccount); VM: the launcher's transcript folder (-LogRoot). NEVER
        throws. Seams (tests): -ListNames { param($Engine) } -> names, -ReadText { param($Name) } -> text.
    #>
    param([string]$StorageAccount, [string]$LogRoot, [scriptblock]$ListNames, [scriptblock]$ReadText, $Map)
    if (-not $Map) { try { $Map = Get-SIJobFlowMap } catch { $Map = $null } }
    $engines = @{}; if ($Map) { foreach ($k in @($Map.Jobs.Keys)) { if ($Map.Jobs[$k].Engine) { $engines[[string]$k] = [string]$Map.Jobs[$k].Engine } } }
    New-SIJobFlowSeams -Fields @{ Account = $StorageAccount; LogRoot = $LogRoot; ListNames = $ListNames; ReadText = $ReadText; Engines = $engines } -Methods @{
        Read = {
            param($Job, $StartedUtc, $EndedUtc)
            try {
                if (-not $StartedUtc) { return $null }
                $end = if ($EndedUtc) { [datetime]$EndedUtc } else { [datetime]::UtcNow }
                $key = Get-SIJobFlowKey ([string]$Job)
                $eng = if ($this.Engines.ContainsKey($key)) { $this.Engines[$key] } else { $key }
                $names = @()
                if ($this.ListNames) { $names = @(& $this.ListNames $eng) }
                elseif ($this.Account) {
                    foreach ($e in @($eng, $key) | Select-Object -Unique) {
                        $names += @(Get-SIBlobList -Account $this.Account -Container 'sistaging' -Prefix ('run-logs/{0}' -f $e) | ForEach-Object { [string]$_.Name })
                    }
                } elseif ($this.LogRoot -and (Test-Path -LiteralPath $this.LogRoot)) {
                    $names = @(Get-ChildItem -LiteralPath $this.LogRoot -Filter '*.log' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
                }
                $pick = Select-SIJobFlowStepLog -Names $names -Engine $eng -Key $key -StartedUtc ([datetime]$StartedUtc) -EndedUtc $end
                if (-not $pick) { return $null }
                $text = ''
                if ($this.ReadText) { $text = [string](& $this.ReadText $pick) }
                elseif ($this.Account) {
                    $bytes = [byte[]](Get-SIBlobContent -Account $this.Account -Container 'sistaging' -Blob $pick)
                    $ms = New-Object System.IO.MemoryStream(, $bytes); try { $text = (New-Object System.IO.StreamReader($ms, $true)).ReadToEnd() } finally { $ms.Dispose() }
                } else {
                    $fs = New-Object System.IO.FileStream($pick, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try { $text = (New-Object System.IO.StreamReader($fs, $true)).ReadToEnd() } finally { $fs.Dispose() }
                }
                [pscustomobject]@{ Name = $pick; Lines = @($text -split "`r?`n") }
            } catch { $null }
        }
    }
}

function Get-SIJobFlowStepFailure {
    <#
        PURE. What the pipeline reports for its failed step (owner 2026-10-10: "the report names the failed step and carries
        THAT step's error class + lines, not the pipeline summary"): @{ Step (the step key); Text; ErrorClass }.
        Text = the first error lines of the step's own run log (-LogLines, Get-SIErrorLines), else the step's recorded error
        (a parts failure, the start ARM refused, a timeout ...). ErrorClass = Get-SIErrorClass of that text (the step's
        recorded error too); a step Microsoft throttled is 'throttled', a step timeout with no better class platform-timeout.
    #>
    param([Parameter(Mandatory)]$Step, [AllowNull()][AllowEmptyCollection()][string[]]$LogLines)
    $rec = "$($Step.Error)".Trim()
    $log = if ($LogLines) { Get-SIErrorLines -Lines @($LogLines) } else { '' }
    $text = if ($log) { $log } else { $rec }
    $cls = if ($text) { Get-SIErrorClass -Message $text } else { 'unknown' }
    if ($cls -eq 'unknown' -and $rec -and $rec -ne $text) { $cls = Get-SIErrorClass -Message $rec }
    switch ([string]$Step.ErrorClass) {
        'throttled' { $cls = 'throttled' }
        'timeout' { if ($cls -eq 'unknown') { $cls = 'platform-timeout' } }
    }
    if (-not $text) { $text = ('the step {0} ended {1}' -f (Get-SIJobFlowKey ([string]$Step.Job)), ([string]$Step.State).ToLowerInvariant()) }
    [pscustomobject]@{ Step = (Get-SIJobFlowKey ([string]$Step.Job)); Text = $text; ErrorClass = $cls }
}

function Get-SIJobFlowStepCauseText {
    <#
        PURE. #850 (live 2026-10-21: a step ran out of memory and its run record said only "the execution ended failed" --
        the cause was in its log alone). The step's recorded error with the cause its own run log gives (the first error
        line: an out-of-memory, a timeout ...), so run health and Operations > Jobs say WHY. No cause = the recorded error
        unchanged; a recorded error that already carries the cause is unchanged. At most 1000 characters (the column).
    #>
    param([AllowEmptyString()][string]$Recorded = '', [AllowEmptyString()][string]$Cause = '')
    $rec = [string]$Recorded
    $c = ''
    foreach ($line in ([string]$Cause).Split([char[]]@("`r", "`n"))) { if (-not [string]::IsNullOrWhiteSpace($line)) { $c = $line.Trim(); break } }
    if (-not $c -or $rec.Contains($c)) { return $rec }
    $t = if ($rec) { '{0}: {1}' -f $rec.TrimEnd([char[]]@('.', ' ')), $c } else { $c }
    if ($t.Length -gt 1000) { $t = $t.Substring(0, 997) + '...' }
    $t
}

function Get-SIJobFlowRetryText {
    <# PURE. The customer words for a step that was started again / that did not start (the log, the step record, the mail). #>
    param([Parameter(Mandatory)][ValidateSet('retried', 'gave-up')][string]$Kind, [string]$Execution, [int]$Attempts = 1)
    if ($Kind -eq 'retried') { return ("the step's container did not start (an Azure platform problem); it was started again{0}" -f $(if ($Execution) { " (the failed execution: $Execution)" } else { '' })) }
    "the step's container did not start (an Azure platform problem), also not when it was started again ($Attempts attempts) -- see the job's executions in Operations > Jobs"
}

function Get-SIJobFlowOverdueText {
    <#
        PURE. The plain words for a step that has run longer than its step timeout (the log and the step record). The
        pipeline REPORTS it and stops nothing (owner 2026-10-13: no give-up on elapsed time). The step record carries
        this sentence (RetryReason); "longer than its step timeout" is what says it was reported already.
    #>
    param([Parameter(Mandatory)][string]$Job, [int]$RunMinutes, [int]$TimeoutMinutes)
    '{0} has run for {1} minutes, longer than its step timeout of {2} minutes. It keeps running: the pipeline stops no step for the time it takes. A step that stands still is reported when it shows no sign of progress.' -f $Job, $RunMinutes, $TimeoutMinutes
}

# =====================================================================================================================
#  A RUN OR STEP MUCH LONGER THAN USUAL FOR THIS INSTALL -- PURE (si-flow-1203, 2026-10-26: four large installs had a run
#  going for ~79 h -- a data sync ~45 h, a correlation ~65 h -- and it looked "Running" and healthy; nobody was told).
#  WARNING ONLY: nothing is stopped, nothing is held, no cap (owner: warn on suspicion, never block). One rule for the
#  runner's own log / step record and for the heartbeat's Warnings.
# =====================================================================================================================
function Get-SIPipelineLongRunRule {
    <#
        PURE. The rule: a run (step) warns once it has run longer than max(Factor x usual, usual + ExtraMinutes). Usual =
        the MEDIAN of the install's own measured lengths among the newest RunsRead run records -- full runs that succeeded
        (scope pipeline, not from a step) for a run; that job's successful steps (any run) for a step. With fewer than
        MinHistory measured lengths there is no usual: the plain floor applies (RunFloorMinutes / StepFloorMinutes).
    #>
    @{ Factor = 2.0; ExtraMinutes = 120; MinHistory = 3; RunFloorMinutes = 1440; StepFloorMinutes = 720; RunsRead = 10 }
}

function ConvertTo-SIPipelineLongRunTime {
    <# PURE. A time as UTC [datetime], or $null (null, DBNull, '' or not a time). #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { return $(if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }) }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    $null
}

function Get-SIPipelineMedian {
    <# PURE. The median of -Values (the mean of the middle two for an even count), or $null for none. #>
    param([double[]]$Values = @())
    $v = @(@($Values) | Sort-Object)
    if (-not $v.Count) { return $null }
    $m = [int][Math]::Floor($v.Count / 2)
    if ($v.Count % 2) { return [double]$v[$m] }
    ([double]$v[$m - 1] + [double]$v[$m]) / 2
}

function Get-SIPipelineUsualMinutes {
    <#
        PURE. How long a run and each step USUALLY take on this install. -Runs { FlowRunId, State, Scope, FromStep,
        StartedUtc, EndedUtc }, -Steps { FlowRunId, Job, State, StartedUtc, EndedUtc } (the newest run records read and
        their steps); -ExcludeRunId = the run going on (never its own steps). Answers @{ RunMinutes; RunCount; Steps =
        @{ <job key> = @{ Minutes; Count } } } -- Minutes $null where fewer than MinHistory lengths were measured.
    #>
    param([object[]]$Runs = @(), [object[]]$Steps = @(), [AllowEmptyString()][string]$ExcludeRunId = '')
    $rule = Get-SIPipelineLongRunRule
    $len = { param($a, $b) $x = ConvertTo-SIPipelineLongRunTime $a; $y = ConvertTo-SIPipelineLongRunTime $b; if ($null -eq $x -or $null -eq $y -or $y -lt $x) { $null } else { ($y - $x).TotalMinutes } }
    $others = @(@($Runs) | Where-Object { $_ -and [string]$_.FlowRunId -and [string]$_.FlowRunId -ne $ExcludeRunId } |
                Sort-Object { ConvertTo-SIPipelineLongRunTime $_.StartedUtc } -Descending | Select-Object -First ([int]$rule.RunsRead))
    $runLens = New-Object System.Collections.Generic.List[double]
    foreach ($r in $others) {
        $scope = if ($r.PSObject.Properties['Scope']) { [string]$r.Scope } else { '' }
        $from = if ($r.PSObject.Properties['FromStep'] -and -not ($r.FromStep -is [DBNull])) { [string]$r.FromStep } else { '' }
        if ([string]$r.State -ne 'Succeeded' -or ($scope -and $scope -ne 'pipeline') -or $from.Trim()) { continue }
        $m = & $len $r.StartedUtc $r.EndedUtc
        if ($null -ne $m) { $runLens.Add([double]$m) }
    }
    $ids = @{}; foreach ($r in $others) { $ids[[string]$r.FlowRunId] = $true }
    $byJob = @{}
    foreach ($s in @(@($Steps) | Where-Object { $_ -and $ids.ContainsKey([string]$_.FlowRunId) -and [string]$_.State -eq 'Success' })) {
        $k = Get-SIJobFlowKey ([string]$s.Job); if (-not $k) { continue }
        $m = & $len $s.StartedUtc $s.EndedUtc
        if ($null -eq $m) { continue }
        if (-not $byJob.ContainsKey($k)) { $byJob[$k] = New-Object System.Collections.Generic.List[double] }
        $byJob[$k].Add([double]$m)
    }
    $stepOut = @{}
    foreach ($k in $byJob.Keys) {
        $l = $byJob[$k]
        $stepOut[$k] = @{ Minutes = $(if ($l.Count -ge [int]$rule.MinHistory) { Get-SIPipelineMedian -Values $l.ToArray() } else { $null }); Count = $l.Count }
    }
    @{ RunMinutes = $(if ($runLens.Count -ge [int]$rule.MinHistory) { Get-SIPipelineMedian -Values $runLens.ToArray() } else { $null }); RunCount = $runLens.Count; Steps = $stepOut }
}

function Get-SIPipelineLongRunThreshold {
    <# PURE. The minutes after which a run (-Kind run) or step (-Kind step) warns: from -UsualMinutes, else the floor. #>
    param([AllowNull()]$UsualMinutes, [ValidateSet('run', 'step')][string]$Kind = 'run')
    $rule = Get-SIPipelineLongRunRule
    if ($null -eq $UsualMinutes) {
        return @{ Minutes = [double]$(if ($Kind -eq 'run') { $rule.RunFloorMinutes } else { $rule.StepFloorMinutes }); Basis = 'floor'; UsualMinutes = $null }
    }
    $u = [double]$UsualMinutes
    @{ Minutes = [Math]::Max($u * [double]$rule.Factor, $u + [double]$rule.ExtraMinutes); Basis = 'history'; UsualMinutes = $u }
}

function Get-SIPipelineLongRun {
    <#
        PURE. What of the run going on has run much longer than usual. -Run { FlowRunId, State, StartedUtc } (the newest
        run), -Steps = ITS steps { Job, Order, State, StartedUtc }, -Usual = Get-SIPipelineUsualMinutes (over the OTHER
        runs), -NowUtc. A run that is not Running answers nothing. One entry per finding:
        { Kind run | step; RunId; Step (job key, '' for the run); Order; StartedUtc; AgeMinutes; UsualMinutes ($null = no
        history); ThresholdMinutes; Basis history | floor; History (the measured lengths behind usual); CrossedUtc (when
        it crossed the threshold) } -- the run first, then the steps by order.
    #>
    param($Run, [object[]]$Steps = @(), $Usual, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Run -or [string]$Run.State -ne 'Running') { return }
    $now = $NowUtc.ToUniversalTime()
    if (-not $Usual) { $Usual = @{ RunMinutes = $null; RunCount = 0; Steps = @{} } }
    $mk = {
        param($kind, $step, $order, $start, $th, $hist)
        $age = ($now - $start).TotalMinutes
        if ($age -le [double]$th.Minutes) { return }
        [pscustomobject]@{ Kind = $kind; RunId = [string]$Run.FlowRunId; Step = $step; Order = $order; StartedUtc = $start; AgeMinutes = [long][Math]::Floor($age)
                           UsualMinutes = $(if ($null -ne $th.UsualMinutes) { [long][Math]::Round([double]$th.UsualMinutes) } else { $null })
                           ThresholdMinutes = [long][Math]::Ceiling([double]$th.Minutes); Basis = $th.Basis; History = [int]$hist; CrossedUtc = $start.AddMinutes([double]$th.Minutes) }
    }
    $rs = ConvertTo-SIPipelineLongRunTime $Run.StartedUtc
    if ($null -ne $rs) { & $mk 'run' '' $null $rs (Get-SIPipelineLongRunThreshold -UsualMinutes $Usual.RunMinutes -Kind run) ([int]$Usual.RunCount) }
    foreach ($s in @(@($Steps) | Where-Object { $_ -and [string]$_.State -in @('Running', 'Starting') } | Sort-Object { [int]$_.Order })) {
        $ss = ConvertTo-SIPipelineLongRunTime $s.StartedUtc; if ($null -eq $ss) { continue }
        $k = Get-SIJobFlowKey ([string]$s.Job); if (-not $k) { continue }
        $u = if ($Usual.Steps -and $Usual.Steps.ContainsKey($k)) { $Usual.Steps[$k] } else { @{ Minutes = $null; Count = 0 } }
        & $mk 'step' $k ([int]$s.Order) $ss (Get-SIPipelineLongRunThreshold -UsualMinutes $u.Minutes -Kind step) ([int]$u.Count)
    }
}

function Get-SIPipelineLongRunText {
    <#
        PURE. The plain words for one finding of Get-SIPipelineLongRun (the runner's log, the step record's RetryReason, the
        run's note). "much longer than usual" is the mark that says it was reported already.
    #>
    param([Parameter(Mandatory)]$Finding)
    $h = { param($m) ('{0} h' -f ([double]$m / 60).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture)) }
    $what = if ($Finding.Kind -eq 'run') { 'pipeline run {0}' -f $Finding.RunId } else { 'step {0} of run {1}' -f $Finding.Step, $Finding.RunId }
    $usual = if ($Finding.Basis -eq 'history') {
        'usually {0} on this install (the median of its last {1} measured {2}); it warns after {3}' -f (& $h $Finding.UsualMinutes), $Finding.History, $(if ($Finding.Kind -eq 'run') { 'complete runs' } else { 'runs of this step' }), (& $h $Finding.ThresholdMinutes)
    } else {
        'this install has fewer than {0} measured {1}, so the plain floor of {2} applies' -f (Get-SIPipelineLongRunRule).MinHistory, $(if ($Finding.Kind -eq 'run') { 'complete runs' } else { 'runs of this step' }), (& $h $Finding.ThresholdMinutes)
    }
    '{0} has run for {1}, much longer than usual ({2}). Warning only: nothing is stopped, the run goes on. Look at it on Operations > Jobs (si-flow-1203).' -f $what, (& $h $Finding.AgeMinutes), $usual
}

# =====================================================================================================================
#  A STEP THAT RUNS FAR PAST ITS LAST TIME WITH NO PROGRESS -- PURE (si-flow-1204, owner 2026-10-29: "a stuck step is seen
#  after days, not hours" -- a correlation ran 55 h and two data syncs 35 h+ before anyone acted). WARNING ONLY: nothing is
#  stopped, nothing is held. One rule for the runner's log / step record and for the heartbeat (Warnings + Pipeline.stalledSteps).
# =====================================================================================================================
function Get-SIPipelineStallRule {
    <#
        PURE. A running step is "stuck" when BOTH hold:
          * it has run longer than max(Factor x its last run's time, its last run's time + ExtraMinutes) -- its last run's time =
            the job's newest successful step among the OTHER runs read; none known: NoTimeMinutes;
          * it shows no progress for QuietMinutes: its newest sign of progress (cfg.StepProgress / cfg.StepPhaseTime since it
            started) is older than that -- or, for a step that leaves no such sign, the runner's log check already found no
            sign of progress (its record says "no sign of progress").
    #>
    @{ Factor = 2.0; ExtraMinutes = 60; NoTimeMinutes = 360; QuietMinutes = 60 }
}

function Get-SIPipelineLastStepMinutes {
    <# PURE. Job key -> the minutes its newest SUCCESSFUL step took among -Steps { FlowRunId, Job, State, StartedUtc, EndedUtc }
       of the runs other than -ExcludeRunId (the run going on). A job that never succeeded in them has no entry. #>
    param([object[]]$Steps = @(), [AllowEmptyString()][string]$ExcludeRunId = '')
    $out = @{}; $at = @{}
    foreach ($s in @(@($Steps) | Where-Object { $_ -and [string]$_.State -eq 'Success' -and [string]$_.FlowRunId -ne $ExcludeRunId })) {
        $k = Get-SIJobFlowKey ([string]$s.Job); if (-not $k) { continue }
        $a = ConvertTo-SIPipelineLongRunTime $s.StartedUtc; $b = ConvertTo-SIPipelineLongRunTime $s.EndedUtc
        if ($null -eq $a -or $null -eq $b -or $b -lt $a) { continue }
        if ($at.ContainsKey($k) -and $at[$k] -ge $a) { continue }
        $at[$k] = $a; $out[$k] = ($b - $a).TotalMinutes
    }
    $out
}

function Get-SIPipelineStallThreshold {
    <# PURE. The minutes after which a running step may be called stuck: from -LastMinutes (its last run's time), else the rule. #>
    param([AllowNull()]$LastMinutes)
    $r = Get-SIPipelineStallRule
    if ($null -eq $LastMinutes) { return @{ Minutes = [double]$r.NoTimeMinutes; Basis = 'rule'; LastMinutes = $null } }
    $l = [double]$LastMinutes
    @{ Minutes = [Math]::Max($l * [double]$r.Factor, $l + [double]$r.ExtraMinutes); Basis = 'last'; LastMinutes = $l }
}

function Get-SIPipelineStalledSteps {
    <#
        PURE. The running steps that are stuck (Get-SIPipelineStallRule). -Steps: the run's steps { Job, Order, State,
        StartedUtc, LastProgressUtc ($null = no sign of progress recorded since it started), Silent (the runner's log check
        found no sign of progress) }; -LastMinutes: Get-SIPipelineLastStepMinutes; -NowUtc. One entry per stuck step, by
        order: { Step (job key); Order; StartedUtc; AgeMinutes; LastMinutes ($null = not known); ThresholdMinutes; Basis
        last | rule; LastProgressUtc; SinceUtc (when it became stuck) }. A step with recent progress, or still inside its
        time, is never said.
    #>
    param([object[]]$Steps = @(), [hashtable]$LastMinutes = @{}, [Parameter(Mandatory)][datetime]$NowUtc)
    $r = Get-SIPipelineStallRule
    $now = $NowUtc.ToUniversalTime()
    foreach ($s in @(@($Steps) | Where-Object { $_ -and [string]$_.State -in @('Running', 'Starting') } | Sort-Object { [int]$_.Order })) {
        $start = ConvertTo-SIPipelineLongRunTime $s.StartedUtc; if ($null -eq $start) { continue }
        $k = Get-SIJobFlowKey ([string]$s.Job); if (-not $k) { continue }
        $th = Get-SIPipelineStallThreshold -LastMinutes $(if ($LastMinutes.ContainsKey($k)) { $LastMinutes[$k] } else { $null })
        $age = ($now - $start).TotalMinutes
        if ($age -le [double]$th.Minutes) { continue }
        $prog = if ($s.PSObject.Properties['LastProgressUtc']) { ConvertTo-SIPipelineLongRunTime $s.LastProgressUtc } else { $null }
        $silent = [bool]($s.PSObject.Properties['Silent'] -and $s.Silent)
        $crossed = $start.AddMinutes([double]$th.Minutes)
        if ($null -ne $prog) {
            if (($now - $prog).TotalMinutes -lt [double]$r.QuietMinutes) { continue }
            $quietFrom = $prog.AddMinutes([double]$r.QuietMinutes)
        } elseif ($silent) {
            $quietFrom = $crossed
        } else { continue }
        [pscustomobject]@{ Step = $k; Order = [int]$s.Order; StartedUtc = $start; AgeMinutes = [long][Math]::Floor($age)
                           LastMinutes = $(if ($null -ne $th.LastMinutes) { [long][Math]::Round([double]$th.LastMinutes) } else { $null })
                           ThresholdMinutes = [long][Math]::Ceiling([double]$th.Minutes); Basis = $th.Basis; LastProgressUtc = $prog
                           SinceUtc = $(if ($quietFrom -gt $crossed) { $quietFrom } else { $crossed }) }
    }
}

function Get-SIPipelineStalledText {
    <# PURE. The plain words for one entry of Get-SIPipelineStalledSteps (the runner's log and the step record). "shows no
       progress" is the mark that says it was reported already. #>
    param([Parameter(Mandatory)]$Finding)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $h = { param($m) ('{0} h' -f ([double]$m / 60).ToString('0.#', $inv)) }
    $basis = if ($Finding.Basis -eq 'last') { 'its last run here took {0}' -f (& $h $Finding.LastMinutes) } else { 'its last run''s time is not known here, so the rule of {0} applies' -f (& $h $Finding.ThresholdMinutes) }
    $quiet = if ($Finding.LastProgressUtc) { 'its last sign of progress was at {0} UTC' -f ([datetime]$Finding.LastProgressUtc).ToString('yyyy-MM-dd HH:mm', $inv) } else { 'it has written no sign of progress' }
    'step {0} has run for {1}, far past its usual time ({2}), and shows no progress: {3}. Warning only: nothing is stopped, the run goes on. Look at it on Operations > Jobs (si-flow-1204).' -f $Finding.Step, (& $h $Finding.AgeMinutes), $basis, $quiet
}

function Test-SIJobFlowExecutionAtLimit {
    <#
        PURE. Did this execution (ARM: name, properties.status / startTime / endTime) END AT ITS JOB'S OWN RUN LIMIT? It
        ended without succeeding, and it ran for the whole limit (-LimitSeconds, less 2 % or 2 minutes -- the same rule the
        update's job sizing uses). -SinceUtc: only an execution that started at or after it (less 5 minutes) counts.
        A run that was killed earlier (out of memory) or failed by itself is NOT at its limit: a longer limit does not help it.
    #>
    param($Execution, [int]$LimitSeconds, $SinceUtc)
    if (-not $Execution -or $LimitSeconds -le 0) { return $false }
    $props = if ($Execution.PSObject.Properties['properties'] -and $Execution.properties) { $Execution.properties } else { $Execution }
    $p = { param($n) $pp = $props.PSObject.Properties[$n]; if ($pp) { $pp.Value } else { $null } }
    $status = [string](& $p 'status')
    if ($status -notmatch '^(?i)(failed|stopped|degraded|cancelled|canceled)$') { return $false }
    $t = { param($v) if ($null -eq $v -or "$v" -eq '') { $null } elseif ($v -is [datetime]) { $v.ToUniversalTime() } else { [datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } }
    $start = $null; $end = $null
    try { $start = & $t (& $p 'startTime'); $end = & $t (& $p 'endTime') } catch { return $false }
    if (-not $start -or -not $end) { return $false }
    if ($SinceUtc -and $start -lt ([datetime]$SinceUtc).ToUniversalTime().AddMinutes(-5)) { return $false }
    [bool](($end - $start).TotalSeconds -ge ($LimitSeconds - [Math]::Max(120, $LimitSeconds * 0.02)))
}

function Select-SIJobFlowRunningExecution {
    <#
        PURE. Of a job's executions (Azure's list), the one that is running NOW (Running / Processing) -- the one that
        started first when there are several. @{ Execution; StartedUtc ($null when Azure does not say) }, or $null when
        none is running. The pipeline follows it as the step's run instead of starting a second one beside it.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Executions = @())
    $live = @(@($Executions) | Where-Object { $_ -and [string]$_.name -and $_.properties -and ([string]$_.properties.status) -in @('Running', 'Processing') } |
              Sort-Object { if ($_.properties.startTime) { ([datetime]$_.properties.startTime).ToUniversalTime() } else { [datetime]::MaxValue } })
    if (-not $live.Count) { return $null }
    $started = $null
    if ($live[0].properties.startTime) { try { $started = ([datetime]$live[0].properties.startTime).ToUniversalTime() } catch { $started = $null } }
    [pscustomobject]@{ Execution = [string]$live[0].name; StartedUtc = $started }
}

function Get-SIJobFlowExecutionStatusOf {
    <#
        PURE (#945). The status Azure's execution LIST gives one execution (-Execution, by name), or '' when it is not in the
        list. The fallback when the single-execution read fails (live 2026-10-28/29, a customer install: the step's execution had ended
        Failed, the runner's read of it never answered, and the step stayed "running" for days).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Executions = @(), [AllowEmptyString()][string]$Execution)
    if (-not "$Execution".Trim()) { return '' }
    $hit = @(@($Executions) | Where-Object { $_ -and [string]$_.name -eq $Execution -and $_.PSObject.Properties['properties'] -and $_.properties })[0]
    if (-not $hit) { return '' }
    [string]$hit.properties.status
}

function Get-SIJobFlowEndedExecutionCloses {
    <#
        PURE (#945, owner 2026-10-29). THE WAKE-UP CHECK: which open steps of the run -State have an execution that Azure says
        has ENDED, while the step's record still says Running? Asked on EVERY wake-up of the pipeline runner -- also the ones
        that find the install busy -- so a run whose runner never noticed the end (a customer install, 28 Oct: Failed at 03:09Z, still
        "running" on 29 Oct) is closed and goes on by the normal rules (a failed step's dependants are skipped, the run ends).
        -ExecutionsByJob: step key -> that job's execution list (ARM shape); a key that is missing or $null = the list could
        not be read -> nothing is closed for it. -PartsJobs: the step keys collected in parts (their list is the PRODUCER's;
        a producer that SUCCEEDED does not end the step -- its parts do -- so only Failed / Stopped close it).
        CLOSES ONLY: a step that is Running, with a recorded execution (never a VM process 'pid@...'), found BY NAME in the
        list, with an ended status (Succeeded / Failed / Degraded / Cancelled / Stopped) AND an end time at least
        -GraceMinutes ago (20: longer than a working runner needs -- it polls every 30 s, and its pause before judging a
        failure is at most 15 minutes). Running / Processing / not in the list / no end time = nothing. A run that has ended:
        nothing. Never stops anything. Returns @(@{ Order; Job; Execution; Status; State; ErrorClass; Error; EndedUtc }).
    #>
    param($State, [hashtable]$ExecutionsByJob = @{}, [Parameter(Mandatory)][datetime]$NowUtc, [int]$GraceMinutes = 20, [hashtable]$PartsJobs = @{})
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $State -or [string]$State.State -in $script:SIJobFlow.RunFinished) { return @() }
    $now = $NowUtc.ToUniversalTime()
    foreach ($st in @($State.Steps)) {
        if (-not $st -or [string]$st.State -ne 'Running') { continue }
        $ex = [string]$st.Execution
        if (-not $ex.Trim() -or $ex.Contains('@')) { continue }
        $k = Get-SIJobFlowKey ([string]$st.Job)
        if (-not $ExecutionsByJob.ContainsKey($k) -or $null -eq $ExecutionsByJob[$k]) { continue }
        $hit = @(@($ExecutionsByJob[$k]) | Where-Object { $_ -and [string]$_.name -eq $ex -and $_.PSObject.Properties['properties'] -and $_.properties })[0]
        if (-not $hit) { continue }
        $p = $hit.properties
        $status = [string]$p.status
        if ($status -notmatch '^(?i)(succeeded|failed|degraded|cancelled|canceled|stopped)$') { continue }
        $end = $null
        try { if ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim()) { $end = [datetime]::Parse([string]$p.endTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } } catch { $end = $null }
        if (-not $end -or ($now - $end).TotalMinutes -lt $GraceMinutes) { continue }
        $parts = $PartsJobs.ContainsKey($k) -and [bool]$PartsJobs[$k]
        $noticed = 'noticed by the pipeline''s wake-up at {0:yyyy-MM-dd HH:mm}Z (its runner had not closed the step)' -f $now
        $endText = '{0:yyyy-MM-dd HH:mm}Z' -f $end
        $s = $null; $cls = ''; $err = ''
        switch -Regex ($status) {
            '^(?i)succeeded$' {
                if ($parts) { break }
                $s = 'Success'; $cls = ''; $err = ''
            }
            '^(?i)stopped$' {
                $s = 'Interrupted'; $cls = 'stopped'
                $err = '{0} -- the execution ended stopped at {1}; {2}' -f (Get-SIJobFlowStoppedText -Job ([string]$st.Job)), $endText, $noticed
            }
            default {
                $s = 'Failed'; $cls = 'job-failed'
                $err = 'the execution ended {0} at {1}; {2}' -f $status.ToLowerInvariant(), $endText, $noticed
            }
        }
        if (-not $s) { continue }
        $out.Add([pscustomobject]@{ Order = [int]$st.Order; Job = [string]$st.Job; Execution = $ex; Status = $status; State = $s; ErrorClass = $cls; Error = $err; EndedUtc = $end })
    }
    $out.ToArray()
}

function Set-SIJobFlowStepClosed {
    <# PURE (#945). The file / blob stores' close of one step in the run record -State: only when it is run -FlowRunId, the
       run has not ended, and the step (-Close.Order) is Running with -Close.Execution. Changes -State in place; $true when
       the step was closed. #>
    param($State, [string]$FlowRunId, [Parameter(Mandatory)]$Close)
    if (-not $State -or [string]$State.FlowRunId -ne $FlowRunId -or [string]$State.State -in $script:SIJobFlow.RunFinished) { return $false }
    $st = @($State.Steps | Where-Object { $_ -and [int]$_.Order -eq [int]$Close.Order })[0]
    if (-not $st -or [string]$st.State -ne 'Running' -or [string]$st.Execution -ne [string]$Close.Execution) { return $false }
    $st.State = [string]$Close.State; $st.ErrorClass = [string]$Close.ErrorClass; $st.Error = [string]$Close.Error; $st.EndedUtc = ([datetime]$Close.EndedUtc).ToUniversalTime()
    $true
}

function Get-SIJobFlowSaveJson {
    <# PURE (#945). The JSON the file / blob store writes for -State: as it is, except a step the STORED record (-Stored, the
       same run) already ended (Success / Failed / Interrupted / TimedOut) with the SAME execution, which -State still says is
       Running -- that step is written as stored (a runner that never saw the wake-up check's close does not reopen it; it
       takes the close over at its next poll). A step started again (a new execution, or Starting) is written as it is.
       -State itself is never changed. #>
    param([Parameter(Mandatory)]$State, $Stored)
    $json = ConvertTo-SIJobFlowRunJson -State $State
    if (-not $Stored -or [string]$Stored.FlowRunId -ne [string]$State.FlowRunId) { return $json }
    $keep = @{}
    foreach ($st in @($State.Steps)) {
        if (-not $st -or [string]$st.State -ne 'Running' -or -not [string]$st.Execution) { continue }
        $was = @($Stored.Steps | Where-Object { $_ -and [int]$_.Order -eq [int]$st.Order })[0]
        if ($was -and [string]$was.Execution -eq [string]$st.Execution -and [string]$was.State -in @('Success', 'Failed', 'Interrupted', 'TimedOut')) { $keep[[int]$st.Order] = $was }
    }
    if (-not $keep.Count) { return $json }
    $copy = ConvertFrom-SIJobFlowRunJson -Json $json
    foreach ($st in @($copy.Steps)) {
        if (-not $st -or -not $keep.ContainsKey([int]$st.Order)) { continue }
        $w = $keep[[int]$st.Order]
        $st.State = [string]$w.State; $st.ErrorClass = [string]$w.ErrorClass; $st.Error = [string]$w.Error; $st.EndedUtc = $w.EndedUtc
    }
    ConvertTo-SIJobFlowRunJson -State $copy
}

function Get-SIJobFlowStepRowOf {
    <# PURE (#945). One step of the stored run record (or $null when the record is another run). #>
    param($State, [string]$FlowRunId, [int]$Order)
    if (-not $State -or [string]$State.FlowRunId -ne $FlowRunId) { return $null }
    @($State.Steps | Where-Object { $_ -and [int]$_.Order -eq $Order })[0]
}

function Get-SIJobFlowHoursText {
    <# PURE. Seconds as hours for a plain line: 14400 -> '4 h', 5400 -> '1.5 h'. #>
    param([int]$Seconds)
    '{0} h' -f ([double]$Seconds / 3600).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture)
}

function Invoke-SIJobFlow {
    <#
        Run (or resume) one flow run. Pure over its seams:
          -Start  { param($Job) }            -> the execution name (throws when it cannot start)
          -Poll   { param($Job, $Execution) } -> the execution status: Running | Processing | Succeeded | Failed | Stopped | Degraded
          -Stop   { param($Job, $Execution) } (optional) -- a timed-out execution is asked to stop
          -JobLimit { param($Job) } (optional; the container flow: the seams' Limit) -> the job's OWN run limit in minutes
                  (its replica timeout), 0 = not known. THE PIPELINE NEVER CUTS A STEP BEFORE ITS JOB WOULD END BY ITSELF:
                  a step's limit is the LARGER of its configured timeout and its job's run limit (plus 5 minutes, so the
                  job ends first), and the log says which one applies. A limit that cannot be read is asked for again on
                  the next poll; until it answers, and without the seam (the VM flow), the configured timeout applies.
          SELF-HEALING IN THE SAME RUN (owner 2026-10-12: "si must self heal with limits"): a step whose job was stopped AT
          ITS OWN RUN LIMIT is not left for the next update and the next day's run. With both seams below:
          -LimitHit { param($Job, $Execution, $SinceUtc) } (the container flow: the seams' LimitHit) -> $null, or
                  @{ JobName; LimitSeconds; Execution } = the job (the step's own, or the producer / a worker of a
                  collection in parts) whose execution ended at its limit;
          -RaiseLimit { param($Hit) } -> @{ Restart; NewSeconds; Why } -- raises that job's run limit by the SAME rule and
                  code as the update's job sizing (setup/_shared/SI-JobSizing.ps1, Invoke-SIJobRunLimitHeal);
          the step is then STARTED AGAIN ONCE in this run (any kind of step: a collection, the CI build, a delivery), and
          the steps after it run when it succeeds. Never a second time for the same step in one run: stopped at its limit
          again, or the limit could not be raised (the customer's own run limit, no right to change the job, already at
          the longest limit Azure takes), the step fails as before with the reason in plain words. A run killed for memory is never at its limit.
          A JOB THAT IS ALREADY RUNNING IS NOT STARTED AGAIN (owner 2026-10-12: "we cannot have 2 builds running at the
          same time"): -Running { param($Job) } (the container flow: the seams' Running) -> $null, or @{ Execution;
                  StartedUtc } = an execution of the step's job that is running now (somebody ran the job by hand, a
                  release check started it). The step then starts NO second execution: it FOLLOWS that one as its own run
                  -- the log and the run's note say so -- and is judged by its result. A collection in parts follows its
                  producer the same way. Nothing went wrong, so no guard event. A check that cannot be made is said and
                  the step is started as before; without the seam (the VM flow) nothing is checked.
          -Save   { param($State) }           -- the run record after every change (and every poll: the heartbeat)
          -OnStep { param($State, $Step, $Phase) } (optional) -- 'Start' / 'End' per step (run health)
          -Now    { } -> UTC [datetime]; -Sleep { param($Seconds) }
          -StartEvidence (optional; the container flow) { param($Job, $Execution, $StartedUtc, $EndedUtc) } or an object
                  with Probe() (New-SIJobFlowStartEvidence) -> @{ HasStartRecord; HasTranscript }. With it, a step whose
                  execution ended Failed without the engine ever starting (Get-SIJobFlowFailureClass: never-started) is
                  started again -StartRetries times after -StartRetryBackoffSeconds; the step record keeps Attempts and
                  RetryReason. Without it (the VM flow) nothing is retried.
        -Previous: the last run record (Resolve-SIJobFlowStart decides). -FromStep: a re-run that starts at that step (the
        steps before it are Skipped, 'before the re-run'). Returns the final run record (+ .Outcome = the Resolve answer).
    #>
    param(
        [Parameter(Mandatory)]$Definition,
        # an adapter object (New-SIJobFlowArmSeams / New-SIJobFlowVmSeams) -- or the three scriptblocks below
        $Seams,
        [scriptblock]$Start,
        [scriptblock]$Poll,
        [scriptblock]$Stop,
        [scriptblock]$JobLimit,
        [scriptblock]$LimitHit,
        [scriptblock]$RaiseLimit,
        [scriptblock]$Running,
        # #882 -- A STEP THE PIPELINE ENDS LEAVES NOTHING RUNNING FOR IT. -StopWorkers { param($Job, $SinceUtc, $Execution) }
        # (the container flow: the workers of a collection in parts, the Risk Analysis queue workers -- their runs closed in
        # the state store first, so a worker started later discards them; Get-SIJobFlowWorkerJobs). Called for a step that
        # ended without success (failed, stopped, its job died), that was cancelled, and for a step a resumed run closes
        # Interrupted (then also its job's execution that runs now and started since the step did is stopped: nobody
        # follows it any more). A stop that fails is said; it never fails the run.
        [scriptblock]$StopWorkers,
        # THE RUN GOES ON WITHOUT ONE SOURCE. -SourceState (New-SISourceStateStore, engine\_shared\SI-SourceState.ps1; none
        # on an install without its database): told when a COLLECTION step ended for good -- Good($Job, $SinceUtc, $NowUtc)
        # or Dropped($Job, $SinceUtc, $NowUtc, $Why) -> when that source last collected completely (or $null). Dropped also
        # makes sure nothing the failed collection wrote counts as a complete collection (no record turns 'not seen').
        # Never fails the run: a state that cannot be written is said, and the run goes on.
        $SourceState,
        # DELIVERY WAITS FOR A SOURCE THAT IS TOO OLD. -DeliverHold { } -> '' or why (Get-SISourceDeliveryHold: a source has
        # had no good collection for SI_Pro_SourceDropout_HoldDeliveryDays days or more). Asked once, when Deliver is about
        # to start: with a reason its steps are Skipped (class 'source-too-old', the reason in the record) -- the stages
        # before it ran, nothing is mailed and no ticket is changed. A step run now on its own is the person's own choice
        # and is not held. Never a guard event (it would mail every run).
        [scriptblock]$DeliverHold,
        # ONE FAILED STEP DOES NOT COST THE REST OF THE RUN (owner 2026-10-12 / 13). After a step of Correlate (the CI build,
        # Risk Analysis) did not succeed, a step the map marks 'runsOnStored' (the data sync, the verification service)
        # still runs, on what is stored -- it holds back by itself whatever is not complete and closes nothing. Every other
        # step that needs this run's result stays held as before. -GoOnAfterFailedStep $false = everything is held as
        # before (the setting SI_Pro_Pipeline_GoOnAfterFailedStep). -FirstRun { } -> $true when this install has no earlier
        # complete data to fall back on (the wording then says "first collection, not complete yet"); without the seam a
        # run with no run before it counts as the first. Never fails the run.
        [bool]$GoOnAfterFailedStep = (Test-SIPipelineGoOnAfterFailedStep),
        [scriptblock]$FirstRun,
        # THE FIRST RUN OF A NEW INSTALL IS ITS OWN FLOW (owner 2026-10-13; engine\_shared\SI-Pipeline.ps1, "THE FIRST RUN").
        # Only with the -FirstRun seam, and only while it answers $true (the database holds no complete collection yet):
        #   * "two restarts": a step that collects, correlates or runs on what is stored and fails or is stopped is started
        #     again at once, up to -FirstRunRestarts times (the setting SI_Pro_Pipeline_FirstRunRestarts, default 2; 0 =
        #     never). NEVER a step that writes to the customer's systems, changes a ticket or sends a mail;
        #   * "wait for merged assets": the moment the asset build has finished whole, the data sync runs at once, on what
        #     is stored (it holds every output), so the merged assets are the first data view; it then runs again at its
        #     own place. Nothing of it ever fails the run.
        [int]$FirstRunRestarts = (Get-SIPipelineFirstRunRestarts),
        # A STEP THAT SHOWS NO PROGRESS IS REPORTED, NEVER STOPPED. -Progress (the container flow: New-SIJobFlowProgressProbe)
        # { param($Job, $Execution, $StartedUtc) } or an object with Probe() -> @{ LastSeenUtc } = when the step's job last
        # wrote a log line or a run-health record; $null / no LastSeenUtc = it cannot be told (then nothing is said). A step
        # silent for -SilentAfterMinutes gets ONE warning in this run -- the log, OnStep 'Silent' (run health) and the step
        # record -- and keeps running. Asked at most every -ProgressCheckMinutes.
        $Progress,
        [int]$SilentAfterMinutes = $script:SIJobFlow.SilentAfterMinutes,
        [int]$ProgressCheckMinutes = $script:SIJobFlow.ProgressCheckMinutes,
        # a run-record store (New-SIJobFlowFileStore / -BlobStore / -SqlStore): its Save() is used when -Save is not given
        $Store,
        [scriptblock]$Save,
        [scriptblock]$OnStep,
        [scriptblock]$Now = { [datetime]::UtcNow },
        [scriptblock]$Sleep = { param($Seconds) Start-Sleep -Seconds $Seconds },
        [scriptblock]$Log = { param($Level, $Message) Write-Host ('[flow] {0}' -f $Message) },
        $Map,
        $Previous,
        [string]$FromStep,
        [string]$Trigger = 'schedule',
        [switch]$Force,
        [int]$PollSeconds = 30,
        [int]$StaleAfterMinutes = 15,
        $StartEvidence,
        [int]$StartRetries = $script:SIJobFlow.StartRetries,
        [int]$StartRetryBackoffSeconds = $script:SIJobFlow.StartRetryBackoff,
        [int]$NeverStartedMaxSeconds = $script:SIJobFlow.NeverStartedMaxSeconds,
        # #306: what this run is -- the pipeline (default), one stage (-Target = stage id), one step (-Target = job), or the
        # pipeline from a step (from-step = -FromStep) -- who asked for it, the queue request it serves, the slot it is for
        # (a queued scheduled run), the run id (the queue names it before the run starts), the note, and the lock's
        # heartbeat (called on every save, so the install's lock stays alive exactly as long as the run record does)
        [ValidateSet('pipeline', 'stage', 'step', 'from-step')][string]$Scope = 'pipeline',
        [string]$Target = '',
        [string]$RequestedBy = '',
        [long]$RequestId = 0,
        $SlotUtc,
        [string]$Note = '',
        [string]$FlowRunId,
        [scriptblock]$Heartbeat,
        # #700: the SecurityInsight version this runner runs (recorded on a NEW run: the updater cancels a run of another
        # version); -Cancelled { param($FlowRunId) } -> $null, or @{ By; Reason } when the run was CANCELLED meanwhile (the
        # web app, a support start of the runner, the updater). Asked at every stage and every poll: a cancelled run starts
        # nothing more, its running executions are asked to stop, and it ends Cancelled. Without the seam nothing is asked.
        [string]$Version = '',
        [scriptblock]$Cancelled,
        # si-flow-1203 (2026-10-26): A RUN OR STEP MUCH LONGER THAN USUAL IS SAID, NEVER STOPPED. -History @{ Runs; Steps }
        # = the newest run records and their steps (New-SIJobFlowSqlStore .Recent(); Get-SIPipelineUsualMinutes' shapes), or
        # a scriptblock that answers them (read once, only when the run goes on).
        # With it, a run that has run longer than its threshold (Get-SIPipelineLongRun: 2 x usual, at least usual + 2 h; the
        # floor without history) is said ONCE in the log and in the run's note, a step once in the log and its step record
        # (RetryReason). Without it (the default) nothing is checked. Never fails the run.
        $History,
        # si-flow-1204 (owner 2026-10-29): A STEP FAR PAST ITS LAST TIME WITH NO PROGRESS IS SAID, NEVER STOPPED. -StepProgress
        # { param($Job, $Execution, $SinceUtc) } -> the step's newest sign of progress since it started (Get-SIStepProgressLast), or
        # $null. Asked only for a step already past its time (Get-SIPipelineStalledSteps), at most every 10 minutes per step;
        # said ONCE in the log and the step record (RetryReason). Needs -History (the last run's times). Never fails the run.
        [scriptblock]$StepProgress
    )
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    if ($Scope -eq 'from-step') { if (-not $FromStep) { $FromStep = $Target }; $Scope = 'pipeline' }
    if ($Scope -eq 'step') { $Target = Get-SIJobFlowKey $Target }
    if ($Seams) {
        if (-not $Start) { $Start = { param($j) $Seams.Start($j) } }
        if (-not $Poll) { $Poll = { param($j, $e) $Seams.Poll($j, $e) } }
        if (-not $Stop -and $Seams.PSObject.Methods['Stop']) { $Stop = { param($j, $e) $Seams.Stop($j, $e) } }
        if (-not $JobLimit -and $Seams.PSObject.Methods['Limit']) { $JobLimit = { param($j) $Seams.Limit($j) } }
        if (-not $LimitHit -and $Seams.PSObject.Methods['LimitHit']) { $LimitHit = { param($j, $e, $since) $Seams.LimitHit($j, $e, $since) } }
        if (-not $Running -and $Seams.PSObject.Methods['Running']) { $Running = { param($j) $Seams.Running($j) } }
        if (-not $StopWorkers -and $Seams.PSObject.Methods['StopWorkers']) { $StopWorkers = { param($j, $s, $e) $Seams.StopWorkers($j, $s, $e) } }
    }
    if (-not $Start -or -not $Poll) { throw 'Invoke-SIJobFlow needs -Seams, or -Start and -Poll' }
    # #882: what worked for a step that ended without success, was cancelled or was closed Interrupted is stopped -- its
    # workers (their runs closed first) and, for a step closed Interrupted by a resumed run (-AlsoRunning), its job's
    # execution that runs now and started since the step did. Never throws; what could not be stopped is said.
    $stopStepWork = {
        param($st, [switch]$AlsoRunning)
        $k = [string]$st.Job
        $since = if ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $null }
        if ($AlsoRunning -and $Running -and $Stop) {
            $live = $null
            try { $live = & $Running $k } catch { $live = $null }
            if ($live -and [string]$live.Execution -and ((-not $since) -or (-not $live.StartedUtc) -or ([datetime]$live.StartedUtc).ToUniversalTime() -ge $since.AddMinutes(-5))) {
                try { $null = & $Stop $k ([string]$live.Execution); & $Log 'WARN' ('step {0} {1}: its execution {2} was still running and nobody follows it any more -- stopped' -f $st.Order, $k, $live.Execution) }
                catch { & $Log 'WARN' ('step {0} {1}: its execution {2} could not be stopped ({3})' -f $st.Order, $k, $live.Execution, $_.Exception.Message) }
            }
        }
        if ($StopWorkers) {
            try { $null = & $StopWorkers $k $since ([string]$st.Execution) }
            catch { & $Log 'WARN' ('step {0} {1}: its workers could not be stopped ({2})' -f $st.Order, $k, $_.Exception.Message) }
        }
    }
    if (-not $Save) { if ($Store) { $Save = { param($s) $Store.Save($s) } } else { $Save = { param($s) } } }
    if (-not $PSBoundParameters.ContainsKey('Previous') -and $Store) { $Previous = $Store.Load() }
    $FromStep = Get-SIJobFlowKey $FromStep
    $t0 = ([datetime](& $Now)).ToUniversalTime()
    # SCHED-1.1: a manual start (Run flow now / re-run from a step) runs now -- unless a run is still running; a wake-up of
    # the schedule runs only when the cadence says the flow is due (finish + interval, or a time-of-day slot).
    $due = $null
    $manual = $Force -or $FromStep -or $Scope -ne 'pipeline'
    if ($manual) { $decision = Resolve-SIJobFlowStart -Previous $Previous -NowUtc $t0 -Force -FromStep $FromStep -StaleAfterMinutes $StaleAfterMinutes }
    else {
        $due = Get-SIJobFlowDue -Definition $Definition -Previous $Previous -NowUtc $t0 -StaleAfterMinutes $StaleAfterMinutes
        $decision = switch ($due.Action) { 'Start' { 'New' } 'Wait' { 'Wait' } default { $due.Action } }
    }
    if ($decision -eq 'Busy') {
        # #277: a schedule wake-up during a run is normal operation (the runner wakes every 5 minutes) -- INFO, not a guard.
        # A manual start (Run flow now / re-run from a step) that is refused is worth a warning.
        if ($manual) { & $Log 'WARN' ('skipped: the previous flow run ({0}, started {1:u}) is still running -- nothing starts twice' -f $Previous.FlowRunId, $Previous.StartedUtc) }
        else { & $Log 'INFO' ('the flow is still running (flow run {0}, started {1:u}); this wake-up does nothing' -f $Previous.FlowRunId, $Previous.StartedUtc) }
        $Previous | Add-Member -NotePropertyName Outcome -NotePropertyValue 'Busy' -Force; return $Previous
    }
    if ($decision -eq 'Wait') {
        & $Log 'INFO' ('not due: {0}' -f $due.Reason)
        $w = if ($Previous) { $Previous } else { [pscustomobject]@{ FlowRunId = ''; State = 'None'; Steps = @() } }
        $w | Add-Member -NotePropertyName Outcome -NotePropertyValue 'Wait' -Force
        $w | Add-Member -NotePropertyName NextUtc -NotePropertyValue $due.NextUtc -Force
        return $w
    }
    $check = Test-SIJobFlowDefinition -Definition $Definition -Map $Map
    if (@($check.Problems).Count) { throw ('the flow definition is not valid: ' + (@($check.Problems) -join '; ')) }
    foreach ($w in @($check.Warnings)) { & $Log 'WARN' $w }

    if ($decision -eq 'Resume') {
        $state = $Previous
        & $Log 'WARN' ('resuming flow run {0} (its runner stopped) -- finished steps are kept, a running step is followed, nothing is started twice' -f $state.FlowRunId)
        foreach ($st in @($state.Steps)) {
            if ($st.State -eq 'Starting') {
                $st.State = 'Interrupted'; $st.ErrorClass = 'interrupted'; $st.EndedUtc = $t0
                $st.Error = 'the flow runner stopped while starting this step; it is not started again (it may or may not have run) -- see the job''s executions'
                # #882: what it may have started is not followed by anyone -- stopped, its workers too
                & $stopStepWork $st -AlsoRunning
            }
        }
    } else {
        if ($FromStep -and -not (@($Definition.Steps) | Where-Object { $_.Job -eq $FromStep })) { throw ("'{0}' is not a step of the flow" -f $FromStep) }
        if ($Scope -eq 'step' -and -not (@($Definition.Steps) | Where-Object { $_.Job -eq $Target })) { throw ("'{0}' is not a step of the pipeline" -f $Target) }
        if ($Scope -eq 'stage' -and -not (@(Get-SIPipelineStages -Definition $Definition) | Where-Object { [string]$_.Id -eq $Target })) { throw ("'{0}' is not a stage of the pipeline" -f $Target) }
        $trg = if ($FromStep) { 'rerun' } elseif ($due -and $due.Trigger) { $due.Trigger } else { $Trigger }
        $slot = if ($due) { $due.SlotUtc } elseif ($SlotUtc -and $Scope -eq 'pipeline') { $SlotUtc } else { $null }
        $nt = if ($due) { [string]$due.Note } else { $Note }
        # why a scheduled start is late, in the run's own note: owed only because the previous run was still going (normal
        # on a large install -- no guard event) or missed for any other reason (the guard reports it). Decided here, at the
        # start, for a start of the schedule and for one that waited in the queue alike.
        if ($Scope -eq 'pipeline' -and -not $FromStep -and $slot) {
            $lateStart = $null; try { $lateStart = Get-SIJobFlowLateStart -Trigger $trg -SlotUtc $slot -Previous $Previous -NowUtc $t0 } catch { $lateStart = $null }
            if ($lateStart -and $lateStart.Kind -ne 'on-time') { $nt = [string]$lateStart.Note }
        }
        # the measured cadence: when the run before this one took longer than the schedule's interval, the run's note says
        # in plain words how often the data is really refreshed (the web app shows the note; the run's record keeps it)
        if ($Scope -eq 'pipeline' -and -not $FromStep -and $slot -and $Previous) {
            $cad = $null; try { $cad = Get-SIPipelineMeasuredCadence -Definition $Definition -Previous $Previous -NowUtc $t0 -SlotUtc $slot } catch { $cad = $null }
            if ($cad) { $nt = ('{0} {1}' -f $cad.Text, $nt).Trim(); if ($nt.Length -gt 400) { $nt = $nt.Substring(0, 400) } }   # the note's column holds 400
        }
        $state = New-SIJobFlowRunState -Definition $Definition -NowUtc $t0 -Trigger $trg -FromStep $FromStep -FlowRunId $FlowRunId `
            -SlotUtc $slot -LastSlotUtc $(if ($Previous) { Get-SIJobFlowSlotRun -Definition $Definition -Previous $Previous } else { $null }) -Note $nt `
            -Scope $Scope -Target $Target -RequestedBy $RequestedBy -RequestId $RequestId -Version $Version
        if ($state.Note) { & $Log 'WARN' $state.Note }
        if ($FromStep) {
            foreach ($st in @($state.Steps)) {
                if ($st.Job -eq $FromStep) { break }
                if ($st.State -eq 'Waiting') { $st.State = 'Skipped'; $st.ErrorClass = 'before-rerun'; $st.Error = ('before the re-run from {0}' -f $FromStep) }
            }
        }
    }
    # a record written before attempts were kept gets them now (a resumed run)
    foreach ($st in @($state.Steps)) {
        if (-not $st.PSObject.Properties['Attempts']) { $st | Add-Member -NotePropertyName Attempts -NotePropertyValue (Get-SIJobFlowAttempts $st) }
        if (-not $st.PSObject.Properties['RetryReason']) { $st | Add-Member -NotePropertyName RetryReason -NotePropertyValue '' }
    }
    foreach ($st in @($state.Steps)) { if (-not $st.PSObject.Properties['Stage']) { $st | Add-Member -NotePropertyName Stage -NotePropertyValue '' } }
    foreach ($n in @('Scope', 'Target', 'RequestedBy', 'RequestId', 'Version', 'CancelledBy')) { if (-not $state.PSObject.Properties[$n]) { $state | Add-Member -NotePropertyName $n -NotePropertyValue $(if ($n -eq 'Scope') { 'pipeline' } elseif ($n -eq 'RequestId') { 0 } else { '' }) } }
    # #700: was this run CANCELLED meanwhile? Asked at every stage and every poll (never fails the run: a check that cannot be
    # made is asked again at the next poll). $cancelHit = @{ By; Reason } once it was.
    $cancelHit = $null
    # (dot-sourced: it sets $cancelHit of this function)
    $askCancelled = {
        if ($Cancelled -and -not $cancelHit) {
            try { $cx = & $Cancelled ([string]$state.FlowRunId); if ($cx) { $cancelHit = $cx } } catch { }
        }
    }
    $saveNow = {
        $state.HeartbeatUtc = ([datetime](& $Now)).ToUniversalTime(); & $Save $state
        if ($Heartbeat) { try { & $Heartbeat $state } catch { & $Log 'WARN' ('the pipeline lock could not be beaten ({0})' -f $_.Exception.Message) } }
    }
    & $saveNow

    $groups = Get-SIJobFlowGroups -Definition $Definition
    $defByJob = @{}; foreach ($s in @($Definition.Steps)) { $defByJob[[string]$s.Job] = $s }
    # the limit of a step: the larger of its configured timeout and its job's own run limit (read once per job, said once)
    $jobLimits = @{}; $saidLimit = @{}
    # a step with no sign of progress: said once per step (this run), asked for at most every ProgressCheckMinutes
    $silentSaid = @{}; $progressAsked = @{}
    # a step that has run longer than its step timeout: said once per step (this run) -- never stopped
    $overdueSaid = @{}
    # si-flow-1203: a run / step much longer than usual for this install -- said once (the run: its note says it; a step:
    # its RetryReason), never stopped. The usual lengths are worked out once, from the OTHER runs read (-History).
    $longUsual = $null; $longRunSaid = $false; $longStepSaid = @{}
    # si-flow-1204: the last run's time of each job (the OTHER runs read), the steps said, when each step's progress was asked
    $stallLast = $null; $stallSaid = @{}; $stallAsked = @{}
    if ($null -ne $History) {
        try {
            # a scriptblock is read only here, once the run goes on (never on a wake-up that only waits)
            $hist = if ($History -is [scriptblock]) { & $History } else { $History }
            $longUsual = Get-SIPipelineUsualMinutes -Runs @($hist.Runs | Where-Object { $_ }) -Steps @($hist.Steps | Where-Object { $_ }) -ExcludeRunId ([string]$state.FlowRunId)
            if ($StepProgress) { $stallLast = Get-SIPipelineLastStepMinutes -Steps @($hist.Steps | Where-Object { $_ }) -ExcludeRunId ([string]$state.FlowRunId) }
        }
        catch { $longUsual = $null; & $Log 'WARN' ('how long a run usually takes here could not be worked out ({0}) -- a long run is not said in this run' -f $_.Exception.Message) }
    }
    # (dot-sourced: it sets $longRunSaid of this function; the caller saves)
    $longCheck = {
        if ($null -eq $longUsual) { return }
        try {
            foreach ($lf in @(Get-SIPipelineLongRun -Run $state -Steps @($state.Steps) -Usual $longUsual -NowUtc ([datetime](& $Now)).ToUniversalTime())) {
                $lt = Get-SIPipelineLongRunText -Finding $lf
                if ($lf.Kind -eq 'run') {
                    if ($longRunSaid -or [string]$state.Note -match 'much longer than usual') { $longRunSaid = $true; continue }
                    $longRunSaid = $true
                    & $Log 'WARN' $lt
                    $ln = 'This run has run much longer than usual: {0} h so far{1} (si-flow-1203).' -f ([double]$lf.AgeMinutes / 60).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture),
                          $(if ($lf.Basis -eq 'history') { ', usually {0} h' -f ([double]$lf.UsualMinutes / 60).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture) } else { '' })
                    $state.Note = ('{0} {1}' -f [string]$state.Note, $ln).Trim()
                    if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
                    continue
                }
                $lst = @(@($state.Steps) | Where-Object { [int]$_.Order -eq [int]$lf.Order })[0]
                if (-not $lst -or $longStepSaid.ContainsKey([int]$lf.Order) -or [string]$lst.RetryReason -match 'much longer than usual') { if ($lst) { $longStepSaid[[int]$lf.Order] = $true }; continue }
                $longStepSaid[[int]$lf.Order] = $true
                & $Log 'WARN' ('step {0} {1}: {2}' -f $lst.Order, $lst.Job, $lt)
                $lst.RetryReason = (@([string]$lst.RetryReason, $lt) | Where-Object { $_ }) -join ' | '
            }
        } catch { & $Log 'WARN' ('whether this run is much longer than usual could not be told ({0})' -f $_.Exception.Message) }
        # si-flow-1204: a step far past its last time that shows no progress -- said once, nothing is stopped
        if ($null -ne $stallLast -and $StepProgress) {
            try {
                $sNow = ([datetime](& $Now)).ToUniversalTime()
                $cand = @()
                foreach ($st0 in @(@($state.Steps) | Where-Object { [string]$_.State -in @('Running', 'Starting') -and $_.StartedUtc })) {
                    $sk0 = Get-SIJobFlowKey ([string]$st0.Job)
                    if ($stallSaid.ContainsKey([int]$st0.Order) -or [string]$st0.RetryReason -match 'shows no progress') { $stallSaid[[int]$st0.Order] = $true; continue }
                    $th0 = Get-SIPipelineStallThreshold -LastMinutes $(if ($stallLast.ContainsKey($sk0)) { $stallLast[$sk0] } else { $null })
                    $since0 = ([datetime]$st0.StartedUtc).ToUniversalTime()
                    if (($sNow - $since0).TotalMinutes -le [double]$th0.Minutes) { continue }
                    if ($stallAsked.ContainsKey([int]$st0.Order) -and ($sNow - [datetime]$stallAsked[[int]$st0.Order]).TotalMinutes -lt 10) { continue }
                    $stallAsked[[int]$st0.Order] = $sNow
                    $lp = $null; try { $lp = & $StepProgress ([string]$st0.Job) ([string]$st0.Execution) $since0 } catch { $lp = $null }
                    $cand += [pscustomobject]@{ Job = [string]$st0.Job; Order = [int]$st0.Order; State = [string]$st0.State; StartedUtc = $since0; LastProgressUtc = $lp
                                                Silent = ([string]$st0.RetryReason -match 'has shown no sign of progress for') }
                }
                foreach ($sf in @(Get-SIPipelineStalledSteps -Steps $cand -LastMinutes $stallLast -NowUtc $sNow)) {
                    $sst = @(@($state.Steps) | Where-Object { [int]$_.Order -eq [int]$sf.Order })[0]
                    if (-not $sst) { continue }
                    $stallSaid[[int]$sf.Order] = $true
                    $stt = Get-SIPipelineStalledText -Finding $sf
                    & $Log 'WARN' ('step {0} {1}: {2}' -f $sst.Order, $sst.Job, $stt)
                    $sst.RetryReason = (@([string]$sst.RetryReason, $stt) | Where-Object { $_ }) -join ' | '
                }
            } catch { & $Log 'WARN' ('whether a step shows progress could not be told ({0})' -f $_.Exception.Message) }
        }
    }
    $limitOf = {
        param($st)
        $k = [string]$st.Job
        $conf = 240; if ($defByJob.ContainsKey($k)) { $conf = [int]$defByJob[$k].TimeoutMinutes }
        $jobMin = 0; $known = $true
        if ($JobLimit) {
            if ($jobLimits.ContainsKey($k)) { $jobMin = [int]$jobLimits[$k] }
            else {
                try { $jobMin = [int](& $JobLimit $k); $jobLimits[$k] = $jobMin }
                catch { $known = $false }   # asked again on the next poll; until it answers the step's own timeout applies
            }
        }
        $fromJob = $jobMin -gt $conf
        $r = [pscustomobject]@{ Minutes = $(if ($fromJob) { $jobMin + 5 } else { $conf }); Configured = $conf; JobMinutes = $jobMin; FromJob = $fromJob; Known = $known }
        if ($JobLimit -and $known -and -not $saidLimit.ContainsKey($k)) {
            $saidLimit[$k] = $true
            if ($jobMin -gt 0) { & $Log 'INFO' ('step {0} {1}: the pipeline stops no step for the time it takes -- its job''s own run limit is {2} minutes; after {3} minutes (the step timeout) the pipeline says it is taking long' -f $st.Order, $k, $jobMin, $conf) }
            else { & $Log 'INFO' ('step {0} {1}: the pipeline stops no step for the time it takes; after {2} minutes (the step timeout) the pipeline says it is taking long' -f $st.Order, $k, $conf) }
        }
        $r
    }
    # a COLLECTION step that ended for good (after self-healing and the start retry): the source's state is recorded, and a
    # failed one learns when that source last collected completely (the run's sentence names it). -SourceState first; else
    # the run before this one, when that step succeeded in it; else no date.
    $firstStart = @{}
    $deliverHoldAsked = $false; $deliverHoldWhy = ''
    # has this install no earlier complete data (a new install's first collection)? Asked at most once per run, only when
    # a step would run on what is stored after a failed step. (dot-sourced: it sets the two variables of this function)
    $firstRunAsked = $false; $isFirstRun = $false
    $askFirstRun = {
        if (-not $firstRunAsked) {
            $firstRunAsked = $true
            if ($FirstRun) { try { $isFirstRun = [bool](& $FirstRun) } catch { $isFirstRun = $false; & $Log 'INFO' ('whether this install has earlier complete data could not be checked ({0})' -f $_.Exception.Message) } }
            else { $isFirstRun = -not $Previous }
        }
    }
    # A FIRST COLLECTION, "wait for merged assets": the asset build ($st) has just finished whole -- the step that shows
    # the merged assets ($fd, the data sync) runs AT ONCE, on what is stored. Its record says so BEFORE it is started, so
    # the data sync holds every output (nothing goes to ServiceNow or a file from a run that is not complete). Then the
    # step goes back to waiting and runs again at its own place. (dot-sourced: it reads and sets this function's variables)
    $firstDelivered = $false
    $deliverFirst = {
        $fdKeep = [string]$fd.RetryReason; $fdOk = $false
        try {
            $fdWhy = Get-SIPipelineFirstRunText -Kind DeliveryWhy -Job ([string]$fd.Job)
            $fd.RetryReason = (@($fdKeep, $fdWhy) | Where-Object { $_ }) -join ' | '
            $fd.State = 'Starting'; $fd.StartedUtc = ([datetime](& $Now)).ToUniversalTime()
            & $saveNow
            $fdExec = [string](& $Start $fd.Job)
            $fd.Execution = $fdExec; $fd.State = 'Running'
            & $Log 'WARN' ('step {0} {1}: {2} ({3})' -f $fd.Order, $fd.Job, $fdWhy, $fdExec)
            & $saveNow
            while ($true) {
                $fdStatus = ''
                try {
                    $fdPr = & $Poll $fd.Job $fdExec
                    if ($null -ne $fdPr -and $fdPr -isnot [string] -and $fdPr.PSObject.Properties['Status']) { $fdStatus = [string]$fdPr.Status } else { $fdStatus = [string]$fdPr }
                } catch { & $Log 'WARN' ('step {0} {1}: its status could not be read ({2}) -- trying again' -f $fd.Order, $fd.Job, $_.Exception.Message) }
                if ($fdStatus -match '^(?i)succeeded$') { $fdOk = $true; break }
                if ($fdStatus -match '^(?i)(failed|stopped|degraded|cancelled|canceled)$') { break }
                & $saveNow
                & $Sleep $PollSeconds
            }
        } catch { & $Log 'WARN' ('first collection: {0} could not be run at once after the asset build ({1})' -f $fd.Job, $_.Exception.Message) }
        $fd.State = 'Waiting'; $fd.Execution = ''; $fd.StartedUtc = $null; $fd.EndedUtc = $null; $fd.ErrorClass = ''; $fd.Error = ''; $fd.RetryReason = $fdKeep
        $fdSaid = Get-SIPipelineFirstRunText -Kind $(if ($fdOk) { 'Delivered' } else { 'NotDelivered' }) -Job ([string]$fd.Job)
        & $Log $(if ($fdOk) { 'INFO' } else { 'WARN' }) $fdSaid
        $st.RetryReason = (@([string]$st.RetryReason, $fdSaid) | Where-Object { $_ }) -join ' | '
        $state.Note = ('{0} {1}' -f $fdSaid, ([string]$state.Note).Replace((Get-SIPipelineFirstRunText -Kind Running), '').Trim()).Trim()
        if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
        & $saveNow
    }
    # a first collection says so from its start (the pipeline page shows the run's note): nothing is shown yet, and why
    if ($FirstRun -and $decision -ne 'Resume' -and [string]$state.Scope -eq 'pipeline' -and -not [string]$state.FromStep) {
        . $askFirstRun
        if ($isFirstRun) {
            $state.Note = ('{0} {1}' -f (Get-SIPipelineFirstRunText -Kind Running), [string]$state.Note).Trim()
            if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
            & $Log 'INFO' (Get-SIPipelineFirstRunText -Kind Running)
        }
    }
    $sourceEnded = {
        param($st)
        if ((Get-SIPipelineStepStage $st) -ne 'collect' -or -not (Test-SIPipelineSourceJob ([string]$st.Job))) { return }
        $k = [string]$st.Job
        $nowU = ([datetime](& $Now)).ToUniversalTime()
        $since = if ($firstStart.ContainsKey($k)) { [datetime]$firstStart[$k] } elseif ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $nowU }
        $good = $null
        if ($SourceState) {
            try {
                if ([string]$st.State -eq 'Success') { $null = $SourceState.Good($k, $since, $nowU) }
                else { $good = $SourceState.Dropped($k, $since, $nowU, [string]$st.Error) }
            } catch { & $Log 'WARN' ('step {0} {1}: the state of this source could not be recorded ({2})' -f $st.Order, $k, $_.Exception.Message) }
        }
        if ([string]$st.State -eq 'Success') { return }
        if (-not $good -and $Previous -and [string]$Previous.FlowRunId -ne [string]$state.FlowRunId) {
            $was = @(@($Previous.Steps) | Where-Object { [string]$_.Job -eq $k -and [string]$_.State -eq 'Success' -and $_.StartedUtc })[0]
            if ($was) { $good = ([datetime]$was.StartedUtc).ToUniversalTime() }
        }
        if ($good) { $st | Add-Member -NotePropertyName LastGoodUtc -NotePropertyValue ([datetime]$good).ToUniversalTime() -Force }
    }
    $saidStage = @{}
    $stageOf = @{}; foreach ($g in $groups) { foreach ($s in $g.Steps) { $stageOf[[string]$s.Job] = $g.Stage } }
    # a resumed run: a collection whose start was interrupted (it may or may not have run) is a dropped source too
    if ($decision -eq 'Resume') {
        foreach ($st in @($state.Steps | Where-Object { [string]$_.State -eq 'Interrupted' -and $_.EndedUtc -and ([datetime]$_.EndedUtc).ToUniversalTime() -eq $t0 })) {
            if (-not $st.Stage -and $stageOf.ContainsKey([string]$st.Job)) { $st.Stage = $stageOf[[string]$st.Job] }
            & $sourceEnded $st
        }
    }
    foreach ($st in @($state.Steps)) { if (-not $st.Stage -and $stageOf.ContainsKey([string]$st.Job)) { $st.Stage = $stageOf[[string]$st.Job] } }
    # delivery waits for a source that is too old: asked once, when Deliver would start
    # (dot-sourced below: it sets the two variables of this function)
    $askDeliverHold = {
        if ($DeliverHold -and -not $deliverHoldAsked -and [string]$state.Scope -ne 'step') {
            $deliverHoldAsked = $true
            try { $deliverHoldWhy = [string](& $DeliverHold) } catch { $deliverHoldWhy = ''; & $Log 'WARN' ('whether delivery must wait for a source could not be checked ({0}) -- delivery runs' -f $_.Exception.Message) }
            if ($deliverHoldWhy) { & $Log 'WARN' $deliverHoldWhy }
        }
    }
    # #754 -- A STEP STARTS AS SOON AS WHAT IT WAITS FOR HAS ENDED (Get-SIJobFlowAwaited): a step waits for every step of the
    # groups above it (the group-by-group order of before: the steps of one group start together, the next group when they
    # have all ended); a Deliver step the map marks 'startsWhenReady' waits, in a run of the whole pipeline, only for the
    # steps it reads and Collect -- so the CMDB connectors run beside Risk Analysis, the vulnerability connector starts when
    # Risk Analysis Detailed has ended. Such a step is also JUDGED only on those steps (its stage gate, what failed before
    # it, the exceptions for a step that runs on what is stored or without a nice-to-have step): a report it does not read
    # neither starts nor holds it; a report it reads that failed, was held or was skipped holds it as before.
    $isEnded = { param($x) [string]$x.State -notin @('Waiting', 'Starting', 'Running') }
    # an install's FIRST collection keeps the group-by-group order: nothing is written to the customer's systems before one
    # run is complete. Known from the run's start (the -FirstRun seam is asked then); without the seam: no run before this
    # one; with the seam not asked (a resumed run, a re-run from a step): the order of before, to be safe.
    $noEarly = $true
    if ($firstRunAsked) { $noEarly = [bool]$isFirstRun } elseif (-not $FirstRun) { $noEarly = -not $Previous }
    $readyOf = {
        param($x)
        $a = Get-SIJobFlowAwaited -State $state -Step $x -Map $Map -NoEarly:$noEarly
        if (@(@($state.Steps) | Where-Object { @($a.Jobs) -contains [string]$_.Job -and -not (& $isEnded $_) }).Count) { return $null }
        $a
    }
    # one step that may start now ($st, its awaited steps $aw). Dot-sourced: it reads and sets this function's variables;
    # $blocked and $gates are this pass's (computed once for the steps that become ready together, as for one group before)
    $startStep = {
        param($st, $aw)
        $g = [pscustomobject]@{ Stage = [string](Get-SIPipelineStepStage $st) }
        # what the step is judged on: the whole run, or (#754) Collect, the steps it waits for, and every step that has
        # already ended (a step still running that it does not read can neither start nor hold it)
        $view = $state
        if ($aw.Early) { $view = [pscustomobject]@{ FlowRunId = $state.FlowRunId; Scope = $state.Scope; Steps = @(@($state.Steps) | Where-Object { (Get-SIPipelineStepStage $_) -notin @('correlate', 'deliver') -or @($aw.Jobs) -contains [string]$_.Job -or [string]$_.Job -eq [string]$st.Job -or ([int]$_.Group -lt [int]$st.Group -and (& $isEnded $_)) }) } }
        # #306: a stage starts only when the stage before it ENDED -- and not at all when that stage did not succeed (unless
        # it is set to run anyway); Deliver never starts after a Collect of this run that did not succeed (rule 4)
        $gk = '{0}|{1}' -f $g.Stage, $(if ($aw.Early) { [string]$st.Job } else { '' })
        if (-not $gates.ContainsKey($gk)) { $gates[$gk] = Get-SIPipelineStageGate -State $view -Definition $Definition -Stage $g.Stage }
        $gate = $gates[$gk]
        if ($gate -and $gate.Reason -and -not $saidStage.ContainsKey($gk)) { $saidStage[$gk] = $true; & $Log 'WARN' $(if ($aw.Early) { 'step {0} {1}: {2}' -f $st.Order, $st.Job, $gate.Reason } else { $gate.Reason }) }
        elseif ($gate -and $gate.Run -and -not $aw.Early -and -not $saidStage.ContainsKey($gk)) { $saidStage[$gk] = $true; & $Log 'INFO' ('stage {0} starts' -f (Get-SIPipelineStageName $g.Stage)) }
        if ($aw.Early -and $gate -and $gate.Run -and -not $blocked.Stopped) {
            $still = @(@($state.Steps) | Where-Object { [int]$_.Group -lt [int]$st.Group -and -not (& $isEnded $_) } | ForEach-Object { [string]$_.Job })
            if ($still.Count) { & $Log 'INFO' ('step {0} {1}: starts now -- what it reads has ended ({2}); it does not wait for {3}' -f $st.Order, $st.Job, $(if (@($aw.Reads).Count) { @($aw.Reads) -join ', ' } else { 'Collect' }), ($still -join ', ')) }
        }
        if ($g.Stage -eq 'deliver' -and -not $blocked.Stopped -and $gate -and $gate.Run) { . $askDeliverHold }
        if ($blocked.Stopped) { $st.State = 'Skipped'; $st.ErrorClass = 'flow-stopped'; $st.Error = $blocked.StopReason; return }
        # what would hold this step: its stage does not start, or a step it needs did not succeed
        $heldClass = ''; $heldWhy = ''
        if ($gate -and -not $gate.Run) { $heldClass = 'stage-blocked'; $heldWhy = $gate.Reason }
        elseif ($blocked.Skip.ContainsKey($st.Job)) { $heldClass = 'needs-failed'; $heldWhy = ('needs {0}, which did not succeed' -f $blocked.Skip[$st.Job]) }
        # ONE FAILED STEP DOES NOT COST THE REST OF THE RUN: a step that runs on what is stored is not held when what
        # failed comes after a Collect that is good (Get-SIPipelineStoredDataRun). Every other step is held as before.
        # THE CONNECTORS NEED THE FINDINGS, NOT THE SUMMARY (owner 2026-10-13): when the only steps that failed after
        # Collect are nice-to-have ones (Risk Analysis Summary), a step the map marks for it runs IN FULL, on this run's
        # own result (Get-SIPipelineOwnResultRun). Never on an install's first collection: nothing is written to the
        # customer's systems before one run is complete.
        $own = $null
        if ($heldClass -eq 'stage-blocked' -and $GoOnAfterFailedStep -and -not $blocked.Skip.ContainsKey($st.Job)) {
            try {
                $own = Get-SIPipelineOwnResultRun -State $view -Definition $Definition -Map $Map -Job ([string]$st.Job)
                if ($own.Run) { . $askFirstRun; if ($isFirstRun) { $own = $null } }
            } catch { $own = $null }
        }
        $onOwn = [bool]($own -and $own.Run)
        $stored = $null
        if ($heldClass -and $GoOnAfterFailedStep -and -not $onOwn) {
            try {
                $stored = Get-SIPipelineStoredDataRun -State $view -Definition $Definition -Map $Map -Job ([string]$st.Job)
                # a new install's first collection: asked once, and only when a step would run on what is stored
                if ($stored.Run) { . $askFirstRun; if ($isFirstRun) { $stored = Get-SIPipelineStoredDataRun -State $view -Definition $Definition -Map $Map -Job ([string]$st.Job) -FirstRun } }
            } catch { $stored = $null }
        }
        $onStored = [bool]($stored -and $stored.Run)
        # the first collection's asset build failed: the step stays held, with the first collection's own reason
        if ($stored -and $stored.FirstHeld) { $heldWhy = [string]$stored.Reason }
        if ($heldClass -eq 'stage-blocked' -and -not $onStored -and -not $onOwn) { $st.State = 'Skipped'; $st.ErrorClass = $heldClass; $st.Error = $heldWhy; return }
        # delivery waits for a source that is too old -- also for a step that would run on what is stored, or in full
        # after a nice-to-have step failed
        if (($onStored -or $onOwn) -and $g.Stage -eq 'deliver') { . $askDeliverHold }
        if ($g.Stage -eq 'deliver' -and $deliverHoldWhy) { $st.State = 'Skipped'; $st.ErrorClass = 'source-too-old'; $st.Error = $deliverHoldWhy; return }
        if ($heldClass -eq 'needs-failed' -and -not $onStored) { $st.State = 'Skipped'; $st.ErrorClass = $heldClass; $st.Error = $heldWhy; return }
        if ($onStored) {
            # kept in the step's own record: the run's sentence, its note and its report are read from it
            $st.RetryReason = (@([string]$st.RetryReason, [string]$stored.Reason) | Where-Object { $_ }) -join ' | '
            & $Log 'WARN' ('step {0} {1}: {2}' -f $st.Order, $st.Job, $stored.Reason)
        }
        if ($onOwn) {
            $st.RetryReason = (@([string]$st.RetryReason, [string]$own.Reason) | Where-Object { $_ }) -join ' | '
            & $Log 'WARN' ('step {0} {1}: {2}' -f $st.Order, $st.Job, $own.Reason)
        }
        $st.State = 'Starting'; $st.StartedUtc = ([datetime](& $Now)).ToUniversalTime()
        if (-not $firstStart.ContainsKey([string]$st.Job)) { $firstStart[[string]$st.Job] = $st.StartedUtc }
        & $saveNow
        try {
            # a job that is already running is not started again: the step follows that execution as its own run
            $already = $null
            if ($Running) {
                try { $already = & $Running $st.Job }
                catch { $already = $null; & $Log 'INFO' ('step {0} {1}: whether its job is already running could not be checked ({2}) -- it is started' -f $st.Order, $st.Job, $_.Exception.Message) }
            }
            $st.Attempts = [int]$st.Attempts + 1
            if ($already -and [string]$already.Execution) {
                $st.Execution = [string]$already.Execution; $st.State = 'Running'
                $alreadySince = ''
                if ($already.StartedUtc) {
                    $alreadySince = ', started {0:u}' -f ([datetime]$already.StartedUtc).ToUniversalTime()
                    # what that run collects counts for this step from ITS start (the source's state)
                    $firstStart[[string]$st.Job] = ([datetime]$already.StartedUtc).ToUniversalTime()
                }
                & $Log 'INFO' ('step {0} {1}: already running ({2}{3}) -- the pipeline follows it instead of starting another' -f $st.Order, $st.Job, $st.Execution, $alreadySince)
                # the run's own note says it too (the pipeline page shows the note; its column holds 400)
                $state.Note = ('{0} {1} was already running ({2}{3}) -- the pipeline followed that run instead of starting another.' -f [string]$state.Note, $st.Job, $st.Execution, $alreadySince).Trim()
                if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
            } else {
                $exec = [string](& $Start $st.Job)
                $st.Execution = $exec; $st.State = 'Running'
                & $Log 'INFO' ('step {0} {1}: started ({2})' -f $st.Order, $st.Job, $exec)
            }
        } catch {
            $st.State = 'Failed'; $st.ErrorClass = 'start-failed'; $st.Error = [string]$_.Exception.Message; $st.EndedUtc = ([datetime](& $Now)).ToUniversalTime()
            & $Log 'WARN' ('step {0} {1}: could not start -- {2}' -f $st.Order, $st.Job, $st.Error)
            & $sourceEnded $st
        }
        & $saveNow
        if ($OnStep) { try { & $OnStep $state $st 'Start' } catch { } ; if ($st.State -eq 'Failed') { try { & $OnStep $state $st 'End' } catch { } } }
    }
    # one poll of one running step ($st). Dot-sourced: it reads and sets this function's variables.
    $pollStep = {
        param($st)
        $tNow = ([datetime](& $Now)).ToUniversalTime()
        $status = ''; $statusError = ''
        try {
            $pr = & $Poll $st.Job $st.Execution
            # #475: a Collect step in parts answers @{ Status; Error } when its collection failed (the parts named)
            if ($null -ne $pr -and $pr -isnot [string] -and $pr.PSObject.Properties['Status']) { $status = [string]$pr.Status; $statusError = [string]$pr.Error } else { $status = [string]$pr }
        } catch { & $Log 'WARN' ('step {0} {1}: its status could not be read ({2}) -- trying again' -f $st.Order, $st.Job, $_.Exception.Message) }
        $ended = $false
        switch -Regex ($status) {
            '^(?i)succeeded$' { $st.State = 'Success'; $ended = $true }
            # #700: an execution STOPPED from outside the pipeline (in Azure, by a person, by a release tool) was ended on
            # purpose -- not a platform error: it is never started again as one, and the run does not go on
            # (Get-SIJobFlowBlocked). A job stopped at its OWN run limit is still self-healed below (that is checked by the
            # time it ran, whatever Azure calls it).
            '^(?i)stopped$' {
                $st.State = 'Interrupted'; $ended = $true; $st.ErrorClass = 'stopped'
                $st.Error = if ($statusError) { $statusError } else { Get-SIJobFlowStoppedText -Job ([string]$st.Job) }
            }
            '^(?i)(failed|degraded|cancelled|canceled)$' {
                $st.State = 'Failed'; $ended = $true
                if ($statusError) { $st.ErrorClass = 'parts-failed'; $st.Error = $statusError }
                else {
                    $st.ErrorClass = 'job-failed'; $st.Error = ('the execution ended {0}' -f $status.ToLowerInvariant())
                    # the job ended at its OWN run limit (Azure stopped it, not the pipeline): say so, and what raises it
                    $jobMin = if ($jobLimits.ContainsKey([string]$st.Job)) { [int]$jobLimits[[string]$st.Job] } else { 0 }
                    $ran = if ($st.StartedUtc) { ($tNow - ([datetime]$st.StartedUtc).ToUniversalTime()).TotalMinutes } else { 0 }
                    if ($jobMin -gt 0 -and $ran -ge ($jobMin - 2)) {
                        $st.Error = ('{0} after {1} minutes -- it ran until its job''s own run limit ({2} minutes). Every update gives every step''s job the longest run limit Azure takes' -f $st.Error, [int]$ran, $jobMin)
                    }
                }
            }
        }
        # #945: the status could not be read, and a wake-up of the pipeline may have closed this step meanwhile (it read
        # that the execution had ENDED -- Get-SIJobFlowEndedExecutionCloses): the close is taken over, so the step ends here
        # by the normal rules (its dependants are judged, the run goes on or ends). Only a row of THIS execution that is no
        # longer Running; a store without the read, or a read that fails, changes nothing.
        $adoptedEnd = $null
        if (-not $ended -and -not $status -and $Store -and $Store.PSObject.Methods['StepRow']) {
            $row = $null
            try { $row = $Store.StepRow([string]$state.FlowRunId, [int]$st.Order) } catch { $row = $null }
            if ($row -and [string]$row.Execution -eq [string]$st.Execution -and [string]$row.State -in @('Success', 'Failed', 'Interrupted')) {
                $st.State = [string]$row.State; $st.ErrorClass = [string]$row.ErrorClass; $st.Error = [string]$row.Error; $ended = $true
                if ($row.EndedUtc) { $adoptedEnd = ([datetime]$row.EndedUtc).ToUniversalTime() }
                & $Log 'WARN' ('step {0} {1}: its execution {2} had ended ({3}) -- closed by the pipeline''s wake-up check; the run goes on by the normal rules' -f $st.Order, $st.Job, $st.Execution, ([string]$row.State).ToLowerInvariant())
            }
        }
        if (-not $ended) {
            $lim = & $limitOf $st
            $since = if ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $tNow }
            $sk = [string]$st.Job
            # NO GIVE-UP ON ELAPSED TIME (owner 2026-10-13): the pipeline stops no step for the time it takes. The
            # step's timeout is the time after which it SAYS so, once for this step in this run -- the step keeps
            # running. What ends a step is its own end (the job finished, failed, or Azure stopped it at the job's
            # own run limit); what watches a step that stands still is the no-progress report below.
            if (($tNow - $since).TotalMinutes -ge [int]$lim.Configured -and -not $overdueSaid.ContainsKey($sk) -and [string]$st.RetryReason -notmatch 'longer than its step timeout') {
                $overdueSaid[$sk] = $true
                $late = Get-SIJobFlowOverdueText -Job $sk -RunMinutes ([int]($tNow - $since).TotalMinutes) -TimeoutMinutes ([int]$lim.Configured)
                & $Log 'WARN' ('step {0} {1}: {2}' -f $st.Order, $sk, $late)
                $st.RetryReason = (@([string]$st.RetryReason, $late) | Where-Object { $_ }) -join ' | '
                & $saveNow
            }
            # NO SIGN OF PROGRESS: reported once for this step in this run -- the step keeps running, nothing is stopped
            if (-not $ended -and $Progress -and $SilentAfterMinutes -gt 0 -and ($tNow - $since).TotalMinutes -ge $SilentAfterMinutes -and
                -not $silentSaid.ContainsKey($sk) -and [string]$st.RetryReason -notmatch 'no sign of progress' -and
                (-not $progressAsked.ContainsKey($sk) -or ($tNow - [datetime]$progressAsked[$sk]).TotalMinutes -ge $ProgressCheckMinutes)) {
                $progressAsked[$sk] = $tNow
                $pg = $null
                try { $pg = if ($Progress -is [scriptblock]) { & $Progress $st.Job $st.Execution $since } else { $Progress.Probe($st.Job, $st.Execution, $since) } } catch { $pg = $null }
                $seen = if ($pg -and $pg.PSObject.Properties['LastSeenUtc'] -and $pg.LastSeenUtc) { ([datetime]$pg.LastSeenUtc).ToUniversalTime() } else { $null }
                if ($seen -and ($tNow - $seen).TotalMinutes -ge $SilentAfterMinutes) {
                    $silentSaid[$sk] = $true
                    $quiet = Get-SIJobFlowSilentText -Job $sk -SilentMinutes ([int]($tNow - $seen).TotalMinutes) -LastSeenUtc $seen -NoticedUtc $tNow
                    & $Log 'WARN' ('step {0} {1}: {2}' -f $st.Order, $sk, $quiet)
                    $st.RetryReason = (@([string]$st.RetryReason, $quiet) | Where-Object { $_ }) -join ' | '
                    if ($OnStep) { try { & $OnStep $state $st 'Silent' } catch { } }
                }
            }
        }
        # SELF-HEALING: the step's job (or the producer / a worker of its collection) was stopped at its OWN run limit --
        # the limit is raised by the update's sizing rule and the step is started again, ONCE in this run.
        # A stop Azure reports for a job at its own run limit is first recorded Interrupted (class 'stopped'): checked here too.
        if ($ended -and $LimitHit -and $RaiseLimit -and ($st.State -in @('Failed', 'TimedOut') -or ($st.State -eq 'Interrupted' -and [string]$st.ErrorClass -eq 'stopped'))) {
            $hit = $null
            try { $hit = & $LimitHit $st.Job $st.Execution $(if ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $tNow }) }
            catch { & $Log 'WARN' ('step {0} {1}: whether it was stopped at its run limit could not be checked ({2})' -f $st.Order, $st.Job, $_.Exception.Message) }
            if ($hit) {
                # stopped at its own run limit: a failure of the step's job (not a stop from outside)
                if ($st.State -eq 'Interrupted') { $st.State = 'Failed' }
                $was = Get-SIJobFlowHoursText -Seconds ([int]$hit.LimitSeconds)
                if ([string]$st.RetryReason -match 'was stopped at its run limit') {
                    # the one retry of this run is used: never a third start
                    $st.ErrorClass = 'timeout'
                    $st.Error = ('{0} was stopped at its run limit again ({1}), after the limit was raised and the step was started again once in this run -- it is not started a third time' -f $hit.JobName, $was)
                } else {
                    $rz = $null
                    try { $rz = & $RaiseLimit $hit } catch { $rz = [pscustomobject]@{ Restart = $false; NewSeconds = 0; Why = [string]$_.Exception.Message } }
                    if ($rz -and $rz.Restart) {
                        $healLine = ('{0} was stopped at its run limit of {1}; the limit is now {2} and the step is started again' -f $hit.JobName, $was, (Get-SIJobFlowHoursText -Seconds ([int]$rz.NewSeconds)))
                        & $Log 'WARN' ('step {0} {1}: {2}' -f $st.Order, $st.Job, $healLine)
                        $st.RetryReason = $healLine; $st.Error = $healLine; $st.ErrorClass = 'run-limit-raised'
                        if ($OnStep) { try { & $OnStep $state $st 'Heal' } catch { } }
                        $st.State = 'Starting'; $st.ErrorClass = ''; $st.Error = ''; $st.EndedUtc = $null; $st.StartedUtc = ([datetime](& $Now)).ToUniversalTime()
                        & $saveNow
                        # the job's limit changed: read again (and said again) for the second start
                        $jobLimits.Remove([string]$st.Job); $saidLimit.Remove([string]$st.Job)
                        try {
                            $st.Attempts = [int]$st.Attempts + 1
                            $st.Execution = [string](& $Start $st.Job); $st.State = 'Running'; $ended = $false
                            & $Log 'INFO' ('step {0} {1}: started again ({2}, attempt {3})' -f $st.Order, $st.Job, $st.Execution, $st.Attempts)
                        } catch {
                            $st.State = 'Failed'; $st.ErrorClass = 'start-failed'; $st.Error = [string]$_.Exception.Message; $tNow = ([datetime](& $Now)).ToUniversalTime()
                        }
                    } else {
                        $st.ErrorClass = 'timeout'
                        $st.Error = ('{0} was stopped at its run limit of {1} and is not started again: {2}' -f $hit.JobName, $was, $(if ($rz -and $rz.Why) { [string]$rz.Why } else { 'the limit could not be raised' }))
                    }
                }
            }
        }
        # Working rule 4: a container that died before the engine ran is a PLATFORM failure -- started again; a
        # failure of the engine itself never is. Classified only after the pause, so the engine's records arrive.
        if ($ended -and $StartEvidence -and $st.State -eq 'Failed' -and $st.ErrorClass -eq 'job-failed') {
            $began = if ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $tNow }
            if ($StartRetryBackoffSeconds -gt 0) { & $Sleep $StartRetryBackoffSeconds }
            $ev = $null
            try { $ev = if ($StartEvidence -is [scriptblock]) { & $StartEvidence $st.Job $st.Execution $began $tNow } else { $StartEvidence.Probe($st.Job, $st.Execution, $began, $tNow) } }
            catch { & $Log 'WARN' ('step {0} {1}: whether it started could not be checked ({2})' -f $st.Order, $st.Job, $_.Exception.Message) }
            $hasRow = if ($ev -and $ev.PSObject.Properties['HasStartRecord']) { $ev.HasStartRecord } else { $null }
            $hasLog = if ($ev -and $ev.PSObject.Properties['HasTranscript']) { $ev.HasTranscript } else { $null }
            $cls = Get-SIJobFlowFailureClass -ErrorClass $st.ErrorClass -HasStartRecord $hasRow -HasTranscript $hasLog -DurationSeconds ($tNow - $began).TotalSeconds `
                       -MaxSeconds $NeverStartedMaxSeconds -Attempts ([int]$st.Attempts) -Retries $StartRetries
            if ($cls.Class -eq 'never-started' -and $cls.Retry) {
                $failedExec = [string]$st.Execution
                $st.RetryReason = Get-SIJobFlowRetryText -Kind retried -Execution $failedExec
                & $Log 'WARN' ('step {0} {1}: {2} -- {3}' -f $st.Order, $st.Job, $st.RetryReason, $cls.Why)
                $st.State = 'Starting'; $st.ErrorClass = ''; $st.Error = ''; $st.EndedUtc = $null; $st.StartedUtc = ([datetime](& $Now)).ToUniversalTime()
                & $saveNow
                try {
                    $st.Attempts = [int]$st.Attempts + 1
                    $st.Execution = [string](& $Start $st.Job); $st.State = 'Running'; $ended = $false
                    & $Log 'INFO' ('step {0} {1}: started again ({2}, attempt {3})' -f $st.Order, $st.Job, $st.Execution, $st.Attempts)
                } catch {
                    $st.State = 'Failed'; $st.ErrorClass = 'start-failed'; $st.Error = [string]$_.Exception.Message; $tNow = ([datetime](& $Now)).ToUniversalTime()
                }
            } elseif ($cls.Class -eq 'never-started') {
                $st.ErrorClass = 'never-started'; $st.Error = Get-SIJobFlowRetryText -Kind gave-up -Attempts ([int]$st.Attempts)
            } else {
                & $Log 'INFO' ('step {0} {1}: {2}' -f $st.Order, $st.Job, $cls.Why)
                # #532 THROTTLE-IS-NORMAL: the engine ran and recorded that Microsoft only throttled it (nothing written).
                # Its END record can arrive a little after the execution ends: asked once more after the same pause.
                $endWhy = if ($ev -and $ev.PSObject.Properties['EndReason']) { $ev.EndReason } else { $null }
                if ($null -eq $endWhy -and $hasRow -eq $true -and $ev -and $ev.PSObject.Properties['EndReason']) {
                    if ($StartRetryBackoffSeconds -gt 0) { & $Sleep $StartRetryBackoffSeconds }
                    try {
                        $ev2 = if ($StartEvidence -is [scriptblock]) { & $StartEvidence $st.Job $st.Execution $began $tNow } else { $StartEvidence.Probe($st.Job, $st.Execution, $began, $tNow) }
                        if ($ev2 -and $ev2.PSObject.Properties['EndReason']) { $endWhy = $ev2.EndReason }
                    } catch { }
                }
                # the step's REAL error text is kept (2026-10-22: it was replaced by "Microsoft throttled this run", and the
                # real cause -- a storage timeout -- was gone from Operations > Jobs); the words only fill an empty one
                if ($endWhy -eq 'throttled') { $st.ErrorClass = 'throttled'; if ([string]::IsNullOrWhiteSpace([string]$st.Error)) { $st.Error = Get-SIThrottleText } }
            }
        }
        # A NEW INSTALL'S FIRST COLLECTION -- "two restarts" (owner 2026-10-13): a step that failed or was stopped is
        # started again at once (the step's own engine carries on from what it finished), up to -FirstRunRestarts
        # times; each restart is kept in the step's own record. After that the step stays failed, and the run ends
        # with the warning that names it. Never a step that writes to the customer's systems; never a step Microsoft
        # only throttled; never after the first complete collection.
        # #700 (owner 2026-10-15: "Stop is final"): never a step whose execution was STOPPED on purpose -- also not on a first
        # collection; a platform failure is still started again
        if ($ended -and $FirstRun -and $FirstRunRestarts -gt 0 -and $st.State -in @('Failed', 'TimedOut') -and [string]$st.ErrorClass -notin @('throttled', 'stopped') -and [string]$state.Scope -ne 'step') {
            $mayAgain = $false; try { $mayAgain = Test-SIPipelineFirstRunRestartStep -Step $st -Map $Map } catch { $mayAgain = $false }
            if ($mayAgain) {
                . $askFirstRun
                $doneAgain = Get-SIPipelineFirstRunRestartCount -Step $st
                if ($isFirstRun -and $doneAgain -lt $FirstRunRestarts) {
                    $againLine = Get-SIPipelineFirstRunRestartText -Job ([string]$st.Job) -Why ([string]$st.Error) -Restart ($doneAgain + 1) -Of $FirstRunRestarts
                    & $Log 'WARN' ('step {0} {1}: {2}' -f $st.Order, $st.Job, $againLine)
                    $st.RetryReason = (@([string]$st.RetryReason, $againLine) | Where-Object { $_ }) -join ' | '
                    $st.State = 'Starting'; $st.ErrorClass = ''; $st.Error = ''; $st.EndedUtc = $null; $st.StartedUtc = ([datetime](& $Now)).ToUniversalTime()
                    & $saveNow
                    try {
                        $st.Attempts = [int]$st.Attempts + 1
                        $st.Execution = [string](& $Start $st.Job); $st.State = 'Running'; $ended = $false
                        & $Log 'INFO' ('step {0} {1}: started again ({2}, attempt {3})' -f $st.Order, $st.Job, $st.Execution, $st.Attempts)
                    } catch {
                        $st.State = 'Failed'; $st.ErrorClass = 'start-failed'; $st.Error = [string]$_.Exception.Message; $tNow = ([datetime](& $Now)).ToUniversalTime()
                    }
                } elseif ($isFirstRun -and $doneAgain -gt 0) {
                    $st.Error = ('{0} -- also after {1} restart(s) on this first collection' -f [string]$st.Error, $doneAgain)
                }
            }
        }
        if ($ended) {
            $st.EndedUtc = if ($adoptedEnd -and [string]$st.State -ne 'Starting' -and [string]$st.State -ne 'Running') { $adoptedEnd } else { $tNow }
            & $Log $(if ($st.State -eq 'Success') { 'INFO' } else { 'WARN' }) ('step {0} {1}: {2}{3}' -f $st.Order, $st.Job, $st.State.ToLowerInvariant(), $(if ($st.Error) { ' -- ' + $st.Error } else { '' }))
            # #882: a step that ended without success leaves no worker running for it (its producer died or was stopped;
            # its queue workers would go on writing for a run nobody finishes)
            if ($st.State -ne 'Success') { & $stopStepWork $st }
            & $sourceEnded $st
            if ($OnStep) { try { & $OnStep $state $st 'End' } catch { } }
            # A FIRST COLLECTION, "wait for merged assets": the asset build has finished whole -> the merged assets
            # are shown at once (asked once per run; never when the web app must not show a run that is not complete)
            if ($st.State -eq 'Success' -and $FirstRun -and -not $firstDelivered -and $GoOnAfterFailedStep -and [string]$state.Scope -eq 'pipeline' -and (Test-SIPipelineAssetBuild -Job ([string]$st.Job) -Map $Map)) {
                $firstDelivered = $true
                . $askFirstRun
                $fd = $null
                if ($isFirstRun) { try { $fd = Get-SIPipelineFirstDeliveryStep -State $state -Map $Map } catch { $fd = $null } }
                if ($fd) { . $deliverFirst }
            }
        }
    }
    while ($true) {
        # #700: a run cancelled meanwhile starts no further step and is not followed any further (its executions are asked to
        # stop after the loop) -- asked before any step starts and at every poll
        . $askCancelled
        if ($cancelHit) { break }
        # the steps that may start now -- together, judged on the run as it is at this moment (as one group was before)
        $ready = New-Object System.Collections.Generic.List[object]
        foreach ($w in @(@($state.Steps) | Where-Object { [string]$_.State -eq 'Waiting' })) { $wa = & $readyOf $w; if ($wa) { $ready.Add([pscustomobject]@{ Step = $w; Awaited = $wa }) } }
        if ($ready.Count) {
            $blocked = Get-SIJobFlowBlocked -State $state -Definition $Definition -Map $Map
            $gates = @{}
            foreach ($r in $ready) { if ([string]$r.Step.State -eq 'Waiting') { . $startStep $r.Step $r.Awaited } }
            continue
        }
        # (not $running: the -Running seam is a parameter of this function)
        $runningNow = @(@($state.Steps) | Where-Object { [string]$_.State -eq 'Running' })
        if (-not $runningNow.Count) {
            $left = @(@($state.Steps) | Where-Object { [string]$_.State -eq 'Waiting' })
            if (-not $left.Count) { break }
            # nothing runs and nothing may start: never by the rules above (the first waiting step waits only for steps above
            # it) -- said, and the steps left are recorded as not reached rather than left waiting
            foreach ($x in $left) { $x.State = 'Skipped'; $x.ErrorClass = 'not-reached'; $x.Error = 'the pipeline did not reach this step: a step it waits for never ended' }
            & $Log 'WARN' ('the pipeline could not reach {0} -- a step they wait for never ended' -f (@($left | ForEach-Object { [string]$_.Job }) -join ', '))
            break
        }
        foreach ($st in $runningNow) { . $pollStep $st }
        . $longCheck
        & $saveNow
        # wait for the running steps -- unless a step may start now (#754: one that waits only for what it reads)
        if (@(@($state.Steps) | Where-Object { [string]$_.State -eq 'Running' }).Count) {
            $now2 = $false
            foreach ($w in @(@($state.Steps) | Where-Object { [string]$_.State -eq 'Waiting' })) { if (& $readyOf $w) { $now2 = $true; break } }
            if (-not $now2) { & $Sleep $PollSeconds }
        }
    }
    # #700: THE RUN WAS CANCELLED (asked once more here: a cancel can land between the last check and the end, and its
    # stopped executions would otherwise read as "stopped from outside"). Nothing more starts; what still runs is asked to
    # stop; the run ends Cancelled -- a finished state, never resumed.
    . $askCancelled
    if ($cancelHit) {
        $cut = Set-SIPipelineRunCancelled -State $state -By ([string]$cancelHit.By) -Reason ([string]$cancelHit.Reason) -NowUtc ([datetime](& $Now)).ToUniversalTime() -Stop $Stop -StopWorkers $StopWorkers
        & $saveNow
        & $Log 'WARN' $cut.Text
        $state | Add-Member -NotePropertyName Outcome -NotePropertyValue $decision -Force
        return $state
    }
    $blocked = Get-SIJobFlowBlocked -State $state -Definition $Definition -Map $Map
    $failed = @($state.Steps | Where-Object { $script:SIJobFlow.Failures -contains $_.State })
    $state.State = if ($blocked.Stopped) { 'Stopped' } elseif ($failed.Count) { 'Failed' } else { 'Succeeded' }
    $state.StopReason = $blocked.StopReason
    $state.EndedUtc = ([datetime](& $Now)).ToUniversalTime()
    # THE RUN WENT ON WITHOUT A SOURCE: said in plain words in the log and kept in the run's own note (the pipeline page
    # shows the note; the note's column holds 400). The run stays Failed -- its failed step is never shown as succeeded.
    $wentOn = ''
    try { $wentOn = Get-SIPipelineWentOnText -State $state -Definition $Definition } catch { $wentOn = '' }
    if ($wentOn) {
        & $Log 'WARN' $wentOn
        if ([string]$state.Note -notmatch 'this run went on without') {
            $state.Note = ('{0} {1}' -f [string]$state.Note, $wentOn).Trim()
            if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
        }
    }
    # A FIRST COLLECTION HAS ENDED: the "running" words leave the note (the note's column holds 400, and what follows says
    # how it ended); a first collection that ended whole says so.
    try {
        if ([string]$state.Note -match [regex]::Escape($script:SIPipelineFirstRunningMark)) {
            foreach ($fk in 'Running', 'Delivered', 'NotDelivered') {
                foreach ($fj in @(@($state.Steps | ForEach-Object { [string]$_.Job }) + 'asset-datasync' | Select-Object -Unique)) { $state.Note = ([string]$state.Note).Replace((Get-SIPipelineFirstRunText -Kind $fk -Job $fj), '') }
            }
            $state.Note = (([string]$state.Note) -replace '\s{2,}', ' ').Trim()
            if ($state.State -eq 'Succeeded') {
                $state.Note = ('{0} {1}' -f (Get-SIPipelineFirstRunText -Kind Complete), [string]$state.Note).Trim()
                if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
                & $Log 'INFO' (Get-SIPipelineFirstRunText -Kind Complete)
            }
        }
    } catch { }
    # ONE FAILED STEP DID NOT COST THE REST OF THE RUN: which step failed, which ran all the same and which were held, in
    # plain words -- in the log, and FIRST in the run's own note (the pipeline page shows the note). The run stays Failed.
    try {
        if (Test-SIPipelinePartialRun -State $state) {
            . $askFirstRun
            $isFirst = [bool]$isFirstRun
            & $Log 'WARN' (Get-SIPipelinePartialText -State $state -Definition $Definition -Map $Map -FirstRun:$isFirst)
            if ([string]$state.Note -notmatch 'not complete( yet)?: ') {
                $state.Note = ('{0} {1}' -f (Get-SIPipelinePartialText -State $state -Definition $Definition -Map $Map -FirstRun:$isFirst -Short), [string]$state.Note).Trim()
                if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
            }
        }
    } catch { & $Log 'WARN' ('what this run delivered after its failed step could not be put into words ({0})' -f $_.Exception.Message) }
    # delivery waited for a source that is too old: the run's note says so too (it was logged when Deliver would have started)
    if ($deliverHoldWhy -and [string]$state.Note -notmatch 'delivery waits:') {
        $state.Note = ('{0} {1}' -f [string]$state.Note, $deliverHoldWhy).Trim()
        if ($state.Note.Length -gt 400) { $state.Note = $state.Note.Substring(0, 400) }
    }
    & $saveNow
    & $Log $(if ($state.State -eq 'Succeeded') { 'INFO' } else { 'WARN' }) ('flow run {0}: {1} ({2})' -f $state.FlowRunId, $state.State.ToLowerInvariant(), (Get-SIJobFlowSummary -State $state))
    $state | Add-Member -NotePropertyName Outcome -NotePropertyValue $decision -Force
    $state
}

function Get-SIJobFlowSummary {
    <# PURE. "12 success, 1 failed, 2 skipped" -- the run's step outcomes in one line (run health + telemetry). #>
    param([Parameter(Mandatory)]$State)
    (@($State.Steps) | Group-Object State | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name.ToLowerInvariant() }) -join ', '
}

function Get-SIJobFlowExitReason {
    <# PURE. The run-health ExitReason of a step / the flow: success | error | skipped | disabled | timeout | interrupted. #>
    param([Parameter(Mandatory)][string]$State)
    switch ($State) {
        'Success' { 'success' } 'Succeeded' { 'success' } 'Failed' { 'error' } 'Stopped' { 'error' } 'TimedOut' { 'timeout' }
        'Interrupted' { 'interrupted' } 'Skipped' { 'skipped' } 'Disabled' { 'disabled' }
        # #700: a run cancelled on purpose (a person, the updater) is not an error and opens no fix request
        'Cancelled' { 'skipped' }
        default { $State.ToLowerInvariant() }
    }
}

function Test-SIJobFlowStepThrottled {
    <# PURE. #532: a step that failed only because Microsoft throttled its engine (State Failed, ErrorClass 'throttled'). #>
    param([AllowNull()]$Step)
    ($null -ne $Step) -and ([string]$Step.State -eq 'Failed') -and ([string]$Step.ErrorClass -eq 'throttled')
}

function Get-SIJobFlowStepExitReason {
    <# PURE. #532: a step's run-health ExitReason -- 'throttled' for a throttled step, else Get-SIJobFlowExitReason. #>
    param([Parameter(Mandatory)]$Step)
    if (Test-SIJobFlowStepThrottled $Step) { return 'throttled' }
    Get-SIJobFlowExitReason ([string]$Step.State)
}

function Test-SIJobFlowThrottledOnly {
    <# PURE. #532: the run did not succeed, and EVERY step that failed (Failed / TimedOut / Interrupted) failed only because
       Microsoft throttled it. A timeout of the step itself, an interruption or any other failure is a real failure. #>
    param([Parameter(Mandatory)]$State)
    if ([string]$State.State -notin @('Failed', 'Stopped')) { return $false }
    $bad = @(@($State.Steps) | Where-Object { $script:SIJobFlow.Failures -contains [string]$_.State })
    if ($bad.Count -eq 0) { return $false }
    foreach ($s in $bad) { if (-not (Test-SIJobFlowStepThrottled $s)) { return $false } }
    $true
}

function Get-SIJobFlowRunExitReason {
    <# PURE. #532: the flow run's run-health ExitReason -- 'throttled' when its only failures were throttled steps (no
       failure mail, Outcome warning, exit 0), else Get-SIJobFlowExitReason of the run's state. #>
    param([Parameter(Mandatory)]$State)
    if (Test-SIJobFlowThrottledOnly -State $State) { return 'throttled' }
    # a run whose only failures are steps stopped from outside / cancelled on purpose: 'interrupted' -- not an error of
    # the product, never reported as a failure (no fix request), the step's own record says it was stopped
    if (Test-SIJobFlowStoppedOnly -State $State) { return 'interrupted' }
    # one failed step did not cost the rest of the run: every step that ran all the same (on what is stored, or in full
    # after a nice-to-have step failed) succeeded, so the run's own record is a WARNING ('success-partial') that NAMES THE
    # FAILED STEP -- never 'success', never an error that stops, never silent. THE WARNING OPENS A FIX REQUEST (owner
    # 2026-10-13: "Warning that opens a fix request"): the report to Invardia carries Outcome warning + FailedStep (the step
    # the run went on after) + that step's own error class and FixKind (SI-TelemetrySend.ps1), and Invardia treats a warning
    # that names a failed step as a fix request. A run that was stopped, or in which such a step failed too, stays 'error'.
    if ([string]$State.State -eq 'Failed' -and (Test-SIPipelineWentOn -State $State -AllSucceeded)) { return 'success-partial' }
    Get-SIJobFlowExitReason ([string]$State.State)
}

# =====================================================================================================================
#  Adapters -- ARM (container), local processes (VM), run-record stores
# =====================================================================================================================
function New-SIJobFlowSeams {
    <#
        An adapter object whose METHODS are the runner's seams (Start / Poll / Stop, and List where it can). Methods, not
        closures: a GetNewClosure() scriptblock runs in its own module scope and cannot see the functions a script
        dot-sourced (measured: "Get-SIJobFlowJobName is not recognized"). -Fields become note properties ($this.<name>).
    #>
    param([Parameter(Mandatory)][hashtable]$Fields, [Parameter(Mandatory)][hashtable]$Methods)
    $o = New-Object psobject
    foreach ($k in $Fields.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $Fields[$k] }
    foreach ($k in $Methods.Keys) { $o | Add-Member -MemberType ScriptMethod -Name $k -Value $Methods[$k] }
    $o
}

function Test-SIJobFlowStopAlreadyEnded {
    <# PURE. Is this the answer ARM gives to a stop of an execution that has already ended (live 2026-10-23: 400 "job
       execution ... not found" when the runner stopped executions that had finished)? Then the execution is already
       stopped: not a failure of the stop. Anything else (no access, the job itself missing, a throttle) is a failure. #>
    param([AllowEmptyString()][AllowNull()][string]$Message)
    [bool]("$Message" -match '(?is)\bexecution\b.{0,300}\bnot\s+found\b|ExecutionNotFound|JobExecutionNotFound')
}

function New-SIJobFlowArmSeams {
    <#
        Start / Poll / Stop / List over Azure Resource Manager (Container Apps jobs), as the job's own identity
        (Invoke-SIArm: managed identity in a container, else the SPN). -Arm is the call seam (tests): { param($Method, $Path, $Body) }.
        Needs 'Container Apps Jobs Contributor' on the jobs' resource group (Bootstrap grants it with -GrantIdentityRoles).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [scriptblock]$Arm, [string]$ApiVersion = $script:SIJobFlow.ArmApi)
    if (-not $Arm) { $Arm = { param($Method, $Path, $Body) Invoke-SIArm -Method $Method -Path $Path -ApiVersion $script:SIJobFlow.ArmApi -Body $Body } }
    New-SIJobFlowSeams -Fields @{ Arm = $Arm; Base = ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup) } -Methods @{
        Start = { param($Job) $r = & $this.Arm 'POST' ('{0}/{1}/start' -f $this.Base, (Get-SIJobFlowJobName $Job)) @{}
                  $n = [string]$r.name; if (-not $n -and $r.id) { $n = ([string]$r.id -split '/')[-1] }
                  if (-not $n) { throw 'the start returned no execution name' }; $n }
        # #945: when the read of the one execution fails or says nothing, its status is taken from the job's execution LIST
        # (live 2026-10-28, a customer install: the step's execution ended Failed and the runner kept "trying again" for days). Neither
        # answers = the first error is thrown (the runner tries again at its next poll, as before).
        Poll  = { param($Job, $Execution)
                  $first = $null; $st = ''
                  try { $r = & $this.Arm 'GET' ('{0}/{1}/executions/{2}' -f $this.Base, (Get-SIJobFlowJobName $Job), $Execution) $null; if ($r -and $r.PSObject.Properties['properties'] -and $r.properties) { $st = [string]$r.properties.status } }
                  catch { $first = $_ }
                  if ($st) { return $st }
                  $list = $null
                  try { $list = $this.Executions($Job) } catch { if ($first) { throw $first }; throw }
                  $st = Get-SIJobFlowExecutionStatusOf -Executions @($list) -Execution ([string]$Execution)
                  if ($st) { return $st }
                  if ($first) { throw $first }
                  '' }
        # #945: the job's executions, every page (at most 5; Azure lists the newest first)
        Executions = { param($Job)
                  $all = New-Object System.Collections.Generic.List[object]; $path = '{0}/{1}/executions' -f $this.Base, (Get-SIJobFlowJobName $Job); $pg = 0
                  while ($path -and $pg -lt 5) {
                      $r = & $this.Arm 'GET' $path $null; $pg++
                      foreach ($v in @($r.value)) { if ($v) { $all.Add($v) } }
                      $path = if ($r -and $r.PSObject.Properties['nextLink'] -and $r.nextLink) { [string]$r.nextLink } else { $null }
                  }
                  $all.ToArray() }
        # an execution that already ended answers 400 "job execution ... not found": it is already stopped, not a failure
        Stop  = { param($Job, $Execution) try { $null = & $this.Arm 'POST' ('{0}/{1}/stop/{2}' -f $this.Base, (Get-SIJobFlowJobName $Job), $Execution) @{} } catch { if (-not (Test-SIJobFlowStopAlreadyEnded -Message ([string]$_.Exception.Message))) { throw } } }
        # the job's own run limit (its replica timeout) in seconds / in whole minutes; 0 when the job does not say
        LimitSeconds = { param($Job) $r = & $this.Arm 'GET' ('{0}/{1}' -f $this.Base, (Get-SIJobFlowJobName $Job)) $null
                  $sec = 0; $cfg = if ($r -and $r.PSObject.Properties['properties'] -and $r.properties -and $r.properties.PSObject.Properties['configuration']) { $r.properties.configuration } else { $null }
                  if ($cfg -and $cfg.PSObject.Properties['replicaTimeout']) { [void][int]::TryParse("$($cfg.replicaTimeout)", [ref]$sec) }
                  [int]$sec }
        Limit = { param($Job) [int][Math]::Floor([int]$this.LimitSeconds($Job) / 60) }
        # SELF-HEALING: did an execution of this job end AT THE JOB'S OWN RUN LIMIT (Azure stopped it)? -Execution: that one
        # execution; '' = any execution of the job that started at or after -SinceUtc (the workers of a collection in parts).
        # @{ JobName; LimitSeconds; Execution } or $null.
        LimitHit = { param($Job, $Execution, $SinceUtc)
                  $lim = [int]$this.LimitSeconds($Job); if ($lim -le 0) { return $null }
                  $name = Get-SIJobFlowJobName $Job
                  $list = if ($Execution) { @(& $this.Arm 'GET' ('{0}/{1}/executions/{2}' -f $this.Base, $name, $Execution) $null) }
                          else { $r = & $this.Arm 'GET' ('{0}/{1}/executions' -f $this.Base, $name) $null; @($r.value) }
                  foreach ($e in @($list)) {
                      if (Test-SIJobFlowExecutionAtLimit -Execution $e -LimitSeconds $lim -SinceUtc $(if ($Execution) { $null } else { $SinceUtc })) {
                          return [pscustomobject]@{ JobName = $name; LimitSeconds = $lim; Execution = [string]$e.name }
                      }
                  }
                  $null }
        # an execution of this job that is running NOW (somebody else started it): @{ Execution; StartedUtc } or $null
        Running = { param($Job) $r = & $this.Arm 'GET' ('{0}/{1}/executions' -f $this.Base, (Get-SIJobFlowJobName $Job)) $null
                  Select-SIJobFlowRunningExecution -Executions @($r.value) }
        # EVERY page: Azure lists 20 jobs a page. Reading only the first one left a job on page 2 out of the default pipeline
        # (internal 2026-10-20: 26 jobs, caj-si-verification on page 2 -- no verification step, every run refused at publish,
        # the data health check never ran). -Arm takes a nextLink as its path (Invoke-SIArm: a full URL, api-version kept).
        List  = { $names = New-Object System.Collections.Generic.List[string]; $path = $this.Base; $seen = 0
                  while ($path -and $seen -lt 50) {
                      $r = & $this.Arm 'GET' $path $null; $seen++
                      foreach ($v in @($r.value)) { if ($v) { $names.Add([string]$v.name) } }
                      $path = if ($r -and $r.PSObject.Properties['nextLink'] -and $r.nextLink) { [string]$r.nextLink } else { $null }
                  }
                  $names.ToArray() }
    }
}

function Add-SIJobFlowCollectParts {
    <#
        #475 -- KEDA for the Collect stage. Wraps a container's Start / Poll / Stop seams: for an engine whose PRODUCER job
        exists (caj-si-<engine>-producer), the step starts the producer; once the producer has succeeded, the step follows
        the run's MANIFEST (SI-CollectParts.ps1: run id = the producer's execution name) until every part is marked --
        succeeded / failed (the parts named) / incomplete after -TimeoutMinutes plus the worker job's own run limit (so a
        part whose worker is still running is never called incomplete). Every other job is unchanged.
        Poll answers a word (Running / Succeeded / Failed) or, for a finished collection that failed, @{ Status; Error }.
        -Store: the collect state store (New-SICollectBlobStore); -ProducerJobs: test seam (the job names), else List().
    #>
    param([Parameter(Mandatory)]$Seams, [Parameter(Mandatory)]$Store, [int]$TimeoutMinutes = 180, [string[]]$ProducerJobs, [scriptblock]$Now)
    if (-not (Get-Command -Name Get-SICollectProgress -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-CollectParts.ps1') }
    if (-not $Now) { $Now = { [datetime]::UtcNow } }
    $names = if ($PSBoundParameters.ContainsKey('ProducerJobs')) { @($ProducerJobs) } else { @($Seams.List()) }
    $keda = @{}
    foreach ($n in $names) { if ([string]$n -match '^caj-si-(.+)-producer$') { $keda[$Matches[1]] = $true } }
    # Progress (#576): { param($Key, $Execution, $Done, $Total) } -- the parts done of all, at every poll of a running
    # collection (the caller sets it: the runner writes the step's progress record); $null = nothing written
    New-SIJobFlowSeams -Fields @{ Inner = $Seams; Store = $Store; Keda = $keda; Timeout = $TimeoutMinutes; NowFn = $Now; Waits = @{}; Progress = $null } -Methods @{
        IsParts = { param($Job) $this.Keda.ContainsKey((Get-SIJobFlowKey $Job)) }
        # NOT A WAIT ANY MORE (2026-10-13: the parts are waited for until they are done -- Poll). Only what the step's own
        # run limit is said to be: -TimeoutMinutes (the parts' start and queueing) plus the worker job's own run limit.
        PartsWait = { param($Key)
            if (-not $this.Waits.ContainsKey($Key)) {
                $w = 0
                if ($this.Inner.PSObject.Methods['Limit']) { try { $w = [int]$this.Inner.Limit($Key + '-worker') } catch { return [int]$this.Timeout } }
                $this.Waits[$Key] = [int]$this.Timeout + $w
            }
            [int]$this.Waits[$Key] }
        # the step's own run limit: the producer's, then the wait for the parts
        Limit = { param($Job)
            if (-not $this.Inner.PSObject.Methods['Limit']) { return 0 }
            if (-not $this.IsParts($Job)) { return [int]$this.Inner.Limit($Job) }
            $k = Get-SIJobFlowKey $Job
            [int]$this.Inner.Limit($k + '-producer') + [int]$this.PartsWait($k) }
        # SELF-HEALING: which job of the step was stopped at its own run limit -- the producer (this execution), else a
        # worker that started since the step did; every other job: the job itself
        LimitHit = { param($Job, $Execution, $SinceUtc)
            if (-not $this.Inner.PSObject.Methods['LimitHit']) { return $null }
            if (-not $this.IsParts($Job)) { return $this.Inner.LimitHit($Job, $Execution, $SinceUtc) }
            $k = Get-SIJobFlowKey $Job
            $h = $this.Inner.LimitHit($k + '-producer', $Execution, $SinceUtc)
            if ($h) { return $h }
            # the wait for the parts follows the worker's limit: read again after a raise
            $this.Waits.Remove($k)
            $this.Inner.LimitHit($k + '-worker', '', $SinceUtc) }
        # a collection in parts that is already running: its PRODUCER is followed like any other job (the step then follows
        # that run's parts by the producer's execution name, as Poll does). The workers are never asked about: several
        # of them running at once is how a collection in parts works.
        Running = { param($Job)
            if (-not $this.Inner.PSObject.Methods['Running']) { return $null }
            if ($this.IsParts($Job)) { $this.Inner.Running((Get-SIJobFlowKey $Job) + '-producer') } else { $this.Inner.Running($Job) } }
        Start = { param($Job) if ($this.IsParts($Job)) { $this.Inner.Start((Get-SIJobFlowKey $Job) + '-producer') } else { $this.Inner.Start($Job) } }
        Stop  = { param($Job, $Execution) if ($this.IsParts($Job)) { $this.Inner.Stop((Get-SIJobFlowKey $Job) + '-producer', $Execution) } else { $this.Inner.Stop($Job, $Execution) } }
        List  = { $this.Inner.List() }
        Poll  = {
            param($Job, $Execution)
            if (-not $this.IsParts($Job)) { return $this.Inner.Poll($Job, $Execution) }
            $k = Get-SIJobFlowKey $Job
            $st = [string]$this.Inner.Poll($k + '-producer', $Execution)
            if ($st -notmatch '^(?i)succeeded$') { return $st }          # the producer is still discovering, or it failed
            $m = Read-SICollectManifest -Store $this.Store -Engine $k -RunId $Execution
            # a run whose records are handed over ends only when the last worker has published them (its records marker)
            $rm = $null
            if ($m -and $m.PSObject.Properties['RecordsHandover'] -and [bool]$m.RecordsHandover) { $rm = Read-SICollectRecordsMarker -Store $this.Store -Engine $k -RunId $Execution }
            # -TimeoutMinutes 0: NO GIVE-UP ON ELAPSED TIME (owner 2026-10-13). The collection is waited for until every part
            # has its marker and the records are published. That ends by itself: a worker that dies gives its part back
            # within one short lease (WorkerQueue.ps1), and a part handed out more than 5 times is parked with a FAILED
            # marker, which ends the step with the part named.
            $p = Get-SICollectProgress -Manifest $m -Markers @(Read-SICollectPartMarkers -Store $this.Store -Engine $k -RunId $Execution) -Now (& $this.NowFn) -TimeoutMinutes 0 -Records $rm
            switch ($p.State) {
                'succeeded' { return 'Succeeded' }
                'failed' { return [pscustomobject]@{ Status = 'Failed'; Error = $p.Text } }
                'incomplete' { return [pscustomobject]@{ Status = 'Failed'; Error = $p.Text } }
                'waiting' {
                    # the producer ended without a manifest: nothing will ever mark the parts
                    return [pscustomobject]@{ Status = 'Failed'; Error = 'the producer ended without writing the list of parts -- the collection did not start' }
                }
                default {
                    if ($this.Progress) { try { $null = & $this.Progress $k ([string]$Execution) ([long]$p.Done) ([long]$p.Parts) } catch { } }
                    return 'Running'
                }
            }
        }
    }
}

function Get-SIJobFlowVmCommand {
    <#
        PURE. The command line a VM flow step runs: the step's launcher (-Flavour community-vm | internal-vm; the
        internal launcher when only that one exists), Risk Analysis with -Summary / -Detailed, the updater as
        Update-SecurityInsight.ps1 -Apply. $null for a job that has no VM launcher (a Pro container job).
        Returns @{ File; Arguments }.
    #>
    param([Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][string]$Root, [string]$Flavour = 'community-vm')
    $k = Get-SIJobFlowKey $Job
    if ($k -eq 'updater') { return [pscustomobject]@{ File = (Join-Path $Root 'Update-SecurityInsight.ps1'); Arguments = @('-Apply') } }
    $folder = switch ($k) { 'ptc' { 'privilege-tier-classifier' } 'risk-analysis-detailed' { 'risk-analysis' } default { $k } }
    $extra = switch ($k) { 'risk-analysis' { @('-Summary') } 'risk-analysis-detailed' { @('-Detailed') } default { @() } }
    $dir = Join-Path (Join-Path $Root 'launcher') $folder
    foreach ($f in @($Flavour, 'community-vm', 'internal-vm') | Select-Object -Unique) {
        $p = Join-Path $dir ('launcher.{0}.ps1' -f $f)
        if (Test-Path -LiteralPath $p) { return [pscustomobject]@{ File = $p; Arguments = @($extra) } }
    }
    $null
}

function Get-SIJobFlowVmInstalled {
    <# The flow keys that have a VM launcher under -Root (the VM's "installed jobs"; the updater when its script exists). #>
    param([Parameter(Mandatory)][string]$Root, [string]$Flavour = 'community-vm', $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    @($Map.DefaultFlow | Where-Object { Get-SIJobFlowVmCommand -Job $_ -Root $Root -Flavour $Flavour } | Where-Object { $_ -ne 'updater' -or (Test-Path -LiteralPath (Join-Path $Root 'Update-SecurityInsight.ps1')) })
}

function New-SIJobFlowVmSeams {
    <#
        Start / Poll / Stop on a VM: each step is its launcher in its own PowerShell process (as the per-engine scheduled
        tasks ran them). The execution name is "<pid>@<process start time>", so a resumed runner can tell its own process
        from a recycled process id. -Exe: powershell.exe (5.1, the launchers' runtime) by default.
    #>
    param([Parameter(Mandatory)][string]$Root, [string]$Flavour = 'community-vm', [string]$Exe = 'powershell.exe')
    New-SIJobFlowSeams -Fields @{ Root = $Root; Flavour = $Flavour; Exe = $Exe; Procs = @{} } -Methods @{
        Start = {
            param($Job)
            $c = Get-SIJobFlowVmCommand -Job $Job -Root $this.Root -Flavour $this.Flavour
            if (-not $c) { throw ("{0} has no VM launcher (it runs as a container job only)" -f $Job) }
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $c.File)) + @($c.Arguments)
            $p = Start-Process -FilePath $this.Exe -ArgumentList $argList -WorkingDirectory $this.Root -PassThru -WindowStyle Hidden
            $name = '{0}@{1}' -f $p.Id, $p.StartTime.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            $this.Procs[$name] = $p
            $name
        }
        Poll = {
            param($Job, $Execution)
            # the process object this runner started holds its exit code; a resumed runner only has the id
            $p = $this.Procs[[string]$Execution]
            if (-not $p) {
                $id, $started = ([string]$Execution) -split '@', 2
                $q = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue
                if ($q -and $q.StartTime.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) -eq $started) { return 'Running' }
                throw ("the process of {0} ({1}) is no longer there and this runner did not start it -- its outcome is unknown" -f $Job, $Execution)
            }
            if (-not $p.HasExited) { return 'Running' }
            if ($p.ExitCode -eq 0) { 'Succeeded' } else { 'Failed' }
        }
        Stop = { param($Job, $Execution) $id = ([string]$Execution -split '@', 2)[0]; Stop-Process -Id ([int]$id) -Force -ErrorAction SilentlyContinue }
    }
}

function Copy-SIJobFlowCancelled {
    <#
        PURE. #700: a run record that is CANCELLED in the store stays cancelled -- a runner that is still alive and saves its
        own (older) copy never turns it back to Running / Stopped. -Stored: what the store holds now; -State: what is about
        to be saved (changed in place: State, StopReason, EndedUtc, CancelledBy of the stored record). $true when it was.
    #>
    param($Stored, [Parameter(Mandatory)]$State)
    if (-not $Stored -or [string]$Stored.State -ne 'Cancelled' -or [string]$Stored.FlowRunId -ne [string]$State.FlowRunId) { return $false }
    if ([string]$State.State -eq 'Cancelled') { return $false }
    $State.State = 'Cancelled'; $State.StopReason = [string]$Stored.StopReason; $State.EndedUtc = $Stored.EndedUtc
    $by = if ($Stored.PSObject.Properties['CancelledBy']) { [string]$Stored.CancelledBy } else { '' }
    if ($State.PSObject.Properties['CancelledBy']) { $State.CancelledBy = $by } else { $State | Add-Member -NotePropertyName CancelledBy -NotePropertyValue $by }
    $true
}

function Get-SIJobFlowCancelledOf {
    <# PURE. #700: @{ By; Reason } when -Stored is run -FlowRunId and it is CANCELLED, else $null (the runner's -Cancelled seam). #>
    param($Stored, [string]$FlowRunId)
    if (-not $Stored -or [string]$Stored.State -ne 'Cancelled') { return $null }
    if ($FlowRunId -and [string]$Stored.FlowRunId -ne $FlowRunId) { return $null }
    [pscustomobject]@{ By = $(if ($Stored.PSObject.Properties['CancelledBy']) { [string]$Stored.CancelledBy } else { '' }); Reason = [string]$Stored.StopReason }
}

function Resolve-SIJobFlowRunFinal {
    <#
        PURE (live 2026-10-19, ring 2). A run CANCELLED once is final. A run record that names who cancelled it
        (CancelledBy) but is not in a finished state was written back to Running after the cancel by a runner that never
        saw it (older code; a container that outlived its stop -- it kept starting the step again). It is returned as
        Cancelled with Revived = $true: never resumed, never "still beating", and Close-SIJobFlowCancelledRun closes it.
        Any other record is returned as it is (Revived = $false).
    #>
    param($State)
    if (-not $State) { return $State }
    $by = if ($State.PSObject.Properties['CancelledBy']) { [string]$State.CancelledBy } else { '' }
    $revived = ("$by".Trim() -and [string]$State.State -notin $script:SIJobFlow.RunFinished)
    if ($revived) { $State.State = 'Cancelled' }
    $State | Add-Member -NotePropertyName Revived -NotePropertyValue ([bool]$revived) -Force
    $State
}

function Close-SIJobFlowCancelledRun {
    <#
        Live 2026-10-19 (ring 2): A CANCELLED RUN IS FINAL, also when a runner that never saw the cancel is still alive. The
        web app's cancel (cfg.FlowRunCancelSet) marks the run and frees the lock; the run's own runner stops its running
        step when it sees the cancel. A runner of older code never asks -- at customer F one whose container outlived its
        stop kept starting the step again and wrote the run back to Running. The runner that holds the lock now closes
        such a run on every wake-up while it is the last run:
          - a step still Starting / Running: its execution is stopped (never started again) and the step is closed
            Interrupted, class 'cancelled' (as the cancel itself closes it);
          - with -Running: an execution of a step's job that is running NOW and started after the cancel (or, for a run
            written back to Running, after the run started) is stopped too -- the runner that started it is not this run's;
          - a run written back to Running (Revived, Resolve-SIJobFlowRunFinal) is ended Cancelled again (its end now, the
            stop reason kept or said).
        -Stop { param($Job, $Execution) }, -Running { param($Job) } -> @{ Execution; StartedUtc } or $null, -Save { param($s) }.
        #882: -StopWorkers { param($Job, $SinceUtc, $Execution) } -- a step closed here, or whose job was found running again,
        has its workers stopped too (their runs closed first).
        Returns @{ Changed; Revived; Stopped (job execution); StopFailed (job: why) }; nothing changed = nothing saved.
    #>
    param([Parameter(Mandatory)]$State, [scriptblock]$Stop, [scriptblock]$Running, [scriptblock]$Save, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$Log = { param($Level, $Message) }, [scriptblock]$StopWorkers)
    $now = $NowUtc.ToUniversalTime()
    $revived = [bool]($State.PSObject.Properties['Revived'] -and $State.Revived)
    $res = [pscustomobject]@{ Changed = $false; Revived = $revived; Stopped = @(); StopFailed = @() }
    if ([string]$State.State -ne 'Cancelled') { return $res }
    $by = if ($State.PSObject.Properties['CancelledBy']) { [string]$State.CancelledBy } else { '' }
    $why = if ("$by".Trim()) { 'cancelled by {0}' -f $by } else { 'cancelled' }
    $since = if (-not $revived -and $State.EndedUtc) { ([datetime]$State.EndedUtc).ToUniversalTime() } elseif ($State.StartedUtc) { ([datetime]$State.StartedUtc).ToUniversalTime() } else { $null }
    $stopped = New-Object System.Collections.Generic.List[string]
    $failed = New-Object System.Collections.Generic.List[string]
    $stopOne = {
        param($Job, $Execution)
        $key = '{0} {1}' -f $Job, $Execution
        if ($stopped -contains $key) { return }
        if (-not $Stop) { $failed.Add(('{0}: nothing can stop it here' -f $Job)); return }
        try { $null = & $Stop $Job $Execution; $stopped.Add($key) } catch { $failed.Add(('{0}: {1}' -f $Job, $_.Exception.Message)) }
    }
    foreach ($st in @($State.Steps)) {
        if ($null -eq $st) { continue }
        $job = [string]$st.Job
        $workersOf = {
            if (-not $StopWorkers) { return }
            $ws = if ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $since }
            try { $null = & $StopWorkers $job $ws ([string]$st.Execution) } catch { $failed.Add(('{0} (its workers): {1}' -f $job, $_.Exception.Message)) }
        }
        if ([string]$st.State -in @('Starting', 'Running')) {
            if ([string]$st.Execution) { & $stopOne $job ([string]$st.Execution) }
            . $workersOf
            $st.State = 'Interrupted'; $st.ErrorClass = 'cancelled'; $st.EndedUtc = $now
            $st.Error = ('stopped: the run was {0} -- a cancelled run is final, the step is not started again' -f $why)
            if (([string]$st.Error).Length -gt 1000) { $st.Error = ([string]$st.Error).Substring(0, 1000) }
            $res.Changed = $true
        } elseif ([string]$st.State -eq 'Waiting') {
            $st.State = 'Skipped'; $st.ErrorClass = 'cancelled'; $st.Error = ('not run: the run was {0}' -f $why)
            $res.Changed = $true
        }
        # a step that had started (not one that never ran) may have been started again by a runner that did not see the cancel
        if ($Running -and [string]$st.State -notin @('Waiting', 'Skipped', 'Disabled', 'Success')) {
            $live = $null
            try { $live = & $Running $job } catch { $live = $null }
            if ($live -and [string]$live.Execution -and ((-not $since) -or (-not $live.StartedUtc) -or ([datetime]$live.StartedUtc).ToUniversalTime() -ge $since)) {
                & $stopOne $job ([string]$live.Execution)
                if ($StopWorkers) { try { $null = & $StopWorkers $job $(if ($live.StartedUtc) { ([datetime]$live.StartedUtc).ToUniversalTime() } else { $since }) ([string]$live.Execution) } catch { $failed.Add(('{0} (its workers): {1}' -f $job, $_.Exception.Message)) } }
            }
        }
    }
    if ($revived) {
        $State.EndedUtc = $now
        $note = 'ended again: a runner that did not see the cancel wrote the run back to Running'
        $State.StopReason = $(if ("$($State.StopReason)".Trim()) { '{0}; {1}' -f $State.StopReason, $note } else { 'the run was {0}; {1}' -f $why, $note })
        if (([string]$State.StopReason).Length -gt 1000) { $State.StopReason = ([string]$State.StopReason).Substring(0, 1000) }
        $res.Changed = $true
    }
    $res.Stopped = $stopped.ToArray(); $res.StopFailed = $failed.ToArray()
    if ($stopped.Count) { $res.Changed = $true }
    if ($res.Changed) {
        if ($Save) { & $Save $State }
        & $Log 'WARN' ('cancelled run {0} closed: {1} execution(s) asked to stop{2}{3} -- a cancelled run is final' -f $State.FlowRunId, $stopped.Count, $(if ($stopped.Count) { (' ({0})' -f ($stopped -join ', ')) } else { '' }), $(if ($failed.Count) { ('; could not be stopped: {0}' -f ($failed -join '; ')) } else { '' }))
    }
    $res
}

function Get-SIJobFlowEndedStepStops {
    <#
        PURE. #882 -- what the runner stops for the started step rows of ENDED runs it is about to close (EndedRunOpenSteps):
        the execution recorded on the row, and the step's workers -- never what the run going on NOW uses: an execution a
        step of the live run follows (a run can follow a job that was already running), or the workers of a job the live
        run has Starting / Running. -Rows: @(@{ Job; Execution; StartedUtc }); -Live: the last run record when it has not
        ended ($null = none). Returns @(@{ Job; Execution ('' = none to stop); Workers (bool); SinceUtc; Why }), one per row.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), $Live = $null)
    $liveExec = @{}; $liveJobs = @{}
    if ($Live) {
        foreach ($s in @($Live.Steps)) {
            if ($null -eq $s) { continue }
            if ([string]$s.Execution) { $liveExec[([string]$s.Execution).ToLowerInvariant()] = $true }
            if ([string]$s.State -in @('Starting', 'Running')) { $liveJobs[(Get-SIJobFlowKey ([string]$s.Job))] = $true }
        }
    }
    @(foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = Get-SIJobFlowKey ([string]$r.Job)
        $ex = ([string]$r.Execution).Trim()
        $why = ''
        if ($ex -and $liveExec.ContainsKey($ex.ToLowerInvariant())) { $why = 'the run going on now follows this execution'; $ex = '' }
        $wk = -not $liveJobs.ContainsKey($k)
        if (-not $wk -and -not $why) { $why = 'the run going on now runs this job -- its workers are left to it' }
        [pscustomobject]@{ Job = $k; Execution = $ex; Workers = [bool]$wk; SinceUtc = $r.StartedUtc; Why = $why }
    })
}

function New-SIJobFlowFileStore {
    <# The run record as a JSON file (VM: <install>\data\flow\flow-run.json). Methods Load() / Save($State) / Cancelled($FlowRunId). #>
    param([Parameter(Mandatory)][string]$Path)
    New-SIJobFlowSeams -Fields @{ Path = $Path } -Methods @{
        Load = { if (Test-Path -LiteralPath $this.Path) { ConvertFrom-SIJobFlowRunJson -Json ([IO.File]::ReadAllText($this.Path)) } else { $null } }
        Cancelled = { param($FlowRunId) $s = $null; try { $s = $this.Load() } catch { $s = $null }; Get-SIJobFlowCancelledOf -Stored $s -FlowRunId $FlowRunId }
        # #945: the wake-up check's close of one step (only while it is Running with that execution, in a run not ended)
        CloseOpenStep = { param($FlowRunId, $Close) $s = $this.Load(); if (Set-SIJobFlowStepClosed -State $s -FlowRunId $FlowRunId -Close $Close) { $this.Save($s); 1 } else { 0 } }
        StepRow = { param($FlowRunId, $Order) Get-SIJobFlowStepRowOf -State $this.Load() -FlowRunId $FlowRunId -Order $Order }
        Save = {
            param($State)
            # #700: a run cancelled in the file stays cancelled (a live runner's later save does not undo it)
            $old = $null; try { $old = $this.Load() } catch { $old = $null }
            if ([string]$State.State -ne 'Cancelled') { $null = Copy-SIJobFlowCancelled -Stored $old -State $State }
            $dir = Split-Path -Parent $this.Path
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $tmp = $this.Path + '.tmp'
            # #945: a step the wake-up check closed is never written back to Running with the same execution
            [IO.File]::WriteAllText($tmp, (Get-SIJobFlowSaveJson -State $State -Stored $old), (New-Object System.Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $tmp -Destination $this.Path -Force
        }
    }
}

function New-SIJobFlowBlobStore {
    <# The run record as a blob (a Community container: <account>/sistate/flow/flow-run.json, OAuth as the job). #>
    param([Parameter(Mandatory)][string]$Account, [string]$Container = 'sistate', [string]$Blob = 'flow/flow-run.json')
    New-SIJobFlowSeams -Fields @{ Account = $Account; Container = $Container; Blob = $Blob } -Methods @{
        Load = {
            try {
                $bytes = Get-SIBlobContent -Account $this.Account -Container $this.Container -Blob $this.Blob
                if (-not $bytes -or $bytes.Length -eq 0) { return $null }
                ConvertFrom-SIJobFlowRunJson -Json ([Text.Encoding]::UTF8.GetString($bytes))
            } catch { if ("$($_.Exception.Message)" -match '404|BlobNotFound|ContainerNotFound|not found') { $null } else { throw } }
        }
        Cancelled = { param($FlowRunId) $s = $null; try { $s = $this.Load() } catch { $s = $null }; Get-SIJobFlowCancelledOf -Stored $s -FlowRunId $FlowRunId }
        # #945: the wake-up check's close of one step (only while it is Running with that execution, in a run not ended)
        CloseOpenStep = { param($FlowRunId, $Close) $s = $this.Load(); if (Set-SIJobFlowStepClosed -State $s -FlowRunId $FlowRunId -Close $Close) { $this.Save($s); 1 } else { 0 } }
        StepRow = { param($FlowRunId, $Order) Get-SIJobFlowStepRowOf -State $this.Load() -FlowRunId $FlowRunId -Order $Order }
        Save = {
            param($State)
            # #700: a run cancelled in the blob stays cancelled (a live runner's later save does not undo it)
            $old = $null; try { $old = $this.Load() } catch { $old = $null }
            if ([string]$State.State -ne 'Cancelled') { $null = Copy-SIJobFlowCancelled -Stored $old -State $State }
            # #945: a step the wake-up check closed is never written back to Running with the same execution
            $null = Set-SIBlobContent -Account $this.Account -Container $this.Container -Blob $this.Blob -Bytes ([Text.Encoding]::UTF8.GetBytes((Get-SIJobFlowSaveJson -State $State -Stored $old))) -ContentType 'application/json'
        }
    }
}

# ---- Pro: cfg.JobFlow (the definition), cfg.FlowRun + cfg.FlowStepRun (the run records) ------------------------------
function Get-SIJobFlowSqlText {
    <# The T-SQL of the Pro store (one place; the LocalSql test runs it against sql\si-pro-settings.sql). #>
    param([Parameter(Mandatory)][ValidateSet('ReadDefinition', 'LastRun', 'LastRunSteps', 'SaveRun', 'SaveStep', 'RunCancelled', 'CloseEndedRunSteps', 'EndedRunOpenSteps', 'RecentRuns', 'RecentSteps', 'CloseOpenStep', 'StepRow')][string]$Name)
    $recent = [int](Get-SIPipelineLongRunRule).RunsRead
    switch ($Name) {
        # si-flow-1203: the newest run records and their steps -- how long a run and each step usually take here (read once
        # per runner process; index reads: IX_FlowRun_Started, the steps by their primary key). SELECT *: Scope exists once
        # the schema is applied again (it only adds); a run without it counts as the pipeline.
        'RecentRuns' { "IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL SELECT TOP ($recent) * FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;" }
        'RecentSteps' { "IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL AND OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL SELECT s.FlowRunId, s.Job, s.State, s.StartedUtc, s.EndedUtc FROM cfg.FlowStepRun s JOIN (SELECT TOP ($recent) FlowRunId FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC) r ON r.FlowRunId = s.FlowRunId;" }
        'ReadDefinition' { "IF OBJECT_ID(N'cfg.JobFlow') IS NULL SELECT CAST(NULL AS nvarchar(max)) AS DefinitionJson, CAST(NULL AS nvarchar(16)) AS Mode ELSE SELECT TOP (1) DefinitionJson, Mode FROM cfg.JobFlow WHERE FlowId = N'daily';" }
        # SELECT *: Scope / Target / RequestedBy / RequestId (#306) exist once the schema is applied again (it only adds)
        'LastRun' { "IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL SELECT TOP (1) * FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;" }
        # SELECT *: Attempts / RetryReason exist once the schema is applied again (it only adds); a reader without them gets none
        'LastRunSteps' { "SELECT * FROM cfg.FlowStepRun WHERE FlowRunId = @FlowRunId ORDER BY StepOrder;" }
        # #700 + live 2026-10-19 (ring 2): a run that has ENDED in the database (Succeeded, Failed, Stopped, Cancelled) is
        # final -- a runner that is still alive and saves its own copy never turns it back (its state, stop reason and end
        # are kept; its heartbeat and note too, unless the save is that same final state again); the version it started on
        # is written once. The schema's trigger cfg.TR_FlowRun_Final refuses the same for any writer (older code included).
        'SaveRun' { @'
MERGE cfg.FlowRun AS t
USING (SELECT @FlowRunId AS FlowRunId) AS s ON t.FlowRunId = s.FlowRunId
WHEN MATCHED THEN UPDATE SET State = CASE WHEN t.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') THEN t.State ELSE @State END,
                             EndedUtc = CASE WHEN t.State = N'Cancelled' OR (t.State IN (N'Succeeded', N'Failed', N'Stopped') AND t.State <> @State) THEN t.EndedUtc ELSE @EndedUtc END,
                             HeartbeatUtc = CASE WHEN t.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') AND t.State <> @State THEN t.HeartbeatUtc ELSE @HeartbeatUtc END,
                             StopReason = CASE WHEN t.State = N'Cancelled' OR (t.State IN (N'Succeeded', N'Failed', N'Stopped') AND t.State <> @State) THEN t.StopReason ELSE @StopReason END,
                             Note = CASE WHEN t.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') AND t.State <> @State THEN t.Note ELSE @Note END
WHEN NOT MATCHED THEN INSERT (FlowRunId, FlowId, Day, Trg, FromStep, State, StartedUtc, EndedUtc, HeartbeatUtc, StopReason, SlotUtc, LastSlotUtc, Note)
     VALUES (@FlowRunId, N'daily', @Day, @Trg, @FromStep, @State, @StartedUtc, @EndedUtc, @HeartbeatUtc, @StopReason, @SlotUtc, @LastSlotUtc, @Note);
IF COL_LENGTH(N'cfg.FlowRun', N'Scope') IS NOT NULL AND COL_LENGTH(N'cfg.FlowRun', N'RequestId') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.FlowRun SET Scope = @S, Target = @T, RequestedBy = @B, RequestId = @Q WHERE FlowRunId = @F AND (Scope IS NULL OR Scope <> @S OR RequestId IS NULL);',
         N'@S nvarchar(16), @T nvarchar(64), @B nvarchar(256), @Q bigint, @F nvarchar(64)', @S = @Scope, @T = @Target, @B = @RequestedBy, @Q = @RequestId, @F = @FlowRunId;
IF COL_LENGTH(N'cfg.FlowRun', N'Version') IS NOT NULL AND COL_LENGTH(N'cfg.FlowRun', N'CancelledBy') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.FlowRun SET Version = COALESCE(Version, NULLIF(@V, N'''')), CancelledBy = COALESCE(CancelledBy, NULLIF(@C, N'''')) WHERE FlowRunId = @F;',
         N'@V nvarchar(32), @C nvarchar(256), @F nvarchar(64)', @V = @Version, @C = @CancelledBy, @F = @FlowRunId;
'@ }
        # #700: is this run cancelled? (the runner asks at every poll; SELECT *: CancelledBy exists once the schema is applied again)
        # live 2026-10-19: a run written back to Running after its cancel (CancelledBy kept) is cancelled all the same
        'RunCancelled' { @'
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL
BEGIN
    IF COL_LENGTH(N'cfg.FlowRun', N'CancelledBy') IS NOT NULL
        EXEC sp_executesql N'SELECT * FROM cfg.FlowRun WHERE FlowRunId = @F AND (State = N''Cancelled'' OR NULLIF(CancelledBy, N'''') IS NOT NULL);', N'@F nvarchar(64)', @F = @FlowRunId;
    ELSE
        SELECT * FROM cfg.FlowRun WHERE FlowRunId = @FlowRunId AND State = N'Cancelled';
END
'@ }
        # #945: a step that has ENDED is never written back to Running with the SAME execution (a runner that never saw the
        # wake-up check's close keeps it closed; it takes the close over at its next poll) -- a new execution is written.
        # a step of a run that has ENDED is never moved (back) to Starting / Running: a runner that did not see the end
        # (older code, a container that outlived its stop) cannot record a step it started again -- the row is kept
        'SaveStep' { @'
MERGE cfg.FlowStepRun AS t
USING (SELECT @FlowRunId AS FlowRunId, @StepOrder AS StepOrder,
              CASE WHEN @State IN (N'Starting', N'Running') AND EXISTS (SELECT 1 FROM cfg.FlowRun r WHERE r.FlowRunId = @FlowRunId AND r.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled')) THEN 1 ELSE 0 END AS RunEnded) AS s
    ON t.FlowRunId = s.FlowRunId AND t.StepOrder = s.StepOrder
WHEN MATCHED AND s.RunEnded = 0 AND NOT (@State = N'Running' AND t.Execution = @Execution AND t.State IN (N'Success', N'Failed', N'Interrupted', N'TimedOut')) THEN UPDATE SET State = @State, Execution = @Execution, StartedUtc = @StartedUtc, EndedUtc = @EndedUtc, ErrorClass = @ErrorClass, Error = @Error
WHEN NOT MATCHED AND s.RunEnded = 0 THEN INSERT (FlowRunId, StepOrder, GroupNo, Job, State, Execution, StartedUtc, EndedUtc, ErrorClass, Error)
     VALUES (@FlowRunId, @StepOrder, @GroupNo, @Job, @State, @Execution, @StartedUtc, @EndedUtc, @ErrorClass, @Error);
IF COL_LENGTH(N'cfg.FlowStepRun', N'Attempts') IS NOT NULL AND COL_LENGTH(N'cfg.FlowStepRun', N'RetryReason') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.FlowStepRun SET Attempts = @A, RetryReason = @R WHERE FlowRunId = @F AND StepOrder = @S;',
         N'@A int, @R nvarchar(1000), @F nvarchar(64), @S int', @A = @Attempts, @R = @RetryReason, @F = @FlowRunId, @S = @StepOrder;
IF COL_LENGTH(N'cfg.FlowStepRun', N'Stage') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.FlowStepRun SET Stage = @G WHERE FlowRunId = @F AND StepOrder = @S;',
         N'@G nvarchar(32), @F nvarchar(64), @S int', @G = @Stage, @F = @FlowRunId, @S = @StepOrder;
'@ }
        # A STEP OF A RUN THAT HAS ENDED IS NEVER LEFT OPEN (live 2026-10-21, ring 2). Two step rows of runs cancelled on
        # 2026-10-18/19 still said Running two days later: the cancel ended the RUN, and the runner closes the open steps of
        # the LAST run only (Close-SIJobFlowCancelledRun) -- a newer run had already started, so nobody closed them, and their
        # executions were long gone. Every wake-up closes them here, in one statement, with the reason: a step that was
        # Starting / Running is Interrupted at the run's end, a step that never started is Skipped. Only rows of runs that
        # have ENDED (Succeeded, Failed, Stopped, Cancelled) are touched -- never the run that is going on, never the lock.
        # Answers Closed (the rows closed).
        'CloseEndedRunSteps' { @'
SET NOCOUNT ON;
UPDATE s SET
    State = CASE WHEN s.State = N'Waiting' THEN N'Skipped' ELSE N'Interrupted' END,
    ErrorClass = CASE WHEN NULLIF(s.ErrorClass, N'') IS NOT NULL THEN s.ErrorClass WHEN r.State = N'Cancelled' THEN N'cancelled' ELSE N'run-ended' END,
    EndedUtc = CASE WHEN s.State = N'Waiting' THEN s.EndedUtc ELSE COALESCE(s.EndedUtc, r.EndedUtc, SYSUTCDATETIME()) END,
    Error = LEFT(CASE WHEN s.State = N'Waiting'
                      THEN N'not run: the run ended (' + r.State + N') before this step started'
                      ELSE N'closed: the run ended (' + r.State + N') while this step was still open -- its execution '
                           + ISNULL(NULLIF(s.Execution, N''), N'(none recorded)') + N' is not followed any more; the step did not finish in this run' END, 1000)
FROM cfg.FlowStepRun s JOIN cfg.FlowRun r ON r.FlowRunId = s.FlowRunId
WHERE r.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') AND s.State IN (N'Starting', N'Running', N'Waiting');
SELECT @@ROWCOUNT AS Closed;
'@ }
        # #882: the step rows CloseEndedRunSteps is about to close that had STARTED (Starting / Running) -- read first, so the
        # runner stops what may still run for them (the execution recorded on the row, the step's workers). Read-only.
        # #945: the wake-up check closes ONE step whose execution Azure says has ended -- only while the row still says Running
        # with THAT execution (a runner that moved the step on -- closed it, started it again -- is never overwritten), and
        # only in a run that has not ended. Answers Closed (0 or 1).
        'CloseOpenStep' { @'
SET NOCOUNT ON;
UPDATE s SET State = @State, EndedUtc = @EndedUtc, ErrorClass = @ErrorClass, Error = LEFT(@Error, 1000)
FROM cfg.FlowStepRun s JOIN cfg.FlowRun r ON r.FlowRunId = s.FlowRunId
WHERE s.FlowRunId = @FlowRunId AND s.StepOrder = @StepOrder AND s.State = N'Running' AND s.Execution = @Execution
  AND r.State NOT IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled');
SELECT @@ROWCOUNT AS Closed;
'@ }
        # #945: one step row as it is stored now (the runner adopts a close the wake-up check made). Read-only.
        'StepRow' { "SELECT State, Execution, EndedUtc, ErrorClass, Error FROM cfg.FlowStepRun WHERE FlowRunId = @FlowRunId AND StepOrder = @StepOrder;" }
        'EndedRunOpenSteps' { @'
SET NOCOUNT ON;
SELECT s.FlowRunId, s.StepOrder, s.Job, s.Execution, s.State, s.StartedUtc
FROM cfg.FlowStepRun s JOIN cfg.FlowRun r ON r.FlowRunId = s.FlowRunId
WHERE r.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') AND s.State IN (N'Starting', N'Running');
'@ }
    }
}

function ConvertTo-SIJobFlowSqlRows {
    <# PURE. The Pro store's reader returns a result set as ONE array of hashtables (New-SIProSettingsStore); a test seam
       may return rows one by one or as objects. Either way: one [pscustomobject] per row, so a property test
       (PSObject.Properties['Attempts']) sees the columns. Before this, a stored run with several steps reached the loader
       as one array and [int]$_.StepOrder failed on it ("Cannot convert System.Object[] to System.Int32"). #>
    process {
        foreach ($row in @($_)) {
            if ($null -eq $row) { continue }
            if ($row -is [System.Collections.IDictionary]) { [pscustomobject]$row } else { $row }
        }
    }
}

function New-SIJobFlowSqlStore {
    <#
        The Pro store over the (sql, params, mode) -Invoke seam every Pro engine uses (New-SIProSettingsStore .Invoke).
        Load(): the last cfg.FlowRun + its steps. Save($State): the run row and the step rows that changed since the last
        save (MERGE, idempotent) -- the heartbeat costs one statement. ReadDefinition(): cfg.JobFlow (or $null).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    New-SIJobFlowSeams -Fields @{ Invoke = $Invoke; Seen = @{} } -Methods @{
        ReadDefinition = {
            $r = @(& $this.Invoke (Get-SIJobFlowSqlText 'ReadDefinition') @{} 'reader' | ConvertTo-SIJobFlowSqlRows)
            if ($r.Count -and "$($r[0].DefinitionJson)" -and -not ($r[0].DefinitionJson -is [DBNull])) { [pscustomobject]@{ Json = [string]$r[0].DefinitionJson; Mode = [string]$r[0].Mode } } else { $null }
        }
        Load = {
            $r = @(& $this.Invoke (Get-SIJobFlowSqlText 'LastRun') @{} 'reader' | ConvertTo-SIJobFlowSqlRows)
            if (-not $r.Count) { return $null }
            $x = $r[0]
            $t = { param($v) if ($null -eq $v -or $v -is [DBNull]) { $null } else { ([datetime]$v).ToUniversalTime() } }
            $steps = @(& $this.Invoke (Get-SIJobFlowSqlText 'LastRunSteps') @{ FlowRunId = [string]$x.FlowRunId } 'reader' | ConvertTo-SIJobFlowSqlRows | ForEach-Object {
                [pscustomobject]@{ Order = [int]$_.StepOrder; Group = [int]$_.GroupNo; Job = [string]$_.Job; Stage = $(if ($_.PSObject.Properties['Stage'] -and -not ($_.Stage -is [DBNull])) { [string]$_.Stage } else { '' }); State = [string]$_.State; Execution = [string]$_.Execution
                                   StartedUtc = (& $t $_.StartedUtc); EndedUtc = (& $t $_.EndedUtc); ErrorClass = [string]$_.ErrorClass; Error = [string]$_.Error
                                   Attempts = (Get-SIJobFlowAttempts $_); RetryReason = $(if ($_.PSObject.Properties['RetryReason'] -and -not ($_.RetryReason -is [DBNull])) { [string]$_.RetryReason } else { '' }) } })
            # a run CANCELLED once is final: a row an older runner wrote back to Running after the cancel (its CancelledBy
            # is kept) loads as Cancelled -- never resumed, its open steps closed (Close-SIJobFlowCancelledRun)
            Resolve-SIJobFlowRunFinal -State ([pscustomobject]@{ FlowRunId = [string]$x.FlowRunId; Day = [string]$x.Day; Trigger = [string]$x.Trg; FromStep = [string]$x.FromStep; State = [string]$x.State
                               StartedUtc = (& $t $x.StartedUtc); EndedUtc = (& $t $x.EndedUtc); HeartbeatUtc = (& $t $x.HeartbeatUtc); StopReason = [string]$x.StopReason
                               SlotUtc = (& $t $x.SlotUtc); LastSlotUtc = (& $t $x.LastSlotUtc); Note = [string]$x.Note
                               Scope = $(if ($x.PSObject.Properties['Scope'] -and -not ($x.Scope -is [DBNull]) -and $x.Scope) { [string]$x.Scope } else { 'pipeline' })
                               Target = $(if ($x.PSObject.Properties['Target'] -and -not ($x.Target -is [DBNull])) { [string]$x.Target } else { '' })
                               RequestedBy = $(if ($x.PSObject.Properties['RequestedBy'] -and -not ($x.RequestedBy -is [DBNull])) { [string]$x.RequestedBy } else { '' })
                               RequestId = $(if ($x.PSObject.Properties['RequestId'] -and -not ($x.RequestId -is [DBNull]) -and $null -ne $x.RequestId) { [long]$x.RequestId } else { 0 })
                               Version = $(if ($x.PSObject.Properties['Version'] -and -not ($x.Version -is [DBNull]) -and $null -ne $x.Version) { [string]$x.Version } else { '' })
                               # #700: a database whose schema was not applied again has no Version column -- the version is then unknown
                               VersionRecorded = [bool]$x.PSObject.Properties['Version']
                               CancelledBy = $(if ($x.PSObject.Properties['CancelledBy'] -and -not ($x.CancelledBy -is [DBNull]) -and $null -ne $x.CancelledBy) { [string]$x.CancelledBy } else { '' })
                               Steps = $steps })
        }
        # si-flow-1203: @{ Runs; Steps } -- the newest run records and their steps (Invoke-SIJobFlow -History)
        Recent = {
            $t = { param($v) if ($null -eq $v -or $v -is [DBNull]) { $null } else { [datetime]::SpecifyKind([datetime]$v, [DateTimeKind]::Utc) } }
            $s = { param($v) if ($null -eq $v -or $v -is [DBNull]) { '' } else { [string]$v } }
            $runs = @(& $this.Invoke (Get-SIJobFlowSqlText 'RecentRuns') @{} 'reader' | ConvertTo-SIJobFlowSqlRows | ForEach-Object {
                [pscustomobject]@{ FlowRunId = [string]$_.FlowRunId; State = [string]$_.State; FromStep = (& $s $_.FromStep)
                                   Scope = $(if ($_.PSObject.Properties['Scope']) { & $s $_.Scope } else { '' }); StartedUtc = (& $t $_.StartedUtc); EndedUtc = (& $t $_.EndedUtc) } })
            $steps = @(& $this.Invoke (Get-SIJobFlowSqlText 'RecentSteps') @{} 'reader' | ConvertTo-SIJobFlowSqlRows | ForEach-Object {
                [pscustomobject]@{ FlowRunId = [string]$_.FlowRunId; Job = [string]$_.Job; State = [string]$_.State; StartedUtc = (& $t $_.StartedUtc); EndedUtc = (& $t $_.EndedUtc) } })
            [pscustomobject]@{ Runs = $runs; Steps = $steps }
        }
        # #700: @{ By; Reason } when run -FlowRunId is cancelled in the database, else $null (one small read per poll)
        Cancelled = {
            param($FlowRunId)
            if (-not $FlowRunId) { return $null }
            $r = @(& $this.Invoke (Get-SIJobFlowSqlText 'RunCancelled') @{ FlowRunId = [string]$FlowRunId } 'reader' | ConvertTo-SIJobFlowSqlRows)
            if (-not $r.Count) { return $null }
            $x = $r[0]
            [pscustomobject]@{ By = $(if ($x.PSObject.Properties['CancelledBy'] -and -not ($x.CancelledBy -is [DBNull]) -and $null -ne $x.CancelledBy) { [string]$x.CancelledBy } else { '' })
                               Reason = $(if ($x.StopReason -is [DBNull] -or $null -eq $x.StopReason) { '' } else { [string]$x.StopReason }) }
        }
        # the open step rows of runs that have ENDED, closed with the reason (Get-SIJobFlowSqlText 'CloseEndedRunSteps');
        # answers how many were closed. The step rows the runner remembers as saved are forgotten: a closed row is the truth.
        CloseEndedRunSteps = {
            $r = @(& $this.Invoke (Get-SIJobFlowSqlText 'CloseEndedRunSteps') @{} 'reader' | ConvertTo-SIJobFlowSqlRows)
            $n = 0; if ($r.Count -and $r[0].PSObject.Properties['Closed'] -and -not ($r[0].Closed -is [DBNull])) { $n = [int]$r[0].Closed }
            if ($n -gt 0) { $this.Seen.Clear() }
            $n
        }
        # #945: the wake-up check's close of one step (Get-SIJobFlowSqlText 'CloseOpenStep'); answers 1 when it was closed
        CloseOpenStep = {
            param($FlowRunId, $Close)
            $r = @(& $this.Invoke (Get-SIJobFlowSqlText 'CloseOpenStep') @{ FlowRunId = [string]$FlowRunId; StepOrder = [int]$Close.Order; Execution = [string]$Close.Execution
                     State = [string]$Close.State; EndedUtc = ([datetime]$Close.EndedUtc).ToUniversalTime(); ErrorClass = [string]$Close.ErrorClass; Error = [string]$Close.Error } 'reader' | ConvertTo-SIJobFlowSqlRows)
            $n = 0; if ($r.Count -and $r[0].PSObject.Properties['Closed'] -and -not ($r[0].Closed -is [DBNull])) { $n = [int]$r[0].Closed }
            if ($n -gt 0) { $this.Seen.Remove(('{0}|{1}' -f $FlowRunId, [int]$Close.Order)) }
            $n
        }
        # #945: one step row as stored now: @{ State; Execution; EndedUtc; ErrorClass; Error } or $null
        StepRow = {
            param($FlowRunId, $Order)
            $r = @(& $this.Invoke (Get-SIJobFlowSqlText 'StepRow') @{ FlowRunId = [string]$FlowRunId; StepOrder = [int]$Order } 'reader' | ConvertTo-SIJobFlowSqlRows)
            if (-not $r.Count) { return $null }
            $x = $r[0]; $s = { param($v) if ($null -eq $v -or $v -is [DBNull]) { '' } else { [string]$v } }
            [pscustomobject]@{ State = (& $s $x.State); Execution = (& $s $x.Execution); ErrorClass = (& $s $x.ErrorClass); Error = (& $s $x.Error)
                               EndedUtc = $(if ($null -eq $x.EndedUtc -or $x.EndedUtc -is [DBNull]) { $null } else { ([datetime]$x.EndedUtc).ToUniversalTime() }) }
        }
        # #882: the started step rows of ended runs that are still open (Get-SIJobFlowSqlText 'EndedRunOpenSteps') -- read
        # before they are closed, so what may still run for them is stopped. @(@{ FlowRunId; Job; Execution; State; StartedUtc })
        EndedRunOpenSteps = {
            @(& $this.Invoke (Get-SIJobFlowSqlText 'EndedRunOpenSteps') @{} 'reader' | ConvertTo-SIJobFlowSqlRows | ForEach-Object {
                [pscustomobject]@{ FlowRunId = [string]$_.FlowRunId; Job = [string]$_.Job
                                   Execution = $(if ($_.Execution -is [DBNull] -or $null -eq $_.Execution) { '' } else { [string]$_.Execution })
                                   State = [string]$_.State
                                   StartedUtc = $(if ($_.StartedUtc -is [DBNull] -or $null -eq $_.StartedUtc) { $null } else { ([datetime]$_.StartedUtc).ToUniversalTime() }) } })
        }
        Save = {
            param($State)
            $nul = { param($v) if ($null -eq $v) { [DBNull]::Value } else { $v } }
            $null = & $this.Invoke (Get-SIJobFlowSqlText 'SaveRun') @{ FlowRunId = $State.FlowRunId; Day = $State.Day; Trg = $State.Trigger; FromStep = [string]$State.FromStep; State = $State.State
                StartedUtc = $State.StartedUtc; EndedUtc = (& $nul $State.EndedUtc); HeartbeatUtc = $State.HeartbeatUtc; StopReason = [string]$State.StopReason
                SlotUtc = (& $nul $State.SlotUtc); LastSlotUtc = (& $nul $State.LastSlotUtc); Note = [string]$State.Note
                Scope = $(if ($State.PSObject.Properties['Scope'] -and $State.Scope) { [string]$State.Scope } else { 'pipeline' }); Target = $(if ($State.PSObject.Properties['Target']) { [string]$State.Target } else { '' })
                RequestedBy = $(if ($State.PSObject.Properties['RequestedBy']) { ([string]$State.RequestedBy) } else { '' }); RequestId = $(if ($State.PSObject.Properties['RequestId'] -and $State.RequestId) { [long]$State.RequestId } else { [long]0 })
                Version = $(if ($State.PSObject.Properties['Version']) { ([string]$State.Version) } else { '' }); CancelledBy = $(if ($State.PSObject.Properties['CancelledBy']) { ([string]$State.CancelledBy) } else { '' }) } 'nonquery'
            foreach ($s in @($State.Steps)) {
                $key = '{0}|{1}' -f $State.FlowRunId, $s.Order
                $att = Get-SIJobFlowAttempts $s
                $why = if ($s.PSObject.Properties['RetryReason']) { [string]$s.RetryReason } else { '' }; if ($why.Length -gt 1000) { $why = $why.Substring(0, 1000) }
                $stg = if ($s.PSObject.Properties['Stage']) { [string]$s.Stage } else { '' }
                $sig = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $s.State, $s.Execution, $s.StartedUtc, $s.EndedUtc, $s.ErrorClass, $s.Error, $att, $why, $stg
                if ($this.Seen[$key] -eq $sig) { continue }
                $err = [string]$s.Error; if ($err.Length -gt 1000) { $err = $err.Substring(0, 1000) }
                $null = & $this.Invoke (Get-SIJobFlowSqlText 'SaveStep') @{ FlowRunId = $State.FlowRunId; StepOrder = [int]$s.Order; GroupNo = [int]$s.Group; Job = $s.Job; State = $s.State
                    Execution = [string]$s.Execution; StartedUtc = (& $nul $s.StartedUtc); EndedUtc = (& $nul $s.EndedUtc); ErrorClass = [string]$s.ErrorClass; Error = $err
                    Attempts = [int]$att; RetryReason = $why; Stage = $stg } 'nonquery'
                $this.Seen[$key] = $sig
            }
        }
    }
}

# =====================================================================================================================
#  Mode switches (Bootstrap, the VM setup step, the web app's preview uses the same rules in C#)
# =====================================================================================================================
function Get-SIJobOrchestrationSwitchPlan {
    <#
        PURE. What switching the install to -Mode does to each job -- the preview, and what -Apply carries out. -Jobs:
        @(@{ Name; TriggerType (Schedule | Manual | Event); Cron; RememberedCron }) as listed. -Definition: the flow (its
        steps are the jobs IN the flow; default: the default flow over the jobs listed).
          flow:      a job of the flow on a timer -> to-manual (its timer remembered in the si-disabled-cron tag);
                     caj-si-flow -> to-schedule at the flow's start time;
          schedules: a job of the flow without a timer -> to-schedule with its remembered timer, or the map's default
                     timer (the dependency order of the shipped schedule); caj-si-flow -> to-manual (its time remembered).
        The updater (Test-SIJobFlowOwnSchedule) keeps its own timer in BOTH modes, and one an earlier switch turned to manual
        (remembered in si-disabled-cron) is given back -- UPDATE-1.6: it runs on its own daily schedule, never in the pipeline.
        A job outside the flow, an event-triggered (KEDA) job and the template job are kept. Reversible: switching back
        restores every timer that was remembered. Returns @(@{ Job; Action = to-manual | to-schedule | keep; Cron; Why }).
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), [Parameter(Mandatory)][ValidateSet('flow', 'schedules')][string]$Mode, $Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $names = @($Jobs | Where-Object { $_ } | ForEach-Object { [string]$_.Name })
    if (-not $Definition) { $Definition = New-SIDefaultJobFlow -Installed $names -Map $Map }
    if (@(@($Definition.Steps) | Where-Object { $_ -and ((Test-SIJobFlowOwnSchedule -Job ([string]$_.Job) -Map $Map) -or (Test-SIJobFlowRetired -Job ([string]$_.Job) -Map $Map)) }).Count) { $Definition = Remove-SIJobFlowOwnScheduleStep -Definition $Definition -Map $Map }
    $inFlow = @(@($Definition.Steps) | ForEach-Object { [string]$_.Job })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($j in @($Jobs | Where-Object { $_ })) {
        $k = Get-SIJobFlowKey $j.Name; $tt = [string]$j.TriggerType
        $row = { param($a, $c, $w) $out.Add([pscustomobject]@{ Job = [string]$j.Name; Action = $a; Cron = $c; Why = $w }) }
        if ($tt -eq 'Event') { & $row 'keep' '' 'event-triggered (scaled by its queue)'; continue }
        if ($k -eq 'flow') {
            if ($Mode -eq 'flow') {
                if ($tt -eq 'Schedule') { & $row 'keep' ([string]$j.Cron) 'the flow''s timer is on' } else { & $row 'to-schedule' $script:SIJobFlow.TickCron ('wakes the flow runner every 5 min; the flow starts {0}' -f (Get-SIJobFlowCadenceText -Definition $Definition)) }
            } else {
                if ($tt -eq 'Schedule') { & $row 'to-manual' ([string]$j.Cron) 'the flow waits (its time is remembered)' } else { & $row 'keep' '' 'the flow is already off' }
            }
            continue
        }
        # UPDATE-1.6: the updater keeps its OWN timer in every mode -- and gets back one an earlier switch took away
        if (Test-SIJobFlowOwnSchedule -Job $k -Map $Map) {
            if ($tt -eq 'Schedule') { & $row 'keep' ([string]$j.Cron) 'the updater runs on its own daily schedule -- never a step of the pipeline' }
            elseif ([string]$j.RememberedCron) { & $row 'to-schedule' ([string]$j.RememberedCron) 'the updater runs on its own daily schedule -- its timer, taken away by an earlier switch, comes back' }
            else { & $row 'keep' '' ('the updater has no timer and none is remembered -- give it its daily schedule ({0} UTC) with setup\Install-SIUpdaterJob.ps1' -f $(if ($Map.Jobs.Contains($k) -and $Map.Jobs[$k].DefaultCron) { $Map.Jobs[$k].DefaultCron } else { '30 16,17 * * *' })) }
            continue
        }
        # #412: a retired job (asset-properties) does nothing any more -- its timer is turned off in both modes (remembered,
        # so the switch stays reversible); it never comes back on
        if (Test-SIJobFlowRetired -Job $k -Map $Map) {
            if ($tt -eq 'Schedule') { & $row 'to-manual' ([string]$j.Cron) 'retired -- the profilers publish the full asset metadata themselves (its timer is remembered)' }
            else { & $row 'keep' '' 'retired -- the profilers publish the full asset metadata themselves' }
            continue
        }
        # #306: the risk trend runs inside Risk Analysis while the jobs run as a pipeline -- its own job waits (runnable by hand)
        if ($inFlow -notcontains $k -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].ManualInFlowMode) {
            if ($Mode -eq 'flow') { if ($tt -eq 'Schedule') { & $row 'to-manual' ([string]$j.Cron) 'Risk Analysis writes the daily trend row itself -- the job is kept for a run by hand (its timer is remembered)' } else { & $row 'keep' '' 'runs by hand only (Risk Analysis writes the daily trend row)' } }
            else { if ($tt -eq 'Schedule') { & $row 'keep' ([string]$j.Cron) 'already on its own timer' } else { $c = [string]$j.RememberedCron; if (-not $c) { $c = $Map.Jobs[$k].DefaultCron }; & $row 'to-schedule' $c 'its own timer again' } }
            continue
        }
        if ($inFlow -notcontains $k) { & $row 'keep' ([string]$j.Cron) 'not in the flow -- keeps its own schedule'; continue }
        if ($Mode -eq 'flow') {
            if ($tt -eq 'Schedule') { & $row 'to-manual' ([string]$j.Cron) ('step {0} of the flow -- its timer {1} is remembered' -f ([array]::IndexOf($inFlow, $k) + 1), $j.Cron) }
            else { & $row 'keep' '' ('step {0} of the flow' -f ([array]::IndexOf($inFlow, $k) + 1)) }
        } else {
            if ($tt -eq 'Schedule') { & $row 'keep' ([string]$j.Cron) 'already on its own timer'; continue }
            $c = [string]$j.RememberedCron; $why = 'its remembered timer'
            if (-not $c) { $c = $(if ($Map.Jobs.Contains($k) -and $Map.Jobs[$k].DefaultCron) { $Map.Jobs[$k].DefaultCron } else { '0 4 * * *' }); $why = 'the default timer (dependency order)' }
            & $row 'to-schedule' $c $why
        }
    }
    , $out.ToArray()
}

function ConvertTo-SIJobFlowTriggerList {
    <# PURE. Container Apps jobs as ARM lists them -> @(@{ Name; TriggerType; Cron; RememberedCron }) (the switch plan's input). #>
    param([AllowEmptyCollection()][object[]]$ArmJobs = @())
    @($ArmJobs | Where-Object { $_ -and $_.PSObject.Properties['name'] -and [string]$_.name -like 'caj-si-*' } | ForEach-Object {
        $c = if ($_.PSObject.Properties['properties'] -and $_.properties -and $_.properties.PSObject.Properties['configuration'] -and $_.properties.configuration) { $_.properties.configuration } else { [pscustomobject]@{ triggerType = '' } }
        [pscustomobject]@{ Name = [string]$_.name; TriggerType = [string]$c.triggerType
                           Cron = $(if ($c.PSObject.Properties['scheduleTriggerConfig'] -and $c.scheduleTriggerConfig) { [string]$c.scheduleTriggerConfig.cronExpression } else { '' })
                           RememberedCron = $(if ($_.PSObject.Properties['tags'] -and $_.tags -and $_.tags.PSObject.Properties['si-disabled-cron']) { [string]$_.tags.'si-disabled-cron' } else { '' }) }
    })
}

function Test-SIJobOrchestrationNeitherMode {
    <#
        PURE. "NEITHER MODE" (found live on a ring 2 install, 2026-10-10: nothing ran for 14 h): caj-si-flow has no timer
        (Manual) AND no job of the flow has its own timer -- so the daily pipeline never starts and its jobs never run. Not
        a mode anyone can choose: flow mode = caj-si-flow on its timer; schedules mode = the jobs of the flow on theirs.
        Jobs outside the flow (the updater's own schedule, the template job, an event-triggered worker, a queue producer,
        a retired job, the trend job that runs by hand in flow mode) do not count. -Jobs: ConvertTo-SIJobFlowTriggerList.
        Returns @{ Neither; Why; FlowJob (caj-si-flow exists); Steps (jobs of the flow that exist); Timed (of them on a timer) }.
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), $Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $list = @($Jobs | Where-Object { $_ })
    $names = @($list | ForEach-Object { [string]$_.Name })
    if (-not $Definition) { $Definition = New-SIDefaultJobFlow -Installed $names -Map $Map }
    if (@(@($Definition.Steps) | Where-Object { $_ -and ((Test-SIJobFlowOwnSchedule -Job ([string]$_.Job) -Map $Map) -or (Test-SIJobFlowRetired -Job ([string]$_.Job) -Map $Map)) }).Count) { $Definition = Remove-SIJobFlowOwnScheduleStep -Definition $Definition -Map $Map }
    $inFlow = @(@($Definition.Steps) | ForEach-Object { Get-SIJobFlowKey ([string]$_.Job) })
    $flow = @($list | Where-Object { (Get-SIJobFlowKey $_.Name) -eq 'flow' }) | Select-Object -First 1
    $steps = @($list | Where-Object { $inFlow -contains (Get-SIJobFlowKey $_.Name) -and [string]$_.TriggerType -ne 'Event' })
    $timed = @($steps | Where-Object { [string]$_.TriggerType -eq 'Schedule' })
    $mk = { param($n, $w) [pscustomobject]@{ Neither = [bool]$n; Why = $w; FlowJob = [bool]$flow; Steps = $steps.Count; Timed = $timed.Count } }
    if (-not $flow) { return (& $mk $false 'no caj-si-flow job (an install made before the pipeline: its jobs run on their own timers)') }
    if ([string]$flow.TriggerType -eq 'Schedule') { return (& $mk $false ('the pipeline is scheduled (caj-si-flow wakes "{0}")' -f $flow.Cron)) }
    if (-not $steps.Count) { return (& $mk $false 'caj-si-flow has no timer, but no job of the pipeline exists yet') }
    if ($timed.Count) { return (& $mk $false ('per-job schedules: {0} of {1} job(s) of the pipeline run on their own timer' -f $timed.Count, $steps.Count)) }
    & $mk $true ('NOTHING RUNS: caj-si-flow has no timer and none of the {0} job(s) of the pipeline has its own -- neither the pipeline nor the jobs start' -f $steps.Count)
}

function Invoke-SIJobOrchestrationRepair {
    <#
        Every update (setup\Invoke-SIContainerUpdate.ps1) -- "neither mode" (Test-SIJobOrchestrationNeitherMode) is put back
        to the PIPELINE (flow mode), by the same plan and the same PATCH as setup\Switch-SIJobOrchestration.ps1 -Mode flow
        (Get-SIJobOrchestrationSwitchPlan + ConvertTo-SIArmJobTrigger): in practice caj-si-flow gets its timer back. ONE
        plain warning line says it. -WhatIf (the update's -DetectOnly): the plan only. Any other state: nothing changes.
          -Jobs  the jobs as ARM lists them; -Arm { param($Method, $Path, $Body) } -> the parsed answer (GET the job / PATCH it;
                 $Path = the job's resource id); -Log { param($Level, $Message) } (INFO / WARN).
        NEVER THROWS. Returns @{ State = ok | repaired | would-repair | failed (the repair did not complete) | unchecked; Why;
        Changed = @(job names); Plan }.
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Log, [switch]$WhatIf, $Definition, $Map)
    if (-not $Log) { $Log = { param($l, $m) } }
    $out = { param($s, $w, $c, $p) [pscustomobject]@{ State = $s; Why = $w; Changed = @($c); Plan = @($p) } }
    try {
        if (-not $Map) { $Map = Get-SIJobFlowMap }
        $list = ConvertTo-SIJobFlowTriggerList -ArmJobs $Jobs
        $chk = Test-SIJobOrchestrationNeitherMode -Jobs $list -Definition $Definition -Map $Map
        if (-not $chk.Neither) { & $Log 'INFO' ('pipeline schedule: {0}' -f $chk.Why); return (& $out 'ok' $chk.Why @() @()) }
        # (assigned, never wrapped in @(): the plan comes back as ONE array -- @() would make it one item)
        $all = Get-SIJobOrchestrationSwitchPlan -Jobs $list -Mode flow -Definition $Definition -Map $Map
        # timers ON first (caj-si-flow), then off -- stopped half-way it never leaves nothing scheduled
        $plan = @(@($all | Where-Object { $_.Action -eq 'to-schedule' }) + @($all | Where-Object { $_.Action -eq 'to-manual' }))
        if ($WhatIf) {
            & $Log 'WARN' ('pipeline schedule: {0} -- the update switches it to the pipeline: {1} (re-run with -Apply)' -f $chk.Why, (($plan | ForEach-Object { '{0} {1} {2}' -f $_.Job, $_.Action, $_.Cron }) -join '; '))
            return (& $out 'would-repair' $chk.Why @() $plan)
        }
        $done = New-Object System.Collections.Generic.List[string]; $bad = New-Object System.Collections.Generic.List[string]
        foreach ($p in $plan) {
            try {
                $raw = @($Jobs | Where-Object { [string]$_.name -eq [string]$p.Job }) | Select-Object -First 1
                $job = & $Arm 'GET' ([string]$raw.id) $null
                $body = ConvertTo-SIArmJobTrigger -Job $job -Action $p.Action -Cron $(if ($p.Action -eq 'to-schedule') { $p.Cron } else { '' })
                $null = & $Arm 'PATCH' ([string]$raw.id) $body
                $done.Add([string]$p.Job)
            } catch { $bad.Add(('{0} ({1})' -f $p.Job, $_.Exception.Message)) }
        }
        if ($bad.Count) {
            & $Log 'WARN' ('pipeline schedule: {0} -- switching it to the pipeline did not complete: {1}; the next update tries again (or run setup\Switch-SIJobOrchestration.ps1 -Mode flow -Apply)' -f $chk.Why, ($bad -join '; '))
            return (& $out 'failed' $chk.Why $done.ToArray() $plan)
        }
        & $Log 'WARN' ('pipeline schedule: {0} -- switched to the pipeline (flow mode): {1}' -f $chk.Why, (($plan | ForEach-Object { '{0} {1} {2}' -f $_.Job, $_.Action, $_.Cron }) -join '; '))
        & $out 'repaired' $chk.Why $done.ToArray() $plan
    } catch {
        & $Log 'WARN' ('pipeline schedule: not checked ({0}) -- the next update tries again' -f $_.Exception.Message)
        & $out 'unchecked' "$($_.Exception.Message)" @() @()
    }
}

function Get-SIFlowRunnerScheduleState {
    <#
        PURE. #732 (live 2026-10-17: one install's caj-si-flow had trigger Manual and never ran after its install; a queued
        run waited 6 h -- every other install wakes the runner every 5 minutes). Is the pipeline runner on its schedule?
        -Jobs: ConvertTo-SIJobFlowTriggerList. Returns @{ State; Why; Cron; Trigger }:
          scheduled       caj-si-flow is on a timer (whatever its cron)
          not-scheduled   caj-si-flow has no timer, and no job of the pipeline runs on its own -- the update puts it on
                          its schedule; the heartbeat says so (si-flow-1201)
          schedules-mode  caj-si-flow has no timer, and the jobs of the pipeline run on their own timers: that install
                          chose per-job schedules -- left as it is (a runner on its timer would run the default pipeline
                          there as well, every job twice)
          no-runner       no caj-si-flow (an install made before the pipeline)
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), $Definition, $Map)
    $list = @($Jobs | Where-Object { $_ })
    $flow = @($list | Where-Object { (Get-SIJobFlowKey ([string]$_.Name)) -eq 'flow' }) | Select-Object -First 1
    $mk = { param($s, $w) [pscustomobject]@{ State = $s; Why = $w; Cron = $(if ($flow) { [string]$flow.Cron } else { '' }); Trigger = $(if ($flow) { [string]$flow.TriggerType } else { '' }) } }
    if (-not $flow) { return (& $mk 'no-runner' 'no caj-si-flow job at this install (an install made before the pipeline: its jobs run on their own timers)') }
    if ([string]$flow.TriggerType -eq 'Schedule') { return (& $mk 'scheduled' ('caj-si-flow wakes "{0}"' -f [string]$flow.Cron)) }
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $chk = Test-SIJobOrchestrationNeitherMode -Jobs $list -Definition $Definition -Map $Map
    if ($chk.Timed -gt 0) { return (& $mk 'schedules-mode' ('caj-si-flow has no timer and {0} of the {1} job(s) of the pipeline run on their own timer -- this install runs its jobs on their own schedules' -f $chk.Timed, $chk.Steps)) }
    & $mk 'not-scheduled' ('caj-si-flow has no timer (trigger {0}) -- the pipeline never starts by itself and a queued run waits' -f $(if ([string]$flow.TriggerType) { [string]$flow.TriggerType } else { 'unknown' }))
}

function New-SIFlowRunnerSchedulePatchBody {
    <#
        PURE. #732: the ARM PATCH that puts caj-si-flow on its schedule, from the job as ARM just returned it (GET): the
        job's WHOLE template as read (the default imageType and the read-only ephemeralStorage left out, as every update
        PATCH does), its configuration with triggerType Schedule and scheduleTriggerConfig { -Cron, its parallelism and
        completion count }, its run limit (replicaTimeout -- 7 days) and retry limit as read; its tags without the
        si-disabled-cron a Manual job remembers. NEVER the secrets or the registries (ARM returns secrets without their
        values). The input is not changed. Returns an ordered dictionary (ConvertTo-Json it).
    #>
    param([Parameter(Mandatory)]$Job, [string]$Cron = $script:SIJobFlow.TickCron)
    $props = if ($Job.PSObject.Properties['properties']) { $Job.properties } else { $null }
    $cfg = if ($props -and $props.PSObject.Properties['configuration']) { $props.configuration } else { $null }
    if (-not $cfg) { throw 'the job has no configuration' }
    if (-not $props.PSObject.Properties['template'] -or -not $props.template) { throw 'the job has no template' }
    if ($Cron -notmatch '^[0-9*/,\-]{1,40}( [0-9*/,\-]{1,40}){4}$') { throw ("'{0}' is not a 5-field cron expression" -f $Cron) }
    $tpl = ConvertTo-Json -InputObject $props.template -Depth 60 | ConvertFrom-Json
    foreach ($c in (@($tpl.containers) + @($tpl.initContainers))) {
        if (-not $c) { continue }
        if ($c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
        if ($c.PSObject.Properties['resources'] -and $c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    $par = 1; $rcc = 1
    $src = if ($cfg.PSObject.Properties['scheduleTriggerConfig'] -and $cfg.scheduleTriggerConfig) { $cfg.scheduleTriggerConfig } elseif ($cfg.PSObject.Properties['manualTriggerConfig'] -and $cfg.manualTriggerConfig) { $cfg.manualTriggerConfig } else { $null }
    if ($src) { if ($src.PSObject.Properties['parallelism'] -and $src.parallelism) { $par = $src.parallelism }; if ($src.PSObject.Properties['replicaCompletionCount'] -and $src.replicaCompletionCount) { $rcc = $src.replicaCompletionCount } }
    $c2 = [ordered]@{ triggerType = 'Schedule' }
    if ($cfg.PSObject.Properties['replicaTimeout'] -and $cfg.replicaTimeout) { $c2.replicaTimeout = $cfg.replicaTimeout }
    if ($cfg.PSObject.Properties['replicaRetryLimit'] -and $null -ne $cfg.replicaRetryLimit -and "$($cfg.replicaRetryLimit)" -ne '') { $c2.replicaRetryLimit = $cfg.replicaRetryLimit }
    $c2.scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = $par; replicaCompletionCount = $rcc }
    $tags = [ordered]@{}
    if ($Job.PSObject.Properties['tags'] -and $null -ne $Job.tags) {
        if ($Job.tags -is [System.Collections.IDictionary]) { foreach ($k in $Job.tags.Keys) { $tags[[string]$k] = [string]$Job.tags[$k] } }
        else { foreach ($p in $Job.tags.PSObject.Properties) { $tags[$p.Name] = [string]$p.Value } }
    }
    $tags.Remove('si-disabled-cron')
    [ordered]@{ tags = $tags; properties = [ordered]@{ template = $tpl; configuration = $c2 } }
}

function Invoke-SIFlowRunnerSchedule {
    <#
        #732, EVERY UPDATE (existing installs reach the new-install state): an existing caj-si-flow without its timer is put
        on its schedule (-Cron, default "*/5 * * * *", the runner's wake-up a new install gets) -- ONE read-modify-write ARM
        PATCH (New-SIFlowRunnerSchedulePatchBody: the whole template, the run limit and retry limit kept, no secret sent
        back), then READ BACK until the trigger is Schedule on that cron. ONE plain line says what happened. A runner on a
        timer is never touched (no PATCH); an install that runs its jobs on their own timers keeps them (schedules-mode);
        no caj-si-flow = nothing. -Jobs: the job list (ARM shape). -Rest: the update's REST seam { param($Method, $Uri, $Body,
        $Resource, $Headers) } -> @{ Status; Body }. -WhatIf: the plan only, no call.
        NEVER THROWS. Returns @{ State = ok | patched | would-patch | schedules-mode | no-runner | failed; Line; Why }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [AllowEmptyCollection()][object[]]$Jobs = @(), [string]$Cron = $script:SIJobFlow.TickCron, [switch]$WhatIf,
          [int]$PollSeconds = 5, [int]$PollMax = 24, $Map)
    $out = { param($s, $l, $w) [pscustomobject]@{ State = $s; Line = $l; Why = $w } }
    $name = 'caj-si-flow'
    try {
        $st = Get-SIFlowRunnerScheduleState -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs $Jobs) -Map $Map
        switch ($st.State) {
            'no-runner'      { return (& $out 'no-runner' ('pipeline runner: {0}' -f $st.Why) $st.Why) }
            'scheduled'      { return (& $out 'ok' ('pipeline runner: on its schedule -- {0}' -f $st.Why) $st.Why) }
            'schedules-mode' { return (& $out 'schedules-mode' ('pipeline runner: left without its timer -- {0}' -f $st.Why) $st.Why) }
        }
        if ($WhatIf) { return (& $out 'would-patch' ('pipeline runner: {0} -- the update puts {1} on its schedule "{2}" (re-run with -Apply)' -f $st.Why, $name, $Cron) $st.Why) }
        $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIJobFlow.ArmApi
        $arm = 'https://management.azure.com/'
        $call = {
            param([string]$Method, $Body)
            $r = $null
            try { $r = & $Rest $Method $uri $Body $arm @{ 'Content-Type' = 'application/json' } } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
            if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }
            $r
        }
        $isOk = { param($r) $r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) if (-not $r -or -not "$($r.Body)".Trim()) { return $null }; $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; $o }
        $why = { param($r) $t = ("$(if ($r) { $r.Body })" -replace '\s+', ' ').Trim(); if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; ('HTTP {0}{1}' -f $(if ($r) { [int]$r.Status } else { 0 }), $(if ($t) { ": $t" } else { '' })) }
        $fail = { param($w) & $out 'failed' ('pipeline runner: {0} was NOT put on its schedule "{1}" ({2}) -- the update goes on; the next update tries again' -f $name, $Cron, $w) $w }
        # read
        $g = & $call 'GET' $null
        if (-not (& $isOk $g)) { return (& $fail ('it could not be read: {0}' -f (& $why $g))) }
        $job = & $parse $g
        if (-not $job) { return (& $fail 'it could not be read') }
        if ([string]$job.properties.configuration.triggerType -eq 'Schedule') { return (& $out 'ok' ('pipeline runner: on its schedule -- {0} wakes "{1}" (set meanwhile)' -f $name, [string]$job.properties.configuration.scheduleTriggerConfig.cronExpression) 'set meanwhile') }
        # modify + write
        $body = New-SIFlowRunnerSchedulePatchBody -Job $job -Cron $Cron
        $p = & $call 'PATCH' (ConvertTo-Json -InputObject $body -Depth 60 -Compress)
        if (-not (& $isOk $p)) { return (& $fail ('Azure refused it: {0}' -f (& $why $p))) }
        # read back (ARM may apply a PATCH asynchronously)
        $tt = ''; $got = ''
        for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
            $b = & $call 'GET' $null
            $j = if (& $isOk $b) { & $parse $b } else { $null }
            $ps = ''; $tt = ''; $got = ''
            if ($j) {
                try { $ps = [string]$j.properties.provisioningState } catch { }
                try { $tt = [string]$j.properties.configuration.triggerType } catch { }
                try { $got = [string]$j.properties.configuration.scheduleTriggerConfig.cronExpression } catch { }
            }
            if ($j -and ($tt -eq 'Schedule' -and (($got -replace '\s+', ' ').Trim() -eq $Cron)) -and (-not $ps -or $ps -in @('Succeeded', 'Failed', 'Canceled'))) { break }
            if ($j -and $ps -in @('Failed', 'Canceled')) { break }
            if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
        }
        if ($tt -ne 'Schedule' -or (($got -replace '\s+', ' ').Trim() -ne $Cron)) { return (& $fail ('read back: trigger {0}, timer "{1}"' -f $(if ($tt) { $tt } else { 'unknown' }), $got)) }
        & $out 'patched' ('pipeline runner: {0} had no timer -- put on its schedule "{1}" and read back (the pipeline starts by itself again; a queued run no longer waits)' -f $name, $Cron) $st.Why
    } catch {
        & $out 'failed' ('pipeline runner: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message) "$($_.Exception.Message)"
    }
}

function Get-SIJobFlowSetModeSql {
    <# PURE. #732: how the stored pipeline runs (cfg.JobFlow Mode), set ONLY through cfg.JobFlowSetMode (sql\si-pro-settings.sql;
       the engine role holds EXECUTE on it and no write right on the table). Returns one row: Updated (0 = none stored). #>
    'EXEC cfg.JobFlowSetMode @Mode = @Mode, @By = @By;'
}

function Get-SIJobFlowMigrationLastComplete {
    <#
        PURE. #732 migration: when the install last ran COMPLETELY under its own timers -- the OLDEST of the pipeline steps'
        newest succeeded execution start (every step ran at least that recently). $null when a step has never succeeded or
        no step was read. -Executions: job name -> its executions (ARM shape). -Steps: the pipeline's step job names.
    #>
    param([System.Collections.IDictionary]$Executions = @{}, [string[]]$Steps = @())
    $oldest = $null
    foreach ($s in @($Steps | Where-Object { $_ })) {
        $newest = $null
        foreach ($x in @($Executions[$s])) {
            if (-not $x) { continue }
            $p = if ($x.PSObject.Properties['properties']) { $x.properties } else { $x }
            if ([string]$p.status -ne 'Succeeded' -or -not $p.startTime) { continue }
            $t = ([datetime]$p.startTime).ToUniversalTime()
            if ($null -eq $newest -or $t -gt $newest) { $newest = $t }
        }
        if ($null -eq $newest) { return $null }
        if ($null -eq $oldest -or $newest -lt $oldest) { $oldest = $newest }
    }
    $oldest
}

function Invoke-SIJobFlowMigration {
    <#
        #732 (owner 2026-10-17: ONE method everywhere -- every install runs as the pipeline). EVERY UPDATE: an install that
        runs its jobs on their OWN timers (Get-SIFlowRunnerScheduleState 'schedules-mode') is moved to the pipeline (flow
        mode) -- the state a new install has -- in one step:
          0. the pipeline: the stored one (cfg.JobFlow) when there is one -- its Mode made 'flow', read back; none stored =
             the default pipeline over the installed jobs, exactly what a new install runs (setup stores none either);
          1. NEVER TWICE: only when no engine job (every caj-si-* job but the updater and the heartbeat; caj-si-flow too) has
             an execution Running / Processing and no pipeline run is going (cfg.FlowRun unfinished with a fresh
             heartbeat). Otherwise -- or when that cannot be read -- one line, nothing changed, the next update tries again;
          2. the jobs of the pipeline go MANUAL (their timer remembered in si-disabled-cron, exactly as a flow install has
             them; Get-SIJobOrchestrationSwitchPlan -Mode flow, ConvertTo-SIArmJobTrigger: the trigger and the tags only,
             everything else on the job kept), then caj-si-flow goes on its schedule ("*/5 * * * *");
          3. EVERYTHING READ BACK. Any step that fails, part-way: what this run changed is put BACK (timers on, caj-si-flow
             Manual, the stored mode as it was) -- the install keeps running on its timers. Should that put-back itself
             fail, the update's neither-mode repair that runs next (Invoke-SIJobOrchestrationRepair, on a fresh job list)
             puts caj-si-flow on its timer: never neither;
          4. NEVER A DAY SKIPPED: when the install's last COMPLETE run (Get-SIJobFlowMigrationLastComplete) is older than the
             pipeline's latest start time (Get-SIJobFlowLatestSlot), ONE pipeline run is queued (cfg.PipelineQueue, as "Run
             now"; requested by 'update'). Without the Pro database: said, not queued.
        -Rest: the update's REST seam { param($Method, $Uri, $Body, $Resource, $Headers) } -> @{ Status; Body }. -Sql: the Pro
        database { param($Query, $Params, $Mode) } ($null = none). -WhatIf (the update's -DetectOnly): the plan only, no
        change. One plain line per change. NEVER THROWS.
        Returns @{ State = not-needed | would-migrate | deferred | migrated | reverted | failed; Lines; Queued; Changed }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [AllowEmptyCollection()][object[]]$Jobs = @(), [scriptblock]$Sql, [switch]$WhatIf, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$PollSeconds = 5, [int]$PollMax = 12, [int]$StaleAfterMinutes = 15, $Map)
    $lines = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]
    $out = { param($s, [bool]$q = $false) [pscustomobject]@{ State = $s; Lines = $lines.ToArray(); Queued = $q; Changed = $changed.ToArray() } }
    try {
        if (-not $Map) { $Map = Get-SIJobFlowMap }
        $now = $NowUtc.ToUniversalTime()
        $list = ConvertTo-SIJobFlowTriggerList -ArmJobs $Jobs
        $st = Get-SIFlowRunnerScheduleState -Jobs $list -Map $Map
        if ($st.State -ne 'schedules-mode') { return (& $out 'not-needed') }
        $arm = 'https://management.azure.com/'
        $base = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup
        $api = '?api-version={0}' -f $script:SIJobFlow.ArmApi
        $call = {
            param([string]$Method, [string]$Uri, $Body)
            $r = $null
            try { $r = & $Rest $Method $Uri $Body $arm @{ 'Content-Type' = 'application/json' } } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
            if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }
            $r
        }
        $isOk = { param($r) $r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) if (-not $r -or -not "$($r.Body)".Trim()) { return $null }; $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; $o }
        $why = { param($r) $t = ("$(if ($r) { $r.Body })" -replace '\s+', ' ').Trim(); if ($t.Length -gt 200) { $t = $t.Substring(0, 197) + '...' }; ('HTTP {0}{1}' -f $(if ($r) { [int]$r.Status } else { 0 }), $(if ($t) { ": $t" } else { '' })) }
        $pre = 'switch to the pipeline:'

        # 0. the pipeline this install will run
        $store = $null; $stored = $null
        if ($Sql) {
            $store = New-SIJobFlowSqlStore -Invoke $Sql
            try { $stored = $store.ReadDefinition() } catch { $lines.Add(('{0} not now -- the stored pipeline could not be read ({1}); the next update tries again' -f $pre, $_.Exception.Message)); return (& $out 'deferred') }
        }
        $names = @($list | ForEach-Object { [string]$_.Name })
        $def = if ($stored) { ConvertFrom-SIJobFlowJson -Json $stored.Json } else { New-SIDefaultJobFlow -Installed $names -Map $Map }
        $def.Mode = 'flow'
        $all = Get-SIJobOrchestrationSwitchPlan -Jobs $list -Mode flow -Definition $def -Map $Map
        # timers OFF first, then caj-si-flow ON: in between nothing starts -- never a job twice
        $toManual = @($all | Where-Object { $_.Action -eq 'to-manual' })
        $toSched = @($all | Where-Object { $_.Action -eq 'to-schedule' })
        $steps = @(@($def.Steps) | ForEach-Object { 'caj-si-' + (Get-SIJobFlowKey ([string]$_.Job)) } | Where-Object { $names -contains $_ })

        # 1. never twice: nothing may be running
        $execs = @{}
        $watch = @($names | Where-Object { $_ -notin @('caj-si-updater', 'caj-si-heartbeat') })
        $busy = New-Object System.Collections.Generic.List[string]
        foreach ($n in $watch) {
            $r = & $call 'GET' ('{0}/{1}/executions{2}' -f $base, $n, $api) $null
            if (-not (& $isOk $r)) { $lines.Add(('{0} not now -- whether {1} is running could not be read ({2}); nothing was changed, the next update tries again' -f $pre, $n, (& $why $r))); return (& $out 'deferred') }
            $v = & $parse $r
            $ex = @(if ($v -and $v.PSObject.Properties['value']) { @($v.value) } else { @() })
            $execs[$n] = $ex
            if (@($ex | Where-Object { $_ -and ([string]$(if ($_.PSObject.Properties['properties']) { $_.properties.status } else { $_.status })) -in @('Running', 'Processing') }).Count) { $busy.Add($n) }
        }
        if ($store) {
            $last = $null
            try { $last = $store.Load() } catch { $lines.Add(('{0} not now -- the last pipeline run could not be read ({1}); nothing was changed, the next update tries again' -f $pre, $_.Exception.Message)); return (& $out 'deferred') }
            if ($last -and [string]$last.State -notin @('Succeeded', 'Failed', 'Stopped') -and $last.HeartbeatUtc -and ($now - ([datetime]$last.HeartbeatUtc).ToUniversalTime()).TotalMinutes -lt $StaleAfterMinutes) { $busy.Add(('the pipeline run {0}' -f $last.FlowRunId)) }
        }
        if ($busy.Count) {
            $lines.Add(('{0} not now -- running: {1}; nothing was changed (a job never runs twice), the next update tries again' -f $pre, ($busy -join ', ')))
            return (& $out 'deferred')
        }

        # 4 (decided now, done last). never a day skipped
        $slot = Get-SIJobFlowLatestSlot -Definition $def -NowUtc $now
        $lastComplete = Get-SIJobFlowMigrationLastComplete -Executions $execs -Steps $steps
        $needRun = [bool]($slot -and ($null -eq $lastComplete -or $lastComplete -lt $slot))
        $runWhy = if (-not $slot) { '' } elseif ($null -eq $lastComplete) { 'no complete run of every step is recorded' } else { 'the last complete run started {0:u}, before the pipeline''s start {1:u}' -f $lastComplete, $slot }

        if ($WhatIf) {
            $lines.Add(('{0} this install runs its jobs on their own timers -- the update moves it to the pipeline (re-run with -Apply):' -f $pre))
            if ($stored -and [string]$stored.Mode -ne 'flow') { $lines.Add(('{0} the stored pipeline would be set to run as the pipeline (it says ''{1}'')' -f $pre, $stored.Mode)) }
            foreach ($p in @($toManual + $toSched)) { $lines.Add(('{0} {1} would go {2}{3} -- {4}' -f $pre, $p.Job, $(if ($p.Action -eq 'to-manual') { 'Manual' } else { 'on its schedule' }), $(if ($p.Cron) { ' "' + $p.Cron + '"' } else { '' }), $p.Why)) }
            if ($needRun) { $lines.Add(('{0} one pipeline run would be queued -- {1}' -f $pre, $runWhy)) }
            return (& $out 'would-migrate')
        }

        # the put-back of whatever this run changed (timers on first, then caj-si-flow off, then the stored mode)
        $doneM = New-Object System.Collections.Generic.List[string]; $doneS = New-Object System.Collections.Generic.List[string]; $modeOld = $null
        $patch = {
            param([string]$Job, [string]$Action, [string]$Cron)
            $g = & $call 'GET' ('{0}/{1}{2}' -f $base, $Job, $api) $null
            if (-not (& $isOk $g)) { throw ('{0} could not be read ({1})' -f $Job, (& $why $g)) }
            $body = ConvertTo-SIArmJobTrigger -Job (& $parse $g) -Action $Action -Cron $Cron
            $p = & $call 'PATCH' ('{0}/{1}{2}' -f $base, $Job, $api) (ConvertTo-Json -InputObject $body -Depth 20 -Compress)
            if (-not (& $isOk $p)) { throw ('{0}: Azure refused it ({1})' -f $Job, (& $why $p)) }
        }
        $putBack = {
            param([string]$Cause)
            $bad = New-Object System.Collections.Generic.List[string]
            foreach ($j in @($doneM)) { try { & $patch $j 'to-schedule' ''; $lines.Add(('{0} {1} back on its own timer' -f $pre, $j)) } catch { $bad.Add($_.Exception.Message) } }
            foreach ($j in @($doneS)) { try { & $patch $j 'to-manual' ''; $lines.Add(('{0} {1} back to Manual' -f $pre, $j)) } catch { $bad.Add($_.Exception.Message) } }
            if ($null -ne $modeOld) {
                try { $null = & $Sql (Get-SIJobFlowSetModeSql) @{ Mode = $modeOld; By = 'update' } 'reader'; $lines.Add(('{0} the stored pipeline back to ''{1}''' -f $pre, $modeOld)) }
                catch { $bad.Add(('the stored pipeline mode: {0}' -f $_.Exception.Message)) }
            }
            if ($bad.Count) {
                $lines.Add(('{0} NOT done ({1}) and NOT fully put back ({2}) -- the neither-mode repair that runs next puts caj-si-flow on its timer; the next update tries again' -f $pre, $Cause, ($bad -join '; ')))
                return 'failed'
            }
            $lines.Add(('{0} NOT done ({1}) -- put back: the install runs on its own timers as before; the next update tries again' -f $pre, $Cause))
            'reverted'
        }

        # 0. the stored pipeline runs as the pipeline
        if ($stored -and [string]$stored.Mode -ne 'flow') {
            try {
                $null = & $Sql (Get-SIJobFlowSetModeSql) @{ Mode = 'flow'; By = 'update' } 'reader'
                $modeOld = [string]$stored.Mode
                $back = $store.ReadDefinition()
                if (-not $back -or [string]$back.Mode -ne 'flow') { throw ('it reads back ''{0}''' -f $(if ($back) { $back.Mode } else { 'nothing' })) }
                $lines.Add(('{0} the stored pipeline runs as the pipeline (was ''{1}'')' -f $pre, $modeOld))
            } catch { return (& $out (& $putBack ('the stored pipeline could not be set to run as the pipeline: {0}' -f $_.Exception.Message))) }
        }
        # 2. timers off, then caj-si-flow on
        foreach ($p in $toManual) {
            try { & $patch $p.Job 'to-manual' ''; $doneM.Add($p.Job); $changed.Add($p.Job); $lines.Add(('{0} {1} Manual -- a step of the pipeline now (its timer "{2}" remembered)' -f $pre, $p.Job, $p.Cron)) }
            catch { return (& $out (& $putBack $_.Exception.Message)) }
        }
        foreach ($p in $toSched) {
            try { & $patch $p.Job 'to-schedule' ([string]$p.Cron); $doneS.Add($p.Job); $changed.Add($p.Job); $lines.Add(('{0} {1} on its schedule "{2}"' -f $pre, $p.Job, $p.Cron)) }
            catch { return (& $out (& $putBack $_.Exception.Message)) }
        }
        # 3. read everything back
        $want = @{}; foreach ($j in $doneM) { $want[$j] = 'Manual' }; foreach ($j in $doneS) { $want[$j] = 'Schedule' }
        $wrong = @()
        for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
            $wrong = @()
            foreach ($j in @($want.Keys)) {
                $g = & $call 'GET' ('{0}/{1}{2}' -f $base, $j, $api) $null
                $o = if (& $isOk $g) { & $parse $g } else { $null }
                $tt = ''; try { $tt = [string]$o.properties.configuration.triggerType } catch { }
                if ($tt -ne $want[$j]) { $wrong += ('{0} reads back {1}' -f $j, $(if ($tt) { $tt } else { 'nothing' })) }
            }
            if (-not $wrong.Count) { break }
            if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
        }
        if ($wrong.Count) { return (& $out (& $putBack ('read back: {0}' -f ($wrong -join '; ')))) }
        $lines.Add(('{0} done and read back -- the install runs as the pipeline ({1} job(s) changed)' -f $pre, $changed.Count))

        # 4. never a day skipped
        $queued = $false
        if ($needRun) {
            if (-not $Sql) { $lines.Add(('{0} today''s pipeline run is not queued -- {1}, and this install has no Pro database for the queue; start it with Run now' -f $pre, $runWhy)) }
            else {
                try {
                    $ctl = New-SIPipelineSqlControl -Invoke $Sql
                    $q = $ctl.Enqueue((New-SIPipelineRequest -Scope pipeline -Trigger manual -RequestedBy 'update' -Note ('the switch to the pipeline: {0}' -f $runWhy) -RequestedUtc $now))
                    if ([string]$q.Outcome -eq 'Missing') { $lines.Add(('{0} today''s pipeline run is not queued -- the Pro database has no pipeline queue yet; start it with Run now' -f $pre)) }
                    else { $queued = $true; $lines.Add(('{0} one pipeline run queued (as Run now) -- {1}' -f $pre, $runWhy)) }
                } catch { $lines.Add(('{0} today''s pipeline run could not be queued ({1}) -- start it with Run now' -f $pre, $_.Exception.Message)) }
            }
        }
        & $out 'migrated' $queued
    } catch {
        $lines.Add(('switch to the pipeline: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
        & $out 'failed'
    }
}

function ConvertTo-SIArmJobTrigger {
    <#
        PURE. A Container Apps job as ARM returned it (GET, ConvertFrom-Json) turned into the PATCH body for -Action:
          to-manual    -- triggerType Manual, the cron remembered in the si-disabled-cron tag (exactly what the web app's
                          Disable does -- JobRules.Disabled in JobsClient.cs);
          to-schedule  -- triggerType Schedule with -Cron (default: the remembered one), the tag removed (JobRules.Enabled).
        The body carries ONLY what changes: { tags: <the job's tags plus/minus si-disabled-cron>, properties: { configuration:
        { triggerType, replicaTimeout, manualTriggerConfig | scheduleTriggerConfig } } } -- never the secrets, the template
        or anything else of the job. Why (#269, found live): ARM's GET returns secrets WITHOUT their values, so a PUT of the
        whole resource is refused for any job that has a secret (ContainerAppSecretInvalid -- the Pro jobs carry
        si-license). Send it with PATCH. The input is not changed.
    #>
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)][ValidateSet('to-manual', 'to-schedule')][string]$Action, [string]$Cron)
    $props = if ($Job.PSObject.Properties['properties']) { $Job.properties } else { $null }
    $cfg = if ($props -and $props.PSObject.Properties['configuration']) { $props.configuration } else { $null }
    if (-not $cfg) { throw 'the job has no configuration' }
    $tags = [ordered]@{}
    if ($Job.PSObject.Properties['tags'] -and $null -ne $Job.tags) {
        if ($Job.tags -is [System.Collections.IDictionary]) { foreach ($k in $Job.tags.Keys) { $tags[[string]$k] = [string]$Job.tags[$k] } }
        else { foreach ($p in $Job.tags.PSObject.Properties) { $tags[$p.Name] = [string]$p.Value } }
    }
    $par = 1; $rcc = 1
    $src = if ($cfg.PSObject.Properties['scheduleTriggerConfig'] -and $cfg.scheduleTriggerConfig) { $cfg.scheduleTriggerConfig } elseif ($cfg.PSObject.Properties['manualTriggerConfig'] -and $cfg.manualTriggerConfig) { $cfg.manualTriggerConfig } else { $null }
    if ($src) { if ($src.PSObject.Properties['parallelism'] -and $src.parallelism) { $par = $src.parallelism }; if ($src.PSObject.Properties['replicaCompletionCount'] -and $src.replicaCompletionCount) { $rcc = $src.replicaCompletionCount } }
    $c = [ordered]@{}
    if ($Action -eq 'to-manual') {
        if ([string]$cfg.triggerType -ne 'Schedule') { throw 'only a scheduled job can be moved off its timer' }
        $tags['si-disabled-cron'] = [string]$cfg.scheduleTriggerConfig.cronExpression
        $c.triggerType = 'Manual'
    } else {
        if (-not $Cron -and $tags.Contains('si-disabled-cron')) { $Cron = [string]$tags['si-disabled-cron'] }
        if ($Cron -notmatch '^[0-9*/,\-]{1,40}( [0-9*/,\-]{1,40}){4}$') { throw ("'{0}' is not a 5-field cron expression" -f $Cron) }
        $tags.Remove('si-disabled-cron')
        $c.triggerType = 'Schedule'
    }
    if ($cfg.PSObject.Properties['replicaTimeout'] -and $cfg.replicaTimeout) { $c.replicaTimeout = $cfg.replicaTimeout }
    if ($Action -eq 'to-manual') { $c.manualTriggerConfig = [ordered]@{ parallelism = $par; replicaCompletionCount = $rcc } }
    else { $c.scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = $par; replicaCompletionCount = $rcc } }
    ([ordered]@{ tags = $tags; properties = [ordered]@{ configuration = $c } } | ConvertTo-Json -Depth 10) | ConvertFrom-Json
}

function Get-SIAzErrorMessage {
    <#
        PURE. The readable reason from what a failed `az rest` printed (stderr + stdout lines): ARM's "<code>: <message>"
        when its error JSON is there (az prints e.g. ERROR: Bad Request({"error":{"code":"ContainerAppSecretInvalid",
        "message":"..."}}) or ERROR: (Code) message), else the text itself without az's "ERROR: " prefix. Max 800 chars.
    #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Lines = @())
    $t = (@($Lines | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) -join ' ').Trim()
    if (-not $t) { return '(az printed no error text)' }
    $code = if ($t -match '"code"\s*:\s*"([^"]{1,120})"') { $Matches[1] } elseif ($t -match '\((\w{3,120})\)') { $Matches[1] } else { '' }
    $msg = if ($t -match '"message"\s*:\s*"((?:[^"\\]|\\.){1,2000})"') { $Matches[1] -replace '\\"', '"' -replace '\\\\', '\' } else { ($t -replace '^(?i)ERROR:\s*', '' -replace '^\(\w{3,120}\)\s*', '') }
    $r = if ($code -and $msg -notmatch [regex]::Escape($code)) { '{0}: {1}' -f $code, $msg } else { $msg }
    if ($r.Length -gt 800) { $r = $r.Substring(0, 800) + '...' }
    $r
}

function Get-SIFlowTaskReplacePlan {
    <#
        PURE (VM). Which existing scheduled tasks the flow task replaces: a task whose action runs the launcher of a step of
        the flow (launcher\<folder>\launcher.*.ps1) -- never the updater's task (it runs on its own daily schedule) -- Risk Analysis
        -Summary / -Detailed told apart by the argument. -Tasks: @(@{ TaskPath; TaskName; State; Execute; Arguments }).
        Returns @(@{ Task (path + name); Job; State }) -- the setup step disables them (enabled ones only) and records them,
        and -Remove enables exactly those again.
    #>
    param([AllowEmptyCollection()][object[]]$Tasks = @(), [Parameter(Mandatory)]$Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $out = New-Object System.Collections.Generic.List[object]
    $steps = @(@($Definition.Steps) | ForEach-Object { [string]$_.Job })
    # #306: the risk trend's own task too -- Risk Analysis writes the daily trend row while the jobs run as a pipeline
    $steps += @(@($Map.Jobs.Keys) | Where-Object { $Map.Jobs[$_].ManualInFlowMode -and $steps -notcontains $_ })
    foreach ($t in @($Tasks | Where-Object { $_ })) {
        $cmd = ('{0} {1}' -f $t.Execute, $t.Arguments)
        if ($cmd -match '(?i)Invoke-SIJobFlowRun\.ps1') { continue }
        $job = $null
        if ($cmd -match '(?i)Update-SecurityInsight\.ps1') { $job = 'updater' }
        elseif ($cmd -match '(?i)[\\/]launcher[\\/]([a-z0-9\-]+)[\\/]launcher\.[a-z\-]+\.ps1') {
            $folder = $Matches[1].ToLowerInvariant()
            $job = switch ($folder) {
                'privilege-tier-classifier' { 'ptc' }
                'risk-analysis' { if ($cmd -match '(?i)-Detailed\b') { 'risk-analysis-detailed' } else { 'risk-analysis' } }
                default { $folder }
            }
        }
        if (-not $job -or $steps -notcontains $job -or (Test-SIJobFlowOwnSchedule -Job $job -Map $Map)) { continue }
        $out.Add([pscustomobject]@{ Task = ('{0}{1}' -f $t.TaskPath, $t.TaskName); TaskPath = [string]$t.TaskPath; TaskName = [string]$t.TaskName; Job = $job; State = [string]$t.State })
    }
    , $out.ToArray()
}

function Get-SIJobOrchestrationMode {
    <#
        PURE. flow | schedules. An explicit value (setting SI_JobOrchestration, a CLI parameter) wins; otherwise a NEW
        install (no SI job yet) gets 'flow' -- the default and the recommendation -- and an EXISTING install keeps its
        timers ('schedules') until someone switches. Returns @{ Mode; Why }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Explicit, [bool]$ExistingInstall,
          # the jobs that exist, with their triggers (ConvertTo-SIJobFlowTriggerList). ROOT CAUSE of "neither mode" (ring 2,
          # 2026-10-10: nothing ran for 14 h): a first install that stopped after creating the jobs of the pipeline (Manual,
          # in flow mode) but before caj-si-flow (created last) was re-run as an EXISTING install -> 'schedules' -> caj-si-flow
          # created Manual, its jobs left Manual. What the existing jobs ARE decides: none of the pipeline's jobs on a timer
          # (or caj-si-flow on its timer) = the install runs as the pipeline.
          [AllowEmptyCollection()][object[]]$ExistingJobs, $Map)
    $e = ([string]$Explicit).Trim().ToLowerInvariant()
    if ($e -in @('flow', 'schedules')) { return [pscustomobject]@{ Mode = $e; Why = 'set explicitly' } }
    if ($e) { return [pscustomobject]@{ Mode = $(if ($ExistingInstall) { 'schedules' } else { 'flow' }); Why = ("'{0}' is not flow or schedules -- ignored" -f $Explicit) } }
    if ($ExistingInstall -and @($ExistingJobs | Where-Object { $_ }).Count) {
        $chk = Test-SIJobOrchestrationNeitherMode -Jobs @($ExistingJobs | Where-Object { $_ }) -Map $Map
        $flowOn = @($ExistingJobs | Where-Object { $_ -and (Get-SIJobFlowKey ([string]$_.Name)) -eq 'flow' -and [string]$_.TriggerType -eq 'Schedule' }).Count
        if ($flowOn) { return [pscustomobject]@{ Mode = 'flow'; Why = 'the install runs as the pipeline (caj-si-flow is on its timer)' } }
        if ($chk.Steps -gt 0 -and $chk.Timed -eq 0) { return [pscustomobject]@{ Mode = 'flow'; Why = 'the jobs that exist run in the pipeline (none of them has its own timer) -- an earlier install that stopped half-way is completed as the pipeline' } }
    }
    if ($ExistingInstall) { return [pscustomobject]@{ Mode = 'schedules'; Why = 'an existing install keeps its timers until it is switched (Operations > Jobs recommends the flow)' } }
    [pscustomobject]@{ Mode = 'flow'; Why = 'a new install runs as one flow (the default)' }
}
