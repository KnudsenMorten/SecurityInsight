#Requires -Version 5.1
<#
    SecurityInsight -- PIPELINES and STAGES (#306), on top of the job flow runner (engine\_shared\SI-JobFlow.ps1, which
    dot-sources this file).

    Operator 2026-10-05: "profiling + risk analyse is what takes data in. Then we have a part 2 with data correlation and
    then we have a data out to sql, servicenow, etc." / "i want it to run as a single flow ... we can run subflows
    individually (run now) and we can appoint schedules to flows". Naming (operator): a flow is a PIPELINE, a subflow a
    STAGE; the default stages are Collect -> Correlate -> Deliver; the default pipeline is "Daily pipeline".

    This file holds:
      * the stage catalog and the schema-1 -> schema-2 migration (lossless: every step, enabled / timeout / on failure
        kept; known jobs go to their stage by the map, an unknown step stays in the stage of the step above it);
      * the stage GATE: a stage starts only when the stage before it has ENDED; when that stage did not succeed the stage
        is skipped (unless it is set to run anyway, runIfPreviousFailed), and Deliver NEVER starts after a Collect that
        did not succeed (working rule 4: nothing is published from a partial collection);
      * THE RUN GOES ON WITHOUT ONE SOURCE (owner 2026-10-12: "a source dropout should not block ci calculation, then use
        latest avail collection from the source"): a COLLECTION step (identity / azure / endpoint / publicip) that did not
        succeed while another collection of the same run did is a DROPOUT, not a failed Collect -- Correlate and Deliver
        run, with that source's records as its last good collection left them (Get-SIPipelineCollectVerdict). The step
        itself stays Failed. Every collection failing, or the tier classifier (a prerequisite, not a source), holds the
        run back as before;
      * ONE RUN LOCK per install and a persisted FIFO QUEUE (Pro: cfg.PipelineLock / cfg.PipelineQueue; a VM: two files
        in data\flow; a Community container: two blobs) -- every run, scheduled or "Run now" on a pipeline, a stage or a
        step, takes the same lock; a request that finds it busy waits in the queue (never dropped, never overlapping,
        the same request queued twice is kept once);
      * the drain (Invoke-SIPipelineDrain): what one wake-up of the runner does. PS 5.1 and 7.
#>

$script:SIPipeline = @{
    StageIds        = @('collect', 'correlate', 'deliver')
    StageNames      = @{ collect = 'Collect'; correlate = 'Correlate'; deliver = 'Deliver' }
    # what each stage is FOR, in the owner's words (2026-10-13): shown wherever a stage is a HEADING or part of the
    # overview ("Stage 2 of 3: Correlate (data structure)"). A sentence about one step keeps the short name above.
    # The same three as config\job-flow.locked.json ('title') and the web app's JobFlow.StageTitle.
    StageTitles     = @{ collect = 'Collect (data-in)'; correlate = 'Correlate (data structure)'; deliver = 'Deliver (data-out)' }
    # inside Deliver the targets are independent: a failed vulnerability connector does not skip the data sync or the mail
    StageOnFailure  = @{ collect = 'skip-dependents'; correlate = 'skip-dependents'; deliver = 'continue' }
    Scopes          = @('pipeline', 'stage', 'step', 'from-step')
    DefaultId       = 'daily'
    DefaultName     = 'Daily pipeline'
    LockStaleMinutes = 15
    # a RUN that has ended (#700: Cancelled = ended on purpose by a person or by the updater -- never resumed)
    RunFinished     = @('Succeeded', 'Failed', 'Stopped', 'Cancelled')
    # THE SOURCES: the Collect steps that each read one family of sources and write its records. A failed one is a DROPOUT
    # (the run goes on with its last good collection). The tier classifier (ptc) is NOT a source: it writes no records --
    # it builds the tier catalog every collection reads, so it stays a prerequisite (its failure skips the collections).
    SourceJobs      = @('identity', 'azure', 'endpoint', 'publicip')
}

# =====================================================================================================================
#  The pipeline's time zone (operator 2026-10-05: the Daily pipeline starts at a time of day in its time zone, all
#  year -- daylight saving included -- and the time and the zone can be changed; owner 2026-10-15: by default 23:30 Danish
#  time on every install, after the 23:00 update -- setup\_shared\SI-NightlySchedule.ps1)
# =====================================================================================================================
# IANA -> Windows for the common zones: Windows PowerShell 5.1 (.NET Framework) knows only the Windows ids. PowerShell 7
# (.NET 6+) knows both on Windows (ICU) and on Linux, so the map is the 5.1 fallback only.
$script:SIPipelineIanaToWindows = @{
    'Europe/Copenhagen' = 'Romance Standard Time'; 'Europe/Paris' = 'Romance Standard Time'; 'Europe/Brussels' = 'Romance Standard Time'; 'Europe/Madrid' = 'Romance Standard Time'
    'Europe/Berlin' = 'W. Europe Standard Time'; 'Europe/Amsterdam' = 'W. Europe Standard Time'; 'Europe/Oslo' = 'W. Europe Standard Time'; 'Europe/Stockholm' = 'W. Europe Standard Time'
    'Europe/Rome' = 'W. Europe Standard Time'; 'Europe/Vienna' = 'W. Europe Standard Time'; 'Europe/Zurich' = 'W. Europe Standard Time'
    'Europe/Warsaw' = 'Central European Standard Time'; 'Europe/Prague' = 'Central Europe Standard Time'; 'Europe/Budapest' = 'Central Europe Standard Time'
    'Europe/Helsinki' = 'FLE Standard Time'; 'Europe/Tallinn' = 'FLE Standard Time'; 'Europe/Riga' = 'FLE Standard Time'; 'Europe/Vilnius' = 'FLE Standard Time'
    'Europe/London' = 'GMT Standard Time'; 'Europe/Dublin' = 'GMT Standard Time'; 'Europe/Lisbon' = 'GMT Standard Time'; 'Atlantic/Reykjavik' = 'Greenwich Standard Time'
    'America/New_York' = 'Eastern Standard Time'; 'America/Chicago' = 'Central Standard Time'; 'America/Denver' = 'Mountain Standard Time'; 'America/Los_Angeles' = 'Pacific Standard Time'
    'America/Sao_Paulo' = 'E. South America Standard Time'; 'Asia/Tokyo' = 'Tokyo Standard Time'; 'Asia/Singapore' = 'Singapore Standard Time'; 'Asia/Kolkata' = 'India Standard Time'
    'Asia/Dubai' = 'Arabian Standard Time'; 'Australia/Sydney' = 'AUS Eastern Standard Time'; 'Pacific/Auckland' = 'New Zealand Standard Time'
    'UTC' = 'UTC'; 'Etc/UTC' = 'UTC'; 'Etc/GMT' = 'UTC'
}

function Resolve-SIPipelineTimeZone {
    <#
        PURE (over the machine's time zone database). A time zone by IANA id (Europe/Copenhagen) or Windows id (Romance
        Standard Time), on PS 5.1 and 7, Windows and Linux. Unknown or empty = UTC, said in .Why (the caller warns once).
        Returns @{ Zone = [TimeZoneInfo]; Id = what was asked; Fallback = $true when UTC stands in for an unknown id; Why }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    $want = ([string]$Id).Trim()
    if (-not $want -or $want -in @('UTC', 'Etc/UTC', 'Z')) { return [pscustomobject]@{ Zone = [TimeZoneInfo]::Utc; Id = 'UTC'; Fallback = $false; Why = '' } }
    $try = New-Object System.Collections.Generic.List[string]
    $try.Add($want)
    if ($script:SIPipelineIanaToWindows.ContainsKey($want)) { $try.Add($script:SIPipelineIanaToWindows[$want]) }
    foreach ($k in $script:SIPipelineIanaToWindows.Keys) { if ($script:SIPipelineIanaToWindows[$k] -eq $want -and -not $try.Contains($k)) { $try.Add($k) } }
    foreach ($t in $try) {
        try { $z = [TimeZoneInfo]::FindSystemTimeZoneById($t); return [pscustomobject]@{ Zone = $z; Id = $want; Fallback = $false; Why = '' } } catch { }
    }
    [pscustomobject]@{ Zone = [TimeZoneInfo]::Utc; Id = $want; Fallback = $true; Why = ("the time zone '{0}' is not known on this machine -- the pipeline's time is read as UTC" -f $want) }
}

function Get-SIPipelineTimeZoneId {
    <# PURE. The definition's time zone id ('UTC' when it has none -- a stored schedule from before time zones). #>
    param($Definition)
    if ($Definition -and $Definition.PSObject.Properties['TimeZone'] -and ([string]$Definition.TimeZone).Trim()) { return ([string]$Definition.TimeZone).Trim() }
    'UTC'
}

function ConvertTo-SIPipelineUtc {
    <#
        PURE. A local wall-clock time in -Zone as UTC. A time that does not exist that day (the spring-forward gap) runs
        when the clock reaches it: one hour later; a time that exists twice (the autumn fall-back) is its first occurrence.
    #>
    param([Parameter(Mandatory)][datetime]$Local, [Parameter(Mandatory)][TimeZoneInfo]$Zone)
    $l = [datetime]::SpecifyKind($Local, 'Unspecified')
    if ($Zone.IsInvalidTime($l)) { $l = $l.AddHours(1) }
    if ($Zone.IsAmbiguousTime($l)) {
        $offs = @($Zone.GetAmbiguousTimeOffsets($l) | Sort-Object -Descending)
        return [datetime]::SpecifyKind($l - $offs[0], 'Utc')
    }
    [TimeZoneInfo]::ConvertTimeToUtc($l, $Zone)
}

function Get-SIPipelineScheduleText {
    <# PURE. "22:00 Europe/Copenhagen (20:00 UTC today)" -- the start time with its zone and today's UTC time. #>
    param([Parameter(Mandatory)]$Definition, [datetime]$NowUtc = [datetime]::UtcNow)
    $tzId = Get-SIPipelineTimeZoneId $Definition
    if ($tzId -eq 'UTC') { return ('{0} UTC' -f $Definition.StartTime) }
    $z = (Resolve-SIPipelineTimeZone $tzId).Zone
    $h, $m = ([string]$Definition.StartTime) -split ':'
    $local = [TimeZoneInfo]::ConvertTimeFromUtc([datetime]::SpecifyKind($NowUtc.ToUniversalTime(), 'Utc'), $z).Date.AddHours([int]$h).AddMinutes([int]$m)
    $u = ConvertTo-SIPipelineUtc -Local $local -Zone $z
    '{0} {1} ({2:HH:mm} UTC today)' -f $Definition.StartTime, $tzId, $u
}

# =====================================================================================================================
#  Stages
# =====================================================================================================================
function Test-SIPipelineStageId {
    <# PURE. collect | correlate | deliver, or a custom stage: custom / custom-<a-z0-9>. #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    ([string]$Id) -match '^(collect|correlate|deliver|custom(-[a-z0-9]{1,24})?)$'
}

function Get-SIPipelineStageName {
    <# PURE. The stage's display name: Collect / Correlate / Deliver, else the id. #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    if ($script:SIPipeline.StageNames.ContainsKey([string]$Id)) { return $script:SIPipeline.StageNames[[string]$Id] }
    [string]$Id
}

function Get-SIPipelineStageTitle {
    <#
        PURE. The stage as a HEADING / in the overview: "Collect (data-in)", "Correlate (data structure)",
        "Deliver (data-out)". Decided from the stage ID, so an install whose STORED pipeline carries the name from before
        ("Collect") shows the new words without anything being rewritten. -Name is the stage's stored name: a name a
        person gave the stage themselves is kept as it is; a custom stage shows its own name (else its id).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Id, [AllowEmptyString()][AllowNull()][string]$Name)
    $k = ([string]$Id).Trim().ToLowerInvariant()
    $n = ([string]$Name).Trim()
    if (-not $script:SIPipeline.StageTitles.ContainsKey($k)) { if ($n) { return $n }; return [string]$Id }
    if (-not $n -or $n -ieq $script:SIPipeline.StageNames[$k] -or $n -ieq $script:SIPipeline.StageTitles[$k] -or $n -ieq $k) { return $script:SIPipeline.StageTitles[$k] }
    $n
}

function Get-SIPipelineStageOnFailure {
    <# PURE. What a step's failure does by default in this stage: Deliver -> continue (independent targets), else skip-dependents. #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    if ($script:SIPipeline.StageOnFailure.ContainsKey([string]$Id)) { return $script:SIPipeline.StageOnFailure[[string]$Id] }
    'skip-dependents'
}

function New-SIPipelineStage {
    param([Parameter(Mandatory)][string]$Id, [string]$Name, [bool]$RunIfPreviousFailed = $false)
    if (-not $Name) { $Name = Get-SIPipelineStageName $Id }
    [pscustomobject]@{ Id = $Id; Name = $Name; RunIfPreviousFailed = $RunIfPreviousFailed }
}

function Get-SIPipelineStageOf {
    <# PURE. The stage a job belongs to by the map ('stage'); '' when the map does not know the job. #>
    param([Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)]$Map)
    if ($Map.Jobs.Contains($Job) -and $Map.Jobs[$Job].PSObject.Properties['Stage']) { return [string]$Map.Jobs[$Job].Stage }
    ''
}

function ConvertFrom-SIPipelineSchema1 {
    <#
        PURE. A schema-1 flow (Steps without a stage) as a schema-2 pipeline -- LOSSLESS: every step stays, with its
        enabled / start together / on failure / timeout, in its order within its stage.
          * a job the map knows goes to the map's stage ('stage' in config\job-flow.locked.json);
          * an unknown (custom) step stays in the stage of the step above it (the first stage when it is first);
          * the stages run in the order collect -> correlate -> deliver (a custom stage is never invented here);
          * a step that started "together with the step above" keeps it when that step is still the one above it in
            the same stage, else it starts on its own (said in the notes);
          * on failure: a Deliver step that had the old default (skip-dependents) gets the Deliver default (continue --
            the operator's rule that the targets are independent); an explicit stop / continue is kept;
          * the risk trend (asset-trend) is kept as a step but switched off: Risk Analysis writes the daily trend row
            itself now (said in the notes).
        Returns the schema-2 definition with .Migrated = $true and .MigrationNotes.
    #>
    param([Parameter(Mandatory)]$Definition, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $notes = New-Object System.Collections.Generic.List[string]
    $byStage = [ordered]@{}
    foreach ($id in $script:SIPipeline.StageIds) { $byStage[$id] = New-Object System.Collections.Generic.List[object] }
    $prevStage = $script:SIPipeline.StageIds[0]
    $prevJob = ''
    foreach ($s in @($Definition.Steps)) {
        if ($null -eq $s) { continue }
        $job = [string]$s.Job
        $st = Get-SIPipelineStageOf -Job $job -Map $Map
        if (-not $st -or -not $byStage.Contains($st)) {
            $st = $prevStage
            $notes.Add(("{0} is not a job SecurityInsight ships: it stays in the stage of the step above it ({1})" -f $job, (Get-SIPipelineStageName $st)))
        }
        $with = [bool]$s.WithPrevious
        if ($with -and ($byStage[$st].Count -eq 0 -or [string]$byStage[$st][$byStage[$st].Count - 1].Job -ne $prevJob)) {
            $with = $false
            $notes.Add(("{0} started together with {1}; they are in different stages now, so it starts on its own" -f $job, $(if ($prevJob) { $prevJob } else { 'the step above' })))
        }
        $of = ([string]$s.OnFailure).ToLowerInvariant()
        if ($st -eq 'deliver' -and $of -eq 'skip-dependents') {
            $of = 'continue'
            $notes.Add(("{0} (Deliver): on failure is now 'continue' -- the Deliver targets are independent of each other" -f $job))
        }
        $en = [bool]$s.Enabled
        if ($job -eq 'asset-trend' -and $en) {
            $en = $false
            $notes.Add('asset-trend is kept but switched off: Risk Analysis writes the daily trend row itself now (switch it on only with SI_Trend_AtEndOfRiskAnalysis = $false)')
        }
        $byStage[$st].Add((New-SIJobFlowStep -Job $job -Enabled $en -WithPrevious $with -OnFailure $of -TimeoutMinutes ([int]$s.TimeoutMinutes) -Stage $st))
        $prevStage = $st; $prevJob = $job
    }
    $stages = @(foreach ($id in $script:SIPipeline.StageIds) { New-SIPipelineStage -Id $id })
    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($id in $script:SIPipeline.StageIds) { foreach ($x in $byStage[$id]) { $steps.Add($x) } }
    $d = New-SIPipelineDefinition -Id $script:SIPipeline.DefaultId -Name $script:SIPipeline.DefaultName -Mode ([string]$Definition.Mode) -StartTime ([string]$Definition.StartTime) `
        -Cadence ([string]$Definition.Cadence) -Weekday ([int]$Definition.Weekday) -IntervalMinutes ([int]$Definition.IntervalMinutes) -Stages $stages -Steps $steps.ToArray() `
        -TimeZone (Get-SIPipelineTimeZoneId $Definition)
    # a stored schedule keeps its time: before time zones every start time was UTC, so it stays UTC (shown converted)
    $d | Add-Member -NotePropertyName Migrated -NotePropertyValue $true -Force
    $d | Add-Member -NotePropertyName MigrationNotes -NotePropertyValue $notes.ToArray() -Force
    $d
}

function New-SIPipelineDefinition {
    <# The schema-2 definition object: Steps is the FLAT ordered list (each step carries its Stage), Stages the order. #>
    param([string]$Id = 'daily', [string]$Name = 'Daily pipeline', [string]$Mode = 'flow', [string]$StartTime = '01:00', [string]$Cadence = 'daily', [int]$Weekday = 1,
          [int]$IntervalMinutes = 1440, [AllowEmptyCollection()][object[]]$Stages = @(), [AllowEmptyCollection()][object[]]$Steps = @(),
          # the start time's zone (IANA or Windows id); 'UTC' = a schedule stored before time zones (it keeps its time)
          [string]$TimeZone = 'UTC',
          # the shipped default layout the pipeline has been brought to (Update-SIJobFlowDefaultLayout; the JSON's 'defaults'):
          # 1 = stored before the layout had levels -- every step one after the other
          [int]$DefaultsLevel = 1)
    if (-not $IntervalMinutes) { $IntervalMinutes = 1440 }
    if (-not $TimeZone) { $TimeZone = 'UTC' }
    if ($DefaultsLevel -lt 1) { $DefaultsLevel = 1 }
    [pscustomobject]@{ Schema = 2; Id = $Id; Name = $Name; Mode = $Mode; StartTime = $StartTime; TimeZone = $TimeZone; Cadence = $Cadence; Weekday = $Weekday; IntervalMinutes = $IntervalMinutes
                       Stages = @($Stages); Steps = @($Steps); Migrated = $false; MigrationNotes = @(); DefaultsLevel = $DefaultsLevel }
}

function Get-SIPipelineStages {
    <# PURE. The definition's stages in order (callers wrap in @()); a definition without .Stages (an old in-memory
       object) gets them from its steps. #>
    param([Parameter(Mandatory)]$Definition)
    if ($Definition.PSObject.Properties['Stages'] -and @($Definition.Stages).Count) { return @($Definition.Stages) }
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Definition.Steps)) { $sid = if ($s.PSObject.Properties['Stage'] -and $s.Stage) { [string]$s.Stage } else { 'collect' }; if (-not $ids.Contains($sid)) { $ids.Add($sid) } }
    foreach ($i in $ids) { New-SIPipelineStage -Id $i }
}

function Get-SIPipelineStepStage {
    <# PURE. A step's stage ('collect' when it has none -- a schema-1 object in memory). #>
    param($Step)
    if ($Step -and $Step.PSObject.Properties['Stage'] -and $Step.Stage) { return [string]$Step.Stage }
    'collect'
}

function Test-SIPipelineStages {
    <# PURE. The schema-2 checks: @{ Problems; Warnings } (Test-SIJobFlowDefinition adds them to its own). #>
    param([Parameter(Mandatory)]$Definition)
    $p = New-Object System.Collections.Generic.List[string]
    $w = New-Object System.Collections.Generic.List[string]
    $stages = @(Get-SIPipelineStages -Definition $Definition)
    $tz = Resolve-SIPipelineTimeZone (Get-SIPipelineTimeZoneId $Definition)
    if ($tz.Fallback) { $w.Add($tz.Why) }
    $seen = @{}
    $i = 0
    foreach ($st in $stages) {
        $i++
        $id = [string]$st.Id
        if (-not (Test-SIPipelineStageId $id)) { $p.Add(("stage {0}: '{1}' is not a stage (collect, correlate, deliver or custom-<name>)" -f $i, $id)); continue }
        if ($seen.ContainsKey($id)) { $p.Add(("stage {0}: {1} is already stage {2}" -f $i, $id, $seen[$id])); continue }
        $seen[$id] = $i
    }
    if ($seen.ContainsKey('collect') -and $seen.ContainsKey('deliver') -and $seen['deliver'] -lt $seen['collect']) { $p.Add('Deliver runs before Collect -- it would publish before the data is collected') }
    if ($seen.ContainsKey('correlate') -and $seen.ContainsKey('deliver') -and $seen['deliver'] -lt $seen['correlate']) { $w.Add('Deliver runs before Correlate -- it publishes the correlation of the run before') }
    $order = @{}; $k = 0; foreach ($st in $stages) { $k++; if (-not $order.ContainsKey([string]$st.Id)) { $order[[string]$st.Id] = $k } }
    $last = 0; $prevStage = ''
    $n = 0
    foreach ($s in @($Definition.Steps)) {
        $n++
        $sid = Get-SIPipelineStepStage $s
        if (-not $order.ContainsKey($sid)) { $p.Add(("step {0} ({1}): its stage '{2}' is not a stage of the pipeline" -f $n, $s.Job, $sid)); continue }
        if ($order[$sid] -lt $last) { $p.Add(("step {0} ({1}): the steps must be in stage order -- {2} comes before {3}" -f $n, $s.Job, (Get-SIPipelineStageName $sid), (Get-SIPipelineStageName $prevStage))) }
        if ($sid -ne $prevStage -and [bool]$s.WithPrevious -and $n -gt 1) { $w.Add(("step {0} ({1}) is the first of {2}: it cannot start together with a step of another stage -- it starts on its own" -f $n, $s.Job, (Get-SIPipelineStageName $sid))) }
        $last = $order[$sid]; $prevStage = $sid
    }
    [pscustomobject]@{ Problems = $p.ToArray(); Warnings = $w.ToArray() }
}

# =====================================================================================================================
#  The stage gate and the words
# =====================================================================================================================
function Get-SIPipelineStageOutcome {
    <#
        PURE. A stage's outcome in a run record: NotRun (none of its steps is part of this run -- a stage / step run, or
        the steps above a re-run), Waiting, Running, Succeeded (every step Success or Disabled), Failed (anything else
        ended: failed, timed out, interrupted, or skipped).
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Stage)
    $mine = @(@($State.Steps) | Where-Object { (Get-SIPipelineStepStage $_) -eq $Stage -and [string]$_.ErrorClass -ne 'before-rerun' })
    if (-not $mine.Count) { return 'NotRun' }
    if (@($mine | Where-Object { $_.State -in @('Running', 'Starting') }).Count) { return 'Running' }
    if (@($mine | Where-Object { $_.State -eq 'Waiting' }).Count) {
        if (@($mine | Where-Object { $_.State -ne 'Waiting' -and $_.State -ne 'Disabled' }).Count) { return 'Running' }
        return 'Waiting'
    }
    if (@($mine | Where-Object { $_.State -notin @('Success', 'Disabled') }).Count) { return 'Failed' }
    'Succeeded'
}

function Test-SIPipelineSourceJob {
    <# PURE. Is -Job a SOURCE -- a Collect step that reads one family of sources and writes its records (identity, azure,
       endpoint, publicip; a collection in parts is the same step)? The tier classifier and a custom step are not. #>
    param([AllowEmptyString()][AllowNull()][string]$Job)
    $k = ([string]$Job).Trim().ToLowerInvariant()
    if ($k.StartsWith('caj-si-')) { $k = $k.Substring(7) }
    $script:SIPipeline.SourceJobs -contains $k
}

function Get-SIPipelineCollectVerdict {
    <#
        PURE. What the Collect stage of this run was, from the steps that have ended:
          GoesOn    $true when the run goes on WITHOUT one or more sources: at least one collection step failed (Failed /
                    TimedOut / Interrupted), at least one collection step SUCCEEDED (there is something new to calculate),
                    nothing else in Collect went wrong (the tier classifier, a custom step, a collection that was skipped),
                    and no failed collection is set to stop the pipeline (the customer's saved "on failure: stop" is kept);
          Dropouts  the failed collection steps (the run's step records) when it goes on, else none;
          AnySource whether a collection step of this run succeeded (the runner asks this while Collect still runs).
        -Definition is optional: without it a saved "stop" cannot be seen (the runner has then stopped the pipeline anyway).
    #>
    param([Parameter(Mandatory)]$State, $Definition)
    $mine = @(@($State.Steps) | Where-Object { (Get-SIPipelineStepStage $_) -eq 'collect' -and [string]$_.ErrorClass -ne 'before-rerun' })
    $sources = @($mine | Where-Object { Test-SIPipelineSourceJob ([string]$_.Job) })
    $failed = @($sources | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') })
    $ok = @($sources | Where-Object { [string]$_.State -eq 'Success' })
    $failedJobs = @($failed | ForEach-Object { [string]$_.Job })
    $other = @($mine | Where-Object { [string]$_.State -notin @('Success', 'Disabled') -and $failedJobs -notcontains [string]$_.Job })
    $stop = $false
    if ($Definition) {
        foreach ($f in $failed) {
            $def = @(@($Definition.Steps) | Where-Object { [string]$_.Job -eq [string]$f.Job })[0]
            if ($def -and [string]$def.OnFailure -eq 'stop') { $stop = $true }
        }
    }
    $go = ($failed.Count -gt 0 -and $ok.Count -gt 0 -and $other.Count -eq 0 -and -not $stop)
    [pscustomobject]@{ GoesOn = $go; Dropouts = @(if ($go) { $failed }); AnySource = ($ok.Count -gt 0); Failed = $failed }
}

function Get-SIPipelineStageGate {
    <#
        PURE. May -Stage start in this run? @{ Run; Reason }. It starts when the stage before it (the nearest earlier stage
        that is part of this run) ended Succeeded. When that stage did not succeed, -Stage runs only when it is set to run
        anyway (RunIfPreviousFailed) -- and Deliver NEVER runs after a Collect of this run that did not succeed, whatever
        it is set to (working rule 4: nothing is published from a partial collection).
        A Collect that only LOST A SOURCE (Get-SIPipelineCollectVerdict: GoesOn) counts as succeeded here: the stages after
        it start, and the reason says which source the run goes on without.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Definition, [Parameter(Mandatory)][string]$Stage)
    $stages = @(Get-SIPipelineStages -Definition $Definition)
    $me = @($stages | Where-Object { [string]$_.Id -eq $Stage })[0]
    $idx = [array]::IndexOf(@($stages | ForEach-Object { [string]$_.Id }), $Stage)
    $verdict = Get-SIPipelineCollectVerdict -State $State -Definition $Definition
    if ($Stage -eq 'deliver') {
        $c = Get-SIPipelineStageOutcome -State $State -Stage 'collect'
        if ($c -notin @('NotRun', 'Succeeded') -and -not $verdict.GoesOn) {
            return [pscustomobject]@{ Run = $false; Reason = 'Collect did not succeed in this run -- nothing is delivered from a partial collection' }
        }
    }
    for ($i = $idx - 1; $i -ge 0; $i--) {
        $prev = [string]$stages[$i].Id
        $o = Get-SIPipelineStageOutcome -State $State -Stage $prev
        if ($o -eq 'NotRun') { continue }
        if ($o -eq 'Succeeded') { return [pscustomobject]@{ Run = $true; Reason = '' } }
        if ($prev -eq 'collect' -and $verdict.GoesOn) {
            return [pscustomobject]@{ Run = $true; Reason = ('Collect: {0} did not succeed -- {1} starts all the same, with the last good collection of that source' -f ((@($verdict.Dropouts | ForEach-Object { [string]$_.Job })) -join ', '), (Get-SIPipelineStageName $Stage)) }
        }
        if ($me -and [bool]$me.RunIfPreviousFailed) { return [pscustomobject]@{ Run = $true; Reason = ('{0} did not succeed; {1} is set to run anyway' -f (Get-SIPipelineStageName $prev), (Get-SIPipelineStageName $Stage)) } }
        return [pscustomobject]@{ Run = $false; Reason = ('{0} did not succeed -- {1} does not start' -f (Get-SIPipelineStageName $prev), (Get-SIPipelineStageName $Stage)) }
    }
    [pscustomobject]@{ Run = $true; Reason = '' }
}

function Get-SIPipelineMeasuredCadence {
    <#
        PURE. THE MEASURED CADENCE (owner 2026-10-12: "start when the last one ends"). The pipeline never runs twice at once:
        a scheduled start that finds a run still going is not lost and not doubled -- ONE start is owed, however many
        scheduled times passed, and it is made on the first wake-up after the run ended (Get-SIJobFlowDue: 'catch-up').
        So on an install whose full run takes longer than the schedule's interval, the data is refreshed as often as a
        run takes -- and that is said in plain words, with the measured numbers:
          -Previous: the last run record (a finished run of the WHOLE pipeline); -NowUtc: when the next run starts;
          -SlotUtc: the scheduled time that next run is for.
        Returns $null when the previous run fitted inside the schedule's interval (nothing to say), was not a run of the
        whole pipeline, or the schedule is 'interval' (it counts from the finish anyway). Else
        @{ RunHours; StartToStartHours; IntervalHours; Text } -- Text is what the run's note, its record and the web app show.
    #>
    param([Parameter(Mandatory)]$Definition, $Previous, [Parameter(Mandatory)][datetime]$NowUtc, $SlotUtc)
    if (-not $Previous -or -not $Previous.StartedUtc -or -not $Previous.EndedUtc) { return $null }
    if ([string]$Definition.Cadence -eq 'interval') { return $null }
    $scope = if ($Previous.PSObject.Properties['Scope'] -and $Previous.Scope) { [string]$Previous.Scope } else { 'pipeline' }
    if ($scope -ne 'pipeline') { return $null }
    $start = ([datetime]$Previous.StartedUtc).ToUniversalTime(); $end = ([datetime]$Previous.EndedUtc).ToUniversalTime(); $now = $NowUtc.ToUniversalTime()
    $slot = if ($SlotUtc) { ([datetime]$SlotUtc).ToUniversalTime() } else { Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $now }
    $interval = 24.0
    if ($slot) { $before = Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $slot.AddMinutes(-1); if ($before) { $interval = ($slot - $before).TotalHours } }
    $run = ($end - $start).TotalHours
    if ($run -le $interval) { return $null }
    $s2s = ($now - $start).TotalHours
    $inv = [Globalization.CultureInfo]::InvariantCulture
    [pscustomobject]@{ RunHours = [Math]::Round($run, 1); StartToStartHours = [Math]::Round($s2s, 1); IntervalHours = [Math]::Round($interval, 1)
        Text = ('At this size a full run takes about {0} hours, so data is refreshed about every {1} hours.' -f [Math]::Round($run).ToString($inv), [Math]::Round($s2s).ToString($inv)) }
}

function Get-SIPipelineHeldBackText {
    <#
        PURE. The plain sentence for a run that was HELD BACK: a collection step or the correlation did not succeed, so the
        steps after it did not run -- nothing goes out on incomplete data (working rule 4: absence is not remediation).
        '' when no step was held back. Says which step stopped it, how many steps did not run, whether anything was
        delivered, and that the data of the last good run stays in place (nothing is deleted or shown as fixed).
    #>
    param([Parameter(Mandatory)]$State)
    $held = @(@($State.Steps) | Where-Object { [string]$_.State -eq 'Skipped' -and [string]$_.ErrorClass -in @('stage-blocked', 'needs-failed', 'flow-stopped') })
    if (-not $held.Count) { return '' }
    # a run in which the steps that run on what is stored ran all the same has its own sentence (Get-SIPipelinePartialText):
    # it names the held steps too, and never says "the data of the last good run" on an install that has none
    if (Test-SIPipelinePartialRun -State $State) { return '' }
    # a source the run went on without did not hold it back: the step named is the one that did (the first other failure)
    $went = @((Get-SIPipelineCollectVerdict -State $State).Dropouts | ForEach-Object { [string]$_.Job })
    $bad = @(@($State.Steps) | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and $went -notcontains [string]$_.Job }) | Select-Object -First 1
    if (-not $bad) { $bad = @(@($State.Steps) | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') }) | Select-Object -First 1 }
    $what = if ($bad) { '{0} ({1}) did not succeed' -f $bad.Job, (Get-SIPipelineStageName (Get-SIPipelineStepStage $bad)) } else { 'an earlier step did not succeed' }
    $deliver = @(@($State.Steps) | Where-Object { (Get-SIPipelineStepStage $_) -eq 'deliver' })
    $out = @($deliver | Where-Object { [string]$_.State -notin @('Skipped', 'Disabled', 'Waiting') })
    $tail = if ($deliver.Count -and -not $out.Count) { ' and nothing was delivered from this run' } else { '' }
    'this run was held back: {0}, so {1} step(s) after it did not run{2} -- the data of the last good run stays in place' -f $what, $held.Count, $tail
}

# =====================================================================================================================
#  ONE FAILED STEP DOES NOT COST THE REST OF THE RUN (owner 2026-10-12: "we can not loose all data when one fail";
#  2026-10-13: "report it, but let it continue", and for a new install: "we nee to revisit that for the initial collection
#  flow" -- an install with no earlier good run was left EMPTY by "the data of the last good run stays in place").
#
#  The map (config\job-flow.locked.json) says per step which kind of need it has:
#    needs          the step reads the output of those steps OF THIS RUN -- it is held when one of them did not succeed;
#    runsOnStored   the step works on what is STORED and holds back by itself whatever is not complete (the data sync loads
#                   only collections whose run is shown complete, and closes no finding on a collection that is not; the
#                   verification service only reads). After a step of Correlate (the CI build, Risk Analysis) did not
#                   succeed, such a step still runs -- so the web app gets what the completed collections brought.
#  What does NOT change (working rule 4, absence is not remediation): a Collect that did not succeed still lets nothing
#  out; Risk Analysis never runs on a CI build that failed; the connectors that write to the customer's systems, the
#  vulnerability tickets and the daily mail stay held; a saved "on failure: stop" still stops the pipeline; delivery
#  still waits for a source that is too old. The run stays Failed in its record, its own run-health record is a WARNING
#  that names the failed step, what ran all the same and what was held.
# =====================================================================================================================
#
#  A NEW INSTALL'S FIRST COLLECTION (owner 2026-10-13, "wait for merged assets"): there is no last good run, and the
#  customer never sees unmerged or half-built assets. The first data view is the merged assets, so while the asset build
#  has not finished whole the data sync does not run either -- the run says "first collection, not complete yet" and names
#  the step that failed. Once the asset build is whole, a failed Risk Analysis no longer keeps the assets from the web app.
$script:SIPipelineStoredMark = 'on what is stored'
$script:SIPipelineFirstMark = 'first collection, not complete yet'
#  THE CONNECTORS NEED THE FINDINGS, NOT THE SUMMARY (owner 2026-10-13: "connectors only need detailed. connectors can
#  work if detailed is ok. summary is nice-to-have (mgmt friendly, good easy overview). detailed is what integrations
#  need"). The map marks Risk Analysis Summary 'niceToHave' and the CMDB connectors, the vulnerability connector, its
#  ServiceNow form and the data sync 'runsWithoutNiceToHave': when the ONLY steps that failed after Collect are
#  nice-to-have ones, those steps run IN FULL, on this run's own result -- the merged assets and the findings of this run
#  are whole. They stay held when Risk Analysis Detailed or the asset correlation did not succeed (anything that is not
#  nice-to-have failed), on an install's first collection, and the daily mail waits for a complete run.
$script:SIPipelineOwnMark = 'on this run''s own result'

function Get-SIPipelineStepBrings {
    <# PURE. What a failed or held step would have brought, as a person reads it -- the map's 'brings' ('' when the map
       says nothing of it: the step is then named by its own name only). #>
    param([AllowEmptyString()][AllowNull()][string]$Job, $Map)
    $k = Get-SIJobFlowKey $Job
    if ($Map -and $k -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['Brings']) { return [string]$Map.Jobs[$k].Brings }
    ''
}

function Test-SIPipelineAssetBuild {
    <# PURE. Is -Job the build of the merged assets (the map's 'assetBuild')? #>
    param([AllowEmptyString()][AllowNull()][string]$Job, $Map)
    $k = Get-SIJobFlowKey $Job
    [bool]($Map -and $k -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['AssetBuild'] -and [bool]$Map.Jobs[$k].AssetBuild)
}

function Test-SIPipelineGoOnAfterFailedStep {
    <# PURE. The setting SI_Pro_Pipeline_GoOnAfterFailedStep: on unless it is set to false / 0 / no / off (then every step
       after a failed one is held as before). #>
    param($Value = $global:SI_Pro_Pipeline_GoOnAfterFailedStep)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return [bool]$Value }
    -not (([string]$Value).Trim().Trim('$') -match '^(?i)(false|0|no|off)$')
}

function Get-SIPipelineStoredDataRun {
    <#
        PURE. A step that would be HELD (its stage does not start, or a step it needs did not succeed): may it run all the
        same, on what is stored? @{ Run; Reason }. Yes only when ALL of this holds:
          * the map marks the step 'runsOnStored';
          * the Collect of this run is good -- it succeeded, it is not part of this run, or it only lost a source
            (Get-SIPipelineCollectVerdict: GoesOn). After a Collect that did not succeed nothing is let out, as before;
          * what failed comes AFTER Collect (a step of Correlate / Deliver / a custom stage);
          * no failed step is set to stop the pipeline (the customer's saved "on failure: stop" is kept).
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Definition, $Map, [Parameter(Mandatory)][string]$Job,
          # A NEW INSTALL'S FIRST COLLECTION (owner 2026-10-13: "wait for merged assets"): the customer never sees a
          # half-built asset list. When the asset build itself failed and the install has no earlier complete data, a step
          # that rests on the asset build (the data sync) does NOT run -- the answer says so (FirstHeld, with the plain
          # reason); a step that does not rest on it (the verification service) still runs.
          [switch]$FirstRun)
    $no = [pscustomobject]@{ Run = $false; Reason = ''; FirstHeld = $false }
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $k = Get-SIJobFlowKey $Job
    if (-not $Map.Jobs.Contains($k) -or -not $Map.Jobs[$k].PSObject.Properties['RunsOnStored'] -or -not [bool]$Map.Jobs[$k].RunsOnStored) { return $no }
    $verdict = Get-SIPipelineCollectVerdict -State $State -Definition $Definition
    if ((Get-SIPipelineStageOutcome -State $State -Stage 'collect') -notin @('NotRun', 'Succeeded') -and -not $verdict.GoesOn) { return $no }
    $bad = @(@($State.Steps) | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and (Get-SIPipelineStepStage $_) -ne 'collect' })
    if (-not $bad.Count) { return $no }
    foreach ($b in $bad) {
        $def = @(@($Definition.Steps) | Where-Object { [string]$_.Job -eq [string]$b.Job })[0]
        if ($def -and [string]$def.OnFailure -eq 'stop') { return $no }
    }
    if ($FirstRun -and @($bad | Where-Object { Test-SIPipelineAssetBuild -Job ([string]$_.Job) -Map $Map }).Count) {
        $rests = $false
        $seen = @{}; $queue = New-Object System.Collections.Generic.Queue[string]; $queue.Enqueue($k)
        while ($queue.Count -and -not $rests) {
            $x = $queue.Dequeue(); if ($seen.ContainsKey($x)) { continue }; $seen[$x] = $true
            if (-not $Map.Jobs.Contains($x)) { continue }
            foreach ($n in @($Map.Jobs[$x].Needs)) { if (Test-SIPipelineAssetBuild -Job ([string]$n) -Map $Map) { $rests = $true; break }; $queue.Enqueue([string]$n) }
        }
        if ($rests) { return [pscustomobject]@{ Run = $false; FirstHeld = $true; Reason = ('{0}: the asset build did not finish, so the assets are not shown yet -- they are shown when the build has finished whole' -f $script:SIPipelineFirstMark) } }
    }
    [pscustomobject]@{ Run = $true; FirstHeld = $false; Reason = ('{0} did not succeed in this run -- {1} runs all the same, {2}: it holds back whatever is not complete and closes nothing' -f ((@($bad | ForEach-Object { [string]$_.Job })) -join ', '), $k, $script:SIPipelineStoredMark) }
}

function Test-SIPipelineNiceToHave {
    <# PURE. Is -Job a nice-to-have step (the map's 'niceToHave': its failure holds only the steps that need it)? #>
    param([AllowEmptyString()][AllowNull()][string]$Job, $Map)
    $k = Get-SIJobFlowKey $Job
    [bool]($Map -and $k -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['NiceToHave'] -and [bool]$Map.Jobs[$k].NiceToHave)
}

function Get-SIPipelineOwnResultRun {
    <#
        PURE. A step whose STAGE does not start because the stage before it did not succeed: may it run all the same, IN
        FULL, on this run's own result? @{ Run; Reason }. Yes only when ALL of this holds:
          * the map marks the step 'runsWithoutNiceToHave' (the CMDB connectors, the vulnerability connector, its
            ServiceNow form, the data sync -- never the daily mail);
          * the Collect of this run is good (as Get-SIPipelineStoredDataRun);
          * a step of the stages between Collect and this step's own stage failed, and EVERY step that failed there is a
            nice-to-have one (Risk Analysis Summary) -- so Risk Analysis Detailed and the asset correlation did not fail
            (a failure inside the step's own stage is judged as in every run: by the step's needs);
          * every other step of the stages before this step's stage ended well (Success, or switched off) -- nothing the
            step rests on was held, timed out or left out;
          * no failed step is set to stop the pipeline (the customer's saved "on failure: stop" is kept).
        The caller holds the step all the same when a step it NEEDS failed, and on an install's first collection.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Definition, $Map, [Parameter(Mandatory)][string]$Job)
    $no = [pscustomobject]@{ Run = $false; Reason = '' }
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $k = Get-SIJobFlowKey $Job
    if (-not $Map.Jobs.Contains($k) -or -not $Map.Jobs[$k].PSObject.Properties['RunsWithoutNiceToHave'] -or -not [bool]$Map.Jobs[$k].RunsWithoutNiceToHave) { return $no }
    $verdict = Get-SIPipelineCollectVerdict -State $State -Definition $Definition
    if ((Get-SIPipelineStageOutcome -State $State -Stage 'collect') -notin @('NotRun', 'Succeeded') -and -not $verdict.GoesOn) { return $no }
    # the stages before this step's own stage (a failure INSIDE its own stage is judged as in every run: by its needs)
    $stages = @(Get-SIPipelineStages -Definition $Definition | ForEach-Object { [string]$_.Id })
    $mine = @(@($State.Steps) | Where-Object { (Get-SIJobFlowKey ([string]$_.Job)) -eq $k })[0]
    $myStage = if ($mine) { Get-SIPipelineStepStage $mine } else { Get-SIPipelineStageOf -Job $k -Map $Map }
    $at = [array]::IndexOf($stages, [string]$myStage)
    if ($at -lt 0) { return $no }
    $bad = @(@($State.Steps) | Where-Object {
        $i = [array]::IndexOf($stages, [string](Get-SIPipelineStepStage $_))
        [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and (Get-SIPipelineStepStage $_) -ne 'collect' -and $i -ge 0 -and $i -lt $at })
    if (-not $bad.Count) { return $no }
    foreach ($b in $bad) {
        if (-not (Test-SIPipelineNiceToHave -Job ([string]$b.Job) -Map $Map)) { return $no }
        $def = @(@($Definition.Steps) | Where-Object { [string]$_.Job -eq [string]$b.Job })[0]
        if ($def -and [string]$def.OnFailure -eq 'stop') { return $no }
    }
    # every other step of those stages ended well
    $badJobs = @($bad | ForEach-Object { [string]$_.Job })
    foreach ($s in @($State.Steps)) {
        $sStage = [string](Get-SIPipelineStepStage $s)
        if ($sStage -eq 'collect' -or [string]$s.ErrorClass -eq 'before-rerun') { continue }
        $i = [array]::IndexOf($stages, $sStage)
        if ($i -lt 0 -or $i -ge $at) { continue }
        if ($badJobs -contains [string]$s.Job) { continue }
        if ([string]$s.State -notin @('Success', 'Disabled')) { return $no }
    }
    $what = @($bad | ForEach-Object { Get-SIPipelineStepBrings -Job ([string]$_.Job) -Map $Map } | Where-Object { $_ } | Select-Object -Unique)
    [pscustomobject]@{ Run = $true; Reason = ('{0} did not succeed in this run -- {1} runs all the same, {2}: the findings and the merged assets of this run are whole, and it does not need {3}' -f ($badJobs -join ', '), $k, $script:SIPipelineOwnMark, $(if ($what.Count) { $what -join '; ' } else { 'what the failed step brings' })) }
}

function Get-SIPipelineWentOnSteps {
    <# PURE. The steps of this run that RAN ALL THE SAME after another step failed: on what is stored, or in full on this
       run's own result (the runner keeps the reason in the step's own record). -Kind stored | own | any. #>
    param([Parameter(Mandatory)]$State, [ValidateSet('any', 'stored', 'own')][string]$Kind = 'any')
    $marks = @(if ($Kind -in @('any', 'stored')) { $script:SIPipelineStoredMark }; if ($Kind -in @('any', 'own')) { $script:SIPipelineOwnMark })
    @(@($State.Steps) | Where-Object {
        $s = $_
        $s.PSObject.Properties['RetryReason'] -and [string]$s.State -notin @('Skipped', 'Waiting', 'Disabled') -and
        @($marks | Where-Object { [string]$s.RetryReason -like ('*' + $_ + '*') }).Count -gt 0 })
}

function Test-SIPipelineWentOn {
    <# PURE. Did a step of this run run all the same after another step failed (on what is stored, or in full on this
       run's own result)? -AllSucceeded: ... and every such step succeeded. #>
    param([Parameter(Mandatory)]$State, [switch]$AllSucceeded)
    $ran = @(Get-SIPipelineWentOnSteps -State $State)
    if (-not $ran.Count) { return $false }
    if ($AllSucceeded) { return (@($ran | Where-Object { [string]$_.State -ne 'Success' }).Count -eq 0) }
    $true
}

function Get-SIPipelineWentOnAfter {
    <# PURE. The failed step(s) THIS RUN WENT ON AFTER, in the run's order: failed / timed out / interrupted, not a source
       the run went on without (it has its own sentence) and not a step that itself ran all the same. None when the run
       did not go on after a failed step. The run's report names the first of them (the warning that opens a fix request). #>
    param([Parameter(Mandatory)]$State, $Definition)
    if (-not (Test-SIPipelinePartialRun -State $State)) { return @() }
    $went = @((Get-SIPipelineCollectVerdict -State $State -Definition $Definition).Dropouts | ForEach-Object { [string]$_.Job })
    $ranJobs = @(Get-SIPipelineWentOnSteps -State $State | ForEach-Object { [string]$_.Job })
    @(@($State.Steps) | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and $went -notcontains [string]$_.Job -and $ranJobs -notcontains [string]$_.Job })
}

function Test-SIPipelinePartialRun {
    <# PURE. Is this a run in which one failed step did not cost the rest -- a step ran on what is stored, or (a first
       collection whose asset build failed) a step was held with the first collection's own reason? Such a run has its own
       sentence (Get-SIPipelinePartialText) instead of "held back ... the data of the last good run stays in place". #>
    param([Parameter(Mandatory)]$State)
    if (Test-SIPipelineWentOn -State $State) { return $true }
    @(@($State.Steps) | Where-Object { [string]$_.State -eq 'Skipped' -and [string]$_.Error -like ($script:SIPipelineFirstMark + ':*') }).Count -gt 0
}

function Test-SIPipelineRanOnStored {
    <# PURE. Did a step of this run run on what is stored after another step failed (the runner keeps the reason in the
       step's own record)? -AllSucceeded: ... and every such step succeeded. #>
    param([Parameter(Mandatory)]$State, [switch]$AllSucceeded)
    $ran = @(@($State.Steps) | Where-Object { $_.PSObject.Properties['RetryReason'] -and [string]$_.RetryReason -like ('*' + $script:SIPipelineStoredMark + '*') -and [string]$_.State -notin @('Skipped', 'Waiting', 'Disabled') })
    if (-not $ran.Count) { return $false }
    if ($AllSucceeded) { return (@($ran | Where-Object { [string]$_.State -ne 'Success' }).Count -eq 0) }
    $true
}

function Get-SIPipelinePartialText {
    <#
        PURE. The plain sentence of a run in which ONE FAILED STEP DID NOT COST THE REST: which step did not succeed, which
        steps ran all the same on what is stored, what is therefore missing or not from this run, and which steps were
        held and why. '' when no step ran on what is stored. Never says the run is whole, never says anything was fixed.
          -FirstRun  the install has no earlier complete data: "first collection, not complete yet: ..." -- there is no
                     last good run to fall back on, so the sentence never claims one;
          -Short     the run's own note (the pipeline page; its column holds 400).
    #>
    param([Parameter(Mandatory)]$State, $Definition, [switch]$FirstRun, [switch]$Short, $Map)
    if (-not (Test-SIPipelinePartialRun -State $State)) { return '' }
    $steps = @($State.Steps)
    $went = @((Get-SIPipelineCollectVerdict -State $State -Definition $Definition).Dropouts | ForEach-Object { [string]$_.Job })
    $ranAll = @($steps | Where-Object { $_.PSObject.Properties['RetryReason'] -and [string]$_.RetryReason -like ('*' + $script:SIPipelineStoredMark + '*') -and [string]$_.State -notin @('Skipped', 'Waiting', 'Disabled') })
    $ranJobs = @($ranAll | ForEach-Object { [string]$_.Job })
    $ran = @($ranAll | Where-Object { [string]$_.State -eq 'Success' } | ForEach-Object { [string]$_.Job })
    $ranBad = @($ranAll | Where-Object { [string]$_.State -ne 'Success' } | ForEach-Object { [string]$_.Job })
    # the steps that ran in full on this run's own result (only nice-to-have steps failed)
    $ownAll = @(Get-SIPipelineWentOnSteps -State $State -Kind own)
    $ownJobs = @($ownAll | ForEach-Object { [string]$_.Job })
    $ownOk = @($ownAll | Where-Object { [string]$_.State -eq 'Success' } | ForEach-Object { [string]$_.Job })
    $ownBad = @($ownAll | Where-Object { [string]$_.State -ne 'Success' } | ForEach-Object { [string]$_.Job })
    $bad = @($steps | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and $went -notcontains [string]$_.Job -and $ranJobs -notcontains [string]$_.Job -and $ownJobs -notcontains [string]$_.Job })
    $held = @($steps | Where-Object { [string]$_.State -eq 'Skipped' -and [string]$_.ErrorClass -in @('stage-blocked', 'needs-failed', 'flow-stopped') })
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    # a first collection whose asset build failed: no asset list is shown at all (never a half-built one)
    $buildFailed = @($bad | Where-Object { Test-SIPipelineAssetBuild -Job ([string]$_.Job) -Map $Map }).Count -gt 0
    $wordOf = {
        param($s)
        if ($FirstRun -and $buildFailed -and (Test-SIPipelineAssetBuild -Job ([string]$s.Job) -Map $Map)) { 'the asset list (its build did not finish)' }
        else { Get-SIPipelineStepBrings -Job ([string]$s.Job) -Map $Map }
    }
    $brings = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($bad) + @($held)) {
        $w = [string](& $wordOf $s)
        if ($w -and -not $brings.Contains($w)) { $brings.Add($w) }
    }
    $missing = if ($brings.Count) { $brings -join '; ' } else { 'what the failed step would have brought' }
    if ($Short) {
        # the note holds 400 and carries other sentences too: what the FAILED step brings is named, the rest in four words
        $own = New-Object System.Collections.Generic.List[string]
        foreach ($s in @($bad)) { $w = [string](& $wordOf $s); if ($w -and -not $own.Contains($w)) { $own.Add($w) } }
        $missing = if ($own.Count) { $own -join '; ' } else { 'what the failed step would have brought' }
        if ($held.Count) { $missing += ' and what the held steps bring' }
    }
    $badShort = (@($bad | ForEach-Object { [string]$_.Job })) -join ', '
    $badLong = (@($bad | ForEach-Object { '{0} ({1})' -f $_.Job, (Get-SIPipelineStageName (Get-SIPipelineStepStage $_)) })) -join ', '
    $ranText = if ($ran.Count) { $ran -join ', ' } else { 'no step' }
    $heldJobs = (@($held | ForEach-Object { [string]$_.Job })) -join ', '
    if ($ownAll.Count) {
        # only nice-to-have steps failed: the connectors and the data sync ran in full, on this run's own result
        $ownText = if ($ownOk.Count) { $ownOk -join ', ' } else { 'no step' }
        $ownAlso = if ($ownBad.Count) { (' {0} was started {1} and did not succeed.' -f ($ownBad -join ', '), $script:SIPipelineOwnMark) } else { '' }
        if ($Short) {
            return ('this run is not complete: {0} did not succeed; from the last good run, not from this one: {1}; {2} ran in full, {3}{4}; {5} step(s) held; nothing was closed because of the failed step.' -f $badShort, $missing, $ownText, $script:SIPipelineOwnMark,
                $(if ($ran.Count) { ('; {0} ran {1}' -f ($ran -join ', '), $script:SIPipelineStoredMark) } else { '' }), $held.Count)
        }
        return ('this run is not complete: {0} did not succeed. {1} ran in full, {2}: the findings and the merged assets of this run are whole, and these steps do not need what the failed step brings; this is from the last good run, not from this one: {3}.{4}{5}{6}{7} Nothing was closed and no ticket was changed because of the failed step: what is missing is unknown, not resolved.' -f $badLong, $ownText, $script:SIPipelineOwnMark, $missing,
            $(if ($ran.Count) { (' {0} ran {1}.' -f ($ran -join ', '), $script:SIPipelineStoredMark) } else { '' }), $ownAlso,
            $(if ($ranBad.Count) { (' {0} was started on what is stored and did not succeed either.' -f ($ranBad -join ', ')) } else { '' }),
            $(if ($held.Count) { (' Held until a run is complete: {0}.' -f $heldJobs) } else { '' }))
    }
    if ($Short) {
        if ($FirstRun -and $buildFailed) {
            return ('{0}: {1} did not succeed; missing: {2}; the assets are shown when their build has finished whole; {3} step(s) held; nothing was closed.' -f $script:SIPipelineFirstMark, $badShort, $missing, $held.Count)
        }
        if ($FirstRun) {
            return ('{0}: {1} did not succeed; missing: {2}; {3} ran, so the assets that were built whole are shown; {4} step(s) held; nothing was closed.' -f $script:SIPipelineFirstMark, $badShort, $missing, $ranText, $held.Count)
        }
        return ('this run is not complete: {0} did not succeed; from the last good run, not from this one: {1}; {2} ran {3}; {4} step(s) held; nothing was closed.' -f $badShort, $missing, $ranText, $script:SIPipelineStoredMark, $held.Count)
    }
    $heldText = if ($held.Count) { (' Held, because they need the result of this run: {0}.' -f $heldJobs) } else { '' }
    $alsoBad = if ($ranBad.Count) { (' {0} was started on what is stored and did not succeed either.' -f ($ranBad -join ', ')) } else { '' }
    $never = ' Nothing was closed, no ticket was changed and no mail was sent because of the failed step: what is missing is unknown, not resolved.'
    # a first collection's failed step was started again before the run gave up on it: said once, after everything else
    $again = @($bad | Where-Object { (Get-SIPipelineFirstRunRestartCount -Step $_) -gt 0 } | ForEach-Object { '{0} was started again {1} time(s) on this first collection, carrying on from what it finished, and did not succeed' -f $_.Job, (Get-SIPipelineFirstRunRestartCount -Step $_) })
    $againText = if ($again.Count) { ' ' + ($again -join '; ') + '.' } else { '' }
    if ($FirstRun -and $buildFailed) {
        return ('{0}: {1} did not succeed. Missing: {2}. The assets are shown when their build has finished whole -- no unmerged and no half-built asset list is shown, and there is no earlier run to fall back on.{3}{4}{5}{6}{7}' -f $script:SIPipelineFirstMark, $badLong, $missing,
            $(if ($ran.Count) { (' {0} ran all the same.' -f $ranText) } else { '' }), $alsoBad, $heldText, $never, $againText)
    }
    if ($FirstRun) {
        return ('{0}: {1} did not succeed. Missing: {2}. {3} ran all the same, so the web app shows the assets that were built whole -- without what is missing; there is no earlier run to fall back on.{4}{5}{6}{7}' -f $script:SIPipelineFirstMark, $badLong, $missing, $ranText, $alsoBad, $heldText, $never, $againText)
    }
    'this run is not complete: {0} did not succeed. {1} ran all the same, {2}, so the web app has what the completed collections brought; this is from the last good run, not from this one: {3}.{4}{5}{6}' -f $badLong, $ranText, $script:SIPipelineStoredMark, $missing, $alsoBad, $heldText, $never
}

function Get-SIPipelineWhoActsText {
    <# PURE. Who must act on the failed step, from its error class (engine\_shared\SI-ErrorClass.ps1: Get-SIErrorFixKind):
       the customer for a permission, licence or setting of the install; the vendor for everything else. #>
    param([AllowEmptyString()][AllowNull()][string]$ErrorClass)
    # a step stopped from outside the pipeline (an update, a roll, a person) or cancelled on purpose is nobody's fault
    if ("$ErrorClass" -in @('stopped', 'cancelled')) { return 'who must act: nobody -- the step was stopped from outside the pipeline on purpose, not a failure; start the pipeline again when it should run' }
    $kind = ''
    if (Get-Command -Name Get-SIErrorFixKind -ErrorAction SilentlyContinue) { $kind = [string](Get-SIErrorFixKind -ErrorClass $ErrorClass) }
    if ($kind -eq 'customer-config') { return 'who must act: you -- the failed step names a permission, a licence or a setting of this install that is missing (see the failed step''s own log)' }
    'who must act: the vendor of SecurityInsight -- the failed step is a fault of the product, not of your setup; nothing has to be done here'
}

function Get-SIPipelineFirstRunSql {
    <# The one guarded statement that answers "has this install no complete findings collection yet?" (1 = none). #>
    "SET NOCOUNT ON; SELECT CASE WHEN OBJECT_ID(N'sidata.Collection') IS NULL THEN 1 WHEN EXISTS (SELECT 1 FROM sidata.Collection WHERE Status = N'Complete') THEN 0 ELSE 1 END;"
}

function Test-SIPipelineFirstRun {
    <# Has this install NO earlier complete data to fall back on (no complete collection in its database)? -Invoke is the
       database seam (sql, params, mode). Throws when it cannot be read -- the caller then does not claim a first run. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    ([int](& $Invoke (Get-SIPipelineFirstRunSql) @{} 'scalar')) -eq 1
}

# =====================================================================================================================
#  THE FIRST RUN OF A NEW INSTALL IS ITS OWN FLOW (owner 2026-10-13: "we nee to revisit that for the initial collection
#  flow"). An install is on its FIRST COLLECTION while its database holds no complete collection (Test-SIPipelineFirstRun).
#  His answers, and what the runner does with each:
#    "Wait for merged assets"  nothing is shown before the asset build has finished whole (Get-SIPipelineStoredDataRun
#                              -FirstRun holds the data sync until then); the moment it has, the data sync runs AT ONCE,
#                              on what is stored -- the merged assets are the first data view, and the findings follow
#                              when Risk Analysis has finished. The run's note says which of the three it is at.
#    "Two restarts"            a step that fails or is stopped is started again at once (it carries on from what it
#                              finished), up to SI_Pro_Pipeline_FirstRunRestarts times (default 2); then the run ends with
#                              a warning that names the step and who must act, and the run's report goes to Invardia.
#    "whole collections only"  what reaches the web app is always a whole collection, marked with what is still missing.
#  NOT COMPROMISED BY ANY OF IT (owner 2026-10-13: "we also agreed upon rules against servicenow and cmdb that must not
#  be compromized after the first run"): the delivery at once holds every output (the data sync is told it runs on what
#  is stored, the mark of Part "one failed step"); a step that writes to a CMDB, to ServiceNow or to a ticket is never
#  started again by this and never started early; the connectors' own guards (refuse an incomplete run, refuse an empty
#  desired set, the closure ceilings, match-only, never create, never from a provisional id) are not touched.
# =====================================================================================================================
$script:SIPipelineFirstRestartMark = 'first collection: started again'
$script:SIPipelineFirstRunningMark = 'first collection running'

function Get-SIPipelineFirstRunRestarts {
    <# PURE. The setting SI_Pro_Pipeline_FirstRunRestarts: how many times a failed step of a first collection is started
       again (default 2; 0 = never; anything that is not a whole number of 0 or more = the default). #>
    param($Value = $global:SI_Pro_Pipeline_FirstRunRestarts)
    $n = 0
    if ($null -eq $Value -or -not [int]::TryParse(([string]$Value).Trim(), [ref]$n) -or $n -lt 0) { return 2 }
    $n
}

function Test-SIPipelineRestsOnAssetBuild {
    <# PURE. Does -Job rest on the build of the merged assets (the map's 'assetBuild' is one of its needs, directly or
       through another step)? #>
    param([AllowEmptyString()][AllowNull()][string]$Job, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $k = Get-SIJobFlowKey $Job
    $seen = @{}; $queue = New-Object System.Collections.Generic.Queue[string]; $queue.Enqueue([string]$k)
    while ($queue.Count) {
        $x = $queue.Dequeue(); if ($seen.ContainsKey($x)) { continue }; $seen[$x] = $true
        if (-not $Map.Jobs.Contains($x)) { continue }
        foreach ($n in @($Map.Jobs[$x].Needs)) { if (Test-SIPipelineAssetBuild -Job ([string]$n) -Map $Map) { return $true }; $queue.Enqueue([string]$n) }
    }
    $false
}

function Test-SIPipelineFirstRunRestartStep {
    <# PURE. May a failed step be STARTED AGAIN on a first collection? Only a step that collects or correlates, or one
       that runs on what is stored (the data sync, the verification service). NEVER a step that writes to the customer's
       systems, changes a ticket or sends a mail: those are started once, behind a complete run, as in every run. #>
    param([Parameter(Mandatory)]$Step, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $k = Get-SIJobFlowKey ([string]$Step.Job)
    if ((Get-SIPipelineStepStage $Step) -in @('collect', 'correlate')) { return $true }
    [bool]($Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['RunsOnStored'] -and [bool]$Map.Jobs[$k].RunsOnStored)
}

function Get-SIPipelineFirstRunRestartCount {
    <# PURE. How many times this step was started again on this first collection (the runner keeps each in the step's own
       record, so a resumed run counts the same). #>
    param([Parameter(Mandatory)]$Step)
    if (-not $Step.PSObject.Properties['RetryReason']) { return 0 }
    [regex]::Matches([string]$Step.RetryReason, [regex]::Escape($script:SIPipelineFirstRestartMark)).Count
}

function Get-SIPipelineFirstRunRestartText {
    <# PURE. The plain line for one restart on a first collection. #>
    param([Parameter(Mandatory)][string]$Job, [AllowEmptyString()][string]$Why, [int]$Restart = 1, [int]$Of = 2)
    if ($Why.Length -gt 160) { $Why = $Why.Substring(0, 160) + ' ...' }   # the step's record holds 1000, and every restart is kept in it
    '{0} ({1} of {2}) -- {3} did not succeed{4}; it carries on from what it finished' -f $script:SIPipelineFirstRestartMark, $Restart, $Of, (Get-SIJobFlowKey $Job), $(if ($Why) { ' (' + $Why + ')' } else { '' })
}

function Get-SIPipelineFirstDeliveryStep {
    <# PURE. The step that shows the merged assets AT ONCE when the asset build of a first collection has finished whole:
       the first step of this run that still waits, runs on what is stored and rests on the asset build (the data sync).
       $null when there is none (it is not installed, switched off, or not part of this run). #>
    param([Parameter(Mandatory)]$State, $Map)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    @(@($State.Steps) | Where-Object {
        $k = Get-SIJobFlowKey ([string]$_.Job)
        [string]$_.State -eq 'Waiting' -and $Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['RunsOnStored'] -and [bool]$Map.Jobs[$k].RunsOnStored -and
        (Test-SIPipelineRestsOnAssetBuild -Job $k -Map $Map) } | Select-Object -First 1)[0]
}

function Get-SIPipelineFirstRunText {
    <#
        PURE. The words of a first collection, one per moment:
          Running       the run's note while nothing is shown yet;
          DeliveryWhy   the reason kept in the data sync's record while it runs at once after the asset build (it carries
                        the "on what is stored" words, so the data sync holds every output);
          Delivered     the merged assets are in the web app, the findings follow;
          NotDelivered  the delivery at once did not succeed -- the step runs again at its own place;
          Complete      the first collection ended whole.
    #>
    param([Parameter(Mandatory)][ValidateSet('Running', 'DeliveryWhy', 'Delivered', 'NotDelivered', 'Complete')][string]$Kind, [string]$Job = 'asset-datasync', [string]$Stage = '')
    $k = Get-SIJobFlowKey $Job
    switch ($Kind) {
        'Running'      { '{0}: nothing is shown before the asset build has finished whole -- then the merged assets, then the findings.' -f $script:SIPipelineFirstRunningMark }
        'DeliveryWhy'  { 'first collection: the asset build finished whole -- {0} runs at once, {1}, so the merged assets are shown while the rest of the run goes on: it holds back whatever is not complete, closes nothing and sends nothing to an output' -f $k, $script:SIPipelineStoredMark }
        'Delivered'    { '{0}: the merged assets are in the web app now ({1} ran at once after the asset build; nothing was closed and nothing was sent to an output) -- the findings follow when Risk Analysis has finished.' -f $script:SIPipelineFirstRunningMark, $k }
        'NotDelivered' { '{0}: the merged assets could not be shown yet ({1} did not succeed when it ran at once after the asset build) -- it runs again at its own place in this run.' -f $script:SIPipelineFirstRunningMark, $k }
        'Complete'     { 'first collection complete: the merged assets and the findings are in the web app.' }
    }
}

function Get-SIPipelineWentOnText {
    <#
        PURE. The plain sentence for a run that WENT ON WITHOUT A SOURCE: a collection step did not succeed, the steps after
        it ran all the same, and that source's data is what its last good collection left -- nothing of it is shown as gone
        or fixed (absence is not remediation). '' when the run lost no source, or was held back at Collect instead.
        Each dropped step may carry .LastGoodUtc (the runner sets it: when that source last collected completely); without
        it the sentence says "its last good collection" and no date. Times are UTC.
          this run went on without endpoint: its data is from 2026-10-10 14:05 UTC, because its last collection did not complete
    #>
    param([Parameter(Mandatory)]$State, $Definition)
    $drop = @((Get-SIPipelineCollectVerdict -State $State -Definition $Definition).Dropouts)
    if (-not $drop.Count) { return '' }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $when = {
        param($s)
        $t = $null
        if ($s.PSObject.Properties['LastGoodUtc'] -and $s.LastGoodUtc) { try { $t = ([datetime]$s.LastGoodUtc).ToUniversalTime() } catch { $t = $null } }
        if ($t) { $t.ToString('yyyy-MM-dd HH:mm', $inv) + ' UTC' } else { 'its last good collection' }
    }
    if ($drop.Count -eq 1) {
        return ('this run went on without {0}: its data is from {1}, because its last collection did not complete' -f $drop[0].Job, (& $when $drop[0]))
    }
    'this run went on without {0}: {1} -- their last collections did not complete' -f ((@($drop | ForEach-Object { [string]$_.Job })) -join ', '),
        ((@($drop | ForEach-Object { '{0} data is from {1}' -f $_.Job, (& $when $_) })) -join '; ')
}

function Get-SIPipelineStatusText {
    <#
        PURE. The run in words: "Daily pipeline - Stage 2 of 3: Correlate (data structure)" while it runs, "Daily pipeline -
        succeeded" when it ended; a stage run "Daily pipeline - Stage 3 of 3: Deliver (data-out) (run now)", a step run
        "... - step Data sync". The stage is named as in the overview's headings (Get-SIPipelineStageTitle).
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Definition)
    $name = if ($Definition.PSObject.Properties['Name'] -and $Definition.Name) { [string]$Definition.Name } else { $script:SIPipeline.DefaultName }
    $stages = @(Get-SIPipelineStages -Definition $Definition)
    $ids = @($stages | ForEach-Object { [string]$_.Id })
    $scope = if ($State.PSObject.Properties['Scope'] -and $State.Scope) { [string]$State.Scope } else { 'pipeline' }
    $target = if ($State.PSObject.Properties['Target']) { [string]$State.Target } else { '' }
    $finished = [string]$State.State -in $script:SIPipeline.RunFinished
    $cur = ''
    if (-not $finished) {
        foreach ($id in $ids) { if ((Get-SIPipelineStageOutcome -State $State -Stage $id) -in @('Running', 'Waiting')) { $cur = $id; break } }
    } elseif ($scope -eq 'stage') { $cur = $target }
    $where = ''
    if ($scope -eq 'step') { $where = ('step {0}' -f $target) }
    elseif ($cur) {
        $curStage = @($stages | Where-Object { [string]$_.Id -eq $cur })[0]
        $curName = if ($curStage -and $curStage.PSObject.Properties['Name']) { [string]$curStage.Name } else { '' }
        $where = ('Stage {0} of {1}: {2}' -f ([array]::IndexOf($ids, $cur) + 1), $ids.Count, (Get-SIPipelineStageTitle -Id $cur -Name $curName))
    }
    $tail = if ($finished) { [string]$State.State.ToLowerInvariant() } else { '' }
    # #532: a run whose only failures were steps Microsoft throttled reads 'throttled', never 'failed' (the web app says the same)
    if ($finished -and (Get-Command -Name Test-SIJobFlowThrottledOnly -ErrorAction SilentlyContinue) -and (Test-SIJobFlowThrottledOnly -State $State)) { $tail = 'throttled' }
    $parts = @($name) + @(@($where, $tail) | Where-Object { $_ })
    # the middle dot as a code point: Windows PowerShell 5.1 reads a file without a byte-order mark as ANSI
    ($parts -join (' {0} ' -f [char]0x00B7)) + $(if ($scope -ne 'pipeline' -and $scope -ne 'from-step') { ' (run now)' } else { '' })
}

# =====================================================================================================================
#  Requests, the queue and the lock
# =====================================================================================================================
function New-SIPipelineRequest {
    <#
        PURE. One request to run: -Scope pipeline (the whole pipeline) | stage (-Target = the stage id) | step (-Target =
        the job) | from-step (the pipeline from -Target on). -Trigger schedule | catch-up | interval | manual; -SlotUtc: the
        time-of-day slot a scheduled request is for (it is then recorded as run).
    #>
    param([Parameter(Mandatory)][ValidateSet('pipeline', 'stage', 'step', 'from-step')][string]$Scope, [string]$Target = '', [string]$Trigger = 'manual',
          [string]$RequestedBy = '', $SlotUtc, [string]$Note = '', $RequestedUtc)
    if ($Scope -eq 'pipeline') { $Target = '' }
    elseif (-not $Target) { throw ("a {0} request names what it runs" -f $Scope) }
    if ($Scope -in @('step', 'from-step')) { $Target = Get-SIJobFlowKey $Target }
    if ($Target -and $Target -notmatch '^[a-z0-9][a-z0-9\-]{0,63}$') { throw ("'{0}' is not a stage or a step" -f $Target) }
    if ($null -eq $RequestedUtc) { $RequestedUtc = [datetime]::UtcNow }
    [pscustomobject]@{ Id = 0; Scope = $Scope; Target = [string]$Target; Trigger = $Trigger; RequestedBy = [string]$RequestedBy; RequestedUtc = $RequestedUtc
                       SlotUtc = $SlotUtc; Note = $Note; State = 'Queued'; FlowRunId = ''; Outcome = '' }
}

function Get-SIPipelineRequestKey {
    <# PURE. Two queued requests with the same key are the same request (it is kept once): scope + target. #>
    param([Parameter(Mandatory)]$Request)
    ('{0}|{1}' -f ([string]$Request.Scope).ToLowerInvariant(), ([string]$Request.Target).ToLowerInvariant())
}

function Get-SIPipelineRequestText {
    <# PURE. "the pipeline" / "stage Correlate" / "step asset-datasync" / "the pipeline from asset-datasync". #>
    param([Parameter(Mandatory)]$Request)
    switch ([string]$Request.Scope) {
        'stage' { 'stage {0}' -f (Get-SIPipelineStageName $Request.Target) }
        'step' { 'step {0}' -f $Request.Target }
        'from-step' { 'the pipeline from {0}' -f $Request.Target }
        default { 'the pipeline' }
    }
}

function Test-SIPipelineRequest {
    <# PURE. $null when -Request can run against -Definition, else why not (an unknown stage / step). #>
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Definition)
    switch ([string]$Request.Scope) {
        'stage' { if (-not @(@(Get-SIPipelineStages -Definition $Definition) | Where-Object { [string]$_.Id -eq [string]$Request.Target }).Count) { return ("'{0}' is not a stage of the pipeline" -f $Request.Target) } }
        { $_ -in @('step', 'from-step') } { if (-not @(@($Definition.Steps) | Where-Object { [string]$_.Job -eq [string]$Request.Target }).Count) { return ("'{0}' is not a step of the pipeline" -f $Request.Target) } }
    }
    $null
}

function Get-SIPipelinePendingSlot {
    <#
        PURE. While a run holds the install (a manual run, or a long one), is a time-of-day slot of the schedule waiting
        for it? The slot is then QUEUED (catch-up: it runs once when the lock is free). @{ SlotUtc; Note } or $null. An
        interval schedule never queues (its next run is counted from the finish).
    #>
    param([Parameter(Mandatory)]$Definition, $Previous, [Parameter(Mandatory)][datetime]$NowUtc, [int]$FirstRunWindowMinutes = 15)
    if ([string]$Definition.Cadence -eq 'interval') { return $null }
    $slot = Get-SIJobFlowLatestSlot -Definition $Definition -NowUtc $NowUtc
    if (-not $slot) { return $null }
    # the slot that has run: the run's own, or one a manual run covered (Get-SIJobFlowSlotRun)
    $last = if ($Previous) { Get-SIJobFlowSlotRun -Definition $Definition -Previous $Previous } else { $null }
    if ($last -and ([datetime]$last).ToUniversalTime() -ge $slot) { return $null }
    if (-not $last -and ($NowUtc.ToUniversalTime() - $slot).TotalMinutes -gt $FirstRunWindowMinutes) { return $null }
    $who = if ($Previous) { ('run {0}' -f $Previous.FlowRunId) } else { 'another run' }
    [pscustomobject]@{ SlotUtc = $slot; Note = ('the {0:u} start waited in the queue: {1} was still running' -f $slot, $who) }
}

function ConvertTo-SIPipelineJsonArray {
    <# PURE. A JSON array of -Items (each through ConvertTo-Json): PS 5.1 never collapses a one-element list. #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Items = @(), [int]$Depth = 6)
    '[' + ((@($Items | Where-Object { $null -ne $_ }) | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth $Depth -Compress }) -join ',') + ']'
}

function ConvertFrom-SIPipelineRequestRow {
    <# PURE. A queue row (SQL reader hashtable / JSON object) as a request object. #>
    param($Row)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { $Row = [pscustomobject]$Row }
    $g = { param($n, $d) if ($Row.PSObject.Properties[$n] -and $null -ne $Row.$n -and -not ($Row.$n -is [DBNull])) { $Row.$n } else { $d } }
    $t = { param($v) if ($null -eq $v -or "$v" -eq '') { $null } elseif ($v -is [datetime]) { $v.ToUniversalTime() } else { [datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } }
    [pscustomobject]@{ Id = [long](& $g 'Id' 0); Scope = [string](& $g 'Scope' 'pipeline'); Target = [string](& $g 'Target' ''); Trigger = [string](& $g 'Trg' (& $g 'Trigger' 'manual'))
                       RequestedBy = [string](& $g 'RequestedBy' ''); RequestedUtc = (& $t (& $g 'RequestedUtc' $null)); SlotUtc = (& $t (& $g 'SlotUtc' $null)); Note = [string](& $g 'Note' '')
                       State = [string](& $g 'State' 'Queued'); FlowRunId = [string](& $g 'FlowRunId' ''); Outcome = [string](& $g 'Outcome' '') }
}

# ---- Pro: cfg.PipelineLock + cfg.PipelineQueue over the (sql, params, mode) -Invoke seam ----------------------------
function Get-SIPipelineSqlText {
    <# The T-SQL of the Pro lock + queue (one place; the LocalSql test runs it against sql\si-pro-settings.sql). #>
    param([Parameter(Mandatory)][ValidateSet('Acquire', 'Heartbeat', 'Release', 'Lock', 'ReleaseRun', 'Enqueue', 'Next', 'MarkRunning', 'MarkDone', 'Cancel', 'List')][string]$Name)
    switch ($Name) {
        'Acquire' { @'
IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT CAST(NULL AS nvarchar(128)) AS Holder, CAST(NULL AS nvarchar(200)) AS What, CAST(NULL AS datetime2) AS AcquiredUtc, CAST(NULL AS datetime2) AS HeartbeatUtc, CAST(NULL AS nvarchar(128)) AS PreviousHolder, -1 AS Mine; RETURN; END
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = N'install') INSERT cfg.PipelineLock (LockId) VALUES (N'install');
DECLARE @prev nvarchar(128) = (SELECT Holder FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = N'install');
UPDATE cfg.PipelineLock
   SET Holder = @Holder, What = @What, FlowRunId = NULL,
       AcquiredUtc = CASE WHEN Holder = @Holder THEN AcquiredUtc ELSE SYSUTCDATETIME() END, HeartbeatUtc = SYSUTCDATETIME()
 WHERE LockId = N'install' AND (Holder IS NULL OR Holder = @Holder OR HeartbeatUtc IS NULL OR HeartbeatUtc < DATEADD(minute, -@StaleMinutes, SYSUTCDATETIME()));
SELECT Holder, What, AcquiredUtc, HeartbeatUtc, CASE WHEN @prev = @Holder THEN NULL ELSE @prev END AS PreviousHolder, CASE WHEN Holder = @Holder THEN 1 ELSE 0 END AS Mine
  FROM cfg.PipelineLock WHERE LockId = N'install';
COMMIT;
'@ }
        'Heartbeat' { "UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), FlowRunId = @FlowRunId, What = @What WHERE LockId = N'install' AND Holder = @Holder; SELECT @@ROWCOUNT AS Held;" }
        'Release' { "IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N'install' AND Holder = @Holder;" }
        # #700: who holds the lock now, and for which run
        'Lock' { "IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL SELECT Holder, What, FlowRunId, HeartbeatUtc FROM cfg.PipelineLock WHERE LockId = N'install';" }
        # #700: the lock of ONE run, released at once when that run is cancelled (whoever holds it for that run)
        'ReleaseRun' { "IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT 0 AS Released; RETURN; END UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N'install' AND Holder IS NOT NULL AND FlowRunId = @FlowRunId; SELECT @@ROWCOUNT AS Released;" }
        'Enqueue' { @'
IF OBJECT_ID(N'cfg.PipelineQueue') IS NULL BEGIN SELECT CAST(0 AS bigint) AS Id, N'Missing' AS Outcome; RETURN; END
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id bigint = (SELECT TOP (1) Id FROM cfg.PipelineQueue WITH (UPDLOCK, HOLDLOCK) WHERE PipelineId = N'daily' AND Scope = @Scope AND Target = @Target AND State = N'Queued' ORDER BY Id);
IF @id IS NOT NULL
BEGIN
    UPDATE cfg.PipelineQueue SET SlotUtc = COALESCE(SlotUtc, @SlotUtc), Note = CASE WHEN Note IS NULL OR Note = N'' THEN @Note ELSE Note END WHERE Id = @id;
    COMMIT; SELECT @id AS Id, N'Deduplicated' AS Outcome; RETURN;
END
INSERT cfg.PipelineQueue (PipelineId, Scope, Target, Trg, RequestedBy, SlotUtc, Note) VALUES (N'daily', @Scope, @Target, @Trg, @RequestedBy, @SlotUtc, @Note);
SET @id = CAST(SCOPE_IDENTITY() AS bigint);
COMMIT;
SELECT @id AS Id, N'Queued' AS Outcome;
'@ }
        'Next' { "IF OBJECT_ID(N'cfg.PipelineQueue') IS NOT NULL SELECT TOP (1) Id, Scope, Target, Trg, RequestedBy, RequestedUtc, SlotUtc, Note, State, FlowRunId, Outcome FROM cfg.PipelineQueue WHERE PipelineId = N'daily' AND State = N'Queued' ORDER BY Id;" }
        # live 2026-10-19 (ring 2): the runner names itself (the session's 'si.pipeline.holder') -- the schema's trigger
        # cfg.TR_PipelineQueue_Claim lets a request be taken only by the runner that holds the install's lock, so a runner of
        # older code that outlived its stop or an update never starts the next queued run
        'MarkRunning' { "EXEC sys.sp_set_session_context @key = N'si.pipeline.holder', @value = @Holder; UPDATE cfg.PipelineQueue SET State = N'Running', FlowRunId = @FlowRunId, StartedUtc = SYSUTCDATETIME() WHERE Id = @Id AND State = N'Queued'; SELECT @@ROWCOUNT AS Taken;" }
        'MarkDone' { "UPDATE cfg.PipelineQueue SET State = N'Done', Outcome = @Outcome, EndedUtc = SYSUTCDATETIME() WHERE Id = @Id AND State IN (N'Queued', N'Running');" }
        'Cancel' { "UPDATE cfg.PipelineQueue SET State = N'Cancelled', CancelledBy = @By, EndedUtc = SYSUTCDATETIME() WHERE Id = @Id AND State = N'Queued'; SELECT @@ROWCOUNT AS Cancelled;" }
        'List' { "IF OBJECT_ID(N'cfg.PipelineQueue') IS NOT NULL SELECT Id, Scope, Target, Trg, RequestedBy, RequestedUtc, SlotUtc, Note, State, FlowRunId, Outcome FROM cfg.PipelineQueue WHERE PipelineId = N'daily' AND State IN (N'Queued', N'Running') ORDER BY Id;" }
    }
}

# =====================================================================================================================
#  #913 (the ride test install 2026-10-27, 3.0.0.202610261957): the runner's wake-up failed in AcquireLock on
#  "Exception calling "Close" ... Error code 9001" (Azure SQL: the log is not available -- a transient) and went to Invardia
#  as a product defect with a red alert, though no run was affected. The LOCK calls (open, acquire, beat, release, close --
#  each one statement on its own connection) now treat the Azure SQL transients like the published-copy ranges do (#890 (4)):
#  the call again after 2, 4, 8, 16, 30 s (about a minute); only then it fails, tagged transient-sql (never product-defect).
#  Every lock statement is idempotent for its holder (Acquire / Heartbeat / Release name the holder), so a call that ran and
#  lost only its Close is safe to send again.
# =====================================================================================================================
$script:SIPipelineLockRetry = @{
    Waits   = @(2, 4, 8, 16, 30)
    # 9001 log not available; 40613 / 40501 / 40197 / 49918-49920 the database or the service busy, moving or not available;
    # 4060 cannot open the database (during a failover); 10928 / 10929 resource limits; 10053 / 10054 / 233 / 64 a reset
    # or closed connection; -2 a client timeout
    Numbers = @(9001, 40613, 40501, 40197, 49918, 49919, 49920, 4060, 10928, 10929, 10053, 10054, 233, 64, -2)
    Pattern = '(?i)\b(9001|40613|40501|40197|49918|49919|49920|10928|10929)\b|log for database .* is not available|is not currently available|transport-level error|connection was forcibly closed|forcibly closed by the remote host|connection reset|Connection reset by peer|broken pipe|Cannot open database .* requested by the login.*(failover|not currently available)'
    Class   = 'transient-sql'
}

function Test-SIPipelineLockTransient {
    <# PURE. #913: is a failure of a lock call an Azure SQL transient worth another attempt? -ErrorRecord: an ErrorRecord, an
       exception (SqlException numbers and inner exceptions are read) or a text. A permission, a syntax error or anything
       else is never retried. #>
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    $texts = New-Object System.Collections.Generic.List[string]
    while ($ex) {
        if ($ex -is [System.Data.SqlClient.SqlException]) {
            foreach ($er in @($ex.Errors)) { if ($script:SIPipelineLockRetry.Numbers -contains [int]$er.Number) { return $true } }
            if ($script:SIPipelineLockRetry.Numbers -contains [int]$ex.Number) { return $true }
        }
        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
    }
    if (-not $texts.Count) { $texts.Add([string]$ErrorRecord) }
    return [bool](($texts -join ' | ') -match $script:SIPipelineLockRetry.Pattern)
}

function Get-SIPipelineErrorClassTag {
    <# PURE. #913: the error class a caller TAGGED on a failure (Exception.Data['SIErrorClass'], on it or an inner exception --
       a script method wraps what it throws), or ''. #>
    param([AllowNull()]$ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    while ($ex) {
        try { if ($ex.Data -and $ex.Data.Contains('SIErrorClass') -and [string]$ex.Data['SIErrorClass']) { return [string]$ex.Data['SIErrorClass'] } } catch { }
        $ex = $ex.InnerException
    }
    ''
}

function Invoke-SIPipelineLockCall {
    <#
        #913: ONE lock call (-Call { }) with the bounded retry on the Azure SQL transients (Test-SIPipelineLockTransient):
        again after each of -Waits seconds (default 2, 4, 8, 16, 30 -- about a minute); any other error is thrown at once.
        When the transient outlasts the retry it is thrown as "the pipeline lock (<What>) ... transient-sql", the class on
        Exception.Data['SIErrorClass'] = 'transient-sql' (Get-SIPipelineErrorClassTag). -Sleep { param($s) } and -Log
        { param($Level, $Text) } are seams.
    #>
    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][scriptblock]$Call, [int[]]$Waits = $script:SIPipelineLockRetry.Waits,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Log)
    $try = 0
    while ($true) {
        try { return (& $Call) }
        catch {
            $err = $_
            if (-not (Test-SIPipelineLockTransient -ErrorRecord $err)) { throw }
            $first = (([string]$err.Exception.Message) -split "`n")[0].Trim()
            if ($try -ge @($Waits).Count) {
                $ex = New-Object System.Exception(('the pipeline lock ({0}) could not be reached: Azure SQL answered a transient error {1} time(s) in about a minute ({2}) -- {3}; the next wake-up tries again' -f $What, ($try + 1), $first, $script:SIPipelineLockRetry.Class), $err.Exception)
                $ex.Data['SIErrorClass'] = $script:SIPipelineLockRetry.Class
                throw $ex
            }
            $w = [int]@($Waits)[$try]; $try++
            if ($Log) { try { & $Log 'WARN' ('the pipeline lock ({0}): Azure SQL is not available for a moment ({1}) -- trying again in {2} s ({3}/{4})' -f $What, $first, $w, $try, @($Waits).Count) } catch { } }
            if ($w -gt 0) { & $Sleep $w }
        }
    }
}

function New-SIPipelineSqlControl {
    <#
        The Pro lock + queue (cfg.PipelineLock / cfg.PipelineQueue) over the -Invoke seam every Pro engine uses
        (New-SIProSettingsStore .Invoke: ONE array of hashtables per reader -- ConvertTo-SIJobFlowSqlRows flattens it).
        A database whose schema was not applied again has neither table: Available is then $false and the runner falls back
        to the run record's heartbeat (SCHED-1.1, as before #306).
        #913: the lock calls (AcquireLock, HeartbeatLock, ReleaseLock, ReleaseLockOfRun, LockHolder) retry the Azure SQL
        transients (Invoke-SIPipelineLockCall); -LockWaits / -LockSleep / -LockLog are its seams.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int[]]$LockWaits = $script:SIPipelineLockRetry.Waits,
          [scriptblock]$LockSleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$LockLog)
    New-SIJobFlowSeams -Fields @{ Invoke = $Invoke; Kind = 'sql'; LockWaits = $LockWaits; LockSleep = $LockSleep; LockLog = $LockLog } -Methods @{
        AcquireLock = {
            param($Holder, $What, $StaleMinutes)
            # (the call block reads uniquely named locals: it runs inside Invoke-SIPipelineLockCall, whose own -What would win)
            $__lkInv = $this.Invoke; $__lkArgs = @{ Holder = [string]$Holder; What = [string]$What; StaleMinutes = [int]$StaleMinutes }
            $r = @(Invoke-SIPipelineLockCall -What 'acquire' -Waits $this.LockWaits -Sleep $this.LockSleep -Log $this.LockLog -Call {
                    @(& $__lkInv (Get-SIPipelineSqlText 'Acquire') $__lkArgs 'reader' | ConvertTo-SIJobFlowSqlRows) })
            if (-not $r.Count -or [int]$r[0].Mine -lt 0) { return [pscustomobject]@{ Available = $false; Acquired = $true; Holder = ''; What = ''; HeartbeatUtc = $null; TookOver = '' } }
            $x = $r[0]
            $tk = if (-not ($x.PreviousHolder -is [DBNull]) -and $x.PreviousHolder -and [int]$x.Mine -eq 1) { [string]$x.PreviousHolder } else { '' }
            [pscustomobject]@{ Available = $true; Acquired = ([int]$x.Mine -eq 1); Holder = [string]$x.Holder; What = [string]$x.What
                               HeartbeatUtc = $(if ($x.HeartbeatUtc -is [DBNull]) { $null } else { $x.HeartbeatUtc }); TookOver = $tk }
        }
        HeartbeatLock = {
            param($Holder, $FlowRunId, $What)
            $__lkInv = $this.Invoke; $__lkArgs = @{ Holder = [string]$Holder; FlowRunId = [string]$FlowRunId; What = [string]$What }
            $r = @(Invoke-SIPipelineLockCall -What 'beat' -Waits $this.LockWaits -Sleep $this.LockSleep -Log $this.LockLog -Call {
                    @(& $__lkInv (Get-SIPipelineSqlText 'Heartbeat') $__lkArgs 'reader' | ConvertTo-SIJobFlowSqlRows) })
            ($r.Count -and [int]$r[0].Held -gt 0)
        }
        ReleaseLock = {
            param($Holder)
            $__lkInv = $this.Invoke; $__lkArgs = @{ Holder = [string]$Holder }
            $null = Invoke-SIPipelineLockCall -What 'release' -Waits $this.LockWaits -Sleep $this.LockSleep -Log $this.LockLog -Call {
                    $null = & $__lkInv (Get-SIPipelineSqlText 'Release') $__lkArgs 'nonquery' }
        }
        ReleaseLockOfRun = {
            param($FlowRunId)
            $__lkInv = $this.Invoke; $__lkArgs = @{ FlowRunId = [string]$FlowRunId }
            $r = @(Invoke-SIPipelineLockCall -What 'release of a run' -Waits $this.LockWaits -Sleep $this.LockSleep -Log $this.LockLog -Call {
                    @(& $__lkInv (Get-SIPipelineSqlText 'ReleaseRun') $__lkArgs 'reader' | ConvertTo-SIJobFlowSqlRows) })
            ($r.Count -and [int]$r[0].Released -gt 0)
        }
        LockHolder = {
            $__lkInv = $this.Invoke
            $r = @(Invoke-SIPipelineLockCall -What 'read' -Waits $this.LockWaits -Sleep $this.LockSleep -Log $this.LockLog -Call {
                    @(& $__lkInv (Get-SIPipelineSqlText 'Lock') @{} 'reader' | ConvertTo-SIJobFlowSqlRows) })
            if (-not $r.Count -or $r[0].Holder -is [DBNull] -or -not [string]$r[0].Holder) { return $null }
            [pscustomobject]@{ Holder = [string]$r[0].Holder; What = $(if ($r[0].What -is [DBNull]) { '' } else { [string]$r[0].What }); FlowRunId = $(if ($r[0].FlowRunId -is [DBNull]) { '' } else { [string]$r[0].FlowRunId }) }
        }
        Enqueue = {
            param($Request)
            $nul = { param($v) if ($null -eq $v) { [DBNull]::Value } else { $v } }
            $r = @(& $this.Invoke (Get-SIPipelineSqlText 'Enqueue') @{ Scope = [string]$Request.Scope; Target = [string]$Request.Target; Trg = [string]$Request.Trigger
                                                                        RequestedBy = [string]$Request.RequestedBy; SlotUtc = (& $nul $Request.SlotUtc); Note = [string]$Request.Note } 'reader' | ConvertTo-SIJobFlowSqlRows)
            if (-not $r.Count) { return [pscustomobject]@{ Id = 0; Outcome = 'Missing' } }
            [pscustomobject]@{ Id = [long]$r[0].Id; Outcome = [string]$r[0].Outcome }
        }
        NextQueued = { $r = @(& $this.Invoke (Get-SIPipelineSqlText 'Next') @{} 'reader' | ConvertTo-SIJobFlowSqlRows); if ($r.Count) { ConvertFrom-SIPipelineRequestRow $r[0] } else { $null } }
        MarkRunning = { param($Id, $FlowRunId, $Holder) $r = @(& $this.Invoke (Get-SIPipelineSqlText 'MarkRunning') @{ Id = [long]$Id; FlowRunId = [string]$FlowRunId; Holder = [string]$Holder } 'reader' | ConvertTo-SIJobFlowSqlRows); ($r.Count -and [int]$r[0].Taken -gt 0) }
        MarkDone = { param($Id, $Outcome) $null = & $this.Invoke (Get-SIPipelineSqlText 'MarkDone') @{ Id = [long]$Id; Outcome = [string]$Outcome } 'nonquery' }
        Cancel = { param($Id, $By) $r = @(& $this.Invoke (Get-SIPipelineSqlText 'Cancel') @{ Id = [long]$Id; By = [string]$By } 'reader' | ConvertTo-SIJobFlowSqlRows); ($r.Count -and [int]$r[0].Cancelled -gt 0) }
        List = { @(& $this.Invoke (Get-SIPipelineSqlText 'List') @{} 'reader' | ConvertTo-SIJobFlowSqlRows | ForEach-Object { ConvertFrom-SIPipelineRequestRow $_ }) }
    }
}

# ---- VM (files) and Community container (blobs): the same two JSON documents ------------------------------------------
function New-SIPipelineDocControl {
    <#
        The lock + queue as two JSON documents over a document seam -Docs with methods Read($name) (text or $null),
        Write($name, $text), CreateNew($name, $text) (atomic: $false when it exists), Delete($name). Names: 'pipeline.lock'
        (the lock: Holder, What, FlowRunId, AcquiredUtc, HeartbeatUtc) and 'pipeline-queue.json' (the queue, oldest first;
        finished requests are kept for the last 50). The queue is changed under a short mutex document
        ('pipeline-queue.mutex', stale after 60 s). -Now: the clock (UTC).
        A file system makes the lock atomic (CreateNew); a blob store is read-check-write -- two runners racing for a
        STALE lock in the same second could both take it (the container's flow job has one execution at a time by its
        own guard, so this is the corner it leaves).
    #>
    param([Parameter(Mandatory)]$Docs, [scriptblock]$Now = { [datetime]::UtcNow }, [string]$Kind = 'file')
    New-SIJobFlowSeams -Fields @{ Docs = $Docs; Now = $Now; Kind = $Kind } -Methods @{
        ReadLock = {
            $t = $this.Docs.Read('pipeline.lock')
            if (-not $t) { return $null }
            try { $o = $t | ConvertFrom-Json } catch { return [pscustomobject]@{ Holder = '?'; What = 'an unreadable lock'; HeartbeatUtc = $null } }
            $hb = $null; if ($o.HeartbeatUtc) { $hb = [datetime]::Parse([string]$o.HeartbeatUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
            [pscustomobject]@{ Holder = [string]$o.Holder; What = [string]$o.What; FlowRunId = [string]$o.FlowRunId; HeartbeatUtc = $hb }
        }
        LockText = {
            param($Holder, $What, $FlowRunId)
            $iso = ([datetime](& $this.Now)).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            ConvertTo-Json -InputObject ([ordered]@{ Holder = [string]$Holder; What = [string]$What; FlowRunId = [string]$FlowRunId; HeartbeatUtc = $iso }) -Compress
        }
        AcquireLock = {
            param($Holder, $What, $StaleMinutes)
            $text = $this.LockText($Holder, $What, '')
            if ($this.Docs.CreateNew('pipeline.lock', $text)) { return [pscustomobject]@{ Available = $true; Acquired = $true; Holder = $Holder; What = $What; HeartbeatUtc = $null; TookOver = '' } }
            $cur = $this.ReadLock()
            $now = ([datetime](& $this.Now)).ToUniversalTime()
            $stale = (-not $cur) -or (-not $cur.HeartbeatUtc) -or (($now - $cur.HeartbeatUtc).TotalMinutes -ge [int]$StaleMinutes)
            if ($cur -and [string]$cur.Holder -eq [string]$Holder) { $stale = $true }
            if (-not $stale) { return [pscustomobject]@{ Available = $true; Acquired = $false; Holder = [string]$cur.Holder; What = [string]$cur.What; HeartbeatUtc = $cur.HeartbeatUtc; TookOver = '' } }
            $this.Docs.Write('pipeline.lock', $text)
            $back = $this.ReadLock()
            $mine = $back -and [string]$back.Holder -eq [string]$Holder
            $took = if ($mine -and $cur -and [string]$cur.Holder -ne [string]$Holder) { [string]$cur.Holder } else { '' }
            [pscustomobject]@{ Available = $true; Acquired = [bool]$mine; Holder = $(if ($back) { [string]$back.Holder } else { '' }); What = $(if ($back) { [string]$back.What } else { '' }); HeartbeatUtc = $(if ($back) { $back.HeartbeatUtc } else { $null }); TookOver = $took }
        }
        HeartbeatLock = {
            param($Holder, $FlowRunId, $What)
            $cur = $this.ReadLock()
            if (-not $cur -or [string]$cur.Holder -ne [string]$Holder) { return $false }
            $this.Docs.Write('pipeline.lock', $this.LockText($Holder, $What, $FlowRunId)); $true
        }
        ReleaseLock = { param($Holder) $cur = $this.ReadLock(); if ($cur -and [string]$cur.Holder -eq [string]$Holder) { $this.Docs.Delete('pipeline.lock') } }
        # #700: the lock of ONE run, released at once when that run is cancelled
        ReleaseLockOfRun = { param($FlowRunId) $cur = $this.ReadLock(); if ($cur -and $FlowRunId -and [string]$cur.FlowRunId -eq [string]$FlowRunId) { $this.Docs.Delete('pipeline.lock'); $true } else { $false } }
        LockHolder = { $this.ReadLock() }
        # ---- the queue (under the mutex) ----
        # -Change { param($Items, $Arg) } changes the list in place and returns the answer. No GetNewClosure: a closure
        # runs in its own module scope and cannot see the functions a script dot-sourced (see New-SIJobFlowSeams).
        WithQueue = {
            param([scriptblock]$Change, $Arg)
            $got = $false
            for ($i = 0; $i -lt 50 -and -not $got; $i++) {
                $got = $this.Docs.CreateNew('pipeline-queue.mutex', ([datetime](& $this.Now)).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture))
                if (-not $got) {
                    $m = $this.Docs.Read('pipeline-queue.mutex'); $mt = $null
                    try { $mt = [datetime]::Parse([string]$m, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { }
                    if (-not $mt -or (([datetime](& $this.Now)).ToUniversalTime() - $mt).TotalSeconds -gt 60) { $this.Docs.Delete('pipeline-queue.mutex') } else { Start-Sleep -Milliseconds 200 }
                }
            }
            if (-not $got) { throw 'the pipeline queue is held by another process (pipeline-queue.mutex) -- try again' }
            try {
                $items = New-Object System.Collections.Generic.List[object]
                $t = $this.Docs.Read('pipeline-queue.json')
                if ($t) { $parsed = ConvertFrom-Json -InputObject $t; foreach ($x in @($parsed)) { if ($x) { $items.Add((ConvertFrom-SIPipelineRequestRow $x)) } } }
                $out = & $Change $items $Arg
                # keep every open request and the last 50 finished ones
                $open = @($items | Where-Object { $_.State -in @('Queued', 'Running') })
                $done = @($items | Where-Object { $_.State -notin @('Queued', 'Running') } | Select-Object -Last 50)
                $keep = @($items | Where-Object { $open -contains $_ -or $done -contains $_ })
                $iso = { param($v) if ($null -eq $v) { $null } else { ([datetime]$v).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) } }
                $rows = @($keep | ForEach-Object { [ordered]@{ Id = [long]$_.Id; Scope = $_.Scope; Target = $_.Target; Trg = $_.Trigger; RequestedBy = $_.RequestedBy; RequestedUtc = (& $iso $_.RequestedUtc)
                                                               SlotUtc = (& $iso $_.SlotUtc); Note = $_.Note; State = $_.State; FlowRunId = $_.FlowRunId; Outcome = $_.Outcome } })
                $this.Docs.Write('pipeline-queue.json', (ConvertTo-SIPipelineJsonArray -Items $rows))
                $out
            } finally { $this.Docs.Delete('pipeline-queue.mutex') }
        }
        Enqueue = {
            param($Request)
            if (-not $Request.RequestedUtc) { $Request.RequestedUtc = ([datetime](& $this.Now)).ToUniversalTime() }
            $this.WithQueue({
                param($items, $req)
                $key = Get-SIPipelineRequestKey $req
                $same = @($items | Where-Object { $_.State -eq 'Queued' -and (Get-SIPipelineRequestKey $_) -eq $key })
                if ($same.Count) {
                    if (-not $same[0].SlotUtc -and $req.SlotUtc) { $same[0].SlotUtc = $req.SlotUtc }
                    if (-not $same[0].Note -and $req.Note) { $same[0].Note = $req.Note }
                    return [pscustomobject]@{ Id = [long]$same[0].Id; Outcome = 'Deduplicated' }
                }
                $max = 0; foreach ($x in $items) { if ([long]$x.Id -gt $max) { $max = [long]$x.Id } }
                $n = ConvertFrom-SIPipelineRequestRow ([pscustomobject]@{ Id = $max + 1; Scope = $req.Scope; Target = $req.Target; Trg = $req.Trigger; RequestedBy = $req.RequestedBy
                                                                          RequestedUtc = $req.RequestedUtc; SlotUtc = $req.SlotUtc; Note = $req.Note; State = 'Queued' })
                $items.Add($n)
                [pscustomobject]@{ Id = [long]$n.Id; Outcome = 'Queued' }
            }, $Request)
        }
        NextQueued = { $t = $this.Docs.Read('pipeline-queue.json'); if (-not $t) { return $null }; $parsed = ConvertFrom-Json -InputObject $t; $q = @(@($parsed) | Where-Object { $_ -and $_.State -eq 'Queued' } | Sort-Object { [long]$_.Id }); if ($q.Count) { ConvertFrom-SIPipelineRequestRow $q[0] } else { $null } }
        MarkRunning = { param($Id, $FlowRunId) [bool]($this.WithQueue({ param($items, $a) $x = @($items | Where-Object { [long]$_.Id -eq $a.Id -and $_.State -eq 'Queued' }); if ($x.Count) { $x[0].State = 'Running'; $x[0].FlowRunId = $a.Run; $true } else { $false } }, @{ Id = [long]$Id; Run = [string]$FlowRunId })) }
        MarkDone = { param($Id, $Outcome) $null = $this.WithQueue({ param($items, $a) foreach ($x in @($items | Where-Object { [long]$_.Id -eq $a.Id -and $_.State -in @('Queued', 'Running') })) { $x.State = 'Done'; $x.Outcome = $a.Outcome } }, @{ Id = [long]$Id; Outcome = [string]$Outcome }) }
        Cancel = { param($Id, $By) [bool]($this.WithQueue({ param($items, $a) $x = @($items | Where-Object { [long]$_.Id -eq $a -and $_.State -eq 'Queued' }); if ($x.Count) { $x[0].State = 'Cancelled'; $true } else { $false } }, [long]$Id)) }
        List = { $t = $this.Docs.Read('pipeline-queue.json'); if (-not $t) { return @() }; $parsed = ConvertFrom-Json -InputObject $t; @(@($parsed) | Where-Object { $_ -and $_.State -in @('Queued', 'Running') } | Sort-Object { [long]$_.Id } | ForEach-Object { ConvertFrom-SIPipelineRequestRow $_ }) }
    }
}

function New-SIPipelineFileDocs {
    <# The document seam over a folder (a VM: <install>\data\flow). CreateNew is atomic (FileMode.CreateNew). #>
    param([Parameter(Mandatory)][string]$Folder)
    New-SIJobFlowSeams -Fields @{ Folder = $Folder } -Methods @{
        Path = { param($Name) if (-not (Test-Path -LiteralPath $this.Folder)) { New-Item -ItemType Directory -Path $this.Folder -Force | Out-Null }; Join-Path $this.Folder $Name }
        Read = { param($Name) $p = $this.Path($Name); if (Test-Path -LiteralPath $p) { try { [IO.File]::ReadAllText($p) } catch { $null } } else { $null } }
        Write = { param($Name, $Text) $p = $this.Path($Name); $tmp = $p + '.' + [guid]::NewGuid().ToString('n') + '.tmp'; [IO.File]::WriteAllText($tmp, [string]$Text, (New-Object System.Text.UTF8Encoding($false))); Move-Item -LiteralPath $tmp -Destination $p -Force }
        CreateNew = {
            param($Name, $Text)
            $p = $this.Path($Name)
            try {
                $fs = [IO.File]::Open($p, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { $b = (New-Object System.Text.UTF8Encoding($false)).GetBytes([string]$Text); $fs.Write($b, 0, $b.Length) } finally { $fs.Dispose() }
                $true
            } catch { $false }
        }
        Delete = { param($Name) $p = $this.Path($Name); if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } }
    }
}

function New-SIPipelineBlobDocs {
    <# The document seam over the install's storage (a Community container: <account>/sistate/flow/<name>), OAuth as the job. #>
    param([Parameter(Mandatory)][string]$Account, [string]$Container = 'sistate', [string]$Prefix = 'flow/')
    New-SIJobFlowSeams -Fields @{ Account = $Account; Container = $Container; Prefix = $Prefix } -Methods @{
        Read = { param($Name) try { $b = Get-SIBlobContent -Account $this.Account -Container $this.Container -Blob ($this.Prefix + $Name); if (-not $b -or $b.Length -eq 0) { $null } else { [Text.Encoding]::UTF8.GetString($b) } } catch { if ("$($_.Exception.Message)" -match '404|BlobNotFound|ContainerNotFound|not found') { $null } else { throw } } }
        Write = { param($Name, $Text) $null = Set-SIBlobContent -Account $this.Account -Container $this.Container -Blob ($this.Prefix + $Name) -Bytes ([Text.Encoding]::UTF8.GetBytes([string]$Text)) -ContentType 'application/json' }
        CreateNew = { param($Name, $Text) if ($this.Read($Name)) { return $false }; $this.Write($Name, $Text); $true }
        Delete = { param($Name) try { if (Get-Command -Name Remove-SIBlob -ErrorAction SilentlyContinue) { Remove-SIBlob -Account $this.Account -Container $this.Container -Blob ($this.Prefix + $Name) } else { $this.Write($Name, '') } } catch { } }
    }
}

function Get-SIPipelineUpdateRunning {
    <#
        PURE. Why the pipeline must not start now because the updater is updating SecurityInsight -- '' when it is not.
        -Executions: the updater job's executions as ARM lists them (name, properties.status, properties.startTime); one in
        Running / Processing that started less than -MaxHours ago counts (an execution older than the updater can run is
        Azure's stale record, not an update). -Processes (VM): command lines of the running PowerShell processes; one that
        runs Update-SecurityInsight.ps1 counts.
    #>
    param([AllowEmptyCollection()][object[]]$Executions = @(), [AllowEmptyCollection()][string[]]$Processes = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxHours = 6)
    foreach ($e in @($Executions | Where-Object { $_ })) {
        $st = ''; if ($e.PSObject.Properties['properties'] -and $e.properties -and $e.properties.PSObject.Properties['status']) { $st = [string]$e.properties.status }
        if ($st -notin @('Running', 'Processing')) { continue }
        $t = $null
        if ($e.properties.PSObject.Properties['startTime'] -and $e.properties.startTime) { try { $t = ([datetime]$e.properties.startTime).ToUniversalTime() } catch { $t = $null } }
        if ($t -and ($NowUtc.ToUniversalTime() - $t).TotalHours -gt $MaxHours) { continue }
        return ('caj-si-updater execution {0}{1}' -f [string]$e.name, $(if ($t) { (', started {0:u}' -f $t) } else { '' }))
    }
    foreach ($c in @($Processes | Where-Object { $_ })) {
        if ([string]$c -match '(?i)Update-SecurityInsight\.ps1') { return 'Update-SecurityInsight.ps1 is running on this machine' }
    }
    ''
}

function ConvertFrom-SIPipelineUpdateWaitsTag {
    <#
        PURE. 2026-10-23: the updater's wait mark (tag si-update-waits on the updater job, written by its run gate --
        container/updater/_shared/SI-UpdaterRunGate.ps1 ConvertTo-SIUpdateWaitsTag): '<sinceUtc>|<setUtc>|<run|store>|<reason>'
        -> @{ SinceUtc; SetUtc; Kind; Reason }, or $null (none / not that shape).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $null }
    $p = "$Value".Split('|', 4)
    if ($p.Count -lt 3 -or $p[2] -notin @('run', 'store')) { return $null }
    $t = { param($s) $d = [datetime]::MinValue; if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $d } else { $null } }
    $since = & $t $p[0]; $set = & $t $p[1]
    if (-not $since -or -not $set) { return $null }
    [pscustomobject]@{ SinceUtc = $since; SetUtc = $set; Kind = $p[2]; Reason = $(if ($p.Count -ge 4) { $p[3] } else { '' }) }
}

function Get-SIPipelineUpdateStart {
    <#
        PURE. 2026-10-23: may the runner start the updater for this wait mark (-Waits)? Once per mark: an execution of the
        updater that started at or after the mark was last written (SetUtc) has run for it already -- running: not again;
        ended (and the mark is still there): not again, said (the queue then runs -- never a block). -Executions: the
        updater job's executions (ARM shape). Returns @{ Start; Running (an execution for it runs now: hold, start nothing); Text }.
    #>
    param([Parameter(Mandatory)]$Waits, [AllowEmptyCollection()][object[]]$Executions = @())
    $set = ([datetime]$Waits.SetUtc).ToUniversalTime()
    foreach ($e in @($Executions | Where-Object { $_ })) {
        $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
        $t = $null
        if ($p.PSObject.Properties['startTime'] -and "$($p.startTime)".Trim()) { try { $t = ([datetime]$p.startTime).ToUniversalTime() } catch { $t = $null } }
        if (-not $t -or $t -lt $set) { continue }
        $st = [string]$p.status
        if ($st -in @('Running', 'Processing') -and -not ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim())) {
            return [pscustomobject]@{ Start = $false; Running = $true; Text = ('the updater is already running for it ({0})' -f [string]$e.name) }
        }
        return [pscustomobject]@{ Start = $false; Running = $false; Text = ('the updater ran for it ({0}, {1}) and left it -- its log says why' -f [string]$e.name, $(if ($st) { $st.ToLowerInvariant() } else { 'ended' })) }
    }
    [pscustomobject]@{ Start = $true; Running = $false; Text = '' }
}

function Get-SIPipelineUpdateOverdueStart {
    <#
        PURE (#947 (b), owner 2026-10-29). An update has waited -MaxHours (6) or more for the pipeline (its wait mark -Waits,
        kind 'run', SinceUtc = when it first began to wait): the runner starts the updater ON A BUSY WAKE-UP TOO -- the update
        then cancels the run that started on an older version and installs (SI-UpdaterWaitBound.ps1 Invoke-SIUpdaterOverdueCancel).
        Without this an update that waits would only be asked again at its next daily start. At most once every -EveryMinutes
        (60): an updater execution that is running, or that started within that time, is not started again.
        -Executions: the updater job's executions (ARM shape). Returns @{ Start; Text }.
    #>
    param($Waits, [AllowEmptyCollection()][object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$NowUtc, [int]$MaxHours = 6, [int]$EveryMinutes = 60)
    $no = { param($t) [pscustomobject]@{ Start = $false; Text = $t } }
    if (-not $Waits -or [string]$Waits.Kind -ne 'run' -or -not $Waits.SinceUtc) { return (& $no '') }
    $now = $NowUtc.ToUniversalTime()
    $hours = ($now - ([datetime]$Waits.SinceUtc).ToUniversalTime()).TotalHours
    if ($hours -lt $MaxHours) { return (& $no '') }
    foreach ($e in @($Executions | Where-Object { $_ })) {
        $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
        $st = [string]$p.status
        $t = $null
        if ($p.PSObject.Properties['startTime'] -and "$($p.startTime)".Trim()) { try { $t = ([datetime]$p.startTime).ToUniversalTime() } catch { $t = $null } }
        if ($st -in @('Running', 'Processing') -and -not ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim()) -and (-not $t -or ($now - $t).TotalHours -lt 6)) {
            return (& $no ('the updater is running ({0})' -f [string]$e.name))
        }
        if ($t -and ($now - $t).TotalMinutes -lt $EveryMinutes) { return (& $no ('the updater started {0} minutes ago ({1})' -f [int]($now - $t).TotalMinutes, [string]$e.name)) }
    }
    [pscustomobject]@{ Start = $true; Text = ('an update has waited {0} hours for the pipeline -- the updater is started; it cancels a run that started on an older version and installs' -f [int][Math]::Floor($hours)) }
}

# =====================================================================================================================
#  #700: cancel the RUNNING pipeline run (owner 2026-10-15: "why not kill it" / "dont let it finish if it runs wrong release")
# =====================================================================================================================
function Get-SIPipelineCancelText {
    <# PURE. The run's stop reason once it is cancelled: "cancelled by <who>: <why>" (at most 1000 characters, its column). #>
    param([AllowEmptyString()][string]$By, [AllowEmptyString()][string]$Reason)
    $who = if ("$By".Trim()) { "$By".Trim() } else { 'someone' }
    $t = if ("$Reason".Trim()) { 'cancelled by {0}: {1}' -f $who, "$Reason".Trim() } else { 'cancelled by {0}' -f $who }
    if ($t.Length -gt 1000) { $t = $t.Substring(0, 1000) }
    $t
}

function Set-SIPipelineRunCancelled {
    <#
        #700. Marks the run record -State CANCELLED, in place: State Cancelled (a finished state -- never resumed), the stop
        reason "cancelled by <who>: <why>", CancelledBy, the end. A step still starting or running is asked to stop (-Stop
        { param($Job, $Execution) }: the job execution over ARM / the process on a VM) and is recorded Interrupted (class
        'cancelled'); a waiting step is Skipped (class 'cancelled'). A stop that fails is said and does not stop the cancel.
        #882: -StopWorkers { param($Job, $SinceUtc, $Execution) } -- the workers of such a step (a collection in parts, the
        Risk Analysis queue workers, their runs closed first) are stopped too: a cancelled step leaves nothing running.
        Returns @{ Text; Stopped (the executions asked to stop); StopFailed (job: why) }.
    #>
    param([Parameter(Mandatory)]$State, [AllowEmptyString()][string]$By = '', [AllowEmptyString()][string]$Reason = '', [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Stop,
          [scriptblock]$StopWorkers)
    $now = $NowUtc.ToUniversalTime()
    $why = Get-SIPipelineCancelText -By $By -Reason $Reason
    $stopped = New-Object System.Collections.Generic.List[object]
    $failed = New-Object System.Collections.Generic.List[string]
    foreach ($st in @($State.Steps)) {
        if ($null -eq $st) { continue }
        if ([string]$st.State -in @('Starting', 'Running')) {
            if ($Stop -and [string]$st.Execution) {
                try { $null = & $Stop ([string]$st.Job) ([string]$st.Execution); $stopped.Add([pscustomobject]@{ Job = [string]$st.Job; Execution = [string]$st.Execution }) }
                catch { $failed.Add(('{0}: {1}' -f $st.Job, $_.Exception.Message)) }
            }
            if ($StopWorkers) {
                $wSince = if ($st.StartedUtc) { ([datetime]$st.StartedUtc).ToUniversalTime() } else { $null }
                try { $null = & $StopWorkers ([string]$st.Job) $wSince ([string]$st.Execution) } catch { $failed.Add(('{0} (its workers): {1}' -f $st.Job, $_.Exception.Message)) }
            }
            $st.State = 'Interrupted'; $st.ErrorClass = 'cancelled'; $st.EndedUtc = $now
            $st.Error = ('stopped: the run was {0}' -f $why)
        } elseif ([string]$st.State -eq 'Waiting') {
            $st.State = 'Skipped'; $st.ErrorClass = 'cancelled'
            $st.Error = ('not run: the run was {0}' -f $why)
        }
        if ($st.Error -and ([string]$st.Error).Length -gt 1000) { $st.Error = ([string]$st.Error).Substring(0, 1000) }
    }
    $State.State = 'Cancelled'; $State.StopReason = $why; $State.EndedUtc = $now
    if ($State.PSObject.Properties['CancelledBy']) { $State.CancelledBy = [string]$By } else { $State | Add-Member -NotePropertyName CancelledBy -NotePropertyValue ([string]$By) }
    $text = 'pipeline run {0} {1}; {2} job execution(s) asked to stop{3}' -f $State.FlowRunId, $why, $stopped.Count, $(if ($failed.Count) { ('; could not be stopped: {0}' -f ($failed -join '; ')) } else { '' })
    [pscustomobject]@{ Text = $text; Stopped = $stopped.ToArray(); StopFailed = $failed.ToArray() }
}

function Invoke-SIPipelineCancelRun {
    <#
        #700 -- THE ONE WAY a running pipeline run is cancelled (Operations > Jobs, a support start of the runner with
        SI_FLOW_CANCEL=1, the updater). In this order, so nothing can bring the run back half-way:
          0. the RUNNER that holds the install's lock for this run (another execution of the pipeline job, or a runner
             process on a VM) is stopped first (-StopRunner { param($Holder) }; -Self = this process's own holder, never
             stopped): a runner of an older version does not know a cancelled run and would save it back and start the
             next step;
          1. the run record is marked CANCELLED (a finished state: the scheduler never resumes it; a runner that is still
             alive sees it at its next poll and starts nothing more), with who and why;
          2. its running job executions are asked to stop (-Stop; -StopWorkers { param($Job, $SinceUtc) } for the workers
             of a collection in parts);
          3. its queue request ends (Outcome Cancelled), and the install's lock is released AT ONCE (only when it is held
             for this run) -- the next queued request starts on the next wake-up;
          4. the run is read back: a runner that saved it back in the meantime is overruled (marked cancelled again);
          5. -Audit { param($Result) } writes the audit record (who, why, what was stopped).
        A run already cancelled (the web app marks it, releases the lock and then starts the runner with the holder it
        released, SI_FLOW_CANCEL_RUNNER, to stop the executions) gets steps 0 and 2-5: who and why of that cancel are kept. -FlowRunId: only this run ('' = the last run, when it has not ended). -OtherVersionThan (the updater): only
        a run that STARTED on another version (or on a version that did not record it) is cancelled.
        Returns @{ Outcome = Cancelled | NothingRunning | SameVersion | NotThatRun; FlowRunId; Version; Stopped; StopFailed;
        LockReleased; Text } -- Text is the one plain line to say.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)]$Control,
        [scriptblock]$Stop,
        [scriptblock]$StopWorkers,
        [scriptblock]$StopRunner,
        [string]$Self = '',
        [string]$RunnerHolder = '',
        [AllowEmptyString()][string]$By = '',
        [AllowEmptyString()][string]$Reason = '',
        [string]$FlowRunId = '',
        # untyped on purpose: a [string] parameter turns $null into '' -- and "not given" must stay "not given"
        [AllowNull()]$OtherVersionThan = $null,
        [scriptblock]$Audit,
        [scriptblock]$Now = { [datetime]::UtcNow },
        [scriptblock]$Log = { param($Level, $Message) Write-Host ('[pipeline] {0}' -f $Message) }
    )
    $mk = { param($o, $id, $ver, $text, $stp, $sf, $lr) [pscustomobject]@{ Outcome = $o; FlowRunId = [string]$id; Version = [string]$ver; Stopped = @($stp); StopFailed = @($sf); LockReleased = [bool]$lr; Text = $text } }
    $run = $Store.Load()
    if (-not $run) { return (& $mk 'NothingRunning' '' '' 'no pipeline run is going -- nothing to cancel' @() @() $false) }
    if ($FlowRunId -and [string]$run.FlowRunId -ne $FlowRunId) { return (& $mk 'NotThatRun' $run.FlowRunId '' ('pipeline run {0} is not the last run any more -- nothing cancelled' -f $FlowRunId) @() @() $false) }
    $ver = if ($run.PSObject.Properties['Version']) { [string]$run.Version } else { '' }
    $already = [string]$run.State -eq 'Cancelled'
    $live = @(@($run.Steps) | Where-Object { $_ -and [string]$_.State -in @('Starting', 'Running') })
    if (-not $already -and [string]$run.State -in $script:SIPipeline.RunFinished) { return (& $mk 'NothingRunning' $run.FlowRunId $ver ('no pipeline run is going (the last one, {0}, has {1}) -- nothing to cancel' -f $run.FlowRunId, ([string]$run.State).ToLowerInvariant()) @() @() $false) }
    # the updater: a run already cancelled by somebody else is left to that cancel
    $byVersion = $null -ne $OtherVersionThan -and "$OtherVersionThan".Trim() -ne ''
    if ($byVersion) { $OtherVersionThan = "$OtherVersionThan".Trim() }
    if ($byVersion -and $already) { return (& $mk 'NothingRunning' $run.FlowRunId $ver ('no pipeline run is going (the last one, {0}, is cancelled) -- nothing to cancel' -f $run.FlowRunId) @() @() $false) }
    # a store that cannot keep the version (a Pro database whose schema was not applied again) tells nothing: left alone
    if ($byVersion -and $run.PSObject.Properties['VersionRecorded'] -and -not $run.VersionRecorded) {
        return (& $mk 'SameVersion' $run.FlowRunId '' ('the version pipeline run {0} started on is not recorded (apply the Pro database schema again) -- it goes on' -f $run.FlowRunId) @() @() $false)
    }
    if ($byVersion -and -not $already -and $ver -and $ver -eq $OtherVersionThan) {
        return (& $mk 'SameVersion' $run.FlowRunId $ver ('the pipeline run that is going ({0}) started on this version ({1}) -- it goes on' -f $run.FlowRunId, $ver) @() @() $false)
    }
    $nowU = ([datetime](& $Now)).ToUniversalTime()
    $useBy = $By; $useWhy = $Reason
    if ($already) {
        # keep who and why of the cancel that was made first
        if ($run.PSObject.Properties['CancelledBy'] -and [string]$run.CancelledBy) { $useBy = [string]$run.CancelledBy }
        $useWhy = ''
    }
    $stopped = New-Object System.Collections.Generic.List[object]; $sf = New-Object System.Collections.Generic.List[string]
    # 0. the runner that holds the lock for this run -- it starts nothing more and saves nothing back. -RunnerHolder: the
    # holder the caller saw (the web app releases the lock at once and names the holder it released)
    $runner = [string]$RunnerHolder
    if (-not $runner) {
        $holder = $null; try { $holder = $Control.LockHolder() } catch { $holder = $null }
        if ($holder -and [string]$holder.Holder -and [string]$holder.FlowRunId -eq [string]$run.FlowRunId) { $runner = [string]$holder.Holder }
    }
    if ($StopRunner -and $runner -and $runner -ne $Self) {
        try { $null = & $StopRunner $runner; $stopped.Add([pscustomobject]@{ Job = 'the pipeline runner'; Execution = $runner }) }
        catch { $sf.Add(('the pipeline runner {0}: {1}' -f $runner, $_.Exception.Message)) }
    }
    # 1. CANCELLED first -- before any step is stopped, so a stopped execution can never read as "resume me"
    $sinceOf = @{}; foreach ($st in $live) { $sinceOf[[string]$st.Job] = $st.StartedUtc }
    if (-not $already) {
        # the steps are marked here without stopping them: the stop follows (step 2), from the list of what was running
        $null = Set-SIPipelineRunCancelled -State $run -By $useBy -Reason $useWhy -NowUtc $nowU
        $Store.Save($run)
    }
    # 2. stop what still runs
    foreach ($st in $live) {
        if ($Stop -and [string]$st.Execution) {
            try { $null = & $Stop ([string]$st.Job) ([string]$st.Execution); $stopped.Add([pscustomobject]@{ Job = [string]$st.Job; Execution = [string]$st.Execution }) }
            catch { $sf.Add(('{0}: {1}' -f $st.Job, $_.Exception.Message)) }
        }
        if ($StopWorkers) { try { $null = & $StopWorkers ([string]$st.Job) $sinceOf[[string]$st.Job] ([string]$st.Execution) } catch { $sf.Add(('{0} (its workers): {1}' -f $st.Job, $_.Exception.Message)) } }
        if ([string]$st.State -in @('Starting', 'Running')) {
            $st.State = 'Interrupted'; $st.ErrorClass = 'cancelled'; $st.EndedUtc = $nowU
            $st.Error = ('stopped: the run was {0}' -f $(if ($already) { [string]$run.StopReason } else { Get-SIPipelineCancelText -By $useBy -Reason $useWhy }))
        }
    }
    if ($already) { foreach ($st in @($run.Steps | Where-Object { $_ -and [string]$_.State -eq 'Waiting' })) { $st.State = 'Skipped'; $st.ErrorClass = 'cancelled'; $st.Error = ('not run: the run was {0}' -f $run.StopReason) } }
    try { $Store.Save($run) } catch { & $Log 'WARN' ('the cancelled run''s steps could not be saved ({0}) -- the run itself is cancelled' -f $_.Exception.Message) }
    # 3. its queue request, and the lock -- at once
    try { foreach ($x in @($Control.List() | Where-Object { $_ -and [string]$_.State -eq 'Running' -and [string]$_.FlowRunId -eq [string]$run.FlowRunId })) { $Control.MarkDone($x.Id, 'Cancelled') } } catch { & $Log 'WARN' ('the queue request of the cancelled run could not be closed ({0})' -f $_.Exception.Message) }
    $lr = $false
    try { $lr = [bool]$Control.ReleaseLockOfRun([string]$run.FlowRunId) } catch { & $Log 'WARN' ('the pipeline lock could not be released ({0}) -- it frees itself when its heartbeat is {1} minutes old' -f $_.Exception.Message, $script:SIPipeline.LockStaleMinutes) }
    # 4. read back: a runner that was saving while it was stopped is overruled
    try {
        $back = $Store.Load()
        if ($back -and [string]$back.FlowRunId -eq [string]$run.FlowRunId -and [string]$back.State -ne 'Cancelled') {
            $null = Set-SIPipelineRunCancelled -State $back -By $(if ($run.PSObject.Properties['CancelledBy']) { [string]$run.CancelledBy } else { $useBy }) -Reason '' -NowUtc $nowU
            $back.StopReason = [string]$run.StopReason
            $Store.Save($back)
            & $Log 'WARN' ('pipeline run {0} had been saved back by its runner -- it is marked cancelled again' -f $run.FlowRunId)
        }
    } catch { & $Log 'WARN' ('the cancelled run could not be read back ({0})' -f $_.Exception.Message) }
    $text ='pipeline run {0} {1}; {2} job execution(s) asked to stop{3}; the next run starts on the next wake-up of the pipeline' -f $run.FlowRunId, [string]$run.StopReason, $stopped.Count, $(if ($sf.Count) { ('; could not be stopped: {0}' -f ($sf -join '; ')) } else { '' })
    $res = & $mk 'Cancelled' $run.FlowRunId $ver $text $stopped.ToArray() $sf.ToArray() $lr
    if ($Audit) { try { $null = & $Audit $res } catch { & $Log 'WARN' ('the cancel could not be put on the audit trail ({0})' -f $_.Exception.Message) } }
    $res
}

# =====================================================================================================================
#  The drain: what one wake-up of the runner does
# =====================================================================================================================
function Test-SIPipelineCodeCurrent {
    <# PURE. Is the code this runner started with still the installed code? -StartImage: the flow job's image when this
       execution started; -NowImage: its image now ('' = could not be read). Unknown is current: a check that cannot read
       never ends a runner's work. #>
    param([AllowEmptyString()][string]$StartImage, [AllowEmptyString()][string]$NowImage)
    if (-not "$StartImage".Trim() -or -not "$NowImage".Trim()) { return $true }
    [string]::Equals("$StartImage".Trim(), "$NowImage".Trim(), [System.StringComparison]::OrdinalIgnoreCase)
}

function Invoke-SIPipelineDrain {
    <#
        One wake-up (the 5-minute timer of caj-si-flow / the VM task, or a "Run now"):
          1. -Request (a Run now) is put in the queue (kept once when the same request already waits);
          2. the schedule (pipeline mode 'flow' only): a pipeline run that is due is queued (a slot passed while another
             run held the install is queued too -- it runs once, when the lock is free);
          2b. an UPDATE of SecurityInsight is running (-UpdateRunning returns why): nothing starts -- what was queued
             stays queued and runs on a later wake-up, once the update has finished (Outcome Busy). THE ORDER (owner
             2026-10-23: "Should the rolls skip installs that are mid-run (large installs pick up the new build at their
             next run)?" -> "yes to both"; this REPLACES the rule of 2026-10-12 that the updater installs at once while an
             SI job runs): the updater never installs while a pipeline run is going -- its run gate reads this install's
             run records and takes this same lock (container/updater/_shared/SI-UpdaterRunGate.ps1) -- and the pipeline
             never starts while an update runs (it does not wait inside the run -- it ends this wake-up and the 5-minute
             wake-up tries again; a due slot stays due);
          3. the install's ONE lock is taken -- busy: nothing more happens (the queue waits; exit quietly);
          4. holding the lock: an unfinished run whose runner died is resumed first (an update that waits for it never
             holds that back -- the run must end for the update to land);
          4c. AN UPDATE WAITS FOR THE PIPELINE (-UpdateWaits returns the updater's wait mark, tag si-update-waits): the
             runner starts NO new run -- it starts the updater (-StartUpdate) and ends this wake-up; what waits in the queue
             stays queued and starts on a later wake-up, on the new build. Asked before the queue, and again before each
             further queued run. A wait of kind 'store' (the updater could not read the state store) starts the updater
             but holds no run back. NEVER A BLOCK: -StartUpdate answering that the updater already ran for this mark and
             ended without taking it away (or that it could not be started) is said, and the queue runs;
          then the queued requests run one after the other, oldest first, until the queue is empty; the lock is beaten
             on every save;
          5. the lock is released.
        Seams: -Control (New-SIPipelineSqlControl / -DocControl), -LoadLast { } (the last run record), -RunOne { param($Request,
        $Previous, $FlowRunId) } (one run -> its final record; $Request $null = resume), -UpdateRunning { } ('' = no update
        runs, else why; a failing check never stops the pipeline), -CodeCurrent { } ($false once an update has replaced the
        code this runner runs; a failing check counts as current), -UpdateWaits { } ($null = no update waits, else
        @{ Kind run | store; SinceUtc; SetUtc; Reason }; a failing check holds nothing back), -StartUpdate { param($Waits) }
        (@{ Started; Text }), -Now, -Log.
        A RUNNER NEVER STARTS A NEW RUN ON REPLACED CODE: one execution drains the queue, and a long run outlives an update
        (the update never stops a running pipeline; since 2026-10-23 it waits for it). Before it takes ANOTHER request after a run it did, it asks -CodeCurrent;
        replaced = it ends here and the next wake-up -- a new execution, on the installed version -- takes the queue (live
        2026-10-19: the run queued after the rc11 roll-out was run by a runner of 10-15, whose counts, causes and versions it
        reported for the new release).
        Returns @{ Outcome = Busy | Idle | Ran | Blocked; Runs; Lock; Queued (what was put in the queue); UpdateStarted }.
    #>
    param(
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)]$Control,
        [Parameter(Mandatory)][scriptblock]$LoadLast,
        [Parameter(Mandatory)][scriptblock]$RunOne,
        $Request,
        [scriptblock]$UpdateRunning,
        [scriptblock]$CodeCurrent,
        # 2026-10-23: the updater waits for the pipeline (its wait mark) / start it (step 4c)
        [scriptblock]$UpdateWaits,
        [scriptblock]$StartUpdate,
        # live 2026-10-19: { param($Run) } -- the last run is CANCELLED (final): its steps still open are stopped and closed
        # (Close-SIJobFlowCancelledRun); a failing close never stops the wake-up
        [scriptblock]$CloseCancelled,
        [string]$Holder =('{0}:{1}:{2}' -f $env:COMPUTERNAME, $PID, ([guid]::NewGuid().ToString('n').Substring(0, 8))),
        [scriptblock]$Now = { [datetime]::UtcNow },
        [scriptblock]$Log = { param($Level, $Message) Write-Host ('[pipeline] {0}' -f $Message) },
        [int]$StaleAfterMinutes = $script:SIPipeline.LockStaleMinutes,
        [int]$MaxRuns = 50
    )
    $queued = New-Object System.Collections.Generic.List[object]
    $runs = New-Object System.Collections.Generic.List[object]
    # 1. the Run now request
    if ($Request) {
        $why = Test-SIPipelineRequest -Request $Request -Definition $Definition
        if ($why) { throw $why }
        $q = $Control.Enqueue($Request)
        $Request.Id = [long]$q.Id
        $queued.Add($Request)
        $said = switch ($q.Outcome) {
            'Deduplicated' { 'already waiting in the queue -- kept once' }
            'Missing' { 'runs now if nothing else runs (the Pro database has no pipeline queue yet -- apply the Pro database schema again, it only adds)' }
            default { 'queued' }
        }
        & $Log $(if ($q.Outcome -eq 'Missing') { 'WARN' } else { 'INFO' }) ('{0}: {1}{2}' -f (Get-SIPipelineRequestText $Request), $said, $(if ($Request.RequestedBy) { (' (by {0})' -f $Request.RequestedBy) } else { '' }))
    }
    # 2. the schedule
    $prev = & $LoadLast
    $t0 = ([datetime](& $Now)).ToUniversalTime()
    if ([string]$Definition.Mode -ne 'schedules') {
        $due = Get-SIJobFlowDue -Definition $Definition -Previous $prev -NowUtc $t0 -StaleAfterMinutes $StaleAfterMinutes
        $sched = $null
        if ($due.Action -eq 'Start') { $sched = New-SIPipelineRequest -Scope pipeline -Trigger $(if ($due.Trigger) { $due.Trigger } else { 'schedule' }) -SlotUtc $due.SlotUtc -Note ([string]$due.Note) -RequestedUtc $t0 }
        elseif ($due.Action -eq 'Busy') {
            $pend = Get-SIPipelinePendingSlot -Definition $Definition -Previous $prev -NowUtc $t0
            if ($pend) { $sched = New-SIPipelineRequest -Scope pipeline -Trigger 'catch-up' -SlotUtc $pend.SlotUtc -Note $pend.Note -RequestedUtc $t0 }
        }
        if ($sched) {
            $q = $Control.Enqueue($sched)
            if ($q.Outcome -ne 'Missing') { $sched.Id = [long]$q.Id; $queued.Add($sched); if ($q.Outcome -eq 'Queued') { & $Log 'INFO' ('the scheduled run is due ({0}) -- queued' -f $(if ($sched.SlotUtc) { '{0:u}' -f $sched.SlotUtc } else { $sched.Trigger })) } }
            else {
                # an older Pro database (no queue table): the schedule runs directly when nothing else runs (SCHED-1.1, before #306)
                if ($due.Action -eq 'Start') { $queued.Add($sched) }
            }
        }
    }
    # 2b. an update of SecurityInsight is running: nothing starts under it (the queue keeps what waits)
    if ($UpdateRunning) {
        $upd = ''
        try { $upd = [string](& $UpdateRunning) } catch { & $Log 'WARN' ('whether an update is running could not be checked ({0}) -- the pipeline runs' -f $_.Exception.Message) }
        if ($upd) {
            $waiting = @(try { $Control.List() } catch { @() })
            & $Log 'INFO' ('an update of SecurityInsight is running ({0}) -- nothing starts until it has finished; {1} request(s) wait in the queue' -f $upd, @($waiting | Where-Object { $_.State -eq 'Queued' }).Count)
            return [pscustomobject]@{ Outcome = 'Busy'; Runs = @(); Lock = [pscustomobject]@{ Acquired = $false; What = ('an update of SecurityInsight ({0})' -f $upd); HeartbeatUtc = $null; TookOver = '' }; Queued = $queued.ToArray() }
        }
    }
    # 3. the lock
    $lock = $Control.AcquireLock($Holder, 'pipeline runner', $StaleAfterMinutes)
    if (-not $lock.Acquired) {
        $waiting = @(try { $Control.List() } catch { @() })
        & $Log 'INFO' ('the install is busy ({0}{1}) -- {2} request(s) wait in the queue and run when it is free' -f $lock.What, $(if ($lock.HeartbeatUtc) { (', alive {0:u}' -f $lock.HeartbeatUtc) } else { '' }), @($waiting | Where-Object { $_.State -eq 'Queued' }).Count)
        return [pscustomobject]@{ Outcome = 'Busy'; Runs = @(); Lock = $lock; Queued = $queued.ToArray() }
    }
    if ($lock.TookOver) { & $Log 'WARN' ('took over the pipeline lock of {0}: its heartbeat is older than {1} minutes (its runner stopped)' -f $lock.TookOver, $StaleAfterMinutes) }
    $outcome = 'Idle'
    try {
        # 4a. an unfinished run (its runner died): resume it before anything else
        $prev = & $LoadLast
        $open = @(try { $Control.List() } catch { @() })
        # live 2026-10-19 (ring 2): a CANCELLED run is final -- what a runner that never saw the cancel left running (or
        # started again) is stopped by the runner that holds the lock now, and the run is ended Cancelled again when it was
        # written back to Running (its CancelledBy kept: the store loads it Cancelled)
        if ($prev -and [string]$prev.State -eq 'Cancelled' -and $CloseCancelled) {
            $closed = $null
            try { $closed = & $CloseCancelled $prev } catch { & $Log 'WARN' ('the cancelled run {0} could not be closed ({1}) -- the next wake-up tries again' -f $prev.FlowRunId, $_.Exception.Message) }
            # it had been written back to Running: a runner that never saw the cancel is (or was until now) alive -- this
            # wake-up starts nothing beside it; what waits in the queue starts on the next one
            if ($closed -and $closed.PSObject.Properties['Revived'] -and [bool]$closed.Revived) {
                & $Log 'WARN' ('run {0} was cancelled and then written back to Running by a runner that did not see the cancel -- it is ended Cancelled again; what waits in the queue starts on the next wake-up' -f $prev.FlowRunId)
                return [pscustomobject]@{ Outcome = 'Idle'; Runs = @(); Lock = $lock; Queued = $queued.ToArray() }
            }
        }
        # #700: a CANCELLED run is finished -- it is never resumed
        if ($prev -and [string]$prev.State -notin $script:SIPipeline.RunFinished) {
            $null = $Control.HeartbeatLock($Holder, [string]$prev.FlowRunId, 'resuming a run')
            $r = & $RunOne $null $prev ([string]$prev.FlowRunId)
            if ($r) { $runs.Add($r) }
            if ($r -and [string]$r.Outcome -eq 'Busy') {
                & $Log 'INFO' ('run {0} is still beating -- nothing else starts until it ends' -f $prev.FlowRunId)
                return [pscustomobject]@{ Outcome = 'Blocked'; Runs = $runs.ToArray(); Lock = $lock; Queued = $queued.ToArray() }
            }
            $outcome = 'Ran'
            foreach ($x in @($open | Where-Object { $_.State -eq 'Running' -and [string]$_.FlowRunId -eq [string]$prev.FlowRunId })) { $Control.MarkDone($x.Id, $(if ($r) { [string]$r.State } else { 'Interrupted' })) }
            $prev = & $LoadLast
            # #700: the resumed run was cancelled meanwhile: the lock was released by the cancel, so this runner starts
            # nothing more -- what waits in the queue starts on the next wake-up (never two runners side by side)
            if ($r -and [string]$r.State -eq 'Cancelled') {
                & $Log 'INFO' ('run {0} was cancelled -- this wake-up starts nothing more; what waits in the queue starts on the next one' -f $r.FlowRunId)
                return [pscustomobject]@{ Outcome = $outcome; Runs = $runs.ToArray(); Lock = $lock; Queued = $queued.ToArray() }
            }
        }
        # a request marked Running whose run is not the current one never finished being recorded
        foreach ($x in @($open | Where-Object { $_.State -eq 'Running' })) {
            if ($prev -and [string]$x.FlowRunId -eq [string]$prev.FlowRunId -and [string]$prev.State -in $script:SIPipeline.RunFinished) { $Control.MarkDone($x.Id, [string]$prev.State) }
            elseif (-not $prev -or [string]$x.FlowRunId -ne [string]$prev.FlowRunId) { $Control.MarkDone($x.Id, 'Interrupted') }
        }
        # 4c. an update waits for the pipeline (owner 2026-10-23): no NEW run -- the updater is started first; a wait of kind
        # 'store' starts it and holds nothing back; a start that did not happen, or an updater that already ran for this
        # mark and left it, is said and the queue runs (never a block). Returns $true = hold the queue (this wake-up ends).
        # once per mark in a wake-up: the same mark (its SetUtc) asked again after a run gets the answer it had (no second start)
        $hand = @{ Started = ''; Mark = $null; Hold = $false }
        $handOff = {
            if (-not $UpdateWaits) { return $false }
            $wt = $null
            try { $wt = & $UpdateWaits } catch { & $Log 'WARN' ('whether an update waits for the pipeline could not be read ({0}) -- the queue runs' -f $_.Exception.Message); return $false }
            if (-not $wt) { return $false }
            if ($null -ne $hand.Mark -and $wt.SetUtc -and ([datetime]$wt.SetUtc).ToUniversalTime() -eq $hand.Mark) { return $hand.Hold }
            $hand.Mark = $(if ($wt.SetUtc) { ([datetime]$wt.SetUtc).ToUniversalTime() } else { [datetime]::MinValue }); $hand.Hold = $false
            $st = $null
            if ($StartUpdate) {
                try { $st = & $StartUpdate $wt } catch { $st = [pscustomobject]@{ Started = $false; Text = ('the updater could not be started ({0})' -f $_.Exception.Message) } }
            } else { $st = [pscustomobject]@{ Started = $false; Text = 'this runner cannot start the updater' } }
            $ql = @(try { $Control.List() } catch { @() }); $nq = @($ql | Where-Object { $_.State -eq 'Queued' }).Count
            $since = if ($wt.SinceUtc) { (' since {0:yyyy-MM-dd HH:mm}Z' -f ([datetime]$wt.SinceUtc).ToUniversalTime()) } else { '' }
            if ($st -and $st.Started) {
                $hand.Started = [string]$st.Text
                if ([string]$wt.Kind -eq 'store') {
                    & $Log 'INFO' ('the updater could not read the state store at its last run ({0}) -- it is started again ({1}); no run is held back for it' -f $wt.Reason, $st.Text)
                    return $false
                }
                & $Log 'INFO' ('an update of SecurityInsight waits for the pipeline{0} -- the updater is started ({1}) before any new run; {2} request(s) wait in the queue and start after it, on the new build' -f $since, $st.Text, $nq)
                $hand.Hold = $true
                return $true
            }
            & $Log 'WARN' ('an update of SecurityInsight waits for the pipeline{0}, but {1} -- the queue runs on the installed build; the updater waits again for that run' -f $since, $(if ($st -and $st.Text) { $st.Text } else { 'the updater was not started' }))
            $false
        }
        if (& $handOff) {
            return [pscustomobject]@{ Outcome = $(if ($runs.Count) { 'Ran' } else { 'Busy' }); Runs = $runs.ToArray(); Lock = $lock; Queued = $queued.ToArray(); UpdateStarted = $hand.Started }
        }
        # 4b. the queue, oldest first
        $direct = @($queued | Where-Object { [long]$_.Id -eq 0 })   # an older Pro database: no queue table
        $n = 0
        while ($n -lt $MaxRuns) {
            # never a NEW run on replaced code: after a run this execution did, an update may have replaced its code
            if ($runs.Count -gt 0 -and $CodeCurrent) {
                $cur = $true
                try { $cur = [bool](& $CodeCurrent) } catch { $cur = $true }
                if (-not $cur) {
                    & $Log 'INFO' 'SecurityInsight was updated while this runner worked -- what waits in the queue starts on the next wake-up, on the new version'
                    break
                }
            }
            # never a NEW run while an update waits: the update that waited for the run this execution just did goes first
            if ($runs.Count -gt 0 -and (& $handOff)) { break }
            $req = $null
            if ($direct.Count) { $req = $direct[0]; $direct = @($direct | Select-Object -Skip 1) } else { $req = $Control.NextQueued() }
            if (-not $req) { break }
            $n++
            # 2026-10-24: a catch-up queued while a manual run held the install is not run when that run covered its slot (it was
            # running at that time and succeeded as a whole run -- Get-SIJobFlowCoveredSlot); closed 'Covered', said once
            if ([string]$req.Trigger -eq 'catch-up' -and $req.SlotUtc) {
                $cov = $null
                try { $cov = Get-SIJobFlowCoveredSlot -Definition $Definition -Previous (& $LoadLast) } catch { $cov = $null }
                if ($cov -and ([datetime]$cov).ToUniversalTime() -ge ([datetime]$req.SlotUtc).ToUniversalTime()) {
                    & $Log 'INFO' ('the queued {0:u} start is not run: the run before it was running at that time and succeeded -- it is that day''s run' -f ([datetime]$req.SlotUtc).ToUniversalTime())
                    if ($req.Id) { $Control.MarkDone($req.Id, 'Covered') }
                    continue
                }
            }
            $why = Test-SIPipelineRequest -Request $req -Definition $Definition
            $fid = [guid]::NewGuid().ToString()
            # the database refuses a claim by a runner that does not hold the install's lock (cfg.TR_PipelineQueue_Claim:
            # its lock was released by a cancel, or taken over) -- this runner then takes nothing more; the next wake-up does
            if ($req.Id) {
                $taken = $false
                try { $taken = [bool]$Control.MarkRunning($req.Id, $fid, $Holder) }
                catch {
                    if ("$($_.Exception.Message)" -notmatch 'holds the install lock') { throw }
                    & $Log 'INFO' ('{0} is not taken: this runner no longer holds the install''s lock -- it starts on the next wake-up' -f (Get-SIPipelineRequestText $req))
                    break
                }
                if (-not $taken) { continue }   # cancelled or taken meanwhile
            }
            if ($why) { & $Log 'WARN' ('{0}: not run -- {1}' -f (Get-SIPipelineRequestText $req), $why); if ($req.Id) { $Control.MarkDone($req.Id, 'Refused') }; continue }
            $null = $Control.HeartbeatLock($Holder, $fid, (Get-SIPipelineRequestText $req))
            & $Log 'INFO' ('running {0} ({1}{2})' -f (Get-SIPipelineRequestText $req), $req.Trigger, $(if ($req.RequestedBy) { ', by ' + $req.RequestedBy } else { '' }))
            $r = $null
            try { $r = & $RunOne $req (& $LoadLast) $fid }
            catch { & $Log 'ERROR' ('{0} could not run: {1}' -f (Get-SIPipelineRequestText $req), $_.Exception.Message); if ($req.Id) { $Control.MarkDone($req.Id, 'Error') }; continue }
            if ($r) { $runs.Add($r) }
            if ($r -and [string]$r.Outcome -eq 'Busy') {
                # an unfinished run still beats (a runner that stopped minutes ago): the request goes back to wait
                if ($req.Id) { $Control.MarkDone($req.Id, 'Requeued'); $back = $req; $back.Id = 0; $null = $Control.Enqueue($back) }
                $outcome = 'Blocked'; break
            }
            if ($req.Id) { $Control.MarkDone($req.Id, $(if ($r) { [string]$r.State } else { 'Unknown' })) }
            $outcome = 'Ran'
            # #700: the run was cancelled meanwhile -- the cancel released the lock, so this runner takes nothing more from
            # the queue (the next wake-up does, as the lock's one holder)
            if ($r -and [string]$r.State -eq 'Cancelled') { & $Log 'INFO' ('run {0} was cancelled -- what waits in the queue starts on the next wake-up' -f $r.FlowRunId); break }
        }
    } finally {
        try { $Control.ReleaseLock($Holder) } catch { & $Log 'WARN' ('the pipeline lock could not be released ({0}) -- it frees itself when its heartbeat is {1} minutes old' -f $_.Exception.Message, $StaleAfterMinutes) }
    }
    [pscustomobject]@{ Outcome = $outcome; Runs = $runs.ToArray(); Lock = $lock; Queued = $queued.ToArray(); UpdateStarted = $hand.Started }
}
