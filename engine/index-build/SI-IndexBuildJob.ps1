#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE INDEX BUILD JOB caj-si-index-build (REQUIREMENTS #1111, owner 2026-11-05: "how to fix the index
    build vs updater. why not split this into 2 jobs, seems like bad design" / "we cannot have env that doesnt upd suddently").

    LIVE 2026-11-05 (a ring 2 install): after the operator stopped a run to update, the pipeline runner's idle wake-up started
    caj-si-updater in its index-build mode every 5 minutes; the stop tool saw "the updater runs already", waited for that
    execution and installed nothing. Each of those runs said "... built now in an idle window (about 1 h 22 min)" and then
    "the install's lock is released" within seconds, with no outcome line. Since then:
      * the index build is THIS job; the updater only updates (it has no index-build mode). Anything that asks "is the
        updater running" sees only updates;
      * THE UPDATE ALWAYS GOES FIRST. Before every step and at every check while it builds (CheckSeconds) the job asks
        whether an update waits (the updater's wait mark si-update-waits) or runs (an execution of the updater job) -- and
        whether it still holds the install's lock (the updater takes a lock held by this job at once, it never waits for
        it). Any of these: a RESUMABLE build is PAUSED (ALTER INDEX ... PAUSE; the row 'paused', resumed in a later idle
        window), a filtered one -- it cannot pause -- is cancelled and waits again; the lock is freed; the job ends;
      * RESUMABLE: an index without a filter is built ONLINE + RESUMABLE with MAX_DURATION = the window's minutes (it pauses
        at the window's end) and a paused one is RESUMED; a filtered index is built only when its estimate fits the window
        (or once after 7 days of waiting), as before;
      * EVERY RUN ENDS WITH ONE OUTCOME LINE, whatever ends it -- INDEX-BUILD outcome=<built|paused|waiting|not-now|nothing|
        failed|stopped> ... -- and a build that ended without an outcome (the execution stopped) sets its row back, so the
        runner's next idle window starts it again and the line says where it stopped. The old updater mode had an outer
        try/finally with no catch around the build: whatever ended it after the start line left through the finally
        ("lock released") only, with no outcome and no row change.

    The job runs SI's own image (container\Start-SIInContainer.ps1, SI_ROLE = index-build -> Invoke-SIIndexBuildJob.ps1) as
    the UPDATER's managed identity -- the identity and database rights the index builds have always had (db_ddladmin for
    CREATE / ALTER INDEX, the rows of cfg.IndexBuild and the install's lock); no new grant. The updater keeps the job present
    on every Pro run (Invoke-SIIndexBuildJobEnsure, read back): new installs and existing ones get it the same way.
    Seams for every outside call; PS 5.1 and 7; no module.
#>

if (-not (Get-Command -Name Get-SIIndexBuildContract -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-IndexBuild.ps1'))
}

function Get-SIIndexBuildJobNames {
    <# PURE. The job's fixed names (a function: a caller that dot-sources this file inside a function sees it). #>
    [ordered]@{
        Job       = 'caj-si-index-build'
        Container = 'index-build'
        Role      = 'index-build'
        TagName   = 'si-component'
        TagValue  = 'index-build'
        SpecTag   = 'si-index-build-spec'
        AppApi    = '2025-07-01'
        RunLimit  = 86400       # the job's run limit: a forced one-time build of a large filtered index runs for hours
    }
}

function Get-SIIndexBuildJobProp {
    <# PURE. A nested property (PSCustomObject or dictionary); $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

# =====================================================================================================================
#  THE JOB'S SIDE
# =====================================================================================================================
function Read-SIIndexBuildJobInput {
    <#
        PURE. The job's inputs (its environment; -Env first, then the process). The job carries the install's: SI_INDEXBUILD_SERVER,
        _DATABASE, _MI_CLIENT_ID (the updater's identity), _SUBSCRIPTION_ID, _RESOURCE_GROUP, _UPDATER_JOB. One start carries the
        runner's choice: SI_INDEXBUILD_TABLE / _INDEX (the row), _MINUTES (the window; 0 = no run scheduled), _FORCE (1 = the
        one-time build after 7 days). Returns @{ Ok; Reason; ... ; Request = @{ Table; Index; Minutes; Force } }.
    #>
    param([hashtable]$Env = @{})
    $e = { param($k) if ($Env.ContainsKey($k)) { [string]$Env[$k] } else { [string][Environment]::GetEnvironmentVariable($k) } }
    $no = { param($r) [pscustomobject]@{ Ok = $false; Reason = $r } }
    $server = (& $e 'SI_INDEXBUILD_SERVER').Trim()
    if ($server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{1,253}$') { return (& $no 'SI_INDEXBUILD_SERVER is not a server name') }
    $db = (& $e 'SI_INDEXBUILD_DATABASE').Trim()
    if ($db -notmatch '^[A-Za-z0-9_.-]{1,128}$') { return (& $no 'SI_INDEXBUILD_DATABASE is not a database name') }
    $mi = (& $e 'SI_INDEXBUILD_MI_CLIENT_ID').Trim(); $g = [guid]::Empty
    if ($mi -and -not [guid]::TryParse($mi, [ref]$g)) { return (& $no 'SI_INDEXBUILD_MI_CLIENT_ID is not a client id') }
    $min = 0; [void][int]::TryParse((& $e 'SI_INDEXBUILD_MINUTES').Trim(), [ref]$min)
    $tab = (& $e 'SI_INDEXBUILD_TABLE').Trim(); $ix = (& $e 'SI_INDEXBUILD_INDEX').Trim()
    if (($tab -or $ix) -and -not (Test-SIIndexBuildName -Table $tab -Index $ix)) { $tab = ''; $ix = '' }
    $exec = (& $e 'CONTAINER_APP_JOB_EXECUTION_NAME').Trim()
    [pscustomobject]@{ Ok = $true; Reason = ''; Server = $server; Database = $db; MiClientId = $mi
                       SubscriptionId = (& $e 'SI_INDEXBUILD_SUBSCRIPTION_ID').Trim(); ResourceGroup = (& $e 'SI_INDEXBUILD_RESOURCE_GROUP').Trim()
                       UpdaterJob = $(if ((& $e 'SI_INDEXBUILD_UPDATER_JOB').Trim()) { (& $e 'SI_INDEXBUILD_UPDATER_JOB').Trim() } else { 'caj-si-updater' })
                       Execution = $exec
                       Request = [pscustomobject]@{ Table = $tab; Index = $ix; Minutes = [Math]::Max(0, $min); Force = ((& $e 'SI_INDEXBUILD_FORCE').Trim() -match '^(?i)(1|true|yes|on)$') } }
}

function Get-SIIndexBuildJobHolder {
    <# PURE. The name the job holds the install's lock under: caj-si-index-build:<its execution> (unique per run). #>
    param([string]$Execution = '')
    $x = "$Execution".Trim(); if (-not $x) { $x = [guid]::NewGuid().ToString('n').Substring(0, 12) }
    'caj-si-index-build:{0}' -f $x
}

function Get-SIIndexBuildUpdateFirst {
    <#
        PURE. Does an update go first? -Job: the updater job as ARM returns it (its tag si-update-waits = the wait mark the
        updater leaves when it waits; the same tag the pipeline runner reads), -Executions: the updater job's executions.
        Returns '' (no update) or the reason in plain words.
    #>
    param($Job, [object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$NowUtc)
    $tag = (Get-SIIndexBuildContract).WaitTag
    $v = [string](Get-SIIndexBuildJobProp $Job @('tags', $tag))
    if ("$v".Trim()) {
        $why = @("$v".Split('|'))
        return ('an update waits to install (the updater''s wait mark{0})' -f $(if ($why.Count -ge 4 -and "$($why[3])".Trim()) { ': ' + "$($why[3])".Trim() } else { '' }))
    }
    $run = ''
    if (Get-Command -Name Test-SIUpdateNowUpdaterRunning -ErrorAction SilentlyContinue) { $run = Test-SIUpdateNowUpdaterRunning -Executions @($Executions) -NowUtc $NowUtc }
    else { $run = @($Executions | Where-Object { $_ -and [string](Get-SIIndexBuildJobProp $_ @('properties', 'status')) -in @('Running', 'Processing') -and -not [string](Get-SIIndexBuildJobProp $_ @('properties', 'endTime')) } | ForEach-Object { [string]$_.name })[0] }
    if ("$run".Trim()) { return ('the updater runs ({0})' -f $run) }
    ''
}

function Get-SIIndexBuildOtherRunning {
    <# PURE. Another running execution of the index build job (not -Self), or ''. #>
    param([object[]]$Executions = @(), [string]$Self = '', [Parameter(Mandatory)][datetime]$NowUtc)
    $others = @($Executions | Where-Object { $_ -and [string]$_.name -ne $Self })
    if (Get-Command -Name Test-SIUpdateNowUpdaterRunning -ErrorAction SilentlyContinue) { return [string](Test-SIUpdateNowUpdaterRunning -Executions $others -NowUtc $NowUtc -RunLimitSeconds (Get-SIIndexBuildJobNames).RunLimit) }
    [string](@($others | Where-Object { [string](Get-SIIndexBuildJobProp $_ @('properties', 'status')) -in @('Running', 'Processing') -and -not [string](Get-SIIndexBuildJobProp $_ @('properties', 'endTime')) } | ForEach-Object { [string]$_.name })[0])
}

function Get-SIIndexBuildLockBeatSql {
    <# PURE. The install's lock beaten while this job holds it; answers N = 1 when it still does (0 = the updater took it). #>
    "SET NOCOUNT ON; DECLARE @n int = 0; IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL BEGIN UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), What = @What WHERE LockId = N'install' AND Holder = @Holder; SET @n = @@ROWCOUNT; END ELSE SET @n = 1; SELECT @n AS N;"
}

function Select-SIIndexBuildJobRow {
    <# PURE. The row this start builds: the one the runner named (-Table / -Index) when it still waits, is paused or was left
       'building'; else the one that has waited longest. $null = nothing to build. #>
    param([object[]]$Rows = @(), [string]$Table = '', [string]$Index = '')
    $ok = @($Rows | Where-Object { $_ -and $_.State -in @('waiting', 'paused', 'building') -and "$($_.Statement)".Trim() })
    if ($Table -and $Index) { $hit = @($ok | Where-Object { [string]$_.Table -ieq $Table -and [string]$_.Name -ieq $Index })[0]; if ($hit) { return $hit } }
    @($ok | Sort-Object { if ($_.SinceUtc) { ([datetime]$_.SinceUtc).ToUniversalTime() } else { [datetime]::MaxValue } })[0]
}

function Invoke-SIIndexBuildJob {
    <#
        ONE run of the index build job. -Store @{ Invoke (sql, params, mode); Open { } -> an open SqlConnection (the build's own) },
        -Holder (Get-SIIndexBuildJobHolder), -Request (Read-SIIndexBuildJobInput's), -Log { param($Line) }.
        -Seams (tests; each has a default over -Store and SI-IndexBuild.ps1 / the updater's run gate):
          Rows { }                                 -> cfg.IndexBuild rows (Read-SIIndexBuildRows)
          Save { param($Table, $Index, $State, $Why, [bool]$Forced) } -> $true when written (Save-SIIndexBuildRow)
          UpdateFirst { }                          -> '' or why an update goes first (REQUIRED in a real run; none = not now)
          OtherRunning { }                         -> '' or another running execution of this job
          Gate { param($Holder) }                  -> @{ Go; Reason; LockTaken } (the updater's run gate, no waiting)
          Beat { param($Holder, $What) }           -> $true while this job still holds the install's lock
          ExitGate { param($Holder) }              -> the lock released (only when this job holds it)
          Exists { param($Table, $Index) }         -> $true / $false / $null (unreadable)
          ResumableOp { param($Table, $Index) }    -> @{ State; Percent } or $null
          Build { param($Sql, $Interrupt, $OnInterrupt) } -> seconds; throws the SQL error, or the interrupt
          Pause { param($Sql) }                    -> ALTER INDEX ... PAUSE on a second connection
          Rate { param($Table, $Seconds) }         -> the measured rate recorded
        Returns @{ ExitCode (0; 1 = failed / stopped); Outcome; Line; Index }. Every path logs exactly one outcome and the
        closing line INDEX-BUILD outcome=... -- also when the run is STOPPED from outside (the finally).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Holder, $Request, [hashtable]$Seams = @{}, [scriptblock]$Log = { param($m) Write-Host $m },
          [datetime]$NowUtc = [datetime]::UtcNow)
    # ONE context, read by the plain scriptblocks below through PowerShell's dynamic scope (never GetNewClosure: a closure
    # does not see the functions dot-sourced into the caller); a distinct name, so no callee's variable hides it
    $siIxJobCtx = [pscustomobject]@{ Store = $Store; Holder = $Holder; Seams = $Seams; C = (Get-SIIndexBuildContract); Log = $Log
                                     Outcome = ''; Line = ''; Step = 'start'; Row = $null; LockTaken = $false; Started = $false; Resumable = $false; Forced = $false }
    if (-not $Request) { $Request = [pscustomobject]@{ Table = ''; Index = ''; Minutes = 0; Force = $false } }
    $say = { param([string]$m) try { $null = & $siIxJobCtx.Log ('index build: ' + $m) } catch { } }
    $seam = { param([string]$n) if ($siIxJobCtx.Seams.ContainsKey($n) -and $siIxJobCtx.Seams[$n]) { $siIxJobCtx.Seams[$n] } else { $null } }
    $save = {
        param([string]$State, [string]$Why, [bool]$Forced = $false)
        $r = $siIxJobCtx.Row; if (-not $r) { return $false }
        try {
            $s = & $seam 'Save'
            if ($s) { [bool](& $s $r.Table $r.Name $State $Why $Forced) }
            else { [bool](Save-SIIndexBuildRow -Invoke $siIxJobCtx.Store.Invoke -Table $r.Table -Index $r.Name -State $State -Why $Why -Forced:$Forced -By $siIxJobCtx.C.Job) }
        } catch { $false }
    }
    $end = { param([string]$Outcome, [string]$Line) $siIxJobCtx.Outcome = $Outcome; $siIxJobCtx.Line = $Line; & $say $Line }
    $updateFirst = {
        $u = & $seam 'UpdateFirst'
        if (-not $u) { return 'whether an update waits is not known to this run' }
        [string](& $u)
    }
    $exists = { param($t, $i) $x = & $seam 'Exists'; if ($x) { & $x $t $i } else { Test-SIIndexExists -Invoke $siIxJobCtx.Store.Invoke -Table $t -Index $i } }
    $op = { param($t, $i) $x = & $seam 'ResumableOp'; if ($x) { & $x $t $i } else { Read-SIIndexResumableOp -Invoke $siIxJobCtx.Store.Invoke -Table $t -Index $i } }
    $code = { param($o) if ($o -in @('failed', 'stopped')) { 1 } else { 0 } }
    # the steps run in ONE inner block: each 'return' there ends the steps, never the function -- the finally and the result
    # below are always reached (a bare return inside the try would have returned nothing)
    try { $null = & {
        # ---- 1. which index ----
        $siIxJobCtx.Step = 'read the waiting indexes'
        $rows = @()
        try { $rs = & $seam 'Rows'; $rows = @(if ($rs) { & $rs } else { Read-SIIndexBuildRows -Invoke $Store.Invoke }) }
        catch { & $end 'not-now' ('the waiting indexes could not be read ({0}) -- nothing built; the next idle window tries again' -f $_.Exception.Message); return }
        $row = Select-SIIndexBuildJobRow -Rows $rows -Table ([string]$Request.Table) -Index ([string]$Request.Index)
        if (-not $row) { & $end 'nothing' 'no index waits -- nothing to build'; return }
        $siIxJobCtx.Row = $row
        # ---- 2. THE UPDATE GOES FIRST: before anything is taken ----
        $siIxJobCtx.Step = 'look for an update'
        $u = ''
        try { $u = & $updateFirst } catch { $u = ('whether an update waits could not be read ({0})' -f $_.Exception.Message) }
        if ("$u".Trim()) { & $end 'not-now' ('not now -- {0}; the update goes first, {1} waits for the next idle window' -f $u, $row.Name); return }
        $siIxJobCtx.Step = 'look for another index build'
        $other = ''; try { $o = & $seam 'OtherRunning'; if ($o) { $other = [string](& $o) } } catch { $other = '' }
        if ("$other".Trim()) { & $end 'not-now' ('not now -- another index build runs ({0})' -f $other); return }
        # ---- 3. the install's lock (a pipeline run waits for the build; the updater takes it from the job at once) ----
        $siIxJobCtx.Step = 'take the install''s lock'
        $gs = & $seam 'Gate'
        $g = if ($gs) { & $gs $Holder } else { Invoke-SIUpdaterRunGate -Store $Store -Holder $Holder -What ('the index build of SecurityInsight: {0}' -f $row.Name) -BusyRetries 0 -TakeFrom '' }
        if (-not $g -or -not $g.Go) { & $end 'not-now' ('not now -- {0}; the pipeline runner starts it again at its next idle wake-up' -f $(if ($g) { $g.Reason } else { 'the install''s lock could not be asked for' })); return }
        $siIxJobCtx.LockTaken = [bool]$g.LockTaken
        $u = ''; try { $u = & $updateFirst } catch { $u = ('whether an update waits could not be read ({0})' -f $_.Exception.Message) }
        if ("$u".Trim()) { & $end 'not-now' ('not now -- {0}; the update goes first, {1} waits for the next idle window' -f $u, $row.Name); return }
        # ---- 4. what is there now ----
        $siIxJobCtx.Step = 'read the index'
        if ((& $exists $row.Table $row.Name) -eq $true) {
            $null = & $save 'built' 'found built'
            & $end 'built' ('{0} on {1} is there already -- nothing to build' -f $row.Name, $row.Table); return
        }
        $now0 = & $op $row.Table $row.Name
        if ($now0 -and [string]$now0.State -eq 'RUNNING') { & $end 'not-now' ('{0} on {1} is being built elsewhere ({2}%) -- nothing started' -f $row.Name, $row.Table, $now0.Percent); return }
        $minutes = if ([int]$Request.Minutes -gt 0) { [int]$Request.Minutes } else { 1440 }
        $run = Get-SIIndexBuildRunSql -Row $row -ResumableState $(if ($now0) { [string]$now0.State } else { '' }) -Minutes $minutes
        if (-not $run.Sql) {
            $null = & $save 'failed' 'its stored statement is not a CREATE INDEX this job builds -- the next update records it again'
            & $end 'failed' ('WARNING: {0} on {1}: its stored statement is not a CREATE INDEX this job builds -- nothing built' -f $row.Name, $row.Table); return
        }
        $siIxJobCtx.Resumable = [bool]$run.Resumable
        $since = if ($row.SinceUtc) { ([datetime]$row.SinceUtc).ToUniversalTime() } else { $NowUtc.ToUniversalTime() }
        $force = [bool]$Request.Force -or ((-not $row.ForcedUtc) -and (($NowUtc.ToUniversalTime() - $since).TotalDays -ge $siIxJobCtx.C.WaitDays))
        if (-not $run.Resumable) { $siIxJobCtx.Forced = $force }
        $est = if ($row.EstMinutes) { 'about ' + (Format-SIIndexDuration ([int]$row.EstMinutes)) } else { 'its time is not known' }
        if (-not $run.Resumable -and -not $force -and [int]$Request.Minutes -gt 0 -and $row.EstMinutes -and [int]$row.EstMinutes -gt [int]$Request.Minutes) {
            & $end 'not-now' ('{0} on {1}: {2}, more than the {3} before the next run -- it waits for a longer window' -f $row.Name, $row.Table, $est, (Format-SIIndexDuration ([int]$Request.Minutes))); return
        }
        # ---- 5. the build ----
        $siIxJobCtx.Step = 'build'
        $null = & $save 'building' $(if ($siIxJobCtx.Forced) { 'built after 7 days of waiting (once)' } elseif ($run.Resumable) { 'built in an idle window (resumable)' } else { 'built in an idle window' }) $siIxJobCtx.Forced
        $siIxJobCtx.Started = $true
        & $say ('{0} on {1} -- {2} now in an idle window ({3}{4}){5}' -f $row.Name, $row.Table, $run.How, $est, $(if ($run.Resumable) { ', up to ' + (Format-SIIndexDuration $minutes) + ' this window' } else { '' }),
                 $(if ($siIxJobCtx.Forced) { '; it has waited 7 days without an idle window long enough, so it is built now, once -- the next pipeline run waits for it' } else { '' }))
        $sayEvery = [pscustomobject]@{ Last = [datetime]::UtcNow }
        $interrupt = {
            param($Minutes)
            $why = ''
            try { $why = [string](& $updateFirst) } catch { $why = '' }
            if (-not "$why".Trim()) {
                $b = & $seam 'Beat'
                $held = $true
                try { $held = if ($b) { [bool](& $b $siIxJobCtx.Holder ('building index {0} ({1} min)' -f $siIxJobCtx.Row.Name, $Minutes)) } elseif ($siIxJobCtx.LockTaken) { [bool](@(Get-SIIndexReaderRows (& $siIxJobCtx.Store.Invoke (Get-SIIndexBuildLockBeatSql) ([ordered]@{ Holder = $siIxJobCtx.Holder; What = ('the index build of SecurityInsight: {0} ({1} min)' -f $siIxJobCtx.Row.Name, $Minutes) }) 'reader'))[0].N -gt 0) } else { $true } } catch { $held = $true }
                if (-not $held -and $siIxJobCtx.LockTaken) { $why = 'the updater took the install''s lock' }
            }
            if (([datetime]::UtcNow - $sayEvery.Last).TotalMinutes -ge $siIxJobCtx.C.SayEveryMinutes) { $sayEvery.Last = [datetime]::UtcNow; & $say ('{0} still building ({1} min so far)' -f $siIxJobCtx.Row.Name, $Minutes) }
            $why
        }
        $onInterrupt = {
            param($Command, $Reason)
            if ($siIxJobCtx.Resumable) {
                $p = Get-SIIndexBuildPauseSql -Table $siIxJobCtx.Row.Table -Index $siIxJobCtx.Row.Name
                $ps = & $seam 'Pause'
                if ($ps) { $null = & $ps $p } else { $null = & $siIxJobCtx.Store.Invoke $p @{} 'nonquery' }
            } elseif ($Command) { $Command.Cancel() }
        }
        $secs = 0.0; $err = $null; $stopWhy = ''
        try {
            $bs = & $seam 'Build'
            if ($bs) { $secs = [double](& $bs $run.Sql $interrupt $onInterrupt) }
            else {
                $cn = & $Store.Open
                try { $secs = [double](Invoke-SIIndexBuildCommand -Connection $cn -Sql $run.Sql -BeatSeconds $siIxJobCtx.C.CheckSeconds -Interrupt $interrupt -OnInterrupt $onInterrupt) } finally { try { $cn.Dispose() } catch { } }
            }
        } catch {
            if ($_.Exception.Data -and $_.Exception.Data.Contains('SIInterrupted')) { $stopWhy = [string]$_.Exception.Data['SIInterrupted'] } else { $err = $_.Exception.Message }
        }
        # ---- 6. what it came to: read back from the database, never assumed ----
        $siIxJobCtx.Step = 'read back'
        if ((& $exists $row.Table $row.Name) -eq $true) {
            $took = Format-SIIndexDuration ([int][Math]::Ceiling([Math]::Max(1.0, $secs) / 60.0))
            $null = & $save 'built' ('built in {0}' -f $took)
            if (-not $stopWhy -and -not $err -and -not ($now0 -and [string]$now0.State -eq 'PAUSED')) {
                try { $rt = & $seam 'Rate'; if ($rt) { $null = & $rt $row.Table $secs } else { $pg = Get-SIIndexTablePages -Invoke $Store.Invoke -Table $row.Table; if ($pg) { $null = Add-SIIndexBuildRateSample -Invoke $Store.Invoke -Pages $pg.Pages -Seconds $secs -By $siIxJobCtx.C.Job } } } catch { }
            }
            & $end 'built' ('{0} on {1} built in {2} (estimated {3})' -f $row.Name, $row.Table, $took, $est); return
        }
        $after = & $op $row.Table $row.Name
        if ($after -and [string]$after.State -eq 'PAUSED') {
            $why = if ($stopWhy) { 'paused at {0}% -- {1}; the update went first' -f $after.Percent, $stopWhy } else { 'paused at {0}% at the end of its window' -f $after.Percent }
            $null = & $save 'paused' $why
            & $end 'paused' ('{0} on {1}: {2} -- it resumes in the next idle window' -f $row.Name, $row.Table, $why); return
        }
        if ($stopWhy) {
            $why = 'stopped for an update ({0}): a filtered index cannot pause, so it was cancelled -- it is built again in the next idle window' -f $stopWhy
            $null = & $save 'waiting' $why
            & $end 'waiting' ('{0} on {1}: {2}' -f $row.Name, $row.Table, $why); return
        }
        $why = 'the build in an idle window failed ({0}) -- it waits for the next window; the release works without it' -f $(if ($err) { $err } else { 'the statement ended, the index is not there' })
        $null = & $save 'waiting' $why
        & $end 'failed' ('WARNING: {0} on {1}: {2}' -f $row.Name, $row.Table, $why)
    } } catch {
        $msg = $_.Exception.Message
        if ($siIxJobCtx.Started) { $null = & $save 'waiting' ('the build stopped at "{0}" ({1}) -- it waits for the next window' -f $siIxJobCtx.Step, $msg) }
        $null = & $end 'failed' ('WARNING: the index build failed at "{0}" ({1})' -f $siIxJobCtx.Step, $msg)
    } finally {
        if (-not $siIxJobCtx.Outcome) {
            # the run was ended from outside (its execution stopped) -- no catch saw it: the row is set back, said once
            $state = 'waiting'
            if ($siIxJobCtx.Started) {
                $o2 = $null; try { $o2 = & $op $siIxJobCtx.Row.Table $siIxJobCtx.Row.Name } catch { }
                if ($o2 -and [string]$o2.State -eq 'PAUSED') { $state = 'paused' }
                $null = & $save $state ('the index build job was stopped at "{0}" without an outcome -- it is built again in the next idle window' -f $siIxJobCtx.Step)
            }
            $siIxJobCtx.Outcome = 'stopped'
            $siIxJobCtx.Line = ('WARNING: the run ended at "{0}" without an outcome (the job was stopped){1}' -f $siIxJobCtx.Step, $(if ($siIxJobCtx.Started) { ' -- the index row is set back to ' + $state + ', the next idle window builds it again' } else { '' }))
            $null = & $say $siIxJobCtx.Line
        }
        if ($siIxJobCtx.LockTaken) {
            try { $x = & $seam 'ExitGate'; if ($x) { $null = & $x $Holder } else { $null = Exit-SIUpdaterRunGate -Store $Store -Holder $Holder } } catch { }
            $null = & $say 'the install''s lock is released'
        }
        $ixName = if ($siIxJobCtx.Row) { '{0}/{1}' -f $siIxJobCtx.Row.Table, $siIxJobCtx.Row.Name } else { 'none' }
        try { $null = & $siIxJobCtx.Log ('INDEX-BUILD outcome={0} index={1}' -f $siIxJobCtx.Outcome, $ixName) } catch { }
    }
    [pscustomobject]@{ ExitCode = (& $code $siIxJobCtx.Outcome); Outcome = $siIxJobCtx.Outcome; Line = $siIxJobCtx.Line
                       Index = $(if ($siIxJobCtx.Row) { $siIxJobCtx.Row.Name } else { '' }) }
}

# =====================================================================================================================
#  THE UPDATER'S SIDE: the job kept present (new and existing installs alike), read back
# =====================================================================================================================
function Get-SIIndexBuildJobIdentity {
    <#
        PURE. The updater's own managed identity, from its job (ARM shape): the attached user-assigned identity whose client id
        the updater signs in with (SI_UPDATER_CLIENT_ID), else the only one attached. An updater that signs in by certificate
        has none to give. Returns @{ Ok; Id; ClientId; Problem }.
    #>
    param($UpdaterJob)
    $no = { param($p) [pscustomobject]@{ Ok = $false; Id = ''; ClientId = ''; Problem = $p } }
    if (-not $UpdaterJob) { return (& $no 'the updater job could not be read') }
    $env = @(Get-SIIndexBuildJobProp (@(Get-SIIndexBuildJobProp $UpdaterJob @('properties', 'template', 'containers'))[0]) @('env'))
    $val = { param($n) $hit = @($env | Where-Object { $_ -and [string](Get-SIIndexBuildJobProp $_ @('name')) -eq $n })[0]; if ($hit) { ([string](Get-SIIndexBuildJobProp $hit @('value'))).Trim() } else { '' } }
    $cid = & $val 'SI_UPDATER_CLIENT_ID'
    $ua = Get-SIIndexBuildJobProp $UpdaterJob @('identity', 'userAssignedIdentities')
    $keys = if (-not $ua) { @() } elseif ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Name }) }
    if (-not $keys.Count) { return (& $no ('the updater has no managed identity (it signs in {0}) -- the index build job runs as the updater''s managed identity' -f $(if ((& $val 'SI_UPDATER_AUTH') -match '(?i)cert|spn') { 'by certificate' } else { 'without one' }))) }
    $cidOf = { param($k) [string](Get-SIIndexBuildJobProp $ua @([string]$k, 'clientId')) }
    if ($cid) { foreach ($k in $keys) { if ((& $cidOf $k) -ieq $cid) { return [pscustomobject]@{ Ok = $true; Id = [string]$k; ClientId = (& $cidOf $k); Problem = '' } } } }
    if ($keys.Count -eq 1 -and (& $cidOf $keys[0])) { return [pscustomobject]@{ Ok = $true; Id = [string]$keys[0]; ClientId = (& $cidOf $keys[0]); Problem = '' } }
    & $no 'the updater''s managed identity could not be told apart from the other identities on its job'
}

function Get-SIIndexBuildJobBody {
    <# PURE. caj-si-index-build: manual trigger, one replica, no retry, the engine image with its DEFAULT entry point
       (container\Start-SIInContainer.ps1 -> SI_ROLE = index-build), the UPDATER's identity (+ the engine jobs' pull identity,
       for the image only), the floor size, tagged with its spec fingerprint; no secret. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId, [Parameter(Mandatory)][string]$Image,
          [Parameter(Mandatory)][string]$RegistryServer, [Parameter(Mandatory)][string]$PullIdentityId, [Parameter(Mandatory)][string]$IdentityId,
          [Parameter(Mandatory)][string]$IdentityClientId, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$UpdaterJob = 'caj-si-updater')
    $n = Get-SIIndexBuildJobNames
    $ua = [ordered]@{}; $ua[$IdentityId] = [ordered]@{}
    if ($PullIdentityId.ToLowerInvariant() -ne $IdentityId.ToLowerInvariant()) { $ua[$PullIdentityId] = [ordered]@{} }
    $env = @(
        [ordered]@{ name = 'SI_ROLE'; value = $n.Role }
        [ordered]@{ name = 'SI_ENGINE'; value = $n.Role }
        [ordered]@{ name = 'SI_INDEXBUILD_SERVER'; value = $Server }
        [ordered]@{ name = 'SI_INDEXBUILD_DATABASE'; value = $Database }
        [ordered]@{ name = 'SI_INDEXBUILD_MI_CLIENT_ID'; value = $IdentityClientId }
        [ordered]@{ name = 'SI_INDEXBUILD_SUBSCRIPTION_ID'; value = $SubscriptionId }
        [ordered]@{ name = 'SI_INDEXBUILD_RESOURCE_GROUP'; value = $ResourceGroup }
        [ordered]@{ name = 'SI_INDEXBUILD_UPDATER_JOB'; value = $UpdaterJob }
    )
    $tags = [ordered]@{ product = 'securityinsight' }; $tags[$n.TagName] = $n.TagValue
    $body = [ordered]@{
        location = $Location; tags = $tags
        identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua }
        properties = [ordered]@{
            environmentId = $EnvironmentId
            configuration = [ordered]@{
                triggerType = 'Manual'; replicaTimeout = $n.RunLimit; replicaRetryLimit = 0
                manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 }
                registries = @([ordered]@{ server = $RegistryServer; identity = $PullIdentityId })
            }
            template = [ordered]@{ containers = @([ordered]@{ name = $n.Container; image = $Image; resources = [ordered]@{ cpu = 0.5; memory = '1Gi' }; env = $env }) }
        }
    }
    $tags[$n.SpecTag] = Get-SIIndexBuildJobFingerprint -Body $body
    $body
}

function Get-SIIndexBuildJobFingerprint {
    <# PURE. What the job must be, as one short hash: its identities, its environment, its trigger and size -- NOT its image
       (every roll moves the image of every job that runs SI's image, this one too). #>
    param([Parameter(Mandatory)]$Body)
    $ids = @(Get-SIIndexBuildJobProp $Body @('identity', 'userAssignedIdentities')) | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { @($_.Keys) } elseif ($_) { @($_.PSObject.Properties | ForEach-Object { $_.Name }) } }
    $c0 = @(Get-SIIndexBuildJobProp $Body @('properties', 'template', 'containers'))[0]
    $env = @(Get-SIIndexBuildJobProp $c0 @('env') | Where-Object { $_ } | ForEach-Object { '{0}={1}' -f [string](Get-SIIndexBuildJobProp $_ @('name')), [string](Get-SIIndexBuildJobProp $_ @('value')) } | Sort-Object)
    $cfg = Get-SIIndexBuildJobProp $Body @('properties', 'configuration')
    $txt = 'ids:{0}|env:{1}|trigger:{2}|limit:{3}|cpu:{4}|mem:{5}' -f ((@($ids | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)) -join ','), ($env -join ';'),
           [string](Get-SIIndexBuildJobProp $cfg @('triggerType')), [string](Get-SIIndexBuildJobProp $cfg @('replicaTimeout')),
           [string](Get-SIIndexBuildJobProp $c0 @('resources', 'cpu')), [string](Get-SIIndexBuildJobProp $c0 @('resources', 'memory'))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($txt)) | Select-Object -First 8 | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Test-SIIndexBuildJobReadBack {
    <# PURE. Is the job as ARM returns it the one -Body describes? @{ Ok; Problem }. #>
    param($Job, [Parameter(Mandatory)]$Body)
    $n = Get-SIIndexBuildJobNames
    if (-not $Job) { return [pscustomobject]@{ Ok = $false; Problem = 'it is not there' } }
    $ps = [string](Get-SIIndexBuildJobProp $Job @('properties', 'provisioningState'))
    if ($ps -and $ps -ne 'Succeeded') { return [pscustomobject]@{ Ok = $false; Problem = ('Azure shows {0}' -f $ps) } }
    $want = [string](Get-SIIndexBuildJobProp $Body @('tags', $n.SpecTag))
    if ([string](Get-SIIndexBuildJobProp $Job @('tags', $n.SpecTag)) -ne $want) { return [pscustomobject]@{ Ok = $false; Problem = 'its settings are not the ones written' } }
    $env = @(Get-SIIndexBuildJobProp (@(Get-SIIndexBuildJobProp $Job @('properties', 'template', 'containers'))[0]) @('env'))
    if (-not @($env | Where-Object { $_ -and [string](Get-SIIndexBuildJobProp $_ @('name')) -eq 'SI_ROLE' -and [string](Get-SIIndexBuildJobProp $_ @('value')) -eq $n.Role }).Count) { return [pscustomobject]@{ Ok = $false; Problem = 'it does not carry SI_ROLE = index-build' } }
    $ua = Get-SIIndexBuildJobProp $Job @('identity', 'userAssignedIdentities')
    $keys = if (-not $ua) { @() } elseif ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Name }) }
    $mine = @((Get-SIIndexBuildJobProp $Body @('identity', 'userAssignedIdentities')).Keys)[0]
    if (-not @($keys | Where-Object { ([string]$_) -ieq [string]$mine }).Count) { return [pscustomobject]@{ Ok = $false; Problem = 'it does not run as the updater''s identity' } }
    [pscustomobject]@{ Ok = $true; Problem = '' }
}

function Invoke-SIIndexBuildJobEnsure {
    <#
        THE UPDATER KEEPS caj-si-index-build PRESENT, on every Pro run (existing installs reach the new-install state through
        the update): the engine jobs' image, environment and pull identity (Get-SIDbInitTemplateJob), the updater's own
        identity (Get-SIIndexBuildJobIdentity), the Pro database. A job that already is what it must be is left alone (its
        spec fingerprint; the image is the roll's); otherwise ONE PUT, then READ BACK until Azure has made it. Never throws;
        nothing here holds an update. -Arm { param($Method, $Path, $Body) } (GET: $null = not found), -Lists { param($Kind) }
        ('jobs'), -Sleep. Returns @{ Ok; Action = kept | made | updated | not-ready | failed; Reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Lists, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [string]$Server, [string]$Database, [string]$UpdaterJob = 'caj-si-updater',
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Polls = 30)
    $n = Get-SIIndexBuildJobNames
    $res = { param($ok, $a, $why) [pscustomobject]@{ Ok = $ok; Action = $a; Reason = $why } }
    try {
        if (-not "$Server".Trim() -or -not "$Database".Trim()) { return (& $res $true 'not-ready' 'the index build job: this install has no Pro database -- nothing to build') }
        if (-not (Get-Command -Name Get-SIDbInitTemplateJob -ErrorAction SilentlyContinue)) { return (& $res $true 'not-ready' 'the index build job: this release does not carry the job template reader -- checked again at the next update') }
        $jobs = @(& $Lists 'jobs' | Where-Object { $_ })
        $tpl = Get-SIDbInitTemplateJob -Jobs $jobs
        if (-not $tpl.Ok) { return (& $res $true 'not-ready' ('the index build job: {0} -- checked again at the next update' -f $tpl.Problem)) }
        $upd = @($jobs | Where-Object { [string](Get-SIIndexBuildJobProp $_ @('name')) -ieq $UpdaterJob })[0]
        $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup
        if (-not $upd) { $upd = & $Arm 'GET' ('{0}/{1}?api-version={2}' -f $base, $UpdaterJob, $n.AppApi) $null }
        $mi = Get-SIIndexBuildJobIdentity -UpdaterJob $upd
        if (-not $mi.Ok) { return (& $res $true 'not-ready' ('the index build job: {0} -- the indexes that wait are built by the next update instead' -f $mi.Problem)) }
        $body = Get-SIIndexBuildJobBody -Location $tpl.Location -EnvironmentId $tpl.EnvironmentId -Image $tpl.Image -RegistryServer $tpl.RegistryServer -PullIdentityId $tpl.PullIdentityId `
                    -IdentityId $mi.Id -IdentityClientId $mi.ClientId -Server $Server -Database $Database -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -UpdaterJob $UpdaterJob
        $path = '{0}/{1}?api-version={2}' -f $base, $n.Job, $n.AppApi
        $cur = & $Arm 'GET' $path $null
        if ($cur -and (Test-SIIndexBuildJobReadBack -Job $cur -Body $body).Ok) { return (& $res $true 'kept' ('the index build job {0} is there as it must be (read back)' -f $n.Job)) }
        # an existing job keeps the image the roll gave it (the fingerprint leaves the image out)
        if ($cur) { $img = [string](Get-SIIndexBuildJobProp (@(Get-SIIndexBuildJobProp $cur @('properties', 'template', 'containers'))[0]) @('image')); if ($img -match '/si-orchestrator[:@]') { $body.properties.template.containers[0].image = $img } }
        $null = & $Arm 'PUT' $path $body
        $rb = $null; $job = $null
        for ($i = 0; $i -lt [Math]::Max(1, $Polls); $i++) {
            $job = & $Arm 'GET' $path $null
            $rb = Test-SIIndexBuildJobReadBack -Job $job -Body $body
            $ps = [string](Get-SIIndexBuildJobProp $job @('properties', 'provisioningState'))
            if ($rb.Ok -or $ps -in 'Failed', 'Canceled') { break }
            & $Sleep 10
        }
        if (-not $rb.Ok) { return (& $res $false 'failed' ('WARNING: the index build job {0} did not read back right ({1}) -- the next update tries again; the indexes that wait keep waiting' -f $n.Job, $rb.Problem)) }
        & $res $true $(if ($cur) { 'updated' } else { 'made' }) ('the index build job {0} was {1} and read back (it runs as the updater''s identity {2})' -f $n.Job, $(if ($cur) { 'brought up to date' } else { 'made' }), $mi.ClientId)
    } catch {
        & $res $false 'failed' ('WARNING: the index build job could not be kept present ({0}) -- the next update tries again' -f $_.Exception.Message)
    }
}
