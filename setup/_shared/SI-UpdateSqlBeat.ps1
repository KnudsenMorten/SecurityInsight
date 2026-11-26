#Requires -Version 5.1
<#
    SecurityInsight -- A DATABASE STATEMENT OF THE UPDATE KEEPS ITS SIGN OF LIFE (setup\Invoke-SIContainerUpdate.ps1).

    WHY. Live 2026-11-12: the pipeline runner's rule "NO FRESH BEAT = DEAD" (engine\_shared\SI-ExecutionLiveness.ps1: an
    execution is dead 15 minutes after its last beat on its lock row) stopped updates at two installs in a silent stretch after
    '9q. COLLECT PRODUCERS'. The updater beats its 'updater' row with every log line -- but a long database statement writes
    no line: the summary views' statement (9f, no time limit) or one long range of the published copies (9j) ran for more
    than 15 minutes without one, and a working update was stopped as a dead one.

    THE BEAT. Every database statement of the update runs inside Invoke-SIUpdateSqlBeat. While the statement runs, a
    BACKGROUND RUNSPACE beats the update's own lock rows every -IntervalSeconds (5 minutes) and writes one log line per beat:
        <step>: SQL statement running <N> min
      * its OWN connection: the beat opens a connection of its own to the database that holds the lock rows (the Pro
        database, cfg.PipelineLock) through the shared open (engine\_shared\SI-SqlRetry.ps1, loaded in the beat's runspace)
        -- never the connection that is busy with the statement. The access token is taken on the main thread when the
        statement starts and is the FIRST one; the beat keeps its one connection open for the statement's whole time (an
        open session stays signed in). A connection that DROPS is opened again with a FRESH token, fetched inside the beat's
        own runspace: the REST client's own token path (engine\_shared\SI-LogIngest.ps1 + SI-AzRest.ps1 +
        auth\SI-ManagedIdentity.ps1, loaded in that runspace at the first re-open) for the identity the update signed in
        as (a copy of its recorded sign-in) -- never a call into the update's runspace. No fresh token = the first one.
      * it always LOSES a deadlock: every beat runs SET DEADLOCK_PRIORITY LOW, so the update's own statement never does.
      * its OWN thread and runspace: the beat's code is compiled INSIDE that runspace from text -- it never calls back into
        the update's runspace (a scriptblock of the busy runspace called from another thread would wait for it: a deadlock).
        The main thread only sets an event when the statement ends and waits for the beat at most -StopWaitMs; nothing the
        beat does can throw into the statement (every beat, every log line and the stop are caught).
      * ONLY WHILE A STATEMENT RUNS: started right before the statement, stopped in a finally when it ends or throws. A hang
        anywhere else writes no beat, and the unchanged rule judges it dead 15 minutes after its last one.
      * NEVER FOREVER: past the liveness rule's own outer cap (Get-SIExecutionLivenessContract FallbackHours, 6 h) the beat
        stops, says so in one line, and the unchanged rule judges the update dead 15 minutes later.
      * the rows: the update's own row ('updater', $global:SI_UpdaterExecBeat) and, while this update holds it, the install
        lock ('install', $global:SI_UpdaterLockBeat) -- what every log line of the update beats (Invoke-SIUpdaterLockBeat).
        Nothing is beaten outside the updater (a run by hand registers no row): the statement just runs.
    Nested statements (a step that runs statements inside a beaten one) are beaten once, by the outer one.

    SEAMS (tests): -Target @{ Server; Database; AccessToken; ConnectText (the open's -Connect seam as text); Libs; Rows =
    @(@{ LockId; Holder }); TokenText (the fresh-token fetch as text: param($Target) -> a token); TokenLibs; Auth }; -BeatScript, the TEXT of
    param($Target, $State, [string]$What) -> $true when a row was beaten (compiled in the beat's runspace);
    -IntervalSeconds / -CapMinutes; -Log, a TextWriter (default the console: the container's log). The same values may come
    from $global:SI_UpdateSqlBeatSettings (a hashtable with those keys). PS 5.1 and 7; no PowerShell module.
#>

# the one statement a beat runs per row (the 'install' row too: Get-SIExecutionLockSql 'Beat' leaves that row to the run gate)
# (DEADLOCK_PRIORITY LOW: a beat always loses a deadlock against the update's own statement)
# #1406 (review) the answer, one number per row: 1 = beaten; 0 = the row is free / gone (the update let it go); -1 = this
# update has written its END MARK (row 'updater-ended' names it) -- nothing is beaten after it, a late beat never makes a
# finished update look alive; -2 = ANOTHER execution holds the row now (a take-over, said -- never read as "let go")
$script:SIUpdateSqlBeatAnswer = "IF @@ROWCOUNT > 0 SELECT 1 AS Held; ELSE IF EXISTS (SELECT 1 FROM cfg.PipelineLock WHERE LockId = @LockId AND Holder IS NOT NULL AND Holder <> @Holder) SELECT -2 AS Held; ELSE SELECT 0 AS Held;"
$script:SIUpdateSqlBeatEndCheck = "IF EXISTS (SELECT 1 FROM cfg.PipelineLock WHERE LockId = N'updater-ended' AND Holder = @Holder) BEGIN SELECT -1 AS Held; RETURN; END"
$script:SIUpdateSqlBeatStatement = "SET NOCOUNT ON; SET DEADLOCK_PRIORITY LOW; SET LOCK_TIMEOUT 10000; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT 0 AS Held; RETURN; END $script:SIUpdateSqlBeatEndCheck UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), What = @What WHERE LockId = @LockId AND Holder = @Holder; $script:SIUpdateSqlBeatAnswer"
# #1406 the run's beat (Start-SIUpdateRunBeat): the heartbeat only, never the row's What (@What is passed and not used)
$script:SIUpdateRunBeatStatement = "SET NOCOUNT ON; SET DEADLOCK_PRIORITY LOW; SET LOCK_TIMEOUT 10000; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT 0 AS Held; RETURN; END $script:SIUpdateSqlBeatEndCheck UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME() WHERE LockId = @LockId AND Holder = @Holder; $script:SIUpdateSqlBeatAnswer"

# the shared open (engine\_shared\SI-SqlRetry.ps1: Microsoft's transient answers tried again), loaded INSIDE the beat's runspace
$script:SIUpdateSqlBeatRetryLib = [IO.Path]::Combine($PSScriptRoot, '..', '..', 'engine', '_shared', 'SI-SqlRetry.ps1')

# the REST client's token path (the one the updater signs in with), loaded INSIDE the beat's runspace only when a dropped
# connection must be opened again -- in this order (the token functions, the client, the managed-identity endpoint)
$script:SIUpdateSqlBeatTokenLibs = @(
    [IO.Path]::Combine($PSScriptRoot, '..', '..', 'engine', '_shared', 'SI-LogIngest.ps1'),
    [IO.Path]::Combine($PSScriptRoot, '..', '..', 'engine', '_shared', 'SI-AzRest.ps1'),
    [IO.Path]::Combine($PSScriptRoot, '..', '..', 'auth', 'SI-ManagedIdentity.ps1'))

# THE FRESH TOKEN (text: compiled in the beat's own runspace). param($Target) -> a NEW access token for Azure SQL, as the
# identity the update signed in as ($Target.Auth: a copy of its recorded sign-in), or '' (the first token is used).
$script:SIUpdateSqlBeatTokenScript = @'
param($Target)
if (-not ($Target.Auth -is [hashtable])) { return '' }
if (-not (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue)) { return '' }
[string](Get-SIAzureToken -Resource 'https://database.windows.net/' -Auth $Target.Auth -ForceRefresh)
'@

# THE PRODUCTION BEAT (text: compiled in the beat's own runspace). One connection -- the shared open, Open-SISqlConnectionRetry,
# with the token the main thread took -- opened at the first beat and kept for the statement's whole time; a broken one is
# opened again at the next beat. $Target.ConnectText: the open's own -Connect seam, as text (tests: a SQL login).
$script:SIUpdateSqlBeatScript = @'
param($Target, $State, [string]$What)
if ($What.Length -gt 200) { $What = $What.Substring(0, 200) }
try {
    if (-not $State.Cn -or $State.Cn.State -ne [System.Data.ConnectionState]::Open) {
        if ($State.Cn) { try { $State.Cn.Dispose() } catch { } }
        $State.Cn = $null
        # the first open: the main thread's token; a RE-open (the connection dropped -- its token may have run out since)
        # or a retry the open asks for: a FRESH token fetched here, in this runspace ($Target.TokenText); none = the first
        $tok = [string]$Target.AccessToken
        $fetchFresh = $null; if ("$($Target.TokenText)".Trim()) { $fetchFresh = [scriptblock]::Create([string]$Target.TokenText) }
        $reopen = ([int]$State.Opens -gt 0)
        $tgt = $Target; $st = $State
        $tokFn = { param([bool]$Fresh)
            if (($Fresh -or $reopen) -and $fetchFresh) {
                $t = ''; try { $t = "$(& $fetchFresh $tgt)".Trim() } catch { $t = ''; $st.TokenError = [string]$_.Exception.Message }
                if ($t) { $st.FreshTokens = [int]$st.FreshTokens + 1; return $t }
            }
            $tok }.GetNewClosure()
        $open = @{ Server = [string]$Target.Server; Database = [string]$Target.Database; Token = $tokFn; Waits = @(5, 10) }
        if ("$($Target.ConnectText)".Trim()) { $open['Connect'] = [scriptblock]::Create([string]$Target.ConnectText) }
        $State.Cn = Open-SISqlConnectionRetry @open
        $State.Opens = [int]$State.Opens + 1
    }
    $held = 0; $State.Lost = @()
    foreach ($r in @($Target.Rows)) {
        $c = $State.Cn.CreateCommand(); $c.CommandTimeout = 30; $c.CommandText = [string]$Target.Statement   # limit-ok: one beat of a sign of life (one row update); a beat that waits longer is tried again at the next one
        [void]$c.Parameters.AddWithValue('@What', $What)
        [void]$c.Parameters.AddWithValue('@LockId', [string]$r.LockId)
        [void]$c.Parameters.AddWithValue('@Holder', [string]$r.Holder)
        $v = $c.ExecuteScalar()
        $n = if ($null -ne $v -and -not ($v -is [System.DBNull])) { [int]$v } else { 0 }
        # (1 beaten; -1 its end mark is written: nothing more is beaten; -2 another execution holds this row now)
        if ($n -eq -1) { $State.Ended = $true; return $false }
        if ($n -eq -2) { $State.Lost = @($State.Lost) + [string]$r.LockId }
        if ($n -gt 0) { $held += $n }
    }
    return ($held -gt 0)
} catch {
    if ($State.Cn) { try { $State.Cn.Dispose() } catch { } }
    $State.Cn = $null
    throw
}
'@

# THE LOOP of the beat's runspace (text). Waits on the stop event; never calls the update's runspace.
$script:SIUpdateSqlBeatLoop = @'
param($Stop, $Shared, [int]$IntervalMs, [double]$CapSeconds, [string]$What, $Log, $Target, [string]$BeatText, [int]$BeatMs = 0, $Progress = $null, [double]$QuietSeconds = 840)
$beat = [scriptblock]::Create($BeatText)
if ($BeatMs -le 0 -or $BeatMs -gt $IntervalMs) { $BeatMs = $IntervalMs }
# the shared helpers the beat uses (the SQL open), loaded in THIS runspace -- never called in the update's. #1406: a library
# that is missing or does not load is SAID (live 2026-11-26 every beat failed and the line never said why)
foreach ($lib in @($Target.Libs)) {
    try { if ("$lib".Trim() -and (Test-Path -LiteralPath $lib)) { . $lib } elseif ("$lib".Trim()) { $Shared.LastError = ('the beat''s library {0} was not found' -f $lib) } }
    catch { $Shared.LastError = [string]$_.Exception.Message }
}
$state = @{ Cn = $null; Opens = 0; FreshTokens = 0; TokenError = ''; TokenLibsLoaded = $false }
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$say = { param([string]$l) try { [void]$Shared.Lines.Add($l) } catch { }; try { $Log.WriteLine(('    ' + $l)); $Log.Flush() } catch { } }
$loadTokenLibs = {
    if ($state.TokenLibsLoaded) { return }
    $state.TokenLibsLoaded = $true
    foreach ($lib in @($Target.TokenLibs)) { try { if ("$lib".Trim() -and (Test-Path -LiteralPath $lib)) { . $lib } } catch { $Shared.LastError = [string]$_.Exception.Message } }
}
# ONE beat: written, or -- #1406 -- tried ONCE MORE at once on a NEW connection with a FRESH token (the old one dropped, its
# sign-in ran out, a lock wait ran out): a beat that fails says WHY in its line
$beatOnce = {
    param([string]$BeatWhat)
    $why = ''
    for ($try = 0; $try -lt 2; $try++) {
        if ($try -gt 0) { if ($state.Cn) { try { $state.Cn.Dispose() } catch { } }; $state.Cn = $null; if ([int]$state.Opens -lt 1) { $state.Opens = 1 }; . $loadTokenLibs }
        elseif ([int]$state.Opens -gt 0 -and -not ($state.Cn -and $state.Cn.State -eq [System.Data.ConnectionState]::Open)) { . $loadTokenLibs }
        try {
            $state.Ended = $false; $state.Lost = @()
            $ok1 = [bool](& $beat $Target $state $BeatWhat)
            $lost = @($state.Lost | Where-Object { $_ })
            if ($lost.Count) { $Shared.LostText = ('another execution holds the lock row(s) {0} now' -f ($lost -join ', ')) }
            if ($ok1) { return '' }
            # its end mark is written, or the rows are free (it let them go): nothing is left to beat -- the beat ends
            if ($state.Ended -or -not $lost.Count) { $Shared.Released = $true; $Shared.EndMark = [bool]$state.Ended; return 'released' }
            # (review) a TAKE-OVER is never read as "let go": a failed beat, said, tried again at the next one
            return [string]$Shared.LostText
        } catch { $why = ([string]$_.Exception.Message -split "`n")[0].Trim() }
        $Shared.LastError = $why
    }
    $why
}
$quietSaid = $false; $lastLine = $sw.Elapsed.TotalSeconds; $failedSince = $false; $lostSaid = $false
try {
    while (-not $Stop.WaitOne($BeatMs)) {
        if ($sw.Elapsed.TotalSeconds -ge $CapSeconds) {
            $Shared.Capped = $true
            & $say ('{0}: SQL statement running {1} min -- past the {2} h a living update may take, so it no longer says it is alive; it is judged by its last sign of life' -f $What, [int][Math]::Floor($sw.Elapsed.TotalMinutes), ([Math]::Round($CapSeconds / 3600, 2)))
            break
        }
        # #1406 THE RUN'S BEAT (-Progress): it beats only while the update works -- a statement runs (Progress.Sql), or a
        # step said a line in the last -QuietSeconds; a hang anywhere else is left to the rule (said once)
        if ($Progress) {
            $busy = ([int]$Progress.Sql -gt 0) -or ((([datetime]::UtcNow) - [datetime]$Progress.LastUtc).TotalSeconds -lt $QuietSeconds)
            if (-not $busy) {
                if (-not $quietSaid) { $quietSaid = $true; & $say ('{0}: no step has reported for {1} min -- its sign of life is no longer written until the next step reports' -f $What, [int][Math]::Floor($QuietSeconds / 60)) }
                continue
            }
            $quietSaid = $false
        }
        $line = '{0}: SQL statement running {1} min' -f $What, [int][Math]::Floor($sw.Elapsed.TotalMinutes)
        # (dot-sourced: the token path it loads stays loaded in THIS scope for every later beat)
        $why = . $beatOnce ('an update of SecurityInsight: ' + $(if ($Progress) { $What } else { $line }))
        if ($why -eq 'released') {
            # the update let its rows go (or another took them): the beat ends -- the run's beat silently, a statement's in one line
            if (-not $Progress) { & $say ('{0} (the update no longer holds its lock rows -- its sign of life is no longer written)' -f $line) }
            break
        }
        $ok = -not $why
        $Shared.Opens = [int]$state.Opens; $Shared.FreshTokens = [int]$state.FreshTokens; if ($state.TokenError) { $Shared.TokenError = [string]$state.TokenError }
        if ($ok) { $Shared.Beats = [int]$Shared.Beats + 1; $Shared.LastBeatUtc = [datetime]::UtcNow }
        else { $Shared.Failed = [int]$Shared.Failed + 1 }
        # the line: every -IntervalMs for a statement (and at once when a beat fails or comes back); the run's beat speaks
        # only when a beat fails or comes back
        $due = (-not $Progress) -and (($sw.Elapsed.TotalSeconds - $lastLine) * 1000 -ge ($IntervalMs - 50))
        if (-not $ok) { & $say ('{0} (its sign of life could not be written this time: {1}; the next beat tries again in {2} s)' -f $(if ($Progress) { $What + ': the update''s sign of life' } else { $line }), $why, [int][Math]::Round($BeatMs / 1000)); $lastLine = $sw.Elapsed.TotalSeconds; $failedSince = $true }
        elseif ($Shared.LostText -and -not $lostSaid) { $lostSaid = $true; & $say ('{0}: {1} -- the sign of life goes on on its other row(s)' -f $What, $Shared.LostText) }
        elseif ($due -or $failedSince) { & $say $(if ($Progress) { $What + ': the update''s sign of life is written again' } else { $line }); $lastLine = $sw.Elapsed.TotalSeconds; $failedSince = $false }
    }
} finally {
    if ($state.Cn) { try { $state.Cn.Dispose() } catch { } }
    $Shared.Ended = $true
}
'@

function Get-SIUpdateSqlBeatCapMinutes {
    <# PURE. The beat's cap: the liveness rule's own outer fallback (6 h) when the rule is loaded, else 360 minutes. #>
    if (Get-Command -Name Get-SIExecutionLivenessContract -ErrorAction SilentlyContinue) {
        try { $h = [double](Get-SIExecutionLivenessContract).FallbackHours; if ($h -gt 0) { return ($h * 60) } } catch { }
    }
    360
}

function Get-SIUpdateSqlBeatRows {
    <# PURE (reads the update's registrations). The lock rows a beat writes: the update's own row and the install lock it holds.
       Test seams registered there (a -Beat scriptblock) are never called from the beat's thread: no row for them. #>
    $rows = New-Object System.Collections.Generic.List[object]
    $x = $global:SI_UpdaterExecBeat
    if ($x -and "$($x.Holder)".Trim() -and -not $x.Beat) { $rows.Add([pscustomobject]@{ LockId = 'updater'; Holder = [string]$x.Holder }) }
    $b = $global:SI_UpdaterLockBeat
    if ($b -and "$($b.Holder)".Trim() -and $b.Real -and -not $b.Beat) { $rows.Add([pscustomobject]@{ LockId = 'install'; Holder = [string]$b.Holder }) }
    , $rows.ToArray()
}

function Get-SIUpdateSqlBeatTarget {
    <#
        Where the beat writes, read on the MAIN thread right before a statement: @{ Server; Database; AccessToken; ConnectText;
        Libs; Statement; Rows }, or $null (no row to beat: not run by the updater; no Pro database; no token). The Pro database is the one the
        updater's sign of life lives in -- the server and database its registration names, else SI_UPDATER_PRO_SQL_SERVER /
        _DATABASE (the variables the updater opened it from). -Token: { } -> an access token (default: the run's REST client).
    #>
    param([scriptblock]$Token)
    $rows = @(Get-SIUpdateSqlBeatRows)
    if (-not $rows.Count) { return $null }
    $x = $global:SI_UpdaterExecBeat
    $srv = ''; $db = ''
    if ($x -and $x.PSObject.Properties['Server']) { $srv = "$($x.Server)".Trim(); $db = "$($x.Database)".Trim() }
    if (-not $srv -or -not $db) {
        $srv = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_PRO_SQL_SERVER'))".Trim()
        $db = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_PRO_SQL_DATABASE'))".Trim()
    }
    if (-not $srv -or -not $db) { return $null }
    if ($srv -notmatch '\.') { $srv = $srv + '.database.windows.net' }
    $tok = ''
    try {
        if ($Token) { $tok = "$(& $Token)".Trim() }
        elseif (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue) { $tok = "$([string](Get-SIAzureToken -Resource 'https://database.windows.net/'))".Trim() }
    } catch { $tok = '' }
    if (-not $tok) { return $null }
    # the means to fetch a FRESH token in the beat's own runspace: a copy of the sign-in the update recorded (who it is --
    # never a token), read here on the main thread; none recorded = the beat has the first token only
    $auth = $null
    try { if (Get-Command -Name Get-SIAzRestState -ErrorAction SilentlyContinue) { $c = (Get-SIAzRestState).Connection; if ($c -is [hashtable]) { $auth = $c.Clone() } } } catch { $auth = $null }
    [pscustomobject]@{ Server = $srv; Database = $db; AccessToken = $tok; ConnectText = ''; Libs = @($script:SIUpdateSqlBeatRetryLib)
                       Statement = $script:SIUpdateSqlBeatStatement; Rows = $rows
                       Auth = $auth; TokenText = $script:SIUpdateSqlBeatTokenScript; TokenLibs = @($script:SIUpdateSqlBeatTokenLibs) }
}

function Start-SIUpdateSqlBeat {
    <# Starts the beat of one statement in a runspace of its own. Returns the handle for Stop-SIUpdateSqlBeat, or $null
       (no target). Throws only when the runspace cannot be made (the caller runs the statement without a beat). #>
    # #1406 -BeatSeconds: how often the row is beaten (default 60 s -- a beat that fails has 14 more chances before the 15
    # minutes of the rule, where 5 minutes gave it 2); -IntervalSeconds stays how often the statement's line is said.
    # -Progress: the RUN's beat (Start-SIUpdateRunBeat) -- beats only while the update works (see the loop)
    param([string]$What = 'an update step', $Target, [double]$IntervalSeconds = 300, [double]$CapMinutes = 0,
          [System.IO.TextWriter]$Log, [string]$BeatScript, [double]$BeatSeconds = 60, $Progress = $null, [double]$QuietSeconds = 840)
    if (-not $Target) { return $null }
    if ($CapMinutes -le 0) { $CapMinutes = Get-SIUpdateSqlBeatCapMinutes }
    if ($IntervalSeconds -le 0) { $IntervalSeconds = 300 }
    if ($BeatSeconds -le 0 -or $BeatSeconds -gt $IntervalSeconds) { $BeatSeconds = $IntervalSeconds }
    if (-not $Log) { $Log = [Console]::Out }
    if (-not "$BeatScript".Trim()) { $BeatScript = $script:SIUpdateSqlBeatScript }
    if ($Target -is [System.Collections.IDictionary]) { $Target = [pscustomobject]$Target }
    if (-not $Target.PSObject.Properties['Statement'] -or -not "$($Target.Statement)".Trim()) { $Target | Add-Member -NotePropertyName Statement -NotePropertyValue $script:SIUpdateSqlBeatStatement -Force }
    $shared = [hashtable]::Synchronized(@{ Beats = 0; Failed = 0; Capped = $false; Ended = $false; LastBeatUtc = $null; LastError = ''; Opens = 0; FreshTokens = 0; TokenError = ''
                                           Lines = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) })
    $stop = New-Object System.Threading.ManualResetEvent($false)
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $ms = [int][Math]::Max(1, [Math]::Min([double][int]::MaxValue, $IntervalSeconds * 1000))
    $bms = [int][Math]::Max(1, [Math]::Min([double][int]::MaxValue, $BeatSeconds * 1000))
    [void]$ps.AddScript($script:SIUpdateSqlBeatLoop).AddArgument($stop).AddArgument($shared).AddArgument($ms).AddArgument([double]($CapMinutes * 60)).AddArgument([string]$What).AddArgument($Log).AddArgument($Target).AddArgument([string]$BeatScript).AddArgument($bms).AddArgument($Progress).AddArgument([double]$QuietSeconds)
    $async = $ps.BeginInvoke()
    [pscustomobject]@{ PowerShell = $ps; Runspace = $rs; Async = $async; Stop = $stop; Shared = $shared; What = $What }
}

function Stop-SIUpdateSqlBeat {
    <# Ends the beat of a statement that ended (or threw). Waits for the beat at most -StopWaitMs (a beat in the middle of its
       own short statement); one that does not end by then is left to end by itself. Never throws. Returns the beat's record
       (Beats, Failed, Capped, Lines, LastBeatUtc, LastError). #>
    param($Beat, [int]$StopWaitMs = 15000)
    if (-not $Beat) { return $null }
    try { [void]$Beat.Stop.Set() } catch { }
    $ended = $false
    try { $ended = [bool]$Beat.Async.AsyncWaitHandle.WaitOne($StopWaitMs) } catch { $ended = $false }
    if ($ended) {
        try { $null = $Beat.PowerShell.EndInvoke($Beat.Async) } catch { }
        try { $Beat.PowerShell.Dispose() } catch { }
        try { $Beat.Runspace.Dispose() } catch { }
        try { $Beat.Stop.Dispose() } catch { }
    }
    $Beat.Shared
}

function Invoke-SIUpdateSqlBeat {
    <#
        Runs -Action (the statement: Execute* and reading its rows) with the beat around it -- started right before, stopped in
        a finally. Its output is passed on unchanged. -What: the step the log line names (default: the step the update is in).
        A beat that cannot start is no reason to fail: the statement runs as before. The record of the last beat is kept in
        $script:SIUpdateSqlBeatLast (tests).
    #>
    param([string]$What = '', [Parameter(Mandatory)][scriptblock]$Action, $Target, [double]$IntervalSeconds = 0, [double]$CapMinutes = 0,
          [System.IO.TextWriter]$Log, [string]$BeatScript)
    # (the action runs in a child scope of this function and reads the statement's variables -- $cmd, $Mode, $rd ... -- by
    # dynamic scope: this function's own variables carry the sb prefix, so none of them hides one of those)
    if ($script:SIUpdateSqlBeatActive) { & $Action; return }
    $sbSet = $global:SI_UpdateSqlBeatSettings
    if ($sbSet -is [System.Collections.IDictionary]) {
        if (-not $Target -and $sbSet.Contains('Target')) { $Target = $sbSet['Target'] }
        if ($IntervalSeconds -le 0 -and $sbSet.Contains('IntervalSeconds')) { $IntervalSeconds = [double]$sbSet['IntervalSeconds'] }
        if ($CapMinutes -le 0 -and $sbSet.Contains('CapMinutes')) { $CapMinutes = [double]$sbSet['CapMinutes'] }
        if (-not $Log -and $sbSet.Contains('Log')) { $Log = $sbSet['Log'] }
        if (-not "$BeatScript".Trim() -and $sbSet.Contains('BeatScript')) { $BeatScript = [string]$sbSet['BeatScript'] }
    }
    $sbWhat = if ("$What".Trim()) { "$What".Trim() } elseif ("$global:SI_UpdateStage".Trim()) { "$global:SI_UpdateStage".Trim() } else { 'an update step' }
    $sbBeat = $null
    try {
        if (-not $Target) { $Target = Get-SIUpdateSqlBeatTarget }
        if ($Target) { $sbBeat = Start-SIUpdateSqlBeat -What $sbWhat -Target $Target -IntervalSeconds $IntervalSeconds -CapMinutes $CapMinutes -Log $Log -BeatScript $BeatScript }
    } catch { $sbBeat = $null }
    $script:SIUpdateSqlBeatActive = [bool]$sbBeat
    # #1406: the run's beat knows a statement runs (it beats on through it, whatever the statement's own beat manages)
    $sbRun = $global:SI_UpdateRunBeat
    if ($sbRun -and $sbRun.Progress) { try { $sbRun.Progress.Sql = [int]$sbRun.Progress.Sql + 1 } catch { } }
    try { & $Action }
    finally {
        $script:SIUpdateSqlBeatActive = $false
        if ($sbRun -and $sbRun.Progress) { try { $sbRun.Progress.Sql = [Math]::Max(0, [int]$sbRun.Progress.Sql - 1); $sbRun.Progress.LastUtc = [datetime]::UtcNow } catch { } }
        if ($sbBeat) { $script:SIUpdateSqlBeatLast = Stop-SIUpdateSqlBeat -Beat $sbBeat }
    }
}

# =====================================================================================================================
#  #1406 THE RUN'S BEAT -- the update's sign of life from a thread and a connection of its own, from the release script's
#  FIRST step to its end (live 2026-11-26: the pipeline flow tick stopped an update whose key-figure statement ran 17
#  minutes while every statement beat failed, and left the install half updated). It does not depend on the update's own
#  thread, its log lines or its connections: it beats the update's rows every -BeatSeconds (60) while the update WORKS -- a
#  statement runs, or a step said a line in the last 14 minutes. A hang anywhere else is not beaten (the rule judges it, as
#  before). One per process; Stop-SIUpdateRunBeat ends it (the end of the release script, the updater's own end); a run's
#  beat left running stops by itself 14 minutes after the last line (and its rows are no longer this update's after the
#  updater lets them go: a beat then changes nothing).
# =====================================================================================================================
function Set-SIUpdateRunBeatProgress {
    <# A step said a line: the run's beat goes on beating. Never throws. #>
    $r = $global:SI_UpdateRunBeat
    if ($r -and $r.Progress) { try { $r.Progress.LastUtc = [datetime]::UtcNow } catch { } }
}

function Start-SIUpdateRunBeat {
    <# Starts the run's beat once (a second call keeps the first). Returns the record, or $null (no row to beat: not run by
       the updater). Never throws. -Target / -BeatSeconds / -QuietSeconds / -Log / -BeatScript: seams. #>
    param($Target, [double]$BeatSeconds = 60, [double]$QuietSeconds = 840, [System.IO.TextWriter]$Log, [string]$BeatScript, [string]$What = 'the update')
    if ($global:SI_UpdateRunBeat) { return $global:SI_UpdateRunBeat }
    try {
        $own = $false
        if (-not $Target) {
            $Target = Get-SIUpdateSqlBeatTarget
            if (-not $Target) { return $null }
            # (review) the run's own row 'updater-run': "this update is CHANGING the install" -- what makes a stale beat QUIET
            # rather than dead (engine\_shared\SI-ExecutionLiveness.ps1); taken here, on the main thread, released at its stop
            $holder = [string]$global:SI_UpdaterExecBeat.Holder
            if (Enter-SIUpdateRunBeatRow -Holder $holder) {
                $own = $true
                $Target.Rows = @(@($Target.Rows) + [pscustomobject]@{ LockId = 'updater-run'; Holder = $holder })
            }
        }
        if ($Target -is [System.Collections.IDictionary]) { $Target = [pscustomobject]$Target }
        # the run's beat writes the heartbeat ONLY -- the row's What stays what the steps write (the web app reads the
        # database window's notice from it, #1112)
        if (-not $Target.PSObject.Properties['Statement'] -or -not "$($Target.Statement)".Trim() -or [string]$Target.Statement -eq $script:SIUpdateSqlBeatStatement) {
            $Target | Add-Member -NotePropertyName Statement -NotePropertyValue $script:SIUpdateRunBeatStatement -Force
        }
        $progress = [hashtable]::Synchronized(@{ Sql = 0; LastUtc = [datetime]::UtcNow })
        $b = Start-SIUpdateSqlBeat -What $What -Target $Target -IntervalSeconds ([Math]::Max($BeatSeconds, 300)) -BeatSeconds $BeatSeconds -Log $Log -BeatScript $BeatScript -Progress $progress -QuietSeconds $QuietSeconds
        if (-not $b) { if ($own) { Exit-SIUpdateRunBeatRow -Holder $holder }; return $null }
        $b | Add-Member -NotePropertyName Progress -NotePropertyValue $progress -Force
        # what the updater (or the release script's own end) needs to end it and let its row go, without this file's functions
        $b | Add-Member -NotePropertyName RunRow -NotePropertyValue $(if ($own) { [pscustomobject]@{ Store = $global:SI_UpdaterExecBeat.Store; Holder = $holder } } else { $null }) -Force
        $global:SI_UpdateRunBeat = $b
        $b
    } catch { $null }
}

function Stop-SIUpdateRunBeat {
    <# Ends the run's beat (when one runs) -- waits for it up to -StopWaitMs (45 s: a beat in the middle of its own short
       statements ends first) -- and lets its row 'updater-run' go. Never throws; returns its record or $null. #>
    param([int]$StopWaitMs = 45000)
    $r = $global:SI_UpdateRunBeat
    $global:SI_UpdateRunBeat = $null
    if (-not $r) { return $null }
    $rec = $null
    try { $rec = Stop-SIUpdateSqlBeat -Beat $r -StopWaitMs $StopWaitMs } catch { $rec = $null }
    if ($r.PSObject.Properties['RunRow'] -and $r.RunRow) { Exit-SIUpdateRunBeatRow -Holder ([string]$r.RunRow.Holder) -Store $r.RunRow.Store }
    $rec
}

function Stop-SIUpdateRunBeatAtEnd {
    <#
        (review) The end of the release script's steps (Complete-SIUpdate): an updater that ends the run's beat itself (its
        Unregister-SIUpdaterExecutionBeat knows SI_UpdateRunBeat -- from this release on) keeps it to its end mark; an OLDER
        updater (the first update to this release runs the release before it) never would -- the beat ends HERE. Never throws.
    #>
    try {
        $u = Get-Command -Name Unregister-SIUpdaterExecutionBeat -ErrorAction SilentlyContinue
        if ($u -and "$($u.Definition)" -match 'SI_UpdateRunBeat') { return }
        $null = Stop-SIUpdateRunBeat
    } catch { }
}

function Enter-SIUpdateRunBeatRow {
    <#
        (review) Takes the run's row 'updater-run' for -Holder (free, stale 15 minutes, or its own) -- but NEVER from another
        execution Azure still runs: $global:SI_UpdaterExecBeat.Busy (the updater's running executions, read by the updater)
        names it -> not taken (a quiet update keeps what protects it). Without that list: the lock rule only. $true = held.
        Never throws.
    #>
    param([Parameter(Mandatory)][string]$Holder, $Store)
    $x = $global:SI_UpdaterExecBeat
    if (-not $Store -and $x) { $Store = $x.Store }
    if (-not $Store -or -not "$Holder".Trim() -or -not (Get-Command -Name Enter-SIExecutionLock -ErrorAction SilentlyContinue)) { return $false }
    try {
        if (-not (Test-SIUpdateRowFreeOfRunning -Store $Store -Lock 'updater-run' -Holder $Holder)) { return $false }
        [bool](Enter-SIExecutionLock -Store $Store -Lock 'updater-run' -Holder $Holder -What 'an update of SecurityInsight: changing the install')
    } catch { $false }
}

function Exit-SIUpdateRunBeatRow {
    <# Lets the run's row 'updater-run' go (only while -Holder holds it). Never throws. #>
    param([string]$Holder, $Store)
    if (-not $Store -and $global:SI_UpdaterExecBeat) { $Store = $global:SI_UpdaterExecBeat.Store }
    if (-not $Store -or -not "$Holder".Trim() -or -not (Get-Command -Name Exit-SIExecutionLock -ErrorAction SilentlyContinue)) { return }
    try { Exit-SIExecutionLock -Store $Store -Lock 'updater-run' -Holder $Holder } catch { }
}

function Test-SIUpdateRowFreeOfRunning {
    <#
        (review) $false when the lock row -Lock is held by ANOTHER execution that Azure still runs ($global:SI_UpdaterExecBeat.Busy:
        the names, read by the updater before it registered). No list, or the rows cannot be read: $true (the lock rule only).
    #>
    param($Store, [string]$Lock, [string]$Holder)
    $x = $global:SI_UpdaterExecBeat
    $busy = @(); if ($x -and $x.PSObject.Properties['Busy']) { $busy = @($x.Busy | Where-Object { "$_".Trim() }) }
    if (-not $busy.Count -or -not (Get-Command -Name Read-SIExecutionLocks -ErrorAction SilentlyContinue)) { return $true }
    try {
        $row = @((Read-SIExecutionLocks -Store $Store).Rows | Where-Object { $_.LockName -eq $Lock })[0]
        if (-not $row -or -not "$($row.Holder)".Trim() -or [string]$row.Holder -eq $Holder) { return $true }
        foreach ($n in $busy) { if (Test-SIExecutionHolder -Holder ([string]$row.Holder) -Name ([string]$n)) { return $false } }
        $true
    } catch { $true }
}
