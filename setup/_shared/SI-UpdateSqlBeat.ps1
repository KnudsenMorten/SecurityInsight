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
$script:SIUpdateSqlBeatStatement = "SET NOCOUNT ON; SET DEADLOCK_PRIORITY LOW; SET LOCK_TIMEOUT 10000; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT 0 AS Held; RETURN; END UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), What = @What WHERE LockId = @LockId AND Holder = @Holder; SELECT @@ROWCOUNT AS Held;"

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
    $held = 0
    foreach ($r in @($Target.Rows)) {
        $c = $State.Cn.CreateCommand(); $c.CommandTimeout = 30; $c.CommandText = [string]$Target.Statement   # limit-ok: one beat of a sign of life (one row update); a beat that waits longer is tried again at the next one
        [void]$c.Parameters.AddWithValue('@What', $What)
        [void]$c.Parameters.AddWithValue('@LockId', [string]$r.LockId)
        [void]$c.Parameters.AddWithValue('@Holder', [string]$r.Holder)
        $v = $c.ExecuteScalar()
        if ($null -ne $v -and -not ($v -is [System.DBNull])) { $held += [int]$v }
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
param($Stop, $Shared, [int]$IntervalMs, [double]$CapSeconds, [string]$What, $Log, $Target, [string]$BeatText)
$beat = [scriptblock]::Create($BeatText)
# the shared helpers the beat uses (the SQL open), loaded in THIS runspace -- never called in the update's
foreach ($lib in @($Target.Libs)) { try { if ("$lib".Trim() -and (Test-Path -LiteralPath $lib)) { . $lib } } catch { $Shared.LastError = [string]$_.Exception.Message } }
$state = @{ Cn = $null; Opens = 0; FreshTokens = 0; TokenError = ''; TokenLibsLoaded = $false }
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$say = { param([string]$l) try { [void]$Shared.Lines.Add($l) } catch { }; try { $Log.WriteLine(('    ' + $l)); $Log.Flush() } catch { } }
try {
    while (-not $Stop.WaitOne($IntervalMs)) {
        if ($sw.Elapsed.TotalSeconds -ge $CapSeconds) {
            $Shared.Capped = $true
            & $say ('{0}: SQL statement running {1} min -- past the {2} h a living update may take, so it no longer says it is alive; it is judged by its last sign of life' -f $What, [int][Math]::Floor($sw.Elapsed.TotalMinutes), ([Math]::Round($CapSeconds / 3600, 2)))
            break
        }
        $line = '{0}: SQL statement running {1} min' -f $What, [int][Math]::Floor($sw.Elapsed.TotalMinutes)
        $ok = $false
        # a dropped connection is about to be opened again: the token path is loaded HERE (this runspace's own scope, once)
        if ([int]$state.Opens -gt 0 -and -not $state.TokenLibsLoaded -and -not ($state.Cn -and $state.Cn.State -eq [System.Data.ConnectionState]::Open)) {
            $state.TokenLibsLoaded = $true
            foreach ($lib in @($Target.TokenLibs)) { try { if ("$lib".Trim() -and (Test-Path -LiteralPath $lib)) { . $lib } } catch { $Shared.LastError = [string]$_.Exception.Message } }
        }
        try { $ok = [bool](& $beat $Target $state ('an update of SecurityInsight: ' + $line)) } catch { $Shared.LastError = [string]$_.Exception.Message; $ok = $false }
        $Shared.Opens = [int]$state.Opens; $Shared.FreshTokens = [int]$state.FreshTokens; if ($state.TokenError) { $Shared.TokenError = [string]$state.TokenError }
        if ($ok) { $Shared.Beats = [int]$Shared.Beats + 1; $Shared.LastBeatUtc = [datetime]::UtcNow }
        else { $Shared.Failed = [int]$Shared.Failed + 1 }
        & $say $(if ($ok) { $line } else { $line + ' (its sign of life could not be written this time; the next beat tries again)' })
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
    param([string]$What = 'an update step', $Target, [double]$IntervalSeconds = 300, [double]$CapMinutes = 0,
          [System.IO.TextWriter]$Log, [string]$BeatScript)
    if (-not $Target) { return $null }
    if ($CapMinutes -le 0) { $CapMinutes = Get-SIUpdateSqlBeatCapMinutes }
    if ($IntervalSeconds -le 0) { $IntervalSeconds = 300 }
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
    [void]$ps.AddScript($script:SIUpdateSqlBeatLoop).AddArgument($stop).AddArgument($shared).AddArgument($ms).AddArgument([double]($CapMinutes * 60)).AddArgument([string]$What).AddArgument($Log).AddArgument($Target).AddArgument([string]$BeatScript)
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
    try { & $Action }
    finally {
        $script:SIUpdateSqlBeatActive = $false
        if ($sbBeat) { $script:SIUpdateSqlBeatLast = Stop-SIUpdateSqlBeat -Beat $sbBeat }
    }
}
