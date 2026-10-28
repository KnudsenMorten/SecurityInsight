#Requires -Version 5.1
<#
    SecurityInsight -- A LONG STEP OF THE UPDATE IS NEVER MISTAKEN FOR A HANG (#911 (e), live 2026-10-27: an update logged
    "==> 9b. PIPELINE SCHEDULE" and then nothing for an hour; the install looked hung).

    Start-SIUpdateWatch starts ONE background thread (its own runspace -- it never touches the update's variables) that
    looks every -CheckSeconds at the time of the update's last log line. When no line came for -QuietMinutes (20), it
    writes one line of its own to the process's standard output -- what the container's log keeps:
        [<utc>]     still working: <step> (no log line for 20 min)
    and again every -QuietMinutes while the step goes on. The update tells it each line (Set-SIUpdateWatchLine -Step),
    and also beats the install's lock at each step (Invoke-SIUpdaterLockBeat, the updater's run gate -- the thread does
    not touch SQL). Stop-SIUpdateWatch ends the thread. Nothing here throws. PS 5.1 and 7, no module.
#>

function New-SIUpdateWatchState {
    <# PURE. The state the update and the watch share (a synchronized table): Step, LastLineUtc, QuietMinutes, Said, Stop. #>
    param([double]$QuietMinutes = 20, $NowUtc)
    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    [hashtable]::Synchronized(@{ Step = ''; LastLineUtc = $now; QuietMinutes = [double]$QuietMinutes; Said = 0; Stop = $false })
}

function Get-SIUpdateWatchLine {
    <# PURE. The "still working" line due at -NowUtc for -State, or '' (a line came within QuietMinutes, or the watch is
       stopped). A line said moves LastLineUtc, so it is said again only after another QuietMinutes. #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][datetime]$NowUtc)
    if ($State.Stop) { return '' }
    $quiet = ($NowUtc.ToUniversalTime() - [datetime]$State.LastLineUtc).TotalMinutes
    if ($quiet -lt [double]$State.QuietMinutes) { return '' }
    $State.LastLineUtc = $NowUtc.ToUniversalTime(); $State.Said = [int]$State.Said + 1
    $step = if ("$($State.Step)".Trim()) { "$($State.Step)".Trim() } else { 'the update' }
    ('[{0:u}]     still working: {1} (no log line for {2:N0} min)' -f $NowUtc.ToUniversalTime(), $step, [Math]::Floor($quiet))
}

function Set-SIUpdateWatchLine {
    <# The update wrote a line (-Step: the step it is in now, when it changed). Never throws. #>
    param([string]$Step, [hashtable]$State = $global:SI_UpdateWatch)
    if (-not $State) { return }
    try { $State.LastLineUtc = [datetime]::UtcNow; if ("$Step".Trim()) { $State.Step = "$Step".Trim() } } catch { }
}

function Start-SIUpdateWatch {
    <#
        Starts the watch (one per process: a running one is kept) and returns its state ($global:SI_UpdateWatch). The thread
        writes to the process's standard output with [Console]::Out (a scriptblock of the update cannot cross runspaces).
        -NoThread: only the state (tests).
    #>
    param([double]$QuietMinutes = 20, [int]$CheckSeconds = 60, [switch]$NoThread)
    if ($global:SI_UpdateWatch -and $global:SI_UpdateWatchThread) { return $global:SI_UpdateWatch }
    $st = New-SIUpdateWatchState -QuietMinutes $QuietMinutes
    $global:SI_UpdateWatch = $st
    if ($NoThread) { return $st }
    try {
        $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        $null = $ps.AddScript({
            param($State, $Check, $LineFn)
            $fn = [scriptblock]::Create($LineFn)
            while (-not $State.Stop) {
                for ($i = 0; $i -lt $Check -and -not $State.Stop; $i++) { Start-Sleep -Seconds 1 }
                if ($State.Stop) { break }
                try { $l = & $fn $State ([datetime]::UtcNow); if ($l) { [Console]::Out.WriteLine($l); [Console]::Out.Flush() } } catch { }
            }
        }).AddArgument($st).AddArgument([Math]::Max(1, $CheckSeconds)).AddArgument(${function:Get-SIUpdateWatchLine}.ToString())
        $h = $ps.BeginInvoke()
        $global:SI_UpdateWatchThread = [pscustomobject]@{ PowerShell = $ps; Runspace = $rs; Handle = $h }
    } catch { $global:SI_UpdateWatchThread = $null }
    $st
}

function Stop-SIUpdateWatch {
    <# Ends the watch's thread. Never throws. #>
    try { if ($global:SI_UpdateWatch) { $global:SI_UpdateWatch.Stop = $true } } catch { }
    $t = $global:SI_UpdateWatchThread
    if ($t) {
        try { $null = $t.Handle.AsyncWaitHandle.WaitOne(3000) } catch { }
        try { $t.PowerShell.Stop() } catch { }
        try { $t.PowerShell.Dispose(); $t.Runspace.Dispose() } catch { }
    }
    $global:SI_UpdateWatchThread = $null; $global:SI_UpdateWatch = $null
}
