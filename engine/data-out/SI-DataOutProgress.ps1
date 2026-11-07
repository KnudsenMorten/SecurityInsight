#Requires -Version 5.1
<#
    SecurityInsight DATA OUT -- THE PROGRESS OF ONE OUTPUT (#1043, owner 2026-11-01: "consider to add telemetry here. i feel
    we are blind"). Found at the pilot: the vulnerable-item output ran 45+ minutes with ONE log line, nothing recorded as sent
    and the database idle -- nobody could tell building from sending, how far it had got or when it would end.

    WHAT IS KEPT (in memory, per output, counted per page -- never per row):
      * the PHASE the writer is in -- read (a page of items from the database), build (the rows of a page: map, keys, the
        state compare, the CI check), send (a page to the destination), close (the end row), readback (the last batch's
        import result) -- and the seconds spent in each so far. The pages interleave (read, build, send, read ...), so each
        phase's time is the sum over the pages; build also keeps the time of its parts (Add-SIDataOutProgressPart);
      * rows read, items built, pages sent, rows sent of the planned (an estimate until the end: the last batch's count, or
        the grain's row count), rows held, rows per second and the time left.

    WHAT IS WRITTEN, BATCHED (owner 2026-11-01: "maybe batch the telemetry for performance so it doesnt delay upload"):
      * at most once per 60 s, and at each milestone (sending starts, the items are done, what was sent before is done, the
        end): ONE INFO log line and ONE small UPDATE of the output's cfg.DataOutBatch row (Phase, RowsPlanned, RowsSent,
        RowsHeld, PagesSent, LastProgressUtc) -- only when the batch has a row;
      * the UPDATE waits at most 2 s for a lock (SET LOCK_TIMEOUT), is NEVER retried, never throws: a write that fails is
        skipped (three failures, or one that took 5 s or more, and the database writes stop for this output, said once); the
        log line goes on. The send never waits for its telemetry.
      * A STALL: no progress for 10 minutes (the time between two signs of progress, whatever the phase) -> one WARN line and
        a note for the run record (Get-SIDataOutProgressNotes). It never stops the send.
    The heartbeat (SI-HeartbeatFields.ps1, DataOut) reads the batch row when it is sent anyway -- no call is added here.

    PURE but for the log and the one UPDATE through the store it is given. -Clock { [datetime] UTC } is the test seam.
    PowerShell 7; also parses on 5.1. No PowerShell modules. No script-scope state: the progress is the hashtable returned.
#>

function Get-SIDataOutProgressPhases { <# PURE. The phases, in the order they first happen in a run. #> , @('readback', 'read', 'build', 'send', 'close') }

function New-SIDataOutProgress {
    <#
        The progress of ONE output (a hashtable the writer carries as W.Progress). -EverySec: the write cadence (60);
        -StallSec: no progress for this long is a stall (600); -SlowWriteSec: a database write this slow stops the database
        writes for this output (5). -Planned: the rows the output is expected to send (-1 = not known); -PlannedKind: where
        that number comes from (Get-SIDataOutPlannedSource) -- 'grain' is the rows the output READS (a first run: the
        grain's table), never rows to send, and the line says so.
    #>
    param([Parameter(Mandatory)][string]$Output, [string]$Label = '', [scriptblock]$Log, [scriptblock]$Clock,
          [int]$EverySec = 60, [int]$StallSec = 600, [int]$SlowWriteSec = 5, [long]$Planned = -1, [string]$PlannedKind = 'batch')
    if (-not $Clock) { $Clock = { [datetime]::UtcNow } }
    $now = [datetime](& $Clock)
    $sec = [ordered]@{}; foreach ($ph in (Get-SIDataOutProgressPhases)) { $sec[$ph] = 0.0 }
    @{ Output = $Output; Label = $(if ($Label) { $Label } else { $Output }); Log = $Log; Clock = $Clock
       EverySec = $EverySec; StallSec = $StallSec; SlowWriteSec = $SlowWriteSec
       Started = $now; Phase = 'read'; PhaseAt = $now; PhaseSec = $sec; Parts = [ordered]@{}
       RowsRead = 0L; ItemsBuilt = 0L; PagesSent = 0L; RowsSent = 0L; RowsHeld = 0L; Planned = $Planned; PlannedKind = $PlannedKind
       LastProgressUtc = $now; LastWriteUtc = $now; Stalls = 0; StallOpen = $false; Notes = (New-Object System.Collections.Generic.List[string])
       Store = $null; BatchId = ''; DbOff = $false; DbFails = 0; DbWrites = 0; DbSkipped = 0; Lines = 0; Done = $false }
}

function Set-SIDataOutProgressBatch {
    <# From here on the progress is also written to the batch row -BatchId (cfg.DataOutBatch) through -Store. #>
    param($Progress, $Store, [string]$BatchId)
    $P = $Progress
    if ($null -eq $P -or -not $Store -or -not $BatchId) { return }
    $P.Store = $Store; $P.BatchId = $BatchId
}

function Add-SIDataOutProgressPart {
    <# The time of one part of the build (a page's map, its state read, ...) since -Watch was started; the watch restarts. #>
    param($Progress, [Parameter(Mandatory)][string]$Part, [Parameter(Mandatory)][System.Diagnostics.Stopwatch]$Watch)
    $P = $Progress
    if ($null -eq $P) { return }
    $s = $Watch.Elapsed.TotalSeconds
    $Watch.Restart()
    if ($P.Parts.Contains($Part)) { $P.Parts[$Part] += $s } else { $P.Parts[$Part] = $s }
}

function Step-SIDataOutProgress {
    <#
        One step of the output: -Phase switches the phase (its time so far is added up); the counts are added. A step with a
        count advances the progress. A stall (no progress for StallSec) is said once per stall; at most every EverySec the
        progress is written (Write-SIDataOutProgress). In memory but for that write. Never throws.
    #>
    param($Progress, [string]$Phase = '', [long]$RowsRead = 0, [long]$ItemsBuilt = 0, [long]$PagesSent = 0, [long]$RowsSent = 0, [long]$RowsHeld = 0)
    $P = $Progress
    if ($null -eq $P -or $P.Done) { return }
    try {
        $now = [datetime](& $P.Clock)
        if ($Phase -and $Phase -ne $P.Phase) {
            $P.PhaseSec[$P.Phase] = [double]$P.PhaseSec[$P.Phase] + [Math]::Max(0.0, ($now - $P.PhaseAt).TotalSeconds)
            $P.Phase = $Phase; $P.PhaseAt = $now
            if (-not $P.PhaseSec.Contains($Phase)) { $P.PhaseSec[$Phase] = 0.0 }
        }
        $moved = ($RowsRead -gt 0 -or $ItemsBuilt -gt 0 -or $PagesSent -gt 0 -or $RowsSent -gt 0 -or $RowsHeld -gt 0)
        if ($moved) {
            $gap = ($now - $P.LastProgressUtc).TotalSeconds
            if ($gap -ge $P.StallSec) { Add-SIDataOutProgressStall -Progress $P -Now $now -Minutes ([int][Math]::Floor($gap / 60)) }
            $P.RowsRead += $RowsRead; $P.ItemsBuilt += $ItemsBuilt; $P.PagesSent += $PagesSent; $P.RowsSent += $RowsSent; $P.RowsHeld += $RowsHeld
            $P.LastProgressUtc = $now
        } elseif (($now - $P.LastProgressUtc).TotalSeconds -ge $P.StallSec -and -not $P.StallOpen) {
            Add-SIDataOutProgressStall -Progress $P -Now $now -Minutes ([int][Math]::Floor(($now - $P.LastProgressUtc).TotalSeconds / 60))
            $P.StallOpen = $true
        }
        if ($moved) { $P.StallOpen = $false }
        if (($now - $P.LastWriteUtc).TotalSeconds -ge $P.EverySec) { Write-SIDataOutProgress -Progress $P -Now $now }
    } catch { }
}

function Add-SIDataOutProgressStall {
    <# A stall: one WARN line, a note for the run record. Never stops anything. #>
    param($Progress, [datetime]$Now, [int]$Minutes)
    $P = $Progress
    if ($P.StallOpen) { return }
    $P.Stalls++
    $note = [string]::Format([Globalization.CultureInfo]::InvariantCulture, 'no progress for {0} min in phase {1} (at {2:HH:mm}Z; {3:N0} rows read, {4:N0} sent) -- the send went on', $Minutes, $P.Phase, $Now, $P.RowsRead, $P.RowsSent)
    if ($P.Notes.Count -lt 5) { $P.Notes.Add($note) }
    try { if ($P.Log) { & $P.Log 'WARN' ('{0}: STALLED -- {1}' -f $P.Label, $note) } } catch { }
}

function Get-SIDataOutProgressRate {
    <# PURE. Rows per second so far (rows read, else rows sent) and the seconds left against Planned (-1 = not known). #>
    param([Parameter(Mandatory)]$Progress, [datetime]$Now)
    $P = $Progress
    $el = [Math]::Max(0.001, ($Now - $P.Started).TotalSeconds)
    $done = $(if ($P.RowsRead -gt 0) { $P.RowsRead } else { $P.RowsSent })
    $rate = [Math]::Round($done / $el, 2)
    $left = -1.0
    if ($P.Planned -gt 0 -and $rate -gt 0 -and $P.Planned -gt $done) { $left = [Math]::Round(($P.Planned - $done) / $rate, 0) }
    elseif ($P.Planned -gt 0 -and $done -ge $P.Planned) { $left = 0.0 }
    [pscustomobject]@{ RowsPerSec = $rate; SecondsLeft = $left; Elapsed = $el }
}

function Format-SIDataOutProgressLine {
    <# PURE. The one progress line (and, -Final, the line that ends the output with the time of every phase). #>
    param([Parameter(Mandatory)]$Progress, [Parameter(Mandatory)][datetime]$Now, [switch]$Final)
    $P = $Progress
    # one number format for the log, whatever the container's culture (1,234.5)
    $fm = { param($f) [string]::Format([Globalization.CultureInfo]::InvariantCulture, $f, $args) }
    $sec = [ordered]@{}; foreach ($k in $P.PhaseSec.get_Keys()) { $sec[$k] = [double]$P.PhaseSec[$k] }
    $sec[$P.Phase] = [double]$sec[$P.Phase] + [Math]::Max(0.0, ($Now - $P.PhaseAt).TotalSeconds)
    $tl = New-Object System.Collections.Generic.List[string]
    foreach ($ph in @($sec.get_Keys())) {
        if ($sec[$ph] -lt 0.05) { continue }
        $t = & $fm '{0} {1:N1} s' $ph $sec[$ph]
        if ($ph -eq 'build' -and $P.Parts.Count) {
            $pl = New-Object System.Collections.Generic.List[string]
            foreach ($pn in @($P.Parts.get_Keys())) { $pl.Add((& $fm '{0} {1:N1} s' $pn $P.Parts[$pn])) }
            $t += ' (' + ($pl -join ', ') + ')'
        }
        $tl.Add($t)
    }
    $times = $tl -join ', '
    $r = Get-SIDataOutProgressRate -Progress $P -Now $Now
    # #1140: the grain's row count (a first run's plan) is the rows the output READS -- said as rows to read, beside the rows
    # read; only an earlier batch's count is a plan of rows to SEND
    $toRead = ''; $plan = ''
    if ($P.Planned -ge 0) {
        if ([string]$P.PlannedKind -eq 'grain') { $toRead = & $fm ' (of ~{0:N0} rows to read)' $P.Planned }
        else { $plan = & $fm ' of ~{0:N0} planned' $P.Planned }
    }
    $counts = & $fm '{0:N0} rows read{6}, {1:N0} items built, {2:N0} page(s) sent, {3:N0} rows sent{4}, {5:N0} held' $P.RowsRead $P.ItemsBuilt $P.PagesSent $P.RowsSent $plan $P.RowsHeld $toRead
    if ($Final) { return (& $fm '{0}: progress -- done in {1:N1} s; {2}; {3:N1} rows/s; {4}' $P.Label $r.Elapsed $counts $r.RowsPerSec $(if ($times) { $times } else { 'no phase timed' })) }
    $left = $(if ($r.SecondsLeft -ge 0) { & $fm 'about {0:N0} min left' ([Math]::Ceiling($r.SecondsLeft / 60)) } else { 'time left not known yet' })
    & $fm '{0}: progress -- phase {1}; {2}; {3:N1} rows/s; {4} ({5})' $P.Label $P.Phase $counts $r.RowsPerSec $left $times
}

function Get-SIDataOutProgressWriteSql {
    <# ONE small UPDATE of the batch row (#1043): its lock wait at most 2 s; a database without the columns does nothing. #>
    @'
SET NOCOUNT ON; SET LOCK_TIMEOUT 2000;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL OR COL_LENGTH('cfg.DataOutBatch', 'LastProgressUtc') IS NULL RETURN;
UPDATE cfg.DataOutBatch SET Phase = @Phase, RowsPlanned = NULLIF(CONVERT(bigint, @RowsPlanned), -1), RowsSent = CONVERT(bigint, @RowsSent), RowsHeld = CONVERT(bigint, @RowsHeld),
       PagesSent = CONVERT(bigint, @PagesSent), LastProgressUtc = CONVERT(datetime2(3), @LastProgressUtc, 126)
WHERE BatchId = @BatchId;
'@
}

function New-SIDataOutProgressParams {
    <# PURE. The parameters of Get-SIDataOutProgressWriteSql for the progress as it stands. #>
    param([Parameter(Mandatory)]$Progress)
    $P = $Progress
    [ordered]@{ BatchId = [string]$P.BatchId; Phase = [string]$P.Phase; RowsPlanned = [long]$P.Planned; RowsSent = [long]$P.RowsSent; RowsHeld = [long]$P.RowsHeld
                PagesSent = [long]$P.PagesSent; LastProgressUtc = ([datetime]$P.LastProgressUtc).ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) }
}

function Write-SIDataOutProgress {
    <#
        THE ONE WRITE (batched: Step-SIDataOutProgress calls it at most every EverySec; a milestone calls it directly): one INFO
        line, and one UPDATE of the batch row when the output has one. Never retried, never throws; a failed write is skipped.
    #>
    param($Progress, [datetime]$Now = [datetime]::MinValue, [switch]$Final)
    $P = $Progress
    if ($null -eq $P) { return }
    try {
        if ($Now -eq [datetime]::MinValue) { $Now = [datetime](& $P.Clock) }
        $P.LastWriteUtc = $Now
        try { if ($P.Log) { & $P.Log 'INFO' (Format-SIDataOutProgressLine -Progress $P -Now $Now -Final:$Final) }; $P.Lines++ } catch { }
        if (-not $P.Store -or -not $P.Store.Invoke -or -not $P.BatchId) { return }
        if ($P.DbOff) { $P.DbSkipped++; return }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { [void](& $P.Store.Invoke (Get-SIDataOutProgressWriteSql) (New-SIDataOutProgressParams -Progress $P) 'nonquery'); $P.DbWrites++ }
        catch {
            $P.DbFails++; $P.DbSkipped++
            if ($P.DbFails -ge 3) {
                $P.DbOff = $true
                try { if ($P.Log) { & $P.Log 'WARN' ('{0}: the progress could not be recorded in the database three times ({1}) -- from here it is only logged; the send goes on' -f $P.Label, $_.Exception.Message) } } catch { }
            }
        }
        if (-not $P.DbOff -and $sw.Elapsed.TotalSeconds -ge $P.SlowWriteSec) {
            $P.DbOff = $true
            try { if ($P.Log) { & $P.Log 'WARN' ('{0}: recording the progress took {1:N1} s -- from here it is only logged, so the send is never slowed by it' -f $P.Label, $sw.Elapsed.TotalSeconds) } } catch { }
        }
    } catch { }
}

function Complete-SIDataOutProgress {
    <# The end of the output: the last phase's time added, the final line and write (-Planned: the rows the run did plan). #>
    param($Progress, [long]$Planned = -1)
    $P = $Progress
    if ($null -eq $P -or $P.Done) { return }
    try {
        $now = [datetime](& $P.Clock)
        if ($Planned -ge 0) { $P.Planned = $Planned }
        Write-SIDataOutProgress -Progress $P -Now $now -Final
        $P.PhaseSec[$P.Phase] = [double]$P.PhaseSec[$P.Phase] + [Math]::Max(0.0, ($now - $P.PhaseAt).TotalSeconds); $P.PhaseAt = $now
        $P.Done = $true
    } catch { }
}

function Get-SIDataOutProgressNotes {
    <# PURE. The notes for the run record (the stalls), one text; '' when there is none. #>
    param($Progress)
    if ($null -eq $Progress -or -not $Progress.Notes -or $Progress.Notes.Count -eq 0) { return '' }
    'SLOW: ' + (@($Progress.Notes) -join '; ')
}

function Get-SIDataOutPlannedSql {
    <# The rows an output is expected to send: its newest ended live / resync batch's planned rows (cfg.DataOutBatch, its index). #>
    @'
SET NOCOUNT ON; SET LOCK_TIMEOUT 2000;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL SELECT CAST(NULL AS bigint) AS Planned WHERE 1 = 0;
ELSE SELECT TOP (1) PlannedRows AS Planned FROM cfg.DataOutBatch
     WHERE OutputId = @OutputId AND State IN (N'complete', N'failed', N'held') AND Mode IN (N'live', N'resync') AND PlannedRows IS NOT NULL
     ORDER BY StartedAt DESC;
'@
}

function Get-SIDataOutGrainCountSql {
    <# The rows of a grain in the data database -- the plan of a first run (no earlier batch): the table's row count from the
       catalogue (sys.partitions -- no read of the table itself, an estimate). #>
    param([Parameter(Mandatory)][string]$Grain)
    $t = switch ($Grain) { 'ci_finding' { 'sidata.CiFinding' } 'ci' { 'sidata.Ci' } default { '' } }
    if (-not $t) { return '' }
    "SET NOCOUNT ON; SELECT ISNULL((SELECT SUM(p.rows) FROM sys.partitions AS p WHERE p.object_id = OBJECT_ID(N'$t') AND p.index_id IN (0, 1)), -1) AS N;"
}

function Get-SIDataOutPlannedSource {
    <#
        The rows an output is expected to send, read ONCE before its first page (never in the send path), and where the number
        comes from: @{ Rows; Kind } -- 'batch' the newest ended batch's planned rows; else, for a first run, 'gen' / 'items'
        (the items in hand) or 'grain' (the grain's table rows in the data database: rows to READ, not rows to send); 'none'
        and -1 = not known. Never throws.
        #1140 (live 2026-11-07): the batch read answered nothing although the last live batch qualified -- the store's reader
        answers its rows as ONE array, and the filter looked at that array (not a dictionary) instead of at its rows. The rows
        are unrolled first now (as every reader of the store does).
    #>
    param([Parameter(Mandatory)][string]$OutputId, [string]$Grain = '', $Store, [hashtable]$Cursor)
    try {
        if ($Store -and $Store.Invoke) {
            $a = @(& $Store.Invoke (Get-SIDataOutPlannedSql) @{ OutputId = $OutputId } 'reader' | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] })
            if ($a.Count -and $null -ne $a[0]['Planned'] -and -not ($a[0]['Planned'] -is [System.DBNull])) { return [pscustomobject]@{ Rows = [long]$a[0]['Planned']; Kind = 'batch' } }
        }
    } catch { }
    try {
        if ($Cursor) {
            if ($Cursor.Phase -eq 'gen') { return [pscustomobject]@{ Rows = [long]$Cursor.Total; Kind = 'gen' } }
            if ($Cursor.Phase -eq 'items' -and $null -ne $Cursor.Items) { return [pscustomobject]@{ Rows = [long]@($Cursor.Items).Count; Kind = 'items' } }
            $sql = $(if ($Grain) { Get-SIDataOutGrainCountSql -Grain $Grain } else { '' })
            if ($sql -and $Cursor.Invoke) {
                $n = & $Cursor.Invoke $sql @{} 'scalar'
                if ($null -ne $n -and -not ($n -is [System.DBNull]) -and [long]$n -ge 0) { return [pscustomobject]@{ Rows = [long]$n; Kind = 'grain' } }
            }
        }
    } catch { }
    [pscustomobject]@{ Rows = -1L; Kind = 'none' }
}

function Get-SIDataOutPlannedEstimate {
    <# The rows of Get-SIDataOutPlannedSource alone (-1 = not known). Never throws. #>
    param([Parameter(Mandatory)][string]$OutputId, [string]$Grain = '', $Store, [hashtable]$Cursor)
    [long](Get-SIDataOutPlannedSource -OutputId $OutputId -Grain $Grain -Store $Store -Cursor $Cursor).Rows
}
