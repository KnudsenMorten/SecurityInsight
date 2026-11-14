#Requires -Version 5.1
<#
    SI -- THE OUTCOME OF A RUN: what it published, not only whether it threw.

    A run that could not publish to Log Analytics used to end 'success' with exit code 0 (measured in the 2.2 -> 3.0
    upgrade test: "[DONE] n rows -> 1/2 sink(s) OK [LA=FAIL]", then "Engine completed successfully"). Everything that
    reads run health -- a monitor, the telemetry run report, the vulnerability close-loop -- then took a lost publish
    for a whole one. Absence is not remediation: a run that published less than it collected says so.

    The ExitReason vocabulary is the existing one (Send-SIRunHealthRow, SI-Telemetry):
      success          -- everything the run produced reached every output it was asked to write
      success-partial  -- the run finished, but an output failed or holds less than it should (exit code stays 0, as
                          for a Risk Analysis run that lost query buckets -- the 2.2 contract)
      error            -- nothing reached any output (the run throws, so the exit code is non-zero, as in 2.2)

    THE DATABASE IS AN OUTPUT OF ITS OWN. A collection reports 'SQL' (its records -> the database) next to 'LA' (its
    profile rows -> Log Analytics), and neither waits for the other (stages\Invoke-Output.ps1). The rule above reads
    them like any two outputs:
      LA failed, SQL written   -- success-partial. The records are in the database and their collection is complete, so
                                  the CI build has this run; the run-health record names Log Analytics as not written, and
                                  what reads the profile tables there (Risk Analysis, the data sync, correlation) is on
                                  the previous snapshot -- Risk Analysis says "built on incomplete profile data".
      SQL failed               -- ERROR, whatever else was written (Log Analytics, JSON / Excel files): the records did not
                                  reach the database, so the collection is not complete there. The run throws, the step
                                  fails, and the pipeline runs the source on its last good collection (a dropout) -- in
                                  one process exactly as in a run collected in parts.

    PURE functions except Get-SIRunOutcome, which also reads the ingest notes SI-LogIngest.ps1 records during the run.
    PS 5.1 safe. Shipped in both editions.
#>

function Merge-SIExitReason {
    <# PURE. The worse of two ExitReasons: error / settings-error > throttled (#532) > success-partial > success. A real
       failure next to a throttled one is a real failure. #>
    param([AllowEmptyString()][string]$Current = 'success', [AllowEmptyString()][string]$Next = 'success')
    $rank = @{ '' = 0; 'success' = 0; 'success-partial' = 1; 'throttled' = 2; 'error' = 3; 'settings-error' = 3 }
    $a = if ($rank.ContainsKey([string]$Current)) { $rank[[string]$Current] } else { 3 }
    $b = if ($rank.ContainsKey([string]$Next))    { $rank[[string]$Next] }    else { 3 }
    if ($b -gt $a) { return $Next }
    if ([string]::IsNullOrWhiteSpace($Current)) { return 'success' }
    return $Current
}

# =====================================================================================================================
#  A CAUGHT FAILURE NEVER ENDS GREEN (#639, working rule 4). A step that catches a failure and goes on records it here, as
#    WARNING  the data is still delivered WHOLE elsewhere (the stored set stays the last whole one, the source still holds
#             it, or only a convenience was not done) -- the run ends 'success-partial';
#    FAILED   data is SHORT or MISSING where it should be (an output not written, a set not stored) -- the run ends 'error'.
#  One plain line per issue names what is missing. Nothing downstream closes or resolves anything on a short result.
# =====================================================================================================================
function Add-SIRunIssue {
    <# Adds one caught failure (Level WARNING | FAILED, a plain line naming what is missing) to -Issues. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Issues,
          [Parameter(Mandatory)][ValidateSet('WARNING', 'FAILED')][string]$Level,
          [Parameter(Mandatory)][string]$Text)
    $Issues.Add([pscustomobject]@{ Level = $Level; Text = $Text })
}

function Get-SIRunIssueOutcome {
    <#
        PURE. The run's issues -> @{ ExitReason; Message; Failed; Warnings }: no issue = 'success'; only warnings =
        'success-partial'; any FAILED = 'error'. Message: one 'FAILED: ...' / 'WARNING: ...' part per issue, failures first.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Issues = @())
    $f = @(@($Issues) | Where-Object { $_ -and [string]$_.Level -eq 'FAILED' })
    $w = @(@($Issues) | Where-Object { $_ -and [string]$_.Level -eq 'WARNING' })
    $parts = @(@($f | ForEach-Object { 'FAILED: ' + [string]$_.Text }) + @($w | ForEach-Object { 'WARNING: ' + [string]$_.Text }))
    $exit = 'success'
    if ($f.Count) { $exit = 'error' } elseif ($w.Count) { $exit = 'success-partial' }
    [pscustomobject]@{ ExitReason = $exit; Message = ($parts -join ' | '); Failed = ($f.Count -gt 0); Warnings = $w.Count }
}

function Get-SISinkOutcome {
    <#
        PURE. One output stage's SinkResults (sink -> result text) as an outcome:
          'FAILED:*'            -> the sink failed
          'PARTIAL:*'           -> the sink holds less than the run produced
          'SKIPPED*' (capital)  -> the sink was asked for but could not be written (e.g. no sign-in configured)
          anything else         -> written ('skipped (no records to write)' is a correct, empty publish)
        Every sink failed or skipped and none written -> 'error'; some written -> 'success-partial'.
    #>
    param([AllowNull()]$SinkResults)
    $ok = 0; $bad = New-Object System.Collections.Generic.List[string]; $partial = New-Object System.Collections.Generic.List[string]
    if ($null -eq $SinkResults) { return [pscustomobject]@{ ExitReason = 'success'; Message = '' } }
    $keys = if ($SinkResults -is [System.Collections.IDictionary]) { @($SinkResults.Keys) } else { @($SinkResults.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($k in ($keys | Sort-Object)) {
        $v = if ($SinkResults -is [System.Collections.IDictionary]) { [string]$SinkResults[$k] } else { [string]$SinkResults.$k }
        if ($v -clike 'FAILED*' -or $v -clike 'SKIPPED*') {
            $why = ($v -replace '^(FAILED|SKIPPED)\s*[:\-]*\s*', '').Trim()
            [void]$bad.Add(('{0} was not written ({1})' -f $k, $why))
        } elseif ($v -clike 'PARTIAL*') {
            [void]$partial.Add(('{0}: {1}' -f $k, ($v -replace '^PARTIAL\s*[:\-]*\s*', '').Trim()))
            $ok++
        } else { $ok++ }
    }
    $msgs = @($bad) + @($partial)
    # THE DATABASE WINS (owner 2026-10-12: "Yes, fail the step"). A collection whose records did not reach the database --
    # a batch could not be written, the collection could not be closed, the rows could not be used -- is a FAILED
    # collection, whatever else was written: Log Analytics having the rows, or JSON / Excel files in a container, do not
    # make it a success. The run ends in error, the step fails, and the pipeline runs the source on its last good collection.
    $dbKey = @($keys | Where-Object { [string]$_ -ieq 'SQL' }) | Select-Object -First 1
    if ($dbKey) {
        $dbText = if ($SinkResults -is [System.Collections.IDictionary]) { [string]$SinkResults[$dbKey] } else { [string]$SinkResults.$dbKey }
        if ($dbText -clike 'FAILED*') { return [pscustomobject]@{ ExitReason = 'error'; Message = ($msgs -join ' | '); DatabaseFailed = $true } }
    }
    if ($bad.Count -gt 0 -and $ok -eq 0) { return [pscustomobject]@{ ExitReason = 'error'; Message = ($msgs -join ' | ') } }
    if ($msgs.Count -gt 0)               { return [pscustomobject]@{ ExitReason = 'success-partial'; Message = ($msgs -join ' | ') } }
    [pscustomobject]@{ ExitReason = 'success'; Message = '' }
}

function Get-SIRunOutcome {
    <#
        A profiling run's outcome from its stage results (every stage that reports SinkResults; a stage whose summary
        says INCOMPLETE published nothing on purpose and is a partial run) and from the ingest notes recorded during
        the run (new columns not yet stored, Get-SILogIngestNotes). Returns ExitReason + Message.
    #>
    param([AllowNull()]$StageResults, [AllowNull()][object[]]$IngestNotes)
    $reason = 'success'; $msgs = New-Object System.Collections.Generic.List[string]
    $dbFailed = $false   # the records did not reach the database: the run is an error whatever else was written
    if ($StageResults) {
        $names = if ($StageResults -is [System.Collections.IDictionary]) { @($StageResults.Keys) } else { @($StageResults.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($n in $names) {
            $r = if ($StageResults -is [System.Collections.IDictionary]) { $StageResults[$n] } else { $StageResults.$n }
            if ($null -eq $r) { continue }
            if ($r.PSObject.Properties['SinkResults']) {
                $o = Get-SISinkOutcome -SinkResults $r.SinkResults
                $reason = Merge-SIExitReason $reason $o.ExitReason
                if ($o.Message) { [void]$msgs.Add($o.Message) }
                if ($o.PSObject.Properties['DatabaseFailed'] -and $o.DatabaseFailed) { $dbFailed = $true }
            }
            if ($r.PSObject.Properties['Summary'] -and [string]$r.Summary -clike 'INCOMPLETE*') {
                $reason = Merge-SIExitReason $reason 'success-partial'
                [void]$msgs.Add(('{0}: {1}' -f $n, [string]$r.Summary))
            }
        }
    }
    foreach ($note in @($IngestNotes)) {
        if ($null -eq $note) { continue }
        $reason = Merge-SIExitReason $reason 'success-partial'
        [void]$msgs.Add([string]$note.Message)
    }
    [pscustomobject]@{ ExitReason = $reason; Message = (@($msgs) -join ' | '); DatabaseFailed = $dbFailed }
}

function Get-SIUpstreamRunHealthKql {
    <#
        The newest END record of each profiling engine within -LookbackHours, for Risk Analysis to check what it is
        built on. Only END rows: a missing End (a crash) is detected elsewhere.
    #>
    param([string[]]$Engines = @('endpoint', 'identity', 'azure', 'publicip'), [int]$LookbackHours = 26)
    $list = (@($Engines) | ForEach-Object { '"{0}"' -f ($_ -replace '[^a-z0-9\-]', '') }) -join ', '
    @"
SI_RunHealth_CL
| where TimeGenerated > ago($($LookbackHours)h)
| where Phase == "End" and Engine in ($list)
| summarize arg_max(TimeGenerated, ExitReason, ErrorMessage) by Engine
| project Engine, ExitReason = tostring(ExitReason), ErrorMessage = tostring(ErrorMessage), EndedAt = TimeGenerated
"@
}

function Get-SIUpstreamOutcome {
    <#
        PURE. Risk Analysis built on a profile whose newest run ended 'success-partial' is itself partial: that run's
        snapshot may lack rows or column values (a post that failed half-way, new columns not stored yet), so a finding
        that is missing tonight is UNKNOWN, not fixed. A profile run that ended 'error' published nothing, so the
        previous, whole snapshot is still the newest -- older, not incomplete -- and does not count here.
        Rows are the result of Get-SIUpstreamRunHealthKql. No rows (no record yet, or it could not be read) changes nothing.
    #>
    param([AllowNull()][object[]]$Rows)
    $bad = @(@($Rows) | Where-Object { $_ -and [string]$_.ExitReason -eq 'success-partial' })
    if ($bad.Count -eq 0) { return [pscustomobject]@{ ExitReason = 'success'; Message = ''; RolesOnly = $false } }
    $parts = @($bad | Sort-Object { [string]$_.Engine } | ForEach-Object { "the newest {0} profile run ended '{1}'" -f [string]$_.Engine, [string]$_.ExitReason })
    # #899 RolesOnly: the ONLY reason is that the identity run's Entra role read was not complete (its roles were kept from
    # the stored records) -- Risk Analysis then holds just the reports that read role lists, not the whole run
    $rolesOnly = $true
    foreach ($b in $bad) {
        $em = ''; $p = $b.PSObject.Properties['ErrorMessage']; if ($p) { $em = [string]$p.Value }
        if ([string]$b.Engine -ne 'identity' -or -not (Test-SIRolesOnlyPartialMessage -Message $em)) { $rolesOnly = $false; break }
    }
    [pscustomobject]@{
        ExitReason = 'success-partial'
        Message    = ('built on incomplete profile data: {0} -- findings missing from this run are unknown, not resolved' -f ($parts -join ', '))
        RolesOnly  = $rolesOnly
    }
}

# =====================================================================================================================
#  #1235 (owner 2026-11-12, #1226: "trusted = the run finished every step"): THIS RUN'S OWN STEPS. The source runs' newest
#  records cannot say it: a source STEP that failed this run (its container never started -- live at internal 2026-11-13
#  00:47Z) leaves its older success as the newest record. The pipeline's own record of this run (cfg.FlowStepRun) can.
# =====================================================================================================================
$script:SIFlowStepFailures = @('Failed', 'TimedOut', 'Interrupted')   # the pipeline's own failure states (SI-JobFlow.ps1 Failures)

function Get-SIFlowStepOutcomeSql {
    <#
        One guarded read of the settings database: the pipeline run that is running -@Job now (its step Starting / Running,
        the run Running), -@Job's own step (Mine = 1) and every step of the GROUPS BEFORE its own -- what it reads. Not the
        steps of its own group: they run beside it and it does not read them (Risk Analysis Summary runs beside Detailed;
        a failed Summary must never hold Detailed's collection -- review 2026-11-13). The runner starts a step only after
        every step of the groups above it has ended, so each of those is in its end state. A lock wait ends after 15 s (the
        settings store has no command time limit): the caller then says so and falls back. A database without the
        pipeline's tables, or a job that runs outside a pipeline run, answers no rows.
    #>
    @'
SET NOCOUNT ON; SET LOCK_TIMEOUT 15000;
IF OBJECT_ID(N'cfg.FlowRun') IS NULL OR OBJECT_ID(N'cfg.FlowStepRun') IS NULL
BEGIN SELECT CAST(NULL AS nvarchar(64)) AS FlowRunId, CAST(NULL AS int) AS StepOrder, CAST(NULL AS int) AS GroupNo, CAST(NULL AS nvarchar(64)) AS Job, CAST(NULL AS nvarchar(16)) AS State, CAST(NULL AS nvarchar(64)) AS ErrorClass, CAST(NULL AS nvarchar(1000)) AS Error, CAST(0 AS int) AS Mine, CAST(NULL AS nvarchar(16)) AS PrevState, CAST(NULL AS nvarchar(64)) AS PrevRunId WHERE 1 = 0; RETURN; END
DECLARE @fr nvarchar(64), @o int, @g int, @fid nvarchar(32), @st datetime2(0);
SELECT TOP (1) @fr = s.FlowRunId, @o = s.StepOrder, @g = s.GroupNo, @fid = r.FlowId, @st = r.StartedUtc FROM cfg.FlowStepRun AS s JOIN cfg.FlowRun AS r ON r.FlowRunId = s.FlowRunId
WHERE (s.Job = @Job OR s.Job = N'caj-si-' + @Job) AND s.State IN (N'Starting', N'Running') AND r.State = N'Running'
ORDER BY r.StartedUtc DESC, r.FlowRunId DESC;
IF @fr IS NULL
BEGIN SELECT CAST(NULL AS nvarchar(64)) AS FlowRunId, CAST(NULL AS int) AS StepOrder, CAST(NULL AS int) AS GroupNo, CAST(NULL AS nvarchar(64)) AS Job, CAST(NULL AS nvarchar(16)) AS State, CAST(NULL AS nvarchar(64)) AS ErrorClass, CAST(NULL AS nvarchar(1000)) AS Error, CAST(0 AS int) AS Mine, CAST(NULL AS nvarchar(16)) AS PrevState, CAST(NULL AS nvarchar(64)) AS PrevRunId WHERE 1 = 0; RETURN; END
-- a step this run did not run because it is a RE-RUN from a later step ('before-rerun'): its outcome in the newest earlier
-- run of the same pipeline in which that step actually RAN (it started: never a row of a run in which it was skipped,
-- cancelled, switched off or still waiting -- review 2026-11-13) -- the run its stored data comes from (NULL = none found)
SELECT s.FlowRunId, s.StepOrder, s.GroupNo, s.Job, s.State, s.ErrorClass, s.Error, CASE WHEN s.StepOrder = @o THEN 1 ELSE 0 END AS Mine,
       p.PrevState, p.PrevRunId
FROM cfg.FlowStepRun AS s
OUTER APPLY (SELECT TOP (1) ps.State AS PrevState, ps.FlowRunId AS PrevRunId
             FROM cfg.FlowStepRun AS ps JOIN cfg.FlowRun AS pr ON pr.FlowRunId = ps.FlowRunId
             WHERE s.ErrorClass = N'before-rerun' AND ps.Job = s.Job AND pr.FlowId = @fid AND pr.StartedUtc < @st
               AND ISNULL(ps.ErrorClass, N'') <> N'before-rerun' AND ps.StartedUtc IS NOT NULL
             ORDER BY pr.StartedUtc DESC, pr.FlowRunId DESC) AS p
WHERE s.FlowRunId = @fr AND (s.GroupNo < @g OR s.StepOrder = @o) ORDER BY s.StepOrder;
'@
}

function Get-SIFlowStepVerdict {
    <#
        PURE. Did THIS run finish every step it reads (the groups before -Rows' own step, Mine = 1)? From
        Get-SIFlowStepOutcomeSql's rows:
          a step that ended Failed / TimedOut / Interrupted   -> NOT trusted; Why names each such step plainly
          Disabled / Skipped (switched off, or not covered by this run -- framework TRUST-1 point 7: absent by design;
          a step skipped because one it needs failed is covered by that failed step)
                                                              -> not counted
        A RE-RUN from a step (Invardia 2026-11-13: the strict reading): a step this run did not run ('before-rerun') is
        judged by its outcome in the run the re-run continues (PrevState: the newest earlier run of the pipeline in which it
        ran) -- a failure there, or a step that never finished there, is NOT trusted; when that run cannot be found: not known.
        @{ Known; Trusted; Why; FlowRunId }. Known $false -- the caller then decides from the source runs' records alone,
        as before -- when: no rows / no own step (a run outside the pipeline, an older database); no earlier step at all
        (a run of one step or one stage: "hold only on real failure" for what cannot be read); a re-run whose earlier run
        cannot be found.
    #>
    param([AllowNull()][object[]]$Rows)
    $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } else { $null } } elseif ($r -and $r.PSObject.Properties[$n]) { $r.$n } else { $null } }
    $unknown = { param($why) [pscustomobject]@{ Known = $false; Trusted = $true; Why = $why; FlowRunId = '' } }
    $rs = @(@($Rows) | Where-Object { $null -ne $_ })
    $mine = @($rs | Where-Object { [int](& $val $_ 'Mine') -eq 1 })
    if ($rs.Count -eq 0 -or $mine.Count -eq 0) { return (& $unknown 'this run''s steps could not be read (not a pipeline run, or no record of it)') }
    $earlier = @($rs | Where-Object { [int](& $val $_ 'Mine') -ne 1 })
    if ($earlier.Count -eq 0) { return (& $unknown 'a run of one step or one stage: the steps it reads are not part of this run') }
    $fine = @('Success', 'Disabled', 'Skipped')
    $failures = @('Failed', 'TimedOut', 'Interrupted')   # the pipeline's own failure states (SI-JobFlow.ps1 Failures)
    # the step in plain words (the reason is shown to the customer): never the job's internal key
    $names = @{ 'ptc' = 'privilege tier catalog'; 'identity' = 'identity collection'; 'endpoint' = 'device collection'; 'azure' = 'Azure collection'
                'publicip' = 'public IP collection'; 'asset-correlation' = 'correlation' }
    $judged = New-Object System.Collections.Generic.List[object]
    $notFound = New-Object System.Collections.Generic.List[string]
    foreach ($r in $earlier) {
        $k = ([string](& $val $r 'Job')) -replace '^caj-si-', ''
        $j = if ($names.ContainsKey($k)) { $names[$k] } else { $k -replace '-', ' ' }
        if ([string](& $val $r 'ErrorClass') -eq 'before-rerun') {
            $ps = [string](& $val $r 'PrevState')
            # a run that cannot be found for ONE step never hides a failure found for another (review 2026-11-13)
            if (-not $ps.Trim()) { $notFound.Add($j); continue }
            if ($fine -notcontains $ps) { $judged.Add(('the {0} step {1} in the run this re-run continues' -f $j, $(switch ($ps) { 'TimedOut' { 'timed out' } 'Interrupted' { 'was interrupted' } 'Failed' { 'failed' } default { 'did not finish' } }))) }
        } elseif ($failures -contains [string](& $val $r 'State')) {
            $judged.Add(('the {0} step of this run {1}' -f $j, $(switch ([string](& $val $r 'State')) { 'TimedOut' { 'timed out' } 'Interrupted' { 'was interrupted' } default { 'failed' } })))
        }
    }
    $fr = [string](& $val $mine[0] 'FlowRunId')
    if ($judged.Count -eq 0 -and $notFound.Count) { return (& $unknown ('a re-run from a later step: the run it continues could not be found for the {0} step(s)' -f ($notFound.ToArray() -join ', '))) }
    if ($judged.Count -eq 0) { return [pscustomobject]@{ Known = $true; Trusted = $true; Why = ''; FlowRunId = $fr } }
    $parts = $judged.ToArray()
    [pscustomobject]@{ Known = $true; Trusted = $false; FlowRunId = $fr
                       Why = ('built on a run that did not finish every step: {0}' -f ($parts -join '; ')) }
}

# =====================================================================================================================
#  #899 A ROLE READ THAT WAS NOT COMPLETE. The identity collection kept every identity's stored roles (IdentityRoleFetcher
#  Resolve-SIEntraRoleReadIncomplete) and says so as ONE note of its own kind: the run ends 'success-partial', and its
#  END record's message is made of this note only -- which Risk Analysis reads as "the role facts are partial" (RolesOnly).
# =====================================================================================================================
function Add-SIEntraRolesPartialNote {
    <# The run's note that the Entra role facts are partial this run -- one note per process; a second reason joins it. #>
    param([Parameter(Mandatory)][string]$Message)
    if (-not ($global:SI_LogIngestNotes -is [System.Collections.Generic.List[object]])) { $global:SI_LogIngestNotes = New-Object System.Collections.Generic.List[object] }
    $code = 'entra-roles-partial'
    $body = ($Message.Trim() -replace ('^' + $code + ':\s*'), '') -replace '\s+\|\s+', ' / '   # the END record joins notes with ' | '
    foreach ($n in $global:SI_LogIngestNotes) {
        if ($n -and $n.PSObject.Properties['Kind'] -and [string]$n.Kind -eq $code) {
            if (-not ([string]$n.Message).Contains($body)) { $n.Message = [string]$n.Message + ' / ' + $body }
            return
        }
    }
    [void]$global:SI_LogIngestNotes.Add([pscustomobject]@{ Table = 'entra-roles'; Columns = @(); Message = ($code + ': ' + $body); Kind = $code })
}

function Test-SIRolesOnlyPartialMessage {
    <# PURE. Is a run's END message made ONLY of role-read notes (each ' | ' part starts 'entra-roles-partial:')? '' = no. #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    $parts = @(([string]$Message) -split '\s\|\s' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $false }
    foreach ($p in $parts) { if ($p -notmatch '^entra-roles-partial:') { return $false } }
    $true
}
