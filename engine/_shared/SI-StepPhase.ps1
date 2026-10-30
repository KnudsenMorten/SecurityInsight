# SI-StepPhase.ps1 -- a step's time per phase, written to SQL (2026-10-25)
#
# The step logs of a customer install cannot be read through the Support app; its database can. So each long step (Risk
# Analysis, the vulnerability close-loop, the data sync) writes how long each of its phases took, and how many rows it
# handled, to cfg.StepPhaseTime -- one row per phase. cfg.FlowStepRun.Execution joins a row to its run and step.
# Measurement only: it never changes a row of product data, and a failed write never fails the step.

function Get-SIStepPhaseTableSql {
    <# PURE. The table (additive, guarded). Append-only for the engine (least privilege: it never deletes in cfg here); a
       few hundred small rows a day. #>
    @'
IF OBJECT_ID('cfg.StepPhaseTime') IS NULL
CREATE TABLE cfg.StepPhaseTime (
    StepPhaseTimeId BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_StepPhaseTime PRIMARY KEY,
    Execution       NVARCHAR(128)   NULL,       -- the job execution (cfg.FlowStepRun.Execution), CONTAINER_APP_JOB_EXECUTION_NAME
    Job             NVARCHAR(64)    NOT NULL,   -- risk-analysis-detailed | asset-vulnerabilities | asset-datasync | ...
    Phase           NVARCHAR(128)   NOT NULL,   -- the phase, e.g. 'remediations' or 'report Device_Missing_CVEs_Detailed: insert'
    Seconds         FLOAT           NOT NULL,
    [Rows]          BIGINT          NULL,       -- rows handled in the phase, when it counts them
    AtUtc           DATETIME2(3)    NOT NULL CONSTRAINT DF_StepPhaseTime_At DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_StepPhaseTime_Execution' AND object_id = OBJECT_ID('cfg.StepPhaseTime'))
CREATE INDEX IX_StepPhaseTime_Execution ON cfg.StepPhaseTime (Execution, AtUtc);
'@
}

function Get-SIStepPhaseInsertSql {
    <# PURE. One phase row; a database without the table writes nothing. #>
    @'
IF OBJECT_ID('cfg.StepPhaseTime') IS NOT NULL
    INSERT cfg.StepPhaseTime (Execution, Job, Phase, Seconds, [Rows]) VALUES (NULLIF(@Execution, N''), LEFT(@Job, 64), LEFT(@Phase, 128), @Seconds, @Rows);
'@
}

function Write-SIStepPhase {
    <#
        One phase's time to cfg.StepPhaseTime. -Invoke: the step's own SQL seam, a scriptblock (sql, params, mode) as the
        data sync's ('nonquery'). -Rows: -1 = not counted. NEVER throws; a failed write is said once in -Log (if given) and
        the step goes on. Returns $true when the row was written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][string]$Phase,
          [double]$Seconds, [long]$Rows = -1, [scriptblock]$Log, [string]$Execution = [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME)
    try {
        $p = @{ Execution = $Execution; Job = $Job; Phase = $Phase; Seconds = [double]$Seconds; Rows = $(if ($Rows -ge 0) { [long]$Rows } else { [DBNull]::Value }) }
        $null = & $Invoke (Get-SIStepPhaseInsertSql) $p 'nonquery'
        return $true
    } catch {
        if ($Log -and -not $script:SIStepPhaseWarned) {
            $script:SIStepPhaseWarned = $true
            try { & $Log 'WARN' ("step phase times: not written to the database ({0}) -- the step goes on" -f $_.Exception.Message) } catch { }
        }
        return $false
    }
}

# =====================================================================================================================
#  A STEP'S PROGRESS (cfg.StepProgress, one row per job execution). Two writers, one row:
#   * its newest SIGN OF PROGRESS (owner 2026-10-29: "a stuck step is seen after days, not hours") -- every batch a long
#     step writes moves it (Invoke-SISqlPacing), at most every few minutes; the heartbeat and the pipeline runner read it
#     to tell a step that moves from one that stands still (si-flow-1204, a warning only -- nothing is stopped);
#   * WHAT IT DOES NOW and done / total where the engine knows it (owner 2026-10-11: "i am blind regarding the phases
#     (completion %)"; framework 12.20 JOB-PROGRESS, smallest version) -- Operations > Jobs shows it on the running step.
#  Both move LastUtc. Measurement only: it never changes a row of product data and never fails a step.
# =====================================================================================================================
$script:SIStepProgress = @{ EverySeconds = 15; Last = @{} }

function Get-SIStepProgressTableSql {
    <# PURE. The table (additive, guarded) -- the same statement is in sql\si-pro-settings.sql. #>
    @'
IF OBJECT_ID('cfg.StepProgress') IS NULL
CREATE TABLE cfg.StepProgress (
    Execution       NVARCHAR(128)   NOT NULL CONSTRAINT PK_StepProgress PRIMARY KEY,   -- the job execution (cfg.FlowStepRun.Execution)
    Job             NVARCHAR(64)    NOT NULL,
    Phase           NVARCHAR(200)   NULL,       -- what the step is doing now, e.g. 'report Device_Missing_CVEs_Detailed'
    Done            BIGINT          NULL,       -- how much of it is done, when the engine counts it
    Total           BIGINT          NULL,       -- out of how much, when the engine knows it
    LastUtc         DATETIME2(3)    NOT NULL CONSTRAINT DF_StepProgress_Last DEFAULT SYSUTCDATETIME(),   -- its newest sign of progress
    Beats           BIGINT          NOT NULL CONSTRAINT DF_StepProgress_Beats DEFAULT 0
);
'@
}

function Get-SIStepProgressMarkSql {
    <# PURE. The execution's mark moved to now (one row per execution); a database without the table writes nothing. #>
    @'
IF OBJECT_ID('cfg.StepProgress') IS NOT NULL
BEGIN
    UPDATE cfg.StepProgress SET LastUtc = SYSUTCDATETIME(), Beats = Beats + 1 WHERE Execution = @Execution;
    IF @@ROWCOUNT = 0
        INSERT cfg.StepProgress (Execution, Job, LastUtc, Beats) VALUES (LEFT(@Execution, 128), LEFT(@Job, 64), SYSUTCDATETIME(), 1);
END
'@
}

function Get-SIStepProgressBeatSeconds { 300 }

function Get-SIStepProgressUpsertSql {
    <# PURE. What the execution does now written (MERGE) -- also its newest sign of progress; a database without the table writes nothing. #>
    @'
IF OBJECT_ID('cfg.StepProgress') IS NOT NULL
MERGE cfg.StepProgress AS t
USING (SELECT LEFT(@Execution, 128) AS Execution) AS s ON t.Execution = s.Execution
WHEN MATCHED THEN UPDATE SET Job = LEFT(@Job, 64), Phase = LEFT(@Phase, 200), Done = @Done, Total = @Total, LastUtc = SYSUTCDATETIME(), Beats = t.Beats + 1
WHEN NOT MATCHED THEN INSERT (Execution, Job, Phase, Done, Total, LastUtc, Beats) VALUES (LEFT(@Execution, 128), LEFT(@Job, 64), LEFT(@Phase, 200), @Done, @Total, SYSUTCDATETIME(), 1);
'@
}

function Test-SIStepProgressDue {
    <# PURE. Is a progress record due for this execution? A new phase: always; the same phase: when -EverySeconds have
       passed since the last write (-Last: @{ Phase; AtUtc } or $null). #>
    param($Last, [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][datetime]$NowUtc, [int]$EverySeconds = 15)
    if (-not $Last -or [string]$Last.Phase -ne $Phase) { return $true }
    [bool](($NowUtc.ToUniversalTime() - ([datetime]$Last.AtUtc).ToUniversalTime()).TotalSeconds -ge $EverySeconds)
}

function Write-SIStepProgress {
    <#
        THIS job execution's progress (cfg.StepProgress), through -Invoke (sql, params, mode). NEVER throws; returns $true when a
        row was written. Outside a job execution (no CONTAINER_APP_JOB_EXECUTION_NAME) nothing is written.
          * With -Phase (what it does now; -Done / -Total, -1 = not counted / not known): the record Operations > Jobs shows,
            written at a phase change and at most every 15 s otherwise (-Force: now).
          * Without -Phase: only its newest sign of progress (a written batch), at most every Get-SIStepProgressBeatSeconds
            (5 minutes) per process.
        Both move LastUtc -- what tells a stuck step from one that moves. Written to the SETTINGS database: when -Invoke's
        database is another one, a seam of the settings database is opened once for the process (SI_ProSqlServer /
        SI_ProSqlDatabase). A failed write is said once in -Log and the step goes on.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Job = [string]$env:CONTAINER_APP_JOB_NAME, [string]$Phase = '',
          [long]$Done = -1, [long]$Total = -1, [scriptblock]$Log, [string]$Execution = [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME,
          [Alias('NowUtc')][datetime]$Now = [datetime]::UtcNow, [switch]$Force)
    try {
        if (-not "$Execution".Trim()) { return $false }
        # made on first use in whichever scope calls (a function loaded by an outer script finds its state set)
        if ($null -eq $script:SIStepProgress) { $script:SIStepProgress = @{ EverySeconds = 15; Last = @{} } }
        if (-not "$Job".Trim()) { $Job = ([string]$Execution -replace '-[a-z0-9]+$', '') }
        $isPhase = [bool]"$Phase".Trim()
        if ($isPhase) {
            if (-not $Force -and -not (Test-SIStepProgressDue -Last $script:SIStepProgress.Last[$Execution] -Phase $Phase -NowUtc $Now -EverySeconds $script:SIStepProgress.EverySeconds)) { return $false }
        } else {
            # process-wide (a global on purpose: the mark is per process, whichever script calls)
            $last = $global:SI_StepProgressAt
            if (-not $Force -and $last -is [datetime] -and ($Now - $last).TotalSeconds -lt (Get-SIStepProgressBeatSeconds)) { return $false }
            $global:SI_StepProgressAt = $Now
        }
        $target = $Invoke
        $t = if ($Invoke.PSObject.Properties['SISqlTarget']) { $Invoke.SISqlTarget } else { $null }
        $ps = [string]$global:SI_ProSqlServer; $pd = [string]$global:SI_ProSqlDatabase
        if ($t -and $ps -and $pd -and -not ([string]$t.Server -eq $ps -and [string]$t.Database -eq $pd)) {
            if (-not ($global:SI_StepProgressInvoke -is [scriptblock]) -and (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) {
                $global:SI_StepProgressInvoke = New-SIDataSqlInvoke -Server $ps -Database $pd -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
            }
            if ($global:SI_StepProgressInvoke -is [scriptblock]) { $target = $global:SI_StepProgressInvoke }
        }
        if ($isPhase) {
            $p = @{ Execution = $Execution; Job = $Job; Phase = $Phase
                    Done = $(if ($Done -ge 0) { [long]$Done } else { [DBNull]::Value }); Total = $(if ($Total -ge 0) { [long]$Total } else { [DBNull]::Value }) }
            $null = & $target (Get-SIStepProgressUpsertSql) $p 'nonquery'
            $script:SIStepProgress.Last[$Execution] = @{ Phase = $Phase; AtUtc = $Now.ToUniversalTime() }
        } else {
            $null = & $target (Get-SIStepProgressMarkSql) @{ Execution = [string]$Execution; Job = [string]$Job } 'nonquery'
        }
        return $true
    } catch {
        if ($Log -and -not $script:SIStepProgressWarned) {
            $script:SIStepProgressWarned = $true
            try { & $Log 'WARN' ("step progress: not written to the database ({0}) -- the step goes on" -f $_.Exception.Message) } catch { }
        }
        return $false
    }
}
function Get-SIStepProgressLastSql {
    <# PURE. The newest sign of progress of one step since it started: its execution's mark and phase rows, and the marks of
       the executions of its job and its job's workers (a job named caj-si-<step>, or that followed by -<suffix>). One row:
       LastUtc (NULL = none). A database without a table answers nothing from it. #>
    @'
SET NOCOUNT ON;
DECLARE @m datetime2(3) = NULL, @f datetime2(3) = NULL, @since datetime2(3) = TRY_CONVERT(datetime2(3), @SinceUtc, 126), @jn nvarchar(80) = N'caj-si-' + @Job;
IF OBJECT_ID(N'cfg.StepProgress') IS NOT NULL
    SELECT @m = MAX(LastUtc) FROM cfg.StepProgress WHERE (Execution = @Execution OR Job = @jn OR Job LIKE @jn + N'-%') AND LastUtc >= @since;
IF OBJECT_ID(N'cfg.StepPhaseTime') IS NOT NULL AND @Execution <> N''
    SELECT @f = MAX(AtUtc) FROM cfg.StepPhaseTime WHERE Execution = @Execution AND AtUtc >= @since;
SELECT CASE WHEN @m IS NULL THEN @f WHEN @f IS NULL OR @m >= @f THEN @m ELSE @f END AS LastUtc;
'@
}

function Get-SIStepProgressLast {
    <# The newest sign of progress of a step (Get-SIStepProgressLastSql) as UTC [datetime], or $null (none, or not readable).
       -Invoke: the settings database seam. -Job: the step's job key (identity, asset-datasync, ...). NEVER throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Job, [AllowEmptyString()][string]$Execution = '', [Parameter(Mandatory)][datetime]$SinceUtc)
    try {
        $k = ([string]$Job).Trim().ToLowerInvariant(); if ($k.StartsWith('caj-si-')) { $k = $k.Substring(7) }
        $rows = @(& $Invoke (Get-SIStepProgressLastSql) @{ Job = $k; Execution = [string]$Execution; SinceUtc = $SinceUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $rows.Count) { return $null }
        $v = if ($rows[0] -is [System.Collections.IDictionary]) { $rows[0]['LastUtc'] } else { $rows[0].LastUtc }
        if ($null -eq $v -or $v -is [System.DBNull]) { return $null }
        $d = [datetime]$v
        if ($d.Kind -eq [DateTimeKind]::Unspecified) { $d = [datetime]::SpecifyKind($d, [DateTimeKind]::Utc) }
        $d.ToUniversalTime()
    } catch { $null }
}
