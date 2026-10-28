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
