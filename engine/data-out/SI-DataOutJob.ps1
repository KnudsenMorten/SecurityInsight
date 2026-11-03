#Requires -Version 5.1
<#
    SecurityInsight -- DATA OUT AS ITS OWN JOB (REQUIREMENTS #1038 part 1; owner 2026-11-01: "servicenow is most critical").

    Until now the ServiceNow push and the other outputs (Invoke-SIDataOut) ran at the very end of the data sync, after the
    key figures, the summaries, the collection clean-up, the metadata and the views: a resend took a whole data sync (hours
    on a large install). Now:

      1. THE MARK. The data sync marks the collection whose findings per CI it has just stored as READY FOR DATA OUT, at
         that moment (Invoke-SIDataSyncCore -OnFindingsStored, right after the findings per CI) -- in SQL, one row per
         collection (sidata.DataOutReady; marking it again re-arms the same row, idempotent). A run that is not complete
         (the pipeline started the sync after a failed step, or that cannot be told) marks it HELD: nothing is sent from
         it. A findings-per-CI store that failed marks nothing (the stored set did not change).
      2. THE JOB. caj-si-data-out (Invoke-SIDataOutJob.ps1: the orchestrator image, the engine identity) sends from the
         NEWEST mark only -- the ServiceNow hand-off, the vulnerable items, every other output -- exactly as the data sync
         did (Invoke-SIDataOut: cfg.ConnectorRun / DataOutBatch / DataOutItem, the contract unchanged). It is started
         (a) by the data sync, a plain job start, right after the mark, and (b) by a person or support (a resend: a plain
         start of the job sends the newest mark again -- the outputs send only what changed). It never waits on the
         sync's later phases, retries its own failed outputs, and after a send looks once more for a newer mark.
      3. ONE AT A TIME (sidata.DataOutLock, one row, a lease): the job sends while it holds it; the data sync holds it while
         it REPLACES the findings per CI (it waits, bounded, for a send to end first) -- so a send never reads a set that is
         being replaced, and a second start while one runs does nothing.
      4. THE FALLBACK. An install whose database has no data-out tables, or that has no caj-si-data-out job (an older
         install), or where the job could not be started: the data sync sends data out itself, as before.

    Pure functions except the seams: -Invoke { param($sql, $params, $mode) } (the data database), -Arm { param($Method,
    $Path, $Body) } (Azure Resource Manager), -Sleep { param($Seconds) }, -Now { [datetime] }. Never throws unless said.
    PowerShell 7; parses on 5.1. No PowerShell modules.
#>

$script:SIDataOutJob = @{
    Job              = 'caj-si-data-out'
    ArmApi           = '2025-07-01'
    LeaseSeconds     = 1800      # the job's hold on the lock; renewed while it works (a job that died frees it within this)
    RenewSeconds     = 120
    SyncLeaseSeconds = 14400     # the data sync's hold while it replaces the findings per CI
    SyncWaitSeconds  = 7200      # how long the data sync waits for a send to end before it replaces the findings anyway
    SyncPollSeconds  = 30
    Attempts         = 3         # sends of one mark per start (the first + its retries)
    RetrySeconds     = @(120, 300)
    MaxRounds        = 5         # newer marks taken in one start
}

function Get-SIDataOutJobTablesSql {
    <# PURE. 1 when the database has the data-out tables (sql\si-data-schema.sql; an update adds them), else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.DataOutReady') IS NOT NULL AND OBJECT_ID('sidata.DataOutLock') IS NOT NULL THEN 1 ELSE 0 END;"
}

function Test-SIDataOutJobTables {
    <# Does the database have the data-out tables? A database that cannot be read answers $false (the fallback). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try { return ([string](& $Invoke (Get-SIDataOutJobTablesSql) @{} 'scalar') -eq '1') } catch { return $false }
}

function Get-SIDataOutLockSql {
    <# PURE. Take (or renew) the one lock row for @Holder (kind @Kind) when it is free, its lease has passed, or @Holder
       holds it already. One row back: Got (1 = @Holder holds it now), Holder, Kind, UntilUtc. #>
    @'
SET NOCOUNT ON;
DECLARE @now DATETIME2(3) = SYSUTCDATETIME(), @got INT = 0;
IF NOT EXISTS (SELECT 1 FROM sidata.DataOutLock WHERE LockId = 1)
BEGIN TRY INSERT sidata.DataOutLock (LockId, Holder, Kind, UntilUtc) VALUES (1, NULL, NULL, NULL); END TRY BEGIN CATCH END CATCH;
UPDATE sidata.DataOutLock SET Holder = @Holder, Kind = @Kind, UntilUtc = DATEADD(second, CONVERT(int, @LeaseSeconds), @now)
 WHERE LockId = 1 AND (Holder IS NULL OR Holder = N'' OR UntilUtc IS NULL OR UntilUtc < @now OR Holder = @Holder);
SET @got = @@ROWCOUNT;
SELECT @got AS Got, Holder, Kind, CONVERT(nvarchar(30), UntilUtc, 126) AS UntilUtc FROM sidata.DataOutLock WHERE LockId = 1;
'@
}

function Get-SIDataOutUnlockSql {
    <# PURE. Free the lock -- only when @Holder holds it (never another's). #>
    "UPDATE sidata.DataOutLock SET Holder = NULL, Kind = NULL, UntilUtc = NULL WHERE LockId = 1 AND Holder = @Holder;"
}

function Get-SIDataOutRow {
    <# The first row of a reader answer (an IDictionary or an object), or $null. #>
    param($Answer)
    foreach ($r in @($Answer)) {
        foreach ($x in @($r)) { if ($x -is [System.Collections.IDictionary] -or ($null -ne $x -and $x -isnot [string] -and $x.PSObject.Properties.Count)) { return $x } }
    }
    $null
}

function Get-SIDataOutField {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Request-SIDataOutLock {
    <# Take the lock for -Holder. @{ Got; Holder; Kind; Why }. A database that cannot be read: Got = $false, Why says it. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Holder, [ValidateSet('data-out', 'datasync')][string]$Kind = 'data-out',
          [int]$LeaseSeconds = $script:SIDataOutJob.LeaseSeconds)
    try {
        $row = Get-SIDataOutRow (& $Invoke (Get-SIDataOutLockSql) @{ Holder = $Holder; Kind = $Kind; LeaseSeconds = [string]$LeaseSeconds } 'reader')
        $got = [int](Get-SIDataOutField $row 'Got') -ge 1
        [pscustomobject]@{ Got = $got; Holder = [string](Get-SIDataOutField $row 'Holder'); Kind = [string](Get-SIDataOutField $row 'Kind'); Why = '' }
    } catch {
        [pscustomobject]@{ Got = $false; Holder = ''; Kind = ''; Why = [string]$_.Exception.Message }
    }
}

function Unlock-SIDataOut {
    <# Free the lock -Holder holds. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Holder)
    try { $null = & $Invoke (Get-SIDataOutUnlockSql) @{ Holder = $Holder } 'nonquery'; $true } catch { $false }
}

function Get-SIDataOutMarkSql {
    <# PURE. Mark one collection (@CollectionTime) @State (ready | held) -- IDEMPOTENT: one row per collection; marking it
       again re-arms the same row. Every OLDER mark still waiting (ready / failed) is superseded: only the newest is sent.
       Returns the row's ReadyId. #>
    @'
SET NOCOUNT ON;
DECLARE @id BIGINT = (SELECT ReadyId FROM sidata.DataOutReady WHERE CollectionTime = @CollectionTime);
IF @id IS NULL
BEGIN
    BEGIN TRY
        INSERT sidata.DataOutReady (CollectionTime, FrozenReports, State, Why, MarkedBy) VALUES (@CollectionTime, @Frozen, @State, NULLIF(@Why, N''), NULLIF(@By, N''));
        SET @id = SCOPE_IDENTITY();
    END TRY
    BEGIN CATCH SET @id = (SELECT ReadyId FROM sidata.DataOutReady WHERE CollectionTime = @CollectionTime); END CATCH
END
UPDATE sidata.DataOutReady SET FrozenReports = @Frozen, State = @State, Why = NULLIF(@Why, N''), MarkedUtc = SYSUTCDATETIME(), MarkedBy = NULLIF(@By, N''), Attempts = 0
 WHERE ReadyId = @id;
UPDATE sidata.DataOutReady SET State = N'superseded' WHERE ReadyId <> @id AND State IN (N'ready', N'failed');
SELECT @id;
'@
}

function Get-SIDataOutNewestSql {
    <# PURE. The newest mark (not superseded): ReadyId, CollectionTime, FrozenReports, State, Why, Attempts. #>
    @'
SET NOCOUNT ON;
SELECT TOP (1) ReadyId, CollectionTime, FrozenReports, State, Why, Attempts, CONVERT(nvarchar(30), MarkedUtc, 126) AS MarkedUtc
FROM sidata.DataOutReady WHERE State <> N'superseded' ORDER BY MarkedUtc DESC, ReadyId DESC;
'@
}

function Get-SIDataOutStateSql {
    <# PURE. One mark's state: sending (one attempt more) | sent (by @By, now) | failed (why). #>
    @'
UPDATE sidata.DataOutReady SET State = @State, Why = NULLIF(@Why, N''), Attempts = Attempts + CONVERT(int, @AddAttempt),
       SentBy = CASE WHEN @State = N'sent' THEN NULLIF(@By, N'') ELSE SentBy END,
       SentUtc = CASE WHEN @State = N'sent' THEN SYSUTCDATETIME() ELSE SentUtc END
 WHERE ReadyId = CONVERT(bigint, @ReadyId);
'@
}

function ConvertTo-SIDataOutReady {
    <# PURE. A mark row as @{ ReadyId; CollectionTime; FrozenReports (string[]); State; Why; Attempts }, or $null. #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $id = Get-SIDataOutField $Row 'ReadyId'
    if ($null -eq $id -or "$id" -eq '') { return $null }
    $fr = @()
    $fj = [string](Get-SIDataOutField $Row 'FrozenReports')
    if ($fj.Trim()) { try { $fr = @(@(ConvertFrom-Json -InputObject $fj) | ForEach-Object { [string]$_ } | Where-Object { $_ }) } catch { $fr = @() } }
    [pscustomobject]@{ ReadyId = [long]$id; CollectionTime = [string](Get-SIDataOutField $Row 'CollectionTime'); FrozenReports = [string[]]$fr
                       State = [string](Get-SIDataOutField $Row 'State'); Why = [string](Get-SIDataOutField $Row 'Why'); Attempts = [int](Get-SIDataOutField $Row 'Attempts') }
}

function Get-SIDataOutNewestReady {
    <# The newest mark, or $null (none yet). Throws when the database cannot be read (the caller says so). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    ConvertTo-SIDataOutReady (Get-SIDataOutRow (& $Invoke (Get-SIDataOutNewestSql) @{} 'reader'))
}

function Set-SIDataOutReadyState {
    <# One mark's state. Never throws; $false when it could not be recorded. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$ReadyId, [Parameter(Mandatory)][ValidateSet('sending', 'sent', 'failed')][string]$State,
          [string]$Why = '', [string]$By = '', [switch]$Attempt)
    try {
        $w = [string]$Why; if ($w.Length -gt 1000) { $w = $w.Substring(0, 997) + '...' }
        $null = & $Invoke (Get-SIDataOutStateSql) @{ ReadyId = [string]$ReadyId; State = $State; Why = $w; By = $By; AddAttempt = $(if ($Attempt) { '1' } else { '0' }) } 'nonquery'
        $true
    } catch { $false }
}

function Set-SIDataOutReadyMark {
    <# Mark -CollectionTime -State (ready | held). Returns the ReadyId, or $null when it could not be written. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CollectionTime, [ValidateSet('ready', 'held')][string]$State = 'ready',
          [AllowEmptyCollection()][string[]]$FrozenReports = @(), [string]$Why = '', [string]$By = '')
    $w = [string]$Why; if ($w.Length -gt 1000) { $w = $w.Substring(0, 997) + '...' }
    $fz = ConvertTo-Json -InputObject @(@($FrozenReports) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -Compress
    $id = & $Invoke (Get-SIDataOutMarkSql) @{ CollectionTime = $CollectionTime; State = $State; Frozen = $fz; Why = $w; By = $By } 'scalar'
    if ($null -eq $id -or $id -is [System.DBNull] -or "$id" -eq '') { return $null }
    [long]$id
}

# =====================================================================================================================
#  THE JOB: is it installed, and start it
# =====================================================================================================================

function Get-SIDataOutJobTarget {
    <# PURE over the environment: where the install's jobs are (SI_JOBS_* as every job has them, else SI_FLOW_*). #>
    param([hashtable]$Environment)
    $ev = { param($n) if ($Environment) { [string]$Environment[$n] } else { [string][Environment]::GetEnvironmentVariable($n) } }
    $sub = (& $ev 'SI_JOBS_SUBSCRIPTIONID'); if (-not $sub.Trim()) { $sub = (& $ev 'SI_FLOW_SUBSCRIPTIONID') }
    $rg = (& $ev 'SI_JOBS_RESOURCEGROUP'); if (-not $rg.Trim()) { $rg = (& $ev 'SI_FLOW_RESOURCEGROUP') }
    [pscustomobject]@{ SubscriptionId = $sub.Trim(); ResourceGroup = $rg.Trim() }
}

function Get-SIDataOutJobPath {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$Action = '')
    '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}{3}' -f $SubscriptionId, $ResourceGroup, $script:SIDataOutJob.Job, $Action
}

function Test-SIDataOutJobInstalled {
    <# Is caj-si-data-out a job of this install? @{ Installed; Known; Why }. Not known (no target, ARM not readable) =
       not installed for the caller: the data sync then sends data out itself (the safe side). Never throws. #>
    param([scriptblock]$Arm, [string]$SubscriptionId, [string]$ResourceGroup)
    if (-not $SubscriptionId -or -not $ResourceGroup) { return [pscustomobject]@{ Installed = $false; Known = $false; Why = 'where the install''s jobs are is not known (SI_JOBS_SUBSCRIPTIONID / SI_JOBS_RESOURCEGROUP)' } }
    if (-not $Arm) { $Arm = { param($Method, $Path, $Body) Invoke-SIArm -Method $Method -Path $Path -ApiVersion $script:SIDataOutJob.ArmApi -Body $Body -AllowNotFound } }
    try {
        $j = & $Arm 'GET' (Get-SIDataOutJobPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup) $null
        if ($null -eq $j) { return [pscustomobject]@{ Installed = $false; Known = $true; Why = ('{0} is not a job of this install yet (the next update creates it)' -f $script:SIDataOutJob.Job) } }
        [pscustomobject]@{ Installed = $true; Known = $true; Why = '' }
    } catch {
        $m = [string]$_.Exception.Message
        if ($m -match '(?i)\b404\b|ResourceNotFound|NotFound') { return [pscustomobject]@{ Installed = $false; Known = $true; Why = ('{0} is not a job of this install yet (the next update creates it)' -f $script:SIDataOutJob.Job) } }
        [pscustomobject]@{ Installed = $false; Known = $false; Why = ('whether {0} exists could not be read ({1})' -f $script:SIDataOutJob.Job, $m) }
    }
}

function Start-SIDataOutJobRun {
    <# A plain start of caj-si-data-out (as the pipeline starts its steps). @{ Started; Execution; Why }. Never throws. #>
    param([scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    if (-not $Arm) { $Arm = { param($Method, $Path, $Body) Invoke-SIArm -Method $Method -Path $Path -ApiVersion $script:SIDataOutJob.ArmApi -Body $Body } }
    try {
        $r = & $Arm 'POST' (Get-SIDataOutJobPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Action '/start') @{}
        $n = ''
        if ($r) { if ($r.PSObject.Properties['name']) { $n = [string]$r.name }; if (-not $n -and $r.PSObject.Properties['id'] -and $r.id) { $n = ([string]$r.id -split '/')[-1] } }
        [pscustomobject]@{ Started = $true; Execution = $n; Why = '' }
    } catch { [pscustomobject]@{ Started = $false; Execution = ''; Why = [string]$_.Exception.Message } }
}

# =====================================================================================================================
#  THE DATA SYNC'S SIDE: hold the lock while the findings per CI are replaced; mark; hand the send to the job
# =====================================================================================================================

function Enter-SIDataOutStore {
    <#
        The data sync is about to REPLACE the findings per CI: it takes the lock (kind datasync), waiting while the data-out
        job sends (at most -WaitSeconds; a send is never cut in the middle). @{ Tables; Held; Waited (seconds); Why }:
          Tables $false  the database has no data-out tables (an older install) -- nothing to coordinate
          Held   $true   the sync holds the lock (it frees it after the mark: Exit-SIDataOutStore)
          Held   $false  the send did not end within the wait (or the database could not be read) -- the sync goes on, said
        Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Holder, [scriptblock]$Log,
          [int]$WaitSeconds = $script:SIDataOutJob.SyncWaitSeconds, [int]$PollSeconds = $script:SIDataOutJob.SyncPollSeconds,
          [int]$LeaseSeconds = $script:SIDataOutJob.SyncLeaseSeconds, [scriptblock]$Sleep, [scriptblock]$Now)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $Now) { $Now = { [datetime]::UtcNow } }
    if (-not (Test-SIDataOutJobTables -Invoke $Invoke)) { return [pscustomobject]@{ Tables = $false; Held = $false; Waited = 0; Why = 'the database has no data-out tables yet' } }
    $start = & $Now; $said = $false
    while ($true) {
        $l = Request-SIDataOutLock -Invoke $Invoke -Holder $Holder -Kind datasync -LeaseSeconds $LeaseSeconds
        $waited = [int]((& $Now) - $start).TotalSeconds
        if ($l.Got) { return [pscustomobject]@{ Tables = $true; Held = $true; Waited = $waited; Why = '' } }
        if ($l.Why) { return [pscustomobject]@{ Tables = $true; Held = $false; Waited = $waited; Why = ('the data-out lock could not be read ({0})' -f $l.Why) } }
        if ($waited -ge $WaitSeconds) {
            return [pscustomobject]@{ Tables = $true; Held = $false; Waited = $waited; Why = ('the data-out job ({0}) was still sending after {1} minute(s); the findings per CI are replaced anyway' -f $l.Holder, [int]($waited / 60)) }
        }
        if (-not $said -and $Log) { $said = $true; & $Log 'INFO' ('data out  : the data-out job ({0}) is sending -- the findings per CI are replaced once it has finished (at most {1} minute(s))' -f $l.Holder, [int]($WaitSeconds / 60)) }
        & $Sleep $PollSeconds
    }
}

function Exit-SIDataOutStore {
    <# The data sync frees the lock it took for the store. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Holder)
    $null = Unlock-SIDataOut -Invoke $Invoke -Holder $Holder
}

function Get-SIDataOutMarkPlan {
    <#
        PURE. What the data sync does with data out once the findings per CI are stored. -DataModel: Invoke-SIDataCiSync's
        result; -Hold / -HoldWhy: the run is not complete (the pipeline started the sync after a failed step) or that cannot
        be told; -Tables: the database has the data-out tables. @{ Mark = '' | ready | held; Why }:
          ''     nothing is marked -- a dry run, an older database (no tables), or the findings per CI were NOT stored
                 this run (a part failed: the stored set did not change, nothing is sent from it)
          held   the run is not complete: the collection is marked held, nothing is sent from it
          ready  the collection is ready for data out
    #>
    param($DataModel, [bool]$Hold, [string]$HoldWhy = '', [bool]$Tables, [switch]$DryRun)
    if ($DryRun) { return [pscustomobject]@{ Mark = ''; Why = 'a dry run' } }
    if (-not $Tables) { return [pscustomobject]@{ Mark = ''; Why = 'the database has no data-out tables yet (the update adds them)' } }
    $st = ''
    if ($null -ne $DataModel) { $st = [string](Get-SIDataOutField $DataModel 'Status') }
    if ($st -eq 'failed') { return [pscustomobject]@{ Mark = ''; Why = 'the findings per CI of the newest collection were not stored this run' } }
    if ($Hold) { return [pscustomobject]@{ Mark = 'held'; Why = $(if ($HoldWhy) { $HoldWhy } else { 'the run is not complete' }) } }
    [pscustomobject]@{ Mark = 'ready'; Why = '' }
}

function Invoke-SIDataOutReadyMark {
    <#
        THE MARK (the data sync, right after the findings per CI are stored). -Plan: Get-SIDataOutMarkPlan. The collection
        is the one the findings per CI were made from (-DataModel CollectionTime); a run that stored no newer set re-arms the
        newest mark (the set did not change). @{ Marked (ready | held | ''); ReadyId; CollectionTime; Why }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Plan, $DataModel, [string]$MarkedBy = '', [scriptblock]$Log)
    $out = [pscustomobject]@{ Marked = ''; ReadyId = $null; CollectionTime = ''; Why = [string]$Plan.Why }
    if (-not [string]$Plan.Mark) { return $out }
    try {
        $ct = [string](Get-SIDataOutField $DataModel 'CollectionTime')
        if (-not $ct.Trim()) { $nw = $null; try { $nw = Get-SIDataOutNewestReady -Invoke $Invoke } catch { $nw = $null }; if ($nw) { $ct = [string]$nw.CollectionTime } }
        if (-not $ct.Trim()) { $ct = 'current' }
        $fr = @(); $f0 = Get-SIDataOutField $DataModel 'FrozenReports'; if ($f0) { $fr = @(@($f0) | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
        $id = Set-SIDataOutReadyMark -Invoke $Invoke -CollectionTime $ct.Trim() -State ([string]$Plan.Mark) -FrozenReports $fr -Why ([string]$Plan.Why) -By $MarkedBy
        if ($null -eq $id) { $out.Why = 'the mark was not written'; return $out }
        $out.Marked = [string]$Plan.Mark; $out.ReadyId = $id; $out.CollectionTime = $ct.Trim()
        if ($Log) {
            if ($out.Marked -eq 'ready') { & $Log 'OK' ('data out  : the collection of {0} is marked ready for data out (the findings per CI are stored)' -f $out.CollectionTime) }
            else { & $Log 'WARN' ('data out  : the collection of {0} is marked HELD for data out -- {1}; nothing is sent from it' -f $out.CollectionTime, [string]$Plan.Why) }
        }
    } catch {
        $out.Marked = ''; $out.Why = ('the mark could not be written ({0})' -f $_.Exception.Message)
        if ($Log) { & $Log 'WARN' ('data out  : {0} -- the data sync sends data out itself' -f $out.Why) }
    }
    $out
}

function Invoke-SIDataOutHandOff {
    <#
        After the mark: start caj-si-data-out when the install has it. @{ HandedToJob; Execution; Why }:
          HandedToJob $true   the job was started -- the data sync does NOT send data out itself
          HandedToJob $false  not marked ready, the job is not there (an older install), or it could not be started -- the
                              data sync sends data out itself, as before (the fallback; never a lost push)
        -Installed { -> Test-SIDataOutJobInstalled result }, -Start { -> Start-SIDataOutJobRun result } (seams). Never throws.
    #>
    param([Parameter(Mandatory)]$Mark, [Parameter(Mandatory)][scriptblock]$Installed, [Parameter(Mandatory)][scriptblock]$Start, [scriptblock]$Log)
    if ([string]$Mark.Marked -ne 'ready') { return [pscustomobject]@{ HandedToJob = $false; Execution = ''; Why = [string]$Mark.Why } }
    $inst = $null; try { $inst = & $Installed } catch { $inst = [pscustomobject]@{ Installed = $false; Known = $false; Why = [string]$_.Exception.Message } }
    if (-not $inst -or -not $inst.Installed) {
        $w = if ($inst) { [string]$inst.Why } else { 'the job could not be checked' }
        if ($Log) { & $Log 'INFO' ('data out  : {0} -- the data sync sends data out itself' -f $w) }
        return [pscustomobject]@{ HandedToJob = $false; Execution = ''; Why = $w }
    }
    $st = $null; try { $st = & $Start } catch { $st = [pscustomobject]@{ Started = $false; Execution = ''; Why = [string]$_.Exception.Message } }
    if (-not $st -or -not $st.Started) {
        $w = ('{0} could not be started ({1})' -f $script:SIDataOutJob.Job, $(if ($st) { [string]$st.Why } else { 'no answer' }))
        if ($Log) { & $Log 'WARN' ('data out  : {0} -- the data sync sends data out itself' -f $w) }
        return [pscustomobject]@{ HandedToJob = $false; Execution = ''; Why = $w }
    }
    if ($Log) { & $Log 'OK' ('data out  : handed to {0} (execution {1}) -- it sends now; the data sync goes on with its other steps' -f $script:SIDataOutJob.Job, $(if ($st.Execution) { $st.Execution } else { '?' })) }
    [pscustomobject]@{ HandedToJob = $true; Execution = [string]$st.Execution; Why = '' }
}

# =====================================================================================================================
#  THE JOB'S CORE
# =====================================================================================================================

function Test-SIDataOutSendFailed {
    <# PURE. Did a send need another try -- an output that was not written ('failed') or not whole ('partial')? A hold, a
       switched-off output or a ServiceNow import that reported errors is not tried again (another try changes nothing). #>
    param([AllowEmptyCollection()][object[]]$Results = @())
    @(@($Results) | Where-Object { $_ -and [string]$_.Outcome -in @('failed', 'partial') }).Count -gt 0
}

function Format-SIDataOutSendWhy {
    <# PURE. One line: the outputs that failed and why. #>
    param([AllowEmptyCollection()][object[]]$Results = @())
    (@(@($Results) | Where-Object { $_ -and [string]$_.Outcome -in @('failed', 'partial') } | ForEach-Object { '{0} {1}: {2}' -f [string]$_.Output, [string]$_.Outcome, [string]$_.Why }) -join '; ')
}

function Invoke-SIDataOutJobCore {
    <#
        THE JOB (caj-si-data-out). -Send { param($Ready) -> Invoke-SIDataOut's results } sends ONE mark (its FrozenReports).
        1. no data-out tables                  -> 'no-tables' (an older database: the data sync sends data out itself)
        2. the lock is held                    -> 'busy': by the data sync (it is replacing the findings per CI and starts
                                                  this job once they are stored) or by another start of this job -- this
                                                  start does nothing
        3. the NEWEST mark (only that one):    none -> 'nothing'; held -> 'held' (nothing is sent); else it is SENT (a mark
                                                  already sent is sent again: a resend -- the outputs send what changed)
        4. a send whose outputs failed is tried again (-Attempts, waiting -RetrySeconds between) -- then sent | failed
        5. after a send, once more: a NEWER mark that arrived meanwhile is sent too (at most -MaxRounds)
        The lock is renewed while it works (-Renew, given to -Send) and freed at the end. Returns @{ Outcome = no-tables |
        busy | nothing | held | sent | failed; Sent (ReadyIds); Results (the last send's); Why; Rounds }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Send,
          [string]$Execution = $(if ($env:CONTAINER_APP_JOB_EXECUTION_NAME) { [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME } else { 'data-out-' + [guid]::NewGuid().ToString('N').Substring(0, 8) }),
          [int]$Attempts = $script:SIDataOutJob.Attempts, [int[]]$RetrySeconds = $script:SIDataOutJob.RetrySeconds, [int]$MaxRounds = $script:SIDataOutJob.MaxRounds,
          [int]$LeaseSeconds = $script:SIDataOutJob.LeaseSeconds, [int]$RenewSeconds = $script:SIDataOutJob.RenewSeconds,
          [scriptblock]$Sleep, [scriptblock]$Now, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $Now) { $Now = { [datetime]::UtcNow } }
    $res = [pscustomobject]@{ Outcome = 'nothing'; Sent = @(); Results = @(); Why = ''; Rounds = 0 }
    if (-not (Test-SIDataOutJobTables -Invoke $Invoke)) {
        $res.Outcome = 'no-tables'; $res.Why = 'the database has no data-out tables yet (the update adds them) -- the data sync sends data out itself'
        & $Log 'WARN' ('data out  : ' + $res.Why); return $res
    }
    $lock = Request-SIDataOutLock -Invoke $Invoke -Holder $Execution -Kind data-out -LeaseSeconds $LeaseSeconds
    if (-not $lock.Got) {
        $res.Outcome = 'busy'
        $res.Why = if ($lock.Why) { 'the data-out lock could not be read ({0}) -- nothing is sent by this start' -f $lock.Why }
                   elseif ($lock.Kind -eq 'datasync') { 'the data sync ({0}) is replacing the findings per CI -- it starts this job once they are stored; this start does nothing' -f $lock.Holder }
                   else { 'another start of this job ({0}) is sending -- this start does nothing (it sends the newest mark when it has finished)' -f $lock.Holder }
        & $Log 'INFO' ('data out  : ' + $res.Why); return $res
    }
    # the lease, renewed while the send works (a job that died frees it within LeaseSeconds)
    $lease = @{ Last = (& $Now) }
    $renew = {
        if (((& $Now) - $lease.Last).TotalSeconds -lt $RenewSeconds) { return }
        $lease.Last = & $Now
        $rl = Request-SIDataOutLock -Invoke $Invoke -Holder $Execution -Kind data-out -LeaseSeconds $LeaseSeconds
        if (-not $rl.Got) { & $Log 'WARN' ('data out  : the hold on the data-out lock could not be renewed ({0})' -f $(if ($rl.Why) { $rl.Why } else { 'held by ' + $rl.Holder })) }
    }
    try {
        $done = New-Object System.Collections.Generic.List[long]
        for ($round = 1; $round -le [Math]::Max(1, $MaxRounds); $round++) {
            $ready = $null
            try { $ready = Get-SIDataOutNewestReady -Invoke $Invoke }
            catch { $res.Outcome = 'failed'; $res.Why = ('the marks could not be read ({0})' -f $_.Exception.Message); & $Log 'WARN' ('data out  : ' + $res.Why); break }
            if (-not $ready) {
                if ($round -eq 1) { $res.Outcome = 'nothing'; $res.Why = 'no collection is marked ready for data out yet -- the data sync marks one once it has stored the findings per CI'; & $Log 'INFO' ('data out  : ' + $res.Why) }
                break
            }
            # after the first round only a NEWER mark that still waits is sent
            if ($round -gt 1 -and ($done.Contains([long]$ready.ReadyId) -or $ready.State -notin @('ready', 'failed'))) { break }
            if ($ready.State -eq 'held') {
                if ($round -eq 1) { $res.Outcome = 'held'; $res.Why = ('the newest collection ({0}) is held -- {1}; nothing is sent from it' -f $ready.CollectionTime, $ready.Why); & $Log 'WARN' ('data out  : ' + $res.Why) }
                break
            }
            $res.Rounds = $round
            if ($ready.State -eq 'sent') { & $Log 'INFO' ('data out  : the newest collection ({0}) was sent before -- sent again (a resend: the outputs send what changed)' -f $ready.CollectionTime) }
            else { & $Log 'INFO' ('data out  : sending the collection of {0}' -f $ready.CollectionTime) }
            $last = @(); $ok = $false; $why = ''
            for ($a = 1; $a -le [Math]::Max(1, $Attempts); $a++) {
                $null = Set-SIDataOutReadyState -Invoke $Invoke -ReadyId $ready.ReadyId -State sending -By $Execution -Attempt
                & $renew
                try { $last = @(& $Send $ready); $ok = -not (Test-SIDataOutSendFailed -Results $last); $why = Format-SIDataOutSendWhy -Results $last }
                catch { $last = @(); $ok = $false; $why = [string]$_.Exception.Message }
                if ($ok) { break }
                if ($a -lt $Attempts) {
                    $wait = 60; if (@($RetrySeconds).Count) { $wait = [int]@($RetrySeconds)[[Math]::Min($a - 1, @($RetrySeconds).Count - 1)] }
                    & $Log 'WARN' ('data out  : attempt {0} of {1} did not deliver everything ({2}) -- tried again in {3} s' -f $a, $Attempts, $why, $wait)
                    if ($wait -gt 0) { & $Sleep $wait }
                    & $renew
                }
            }
            $res.Results = $last
            if ($ok) {
                $null = Set-SIDataOutReadyState -Invoke $Invoke -ReadyId $ready.ReadyId -State sent -By $Execution
                $done.Add([long]$ready.ReadyId); $res.Sent = @($done.ToArray()); $res.Outcome = 'sent'; $res.Why = ''
                & $Log 'OK' ('data out  : the collection of {0} was sent' -f $ready.CollectionTime)
            } else {
                $null = Set-SIDataOutReadyState -Invoke $Invoke -ReadyId $ready.ReadyId -State failed -Why $why -By $Execution
                $res.Outcome = 'failed'; $res.Why = ('the collection of {0} was not sent whole after {1} attempt(s) -- {2}; the next start sends it' -f $ready.CollectionTime, $Attempts, $why)
                & $Log 'WARN' ('data out  : ' + $res.Why)
                break
            }
        }
    } finally {
        $null = Unlock-SIDataOut -Invoke $Invoke -Holder $Execution
    }
    $res
}
