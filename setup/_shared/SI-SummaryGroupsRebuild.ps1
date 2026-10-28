#Requires -Version 5.1
<#
    SecurityInsight -- #842 (owner 2026-10-20: Security recommendations > Summary "still not working"). THE SUMMARY VIEWS OF AN
    EXISTING INSTALL ARE WRITTEN AGAIN RIGHT AFTER AN UPDATE THAT CHANGED THEM -- not on the next nightly run.

    The Summary views are groupings the data sync writes per collection (engine\pro-data\_shared\SI-DataSummaryGroups.ps1:
    sidata.SummaryGroup / SummaryGroupCounted, sidata.SummaryGroupState with the hash of the definition they were written
    from). A collection written from another definition (data-model\summary-groupings.locked.json changed -- a new grouping,
    a new default) is written again by the NEXT data sync. Until then the view it lacks is not there: after the update of
    2026-10-20 the new default view of every collection waited a day for the nightly run.

    The step, run by the update (Invoke-SIContainerUpdate.ps1 step 9f), Pro only:
      * reads how many live complete Detailed collections were written from another definition than the one this release
        ships (Get-SISummaryGroupingDefinition .Hash -- the engine's own hash; nothing is hashed here);
      * none -> nothing, and nothing is said (every later update finds none too: the step is idempotent);
      * some -> queues ONE run of the pipeline step asset-datasync in cfg.PipelineQueue -- the same statement and the same
        dedup the web app's "Run now" and the runner use (Get-SIPipelineSqlText 'Enqueue'): a request that already waits is
        kept once. A queued request never runs over anything: it waits until the install's lock is free (a pipeline run
        going finishes first), then the pipeline job takes it on its next wake-up (every 5 minutes);
      * a pipeline run, the Deliver stage or a data sync already waiting -> nothing is queued (that run writes them);
      * the install runs its jobs on their own schedules (Operations > Jobs: Schedules), or the pipeline has no data sync
        step -> nothing is queued; the data sync's next run writes them (said).
    One plain line in the update log. Never fails the update. PURE planning (Get-SISummaryGroupsRebuildPlan) over two SQL
    seams (the data database, the Pro database).
#>

if (-not (Get-Command -Name Get-SIPipelineSqlText -ErrorAction SilentlyContinue)) {
    $siPipe = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-Pipeline.ps1')
    if (Test-Path -LiteralPath $siPipe) { . $siPipe }
}

$script:SISummaryRebuild = @{ Step = 'asset-datasync'; By = 'SecurityInsight update' }

function Get-SISummaryGroupsRebuildSql {
    <#
        'Stale' (the data database, @Hash): how many live complete Detailed collections hold Summary views written from another
        definition; -1 = the database has no Summary views yet (the schema step adds them; the data sync then fills them).
        'Pipeline' (the Pro database): the pipeline's mode and definition, and the requests that wait in its queue.
    #>
    param([Parameter(Mandatory)][ValidateSet('Stale', 'Pipeline')][string]$Name)
    if ($Name -eq 'Stale') {
        return @'
IF OBJECT_ID(N'sidata.SummaryGroupState') IS NULL OR OBJECT_ID(N'sidata.Collection') IS NULL OR COL_LENGTH(N'sidata.SummaryGroupState', N'DefinitionHash') IS NULL
BEGIN SELECT CAST(-1 AS int) AS Stale; RETURN; END
DECLARE @q nvarchar(max) = N'SELECT COUNT(*) AS Stale FROM sidata.SummaryGroupState AS s JOIN sidata.Collection AS c ON c.CollectionId = s.CollectionId WHERE c.Status = N''Complete'' AND c.Kind = N''Detailed'' AND ISNULL(s.DefinitionHash, N'''') <> @Hash'
    + CASE WHEN COL_LENGTH(N'sidata.Collection', N'RetiredAt') IS NULL THEN N'' ELSE N' AND c.RetiredAt IS NULL' END + N';';
EXEC sys.sp_executesql @q, N'@Hash nvarchar(64)', @Hash = @Hash;
'@
    }
    @'
DECLARE @mode nvarchar(16) = NULL, @def nvarchar(max) = NULL;
IF OBJECT_ID(N'cfg.JobFlow') IS NOT NULL SELECT @mode = Mode, @def = DefinitionJson FROM cfg.JobFlow WHERE FlowId = N'daily';
IF OBJECT_ID(N'cfg.PipelineQueue') IS NULL
    SELECT N'flow' AS Kind, CAST(@mode AS nvarchar(max)) AS Scope, @def AS Target, CAST(0 AS int) AS HasQueue;
ELSE
    SELECT N'flow' AS Kind, CAST(@mode AS nvarchar(max)) AS Scope, @def AS Target, CAST(1 AS int) AS HasQueue
    UNION ALL
    SELECT N'queued', CAST(Scope AS nvarchar(max)), CAST(Target AS nvarchar(max)), CAST(1 AS int) FROM cfg.PipelineQueue WHERE PipelineId = N'daily' AND State = N'Queued';
'@
}

function Test-SISummaryGroupsRebuildCovered {
    <# PURE. A waiting request that runs the data sync: the pipeline, the Deliver stage, the data sync step (or the pipeline from it). #>
    param($Request)
    $scope = ([string]$Request.Scope).Trim().ToLowerInvariant(); $target = ([string]$Request.Target).Trim().ToLowerInvariant()
    if ($target.StartsWith('caj-si-')) { $target = $target.Substring(7) }
    ($scope -eq 'pipeline') -or ($scope -eq 'stage' -and $target -eq 'deliver') -or ($scope -in 'step', 'from-step' -and $target -eq $script:SISummaryRebuild.Step)
}

function Get-SISummaryGroupsRebuildPlan {
    <#
        PURE. -Stale: collections written from another definition (-1 = no Summary views in the database yet); -Mode / -DefinitionJson:
        the stored pipeline (empty = none stored: the default pipeline over the installed jobs); -Queued: the waiting requests
        (Scope, Target); -HasQueue: cfg.PipelineQueue exists; -DataSyncInstalled: the install has the data sync job.
        Returns @{ Action = none | schedules | no-step | no-queue | already | queue; Stale; Lines }.
    #>
    param([int]$Stale = 0, [string]$Mode = '', [string]$DefinitionJson = '', [AllowEmptyCollection()][object[]]$Queued = @(),
          [bool]$HasQueue = $true, [bool]$DataSyncInstalled = $true)
    $n = [Math]::Max(0, $Stale)
    $what = '{0} collection(s) hold Summary views from the previous version' -f $n
    $out = { param($a, $l) [pscustomobject]@{ Action = $a; Stale = $n; Lines = @($l | Where-Object { $_ }) } }
    if ($Stale -le 0) { return (& $out 'none' @()) }
    if (([string]$Mode).Trim().ToLowerInvariant() -eq 'schedules') {
        return (& $out 'schedules' ('summary views: {0} -- the data sync writes them again on its next scheduled run (this install runs its jobs on their own schedules)' -f $what))
    }
    $hasStep = $DataSyncInstalled -and (-not ([string]$DefinitionJson).Trim() -or ([string]$DefinitionJson -match '(?i)"job"\s*:\s*"(caj-si-)?asset-datasync"'))
    if (-not $hasStep) {
        return (& $out 'no-step' ('summary views: {0} -- the data sync is not a step of the pipeline, so nothing is queued; the data sync writes them again on its next run' -f $what))
    }
    if (-not $HasQueue) {
        return (& $out 'no-queue' ('summary views: {0} -- the pipeline''s queue is not in the database yet, so nothing is queued; the next data sync writes them again' -f $what))
    }
    if (@($Queued | Where-Object { $_ -and (Test-SISummaryGroupsRebuildCovered $_) }).Count) {
        return (& $out 'already' ('summary views: {0} -- a data sync already waits in the queue and writes them again' -f $what))
    }
    & $out 'queue' ('summary views: {0} -- the data sync is queued now to write them again; it starts as soon as no pipeline run is going' -f $what)
}

function Invoke-SISummaryGroupsRebuild {
    <#
        -DataSql / -Sql: { param($Query, $Params, $Mode) } over the data database and the Pro database ('reader' -> rows);
        -Hash: the shipped definition's hash (Get-SISummaryGroupingDefinition .Hash); -DataSyncInstalled: the install has the
        data sync job. -WhatIf: the plan only. Never throws. Returns @{ Action = none | schedules | no-step | no-queue | already
        | queued | plan | failed; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$DataSql, [Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$Hash,
          [bool]$DataSyncInstalled = $true, [switch]$WhatIf)
    $rows = { param($r) @($r | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) }
    $val = { param($o, $n) if ($null -eq $o) { return $null }; $p = $o.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value -and -not ($p.Value -is [DBNull])) { $p.Value } else { $null } }
    try {
        if (-not "$Hash".Trim()) { throw 'the shipped definition of the Summary views has no hash' }
        $s = @(& $rows (& $DataSql (Get-SISummaryGroupsRebuildSql -Name Stale) @{ Hash = [string]$Hash } 'reader'))
        $stale = if ($s.Count) { [int](& $val $s[0] 'Stale') } else { 0 }
        if ($stale -le 0) { return [pscustomobject]@{ Action = 'none'; Lines = @() } }
        $p = @(& $rows (& $Sql (Get-SISummaryGroupsRebuildSql -Name Pipeline) @{} 'reader'))
        $flow = @($p | Where-Object { [string]$_.Kind -eq 'flow' })[0]
        $plan = Get-SISummaryGroupsRebuildPlan -Stale $stale -Mode ([string](& $val $flow 'Scope')) -DefinitionJson ([string](& $val $flow 'Target')) `
            -Queued @($p | Where-Object { [string]$_.Kind -eq 'queued' }) -HasQueue ($flow -and [int](& $val $flow 'HasQueue') -eq 1) -DataSyncInstalled $DataSyncInstalled
        if ($plan.Action -ne 'queue') { return [pscustomobject]@{ Action = $plan.Action; Lines = $plan.Lines } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($plan.Lines | ForEach-Object { $_ -replace 'is queued now', 'would be queued (re-run with -Apply)' }) } }
        if (-not (Get-Command -Name Get-SIPipelineSqlText -ErrorAction SilentlyContinue)) { throw 'the pipeline''s queue statement is not loaded' }
        $note = 'the update changed the Summary views: the data sync writes them again for {0} collection(s)' -f $plan.Stale
        $q = @(& $rows (& $Sql (Get-SIPipelineSqlText 'Enqueue') @{ Scope = 'step'; Target = $script:SISummaryRebuild.Step; Trg = 'manual'; RequestedBy = $script:SISummaryRebuild.By; SlotUtc = $null; Note = $note } 'reader'))
        $outcome = if ($q.Count) { [string](& $val $q[0] 'Outcome') } else { 'Missing' }
        switch ($outcome) {
            'Queued' { return [pscustomobject]@{ Action = 'queued'; Lines = $plan.Lines } }
            'Deduplicated' { return [pscustomobject]@{ Action = 'already'; Lines = @(('summary views: {0} collection(s) hold Summary views from the previous version -- a data sync already waits in the queue and writes them again' -f $plan.Stale)) } }
            default { return [pscustomobject]@{ Action = 'no-queue'; Lines = @(('summary views: {0} collection(s) hold Summary views from the previous version -- the pipeline''s queue is not in the database yet, so nothing is queued; the next data sync writes them again' -f $plan.Stale)) } }
        }
    } catch {
        return [pscustomobject]@{ Action = 'failed'; Lines = @(('summary views: whether they must be written again was not checked ({0}) -- the next data sync writes them; the next update checks again' -f $_.Exception.Message)) }
    }
}
