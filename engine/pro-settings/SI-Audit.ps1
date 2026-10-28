#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE AUDIT TRAIL, PowerShell half (#260, framework DOCS\REQUIREMENTS.md AUDIT-1).

    ONE trail per install: cfg.AuditEvent in the Pro database (sql\si-pro-settings.sql). The web app writes its events
    there (SI.Management.Web Audit\AuditCore.cs); the jobs, setup tools and engines write theirs with Write-SIAuditEvent;
    every cfg.ChangeLog row is copied in by the table's trigger in the same transaction.

    The CLOSED action list is config\audit-actions.locked.json -- the file the web app reads too; a test compares the two
    lists. A failed write NEVER fails the step it records (the change already happened): it is warned once per failure,
    counted (Get-SIAuditHealth) and answered $false. A plan / dry run is written with WhatIf = 1, or not at all.

    Append-only: the database refuses UPDATE / DELETE on the trail to every identity (#289, a DENY in
    sql\si-pro-settings.sql). The ONE removal is the retention step below (Invoke-SIAuditRetention), run by the data
    sync job through the procedure cfg.AuditRetentionApply, bounded by SI_Pro_AuditRetentionMonths (not set = kept forever;
    at least 13 months), and it records itself on the trail.
#>

$script:SIAuditRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:SIAuditHealth = @{ Written = 0; Failed = 0; LastError = '' }
$script:SIAuditMinRetentionMonths = 13

function Get-SIAuditActionCatalog {
    <# PURE (reads one shipped file). The closed list as shipped: actions, change categories / verbs, sources, outcomes. #>
    param([string]$SIRoot = $script:SIAuditRoot)
    $p = [System.IO.Path]::Combine($SIRoot, 'config', 'audit-actions.locked.json')
    ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($p))
}

function Get-SIAuditActionList {
    <# Every action a row may carry, sorted ordinally: the listed actions + <category>.change.<verb> of the change rows. #>
    param([string]$SIRoot = $script:SIAuditRoot)
    $c = Get-SIAuditActionCatalog -SIRoot $SIRoot
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($c.actions)) { $all.Add([string]$a.action) }
    foreach ($cat in @($c.changeCategories)) { foreach ($v in @($c.changeVerbs)) { $all.Add(('{0}.change.{1}' -f $cat, $v)) } }
    $arr = [string[]]@($all | Select-Object -Unique)
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    $arr
}

function Test-SIAuditAction {
    <# $true when the action is on the closed list. #>
    param([Parameter(Mandatory)][string]$Action, [string]$SIRoot = $script:SIAuditRoot)
    @(Get-SIAuditActionList -SIRoot $SIRoot) -contains $Action
}

function Get-SIAuditInsertSql {
    <# THE PowerShell writer's one statement: an INSERT into cfg.AuditEvent (TsUtc is the store's). Same text as the web app's. #>
@'
IF OBJECT_ID(N'cfg.AuditEvent') IS NULL
    SELECT N'Missing' AS Outcome;
ELSE
BEGIN
    INSERT cfg.AuditEvent (RecordType, Action, Actor, ActorSource, Target, Reason, Outcome, OutcomeText, BeforeJson, AfterJson, CorrelationId, WhatIf, ScopeDomain, ScopeDepartmentId)
    VALUES (N'event', @Action, @Actor, @ActorSource, @Target, @Reason, @Outcome, @OutcomeText, @BeforeJson, @AfterJson, @CorrelationId, @WhatIf, @ScopeDomain, @ScopeDepartmentId);
    SELECT N'Saved' AS Outcome;
END
'@
}

function Test-SIAuditSecretName {
    <# PURE. A field whose value is a secret or a credential -- never written to the trail (the web app's rule). #>
    param([AllowEmptyString()][string]$Name)
    if ($Name.StartsWith('__')) { return $true }
    $Name -match '(?i)(secret|password|passwd|^pwd$|token|^otp|otp$|^pin$|code$|credential|apikey|api_key|signature|cookie|^t$|^sig$)'
}

function ConvertTo-SIAuditText {
    <# PURE. Free text with any long opaque run (a token, a key) cut out, at most -Max characters. #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Max = 1000)
    if ($null -eq $Text) { return $null }
    $t = [regex]::Replace($Text, '(?<![A-Za-z0-9_\-+=])(?=[A-Za-z0-9_\-+=]*[0-9])(?=[A-Za-z0-9_\-+=]*[A-Za-z])[A-Za-z0-9_\-+=]{40,}', '(hidden)')
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) }
    $t
}

function ConvertTo-SIAuditJson {
    <# PURE. A before / after state as compact JSON with every secret-named field hidden (one level of a hashtable or object). #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { return (ConvertTo-Json -InputObject (ConvertTo-SIAuditText -Text $InputObject -Max 4000) -Compress) }
    $o = [ordered]@{}
    $isDict = $InputObject -is [System.Collections.IDictionary]
    $names = if ($isDict) { @($InputObject.get_Keys() | ForEach-Object { [string]$_ }) } else { @($InputObject.PSObject.Properties | ForEach-Object { [string]$_.Name }) }
    foreach ($k in $names) {
        $v = if ($isDict) { $InputObject[$k] } else { $InputObject.$k }
        if (Test-SIAuditSecretName -Name $k) { $o[$k] = '(hidden)' }
        elseif ($v -is [string]) { $o[$k] = ConvertTo-SIAuditText -Text $v -Max 2000 }
        else { $o[$k] = $v }
    }
    ConvertTo-Json -InputObject $o -Depth 5 -Compress
}

function Get-SIAuditActor {
    <#
        Who a job / setup step runs as: the managed identity (its client id) in a container, else the signed-in Windows
        account, else the operating-system user -- never a parameter (PIM BUG-180). -Job names the job it ran in.
    #>
    param([string]$Job)
    $id = if (Get-Command -Name Get-SIProSessionActor -ErrorAction SilentlyContinue) { Get-SIProSessionActor }
          elseif ($global:SI_UseManagedIdentity) { $c = [Environment]::GetEnvironmentVariable('AZURE_CLIENT_ID'); if ($c) { 'managed identity ' + $c } else { 'managed identity' } }
          else { [System.Environment]::UserName }
    if ($Job) { '{0} ({1})' -f $Job, $id } else { [string]$id }
}

function New-SIAuditRecord {
    <# PURE. The parameters of one event row, validated against the closed lists; refuses a malformed row. #>
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Actor,
        [ValidateSet('web', 'job', 'engine', 'setup', 'api', 'portal')][string]$ActorSource = 'job',
        [string]$Target, [string]$Reason,
        [ValidateSet('ok', 'error', 'refused', 'held')][string]$Outcome = 'ok',
        [string]$OutcomeText, $Before, $After, [string]$CorrelationId,
        [switch]$WhatIfRun, [string]$ScopeDomain, $ScopeDepartmentId
    )
    if ($Action -notmatch '^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$') { throw "audit action '$Action' is not lower-case domain.object.verb" }
    $cut = { param([string]$s, [int]$n) if ($null -eq $s -or $s.Length -le $n) { $s } else { $s.Substring(0, $n) } }
    [ordered]@{
        Action = $Action; Actor = (& $cut $Actor 256); ActorSource = $ActorSource; Target = (& $cut $Target 400); Reason = (& $cut $Reason 400)
        Outcome = $Outcome; OutcomeText = (ConvertTo-SIAuditText -Text $OutcomeText -Max 1000)
        BeforeJson = (ConvertTo-SIAuditJson -InputObject $Before); AfterJson = (ConvertTo-SIAuditJson -InputObject $After)
        CorrelationId = $(if ($CorrelationId) { $CorrelationId } else { $null }); WhatIf = [bool]$WhatIfRun
        ScopeDomain = (& $cut $ScopeDomain 64); ScopeDepartmentId = $(if ($null -ne $ScopeDepartmentId -and "$ScopeDepartmentId" -match '^\d+$') { [int]$ScopeDepartmentId } else { $null })
    }
}

function Write-SIAuditEvent {
    <#
        THE PowerShell writer: one 'event' row on the trail. -Store (New-SIProSettingsStore) or -Invoke (the
        (sql, params, mode) seam of every Pro engine). NEVER throws: a failure is warned, counted and answered $false.
    #>
    <#
        #302 (framework AUDIT-1.1): a row a JOB writes (-ActorSource job / engine) names the PERSON who asked for the
        change when one did: -Attribution (a record from Get-SIChangeAttribution, looked up by the caller by its target),
        else the person who started this job execution (Get-SIJobAttribution: SI_AUDIT_CID in the environment, set by the
        web app). The row then reads Actor = that person, After.appliedBy = the job (-Actor), After.jobRun = -JobRun (else
        the caller's -CorrelationId, else the execution), After.approvedBy, and CorrelationId = the commit / request id.
        No person asked: the job stays the actor and After.initiatedBy says so. -NoAttribution: a row that already names
        the person itself (a release approved on a VM's command line).
    #>
    param(
        $Store, [scriptblock]$Invoke,
        [Parameter(Mandatory)][string]$Action,
        [string]$Actor,
        [string]$ActorSource = 'job',
        [string]$Target, [string]$Reason,
        [string]$Outcome = 'ok',
        [string]$OutcomeText, $Before, $After, [string]$CorrelationId,
        [switch]$WhatIfRun, [string]$ScopeDomain, $ScopeDepartmentId,
        $Attribution, [string]$JobRun, [switch]$NoAttribution,
        [scriptblock]$Log
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Warning $msg } }
    if (-not $Invoke -and $Store) { $Invoke = $Store.Invoke }
    try {
        if (-not $Invoke) { throw 'no Pro database to write to' }
        if (-not $Actor) { $Actor = Get-SIAuditActor }
        if ($ActorSource -in @('job', 'engine') -and -not $NoAttribution) {
            $attr = $Attribution
            if ($null -eq $attr) { try { $attr = Get-SIJobAttribution -Invoke $Invoke -Log $Log } catch { $attr = $null } }
            $res = Resolve-SIAuditAttribution -JobActor $Actor -Attribution $attr -JobRun $JobRun -CorrelationId $CorrelationId -After $After
            $Actor = $res.Actor; $After = $res.After; $CorrelationId = $res.CorrelationId
        }
        try { if (-not (Test-SIAuditAction -Action $Action)) { & $Log 'WARN' ("audit action '{0}' is not on the closed list (config\audit-actions.locked.json) -- written anyway" -f $Action) } } catch { }
        $p = New-SIAuditRecord -Action $Action -Actor $Actor -ActorSource $ActorSource -Target $Target -Reason $Reason -Outcome $Outcome -OutcomeText $OutcomeText `
                -Before $Before -After $After -CorrelationId $CorrelationId -WhatIfRun:$WhatIfRun -ScopeDomain $ScopeDomain -ScopeDepartmentId $ScopeDepartmentId
        $r = & $Invoke (Get-SIAuditInsertSql) $p 'scalar'
        if ("$r" -eq 'Missing') { throw 'the Pro database has no cfg.AuditEvent yet -- apply sql\si-pro-settings.sql (it only adds)' }
        if ($null -eq $script:SIAuditHealth) { $script:SIAuditHealth = @{ Written = 0; Failed = 0; LastError = '' } }
        $script:SIAuditHealth.Written++
        return $true
    } catch {
        # 2026-10-04, live on ring 1: loaded into another scope, the counter was $null and `.Failed++` THREW -- an audit
        # failure stopped the vulnerability connector. An audit failure never fails the step: initialise here, never throw.
        $auditErr = [string]$_.Exception.Message
        if ($null -eq $script:SIAuditHealth) { $script:SIAuditHealth = @{ Written = 0; Failed = 0; LastError = '' } }
        try { $script:SIAuditHealth.Failed++; $script:SIAuditHealth.LastError = $auditErr } catch { }
        & $Log 'WARN' ("the audit trail row '{0}' could not be written: {1} -- the step itself is not affected" -f $Action, $auditErr)
        return $false
    }
}

# ------------------------------------------------------------------------------------------------------------------
# #302 (framework AUDIT-1.1): THE ACTOR OF A CHANGE A JOB CARRIES OUT IS THE PERSON WHO ASKED FOR IT.
# The web app records, AT COMMIT, who initiated each change it hands to a job (and who approved it) in
# cfg.ChangeAttribution, under the commit's correlation id and keyed by the changed target. The jobs look it up here.
# ------------------------------------------------------------------------------------------------------------------
$script:SIAttributionDays = 30
$script:SIJobAttribution = $null

function Get-SIChangeAttributionInsertSql {
    <# The one write of an attribution row (a release approved on a VM's command line; the web app has the same text). #>
@'
IF OBJECT_ID(N'cfg.ChangeAttribution') IS NULL
    SELECT N'Missing' AS Outcome;
ELSE
BEGIN
    INSERT cfg.ChangeAttribution (CorrelationId, TargetKey, Kind, Op, Title, Actor, ApprovedBy, Source)
    VALUES (@CorrelationId, @TargetKey, @Kind, @Op, @Title, @Actor, @ApprovedBy, @Source);
    SELECT N'Saved' AS Outcome;
END
'@
}

function Get-SIChangeAttributionSelectSql {
    <# The newest attribution of a correlation id and / or a target (and kind), within the last @Days days. #>
@'
IF OBJECT_ID(N'cfg.ChangeAttribution') IS NOT NULL
SELECT TOP (1) CorrelationId, TargetKey, Kind, Op, Title, Actor, ApprovedBy, Source, CreatedAt
FROM cfg.ChangeAttribution
WHERE (@Cid IS NULL OR CorrelationId = @Cid) AND (@Target IS NULL OR TargetKey = @Target) AND (@Kind IS NULL OR Kind = @Kind)
  AND CreatedAt >= DATEADD(day, -@Days, SYSUTCDATETIME())
ORDER BY AttributionId DESC;
'@
}

function ConvertTo-SIChangeAttribution {
    <# PURE. A cfg.ChangeAttribution row (hashtable or object) -> the attribution record the writer applies; $null without an actor. #>
    param($Row, [string]$Via = 'store')
    if ($null -eq $Row) { return $null }
    $g = { param($n) if ($Row -is [System.Collections.IDictionary]) { $Row[$n] } elseif ($Row.PSObject.Properties[$n]) { $Row.$n } else { $null } }
    $actor = [string](& $g 'Actor')
    if ([string]::IsNullOrWhiteSpace($actor)) { return $null }
    $ap = [string](& $g 'ApprovedBy')
    [pscustomobject]@{
        Actor = $actor.Trim(); ApprovedBy = $(if ($ap.Trim()) { $ap.Trim() } else { '' }); CorrelationId = [string](& $g 'CorrelationId')
        TargetKey = [string](& $g 'TargetKey'); Kind = [string](& $g 'Kind'); Op = [string](& $g 'Op'); Title = [string](& $g 'Title'); Via = $Via
    }
}

function Save-SIChangeAttribution {
    <# One attribution row, AT COMMIT. NEVER throws: a failure is warned and answered $false (the change itself happened). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CorrelationId, [Parameter(Mandatory)][string]$TargetKey,
          [Parameter(Mandatory)][string]$Actor, [string]$ApprovedBy, [ValidateSet('change', 'start', 'release', 'flow')][string]$Kind = 'change',
          [ValidateSet('set', 'remove', 'start', 'approve')][string]$Op = 'set', [string]$Title, [string]$Source = 'job', [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Warning $msg } }
    $cut = { param([string]$s, [int]$n) if ($null -eq $s -or $s.Length -le $n) { $s } else { $s.Substring(0, $n) } }
    try {
        $p = [ordered]@{ CorrelationId = (& $cut $CorrelationId 64); TargetKey = (& $cut $TargetKey 400); Kind = $Kind; Op = $Op; Title = (& $cut $Title 400)
                         Actor = (& $cut $Actor 256); ApprovedBy = $(if ($ApprovedBy) { & $cut $ApprovedBy 256 } else { $null }); Source = (& $cut $Source 16) }
        $r = & $Invoke (Get-SIChangeAttributionInsertSql) $p 'scalar'
        if ("$r" -eq 'Missing') { throw 'the Pro database has no cfg.ChangeAttribution yet -- apply sql\si-pro-settings.sql (it only adds)' }
        return $true
    } catch {
        & $Log 'WARN' ("who asked for '{0}' could not be recorded: {1} -- the change itself is not affected" -f $TargetKey, $_.Exception.Message)
        return $false
    }
}

function Get-SIChangeAttribution {
    <#
        The newest attribution of -CorrelationId and / or -TargetKey (optionally of one -Kind), at most -Days old -- or $null.
        NEVER throws: an unreadable store attributes nothing (the job stays the actor), warned once.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$CorrelationId, [string]$TargetKey, [string]$Kind, [int]$Days = $script:SIAttributionDays, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Warning $msg } }
    if (-not $CorrelationId -and -not $TargetKey) { return $null }
    try {
        $p = [ordered]@{ Cid = $(if ($CorrelationId) { $CorrelationId } else { $null }); Target = $(if ($TargetKey) { $TargetKey } else { $null }); Kind = $(if ($Kind) { $Kind } else { $null }); Days = $Days }
        $rows = @(& $Invoke (Get-SIChangeAttributionSelectSql) $p 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $rows.Count) { return $null }
        return (ConvertTo-SIChangeAttribution -Row $rows[0] -Via 'store')
    } catch {
        & $Log 'WARN' ("who asked for this change could not be read (the job is recorded as the actor): {0}" -f $_.Exception.Message)
        return $null
    }
}

function Get-SIJobAttribution {
    <#
        The person who started THIS job execution, when one did: the web app starts a job for a person with SI_AUDIT_CID
        (the request's correlation id, recorded in cfg.ChangeAttribution at that moment) and SI_AUDIT_STARTED_BY. The
        store's row wins; the variable is the fallback when the store cannot be read (Via 'environment'). $null = the
        job's own run (a schedule). Resolved once per process and execution.
    #>
    param([scriptblock]$Invoke, [scriptblock]$Log)
    $cid = [string]$env:SI_AUDIT_CID; $by = [string]$env:SI_AUDIT_STARTED_BY
    if (-not $cid.Trim() -and -not $by.Trim()) { return $null }
    $key = $cid + '|' + $by
    if ($script:SIJobAttribution -and $script:SIJobAttribution.Key -eq $key) { return $script:SIJobAttribution.Value }
    $v = $null
    if ($Invoke -and $cid.Trim()) { $v = Get-SIChangeAttribution -Invoke $Invoke -CorrelationId $cid.Trim() -Log $Log }
    if (-not $v -and $by.Trim()) {
        $v = [pscustomobject]@{ Actor = $by.Trim(); ApprovedBy = ''; CorrelationId = $cid.Trim(); TargetKey = ''; Kind = 'start'; Op = 'start'; Title = ''; Via = 'environment' }
    }
    $script:SIJobAttribution = @{ Key = $key; Value = $v }
    $v
}

function Get-SIAuditJobRun {
    <# The job execution this process runs in (a container's execution name), else ''. #>
    $e = [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME
    if ($e.Trim()) { return $e.Trim() }
    ''
}

function Resolve-SIAuditAttribution {
    <#
        PURE. The rule of AUDIT-1.1 for one row a job writes. With an attribution: Actor = the person who initiated it,
        After.appliedBy = the job (-JobActor), After.jobRun = -JobRun (else the caller's -CorrelationId, which was the job's
        run, else the execution), After.approvedBy when an approval applied, CorrelationId = the commit / request id (the
        caller's when the attribution has none). Without: the job stays the actor, After.initiatedBy says no person asked,
        and the run is kept. Returns @{ Actor; After; CorrelationId; Attributed }.
    #>
    param([Parameter(Mandatory)][string]$JobActor, $Attribution, [string]$JobRun, [string]$CorrelationId, $After)
    $a = [ordered]@{}
    if ($null -ne $After) {
        if ($After -is [string]) { $a['detail'] = $After }
        elseif ($After -is [System.Collections.IDictionary]) { foreach ($k in @($After.Keys)) { $a[[string]$k] = $After[$k] } }
        else { foreach ($pp in @($After.PSObject.Properties)) { $a[$pp.Name] = $pp.Value } }
    }
    $run = if ($JobRun) { $JobRun } elseif ($CorrelationId) { $CorrelationId } else { Get-SIAuditJobRun }
    if ($null -ne $Attribution -and [string]$Attribution.Actor) {
        $a['appliedBy'] = $JobActor
        if ($run) { $a['jobRun'] = $run }
        if ([string]$Attribution.ApprovedBy -and ([string]$Attribution.ApprovedBy).ToLowerInvariant() -ne ([string]$Attribution.Actor).ToLowerInvariant()) { $a['approvedBy'] = [string]$Attribution.ApprovedBy }
        $cid = if ([string]$Attribution.CorrelationId) { [string]$Attribution.CorrelationId } else { $CorrelationId }
        return [pscustomobject]@{ Actor = [string]$Attribution.Actor; After = $a; CorrelationId = $cid; Attributed = $true }
    }
    if (-not $a.Contains('initiatedBy')) { $a['initiatedBy'] = 'no person -- the job''s own run (a schedule, an expiry, a retention or its own checks)' }
    if ($run -and -not $a.Contains('jobRun')) { $a['jobRun'] = $run }
    [pscustomobject]@{ Actor = $JobActor; After = $a; CorrelationId = $CorrelationId; Attributed = $false }
}

function Get-SIChangeAttributionPendingSql {
    <#
        The committed changes (Kind 'change') of the last @Days days that THIS job has not yet recorded as put in force
        (no settings.change.apply event of the same commit, target and job) -- oldest first, at most @Max.
    #>
@'
IF OBJECT_ID(N'cfg.ChangeAttribution') IS NOT NULL AND OBJECT_ID(N'cfg.AuditEvent') IS NOT NULL
SELECT TOP (@Max) a.AttributionId, a.CorrelationId, a.TargetKey, a.Kind, a.Op, a.Title, a.Actor, a.ApprovedBy, a.Source, a.CreatedAt
FROM cfg.ChangeAttribution AS a
WHERE a.Kind = N'change' AND a.CreatedAt >= DATEADD(day, -@Days, SYSUTCDATETIME())
  AND NOT EXISTS (SELECT 1 FROM cfg.AuditEvent AS e
                  WHERE e.CorrelationId = a.CorrelationId AND e.Action = N'settings.change.apply' AND e.RecordType = N'event'
                    AND e.Target = LEFT(a.TargetKey, 400) AND e.AfterJson LIKE @JobLike ESCAPE N'\')
ORDER BY a.AttributionId;
'@
}

function Invoke-SIChangeAttributionApply {
    <#
        Run start (the settings layer of every Pro job): each change a person committed in the web app since this job last
        ran is now in force for it -- ONE event 'settings.change.apply' per change and job, Actor = the person who initiated
        it, After.appliedBy = the job, After.jobRun = the run, After.approvedBy, CorrelationId = the commit id (the same id
        as the web event and its change rows). A removal is attributed the same way (the row is keyed by its target, not
        read from the live table). NEVER throws; returns the number recorded.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Job, [string]$JobRun, [int]$Days = $script:SIAttributionDays, [int]$Max = 500, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Warning $msg } }
    $jobKey = ($Job -replace '[^A-Za-z0-9:._ -]', '').Trim()
    if (-not $jobKey) { return 0 }
    $like = '%"appliedJob":"' + ($jobKey -replace '\\', '\\' -replace '%', '\%' -replace '_', '\_' -replace '\[', '\[') + '"%'
    $rows = @()
    try { $rows = @(& $Invoke (Get-SIChangeAttributionPendingSql) ([ordered]@{ Days = $Days; Max = $Max; JobLike = $like }) 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    catch { & $Log 'WARN' ("the changes committed in the web app could not be read for the audit trail: {0}" -f $_.Exception.Message); return 0 }
    $n = 0
    $actor = Get-SIAuditActor -Job $jobKey
    foreach ($r in $rows) {
        $attr = ConvertTo-SIChangeAttribution -Row $r -Via 'store'
        if (-not $attr) { continue }
        $after = [ordered]@{ appliedJob = $jobKey; op = $attr.Op; change = $attr.Title }
        $ok = Write-SIAuditEvent -Invoke $Invoke -Action 'settings.change.apply' -Actor $actor -ActorSource 'job' -Target $attr.TargetKey `
                -OutcomeText $(if ($attr.Op -eq 'remove') { 'removed -- no longer in force from this run' } else { 'in force from this run' }) `
                -After $after -Attribution $attr -JobRun $JobRun -Log $Log
        if ($ok) { $n++ }
    }
    $n
}

function Get-SIAuditHealth {
    <# How many trail rows this process wrote, and how many it could not (with the last reason). #>
    if ($null -eq $script:SIAuditHealth) { $script:SIAuditHealth = @{ Written = 0; Failed = 0; LastError = '' } }
    [pscustomobject]@{ Written = [int]$script:SIAuditHealth.Written; Failed = [int]$script:SIAuditHealth.Failed; LastError = [string]$script:SIAuditHealth.LastError }
}

function Get-SIAuditSessionContextSql {
    <# The SESSION_CONTEXT the cfg.ChangeLog trigger reads (the web app's SessionContextSql): change rows join the event. #>
@'
EXEC sys.sp_set_session_context @key = N'si.audit.cid', @value = @AuditCid;
EXEC sys.sp_set_session_context @key = N'si.audit.source', @value = @AuditSource;
'@
}

function New-SIAuditInvoke {
    <#
        Wraps an -Invoke seam so every batch first stamps the audit context: the cfg.ChangeLog rows the step writes carry
        -CorrelationId and -ActorSource and show under the step's event on the Audit page. Pure wrapper (no I/O itself).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CorrelationId, [string]$ActorSource = 'job')
    $inner = $Invoke; $prefix = Get-SIAuditSessionContextSql; $cid = $CorrelationId; $src = $ActorSource
    {
        param([string]$sql, $p, [string]$mode)
        $q = [ordered]@{}
        if ($p) { foreach ($k in @($p.Keys)) { $q[$k] = $p[$k] } }
        $q['AuditCid'] = $cid; $q['AuditSource'] = $src
        & $inner ($prefix + $sql) $q $mode
    }.GetNewClosure()
}

function Resolve-SIAuditRetentionMonths {
    <#
        PURE. SI_Pro_AuditRetentionMonths -> @{ Months; Problem }. Not set (or empty) = $null: kept forever. A whole number
        of at least 13 (AUDIT-1.3: at least as long as Invardia's uplink rows); anything else is refused -- the trail is
        then kept, never cut shorter by a typo.
    #>
    param($Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return [pscustomobject]@{ Months = $null; Problem = '' } }
    $n = 0
    if (-not [int]::TryParse("$Value".Trim(), [ref]$n)) { return [pscustomobject]@{ Months = $null; Problem = ("SI_Pro_AuditRetentionMonths = '{0}' is not a whole number -- the audit trail is kept" -f $Value) } }
    if ($n -lt $script:SIAuditMinRetentionMonths) { return [pscustomobject]@{ Months = $null; Problem = ("SI_Pro_AuditRetentionMonths = {0} is below the minimum of {1} months -- the audit trail is kept" -f $n, $script:SIAuditMinRetentionMonths) } }
    [pscustomobject]@{ Months = $n; Problem = '' }
}

function Get-SIAuditRetentionDeleteSql {
    <#
        The ONE removal of trail rows (#289): a call of cfg.AuditRetentionApply (sql\si-pro-settings.sql). The database
        refuses UPDATE / DELETE on the trail to every identity (DENY); only that procedure removes rows, and it decides
        what may go: at least 13 months, never younger than that before the server's clock, a batch at a time, for the
        job identity only. A database without the procedure answers -1 and nothing is removed.
    #>
    "IF OBJECT_ID(N'cfg.AuditRetentionApply') IS NULL SELECT -1 AS N; ELSE EXEC cfg.AuditRetentionApply @Months = @Months, @Cutoff = @Cutoff, @Batch = @Batch;"
}

function Get-SIAuditRetentionCountSql { "IF OBJECT_ID(N'cfg.AuditEvent') IS NULL SELECT -1 AS N; ELSE SELECT COUNT_BIG(*) AS N FROM cfg.AuditEvent WHERE TsUtc < @Cutoff;" }

function Invoke-SIAuditRetention {
    <#
        The audited retention step (AUDIT-1.3), run by the data sync job: removes trail rows older than
        SI_Pro_AuditRetentionMonths, in batches, and records ONE event 'audit.retention.apply' with the cutoff and the
        count (a dry run counts only and records the plan with WhatIf = 1). Not set = nothing removed, nothing recorded.
        Returns @{ Months; Cutoff; Removed; Problem; DryRun }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke,
        $Months,
        [datetime]$Now = [datetime]::UtcNow,
        [switch]$DryRun,
        [string]$Actor,
        [int]$Batch = 5000,
        [scriptblock]$Log
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $cfg = Resolve-SIAuditRetentionMonths -Value $Months
    $res = [ordered]@{ Months = $cfg.Months; Cutoff = $null; Removed = 0; Problem = $cfg.Problem; DryRun = [bool]$DryRun }
    if ($cfg.Problem) { & $Log 'WARN' ('audit     : ' + $cfg.Problem); return [pscustomobject]$res }
    if ($null -eq $cfg.Months) { & $Log 'INFO' 'audit     : SI_Pro_AuditRetentionMonths is not set -- the audit trail is kept in full.'; return [pscustomobject]$res }
    $cutoff = $Now.ToUniversalTime().AddMonths(-[int]$cfg.Months)
    $res.Cutoff = $cutoff
    $cutText = $cutoff.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    if (-not $Actor) { $Actor = Get-SIAuditActor -Job 'data sync' }
    $n = [long](& $Invoke (Get-SIAuditRetentionCountSql) @{ Cutoff = $cutText } 'scalar')
    if ($n -lt 0) { & $Log 'INFO' 'audit     : the Pro database has no audit trail yet -- nothing to keep or remove.'; return [pscustomobject]$res }
    $after = [ordered]@{ months = [int]$cfg.Months; cutoffUtc = $cutText; rows = $n }
    if ($DryRun) {
        & $Log 'INFO' ("audit     : {0} trail row(s) older than {1} month(s) would be removed (before {2:yyyy-MM-dd}); nothing is removed." -f $n, $cfg.Months, $cutoff)
        [void](Write-SIAuditEvent -Invoke $Invoke -Action 'audit.retention.apply' -Actor $Actor -ActorSource 'job' -Target 'cfg.AuditEvent' -Reason 'SI_Pro_AuditRetentionMonths' -WhatIfRun -After $after -Log $Log)
        return [pscustomobject]$res
    }
    $removed = [long]0
    try {
        while ($true) {
            $k = [long](& $Invoke (Get-SIAuditRetentionDeleteSql) @{ Months = [int]$cfg.Months; Cutoff = $cutText; Batch = $Batch } 'scalar')
            if ($k -lt 0) {
                $res.Problem = 'the Pro database does not have the audit retention procedure yet -- apply sql\si-pro-settings.sql (it only adds); the audit trail is kept'
                & $Log 'WARN' ('audit     : ' + $res.Problem)
                return [pscustomobject]$res
            }
            $removed += $k
            if ($k -lt $Batch) { break }
        }
    } catch {
        $res.Removed = $removed
        $after.removed = $removed
        [void](Write-SIAuditEvent -Invoke $Invoke -Action 'audit.retention.apply' -Actor $Actor -ActorSource 'job' -Target 'cfg.AuditEvent' -Reason 'SI_Pro_AuditRetentionMonths' -Outcome 'error' -OutcomeText $_.Exception.Message -After $after -Log $Log)
        throw
    }
    $res.Removed = $removed
    $after.removed = $removed
    [void](Write-SIAuditEvent -Invoke $Invoke -Action 'audit.retention.apply' -Actor $Actor -ActorSource 'job' -Target 'cfg.AuditEvent' -Reason 'SI_Pro_AuditRetentionMonths' -After $after -Log $Log)
    & $Log 'OK' ("audit     : {0} month(s) -- removed {1} trail row(s) from before {2:yyyy-MM-dd} (recorded on the trail)" -f $cfg.Months, $removed, $cutoff)
    [pscustomobject]$res
}
