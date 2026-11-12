#Requires -Version 5.1
<#
    SecurityInsight -- THE HOURLY HEARTBEAT (#718; owner 2026-10-16: "it must sent outside of the pipeline" / "let si fix it").

    Until #718 SecurityInsight told Invardia it was alive only when an ENGINE RUN ENDED (Send-SITelemetryRunEnd: one heartbeat
    a day + a run report per run). A long step -- a 6-hour Detailed report, a 5-hour correlation -- meant 5-18 hours without a
    word, and the install looked dead. The heartbeat is now its OWN small job (caj-si-heartbeat, engine\heartbeat\
    Invoke-SIHeartbeat.ps1) on its own hourly timer, never a step of the pipeline: it runs whether or not a pipeline runs, and
    whether the pipeline runner is alive or not.

    EACH TICK (Send-SIHeartbeatTick) sends ONE IDENTIFIED heartbeat -- the same record the end-of-run heartbeat is
    (ConvertTo-SITelemetryWire: edition, version, ring, hosting, runtime identity, licence, the tenant counts, the guard mode,
    the release fields, the environment name, the licence id). Rules, unchanged from the end-of-run sender:
      * the telemetry switch (SI_Telemetry_Enabled) is honoured; a test session never sends without -Transport;
      * ANONYMOUS installs (Community, a Pro install without its install key) send NOTHING here -- their one heartbeat a day
        stays with their engine runs, exactly as before;
      * one attempt, the 5-second timeout, never a retry; a failure is said ONCE and swallowed -- the job always ends well;
      * one heartbeat per HALF HOUR per install (owner 2026-10-17: "not real time but like 30 min refresh"): the half hour
        (:00-:29, :30-:59 UTC) is claimed in the Pro database (cfg.InstallState 'HeartbeatJob') before sending, so a second
        execution in the same half hour (the 15-minute timer's other tick, a manual start, a late timer) sends nothing.
        The job's timer (every 15 minutes, 7,22,37,52) gives each half hour its own first tick; the update moves an
        install still on the old hourly timer to it (SI-MissingJobs.ps1, Get-SIMissingJobRetime).

    TWO NEW OPTIONAL FIELDS -- BUILT, TESTED, AND OFF BY DEFAULT. Invardia's validator REFUSES a record with a field it does not
    know (a 4xx = the heartbeat is lost), so each goes out only where its switch says so (Resolve-SIUplinkFieldSwitch):
      runProgress   what the pipeline is doing: { state: running | idle | stalled, runId, stage, step, stepSinceUtc,
                    runSinceUtc } (Get-SIHeartbeatRunProgress, from the run record cfg.FlowRun / cfg.FlowStepRun).
                    Switch: SI_Uplink_SendRunProgress (job variable SI_UPLINK_SENDRUNPROGRESS).
      Collections   one entry per collection kind -- the schema agreed with Invardia 2026-10-16 (Test-SIHeartbeatCollection):
                    { kind, state, lastCompleteUtc, lastAttemptUtc, expected, collected, note } (ConvertTo-SIHeartbeatCollections).
                    Switch: SI_Uplink_SendCollections (job variable SI_UPLINK_SENDCOLLECTIONS).
    Each switch: on / off / a ring list ("0" or "0,1": on for those rings) / auto (the default: on only for the rings in the
    field's ConfirmedRings below). Collections: ring 0 CONFIRMED 2026-10-16 (Invardia 1.0.498, its validator takes the
    field; owner: "collection state must be enabled when ready"). runProgress: none yet (Invardia does not take it).
    REMOVE-ME (#718): rings 1 and 2 follow for Collections as the release moves through the rings (one edit per ring); put
    runProgress's rings in once Invardia confirms it; finally drop the switches.
    #719 adds EIGHT more optional fields -- Pipeline, Jobs, Sources, Database, Update, Mail, Warnings, Security -- built in
    SI-HeartbeatFields.ps1 (New-SIHeartbeatFields), each behind its own switch SI_Uplink_Send<Field> (ring 0 confirmed:
    Invardia 1.0.500 validates the final schema); the record is kept under 48 KB (Limit-SIHeartbeatRecordSize).
    And even when on: a heartbeat Invardia does not take WITH them is sent again ONCE without them
    (Send-SITelemetryRecordWithFallback -- 'Collections' and 'runProgress' are in Get-SITelemetryOptionalFields), said once,
    so a heartbeat is never lost to a new field.

    CHEAP BY DESIGN: the collection state is ONE batch of small reads -- sidata.SourceState (a row per source),
    sidata.RecordCollection (by its Engine index), sidata.Collection (by its Kind index), sidata.CollectionPartial and
    sidata.RaReportStatus (by primary key, the newest collection time only), sidata.CiBuildState (a few rows). Never
    sidata.Finding. The expected user count is ONE Graph $count call.

    NEVER THROWS where the job calls it. PowerShell 5.1 and 7. No PowerShell modules.
#>

if (-not (Get-Command -Name ConvertTo-SITelemetryWire -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-TelemetrySend.ps1')) }
# #719: the eight further fields (Pipeline, Jobs, Sources, Database, Update, Mail, Warnings, Security) -- each behind its own switch
if (-not (Get-Command -Name New-SIHeartbeatFields -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-HeartbeatFields.ps1')) }
# #723: the "update now" signal -- asked on every tick (every 15 minutes), the full heartbeat stays once per hour
if (-not (Get-Command -Name Invoke-SIUpdateNowCheck -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-UpdateNowSignal.ps1')) }
# #1151 (5) NAM-02: Invardia's name for this environment -- read on every full heartbeat, the last good value kept
if (-not (Get-Command -Name Invoke-SIInvardiaEnvironmentRead -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaEnvironment.ps1')) }
# framework 4.1b: the Invardia Support app's database access, read only -- supportSqlAccess on the identified heartbeat
if (-not (Get-Command -Name Get-SISupportSqlAccess -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-SupportSqlAccess.ps1')) }
# #1021: the support grant (just in time) -- its state read on every heartbeat, its sweep on every tick (engine\heartbeat)
$siSgLib = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'support-grant', 'SI-SupportGrant.ps1')
if (-not (Get-Command -Name Get-SISupportGrantStatus -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $siSgLib)) { . $siSgLib }
# #1065 (3.0.30): the install's one-time steps with their state (setupSteps), each from a check that ran here
if (-not (Get-Command -Name Get-SISetupSteps -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-SetupSteps.ps1')) }

$script:SIHeartbeatJob = @{
    # the closed lists and caps agreed with Invardia (2026-10-16) -- Invardia's validator is built to EXACTLY these
    Kinds          = @('identity', 'endpoint', 'azure', 'publicip', 'riskAnalysisSummary', 'riskAnalysisDetailed', 'correlation', 'ciBuild')
    States         = @('complete', 'partial', 'running', 'failed', 'never')
    EntryFields    = @('kind', 'state', 'lastCompleteUtc', 'lastAttemptUtc', 'expected', 'collected', 'note')
    MaxEntries     = 12
    NoteMax        = 300
    RunStates      = @('running', 'idle', 'stalled')
    # REMOVE-ME (#718): the rings whose heartbeat carries the field while its switch is 'auto'. Collections: EVERY ring since
    # 2026-10-17 (Invardia 1.0.498 validates it; owner: "i want data"); SI_Uplink_SendCollections 'off' still turns it off.
    # runProgress: OFF -- Invardia does not take it yet.
    CollectionsConfirmedRings = @(0, 1, 2, 3)
    RunProgressConfirmedRings = @()
    # supportSqlAccess readOnly / jitOpen / jitUntil: EVERY ring since 2026-11-08 (Invardia: its closed heartbeat contract takes
    # them since 2026-11-01 and its support-SQL check expects no standing admin where readOnly is true);
    # SI_Uplink_SendSupportSqlAccessJit 'off' still turns them off.
    SupportSqlAccessJitConfirmedRings = @(0, 1, 2, 3)
    # a run record whose runner has not beaten for this long is not "running" -- its runner stopped (the next wake-up resumes it)
    StaleRunMinutes = 30
    ClaimRow       = 'HeartbeatJob'
}

# =====================================================================================================================
#  The switches -- PURE
# =====================================================================================================================
function Resolve-SIUplinkFieldSwitch {
    <#
        PURE. Does a new optional uplink field go out from this install? -Value (the setting) wins when set, then -EnvValue
        (the job variable), else 'auto'. on / true / 1 / yes = on; off / false / no = off; a ring list ("0", "0,1", "ring 1")
        = on for those rings only; anything else = auto (on for a ring in -ConfirmedRings). -Ring not known = off unless 'on'.
        Returns @{ On; Setting; Reason }.
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()]$Value, [AllowNull()][AllowEmptyString()][string]$EnvValue, [AllowNull()]$Ring, [int[]]$ConfirmedRings = @())
    $rn = -1
    if ($null -ne $Ring -and "$Ring".Trim() -ne '') { if (-not [int]::TryParse("$Ring", [ref]$rn)) { $rn = -1 } }
    $set = ''
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { $set = $(if ($v) { 'on' } else { 'off' }); break }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        $set = $s; break
    }
    if ($set -in @('on', 'true', 'yes', 'enabled')) { return [pscustomobject]@{ On = $true; Setting = 'on'; Reason = "$Name is on" } }
    if ($set -in @('off', 'false', 'no', 'disabled')) { return [pscustomobject]@{ On = $false; Setting = 'off'; Reason = "$Name is off" } }
    if ($set -match '^(ring\s*)?[0-3](\s*[,;]\s*(ring\s*)?[0-3])*$') {
        $rings = @([regex]::Matches($set, '[0-3]') | ForEach-Object { [int]$_.Value })
        $on = ($rn -ge 0 -and $rings -contains $rn)
        return [pscustomobject]@{ On = $on; Setting = 'rings'; Reason = $(if ($on) { "$Name is on for ring $rn" } else { "$Name is on for ring(s) $($rings -join ', ') only" }) }
    }
    $on = ($rn -ge 0 -and @($ConfirmedRings) -contains $rn)
    [pscustomobject]@{ On = $on; Setting = 'auto'
        Reason = $(if ($on) { "ring $rn takes $Name" } else { "$Name waits until Invardia has confirmed the field" }) }
}

function Resolve-SIUplinkCollectionsSwitch {
    param([AllowNull()]$Value = $global:SI_Uplink_SendCollections, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_UPLINK_SENDCOLLECTIONS, [AllowNull()]$Ring,
          [int[]]$ConfirmedRings = @($script:SIHeartbeatJob.CollectionsConfirmedRings))
    Resolve-SIUplinkFieldSwitch -Name 'SI_Uplink_SendCollections' -Value $Value -EnvValue $EnvValue -Ring $Ring -ConfirmedRings $ConfirmedRings
}

function Resolve-SIUplinkSupportSqlAccessJitSwitch {
    <# #1021: does supportSqlAccess carry the support grant's keys readOnly / jitOpen / jitUntil (beside its own group, dbUser,
       checkedUtc, healedUtc, which it always keeps -- agreed with Invardia 2026-11-01)? SI_Uplink_SendSupportSqlAccessJit /
       SI_UPLINK_SENDSUPPORTSQLACCESSJIT; 'auto' = the confirmed rings (every ring since 2026-11-08: Invardia's side is live). #>
    param([AllowNull()]$Value = $global:SI_Uplink_SendSupportSqlAccessJit, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_UPLINK_SENDSUPPORTSQLACCESSJIT, [AllowNull()]$Ring,
          [int[]]$ConfirmedRings = @($script:SIHeartbeatJob.SupportSqlAccessJitConfirmedRings))
    Resolve-SIUplinkFieldSwitch -Name 'SI_Uplink_SendSupportSqlAccessJit' -Value $Value -EnvValue $EnvValue -Ring $Ring -ConfirmedRings $ConfirmedRings
}

function Resolve-SIUplinkRunProgressSwitch {
    param([AllowNull()]$Value = $global:SI_Uplink_SendRunProgress, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_UPLINK_SENDRUNPROGRESS, [AllowNull()]$Ring,
          [int[]]$ConfirmedRings = @($script:SIHeartbeatJob.RunProgressConfirmedRings))
    Resolve-SIUplinkFieldSwitch -Name 'SI_Uplink_SendRunProgress' -Value $Value -EnvValue $EnvValue -Ring $Ring -ConfirmedRings $ConfirmedRings
}

# =====================================================================================================================
#  Small helpers -- PURE
# =====================================================================================================================
function ConvertTo-SIHeartbeatUtc {
    <# PURE. A time as ISO-8601 UTC text (yyyy-MM-ddTHH:mm:ssZ), or $null (nothing, DBNull, not a time). #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    $d = $null
    if ($Value -is [datetime]) { $d = $(if ($Value.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($Value, 'Utc') } else { $Value.ToUniversalTime() }) }
    else {
        try { $d = [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { return $null }
    }
    $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-SIHeartbeatCount {
    <# PURE. A count as [long] >= 0, or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    $n = 0L
    if (-not [long]::TryParse("$Value".Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n) -or $n -lt 0) { return $null }
    $n
}

function ConvertTo-SIHeartbeatNote {
    <# PURE. One plain line of at most 300 characters, or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = ("$Text" -replace '[\r\n\t]+', ' ' -replace '\s{2,}', ' ').Trim()
    if (-not $t) { return $null }
    $max = [int]$script:SIHeartbeatJob.NoteMax
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3).TrimEnd() + '...' }
    $t
}

function Get-SIHeartbeatRowValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } else { return $null } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name } else { return $null }
    if ($v -is [DBNull]) { return $null }
    $v
}

function New-SIHeartbeatCollectionEntry {
    <# PURE. One entry in the agreed shape: every field present, null rather than absent, in the agreed order. #>
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$State, $LastCompleteUtc, $LastAttemptUtc, $Expected, $Collected, [AllowNull()][AllowEmptyString()][string]$Note)
    [pscustomobject][ordered]@{
        kind = $Kind; state = $State
        lastCompleteUtc = (ConvertTo-SIHeartbeatUtc $LastCompleteUtc); lastAttemptUtc = (ConvertTo-SIHeartbeatUtc $LastAttemptUtc)
        expected = (ConvertTo-SIHeartbeatCount $Expected); collected = (ConvertTo-SIHeartbeatCount $Collected)
        note = (ConvertTo-SIHeartbeatNote $Note)
    }
}

function Test-SIHeartbeatCollection {
    <#
        PURE. Is -Entry EXACTLY the agreed shape? Exactly the seven names (no more, none missing), kind and state from the
        closed lists, the times ISO-8601 UTC text or null, the counts whole numbers >= 0 or null, the note text of at most 300
        characters or null. Returns '' (good) or what is wrong. -Array: the whole Collections value (an array, at most 12).
    #>
    param($Entry, [object[]]$Array, [switch]$IsArray)
    $c = $script:SIHeartbeatJob
    if ($IsArray) {
        if ($null -eq $Array) { return 'Collections is not an array' }
        if (@($Array).Count -gt $c.MaxEntries) { return ('Collections has {0} entries (at most {1})' -f @($Array).Count, $c.MaxEntries) }
        foreach ($e in @($Array)) { $w = Test-SIHeartbeatCollection -Entry $e; if ($w) { return $w } }
        $dup = @(@($Array) | Group-Object -Property kind | Where-Object { $_.Count -gt 1 })
        if ($dup.Count) { return ('kind {0} appears more than once' -f $dup[0].Name) }
        return ''
    }
    if ($null -eq $Entry) { return 'an entry is null' }
    $names = @($Entry.PSObject.Properties | ForEach-Object { $_.Name })
    $extra = @($names | Where-Object { $c.EntryFields -cnotcontains $_ })
    if ($extra.Count) { return ('an entry has a field that is not agreed: {0}' -f ($extra -join ', ')) }
    $missing = @($c.EntryFields | Where-Object { $names -cnotcontains $_ })
    if ($missing.Count) { return ('an entry lacks {0}' -f ($missing -join ', ')) }
    if (-not ($Entry.kind -is [string]) -or $c.Kinds -cnotcontains $Entry.kind) { return ("kind '{0}' is not in the list" -f $Entry.kind) }
    if (-not ($Entry.state -is [string]) -or $c.States -cnotcontains $Entry.state) { return ("state '{0}' is not in the list" -f $Entry.state) }
    foreach ($t in 'lastCompleteUtc', 'lastAttemptUtc') {
        $v = $Entry.$t
        if ($null -ne $v -and (-not ($v -is [string]) -or $v -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$')) { return ("{0} '{1}' is not ISO-8601 UTC" -f $t, $v) }
    }
    foreach ($n in 'expected', 'collected') {
        $v = $Entry.$n
        if ($null -ne $v -and (-not ($v -is [int] -or $v -is [long]) -or $v -lt 0)) { return ("{0} '{1}' is not a whole number >= 0" -f $n, $v) }
    }
    if ($null -ne $Entry.note -and (-not ($Entry.note -is [string]) -or $Entry.note.Length -gt $c.NoteMax -or -not $Entry.note.Trim())) { return 'note is not text of 1 to 300 characters' }
    ''
}

# =====================================================================================================================
#  What the pipeline is doing -- PURE over the run record (Load() of the run store: cfg.FlowRun + cfg.FlowStepRun)
# =====================================================================================================================
function Get-SIHeartbeatRunProgress {
    <#
        PURE. -State: the newest run record (or $null). running = the run is Running and its runner beat within
        StaleRunMinutes; stalled = Running but its runner went quiet (the next wake-up of the pipeline resumes it); idle =
        no run in progress. The step running: the first step (by order) that is Running or Starting.
        Returns the wire shape { state; runId; stage; step; stepSinceUtc; runSinceUtc } -- null rather than absent.
    #>
    param($State, [Parameter(Mandatory)][datetime]$NowUtc, [int]$StaleMinutes = $script:SIHeartbeatJob.StaleRunMinutes)
    $idle = [pscustomobject][ordered]@{ state = 'idle'; runId = $null; stage = $null; step = $null; stepSinceUtc = $null; runSinceUtc = $null }
    if ($null -eq $State -or [string](Get-SIHeartbeatRowValue $State 'State') -ne 'Running') { return $idle }
    $hb = Get-SIHeartbeatRowValue $State 'HeartbeatUtc'
    $stale = $true
    if ($null -ne $hb) { try { $stale = (($NowUtc.ToUniversalTime() - ([datetime]$hb).ToUniversalTime()).TotalMinutes -gt $StaleMinutes) } catch { $stale = $true } }
    $step = @(@(Get-SIHeartbeatRowValue $State 'Steps') | Where-Object { $_ -and [string](Get-SIHeartbeatRowValue $_ 'State') -in @('Running', 'Starting') } |
              Sort-Object { [int](Get-SIHeartbeatRowValue $_ 'Order') }) | Select-Object -First 1
    $txt = { param($v, $max) $s = ("$v" -replace '[\r\n\t]+', ' ').Trim(); if (-not $s) { $null } elseif ($s.Length -gt $max) { $s.Substring(0, $max) } else { $s } }
    [pscustomobject][ordered]@{
        state        = $(if ($stale) { 'stalled' } else { 'running' })
        runId        = (& $txt (Get-SIHeartbeatRowValue $State 'FlowRunId') 64)
        stage        = $(if ($step) { & $txt (Get-SIHeartbeatRowValue $step 'Stage') 32 } else { $null })
        step         = $(if ($step) { & $txt (Get-SIJobFlowStepId (Get-SIHeartbeatRowValue $step 'Job')) 60 } else { $null })
        stepSinceUtc = $(if ($step) { ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $step 'StartedUtc') } else { $null })
        runSinceUtc  = (ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $State 'StartedUtc'))
    }
}

function Get-SIJobFlowStepId {
    <# PURE. A step's job as the short key (caj-si-identity -> identity). #>
    param($Job)
    ((("$Job").Trim().ToLowerInvariant()) -replace '^caj-si-', '')
}

# =====================================================================================================================
#  The collection state -- ONE batch of small reads, then PURE
# =====================================================================================================================
function Get-SIHeartbeatCollectionsSql {
    <#
        The read behind Collections (the data database; every table may be missing on an older schema -- then no rows).
        Rows: K (source | records | ra | ci), Name, T1, T2, F1, F2, N1, N2, N3, Txt. Index reads only, never sidata.Finding.
    #>
    @'
SET NOCOUNT ON;
DECLARE @r TABLE (K NVARCHAR(16) NOT NULL, Name NVARCHAR(64) NULL, T1 DATETIME2(3) NULL, T2 DATETIME2(3) NULL, F1 INT NULL, F2 INT NULL, N1 BIGINT NULL, N2 BIGINT NULL, N3 BIGINT NULL, Txt NVARCHAR(400) NULL, N4 BIGINT NULL);
IF OBJECT_ID('sidata.SourceState') IS NOT NULL
    INSERT @r (K, Name, T1, T2, F1) SELECT N'source', Source, LastGoodAt, LastAttemptAt, CAST(LastAttemptOk AS INT) FROM sidata.SourceState;
IF OBJECT_ID('sidata.RecordCollection') IS NOT NULL
    INSERT @r (K, Name, T1, F1, N1, N2)
    SELECT N'records', e.Engine, e.T, h.Held, h.Recs, h.Users
    FROM (SELECT Engine, MAX(CollectionTime) AS T FROM sidata.RecordCollection WHERE Engine <> N'' GROUP BY Engine) e
    CROSS APPLY (SELECT SUM(CAST(c.Records AS BIGINT)) AS Recs, MAX(CASE WHEN c.State <> N'good' THEN 1 ELSE 0 END) AS Held,
                        SUM(CASE WHEN c.RecordType = N'user' THEN CAST(c.Records AS BIGINT) END) AS Users
                 FROM sidata.RecordCollection c WHERE c.Engine = e.Engine AND c.CollectionTime = e.T) h;
IF OBJECT_ID('sidata.Collection') IS NOT NULL
BEGIN
    DECLARE @k NVARCHAR(16), @i INT = 0;
    WHILE @i < 2
    BEGIN
        SET @k = CASE WHEN @i = 0 THEN N'Detailed' ELSE N'Summary' END; SET @i += 1;
        DECLARE @cid INT = NULL, @ct DATETIME2(3) = NULL, @cl DATETIME2(3) = NULL, @lt DATETIME2(3) = NULL, @ls NVARCHAR(16) = NULL;
        SELECT TOP (1) @cid = CollectionId, @ct = CollectionTime, @cl = LoadedAt FROM sidata.Collection WHERE Kind = @k AND Status = N'Complete' ORDER BY CollectionTime DESC;
        SELECT TOP (1) @lt = CollectionTime, @ls = Status FROM sidata.Collection WHERE Kind = @k ORDER BY CollectionTime DESC;
        IF @lt IS NULL CONTINUE;
        DECLARE @part INT = 0, @why NVARCHAR(400) = NULL, @exp BIGINT = NULL, @sto BIGINT = NULL, @unk BIGINT = NULL, @nc BIGINT = NULL, @nh BIGINT = NULL;
        IF @cid IS NOT NULL AND OBJECT_ID('sidata.CollectionPartial') IS NOT NULL
            SELECT @part = 1, @why = LEFT(Reason, 400) FROM sidata.CollectionPartial WHERE CollectionId = @cid;
        IF OBJECT_ID('sidata.RaReportStatus') IS NOT NULL
            SELECT @exp = SUM(ExpectedRows), @sto = SUM(StoredRows), @unk = SUM(CASE WHEN ExpectedRows IS NULL THEN 1 ELSE 0 END),
                   @nc = SUM(CASE WHEN State = N'NotComplete' THEN 1 ELSE 0 END)
            FROM sidata.RaReportStatus WHERE CollectionTime = @lt AND Grain = @k;
        -- #902: of them, the reports held ON PURPOSE at their last complete result (a HoldKind, no hold-back)
        IF @nc > 0 AND COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'HeldRaReport') IS NOT NULL
            EXEC sp_executesql N'SELECT @h = COUNT_BIG(*) FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = @g AND State = N''NotComplete'' AND NULLIF(HoldKind, N'''') IS NOT NULL AND HeldRaReport IS NULL',
                 N'@t datetime2(3), @g nvarchar(16), @h bigint OUTPUT', @t = @lt, @g = @k, @h = @nh OUTPUT;
        INSERT @r (K, Name, T1, T2, F1, F2, N1, N2, N3, Txt, N4)
        VALUES (N'ra', @k, ISNULL(@cl, @ct), @lt, CASE WHEN @ls = N'Complete' THEN 1 ELSE 0 END, @part,
                CASE WHEN @unk = 0 THEN @exp END, @sto, @nc, @why, @nh);
    END
END
IF OBJECT_ID('sidata.CiBuildState') IS NOT NULL
    INSERT @r (K, Name, T1, Txt) SELECT N'ci', Name, UpdatedAt, LEFT(Value, 400) FROM sidata.CiBuildState WHERE Name IN (N'LastBuildStatus', N'LastBuildStart');
SELECT K, Name, T1, T2, F1, F2, N1, N2, N3, Txt, N4 FROM @r;
'@
}

function ConvertTo-SIHeartbeatCollections {
    <#
        PURE. The Collections entries from the rows of Get-SIHeartbeatCollectionsSql, the run record (-RunProgress, the result
        of Get-SIHeartbeatRunProgress: a step of a kind that is running now makes that kind 'running') and the counts SI knows
        from outside its own collection (-Expected @{ identity = <the tenant's users, Graph $count> }).
        State rules:
          identity / endpoint / azure / publicip (sidata.SourceState + sidata.RecordCollection):
            running   its step runs now
            failed    its newest attempt did not end well (the run went on with its last good collection)
            partial   its newest collection ended, but a feed of it is held (it did not reach every record)
            never     no complete collection is recorded (and it does not run now)
            complete  otherwise
            collected = the records of its newest collection (identity: its users); expected = identity: the tenant's users
          riskAnalysisSummary / riskAnalysisDetailed (sidata.Collection + CollectionPartial + RaReportStatus):
            running   its step runs now, or the newest collection is not complete yet while a pipeline run still goes (it is
                      marked complete when that run publishes -- never 'failed' before the run has ended);
            never  no complete collection;  failed  the newest collection never completed (and no pipeline run goes);
            partial   the newest is complete but loaded as partial, or a report of it is not complete;  complete  otherwise
            expected / collected = the rows the source said its reports hold / the rows stored (expected null when a report
            could not say)
          ciBuild (sidata.CiBuildState): running | complete (ok) | partial | failed; a build recorded as running while the CI
            build step does not run = failed (it was stopped)
        Kinds SI has no record of at all are left out. At most 12 entries, unrolled (wrap the call in @( )).
    #>
    param([object[]]$Rows = @(), $RunProgress, [hashtable]$Expected = @{},
          # #636: 'off' = the Risk Analysis Summary step is off -- its entry is left out (unless its step runs now)
          [string]$SummaryStep = 'unknown',
          # #1105 (Invardia 2026-11-04): the state of the newest pipeline run (cfg.FlowRun State). A newest collection that did
          # not complete because its run was STOPPED (an update, support or a person -- Cancelled / Stopped) is 'partial' with a
          # note, never 'failed' (Invardia tickets 'failed'); 'failed' only when the run itself failed. lastCompleteUtc stays
          # the last collection the customer can see.
          [string]$LastRunState = '')
    $stoppedRun = ("$LastRunState".Trim() -in @('Cancelled', 'Stopped'))
    $rows = @(@($Rows) | Where-Object { $_ })
    $runningSteps = @()
    if ($RunProgress -and [string]$RunProgress.state -eq 'running' -and $RunProgress.step) { $runningSteps = @([string]$RunProgress.step) }
    $since = if ($RunProgress -and [string]$RunProgress.state -eq 'running') { $RunProgress.stepSinceUtc } else { $null }
    $get = { param($k, $n) @($rows | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'K') -eq $k -and ([string](Get-SIHeartbeatRowValue $_ 'Name')).ToLowerInvariant() -eq $n.ToLowerInvariant() })[0] }
    $out = New-Object System.Collections.Generic.List[object]

    foreach ($kind in 'identity', 'endpoint', 'azure', 'publicip') {
        $src = & $get 'source' $kind; $rec = & $get 'records' $kind
        $run = $runningSteps -contains $kind
        if (-not $src -and -not $rec -and -not $run) { continue }
        $good = Get-SIHeartbeatRowValue $src 'T1'; $att = Get-SIHeartbeatRowValue $src 'T2'
        $okv = Get-SIHeartbeatRowValue $src 'F1'; $ok = ($null -eq $okv -or "$okv" -in @('1', 'True'))
        $held = "$(Get-SIHeartbeatRowValue $rec 'F1')" -in @('1', 'True')
        if ($null -eq $att) { $att = Get-SIHeartbeatRowValue $rec 'T1' }
        if ($null -eq $good -and $rec -and -not $held) { $good = Get-SIHeartbeatRowValue $rec 'T1' }
        $collected = if ($kind -eq 'identity') { Get-SIHeartbeatRowValue $rec 'N2' } else { Get-SIHeartbeatRowValue $rec 'N1' }
        $exp = if ($Expected -and $Expected.ContainsKey($kind)) { $Expected[$kind] } else { $null }
        if ($run) { $state = 'running'; $note = 'collecting now'; if ($since) { $att = $since } }
        elseif ($src -and -not $ok) { $state = 'failed'; $note = $(if ($good) { 'the newest collection did not end well; the data is from the last complete collection' } else { 'the newest collection did not end well and no complete collection is recorded' }) }
        elseif ($held) { $state = 'partial'; $note = 'the newest collection did not reach every record; what it did not reach keeps its last known state' }
        elseif ($null -eq $good) { $state = 'never'; $note = 'no complete collection is recorded yet' }
        else { $state = 'complete'; $note = $null }
        if ($state -eq 'complete' -and $null -ne (ConvertTo-SIHeartbeatCount $exp) -and $null -ne (ConvertTo-SIHeartbeatCount $collected) -and [long]$collected -lt [long]$exp) {
            $note = 'fewer stored than the source holds (the difference may be objects SecurityInsight leaves out by design)'
        }
        $out.Add((New-SIHeartbeatCollectionEntry -Kind $kind -State $state -LastCompleteUtc $good -LastAttemptUtc $att -Expected $exp -Collected $collected -Note $note))
    }

    foreach ($p in @(@{ Kind = 'riskAnalysisSummary'; Grain = 'Summary'; Step = 'risk-analysis' }, @{ Kind = 'riskAnalysisDetailed'; Grain = 'Detailed'; Step = 'risk-analysis-detailed' })) {
        $ra = & $get 'ra' $p.Grain
        $run = $runningSteps -contains $p.Step
        if (-not $ra -and -not $run) { continue }
        if ($p.Grain -eq 'Summary' -and $SummaryStep -eq 'off' -and -not $run) { continue }
        $complete = Get-SIHeartbeatRowValue $ra 'T1'; $att = Get-SIHeartbeatRowValue $ra 'T2'
        $newestDone = "$(Get-SIHeartbeatRowValue $ra 'F1')" -in @('1', 'True')
        $partial = "$(Get-SIHeartbeatRowValue $ra 'F2')" -in @('1', 'True')
        $nc = ConvertTo-SIHeartbeatCount (Get-SIHeartbeatRowValue $ra 'N3')
        if ($run) { $state = 'running'; $note = 'Risk Analysis runs now'; if ($since) { $att = $since } }
        elseif ($null -eq $complete) { $state = 'never'; $note = 'no complete Risk Analysis collection yet' }
        elseif (-not $newestDone -and $since) { $state = 'running'; $note = 'the newest Risk Analysis collection completes when the running pipeline run ends; the last complete collection is shown until then' }
        elseif (-not $newestDone -and $stoppedRun) { $state = 'partial'; $note = 'the newest run was stopped before it published (an update, support or a person stopped it); the last complete collection is shown' }
        elseif (-not $newestDone) { $state = 'failed'; $note = 'the newest Risk Analysis run did not complete; the last complete collection is shown' }
        elseif ($partial -or ($null -ne $nc -and $nc -gt 0)) {
            $state = 'partial'
            $note = $(if ($null -ne $nc -and $nc -gt 0) { '{0} report(s) of the newest collection are not complete' -f $nc } else { 'the newest collection was loaded although part of its run was not complete' })
            # #902: the reports SI held ON PURPOSE (they keep their last complete result) are said as such -- the state stays partial
            $nh = ConvertTo-SIHeartbeatCount (Get-SIHeartbeatRowValue $ra 'N4')
            if ($null -ne $nc -and $nc -gt 0 -and $null -ne $nh -and $nh -gt 0) {
                $note = $(if ($nh -ge $nc) { '{0} report(s) of the newest collection held on purpose at their last complete result' -f $nh } else { '{0} report(s) of the newest collection are not complete, {1} of them held on purpose at their last complete result' -f $nc, $nh })
            }
        }
        else { $state = 'complete'; $note = $null }
        $out.Add((New-SIHeartbeatCollectionEntry -Kind $p.Kind -State $state -LastCompleteUtc $complete -LastAttemptUtc $att -Expected (Get-SIHeartbeatRowValue $ra 'N1') -Collected (Get-SIHeartbeatRowValue $ra 'N2') -Note $note))
    }

    $st = & $get 'ci' 'LastBuildStatus'; $start = & $get 'ci' 'LastBuildStart'
    $ciRun = $runningSteps -contains 'asset-correlation'
    if ($st -or $ciRun) {
        $v = ([string](Get-SIHeartbeatRowValue $st 'Txt')).Trim().ToLowerInvariant()
        $att = Get-SIHeartbeatRowValue $start 'Txt'
        $done = $null
        if ($ciRun -or $v -eq 'running') {
            if ($ciRun) { $state = 'running'; $note = 'the CI build runs now'; if ($since) { $att = $since } } elseif ($stoppedRun) { $state = 'partial'; $note = 'the last CI build was stopped before it finished (its run was stopped by an update, support or a person); the CIs of the build before are shown' } else { $state = 'failed'; $note = 'the last CI build was stopped before it finished' }
        }
        elseif ($v -eq 'ok') { $state = 'complete'; $note = $null; $done = Get-SIHeartbeatRowValue $st 'T1' }
        elseif ($v -eq 'partial') { $state = 'partial'; $note = 'the last CI build finished, but not every CI reached Log Analytics' }
        elseif ($v -eq 'failed') { $state = 'failed'; $note = 'the last CI build failed' }
        else { $state = 'never'; $note = 'no CI build is recorded yet' }
        $out.Add((New-SIHeartbeatCollectionEntry -Kind 'ciBuild' -State $state -LastCompleteUtc $done -LastAttemptUtc $att -Expected $null -Collected $null -Note $note))
    }
    # unrolled: callers take @( ... ) (a leading comma would hand them ONE nested array)
    $out.ToArray() | Select-Object -First ([int]$script:SIHeartbeatJob.MaxEntries)
}

function Get-SIHeartbeatExpectedUsers {
    <# The tenant's users (Microsoft Graph $count) -- one call; $null when it cannot be read. -Invoke: the test seam. #>
    param([scriptblock]$Invoke)
    try {
        if (-not $Invoke) {
            if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue)) { return $null }
            $Invoke = { param($Uri) (Invoke-SIAzRestRequest -Method GET -Uri $Uri -Audience Graph -Headers @{ ConsistencyLevel = 'eventual' } -What 'Microsoft Graph count').Content }
        }
        $t = ([string](& $Invoke 'https://graph.microsoft.com/v1.0/users/$count')).Trim().TrimStart([char]0xFEFF)
        ConvertTo-SIHeartbeatCount $t
    } catch { $null }
}

# =====================================================================================================================
#  One heartbeat per clock hour per install -- the hour is claimed in the Pro database
# =====================================================================================================================
#  LIVE 2026-10-16 (ring 0): the claim was WRITTEN but read back as "not claimed" -- the real Pro store's
#  'reader' answers ONE array of hashtables (New-SIProSettingsStore: , $out.ToArray()), the test fake answered a single row,
#  and @(... | Where-Object) kept the array as ONE element, so 'Claimed' read as $null. The tick said "not-due" and sent
#  nothing, every hour. Now: every answer is flattened (ConvertTo-SIHeartbeatSqlRows), and the hour is recorded as SENT only
#  after Invardia answered 2xx -- the claim says {hour, claimedUtc, sentUtc, status, reason}; a FAILED claim (status failed)
#  or a claim left 'claimed' for more than ClaimStaleMinutes (the job died) is taken again by the next execution.
$script:SIHeartbeatJob['ClaimStaleMinutes'] = 10
$script:SIHeartbeatJob['ClaimStates'] = @('claimed', 'sent', 'failed')
# owner 2026-10-17 ("not real time but like 30 min refresh"): ONE identified heartbeat per HALF hour. The claim names its
# slot ('yyyy-MM-ddTHH:00' / 'yyyy-MM-ddTHH:30', UTC) in 'slot'; a row written by the hourly code names its hour in 'hour'
# ('yyyy-MM-ddTHH') and counts as that hour's :00 slot -- so the update itself never sends a half hour twice.
$script:SIHeartbeatJob['SlotMinutes'] = 30

function Get-SIHeartbeatSlot {
    <# PURE. The half hour -NowUtc is in: @{ Slot = 'yyyy-MM-ddTHH:00' | 'yyyy-MM-ddTHH:30'; LegacyHour = 'yyyy-MM-ddTHH' for the
       :00 slot (the hourly code's claim of this hour), '' for the :30 slot }. #>
    param([Parameter(Mandatory)][datetime]$NowUtc)
    $u = $NowUtc.ToUniversalTime()
    $mm = if ($u.Minute -ge 30) { 30 } else { 0 }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    [pscustomobject]@{ Slot = ('{0}:{1:00}' -f $u.ToString('yyyy-MM-ddTHH', $inv), $mm); LegacyHour = $(if ($mm -eq 0) { $u.ToString('yyyy-MM-ddTHH', $inv) } else { '' }) }
}

function ConvertTo-SIHeartbeatSqlRows {
    <# PURE. Whatever a database seam answers -- ONE array of rows (the Pro store's reader), rows one by one, a single row, a
       scalar -- as rows, one per element ($null / DBNull dropped). Use @(ConvertTo-SIHeartbeatSqlRows $answer). #>
    param($Answer)
    foreach ($x in @($Answer)) {
        if ($null -eq $x -or $x -is [DBNull]) { continue }
        if ($x -is [array]) { foreach ($y in $x) { if ($null -ne $y -and -not ($y -is [DBNull])) { $y } } } else { $x }
    }
}

function Get-SIHeartbeatClaimSql {
    <# Claim this half hour (@Slot): no row / another slot / a FAILED claim of this slot / a claim of this slot left
       'claimed' for more than @StaleMinutes (by @NowUtc) = taken. A SENT slot (status sent, or an older row without a
       status) is never taken again. A row of the hourly code ('hour' = @LegacyHour) is this hour's :00 slot. Answers ONE
       row: Claimed (1 / 0). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL
    SELECT CAST(1 AS int) AS Claimed;
ELSE
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @cur NVARCHAR(400) = NULL, @has int = 0, @ok int = 0;
    SELECT @cur = Value, @has = 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'HeartbeatJob';
    DECLARE @h NVARCHAR(32) = CASE WHEN ISJSON(@cur) = 1 THEN COALESCE(JSON_VALUE(@cur, '$.slot'), JSON_VALUE(@cur, '$.hour')) END;
    DECLARE @st NVARCHAR(32) = CASE WHEN ISJSON(@cur) = 1 THEN JSON_VALUE(@cur, '$.status') END;
    DECLARE @cl DATETIME2(0) = CASE WHEN ISJSON(@cur) = 1 THEN TRY_CONVERT(DATETIME2(0), JSON_VALUE(@cur, '$.claimedUtc'), 127) END;
    DECLARE @same int = CASE WHEN ISNULL(@h, N'') = @Slot OR (ISNULL(@LegacyHour, N'') <> N'' AND ISNULL(@h, N'') = @LegacyHour) THEN 1 ELSE 0 END;
    IF @has = 0
    BEGIN
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'HeartbeatJob', @Value, NULL, N'heartbeat');
        SET @ok = 1;
    END
    ELSE IF @same = 0 OR ISNULL(@st, N'') = N'failed'
         OR (ISNULL(@st, N'') = N'claimed' AND (@cl IS NULL OR @cl < DATEADD(MINUTE, -@StaleMinutes, @NowUtc)))
    BEGIN
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat' WHERE Name = N'HeartbeatJob';
        SET @ok = 1;
    END
    COMMIT;
    SELECT @ok AS Claimed;
END
'@
}

function Get-SIHeartbeatClaimDoneSql {
    <# The outcome of THIS half hour's claim (only while the row still names this slot). Answers ONE row: Updated. #>
    @'
SET NOCOUNT ON;
DECLARE @n int = 0;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat'
    WHERE Name = N'HeartbeatJob' AND ISJSON(Value) = 1 AND JSON_VALUE(Value, '$.slot') = @Slot;
    SET @n = @@ROWCOUNT;
END
SELECT @n AS Updated;
'@
}

function New-SIHeartbeatClaimValue {
    <# PURE. The claim row's value: {slot, claimedUtc, sentUtc, status, reason} -- at most 400 characters (the reason is cut). #>
    param([Parameter(Mandatory)][datetime]$NowUtc, [Parameter(Mandatory)][ValidateSet('claimed', 'sent', 'failed')][string]$Status,
          $ClaimedUtc, [AllowNull()][AllowEmptyString()][string]$Reason)
    $slot = (Get-SIHeartbeatSlot -NowUtc $NowUtc).Slot
    $why = ("$Reason" -replace '[\r\n\t]+', ' ').Trim()
    foreach ($max in 240, 120, 40, 0) {
        $r = if ($why.Length -gt $max) { if ($max -le 3) { '' } else { $why.Substring(0, $max - 3) + '...' } } else { $why }
        $v = [ordered]@{ slot = $slot; claimedUtc = (ConvertTo-SIHeartbeatUtc $(if ($ClaimedUtc) { $ClaimedUtc } else { $NowUtc }))
                         sentUtc = $(if ($Status -eq 'sent') { ConvertTo-SIHeartbeatUtc $NowUtc } else { $null }); status = $Status; reason = $(if ($r) { $r } else { $null }) } | ConvertTo-Json -Compress
        if ($v.Length -le 400) { return $v }
    }
    $v
}

function Invoke-SIHeartbeatClaim {
    <# Claim this half hour's heartbeat. $true = this execution sends it. No database = $true (nothing to share). A claim
       that cannot be made or read = $true as well: a heartbeat too many is better than none. The answer is read whatever
       its shape (ConvertTo-SIHeartbeatSqlRows). #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Invoke) { return $true }
    try {
        $sl = Get-SIHeartbeatSlot -NowUtc $NowUtc
        $v = New-SIHeartbeatClaimValue -NowUtc $NowUtc -Status 'claimed'
        $p = [ordered]@{ Value = $v; Slot = $sl.Slot; LegacyHour = $sl.LegacyHour; NowUtc = $NowUtc.ToUniversalTime(); StaleMinutes = [int]$script:SIHeartbeatJob.ClaimStaleMinutes }
        $rows = @(ConvertTo-SIHeartbeatSqlRows (& $Invoke (Get-SIHeartbeatClaimSql) $p 'reader'))
        if (-not $rows.Count) { return $true }
        $c = Get-SIHeartbeatRowValue $rows[0] 'Claimed'
        if ($null -eq $c -and ($rows[0] -is [ValueType] -or $rows[0] -is [string])) { $c = $rows[0] }   # a scalar answer
        if ($null -eq $c) { return $true }
        [int]$c -eq 1
    } catch { $true }
}

function Complete-SIHeartbeatClaim {
    <# Record how THIS half hour's claim ended: 'sent' (Invardia answered 2xx) or 'failed' (+ why) -- a failed half hour is
       taken again by the next execution. Never throws; $true when recorded. #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$NowUtc, [Parameter(Mandatory)][ValidateSet('sent', 'failed')][string]$Status,
          [AllowNull()][AllowEmptyString()][string]$Reason, $ClaimedUtc)
    if (-not $Invoke) { return $false }
    try {
        $v = New-SIHeartbeatClaimValue -NowUtc $NowUtc -Status $Status -ClaimedUtc $ClaimedUtc -Reason $Reason
        $null = & $Invoke (Get-SIHeartbeatClaimDoneSql) ([ordered]@{ Value = $v; Slot = (Get-SIHeartbeatSlot -NowUtc $NowUtc).Slot }) 'reader'
        $true
    } catch { $false }
}

# =====================================================================================================================
#  SUPPORT-LINK-1 (framework, owner 2026-11-10: "must go into all solutions"): THE DELIVERY STATE of the Invardia support link
# =====================================================================================================================
#  The job always ends well (exit 0), so its executions are always green -- a link that cannot deliver must still show. Every
#  half hour that was claimed ends 'sent' or 'failed'; the count of half hours in a row that were NOT delivered is kept in
#  cfg.InstallState 'HeartbeatDelivery' ({failedInRow, lastFailedSlot, lastFailedUtc, lastSentUtc}). A half hour counts once,
#  however many ticks retry it; a delivered half hour sets the count to 0. The Jobs page reads the row (SupportLinkDelivery.cs):
#  0 = green; 1-2 = green with an info line ("it is retried next cycle"); 3 or more = amber. NEVER a mail to the customer when a
#  report cannot be delivered -- the page line is the only place it shows (tests\pester\SIv3-SupportLink.Tests.ps1).
$script:SIHeartbeatJob['DeliveryRow'] = 'HeartbeatDelivery'

function Get-SIHeartbeatDeliveryNext {
    <# PURE. The delivery row after this half hour ended -Status sent | failed. -Previous: the row's value (JSON text, an
       object, or $null). A failed half hour already counted (lastFailedSlot = this slot: a later tick of the same half hour
       retried it) keeps the count; a delivered one resets it to 0. Returns the ordered value. #>
    param($Previous, [Parameter(Mandatory)][ValidateSet('sent', 'failed')][string]$Status, [Parameter(Mandatory)][datetime]$NowUtc)
    $p = $null
    if ($Previous -is [string]) { if ("$Previous".Trim()) { try { $p = $Previous | ConvertFrom-Json -ErrorAction Stop } catch { $p = $null } } }
    elseif ($null -ne $Previous -and -not ($Previous -is [DBNull])) { $p = $Previous }
    $count = 0; $lastSlot = $null; $lastFailed = $null; $lastSent = $null
    if ($p) {
        $c = 0
        if ([int]::TryParse("$(Get-SIHeartbeatRowValue $p 'failedInRow')", [ref]$c) -and $c -gt 0) { $count = $c }
        $lastSlot = [string](Get-SIHeartbeatRowValue $p 'lastFailedSlot'); if (-not $lastSlot) { $lastSlot = $null }
        $lastFailed = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $p 'lastFailedUtc')
        $lastSent = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $p 'lastSentUtc')
    }
    $slot = (Get-SIHeartbeatSlot -NowUtc $NowUtc).Slot
    $now = ConvertTo-SIHeartbeatUtc $NowUtc
    if ($Status -eq 'sent') { return [ordered]@{ failedInRow = 0; lastFailedSlot = $null; lastFailedUtc = $lastFailed; lastSentUtc = $now } }
    if ($lastSlot -ne $slot -or $count -lt 1) { $count++ }
    [ordered]@{ failedInRow = $count; lastFailedSlot = $slot; lastFailedUtc = $now; lastSentUtc = $lastSent }
}

function Get-SIHeartbeatDeliveryReadSql {
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'HeartbeatDelivery';
'@
}

function Get-SIHeartbeatDeliveryWriteSql {
    @'
SET NOCOUNT ON;
DECLARE @done int = 0;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat' WHERE Name = N'HeartbeatDelivery';
    IF @@ROWCOUNT = 0 INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'HeartbeatDelivery', @Value, NULL, N'heartbeat');
    SET @done = 1;
END
SELECT @done AS Recorded;
'@
}

function Update-SIHeartbeatDelivery {
    <# Record how this half hour's delivery ended (sent | failed) in cfg.InstallState 'HeartbeatDelivery'. Never throws;
       returns the value written, or $null (no database, or it could not be read / written). Never sends a mail. #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$NowUtc, [Parameter(Mandatory)][ValidateSet('sent', 'failed')][string]$Status)
    if (-not $Invoke) { return $null }
    try {
        $rows = @(ConvertTo-SIHeartbeatSqlRows (& $Invoke (Get-SIHeartbeatDeliveryReadSql) @{} 'reader'))
        $prev = if ($rows.Count) { Get-SIHeartbeatRowValue $rows[0] 'Value' } else { $null }
        $next = Get-SIHeartbeatDeliveryNext -Previous $prev -Status $Status -NowUtc $NowUtc
        $null = & $Invoke (Get-SIHeartbeatDeliveryWriteSql) ([ordered]@{ Value = ($next | ConvertTo-Json -Compress) }) 'reader'
        [pscustomobject]$next
    } catch { $null }
}

function Get-SIHeartbeatTickLine {
    <# PURE. The ONE plain line every tick says: what happened, where to (the endpoint's HOST only, never a key), the mode,
       Invardia's answer or the error, and which optional fields rode along. #>
    param([string]$Status, $Context, [AllowEmptyString()][string]$Answer, [string[]]$Fields = @(), [AllowEmptyString()][string]$Note)
    $hostName = ''
    try { if ($Context -and "$($Context.Endpoint)".Trim()) { $hostName = ([uri]"$($Context.Endpoint)").Host } } catch { $hostName = '' }
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add(('to {0}' -f $(if ($hostName) { $hostName } else { 'no endpoint' })))
    if ($Context) { $parts.Add(('mode {0}' -f $(if ("$($Context.Mode)".Trim()) { $Context.Mode } else { 'unknown' }))) }
    if ($Context -and "$($Context.Mode)" -eq 'anonymous' -and "$($Context.AnonymousReason)".Trim()) { $parts.Add(('why anonymous: {0}' -f $Context.AnonymousReason)) }
    if ($Context -and "$($Context.Mode)" -eq 'identified' -and $Context.PSObject.Properties['Endpoints'] -and -not @($Context.Endpoints | Where-Object { $_ }).Count) { $parts.Add('no install endpoints known') }
    if ("$Answer".Trim()) { $parts.Add(('answer: {0}' -f (ConvertTo-AitUplinkRedacted -Text "$Answer"))) }
    $parts.Add(('fields: {0}' -f $(if (@($Fields).Count) { @($Fields) -join ', ' } else { 'none' })))
    if ("$Note".Trim()) { $parts.Add("$Note".Trim()) }
    ('{0} ({1})' -f $Status, ($parts -join '; '))
}

# =====================================================================================================================
#  THE TICK
# =====================================================================================================================
function Send-SIHeartbeatTick {
    <#
        One hourly heartbeat. NEVER throws; returns @{ Status; Reason; Record; Sent } -- Status: disabled | skipped | not-due |
        sent | failed | error. Every input is a seam (tests):
          -Context         Get-SITelemetryContext (default: this install's)
          -Transport       { param($Record, $Endpoint, $AccessCode, $TimeoutSec) } (default: Send-SITelemetryUplink)
          -HeartbeatCounts { } -> the tenant counts (default Get-SITelemetryHeartbeatCounts; never in a test session)
          -RunState        the newest run record, or -RunStore (its Load())
          -CollectionRows  the rows of Get-SIHeartbeatCollectionsSql, or -DataInvoke { param($Sql, $Params, $Mode) } to read them
          -ExpectedUsers   the tenant's users (default: one Graph $count, only when Collections go out)
          -ClaimInvoke     the Pro database seam for the hour's claim (and the release fields)
          -Collections / -RunProgress   force the switch (tests); default Resolve-SIUplinkCollectionsSwitch / ...RunProgressSwitch
          #719 (SI-HeartbeatFields.ps1, New-SIHeartbeatFields): -FieldSwitch @{ <Field> = $true/$false } forces a field's switch;
          -CfgRows / -SecurityRows / -SourceRows / -Arm / -RunQuery / -Installed are its seams (the settings database is read
          through -ClaimInvoke, the data database through -DataInvoke)
          -SupportSqlAccess { param([datetime]$NowUtc) } -> Get-SISupportSqlAccess's answer @{ Wire; Text } (framework 4.1b,
          READ ONLY; default: the job's own databases, Graph and ARM -- New-SISupportSqlAccessSeams; never in a test session)
          -SupportGrantStatus { param([datetime]$NowUtc) } -> Get-SISupportGrantStatus's answer @{ Wire; Text } (#1021, READ ONLY;
          default: the job's own databases; never in a test session); -SupportSqlAccessJit forces its switch (tests)
    #>
    [CmdletBinding()]
    param($Context, [scriptblock]$Transport, $Now, [scriptblock]$HeartbeatCounts, $RunState, $RunStore, [object[]]$CollectionRows, [scriptblock]$DataInvoke,
          $ExpectedUsers, [scriptblock]$ClaimInvoke, [AllowNull()]$Collections, [AllowNull()]$RunProgress,
          [hashtable]$FieldSwitch = @{}, [object[]]$CfgRows, [object[]]$SecurityRows, [object[]]$SourceRows, [scriptblock]$Arm, [scriptblock]$RunQuery,
          [AllowNull()][AllowEmptyString()][string]$Installed, [scriptblock]$SupportSqlAccess, [scriptblock]$SupportGrantStatus, [AllowNull()]$SupportSqlAccessJit,
          # Invardia S16 (answer 2, 2026-11-01): the install's lasting id is MADE here once when it is missing
          # (Initialize-SITelemetryLastingInstallId); the vault seams { param($Name) } / { param($Name, $Value) } -- tests
          [scriptblock]$InstallIdRead, [scriptblock]$InstallIdWrite, [scriptblock]$InstallIdVersions,
          # #1065 (3.0.30): the cfg.InstallState rows the setup steps are read from (tests; default: one read through -ClaimInvoke)
          [AllowNull()][object[]]$SetupStepRows)
    $out = { param($s, $why, $rec, $sent) [pscustomobject]@{ Status = $s; Reason = $why; Record = $rec; Sent = [bool]$sent } }
    # LIVE 2026-10-16 (#718): the hour is recorded SENT only after Invardia answered 2xx; every other end of a claimed tick
    # records it FAILED (with why), so the next execution takes the hour again -- never a claimed hour that sent nothing
    $claimed = $false; $completed = $false; $failWhy = 'the tick ended before the heartbeat was sent'; $nowUtc = [datetime]::UtcNow
    try {
        if (-not (Test-SITelemetryEnabled)) { return (& $out 'disabled' 'telemetry is switched off (SI_Telemetry_Enabled)' $null $false) }
        if (-not $Transport -and (Get-Module -Name Pester)) { return (& $out 'skipped' 'a test session (Pester is loaded) never sends; pass -Transport to test the sender' $null $false) }
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        if (-not $Context) { $Context = Get-SITelemetryContext }
        # framework PRO-COMMUNITY-SAME (opt-in): an install that did not say yes to "Connect this install to Invardia" sends no report
        if ($Context.PSObject.Properties['Connected'] -and -not [bool]$Context.Connected) {
            return (& $out 'skipped' (Get-SIHeartbeatTickLine -Status 'skipped' -Context $Context -Note (Get-SIInvardiaConnectSkipText -What 'no status report')) $null $false)
        }
        if ($Context.Mode -eq 'anonymous') {
            return (& $out 'skipped' (Get-SIHeartbeatTickLine -Status 'skipped' -Context $Context -Note 'an anonymous install sends its one heartbeat a day with its engine runs -- nothing is sent from here') $null $false)
        }
        if (-not (Invoke-SIHeartbeatClaim -Invoke $ClaimInvoke -NowUtc $nowUtc)) {
            return (& $out 'not-due' (Get-SIHeartbeatTickLine -Status 'not-due' -Context $Context -Note 'the heartbeat of this half hour was sent already (or another execution is sending it)') $null $false)
        }
        $claimed = $true
        # Invardia S16: the uplink job makes the install's lasting id ONCE when it is missing (the knock's code; never rewritten;
        # a vault it cannot write = no id this tick, never a failure) -- the heartbeat then carries it as InstallId
        if (Get-Command -Name Initialize-SITelemetryLastingInstallId -ErrorAction SilentlyContinue) {
            $Context = Initialize-SITelemetryLastingInstallId -Context $Context -ReadSecret $InstallIdRead -WriteSecret $InstallIdWrite -ReadVersions $InstallIdVersions
        }
        if (-not $Transport) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-SITelemetryUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
        $ring = if ($Context.PSObject.Properties['Ring']) { $Context.Ring } else { $null }

        # the heartbeat itself -- exactly the end-of-run heartbeat's record
        $base = @{ Edition = $Context.Edition; Version = $Context.Version; Hosting = $Context.Hosting; RuntimeIdentity = $Context.RuntimeIdentity
                   LicenceState = $Context.LicenceState; Now = $nowUtc; Ring = $ring; TenantId = $Context.TenantId }
        $hbCounts = $null
        try { $hbCounts = if ($HeartbeatCounts) { & $HeartbeatCounts } elseif (-not (Get-Module -Name Pester)) { Get-SITelemetryHeartbeatCounts -NowUtc $nowUtc } } catch { $hbCounts = $null }
        $relF = $null
        try { $relF = Get-SITelemetryReleaseFields -Context $Context -NowUtc $nowUtc -Invoke $ClaimInvoke } catch { $relF = $null }
        # CR4: the guard mode from the Pro database this job has open (-ClaimInvoke). LIVE 2026-10-18: this job does not load
        # the guard code that finds the database by itself, so the half-hourly heartbeat went WITHOUT guardMode while the
        # install was strict (Get-SITelemetryGuardModeWire)
        $gmWire = Get-SITelemetryGuardModeWire -Context $Context -Invoke $ClaimInvoke -Rows $(if ($relF) { $relF.Rows } else { $null }) -NowUtc $nowUtc
        $eps = @(if ($Context.PSObject.Properties['Endpoints']) { @($Context.Endpoints) })
        $lid = if ($Context.PSObject.Properties['LicenceId']) { [string]$Context.LicenceId } else { '' }
        $envName = if ($Context.PSObject.Properties['EnvironmentName']) { [string]$Context.EnvironmentName } else { '' }
        # framework 4.1b (owner 2026-10-18): both parts of the Invardia Support app's database access, READ ONLY -- SI never
        # heals them (Invardia does). No Support app recorded / nothing readable = the field is left out. Never fails the tick.
        $ssa = $null
        try {
            if ($SupportSqlAccess) { $ssa = & $SupportSqlAccess $nowUtc }
            elseif (-not (Get-Module -Name Pester)) { $ssaSeams = New-SISupportSqlAccessSeams; if ($ssaSeams) { $ssa = Get-SISupportSqlAccess @ssaSeams -NowUtc $nowUtc } }
        } catch { $ssa = $null }
        # #1021: the support grant's state (read only) -- its keys ride on supportSqlAccess only where the switch says so
        # (default OFF until Invardia's side is live); what it says always goes in this tick's line
        $sgs = $null
        try {
            if ($SupportGrantStatus) { $sgs = & $SupportGrantStatus $nowUtc }
            elseif (-not (Get-Module -Name Pester) -and (Get-Command -Name Get-SISupportGrantDatabases -ErrorAction SilentlyContinue)) { $sgDbs = Get-SISupportGrantDatabases; if ($sgDbs.Count) { $sgs = Get-SISupportGrantStatus -Databases $sgDbs -NowUtc $nowUtc } }
        } catch { $sgs = $null }
        $sendJit = if ($null -ne $SupportSqlAccessJit) { [bool]$SupportSqlAccessJit } else { (Resolve-SIUplinkSupportSqlAccessJitSwitch -Ring $ring).On }
        if ($sendJit -and $ssa -and $ssa.Wire -and $sgs -and $sgs.Wire) {
            foreach ($k in 'readOnly', 'jitOpen', 'jitUntil') {
                $v = if ($sgs.Wire -is [System.Collections.IDictionary]) { $sgs.Wire[$k] } else { $sgs.Wire.$k }
                if ($ssa.Wire -is [System.Collections.IDictionary]) { $ssa.Wire[$k] = $v } else { $ssa.Wire | Add-Member -NotePropertyName $k -NotePropertyValue $v -Force }
            }
        }
        # CR3: components + evidence ride on this heartbeat too (they went only on the end-of-run and release-mode reports)
        $w = ConvertTo-SITelemetryWire -Record (New-SITelemetryHeartbeat @base) -Mode $Context.Mode -Counts $hbCounts -Now $nowUtc -Endpoints $eps -LicenceId $lid -EnvironmentName $envName `
                -GuardMode $gmWire -Wave $(if ($relF) { $relF.Wave } else { $null }) -ReleaseMode $(if ($relF) { $relF.ReleaseMode } else { $null }) `
                -Components $(if ($relF) { $relF.Components } else { $null }) -Evidence $(if ($relF) { $relF.Evidence } else { $null }) -SupportSqlAccess $(if ($ssa) { $ssa.Wire } else { $null }) -Build $(if ($Context.PSObject.Properties['Build']) { [string]$Context.Build } else { '' })
        if ($null -eq $w) { $failWhy = 'the heartbeat could not be built'; return (& $out 'error' (Get-SIHeartbeatTickLine -Status 'error' -Context $Context -Note $failWhy) $null $false) }

        # #1065 (3.0.30, Invardia's alignment gap no-setup-steps): every one-time step this install can check, with its state
        # -- the updater's record of its last run (cfg.InstallState) and this tick's support grant read. Identified only (this
        # job sends nothing else); no step checked = no field. Never costs the tick.
        try {
            $ssRows = if ($PSBoundParameters.ContainsKey('SetupStepRows')) { @($SetupStepRows) } else { @(Read-SISetupStepRows -Invoke $ClaimInvoke) }
            $steps = @(Get-SISetupSteps -StateRows $ssRows -SupportGrant $sgs -NowUtc $nowUtc)
            if ($steps.Count) { $w | Add-Member -NotePropertyName 'setupSteps' -NotePropertyValue $steps -Force }
        } catch { if ($w.PSObject.Properties['setupSteps']) { $w.PSObject.Properties.Remove('setupSteps') } }

        # the two new optional fields -- each only where its switch says so (default: off until Invardia confirms them)
        $sendProgress = if ($null -ne $RunProgress) { [bool]$RunProgress } else { (Resolve-SIUplinkRunProgressSwitch -Ring $ring).On }
        $sendCollections = if ($null -ne $Collections) { [bool]$Collections } else { (Resolve-SIUplinkCollectionsSwitch -Ring $ring).On }
        $progress = $null
        if ($sendProgress -or $sendCollections) {
            try {
                if ($null -eq $RunState -and $RunStore) { $RunState = $RunStore.Load() }
                $progress = Get-SIHeartbeatRunProgress -State $RunState -NowUtc $nowUtc
            } catch { $progress = $null }
        }
        if ($sendProgress -and $progress) { $w | Add-Member -NotePropertyName 'runProgress' -NotePropertyValue $progress -Force }
        if ($sendCollections) {
            try {
                if ($null -eq $CollectionRows -and $DataInvoke) { $CollectionRows = @(& $DataInvoke (Get-SIHeartbeatCollectionsSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
                if ($null -eq $ExpectedUsers -and -not (Get-Module -Name Pester)) { $ExpectedUsers = Get-SIHeartbeatExpectedUsers }
                $exp = @{}; if ($null -ne (ConvertTo-SIHeartbeatCount $ExpectedUsers)) { $exp['identity'] = ConvertTo-SIHeartbeatCount $ExpectedUsers }
                # #636: the Risk Analysis Summary entry only while the Summary step is not off (it is optional and off by default)
                $sumStep = 'unknown'
                $ssLib = [System.IO.Path]::Combine($PSScriptRoot, 'SI-SummaryStep.ps1')
                if ($DataInvoke -and -not (Get-Command -Name Get-SISummaryStepState -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $ssLib)) { . $ssLib }
                if ($DataInvoke -and (Get-Command -Name Get-SISummaryStepState -ErrorAction SilentlyContinue)) { $sumStep = Get-SISummaryStepState -Invoke $DataInvoke -Mode 'rows' -StoredOnly }
                $col = @(ConvertTo-SIHeartbeatCollections -Rows @($CollectionRows) -RunProgress $progress -Expected $exp -SummaryStep $sumStep -LastRunState $(if ($RunState) { [string](Get-SIHeartbeatRowValue $RunState 'State') } else { '' }))
                # never an entry Invardia would refuse: the whole value is checked against the agreed schema first
                if ($col.Count -and -not (Test-SIHeartbeatCollection -Array $col -IsArray)) { $w | Add-Member -NotePropertyName 'Collections' -NotePropertyValue $col -Force }
            } catch { if ($w.PSObject.Properties['Collections']) { $w.PSObject.Properties.Remove('Collections') } }
        }
        # #719: the eight further fields -- each behind its own switch, each read in its own try and checked against the agreed
        # schema (New-SIHeartbeatFields never throws; a field that cannot be read or does not pass is left out)
        $sizeNote = ''
        try {
            $fa = @{ Ring = $ring; NowUtc = $nowUtc; Switch = $FieldSwitch; CfgInvoke = $ClaimInvoke; DataInvoke = $DataInvoke
                     Counts = $(if ($hbCounts -is [System.Collections.IDictionary]) { $hbCounts } else { @{} }) }
            foreach ($k in 'CfgRows', 'SecurityRows', 'SourceRows', 'Arm', 'RunQuery', 'Installed') { if ($PSBoundParameters.ContainsKey($k)) { $fa[$k] = $PSBoundParameters[$k] } }
            $fields = New-SIHeartbeatFields @fa
            foreach ($k in @($fields.Keys)) { $w | Add-Member -NotePropertyName $k -NotePropertyValue $fields[$k] -Force }
            # Invardia takes an identified heartbeat of at most 48 KB: over it, the optional fields go in a fixed order
            $lim = Limit-SIHeartbeatRecordSize -Record $w
            if (@($lim.Dropped).Count) { $sizeNote = ('over 48 KB: sent without {0}' -f (@($lim.Dropped) -join ', ')) }
        } catch { foreach ($k in (Get-SIHeartbeatFieldsContract).Names) { if ($w.PSObject.Properties[$k]) { $w.PSObject.Properties.Remove($k) } } }
        $had = @(@('guardMode', 'wave', 'releaseMode', 'components', 'evidence', 'Collections', 'runProgress', 'supportSqlAccess') + @((Get-SIHeartbeatFieldsContract).Names) + @('setupSteps') | Where-Object { $w.PSObject.Properties[$_] })

        # the pipeline's progress and estimated end are newer than the rest of Pipeline: a heartbeat Invardia refuses (4xx)
        # WITH them is sent again with Pipeline WITHOUT them first -- never the rest of the record lost to them (the same for
        # housekeepingRowsLeft, newer still: the resend leaves Pipeline with its agreed seven only). Plain
        # (not a closure): the sender calls it in this function's scope chain, so $etaSend / $etaState are the ones here.
        $etaState = @{ Dropped = $false }
        $etaSend = $Transport
        $sendWith = $Transport
        if ($w.PSObject.Properties['Pipeline'] -and (Test-SIPipelineHasExtras $w.Pipeline)) {
            $sendWith = {
                param($Record, $Endpoint, $AccessCode, $TimeoutSec)
                $a = & $etaSend $Record $Endpoint $AccessCode $TimeoutSec
                if ("$($a.Status)" -ne 'ok' -and "$($a.Reason)" -match '\b4\d\d\b' -and $Record.PSObject.Properties['Pipeline'] -and (Test-SIPipelineHasExtras $Record.Pipeline)) {
                    $Record.Pipeline = Remove-SIPipelineEta $Record.Pipeline
                    $etaState.Dropped = $true
                    $a = & $etaSend $Record $Endpoint $AccessCode $TimeoutSec
                }
                $a
            }
        }
        $s = Send-SITelemetryRecordWithFallback -Record $w -Transport $sendWith -Context $Context -TimeoutSec (Get-SITelemetrySendState).TimeoutSec -Invoke $(if ($relF) { $relF.Invoke } else { $ClaimInvoke }) -NowUtc $nowUtc
        $answer = if ($null -eq $s -or $null -eq $s.Result) { 'no answer' } else { "$($s.Result.Reason)" }
        if ($null -eq $s -or $null -eq $s.Result -or "$($s.Result.Status)" -ne 'ok') {
            $failWhy = ConvertTo-AitUplinkRedacted -Text $(if ("$answer".Trim()) { $answer } else { 'the uplink gave no answer' })
            if (-not $global:SI_HeartbeatJobWarned) { $global:SI_HeartbeatJobWarned = $true; try { Write-Warning ("The Invardia support link could not deliver this report ({0}). Nothing else is affected; it is retried next cycle." -f $failWhy) } catch { } }
            return (& $out 'failed' (Get-SIHeartbeatTickLine -Status 'failed' -Context $Context -Answer $failWhy -Fields $had -Note $sizeNote) $(if ($s) { $s.Record } else { $w }) $false)
        }
        $null = Complete-SIHeartbeatClaim -Invoke $ClaimInvoke -NowUtc $nowUtc -Status 'sent' -Reason $answer
        $completed = $true
        $sentFields = @($had | Where-Object { $s.Record.PSObject.Properties[$_] })
        $dropped = @($had | Where-Object { -not $s.Record.PSObject.Properties[$_] })
        $etaNote = if ($etaState.Dropped -and $s.Record.PSObject.Properties['Pipeline']) { 'Invardia did not take the pipeline estimate -- sent again without it' } else { '' }
        $note = @($sizeNote, $etaNote, $(if ($dropped.Count) { 'Invardia did not take ' + ($dropped -join ', ') + ' -- sent again without them' } else { '' }), $(if ($progress -and $s.Record.PSObject.Properties['runProgress']) { 'pipeline ' + $progress.state } else { '' }), $(if ($ssa) { [string]$ssa.Text } else { '' }), $(if ($sgs) { [string]$sgs.Text } else { '' })) | Where-Object { $_ }
        & $out 'sent' (Get-SIHeartbeatTickLine -Status 'sent' -Context $Context -Answer $answer -Fields $sentFields -Note ($note -join '; ')) $s.Record $true
    } catch {
        $failWhy = ConvertTo-AitUplinkRedacted -Text $_.Exception.Message
        if (-not $global:SI_HeartbeatJobWarned) { $global:SI_HeartbeatJobWarned = $true; try { Write-Warning ("The Invardia support link could not prepare this report ({0}). Nothing else is affected; it is retried next cycle." -f $failWhy) } catch { } }
        & $out 'error' (Get-SIHeartbeatTickLine -Status 'error' -Context $Context -Note $failWhy) $null $false
    } finally {
        # a claimed hour that did not end SENT is released as FAILED: the next execution sends it
        if ($claimed -and -not $completed) { $null = Complete-SIHeartbeatClaim -Invoke $ClaimInvoke -NowUtc $nowUtc -Status 'failed' -Reason $failWhy }
        # SUPPORT-LINK-1: the delivery state the Jobs page shows (a claimed half hour only; never a mail)
        if ($claimed) { $null = Update-SIHeartbeatDelivery -Invoke $ClaimInvoke -NowUtc $nowUtc -Status $(if ($completed) { 'sent' } else { 'failed' }) }
    }
}
