#Requires -Version 5.1
<#
    SecurityInsight -- THE "UPDATE NOW" SIGNAL (#723; framework, agreed by SI + PIM + Invardia 2026-10-16; owner: "i like it").

    Invardia can raise a signal for a ring (or for one environment): "update now". The heartbeat job (caj-si-heartbeat) asks
    for it on EVERY tick -- the job runs every 15 minutes ("7,22,37,52 * * * *"); the FULL heartbeat still goes out once per
    clock hour (the hour's claim in SI-HeartbeatJob.ps1 decides: a tick that is not the hour's first only asks for the
    signal). When the signal says updateNow and names a version NEWER than the release this install runs, the job starts the
    updater (caj-si-updater) ONCE for that signal:

      GET <Invardia>/api/updates/securityinsight/signal?ring=<n>    header X-Ait-Uplink-Code = the install key (the uplink's
          own key and header; Invardia knows the environment from the key)   If-None-Match = the last ETag
        200 { updateNow, version, raisedAt, by, scope: ring | environment }    304 = unchanged since the last ask
        404 / 5xx / no answer = NO signal (Invardia may not have the route yet): said once per hour, never a failure

    Rules (owner 2026-10-16):
      * the updater is started at most ONCE per raisedAt -- claimed atomically in the Pro database (cfg.InstallState
        'UpdateSignal' = { raisedAt, version, startedUtc, result, attempts, execution, etag, by }), read whatever the store's
        answer shape (ConvertTo-SIHeartbeatSqlRows -- the #718 lesson); no database = never started (once could not be kept);
      * never while an execution of the updater is Running (its executions are read, every page; a Failed execution without
        an endTime has ENDED; a Running one older than the job's run limit is not running) -- the next tick looks again;
      * a FAILED updater run is not retried here (the nightly run retries); a start Azure REFUSED (nothing ran) is tried
        again on a later tick, at most 3 times per signal;
      * a running pipeline is never waited for here and never stopped ("the update never stops a run"): the updater itself
        never installs while a pipeline run is going (owner 2026-10-23, its run gate) and installs between that run and
        the next one;
      * the updater still takes ONLY the signed manifest of its own ring -- the signal changes WHEN, never WHAT. It is
        started with SI_UPDATER_MODE = update-now so its nightly-tick check lets it run outside 23:00 (a run started for a
        purpose), and is otherwise the normal update run;
      * one plain line per action (Get-SIUpdateNowLine); the next heartbeat's Update field carries the updater's result.

    Behind SI_UpdateNow_Enabled (job variable SI_UPDATENOW_ENABLED): on / off / a ring list / auto (default: on for the rings
    in ConfirmedRings -- every ring, 0-3, since #985: owner 2026-11-01, a ring release that landed just after the daily
    update waited a day at every ring 2/3 install).

    #985 THE PRE-RUN CHECK (Invoke-SIUpdatePreRunCheck): once a day, on the heartbeat tick 30 minutes before the next
    scheduled pipeline run, the updater is started (SI_UPDATER_MODE = update-now) when its last look at Invardia's manifest is
    more than 15 minutes old (the daily update itself just before the run counts) -- so a release that came out after the daily update is installed before the night's run even
    where no signal was raised. At most one extra manifest read a day; claimed once per run slot (cfg.InstallState
    'UpdatePreRunCheck').

    #1151 (5) UPD-03 THE HEAD CALL ("Update now" / expedite, framework §8.18 + Invardia DESIGN "The head call"): on the same
    15-minute tick the job asks Invardia's head call FIRST -- it is the one that applies the owner's rule for customers:
      POST <Invardia>/api/updates/securityinsight/head   header X-Invardia-Install-Key = the install key (optional
          X-Invardia-Install-Id = the lasting install id)   body { kind: "code", licence: <the licence file text>, ring }
        200 { version, sequence, wave?, expedite?: { apply: "now" | "window", until: ISO UTC (raised + 24 h), reason } }
      * expedite.apply "now" (and `until` still ahead on this install's UTC clock, the version newer than the one running
        here) -> the updater is started exactly as for a signal (once per mark -- the mark is keyed on until - 24 h, the
        raise time the contract defines; never while it runs; the run gate still installs between two pipeline runs);
      * expedite.apply "window" -> NOT now: the release is installed at this install's own agreed update time (the daily
        update, or the check before the next run, #985) -- said once an hour;
      * no expedite / `until` past = absent -> nothing to do; the signal is NOT asked (its updateNow does not apply the
        customer rule -- Invardia: "the head call is the one that does");
      * 404 (an older Invardia without the route) -> taken silently, and the signal below is asked as before;
      * any other answer / no answer / an answer that is not the agreed shape -> the install does nothing this tick (the
        contract: "a failed head call = the install does nothing"), said once an hour.
    The mark's reason text is never printed (it is Invardia's own note); the head call writes nothing at Invardia.

    NEVER THROWS where the job calls it (Invoke-SIUpdateNowCheck). PowerShell 5.1 and 7. No PowerShell modules.
#>

$script:SIUpdateNow = @{
    # the rings where the signal is acted on while the switch is 'auto' -- every ring (#985, owner 2026-11-01)
    ConfirmedRings   = @(0, 1, 2, 3)
    # #985: the pre-run check -- the tick in [next run - 30 min, next run - 15 min), when the last manifest read is older than 15 min (a 2 h rule missed the 31 Oct case: the look was 67 min before the check)
    PreRunLeadMinutes  = 30
    PreRunTickMinutes  = 15
    PreRunFreshMinutes = 15
    PreRunRow          = 'UpdatePreRunCheck'
    Row              = 'UpdateSignal'
    Product          = 'securityinsight'
    Header           = 'X-Ait-Uplink-Code'
    # #1151 (5) UPD-03: the head call's own header and the install's lasting id (Invardia S16)
    HeadKeyHeader    = 'X-Invardia-Install-Key'
    HeadIdHeader     = 'X-Invardia-Install-Id'
    HeadKind         = 'code'
    TimeoutSec       = 5
    MaxAgeHours      = 24
    MaxStartAttempts = 3
    Mode             = 'update-now'
    ArmApi           = '2025-07-01'
    ExecutionPages   = 10
    Results          = @('seen', 'not-newer', 'waiting', 'starting', 'started', 'start-failed')
}

# =====================================================================================================================
#  The switch -- PURE
# =====================================================================================================================
function Resolve-SIUpdateNowSwitch {
    param([AllowNull()]$Value = $global:SI_UpdateNow_Enabled, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_UPDATENOW_ENABLED, [AllowNull()]$Ring,
          [int[]]$ConfirmedRings = @($script:SIUpdateNow.ConfirmedRings))
    Resolve-SIUplinkFieldSwitch -Name 'SI_UpdateNow_Enabled' -Value $Value -EnvValue $EnvValue -Ring $Ring -ConfirmedRings $ConfirmedRings
}

# =====================================================================================================================
#  Small helpers -- PURE
# =====================================================================================================================
function Get-SIUpdateNowSignalUri {
    <# PURE. The signal's address: the ORIGIN of the uplink endpoint this install reports to (https only; else Invardia's) +
       /api/updates/securityinsight/signal?ring=<n>. $null when the ring is not 0-3. #>
    param([AllowNull()][AllowEmptyString()][string]$Endpoint, [AllowNull()]$Ring)
    $rn = -1
    if ($null -eq $Ring -or -not [int]::TryParse("$Ring", [ref]$rn) -or $rn -lt 0 -or $rn -gt 3) { return $null }
    $origin = 'https://invardia.com'
    if ("$Endpoint".Trim() -match '^(https://[^/\s?#]+)') { $origin = $Matches[1] }
    '{0}/api/updates/{1}/signal?ring={2}' -f $origin, $script:SIUpdateNow.Product, $rn
}

function Get-SIUpdateNowHeadUri {
    <# PURE. #1151 (5) UPD-03: the head call's address -- the same origin as the signal (https only; else Invardia's) +
       /api/updates/securityinsight/head. $null when the ring is not 0-3 (the body must name it). #>
    param([AllowNull()][AllowEmptyString()][string]$Endpoint, [AllowNull()]$Ring)
    $rn = -1
    if ($null -eq $Ring -or -not [int]::TryParse("$Ring", [ref]$rn) -or $rn -lt 0 -or $rn -gt 3) { return $null }
    $origin = 'https://invardia.com'
    if ("$Endpoint".Trim() -match '^(https://[^/\s?#]+)') { $origin = $Matches[1] }
    '{0}/api/updates/{1}/head' -f $origin, $script:SIUpdateNow.Product
}

function New-SIUpdateNowHeadBody {
    <# PURE. The head call's JSON body: { kind: "code", licence: <the licence FILE text, as installed>, ring: 0-3 } -- exactly
       the manifest pull's body (Invardia checks it the same way). -Community (framework PRO-COMMUNITY-SAME: a Community install
       connected to Invardia, with its install key and no licence): { kind: "community", ring } -- the same answer and mark. #>
    param([AllowEmptyString()][string]$Licence = '', [Parameter(Mandatory)][int]$Ring, [switch]$Community)
    if ($Community) { return (([ordered]@{ kind = 'community'; ring = $Ring }) | ConvertTo-Json -Compress) }
    if (-not "$Licence".Trim()) { throw 'New-SIUpdateNowHeadBody: the code head call needs -Licence' }
    ([ordered]@{ kind = $script:SIUpdateNow.HeadKind; licence = $Licence; ring = $Ring }) | ConvertTo-Json -Compress
}

function ConvertFrom-SIUpdateNowHead {
    <#
        PURE. The head call's 200 answer (JSON text or an object) -> @{ Version; Sequence; Wave; Expedite }, or $null when it is
        not the agreed shape (an object with a 'version' key, null allowed). Expedite = @{ Apply (now | window); Until (ISO
        UTC); RaisedAt (Until - 24 h, the contract's "until = raised + 24 h") } or $null: absent, an unknown 'apply', or an
        'until' that cannot be read are all "no mark". The mark's reason is NOT kept (never printed).
    #>
    param($Body)
    try {
        $o = if ($Body -is [string]) { if (-not "$Body".Trim()) { return $null }; ("$Body".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop) } else { $Body }
        if ($null -eq $o -or $o -is [string] -or $o -is [ValueType] -or $o -is [array] -or -not $o.PSObject.Properties['version']) { return $null }
        $ver = if ($null -ne $o.version) { ("$($o.version)" -replace '[\r\n\t]+', ' ').Trim() } else { '' }
        if ($ver.Length -gt 64) { $ver = $ver.Substring(0, 64) }
        $seq = $null; if ($o.PSObject.Properties['sequence'] -and $null -ne $o.sequence) { $n = [long]0; if ([long]::TryParse("$($o.sequence)", [ref]$n)) { $seq = $n } }
        $wave = if ($o.PSObject.Properties['wave'] -and $null -ne $o.wave) { "$($o.wave)".Trim() } else { '' }
        $exp = $null
        if ($o.PSObject.Properties['expedite'] -and $null -ne $o.expedite -and $o.expedite.PSObject.Properties['apply']) {
            $apply = "$($o.expedite.apply)".Trim().ToLowerInvariant()
            $until = ConvertTo-SIUpdateNowUtc $(if ($o.expedite.PSObject.Properties['until']) { $o.expedite.until })
            if ($apply -in @('now', 'window') -and $until) {
                $u = [datetime]::Parse($until, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
                $exp = [pscustomobject]@{ Apply = $apply; Until = $until; RaisedAt = (ConvertTo-SIUpdateNowUtc $u.AddHours(-24)) }
            }
        }
        [pscustomobject]@{ Version = $ver; Sequence = $seq; Wave = $wave; Expedite = $exp }
    } catch { $null }
}

function ConvertTo-SIUpdateNowUtc {
    <# PURE. ISO-8601 UTC text (yyyy-MM-ddTHH:mm:ssZ) or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    try {
        $d = if ($Value -is [datetime]) { $(if ($Value.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($Value, 'Utc') } else { $Value.ToUniversalTime() }) }
             else { [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
        $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    } catch { $null }
}

function Compare-SIUpdateNowVersion {
    <# PURE. -1 / 0 / 1 for two dotted versions (each part a 64-bit number: 3.0.0.202610161829); only the leading dotted
       digits count ('3.0.0.2026...+abc' reads). $null when either cannot be read. #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    if ("$A" -notmatch '^\s*v?(\d+(?:\.\d+)*)') { return $null }; $pa = @($Matches[1] -split '\.')
    if ("$B" -notmatch '^\s*v?(\d+(?:\.\d+)*)') { return $null }; $pb = @($Matches[1] -split '\.')
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = [decimal]0; $y = [decimal]0
        if ($i -lt $pa.Count) { $x = [decimal]$pa[$i] }
        if ($i -lt $pb.Count) { $y = [decimal]$pb[$i] }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    0
}

function ConvertFrom-SIUpdateNowSignal {
    <# PURE. Invardia's answer (JSON text or an object) -> @{ UpdateNow; Version; RaisedAt (ISO UTC); By; Scope }, or $null when
       it is not the agreed shape (updateNow must be a boolean). #>
    param($Body)
    try {
        $o = if ($Body -is [string]) { if (-not "$Body".Trim()) { return $null }; ("$Body".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop) } else { $Body }
        if ($null -eq $o -or -not $o.PSObject.Properties['updateNow']) { return $null }
        $u = $o.updateNow
        if (-not ($u -is [bool])) { if ("$u" -in @('true', 'True')) { $u = $true } elseif ("$u" -in @('false', 'False')) { $u = $false } else { return $null } }
        $txt = { param($n, $max) if ($o.PSObject.Properties[$n] -and $null -ne $o.$n) { $s = ("$($o.$n)" -replace '[\r\n\t]+', ' ').Trim(); if ($s.Length -gt $max) { $s.Substring(0, $max) } else { $s } } else { '' } }
        [pscustomobject]@{ UpdateNow = [bool]$u; Version = (& $txt 'version' 64); RaisedAt = (ConvertTo-SIUpdateNowUtc $(if ($o.PSObject.Properties['raisedAt']) { $o.raisedAt }))
                           By = (& $txt 'by' 80); Scope = (& $txt 'scope' 16) }
    } catch { $null }
}

function New-SIUpdateNowStateValue {
    <# PURE. The cfg.InstallState 'UpdateSignal' value: { raisedAt, version, startedUtc, result, attempts, execution, etag, by }
       -- at most 400 characters (by, then etag, then execution are dropped first when it would not fit). #>
    param([AllowNull()][AllowEmptyString()][string]$RaisedAt, [AllowNull()][AllowEmptyString()][string]$Version, $StartedUtc,
          [Parameter(Mandatory)][string]$Result, [int]$Attempts = 0, [AllowNull()][AllowEmptyString()][string]$Execution,
          [AllowNull()][AllowEmptyString()][string]$ETag, [AllowNull()][AllowEmptyString()][string]$By)
    $nz = { param($s) if ("$s".Trim()) { "$s".Trim() } else { $null } }
    $o = [ordered]@{ raisedAt = (& $nz $RaisedAt); version = (& $nz $Version); startedUtc = (ConvertTo-SIUpdateNowUtc $StartedUtc); result = $Result
                     attempts = $Attempts; execution = (& $nz $Execution); etag = (& $nz $ETag); by = (& $nz $By) }
    foreach ($drop in @('', 'by', 'etag', 'execution')) {
        if ($drop) { $o[$drop] = $null }
        $v = $o | ConvertTo-Json -Compress
        if ($v.Length -le 400) { return $v }
    }
    $o.version = $(if ($o.version -and $o.version.Length -gt 40) { $o.version.Substring(0, 40) } else { $o.version })
    $o | ConvertTo-Json -Compress
}

function ConvertFrom-SIUpdateNowStateRow {
    <# PURE. The stored state (the answer of Get-SIUpdateNowStateSql, any shape) -> the parsed value, or $null. #>
    param($Answer)
    try {
        $rows = @(ConvertTo-SIHeartbeatSqlRows $Answer)
        if (-not $rows.Count) { return $null }
        $v = Get-SIHeartbeatRowValue $rows[0] 'Value'
        if ($null -eq $v -and ($rows[0] -is [string])) { $v = $rows[0] }
        if (-not "$v".Trim()) { return $null }
        "$v" | ConvertFrom-Json -ErrorAction Stop
    } catch { $null }
}

# =====================================================================================================================
#  The Pro database: the state and the ONE claim per raisedAt
# =====================================================================================================================
function Get-SIUpdateNowStateSql {
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    SELECT Value FROM cfg.InstallState WHERE Name = N'UpdateSignal';
'@
}

function Get-SIUpdateNowClaimSql {
    <# Claim the start for @RaisedAt: taken unless the row already names this raisedAt with a start (startedUtc set) that is
       not a refused start, or a refused start tried @MaxAttempts times. No table = not taken (once cannot be kept). Answers
       ONE row: Claimed (1 / 0). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS Claimed;
ELSE
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @cur NVARCHAR(400) = NULL, @has int = 0, @ok int = 0;
    SELECT @cur = Value, @has = 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'UpdateSignal';
    DECLARE @ra NVARCHAR(40) = CASE WHEN ISJSON(@cur) = 1 THEN JSON_VALUE(@cur, '$.raisedAt') END;
    DECLARE @su NVARCHAR(40) = CASE WHEN ISJSON(@cur) = 1 THEN JSON_VALUE(@cur, '$.startedUtc') END;
    DECLARE @rs NVARCHAR(32) = CASE WHEN ISJSON(@cur) = 1 THEN JSON_VALUE(@cur, '$.result') END;
    DECLARE @at int = CASE WHEN ISJSON(@cur) = 1 THEN TRY_CONVERT(int, JSON_VALUE(@cur, '$.attempts')) END;
    IF @has = 0
    BEGIN
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'UpdateSignal', @Value, NULL, N'heartbeat');
        SET @ok = 1;
    END
    ELSE IF ISNULL(@ra, N'') <> @RaisedAt OR @su IS NULL
         OR (ISNULL(@rs, N'') = N'start-failed' AND ISNULL(@at, 0) < @MaxAttempts)
    BEGIN
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat' WHERE Name = N'UpdateSignal';
        SET @ok = 1;
    END
    COMMIT;
    SELECT @ok AS Claimed;
END
'@
}

function Get-SIUpdateNowSaveSql {
    <# Record what this tick saw. A row that names THIS raisedAt with a start is changed only by the start's own outcome
       (@Force = 1); every other write leaves it. Answers ONE row: Updated. #>
    @'
SET NOCOUNT ON;
DECLARE @n int = 0;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'UpdateSignal')
    BEGIN
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'UpdateSignal', @Value, NULL, N'heartbeat');
        SET @n = 1;
    END
    ELSE
    BEGIN
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat'
        WHERE Name = N'UpdateSignal'
          AND (@Force = 1 OR ISJSON(Value) = 0 OR ISNULL(JSON_VALUE(Value, '$.raisedAt'), N'') <> ISNULL(@RaisedAt, N'') OR JSON_VALUE(Value, '$.startedUtc') IS NULL);
        SET @n = @@ROWCOUNT;
    END
    COMMIT;
END
SELECT @n AS Updated;
'@
}

function Read-SIUpdateNowState {
    param([scriptblock]$Invoke)
    if (-not $Invoke) { return $null }
    try { ConvertFrom-SIUpdateNowStateRow (& $Invoke (Get-SIUpdateNowStateSql) @{} 'reader') } catch { $null }
}

function Invoke-SIUpdateNowClaim {
    <# $true = this tick starts the updater for -RaisedAt. No database / a claim that cannot be made or read = $false (once
       per raisedAt could not be kept -- the nightly run updates as always). #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][string]$RaisedAt, [Parameter(Mandatory)][string]$Value)
    if (-not $Invoke) { return $false }
    try {
        $rows = @(ConvertTo-SIHeartbeatSqlRows (& $Invoke (Get-SIUpdateNowClaimSql) ([ordered]@{ Value = $Value; RaisedAt = $RaisedAt; MaxAttempts = [int]$script:SIUpdateNow.MaxStartAttempts }) 'reader'))
        if (-not $rows.Count) { return $false }
        $c = Get-SIHeartbeatRowValue $rows[0] 'Claimed'
        if ($null -eq $c -and ($rows[0] -is [ValueType] -or $rows[0] -is [string])) { $c = $rows[0] }
        ($null -ne $c -and [int]$c -eq 1)
    } catch { $false }
}

function Save-SIUpdateNowState {
    param([scriptblock]$Invoke, [Parameter(Mandatory)][string]$Value, [AllowEmptyString()][string]$RaisedAt = '', [switch]$Force)
    if (-not $Invoke) { return $false }
    try { $null = & $Invoke (Get-SIUpdateNowSaveSql) ([ordered]@{ Value = $Value; RaisedAt = $RaisedAt; Force = [int][bool]$Force }) 'reader'; $true } catch { $false }
}

# =====================================================================================================================
#  Invardia: the one GET
# =====================================================================================================================
function Invoke-SIUpdateNowSignalHttp {
    <# The signal's GET (the uplink's key header, If-None-Match) through Invoke-SIUpdateNowHttp. Never throws. #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$AccessCode, [AllowEmptyString()][string]$ETag, [int]$TimeoutSec = $script:SIUpdateNow.TimeoutSec)
    $h = [ordered]@{}; $h[$script:SIUpdateNow.Header] = $AccessCode
    if ("$ETag".Trim()) { $h['If-None-Match'] = "$ETag".Trim() }
    Invoke-SIUpdateNowHttp -Method 'GET' -Uri $Uri -Headers $h -TimeoutSec $TimeoutSec
}

function Invoke-SIUpdateNowHeadHttp {
    <# #1151 (5) UPD-03: the head call's POST (X-Invardia-Install-Key; X-Invardia-Install-Id only when there is one) through
       Invoke-SIUpdateNowHttp. The body carries the licence text: it is never logged. Never throws. #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$InstallKey, [AllowEmptyString()][string]$InstallId, [Parameter(Mandatory)][string]$Body,
          [int]$TimeoutSec = $script:SIUpdateNow.TimeoutSec)
    $h = [ordered]@{}; $h[$script:SIUpdateNow.HeadKeyHeader] = $InstallKey
    if ("$InstallId".Trim()) { $h[$script:SIUpdateNow.HeadIdHeader] = "$InstallId".Trim() }
    Invoke-SIUpdateNowHttp -Method 'POST' -Uri $Uri -Headers $h -Body $Body -TimeoutSec $TimeoutSec
}

function Invoke-SIUpdateNowHttp {
    <# THE one call to Invardia for the heartbeat job's small reads (HttpClient: every status comes back, no exception for
       304 / 404 / 5xx): the signal, the head call (#1151 (5)), the environment name (#1151 (5) NAM-02). -Body (JSON text) only
       with POST. Returns @{ Status (0 = no answer); Body; ETag; Error }. Never throws. #>
    param([ValidateSet('GET', 'POST')][string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, [System.Collections.IDictionary]$Headers = @{},
          [AllowNull()][AllowEmptyString()][string]$Body, [int]$TimeoutSec = $script:SIUpdateNow.TimeoutSec)
    $client = $null
    try {
        try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds([Math]::Max(1, $TimeoutSec))
        $m = if ($Method -eq 'POST') { [System.Net.Http.HttpMethod]::Post } else { [System.Net.Http.HttpMethod]::Get }
        $req = New-Object System.Net.Http.HttpRequestMessage($m, $Uri)
        foreach ($k in @($Headers.Keys)) { if ("$($Headers[$k])".Trim()) { [void]$req.Headers.TryAddWithoutValidation([string]$k, [string]$Headers[$k]) } }
        [void]$req.Headers.TryAddWithoutValidation('Accept', 'application/json')
        if ($Method -eq 'POST') { $req.Content = New-Object System.Net.Http.StringContent($(if ($null -ne $Body) { $Body } else { '{}' }), [System.Text.Encoding]::UTF8, 'application/json') }
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $tag = ''; try { if ($resp.Headers.ETag) { $tag = [string]$resp.Headers.ETag.ToString() } } catch { $tag = '' }
        $body = ''; try { $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() } catch { $body = '' }
        [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = $body; ETag = $tag; Error = '' }
    } catch {
        $m = $_.Exception; while ($m.InnerException) { $m = $m.InnerException }
        [pscustomobject]@{ Status = 0; Body = ''; ETag = ''; Error = [string]$m.Message }
    } finally { if ($client) { try { $client.Dispose() } catch { } } }
}

# =====================================================================================================================
#  The updater over ARM: is it running, and the start
# =====================================================================================================================
function Get-SIUpdateNowArmList {
    <# Every item of an ARM list through -Arm { param($Method, $Path, $Body) } (GET), following nextLink up to -Pages pages. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [int]$Pages = 5)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path; $i = 0
    while ($next -and $i -lt $Pages) {
        $i++
        $page = & $Arm 'GET' $next $null
        if ($null -eq $page) { break }
        foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.PSObject.Properties['nextLink']) { [string]$page.nextLink } else { '' }
    }
    $items.ToArray()
}

# Test-SIUpdateNowUpdaterRunning + New-SIUpdateNowStartTemplate live in SI-UpdaterStart.ps1 (every edition: the pipeline runner
# and the updater use them too, #897)
. (Join-Path $PSScriptRoot 'SI-UpdaterStart.ps1')

# =====================================================================================================================
#  The plain line -- PURE
# =====================================================================================================================
function Get-SIUpdateNowLine {
    <# PURE. ONE plain line per action. #>
    param([Parameter(Mandatory)][string]$Status, $Signal, [AllowEmptyString()][string]$Installed = '', [AllowEmptyString()][string]$Why = '',
          [AllowEmptyString()][string]$Pipeline = '', [AllowEmptyString()][string]$Execution = '')
    $isMark = [bool]($Signal -and $Signal.PSObject.Properties['Until'] -and $Signal.Until)
    $sig = if ($isMark) { 'Invardia''s update-now mark, until {0}' -f $Signal.Until }
           elseif ($Signal) { 'signal raised {0} by {1}' -f $(if ($Signal.RaisedAt) { $Signal.RaisedAt } else { 'at an unknown time' }), $(if ($Signal.By) { $Signal.By } else { 'Invardia' }) } else { '' }
    $run = if ($Pipeline) { $Pipeline } else { 'none' }
    switch ($Status) {
        # #1151 (5) UPD-03: the head call's own outcomes
        'window'       { 'update now: Invardia marks {0} for this install''s agreed update hours ({1}) -- it is installed at this install''s own update time (the daily update, or the check before the next run), not now' -f $Signal.Version, $sig }
        'no-mark'      { 'update now: no update-now mark for this install{0}' -f $(if ($Why) { " ($Why)" } else { '' }) }
        'mark-ended'   { 'update now: the update-now mark for {0} ended at {1} -- nothing to do' -f $Signal.Version, $Signal.Until }
        'started'      { 'update now: starting the updater for {0} ({1}, a pipeline run is in progress: {2}){3}' -f $Signal.Version, $sig, $run, $(if ($Execution) { " -- execution $Execution" } else { '' }) }
        'start-failed' { 'update now: the updater could not be started for {0} ({1}): {2} -- a later tick tries again (at most {3} times); the nightly update runs as always' -f $Signal.Version, $sig, $Why, $script:SIUpdateNow.MaxStartAttempts }
        'waiting'      { 'update now: the updater is running already ({0}) -- {1} {2} is looked at again on the next tick' -f $Why, $(if ($Signal) { $Signal.Version } else { '' }), $(if ($sig) { "($sig)" } else { '' }) }
        'already'      { 'update now: the updater was already started for {0} ({1}) -- nothing more to do' -f $Signal.Version, $sig }
        'not-newer'    { 'update now: the signal names {0}, and this install runs {1} -- nothing to do' -f $Signal.Version, $(if ($Installed) { $Installed } else { 'an unknown release' }) }
        'expired'      { 'update now: the signal raised {0} is older than {1} hours -- ignored' -f $Signal.RaisedAt, $script:SIUpdateNow.MaxAgeHours }
        'none'         { 'update now: no signal' }
        'unavailable'  { 'update now: Invardia''s signal could not be read ({0}) -- treated as no signal' -f $Why }
        default        { 'update now: {0}{1}' -f $Status, $(if ($Why) { " -- $Why" } else { '' }) }
    }
}

# =====================================================================================================================
#  THE CHECK -- one per tick
# =====================================================================================================================
function Invoke-SIUpdateNowCheck {
    <#
        One check of the signal. NEVER throws; returns @{ Status; Line; Started (bool); Signal }. Status: off | skipped |
        unavailable | none | expired | not-newer | already | waiting | no-database | no-updater | started | start-failed | error.
        Line: the plain line to say ('' = say nothing: a check that could not reach Invardia says so only on the hour's first
        tick, -FullTick). Seams (tests):
          -Context   Get-SITelemetryContext (Mode, Endpoint, AccessCode, Ring)
          -Invoke    the Pro database { param($Sql, $Params, $Mode) } (the store's reader answers ONE array of rows)
          -Http      { param($Uri, $AccessCode, $ETag) } -> @{ Status; Body; ETag; Error } (default Invoke-SIUpdateNowSignalHttp)
          -Arm       { param($Method, $Path, $Body) } -> the parsed answer (default Invoke-SIArm as the job's identity)
          -Scope     @{ Sub; Rg } (default Get-SIHeartbeatArmScope)
          -Installed the release this job runs (default Get-SITelemetryReleaseVersion)
          -RunState / -RunStore  the pipeline's run record (said in the line, never waited for)
          -Enabled   force the switch
          #1151 (5) UPD-03, the head call (asked FIRST; see the file header):
          -HeadHttp  { param($Uri, $InstallKey, $InstallId, $Body) } -> @{ Status; Body; ETag; Error } (default
                     Invoke-SIUpdateNowHeadHttp; a test session without it never asks the head call -- the signal decides)
          -Licence   the licence file text (default Get-SILicenseSecretText; none = the head call is not asked)
          -InstallId the lasting install id (default the context's LastingInstallId)
    #>
    [CmdletBinding()]
    param($Context, [scriptblock]$Invoke, [scriptblock]$Http, [scriptblock]$Arm, $Scope, $Now, [AllowNull()][AllowEmptyString()][string]$Installed,
          $RunState, $RunStore, [switch]$FullTick, [AllowNull()]$Enabled,
          [scriptblock]$HeadHttp, [AllowNull()][AllowEmptyString()][string]$Licence, [AllowNull()][AllowEmptyString()][string]$InstallId)
    $out = { param($s, $line, $sig, [bool]$started = $false) [pscustomobject]@{ Status = $s; Line = $line; Started = $started; Signal = $sig } }
    $sig = $null
    try {
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        $testSession = [bool](Get-Module -Name Pester)
        if (-not $Context) { $Context = Get-SITelemetryContext }
        $ring = if ($Context -and $Context.PSObject.Properties['Ring']) { $Context.Ring } else { $null }
        $on = if ($null -ne $Enabled) { [bool]$Enabled } else { (Resolve-SIUpdateNowSwitch -Ring $ring).On }
        if (-not $on) { return (& $out 'off' '' $null) }
        if (-not $Context -or [string]$Context.Mode -ne 'identified' -or -not "$($Context.AccessCode)".Trim()) { return (& $out 'skipped' '' $null) }
        # framework PRO-COMMUNITY-SAME (opt-in): the poll carries the install key -- never from an install that did not say yes
        if ($Context.PSObject.Properties['Connected'] -and -not [bool]$Context.Connected) { return (& $out 'skipped' $(if ($FullTick) { 'update now: ' + (Get-SIInvardiaConnectSkipText -What 'no poll') } else { '' }) $null) }
        $uri = Get-SIUpdateNowSignalUri -Endpoint ([string]$Context.Endpoint) -Ring $ring
        if (-not $uri) { return (& $out 'skipped' (Get-SIUpdateNowLine -Status 'skipped' -Why 'the update ring of this install is not known') $null) }

        # what this install recorded for the last signal / mark (its ETag, and whether the updater was started for it)
        $state = Read-SIUpdateNowState -Invoke $Invoke
        $etagNow = ''

        # ---- #1151 (5) UPD-03: THE HEAD CALL FIRST -- it applies the owner's rule for customers; 404 = an older Invardia ----
        $fromHead = $false
        $headUri = Get-SIUpdateNowHeadUri -Endpoint ([string]$Context.Endpoint) -Ring $ring
        if ($headUri -and -not $HeadHttp -and -not $testSession) {
            $HeadHttp = { param($Uri, $InstallKey, $InstallId, $Body) Invoke-SIUpdateNowHeadHttp -Uri $Uri -InstallKey $InstallKey -InstallId $InstallId -Body $Body }
        }
        if ($headUri -and $HeadHttp) {
            if (-not $PSBoundParameters.ContainsKey('Licence')) {
                $Licence = ''
                if (Get-Command -Name Get-SILicenseSecretText -ErrorAction SilentlyContinue) { try { $Licence = [string](Get-SILicenseSecretText) } catch { $Licence = '' } }
            }
            if (-not $PSBoundParameters.ContainsKey('InstallId')) { $InstallId = if ($Context.PSObject.Properties['LastingInstallId']) { [string]$Context.LastingInstallId } else { '' } }
            # a connected Community install (its install key, no licence) asks the same head call with kind "community"
            $headBody = if ("$Licence".Trim()) { New-SIUpdateNowHeadBody -Licence ([string]$Licence) -Ring ([int]$ring) }
                         elseif ($Context.PSObject.Properties['Edition'] -and [string]$Context.Edition -eq 'community') { New-SIUpdateNowHeadBody -Community -Ring ([int]$ring) }
                         else { $null }
            if ($headBody) {
                $hans = $null
                try { $hans = & $HeadHttp $headUri ([string]$Context.AccessCode) ([string]$InstallId) $headBody }
                catch { $hans = [pscustomobject]@{ Status = 0; Body = ''; ETag = ''; Error = $_.Exception.Message } }
                $hcode = if ($hans) { [int]$hans.Status } else { 0 }
                if ($hcode -eq 404) {
                    # an older Invardia without the head call: taken silently -- the signal below decides, as before
                } elseif ($hcode -eq 200) {
                    $head = ConvertFrom-SIUpdateNowHead -Body $hans.Body
                    if (-not $head) { return (& $out 'unavailable' $(if ($FullTick) { 'update now: Invardia''s head call answered, but not in the agreed shape -- nothing is done this tick' } else { '' }) $null) }
                    if (-not $head.Expedite) { return (& $out 'none' $(if ($FullTick) { Get-SIUpdateNowLine -Status 'no-mark' -Why $(if ($head.Version) { "Invardia serves $($head.Version) to this ring" } else { 'Invardia serves no release to this ring' }) } else { '' }) $null) }
                    $sig = [pscustomobject]@{ UpdateNow = $true; Version = [string]$head.Version; RaisedAt = [string]$head.Expedite.RaisedAt; By = 'Invardia'; Scope = 'expedite'
                                              Until = [string]$head.Expedite.Until; Apply = [string]$head.Expedite.Apply }
                    if (-not $sig.Version) { return (& $out 'none' $(if ($FullTick) { Get-SIUpdateNowLine -Status 'no-mark' -Why 'the mark names no release' } else { '' }) $sig) }
                    $untilUtc = [datetime]::Parse($sig.Until, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
                    # `until` is compared with this install's own UTC clock: past = absent (the contract)
                    if ($untilUtc -le $nowUtc) { return (& $out 'none' $(if ($FullTick) { Get-SIUpdateNowLine -Status 'mark-ended' -Signal $sig } else { '' }) $sig) }
                    # "window" = the hours agreed with this customer: SI's own update time, never now
                    if ($sig.Apply -eq 'window') { return (& $out 'window' $(if ($FullTick) { Get-SIUpdateNowLine -Status 'window' -Signal $sig } else { '' }) $sig) }
                    $fromHead = $true
                } else {
                    $why = if ($hcode -gt 0) { 'HTTP {0}' -f $hcode } else { 'no answer: {0}' -f $(if ($hans -and "$($hans.Error)".Trim()) { ConvertTo-AitUplinkRedacted -Text ([string]$hans.Error) } else { 'unknown' }) }
                    # a failed head call = the install does nothing (the contract); the nightly update runs as always
                    return (& $out 'unavailable' $(if ($FullTick) { 'update now: Invardia''s head call could not be read ({0}) -- nothing is done this tick; the daily update runs as always' -f $why } else { '' }) $null)
                }
            }
        }

        if (-not $fromHead) {
        if (-not $Http) {
            if ($testSession) { return (& $out 'skipped' 'update now: a test session never asks Invardia; pass -Http' $null) }
            $Http = { param($Uri, $AccessCode, $ETag) Invoke-SIUpdateNowSignalHttp -Uri $Uri -AccessCode $AccessCode -ETag $ETag }
        }
        $etag = if ($state -and $state.PSObject.Properties['etag'] -and $state.etag) { [string]$state.etag } else { '' }
        $ans = $null; try { $ans = & $Http $uri ([string]$Context.AccessCode) $etag } catch { $ans = [pscustomobject]@{ Status = 0; Body = ''; ETag = ''; Error = $_.Exception.Message } }
        $code = if ($ans) { [int]$ans.Status } else { 0 }
        if ($code -eq 304) {
            # unchanged since the last ask: the signal is the one recorded (only an updateNow signal is ever recorded)
            if (-not $state -or -not $state.raisedAt -or -not $state.version) { return (& $out 'none' (Get-SIUpdateNowLine -Status 'none') $null) }
            $sig = [pscustomobject]@{ UpdateNow = $true; Version = [string]$state.version; RaisedAt = (ConvertTo-SIUpdateNowUtc $state.raisedAt); By = $(if ($state.PSObject.Properties['by']) { [string]$state.by } else { '' }); Scope = '' }
            $etagNow = $etag
        } elseif ($code -ge 200 -and $code -lt 300) {
            $sig = ConvertFrom-SIUpdateNowSignal -Body $ans.Body
            if (-not $sig) { return (& $out 'unavailable' $(if ($FullTick) { Get-SIUpdateNowLine -Status 'unavailable' -Why ('HTTP {0}, not the agreed answer' -f $code) } else { '' }) $null) }
            $etagNow = [string]$ans.ETag
        } else {
            $why = if ($code -gt 0) { 'HTTP {0}' -f $code } else { 'no answer: {0}' -f $(if ($ans -and "$($ans.Error)".Trim()) { ConvertTo-AitUplinkRedacted -Text ([string]$ans.Error) } else { 'unknown' }) }
            return (& $out 'unavailable' $(if ($FullTick) { Get-SIUpdateNowLine -Status 'unavailable' -Why $why } else { '' }) $null)
        }
        }
        if (-not $sig.UpdateNow) { return (& $out 'none' (Get-SIUpdateNowLine -Status 'none') $sig) }
        if (-not $sig.RaisedAt -or -not $sig.Version) { return (& $out 'none' (Get-SIUpdateNowLine -Status 'ignored' -Why 'the signal names no version or no time') $sig) }
        $raised = [datetime]::Parse($sig.RaisedAt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
        if (($nowUtc - $raised).TotalHours -gt $script:SIUpdateNow.MaxAgeHours) { return (& $out 'expired' (Get-SIUpdateNowLine -Status 'expired' -Signal $sig) $sig) }
        # (PowerShell 7's ConvertFrom-Json turns an ISO time into a [datetime] -- compared as ISO UTC text, never as [string])
        $same = [bool]($state -and (ConvertTo-SIUpdateNowUtc $state.raisedAt) -eq $sig.RaisedAt)
        $attempts = if ($same -and $state.PSObject.Properties['attempts']) { [int]$state.attempts } else { 0 }
        $startedBefore = [bool]($same -and $state.startedUtc -and [string]$state.result -ne 'start-failed')
        if ($startedBefore) { return (& $out 'already' (Get-SIUpdateNowLine -Status 'already' -Signal $sig) $sig) }

        # newer than what runs here?
        if (-not $PSBoundParameters.ContainsKey('Installed')) { $Installed = $(if (Get-Command -Name Get-SITelemetryReleaseVersion -ErrorAction SilentlyContinue) { Get-SITelemetryReleaseVersion } else { '' }) }
        $cmp = Compare-SIUpdateNowVersion -A $sig.Version -B $Installed
        if ($null -eq $cmp -or $cmp -le 0) {
            $null = Save-SIUpdateNowState -Invoke $Invoke -RaisedAt $sig.RaisedAt -Value (New-SIUpdateNowStateValue -RaisedAt $sig.RaisedAt -Version $sig.Version -Result 'not-newer' -ETag $etagNow -By $sig.By)
            return (& $out 'not-newer' (Get-SIUpdateNowLine -Status 'not-newer' -Signal $sig -Installed $Installed) $sig)
        }
        if ($same -and [string]$state.result -eq 'start-failed' -and $attempts -ge $script:SIUpdateNow.MaxStartAttempts) {
            return (& $out 'start-failed' (Get-SIUpdateNowLine -Status 'gave-up' -Why ('the start was refused {0} times for the signal raised {1} -- the nightly update runs as always' -f $attempts, $sig.RaisedAt)) $sig)
        }
        if (-not $Invoke) { return (& $out 'no-database' (Get-SIUpdateNowLine -Status 'not started' -Why ('{0} is newer, but the Pro database could not be opened -- the updater is started only when it can be recorded (once per signal); the nightly update runs as always' -f $sig.Version)) $sig) }

        # the updater: its job and its executions (every page)
        if (-not $Arm) {
            if ($testSession -or -not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { return (& $out 'no-updater' (Get-SIUpdateNowLine -Status 'not started' -Why 'Azure Resource Manager cannot be reached from here') $sig) }
            $Arm = { param($Method, $Path, $Body) Invoke-SIArm -Method $Method -Path $Path -ApiVersion $script:SIUpdateNow.ArmApi -Body $Body }
        }
        if (-not $Scope) { $Scope = Get-SIHeartbeatArmScope }
        if (-not "$($Scope.Sub)".Trim() -or -not "$($Scope.Rg)".Trim()) { return (& $out 'no-updater' (Get-SIUpdateNowLine -Status 'not started' -Why 'the subscription or resource group of this install is not known') $sig) }
        $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f "$($Scope.Sub)".Trim(), "$($Scope.Rg)".Trim()
        $jobs = @(Get-SIUpdateNowArmList -Arm $Arm -Path ('{0}?api-version={1}' -f $base, $script:SIUpdateNow.ArmApi))
        # the updater: caj-si-updater, or (CR5: the install's own names) the one job whose name ends in -updater
        $upd = @($jobs | Where-Object { $_ -and (ConvertTo-SIHeartbeatJobName ([string]$_.name)) -eq 'updater' })[0]
        if (-not $upd) { $cand = @($jobs | Where-Object { $_ -and [string]$_.name -match '-updater$' }); if ($cand.Count -eq 1) { $upd = $cand[0] } }
        if (-not $upd) { return (& $out 'no-updater' (Get-SIUpdateNowLine -Status 'not started' -Why 'this install has no updater job') $sig) }
        $limit = 0; try { $limit = [int]$upd.properties.configuration.replicaTimeout } catch { $limit = 0 }
        $execs = @(Get-SIUpdateNowArmList -Arm $Arm -Path ('{0}/{1}/executions?api-version={2}' -f $base, $upd.name, $script:SIUpdateNow.ArmApi) -Pages $script:SIUpdateNow.ExecutionPages)
        $running = Test-SIUpdateNowUpdaterRunning -Executions $execs -NowUtc $nowUtc -RunLimitSeconds $limit
        if ($running) {
            $null = Save-SIUpdateNowState -Invoke $Invoke -RaisedAt $sig.RaisedAt -Value (New-SIUpdateNowStateValue -RaisedAt $sig.RaisedAt -Version $sig.Version -Result 'waiting' -Attempts $attempts -ETag $etagNow -By $sig.By)
            return (& $out 'waiting' (Get-SIUpdateNowLine -Status 'waiting' -Signal $sig -Why $running) $sig)
        }

        # the pipeline: said, never waited for, never stopped
        $pipe = ''
        try {
            if ($null -eq $RunState -and $RunStore) { $RunState = $RunStore.Load() }
            if ($RunState -and [string](Get-SIHeartbeatRowValue $RunState 'State') -eq 'Running') {
                $p = Get-SIHeartbeatRunProgress -State $RunState -NowUtc $nowUtc
                $pipe = $(if ($p -and $p.step) { 'yes, {0} ({1})' -f $p.step, $p.state } else { 'yes' })
            }
        } catch { $pipe = '' }

        # ONE start per raisedAt: claimed first
        $claimValue = New-SIUpdateNowStateValue -RaisedAt $sig.RaisedAt -Version $sig.Version -StartedUtc $nowUtc -Result 'starting' -Attempts ($attempts + 1) -ETag $etagNow -By $sig.By
        if (-not (Invoke-SIUpdateNowClaim -Invoke $Invoke -RaisedAt $sig.RaisedAt -Value $claimValue)) { return (& $out 'already' (Get-SIUpdateNowLine -Status 'already' -Signal $sig) $sig) }
        $exec = ''; $err = ''
        try {
            $body = New-SIUpdateNowStartTemplate -Job $upd
            $r = & $Arm 'POST' ('{0}/{1}/start?api-version={2}' -f $base, $upd.name, $script:SIUpdateNow.ArmApi) $body
            if ($r) { $exec = [string]$r.name; if (-not $exec -and $r.PSObject.Properties['id'] -and $r.id) { $exec = ([string]$r.id -split '/')[-1] } }
            if (-not $exec) { $exec = '(started)' }
        } catch { $err = ConvertTo-AitUplinkRedacted -Text $_.Exception.Message; if (-not $err) { $err = 'the start was refused' } }
        if ($err) {
            $null = Save-SIUpdateNowState -Force -Invoke $Invoke -RaisedAt $sig.RaisedAt -Value (New-SIUpdateNowStateValue -RaisedAt $sig.RaisedAt -Version $sig.Version -StartedUtc $nowUtc -Result 'start-failed' -Attempts ($attempts + 1) -ETag $etagNow -By $sig.By)
            return (& $out 'start-failed' (Get-SIUpdateNowLine -Status 'start-failed' -Signal $sig -Why $err) $sig)
        }
        $null = Save-SIUpdateNowState -Force -Invoke $Invoke -RaisedAt $sig.RaisedAt -Value (New-SIUpdateNowStateValue -RaisedAt $sig.RaisedAt -Version $sig.Version -StartedUtc $nowUtc -Result 'started' -Attempts ($attempts + 1) -Execution $exec -ETag $etagNow -By $sig.By)
        & $out 'started' (Get-SIUpdateNowLine -Status 'started' -Signal $sig -Pipeline $pipe -Execution $exec) $sig $true
    } catch {
        & $out 'error' ('update now: the signal could not be checked ({0}) -- the nightly update runs as always' -f (ConvertTo-AitUplinkRedacted -Text $_.Exception.Message)) $sig
    }
}

# =====================================================================================================================
#  #985 THE PRE-RUN CHECK -- once a day, 30 minutes before the next scheduled run
# =====================================================================================================================
function Get-SIUpdatePreRunDecision {
    <#
        PURE. Does this heartbeat tick start the updater to look for a newer release before the next run? -NextRunUtc: the
        next scheduled pipeline run ($null = none scheduled); -LastCheckUtc: the updater's last look at the manifest
        (cfg.InstallState 'UpdateState' lastCheckUtc; $null = never); -ClaimedSlot: the run slot this check last started
        for (ISO). Only the tick in [next run - PreRunLeadMinutes, next run - PreRunLeadMinutes + PreRunTickMinutes) goes on
        (one tick a day: the job runs every 15 minutes). Returns @{ Go; Status (not-due | already | fresh | go); Slot; Why }.
    #>
    param([Parameter(Mandatory)][datetime]$NowUtc, $NextRunUtc, $LastCheckUtc, [AllowEmptyString()][string]$ClaimedSlot = '')
    $S = $script:SIUpdateNow
    $o = { param($go, $st, $slot, $why) [pscustomobject]@{ Go = $go; Status = $st; Slot = $slot; Why = $why } }
    if (-not $NextRunUtc) { return (& $o $false 'not-due' '' 'no pipeline run is scheduled') }
    $now = $NowUtc.ToUniversalTime(); $next = ([datetime]$NextRunUtc).ToUniversalTime()
    $slot = ConvertTo-SIUpdateNowUtc $next
    $mins = ($next - $now).TotalMinutes
    if ($mins -gt $S.PreRunLeadMinutes -or $mins -le ($S.PreRunLeadMinutes - $S.PreRunTickMinutes)) { return (& $o $false 'not-due' $slot ('the next run starts {0}' -f $slot)) }
    if ("$ClaimedSlot".Trim() -and (ConvertTo-SIUpdateNowUtc $ClaimedSlot) -eq $slot) { return (& $o $false 'already' $slot ('the updater was started already for the {0} run' -f $slot)) }
    if ($LastCheckUtc) {
        $last = ([datetime]$LastCheckUtc).ToUniversalTime(); $age = ($now - $last).TotalMinutes
        if ($age -ge 0 -and $age -lt $S.PreRunFreshMinutes) { return (& $o $false 'fresh' $slot ('the updater looked for a newer release {0:N0} min ago' -f $age)) }
    }
    & $o $true 'go' $slot ('the updater last looked for a newer release {0}' -f $(if ($LastCheckUtc) { 'at ' + (ConvertTo-SIUpdateNowUtc $LastCheckUtc) } else { 'never' }))
}

function Get-SIUpdatePreRunClaimSql {
    <# Claim the start for @Slot: taken unless the row names this slot already. No table = not taken. ONE row: Claimed. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS Claimed;
ELSE
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @cur NVARCHAR(400) = NULL, @has int = 0, @ok int = 0;
    SELECT @cur = Value, @has = 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @N;
    IF @has = 0
    BEGIN
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@N, @Value, NULL, N'heartbeat');
        SET @ok = 1;
    END
    ELSE IF ISNULL(CASE WHEN ISJSON(@cur) = 1 THEN JSON_VALUE(@cur, '$.slot') END, N'') <> @Slot
    BEGIN
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat' WHERE Name = @N;
        SET @ok = 1;
    END
    COMMIT;
    SELECT @ok AS Claimed;
END
'@
}

function Read-SIUpdatePreRunFacts {
    <# The updater's last manifest read (UpdateState lastCheckUtc) and the slot this check last claimed. Never throws. #>
    param([scriptblock]$Invoke)
    $f = [pscustomobject]@{ LastCheckUtc = $null; ClaimedSlot = '' }
    if (-not $Invoke) { return $f }
    try {
        $rows = @(ConvertTo-SIHeartbeatSqlRows (& $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Name, Value FROM cfg.InstallState WHERE Name IN (N'UpdateState', @N);" ([ordered]@{ N = $script:SIUpdateNow.PreRunRow }) 'reader'))
        foreach ($r in $rows) {
            $n = [string](Get-SIHeartbeatRowValue $r 'Name'); $v = [string](Get-SIHeartbeatRowValue $r 'Value')
            if (-not $v.Trim()) { continue }
            $o = $null; try { $o = $v | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ($n -eq 'UpdateState' -and $o.PSObject.Properties['lastCheckUtc'] -and $o.lastCheckUtc) { $t = ConvertTo-SIUpdateNowUtc $o.lastCheckUtc; if ($t) { $f.LastCheckUtc = [datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } }
            if ($n -eq $script:SIUpdateNow.PreRunRow -and $o.PSObject.Properties['slot'] -and $o.slot) { $f.ClaimedSlot = [string](ConvertTo-SIUpdateNowUtc $o.slot) }
        }
    } catch { }
    $f
}

function Invoke-SIUpdatePreRunCheck {
    <#
        #985 (owner 2026-11-01): once a day, 30 minutes before the next scheduled pipeline run, the updater is started
        (SI_UPDATER_MODE = update-now) when its last look at Invardia's manifest is more than 15 minutes old -- a release that
        came out after the daily update is then installed before the night's run (the run gate still lands it between two
        runs). At most one start per run slot (claimed in cfg.InstallState 'UpdatePreRunCheck'); never while the updater runs.
        The same switch as the signal (SI_UpdateNow_Enabled). NEVER throws; returns @{ Status; Line; Started }.
        Seams (tests): -Invoke, -RunStore (Load(); ReadDefinition()), -Definition, -Arm, -Scope, -Now, -Ring, -Enabled.
    #>
    [CmdletBinding()]
    param([scriptblock]$Invoke, $RunStore, $Definition, [scriptblock]$Arm, $Scope, $Now, $Ring, [AllowNull()]$Enabled)
    $out = { param($s, $line, [bool]$started = $false) [pscustomobject]@{ Status = $s; Line = $line; Started = $started } }
    try {
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        if (-not $PSBoundParameters.ContainsKey('Ring')) { $ctx = $null; try { $ctx = Get-SITelemetryContext } catch { }; $Ring = if ($ctx -and $ctx.PSObject.Properties['Ring']) { $ctx.Ring } else { $null } }
        $on = if ($null -ne $Enabled) { [bool]$Enabled } else { (Resolve-SIUpdateNowSwitch -Ring $Ring).On }
        if (-not $on) { return (& $out 'off' '') }
        if (-not $Invoke -or -not $RunStore) { return (& $out 'skipped' '') }
        if (-not $Definition) {
            $row = $null; try { if ($RunStore.PSObject.Methods['ReadDefinition']) { $row = $RunStore.ReadDefinition() } } catch { $row = $null }
            $json = if ($row) { [string](Get-SIHeartbeatRowValue $row 'Json') } else { '' }
            if (-not $json -and $row) { $json = [string](Get-SIHeartbeatRowValue $row 'DefinitionJson') }
            if (-not $json.Trim()) { return (& $out 'skipped' '') }
            $Definition = ConvertFrom-SIJobFlowJson -Json $json
            $mode = if ($row) { [string](Get-SIHeartbeatRowValue $row 'Mode') } else { '' }
            if ($mode) { $Definition.Mode = $mode.ToLowerInvariant() }
        }
        if ([string]$Definition.Mode -eq 'schedules') { return (& $out 'skipped' '') }
        $due = Get-SIJobFlowDue -Definition $Definition -Previous $RunStore.Load() -NowUtc $nowUtc
        if ([string]$due.Action -ne 'Wait') { return (& $out 'not-due' '') }
        $facts = Read-SIUpdatePreRunFacts -Invoke $Invoke
        $d = Get-SIUpdatePreRunDecision -NowUtc $nowUtc -NextRunUtc $due.NextUtc -LastCheckUtc $facts.LastCheckUtc -ClaimedSlot $facts.ClaimedSlot
        if (-not $d.Go) { return (& $out $d.Status $(if ($d.Status -in @('fresh', 'already')) { 'update check before the run: not needed -- {0}' -f $d.Why } else { '' })) }

        # the updater: its job and its executions
        if (-not $Arm) {
            if ((Get-Module -Name Pester) -or -not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { return (& $out 'no-updater' 'update check before the run: Azure Resource Manager cannot be reached from here') }
            $Arm = { param($Method, $Path, $Body) Invoke-SIArm -Method $Method -Path $Path -ApiVersion $script:SIUpdateNow.ArmApi -Body $Body }
        }
        if (-not $Scope) { $Scope = Get-SIHeartbeatArmScope }
        if (-not "$($Scope.Sub)".Trim() -or -not "$($Scope.Rg)".Trim()) { return (& $out 'no-updater' 'update check before the run: the subscription or resource group of this install is not known') }
        $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f "$($Scope.Sub)".Trim(), "$($Scope.Rg)".Trim()
        $jobs = @(Get-SIUpdateNowArmList -Arm $Arm -Path ('{0}?api-version={1}' -f $base, $script:SIUpdateNow.ArmApi))
        $upd = @($jobs | Where-Object { $_ -and (ConvertTo-SIHeartbeatJobName ([string]$_.name)) -eq 'updater' })[0]
        if (-not $upd) { $cand = @($jobs | Where-Object { $_ -and [string]$_.name -match '-updater$' }); if ($cand.Count -eq 1) { $upd = $cand[0] } }
        if (-not $upd) { return (& $out 'no-updater' 'update check before the run: this install has no updater job') }
        $limit = 0; try { $limit = [int]$upd.properties.configuration.replicaTimeout } catch { $limit = 0 }
        $execs = @(Get-SIUpdateNowArmList -Arm $Arm -Path ('{0}/{1}/executions?api-version={2}' -f $base, $upd.name, $script:SIUpdateNow.ArmApi) -Pages $script:SIUpdateNow.ExecutionPages)
        $running = Test-SIUpdateNowUpdaterRunning -Executions $execs -NowUtc $nowUtc -RunLimitSeconds $limit
        if ($running) { return (& $out 'waiting' ('update check before the run: the updater runs already ({0}) -- nothing started' -f $running)) }

        # ONE start per run slot: claimed first
        $val = ConvertTo-Json -Compress -InputObject ([ordered]@{ slot = $d.Slot; startedUtc = (ConvertTo-SIUpdateNowUtc $nowUtc); result = 'starting' })
        $claimed = $false
        try {
            $rows = @(ConvertTo-SIHeartbeatSqlRows (& $Invoke (Get-SIUpdatePreRunClaimSql) ([ordered]@{ N = $script:SIUpdateNow.PreRunRow; Value = $val; Slot = $d.Slot }) 'reader'))
            if ($rows.Count) { $c = Get-SIHeartbeatRowValue $rows[0] 'Claimed'; if ($null -eq $c -and ($rows[0] -is [ValueType])) { $c = $rows[0] }; $claimed = ($null -ne $c -and [int]$c -eq 1) }
        } catch { $claimed = $false }
        if (-not $claimed) { return (& $out 'already' '') }
        $exec = ''; $err = ''
        try {
            $r = & $Arm 'POST' ('{0}/{1}/start?api-version={2}' -f $base, $upd.name, $script:SIUpdateNow.ArmApi) (New-SIUpdateNowStartTemplate -Job $upd)
            if ($r) { $exec = [string]$r.name; if (-not $exec -and $r.PSObject.Properties['id'] -and $r.id) { $exec = ([string]$r.id -split '/')[-1] } }
            if (-not $exec) { $exec = '(started)' }
        } catch { $err = ConvertTo-AitUplinkRedacted -Text $_.Exception.Message; if (-not $err) { $err = 'the start was refused' } }
        $res = if ($err) { 'start-failed' } else { 'started' }
        try { $null = & $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat' WHERE Name = @N;" ([ordered]@{ N = $script:SIUpdateNow.PreRunRow; Value = (ConvertTo-Json -Compress -InputObject ([ordered]@{ slot = $d.Slot; startedUtc = (ConvertTo-SIUpdateNowUtc $nowUtc); result = $res; execution = $exec })) }) 'nonquery' } catch { }
        if ($err) { return (& $out 'start-failed' ('update check before the run: the updater could not be started ({0}) -- the next daily update looks again' -f $err)) }
        & $out 'started' ('update check before the run: the updater was started to look for a newer release before the {0} run ({1}) -- execution {2}' -f $d.Slot, $d.Why, $exec) $true
    } catch {
        & $out 'error' ('update check before the run: not done ({0})' -f (ConvertTo-AitUplinkRedacted -Text $_.Exception.Message))
    }
}
