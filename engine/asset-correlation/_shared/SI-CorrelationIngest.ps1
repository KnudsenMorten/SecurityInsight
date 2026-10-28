#Requires -Version 5.1
<#
    SI v3 -- the correlation stage's I/O: read the snapshot out of Log Analytics, write the object map
    back into it. Everything that touches a workspace lives here, so SI-CorrelationCore.ps1 stays pure
    and the join logic stays provable offline.

    WHY THE AUTH BLOCK IS DUPLICATED RATHER THAN SHARED. Resolve-SICorrelationAuthParams (now in
    engine/_shared/SI-LogIngest.ps1, because a free stage publishes with it too) is the
    fourth copy of the same MI / SPN+cert / SPN+secret ladder -- Invoke-Output.ps1, Send-SIRunHealthRow.ps1
    and Invoke-RiskAnalysis.ps1 each carry their own. Extracting it would mean editing files on the path
    that ships to ~30 paying customers and ~6,000 community installs, to serve an engine that is not
    merged yet. That trade is not worth it today, and this repo has already been bitten by widening a
    shared thing for one consumer. Recorded as a finding instead -- see docs/V3-HANDOFF.md.
#>

# NO Set-StrictMode HERE -- same reason as SI-CorrelationCore.ps1: MEASURED 2026-08-12, Set-StrictMode
# in a dot-sourced file LEAKS INTO THE CALLER'S SCOPE, so a library setting it silently overrides the
# strictness its host chose. See that file's header for the full note.

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

# Declared at file scope rather than lazily inside the function that uses it. Kept that way even now
# that StrictMode is gone: the lazy `if (-not $script:X)` idiom is what threw on the first live run, and
# file-scope declaration is the clearer form regardless of strictness. Worth remembering that 60 green
# tests did NOT catch it -- every offline test dot-sources into a scope that already touched the
# variable, so only a cold process ever exercised the failing path.
$script:_SICorrWsCache = @{}

# The identifier columns worth pulling. Read straight from the core so a new joinable type is added in
# exactly one place -- if this list drifted from SIJoinableIdTypes, the column would exist, the join
# would not, and nothing would look wrong.
function Get-SICorrelationProjection {
    $cols = @('SI_AssetId') + (Get-SIJoinableIdTypes) + @('EgNodeId')
    @($cols | Sort-Object -Unique)
}

function Get-SICorrelationSnapshotKql {
    <#
        One engine's slice of the CURRENT snapshot.

        CollectionTime == max(CollectionTime) is how this codebase defines "the latest snapshot" -- the
        value is identical across every shard and replica of one execution, so this picks a whole run
        rather than a ragged mix of two.

        column_ifexists on every field on purpose: the four profile schemas do NOT carry the same
        identifier columns (identity has no AzureResourceId, public-ip has almost none of them), and a
        plain project against a missing column fails the whole query. A missing column must degrade to
        "this engine does not know that id", never to a dead run.
    #>
    param(
        [Parameter(Mandatory)][string]$TableName,
        [int]$RowLimit = 0,
        # #639 a PART of the snapshot (Read-SICorrelationSnapshotParts): the snapshot's time pinned (every part reads the
        # same snapshot) and only the rows with abs(hash(SI_AssetId)) % Parts == Part. Not given: the whole snapshot.
        [Nullable[datetime]]$SnapshotTime,
        [int]$Part = 0,
        [int]$Parts = 0
    )

    $proj = foreach ($c in (Get-SICorrelationProjection)) {
        '    {0} = tostring(column_ifexists("{0}", ""))' -f $c
    }
    # EntityIds is dynamic, not a string -- it carries the typed identifier array that links engines.
    $proj += '    EntityIds = column_ifexists("EntityIds", dynamic(null))'
    # Label only. AssetName is a WEAK identifier and the core drops it before the join; it is here so a
    # human reading the run report can recognise the object.
    # 🔒 READS SI_AssetName, the AUTHORED column. The legacy `AssetName` mirror was removed from the
    # four profile schemas on 2026-08-28 so the data structure carries ONE name for one thing; the
    # fallback below is only for a v2.2-era table that has not been rewritten yet.
    $proj += '    AssetName = coalesce(tostring(column_ifexists("SI_AssetName", "")), tostring(column_ifexists("AssetName", "")))'
    # The snapshot's own timestamp, carried on every row so the run report can show how OLD each
    # engine's contribution is. Measured 2026-08-12: publicip's newest snapshot was 52 days stale while
    # every count still looked perfectly healthy. A stale table does not fail -- it quietly asserts that
    # assets still exist, and correlation would happily build a map of a two-month-old estate.
    $proj += '    SnapshotTime = snap'

    # 🔴 FILTER TO v3 ROWS FIRST, THEN TAKE THE NEWEST (#158 -- finding #83, fourth file). Both editions
    # write the profile tables. Measured 2026-09-29: the v2.2 scheduled job's snapshot (13:40Z, no
    # SI_ columns) was the newest, so correlation read identity 68 rows instead of 762 and published a
    # map of the OTHER edition's estate -- no error, just a smaller world. Same rule and same test as
    # engine/_shared/SI-V3Snapshot.ps1 (`isnotempty(SI_AssetId)`, which v2.2 never emits).
    $snapLine = 'let snap = toscalar(v3 | summarize max(CollectionTime));'
    if ($null -ne $SnapshotTime) { $snapLine = ('let snap = datetime({0});' -f ([datetime]$SnapshotTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')) }
    $kql = @(
        ('let v3 = {0} | where isnotempty(tostring(column_ifexists("SI_AssetId", "")));' -f $TableName)
        $snapLine
        'v3'
        '| where CollectionTime == snap'
    )
    if ($Parts -gt 1) { $kql += ('| where abs(hash(tostring(column_ifexists("SI_AssetId", "")))) % {0} == {1}' -f $Parts, $Part) }
    $kql += @(
        '| project'
        ($proj -join ",`n")
    )
    if ($RowLimit -gt 0) { $kql += ('| take {0}' -f $RowLimit) }
    ($kql -join "`n")
}

function Resolve-SICorrelationWorkspaceId {
    <#
        Workspace ARM id -> the customer (workspace) GUID the query API wants.

        Deliberately NOT dot-sourced from risk-analysis/_shared: those files sit on the path that ships
        to ~30 customers, and asset-correlation must not be able to break Risk Analysis by loading. A
        distinct function name also means both can coexist in one process without either shadowing the
        other -- one fact, two spellings is a trap in code as much as in data.
    #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)

    if ($script:_SICorrWsCache.ContainsKey($WorkspaceResourceId)) { return $script:_SICorrWsCache[$WorkspaceResourceId] }

    if ($WorkspaceResourceId -notmatch '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
        throw "correlation: invalid WorkspaceResourceId -- $WorkspaceResourceId"
    }
    $subId = $matches[1]; $rgName = $matches[2]; $wsName = $matches[3]

    # Restore the caller's subscription afterwards. The engine may run under a context that another
    # stage depends on, and az/Az context on this machine is shared state.
    $curSubId = $null
    try { $curSubId = (Get-SIAzContext).Subscription.Id } catch { }
    if ($curSubId -and $curSubId -ne $subId) { $null = Set-SIAzContext -Subscription $subId -ErrorAction Stop }
    try {
        $ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction Stop
        $custId = $ws.CustomerId.Guid
    } finally {
        if ($curSubId -and $curSubId -ne $subId) {
            try { $null = Set-SIAzContext -Subscription $curSubId -ErrorAction SilentlyContinue } catch { }
        }
    }

    $script:_SICorrWsCache[$WorkspaceResourceId] = $custId
    $custId
}

function Invoke-SICorrelationKql {
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 600
    )
    $custId = Resolve-SICorrelationWorkspaceId -WorkspaceResourceId $WorkspaceResourceId
    $resp = Invoke-SIAzOperationalInsightsQuery -WorkspaceId $custId -Query $Query -Wait $TimeoutSec -ErrorAction Stop
    # #639 a CUT answer is never taken for the whole one: the service answers part of the rows and says why beside them
    # (.Error) -- correlating over part of an engine splits objects and the map would read like data. Refused here (the
    # paged reader then reads that part again as two).
    if ($resp -and $resp.PSObject.Properties['Error'] -and $resp.Error) {
        $e = $resp.Error; $msg = ''
        if ($e -is [string]) { $msg = $e } else { foreach ($n in 'message', 'Message', 'code', 'Code') { $p = $e.PSObject.Properties[$n]; if ($p -and $p.Value) { $msg = [string]$p.Value; break } }; if (-not $msg) { $msg = ($e | ConvertTo-Json -Compress -Depth 4) } }
        throw ("correlation: the answer was cut by the service (partial answer, not used): {0}" -f $msg)
    }
    if (-not $resp -or -not $resp.Results) { return @() }
    # Return the collection plainly. `return , @(...)` yields a NESTED array once a caller wraps the
    # result with @(), and .Count then reads 1 for zero matches -- that bug has been paid for twice
    # already in this codebase, in two different files.
    @($resp.Results)
}

function Get-SILocalEngineRunStart {
    <#
        The newest LOCAL launcher transcript per engine, as UTC -- i.e. when that engine last STARTED
        on this host. The transcript is opened at launch, so its stamp is a start, not a finish; the
        name says so because an earlier version called it RunEnd and the mismatch went straight into a
        comparison (see the minute-truncation note in Get-SICorrelationSnapshot).

        🔑 WHY LOCAL AND NOT LOG ANALYTICS. This exists to detect that a profiler has just run but its
        rows are not queryable yet. Any signal that travels through Log Analytics -- including
        SI_RunHealth_CL -- is delayed by the SAME ingest lag as the data, so it cannot report on it: on
        the run that matters, both the rows and the heartbeat are missing together, and the check would
        conclude everything is current. A transcript is written by the launcher on this host at run end,
        so it is available immediately and cannot lag.

        Filenames are `<engine>_<flavour>[_extra]_<yyyyMMddTHHmmssZ>.log` (Start-LauncherTranscript), so
        the engine and the run time are both already in the name. Returns @{} when the folder is absent
        -- a container or a fresh install simply has no history, which is not an error.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Engines,
        [string]$LogRoot
    )
    $result = @{}
    if ([string]::IsNullOrWhiteSpace($LogRoot) -or -not (Test-Path -LiteralPath $LogRoot)) { return $result }

    foreach ($engine in $Engines) {
        $pattern = ('{0}_*.log' -f $engine)
        $newest  = $null
        foreach ($f in @(Get-ChildItem -LiteralPath $LogRoot -Filter $pattern -File -ErrorAction SilentlyContinue)) {
            if ($f.Name -match '_(?<stamp>\d{8}T\d{6}Z)\.log$') {
                $utc = $null
                try {
                    $utc = [datetime]::ParseExact($Matches['stamp'], 'yyyyMMddTHHmmssZ',
                              [Globalization.CultureInfo]::InvariantCulture,
                              [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
                } catch { $utc = $null }
                if ($utc -and (-not $newest -or $utc -gt $newest)) { $newest = $utc }
            }
        }
        if ($newest) { $result[$engine] = $newest }
    }
    $result
}

function Get-SICorrelationSnapshot {
    <#
        Read every engine's current snapshot and normalise it into correlation inputs.

        A table that does not exist yet is SKIPPED WITH A LOUD LINE, not a failure: a customer who has
        never run the public-ip engine has no SI_PublicIP_Profile_CL, and correlation over the three
        tables they do have is still correct. A table that exists but errors is a different thing and
        rethrows -- silently correlating over half the estate would produce splits that look like data.

        ⏱️ FRESHNESS. Log Analytics does not serve a row the instant it is accepted. Measured 2026-08-14:
        this stage started 2 SECONDS after the publicip profiler posted 13 rows successfully, could not
        see them, and used the previous snapshot -- which was 54 DAYS old -- excluding 16 objects as
        unkeyable. Four minutes later, unchanged code, the same query returned the fresh 13 rows and
        excluded nothing.
        🔑 So when a profiler is known to have finished after the newest snapshot we can see, this WAITS
        and re-reads rather than correlating yesterday's estate. It never fails on age: a standalone run
        legitimately uses the last data that was sent, which may be several hours old, and refusing that
        would make the stage unusable outside the pipeline.
    #>
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][hashtable]$EngineTables,
        [int]$RowLimit = 0,

        # Require every engine's snapshot to be at least this new (UTC). The orchestrator passes the
        # time it started the profilers; unset means "no expectation", the standalone case.
        [datetime]$ExpectFreshSince = [datetime]::MinValue,

        # Bounded. On timeout the stage proceeds with what it has and says so -- a late map beats none.
        [int]$MaxWaitSeconds = -1,
        [int]$PollSeconds = 30,

        # Auto-detection input: engine -> local run-START (UTC). Pass @{} to disable.
        [hashtable]$LocalRunStart = $null
    )

    if ($MaxWaitSeconds -lt 0) {
        $MaxWaitSeconds = if ($global:SI_CorrelationFreshnessWaitSec) { [int]$global:SI_CorrelationFreshnessWaitSec } else { 600 }
    }

    # What each engine must beat before we accept its snapshot.
    #
    # 🔴 TRUNCATED TO THE MINUTE, and that is not cosmetic. `CollectionTime` is stamped
    # `[datetime]::new(y, M, d, h, m, 0)` in Invoke-SIEngineRun.ps1 -- deliberately whole-minute, so
    # every shard of one run shares it. Comparing that against a second-precision launcher stamp is
    # never satisfiable: measured 2026-08-14, endpoint's snapshot read 14:11:00Z while the expectation
    # was 14:11:12Z, so the gate waited its full 600s and then proceeded with data that had been
    # current the whole time. It cost ten minutes a run and lost nothing, which is exactly the kind of
    # defect that survives review. Compare at the precision the data actually has.
    $toMinute = { param([datetime]$T) [datetime]::new($T.Year, $T.Month, $T.Day, $T.Hour, $T.Minute, 0, [DateTimeKind]::Utc) }

    $expected = @{}
    foreach ($engine in @($EngineTables.Keys)) {
        $want = $ExpectFreshSince
        if ($LocalRunStart -and $LocalRunStart.ContainsKey($engine)) {
            $local = [datetime]$LocalRunStart[$engine]
            if ($local -gt $want) { $want = $local }
        }
        if ($want -gt [datetime]::MinValue) { $expected[$engine] = (& $toMinute $want.ToUniversalTime()) }
    }

    $deadline   = (Get-Date).ToUniversalTime().AddSeconds($MaxWaitSeconds)
    $announced  = $false
    $result     = $null

    while ($true) {
        $result = Read-SICorrelationSnapshotOnce -WorkspaceResourceId $WorkspaceResourceId -EngineTables $EngineTables -RowLimit $RowLimit

        if ($expected.Count -eq 0) { break }

        $behind = @()
        foreach ($t in @($result.Tables)) {
            if (-not $expected.ContainsKey($t.Engine)) { continue }
            $want = [datetime]$expected[$t.Engine]
            # A table that is absent entirely is not "behind" -- it has no rows to wait for.
            if ($t.Note) { continue }
            $have = if ($t.SnapshotTime) { & $toMinute ([datetime]$t.SnapshotTime).ToUniversalTime() } else { $null }
            if (-not $have -or $have -lt $want) {
                $behind += ('{0} (snapshot {1}, expected >= {2:u})' -f $t.Engine,
                            $(if ($t.SnapshotTime) { '{0:u}' -f $t.SnapshotTime } else { 'none' }), $want)
            }
        }

        if ($behind.Count -eq 0) {
            if ($announced) { Write-Warning ("correlation: all snapshots are current; continuing.") }
            break
        }

        if ((Get-Date).ToUniversalTime() -ge $deadline) {
            Write-Warning ("correlation: PROCEEDING WITH OLDER DATA after waiting {0}s for Log Analytics ingest. Still behind: {1}. The map is built from the last data that WAS queryable, which is correct but not current." -f $MaxWaitSeconds, ($behind -join '; '))
            break
        }

        if (-not $announced) {
            Write-Warning ("correlation: a profiler finished more recently than the newest queryable snapshot -- waiting up to {0}s for Log Analytics ingest. Behind: {1}" -f $MaxWaitSeconds, ($behind -join '; '))
            $announced = $true
        }
        Start-Sleep -Seconds $PollSeconds
    }

    $result
}

function Get-SICorrelationNoAssetsText {
    <#
        PURE. #876 (a first run on an empty or near-empty tenant): the one line said when EVERY profile table ANSWERED and
        none held a row -- an engine whose table is not there yet has never collected anything, and both snapshot readers
        THROW on a read that failed, so reaching this line means the sources answered with nothing. Names every engine with
        its row count. Nothing is published and nothing is removed: absence is not remediation.
    #>
    param([object[]]$Tables = @())
    $parts = @(@($Tables) | Where-Object { $_ } | ForEach-Object {
        $n = '{0} {1}' -f [string]$_.Engine, [long]$_.Rows
        if ([string]$_.Note) { $n += ' (nothing collected yet)' }
        $n
    })
    $list = if ($parts.Count) { ' (' + ($parts -join ', ') + ')' } else { '' }
    'no assets yet: every source answered, and none holds an asset to correlate{0} -- nothing was published and nothing was removed. The map is built on the first run that finds assets.' -f $list
}

function Read-SICorrelationSnapshotOnce {
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][hashtable]$EngineTables,
        [int]$RowLimit = 0
    )

    $inputs = New-Object System.Collections.ArrayList
    $stats  = New-Object System.Collections.ArrayList

    foreach ($engine in @($EngineTables.Keys | Sort-Object)) {
        $table = [string]$EngineTables[$engine]
        $kql   = Get-SICorrelationSnapshotKql -TableName $table -RowLimit $RowLimit
        $rows  = @()
        $note  = ''
        try {
            $rows = Invoke-SICorrelationKql -WorkspaceResourceId $WorkspaceResourceId -Query $kql
        } catch {
            # ONLY a genuine "this table does not exist" skips the engine (#132). It used to be ANY error
            # that merely MENTIONED the table name -- and a throttle or timeout message quotes the query,
            # which names the table -- so a transient failure silently dropped a whole engine from the
            # correlation, and its assets looked uncorrelated. Anything else now fails the run loudly.
            # #221: the reason is in the RESPONSE BODY, not the exception message ("... invalid status code
            # 'BadRequest'"), so a missing table was never recognised and a fresh install failed here.
            $tableMissing = Test-SIKqlTableMissing -ErrorRecord $_ -TableName $table
            if ($tableMissing) {
                $note = 'table not present -- engine has never run here'
                Write-Warning ("correlation: SKIPPING {0} ({1}) -- {2}" -f $engine, $table, $note)
            } else {
                throw
            }
        }

        $noKeys = 0
        foreach ($r in @($rows)) {
            $in = ConvertTo-SICorrelationInput -Row $r -Engine $engine
            if (@($in.Identifiers).Count -eq 0) { $noKeys++ }
            [void]$inputs.Add($in)
        }

        # Snapshot age. Every row of one snapshot carries the same SnapshotTime, so the first row is
        # the whole answer. Measured 2026-08-12: publicip's NEWEST snapshot was 52 days old while every
        # count in the run report looked perfectly healthy. A stale table does not fail -- it quietly
        # asserts that assets still exist, and correlation would happily publish a map of a two-month-old
        # estate that a connector would then act on.
        $snapUtc = $null
        if (@($rows).Count -gt 0) {
            $raw = $null
            $first = @($rows)[0]
            if ($first -is [System.Collections.IDictionary]) { if ($first.Contains('SnapshotTime')) { $raw = $first['SnapshotTime'] } }
            elseif ($first.PSObject.Properties['SnapshotTime']) { $raw = $first.SnapshotTime }
            if ($raw) { try { $snapUtc = ([datetime]$raw).ToUniversalTime() } catch { $snapUtc = $null } }
        }
        $ageDays = if ($snapUtc) { [int]([datetime]::UtcNow - $snapUtc).TotalDays } else { -1 }

        [void]$stats.Add([pscustomobject]@{
            Engine       = $engine
            Table        = $table
            Rows         = @($rows).Count
            NoJoinableId = $noKeys
            SnapshotTime = $snapUtc
            AgeDays      = $ageDays
            Note         = $note
        })
    }

    [pscustomobject]@{
        Inputs = @($inputs)
        Tables = @($stats)
    }
}

function ConvertTo-SIObjectMapRows {
    <#
        The groups, flattened into the shape SI_ObjectMap_CL publishes.

        A MAP, NOT A MERGED ROW -- one row per
        (SI_CorrelationId, SI_MemberEngine, SI_IdentifierType, SI_IdentifierValue).
        A merged row would have to pick a winner for every column (whose DisplayName? whose Tier?),
        which is the collect-time pre-aggregation the design forbids. Consumers get the join and each
        decides for itself what a merged view means. A merged view is a VIEW.

        SI_IsJoinBasis is the field that makes the map auditable: it marks the identifiers that ACTUALLY
        held the object together, so "why are these one object" is answerable from the published table
        alone, without re-running anything.

        ---------------------------------------------------------------------------------------------
        NAMING, and why every v3-specific column is SI_-prefixed here (renamed 2026-08-13).

        The house rule is COLLISION AVOIDANCE, not branding: the endpoint schema has 178 fields and
        only 4 carry SI_, each for a stated reason ("unprefixed AssetId already means three different
        things across the engines"). By that rule these columns were under-prefixed, and two were
        actively misleading:

          * `Confidence` states confidence in the JOIN, not in the data -- the resolver's own docblock
            says so. Sitting beside vulnerability data, every reader would take it for data confidence.
          * `Engine` was ambiguous against `ObjectEngines` in the SAME row.

        And `EntityIdType`/`EntityIdValue` were ONE FACT WITH TWO SPELLINGS: the engine calls them
        identifiers everywhere (Get-SIJoinableIdTypes, $Identifiers, JoinBasis, SIWeakIdTypes) and then
        published them as "EntityId". That is precisely the defect class SI-CorrelationCore's header
        warns about -- it cost a silent split when EgNodeId and ExposureGraphNodeId diverged -- so
        reintroducing it at the output boundary was not acceptable. "Entity" is also a Microsoft-loaded
        word, and the profile schema already has a differently-shaped `EntityIds`.

        🔒 THREE COLUMNS STAY UNPREFIXED, DELIBERATELY:
          TimeGenerated  -- Log Analytics reserved; prefixing breaks ingestion outright.
          CollectionTime -- AzLogDcrIngestPS convention, and the whole
                            `where CollectionTime == max(CollectionTime)` snapshot idiom rests on it.
          RunId          -- already unprefixed in every other SI table. Prefixing here would fix one
                            table's internal consistency by breaking the family's.

        ⏱️ Renamed while the table had exactly ONE run of throwaway data in it and no consumers. The v2
        profile tables can never be renamed -- public contract, ~30 paying customers and ~6,000 installs,
        finite retention, no backfill. This table was renameable only in that window.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Groups,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][datetime]$CollectionTime,
        # Ledger-resolved ids, keyed by the group's derived SICorrelationId. Absent means no store is
        # configured yet, which is the state today -- see SI_IdSource below.
        [Parameter()][hashtable]$ResolvedIds
    )

    $out = New-Object System.Collections.ArrayList
    foreach ($g in @($Groups)) {
        $basis = @{}
        foreach ($b in @($g.JoinBasis)) { $basis[$b.ToLowerInvariant()] = $true }

        # 🔴 SAY WHETHER THIS ID IS DURABLE OR PROVISIONAL. Without this a consumer cannot tell a
        # ledger-minted id -- stable for the life of the asset -- from today's derived seed, which moves
        # when a member joins or leaves the group (measured: ...:aaa -> ...:000). A connector that
        # cannot tell them apart will happily CREATE a ServiceNow CI from an id that can still change,
        # and duplicate CIs are effectively permanent once incidents point at them.
        # So the map states it, per row, rather than leaving it to be inferred from whether SQL happens
        # to be configured.
        $emitId  = [string]$g.SICorrelationId
        $idSrc   = 'derived-provisional'
        if ($null -ne $ResolvedIds -and $ResolvedIds.ContainsKey($emitId)) {
            $resolved = [string]$ResolvedIds[$emitId]
            if (-not [string]::IsNullOrWhiteSpace($resolved)) { $emitId = $resolved; $idSrc = 'ledger' }
        }

        foreach ($m in @($g.Members)) {
            # A member with NO joinable identifier still belongs on the map (#132). Rows were emitted only
            # per identifier, so such an object was counted as published and then never appeared in
            # SI_ObjectMap_CL -- and every downstream reader (the CMDB connector, asset-properties) saw
            # it as uncorrelated. Its own SI_AssetId stands in; it is never join basis.
            $memberIds = @($m.Identifiers)
            if ($memberIds.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$m.SIAssetId)) {
                $memberIds = @([pscustomobject]@{ Type = 'SI_AssetId'; Value = [string]$m.SIAssetId })
            }
            foreach ($id in $memberIds) {
                [void]$out.Add([pscustomobject]@{
                    CollectionTime      = $CollectionTime
                    RunId               = [string]$RunId
                    SI_CorrelationId    = $emitId
                    SI_IdSource         = $idSrc
                    SI_AssetId          = [string]$m.SIAssetId
                    SI_MemberEngine     = [string]$m.Engine
                    SI_IdentifierType   = [string]$id.Type
                    SI_IdentifierValue  = [string]$id.Value
                    SI_IsJoinBasis      = [bool]$basis.ContainsKey($id.Type.ToLowerInvariant())
                    SI_JoinConfidence   = [string]$g.Confidence
                    SI_IsCrossEngine    = [bool]$g.IsCrossEngine
                    SI_MemberCount      = [int]@($g.Members).Count
                    SI_ObjectEngines    = (@($g.Engines) -join ',')
                })
            }
        }
    }
    @($out)
}

# Resolve-SICorrelationAuthParams + Send-SIObjectMapRows live in engine/_shared (a free stage uses them).
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-LogIngest.ps1')
# #221: classify a failed query on what the service said (the response body), not on the exception's message.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-KqlError.ps1')
